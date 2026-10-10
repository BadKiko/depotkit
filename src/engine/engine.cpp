#include "engine.hpp"
#include "file_slot.hpp"

#include "../crypto/depot_crypto.hpp"
#include "../http/http.hpp"
#include "../manifest/manifest.hpp"
#include "../steam/session.hpp"
#include "../util/util.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <climits>
#include <deque>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#endif

namespace depotkit {
namespace {

struct WorkItem {
    uint32_t depotIndex = 0;
    uint32_t depotId = 0;
    std::string path;
    uint64_t fileSize = 0;
    std::vector<uint8_t> fileHash;
    ChunkInfo chunk;
    std::vector<uint8_t> key;
    uint8_t requeues = 0;
};

void emit(depotkit_progress_fn cb, void *user, depotkit_progress p)
{
    if (cb)
        cb(&p, user);
}

bool fileLooksComplete(const std::string &path, uint64_t size, const std::vector<uint8_t> &hash, bool validate)
{
    namespace fs = std::filesystem;
    std::error_code ec;
    if (!fs::exists(path, ec))
        return false;
    if (fs::file_size(path, ec) != size || ec)
        return false;
    // Size-only skip is wrong: we SetEndOfFile/preallocate before chunks land, so a
    // killed download leaves full-sized stubs that would look "done" and skip forever.
    if (!validate)
        return false;
    try {
        return sha1File(path) == hash;
    } catch (...) {
        return false;
    }
}

/** TCP connect RTT in ms; INT_MAX on failure. Used to pin the fastest CDN. */
int tcpConnectMs(const std::string &host, int port)
{
#if defined(_WIN32)
    WSADATA wsa{};
    static std::once_flag once;
    std::call_once(once, [&] { WSAStartup(MAKEWORD(2, 2), &wsa); });

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo *res = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res)
        return INT_MAX;

    int best = INT_MAX;
    for (addrinfo *ai = res; ai; ai = ai->ai_next) {
        SOCKET s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET)
            continue;
        u_long nonblock = 1;
        ioctlsocket(s, FIONBIO, &nonblock);
        const auto t0 = std::chrono::steady_clock::now();
        const int rc = connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
        if (rc == 0) {
            const auto ms = static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
                    .count());
            best = std::min(best, std::max(1, ms));
            closesocket(s);
            break;
        }
        if (WSAGetLastError() == WSAEWOULDBLOCK) {
            fd_set wset;
            FD_ZERO(&wset);
            FD_SET(s, &wset);
            timeval tv{1, 500000}; // 1.5s
            if (select(0, nullptr, &wset, nullptr, &tv) > 0) {
                const auto ms = static_cast<int>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
                        .count());
                best = std::min(best, std::max(1, ms));
            }
        }
        closesocket(s);
        if (best != INT_MAX)
            break;
    }
    freeaddrinfo(res);
    return best;
#else
    (void)host;
    (void)port;
    return INT_MAX;
#endif
}

void pinFastestServers(std::vector<CdnServer> &servers, size_t keep)
{
    if (servers.size() <= 1)
        return;
    struct Scored {
        CdnServer srv;
        int score = INT_MAX;
    };
    std::vector<Scored> scored;
    scored.reserve(servers.size());
    for (auto &s : servers) {
        Scored sc;
        sc.srv = s;
        int rtt = tcpConnectMs(s.host, s.port ? s.port : 443);
        if (rtt == INT_MAX)
            rtt = 5000;
        // Prefer local SteamCache edges; anycast CDNs often connect fast then throttle/401.
        if (s.type == "SteamCache" || s.type == "CDNCache")
            rtt = static_cast<int>(rtt * 0.7);
        if (s.cellId < 0)
            rtt += 800;
        sc.score = rtt;
        scored.push_back(std::move(sc));
    }
    std::sort(scored.begin(), scored.end(), [](const Scored &a, const Scored &b) {
        if (a.score != b.score)
            return a.score < b.score;
        return a.srv.weightedLoad < b.srv.weightedLoad;
    });
    servers.clear();
    for (size_t i = 0; i < scored.size() && servers.size() < keep; ++i)
        servers.push_back(std::move(scored[i].srv));
}

/** Spread chunks across files so many paths stay hot in parallel. */
std::deque<WorkItem> interleaveWork(std::vector<WorkItem> &&flat)
{
    std::unordered_map<std::string, std::deque<WorkItem>> byPath;
    std::vector<std::string> order;
    order.reserve(flat.size());
    for (auto &w : flat) {
        auto &q = byPath[w.path];
        if (q.empty())
            order.push_back(w.path);
        q.push_back(std::move(w));
    }
    std::deque<WorkItem> out;
    bool any = true;
    while (any) {
        any = false;
        for (const auto &path : order) {
            auto &q = byPath[path];
            if (q.empty())
                continue;
            any = true;
            out.push_back(std::move(q.front()));
            q.pop_front();
        }
    }
    return out;
}

} // namespace

depotkit_result runDownload(const depotkit_request *req, depotkit_progress_fn onProgress, void *user,
                            Control *ctrl)
{
    if (!req || !req->install_dir || !req->depots || req->depot_count == 0)
        return DEPOTKIT_ERR_INVALID_ARG;

    const uint32_t jobs = req->max_downloads ? req->max_downloads : 48;
    const uint32_t cellId = req->cell_id ? req->cell_id : detectSteamCellId();
    SteamSession session;

    const std::string connectingMsg = "Steam CDN cell " + std::to_string(cellId);
    emit(onProgress, user,
         depotkit_progress{0, 0, 0, 0, 0, 0, static_cast<uint32_t>(req->depot_count),
                           DEPOTKIT_PHASE_CONNECTING, connectingMsg.c_str()});

    std::vector<CdnServer> servers;
    try {
        servers = session.contentServers(cellId, 40);
        if (!servers.empty()) {
            const std::string detail = "CDN " + servers.front().host + " cell="
                                       + std::to_string(servers.front().cellId) + " load="
                                       + std::to_string(servers.front().weightedLoad)
                                       + " (n=" + std::to_string(servers.size()) + ")";
            emit(onProgress, user,
                 depotkit_progress{0, 0, 0, 0, 0, 0, static_cast<uint32_t>(req->depot_count),
                                   DEPOTKIT_PHASE_CONNECTING, detail.c_str()});
        }
    } catch (const std::exception &ex) {
        emit(onProgress, user,
             depotkit_progress{0, 0, 0, 0, 0, 0, static_cast<uint32_t>(req->depot_count),
                               DEPOTKIT_PHASE_ERROR, ex.what()});
        return DEPOTKIT_ERR_STEAM;
    }

    if (servers.empty()) {
        emit(onProgress, user,
             depotkit_progress{0, 0, 0, 0, 0, 0, static_cast<uint32_t>(req->depot_count),
                               DEPOTKIT_PHASE_ERROR, "No CDN servers"});
        return DEPOTKIT_ERR_STEAM;
    }

    // Probe TCP RTT and keep the fastest SteamCache edge (+1 failover).
    pinFastestServers(servers, 4);
    {
        const std::string detail = "CDN pin " + servers.front().host + " cell="
                                   + std::to_string(servers.front().cellId);
        emit(onProgress, user,
             depotkit_progress{0, 0, 0, 0, 0, 0, static_cast<uint32_t>(req->depot_count),
                               DEPOTKIT_PHASE_CONNECTING, detail.c_str()});
    }

    emit(onProgress, user,
         depotkit_progress{0, 0, 0, 0, 0, 0, static_cast<uint32_t>(req->depot_count),
                           DEPOTKIT_PHASE_PLANNING, "Planning…"});

    std::vector<WorkItem> workFlat;
    uint64_t totalBytes = 0;
    uint64_t seenBytes = 0;
    uint64_t completeBytes = 0;
    uint32_t totalFiles = 0;
    uint32_t filesDone = 0;
    uint32_t depotsLoaded = 0;
    std::vector<std::string> skipReasons;

    for (size_t di = 0; di < req->depot_count; ++di) {
        if (ctrl && ctrl->cancelled.load())
            return DEPOTKIT_ERR_CANCELLED;
        const auto &d = req->depots[di];
        if (!d.manifest_path || !d.key_hex)
            return DEPOTKIT_ERR_INVALID_ARG;
        {
            const std::string detail = "Planning depot " + std::to_string(di + 1) + "/"
                                       + std::to_string(req->depot_count)
                                       + " (" + std::to_string(d.depot_id) + ")…";
            emit(onProgress, user,
                 depotkit_progress{completeBytes, std::max(seenBytes, totalBytes), 0, filesDone,
                                   totalFiles, static_cast<uint32_t>(di),
                                   static_cast<uint32_t>(req->depot_count), DEPOTKIT_PHASE_PLANNING,
                                   detail.c_str()});
        }
        Manifest man;
        try {
            man = loadManifestFile(d.manifest_path);
            auto key = fromHex(d.key_hex);
            if (key.size() != 32)
                return DEPOTKIT_ERR_CRYPTO;
            decryptManifestFilenames(man, key.data());
            auto lastHashEmit = std::chrono::steady_clock::now();
            uint32_t hashedSinceEmit = 0;
            for (const auto &f : man.files) {
                if (ctrl && ctrl->cancelled.load())
                    return DEPOTKIT_ERR_CANCELLED;
                if (f.flags & kFileFlagDirectory)
                    continue;
                ++totalFiles;
                seenBytes += f.size;
                std::string path = std::string(req->install_dir);
#if defined(_WIN32)
                if (!path.empty() && path.back() != '\\' && path.back() != '/')
                    path.push_back('\\');
#else
                if (!path.empty() && path.back() != '/')
                    path.push_back('/');
#endif
                path += f.filename;
                if (fileLooksComplete(path, f.size, f.contentHash, req->validate != 0)) {
                    ++filesDone;
                    completeBytes += f.size;
                    ++hashedSinceEmit;
                    const auto now = std::chrono::steady_clock::now();
                    if (hashedSinceEmit >= 4
                        || std::chrono::duration<double>(now - lastHashEmit).count() >= 0.35) {
                        const std::string detail =
                            "Checking existing files… " + std::to_string(filesDone) + "/"
                            + std::to_string(totalFiles);
                        emit(onProgress, user,
                             depotkit_progress{completeBytes, seenBytes, 0, filesDone, totalFiles,
                                               static_cast<uint32_t>(di),
                                               static_cast<uint32_t>(req->depot_count),
                                               DEPOTKIT_PHASE_PLANNING, detail.c_str()});
                        lastHashEmit = now;
                        hashedSinceEmit = 0;
                    }
                    continue;
                }
                for (const auto &ch : f.chunks) {
                    WorkItem w;
                    w.depotIndex = static_cast<uint32_t>(di);
                    w.depotId = d.depot_id ? d.depot_id : man.depotId;
                    w.path = path;
                    w.fileSize = f.size;
                    w.fileHash = f.contentHash;
                    w.chunk = ch;
                    w.key = key;
                    totalBytes += ch.uncompressed;
                    workFlat.push_back(std::move(w));
                }
            }
            ++depotsLoaded;
        } catch (const std::exception &ex) {
            // One bad DLC/staging manifest should not kill the whole install.
            const std::string detail =
                std::string("Skipping depot ") + std::to_string(d.depot_id) + ": " + ex.what();
            if (skipReasons.size() < 3)
                skipReasons.push_back(detail);
            emit(onProgress, user,
                 depotkit_progress{completeBytes, seenBytes, 0, filesDone, totalFiles,
                                   static_cast<uint32_t>(di),
                                   static_cast<uint32_t>(req->depot_count), DEPOTKIT_PHASE_PLANNING,
                                   detail.c_str()});
            continue;
        }
    }
    if (depotsLoaded == 0) {
        std::string err = "No readable manifests";
        if (!skipReasons.empty()) {
            err.push_back(':');
            for (size_t i = 0; i < skipReasons.size(); ++i) {
                err.push_back(' ');
                err += skipReasons[i];
                if (i + 1 < skipReasons.size())
                    err.push_back(';');
            }
        }
        emit(onProgress, user,
             depotkit_progress{0, 0, 0, 0, 0, 0, static_cast<uint32_t>(req->depot_count),
                               DEPOTKIT_PHASE_ERROR, err.c_str()});
        return DEPOTKIT_ERR_MANIFEST;
    }

    std::atomic<uint64_t> bytesDone{0};
    std::atomic<uint32_t> filesDoneAtomic{filesDone};
    std::mutex tokenMu;
    std::unordered_map<std::string, std::string> tokens; // host -> query

    // Warm CDN auth on sticky hosts before the download storm.
    emit(onProgress, user,
         depotkit_progress{0, totalBytes, 0, filesDoneAtomic.load(), totalFiles, 0,
                           static_cast<uint32_t>(req->depot_count), DEPOTKIT_PHASE_CONNECTING,
                           "CDN auth…"});
    const uint32_t warmDepot =
        (req->depot_count > 0 && req->depots[0].depot_id) ? req->depots[0].depot_id : 0;
    for (const auto &srv : servers) {
        if (ctrl && ctrl->cancelled.load())
            return DEPOTKIT_ERR_CANCELLED;
        try {
            auto t = session.cdnAuthToken(req->app_id, warmDepot ? warmDepot : req->app_id, srv.host);
            if (!t.empty()) {
                std::lock_guard lock(tokenMu);
                tokens[srv.host] = t;
            }
        } catch (...) {
            // Token optional on some pipes; first 403 will refresh.
        }
    }

    std::mutex filesMu;
    std::unordered_map<std::string, std::unique_ptr<FileSlot>> fileSlots;
    auto slotFor = [&](const std::string &path) -> FileSlot & {
        std::lock_guard lock(filesMu);
        auto &ptr = fileSlots[path];
        if (!ptr)
            ptr = std::make_unique<FileSlot>();
        return *ptr;
    };

    std::mutex qmu;
    std::deque<WorkItem> queue = interleaveWork(std::move(workFlat));
    std::atomic<bool> failed{false};
    std::string failMsg;
    std::mutex failMu;

    std::mutex emitMu;
    auto lastEmit = std::chrono::steady_clock::now();
    uint64_t lastBytes = 0;
    double rate = 0;

    auto maybeEmit = [&](depotkit_phase phase, const char *detail, uint32_t depotIndex) {
        const auto now = std::chrono::steady_clock::now();
        const auto done = bytesDone.load();
        double emitRate = 0;
        bool shouldEmit = (phase != DEPOTKIT_PHASE_DOWNLOADING);
        {
            std::lock_guard lock(emitMu);
            const double dt = std::chrono::duration<double>(now - lastEmit).count();
            if (dt > 0.12) {
                const double inst = (done - lastBytes) / (dt > 0 ? dt : 1.0);
                rate = rate * 0.6 + inst * 0.4;
                lastEmit = now;
                lastBytes = done;
                shouldEmit = true;
            }
            emitRate = rate;
        }
        if (!shouldEmit)
            return;
        emit(onProgress, user,
             depotkit_progress{done, totalBytes, emitRate, filesDoneAtomic.load(), totalFiles, depotIndex,
                               static_cast<uint32_t>(req->depot_count), phase, detail});
    };

    HttpSession http(jobs);
    maybeEmit(DEPOTKIT_PHASE_DOWNLOADING, "Downloading…", 0);

    auto workerFn = [&](uint32_t workerId) {
        std::vector<uint8_t> outBuf;
        const size_t stickyN = servers.size();
        size_t hostCursor = stickyN ? (workerId % stickyN) : 0;

        while (!failed.load()) {
            if (ctrl) {
                if (ctrl->cancelled.load())
                    return;
                if (ctrl->paused.load()) {
                    maybeEmit(DEPOTKIT_PHASE_PAUSED, "Paused", 0);
                    ctrl->waitIfPaused();
                    if (ctrl->cancelled.load())
                        return;
                    maybeEmit(DEPOTKIT_PHASE_DOWNLOADING, "Downloading…", 0);
                }
            }

            WorkItem item;
            {
                std::lock_guard lock(qmu);
                if (queue.empty())
                    return;
                item = std::move(queue.front());
                queue.pop_front();
            }

            bool ok = false;
            bool ioFailure = false;
            std::string lastErr;
            for (int attempt = 0; attempt < 10 && !ok; ++attempt) {
                if (ctrl && ctrl->cancelled.load())
                    return;
                if (ctrl && ctrl->paused.load()) {
                    maybeEmit(DEPOTKIT_PHASE_PAUSED, "Paused", 0);
                    ctrl->waitIfPaused();
                    if (ctrl->cancelled.load())
                        return;
                    maybeEmit(DEPOTKIT_PHASE_DOWNLOADING, "Downloading…", 0);
                }
                if (attempt > 0)
                    std::this_thread::sleep_for(std::chrono::milliseconds(40 * attempt));

                if (stickyN == 0) {
                    lastErr = "no CDN servers";
                    break;
                }
                const size_t srvIndex = (hostCursor + static_cast<size_t>(attempt)) % stickyN;
                const CdnServer &srv = servers[srvIndex];
                std::string token;
                {
                    std::lock_guard lock(tokenMu);
                    auto it = tokens.find(srv.host);
                    if (it != tokens.end())
                        token = it->second;
                }

                const std::string shaHex = toHex(item.chunk.sha.data(), item.chunk.sha.size());
                std::string url = buildChunkUrl(srv, item.depotId, shaHex, token);
                // Download + decrypt WITHOUT holding the file lock (Steam-like parallelism).
                auto resp = http.get(url, 45000);
                if (resp.status == 403 || resp.status == 401) {
                    try {
                        auto t = session.cdnAuthToken(req->app_id, item.depotId, srv.host);
                        if (!t.empty()) {
                            std::lock_guard lock(tokenMu);
                            tokens[srv.host] = t;
                            token = t;
                        }
                    } catch (const std::exception &ex) {
                        lastErr = ex.what();
                    }
                    url = buildChunkUrl(srv, item.depotId, shaHex, token);
                    resp = http.get(url, 45000);
                }
                if (resp.status != 200 || resp.body.empty()) {
                    lastErr = "HTTP " + std::to_string(resp.status) + " " + resp.error;
                    continue;
                }

                try {
                    outBuf.resize(std::max<size_t>(item.chunk.uncompressed, 1));
                    const size_t n =
                        processDepotChunk(item.key.data(), resp.body.data(), resp.body.size(), outBuf.data(),
                                          outBuf.size(), item.chunk.uncompressed, item.chunk.crc);

                    FileSlot &slot = slotFor(item.path);
                    std::string ioErr;
                    if (!slot.write(item.path, item.fileSize, item.chunk.offset,
                                    outBuf.data(), n, ioErr)) {
                        lastErr = ioErr;
                        ioFailure = true;
                        break;
                    }

                    bytesDone += n;
                    ok = true;
                    hostCursor = srvIndex;
                    maybeEmit(DEPOTKIT_PHASE_DOWNLOADING, item.path.c_str(), item.depotIndex);
                } catch (const std::exception &ex) {
                    lastErr = ex.what();
                    ok = false;
                }
            }

            if (!ok) {
                // One soft requeue - transient CDN / HTTP2 flakes shouldn't kill the whole job.
                if (!ioFailure && item.requeues < 1 && !failed.load()) {
                    item.requeues = static_cast<uint8_t>(item.requeues + 1);
                    std::lock_guard lock(qmu);
                    queue.push_back(std::move(item));
                    continue;
                }
                std::lock_guard lock(failMu);
                failed = true;
                failMsg = "chunk download failed for " + item.path + ": " + lastErr;
                return;
            }
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(jobs);
    for (uint32_t i = 0; i < jobs; ++i)
        threads.emplace_back(workerFn, i);
    for (auto &t : threads)
        t.join();

    if (ctrl && ctrl->cancelled.load()) {
        emit(onProgress, user,
             depotkit_progress{bytesDone.load(), totalBytes, rate, filesDoneAtomic.load(), totalFiles, 0,
                               static_cast<uint32_t>(req->depot_count), DEPOTKIT_PHASE_CANCELLED,
                               "Cancelled"});
        return DEPOTKIT_ERR_CANCELLED;
    }
    if (failed.load()) {
        emit(onProgress, user,
             depotkit_progress{bytesDone.load(), totalBytes, rate, filesDoneAtomic.load(), totalFiles, 0,
                               static_cast<uint32_t>(req->depot_count), DEPOTKIT_PHASE_ERROR,
                               failMsg.c_str()});
        return DEPOTKIT_ERR_NETWORK;
    }

    emit(onProgress, user,
         depotkit_progress{totalBytes, totalBytes, rate, totalFiles, totalFiles, 0,
                           static_cast<uint32_t>(req->depot_count), DEPOTKIT_PHASE_DONE, "Done"});
    return DEPOTKIT_OK;
}

} // namespace depotkit
