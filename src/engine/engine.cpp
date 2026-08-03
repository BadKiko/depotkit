#include "engine.hpp"

#include "../crypto/depot_crypto.hpp"
#include "../http/http.hpp"
#include "../manifest/manifest.hpp"
#include "../steam/session.hpp"
#include "../util/util.hpp"

#include <chrono>
#include <deque>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>

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
    if (!validate)
        return true;
    try {
        return sha1File(path) == hash;
    } catch (...) {
        return false;
    }
}

} // namespace

depotkit_result runDownload(const depotkit_request *req, depotkit_progress_fn onProgress, void *user,
                            Control *ctrl)
{
    if (!req || !req->install_dir || !req->depots || req->depot_count == 0)
        return DEPOTKIT_ERR_INVALID_ARG;

    const uint32_t jobs = req->max_downloads ? req->max_downloads : 32;
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

    emit(onProgress, user,
         depotkit_progress{0, 0, 0, 0, 0, 0, static_cast<uint32_t>(req->depot_count),
                           DEPOTKIT_PHASE_PLANNING, "Planning…"});

    std::vector<WorkItem> work;
    uint64_t totalBytes = 0;
    uint32_t totalFiles = 0;
    uint32_t filesDone = 0;

    for (size_t di = 0; di < req->depot_count; ++di) {
        const auto &d = req->depots[di];
        if (!d.manifest_path || !d.key_hex)
            return DEPOTKIT_ERR_INVALID_ARG;
        Manifest man;
        try {
            man = loadManifestFile(d.manifest_path);
            auto key = fromHex(d.key_hex);
            if (key.size() != 32)
                return DEPOTKIT_ERR_CRYPTO;
            decryptManifestFilenames(man, key.data());
            for (const auto &f : man.files) {
                if (f.flags & kFileFlagDirectory)
                    continue;
                ++totalFiles;
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
                    totalBytes += f.size; // count as done via bytes_done later
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
                    work.push_back(std::move(w));
                }
            }
        } catch (const std::exception &ex) {
            emit(onProgress, user,
                 depotkit_progress{0, 0, 0, 0, 0, 0, static_cast<uint32_t>(req->depot_count),
                                   DEPOTKIT_PHASE_ERROR, ex.what()});
            return DEPOTKIT_ERR_MANIFEST;
        }
    }

    // bytes already present from skipped files
    std::atomic<uint64_t> bytesDone{0};
    // recount skipped: for simplicity start at 0 and only count downloaded chunks;
    // skipped complete files are reported via files_done.
    std::atomic<uint32_t> filesDoneAtomic{filesDone};
    std::atomic<uint32_t> serverIdx{0};
    std::mutex tokenMu;
    std::unordered_map<std::string, std::string> tokens; // host -> query
    std::mutex fileMu;
    std::unordered_map<std::string, std::unique_ptr<std::mutex>> pathLocks;

    auto lockForPath = [&](const std::string &path) -> std::unique_lock<std::mutex> {
        std::mutex *m = nullptr;
        {
            std::lock_guard lock(fileMu);
            auto &slot = pathLocks[path];
            if (!slot)
                slot = std::make_unique<std::mutex>();
            m = slot.get();
        }
        return std::unique_lock<std::mutex>(*m);
    };

    std::mutex qmu;
    std::deque<WorkItem> queue(work.begin(), work.end());
    std::atomic<bool> failed{false};
    std::string failMsg;
    std::mutex failMu;

    auto lastEmit = std::chrono::steady_clock::now();
    uint64_t lastBytes = 0;
    double rate = 0;

    auto maybeEmit = [&](depotkit_phase phase, const char *detail, uint32_t depotIndex) {
        const auto now = std::chrono::steady_clock::now();
        const auto done = bytesDone.load();
        const double dt =
            std::chrono::duration<double>(now - lastEmit).count();
        if (dt > 0.2) {
            const double inst = (done - lastBytes) / (dt > 0 ? dt : 1.0);
            rate = rate * 0.7 + inst * 0.3;
            lastEmit = now;
            lastBytes = done;
        }
        emit(onProgress, user,
             depotkit_progress{done, totalBytes, rate, filesDoneAtomic.load(), totalFiles, depotIndex,
                               static_cast<uint32_t>(req->depot_count), phase, detail});
    };

    maybeEmit(DEPOTKIT_PHASE_DOWNLOADING, "Downloading…", 0);

    auto workerFn = [&]() {
        std::vector<uint8_t> outBuf;
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

            ensureParentDir(item.path);
            auto pathLock = lockForPath(item.path);
            // Open/create file and write at offset.
            std::fstream file(item.path,
                              std::ios::in | std::ios::out | std::ios::binary);
            if (!file) {
                std::ofstream create(item.path, std::ios::binary | std::ios::trunc);
                create.close();
                file.open(item.path, std::ios::in | std::ios::out | std::ios::binary);
            }
            if (!file) {
                std::lock_guard lock(failMu);
                failed = true;
                failMsg = "cannot open " + item.path;
                return;
            }

            bool ok = false;
            std::string lastErr;
            for (int attempt = 0; attempt < 5 && !ok; ++attempt) {
                if (ctrl && ctrl->cancelled.load())
                    return;
                const uint32_t si = serverIdx.fetch_add(1) % static_cast<uint32_t>(servers.size());
                CdnServer srv = servers[si];
                if (!srv.type.empty() && srv.type != "CDN" && srv.type != "SteamCache"
                    && srv.type != "CDNCache") {
                    // Still try, but prefer CDN hosts by rotating.
                }
                std::string token;
                {
                    std::lock_guard lock(tokenMu);
                    auto it = tokens.find(srv.host);
                    if (it != tokens.end())
                        token = it->second;
                }
                const std::string shaHex = toHex(item.chunk.sha.data(), item.chunk.sha.size());
                const std::string url = buildChunkUrl(srv, item.depotId, shaHex, token);
                auto resp = httpGet(url, 60000);
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
                    const std::string url2 = buildChunkUrl(srv, item.depotId, shaHex, token);
                    resp = httpGet(url2, 60000);
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
                    file.seekp(static_cast<std::streamoff>(item.chunk.offset));
                    file.write(reinterpret_cast<const char *>(outBuf.data()), static_cast<std::streamsize>(n));
                    if (!file) {
                        lastErr = "write failed";
                        continue;
                    }
                    file.flush();
                    bytesDone += n;
                    ok = true;
                    maybeEmit(DEPOTKIT_PHASE_DOWNLOADING, item.path.c_str(), item.depotIndex);
                } catch (const std::exception &ex) {
                    lastErr = ex.what();
                    ok = false;
                }
            }
            if (!ok) {
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
        threads.emplace_back(workerFn);
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
