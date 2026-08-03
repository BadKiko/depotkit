#include <depotkit.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace {

void usage()
{
    std::fprintf(stderr,
                 "depotkit-cli %s\n"
                 "  cell\n"
                 "  servers [-cell N]\n"
                 "  inspect  -manifest <file> [-key <64hex>]\n"
                 "  download -app <id> -dir <out> -depot <id> -manifest <file> -key <64hex>\n"
                 "           [-jobs N] [-validate] [-cell N]\n"
                 "  download -app <id> -dir <out> -keys <depotkeys.txt> -manifests-dir <dir>\n"
                 "           [-jobs N] [-cell N]\n"
                 "\n"
                 "  -cell N   Steam cell id for nearby CDN (default: auto from Steam config)\n",
                 depotkit_version());
}

void onProgress(const depotkit_progress *p, void *)
{
    const double pct = (p->bytes_total > 0) ? (100.0 * static_cast<double>(p->bytes_done) / static_cast<double>(p->bytes_total))
                                            : 0.0;
    std::fprintf(stdout, "\r[%3.0f%%] %llu/%llu  %.1f MB/s  files %u/%u  depot %u/%u  %s          ", pct,
                 static_cast<unsigned long long>(p->bytes_done),
                 static_cast<unsigned long long>(p->bytes_total), p->rate_bps / (1024.0 * 1024.0), p->files_done,
                 p->files_total, p->depot_index + 1, p->depot_count, p->detail ? p->detail : "");
    std::fflush(stdout);
    if (p->phase == DEPOTKIT_PHASE_DONE || p->phase == DEPOTKIT_PHASE_ERROR
        || p->phase == DEPOTKIT_PHASE_CANCELLED)
        std::fputc('\n', stdout);
}

std::vector<depotkit_depot> loadFromKeysAndDir(const std::string &keysPath, const std::string &manifestsDir,
                                               std::vector<std::string> &storage)
{
    std::ifstream in(keysPath);
    std::vector<depotkit_depot> out;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#')
            continue;
        const auto semi = line.find(';');
        if (semi == std::string::npos)
            continue;
        const std::string id = line.substr(0, semi);
        std::string key = line.substr(semi + 1);
        while (!key.empty() && (key.back() == '\r' || key.back() == ' '))
            key.pop_back();
        // Find <depot>_<anything>.manifest
        std::string best;
        // naive directory scan via cmd is avoided - try common pattern
        // Expect files named like 123456_789.manifest
#ifdef _WIN32
        std::string pattern = manifestsDir + "\\" + id + "_*.manifest";
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) {
            best = manifestsDir + "\\" + fd.cFileName;
            FindClose(h);
        }
#else
        (void)manifestsDir;
#endif
        if (best.empty())
            continue;
        storage.push_back(best);
        storage.push_back(key);
        depotkit_depot d{};
        d.depot_id = static_cast<uint32_t>(std::stoul(id));
        d.manifest_path = storage[storage.size() - 2].c_str();
        d.key_hex = storage[storage.size() - 1].c_str();
        out.push_back(d);
    }
    return out;
}

} // namespace

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage();
        return 2;
    }
    const std::string cmd = argv[1];
    if (cmd == "cell") {
        std::printf("detected Steam cell id: %u\n", depotkit_detect_cell_id());
        return 0;
    }
    if (cmd == "servers") {
        uint32_t cell = 0;
        for (int i = 2; i < argc; ++i) {
            if (!std::strcmp(argv[i], "-cell") && i + 1 < argc)
                cell = static_cast<uint32_t>(std::stoul(argv[++i]));
        }
        char buf[8192];
        const int n = depotkit_list_cdn_servers(cell, buf, sizeof(buf));
        if (n < 0) {
            std::fprintf(stderr, "servers failed\n");
            return 1;
        }
        std::fputs(buf, stdout);
        std::printf("(%d servers)\n", n);
        return 0;
    }
    if (cmd == "inspect") {
        const char *manifest = nullptr;
        const char *key = nullptr;
        for (int i = 2; i < argc; ++i) {
            if (!std::strcmp(argv[i], "-manifest") && i + 1 < argc)
                manifest = argv[++i];
            else if (!std::strcmp(argv[i], "-key") && i + 1 < argc)
                key = argv[++i];
        }
        if (!manifest) {
            usage();
            return 2;
        }
        uint64_t files = 0, bytes = 0;
        uint32_t depot = 0;
        uint64_t mid = 0;
        const depotkit_result r = depotkit_inspect_manifest(manifest, key, &files, &bytes, &depot, &mid);
        if (r != DEPOTKIT_OK) {
            std::fprintf(stderr, "inspect failed: %s\n", depotkit_strerror(r));
            return 1;
        }
        std::printf("depot=%u manifest=%llu files=%llu bytes=%llu (%.2f GiB)\n", depot,
                    static_cast<unsigned long long>(mid), static_cast<unsigned long long>(files),
                    static_cast<unsigned long long>(bytes), bytes / (1024.0 * 1024.0 * 1024.0));
        return 0;
    }

    if (cmd == "download") {
        uint32_t app = 0;
        uint32_t depot = 0;
        uint32_t jobs = 64;
        uint32_t cell = 0;
        int validate = 0;
        const char *dir = nullptr;
        const char *manifest = nullptr;
        const char *key = nullptr;
        const char *keysFile = nullptr;
        const char *manifestsDir = nullptr;
        for (int i = 2; i < argc; ++i) {
            if (!std::strcmp(argv[i], "-app") && i + 1 < argc)
                app = static_cast<uint32_t>(std::stoul(argv[++i]));
            else if (!std::strcmp(argv[i], "-depot") && i + 1 < argc)
                depot = static_cast<uint32_t>(std::stoul(argv[++i]));
            else if (!std::strcmp(argv[i], "-dir") && i + 1 < argc)
                dir = argv[++i];
            else if (!std::strcmp(argv[i], "-manifest") && i + 1 < argc)
                manifest = argv[++i];
            else if (!std::strcmp(argv[i], "-key") && i + 1 < argc)
                key = argv[++i];
            else if (!std::strcmp(argv[i], "-keys") && i + 1 < argc)
                keysFile = argv[++i];
            else if (!std::strcmp(argv[i], "-manifests-dir") && i + 1 < argc)
                manifestsDir = argv[++i];
            else if (!std::strcmp(argv[i], "-jobs") && i + 1 < argc)
                jobs = static_cast<uint32_t>(std::stoul(argv[++i]));
            else if (!std::strcmp(argv[i], "-cell") && i + 1 < argc)
                cell = static_cast<uint32_t>(std::stoul(argv[++i]));
            else if (!std::strcmp(argv[i], "-validate"))
                validate = 1;
        }
        if (!dir || !app) {
            usage();
            return 2;
        }

        std::vector<std::string> storage;
        std::vector<depotkit_depot> depots;
        depotkit_depot single{};
        if (keysFile && manifestsDir) {
            depots = loadFromKeysAndDir(keysFile, manifestsDir, storage);
        } else if (manifest && key && depot) {
            single.depot_id = depot;
            single.manifest_path = manifest;
            single.key_hex = key;
            depots.push_back(single);
        } else {
            usage();
            return 2;
        }

        depotkit_request req{};
        req.app_id = app;
        req.depots = depots.data();
        req.depot_count = depots.size();
        req.install_dir = dir;
        req.max_downloads = jobs;
        req.validate = validate;
        req.cell_id = cell;

        depotkit_control *ctrl = depotkit_control_create();
        const depotkit_result r = depotkit_download(&req, onProgress, nullptr, ctrl);
        depotkit_control_destroy(ctrl);
        if (r != DEPOTKIT_OK) {
            std::fprintf(stderr, "download failed: %s\n", depotkit_strerror(r));
            return 1;
        }
        return 0;
    }

    usage();
    return 2;
}
