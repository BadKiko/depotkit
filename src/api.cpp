#include "../include/depotkit.h"

#include "engine/engine.hpp"
#include "manifest/manifest.hpp"
#include "steam/session.hpp"
#include "util/util.hpp"

#include <cstring>
#include <new>
#include <string>

extern "C" {

const char *depotkit_version(void)
{
    return "0.1.0";
}

const char *depotkit_strerror(depotkit_result code)
{
    switch (code) {
    case DEPOTKIT_OK:
        return "ok";
    case DEPOTKIT_ERR_INVALID_ARG:
        return "invalid argument";
    case DEPOTKIT_ERR_IO:
        return "io error";
    case DEPOTKIT_ERR_MANIFEST:
        return "manifest error";
    case DEPOTKIT_ERR_CRYPTO:
        return "crypto error";
    case DEPOTKIT_ERR_NETWORK:
        return "network error";
    case DEPOTKIT_ERR_STEAM:
        return "steam session error";
    case DEPOTKIT_ERR_CANCELLED:
        return "cancelled";
    case DEPOTKIT_ERR_INTERNAL:
        return "internal error";
    }
    return "unknown";
}

uint32_t depotkit_detect_cell_id(void)
{
    return depotkit::detectSteamCellId();
}

int depotkit_list_cdn_servers(uint32_t cell_id, char *out_text, size_t out_len)
{
    if (!out_text || out_len == 0)
        return -1;
    out_text[0] = '\0';
    try {
        depotkit::SteamSession session;
        const uint32_t cell = cell_id ? cell_id : depotkit::detectSteamCellId();
        auto servers = session.contentServers(cell, 40);
        std::string text = "cell=" + std::to_string(cell) + "\n";
        int n = 0;
        for (const auto &s : servers) {
            text += s.host + "\tcell=" + std::to_string(s.cellId) + "\tload="
                    + std::to_string(s.weightedLoad) + "\ttype=" + s.type + "\n";
            ++n;
        }
        if (text.size() >= out_len)
            text.resize(out_len - 1);
        std::memcpy(out_text, text.data(), text.size());
        out_text[text.size()] = '\0';
        return n;
    } catch (...) {
        return -1;
    }
}

depotkit_control *depotkit_control_create(void)
{
    return reinterpret_cast<depotkit_control *>(new (std::nothrow) depotkit::Control());
}

void depotkit_control_destroy(depotkit_control *ctrl)
{
    delete reinterpret_cast<depotkit::Control *>(ctrl);
}

void depotkit_pause(depotkit_control *ctrl)
{
    if (!ctrl)
        return;
    auto *c = reinterpret_cast<depotkit::Control *>(ctrl);
    c->paused = true;
}

void depotkit_resume(depotkit_control *ctrl)
{
    if (!ctrl)
        return;
    auto *c = reinterpret_cast<depotkit::Control *>(ctrl);
    {
        std::lock_guard lock(c->mu);
        c->paused = false;
    }
    c->cv.notify_all();
}

void depotkit_cancel(depotkit_control *ctrl)
{
    if (!ctrl)
        return;
    auto *c = reinterpret_cast<depotkit::Control *>(ctrl);
    {
        std::lock_guard lock(c->mu);
        c->cancelled = true;
        c->paused = false;
    }
    c->cv.notify_all();
}

int depotkit_is_paused(const depotkit_control *ctrl)
{
    if (!ctrl)
        return 0;
    return reinterpret_cast<const depotkit::Control *>(ctrl)->paused.load() ? 1 : 0;
}

int depotkit_is_cancelled(const depotkit_control *ctrl)
{
    if (!ctrl)
        return 0;
    return reinterpret_cast<const depotkit::Control *>(ctrl)->cancelled.load() ? 1 : 0;
}

depotkit_result depotkit_download(const depotkit_request *req, depotkit_progress_fn on_progress, void *user,
                                  depotkit_control *ctrl)
{
    try {
        return depotkit::runDownload(req, on_progress, user, reinterpret_cast<depotkit::Control *>(ctrl));
    } catch (...) {
        return DEPOTKIT_ERR_INTERNAL;
    }
}

depotkit_result depotkit_inspect_manifest(const char *manifest_path, const char *key_hex, uint64_t *out_files,
                                          uint64_t *out_bytes, uint32_t *out_depot_id, uint64_t *out_manifest_id)
{
    if (!manifest_path)
        return DEPOTKIT_ERR_INVALID_ARG;
    try {
        auto man = depotkit::loadManifestFile(manifest_path);
        if (key_hex && *key_hex) {
            auto key = depotkit::fromHex(key_hex);
            if (key.size() != 32)
                return DEPOTKIT_ERR_CRYPTO;
            depotkit::decryptManifestFilenames(man, key.data());
        }
        uint64_t files = 0, bytes = 0;
        for (const auto &f : man.files) {
            if (f.flags & depotkit::kFileFlagDirectory)
                continue;
            ++files;
            bytes += f.size;
        }
        if (out_files)
            *out_files = files;
        if (out_bytes)
            *out_bytes = bytes ? bytes : man.totalUncompressed;
        if (out_depot_id)
            *out_depot_id = man.depotId;
        if (out_manifest_id)
            *out_manifest_id = man.manifestId;
        return DEPOTKIT_OK;
    } catch (...) {
        return DEPOTKIT_ERR_MANIFEST;
    }
}

} // extern "C"
