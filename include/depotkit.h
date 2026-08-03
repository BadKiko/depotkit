#ifndef DEPOTKIT_H
#define DEPOTKIT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(DEPOTKIT_SHARED)
#  if defined(DEPOTKIT_BUILD)
#    define DEPOTKIT_API __declspec(dllexport)
#  else
#    define DEPOTKIT_API __declspec(dllimport)
#  endif
#else
#  define DEPOTKIT_API
#endif

typedef enum depotkit_phase {
    DEPOTKIT_PHASE_IDLE = 0,
    DEPOTKIT_PHASE_CONNECTING = 1,
    DEPOTKIT_PHASE_PLANNING = 2,
    DEPOTKIT_PHASE_DOWNLOADING = 3,
    DEPOTKIT_PHASE_VERIFYING = 4,
    DEPOTKIT_PHASE_PAUSED = 5,
    DEPOTKIT_PHASE_DONE = 6,
    DEPOTKIT_PHASE_CANCELLED = 7,
    DEPOTKIT_PHASE_ERROR = 8
} depotkit_phase;

typedef enum depotkit_result {
    DEPOTKIT_OK = 0,
    DEPOTKIT_ERR_INVALID_ARG = 1,
    DEPOTKIT_ERR_IO = 2,
    DEPOTKIT_ERR_MANIFEST = 3,
    DEPOTKIT_ERR_CRYPTO = 4,
    DEPOTKIT_ERR_NETWORK = 5,
    DEPOTKIT_ERR_STEAM = 6,
    DEPOTKIT_ERR_CANCELLED = 7,
    DEPOTKIT_ERR_INTERNAL = 8
} depotkit_result;

typedef struct depotkit_progress {
    uint64_t bytes_done;
    uint64_t bytes_total;
    double rate_bps;
    uint32_t files_done;
    uint32_t files_total;
    uint32_t depot_index;
    uint32_t depot_count;
    depotkit_phase phase;
    const char *detail; /* UTF-8, owned by library for callback duration */
} depotkit_progress;

typedef void (*depotkit_progress_fn)(const depotkit_progress *progress, void *user);

typedef struct depotkit_depot {
    uint32_t depot_id;
    const char *manifest_path; /* required local .manifest */
    const char *key_hex;       /* 64 hex chars = 32-byte depot key */
} depotkit_depot;

typedef struct depotkit_request {
    uint32_t app_id;
    const depotkit_depot *depots;
    size_t depot_count;
    const char *install_dir;
    uint32_t max_downloads; /* 0 = default 32; raise for fat pipes */
    int validate;           /* re-check existing files */
    uint32_t cell_id;       /* 0 = default */
} depotkit_request;

typedef struct depotkit_control depotkit_control;

DEPOTKIT_API const char *depotkit_version(void);
DEPOTKIT_API const char *depotkit_strerror(depotkit_result code);

/** Best-effort Steam cell id from local Steam config (proximity hint). 0 if unknown. */
DEPOTKIT_API uint32_t depotkit_detect_cell_id(void);

/** Write nearby CDN server list (one host per line: host cell load type). Returns lines written. */
DEPOTKIT_API int depotkit_list_cdn_servers(uint32_t cell_id, char *out_text, size_t out_len);

DEPOTKIT_API depotkit_control *depotkit_control_create(void);
DEPOTKIT_API void depotkit_control_destroy(depotkit_control *ctrl);
DEPOTKIT_API void depotkit_pause(depotkit_control *ctrl);
DEPOTKIT_API void depotkit_resume(depotkit_control *ctrl);
DEPOTKIT_API void depotkit_cancel(depotkit_control *ctrl);
DEPOTKIT_API int depotkit_is_paused(const depotkit_control *ctrl);
DEPOTKIT_API int depotkit_is_cancelled(const depotkit_control *ctrl);

/** Blocking download. Safe to call from a worker thread. */
DEPOTKIT_API depotkit_result depotkit_download(const depotkit_request *req,
                                               depotkit_progress_fn on_progress,
                                               void *user,
                                               depotkit_control *ctrl);

/** Offline inspect: parse manifest + decrypt names, print totals (CLI helper). */
DEPOTKIT_API depotkit_result depotkit_inspect_manifest(const char *manifest_path,
                                                       const char *key_hex,
                                                       uint64_t *out_files,
                                                       uint64_t *out_bytes,
                                                       uint32_t *out_depot_id,
                                                       uint64_t *out_manifest_id);

/** Platform bits from decrypted filenames: 1=windows, 2=linux, 4=macos (OR-able). */
DEPOTKIT_API depotkit_result depotkit_manifest_platform_hint(const char *manifest_path,
                                                             const char *key_hex,
                                                             uint32_t *out_flags);

#ifdef __cplusplus
}
#endif

#endif /* DEPOTKIT_H */
