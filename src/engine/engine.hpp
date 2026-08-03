#pragma once

#include "../../include/depotkit.h"

#include <atomic>
#include <condition_variable>
#include <mutex>

namespace depotkit {

struct Control {
    std::atomic<bool> paused{false};
    std::atomic<bool> cancelled{false};
    std::mutex mu;
    std::condition_variable cv;

    void waitIfPaused()
    {
        std::unique_lock lock(mu);
        cv.wait(lock, [&] { return !paused.load() || cancelled.load(); });
    }
};

depotkit_result runDownload(const depotkit_request *req, depotkit_progress_fn onProgress, void *user,
                            Control *ctrl);

} // namespace depotkit
