#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>

namespace depotkit {

// Keeps synchronization and initialization state for one output path.
// File handles are scoped to each write, so a large manifest cannot exhaust
// the process descriptor limit merely by touching many different files.
class FileSlot {
public:
    bool write(const std::string &path, uint64_t fileSize, uint64_t offset,
               const uint8_t *data, size_t size, std::string &error);

private:
    std::mutex mutex_;
    bool initialized_ = false;
};

} // namespace depotkit
