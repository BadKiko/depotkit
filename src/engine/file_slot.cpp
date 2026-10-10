#include "file_slot.hpp"

#include "../util/util.hpp"

#include <cerrno>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <limits>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace depotkit {

bool FileSlot::write(const std::string &path, uint64_t fileSize, uint64_t offset,
                     const uint8_t *data, size_t size, std::string &error)
{
    std::lock_guard lock(mutex_);
    try {
        ensureParentDir(path);
    } catch (const std::exception &ex) {
        error = "cannot create parent directory for " + path + ": " + ex.what();
        return false;
    }

#if defined(_WIN32)
    if (fileSize > static_cast<uint64_t>(std::numeric_limits<LONGLONG>::max())
        || offset > static_cast<uint64_t>(std::numeric_limits<LONGLONG>::max())
        || size > static_cast<size_t>(std::numeric_limits<DWORD>::max())) {
        error = "file size, offset, or chunk size exceeds Windows limits: " + path;
        return false;
    }

    std::wstring widePath;
    try {
        widePath = std::filesystem::path(path).wstring();
    } catch (const std::exception &ex) {
        error = "cannot use path " + path + ": " + ex.what();
        return false;
    }
    HANDLE handle = CreateFileW(widePath.c_str(), GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        error = "CreateFile failed for " + path + " (error " + std::to_string(GetLastError()) + ")";
        return false;
    }
    struct HandleGuard {
        HANDLE handle;
        ~HandleGuard() { CloseHandle(handle); }
    } guard{handle};

    if (!initialized_ && fileSize > 0) {
        LARGE_INTEGER end{};
        end.QuadPart = static_cast<LONGLONG>(fileSize);
        if (!SetFilePointerEx(handle, end, nullptr, FILE_BEGIN) || !SetEndOfFile(handle)) {
            error = "cannot size " + path + " (error " + std::to_string(GetLastError()) + ")";
            return false;
        }
    }

    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(handle, position, nullptr, FILE_BEGIN)) {
        error = "cannot seek " + path + " (error " + std::to_string(GetLastError()) + ")";
        return false;
    }
    DWORD written = 0;
    if (!WriteFile(handle, data, static_cast<DWORD>(size), &written, nullptr) || written != size) {
        error = "write failed for " + path + " (error " + std::to_string(GetLastError()) + ")";
        return false;
    }
#else
    std::fstream stream(path, std::ios::in | std::ios::out | std::ios::binary);
    if (!stream) {
        const int openError = errno;
        std::error_code ec;
        if (std::filesystem::exists(path, ec) || ec) {
            error = "cannot open " + path + ": " + std::strerror(openError);
            return false;
        }
        std::ofstream create(path, std::ios::binary | std::ios::app);
        if (!create) {
            error = "cannot create " + path + ": " + std::strerror(errno);
            return false;
        }
        create.close();
        stream.clear();
        stream.open(path, std::ios::in | std::ios::out | std::ios::binary);
    }
    if (!stream) {
        error = "cannot open " + path + ": " + std::strerror(errno);
        return false;
    }
    if (!initialized_ && fileSize > 0) {
        if (fileSize - 1 > static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max())) {
            error = "file size exceeds stream limits: " + path;
            return false;
        }
        stream.seekp(static_cast<std::streamoff>(fileSize - 1));
        const char zero = 0;
        stream.write(&zero, 1);
        if (!stream) {
            error = "cannot size " + path;
            return false;
        }
    }
    if (offset > static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max())) {
        error = "chunk offset exceeds stream limits: " + path;
        return false;
    }
    if (size > static_cast<size_t>(std::numeric_limits<std::streamsize>::max())) {
        error = "chunk size exceeds stream limits: " + path;
        return false;
    }
    stream.seekp(static_cast<std::streamoff>(offset));
    stream.write(reinterpret_cast<const char *>(data), static_cast<std::streamsize>(size));
    if (!stream) {
        error = "write failed for " + path;
        return false;
    }
    stream.flush();
    if (!stream) {
        error = "flush failed for " + path;
        return false;
    }
    stream.close();
    if (!stream) {
        error = "close failed for " + path;
        return false;
    }
#endif

    initialized_ = true;
    return true;
}

} // namespace depotkit
