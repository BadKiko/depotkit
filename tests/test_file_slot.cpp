#include "../src/engine/file_slot.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace {

void require(bool condition, const std::string &message)
{
    if (!condition) {
        std::cerr << message << '\n';
        std::exit(1);
    }
}

std::optional<size_t> openHandleCount()
{
#if defined(__linux__)
    size_t count = 0;
    for (const auto &entry : std::filesystem::directory_iterator("/proc/self/fd")) {
        (void)entry;
        ++count;
    }
    return count;
#elif defined(_WIN32)
    DWORD count = 0;
    if (GetProcessHandleCount(GetCurrentProcess(), &count))
        return static_cast<size_t>(count);
    return std::nullopt;
#else
    return std::nullopt;
#endif
}

std::string readFile(const std::filesystem::path &path)
{
    std::ifstream file(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

} // namespace

int main()
{
    const auto root = std::filesystem::temp_directory_path()
        / ("depotkit-file-slot-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(root);

    std::string error;
    depotkit::FileSlot slot;
    const auto out = root / "out.bin";
    const uint8_t tail[] = {'E', 'F', 'G', 'H'};
    const uint8_t head[] = {'A', 'B', 'C', 'D'};
    require(slot.write(out.string(), 8, 4, tail, sizeof(tail), error), error);
    require(slot.write(out.string(), 8, 0, head, sizeof(head), error), error);
    require(readFile(out) == "ABCDEFGH", "reopening a file corrupted an earlier chunk");

    const auto baseline = openHandleCount();
    std::vector<std::unique_ptr<depotkit::FileSlot>> slots;
    slots.reserve(1200);
    const uint8_t byte = 'x';
    for (size_t i = 0; i < 1200; ++i) {
        auto next = std::make_unique<depotkit::FileSlot>();
        const auto path = root / ("file-" + std::to_string(i));
        require(next->write(path.string(), 1, 0, &byte, 1, error), error);
        slots.push_back(std::move(next));
        if (baseline && i % 100 == 0) {
            const auto current = openHandleCount();
            require(current && *current <= *baseline + 12,
                    "open handle count grew with the number of files");
        }
    }

    depotkit::FileSlot concurrent;
    const auto concurrentPath = root / "concurrent.bin";
    std::vector<std::thread> writers;
    for (size_t i = 0; i < 8; ++i) {
        writers.emplace_back([&, i] {
            const uint8_t value = static_cast<uint8_t>('0' + i);
            std::string localError;
            if (!concurrent.write(concurrentPath.string(), 8, i, &value, 1, localError)) {
                std::cerr << localError << '\n';
                std::exit(1);
            }
        });
    }
    for (auto &writer : writers)
        writer.join();
    require(readFile(concurrentPath) == "01234567", "concurrent writes corrupted a file");

    std::filesystem::remove_all(root);
    return 0;
}
