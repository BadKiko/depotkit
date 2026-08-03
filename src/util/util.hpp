#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace depotkit {

std::string toHex(const uint8_t *data, size_t len);
std::vector<uint8_t> fromHex(std::string_view hex);

std::vector<uint8_t> sha1(const uint8_t *data, size_t len);
std::vector<uint8_t> sha1File(const std::string &path);

uint32_t adler32(const uint8_t *data, size_t len);
uint32_t crc32(const uint8_t *data, size_t len);

std::string readFileBytesAsString(const std::string &path);
std::vector<uint8_t> readFile(const std::string &path);
bool writeFileAtomic(const std::string &path, const uint8_t *data, size_t len);
bool ensureParentDir(const std::string &path);

} // namespace depotkit
