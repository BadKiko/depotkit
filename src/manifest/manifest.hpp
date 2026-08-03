#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace depotkit {

struct ChunkInfo {
    std::vector<uint8_t> sha; // 20 bytes
    uint32_t crc = 0;
    uint64_t offset = 0;
    uint32_t uncompressed = 0;
    uint32_t compressed = 0;
};

struct FileInfo {
    std::string filename;
    std::vector<uint8_t> filenameHash;
    std::vector<uint8_t> contentHash;
    uint64_t size = 0;
    uint32_t flags = 0;
    std::string linkTarget;
    std::vector<ChunkInfo> chunks;
};

struct Manifest {
    uint32_t depotId = 0;
    uint64_t manifestId = 0;
    uint32_t creationTime = 0;
    bool filenamesEncrypted = false;
    uint64_t totalUncompressed = 0;
    uint64_t totalCompressed = 0;
    std::vector<FileInfo> files;
};

Manifest loadManifestFile(const std::string &path);
bool decryptManifestFilenames(Manifest &m, const uint8_t key[32]);

constexpr uint32_t kFileFlagDirectory = 0x40;

} // namespace depotkit
