#include <depotkit.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

// Build a minimal protobuf ContentManifest on the fly and ensure inspect works
// without encrypted names.

namespace {

void writeU32(std::vector<uint8_t> &b, uint32_t v)
{
    b.push_back(uint8_t(v));
    b.push_back(uint8_t(v >> 8));
    b.push_back(uint8_t(v >> 16));
    b.push_back(uint8_t(v >> 24));
}
void writeVarint(std::vector<uint8_t> &b, uint64_t v)
{
    while (v >= 0x80) {
        b.push_back(uint8_t((v & 0x7f) | 0x80));
        v >>= 7;
    }
    b.push_back(uint8_t(v));
}
void writeBytesField(std::vector<uint8_t> &b, uint32_t field, const void *data, size_t n)
{
    writeVarint(b, (uint64_t(field) << 3) | 2);
    writeVarint(b, n);
    const auto *p = static_cast<const uint8_t *>(data);
    b.insert(b.end(), p, p + n);
}
void writeStringField(std::vector<uint8_t> &b, uint32_t field, const char *s)
{
    writeBytesField(b, field, s, std::strlen(s));
}
void writeVarintField(std::vector<uint8_t> &b, uint32_t field, uint64_t v)
{
    writeVarint(b, (uint64_t(field) << 3) | 0);
    writeVarint(b, v);
}

} // namespace

int main()
{
    // Chunk
    std::vector<uint8_t> chunk;
    const uint8_t sha[20] = {};
    writeBytesField(chunk, 1, sha, 20);
    // crc as fixed32 field 2
    writeVarint(chunk, (2ull << 3) | 5);
    writeU32(chunk, 1);
    writeVarintField(chunk, 3, 0);
    writeVarintField(chunk, 4, 4);
    writeVarintField(chunk, 5, 8);

    std::vector<uint8_t> file;
    writeStringField(file, 1, "hello.txt");
    writeVarintField(file, 2, 4);
    writeVarintField(file, 3, 0);
    writeBytesField(file, 4, sha, 20);
    writeBytesField(file, 5, sha, 20);
    writeBytesField(file, 6, chunk.data(), chunk.size());

    std::vector<uint8_t> payload;
    writeBytesField(payload, 1, file.data(), file.size());

    std::vector<uint8_t> meta;
    writeVarintField(meta, 1, 42);
    writeVarintField(meta, 2, 99);
    writeVarintField(meta, 4, 0);
    writeVarintField(meta, 5, 4);

    std::vector<uint8_t> sig;
    const char dummySig[] = "sig";
    writeBytesField(sig, 1, dummySig, 3);

    std::vector<uint8_t> man;
    writeU32(man, 0x71F617D0u);
    writeU32(man, uint32_t(payload.size()));
    man.insert(man.end(), payload.begin(), payload.end());
    writeU32(man, 0x1F4812BEu);
    writeU32(man, uint32_t(meta.size()));
    man.insert(man.end(), meta.begin(), meta.end());
    writeU32(man, 0x1B81B817u);
    writeU32(man, uint32_t(sig.size()));
    man.insert(man.end(), sig.begin(), sig.end());
    writeU32(man, 0x32C415ABu);

    const auto path = (std::filesystem::temp_directory_path() / "depotkit_test.manifest").string();
    {
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char *>(man.data()), static_cast<std::streamsize>(man.size()));
    }

    uint64_t files = 0, bytes = 0;
    uint32_t depot = 0;
    uint64_t mid = 0;
    const depotkit_result r = depotkit_inspect_manifest(path.c_str(), nullptr, &files, &bytes, &depot, &mid);
    if (r != DEPOTKIT_OK) {
        std::fprintf(stderr, "inspect failed: %s\n", depotkit_strerror(r));
        return 1;
    }
    if (depot != 42 || mid != 99 || files != 1 || bytes != 4) {
        std::fprintf(stderr, "unexpected values depot=%u mid=%llu files=%llu bytes=%llu\n", depot,
                     (unsigned long long)mid, (unsigned long long)files, (unsigned long long)bytes);
        return 1;
    }
    std::printf("manifest test ok\n");
    return 0;
}
