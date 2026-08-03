#include "manifest.hpp"

#include "../crypto/depot_crypto.hpp"
#include "../util/util.hpp"

#include <cstring>
#include <stdexcept>

namespace depotkit {
namespace {

constexpr uint32_t kProtoPayloadMagic = 0x71F617D0u;
constexpr uint32_t kProtoMetadataMagic = 0x1F4812BEu;
constexpr uint32_t kProtoSignatureMagic = 0x1B81B817u;
constexpr uint32_t kProtoEndMagic = 0x32C415ABu;
constexpr uint32_t kBinaryManifestMagic = 0x16349781u;

struct Cursor {
    const uint8_t *p = nullptr;
    const uint8_t *end = nullptr;

    size_t left() const { return static_cast<size_t>(end - p); }
    uint8_t u8()
    {
        if (p >= end)
            throw std::runtime_error("manifest truncated");
        return *p++;
    }
    uint32_t u32()
    {
        if (left() < 4)
            throw std::runtime_error("manifest truncated");
        uint32_t v = static_cast<uint32_t>(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
        p += 4;
        return v;
    }
    uint64_t u64()
    {
        if (left() < 8)
            throw std::runtime_error("manifest truncated");
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i)
            v |= static_cast<uint64_t>(p[i]) << (8 * i);
        p += 8;
        return v;
    }
    void skip(size_t n)
    {
        if (left() < n)
            throw std::runtime_error("manifest truncated");
        p += n;
    }
    std::vector<uint8_t> bytes(size_t n)
    {
        if (left() < n)
            throw std::runtime_error("manifest truncated");
        std::vector<uint8_t> out(p, p + n);
        p += n;
        return out;
    }
};

uint64_t readVarint(Cursor &c)
{
    uint64_t v = 0;
    int shift = 0;
    for (;;) {
        const uint8_t b = c.u8();
        v |= static_cast<uint64_t>(b & 0x7f) << shift;
        if ((b & 0x80) == 0)
            break;
        shift += 7;
        if (shift > 63)
            throw std::runtime_error("varint overflow");
    }
    return v;
}

void skipProtoField(Cursor &c, uint32_t wire)
{
    switch (wire) {
    case 0:
        (void)readVarint(c);
        break;
    case 1:
        c.skip(8);
        break;
    case 2: {
        const auto n = static_cast<size_t>(readVarint(c));
        c.skip(n);
        break;
    }
    case 5:
        c.skip(4);
        break;
    default:
        throw std::runtime_error("unsupported protobuf wire");
    }
}

ChunkInfo parseChunk(Cursor &c)
{
    ChunkInfo ch;
    while (c.p < c.end) {
        const uint64_t tag = readVarint(c);
        const uint32_t field = static_cast<uint32_t>(tag >> 3);
        const uint32_t wire = static_cast<uint32_t>(tag & 7);
        if (field == 1 && wire == 2) {
            const auto n = static_cast<size_t>(readVarint(c));
            ch.sha = c.bytes(n);
        } else if (field == 2 && wire == 5) {
            ch.crc = c.u32();
        } else if (field == 3 && wire == 0) {
            ch.offset = readVarint(c);
        } else if (field == 4 && wire == 0) {
            ch.uncompressed = static_cast<uint32_t>(readVarint(c));
        } else if (field == 5 && wire == 0) {
            ch.compressed = static_cast<uint32_t>(readVarint(c));
        } else {
            skipProtoField(c, wire);
        }
    }
    return ch;
}

FileInfo parseFileMapping(Cursor &c)
{
    FileInfo f;
    while (c.p < c.end) {
        const uint64_t tag = readVarint(c);
        const uint32_t field = static_cast<uint32_t>(tag >> 3);
        const uint32_t wire = static_cast<uint32_t>(tag & 7);
        if (field == 1 && wire == 2) {
            const auto n = static_cast<size_t>(readVarint(c));
            auto b = c.bytes(n);
            f.filename.assign(reinterpret_cast<const char *>(b.data()), b.size());
        } else if (field == 2 && wire == 0) {
            f.size = readVarint(c);
        } else if (field == 3 && wire == 0) {
            f.flags = static_cast<uint32_t>(readVarint(c));
        } else if (field == 4 && wire == 2) {
            const auto n = static_cast<size_t>(readVarint(c));
            f.filenameHash = c.bytes(n);
        } else if (field == 5 && wire == 2) {
            const auto n = static_cast<size_t>(readVarint(c));
            f.contentHash = c.bytes(n);
        } else if (field == 6 && wire == 2) {
            const auto n = static_cast<size_t>(readVarint(c));
            Cursor sub{c.p, c.p + n};
            c.p += n;
            f.chunks.push_back(parseChunk(sub));
        } else if (field == 7 && wire == 2) {
            const auto n = static_cast<size_t>(readVarint(c));
            auto b = c.bytes(n);
            f.linkTarget.assign(reinterpret_cast<const char *>(b.data()), b.size());
        } else {
            skipProtoField(c, wire);
        }
    }
    return f;
}

void parsePayload(Manifest &m, Cursor c)
{
    while (c.p < c.end) {
        const uint64_t tag = readVarint(c);
        const uint32_t field = static_cast<uint32_t>(tag >> 3);
        const uint32_t wire = static_cast<uint32_t>(tag & 7);
        if (field == 1 && wire == 2) {
            const auto n = static_cast<size_t>(readVarint(c));
            Cursor sub{c.p, c.p + n};
            c.p += n;
            m.files.push_back(parseFileMapping(sub));
        } else {
            skipProtoField(c, wire);
        }
    }
}

void parseMetadata(Manifest &m, Cursor c)
{
    while (c.p < c.end) {
        const uint64_t tag = readVarint(c);
        const uint32_t field = static_cast<uint32_t>(tag >> 3);
        const uint32_t wire = static_cast<uint32_t>(tag & 7);
        if (field == 1 && wire == 0) {
            m.depotId = static_cast<uint32_t>(readVarint(c));
        } else if (field == 2 && wire == 0) {
            m.manifestId = readVarint(c);
        } else if (field == 3 && wire == 0) {
            m.creationTime = static_cast<uint32_t>(readVarint(c));
        } else if (field == 4 && wire == 0) {
            m.filenamesEncrypted = readVarint(c) != 0;
        } else if (field == 5 && wire == 0) {
            m.totalUncompressed = readVarint(c);
        } else if (field == 6 && wire == 0) {
            m.totalCompressed = readVarint(c);
        } else {
            skipProtoField(c, wire);
        }
    }
}

void parseBinaryManifest(Manifest &m, Cursor &c)
{
    // Steam3 binary manifest after magic already consumed.
    const uint32_t headerVersion = c.u32();
    (void)headerVersion;
    m.depotId = c.u32();
    m.manifestId = c.u64();
    m.creationTime = c.u32();
    m.filenamesEncrypted = c.u32() != 0;
    m.totalUncompressed = c.u64();
    m.totalCompressed = c.u64();
    const uint32_t encryptedCrc = c.u32();
    (void)encryptedCrc;
    const uint32_t mappingCount = c.u32();
    const uint32_t mapSize = c.u32();
    (void)mapSize;
    for (uint32_t i = 0; i < mappingCount; ++i) {
        FileInfo f;
        const uint32_t chunkCount = c.u32();
        const uint32_t fileNameSize = c.u32();
        auto nameBytes = c.bytes(fileNameSize);
        // binary names are null-terminated
        size_t nlen = 0;
        while (nlen < nameBytes.size() && nameBytes[nlen] != 0)
            ++nlen;
        f.filename.assign(reinterpret_cast<const char *>(nameBytes.data()), nlen);
        f.flags = c.u32();
        f.size = c.u64();
        f.filenameHash = c.bytes(20);
        f.contentHash = c.bytes(20);
        for (uint32_t ci = 0; ci < chunkCount; ++ci) {
            ChunkInfo ch;
            ch.sha = c.bytes(20);
            ch.crc = c.u32(); // actually checksum / adler in binary format
            ch.offset = c.u64();
            ch.compressed = c.u32();
            ch.uncompressed = c.u32();
            f.chunks.push_back(std::move(ch));
        }
        m.files.push_back(std::move(f));
    }
}

} // namespace

Manifest loadManifestFile(const std::string &path)
{
    const auto data = readFile(path);
    Cursor c{data.data(), data.data() + data.size()};
    Manifest m;

    while (c.p < c.end) {
        const uint32_t magic = c.u32();
        if (magic == kProtoEndMagic)
            break;
        if (magic == kBinaryManifestMagic) {
            parseBinaryManifest(m, c);
            // trailing marker
            if (c.left() >= 4)
                (void)c.u32();
            return m;
        }
        if (magic == kProtoPayloadMagic) {
            const uint32_t len = c.u32();
            Cursor sub{c.p, c.p + len};
            c.p += len;
            parsePayload(m, sub);
        } else if (magic == kProtoMetadataMagic) {
            const uint32_t len = c.u32();
            Cursor sub{c.p, c.p + len};
            c.p += len;
            parseMetadata(m, sub);
        } else if (magic == kProtoSignatureMagic) {
            const uint32_t len = c.u32();
            c.skip(len);
        } else {
            throw std::runtime_error("unrecognized manifest magic");
        }
    }

    if (m.totalUncompressed == 0) {
        for (const auto &f : m.files)
            m.totalUncompressed += f.size;
    }
    return m;
}

bool decryptManifestFilenames(Manifest &m, const uint8_t key[32])
{
    if (!m.filenamesEncrypted)
        return true;
    for (auto &f : m.files) {
        f.filename = decryptDepotFilename(key, f.filename);
        if (!f.linkTarget.empty())
            f.linkTarget = decryptDepotFilename(key, f.linkTarget);
    }
    m.filenamesEncrypted = false;
    return true;
}

} // namespace depotkit
