#include "util.hpp"

#include <array>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <stdexcept>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <openssl/evp.h>
#include <openssl/sha.h>
#endif

namespace depotkit {
namespace {

constexpr char kHex[] = "0123456789abcdef";

} // namespace

std::string toHex(const uint8_t *data, size_t len)
{
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[i * 2] = kHex[data[i] >> 4];
        out[i * 2 + 1] = kHex[data[i] & 0xf];
    }
    return out;
}

std::vector<uint8_t> fromHex(std::string_view hex)
{
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    if (hex.size() % 2 != 0)
        throw std::runtime_error("odd hex length");
    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        const int hi = nibble(hex[i * 2]);
        const int lo = nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            throw std::runtime_error("bad hex");
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return out;
}

#if defined(_WIN32)
std::vector<uint8_t> sha1(const uint8_t *data, size_t len)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::vector<uint8_t> out(20);
    DWORD hashLen = 20;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, nullptr, 0) != 0)
        throw std::runtime_error("BCryptOpenAlgorithmProvider SHA1");
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        throw std::runtime_error("BCryptCreateHash");
    }
    if (BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<uint8_t *>(data)),
                       static_cast<ULONG>(len), 0)
        != 0) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        throw std::runtime_error("BCryptHashData");
    }
    if (BCryptFinishHash(hash, out.data(), hashLen, 0) != 0) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        throw std::runtime_error("BCryptFinishHash");
    }
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return out;
}
#else
std::vector<uint8_t> sha1(const uint8_t *data, size_t len)
{
    std::vector<uint8_t> out(SHA_DIGEST_LENGTH);
    SHA1(data, len, out.data());
    return out;
}
#endif

std::vector<uint8_t> sha1File(const std::string &path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
        throw std::runtime_error("open failed: " + path);
    std::vector<uint8_t> buf(1 << 20);
    // Streaming SHA-1 via full read for simplicity on typical game files chunks path;
    // for whole-file verify we accumulate.
#if defined(_WIN32)
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, nullptr, 0) != 0)
        throw std::runtime_error("BCryptOpenAlgorithmProvider SHA1");
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        throw std::runtime_error("BCryptCreateHash");
    }
    while (in) {
        in.read(reinterpret_cast<char *>(buf.data()), static_cast<std::streamsize>(buf.size()));
        const auto n = in.gcount();
        if (n > 0) {
            if (BCryptHashData(hash, buf.data(), static_cast<ULONG>(n), 0) != 0) {
                BCryptDestroyHash(hash);
                BCryptCloseAlgorithmProvider(alg, 0);
                throw std::runtime_error("BCryptHashData");
            }
        }
    }
    std::vector<uint8_t> out(20);
    if (BCryptFinishHash(hash, out.data(), 20, 0) != 0) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        throw std::runtime_error("BCryptFinishHash");
    }
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return out;
#else
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    while (in) {
        in.read(reinterpret_cast<char *>(buf.data()), static_cast<std::streamsize>(buf.size()));
        const auto n = in.gcount();
        if (n > 0)
            SHA1_Update(&ctx, buf.data(), static_cast<size_t>(n));
    }
    std::vector<uint8_t> out(SHA_DIGEST_LENGTH);
    SHA1_Final(out.data(), &ctx);
    return out;
#endif
}

uint32_t adler32(const uint8_t *data, size_t len)
{
    uint32_t a = 0, b = 0;
    for (size_t i = 0; i < len; ++i) {
        a = (a + data[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

uint32_t crc32(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xffffffffu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b) {
            const uint32_t mask = static_cast<uint32_t>(-(crc & 1u));
            crc = (crc >> 1) ^ (0xedb88320u & mask);
        }
    }
    return ~crc;
}

std::vector<uint8_t> readFile(const std::string &path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
        throw std::runtime_error("open failed: " + path);
    in.seekg(0, std::ios::end);
    const auto sz = in.tellg();
    in.seekg(0, std::ios::beg);
    std::vector<uint8_t> out(static_cast<size_t>(sz));
    if (sz > 0)
        in.read(reinterpret_cast<char *>(out.data()), sz);
    return out;
}

std::string readFileBytesAsString(const std::string &path)
{
    const auto bytes = readFile(path);
    return std::string(reinterpret_cast<const char *>(bytes.data()), bytes.size());
}

bool ensureParentDir(const std::string &path)
{
    std::filesystem::path p(path);
    if (!p.has_parent_path())
        return true;
    std::error_code ec;
    std::filesystem::create_directories(p.parent_path(), ec);
    return !ec;
}

bool writeFileAtomic(const std::string &path, const uint8_t *data, size_t len)
{
    if (!ensureParentDir(path))
        return false;
    const std::string tmp = path + ".partial";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out)
            return false;
        out.write(reinterpret_cast<const char *>(data), static_cast<std::streamsize>(len));
        if (!out)
            return false;
    }
    std::error_code ec;
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        std::filesystem::remove(path, ec);
        std::filesystem::rename(tmp, path, ec);
    }
    return !ec;
}

} // namespace depotkit
