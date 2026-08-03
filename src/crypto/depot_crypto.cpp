#include "depot_crypto.hpp"

#include "../util/util.hpp"

#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

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
#endif

#if defined(DEPOTKIT_HAVE_ZSTD)
#include <zstd.h>
#endif

#if defined(DEPOTKIT_HAVE_ZLIB)
#include <zlib.h>
#endif

#if defined(DEPOTKIT_HAVE_LZMA)
extern "C" {
#include "../../third_party/lzma/LzmaDec.h"
}
#endif

namespace depotkit {
namespace {

std::vector<uint8_t> base64Decode(const std::string &in)
{
    static const int8_t kTable[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};
    std::vector<uint8_t> out;
    out.reserve(in.size() * 3 / 4);
    uint32_t buf = 0;
    int bits = 0;
    for (unsigned char c : in) {
        if (c == '=' || c == '\r' || c == '\n' || c == ' ')
            continue;
        const int v = kTable[c];
        if (v < 0)
            throw std::runtime_error("bad base64");
        buf = (buf << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buf >> bits) & 0xff));
        }
    }
    return out;
}

#if defined(_WIN32)
std::vector<uint8_t> bcryptDecrypt(const uint8_t key[32], const uint8_t *iv, bool useCbc,
                                   const uint8_t *data, size_t len, bool pkcs7)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE hkey = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
        throw std::runtime_error("BCrypt AES open");
    const wchar_t *chain = useCbc ? BCRYPT_CHAIN_MODE_CBC : BCRYPT_CHAIN_MODE_ECB;
    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(chain)),
                          static_cast<ULONG>((wcslen(chain) + 1) * sizeof(wchar_t)), 0)
        != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        throw std::runtime_error("BCrypt chain mode");
    }
    if (BCryptGenerateSymmetricKey(alg, &hkey, nullptr, 0, reinterpret_cast<PUCHAR>(const_cast<uint8_t *>(key)),
                                   32, 0)
        != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        throw std::runtime_error("BCrypt key");
    }
    DWORD flags = pkcs7 ? BCRYPT_BLOCK_PADDING : 0;
    ULONG outLen = 0;
    std::vector<uint8_t> ivCopy;
    PUCHAR ivPtr = nullptr;
    ULONG ivLen = 0;
    if (useCbc && iv) {
        ivCopy.assign(iv, iv + 16);
        ivPtr = ivCopy.data();
        ivLen = 16;
    }
    BCryptDecrypt(hkey, reinterpret_cast<PUCHAR>(const_cast<uint8_t *>(data)), static_cast<ULONG>(len),
                  nullptr, ivPtr, ivLen, nullptr, 0, &outLen, flags);
    std::vector<uint8_t> out(outLen);
    const NTSTATUS st =
        BCryptDecrypt(hkey, reinterpret_cast<PUCHAR>(const_cast<uint8_t *>(data)), static_cast<ULONG>(len),
                      nullptr, ivPtr, ivLen, out.data(), outLen, &outLen, flags);
    BCryptDestroyKey(hkey);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (st != 0)
        throw std::runtime_error("BCryptDecrypt failed");
    out.resize(outLen);
    return out;
}
#else
std::vector<uint8_t> opensslDecrypt(const uint8_t key[32], const uint8_t *iv, bool useCbc,
                                    const uint8_t *data, size_t len, bool pkcs7)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("EVP_CIPHER_CTX_new");
    const EVP_CIPHER *cipher = useCbc ? EVP_aes_256_cbc() : EVP_aes_256_ecb();
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key, useCbc ? iv : nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex");
    }
    EVP_CIPHER_CTX_set_padding(ctx, pkcs7 ? 1 : 0);
    std::vector<uint8_t> out(len + 16);
    int out1 = 0, out2 = 0;
    if (EVP_DecryptUpdate(ctx, out.data(), &out1, data, static_cast<int>(len)) != 1
        || EVP_DecryptFinal_ex(ctx, out.data() + out1, &out2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP decrypt failed");
    }
    EVP_CIPHER_CTX_free(ctx);
    out.resize(static_cast<size_t>(out1 + out2));
    return out;
}
#endif

size_t decompressPkZip(const uint8_t *data, size_t len, uint8_t *out, size_t outCap)
{
#if !defined(DEPOTKIT_HAVE_ZLIB)
    (void)data;
    (void)len;
    (void)out;
    (void)outCap;
    throw std::runtime_error("zlib support not built");
#else
    // Local file header + single stored/deflated entry (Steam PKzip chunk).
    if (len < 30 || data[0] != 'P' || data[1] != 'K' || data[2] != 0x03 || data[3] != 0x04)
        throw std::runtime_error("not a pkzip local header");
    const uint16_t method = static_cast<uint16_t>(data[8] | (data[9] << 8));
    const uint32_t compSize = static_cast<uint32_t>(data[18] | (data[19] << 8) | (data[20] << 16) | (data[21] << 24));
    const uint32_t uncompSize =
        static_cast<uint32_t>(data[22] | (data[23] << 8) | (data[24] << 16) | (data[25] << 24));
    const uint16_t nameLen = static_cast<uint16_t>(data[26] | (data[27] << 8));
    const uint16_t extraLen = static_cast<uint16_t>(data[28] | (data[29] << 8));
    const size_t dataOff = 30u + nameLen + extraLen;
    if (dataOff + compSize > len)
        throw std::runtime_error("pkzip truncated");
    if (uncompSize > outCap)
        throw std::runtime_error("pkzip output too small");
    if (method == 0) {
        std::memcpy(out, data + dataOff, uncompSize);
        return uncompSize;
    }
    if (method != 8)
        throw std::runtime_error("unsupported pkzip method");
    z_stream strm{};
    strm.next_in = const_cast<Bytef *>(reinterpret_cast<const Bytef *>(data + dataOff));
    strm.avail_in = compSize;
    strm.next_out = out;
    strm.avail_out = static_cast<uInt>(outCap);
    if (inflateInit2(&strm, -MAX_WBITS) != Z_OK)
        throw std::runtime_error("inflateInit2");
    const int rc = inflate(&strm, Z_FINISH);
    inflateEnd(&strm);
    if (rc != Z_STREAM_END)
        throw std::runtime_error("inflate failed");
    return strm.total_out;
#endif
}

size_t decompressVZstd(const uint8_t *data, size_t len, uint8_t *out, size_t outCap)
{
#if !defined(DEPOTKIT_HAVE_ZSTD)
    (void)data;
    (void)len;
    (void)out;
    (void)outCap;
    throw std::runtime_error("zstd support not built");
#else
    if (len < 8 + 15)
        throw std::runtime_error("vzstd too short");
    const uint32_t magic = static_cast<uint32_t>(data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24));
    if (magic != 0x615A5356u) // 'VSZa' little-endian
        throw std::runtime_error("bad vzstd header");
    if (data[len - 3] != 'z' || data[len - 2] != 's' || data[len - 1] != 'v')
        throw std::runtime_error("bad vzstd footer");
    const int32_t sizeDecompressed = static_cast<int32_t>(
        data[len - 11] | (data[len - 10] << 8) | (data[len - 9] << 16) | (data[len - 8] << 24));
    if (sizeDecompressed < 0 || static_cast<size_t>(sizeDecompressed) > outCap)
        throw std::runtime_error("vzstd size");
    const size_t written =
        ZSTD_decompress(out, static_cast<size_t>(sizeDecompressed), data + 8, len - 8 - 15);
    if (ZSTD_isError(written) || written != static_cast<size_t>(sizeDecompressed))
        throw std::runtime_error("zstd decompress failed");
    return written;
#endif
}

// Minimal LZMA decoder for VZip 'VZa' - uses a compact public-domain style path via
// pre-parsed props. For v1 we support VZstd + PKzip primarily; VZip LZMA is best-effort
// through an external tiny decoder if DEPOTKIT_HAVE_LZMA is set.
size_t decompressVZipLzma(const uint8_t *data, size_t len, uint8_t *out, size_t outCap)
{
#if !defined(DEPOTKIT_HAVE_LZMA)
    (void)data;
    (void)len;
    (void)out;
    (void)outCap;
    throw std::runtime_error("VZip/LZMA not built");
#else
    if (len < 7 + 10)
        throw std::runtime_error("vzip too short");
    if (data[0] != 'V' || data[1] != 'Z' || data[2] != 'a')
        throw std::runtime_error("bad vzip header");
    if (data[len - 2] != 'z' || data[len - 1] != 'v')
        throw std::runtime_error("bad vzip footer");
    // footer: crc32 (4) + sizeDecompressed (4) + magic 'zv' (2) = 10 bytes
    const int32_t sizeDecompressed = static_cast<int32_t>(
        data[len - 6] | (data[len - 5] << 8) | (data[len - 4] << 16) | (data[len - 3] << 24));
    if (sizeDecompressed < 0 || static_cast<size_t>(sizeDecompressed) > outCap)
        throw std::runtime_error("vzip size");
    constexpr size_t kHeader = 7;
    constexpr size_t kFooter = 10;
    constexpr size_t kProps = 5;
    if (len < kHeader + kProps + kFooter)
        throw std::runtime_error("vzip truncated");
    const uint8_t *props = data + kHeader;
    const uint8_t *src = props + kProps;
    SizeT srcLen = static_cast<SizeT>(len - kHeader - kProps - kFooter);
    SizeT destLen = static_cast<SizeT>(sizeDecompressed);
    ELzmaStatus status = LZMA_STATUS_NOT_SPECIFIED;
    ISzAlloc alloc{};
    alloc.Alloc = [](ISzAllocPtr, size_t size) -> void * { return std::malloc(size); };
    alloc.Free = [](ISzAllocPtr, void *addr) { std::free(addr); };
    const SRes rc =
        LzmaDecode(out, &destLen, src, &srcLen, props, static_cast<unsigned>(kProps), LZMA_FINISH_END,
                   &status, &alloc);
    if (rc != SZ_OK)
        throw std::runtime_error("lzma decode failed");
    return static_cast<size_t>(destLen);
#endif
}

} // namespace

std::vector<uint8_t> aesDecryptEcbBlock(const uint8_t key[32], const uint8_t block[16])
{
#if defined(_WIN32)
    return bcryptDecrypt(key, nullptr, false, block, 16, false);
#else
    return opensslDecrypt(key, nullptr, false, block, 16, false);
#endif
}

std::vector<uint8_t> aesDecryptCbcPkcs7(const uint8_t key[32], const uint8_t iv[16],
                                        const uint8_t *data, size_t len)
{
#if defined(_WIN32)
    return bcryptDecrypt(key, iv, true, data, len, true);
#else
    return opensslDecrypt(key, iv, true, data, len, true);
#endif
}

std::vector<uint8_t> steamSymmetricDecrypt(const uint8_t key[32], const uint8_t *data, size_t len)
{
    if (len < 16)
        throw std::runtime_error("cipher too short");
    const auto iv = aesDecryptEcbBlock(key, data);
    return aesDecryptCbcPkcs7(key, iv.data(), data + 16, len - 16);
}

std::string decryptDepotFilename(const uint8_t key[32], const std::string &b64)
{
    auto decoded = base64Decode(b64);
    if (decoded.size() < 16)
        throw std::runtime_error("filename blob too short");
    uint8_t iv[16];
    auto ivPlain = aesDecryptEcbBlock(key, decoded.data());
    std::memcpy(iv, ivPlain.data(), 16);
    auto name = aesDecryptCbcPkcs7(key, iv, decoded.data() + 16, decoded.size() - 16);
    while (!name.empty() && name.back() == 0)
        name.pop_back();
    for (auto &c : name) {
        if (c == '\\')
            c = '/';
#if defined(_WIN32)
        if (c == '/')
            c = '\\';
#endif
    }
    return std::string(reinterpret_cast<const char *>(name.data()), name.size());
}

size_t processDepotChunk(const uint8_t key[32], const uint8_t *encrypted, size_t encryptedLen,
                         uint8_t *out, size_t outCap, uint32_t expectedUncompressed,
                         uint32_t expectedAdler)
{
    auto decrypted = steamSymmetricDecrypt(key, encrypted, encryptedLen);
    if (decrypted.size() < 4)
        throw std::runtime_error("decrypted chunk too short");
    size_t written = 0;
    if (decrypted[0] == 'V' && decrypted[1] == 'S' && decrypted[2] == 'Z' && decrypted[3] == 'a') {
        written = decompressVZstd(decrypted.data(), decrypted.size(), out, outCap);
    } else if (decrypted[0] == 'V' && decrypted[1] == 'Z' && decrypted[2] == 'a') {
        written = decompressVZipLzma(decrypted.data(), decrypted.size(), out, outCap);
    } else if (decrypted[0] == 'P' && decrypted[1] == 'K' && decrypted[2] == 0x03 && decrypted[3] == 0x04) {
        written = decompressPkZip(decrypted.data(), decrypted.size(), out, outCap);
    } else {
        throw std::runtime_error("unknown chunk compression");
    }
    if (expectedUncompressed != 0 && written != expectedUncompressed)
        throw std::runtime_error("chunk uncompressed size mismatch");
    if (expectedAdler != 0 && adler32(out, written) != expectedAdler)
        throw std::runtime_error("chunk adler mismatch (bad key or corrupt)");
    return written;
}

} // namespace depotkit
