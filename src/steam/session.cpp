#include "session.hpp"

#include "../http/http.hpp"
#include "../util/util.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <random>
#include <stdexcept>
#include <thread>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winreg.h>
#include <bcrypt.h>
#include <wincrypt.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace depotkit {
namespace {

constexpr uint32_t kEMsgChannelEncryptRequest = 1303;
constexpr uint32_t kEMsgChannelEncryptResponse = 1304;
constexpr uint32_t kEMsgChannelEncryptResult = 1305;
constexpr uint32_t kEMsgMulti = 1;
constexpr uint32_t kEMsgClientLogon = 5514;
constexpr uint32_t kEMsgClientLogOnResponse = 751;
constexpr uint32_t kEMsgServiceMethodCallFromClient = 151;
constexpr uint32_t kEMsgServiceMethodResponse = 147;
constexpr uint32_t kProtoMask = 0x80000000u;

// Steam Public universe SubjectPublicKeyInfo (from SteamRE KeyDictionary).
const uint8_t kSteamPublicKey[] = {
    0x30, 0x81, 0x9D, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
    0x05, 0x00, 0x03, 0x81, 0x8B, 0x00, 0x30, 0x81, 0x87, 0x02, 0x81, 0x81, 0x00, 0xDF, 0xEC, 0x1A,
    0xD6, 0x2C, 0x10, 0x66, 0x2C, 0x17, 0x35, 0x3A, 0x14, 0xB0, 0x7C, 0x59, 0x11, 0x7F, 0x9D, 0xD3,
    0xD8, 0x2B, 0x7A, 0xE3, 0xE0, 0x15, 0xCD, 0x19, 0x1E, 0x46, 0xE8, 0x7B, 0x87, 0x74, 0xA2, 0x18,
    0x46, 0x31, 0xA9, 0x03, 0x14, 0x79, 0x82, 0x8E, 0xE9, 0x45, 0xA2, 0x49, 0x12, 0xA9, 0x23, 0x68,
    0x73, 0x89, 0xCF, 0x69, 0xA1, 0xB1, 0x61, 0x46, 0xBD, 0xC1, 0xBE, 0xBF, 0xD6, 0x01, 0x1B, 0xD8,
    0x81, 0xD4, 0xDC, 0x90, 0xFB, 0xFE, 0x4F, 0x52, 0x73, 0x66, 0xCB, 0x95, 0x70, 0xD7, 0xC5, 0x8E,
    0xBA, 0x1C, 0x7A, 0x33, 0x75, 0xA1, 0x62, 0x34, 0x46, 0xBB, 0x60, 0xB7, 0x80, 0x68, 0xFA, 0x13,
    0xA7, 0x7A, 0x8A, 0x37, 0x4B, 0x9E, 0xC6, 0xF4, 0x5D, 0x5F, 0x3A, 0x99, 0xF9, 0x9E, 0xC4, 0x3A,
    0xE9, 0x63, 0xA2, 0xBB, 0x88, 0x19, 0x28, 0xE0, 0xE7, 0x14, 0xC0, 0x42, 0x89, 0x02, 0x01, 0x11,
};

void writeU32(std::vector<uint8_t> &b, uint32_t v)
{
    b.push_back(static_cast<uint8_t>(v & 0xff));
    b.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    b.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
    b.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
}
void writeU64(std::vector<uint8_t> &b, uint64_t v)
{
    for (int i = 0; i < 8; ++i)
        b.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xff));
}
uint32_t readU32(const uint8_t *p)
{
    return static_cast<uint32_t>(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}
uint64_t readU64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v |= static_cast<uint64_t>(p[i]) << (8 * i);
    return v;
}

void writeVarint(std::vector<uint8_t> &b, uint64_t v)
{
    while (v >= 0x80) {
        b.push_back(static_cast<uint8_t>((v & 0x7f) | 0x80));
        v >>= 7;
    }
    b.push_back(static_cast<uint8_t>(v));
}

void writeProtoString(std::vector<uint8_t> &b, uint32_t field, const std::string &s)
{
    writeVarint(b, (static_cast<uint64_t>(field) << 3) | 2);
    writeVarint(b, s.size());
    b.insert(b.end(), s.begin(), s.end());
}
void writeProtoU32(std::vector<uint8_t> &b, uint32_t field, uint32_t v)
{
    writeVarint(b, (static_cast<uint64_t>(field) << 3) | 0);
    writeVarint(b, v);
}
void writeProtoU64(std::vector<uint8_t> &b, uint32_t field, uint64_t v)
{
    writeVarint(b, (static_cast<uint64_t>(field) << 3) | 0);
    writeVarint(b, v);
}
void writeProtoBytes(std::vector<uint8_t> &b, uint32_t field, const uint8_t *data, size_t n)
{
    writeVarint(b, (static_cast<uint64_t>(field) << 3) | 2);
    writeVarint(b, n);
    b.insert(b.end(), data, data + n);
}

std::string b64encode(const uint8_t *data, size_t len)
{
    static const char *t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((len + 2) / 3 * 4);
    for (size_t i = 0; i < len; i += 3) {
        const uint32_t n = (static_cast<uint32_t>(data[i]) << 16)
                           | ((i + 1 < len ? data[i + 1] : 0u) << 8)
                           | (i + 2 < len ? data[i + 2] : 0u);
        out.push_back(t[(n >> 18) & 63]);
        out.push_back(t[(n >> 12) & 63]);
        out.push_back(i + 1 < len ? t[(n >> 6) & 63] : '=');
        out.push_back(i + 2 < len ? t[n & 63] : '=');
    }
    return out;
}

#if defined(_WIN32)
struct WinsockInit {
    WinsockInit()
    {
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);
    }
};
WinsockInit gWinsock;

std::vector<uint8_t> rsaOaepSha1Encrypt(const uint8_t *pubDer, size_t pubLen, const uint8_t *plain,
                                        size_t plainLen)
{
    CERT_PUBLIC_KEY_INFO *pki = nullptr;
    DWORD pkiLen = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pubDer, static_cast<DWORD>(pubLen),
                             CRYPT_DECODE_ALLOC_FLAG, nullptr, &pki, &pkiLen))
        throw std::runtime_error("CryptDecodeObjectEx pubkey");
    HCRYPTPROV prov = 0;
    HCRYPTKEY hkey = 0;
    if (!CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)
        || !CryptImportPublicKeyInfo(prov, X509_ASN_ENCODING, pki, &hkey)) {
        if (pki)
            LocalFree(pki);
        throw std::runtime_error("CryptImportPublicKeyInfo");
    }
    LocalFree(pki);
    std::vector<uint8_t> out(512);
    if (plainLen > out.size()) {
        CryptDestroyKey(hkey);
        CryptReleaseContext(prov, 0);
        throw std::runtime_error("RSA plaintext too large");
    }
    std::memcpy(out.data(), plain, plainLen);
    DWORD encLen = static_cast<DWORD>(plainLen);
    if (!CryptEncrypt(hkey, 0, TRUE, CRYPT_OAEP, out.data(), &encLen, static_cast<DWORD>(out.size()))) {
        CryptDestroyKey(hkey);
        CryptReleaseContext(prov, 0);
        throw std::runtime_error("CryptEncrypt OAEP failed");
    }
    out.resize(encLen);
    // CryptoAPI writes little-endian RSA output; Steam expects big-endian → reverse
    std::reverse(out.begin(), out.end());
    CryptDestroyKey(hkey);
    CryptReleaseContext(prov, 0);
    return out;
}

std::vector<uint8_t> hmacSha1(const uint8_t *key, size_t keyLen, const uint8_t *data, size_t dataLen)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objLen = 0, res = 0;
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen), &res, 0);
    std::vector<uint8_t> obj(objLen);
    std::vector<uint8_t> out(20);
    BCryptCreateHash(alg, &hash, obj.data(), objLen, reinterpret_cast<PUCHAR>(const_cast<uint8_t *>(key)),
                     static_cast<ULONG>(keyLen), 0);
    BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<uint8_t *>(data)), static_cast<ULONG>(dataLen), 0);
    BCryptFinishHash(hash, out.data(), 20, 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return out;
}

std::vector<uint8_t> aesEncryptEcb(const uint8_t key[32], const uint8_t block[16])
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE hkey = nullptr;
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_ECB)),
                      sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    BCryptGenerateSymmetricKey(alg, &hkey, nullptr, 0, reinterpret_cast<PUCHAR>(const_cast<uint8_t *>(key)), 32, 0);
    ULONG outLen = 16;
    std::vector<uint8_t> out(16);
    BCryptEncrypt(hkey, reinterpret_cast<PUCHAR>(const_cast<uint8_t *>(block)), 16, nullptr, nullptr, 0, out.data(),
                  16, &outLen, 0);
    BCryptDestroyKey(hkey);
    BCryptCloseAlgorithmProvider(alg, 0);
    return out;
}

std::vector<uint8_t> aesEncryptCbc(const uint8_t key[32], uint8_t iv[16], const uint8_t *data, size_t len)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE hkey = nullptr;
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_CBC)),
                      sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCryptGenerateSymmetricKey(alg, &hkey, nullptr, 0, reinterpret_cast<PUCHAR>(const_cast<uint8_t *>(key)), 32, 0);
    std::vector<uint8_t> ivCopy(iv, iv + 16);
    ULONG outLen = 0;
    BCryptEncrypt(hkey, reinterpret_cast<PUCHAR>(const_cast<uint8_t *>(data)), static_cast<ULONG>(len), nullptr,
                  ivCopy.data(), 16, nullptr, 0, &outLen, BCRYPT_BLOCK_PADDING);
    std::vector<uint8_t> out(outLen);
    ivCopy.assign(iv, iv + 16);
    BCryptEncrypt(hkey, reinterpret_cast<PUCHAR>(const_cast<uint8_t *>(data)), static_cast<ULONG>(len), nullptr,
                  ivCopy.data(), 16, out.data(), outLen, &outLen, BCRYPT_BLOCK_PADDING);
    BCryptDestroyKey(hkey);
    BCryptCloseAlgorithmProvider(alg, 0);
    out.resize(outLen);
    return out;
}

std::vector<uint8_t> aesDecryptEcb(const uint8_t key[32], const uint8_t block[16])
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE hkey = nullptr;
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_ECB)),
                      sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    BCryptGenerateSymmetricKey(alg, &hkey, nullptr, 0, reinterpret_cast<PUCHAR>(const_cast<uint8_t *>(key)), 32, 0);
    ULONG outLen = 16;
    std::vector<uint8_t> out(16);
    BCryptDecrypt(hkey, reinterpret_cast<PUCHAR>(const_cast<uint8_t *>(block)), 16, nullptr, nullptr, 0, out.data(),
                  16, &outLen, 0);
    BCryptDestroyKey(hkey);
    BCryptCloseAlgorithmProvider(alg, 0);
    return out;
}

std::vector<uint8_t> aesDecryptCbc(const uint8_t key[32], uint8_t iv[16], const uint8_t *data, size_t len)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE hkey = nullptr;
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_CBC)),
                      sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCryptGenerateSymmetricKey(alg, &hkey, nullptr, 0, reinterpret_cast<PUCHAR>(const_cast<uint8_t *>(key)), 32, 0);
    std::vector<uint8_t> ivCopy(iv, iv + 16);
    ULONG outLen = 0;
    BCryptDecrypt(hkey, reinterpret_cast<PUCHAR>(const_cast<uint8_t *>(data)), static_cast<ULONG>(len), nullptr,
                  ivCopy.data(), 16, nullptr, 0, &outLen, BCRYPT_BLOCK_PADDING);
    std::vector<uint8_t> out(outLen);
    ivCopy.assign(iv, iv + 16);
    BCryptDecrypt(hkey, reinterpret_cast<PUCHAR>(const_cast<uint8_t *>(data)), static_cast<ULONG>(len), nullptr,
                  ivCopy.data(), 16, out.data(), outLen, &outLen, BCRYPT_BLOCK_PADDING);
    BCryptDestroyKey(hkey);
    BCryptCloseAlgorithmProvider(alg, 0);
    out.resize(outLen);
    return out;
}
#endif

std::vector<uint8_t> netfilterEncrypt(const uint8_t sessionKey[32], const uint8_t *plain, size_t len)
{
    uint8_t iv[16]{};
    std::random_device rd;
    for (int i = 13; i < 16; ++i)
        iv[i] = static_cast<uint8_t>(rd());
    std::vector<uint8_t> hmacBuf;
    hmacBuf.insert(hmacBuf.end(), iv + 13, iv + 16);
    hmacBuf.insert(hmacBuf.end(), plain, plain + len);
    auto mac = hmacSha1(sessionKey, 16, hmacBuf.data(), hmacBuf.size());
    std::memcpy(iv, mac.data(), 13);
#if defined(_WIN32)
    auto encIv = aesEncryptEcb(sessionKey, iv);
    uint8_t ivCopy[16];
    std::memcpy(ivCopy, iv, 16);
    auto encBody = aesEncryptCbc(sessionKey, ivCopy, plain, len);
#else
    (void)sessionKey;
    (void)plain;
    (void)len;
    throw std::runtime_error("netfilter encrypt needs Win BCrypt path or OpenSSL port");
#endif
    std::vector<uint8_t> out = encIv;
    out.insert(out.end(), encBody.begin(), encBody.end());
    return out;
}

std::vector<uint8_t> netfilterDecrypt(const uint8_t sessionKey[32], const uint8_t *data, size_t len)
{
    if (len < 16)
        throw std::runtime_error("packet too short");
#if defined(_WIN32)
    auto iv = aesDecryptEcb(sessionKey, data);
    uint8_t ivCopy[16];
    std::memcpy(ivCopy, iv.data(), 16);
    return aesDecryptCbc(sessionKey, ivCopy, data + 16, len - 16);
#else
    (void)sessionKey;
    (void)data;
    (void)len;
    throw std::runtime_error("netfilter decrypt needs Win BCrypt path or OpenSSL port");
#endif
}

std::vector<uint8_t> buildMsgHdr(uint32_t emsg, uint64_t sourceJob = 0xFFFFFFFFFFFFFFFFULL,
                                 uint64_t targetJob = 0xFFFFFFFFFFFFFFFFULL)
{
    std::vector<uint8_t> b;
    writeU32(b, emsg);
    writeU64(b, targetJob);
    writeU64(b, sourceJob);
    return b;
}

} // namespace

uint32_t detectSteamCellId()
{
#if defined(_WIN32)
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Valve\\Steam", 0, KEY_READ, &key) != ERROR_SUCCESS)
        return 0;
    wchar_t pathBuf[MAX_PATH]{};
    DWORD pathBytes = sizeof(pathBuf);
    DWORD type = 0;
    const LONG st =
        RegQueryValueExW(key, L"SteamPath", nullptr, &type, reinterpret_cast<LPBYTE>(pathBuf), &pathBytes);
    RegCloseKey(key);
    if (st != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ))
        return 0;
    char narrow[MAX_PATH * 2]{};
    WideCharToMultiByte(CP_UTF8, 0, pathBuf, -1, narrow, sizeof(narrow), nullptr, nullptr);
    std::string cfg = narrow;
    for (char &c : cfg) {
        if (c == '/')
            c = '\\';
    }
    if (!cfg.empty() && cfg.back() == '\\')
        cfg.pop_back();
    cfg += "\\config\\config.vdf";
    try {
        const std::string text = readFileBytesAsString(cfg);
        const std::string needle = "\"CurrentCellID\"";
        size_t pos = text.find(needle);
        if (pos == std::string::npos)
            return 0;
        pos = text.find('"', pos + needle.size());
        if (pos == std::string::npos)
            return 0;
        const size_t start = pos + 1;
        const size_t end = text.find('"', start);
        if (end == std::string::npos)
            return 0;
        return static_cast<uint32_t>(std::stoul(text.substr(start, end - start)));
    } catch (...) {
        return 0;
    }
#else
    return 0;
#endif
}

SteamSession::SteamSession() = default;

SteamSession::~SteamSession()
{
    disconnect();
}

void SteamSession::disconnect()
{
#if defined(_WIN32)
    if (sock_ != ~static_cast<uintptr_t>(0)) {
        closesocket(static_cast<SOCKET>(sock_));
        sock_ = ~static_cast<uintptr_t>(0);
    }
#else
    if (sock_ >= 0) {
        close(sock_);
        sock_ = -1;
    }
#endif
    connected_ = false;
    encrypted_ = false;
}

std::string SteamSession::pickCmEndpoint()
{
    auto resp = httpGet("https://api.steampowered.com/ISteamDirectory/GetCMListForConnect/v1/?cellid=0&maxcount=40");
    if (resp.status != 200)
        throw std::runtime_error("CM list HTTP " + std::to_string(resp.status));
    const std::string body(resp.body.begin(), resp.body.end());
    // Prefer netfilter TCP endpoints.
    size_t pos = 0;
    while ((pos = body.find("\"type\":\"netfilter\"", pos)) != std::string::npos) {
        const size_t epKey = body.rfind("\"endpoint\":\"", pos);
        if (epKey != std::string::npos && epKey + 12 < pos) {
            const size_t start = epKey + 12;
            const size_t end = body.find('"', start);
            if (end != std::string::npos)
                return body.substr(start, end - start);
        }
        pos += 18;
    }
    throw std::runtime_error("no netfilter CM endpoint");
}

void SteamSession::tcpConnect(const std::string &host, int port)
{
#if defined(_WIN32)
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *res = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0)
        throw std::runtime_error("getaddrinfo CM failed");
    SOCKET s = INVALID_SOCKET;
    for (auto *p = res; p; p = p->ai_next) {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == INVALID_SOCKET)
            continue;
        if (connect(s, p->ai_addr, static_cast<int>(p->ai_addrlen)) == 0)
            break;
        closesocket(s);
        s = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    if (s == INVALID_SOCKET)
        throw std::runtime_error("connect CM failed");
    DWORD timeout = 15000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&timeout), sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char *>(&timeout), sizeof(timeout));
    sock_ = static_cast<uintptr_t>(s);
#else
    (void)host;
    (void)port;
    throw std::runtime_error("CM TCP not ported to non-Windows yet");
#endif
}

bool SteamSession::recvPacket(std::vector<uint8_t> &out, int timeoutMs)
{
#if defined(_WIN32)
    SOCKET s = static_cast<SOCKET>(sock_);
    DWORD t = static_cast<DWORD>(timeoutMs);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&t), sizeof(t));
    uint8_t lenBuf[4];
    int got = 0;
    while (got < 4) {
        const int n = recv(s, reinterpret_cast<char *>(lenBuf + got), 4 - got, 0);
        if (n <= 0)
            return false;
        got += n;
    }
    const uint32_t len = readU32(lenBuf);
    if (len == 0 || len > 8 * 1024 * 1024)
        return false;
    out.resize(len);
    got = 0;
    while (got < static_cast<int>(len)) {
        const int n = recv(s, reinterpret_cast<char *>(out.data() + got), static_cast<int>(len) - got, 0);
        if (n <= 0)
            return false;
        got += n;
    }
    if (encrypted_)
        out = netfilterDecrypt(sessionKey_.data(), out.data(), out.size());
    return true;
#else
    (void)out;
    (void)timeoutMs;
    return false;
#endif
}

void SteamSession::sendRaw(const uint8_t *data, size_t len, bool encrypt)
{
    std::vector<uint8_t> payload(data, data + len);
    if (encrypt && encrypted_)
        payload = netfilterEncrypt(sessionKey_.data(), data, len);
    std::vector<uint8_t> packet;
    writeU32(packet, static_cast<uint32_t>(payload.size()));
    packet.insert(packet.end(), payload.begin(), payload.end());
#if defined(_WIN32)
    SOCKET s = static_cast<SOCKET>(sock_);
    size_t off = 0;
    while (off < packet.size()) {
        const int n = send(s, reinterpret_cast<const char *>(packet.data() + off),
                           static_cast<int>(packet.size() - off), 0);
        if (n <= 0)
            throw std::runtime_error("CM send failed");
        off += static_cast<size_t>(n);
    }
#else
    (void)encrypt;
    throw std::runtime_error("CM send not ported");
#endif
}

void SteamSession::performChannelEncrypt()
{
    std::vector<uint8_t> pkt;
    if (!recvPacket(pkt, 15000) || pkt.size() < 20)
        throw std::runtime_error("no ChannelEncryptRequest");
    const uint32_t msg = readU32(pkt.data()) & ~kProtoMask;
    if (msg != kEMsgChannelEncryptRequest)
        throw std::runtime_error("expected ChannelEncryptRequest");
    // MsgHdr 20 bytes + protocolVersion u32 + universe u32 + challenge
    if (pkt.size() < 28)
        throw std::runtime_error("encrypt request too short");
    const size_t challengeOff = 28;
    std::vector<uint8_t> challenge(pkt.begin() + static_cast<std::ptrdiff_t>(challengeOff), pkt.end());
    if (challenge.size() < 16)
        throw std::runtime_error("missing encrypt challenge");

    sessionKey_.resize(32);
    std::random_device rd;
    for (auto &b : sessionKey_)
        b = static_cast<uint8_t>(rd());

    std::vector<uint8_t> blob = sessionKey_;
    blob.insert(blob.end(), challenge.begin(), challenge.end());
#if defined(_WIN32)
    auto enc = rsaOaepSha1Encrypt(kSteamPublicKey, sizeof(kSteamPublicKey), blob.data(), blob.size());
#else
    throw std::runtime_error("RSA encrypt not ported");
#endif
    auto crc = crc32(enc.data(), enc.size());

    auto resp = buildMsgHdr(kEMsgChannelEncryptResponse);
    writeU32(resp, 1);                 // protocol
    writeU32(resp, static_cast<uint32_t>(enc.size())); // keySize
    resp.insert(resp.end(), enc.begin(), enc.end());
    writeU32(resp, crc);
    writeU32(resp, 0);
    sendRaw(resp.data(), resp.size(), false);

    std::vector<uint8_t> resultPkt;
    if (!recvPacket(resultPkt, 15000) || resultPkt.size() < 24)
        throw std::runtime_error("no ChannelEncryptResult");
    const uint32_t rmsg = readU32(resultPkt.data()) & ~kProtoMask;
    if (rmsg != kEMsgChannelEncryptResult)
        throw std::runtime_error("expected ChannelEncryptResult");
    const uint32_t eresult = readU32(resultPkt.data() + 20);
    if (eresult != 1) // OK
        throw std::runtime_error("channel encrypt failed: " + std::to_string(eresult));
    encrypted_ = true;
}

void SteamSession::sendLogonAnonymous()
{
    // CMsgClientLogon protobuf body
    std::vector<uint8_t> body;
    writeProtoU32(body, 1, 65581); // protocol_version (SteamKit CurrentProtocol ~65580+)
    writeProtoU32(body, 2, 0);     // deprecated obfuscated private ip
    writeProtoU32(body, 3, cellId_);
    writeProtoU32(body, 7, 16); // client_os_type Windows 10-ish
    writeProtoString(body, 8, "english");

    // MsgHdrProtoBuf: emsg|mask, headerLength, CMsgProtoBufHeader, body
    std::vector<uint8_t> hdrProto;
    writeProtoU64(hdrProto, 1, 0xFFFFFFFFFFFFFFFFULL); // client_sessionid later
    writeProtoU64(hdrProto, 2, 0);                     // steamid
    writeProtoU64(hdrProto, 3, jobId_++);              // jobid_source
    // jobid_target = -1 default

    std::vector<uint8_t> packet;
    writeU32(packet, kEMsgClientLogon | kProtoMask);
    writeU32(packet, static_cast<uint32_t>(hdrProto.size()));
    packet.insert(packet.end(), hdrProto.begin(), hdrProto.end());
    packet.insert(packet.end(), body.begin(), body.end());
    sendRaw(packet.data(), packet.size(), true);
}

void SteamSession::pumpUntil(uint32_t wantMsg, std::vector<uint8_t> *payloadOut, int timeoutMs)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        std::vector<uint8_t> pkt;
        if (!recvPacket(pkt, 2000))
            continue;
        if (pkt.size() < 4)
            continue;
        uint32_t msg = readU32(pkt.data());
        const bool proto = (msg & kProtoMask) != 0;
        msg &= ~kProtoMask;
        if (msg == kEMsgMulti) {
            // skip for now - may contain logon response; naive: ignore nested
            continue;
        }
        if (msg == wantMsg) {
            if (payloadOut)
                *payloadOut = pkt;
            return;
        }
        (void)proto;
    }
    throw std::runtime_error("timeout waiting for steam msg " + std::to_string(wantMsg));
}

void SteamSession::ensureConnected(uint32_t cellId)
{
    if (connected_)
        return;
    cellId_ = cellId;
    const auto ep = pickCmEndpoint();
    const auto colon = ep.rfind(':');
    if (colon == std::string::npos)
        throw std::runtime_error("bad CM endpoint");
    tcpConnect(ep.substr(0, colon), std::stoi(ep.substr(colon + 1)));
    performChannelEncrypt();
    sendLogonAnonymous();
    std::vector<uint8_t> logonResp;
    // Multi messages often wrap logon - try a few packets
    for (int i = 0; i < 20; ++i) {
        std::vector<uint8_t> pkt;
        if (!recvPacket(pkt, 5000))
            continue;
        if (pkt.size() < 4)
            continue;
        uint32_t msg = readU32(pkt.data()) & ~kProtoMask;
        if (msg == kEMsgClientLogOnResponse || msg == kEMsgMulti) {
            connected_ = true;
            // Best-effort: treat any response after logon as success if encrypt worked.
            // Full Multi unpack can be refined later.
            if (msg == kEMsgClientLogOnResponse)
                logonResp = pkt;
            if (msg == kEMsgMulti || !logonResp.empty()) {
                connected_ = true;
                return;
            }
        }
    }
    connected_ = true; // allow CDN attempts even if logon parsing is soft
}

void SteamSession::connectAnonymous(uint32_t cellId)
{
    std::lock_guard lock(mu_);
    disconnect();
    ensureConnected(cellId);
}

std::vector<CdnServer> SteamSession::contentServers(uint32_t cellId, uint32_t maxServers)
{
    if (cellId == 0)
        cellId = detectSteamCellId();
    if (maxServers == 0)
        maxServers = 40;

    // WebAPI protobuf (no CM required).
    std::vector<uint8_t> req;
    writeProtoU32(req, 1, cellId);
    writeProtoU32(req, 2, maxServers);
    const std::string b64 = b64encode(req.data(), req.size());
    std::string enc;
    for (char c : b64) {
        if (c == '+')
            enc += "%2B";
        else if (c == '/')
            enc += "%2F";
        else if (c == '=')
            enc += "%3D";
        else
            enc.push_back(c);
    }
    const std::string url =
        "https://api.steampowered.com/IContentServerDirectoryService/GetServersForSteamPipe/v1?input_protobuf_encoded="
        + enc;
    auto resp = httpGet(url);
    if (resp.status != 200)
        throw std::runtime_error("content server directory HTTP " + std::to_string(resp.status));

    std::vector<CdnServer> out;
    const uint8_t *p = resp.body.data();
    const uint8_t *end = p + resp.body.size();
    auto readVar = [&]() -> uint64_t {
        uint64_t v = 0;
        int s = 0;
        for (;;) {
            if (p >= end)
                throw std::runtime_error("cdn dir truncated");
            uint8_t b = *p++;
            v |= static_cast<uint64_t>(b & 0x7f) << s;
            if ((b & 0x80) == 0)
                break;
            s += 7;
        }
        return v;
    };
    while (p < end) {
        const uint64_t tag = readVar();
        const uint32_t field = static_cast<uint32_t>(tag >> 3);
        const uint32_t wire = static_cast<uint32_t>(tag & 7);
        if (field == 1 && wire == 2) {
            const auto n = static_cast<size_t>(readVar());
            if (p + n > end)
                break;
            const uint8_t *sp = p;
            const uint8_t *send = p + n;
            p += n;
            CdnServer srv;
            srv.https = true;
            srv.port = 443;
            while (sp < send) {
                auto readVar2 = [&]() -> uint64_t {
                    uint64_t v = 0;
                    int s = 0;
                    for (;;) {
                        if (sp >= send)
                            return 0;
                        uint8_t b = *sp++;
                        v |= static_cast<uint64_t>(b & 0x7f) << s;
                        if ((b & 0x80) == 0)
                            break;
                        s += 7;
                    }
                    return v;
                };
                const uint64_t t2 = readVar2();
                const uint32_t f2 = static_cast<uint32_t>(t2 >> 3);
                const uint32_t w2 = static_cast<uint32_t>(t2 & 7);
                if (w2 == 2) {
                    const auto ln = static_cast<size_t>(readVar2());
                    std::string s(reinterpret_cast<const char *>(sp), ln);
                    sp += ln;
                    if (f2 == 1)
                        srv.type = s;
                    else if (f2 == 8)
                        srv.host = s;
                    else if (f2 == 9)
                        srv.vhost = s;
                    else if (f2 == 12) {
                        if (s == "mandatory") {
                            srv.https = true;
                            srv.port = 443;
                        } else if (s == "disabled") {
                            srv.https = false;
                            srv.port = 80;
                        }
                    }
                } else if (w2 == 0) {
                    const uint64_t v = readVar2();
                    if (f2 == 2)
                        /* source_id */ (void)v;
                    else if (f2 == 3)
                        srv.cellId = static_cast<int32_t>(v);
                    else if (f2 == 4)
                        srv.load = static_cast<int32_t>(v);
                    else if (f2 == 6)
                        /* num_entries */ (void)v;
                    else if (f2 == 7)
                        srv.steamChinaOnly = v != 0;
                    else if (f2 == 10)
                        /* use_as_proxy */ (void)v;
                    else if (f2 == 15)
                        /* priority_class */ (void)v;
                } else if (w2 == 5) {
                    if (sp + 4 > send)
                        break;
                    uint32_t bits = 0;
                    std::memcpy(&bits, sp, 4);
                    sp += 4;
                    if (f2 == 5) {
                        float f = 0.f;
                        std::memcpy(&f, &bits, 4);
                        srv.weightedLoad = f;
                    }
                } else if (w2 == 1) {
                    sp += 8;
                } else {
                    break;
                }
            }
            if (srv.vhost.empty())
                srv.vhost = srv.host;
            if (!srv.host.empty() && !srv.steamChinaOnly)
                out.push_back(std::move(srv));
        } else if (wire == 2) {
            const auto n = static_cast<size_t>(readVar());
            p += n;
        } else if (wire == 0) {
            (void)readVar();
        } else if (wire == 5) {
            p += 4;
        } else if (wire == 1) {
            p += 8;
        } else {
            break;
        }
    }
    if (out.empty())
        throw std::runtime_error("no CDN servers parsed");

    // Prefer CDN caches near requested cell with lowest weighted load.
    std::sort(out.begin(), out.end(), [&](const CdnServer &a, const CdnServer &b) {
        auto rank = [&](const CdnServer &s) {
            int score = 0;
            if (s.type == "CDN" || s.type == "SteamCache")
                score += 1000;
            else if (s.type == "CDNCache")
                score += 900;
            if (cellId != 0 && s.cellId == static_cast<int32_t>(cellId))
                score += 800;
            else if (cellId != 0 && s.cellId >= 0)
                score += std::max(0, 300 - std::abs(s.cellId - static_cast<int32_t>(cellId)));
            else if (s.cellId < 0)
                score -= 400; // unknown / global anycast - often slower than local cell
            score -= static_cast<int>(s.weightedLoad * 10.f);
            score -= s.load;
            return score;
        };
        const int ra = rank(a);
        const int rb = rank(b);
        if (ra != rb)
            return ra > rb;
        if (a.weightedLoad != b.weightedLoad)
            return a.weightedLoad < b.weightedLoad;
        return a.host < b.host;
    });

    // If we have same-cell hosts, drop everything else - remote SteamCache kills RTT.
    if (cellId != 0) {
        std::vector<CdnServer> sameCell;
        for (const auto &s : out) {
            if (s.cellId == static_cast<int32_t>(cellId))
                sameCell.push_back(s);
        }
        if (!sameCell.empty())
            out.swap(sameCell);
    }

    // Tight nearby set - engine pins workers to the top few.
    constexpr size_t kKeep = 6;
    if (out.size() > kKeep)
        out.resize(kKeep);
    return out;
}

std::string SteamSession::cdnAuthToken(uint32_t appId, uint32_t depotId, const std::string &host)
{
    std::lock_guard lock(mu_);
    ensureConnected(cellId_);

    // CContentServerDirectory_GetCDNAuthToken_Request
    std::vector<uint8_t> body;
    writeProtoU32(body, 1, depotId);
    writeProtoString(body, 2, host);
    writeProtoU32(body, 3, appId);

    std::vector<uint8_t> hdr;
    writeProtoU32(hdr, 1, sessionId_);
    writeProtoU64(hdr, 2, steamId_);
    const uint64_t job = jobId_++;
    writeProtoU64(hdr, 3, job); // jobid_source
    writeProtoString(hdr, 10, "ContentServerDirectory.GetCDNAuthToken#1");
    writeProtoU32(hdr, 11, 1); // realm

    std::vector<uint8_t> packet;
    writeU32(packet, kEMsgServiceMethodCallFromClient | kProtoMask);
    writeU32(packet, static_cast<uint32_t>(hdr.size()));
    packet.insert(packet.end(), hdr.begin(), hdr.end());
    packet.insert(packet.end(), body.begin(), body.end());
    sendRaw(packet.data(), packet.size(), true);

    // Soft wait for ServiceMethodResponse and extract token string field.
    for (int i = 0; i < 30; ++i) {
        std::vector<uint8_t> pkt;
        if (!recvPacket(pkt, 3000))
            continue;
        if (pkt.size() < 8)
            continue;
        uint32_t msg = readU32(pkt.data());
        const bool proto = (msg & kProtoMask) != 0;
        msg &= ~kProtoMask;
        if (!proto)
            continue;
        if (msg != kEMsgServiceMethodResponse && msg != kEMsgMulti)
            continue;
        // Heuristic: find query-looking token "?...=" in packet bytes.
        const std::string s(pkt.begin(), pkt.end());
        const size_t q = s.find('?');
        if (q != std::string::npos) {
            size_t end = q;
            while (end < s.size() && static_cast<unsigned char>(s[end]) >= 32 && s[end] != '\0')
                ++end;
            return s.substr(q, end - q);
        }
    }
    return {};
}

std::string buildChunkUrl(const CdnServer &srv, uint32_t depotId, const std::string &chunkShaHex,
                          const std::string &authQuery)
{
    const char *scheme = srv.https ? "https" : "http";
    std::string url = std::string(scheme) + "://" + (srv.vhost.empty() ? srv.host : srv.vhost);
    if ((srv.https && srv.port != 443) || (!srv.https && srv.port != 80))
        url += ":" + std::to_string(srv.port);
    url += "/depot/" + std::to_string(depotId) + "/chunk/" + chunkShaHex;
    if (!authQuery.empty()) {
        if (authQuery[0] == '?')
            url += authQuery;
        else
            url += "?" + authQuery;
    }
    return url;
}

} // namespace depotkit
