#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace depotkit {

struct CdnServer {
    std::string host;
    std::string vhost;
    int port = 443;
    bool https = true;
    std::string type;
    int32_t cellId = -1;
    int32_t load = 0;
    float weightedLoad = 0.f;
    bool steamChinaOnly = false;
};

/** Read Steam CurrentCellID from local Steam install (0 if unknown). */
uint32_t detectSteamCellId();

class SteamSession {
public:
    SteamSession();
    ~SteamSession();

    SteamSession(const SteamSession &) = delete;
    SteamSession &operator=(const SteamSession &) = delete;

    void connectAnonymous(uint32_t cellId = 0);
    void disconnect();

    std::vector<CdnServer> contentServers(uint32_t cellId = 0, uint32_t maxServers = 20);
    std::string cdnAuthToken(uint32_t appId, uint32_t depotId, const std::string &host);

    bool connected() const { return connected_; }

private:
    void ensureConnected(uint32_t cellId);
    std::string pickCmEndpoint();
    void tcpConnect(const std::string &host, int port);
    void performChannelEncrypt();
    void sendLogonAnonymous();
    void pumpUntil(uint32_t wantMsg, std::vector<uint8_t> *payloadOut, int timeoutMs);
    void sendRaw(const uint8_t *data, size_t len, bool encrypt);
    bool recvPacket(std::vector<uint8_t> &out, int timeoutMs);

    bool connected_ = false;
    bool encrypted_ = false;
    uint32_t cellId_ = 0;
    uint64_t steamId_ = 0;
    uint32_t sessionId_ = 0;
    std::vector<uint8_t> sessionKey_; // 32 bytes AES
    uint64_t jobId_ = 1;

#if defined(_WIN32)
    uintptr_t sock_ = ~static_cast<uintptr_t>(0);
#else
    int sock_ = -1;
#endif
    std::mutex mu_;
};

std::string buildChunkUrl(const CdnServer &srv, uint32_t depotId, const std::string &chunkShaHex,
                          const std::string &authQuery);

} // namespace depotkit
