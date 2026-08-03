#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace depotkit {

struct HttpResponse {
    int status = 0;
    std::vector<uint8_t> body;
    std::string error;
};

/** Process-wide keep-alive client. Share one instance across download workers. */
class HttpSession {
public:
    explicit HttpSession(uint32_t maxConnectionsPerHost = 64);
    ~HttpSession();

    HttpSession(const HttpSession &) = delete;
    HttpSession &operator=(const HttpSession &) = delete;

    HttpResponse get(const std::string &url, int timeoutMs = 30000);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/** One-shot GET (CM / directory). Prefer HttpSession for bulk CDN traffic. */
HttpResponse httpGet(const std::string &url, int timeoutMs = 60000);
HttpResponse httpGetJsonApi(const std::string &url, int timeoutMs = 30000);

} // namespace depotkit
