#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace depotkit {

struct HttpResponse {
    int status = 0;
    std::vector<uint8_t> body;
    std::string error;
};

HttpResponse httpGet(const std::string &url, int timeoutMs = 60000);
HttpResponse httpGetJsonApi(const std::string &url, int timeoutMs = 30000);

} // namespace depotkit
