#include "http.hpp"

#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

namespace depotkit {
namespace {

std::wstring toWide(const std::string &s)
{
    if (s.empty())
        return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring out(static_cast<size_t>(n ? n - 1 : 0), L'\0');
    if (n > 1)
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), n);
    return out;
}

struct ParsedUrl {
    std::wstring host;
    std::wstring path;
    INTERNET_PORT port = 0;
    bool https = true;
    std::string hostKey; // host:port for pooling
};

bool parseUrl(const std::string &url, ParsedUrl &out, std::string &error)
{
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    uc.dwSchemeLength = static_cast<DWORD>(-1);
    uc.dwHostNameLength = static_cast<DWORD>(-1);
    uc.dwUrlPathLength = static_cast<DWORD>(-1);
    uc.dwExtraInfoLength = static_cast<DWORD>(-1);
    auto wurl = toWide(url);
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc)) {
        error = "WinHttpCrackUrl failed";
        return false;
    }
    out.host.assign(uc.lpszHostName, uc.dwHostNameLength);
    out.path.assign(uc.lpszUrlPath, uc.dwUrlPathLength);
    if (uc.dwExtraInfoLength)
        out.path.append(uc.lpszExtraInfo, uc.dwExtraInfoLength);
    out.https = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    out.port = uc.nPort ? uc.nPort
                        : (out.https ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT);
    out.hostKey = std::string(out.host.begin(), out.host.end()) + ":" + std::to_string(out.port);
    return true;
}

HttpResponse winHttpGetOnce(const std::string &url, int timeoutMs)
{
    HttpSession session(4);
    return session.get(url, timeoutMs);
}

} // namespace

struct HttpSession::Impl {
    HINTERNET session = nullptr;
    uint32_t maxPerHost = 64;
    std::mutex mu;
    std::unordered_map<std::string, std::vector<HINTERNET>> idle;

    explicit Impl(uint32_t maxConnectionsPerHost) : maxPerHost(maxConnectionsPerHost ? maxConnectionsPerHost : 64)
    {
        session = WinHttpOpen(L"depotkit/0.2", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
                              WINHTTP_NO_PROXY_BYPASS, 0);
        if (!session)
            return;
        // WinHTTP defaults to 2 connections/server - that caps throughput hard.
        DWORD maxConn = maxPerHost;
        WinHttpSetOption(session, WINHTTP_OPTION_MAX_CONNS_PER_SERVER, &maxConn, sizeof(maxConn));
        WinHttpSetOption(session, WINHTTP_OPTION_MAX_CONNS_PER_1_0_SERVER, &maxConn, sizeof(maxConn));
        WinHttpSetTimeouts(session, 15000, 15000, 30000, 60000);
#if defined(WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL)
        {
            DWORD protocols = WINHTTP_PROTOCOL_FLAG_HTTP2;
            WinHttpSetOption(session, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &protocols, sizeof(protocols));
        }
#endif
    }

    ~Impl()
    {
        std::lock_guard lock(mu);
        for (auto &kv : idle) {
            for (HINTERNET c : kv.second) {
                if (c)
                    WinHttpCloseHandle(c);
            }
        }
        idle.clear();
        if (session)
            WinHttpCloseHandle(session);
        session = nullptr;
    }

    HINTERNET borrow(const ParsedUrl &u)
    {
        {
            std::lock_guard lock(mu);
            auto &pool = idle[u.hostKey];
            if (!pool.empty()) {
                HINTERNET c = pool.back();
                pool.pop_back();
                return c;
            }
        }
        if (!session)
            return nullptr;
        return WinHttpConnect(session, u.host.c_str(), u.port, 0);
    }

    void release(const ParsedUrl &u, HINTERNET conn, bool keep)
    {
        if (!conn)
            return;
        if (!keep) {
            WinHttpCloseHandle(conn);
            return;
        }
        std::lock_guard lock(mu);
        auto &pool = idle[u.hostKey];
        if (pool.size() < maxPerHost)
            pool.push_back(conn);
        else
            WinHttpCloseHandle(conn);
    }
};

HttpSession::HttpSession(uint32_t maxConnectionsPerHost) : impl_(std::make_unique<Impl>(maxConnectionsPerHost)) {}

HttpSession::~HttpSession() = default;

HttpResponse HttpSession::get(const std::string &url, int timeoutMs)
{
    HttpResponse resp;
    (void)timeoutMs;
    if (!impl_ || !impl_->session) {
        resp.error = "WinHttpOpen failed";
        return resp;
    }

    ParsedUrl u;
    if (!parseUrl(url, u, resp.error))
        return resp;

    HINTERNET conn = impl_->borrow(u);
    if (!conn) {
        resp.error = "WinHttpConnect failed";
        return resp;
    }

    const DWORD flags = u.https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET req = WinHttpOpenRequest(conn, L"GET", u.path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!req) {
        impl_->release(u, conn, false);
        resp.error = "WinHttpOpenRequest failed";
        return resp;
    }

    // Prefer keep-alive explicitly.
    WinHttpAddRequestHeaders(req, L"Connection: keep-alive\r\n", static_cast<DWORD>(-1),
                             WINHTTP_ADDREQ_FLAG_ADD);

    bool ok = WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
              && WinHttpReceiveResponse(req, nullptr);
    if (!ok) {
        WinHttpCloseHandle(req);
        impl_->release(u, conn, false);
        resp.error = "WinHttp request failed";
        return resp;
    }

    DWORD status = 0;
    DWORD statusSize = sizeof(status);
    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX);
    resp.status = static_cast<int>(status);

    DWORD contentLen = 0;
    DWORD contentLenSize = sizeof(contentLen);
    if (WinHttpQueryHeaders(req, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &contentLen, &contentLenSize,
                            WINHTTP_NO_HEADER_INDEX)
        && contentLen > 0) {
        resp.body.reserve(contentLen);
    }

    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(req, &avail)) {
            resp.error = "WinHttpQueryDataAvailable failed";
            break;
        }
        if (avail == 0)
            break;
        const size_t off = resp.body.size();
        resp.body.resize(off + avail);
        DWORD read = 0;
        if (!WinHttpReadData(req, resp.body.data() + off, avail, &read)) {
            resp.error = "WinHttpReadData failed";
            resp.body.resize(off);
            break;
        }
        resp.body.resize(off + read);
        if (read == 0)
            break;
    }

    WinHttpCloseHandle(req);
    const bool keep = resp.error.empty() && (resp.status == 200 || resp.status == 401 || resp.status == 403
                                             || resp.status == 404);
    impl_->release(u, conn, keep);
    return resp;
}

HttpResponse httpGet(const std::string &url, int timeoutMs)
{
    return winHttpGetOnce(url, timeoutMs);
}

HttpResponse httpGetJsonApi(const std::string &url, int timeoutMs)
{
    return winHttpGetOnce(url, timeoutMs);
}

} // namespace depotkit

#else
#include <curl/curl.h>

namespace depotkit {
namespace {

size_t writeCb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    auto *out = static_cast<std::vector<uint8_t> *>(userdata);
    const size_t n = size * nmemb;
    out->insert(out->end(), reinterpret_cast<uint8_t *>(ptr), reinterpret_cast<uint8_t *>(ptr) + n);
    return n;
}

struct CurlSlot {
    CURL *easy = nullptr;
    CurlSlot()
    {
        easy = curl_easy_init();
        if (!easy)
            return;
        curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(easy, CURLOPT_USERAGENT, "depotkit/0.2");
        curl_easy_setopt(easy, CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(easy, CURLOPT_TCP_KEEPIDLE, 30L);
        curl_easy_setopt(easy, CURLOPT_TCP_KEEPINTVL, 15L);
        curl_easy_setopt(easy, CURLOPT_ACCEPT_ENCODING, "");
        curl_easy_setopt(easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
    }
    ~CurlSlot()
    {
        if (easy)
            curl_easy_cleanup(easy);
    }
};

thread_local CurlSlot tCurl;

HttpResponse curlGetReuse(const std::string &url, int timeoutMs)
{
    HttpResponse resp;
    CURL *curl = tCurl.easy;
    if (!curl) {
        resp.error = "curl_easy_init failed";
        return resp;
    }
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(timeoutMs));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp.body);
    const CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        resp.error = curl_easy_strerror(rc);
    } else {
        long code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        resp.status = static_cast<int>(code);
    }
    return resp;
}

} // namespace

struct HttpSession::Impl {
    uint32_t maxPerHost = 64;
    explicit Impl(uint32_t maxConnectionsPerHost)
        : maxPerHost(maxConnectionsPerHost ? maxConnectionsPerHost : 64)
    {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }
};

HttpSession::HttpSession(uint32_t maxConnectionsPerHost) : impl_(std::make_unique<Impl>(maxConnectionsPerHost)) {}

HttpSession::~HttpSession() = default;

HttpResponse HttpSession::get(const std::string &url, int timeoutMs)
{
    (void)impl_;
    return curlGetReuse(url, timeoutMs);
}

HttpResponse httpGet(const std::string &url, int timeoutMs)
{
    return curlGetReuse(url, timeoutMs);
}

HttpResponse httpGetJsonApi(const std::string &url, int timeoutMs)
{
    return curlGetReuse(url, timeoutMs);
}

} // namespace depotkit
#endif
