#include "http.hpp"

#include <stdexcept>
#include <string>

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

HttpResponse winHttpGet(const std::string &url, int timeoutMs)
{
    HttpResponse resp;
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    uc.dwSchemeLength = static_cast<DWORD>(-1);
    uc.dwHostNameLength = static_cast<DWORD>(-1);
    uc.dwUrlPathLength = static_cast<DWORD>(-1);
    uc.dwExtraInfoLength = static_cast<DWORD>(-1);
    auto wurl = toWide(url);
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc)) {
        resp.error = "WinHttpCrackUrl failed";
        return resp;
    }
    std::wstring host(uc.lpszHostName, uc.dwHostNameLength);
    std::wstring path(uc.lpszUrlPath, uc.dwUrlPathLength);
    if (uc.dwExtraInfoLength)
        path.append(uc.lpszExtraInfo, uc.dwExtraInfoLength);

    HINTERNET session = WinHttpOpen(L"depotkit/0.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        resp.error = "WinHttpOpen failed";
        return resp;
    }
    WinHttpSetTimeouts(session, timeoutMs, timeoutMs, timeoutMs, timeoutMs);
    const INTERNET_PORT port = uc.nPort ? uc.nPort
                                        : (uc.nScheme == INTERNET_SCHEME_HTTPS ? INTERNET_DEFAULT_HTTPS_PORT
                                                                              : INTERNET_DEFAULT_HTTP_PORT);
    HINTERNET conn = WinHttpConnect(session, host.c_str(), port, 0);
    if (!conn) {
        WinHttpCloseHandle(session);
        resp.error = "WinHttpConnect failed";
        return resp;
    }
    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET req =
        WinHttpOpenRequest(conn, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER,
                           WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!req) {
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        resp.error = "WinHttpOpenRequest failed";
        return resp;
    }
    if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
        || !WinHttpReceiveResponse(req, nullptr)) {
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        resp.error = "WinHttp request failed";
        return resp;
    }
    DWORD status = 0;
    DWORD statusSize = sizeof(status);
    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX);
    resp.status = static_cast<int>(status);
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(req, &avail))
            break;
        if (avail == 0)
            break;
        const size_t off = resp.body.size();
        resp.body.resize(off + avail);
        DWORD read = 0;
        if (!WinHttpReadData(req, resp.body.data() + off, avail, &read)) {
            resp.error = "WinHttpReadData failed";
            break;
        }
        resp.body.resize(off + read);
    }
    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
    return resp;
}

} // namespace

HttpResponse httpGet(const std::string &url, int timeoutMs)
{
    return winHttpGet(url, timeoutMs);
}

HttpResponse httpGetJsonApi(const std::string &url, int timeoutMs)
{
    return winHttpGet(url, timeoutMs);
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

HttpResponse curlGet(const std::string &url, int timeoutMs)
{
    HttpResponse resp;
    CURL *curl = curl_easy_init();
    if (!curl) {
        resp.error = "curl_easy_init failed";
        return resp;
    }
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(timeoutMs));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp.body);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "depotkit/0.1");
    const CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        resp.error = curl_easy_strerror(rc);
    } else {
        long code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        resp.status = static_cast<int>(code);
    }
    curl_easy_cleanup(curl);
    return resp;
}

} // namespace

HttpResponse httpGet(const std::string &url, int timeoutMs)
{
    return curlGet(url, timeoutMs);
}

HttpResponse httpGetJsonApi(const std::string &url, int timeoutMs)
{
    return curlGet(url, timeoutMs);
}

} // namespace depotkit
#endif
