// AuthentikAPI.cpp
// HTTP client for Authentik API communication with session management

#include "AuthentikAPI.h"
#include "Logger.h"
#include <sstream>

#pragma comment(lib, "Winhttp.lib")

// Constructor
AuthentikAPI::AuthentikAPI() :
    _serverUrl(L"authentik.test.local"),
    _serverPort(443),
    _flowSlug(L"windows-passwordless"),
    _useHttps(true),
    _ignoreCertErrors(true),
    _domain(L"TEST"),
    _domainFQDN(L"test.local")
{
    LOG("AuthentikAPI::Constructor");
    _LoadConfiguration();
}

// Destructor
AuthentikAPI::~AuthentikAPI()
{
    LOG("AuthentikAPI::Destructor");
}

// Reset session for new authentication
void AuthentikAPI::ResetSession()
{
    LOG("ResetSession");
    _currentUsername.clear();
    _cookies.clear();
    _csrfToken.clear();
    _flowExecutorUrl.clear();
}

// Step 1: Submit username
AuthentikResponse AuthentikAPI::SubmitUsername(const std::wstring& username)
{
    LOG("SubmitUsername: %S", username.c_str());
    
    AuthentikResponse response;
    _currentUsername = username;
    
    // Build request URL - flow executor endpoint
    std::wstring url = L"/api/v3/flows/executor/" + _flowSlug + L"/";
    
    // Build JSON payload for identification stage
    std::wstring payload = L"{\"uid_field\":\"" + username + L"\"}";
    
    // Make HTTP request
    std::wstring responseBody;
    DWORD statusCode = 0;
    HRESULT hr = _MakeHttpRequest(L"POST", url, payload, responseBody, statusCode);
    
    if (FAILED(hr))
    {
        LOG("SubmitUsername request failed: 0x%08x", hr);
        response.status = AuthStatus::ERROR_NETWORK;
        response.message = L"Failed to connect to authentication server";
        return response;
    }
    
    LOG("SubmitUsername response: status=%d, length=%d", statusCode, responseBody.length());
    
    // Parse response
    response = _ParseAuthentikResponse(responseBody);
    response.rawResponse = responseBody;
    
    return response;
}

// Step 2: Submit OTP
AuthentikResponse AuthentikAPI::SubmitOTP(const std::wstring& otp)
{
    LOG("SubmitOTP");
    
    AuthentikResponse response;
    
    // Build request URL
    std::wstring url = L"/api/v3/flows/executor/" + _flowSlug + L"/";
    
    // Build JSON payload for OTP stage
    std::wstring payload = L"{\"code\":\"" + otp + L"\"}";
    
    // Make HTTP request (cookies maintain session)
    std::wstring responseBody;
    DWORD statusCode = 0;
    HRESULT hr = _MakeHttpRequest(L"POST", url, payload, responseBody, statusCode);
    
    if (FAILED(hr))
    {
        LOG("SubmitOTP request failed: 0x%08x", hr);
        response.status = AuthStatus::ERROR_NETWORK;
        response.message = L"Failed to connect to authentication server";
        return response;
    }
    
    LOG("SubmitOTP response: status=%d, length=%d", statusCode, responseBody.length());
    
    // Parse response
    response = _ParseAuthentikResponse(responseBody);
    response.rawResponse = responseBody;
    
    // If successful, populate certificate info
    if (response.status == AuthStatus::SUCCESS)
    {
        response.username = _currentUsername;
        response.domain = _domain;
        response.upn = _currentUsername + L"@" + _domainFQDN;
    }
    
    return response;
}

// Load configuration from registry
void AuthentikAPI::_LoadConfiguration()
{
    LOG("Loading configuration from registry");

    HKEY hKey;
    LONG result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\AuthentikPasswordlessCP",
        0,
        KEY_READ,
        &hKey);

    if (result == ERROR_SUCCESS)
    {
        WCHAR buffer[256];
        DWORD bufferSize;
        DWORD dwValue;

        // Read server URL
        bufferSize = sizeof(buffer);
        result = RegQueryValueExW(hKey, L"ServerUrl", NULL, NULL, (LPBYTE)buffer, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _serverUrl = buffer;
            LOG("ServerUrl: %S", _serverUrl.c_str());
        }

        // Read server port
        bufferSize = sizeof(DWORD);
        result = RegQueryValueExW(hKey, L"ServerPort", NULL, NULL, (LPBYTE)&dwValue, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _serverPort = (INTERNET_PORT)dwValue;
            LOG("ServerPort: %d", _serverPort);
        }

        // Read flow slug
        bufferSize = sizeof(buffer);
        result = RegQueryValueExW(hKey, L"FlowSlug", NULL, NULL, (LPBYTE)buffer, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _flowSlug = buffer;
            LOG("FlowSlug: %S", _flowSlug.c_str());
        }

        // Read HTTPS flag
        bufferSize = sizeof(DWORD);
        result = RegQueryValueExW(hKey, L"UseHttps", NULL, NULL, (LPBYTE)&dwValue, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _useHttps = (dwValue != 0);
            LOG("UseHttps: %d", _useHttps);
        }

        // Read ignore cert errors flag
        bufferSize = sizeof(DWORD);
        result = RegQueryValueExW(hKey, L"IgnoreCertErrors", NULL, NULL, (LPBYTE)&dwValue, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _ignoreCertErrors = (dwValue != 0);
            LOG("IgnoreCertErrors: %d", _ignoreCertErrors);
        }

        // Read domain
        bufferSize = sizeof(buffer);
        result = RegQueryValueExW(hKey, L"Domain", NULL, NULL, (LPBYTE)buffer, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _domain = buffer;
            LOG("Domain: %S", _domain.c_str());
        }

        // Read domain FQDN
        bufferSize = sizeof(buffer);
        result = RegQueryValueExW(hKey, L"DomainFQDN", NULL, NULL, (LPBYTE)buffer, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _domainFQDN = buffer;
            LOG("DomainFQDN: %S", _domainFQDN.c_str());
        }

        RegCloseKey(hKey);
    }
    else
    {
        LOG("Failed to open registry key: %d (using defaults)", result);
    }
}

// Make HTTP request
HRESULT AuthentikAPI::_MakeHttpRequest(
    const std::wstring& method,
    const std::wstring& url,
    const std::wstring& payload,
    std::wstring& responseBody,
    DWORD& statusCode)
{
    LOG("HTTP %S %S", method.c_str(), url.c_str());

    HRESULT hr = E_FAIL;
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;

    // Initialize WinHTTP
    hSession = WinHttpOpen(
        L"AuthentikCredentialProvider/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!hSession)
    {
        LOG("WinHttpOpen failed: %d", GetLastError());
        return E_FAIL;
    }

    // Connect to server
    hConnect = WinHttpConnect(
        hSession,
        _serverUrl.c_str(),
        _serverPort,
        0);

    if (!hConnect)
    {
        LOG("WinHttpConnect failed: %d", GetLastError());
        WinHttpCloseHandle(hSession);
        return E_FAIL;
    }

    // Create request
    DWORD dwFlags = _useHttps ? WINHTTP_FLAG_SECURE : 0;
    
    hRequest = WinHttpOpenRequest(
        hConnect,
        method.c_str(),
        url.c_str(),
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        dwFlags);

    if (!hRequest)
    {
        LOG("WinHttpOpenRequest failed: %d", GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return E_FAIL;
    }

    // Configure SSL options
    if (_useHttps && _ignoreCertErrors)
    {
        DWORD dwSecFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        
        WinHttpSetOption(
            hRequest,
            WINHTTP_OPTION_SECURITY_FLAGS,
            &dwSecFlags,
            sizeof(dwSecFlags));
        
        LOG("WARNING: SSL certificate validation disabled");
    }

    // Set headers
    std::wstring headers = L"Content-Type: application/json\r\n";
    headers += L"Accept: application/json\r\n";
    
    WinHttpAddRequestHeaders(
        hRequest,
        headers.c_str(),
        (DWORD)-1,
        WINHTTP_ADDREQ_FLAG_ADD);

    // Add cookies from previous requests
    _AddCookies(hRequest);

    // Convert payload to UTF-8
    std::string payloadUtf8;
    if (!payload.empty())
    {
        int size = WideCharToMultiByte(CP_UTF8, 0, payload.c_str(), -1, NULL, 0, NULL, NULL);
        if (size > 0)
        {
            std::vector<char> buffer(size);
            WideCharToMultiByte(CP_UTF8, 0, payload.c_str(), -1, &buffer[0], size, NULL, NULL);
            payloadUtf8 = &buffer[0];
        }
    }

    // Send request
    BOOL bResult = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        payloadUtf8.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)payloadUtf8.c_str(),
        payloadUtf8.empty() ? 0 : (DWORD)payloadUtf8.length(),
        payloadUtf8.empty() ? 0 : (DWORD)payloadUtf8.length(),
        0);

    if (!bResult)
    {
        LOG("WinHttpSendRequest failed: %d", GetLastError());
        goto cleanup;
    }

    // Receive response
    bResult = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResult)
    {
        LOG("WinHttpReceiveResponse failed: %d", GetLastError());
        goto cleanup;
    }

    // Get status code
    DWORD dwSize = sizeof(statusCode);
    WinHttpQueryHeaders(
        hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode,
        &dwSize,
        WINHTTP_NO_HEADER_INDEX);

    LOG("HTTP Status: %d", statusCode);

    // Save cookies from response
    _SaveCookies(hRequest);

    // Read response body
    {
        DWORD dwDownloaded = 0;
        std::vector<char> responseBuffer;

        do
        {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
            {
                LOG("WinHttpQueryDataAvailable failed: %d", GetLastError());
                break;
            }

            if (dwSize == 0)
                break;

            std::vector<char> tempBuffer(dwSize + 1);
            ZeroMemory(&tempBuffer[0], dwSize + 1);

            if (!WinHttpReadData(hRequest, &tempBuffer[0], dwSize, &dwDownloaded))
            {
                LOG("WinHttpReadData failed: %d", GetLastError());
                break;
            }

            responseBuffer.insert(responseBuffer.end(), tempBuffer.begin(), tempBuffer.begin() + dwDownloaded);

        } while (dwSize > 0);

        // Convert response to wide string
        if (!responseBuffer.empty())
        {
            responseBuffer.push_back('\0');
            int wideSize = MultiByteToWideChar(CP_UTF8, 0, &responseBuffer[0], -1, NULL, 0);
            if (wideSize > 0)
            {
                std::vector<wchar_t> wideBuffer(wideSize);
                MultiByteToWideChar(CP_UTF8, 0, &responseBuffer[0], -1, &wideBuffer[0], wideSize);
                responseBody = &wideBuffer[0];
                
                LOG("Response received: %d bytes", responseBuffer.size());
                hr = S_OK;
            }
        }
    }

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return hr;
}

// Save cookies from response headers
void AuthentikAPI::_SaveCookies(HINTERNET hRequest)
{
    DWORD dwSize = 0;
    
    // Get required buffer size
    WinHttpQueryHeaders(
        hRequest,
        WINHTTP_QUERY_SET_COOKIE,
        WINHTTP_HEADER_NAME_BY_INDEX,
        NULL,
        &dwSize,
        WINHTTP_NO_HEADER_INDEX);
    
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && dwSize > 0)
    {
        std::vector<WCHAR> buffer(dwSize / sizeof(WCHAR) + 1);
        DWORD dwIndex = 0;
        
        while (WinHttpQueryHeaders(
            hRequest,
            WINHTTP_QUERY_SET_COOKIE,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &buffer[0],
            &dwSize,
            &dwIndex))
        {
            std::wstring cookie = &buffer[0];
            
            // Parse cookie name=value
            size_t eqPos = cookie.find(L'=');
            size_t scPos = cookie.find(L';');
            
            if (eqPos != std::wstring::npos)
            {
                std::wstring name = cookie.substr(0, eqPos);
                std::wstring value = (scPos != std::wstring::npos) ?
                    cookie.substr(eqPos + 1, scPos - eqPos - 1) :
                    cookie.substr(eqPos + 1);
                
                _cookies[name] = value;
                LOG("Saved cookie: %S", name.c_str());
                
                // Check for CSRF token
                if (name == L"authentik_csrf")
                {
                    _csrfToken = value;
                }
            }
            
            dwSize = (DWORD)(buffer.size() * sizeof(WCHAR));
        }
    }
}

// Add cookies to request
void AuthentikAPI::_AddCookies(HINTERNET hRequest)
{
    if (_cookies.empty())
        return;
    
    std::wstring cookieHeader = L"Cookie: ";
    bool first = true;
    
    for (const auto& cookie : _cookies)
    {
        if (!first)
            cookieHeader += L"; ";
        cookieHeader += cookie.first + L"=" + cookie.second;
        first = false;
    }
    
    cookieHeader += L"\r\n";
    
    WinHttpAddRequestHeaders(
        hRequest,
        cookieHeader.c_str(),
        (DWORD)-1,
        WINHTTP_ADDREQ_FLAG_ADD);
    
    // Add CSRF token if available
    if (!_csrfToken.empty())
    {
        std::wstring csrfHeader = L"X-authentik-CSRF: " + _csrfToken + L"\r\n";
        WinHttpAddRequestHeaders(
            hRequest,
            csrfHeader.c_str(),
            (DWORD)-1,
            WINHTTP_ADDREQ_FLAG_ADD);
    }
}

// Parse Authentik API response
AuthentikResponse AuthentikAPI::_ParseAuthentikResponse(const std::wstring& json)
{
    LOG("Parsing Authentik response");

    AuthentikResponse response;
    response.status = AuthStatus::FAILED;

    // Check for success (redirect type indicates completion)
    if (json.find(L"\"type\":\"redirect\"") != std::wstring::npos ||
        json.find(L"\"type\": \"redirect\"") != std::wstring::npos)
    {
        // Check if certificate is present
        if (json.find(L"\"certificate\"") != std::wstring::npos)
        {
            response.status = AuthStatus::SUCCESS;
            response.message = L"Authentication successful";
            
            // Extract certificate data
            response.certificatePem = _ParseJsonString(json, L"certificate");
            response.privateKeyPem = _ParseJsonString(json, L"private_key");
            response.username = _ParseJsonString(json, L"username");
            response.domain = _ParseJsonString(json, L"domain");
            response.upn = _ParseJsonString(json, L"upn");
            
            std::wstring validStr = _ParseJsonString(json, L"valid_minutes");
            if (!validStr.empty())
            {
                response.certValidMinutes = (DWORD)_wtoi(validStr.c_str());
            }
            
            LOG("Parsed: SUCCESS with certificate");
        }
        else
        {
            // Redirect without certificate - might be intermediate step
            response.status = AuthStatus::SUCCESS;
            response.message = L"Authentication successful";
            LOG("Parsed: SUCCESS (redirect)");
        }
    }
    // Check for OTP challenge
    else if (json.find(L"ak-stage-authenticator-validate") != std::wstring::npos ||
             json.find(L"authenticator") != std::wstring::npos ||
             json.find(L"otp") != std::wstring::npos ||
             json.find(L"\"code\"") != std::wstring::npos)
    {
        response.status = AuthStatus::NEED_OTP;
        response.message = L"Enter your OTP code";
        LOG("Parsed: NEED_OTP");
    }
    // Check for identification stage (need username)
    else if (json.find(L"ak-stage-identification") != std::wstring::npos ||
             json.find(L"uid_field") != std::wstring::npos)
    {
        response.status = AuthStatus::NEED_USERNAME;
        response.message = L"Enter your username";
        LOG("Parsed: NEED_USERNAME");
    }
    // Check for error
    else if (json.find(L"\"error\"") != std::wstring::npos ||
             json.find(L"\"detail\"") != std::wstring::npos)
    {
        response.status = AuthStatus::FAILED;
        response.message = _ParseJsonString(json, L"detail");
        if (response.message.empty())
        {
            response.message = _ParseJsonString(json, L"error");
        }
        if (response.message.empty())
        {
            response.message = L"Authentication failed";
        }
        LOG("Parsed: FAILED - %S", response.message.c_str());
    }
    else
    {
        // Unknown response - might be a challenge we don't recognize
        response.status = AuthStatus::NEED_OTP;
        response.message = L"Enter your verification code";
        LOG("Parsed: Unknown format, assuming OTP needed");
    }

    return response;
}

// Parse JSON string value
std::wstring AuthentikAPI::_ParseJsonString(const std::wstring& json, const std::wstring& key)
{
    // Look for "key":"value" or "key": "value"
    std::wstring searchKey = L"\"" + key + L"\"";
    size_t keyPos = json.find(searchKey);
    
    if (keyPos == std::wstring::npos)
        return L"";
    
    // Find the colon
    size_t colonPos = json.find(L':', keyPos + searchKey.length());
    if (colonPos == std::wstring::npos)
        return L"";
    
    // Find the opening quote
    size_t startQuote = json.find(L'"', colonPos + 1);
    if (startQuote == std::wstring::npos)
        return L"";
    
    // Find the closing quote (handle escaped quotes)
    size_t endQuote = startQuote + 1;
    while (endQuote < json.length())
    {
        if (json[endQuote] == L'"' && (endQuote == 0 || json[endQuote - 1] != L'\\'))
            break;
        endQuote++;
    }
    
    if (endQuote >= json.length())
        return L"";
    
    std::wstring value = json.substr(startQuote + 1, endQuote - startQuote - 1);
    
    // Handle escape sequences
    size_t pos = 0;
    while ((pos = value.find(L"\\n", pos)) != std::wstring::npos)
    {
        value.replace(pos, 2, L"\n");
        pos++;
    }
    pos = 0;
    while ((pos = value.find(L"\\\"", pos)) != std::wstring::npos)
    {
        value.replace(pos, 2, L"\"");
        pos++;
    }
    pos = 0;
    while ((pos = value.find(L"\\\\", pos)) != std::wstring::npos)
    {
        value.replace(pos, 2, L"\\");
        pos++;
    }
    
    return value;
}
