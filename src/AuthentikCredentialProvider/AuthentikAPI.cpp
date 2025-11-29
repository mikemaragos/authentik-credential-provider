// AuthentikAPI.cpp
// HTTP client for Authentik API communication with session management

#include "AuthentikAPI.h"
#include "Logger.h"
#include <sstream>
#include <new>

#pragma comment(lib, "Winhttp.lib")

// Constructor
AuthentikAPI::AuthentikAPI() :
    _serverUrl(L"authentik.test.local"),
    _serverPort(443),
    _flowSlug(L"default-authentication-flow"),
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
    
    // First, we need to GET the flow to start a session
    std::wstring url = L"/api/v3/flows/executor/" + _flowSlug + L"/";
    
    std::wstring responseBody;
    DWORD statusCode = 0;
    
    // GET request to initiate flow
    HRESULT hr = _MakeHttpRequest(L"GET", url, L"", responseBody, statusCode);
    
    if (FAILED(hr))
    {
        LOG("GET flow failed: 0x%08x", hr);
        response.status = AuthStatus::ERROR_NETWORK;
        response.message = L"Failed to connect to authentication server";
        return response;
    }
    
    LOG("GET flow response: status=%d", statusCode);
    
    if (statusCode == 404)
    {
        LOG("Flow not found: %S", _flowSlug.c_str());
        response.status = AuthStatus::ERROR_SERVER;
        response.message = L"Authentication flow not found on server";
        return response;
    }
    
    // Now POST the username
    std::wstring payload = L"{\"uid_field\":\"" + _EscapeJson(username) + L"\"}";
    
    hr = _MakeHttpRequest(L"POST", url, payload, responseBody, statusCode);
    
    if (FAILED(hr))
    {
        LOG("SubmitUsername request failed: 0x%08x", hr);
        response.status = AuthStatus::ERROR_NETWORK;
        response.message = L"Failed to connect to authentication server";
        return response;
    }
    
    LOG("SubmitUsername response: status=%d, length=%d", statusCode, (int)responseBody.length());
    
    if (statusCode >= 400)
    {
        LOG("Server error: %d", statusCode);
        response.status = AuthStatus::ERROR_SERVER;
        response.message = L"Server error: " + std::to_wstring(statusCode);
        return response;
    }
    
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
    std::wstring payload = L"{\"code\":\"" + _EscapeJson(otp) + L"\"}";
    
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
    
    LOG("SubmitOTP response: status=%d, length=%d", statusCode, (int)responseBody.length());
    
    if (statusCode >= 400)
    {
        LOG("Server error: %d", statusCode);
        response.status = AuthStatus::ERROR_SERVER;
        response.message = L"Server error: " + std::to_wstring(statusCode);
        return response;
    }
    
    // Parse response
    response = _ParseAuthentikResponse(responseBody);
    response.rawResponse = responseBody;
    
    // If successful, populate user info
    if (response.status == AuthStatus::SUCCESS)
    {
        response.username = _currentUsername;
        response.domain = _domain;
        response.upn = _currentUsername + L"@" + _domainFQDN;
    }
    
    return response;
}

// Escape JSON string
std::wstring AuthentikAPI::_EscapeJson(const std::wstring& input)
{
    std::wstring result;
    result.reserve(input.length() * 2);
    
    for (wchar_t ch : input)
    {
        switch (ch)
        {
        case L'"':  result += L"\\\""; break;
        case L'\\': result += L"\\\\"; break;
        case L'\n': result += L"\\n"; break;
        case L'\r': result += L"\\r"; break;
        case L'\t': result += L"\\t"; break;
        default:    result += ch; break;
        }
    }
    
    return result;
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
    BOOL bResult = FALSE;

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
    LPVOID pData = payloadUtf8.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)payloadUtf8.c_str();
    DWORD dataLen = payloadUtf8.empty() ? 0 : (DWORD)payloadUtf8.length();
    
    bResult = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        pData,
        dataLen,
        dataLen,
        0);

    if (!bResult)
    {
        LOG("WinHttpSendRequest failed: %d", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return E_FAIL;
    }

    // Receive response
    bResult = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResult)
    {
        LOG("WinHttpReceiveResponse failed: %d", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return E_FAIL;
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

        for (;;)
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
        }

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
                
                LOG("Response body: %.200S...", responseBody.c_str());
                hr = S_OK;
            }
        }
        else
        {
            hr = S_OK; // Empty response is OK
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return hr;
}

// Save cookies from response headers
void AuthentikAPI::_SaveCookies(HINTERNET hRequest)
{
    DWORD dwSize = 0;
    DWORD dwIndex = 0;
    
    // Query for Set-Cookie headers
    WinHttpQueryHeaders(
        hRequest,
        WINHTTP_QUERY_SET_COOKIE,
        WINHTTP_HEADER_NAME_BY_INDEX,
        NULL,
        &dwSize,
        &dwIndex);
    
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && dwSize > 0)
    {
        dwIndex = 0; // Reset index
        
        std::vector<WCHAR> buffer(dwSize / sizeof(WCHAR) + 1);
        
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
    
    LOG("Added cookies: %S", cookieHeader.c_str());
    
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

    // Log first part of response for debugging
    LOG("Response preview: %.300S", json.c_str());

    // Check for redirect responses (indicates flow completion)
    // xak-flow-redirect means authentication succeeded and flow is complete
    if (json.find(L"xak-flow-redirect") != std::wstring::npos ||
        json.find(L"\"type\":\"redirect\"") != std::wstring::npos ||
        json.find(L"\"type\": \"redirect\"") != std::wstring::npos)
    {
        response.status = AuthStatus::SUCCESS;
        response.message = L"Authentication successful";
        
        // Extract certificate data if present
        response.certificatePem = _ParseJsonString(json, L"certificate");
        response.privateKeyPem = _ParseJsonString(json, L"private_key");
        
        // If redirect has "to" field, it's a success
        std::wstring redirectTo = _ParseJsonString(json, L"to");
        LOG("Parsed: SUCCESS - redirect to: %S", redirectTo.c_str());
        return response;
    }
    
    // Check for native flow response (component indicates a stage)
    if (json.find(L"\"component\"") != std::wstring::npos)
    {
        std::wstring component = _ParseJsonString(json, L"component");
        LOG("Flow component: %S", component.c_str());
        
        // Check for OTP/authenticator stages
        if (component.find(L"ak-stage-authenticator") != std::wstring::npos ||
            component.find(L"totp") != std::wstring::npos ||
            component.find(L"otp") != std::wstring::npos ||
            component.find(L"authenticator-validate") != std::wstring::npos)
        {
            response.status = AuthStatus::NEED_OTP;
            response.message = L"Enter your OTP code";
            LOG("Parsed: NEED_OTP");
            return response;
        }
        
        // Check for identification stage
        if (component.find(L"ak-stage-identification") != std::wstring::npos)
        {
            response.status = AuthStatus::NEED_USERNAME;
            response.message = L"Enter your username";
            LOG("Parsed: NEED_USERNAME");
            return response;
        }
        
        // Check for password stage (might be part of the flow)
        if (component.find(L"ak-stage-password") != std::wstring::npos)
        {
            response.status = AuthStatus::NEED_OTP;
            response.message = L"Enter your verification code";
            LOG("Parsed: NEED_OTP (password stage)");
            return response;
        }
        
        // Unknown component but not an error - might need more input
        response.status = AuthStatus::NEED_OTP;
        response.message = L"Continue authentication";
        LOG("Parsed: Unknown component, assuming more input needed");
        return response;
    }
    
    // Check for error response
    if (json.find(L"\"detail\"") != std::wstring::npos)
    {
        response.status = AuthStatus::FAILED;
        response.message = _ParseJsonString(json, L"detail");
        if (response.message.empty())
        {
            response.message = L"Authentication failed";
        }
        LOG("Parsed: FAILED - %S", response.message.c_str());
        return response;
    }
    
    if (json.find(L"\"error\"") != std::wstring::npos)
    {
        response.status = AuthStatus::FAILED;
        response.message = _ParseJsonString(json, L"error");
        if (response.message.empty())
        {
            response.message = L"Authentication failed";
        }
        LOG("Parsed: FAILED - %S", response.message.c_str());
        return response;
    }

    // No recognized response - treat as needing more input
    response.status = AuthStatus::NEED_OTP;
    response.message = L"Continue authentication";
    LOG("Parsed: Unrecognized format, assuming more input needed");
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
    
    // Skip whitespace
    size_t startQuote = colonPos + 1;
    while (startQuote < json.length() && (json[startQuote] == L' ' || json[startQuote] == L'\t'))
        startQuote++;
    
    // Check for opening quote
    if (startQuote >= json.length() || json[startQuote] != L'"')
        return L"";
    
    // Find the closing quote (handle escaped quotes)
    size_t endQuote = startQuote + 1;
    while (endQuote < json.length())
    {
        if (json[endQuote] == L'"' && json[endQuote - 1] != L'\\')
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
