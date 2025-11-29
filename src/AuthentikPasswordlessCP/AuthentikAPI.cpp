// AuthentikAPI.cpp
// HTTP client for Authentik API communication
// Supports passwordless authentication with certificate response

#include "AuthentikAPI.h"
#include "Logger.h"
#include <sstream>
#include <algorithm>

#pragma comment(lib, "winhttp.lib")

// Registry key for configuration
#define REGISTRY_KEY L"SOFTWARE\\AuthentikPasswordlessCP"

AuthentikAPI::AuthentikAPI() :
    _serverUrl(L"authentik.test.local"),
    _serverPort(443),
    _flowSlug(L"windows-passwordless"),
    _useHttps(true),
    _domain(L"TEST"),
    _domainFQDN(L"test.local"),
    _certValidMinutes(5),
    _ignoreCertErrors(true),  // Default true for development
    _hSession(nullptr)
{
    LOG("AuthentikAPI::Constructor");
}

AuthentikAPI::~AuthentikAPI()
{
    LOG("AuthentikAPI::Destructor");
    
    if (_hSession)
    {
        WinHttpCloseHandle(_hSession);
        _hSession = nullptr;
    }
    
    // Secure clear sensitive data
    SecureZeroMemory(&_currentFlowToken[0], _currentFlowToken.size() * sizeof(wchar_t));
}

HRESULT AuthentikAPI::Initialize()
{
    LOG("AuthentikAPI::Initialize");
    
    _LoadConfiguration();
    
    // Initialize WinHTTP session
    _hSession = WinHttpOpen(
        L"AuthentikPasswordlessCP/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    
    if (!_hSession)
    {
        LOG_E("WinHttpOpen failed: %d", GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }
    
    LOG("WinHTTP session initialized");
    return S_OK;
}

void AuthentikAPI::_LoadConfiguration()
{
    LOG("Loading configuration from registry");

    HKEY hKey;
    LONG result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        REGISTRY_KEY,
        0,
        KEY_READ,
        &hKey);

    if (result == ERROR_SUCCESS)
    {
        WCHAR buffer[256];
        DWORD bufferSize;

        // Server URL
        bufferSize = sizeof(buffer);
        result = RegQueryValueExW(hKey, L"ServerUrl", nullptr, nullptr, (LPBYTE)buffer, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _serverUrl = buffer;
            LOG("ServerUrl: %S", _serverUrl.c_str());
        }

        // Server port
        DWORD port = 443;
        bufferSize = sizeof(DWORD);
        result = RegQueryValueExW(hKey, L"ServerPort", nullptr, nullptr, (LPBYTE)&port, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _serverPort = (INTERNET_PORT)port;
            LOG("ServerPort: %d", _serverPort);
        }

        // Flow slug
        bufferSize = sizeof(buffer);
        result = RegQueryValueExW(hKey, L"FlowSlug", nullptr, nullptr, (LPBYTE)buffer, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _flowSlug = buffer;
            LOG("FlowSlug: %S", _flowSlug.c_str());
        }

        // Use HTTPS
        DWORD useHttps = 1;
        bufferSize = sizeof(DWORD);
        result = RegQueryValueExW(hKey, L"UseHttps", nullptr, nullptr, (LPBYTE)&useHttps, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _useHttps = (useHttps != 0);
            LOG("UseHttps: %d", _useHttps);
        }

        // Domain
        bufferSize = sizeof(buffer);
        result = RegQueryValueExW(hKey, L"Domain", nullptr, nullptr, (LPBYTE)buffer, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _domain = buffer;
            LOG("Domain: %S", _domain.c_str());
        }

        // Domain FQDN
        bufferSize = sizeof(buffer);
        result = RegQueryValueExW(hKey, L"DomainFQDN", nullptr, nullptr, (LPBYTE)buffer, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _domainFQDN = buffer;
            LOG("DomainFQDN: %S", _domainFQDN.c_str());
        }

        // Certificate validity
        bufferSize = sizeof(DWORD);
        result = RegQueryValueExW(hKey, L"CertValidMinutes", nullptr, nullptr, (LPBYTE)&_certValidMinutes, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            LOG("CertValidMinutes: %d", _certValidMinutes);
        }

        // Ignore cert errors (testing only!)
        DWORD ignoreCert = 1;
        bufferSize = sizeof(DWORD);
        result = RegQueryValueExW(hKey, L"IgnoreCertErrors", nullptr, nullptr, (LPBYTE)&ignoreCert, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _ignoreCertErrors = (ignoreCert != 0);
            if (_ignoreCertErrors)
            {
                LOG_W("WARNING: SSL certificate validation is DISABLED!");
            }
        }

        RegCloseKey(hKey);
    }
    else
    {
        LOG_W("Failed to open registry key: %d (using defaults)", result);
    }
}

AuthentikResponse AuthentikAPI::InitiateAuthentication(const std::wstring& username)
{
    LOG("InitiateAuthentication: user=%S", username.c_str());
    
    AuthentikResponse response;
    response.type = AuthResponseType::ERROR;
    
    // Store username for this flow
    _currentUsername = username;
    
    // Build request URL
    std::wstring url = L"/api/v3/flows/executor/" + _flowSlug + L"/";
    
    // Build JSON payload
    std::wstring payload = L"{\"uid_field\":\"" + username + L"\"}";
    
    LOG("Request URL: %S", url.c_str());
    LOG("Payload: %S", payload.c_str());
    
    // Make HTTP request
    std::wstring responseBody;
    HRESULT hr = _MakeHttpRequest(L"POST", url, payload, responseBody);
    
    if (FAILED(hr))
    {
        LOG_E("HTTP request failed: 0x%08x", hr);
        response.message = L"Failed to connect to authentication server";
        return response;
    }
    
    // Parse response
    response = _ParseResponse(responseBody);
    
    LOG("InitiateAuthentication result: type=%d, requiresOTP=%d", 
        (int)response.type, response.requiresOTP);
    
    return response;
}

AuthentikResponse AuthentikAPI::SubmitOTP(const std::wstring& otp)
{
    LOG("SubmitOTP");
    
    AuthentikResponse response;
    response.type = AuthResponseType::ERROR;
    
    if (_currentFlowToken.empty())
    {
        LOG_E("No active flow token");
        response.message = L"No active authentication session";
        return response;
    }
    
    // Build request URL
    std::wstring url = L"/api/v3/flows/executor/" + _flowSlug + L"/";
    
    // Build JSON payload
    std::wstring payload = L"{\"code\":\"" + otp + L"\"}";
    
    LOG("Request URL: %S", url.c_str());
    
    // Make HTTP request
    std::wstring responseBody;
    HRESULT hr = _MakeHttpRequest(L"POST", url, payload, responseBody);
    
    if (FAILED(hr))
    {
        LOG_E("HTTP request failed: 0x%08x", hr);
        response.message = L"Failed to validate OTP";
        return response;
    }
    
    // Parse response
    response = _ParseResponse(responseBody);
    
    // If successful with certificate, populate domain info
    if (response.type == AuthResponseType::SUCCESS_WITH_CERTIFICATE)
    {
        if (response.domain.empty())
        {
            response.domain = _domain;
        }
        if (response.upn.empty() && !_currentUsername.empty())
        {
            response.upn = _currentUsername + L"@" + _domainFQDN;
        }
        if (response.username.empty())
        {
            response.username = _currentUsername;
        }
    }
    
    LOG("SubmitOTP result: type=%d, hasCert=%d", 
        (int)response.type, response.hasCertificate);
    
    return response;
}

void AuthentikAPI::ResetFlow()
{
    LOG("ResetFlow");
    
    SecureZeroMemory(&_currentFlowToken[0], _currentFlowToken.size() * sizeof(wchar_t));
    _currentFlowToken.clear();
    _currentUsername.clear();
    _cookies.clear();
}

HRESULT AuthentikAPI::_MakeHttpRequest(
    const std::wstring& method,
    const std::wstring& url,
    const std::wstring& payload,
    std::wstring& responseBody)
{
    LOG("HTTP %S %S", method.c_str(), url.c_str());
    
    if (!_hSession)
    {
        LOG_E("HTTP session not initialized");
        return E_FAIL;
    }
    
    HRESULT hr = E_FAIL;
    HINTERNET hConnect = nullptr;
    HINTERNET hRequest = nullptr;
    
    // Connect to server
    hConnect = WinHttpConnect(
        _hSession,
        _serverUrl.c_str(),
        _serverPort,
        0);
    
    if (!hConnect)
    {
        LOG_E("WinHttpConnect failed: %d", GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }
    
    // Create request
    DWORD dwFlags = _useHttps ? WINHTTP_FLAG_SECURE : 0;
    
    hRequest = WinHttpOpenRequest(
        hConnect,
        method.c_str(),
        url.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        dwFlags);
    
    if (!hRequest)
    {
        LOG_E("WinHttpOpenRequest failed: %d", GetLastError());
        WinHttpCloseHandle(hConnect);
        return HRESULT_FROM_WIN32(GetLastError());
    }
    
    // Disable SSL certificate validation for testing
    if (_useHttps && _ignoreCertErrors)
    {
        DWORD dwSecFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        
        WinHttpSetOption(
            hRequest,
            WINHTTP_OPTION_SECURITY_FLAGS,
            &dwSecFlags,
            sizeof(dwSecFlags));
        
        LOG_W("SSL certificate validation disabled for this request");
    }
    
    // Set headers
    std::wstring headers = L"Content-Type: application/json\r\n";
    headers += L"Accept: application/json\r\n";
    
    // Add session cookies
    _ApplyCookies(hRequest);
    
    WinHttpAddRequestHeaders(
        hRequest,
        headers.c_str(),
        (DWORD)-1,
        WINHTTP_ADDREQ_FLAG_ADD);
    
    // Convert payload to UTF-8
    std::string payloadUtf8;
    if (!payload.empty())
    {
        int size = WideCharToMultiByte(CP_UTF8, 0, payload.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (size > 0)
        {
            std::vector<char> buffer(size);
            WideCharToMultiByte(CP_UTF8, 0, payload.c_str(), -1, &buffer[0], size, nullptr, nullptr);
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
        DWORD err = GetLastError();
        LOG_E("WinHttpSendRequest failed: %d", err);
        
        if (err == ERROR_WINHTTP_SECURE_FAILURE)
        {
            LOG_E("SSL/TLS error - check certificate configuration");
        }
        
        hr = HRESULT_FROM_WIN32(err);
        goto cleanup;
    }
    
    // Receive response
    bResult = WinHttpReceiveResponse(hRequest, nullptr);
    if (!bResult)
    {
        LOG_E("WinHttpReceiveResponse failed: %d", GetLastError());
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }
    
    // Save session cookies
    _SaveCookies(hRequest);
    
    // Check status code
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    WinHttpQueryHeaders(
        hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode,
        &statusCodeSize,
        WINHTTP_NO_HEADER_INDEX);
    
    LOG("HTTP Status: %d", statusCode);
    
    // Read response body
    std::vector<char> responseBuffer;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    
    do
    {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
        {
            LOG_E("WinHttpQueryDataAvailable failed: %d", GetLastError());
            break;
        }
        
        if (dwSize == 0)
            break;
        
        std::vector<char> tempBuffer(dwSize + 1);
        ZeroMemory(&tempBuffer[0], dwSize + 1);
        
        if (!WinHttpReadData(hRequest, &tempBuffer[0], dwSize, &dwDownloaded))
        {
            LOG_E("WinHttpReadData failed: %d", GetLastError());
            break;
        }
        
        responseBuffer.insert(responseBuffer.end(), tempBuffer.begin(), tempBuffer.begin() + dwDownloaded);
        
    } while (dwSize > 0);
    
    // Convert response to wide string
    if (!responseBuffer.empty())
    {
        responseBuffer.push_back('\0');
        int wideSize = MultiByteToWideChar(CP_UTF8, 0, &responseBuffer[0], -1, nullptr, 0);
        if (wideSize > 0)
        {
            std::vector<wchar_t> wideBuffer(wideSize);
            MultiByteToWideChar(CP_UTF8, 0, &responseBuffer[0], -1, &wideBuffer[0], wideSize);
            responseBody = &wideBuffer[0];
            
            LOG("Response received: %d bytes", responseBuffer.size() - 1);
            LOG_D("Response body (first 500 chars): %.500S", responseBody.c_str());
            
            hr = S_OK;
        }
    }
    else
    {
        LOG_W("Empty response body");
        hr = S_OK;  // Empty response might be valid
    }
    
cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    
    return hr;
}

AuthentikResponse AuthentikAPI::_ParseResponse(const std::wstring& json)
{
    LOG("ParseResponse");
    
    AuthentikResponse response;
    response.rawResponse = json;
    
    // Check for redirect (success without certificate)
    if (json.find(L"\"type\":\"redirect\"") != std::wstring::npos)
    {
        // Check if certificate bundle is present
        if (json.find(L"certificate_bundle") != std::wstring::npos ||
            json.find(L"\"certificate\"") != std::wstring::npos)
        {
            LOG("Found certificate in redirect response");
            
            HRESULT hr = _ExtractCertificateBundle(json, response);
            if (SUCCEEDED(hr))
            {
                response.type = AuthResponseType::SUCCESS_WITH_CERTIFICATE;
                response.message = L"Authentication successful";
                LOG("Certificate bundle extracted successfully");
            }
            else
            {
                LOG_E("Failed to extract certificate bundle: 0x%08x", hr);
                response.type = AuthResponseType::SUCCESS_REDIRECT;
                response.message = L"Authentication successful (no certificate)";
            }
        }
        else
        {
            response.type = AuthResponseType::SUCCESS_REDIRECT;
            response.message = L"Authentication successful";
            LOG("Redirect without certificate");
        }
        
        return response;
    }
    
    // Check for OTP challenge
    if (json.find(L"ak-stage-authenticator-validate") != std::wstring::npos ||
        json.find(L"\"component\":\"ak-stage-authenticator") != std::wstring::npos)
    {
        response.type = AuthResponseType::NEED_OTP;
        response.requiresOTP = true;
        response.message = L"Enter your verification code";
        
        // Try to determine OTP type
        if (json.find(L"totp") != std::wstring::npos)
        {
            response.otpType = OTPChallengeType::TOTP;
            response.otpPrompt = L"Enter your authenticator code";
        }
        else if (json.find(L"push") != std::wstring::npos)
        {
            response.otpType = OTPChallengeType::PUSH;
            response.otpPrompt = L"Approve the push notification";
        }
        else if (json.find(L"sms") != std::wstring::npos)
        {
            response.otpType = OTPChallengeType::SMS;
            response.otpPrompt = L"Enter the SMS code";
        }
        else
        {
            response.otpType = OTPChallengeType::TOTP;
            response.otpPrompt = L"Enter your verification code";
        }
        
        // Save flow token for next request
        // Look for flow token in response
        size_t tokenPos = json.find(L"\"flow_token\"");
        if (tokenPos != std::wstring::npos)
        {
            // Simple extraction - find value after colon and quotes
            size_t colonPos = json.find(L':', tokenPos);
            if (colonPos != std::wstring::npos)
            {
                size_t startQuote = json.find(L'"', colonPos);
                size_t endQuote = json.find(L'"', startQuote + 1);
                if (startQuote != std::wstring::npos && endQuote != std::wstring::npos)
                {
                    _currentFlowToken = json.substr(startQuote + 1, endQuote - startQuote - 1);
                    LOG("Captured flow token");
                }
            }
        }
        else
        {
            // Use cookies for session persistence instead
            LOG("No flow token found, relying on cookies");
            _currentFlowToken = L"cookie-session";
        }
        
        LOG("OTP challenge: type=%d, prompt=%S", (int)response.otpType, response.otpPrompt.c_str());
        return response;
    }
    
    // Check for identification stage (need username)
    if (json.find(L"ak-stage-identification") != std::wstring::npos)
    {
        response.type = AuthResponseType::NEED_USERNAME;
        response.message = L"Enter your username";
        LOG("Identification stage - need username");
        return response;
    }
    
    // Check for error
    if (json.find(L"\"type\":\"error\"") != std::wstring::npos ||
        json.find(L"\"detail\"") != std::wstring::npos)
    {
        response.type = AuthResponseType::ERROR;
        
        // Try to extract error message
        size_t msgPos = json.find(L"\"detail\"");
        if (msgPos == std::wstring::npos)
        {
            msgPos = json.find(L"\"message\"");
        }
        
        if (msgPos != std::wstring::npos)
        {
            size_t colonPos = json.find(L':', msgPos);
            if (colonPos != std::wstring::npos)
            {
                size_t startQuote = json.find(L'"', colonPos);
                size_t endQuote = json.find(L'"', startQuote + 1);
                if (startQuote != std::wstring::npos && endQuote != std::wstring::npos)
                {
                    response.message = json.substr(startQuote + 1, endQuote - startQuote - 1);
                }
            }
        }
        
        if (response.message.empty())
        {
            response.message = L"Authentication failed";
        }
        
        LOG_E("Error response: %S", response.message.c_str());
        return response;
    }
    
    // Unknown response type
    response.type = AuthResponseType::ERROR;
    response.message = L"Unknown response from server";
    LOG_W("Unknown response format");
    
    return response;
}

HRESULT AuthentikAPI::_ExtractCertificateBundle(
    const std::wstring& json,
    AuthentikResponse& response)
{
    LOG("ExtractCertificateBundle");
    
    // Helper lambda to extract JSON string value
    auto extractString = [&json](const std::wstring& key) -> std::wstring {
        std::wstring searchKey = L"\"" + key + L"\"";
        size_t keyPos = json.find(searchKey);
        if (keyPos == std::wstring::npos) return L"";
        
        size_t colonPos = json.find(L':', keyPos);
        if (colonPos == std::wstring::npos) return L"";
        
        size_t startQuote = json.find(L'"', colonPos);
        if (startQuote == std::wstring::npos) return L"";
        
        // Handle escaped quotes within value
        size_t endQuote = startQuote + 1;
        while (endQuote < json.length())
        {
            if (json[endQuote] == L'"' && json[endQuote - 1] != L'\\')
                break;
            endQuote++;
        }
        
        if (endQuote >= json.length()) return L"";
        
        std::wstring value = json.substr(startQuote + 1, endQuote - startQuote - 1);
        
        // Unescape newlines and quotes
        size_t pos = 0;
        while ((pos = value.find(L"\\n", pos)) != std::wstring::npos)
        {
            value.replace(pos, 2, L"\n");
            pos += 1;
        }
        pos = 0;
        while ((pos = value.find(L"\\\"", pos)) != std::wstring::npos)
        {
            value.replace(pos, 2, L"\"");
            pos += 1;
        }
        
        return value;
    };
    
    // Extract certificate
    response.certificatePem = extractString(L"certificate");
    if (response.certificatePem.empty())
    {
        LOG_E("No certificate found in response");
        return E_FAIL;
    }
    
    // Extract private key
    response.privateKeyPem = extractString(L"private_key");
    if (response.privateKeyPem.empty())
    {
        LOG_E("No private key found in response");
        return E_FAIL;
    }
    
    // Extract optional fields
    response.username = extractString(L"username");
    response.domain = extractString(L"domain");
    response.upn = extractString(L"upn");
    
    std::wstring validMin = extractString(L"valid_minutes");
    if (!validMin.empty())
    {
        response.certValidMinutes = _wtoi(validMin.c_str());
    }
    else
    {
        response.certValidMinutes = _certValidMinutes;
    }
    
    // Extract CA chain (simple single cert for now)
    std::wstring caCert = extractString(L"ca_cert");
    if (!caCert.empty())
    {
        response.caChainPem.push_back(caCert);
    }
    
    response.hasCertificate = true;
    
    LOG("Certificate bundle extracted:");
    LOG("  Certificate: %d chars", response.certificatePem.length());
    LOG("  Private key: %d chars", response.privateKeyPem.length());
    LOG("  Username: %S", response.username.c_str());
    LOG("  Domain: %S", response.domain.c_str());
    LOG("  UPN: %S", response.upn.c_str());
    LOG("  Valid minutes: %d", response.certValidMinutes);
    
    return S_OK;
}

void AuthentikAPI::_SaveCookies(HINTERNET hRequest)
{
    // Query for Set-Cookie headers
    DWORD dwSize = 0;
    WinHttpQueryHeaders(
        hRequest,
        WINHTTP_QUERY_SET_COOKIE,
        WINHTTP_HEADER_NAME_BY_INDEX,
        NULL,
        &dwSize,
        WINHTTP_NO_HEADER_INDEX);
    
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && dwSize > 0)
    {
        std::vector<wchar_t> buffer(dwSize / sizeof(wchar_t) + 1);
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
            
            // Extract cookie name and value
            size_t eqPos = cookie.find(L'=');
            if (eqPos != std::wstring::npos)
            {
                std::wstring name = cookie.substr(0, eqPos);
                
                size_t valueEnd = cookie.find(L';', eqPos);
                std::wstring value = (valueEnd != std::wstring::npos) ?
                    cookie.substr(eqPos + 1, valueEnd - eqPos - 1) :
                    cookie.substr(eqPos + 1);
                
                _cookies[name] = value;
                LOG_D("Saved cookie: %S", name.c_str());
            }
            
            // Reset for next iteration
            dwSize = (DWORD)(buffer.size() * sizeof(wchar_t));
        }
    }
}

void AuthentikAPI::_ApplyCookies(HINTERNET hRequest)
{
    if (_cookies.empty())
    {
        return;
    }
    
    std::wstring cookieHeader = L"Cookie: ";
    bool first = true;
    
    for (const auto& cookie : _cookies)
    {
        if (!first)
        {
            cookieHeader += L"; ";
        }
        cookieHeader += cookie.first + L"=" + cookie.second;
        first = false;
    }
    
    WinHttpAddRequestHeaders(
        hRequest,
        cookieHeader.c_str(),
        (DWORD)-1,
        WINHTTP_ADDREQ_FLAG_ADD);
    
    LOG_D("Applied %d cookies", _cookies.size());
}

// Factory function
HRESULT AuthentikAPI_CreateInstance(AuthentikAPI** ppAPI)
{
    if (!ppAPI)
    {
        return E_INVALIDARG;
    }
    
    *ppAPI = new (std::nothrow) AuthentikAPI();
    if (!*ppAPI)
    {
        return E_OUTOFMEMORY;
    }
    
    HRESULT hr = (*ppAPI)->Initialize();
    if (FAILED(hr))
    {
        delete *ppAPI;
        *ppAPI = nullptr;
    }
    
    return hr;
}
