// AuthentikAPI.cpp
// HTTP client for Authentik API communication with certificate support

#include "AuthentikAPI.h"
#include "Logger.h"
#include <winhttp.h>
#include <sstream>
#include <vector>
#include <wincrypt.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")

// Constructor
AuthentikAPI::AuthentikAPI() :
    _serverUrl(L"authentik.test.local"),
    _serverPort(443),
    _flowSlug(L"windows-smartcard-auth"),
    _useHttps(true),
    _certIssuerUrl(L""),
    _certIssuerPort(8443),
    _certIssuerToken(L""),
    _domain(L"test.local"),
    _upnSuffix(L"@test.local")
{
    LOG("AuthentikAPI::Constructor");
    _LoadConfiguration();
}

// Destructor
AuthentikAPI::~AuthentikAPI()
{
    LOG("AuthentikAPI::Destructor");
    // Clear sensitive data
    SecureZeroMemory(&_certIssuerToken[0], _certIssuerToken.length() * sizeof(wchar_t));
}

// Initiate authentication flow (username only for passwordless)
AuthentikResponse AuthentikAPI::InitiateAuthentication(const std::wstring& username)
{
    LOG("InitiateAuthentication: user=%S", username.c_str());
    
    // Clear any previous session cookies to start fresh
    _sessionCookies.clear();
    LOG("Cleared previous session cookies");

    AuthentikResponse response;
    response.success = false;
    response.requiresOTP = false;

    // Build request URL for flow executor
    std::wstring url = L"/api/v3/flows/executor/" + _flowSlug + L"/";
    
    // Step 1: GET request to start the flow and get initial challenge
    std::wstring getResponseBody;
    HRESULT hr = _MakeHttpRequest(L"GET", url, L"", getResponseBody);
    
    if (FAILED(hr))
    {
        LOG("InitiateAuthentication: Failed to start flow: 0x%08x", hr);
        response.message = L"Failed to connect to authentication server";
        return response;
    }
    
    LOG("InitiateAuthentication: Flow started, got initial challenge");

    // Step 2: POST username to complete identification stage
    std::wstring payload = L"{\"uid_field\":\"" + username + L"\"}";
    LOG("InitiateAuthentication: Sending payload: %S", payload.c_str());

    // Make HTTP request
    std::wstring responseBody;
    hr = _MakeHttpRequest(L"POST", url, payload, responseBody);

    if (SUCCEEDED(hr))
    {
        // Parse response
        response = _ParseAuthentikResponse(responseBody);
        LOG("InitiateAuthentication response: success=%d, requiresOTP=%d", response.success, response.requiresOTP);
    }
    else
    {
        LOG("InitiateAuthentication failed: 0x%08x", hr);
        response.message = L"Failed to connect to authentication server";
    }

    return response;
}

// Validate OTP
AuthentikResponse AuthentikAPI::ValidateOTP(const std::wstring& username, const std::wstring& otp, const std::wstring& flowToken)
{
    LOG("ValidateOTP: user=%S, otp_length=%d", username.c_str(), (int)otp.length());

    AuthentikResponse response;
    response.success = false;
    response.requiresOTP = false;

    // Build request URL
    std::wstring url = L"/api/v3/flows/executor/" + _flowSlug + L"/";

    // Build JSON payload with OTP code
    std::wstring payload = L"{\"code\":\"" + otp + L"\"}";
    
    LOG("ValidateOTP: Sending payload: %S", payload.c_str());
    LOG("ValidateOTP: Session cookies: %S", _sessionCookies.empty() ? L"(none)" : _sessionCookies.substr(0, 100).c_str());

    // Make HTTP request (cookies should maintain session)
    std::wstring responseBody;
    HRESULT hr = _MakeHttpRequest(L"POST", url, payload, responseBody);

    if (SUCCEEDED(hr))
    {
        // Parse response
        response = _ParseAuthentikResponse(responseBody);
        
        // Check if we got a redirect (success) or still in flow
        if (response.success)
        {
            LOG("ValidateOTP: Authentication successful");
            // Extract any tokens from the response for certificate request
            response.flowToken = _ExtractJsonString(responseBody, L"token");
        }
        else
        {
            LOG("ValidateOTP: Still in flow or failed");
        }
    }
    else
    {
        LOG("ValidateOTP failed: 0x%08x", hr);
        response.message = L"Failed to validate OTP";
    }

    return response;
}

// Request certificate from Certificate Issuer service
CertificateResponse AuthentikAPI::RequestCertificate(const std::wstring& username, const std::wstring& upn, const std::wstring& authToken)
{
    LOG("RequestCertificate: user=%S, upn=%S", username.c_str(), upn.c_str());

    CertificateResponse response;
    response.success = false;

    // Check if certificate issuer is configured
    if (_certIssuerUrl.empty())
    {
        LOG("Certificate issuer URL not configured");
        response.message = L"Certificate issuer not configured";
        return response;
    }

    // Build the actual UPN if not provided
    std::wstring actualUpn = upn;
    if (actualUpn.empty())
    {
        actualUpn = username + _upnSuffix;
    }

    // Build JSON payload
    std::wstring payload = L"{\"username\":\"" + username + L"\",\"upn\":\"" + actualUpn + L"\",\"domain\":\"" + _domain + L"\"}";

    // Make HTTP request to certificate issuer
    std::wstring responseBody;
    HRESULT hr = _MakeCertRequest(L"/api/v1/issue-certificate", payload, responseBody);

    if (SUCCEEDED(hr))
    {
        // Parse certificate response
        response = _ParseCertificateResponse(responseBody);
        
        if (response.success)
        {
            LOG("RequestCertificate: Certificate issued successfully, thumbprint=%S", response.thumbprint.c_str());
        }
        else
        {
            LOG("RequestCertificate: Certificate issuance failed: %S", response.message.c_str());
        }
    }
    else
    {
        LOG("RequestCertificate failed: 0x%08x", hr);
        response.message = L"Failed to connect to certificate issuer";
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
        L"SOFTWARE\\AuthentikCredentialProvider",
        0,
        KEY_READ,
        &hKey);

    if (result == ERROR_SUCCESS)
    {
        WCHAR buffer[512];
        DWORD bufferSize;

        // Read Authentik server URL
        bufferSize = sizeof(buffer);
        result = RegQueryValueExW(hKey, L"ServerUrl", nullptr, nullptr, (LPBYTE)buffer, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _serverUrl = buffer;
            LOG("ServerUrl: %S", _serverUrl.c_str());
        }

        // Read server port
        DWORD port = 443;
        bufferSize = sizeof(DWORD);
        result = RegQueryValueExW(hKey, L"ServerPort", nullptr, nullptr, (LPBYTE)&port, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _serverPort = (INTERNET_PORT)port;
            LOG("ServerPort: %d", _serverPort);
        }

        // Read flow slug
        bufferSize = sizeof(buffer);
        result = RegQueryValueExW(hKey, L"FlowSlug", nullptr, nullptr, (LPBYTE)buffer, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _flowSlug = buffer;
            LOG("FlowSlug: %S", _flowSlug.c_str());
        }

        // Read HTTPS flag
        DWORD useHttps = 1;
        bufferSize = sizeof(DWORD);
        result = RegQueryValueExW(hKey, L"UseHttps", nullptr, nullptr, (LPBYTE)&useHttps, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _useHttps = (useHttps != 0);
            LOG("UseHttps: %d", _useHttps);
        }

        // Read Certificate Issuer URL
        bufferSize = sizeof(buffer);
        result = RegQueryValueExW(hKey, L"CertIssuerUrl", nullptr, nullptr, (LPBYTE)buffer, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _certIssuerUrl = buffer;
            LOG("CertIssuerUrl: %S", _certIssuerUrl.c_str());
        }

        // Read Certificate Issuer port
        port = 8443;
        bufferSize = sizeof(DWORD);
        result = RegQueryValueExW(hKey, L"CertIssuerPort", nullptr, nullptr, (LPBYTE)&port, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _certIssuerPort = (INTERNET_PORT)port;
            LOG("CertIssuerPort: %d", _certIssuerPort);
        }

        // Read Certificate Issuer Token
        bufferSize = sizeof(buffer);
        result = RegQueryValueExW(hKey, L"CertIssuerToken", nullptr, nullptr, (LPBYTE)buffer, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _certIssuerToken = buffer;
            LOG("CertIssuerToken: (configured)");
        }

        // Read Domain
        bufferSize = sizeof(buffer);
        result = RegQueryValueExW(hKey, L"Domain", nullptr, nullptr, (LPBYTE)buffer, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _domain = buffer;
            LOG("Domain: %S", _domain.c_str());
        }

        // Read UPN Suffix
        bufferSize = sizeof(buffer);
        result = RegQueryValueExW(hKey, L"UPNSuffix", nullptr, nullptr, (LPBYTE)buffer, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _upnSuffix = buffer;
            LOG("UPNSuffix: %S", _upnSuffix.c_str());
        }

        RegCloseKey(hKey);
    }
    else
    {
        LOG("Failed to open registry key: %d (using defaults)", result);
    }
}

// Make HTTP request to Authentik
HRESULT AuthentikAPI::_MakeHttpRequest(
    const std::wstring& method,
    const std::wstring& url,
    const std::wstring& payload,
    std::wstring& responseBody,
    const std::wstring& authHeader)
{
    LOG("HTTP %S %S", method.c_str(), url.c_str());

    HRESULT hr = E_FAIL;
    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;
    HINTERNET hRequest = nullptr;

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
        nullptr,
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

    // Disable SSL certificate validation for testing (REMOVE IN PRODUCTION)
    if (_useHttps)
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

    // Build headers
    std::wstring headers = L"Content-Type: application/json\r\n";
    if (!authHeader.empty())
    {
        headers += L"Authorization: " + authHeader + L"\r\n";
    }
    if (!_sessionCookies.empty())
    {
        headers += L"Cookie: " + _sessionCookies + L"\r\n";
    }

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
        LOG("WinHttpSendRequest failed: %d", GetLastError());
        goto cleanup;
    }

    // Receive response
    bResult = WinHttpReceiveResponse(hRequest, nullptr);
    if (!bResult)
    {
        LOG("WinHttpReceiveResponse failed: %d", GetLastError());
        goto cleanup;
    }

    // Extract ALL cookies from response headers
    {
        DWORD dwIndex = 0;
        while (true)
        {
            DWORD dwCookieSize = 0;
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_SET_COOKIE, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &dwCookieSize, &dwIndex);
            
            if (GetLastError() == ERROR_WINHTTP_HEADER_NOT_FOUND)
            {
                break;  // No more cookies
            }
            
            if (dwCookieSize > 0)
            {
                std::vector<wchar_t> cookieBuffer(dwCookieSize / sizeof(wchar_t) + 1);
                DWORD tempIndex = dwIndex;  // WinHttpQueryHeaders modifies the index
                if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_SET_COOKIE, WINHTTP_HEADER_NAME_BY_INDEX, &cookieBuffer[0], &dwCookieSize, &tempIndex))
                {
                    std::wstring fullCookie = &cookieBuffer[0];
                    
                    // Extract just the name=value part (before the first semicolon)
                    size_t semicolonPos = fullCookie.find(L';');
                    std::wstring cookieValue = (semicolonPos != std::wstring::npos) 
                        ? fullCookie.substr(0, semicolonPos) 
                        : fullCookie;
                    
                    // Add to session cookies if not empty
                    if (!cookieValue.empty())
                    {
                        if (!_sessionCookies.empty()) _sessionCookies += L"; ";
                        _sessionCookies += cookieValue;
                        LOG("Cookie captured: %S", cookieValue.c_str());
                    }
                }
            }
            dwIndex++;
        }
        
        if (!_sessionCookies.empty())
        {
            LOG("Total session cookies: %S", _sessionCookies.substr(0, 200).c_str());
        }
    }

    // Read response body
    {
        DWORD dwSize = 0;
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
            int wideSize = MultiByteToWideChar(CP_UTF8, 0, &responseBuffer[0], -1, nullptr, 0);
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

// Make HTTP request to Certificate Issuer service
HRESULT AuthentikAPI::_MakeCertRequest(
    const std::wstring& url,
    const std::wstring& payload,
    std::wstring& responseBody)
{
    LOG("CertRequest: POST %S", url.c_str());

    HRESULT hr = E_FAIL;
    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;
    HINTERNET hRequest = nullptr;

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

    // Connect to certificate issuer server
    hConnect = WinHttpConnect(
        hSession,
        _certIssuerUrl.c_str(),
        _certIssuerPort,
        0);

    if (!hConnect)
    {
        LOG("WinHttpConnect to cert issuer failed: %d", GetLastError());
        WinHttpCloseHandle(hSession);
        return E_FAIL;
    }

    // Create request (HTTP for now - cert issuer runs locally)
    hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",
        url.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);  // No HTTPS flag for local service

    if (!hRequest)
    {
        LOG("WinHttpOpenRequest failed: %d", GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return E_FAIL;
    }

    // Build headers with authorization
    std::wstring headers = L"Content-Type: application/json\r\n";
    headers += L"Authorization: Bearer " + _certIssuerToken + L"\r\n";

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
        (LPVOID)payloadUtf8.c_str(),
        (DWORD)payloadUtf8.length(),
        (DWORD)payloadUtf8.length(),
        0);

    if (!bResult)
    {
        LOG("WinHttpSendRequest failed: %d", GetLastError());
        goto cleanup;
    }

    // Receive response
    bResult = WinHttpReceiveResponse(hRequest, nullptr);
    if (!bResult)
    {
        LOG("WinHttpReceiveResponse failed: %d", GetLastError());
        goto cleanup;
    }

    // Read response body
    {
        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;
        std::vector<char> responseBuffer;

        do
        {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                break;

            if (dwSize == 0)
                break;

            std::vector<char> tempBuffer(dwSize + 1);
            ZeroMemory(&tempBuffer[0], dwSize + 1);

            if (!WinHttpReadData(hRequest, &tempBuffer[0], dwSize, &dwDownloaded))
                break;

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
                
                LOG("Cert response received: %d bytes", responseBuffer.size());
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

// Parse Authentik API response
AuthentikResponse AuthentikAPI::_ParseAuthentikResponse(const std::wstring& json)
{
    LOG("Parsing Authentik response");
    
    // Log response preview for debugging (first 500 chars)
    std::wstring preview = json.substr(0, min((size_t)500, json.length()));
    LOG("Response preview: %S", preview.c_str());

    AuthentikResponse response;
    response.success = false;
    response.requiresOTP = false;

    // Check for success (redirect type indicates flow complete) - CHECK FIRST
    if (json.find(L"\"type\":\"redirect\"") != std::wstring::npos)
    {
        response.success = true;
        response.message = L"Authentication successful";
        LOG("Parsed: Authentication successful (redirect)");
        return response;  // Return immediately on success
    }
    // Check for xak-flow-redirect component (Authentik flow completion)
    if (json.find(L"xak-flow-redirect") != std::wstring::npos)
    {
        response.success = true;
        response.message = L"Authentication successful";
        LOG("Parsed: Authentication successful (xak-flow-redirect)");
        return response;
    }
    // Check for native flow completion
    if (json.find(L"\"type\":\"native\"") != std::wstring::npos && 
        json.find(L"\"to\":\"") != std::wstring::npos)
    {
        response.success = true;
        response.message = L"Authentication successful";
        LOG("Parsed: Authentication successful (native)");
        return response;
    }
    // Check for shell (flow complete with shell response)
    if (json.find(L"\"type\":\"shell\"") != std::wstring::npos)
    {
        response.success = true;
        response.message = L"Authentication successful";
        LOG("Parsed: Authentication successful (shell)");
        return response;
    }
    // Check for OTP/authenticator challenge
    if (json.find(L"ak-stage-authenticator-validate") != std::wstring::npos ||
        json.find(L"authenticator_validate") != std::wstring::npos ||
        json.find(L"\"component\":\"ak-stage-authenticator") != std::wstring::npos)
    {
        response.requiresOTP = true;
        response.message = L"Enter your authentication code";
        
        // Try to extract flow token
        response.flowToken = _ExtractJsonString(json, L"flow_token");
        
        LOG("Parsed: OTP required");
        return response;
    }
    // Check for identification stage (username prompt)
    if (json.find(L"ak-stage-identification") != std::wstring::npos)
    {
        response.success = false;
        response.message = L"Enter username";
        LOG("Parsed: Identification stage");
        return response;
    }
    // Check for error
    if (json.find(L"\"error\"") != std::wstring::npos ||
        json.find(L"\"errors\"") != std::wstring::npos)
    {
        response.success = false;
        response.message = _ExtractJsonString(json, L"error");
        if (response.message.empty())
        {
            response.message = L"Authentication failed";
        }
        LOG("Parsed: Error - %S", response.message.c_str());
        return response;
    }

    // Unknown state - log for debugging
    response.success = false;
    response.message = L"Continue authentication...";
    LOG("Parsed: Unknown/continuing state - check response preview");

    return response;
}

// Parse Certificate Issuer response
CertificateResponse AuthentikAPI::_ParseCertificateResponse(const std::wstring& json)
{
    LOG("Parsing certificate response");

    CertificateResponse response;
    response.success = false;

    // Check for success
    std::wstring successStr = _ExtractJsonString(json, L"success");
    response.success = (successStr == L"true");

    if (response.success)
    {
        // Extract certificate data
        response.thumbprint = _ExtractJsonString(json, L"thumbprint");
        response.subject = _ExtractJsonString(json, L"subject");
        response.upn = _ExtractJsonString(json, L"upn");
        response.pfxPassword = _ExtractJsonString(json, L"pfx_password");
        response.notBefore = _ExtractJsonString(json, L"not_before");
        response.notAfter = _ExtractJsonString(json, L"not_after");

        // Decode PFX data from base64
        std::wstring pfxBase64 = _ExtractJsonString(json, L"pfx_base64");
        if (!pfxBase64.empty())
        {
            response.pfxData = _Base64Decode(pfxBase64);
            LOG("PFX data decoded: %d bytes", response.pfxData.size());
        }

        response.message = L"Certificate issued successfully";
        LOG("Certificate parsed: thumbprint=%S, subject=%S", response.thumbprint.c_str(), response.subject.c_str());
    }
    else
    {
        response.message = _ExtractJsonString(json, L"error");
        if (response.message.empty())
        {
            response.message = L"Certificate issuance failed";
        }
        LOG("Certificate error: %S", response.message.c_str());
    }

    return response;
}

// Extract JSON string value (simple parser - handles basic cases)
std::wstring AuthentikAPI::_ExtractJsonString(const std::wstring& json, const std::wstring& key)
{
    std::wstring searchKey = L"\"" + key + L"\":";
    size_t keyPos = json.find(searchKey);
    
    if (keyPos == std::wstring::npos)
    {
        // Try with space after colon
        searchKey = L"\"" + key + L"\": ";
        keyPos = json.find(searchKey);
    }

    if (keyPos == std::wstring::npos)
        return L"";

    size_t valueStart = keyPos + searchKey.length();
    
    // Skip whitespace
    while (valueStart < json.length() && (json[valueStart] == L' ' || json[valueStart] == L'\t'))
        valueStart++;

    if (valueStart >= json.length())
        return L"";

    // Check if value is a string (starts with quote)
    if (json[valueStart] == L'"')
    {
        valueStart++;
        size_t valueEnd = json.find(L'"', valueStart);
        if (valueEnd != std::wstring::npos)
        {
            return json.substr(valueStart, valueEnd - valueStart);
        }
    }
    // Check if value is a boolean or number
    else
    {
        size_t valueEnd = json.find_first_of(L",}\n\r", valueStart);
        if (valueEnd != std::wstring::npos)
        {
            std::wstring value = json.substr(valueStart, valueEnd - valueStart);
            // Trim whitespace
            while (!value.empty() && (value.back() == L' ' || value.back() == L'\t'))
                value.pop_back();
            return value;
        }
    }

    return L"";
}

// Base64 decode
std::vector<BYTE> AuthentikAPI::_Base64Decode(const std::wstring& base64)
{
    std::vector<BYTE> result;

    if (base64.empty())
        return result;

    // Convert to narrow string
    std::string base64Narrow;
    for (wchar_t c : base64)
    {
        if (c < 128)
            base64Narrow += (char)c;
    }

    // Calculate required buffer size
    DWORD dwSize = 0;
    if (!CryptStringToBinaryA(
        base64Narrow.c_str(),
        (DWORD)base64Narrow.length(),
        CRYPT_STRING_BASE64,
        nullptr,
        &dwSize,
        nullptr,
        nullptr))
    {
        LOG("CryptStringToBinaryA size query failed: %d", GetLastError());
        return result;
    }

    // Decode
    result.resize(dwSize);
    if (!CryptStringToBinaryA(
        base64Narrow.c_str(),
        (DWORD)base64Narrow.length(),
        CRYPT_STRING_BASE64,
        result.data(),
        &dwSize,
        nullptr,
        nullptr))
    {
        LOG("CryptStringToBinaryA decode failed: %d", GetLastError());
        result.clear();
    }

    return result;
}
