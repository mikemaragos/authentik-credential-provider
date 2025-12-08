// AuthentikAPI.cpp
// HTTP client for Authentik API communication - Phase 2 (Passwordless with Certificate)

#include "AuthentikAPI.h"
#include "Logger.h"
#include <winhttp.h>
#include <wincrypt.h>
#include <sstream>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")

// Constructor
AuthentikAPI::AuthentikAPI() :
    _authentikServer(L"authentik.test.local"),
    _authentikPort(443),
    _flowSlug(L"windows-otp-auth"),
    _useHttps(true),
    _certIssuerServer(L"authentik.test.local"),
    _certIssuerPort(8443),
    _certIssuerApiToken(L"")
{
    LOG("AuthentikAPI::Constructor (Phase 2)");
    _LoadConfiguration();
}

// Destructor
AuthentikAPI::~AuthentikAPI()
{
    LOG("AuthentikAPI::Destructor");
    // Clear sensitive data
    SecureZeroMemory(&_certIssuerApiToken[0], _certIssuerApiToken.length() * sizeof(wchar_t));
}

// Validate OTP with Authentik
AuthentikResponse AuthentikAPI::ValidateOTP(const std::wstring& username, const std::wstring& otp)
{
    LOG("ValidateOTP: user=%S", username.c_str());

    AuthentikResponse response;
    response.success = false;

    // Build request URL for Authentik flow executor
    std::wstring url = L"/api/v3/flows/executor/" + _flowSlug + L"/";

    // Step 1: Send username to identify user
    std::wstring payload = L"{\"uid_field\":\"" + username + L"\"}";
    std::wstring responseBody;
    
    HRESULT hr = _MakeHttpRequest(_authentikServer, _authentikPort, L"POST", url, payload, responseBody);
    if (FAILED(hr))
    {
        LOG("Failed to initiate auth: 0x%08x", hr);
        response.message = L"Failed to connect to authentication server";
        return response;
    }

    // Check if we got OTP challenge
    if (responseBody.find(L"ak-stage-authenticator-validate") == std::wstring::npos &&
        responseBody.find(L"otp") == std::wstring::npos)
    {
        LOG("Unexpected response - no OTP challenge");
        response.message = L"Authentication flow error";
        return response;
    }

    // Step 2: Send OTP code
    payload = L"{\"code\":\"" + otp + L"\"}";
    hr = _MakeHttpRequest(_authentikServer, _authentikPort, L"POST", url, payload, responseBody);
    
    if (FAILED(hr))
    {
        LOG("Failed to validate OTP: 0x%08x", hr);
        response.message = L"Failed to validate OTP";
        return response;
    }

    // Parse response
    response = _ParseOTPResponse(responseBody);
    LOG("ValidateOTP result: success=%d", response.success);

    return response;
}

// Request certificate from CertIssuer
CertificateResponse AuthentikAPI::RequestCertificate(const std::wstring& username, const std::wstring& domain)
{
    LOG("RequestCertificate: user=%S, domain=%S", username.c_str(), domain.c_str());

    CertificateResponse response;
    response.success = false;

    // Build request to CertIssuer API
    std::wstring url = L"/api/v1/certificate/issue";

    // Build JSON payload
    std::wstring payload = L"{";
    payload += L"\"username\":\"" + username + L"\",";
    payload += L"\"domain\":\"" + domain + L"\",";
    payload += L"\"template\":\"AuthentikSmartcard\"";
    payload += L"}";

    std::wstring responseBody;
    std::vector<BYTE> binaryResponse;

    HRESULT hr = _MakeHttpRequest(
        _certIssuerServer, 
        _certIssuerPort, 
        L"POST", 
        url, 
        payload, 
        responseBody,
        &binaryResponse);

    if (FAILED(hr))
    {
        LOG("Failed to request certificate: 0x%08x", hr);
        response.message = L"Failed to connect to certificate issuer";
        return response;
    }

    // Parse response
    response = _ParseCertificateResponse(responseBody, binaryResponse);
    LOG("RequestCertificate result: success=%d, certSize=%d", 
        response.success, response.certificateDer.size());

    return response;
}

// Combined: Validate OTP and get certificate
CertificateResponse AuthentikAPI::AuthenticateAndGetCertificate(
    const std::wstring& username, 
    const std::wstring& otp,
    const std::wstring& domain)
{
    LOG("AuthenticateAndGetCertificate: user=%S", username.c_str());

    CertificateResponse certResponse;
    certResponse.success = false;

    // Step 1: Validate OTP
    AuthentikResponse otpResponse = ValidateOTP(username, otp);
    if (!otpResponse.success)
    {
        certResponse.message = otpResponse.message;
        return certResponse;
    }

    // Step 2: Request certificate (CertIssuer will also update AD mapping)
    certResponse = RequestCertificate(username, domain);

    return certResponse;
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
        WCHAR buffer[256];
        DWORD bufferSize;

        // Authentik server
        bufferSize = sizeof(buffer);
        result = RegQueryValueExW(hKey, L"AuthentikServer", nullptr, nullptr, (LPBYTE)buffer, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _authentikServer = buffer;
            LOG("AuthentikServer: %S", _authentikServer.c_str());
        }

        // Authentik port
        DWORD port = 443;
        bufferSize = sizeof(DWORD);
        result = RegQueryValueExW(hKey, L"AuthentikPort", nullptr, nullptr, (LPBYTE)&port, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _authentikPort = (INTERNET_PORT)port;
            LOG("AuthentikPort: %d", _authentikPort);
        }

        // Flow slug
        bufferSize = sizeof(buffer);
        result = RegQueryValueExW(hKey, L"FlowSlug", nullptr, nullptr, (LPBYTE)buffer, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _flowSlug = buffer;
            LOG("FlowSlug: %S", _flowSlug.c_str());
        }

        // HTTPS flag
        DWORD useHttps = 1;
        bufferSize = sizeof(DWORD);
        result = RegQueryValueExW(hKey, L"UseHttps", nullptr, nullptr, (LPBYTE)&useHttps, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _useHttps = (useHttps != 0);
            LOG("UseHttps: %d", _useHttps);
        }

        // CertIssuer server
        bufferSize = sizeof(buffer);
        result = RegQueryValueExW(hKey, L"CertIssuerServer", nullptr, nullptr, (LPBYTE)buffer, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _certIssuerServer = buffer;
            LOG("CertIssuerServer: %S", _certIssuerServer.c_str());
        }

        // CertIssuer port
        port = 8443;
        bufferSize = sizeof(DWORD);
        result = RegQueryValueExW(hKey, L"CertIssuerPort", nullptr, nullptr, (LPBYTE)&port, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _certIssuerPort = (INTERNET_PORT)port;
            LOG("CertIssuerPort: %d", _certIssuerPort);
        }

        // CertIssuer API token
        bufferSize = sizeof(buffer);
        result = RegQueryValueExW(hKey, L"CertIssuerApiToken", nullptr, nullptr, (LPBYTE)buffer, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _certIssuerApiToken = buffer;
            LOG("CertIssuerApiToken: (loaded)");
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
    const std::wstring& server,
    INTERNET_PORT port,
    const std::wstring& method,
    const std::wstring& url,
    const std::wstring& payload,
    std::wstring& responseBody,
    std::vector<BYTE>* binaryResponse)
{
    LOG("HTTP %S %S:%d%S", method.c_str(), server.c_str(), port, url.c_str());

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
    hConnect = WinHttpConnect(hSession, server.c_str(), port, 0);
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
        
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwSecFlags, sizeof(dwSecFlags));
        LOG("WARNING: SSL certificate validation disabled");
    }

    // Set headers
    std::wstring headers = L"Content-Type: application/json\r\n";
    
    // Add session cookies if we have them
    if (!_sessionCookies.empty())
    {
        headers += L"Cookie: " + _sessionCookies + L"\r\n";
    }

    // Add API token for CertIssuer
    if (!_certIssuerApiToken.empty() && server == _certIssuerServer)
    {
        headers += L"Authorization: Bearer " + _certIssuerApiToken + L"\r\n";
    }

    WinHttpAddRequestHeaders(hRequest, headers.c_str(), (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);

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

    // Extract cookies from response headers
    {
        DWORD dwSize = 0;
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_SET_COOKIE, WINHTTP_HEADER_NAME_BY_INDEX, 
                           nullptr, &dwSize, WINHTTP_NO_HEADER_INDEX);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && dwSize > 0)
        {
            std::vector<wchar_t> cookieBuffer(dwSize / sizeof(wchar_t) + 1);
            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_SET_COOKIE, WINHTTP_HEADER_NAME_BY_INDEX,
                                   &cookieBuffer[0], &dwSize, WINHTTP_NO_HEADER_INDEX))
            {
                _sessionCookies = &cookieBuffer[0];
                LOG("Cookies saved");
            }
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

        // Store binary response if requested
        if (binaryResponse && !responseBuffer.empty())
        {
            binaryResponse->assign(responseBuffer.begin(), responseBuffer.end());
        }

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

// Parse OTP validation response
AuthentikResponse AuthentikAPI::_ParseOTPResponse(const std::wstring& json)
{
    LOG("Parsing OTP response");

    AuthentikResponse response;
    response.success = false;

    // Check for success (redirect type indicates successful auth)
    if (json.find(L"\"type\":\"redirect\"") != std::wstring::npos)
    {
        response.success = true;
        response.message = L"OTP validated successfully";
        LOG("OTP validation successful");
    }
    else if (json.find(L"\"error\"") != std::wstring::npos)
    {
        response.success = false;
        response.message = L"Invalid OTP code";
        LOG("OTP validation failed");
    }
    else
    {
        response.success = false;
        response.message = L"Unknown response";
        LOG("Unknown OTP response format");
    }

    return response;
}

// Parse certificate response
CertificateResponse AuthentikAPI::_ParseCertificateResponse(const std::wstring& json, const std::vector<BYTE>& binaryData)
{
    LOG("Parsing certificate response");

    CertificateResponse response;
    response.success = false;

    // Check for success
    if (json.find(L"\"success\":true") != std::wstring::npos ||
        json.find(L"\"success\": true") != std::wstring::npos)
    {
        response.success = true;

        // Extract certificate (base64 encoded)
        std::wstring certB64 = _ExtractJsonValue(json, L"certificate");
        if (!certB64.empty())
        {
            response.certificateDer = _Base64Decode(certB64);
            LOG("Certificate extracted: %d bytes", response.certificateDer.size());
        }

        // Extract private key (base64 encoded PKCS#8 or blob)
        std::wstring keyB64 = _ExtractJsonValue(json, L"private_key");
        if (!keyB64.empty())
        {
            response.privateKeyBlob = _Base64Decode(keyB64);
            LOG("Private key extracted: %d bytes", response.privateKeyBlob.size());
        }

        // Extract SKI
        response.subjectKeyIdentifier = _ExtractJsonValue(json, L"ski");
        LOG("SKI: %S", response.subjectKeyIdentifier.c_str());

        response.message = L"Certificate issued successfully";
    }
    else
    {
        response.message = _ExtractJsonValue(json, L"error");
        if (response.message.empty())
        {
            response.message = L"Failed to issue certificate";
        }
        LOG("Certificate issuance failed: %S", response.message.c_str());
    }

    return response;
}

// Extract value from simple JSON
std::wstring AuthentikAPI::_ExtractJsonValue(const std::wstring& json, const std::wstring& key)
{
    std::wstring searchKey = L"\"" + key + L"\":";
    size_t pos = json.find(searchKey);
    if (pos == std::wstring::npos)
    {
        searchKey = L"\"" + key + L"\": ";
        pos = json.find(searchKey);
    }
    
    if (pos == std::wstring::npos)
        return L"";

    pos += searchKey.length();
    
    // Skip whitespace
    while (pos < json.length() && (json[pos] == L' ' || json[pos] == L'\t'))
        pos++;

    if (pos >= json.length())
        return L"";

    // Check if value is a string (starts with quote)
    if (json[pos] == L'"')
    {
        pos++; // Skip opening quote
        size_t endPos = json.find(L'"', pos);
        if (endPos != std::wstring::npos)
        {
            return json.substr(pos, endPos - pos);
        }
    }
    else
    {
        // Non-string value (number, boolean, etc.)
        size_t endPos = json.find_first_of(L",}", pos);
        if (endPos != std::wstring::npos)
        {
            return json.substr(pos, endPos - pos);
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

    // Convert to narrow string for CryptStringToBinaryW
    DWORD cbBinary = 0;
    
    // Get required size
    if (!CryptStringToBinaryW(
        base64.c_str(),
        (DWORD)base64.length(),
        CRYPT_STRING_BASE64,
        nullptr,
        &cbBinary,
        nullptr,
        nullptr))
    {
        LOG("CryptStringToBinaryW size query failed: %d", GetLastError());
        return result;
    }

    result.resize(cbBinary);

    // Decode
    if (!CryptStringToBinaryW(
        base64.c_str(),
        (DWORD)base64.length(),
        CRYPT_STRING_BASE64,
        &result[0],
        &cbBinary,
        nullptr,
        nullptr))
    {
        LOG("CryptStringToBinaryW decode failed: %d", GetLastError());
        result.clear();
    }

    return result;
}
