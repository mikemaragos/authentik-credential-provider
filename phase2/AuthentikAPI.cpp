// AuthentikAPI.cpp
// HTTP client for Authentik and CertIssuer API communication
// Phase 2: Passwordless certificate-based authentication
// Updated December 8, 2025

#include "AuthentikAPI.h"
#include "Logger.h"
#include <wincrypt.h>
#include <objbase.h>
#include <sstream>
#include <algorithm>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ole32.lib")

// Constructor
AuthentikAPI::AuthentikAPI() :
    _authentikServer(L"authentik.test.local"),
    _authentikPort(443),
    _flowSlug(L"windows-otp-auth"),
    _useHttps(true),
    _certIssuerServer(L"192.168.1.101"),
    _certIssuerPort(8443),
    _certIssuerApiToken(L"")
{
    LOG("AuthentikAPI::Constructor");
    _LoadConfiguration();
}

// Destructor
AuthentikAPI::~AuthentikAPI()
{
    LOG("AuthentikAPI::Destructor");
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

        // Authentik server settings
        bufferSize = sizeof(buffer);
        if (RegQueryValueExW(hKey, L"AuthentikServer", nullptr, nullptr, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS)
        {
            _authentikServer = buffer;
            LOG("AuthentikServer: %S", _authentikServer.c_str());
        }

        DWORD port = 443;
        bufferSize = sizeof(DWORD);
        if (RegQueryValueExW(hKey, L"AuthentikPort", nullptr, nullptr, (LPBYTE)&port, &bufferSize) == ERROR_SUCCESS)
        {
            _authentikPort = (INTERNET_PORT)port;
            LOG("AuthentikPort: %d", _authentikPort);
        }

        bufferSize = sizeof(buffer);
        if (RegQueryValueExW(hKey, L"FlowSlug", nullptr, nullptr, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS)
        {
            _flowSlug = buffer;
            LOG("FlowSlug: %S", _flowSlug.c_str());
        }

        DWORD useHttps = 1;
        bufferSize = sizeof(DWORD);
        if (RegQueryValueExW(hKey, L"UseHttps", nullptr, nullptr, (LPBYTE)&useHttps, &bufferSize) == ERROR_SUCCESS)
        {
            _useHttps = (useHttps != 0);
            LOG("UseHttps: %d", _useHttps);
        }

        // CertIssuer server settings
        bufferSize = sizeof(buffer);
        if (RegQueryValueExW(hKey, L"CertIssuerServer", nullptr, nullptr, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS)
        {
            _certIssuerServer = buffer;
            LOG("CertIssuerServer: %S", _certIssuerServer.c_str());
        }

        port = 8443;
        bufferSize = sizeof(DWORD);
        if (RegQueryValueExW(hKey, L"CertIssuerPort", nullptr, nullptr, (LPBYTE)&port, &bufferSize) == ERROR_SUCCESS)
        {
            _certIssuerPort = (INTERNET_PORT)port;
            LOG("CertIssuerPort: %d", _certIssuerPort);
        }

        bufferSize = sizeof(buffer);
        if (RegQueryValueExW(hKey, L"CertIssuerApiToken", nullptr, nullptr, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS)
        {
            _certIssuerApiToken = buffer;
            LOG("CertIssuerApiToken: (loaded, %d chars)", _certIssuerApiToken.length());
        }

        RegCloseKey(hKey);
    }
    else
    {
        LOG("Failed to open registry key: %d (using defaults)", result);
    }
}

// Validate OTP with Authentik
AuthentikResponse AuthentikAPI::ValidateOTP(const std::wstring& username, const std::wstring& otp)
{
    LOG("ValidateOTP: user=%S", username.c_str());

    AuthentikResponse response;
    response.success = false;

    // Build request URL for Authentik flow
    std::wstring url = L"/api/v3/flows/executor/" + _flowSlug + L"/";

    std::wstring responseBody;
    std::wstring payload;
    HRESULT hr;

    // Step 1: GET the flow to initialize and see what stage we're on
    LOG("ValidateOTP: Step 1 - GET flow to initialize");
    hr = _MakeHttpRequest(
        _authentikServer,
        _authentikPort,
        _useHttps,
        L"GET",
        url,
        L"",
        L"",
        responseBody);

    if (FAILED(hr))
    {
        LOG("ValidateOTP: GET flow failed: 0x%08x", hr);
        response.message = L"Failed to connect to authentication server";
        return response;
    }

    LOG("ValidateOTP: GET response length=%d", (int)responseBody.length());
    if (responseBody.length() < 300)
    {
        LOG("ValidateOTP: GET response: %S", responseBody.c_str());
    }

    // Step 2: POST username to identification stage
    LOG("ValidateOTP: Step 2 - POST username");
    payload = L"{\"uid_field\":\"" + username + L"\"}";
    hr = _MakeHttpRequest(
        _authentikServer,
        _authentikPort,
        _useHttps,
        L"POST",
        url,
        payload,
        L"",
        responseBody);

    // Log response even on failure
    if (!responseBody.empty())
    {
        if (responseBody.length() < 500)
        {
            LOG("ValidateOTP: POST response: %S", responseBody.c_str());
        }
        else
        {
            LOG("ValidateOTP: POST response (truncated): %S...", responseBody.substr(0, 500).c_str());
        }
    }

    if (FAILED(hr))
    {
        LOG("ValidateOTP: POST username failed: 0x%08x", hr);
        response.message = L"Failed to submit username";
        return response;
    }

    LOG("ValidateOTP: Username response length=%d", (int)responseBody.length());
    if (responseBody.length() < 500)
    {
        LOG("ValidateOTP: Username response: %S", responseBody.c_str());
    }
    else
    {
        LOG("ValidateOTP: Username response (truncated): %S...", responseBody.substr(0, 500).c_str());
    }

    // Check if we got a redirect (no password/OTP required)
    if (responseBody.find(L"\"type\"") != std::wstring::npos && 
        responseBody.find(L"\"redirect\"") != std::wstring::npos)
    {
        LOG("ValidateOTP: Got redirect after username - flow complete");
        response.success = true;
        response.message = L"Authentication successful";
        return response;
    }

    // Check if password stage is shown (we need to skip or handle)
    if (responseBody.find(L"ak-stage-password") != std::wstring::npos ||
        responseBody.find(L"\"password\"") != std::wstring::npos)
    {
        LOG("ValidateOTP: Password stage detected - flow not configured for passwordless");
        response.message = L"Flow requires password - configure for passwordless";
        return response;
    }

    // Step 3: POST OTP code
    LOG("ValidateOTP: Step 3 - POST OTP code");
    payload = L"{\"code\":\"" + otp + L"\"}";
    hr = _MakeHttpRequest(
        _authentikServer,
        _authentikPort,
        _useHttps,
        L"POST",
        url,
        payload,
        L"",
        responseBody);

    if (FAILED(hr))
    {
        LOG("ValidateOTP: POST OTP failed: 0x%08x", hr);
        response.message = L"Failed to validate OTP";
        return response;
    }

    LOG("ValidateOTP: OTP response length=%d", (int)responseBody.length());
    if (responseBody.length() < 500)
    {
        LOG("ValidateOTP: OTP response: %S", responseBody.c_str());
    }
    else
    {
        LOG("ValidateOTP: OTP response (truncated): %S...", responseBody.substr(0, 500).c_str());
    }

    // Parse final response
    response = _ParseOTPResponse(responseBody);
    LOG("ValidateOTP response: success=%d", response.success);

    return response;
}

// Request certificate from CertIssuer
CertificateResponse AuthentikAPI::RequestCertificate(const std::wstring& username, const std::wstring& domain)
{
    LOG("RequestCertificate: user=%S, domain=%S", username.c_str(), domain.c_str());

    CertificateResponse response;
    response.success = false;
    response.adMappingUpdated = false;

    // Build request URL
    std::wstring url = L"/api/v1/certificate/issue";

    // Build JSON payload
    std::wstring payload = L"{\"username\":\"" + username + L"\",\"domain\":\"" + domain + L"\"}";

    // Build auth header
    std::wstring authHeader = L"Bearer " + _certIssuerApiToken;

    std::wstring responseBody;
    HRESULT hr = _MakeHttpRequest(
        _certIssuerServer,
        _certIssuerPort,
        false,  // CertIssuer uses HTTP
        L"POST",
        url,
        payload,
        authHeader,
        responseBody);

    if (FAILED(hr))
    {
        LOG("RequestCertificate: HTTP request failed: 0x%08x", hr);
        response.message = L"Failed to connect to certificate issuer";
        return response;
    }

    // Parse response
    response = _ParseCertificateResponse(responseBody);
    LOG("RequestCertificate: success=%d, ski=%S", response.success, response.subjectKeyIdentifier.c_str());

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

    // Step 1: Validate OTP with Authentik
    AuthentikResponse otpResponse = ValidateOTP(username, otp);
    if (!otpResponse.success)
    {
        LOG("AuthenticateAndGetCertificate: OTP validation failed");
        certResponse.message = otpResponse.message;
        return certResponse;
    }

    LOG("AuthenticateAndGetCertificate: OTP validated, requesting certificate");

    // Step 2: Request certificate from CertIssuer
    certResponse = RequestCertificate(username, domain);

    return certResponse;
}

// Make HTTP request
HRESULT AuthentikAPI::_MakeHttpRequest(
    const std::wstring& server,
    INTERNET_PORT port,
    bool useHttps,
    const std::wstring& method,
    const std::wstring& path,
    const std::wstring& payload,
    const std::wstring& authHeader,
    std::wstring& responseBody)
{
    LOG("HTTP %S %S:%d%S", method.c_str(), server.c_str(), port, path.c_str());

    HRESULT hr = E_FAIL;
    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;
    HINTERNET hRequest = nullptr;
    DWORD httpStatusCode = 0;

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
    DWORD dwFlags = useHttps ? WINHTTP_FLAG_SECURE : 0;
    hRequest = WinHttpOpenRequest(
        hConnect,
        method.c_str(),
        path.c_str(),
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
    if (useHttps)
    {
        DWORD dwSecFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwSecFlags, sizeof(dwSecFlags));
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

    // Check HTTP status code
    {
        DWORD statusCodeSize = sizeof(httpStatusCode);
        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                               WINHTTP_HEADER_NAME_BY_INDEX, &httpStatusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX))
        {
            LOG("HTTP Status Code: %d", httpStatusCode);
            if (httpStatusCode >= 400)
            {
                LOG("HTTP Error: %d", httpStatusCode);
            }
        }
    }

    // Store cookies from response
    {
        WCHAR cookieBuffer[4096];
        DWORD cookieSize = sizeof(cookieBuffer);
        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_SET_COOKIE, WINHTTP_HEADER_NAME_BY_INDEX,
                               cookieBuffer, &cookieSize, WINHTTP_NO_HEADER_INDEX))
        {
            _sessionCookies = cookieBuffer;
            LOG("Session cookies updated");
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
                break;
            if (dwSize == 0)
                break;

            std::vector<char> tempBuffer(dwSize + 1, 0);
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
                LOG("Response received: %d bytes", responseBuffer.size());
                hr = S_OK;
            }
            else
            {
                LOG("MultiByteToWideChar failed for response");
                hr = E_FAIL;
            }
        }
        else
        {
            // Empty response body - still consider success if HTTP status is OK
            LOG("Response body is empty");
            if (httpStatusCode >= 200 && httpStatusCode < 300)
            {
                hr = S_OK;
            }
            else
            {
                hr = HRESULT_FROM_WIN32(httpStatusCode);
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
    
    // Log the actual response for debugging (truncate if too long)
    if (json.length() < 500)
    {
        LOG("Response body: %S", json.c_str());
    }
    else
    {
        LOG("Response body (first 500 chars): %S...", json.substr(0, 500).c_str());
    }

    AuthentikResponse response;
    response.success = false;

    // Check for success - multiple patterns
    // Authentik returns "type": "redirect" when flow completes successfully
    if (json.find(L"\"type\"") != std::wstring::npos && json.find(L"\"redirect\"") != std::wstring::npos)
    {
        response.success = true;
        response.message = L"OTP validated successfully";
        LOG("OTP validation successful (redirect)");
    }
    // Also check for "to" field which indicates redirect destination
    else if (json.find(L"\"to\"") != std::wstring::npos && json.find(L"\"type\"") != std::wstring::npos)
    {
        response.success = true;
        response.message = L"OTP validated successfully";
        LOG("OTP validation successful (to field present)");
    }
    // Check for response_errors which indicates validation failure
    else if (json.find(L"\"response_errors\"") != std::wstring::npos)
    {
        response.message = L"OTP validation failed - invalid code";
        LOG("OTP validation failed - response_errors present");
    }
    // Check for "error" field
    else if (json.find(L"\"error\"") != std::wstring::npos)
    {
        response.message = L"OTP validation failed";
        LOG("OTP validation failed - error field present");
    }
    // Check if we're getting another challenge (need more auth steps)
    else if (json.find(L"ak-stage-") != std::wstring::npos || json.find(L"\"component\"") != std::wstring::npos)
    {
        // This could mean we need another authentication step
        // Or the OTP was accepted but flow continues
        // For now, check if it's asking for authenticator again (failure)
        if (json.find(L"ak-stage-authenticator-validate") != std::wstring::npos)
        {
            response.message = L"OTP validation failed - code rejected";
            LOG("OTP rejected - same stage returned");
        }
        else
        {
            // Different stage - assume OTP was accepted
            response.success = true;
            response.message = L"OTP validated, flow continuing";
            LOG("OTP accepted, flow continuing to next stage");
        }
    }
    else
    {
        response.message = L"Unknown response from authentication server";
        LOG("Unknown response format");
    }

    return response;
}

// Parse certificate response from CertIssuer
CertificateResponse AuthentikAPI::_ParseCertificateResponse(const std::wstring& json)
{
    LOG("Parsing certificate response");

    CertificateResponse response;
    response.success = false;
    response.adMappingUpdated = false;

    // Check for success
    response.success = _ExtractJsonBool(json, L"success");
    
    if (!response.success)
    {
        response.message = _ExtractJsonValue(json, L"error");
        if (response.message.empty())
        {
            response.message = L"Certificate issuance failed";
        }
        LOG("Certificate issuance failed: %S", response.message.c_str());
        return response;
    }

    // Extract PFX (base64 encoded)
    std::wstring pfxBase64 = _ExtractJsonValue(json, L"pfx");
    if (!pfxBase64.empty())
    {
        response.pfxData = _Base64Decode(pfxBase64);
        LOG("PFX decoded: %d bytes", response.pfxData.size());
    }

    // Extract PFX password
    response.pfxPassword = _ExtractJsonValue(json, L"pfx_password");
    LOG("PFX password: %d chars", response.pfxPassword.length());

    // Extract certificate DER (base64 encoded)
    std::wstring certBase64 = _ExtractJsonValue(json, L"certificate");
    if (!certBase64.empty())
    {
        response.certificateDer = _Base64Decode(certBase64);
        LOG("Certificate DER decoded: %d bytes", response.certificateDer.size());
    }

    // Extract metadata
    response.subjectKeyIdentifier = _ExtractJsonValue(json, L"ski");
    response.thumbprint = _ExtractJsonValue(json, L"thumbprint");
    response.upn = _ExtractJsonValue(json, L"upn");
    response.adMappingUpdated = _ExtractJsonBool(json, L"ad_mapping_updated");

    LOG("Certificate parsed: SKI=%S, thumbprint=%S, AD updated=%d",
        response.subjectKeyIdentifier.c_str(),
        response.thumbprint.c_str(),
        response.adMappingUpdated);

    response.message = L"Certificate issued successfully";
    return response;
}

// Extract string value from JSON
std::wstring AuthentikAPI::_ExtractJsonValue(const std::wstring& json, const std::wstring& key)
{
    std::wstring searchKey = L"\"" + key + L"\":";
    size_t pos = json.find(searchKey);
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
        size_t endPos = pos;
        while (endPos < json.length() && json[endPos] != L'"')
        {
            if (json[endPos] == L'\\' && endPos + 1 < json.length())
                endPos++; // Skip escaped character
            endPos++;
        }
        return json.substr(pos, endPos - pos);
    }

    // Value is not a string, read until delimiter
    size_t endPos = pos;
    while (endPos < json.length() && json[endPos] != L',' && json[endPos] != L'}' && json[endPos] != L'\n')
        endPos++;

    return json.substr(pos, endPos - pos);
}

// Extract boolean value from JSON
bool AuthentikAPI::_ExtractJsonBool(const std::wstring& json, const std::wstring& key)
{
    std::wstring value = _ExtractJsonValue(json, key);
    return (value == L"true" || value == L"True" || value == L"1");
}

// Base64 decode
std::vector<BYTE> AuthentikAPI::_Base64Decode(const std::wstring& base64)
{
    std::vector<BYTE> result;
    
    if (base64.empty())
        return result;

    // Convert wide string to narrow for CryptStringToBinaryW
    DWORD cbBinary = 0;
    if (!CryptStringToBinaryW(
        base64.c_str(),
        (DWORD)base64.length(),
        CRYPT_STRING_BASE64,
        nullptr,
        &cbBinary,
        nullptr,
        nullptr))
    {
        LOG("Base64 decode size query failed: %d", GetLastError());
        return result;
    }

    result.resize(cbBinary);
    if (!CryptStringToBinaryW(
        base64.c_str(),
        (DWORD)base64.length(),
        CRYPT_STRING_BASE64,
        &result[0],
        &cbBinary,
        nullptr,
        nullptr))
    {
        LOG("Base64 decode failed: %d", GetLastError());
        result.clear();
        return result;
    }

    result.resize(cbBinary);
    return result;
}
