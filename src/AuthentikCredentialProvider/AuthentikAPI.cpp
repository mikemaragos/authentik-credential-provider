// AuthentikAPI.cpp
// HTTP client for Authentik API communication

#include "AuthentikAPI.h"
#include "Logger.h"
#include <winhttp.h>
#include <sstream>
#include <vector>

#pragma comment(lib, "winhttp.lib")

// Constructor
AuthentikAPI::AuthentikAPI() :
    _serverUrl(L""),  // Will be loaded from registry
    _serverPort(443),
    _flowSlug(L""),   // Will be loaded from registry
    _useHttps(true),
    _ignoreSslErrors(false)  // Secure by default
{
    LOG("AuthentikAPI::Constructor");
    _LoadConfiguration();
    
    // Validate critical configuration was loaded
    if (_serverUrl.empty())
    {
        LOG("ERROR: ServerUrl not configured in registry!");
        _serverUrl = L"localhost";  // Fallback to prevent crash
    }
    if (_flowSlug.empty())
    {
        LOG("ERROR: FlowSlug not configured in registry!");
        _flowSlug = L"default-authentication-flow";  // Fallback
    }
}

// Destructor
AuthentikAPI::~AuthentikAPI()
{
    LOG("AuthentikAPI::Destructor");
}

// Initiate authentication flow
AuthentikResponse AuthentikAPI::InitiateAuthentication(const std::wstring& username, const std::wstring& password)
{
    LOG("InitiateAuthentication: user=%S", username.c_str());

    AuthentikResponse response;
    response.success = false;
    response.requiresOTP = false;

    // Build request URL
    std::wstring url = L"/api/v3/flows/executor/" + _flowSlug + L"/";

    // Build JSON payload
    std::wstring payload = L"{\"uid_field\":\"" + username + L"\"";
    if (!password.empty())
    {
        payload += L",\"password\":\"" + password + L"\"";
    }
    payload += L"}";

    // Make HTTP request
    std::wstring responseBody;
    HRESULT hr = _MakeHttpRequest(L"POST", url, payload, responseBody);

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
AuthentikResponse AuthentikAPI::ValidateOTP(const std::wstring& username, const std::wstring& otp, const std::wstring& transactionId)
{
    LOG("ValidateOTP: user=%S, transaction=%S", username.c_str(), transactionId.c_str());

    AuthentikResponse response;
    response.success = false;
    response.requiresOTP = false;

    // Build request URL
    std::wstring url = L"/api/v3/flows/executor/" + _flowSlug + L"/";

    // Build JSON payload
    std::wstring payload = L"{\"code\":\"" + otp + L"\"";
    if (!transactionId.empty())
    {
        payload += L",\"transaction_id\":\"" + transactionId + L"\"";
    }
    payload += L"}";

    // Make HTTP request
    std::wstring responseBody;
    HRESULT hr = _MakeHttpRequest(L"POST", url, payload, responseBody);

    if (SUCCEEDED(hr))
    {
        // Parse response
        response = _ParseAuthentikResponse(responseBody);
        LOG("ValidateOTP response: success=%d", response.success);
    }
    else
    {
        LOG("ValidateOTP failed: 0x%08x", hr);
        response.message = L"Failed to validate OTP";
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
        // Read server URL
        WCHAR buffer[256];
        DWORD bufferSize = sizeof(buffer);
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

        // Read IgnoreSslErrors flag (for testing with self-signed certificates)
        DWORD ignoreSslErrors = 0;  // Default to secure (don't ignore)
        bufferSize = sizeof(DWORD);
        result = RegQueryValueExW(hKey, L"IgnoreSslErrors", nullptr, nullptr, (LPBYTE)&ignoreSslErrors, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _ignoreSslErrors = (ignoreSslErrors != 0);
            LOG("IgnoreSslErrors: %d %s", _ignoreSslErrors, 
                _ignoreSslErrors ? "(WARNING: SSL validation disabled!)" : "(secure)");
        }
        else
        {
            _ignoreSslErrors = false;  // Secure by default
            LOG("IgnoreSslErrors not set, defaulting to secure (validate SSL)");
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
    std::wstring& responseBody)
{
    LOG("HTTP %S %S", method.c_str(), url.c_str());

    HRESULT hr = E_FAIL;
    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;
    HINTERNET hRequest = nullptr;

    // Initialize WinHTTP
    hSession = WinHttpOpen(
        L"AuthentikCredentialProvider/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!hSession)
    {
        LOG("WinHttpOpen failed: %d", GetLastError());
        return E_FAIL;
    }

    // Set TLS 1.2 (required for modern servers)
    DWORD dwSecureProtocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
    if (!WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &dwSecureProtocols, sizeof(dwSecureProtocols)))
    {
        LOG("WARNING: Failed to set TLS 1.2: %d", GetLastError());
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

    // Disable SSL certificate validation if configured (for testing with self-signed certs)
    // Must be set BEFORE sending the request
    if (_useHttps && _ignoreSslErrors)
    {
        // Try to set on request handle
        DWORD dwSecFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        
        BOOL bResult = WinHttpSetOption(
            hRequest,
            WINHTTP_OPTION_SECURITY_FLAGS,
            &dwSecFlags,
            sizeof(dwSecFlags));
        
        if (bResult)
        {
            LOG("WARNING: SSL certificate validation disabled (IgnoreSslErrors=1)");
        }
        else
        {
            DWORD err = GetLastError();
            LOG("ERROR: Failed to disable SSL validation: %d (0x%08x)", err, err);
        }
    }
    else if (_useHttps)
    {
        LOG("SSL certificate validation enabled (secure mode)");
    }

    // Set headers
    std::wstring headers = L"Content-Type: application/json\r\n";
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
        DWORD dwError = GetLastError();
        LOG("WinHttpSendRequest failed: %d (0x%08x)", dwError, dwError);
        if (dwError == ERROR_WINHTTP_SECURE_FAILURE)
        {
            LOG("SSL/TLS error - certificate validation failed");
        }
        goto cleanup;
    }

    // Receive response
    bResult = WinHttpReceiveResponse(hRequest, nullptr);
    
    // If SSL error and we're configured to ignore, try again with flags set
    if (!bResult && _ignoreSslErrors)
    {
        DWORD dwError = GetLastError();
        if (dwError == ERROR_WINHTTP_SECURE_FAILURE || dwError == 12156)
        {
            LOG("SSL error on receive, attempting to ignore and retry...");
            
            // Set security flags again
            DWORD dwSecFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                              SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                              SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                              SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
            
            WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwSecFlags, sizeof(dwSecFlags));
            
            // Retry receive
            bResult = WinHttpReceiveResponse(hRequest, nullptr);
        }
    }
    
    if (!bResult)
    {
        DWORD dwError = GetLastError();
        LOG("WinHttpReceiveResponse failed: %d (0x%08x)", dwError, dwError);
        if (dwError == ERROR_WINHTTP_SECURE_FAILURE || dwError == 12156)
        {
            LOG("SSL/TLS secure failure during response");
            // Try to get more details
            DWORD dwFlags = 0;
            DWORD dwSize = sizeof(dwFlags);
            if (WinHttpQueryOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, &dwSize))
            {
                LOG("Current security flags: 0x%08x", dwFlags);
            }
        }
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
    } // End of scope block

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

    AuthentikResponse response;
    response.success = false;
    response.requiresOTP = false;

    // Simple JSON parsing (you may want to use a proper JSON library)
    // For now, just check for key indicators

    // Check for success (redirect type indicates success)
    if (json.find(L"\"type\":\"redirect\"") != std::wstring::npos)
    {
        response.success = true;
        response.message = L"Authentication successful";
        LOG("Parsed: Authentication successful");
    }
    // Check for OTP challenge
    else if (json.find(L"ak-stage-authenticator-validate") != std::wstring::npos)
    {
        response.requiresOTP = true;
        response.message = L"OTP required";
        
        // Extract transaction ID if present (simplified parsing)
        size_t pos = json.find(L"\"flow_info\"");
        if (pos != std::wstring::npos)
        {
            // In a real implementation, parse JSON properly
            // For now, generate a simple transaction ID
            response.transactionId = L"tx_" + std::to_wstring(GetTickCount64());
        }
        
        LOG("Parsed: OTP required, transaction=%S", response.transactionId.c_str());
    }
    // Check for error
    else if (json.find(L"\"error\"") != std::wstring::npos)
    {
        response.success = false;
        response.message = L"Authentication failed";
        LOG("Parsed: Authentication failed");
    }
    else
    {
        response.success = false;
        response.message = L"Unknown response";
        LOG("Parsed: Unknown response format");
    }

    return response;
}
