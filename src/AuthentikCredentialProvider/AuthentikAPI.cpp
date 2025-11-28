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
    _ignoreSslErrors(false),  // Secure by default
    _hSession(nullptr),
    _hConnect(nullptr)
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

    // Initialize persistent session for cookie management
    _InitializeSession();
    
    LOG("AuthentikAPI::Constructor - API client created");
}

// Destructor
AuthentikAPI::~AuthentikAPI()
{
    LOG("AuthentikAPI::Destructor");
    
    // Clean up session handles
    if (_hConnect)
    {
        WinHttpCloseHandle(_hConnect);
        _hConnect = nullptr;
    }
    if (_hSession)
    {
        WinHttpCloseHandle(_hSession);
        _hSession = nullptr;
    }
}

// Initialize HTTP session (called once, maintains cookies)
bool AuthentikAPI::_InitializeSession()
{
    LOG("Initializing HTTP session for cookie management");

    // Close existing handles if any
    if (_hConnect)
    {
        WinHttpCloseHandle(_hConnect);
        _hConnect = nullptr;
    }
    if (_hSession)
    {
        WinHttpCloseHandle(_hSession);
        _hSession = nullptr;
    }

    // Create session
    _hSession = WinHttpOpen(
        L"AuthentikCredentialProvider/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!_hSession)
    {
        LOG("ERROR: WinHttpOpen failed: %d", GetLastError());
        return false;
    }

    // Enable cookies (automatic cookie handling)
    DWORD dwOption = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    WinHttpSetOption(_hSession, WINHTTP_OPTION_REDIRECT_POLICY, &dwOption, sizeof(dwOption));

    // Set TLS 1.2 (required for modern servers)
    DWORD dwSecureProtocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
    WinHttpSetOption(_hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &dwSecureProtocols, sizeof(dwSecureProtocols));

    // Connect to server (persistent connection for cookies)
    _hConnect = WinHttpConnect(
        _hSession,
        _serverUrl.c_str(),
        _serverPort,
        0);

    if (!_hConnect)
    {
        LOG("ERROR: WinHttpConnect failed: %d", GetLastError());
        WinHttpCloseHandle(_hSession);
        _hSession = nullptr;
        return false;
    }

    LOG("HTTP session initialized successfully (cookies enabled)");
    return true;
}

// Reset the session (clear cookies for new auth flow)
void AuthentikAPI::ResetSession()
{
    LOG("Resetting HTTP session (clearing cookies)");
    _InitializeSession();
}

// Initiate authentication flow
AuthentikResponse AuthentikAPI::InitiateAuthentication(const std::wstring& username, const std::wstring& password)
{
    LOG("InitiateAuthentication: user=%S", username.c_str());

    AuthentikResponse response;
    response.success = false;
    response.requiresOTP = false;
    response.requiresPassword = false;

    // Build request URL
    std::wstring url = L"/api/v3/flows/executor/" + _flowSlug + L"/";

    // Step 1: Send username first (identification stage)
    std::wstring payload = L"{\"uid_field\":\"" + username + L"\"}";
    LOG("Step 1: Sending username");

    std::wstring responseBody;
    HRESULT hr = _MakeHttpRequest(L"POST", url, payload, responseBody);

    if (FAILED(hr))
    {
        LOG("InitiateAuthentication failed at Step 1: 0x%08x", hr);
        response.message = L"Failed to connect to authentication server";
        return response;
    }

    // Parse Step 1 response
    response = _ParseAuthentikResponse(responseBody);

    // If Authentik asks for password, send it in Step 2
    if (response.requiresPassword && !password.empty())
    {
        LOG("Step 2: Sending password");
        payload = L"{\"password\":\"" + password + L"\"}";
        
        hr = _MakeHttpRequest(L"POST", url, payload, responseBody);
        
        if (FAILED(hr))
        {
            LOG("InitiateAuthentication failed at Step 2: 0x%08x", hr);
            response.message = L"Failed to send password";
            return response;
        }
        
        // Parse Step 2 response
        response = _ParseAuthentikResponse(responseBody);
    }

    LOG("InitiateAuthentication final: success=%d, requiresOTP=%d, requiresPassword=%d", 
        response.success, response.requiresOTP, response.requiresPassword);

    return response;
}

// Validate OTP
AuthentikResponse AuthentikAPI::ValidateOTP(const std::wstring& username, const std::wstring& otp, const std::wstring& transactionId)
{
    LOG("ValidateOTP: user=%S, transaction=%S", username.c_str(), transactionId.c_str());

    AuthentikResponse response;
    response.success = false;
    response.requiresOTP = false;
    response.requiresPassword = false;

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

// Make HTTP request (uses persistent session for cookie management)
HRESULT AuthentikAPI::_MakeHttpRequest(
    const std::wstring& method,
    const std::wstring& url,
    const std::wstring& payload,
    std::wstring& responseBody)
{
    LOG("HTTP %S %S", method.c_str(), url.c_str());

    HRESULT hr = E_FAIL;
    HINTERNET hRequest = nullptr;

    // Ensure session is initialized
    if (!_hSession || !_hConnect)
    {
        LOG("Session not initialized, initializing now...");
        if (!_InitializeSession())
        {
            LOG("ERROR: Failed to initialize session");
            return E_FAIL;
        }
    }

    // Create request (using persistent connection for cookies)
    DWORD dwFlags = _useHttps ? WINHTTP_FLAG_SECURE : 0;
    
    hRequest = WinHttpOpenRequest(
        _hConnect,  // Use persistent connection
        method.c_str(),
        url.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        dwFlags);

    if (!hRequest)
    {
        LOG("WinHttpOpenRequest failed: %d", GetLastError());
        return E_FAIL;
    }

    // Disable SSL certificate validation if configured (for testing with self-signed certs)
    if (_useHttps && _ignoreSslErrors)
    {
        DWORD dwSecFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwSecFlags, sizeof(dwSecFlags));
        LOG("WARNING: SSL certificate validation disabled");
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
        goto cleanup;
    }

    // Receive response
    bResult = WinHttpReceiveResponse(hRequest, nullptr);
    
    if (!bResult)
    {
        DWORD dwError = GetLastError();
        LOG("WinHttpReceiveResponse failed: %d (0x%08x)", dwError, dwError);
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
    }

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    // Don't close _hSession and _hConnect - they're persistent for cookies!

    return hr;
}

// Parse Authentik API response
AuthentikResponse AuthentikAPI::_ParseAuthentikResponse(const std::wstring& json)
{
    LOG("Parsing Authentik response");

    AuthentikResponse response;
    response.success = false;
    response.requiresOTP = false;
    response.requiresPassword = false;

    // Log a portion of the response for debugging
    if (json.length() > 200)
    {
        LOG("Response (first 200 chars): %S...", json.substr(0, 200).c_str());
    }
    else
    {
        LOG("Response: %S", json.c_str());
    }

    // Check for success (redirect type indicates success)
    // Authentik returns either "type":"redirect" or "component":"xak-flow-redirect"
    if (json.find(L"\"type\":\"redirect\"") != std::wstring::npos ||
        json.find(L"xak-flow-redirect") != std::wstring::npos)
    {
        response.success = true;
        response.message = L"Authentication successful";
        
        // Extract windows_password if present in response
        // Authentik can return this via flow context or user attributes
        response.windowsPassword = _ExtractJsonString(json, L"windows_password");
        if (!response.windowsPassword.empty())
        {
            LOG("Parsed: Authentication successful with windows_password");
        }
        else
        {
            LOG("Parsed: Authentication successful (no windows_password in response)");
        }
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
            response.transactionId = L"tx_" + std::to_wstring(GetTickCount64());
        }
        
        LOG("Parsed: OTP required, transaction=%S", response.transactionId.c_str());
    }
    // Check for password stage - need to send password separately
    else if (json.find(L"ak-stage-password") != std::wstring::npos)
    {
        response.requiresPassword = true;
        response.message = L"Password required";
        LOG("Parsed: Password stage - need to send password");
    }
    // Check for identification stage - need to send username
    else if (json.find(L"ak-stage-identification") != std::wstring::npos)
    {
        response.message = L"Identification required";
        LOG("Parsed: Identification stage - need to send username");
    }
    // Check for error responses
    else if (json.find(L"\"response_errors\"") != std::wstring::npos || 
             json.find(L"\"error\"") != std::wstring::npos)
    {
        response.success = false;
        response.message = L"Authentication failed";
        LOG("Parsed: Authentication failed (error in response)");
    }
    // Check for denied
    else if (json.find(L"\"type\":\"denied\"") != std::wstring::npos ||
             json.find(L"access_denied") != std::wstring::npos)
    {
        response.success = false;
        response.message = L"Access denied";
        LOG("Parsed: Access denied");
    }
    else
    {
        response.success = false;
        response.message = L"Unknown response";
        LOG("Parsed: Unknown response format");
    }

    LOG("InitiateAuthentication response: success=%d, requiresOTP=%d, requiresPassword=%d", 
        response.success, response.requiresOTP, response.requiresPassword);

    return response;
}

// Helper function to extract a string value from JSON
std::wstring AuthentikAPI::_ExtractJsonString(const std::wstring& json, const std::wstring& key)
{
    // Look for "key": "value" pattern
    std::wstring searchKey = L"\"" + key + L"\"";
    size_t keyPos = json.find(searchKey);
    
    if (keyPos == std::wstring::npos)
    {
        return L"";
    }
    
    // Find the colon after the key
    size_t colonPos = json.find(L':', keyPos + searchKey.length());
    if (colonPos == std::wstring::npos)
    {
        return L"";
    }
    
    // Find the opening quote of the value
    size_t valueStart = json.find(L'"', colonPos + 1);
    if (valueStart == std::wstring::npos)
    {
        return L"";
    }
    
    // Find the closing quote of the value
    size_t valueEnd = json.find(L'"', valueStart + 1);
    if (valueEnd == std::wstring::npos)
    {
        return L"";
    }
    
    // Extract the value
    return json.substr(valueStart + 1, valueEnd - valueStart - 1);
}
