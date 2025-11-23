// AuthentikAPI_IMPROVED.cpp
// Enhanced HTTP client for Authentik API communication with security fixes
// Version 2.0 - Production Ready

#include "AuthentikAPI.h"
#include "Logger.h"
#include "ConfigurationManager.h"
#include "CertificateValidator.h"
#include "RateLimiter.h"
#include <winhttp.h>
#include <sstream>
#include <vector>
#include <memory>
#include <chrono>

// Include RapidJSON for proper JSON parsing
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#pragma comment(lib, "winhttp.lib")

// RAII wrapper for WinHTTP handles
class WinHttpHandle {
private:
    HINTERNET _handle;

public:
    WinHttpHandle(HINTERNET handle = nullptr) : _handle(handle) {}
    
    ~WinHttpHandle() {
        if (_handle) {
            WinHttpCloseHandle(_handle);
        }
    }

    // Disable copying
    WinHttpHandle(const WinHttpHandle&) = delete;
    WinHttpHandle& operator=(const WinHttpHandle&) = delete;

    // Allow moving
    WinHttpHandle(WinHttpHandle&& other) noexcept : _handle(other._handle) {
        other._handle = nullptr;
    }

    WinHttpHandle& operator=(WinHttpHandle&& other) noexcept {
        if (this != &other) {
            if (_handle) WinHttpCloseHandle(_handle);
            _handle = other._handle;
            other._handle = nullptr;
        }
        return *this;
    }

    operator HINTERNET() const { return _handle; }
    HINTERNET Get() const { return _handle; }
    HINTERNET* GetAddressOf() { return &_handle; }
    
    HINTERNET Release() {
        HINTERNET h = _handle;
        _handle = nullptr;
        return h;
    }
};

// Constructor
AuthentikAPI::AuthentikAPI() :
    _requestTimeout(30000), // 30 seconds default
    _maxRetries(3)
{
    LOG_INFO("AuthentikAPI::Constructor");
    
    // Load configuration from ConfigurationManager
    _LoadConfiguration();
    
    // Initialize certificate validator
    _pCertValidator = std::make_unique<CertificateValidator>();
    _pCertValidator->LoadPinnedCertificates();
    
    // Initialize rate limiter
    _pRateLimiter = std::make_unique<RateLimiter>();
}

// Destructor
AuthentikAPI::~AuthentikAPI()
{
    LOG_INFO("AuthentikAPI::Destructor");
}

// Load configuration
void AuthentikAPI::_LoadConfiguration()
{
    LOG_INFO("Loading configuration");

    auto& config = ConfigurationManager::Instance();
    
    // Load and validate configuration
    HRESULT hr = config.Load();
    if (FAILED(hr)) {
        LOG_ERROR("Failed to load configuration: 0x%08x", hr);
        // Use defaults
        _serverUrl = L"authentik.test.local";
        _serverPort = 443;
        _flowSlug = L"windows-otp-auth";
        _useHttps = true;
        return;
    }

    _serverUrl = config.GetServerUrl();
    _serverPort = config.GetServerPort();
    _flowSlug = config.GetFlowSlug();
    _useHttps = config.GetUseHttps();

    LOG_INFO("Configuration loaded - Server: %S:%d, Flow: %S, HTTPS: %d",
             _serverUrl.c_str(), _serverPort, _flowSlug.c_str(), _useHttps);
}

// Validate input
bool AuthentikAPI::_ValidateInput(const std::wstring& username, const std::wstring& password)
{
    // Username validation
    if (username.empty()) {
        LOG_WARN("Empty username provided");
        return false;
    }

    if (username.length() > 256) {
        LOG_WARN("Username too long: %zu characters", username.length());
        return false;
    }

    // Check for invalid characters (basic validation)
    for (wchar_t c : username) {
        if (c == L'"' || c == L'\\' || c == L'\0') {
            LOG_WARN("Invalid character in username");
            return false;
        }
    }

    // Password validation (if provided)
    if (!password.empty() && password.length() > 1024) {
        LOG_WARN("Password too long: %zu characters", password.length());
        return false;
    }

    return true;
}

// Sanitize string for JSON
std::wstring AuthentikAPI::_SanitizeJsonString(const std::wstring& input)
{
    std::wstring output;
    output.reserve(input.length());

    for (wchar_t c : input) {
        switch (c) {
            case L'"':  output += L"\\\""; break;
            case L'\\': output += L"\\\\"; break;
            case L'/':  output += L"\\/"; break;
            case L'\b': output += L"\\b"; break;
            case L'\f': output += L"\\f"; break;
            case L'\n': output += L"\\n"; break;
            case L'\r': output += L"\\r"; break;
            case L'\t': output += L"\\t"; break;
            default:
                if (c < 0x20) {
                    // Control character - escape as unicode
                    wchar_t buf[8];
                    swprintf_s(buf, L"\\u%04x", (int)c);
                    output += buf;
                } else {
                    output += c;
                }
                break;
        }
    }

    return output;
}

// Initiate authentication flow with enhanced error handling
AuthentikResponse AuthentikAPI::InitiateAuthentication(
    const std::wstring& username, 
    const std::wstring& password)
{
    LOG_INFO("InitiateAuthentication: user=%S", username.c_str());

    AuthentikResponse response;
    response.success = false;
    response.requiresOTP = false;

    // Input validation
    if (!_ValidateInput(username, password)) {
        response.message = L"Invalid username or password format";
        LOG_ERROR("Input validation failed");
        return response;
    }

    // Rate limiting check
    if (!_pRateLimiter->AllowAttempt(username)) {
        response.message = L"Too many authentication attempts. Please try again later.";
        LOG_WARN("Rate limit exceeded for user: %S", username.c_str());
        return response;
    }

    // Build request URL
    std::wstring url = L"/api/v3/flows/executor/" + _flowSlug + L"/";

    // Build JSON payload with sanitization
    std::wstring sanitizedUsername = _SanitizeJsonString(username);
    std::wstring sanitizedPassword = _SanitizeJsonString(password);

    std::wstring payload = L"{\"uid_field\":\"" + sanitizedUsername + L"\"";
    if (!password.empty()) {
        payload += L",\"password\":\"" + sanitizedPassword + L"\"";
    }
    payload += L"}";

    // Make HTTP request with retry
    std::wstring responseBody;
    HRESULT hr = _MakeHttpRequestWithRetry(L"POST", url, payload, responseBody);

    if (SUCCEEDED(hr)) {
        // Parse response using RapidJSON
        response = _ParseAuthentikResponseJson(responseBody);
        
        if (response.success) {
            _pRateLimiter->RecordSuccess(username);
            LOG_INFO("Authentication successful for user: %S", username.c_str());
        } else if (!response.requiresOTP) {
            _pRateLimiter->RecordFailure(username);
            LOG_WARN("Authentication failed for user: %S", username.c_str());
        }
        
        LOG_INFO("InitiateAuthentication response: success=%d, requiresOTP=%d", 
                response.success, response.requiresOTP);
    } else {
        _pRateLimiter->RecordFailure(username);
        LOG_ERROR("InitiateAuthentication HTTP request failed: 0x%08x", hr);
        response.message = L"Failed to connect to authentication server";
    }

    return response;
}

// Validate OTP with enhanced error handling
AuthentikResponse AuthentikAPI::ValidateOTP(
    const std::wstring& username, 
    const std::wstring& otp, 
    const std::wstring& transactionId)
{
    LOG_INFO("ValidateOTP: user=%S, transaction=%S", username.c_str(), transactionId.c_str());

    AuthentikResponse response;
    response.success = false;
    response.requiresOTP = false;

    // Validate OTP format
    if (otp.empty() || otp.length() < 4 || otp.length() > 10) {
        response.message = L"Invalid OTP format";
        LOG_ERROR("Invalid OTP format");
        return response;
    }

    // Check for numeric OTP (most common)
    bool isNumeric = true;
    for (wchar_t c : otp) {
        if (!iswdigit(c)) {
            isNumeric = false;
            break;
        }
    }

    if (!isNumeric) {
        // Some OTP formats allow alphanumeric
        LOG_DEBUG("Non-numeric OTP provided");
    }

    // Build request URL
    std::wstring url = L"/api/v3/flows/executor/" + _flowSlug + L"/";

    // Build JSON payload
    std::wstring sanitizedOtp = _SanitizeJsonString(otp);
    std::wstring sanitizedTxId = _SanitizeJsonString(transactionId);

    std::wstring payload = L"{\"code\":\"" + sanitizedOtp + L"\"";
    if (!transactionId.empty()) {
        payload += L",\"transaction_id\":\"" + sanitizedTxId + L"\"";
    }
    payload += L"}";

    // Make HTTP request with retry
    std::wstring responseBody;
    HRESULT hr = _MakeHttpRequestWithRetry(L"POST", url, payload, responseBody);

    if (SUCCEEDED(hr)) {
        // Parse response
        response = _ParseAuthentikResponseJson(responseBody);
        
        if (response.success) {
            _pRateLimiter->RecordSuccess(username);
            LOG_INFO("OTP validation successful");
        } else {
            _pRateLimiter->RecordFailure(username);
            LOG_WARN("OTP validation failed");
        }
        
        LOG_INFO("ValidateOTP response: success=%d", response.success);
    } else {
        _pRateLimiter->RecordFailure(username);
        LOG_ERROR("ValidateOTP HTTP request failed: 0x%08x", hr);
        response.message = L"Failed to validate OTP";
    }

    return response;
}

// Make HTTP request with retry logic
HRESULT AuthentikAPI::_MakeHttpRequestWithRetry(
    const std::wstring& method,
    const std::wstring& url,
    const std::wstring& payload,
    std::wstring& responseBody)
{
    HRESULT hr = E_FAIL;
    int retryCount = 0;

    while (retryCount <= _maxRetries) {
        hr = _MakeHttpRequestWithTimeout(method, url, payload, responseBody, _requestTimeout);

        if (SUCCEEDED(hr)) {
            return hr;
        }

        retryCount++;
        if (retryCount <= _maxRetries) {
            // Exponential backoff
            DWORD sleepTime = 1000 * (1 << (retryCount - 1)); // 1s, 2s, 4s
            LOG_WARN("HTTP request failed (attempt %d/%d), retrying in %dms", 
                    retryCount, _maxRetries, sleepTime);
            Sleep(sleepTime);
        }
    }

    LOG_ERROR("HTTP request failed after %d retries", _maxRetries);
    return hr;
}

// Make HTTP request with timeout
HRESULT AuthentikAPI::_MakeHttpRequestWithTimeout(
    const std::wstring& method,
    const std::wstring& url,
    const std::wstring& payload,
    std::wstring& responseBody,
    DWORD timeoutMs)
{
    LOG_DEBUG("HTTP %S %S (timeout: %dms)", method.c_str(), url.c_str(), timeoutMs);

    HRESULT hr = E_FAIL;

    // Initialize WinHTTP with RAII
    WinHttpHandle hSession = WinHttpOpen(
        L"AuthentikCredentialProvider/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!hSession.Get()) {
        LOG_ERROR("WinHttpOpen failed: %d", GetLastError());
        return E_FAIL;
    }

    // Set timeouts
    WinHttpSetTimeouts(hSession, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

    // Connect to server
    WinHttpHandle hConnect = WinHttpConnect(
        hSession,
        _serverUrl.c_str(),
        _serverPort,
        0);

    if (!hConnect.Get()) {
        LOG_ERROR("WinHttpConnect failed: %d", GetLastError());
        return E_FAIL;
    }

    // Create request
    DWORD dwFlags = _useHttps ? WINHTTP_FLAG_SECURE : 0;
    
    WinHttpHandle hRequest = WinHttpOpenRequest(
        hConnect,
        method.c_str(),
        url.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        dwFlags);

    if (!hRequest.Get()) {
        LOG_ERROR("WinHttpOpenRequest failed: %d", GetLastError());
        return E_FAIL;
    }

    // CRITICAL SECURITY FIX: Enable proper SSL certificate validation
    if (_useHttps) {
        // Set security callback for certificate validation
        WinHttpSetStatusCallback(
            hRequest,
            _WinHttpStatusCallback,
            WINHTTP_CALLBACK_FLAG_SECURE_FAILURE,
            0);

        // DO NOT DISABLE CERTIFICATE VALIDATION IN PRODUCTION
        // The old code had this - REMOVED FOR SECURITY:
        // DWORD dwSecFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | ...;
        // WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, ...);
        
        LOG_INFO("SSL certificate validation ENABLED (production mode)");
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
    if (!payload.empty()) {
        int size = WideCharToMultiByte(CP_UTF8, 0, payload.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (size > 0) {
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

    if (!bResult) {
        DWORD error = GetLastError();
        LOG_ERROR("WinHttpSendRequest failed: %d", error);
        return HRESULT_FROM_WIN32(error);
    }

    // Receive response
    bResult = WinHttpReceiveResponse(hRequest, nullptr);
    if (!bResult) {
        DWORD error = GetLastError();
        LOG_ERROR("WinHttpReceiveResponse failed: %d", error);
        return HRESULT_FROM_WIN32(error);
    }

    // Check HTTP status code
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    WinHttpQueryHeaders(
        hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode,
        &statusCodeSize,
        WINHTTP_NO_HEADER_INDEX);

    LOG_DEBUG("HTTP Status Code: %d", statusCode);

    if (statusCode >= 400) {
        LOG_WARN("HTTP error status: %d", statusCode);
        // Continue to read error response
    }

    // Read response body
    std::vector<char> responseBuffer;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;

    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            LOG_ERROR("WinHttpQueryDataAvailable failed: %d", GetLastError());
            break;
        }

        if (dwSize == 0)
            break;

        std::vector<char> tempBuffer(dwSize + 1);
        ZeroMemory(&tempBuffer[0], dwSize + 1);

        if (!WinHttpReadData(hRequest, &tempBuffer[0], dwSize, &dwDownloaded)) {
            LOG_ERROR("WinHttpReadData failed: %d", GetLastError());
            break;
        }

        responseBuffer.insert(responseBuffer.end(), tempBuffer.begin(), 
                            tempBuffer.begin() + dwDownloaded);

    } while (dwSize > 0);

    // Convert response to wide string
    if (!responseBuffer.empty()) {
        responseBuffer.push_back('\0');
        int wideSize = MultiByteToWideChar(CP_UTF8, 0, &responseBuffer[0], -1, nullptr, 0);
        if (wideSize > 0) {
            std::vector<wchar_t> wideBuffer(wideSize);
            MultiByteToWideChar(CP_UTF8, 0, &responseBuffer[0], -1, &wideBuffer[0], wideSize);
            responseBody = &wideBuffer[0];
            
            LOG_DEBUG("Response received: %zu bytes", responseBuffer.size());
            hr = S_OK;
        }
    } else {
        LOG_WARN("Empty response received");
        hr = S_OK; // Empty response might be valid for some endpoints
    }

    // Validate server certificate if HTTPS
    if (_useHttps && SUCCEEDED(hr)) {
        PCCERT_CONTEXT pCertContext = nullptr;
        DWORD certContextSize = sizeof(pCertContext);
        
        if (WinHttpQueryOption(
            hRequest,
            WINHTTP_OPTION_SERVER_CERT_CONTEXT,
            &pCertContext,
            &certContextSize))
        {
            if (!_pCertValidator->ValidateCertificate(pCertContext)) {
                LOG_ERROR("Certificate validation failed!");
                hr = E_FAIL;
            }
            
            CertFreeCertificateContext(pCertContext);
        }
    }

    return hr;
}

// WinHTTP status callback for SSL errors
void CALLBACK AuthentikAPI::_WinHttpStatusCallback(
    HINTERNET hInternet,
    DWORD_PTR dwContext,
    DWORD dwInternetStatus,
    LPVOID lpvStatusInformation,
    DWORD dwStatusInformationLength)
{
    if (dwInternetStatus == WINHTTP_CALLBACK_STATUS_SECURE_FAILURE) {
        DWORD secureFailure = *(DWORD*)lpvStatusInformation;
        LOG_ERROR("SSL/TLS failure: 0x%08x", secureFailure);
        
        if (secureFailure & WINHTTP_CALLBACK_STATUS_FLAG_CERT_REV_FAILED) {
            LOG_ERROR("Certificate revocation check failed");
        }
        if (secureFailure & WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CERT) {
            LOG_ERROR("Invalid certificate");
        }
        if (secureFailure & WINHTTP_CALLBACK_STATUS_FLAG_CERT_REVOKED) {
            LOG_ERROR("Certificate revoked");
        }
        if (secureFailure & WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA) {
            LOG_ERROR("Invalid certificate authority");
        }
        if (secureFailure & WINHTTP_CALLBACK_STATUS_FLAG_CERT_CN_INVALID) {
            LOG_ERROR("Certificate CN invalid");
        }
        if (secureFailure & WINHTTP_CALLBACK_STATUS_FLAG_CERT_DATE_INVALID) {
            LOG_ERROR("Certificate date invalid");
        }
        if (secureFailure & WINHTTP_CALLBACK_STATUS_FLAG_SECURITY_CHANNEL_ERROR) {
            LOG_ERROR("Security channel error");
        }
    }
}

// Parse Authentik API response using RapidJSON
AuthentikResponse AuthentikAPI::_ParseAuthentikResponseJson(const std::wstring& jsonWide)
{
    LOG_DEBUG("Parsing Authentik response");

    AuthentikResponse response;
    response.success = false;
    response.requiresOTP = false;

    // Convert wide string to UTF-8 for RapidJSON
    int size = WideCharToMultiByte(CP_UTF8, 0, jsonWide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        LOG_ERROR("Failed to convert JSON to UTF-8");
        response.message = L"Invalid response format";
        return response;
    }

    std::vector<char> jsonUtf8(size);
    WideCharToMultiByte(CP_UTF8, 0, jsonWide.c_str(), -1, &jsonUtf8[0], size, nullptr, nullptr);

    // Parse JSON
    rapidjson::Document doc;
    doc.Parse(&jsonUtf8[0]);

    if (doc.HasParseError()) {
        LOG_ERROR("JSON parse error at offset %zu: %d", 
                doc.GetErrorOffset(), doc.GetParseError());
        response.message = L"Invalid JSON response";
        return response;
    }

    // Check for redirect type (success)
    if (doc.HasMember("type") && doc["type"].IsString()) {
        std::string type = doc["type"].GetString();
        
        if (type == "redirect") {
            response.success = true;
            response.message = L"Authentication successful";
            LOG_INFO("Parsed: Authentication successful (redirect)");
            return response;
        }
    }

    // Check for OTP challenge
    if (doc.HasMember("component") && doc["component"].IsString()) {
        std::string component = doc["component"].GetString();
        
        if (component.find("ak-stage-authenticator-validate") != std::string::npos) {
            response.requiresOTP = true;
            response.message = L"OTP required";
            
            // Extract transaction ID
            if (doc.HasMember("flow_info") && doc["flow_info"].IsObject()) {
                const auto& flowInfo = doc["flow_info"];
                if (flowInfo.HasMember("flow_id") && flowInfo["flow_id"].IsString()) {
                    std::string flowId = flowInfo["flow_id"].GetString();
                    response.transactionId = std::wstring(flowId.begin(), flowId.end());
                }
            }
            
            // Generate transaction ID if not provided
            if (response.transactionId.empty()) {
                response.transactionId = L"tx_" + std::to_wstring(GetTickCount64());
            }
            
            LOG_INFO("Parsed: OTP required, transaction=%S", response.transactionId.c_str());
            return response;
        }
    }

    // Check for error
    if (doc.HasMember("error") || doc.HasMember("detail")) {
        response.success = false;
        
        if (doc.HasMember("detail") && doc["detail"].IsString()) {
            std::string detail = doc["detail"].GetString();
            response.message = std::wstring(detail.begin(), detail.end());
        } else {
            response.message = L"Authentication failed";
        }
        
        LOG_WARN("Parsed: Authentication failed - %S", response.message.c_str());
        return response;
    }

    // Unknown response format
    response.success = false;
    response.message = L"Unknown response format";
    LOG_WARN("Parsed: Unknown response format");

    return response;
}
