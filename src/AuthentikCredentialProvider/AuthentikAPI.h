// AuthentikAPI.h
// Header for Authentik API client with session management

#pragma once

#include <windows.h>
#include <winhttp.h>
#include <string>
#include <map>
#include <vector>

#pragma comment(lib, "Winhttp.lib")

// Authentication status
enum class AuthStatus
{
    SUCCESS,            // Authentication complete
    NEED_USERNAME,      // Need username input
    NEED_OTP,           // Need OTP input
    FAILED,             // Authentication failed
    ERROR_NETWORK,      // Network error
    ERROR_SERVER,       // Server error
    ERROR_CONFIG        // Configuration error
};

// Response structure
struct AuthentikResponse
{
    AuthStatus status;
    std::wstring message;
    std::wstring rawResponse;
    
    // Certificate data (if provided by server)
    std::wstring certificatePem;
    std::wstring privateKeyPem;
    int certValidMinutes;
    
    // User info
    std::wstring username;
    std::wstring domain;
    std::wstring upn;
    
    AuthentikResponse() : status(AuthStatus::FAILED), certValidMinutes(0) {}
};

class AuthentikAPI
{
public:
    AuthentikAPI();
    ~AuthentikAPI();

    // Check if configuration is valid
    bool IsConfigurationValid() const;
    
    // Get configuration error message
    std::wstring GetConfigurationError() const;

    // Reset session (for new authentication attempt)
    void ResetSession();

    // Step 1: Submit username - returns NEED_OTP or error
    AuthentikResponse SubmitUsername(const std::wstring& username);

    // Step 2: Submit OTP - returns SUCCESS with certificate or error
    AuthentikResponse SubmitOTP(const std::wstring& otp);

private:
    // Load configuration from registry
    void _LoadConfiguration();

    // Make HTTP request to Authentik
    HRESULT _MakeHttpRequest(
        const std::wstring& method, 
        const std::wstring& url, 
        const std::wstring& payload, 
        std::wstring& responseBody,
        DWORD& statusCode);

    // Parse Authentik JSON response
    AuthentikResponse _ParseAuthentikResponse(const std::wstring& json);
    
    // Parse JSON string value
    std::wstring _ParseJsonString(const std::wstring& json, const std::wstring& key);
    
    // Escape JSON string
    std::wstring _EscapeJson(const std::wstring& input);
    
    // Cookie management
    void _SaveCookies(HINTERNET hRequest);
    void _AddCookies(HINTERNET hRequest);

    // Configuration
    std::wstring _serverUrl;
    INTERNET_PORT _serverPort;
    std::wstring _flowSlug;
    bool _useHttps;
    bool _ignoreCertErrors;
    std::wstring _domain;
    std::wstring _domainFQDN;
    
    // Configuration validation
    bool _configurationValid;
    std::wstring _configurationError;
    
    // Session state
    std::wstring _currentUsername;
    std::map<std::wstring, std::wstring> _cookies;
    std::wstring _csrfToken;
    std::wstring _flowExecutorUrl;
};
