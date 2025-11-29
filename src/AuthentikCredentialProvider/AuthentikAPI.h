// AuthentikAPI.h
// Header for Authentik API client with session management

#pragma once

#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <map>

#pragma comment(lib, "Winhttp.lib")

// Authentication response status
enum class AuthStatus
{
    SUCCESS,                    // Authentication complete, certificate available
    NEED_USERNAME,              // Need username (initial state)
    NEED_OTP,                   // OTP challenge sent, waiting for code
    FAILED,                     // Authentication failed
    ERROR_NETWORK,              // Network error
    ERROR_SERVER                // Server error
};

// Response structure from Authentik
struct AuthentikResponse
{
    AuthStatus status;
    std::wstring message;
    std::wstring transactionId;
    
    // Certificate data (populated on SUCCESS)
    std::wstring certificatePem;
    std::wstring privateKeyPem;
    std::wstring username;
    std::wstring domain;
    std::wstring upn;
    DWORD certValidMinutes;
    
    // Raw JSON response for additional parsing
    std::wstring rawResponse;
    
    AuthentikResponse() : status(AuthStatus::FAILED), certValidMinutes(5) {}
};

class AuthentikAPI
{
public:
    AuthentikAPI();
    ~AuthentikAPI();

    // Step 1: Submit username to start authentication flow
    AuthentikResponse SubmitUsername(const std::wstring& username);

    // Step 2: Submit OTP code to complete authentication
    AuthentikResponse SubmitOTP(const std::wstring& otp);

    // Reset the session (for new authentication attempt)
    void ResetSession();

    // Get the current username
    const std::wstring& GetUsername() const { return _currentUsername; }

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

    // Parse Authentik API response
    AuthentikResponse _ParseAuthentikResponse(const std::wstring& json);

    // Parse JSON string value
    std::wstring _ParseJsonString(const std::wstring& json, const std::wstring& key);

    // Save cookies from response
    void _SaveCookies(HINTERNET hRequest);

    // Add cookies to request
    void _AddCookies(HINTERNET hRequest);

    // Configuration
    std::wstring _serverUrl;
    INTERNET_PORT _serverPort;
    std::wstring _flowSlug;
    bool _useHttps;
    bool _ignoreCertErrors;
    std::wstring _domain;
    std::wstring _domainFQDN;

    // Session management
    std::wstring _currentUsername;
    std::map<std::wstring, std::wstring> _cookies;
    std::wstring _csrfToken;
    std::wstring _flowExecutorUrl;
};
