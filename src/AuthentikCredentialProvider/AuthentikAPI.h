// AuthentikAPI.h
// Header for Authentik API client with session management and certificate issuer integration

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
    
    // Certificate data (from certificate issuer)
    std::wstring certificatePem;
    std::wstring privateKeyPem;
    std::wstring pfxBase64;      // Base64-encoded PFX with private key
    std::wstring pfxPassword;    // Password for the PFX
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

    // Make HTTP request to Certificate Issuer
    HRESULT _MakeCertIssuerRequest(
        const std::wstring& method, 
        const std::wstring& url, 
        const std::wstring& payload, 
        std::wstring& responseBody,
        DWORD& statusCode);

    // Request certificate from certificate issuer service
    AuthentikResponse _RequestCertificate(
        const std::wstring& username,
        const std::wstring& upn,
        const std::wstring& domain);

    // Parse Authentik JSON response
    AuthentikResponse _ParseAuthentikResponse(const std::wstring& json);
    
    // Parse JSON string value
    std::wstring _ParseJsonString(const std::wstring& json, const std::wstring& key);
    
    // Escape JSON string
    std::wstring _EscapeJson(const std::wstring& input);
    
    // Cookie management
    void _SaveCookies(HINTERNET hRequest);
    void _AddCookies(HINTERNET hRequest);

    // Authentik configuration
    std::wstring _serverUrl;
    INTERNET_PORT _serverPort;
    std::wstring _flowSlug;
    bool _useHttps;
    bool _ignoreCertErrors;
    std::wstring _domain;
    std::wstring _domainFQDN;
    
    // Certificate Issuer configuration
    std::wstring _certIssuerUrl;
    INTERNET_PORT _certIssuerPort;
    std::wstring _certIssuerToken;
    
    // Configuration validation
    bool _configurationValid;
    std::wstring _configurationError;
    
    // Session state
    std::wstring _currentUsername;
    std::map<std::wstring, std::wstring> _cookies;
    std::wstring _csrfToken;
    std::wstring _flowExecutorUrl;
};
