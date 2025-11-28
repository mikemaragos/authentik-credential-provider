// AuthentikAPI.h
// Header for Authentik API client

#pragma once

#include <windows.h>
#include <winhttp.h>
#include <string>

// Response structure
struct AuthentikResponse
{
    bool success;
    bool requiresOTP;
    bool requiresPassword;  // For multi-stage flows where password is sent separately
    std::wstring message;
    std::wstring transactionId;
    std::wstring windowsPassword;  // For passwordless scenarios
};

class AuthentikAPI
{
public:
    AuthentikAPI();
    ~AuthentikAPI();

    // Initiate authentication flow
    AuthentikResponse InitiateAuthentication(const std::wstring& username, const std::wstring& password);

    // Validate OTP
    AuthentikResponse ValidateOTP(const std::wstring& username, const std::wstring& otp, const std::wstring& transactionId);

    // Reset the session (clear cookies)
    void ResetSession();

private:
    // Load configuration from registry
    void _LoadConfiguration();

    // Initialize HTTP session
    bool _InitializeSession();

    // Make HTTP request to Authentik (uses persistent session for cookies)
    HRESULT _MakeHttpRequest(const std::wstring& method, const std::wstring& url, const std::wstring& payload, std::wstring& responseBody);

    // Parse Authentik JSON response
    AuthentikResponse _ParseAuthentikResponse(const std::wstring& json);

    // Extract a string value from JSON
    std::wstring _ExtractJsonString(const std::wstring& json, const std::wstring& key);

    // Configuration
    std::wstring _serverUrl;
    INTERNET_PORT _serverPort;
    std::wstring _flowSlug;
    bool _useHttps;
    bool _ignoreSslErrors;  // For testing with self-signed certificates

    // Persistent session handles for cookie management
    HINTERNET _hSession;
    HINTERNET _hConnect;
};
