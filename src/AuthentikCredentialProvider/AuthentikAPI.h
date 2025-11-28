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

private:
    // Load configuration from registry
    void _LoadConfiguration();

    // Make HTTP request to Authentik
    HRESULT _MakeHttpRequest(const std::wstring& method, const std::wstring& url, const std::wstring& payload, std::wstring& responseBody);

    // Parse Authentik JSON response
    AuthentikResponse _ParseAuthentikResponse(const std::wstring& json);

    // Configuration
    std::wstring _serverUrl;
    INTERNET_PORT _serverPort;
    std::wstring _flowSlug;
    bool _useHttps;
    bool _ignoreSslErrors;  // For testing with self-signed certificates
};
