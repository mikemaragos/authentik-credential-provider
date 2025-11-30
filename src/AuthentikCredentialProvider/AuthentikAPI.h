// AuthentikAPI.h
// Header for Authentik API client with certificate support

#pragma once

#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>

// Response structure for authentication
struct AuthentikResponse
{
    bool success;
    bool requiresOTP;
    std::wstring message;
    std::wstring transactionId;
    std::wstring flowToken;          // Session token for multi-step flow
};

// Response structure for certificate issuance
struct CertificateResponse
{
    bool success;
    std::wstring message;
    std::wstring thumbprint;
    std::wstring subject;
    std::wstring upn;
    std::vector<BYTE> pfxData;       // PFX file content
    std::wstring pfxPassword;        // Password to open PFX
    std::wstring notBefore;
    std::wstring notAfter;
};

class AuthentikAPI
{
public:
    AuthentikAPI();
    ~AuthentikAPI();

    // Authentication flow - Step 1: Submit username, get OTP challenge
    AuthentikResponse InitiateAuthentication(const std::wstring& username);

    // Authentication flow - Step 2: Validate OTP
    AuthentikResponse ValidateOTP(const std::wstring& username, const std::wstring& otp, const std::wstring& flowToken);

    // Certificate flow - Request certificate after successful OTP validation
    CertificateResponse RequestCertificate(const std::wstring& username, const std::wstring& upn, const std::wstring& authToken);

private:
    // Load configuration from registry
    void _LoadConfiguration();

    // Make HTTP request to Authentik
    HRESULT _MakeHttpRequest(
        const std::wstring& method,
        const std::wstring& url,
        const std::wstring& payload,
        std::wstring& responseBody,
        const std::wstring& authHeader = L"");

    // Make HTTP request to Certificate Issuer service
    HRESULT _MakeCertRequest(
        const std::wstring& url,
        const std::wstring& payload,
        std::wstring& responseBody);

    // Parse Authentik JSON response
    AuthentikResponse _ParseAuthentikResponse(const std::wstring& json);

    // Parse Certificate Issuer JSON response
    CertificateResponse _ParseCertificateResponse(const std::wstring& json);

    // Extract JSON string value (simple parser)
    std::wstring _ExtractJsonString(const std::wstring& json, const std::wstring& key);

    // Base64 decode
    std::vector<BYTE> _Base64Decode(const std::wstring& base64);

    // Configuration - Authentik
    std::wstring _serverUrl;
    INTERNET_PORT _serverPort;
    std::wstring _flowSlug;
    bool _useHttps;

    // Configuration - Certificate Issuer
    std::wstring _certIssuerUrl;
    INTERNET_PORT _certIssuerPort;
    std::wstring _certIssuerToken;
    std::wstring _domain;
    std::wstring _upnSuffix;

    // Session state
    std::wstring _sessionCookies;
};
