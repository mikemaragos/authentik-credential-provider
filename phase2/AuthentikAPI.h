// AuthentikAPI.h
// Header for Authentik API client - Phase 2 (Passwordless with Certificate)

#pragma once

#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>

// Response structure for OTP validation
struct AuthentikResponse
{
    bool success;
    std::wstring message;
    std::wstring transactionId;
};

// Response structure for certificate issuance
struct CertificateResponse
{
    bool success;
    std::wstring message;
    std::vector<BYTE> certificateDer;      // Certificate in DER format
    std::vector<BYTE> privateKeyBlob;       // Private key blob for import
    std::wstring subjectKeyIdentifier;      // SKI for AD mapping verification
};

class AuthentikAPI
{
public:
    AuthentikAPI();
    ~AuthentikAPI();

    // Validate OTP with Authentik
    // Returns success/failure and triggers certificate issuance on success
    AuthentikResponse ValidateOTP(const std::wstring& username, const std::wstring& otp);

    // Request certificate from CertIssuer after OTP validation
    // CertIssuer handles: AD CS request, SKI extraction, altSecurityIdentities update
    CertificateResponse RequestCertificate(const std::wstring& username, const std::wstring& domain);

    // Combined: Validate OTP and get certificate in one call
    // This is the main entry point for the credential provider
    CertificateResponse AuthenticateAndGetCertificate(
        const std::wstring& username, 
        const std::wstring& otp,
        const std::wstring& domain);

private:
    // Load configuration from registry
    void _LoadConfiguration();

    // Make HTTP request to Authentik/CertIssuer
    HRESULT _MakeHttpRequest(
        const std::wstring& server,
        INTERNET_PORT port,
        const std::wstring& method, 
        const std::wstring& url, 
        const std::wstring& payload, 
        std::wstring& responseBody,
        std::vector<BYTE>* binaryResponse = nullptr);

    // Parse JSON responses
    AuthentikResponse _ParseOTPResponse(const std::wstring& json);
    CertificateResponse _ParseCertificateResponse(const std::wstring& json, const std::vector<BYTE>& binaryData);

    // Extract value from simple JSON
    std::wstring _ExtractJsonValue(const std::wstring& json, const std::wstring& key);
    
    // Base64 decode
    std::vector<BYTE> _Base64Decode(const std::wstring& base64);

    // Configuration - Authentik server
    std::wstring _authentikServer;
    INTERNET_PORT _authentikPort;
    std::wstring _flowSlug;
    bool _useHttps;

    // Configuration - CertIssuer server
    std::wstring _certIssuerServer;
    INTERNET_PORT _certIssuerPort;
    std::wstring _certIssuerApiToken;

    // HTTP session cookies for multi-step auth
    std::wstring _sessionCookies;
};
