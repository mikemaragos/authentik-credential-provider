// AuthentikAPI.h
// Header for Authentik API client - Phase 2 (Passwordless with Certificate)
// Updated December 8, 2025 - PFX support from CertIssuer

#pragma once

#include <windows.h>
#include <winhttp.h>
#include <objbase.h>
#include <string>
#include <vector>

#pragma comment(lib, "ole32.lib")

// Response structure for OTP validation
struct AuthentikResponse
{
    bool success;
    std::wstring message;
    std::wstring transactionId;
};

// Response structure for certificate issuance from CertIssuer
struct CertificateResponse
{
    bool success;
    std::wstring message;
    
    // PFX (PKCS#12) containing certificate and private key
    std::vector<BYTE> pfxData;
    std::wstring pfxPassword;
    
    // Certificate in DER format (for verification)
    std::vector<BYTE> certificateDer;
    
    // SKI for AD mapping verification
    std::wstring subjectKeyIdentifier;
    std::wstring thumbprint;
    std::wstring upn;
    
    // Did CertIssuer update AD?
    bool adMappingUpdated;
};

class AuthentikAPI
{
public:
    AuthentikAPI();
    ~AuthentikAPI();

    // Validate OTP with Authentik
    AuthentikResponse ValidateOTP(const std::wstring& username, const std::wstring& otp);

    // Request certificate from CertIssuer (after OTP validation)
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

    // Make HTTP request
    HRESULT _MakeHttpRequest(
        const std::wstring& server,
        INTERNET_PORT port,
        bool useHttps,
        const std::wstring& method, 
        const std::wstring& path, 
        const std::wstring& payload,
        const std::wstring& authHeader,
        std::wstring& responseBody);

    // Parse JSON responses
    AuthentikResponse _ParseOTPResponse(const std::wstring& json);
    CertificateResponse _ParseCertificateResponse(const std::wstring& json);

    // Extract value from simple JSON
    std::wstring _ExtractJsonValue(const std::wstring& json, const std::wstring& key);
    bool _ExtractJsonBool(const std::wstring& json, const std::wstring& key);
    
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
