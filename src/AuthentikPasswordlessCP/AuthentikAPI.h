// AuthentikAPI.h
// HTTP client for Authentik API communication
// Supports passwordless authentication with certificate response

#pragma once

#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <map>

// Authentication response types
enum class AuthResponseType
{
    ERROR,
    NEED_USERNAME,
    NEED_OTP,
    SUCCESS_WITH_CERTIFICATE,
    SUCCESS_REDIRECT
};

// OTP challenge types supported
enum class OTPChallengeType
{
    TOTP,           // Time-based OTP
    STATIC,         // Static token
    PUSH,           // Push notification
    WEBAUTHN,       // Security key
    SMS,            // SMS code
    EMAIL           // Email code
};

// Response structure from Authentik
struct AuthentikResponse
{
    AuthResponseType type;
    std::wstring message;
    std::wstring transactionId;
    std::wstring flowToken;         // Flow execution token for multi-step
    
    // OTP challenge info
    bool requiresOTP;
    OTPChallengeType otpType;
    std::wstring otpPrompt;
    
    // Certificate response (on success)
    bool hasCertificate;
    std::wstring certificatePem;
    std::wstring privateKeyPem;
    std::vector<std::wstring> caChainPem;
    std::wstring username;
    std::wstring domain;
    std::wstring upn;
    DWORD certValidMinutes;
    
    // Raw response for debugging
    std::wstring rawResponse;
    
    AuthentikResponse() : 
        type(AuthResponseType::ERROR),
        requiresOTP(false),
        otpType(OTPChallengeType::TOTP),
        hasCertificate(false),
        certValidMinutes(5)
    {}
    
    void Clear()
    {
        type = AuthResponseType::ERROR;
        message.clear();
        transactionId.clear();
        flowToken.clear();
        requiresOTP = false;
        otpPrompt.clear();
        hasCertificate = false;
        certificatePem.clear();
        
        // Secure clear private key
        SecureZeroMemory(&privateKeyPem[0], privateKeyPem.size() * sizeof(wchar_t));
        privateKeyPem.clear();
        
        caChainPem.clear();
        username.clear();
        domain.clear();
        upn.clear();
        certValidMinutes = 5;
        rawResponse.clear();
    }
};

class AuthentikAPI
{
public:
    AuthentikAPI();
    ~AuthentikAPI();

    // Initialize and load configuration
    HRESULT Initialize();
    
    // Step 1: Initiate authentication flow with username
    AuthentikResponse InitiateAuthentication(const std::wstring& username);
    
    // Step 2: Submit OTP code
    AuthentikResponse SubmitOTP(const std::wstring& otp);
    
    // Get current flow state
    const std::wstring& GetCurrentFlowToken() const { return _currentFlowToken; }
    const std::wstring& GetCurrentUsername() const { return _currentUsername; }
    
    // Reset flow state
    void ResetFlow();

    // Configuration getters
    const std::wstring& GetServerUrl() const { return _serverUrl; }
    const std::wstring& GetDomain() const { return _domain; }
    const std::wstring& GetDomainFQDN() const { return _domainFQDN; }

private:
    // Load configuration from registry
    void _LoadConfiguration();
    
    // Make HTTP request to Authentik
    HRESULT _MakeHttpRequest(
        const std::wstring& method,
        const std::wstring& url,
        const std::wstring& payload,
        std::wstring& responseBody);
    
    // Parse Authentik API response
    AuthentikResponse _ParseResponse(const std::wstring& json);
    
    // Extract certificate bundle from response
    HRESULT _ExtractCertificateBundle(
        const std::wstring& json,
        AuthentikResponse& response);
    
    // Cookie management for session persistence
    void _SaveCookies(HINTERNET hRequest);
    void _ApplyCookies(HINTERNET hRequest);
    
    // Configuration
    std::wstring _serverUrl;
    INTERNET_PORT _serverPort;
    std::wstring _flowSlug;
    bool _useHttps;
    std::wstring _domain;
    std::wstring _domainFQDN;
    DWORD _certValidMinutes;
    bool _ignoreCertErrors;     // For testing only!
    
    // Session state
    std::wstring _currentFlowToken;
    std::wstring _currentUsername;
    std::map<std::wstring, std::wstring> _cookies;
    
    // HTTP handles
    HINTERNET _hSession;
};

// Factory function
HRESULT AuthentikAPI_CreateInstance(AuthentikAPI** ppAPI);
