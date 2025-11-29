// CertificateHelper.h
// Certificate parsing, import, and management for PKINIT authentication
//
// This module handles:
// - Parsing certificates from Authentik/cert issuer responses
// - Storing keys in the KSP shared memory
// - Building KERB_CERTIFICATE_LOGON structures for Windows authentication

#pragma once

#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <NTSecAPI.h>
#include <string>
#include <vector>

// Include shared memory structures (defines all AUTHENTIK_* constants and structures)
#include "SharedMemory.h"

// Link required libraries
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "NCrypt.lib")
#pragma comment(lib, "BCrypt.lib")

// ============================================================================
// Certificate Bundle Structure
// ============================================================================

// Certificate bundle received from Authentik/Cert Issuer
struct CertificateBundle
{
    // PEM format (legacy/alternative)
    std::string certificate;            // PEM-encoded certificate
    std::string privateKey;             // PEM-encoded private key
    std::vector<std::string> caChain;   // PEM-encoded CA chain
    
    // PFX format (preferred - from cert issuer)
    std::wstring pfxBase64;             // Base64-encoded PFX/PKCS#12
    std::wstring pfxPassword;           // Password for the PFX
    
    // User info
    std::wstring username;
    std::wstring domain;
    std::wstring upn;                   // User Principal Name
    DWORD validMinutes;
    
    // Parsed handles (populated by ParseCertificateBundle)
    PCCERT_CONTEXT pCertContext;
    NCRYPT_KEY_HANDLE hKey;
    HCERTSTORE hMemStore;
    
    // Extracted private key blob (BCRYPT_RSAPRIVATE_BLOB format)
    // This is populated by ParsePfxBundle and used by BuildCertificateLogon
    std::vector<BYTE> privateKeyBlob;
    
    CertificateBundle() : 
        pCertContext(NULL), 
        hKey(0), 
        hMemStore(NULL), 
        validMinutes(AUTHENTIK_DEFAULT_KEY_VALIDITY) 
    {}
    
    // Check if PFX data is available
    bool HasPfx() const { return !pfxBase64.empty() && !pfxPassword.empty(); }
    
    // Check if PEM data is available
    bool HasPem() const { return !certificate.empty() && !privateKey.empty(); }
    
    // Check if we have a usable private key
    bool HasPrivateKey() const { return hKey != 0 || !privateKeyBlob.empty(); }
    
    // Cleanup method
    void Cleanup()
    {
        if (hKey)
        {
            NCryptFreeObject(hKey);
            hKey = 0;
        }
        if (pCertContext)
        {
            CertFreeCertificateContext(pCertContext);
            pCertContext = NULL;
        }
        if (hMemStore)
        {
            CertCloseStore(hMemStore, 0);
            hMemStore = NULL;
        }
        
        // Secure clear sensitive data
        if (!privateKey.empty())
        {
            SecureZeroMemory(&privateKey[0], privateKey.size());
            privateKey.clear();
        }
        if (!pfxPassword.empty())
        {
            SecureZeroMemory(&pfxPassword[0], pfxPassword.size() * sizeof(wchar_t));
            pfxPassword.clear();
        }
        if (!pfxBase64.empty())
        {
            SecureZeroMemory(&pfxBase64[0], pfxBase64.size() * sizeof(wchar_t));
            pfxBase64.clear();
        }
        if (!privateKeyBlob.empty())
        {
            SecureZeroMemory(privateKeyBlob.data(), privateKeyBlob.size());
            privateKeyBlob.clear();
        }
    }
};

// ============================================================================
// CertificateHelper Class
// ============================================================================

class CertificateHelper
{
public:
    CertificateHelper();
    ~CertificateHelper();

    // Parse JSON response from Authentik and populate CertificateBundle
    HRESULT ParseAuthResponseForCertificate(
        const std::wstring& jsonResponse,
        CertificateBundle& bundle);

    // Parse PEM certificate and private key, create Windows crypto handles
    HRESULT ParseCertificateBundle(CertificateBundle& bundle);
    
    // Parse PFX (PKCS#12) file, create Windows crypto handles
    HRESULT ParsePfxBundle(CertificateBundle& bundle);

    // Import certificate and key into ephemeral store for PKINIT
    HRESULT ImportCertificateForPKINIT(CertificateBundle& bundle);

    // Build KERB_CERTIFICATE_LOGON structure for serialization
    // This stores the key in the KSP's shared memory and references our KSP
    HRESULT BuildCertificateLogon(
        const CertificateBundle& bundle,
        BYTE** ppPackage,
        DWORD* pcbPackage);

    // Build CSP Info structure for KERB_CERTIFICATE_LOGON
    HRESULT BuildCspInfo(
        const std::wstring& containerName,
        const std::wstring& providerName,
        BYTE** ppCspInfo,
        DWORD* pcbCspInfo);

    // Clean up certificate handles
    void CleanupCertificate(CertificateBundle& bundle);
    
    // Get the container name for this session
    const std::wstring& GetContainerName() const { return _containerName; }

private:
    // Convert PEM to DER
    HRESULT PemToDer(
        const std::string& pem,
        const char* pemHeader,
        const char* pemFooter,
        std::vector<BYTE>& der);

    // Import private key from DER
    HRESULT ImportPrivateKey(
        const std::vector<BYTE>& keyDer,
        NCRYPT_KEY_HANDLE* phKey);

    // Associate private key with certificate
    HRESULT AssociateKeyWithCert(
        PCCERT_CONTEXT pCert,
        NCRYPT_KEY_HANDLE hKey);

    // Parse simple JSON value (basic implementation)
    std::wstring ParseJsonString(
        const std::wstring& json,
        const std::wstring& key);
    
    std::string ParseJsonStringNarrow(
        const std::wstring& json,
        const std::wstring& key);
    
    // Base64 decode
    HRESULT Base64Decode(
        const std::wstring& base64,
        std::vector<BYTE>& decoded);

    // Storage provider for ephemeral keys (used during parsing)
    NCRYPT_PROV_HANDLE _hProvider;
    
    // Container name for this session (format: AuthentikPKINIT_{GUID})
    std::wstring _containerName;
};

// Factory function
HRESULT CertificateHelper_CreateInstance(CertificateHelper** ppHelper);
