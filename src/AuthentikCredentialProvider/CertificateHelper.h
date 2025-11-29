// CertificateHelper.h
// Certificate parsing, import, and management for PKINIT authentication

#pragma once

#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <NTSecAPI.h>
#include <string>
#include <vector>

// Link required libraries
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "NCrypt.lib")
#pragma comment(lib, "BCrypt.lib")

// Certificate bundle received from Authentik/Cert Issuer
struct CertificateBundle
{
    // PEM format (legacy/alternative)
    std::string certificate;        // PEM-encoded certificate
    std::string privateKey;         // PEM-encoded private key
    std::vector<std::string> caChain;  // PEM-encoded CA chain
    
    // PFX format (preferred - from cert issuer)
    std::wstring pfxBase64;         // Base64-encoded PFX/PKCS#12
    std::wstring pfxPassword;       // Password for the PFX
    
    // User info
    std::wstring username;
    std::wstring domain;
    std::wstring upn;               // User Principal Name
    DWORD validMinutes;
    
    // Parsed handles (populated by ParseCertificateBundle)
    PCCERT_CONTEXT pCertContext;
    NCRYPT_KEY_HANDLE hKey;
    HCERTSTORE hMemStore;
    
    CertificateBundle() : pCertContext(NULL), hKey(0), hMemStore(NULL), validMinutes(5) {}
    
    // Check if PFX data is available
    bool HasPfx() const { return !pfxBase64.empty() && !pfxPassword.empty(); }
    
    // Check if PEM data is available
    bool HasPem() const { return !certificate.empty() && !privateKey.empty(); }
    
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
    }
};

// Smart Card CSP Info structure for KERB_CERTIFICATE_LOGON
// This mimics what a smart card would provide
#pragma pack(push, 1)
typedef struct _AUTHENTIK_SMARTCARD_CSP_INFO {
    DWORD dwCspInfoLen;
    DWORD MessageType;              // Always 1
    union {
        PVOID ContextInformation;
        ULONG64 SpaceHolderForWow64;
    };
    DWORD flags;
    DWORD KeySpec;                  // AT_KEYEXCHANGE (1) or AT_SIGNATURE (2)
    ULONG nCardNameOffset;
    ULONG nReaderNameOffset;
    ULONG nContainerNameOffset;
    ULONG nCSPNameOffset;
    // Variable length buffer follows containing null-terminated strings:
    // CardName, ReaderName, ContainerName, CSPName
    WCHAR bBuffer[1];
} AUTHENTIK_SMARTCARD_CSP_INFO, *PAUTHENTIK_SMARTCARD_CSP_INFO;
#pragma pack(pop)

// Use Windows SDK KERB_CERTIFICATE_LOGON if available, otherwise define our own
// The SDK version is in NTSecAPI.h on Windows 10+
#ifndef KERB_CERTIFICATE_LOGON_FLAG_CHECK_DUPLICATES
#define KERB_CERTIFICATE_LOGON_FLAG_CHECK_DUPLICATES 0x1
#endif

#ifndef KERB_CERTIFICATE_LOGON_FLAG_USE_CERTIFICATE_INFO
#define KERB_CERTIFICATE_LOGON_FLAG_USE_CERTIFICATE_INFO 0x2
#endif

// Certificate logon message type values
// These are the KERB_LOGON_SUBMIT_TYPE enum values
#define AUTHENTIK_KerbCertificateLogon 13
#define AUTHENTIK_KerbCertificateUnlockLogon 15

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
    HRESULT ImportCertificateForPKINIT(
        CertificateBundle& bundle);

    // Build KERB_CERTIFICATE_LOGON structure for serialization
    HRESULT BuildCertificateLogon(
        const CertificateBundle& bundle,
        BYTE** ppPackage,
        DWORD* pcbPackage);

    // Build CSP Info structure
    HRESULT BuildCspInfo(
        const std::wstring& containerName,
        const std::wstring& providerName,
        BYTE** ppCspInfo,
        DWORD* pcbCspInfo);

    // Clean up certificate handles
    void CleanupCertificate(CertificateBundle& bundle);

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

    // Storage provider for ephemeral keys
    NCRYPT_PROV_HANDLE _hProvider;
    
    // Container name for this session
    std::wstring _containerName;
};

// Factory function
HRESULT CertificateHelper_CreateInstance(CertificateHelper** ppHelper);
