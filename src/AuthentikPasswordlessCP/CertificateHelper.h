// CertificateHelper.h
// Certificate parsing, import, and management for PKINIT authentication

#pragma once

#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <ntsecapi.h>
#include <string>
#include <vector>

// Certificate bundle received from Authentik
struct CertificateBundle
{
    std::string certificate;        // PEM-encoded certificate
    std::string privateKey;         // PEM-encoded private key
    std::vector<std::string> caChain;  // PEM-encoded CA chain
    std::wstring username;
    std::wstring domain;
    std::wstring upn;               // User Principal Name
    DWORD validMinutes;
    
    // Parsed handles (populated by ParseCertificateBundle)
    PCCERT_CONTEXT pCertContext;
    NCRYPT_KEY_HANDLE hKey;
    HCERTSTORE hMemStore;
    
    CertificateBundle() : pCertContext(nullptr), hKey(0), hMemStore(nullptr), validMinutes(5) {}
    
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
            pCertContext = nullptr;
        }
        if (hMemStore)
        {
            CertCloseStore(hMemStore, 0);
            hMemStore = nullptr;
        }
        
        // Secure clear sensitive data
        SecureZeroMemory(&privateKey[0], privateKey.size());
        privateKey.clear();
    }
};

// Smart Card CSP Info structure for KERB_CERTIFICATE_LOGON
// This mimics what a smart card would provide
#pragma pack(push, 1)
typedef struct _KERB_SMARTCARD_CSP_INFO {
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
} KERB_SMARTCARD_CSP_INFO, *PKERB_SMARTCARD_CSP_INFO;
#pragma pack(pop)

// KERB_CERTIFICATE_LOGON structure
typedef struct _KERB_CERTIFICATE_LOGON {
    KERB_LOGON_SUBMIT_TYPE MessageType;
    UNICODE_STRING DomainName;
    UNICODE_STRING UserName;
    UNICODE_STRING Pin;
    ULONG Flags;
    ULONG CspDataLength;
    PUCHAR CspData;
} KERB_CERTIFICATE_LOGON, *PKERB_CERTIFICATE_LOGON;

// Flags for KERB_CERTIFICATE_LOGON
#define KERB_CERTIFICATE_LOGON_FLAG_CHECK_DUPLICATES 0x1
#define KERB_CERTIFICATE_LOGON_FLAG_USE_CERTIFICATE_INFO 0x2

// Certificate logon message type
#define KerbCertificateLogon 13
#define KerbCertificateUnlockLogon 15

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

    // Storage provider for ephemeral keys
    NCRYPT_PROV_HANDLE _hProvider;
    
    // Container name for this session
    std::wstring _containerName;
};

// Factory function
HRESULT CertificateHelper_CreateInstance(CertificateHelper** ppHelper);
