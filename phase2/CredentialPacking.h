// CredentialPacking.h
// Header for credential serialization functions - Phase 2 (Smart Card/Certificate)

#pragma once

#include <windows.h>
#include <NTSecAPI.h>
#include <string>
#include <vector>

// KERB_CERTIFICATE_LOGON message type
#define KerbCertificateLogon 11
#define KerbCertificateUnlockLogon 12

// KERB_SMARTCARD_CSP_INFO structure (not fully defined in SDK)
#pragma pack(push, 1)
typedef struct _KERB_SMARTCARD_CSP_INFO {
    DWORD dwCspInfoLen;
    DWORD MessageType;          // Must be 1
    union {
        PVOID ContextInformation;
        ULONG64 SpaceHolderForWow64;
    };
    DWORD flags;
    DWORD KeySpec;              // AT_KEYEXCHANGE = 1
    ULONG nCardNameOffset;
    ULONG nReaderNameOffset;
    ULONG nContainerNameOffset;
    ULONG nCSPNameOffset;
    TCHAR bBuffer[1];           // Variable length buffer
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
    PUCHAR CspData;             // Points to KERB_SMARTCARD_CSP_INFO
} KERB_CERTIFICATE_LOGON, *PKERB_CERTIFICATE_LOGON;

// KERB_CERTIFICATE_UNLOCK_LOGON structure
typedef struct _KERB_CERTIFICATE_UNLOCK_LOGON {
    KERB_CERTIFICATE_LOGON Logon;
    LUID LogonId;
} KERB_CERTIFICATE_UNLOCK_LOGON, *PKERB_CERTIFICATE_UNLOCK_LOGON;

// VSC (Virtual Smart Card) information
struct VSCInfo {
    std::wstring readerName;
    std::wstring containerName;
    std::wstring cspName;
    std::wstring cardName;
};

// Pack credentials for smart card certificate logon
HRESULT PackKerbCertificateLogon(
    const std::wstring& username,
    const std::wstring& domain,
    const std::wstring& pin,
    const VSCInfo& vscInfo,
    BYTE** ppPackage,
    DWORD* pcbPackage);

// Pack credentials for smart card certificate unlock
HRESULT PackKerbCertificateUnlockLogon(
    const std::wstring& username,
    const std::wstring& domain,
    const std::wstring& pin,
    const VSCInfo& vscInfo,
    BYTE** ppPackage,
    DWORD* pcbPackage);

// Helper to build KERB_SMARTCARD_CSP_INFO
HRESULT BuildSmartCardCspInfo(
    const VSCInfo& vscInfo,
    BYTE** ppCspInfo,
    DWORD* pcbCspInfo);

// Legacy functions (kept for compatibility)
HRESULT PackKerbInteractiveLogon(
    const std::wstring& username,
    const std::wstring& password,
    const std::wstring& domain,
    BYTE** ppPackage,
    DWORD* pcbPackage);

HRESULT PackKerbInteractiveUnlockLogon(
    const std::wstring& username,
    const std::wstring& password,
    const std::wstring& domain,
    BYTE** ppPackage,
    DWORD* pcbPackage);
