// CredentialPacking.h
// Header for credential serialization functions - Phase 2 (Smart Card/Certificate)
// December 8, 2025

#pragma once

#include <windows.h>
#include <wincrypt.h>
#include <NTSecAPI.h>
#include <objbase.h>
#include <string>
#include <vector>

#pragma comment(lib, "ole32.lib")

// KERB_CERTIFICATE_LOGON message types
#ifndef KerbCertificateLogon
#define KerbCertificateLogon 11
#endif

#ifndef KerbCertificateUnlockLogon
#define KerbCertificateUnlockLogon 12
#endif

// AT_KEYEXCHANGE if not defined
#ifndef AT_KEYEXCHANGE
#define AT_KEYEXCHANGE 1
#endif

// VSC (Virtual Smart Card) information - single definition
struct VSCInfo {
    std::wstring readerName;      // e.g., "Microsoft Virtual Smart Card 0"
    std::wstring containerName;   // Key container name
    std::wstring cspName;         // "Microsoft Base Smart Card Crypto Provider"
    std::wstring cardName;        // Card name (can be empty)
};

// KERB_SMARTCARD_CSP_INFO structure
// This structure is not fully documented in the SDK
#pragma pack(push, 1)
typedef struct _MY_KERB_SMARTCARD_CSP_INFO {
    DWORD dwCspInfoLen;         // Total length of this structure including strings
    DWORD MessageType;          // Must be 1
    union {
        PVOID ContextInformation;
        ULONG64 SpaceHolderForWow64;
    };
    DWORD flags;                // 0
    DWORD KeySpec;              // AT_KEYEXCHANGE = 1
    ULONG nCardNameOffset;      // Offset to card name in bBuffer
    ULONG nReaderNameOffset;    // Offset to reader name in bBuffer
    ULONG nContainerNameOffset; // Offset to container name in bBuffer
    ULONG nCSPNameOffset;       // Offset to CSP name in bBuffer
    WCHAR bBuffer[1];           // Variable length buffer containing strings
} MY_KERB_SMARTCARD_CSP_INFO, *PMY_KERB_SMARTCARD_CSP_INFO;
#pragma pack(pop)

// KERB_CERTIFICATE_LOGON structure (custom definition to avoid SDK conflicts)
typedef struct _MY_KERB_CERTIFICATE_LOGON {
    KERB_LOGON_SUBMIT_TYPE MessageType;  // KerbCertificateLogon or KerbCertificateUnlockLogon
    UNICODE_STRING DomainName;
    UNICODE_STRING UserName;
    UNICODE_STRING Pin;
    ULONG Flags;                // 0
    ULONG CspDataLength;        // Size of CspData
    PUCHAR CspData;             // Points to MY_KERB_SMARTCARD_CSP_INFO
} MY_KERB_CERTIFICATE_LOGON, *PMY_KERB_CERTIFICATE_LOGON;

// KERB_CERTIFICATE_UNLOCK_LOGON structure (for unlock scenarios)
typedef struct _MY_KERB_CERTIFICATE_UNLOCK_LOGON {
    MY_KERB_CERTIFICATE_LOGON Logon;
    LUID LogonId;
} MY_KERB_CERTIFICATE_UNLOCK_LOGON, *PMY_KERB_CERTIFICATE_UNLOCK_LOGON;

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
