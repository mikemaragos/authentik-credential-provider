// CredentialPacking.h
// Header for smart card credential serialization
// 
// CRITICAL IMPLEMENTATION NOTES:
// 1. KERB_SMARTCARD_CSP_INFO requires 1-byte packing (#pragma pack(push, 1))
// 2. CSP INFO MessageType is ALWAYS 1 (not the logon type!)
// 3. CSP INFO string offsets are CHARACTER COUNT (WCHAR units), NOT bytes
// 4. For credential providers, UNICODE_STRING.Buffer is a BYTE OFFSET, not pointer
// 5. All data must be in a single contiguous memory block
//
// References:
// - IDRIX LsaSmartCardLogon.cpp: http://www.idrix.fr/Root/Samples/LsaSmartCardLogon.cpp
// - Microsoft helpers.cpp: github.com/microsoft/Windows-classic-samples/blob/main/Samples/CredentialProvider/cpp/helpers.cpp
// - Microsoft KERB_SMARTCARD_CSP_INFO: learn.microsoft.com/en-us/windows/win32/secauthn/kerb-smartcard-csp-info

#pragma once

#include <windows.h>
#include <ntsecapi.h>
#include <string>

// KeySpec values from WinCrypt.h
#ifndef AT_KEYEXCHANGE
#define AT_KEYEXCHANGE 1
#endif
#ifndef AT_SIGNATURE
#define AT_SIGNATURE 2
#endif

// KERB_CERTIFICATE_LOGON MessageType values
// Note: These are defined in ntsecapi.h but may not be available in all SDK versions
#ifndef KerbCertificateLogon
#define KerbCertificateLogon 13
#endif
#ifndef KerbCertificateUnlockLogon
#define KerbCertificateUnlockLogon 15
#endif

//=============================================================================
// KERB_SMARTCARD_CSP_INFO Structure
//
// CRITICAL: This structure requires 1-byte packing!
// CRITICAL: MessageType must ALWAYS be 1 (not the logon type!)
// CRITICAL: Offsets are CHARACTER COUNT (WCHAR units), not bytes!
//
// From Microsoft documentation:
// "The type of message being passed. This member must be set to 1."
// "The number of characters in the bBuffer buffer that precede the name..."
//=============================================================================
#pragma pack(push, 1)
typedef struct _MY_KERB_SMARTCARD_CSP_INFO
{   
    DWORD dwCspInfoLen;              // Total size in BYTES (including strings)
    DWORD MessageType;               // MUST be 1 (not logon type!)
    union {     
        PVOID ContextInformation;    // Not used
        ULONG64 SpaceHolderForWow64; // For 32/64-bit compatibility
    }; 
    DWORD flags;                     // Usually 0
    DWORD KeySpec;                   // AT_KEYEXCHANGE (1) or AT_SIGNATURE (2)
    ULONG nCardNameOffset;           // CHARACTER offset to card name in bBuffer
    ULONG nReaderNameOffset;         // CHARACTER offset to reader name
    ULONG nContainerNameOffset;      // CHARACTER offset to container name
    ULONG nCSPNameOffset;            // CHARACTER offset to CSP name
    TCHAR bBuffer;                   // Start of string buffer (placeholder)
} MY_KERB_SMARTCARD_CSP_INFO, *PMY_KERB_SMARTCARD_CSP_INFO;
#pragma pack(pop)

//=============================================================================
// Virtual Smart Card Information Structure
//=============================================================================
struct VSCInfo
{
    std::wstring readerName;         // e.g., "Microsoft Virtual Smart Card 0"
    std::wstring containerName;      // Certificate container/thumbprint
    std::wstring cspName;            // e.g., "Microsoft Base Smart Card Crypto Provider"
    std::wstring cardName;           // Usually empty string ""
    std::wstring pin;                // VSC PIN
};

//=============================================================================
// Function Declarations
//=============================================================================

// Pack credentials for smart card certificate logon (credential provider format)
// Returns: S_OK on success, error HRESULT on failure
// 
// Parameters:
//   username     - User name (optional, helps KDC find account)
//   domain       - Domain name (optional, uppercase for Kerberos realm)
//   vscInfo      - Virtual smart card information
//   isUnlock     - true for unlock, false for logon
//   ppPackage    - [out] Receives allocated buffer (CoTaskMemAlloc)
//   pcbPackage   - [out] Receives buffer size in bytes
//
// NOTES:
// - Buffer is allocated with CoTaskMemAlloc (caller must free)
// - UNICODE_STRING.Buffer values are BYTE OFFSETS, not pointers
// - CSP data is embedded at the end of the buffer
// - All strings are packed contiguously after the structure
HRESULT PackKerbCertificateLogon(
    const std::wstring& username,
    const std::wstring& domain,
    const VSCInfo& vscInfo,
    bool isUnlock,
    BYTE** ppPackage,
    DWORD* pcbPackage);

// Build KERB_SMARTCARD_CSP_INFO structure with string data
// Returns: S_OK on success, error HRESULT on failure
//
// Parameters:
//   vscInfo      - Virtual smart card information
//   ppCspInfo    - [out] Receives allocated buffer (HeapAlloc)
//   pcbCspInfo   - [out] Receives buffer size in bytes
//
// NOTES:
// - Uses 1-byte packing
// - MessageType is set to 1 (not logon type!)
// - Offsets are CHARACTER COUNT (WCHAR units)
HRESULT BuildSmartCardCspInfo(
    const VSCInfo& vscInfo,
    BYTE** ppCspInfo,
    DWORD* pcbCspInfo);

// Helper: Calculate the size of a packed KERB_CERTIFICATE_LOGON structure
DWORD CalculatePackedCertificateLogonSize(
    const std::wstring& username,
    const std::wstring& domain,
    const std::wstring& pin,
    DWORD cbCspInfo);

// Legacy functions from Phase 1 (for fallback to password auth)
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
