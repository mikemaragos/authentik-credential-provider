// CredentialPacking.cpp
// Implementation of smart card credential serialization for Windows Credential Provider
//
// This implementation follows the patterns from:
// 1. IDRIX LsaSmartCardLogon.cpp - Working direct LsaLogonUser sample
// 2. Microsoft helpers.cpp - Credential provider packing example
//
// KEY DIFFERENCES between direct LsaLogonUser and Credential Provider:
// - Direct LsaLogonUser: UNICODE_STRING.Buffer is an actual memory pointer
// - Credential Provider: UNICODE_STRING.Buffer is a BYTE OFFSET from buffer start
//
// This file implements the Credential Provider format (byte offsets).

#include "CredentialPacking.h"
#include "Logger.h"
#include <vector>
#include <shlwapi.h>

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shlwapi.lib")

//=============================================================================
// BuildSmartCardCspInfo
//
// Builds a KERB_SMARTCARD_CSP_INFO structure with embedded string data.
// This function uses the IDRIX pattern which is proven to work.
//
// CRITICAL POINTS:
// - Uses 1-byte packing (structure is already defined with #pragma pack(push, 1))
// - MessageType = 1 (ALWAYS, not the logon type!)
// - String offsets are CHARACTER COUNT (WCHAR units), not bytes
//=============================================================================
HRESULT BuildSmartCardCspInfo(
    const VSCInfo& vscInfo,
    BYTE** ppCspInfo,
    DWORD* pcbCspInfo)
{
    LOG("BuildSmartCardCspInfo: reader=%S, container=%S", 
        vscInfo.readerName.c_str(), vscInfo.containerName.c_str());

    if (!ppCspInfo || !pcbCspInfo)
    {
        return E_INVALIDARG;
    }

    *ppCspInfo = nullptr;
    *pcbCspInfo = 0;

    // Calculate string sizes in BYTES (including null terminators)
    // Using size_t for safety, then convert to DWORD
    size_t cbCardName = (vscInfo.cardName.length() + 1) * sizeof(WCHAR);
    size_t cbReaderName = (vscInfo.readerName.length() + 1) * sizeof(WCHAR);
    size_t cbContainerName = (vscInfo.containerName.length() + 1) * sizeof(WCHAR);
    size_t cbCspName = (vscInfo.cspName.length() + 1) * sizeof(WCHAR);

    // Calculate total CSP INFO size
    // Formula from IDRIX: sizeof(struct) - sizeof(TCHAR) + all string bytes
    size_t cbCspInfo = sizeof(MY_KERB_SMARTCARD_CSP_INFO) - sizeof(TCHAR) +
        cbCardName + cbReaderName + cbContainerName + cbCspName;

    LOG("CSP INFO sizes - Total: %zu, Card: %zu, Reader: %zu, Container: %zu, CSP: %zu",
        cbCspInfo, cbCardName, cbReaderName, cbContainerName, cbCspName);

    // Allocate buffer
    BYTE* pBuffer = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbCspInfo);
    if (!pBuffer)
    {
        LOG("ERROR: Failed to allocate CSP INFO buffer");
        return E_OUTOFMEMORY;
    }

    // Cast to structure
    PMY_KERB_SMARTCARD_CSP_INFO pCspInfo = (PMY_KERB_SMARTCARD_CSP_INFO)pBuffer;

    // Fill structure fields
    pCspInfo->dwCspInfoLen = (DWORD)cbCspInfo;
    pCspInfo->MessageType = 1;  // CRITICAL: Always 1, NOT the logon type!
    pCspInfo->ContextInformation = NULL;
    pCspInfo->flags = 0;
    pCspInfo->KeySpec = AT_KEYEXCHANGE;

    // Calculate string offsets (CHARACTER COUNT, not bytes!)
    // Order in buffer: CardName, ReaderName, ContainerName, CSPName
    pCspInfo->nCardNameOffset = 0;
    pCspInfo->nReaderNameOffset = (ULONG)(pCspInfo->nCardNameOffset + vscInfo.cardName.length() + 1);
    pCspInfo->nContainerNameOffset = (ULONG)(pCspInfo->nReaderNameOffset + vscInfo.readerName.length() + 1);
    pCspInfo->nCSPNameOffset = (ULONG)(pCspInfo->nContainerNameOffset + vscInfo.containerName.length() + 1);

    LOG("CSP INFO offsets (chars) - Card: %u, Reader: %u, Container: %u, CSP: %u",
        pCspInfo->nCardNameOffset, pCspInfo->nReaderNameOffset,
        pCspInfo->nContainerNameOffset, pCspInfo->nCSPNameOffset);

    // Calculate where string buffer starts (after structure, minus placeholder bBuffer)
    BYTE* pStringBuffer = pBuffer + sizeof(MY_KERB_SMARTCARD_CSP_INFO) - sizeof(TCHAR);

    // Copy strings to buffer
    // Note: Offsets are character positions, so we multiply by sizeof(WCHAR) for byte position
    memcpy(pStringBuffer + (pCspInfo->nCardNameOffset * sizeof(WCHAR)), 
           vscInfo.cardName.c_str(), cbCardName);
    
    memcpy(pStringBuffer + (pCspInfo->nReaderNameOffset * sizeof(WCHAR)), 
           vscInfo.readerName.c_str(), cbReaderName);
    
    memcpy(pStringBuffer + (pCspInfo->nContainerNameOffset * sizeof(WCHAR)), 
           vscInfo.containerName.c_str(), cbContainerName);
    
    memcpy(pStringBuffer + (pCspInfo->nCSPNameOffset * sizeof(WCHAR)), 
           vscInfo.cspName.c_str(), cbCspName);

    LOG("CSP INFO built successfully - MessageType: %u, KeySpec: %u, Size: %u",
        pCspInfo->MessageType, pCspInfo->KeySpec, pCspInfo->dwCspInfoLen);

    *ppCspInfo = pBuffer;
    *pcbCspInfo = (DWORD)cbCspInfo;

    return S_OK;
}

//=============================================================================
// CalculatePackedCertificateLogonSize
//
// Helper function to calculate total buffer size needed.
//=============================================================================
DWORD CalculatePackedCertificateLogonSize(
    const std::wstring& username,
    const std::wstring& domain,
    const std::wstring& pin,
    DWORD cbCspInfo)
{
    // String sizes including null terminators (for buffer allocation)
    DWORD cbDomain = (DWORD)((domain.length() + 1) * sizeof(WCHAR));
    DWORD cbUsername = (DWORD)((username.length() + 1) * sizeof(WCHAR));
    DWORD cbPin = (DWORD)((pin.length() + 1) * sizeof(WCHAR));

    // Total size: structure + all strings + CSP INFO
    return sizeof(KERB_CERTIFICATE_LOGON) + cbDomain + cbUsername + cbPin + cbCspInfo;
}

//=============================================================================
// PackKerbCertificateLogon
//
// Packs credentials into KERB_CERTIFICATE_LOGON format for credential provider.
//
// CRITICAL: For credential providers, UNICODE_STRING.Buffer is a BYTE OFFSET
// from the start of the buffer, NOT an actual pointer!
//
// From Microsoft helpers.cpp:
// "WinLogon and LSA consume 'packed' KERB_INTERACTIVE_UNLOCK_LOGONs. In these,
// the PWSTR members of each UNICODE_STRING are not actually pointers but byte
// offsets into the overall buffer"
//=============================================================================
HRESULT PackKerbCertificateLogon(
    const std::wstring& username,
    const std::wstring& domain,
    const VSCInfo& vscInfo,
    bool isUnlock,
    BYTE** ppPackage,
    DWORD* pcbPackage)
{
    LOG("PackKerbCertificateLogon: user=%S, domain=%S, unlock=%d",
        username.c_str(), domain.c_str(), isUnlock);

    if (!ppPackage || !pcbPackage)
    {
        return E_INVALIDARG;
    }

    *ppPackage = nullptr;
    *pcbPackage = 0;

    HRESULT hr = S_OK;
    BYTE* pCspInfo = nullptr;
    DWORD cbCspInfo = 0;

    // Step 1: Build CSP INFO structure
    hr = BuildSmartCardCspInfo(vscInfo, &pCspInfo, &cbCspInfo);
    if (FAILED(hr))
    {
        LOG("ERROR: Failed to build CSP INFO: 0x%08x", hr);
        return hr;
    }

    // Step 2: Calculate string sizes (in BYTES, including null terminators)
    DWORD cbDomain = (DWORD)((domain.length() + 1) * sizeof(WCHAR));
    DWORD cbUsername = (DWORD)((username.length() + 1) * sizeof(WCHAR));
    DWORD cbPin = (DWORD)((vscInfo.pin.length() + 1) * sizeof(WCHAR));

    // Step 3: Calculate total buffer size
    DWORD cbTotal = sizeof(KERB_CERTIFICATE_LOGON) + cbDomain + cbUsername + cbPin + cbCspInfo;

    LOG("Buffer sizes - Total: %u, Domain: %u, User: %u, PIN: %u, CSP: %u",
        cbTotal, cbDomain, cbUsername, cbPin, cbCspInfo);
    LOG("sizeof(KERB_CERTIFICATE_LOGON) = %zu", sizeof(KERB_CERTIFICATE_LOGON));

    // Step 4: Allocate buffer using CoTaskMemAlloc (required for credential providers)
    BYTE* pBuffer = (BYTE*)CoTaskMemAlloc(cbTotal);
    if (!pBuffer)
    {
        LOG("ERROR: Failed to allocate buffer");
        HeapFree(GetProcessHeap(), 0, pCspInfo);
        return E_OUTOFMEMORY;
    }

    // Zero the buffer
    ZeroMemory(pBuffer, cbTotal);

    // Step 5: Calculate byte offsets for each string
    // Buffer layout:
    // [KERB_CERTIFICATE_LOGON] [Domain] [Username] [PIN] [CSP INFO]
    ULONG offsetDomain = sizeof(KERB_CERTIFICATE_LOGON);
    ULONG offsetUsername = offsetDomain + cbDomain;
    ULONG offsetPin = offsetUsername + cbUsername;
    ULONG offsetCspData = offsetPin + cbPin;

    LOG("Byte offsets - Domain: %u, Username: %u, PIN: %u, CSP: %u",
        offsetDomain, offsetUsername, offsetPin, offsetCspData);

    // Step 6: Copy strings to buffer
    memcpy(pBuffer + offsetDomain, domain.c_str(), cbDomain);
    memcpy(pBuffer + offsetUsername, username.c_str(), cbUsername);
    memcpy(pBuffer + offsetPin, vscInfo.pin.c_str(), cbPin);
    memcpy(pBuffer + offsetCspData, pCspInfo, cbCspInfo);

    // Step 7: Fill KERB_CERTIFICATE_LOGON structure
    KERB_CERTIFICATE_LOGON* pLogon = (KERB_CERTIFICATE_LOGON*)pBuffer;

    // Set message type
    pLogon->MessageType = isUnlock ? (KERB_LOGON_SUBMIT_TYPE)KerbCertificateUnlockLogon 
                                   : (KERB_LOGON_SUBMIT_TYPE)KerbCertificateLogon;

    LOG("MessageType set to %d", pLogon->MessageType);

    // Set DomainName (BYTE OFFSET, not pointer!)
    // Length = string bytes WITHOUT null terminator
    // MaximumLength = string bytes WITH null terminator
    pLogon->DomainName.Length = (USHORT)(domain.length() * sizeof(WCHAR));
    pLogon->DomainName.MaximumLength = (USHORT)cbDomain;
    pLogon->DomainName.Buffer = (PWSTR)(ULONG_PTR)offsetDomain;  // BYTE OFFSET!

    // Set UserName
    pLogon->UserName.Length = (USHORT)(username.length() * sizeof(WCHAR));
    pLogon->UserName.MaximumLength = (USHORT)cbUsername;
    pLogon->UserName.Buffer = (PWSTR)(ULONG_PTR)offsetUsername;  // BYTE OFFSET!

    // Set Pin
    pLogon->Pin.Length = (USHORT)(vscInfo.pin.length() * sizeof(WCHAR));
    pLogon->Pin.MaximumLength = (USHORT)cbPin;
    pLogon->Pin.Buffer = (PWSTR)(ULONG_PTR)offsetPin;  // BYTE OFFSET!

    // Set Flags (usually 0)
    pLogon->Flags = 0;

    // Set CSP Data (also BYTE OFFSET!)
    pLogon->CspDataLength = cbCspInfo;
    pLogon->CspData = (PUCHAR)(ULONG_PTR)offsetCspData;  // BYTE OFFSET!

    LOG("UNICODE_STRING offsets - Domain.Buffer: %p, User.Buffer: %p, Pin.Buffer: %p",
        (void*)pLogon->DomainName.Buffer, (void*)pLogon->UserName.Buffer, (void*)pLogon->Pin.Buffer);
    LOG("CspData offset: %p, CspDataLength: %u", (void*)pLogon->CspData, pLogon->CspDataLength);

    // Clean up temporary CSP INFO buffer
    HeapFree(GetProcessHeap(), 0, pCspInfo);

    // Return the packed buffer
    *ppPackage = pBuffer;
    *pcbPackage = cbTotal;

    LOG("PackKerbCertificateLogon completed successfully - Total size: %u bytes", cbTotal);

    return S_OK;
}

//=============================================================================
// Legacy password-based authentication functions (from Phase 1)
//=============================================================================

// Helper function to initialize UNICODE_STRING
static void InitUnicodeString(UNICODE_STRING* pus, PWSTR pwz)
{
    if (pwz != nullptr)
    {
        size_t len = wcslen(pwz);
        pus->Length = (USHORT)(len * sizeof(WCHAR));
        pus->MaximumLength = (USHORT)((len + 1) * sizeof(WCHAR));
        pus->Buffer = pwz;
    }
    else
    {
        pus->Length = 0;
        pus->MaximumLength = 0;
        pus->Buffer = nullptr;
    }
}

HRESULT PackKerbInteractiveLogon(
    const std::wstring& username,
    const std::wstring& password,
    const std::wstring& domain,
    BYTE** ppPackage,
    DWORD* pcbPackage)
{
    LOG("PackKerbInteractiveLogon: user=%S, domain=%S", username.c_str(), domain.c_str());

    if (!ppPackage || !pcbPackage)
    {
        return E_INVALIDARG;
    }

    // Calculate buffer sizes
    DWORD cbUsername = (DWORD)((username.length() + 1) * sizeof(WCHAR));
    DWORD cbPassword = (DWORD)((password.length() + 1) * sizeof(WCHAR));
    DWORD cbDomain = (DWORD)((domain.length() + 1) * sizeof(WCHAR));

    // Total size: structure + all strings
    DWORD cbTotal = sizeof(KERB_INTERACTIVE_LOGON) + cbUsername + cbPassword + cbDomain;

    // Allocate buffer
    BYTE* pBuffer = (BYTE*)CoTaskMemAlloc(cbTotal);
    if (!pBuffer)
    {
        return E_OUTOFMEMORY;
    }

    ZeroMemory(pBuffer, cbTotal);

    // Cast to structure
    KERB_INTERACTIVE_LOGON* pkil = (KERB_INTERACTIVE_LOGON*)pBuffer;
    pkil->MessageType = KerbInteractiveLogon;

    // String buffer starts after structure
    BYTE* pStringBuffer = pBuffer + sizeof(KERB_INTERACTIVE_LOGON);
    ULONG currentOffset = sizeof(KERB_INTERACTIVE_LOGON);

    // Copy and setup domain
    if (!domain.empty())
    {
        memcpy(pStringBuffer, domain.c_str(), cbDomain);
        pkil->LogonDomainName.Length = (USHORT)(domain.length() * sizeof(WCHAR));
        pkil->LogonDomainName.MaximumLength = (USHORT)cbDomain;
        pkil->LogonDomainName.Buffer = (PWSTR)(ULONG_PTR)currentOffset;
        pStringBuffer += cbDomain;
        currentOffset += cbDomain;
    }

    // Copy and setup username
    if (!username.empty())
    {
        memcpy(pStringBuffer, username.c_str(), cbUsername);
        pkil->UserName.Length = (USHORT)(username.length() * sizeof(WCHAR));
        pkil->UserName.MaximumLength = (USHORT)cbUsername;
        pkil->UserName.Buffer = (PWSTR)(ULONG_PTR)currentOffset;
        pStringBuffer += cbUsername;
        currentOffset += cbUsername;
    }

    // Copy and setup password
    if (!password.empty())
    {
        memcpy(pStringBuffer, password.c_str(), cbPassword);
        pkil->Password.Length = (USHORT)(password.length() * sizeof(WCHAR));
        pkil->Password.MaximumLength = (USHORT)cbPassword;
        pkil->Password.Buffer = (PWSTR)(ULONG_PTR)currentOffset;
    }

    *ppPackage = pBuffer;
    *pcbPackage = cbTotal;

    LOG("PackKerbInteractiveLogon success - size: %u", cbTotal);
    return S_OK;
}

HRESULT PackKerbInteractiveUnlockLogon(
    const std::wstring& username,
    const std::wstring& password,
    const std::wstring& domain,
    BYTE** ppPackage,
    DWORD* pcbPackage)
{
    LOG("PackKerbInteractiveUnlockLogon: user=%S, domain=%S", username.c_str(), domain.c_str());

    if (!ppPackage || !pcbPackage)
    {
        return E_INVALIDARG;
    }

    // Calculate buffer sizes
    DWORD cbUsername = (DWORD)((username.length() + 1) * sizeof(WCHAR));
    DWORD cbPassword = (DWORD)((password.length() + 1) * sizeof(WCHAR));
    DWORD cbDomain = (DWORD)((domain.length() + 1) * sizeof(WCHAR));

    // Total size: structure + all strings
    DWORD cbTotal = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + cbUsername + cbPassword + cbDomain;

    // Allocate buffer
    BYTE* pBuffer = (BYTE*)CoTaskMemAlloc(cbTotal);
    if (!pBuffer)
    {
        return E_OUTOFMEMORY;
    }

    ZeroMemory(pBuffer, cbTotal);

    // Cast to structure
    KERB_INTERACTIVE_UNLOCK_LOGON* pkiul = (KERB_INTERACTIVE_UNLOCK_LOGON*)pBuffer;
    pkiul->Logon.MessageType = KerbWorkstationUnlockLogon;

    // String buffer starts after structure
    BYTE* pStringBuffer = pBuffer + sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);
    ULONG currentOffset = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);

    // Copy and setup domain
    if (!domain.empty())
    {
        memcpy(pStringBuffer, domain.c_str(), cbDomain);
        pkiul->Logon.LogonDomainName.Length = (USHORT)(domain.length() * sizeof(WCHAR));
        pkiul->Logon.LogonDomainName.MaximumLength = (USHORT)cbDomain;
        pkiul->Logon.LogonDomainName.Buffer = (PWSTR)(ULONG_PTR)currentOffset;
        pStringBuffer += cbDomain;
        currentOffset += cbDomain;
    }

    // Copy and setup username
    if (!username.empty())
    {
        memcpy(pStringBuffer, username.c_str(), cbUsername);
        pkiul->Logon.UserName.Length = (USHORT)(username.length() * sizeof(WCHAR));
        pkiul->Logon.UserName.MaximumLength = (USHORT)cbUsername;
        pkiul->Logon.UserName.Buffer = (PWSTR)(ULONG_PTR)currentOffset;
        pStringBuffer += cbUsername;
        currentOffset += cbUsername;
    }

    // Copy and setup password
    if (!password.empty())
    {
        memcpy(pStringBuffer, password.c_str(), cbPassword);
        pkiul->Logon.Password.Length = (USHORT)(password.length() * sizeof(WCHAR));
        pkiul->Logon.Password.MaximumLength = (USHORT)cbPassword;
        pkiul->Logon.Password.Buffer = (PWSTR)(ULONG_PTR)currentOffset;
    }

    // LogonId - set to zero (filled by WinLogon)
    pkiul->LogonId.LowPart = 0;
    pkiul->LogonId.HighPart = 0;

    *ppPackage = pBuffer;
    *pcbPackage = cbTotal;

    LOG("PackKerbInteractiveUnlockLogon success - size: %u", cbTotal);
    return S_OK;
}
