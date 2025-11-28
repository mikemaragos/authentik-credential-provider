// CertificateCredentialPacking.h
// Functions to pack KERB_CERTIFICATE_LOGON for PKINIT authentication

#pragma once

#include <windows.h>
#include <ntsecapi.h>
#include <NTSecPKG.h>
#include <wincred.h>
#include <string>

// KSP name used for certificate authentication
#define AUTHENTIK_KSP_NAME L"Authentik Key Storage Provider"

// KERB_CERTIFICATE_LOGON message type
#ifndef KerbCertificateLogon
#define KerbCertificateLogon 13
#endif

#ifndef KerbCertificateUnlockLogon
#define KerbCertificateUnlockLogon 15
#endif

// KERB_CERTIFICATE_LOGON structure (if not in headers)
#ifndef _KERB_CERTIFICATE_LOGON_
#define _KERB_CERTIFICATE_LOGON_

typedef struct _KERB_CERTIFICATE_LOGON {
    KERB_LOGON_SUBMIT_TYPE MessageType;
    UNICODE_STRING DomainName;
    UNICODE_STRING UserName;
    UNICODE_STRING Pin;
    ULONG Flags;
    ULONG CspDataLength;
    PUCHAR CspData;
} KERB_CERTIFICATE_LOGON, *PKERB_CERTIFICATE_LOGON;

typedef struct _KERB_CERTIFICATE_UNLOCK_LOGON {
    KERB_CERTIFICATE_LOGON Logon;
    LUID LogonId;
} KERB_CERTIFICATE_UNLOCK_LOGON, *PKERB_CERTIFICATE_UNLOCK_LOGON;

#endif

// KERB_SMARTCARD_CSP_INFO structure
#ifndef _KERB_SMARTCARD_CSP_INFO_
#define _KERB_SMARTCARD_CSP_INFO_

typedef struct _KERB_SMARTCARD_CSP_INFO {
    DWORD dwCspInfoLen;
    DWORD MessageType;      // Always 1
    union {
        PVOID ContextInformation;
        ULONG64 SpaceHolderForWow64;
    };
    DWORD flags;
    DWORD KeySpec;
    ULONG nCardNameOffset;
    ULONG nReaderNameOffset;
    ULONG nContainerNameOffset;
    ULONG nCSPNameOffset;
    TCHAR bBuffer[1];       // Variable length - contains strings
} KERB_SMARTCARD_CSP_INFO, *PKERB_SMARTCARD_CSP_INFO;

#endif

// Pack KERB_CERTIFICATE_LOGON structure for PKINIT
// This is used instead of KERB_INTERACTIVE_LOGON for certificate-based auth
HRESULT PackKerbCertificateLogon(
    const std::wstring& username,
    const std::wstring& domain,
    const std::wstring& pin,              // Can be empty if OTP already validated
    const std::wstring& kspName,          // KSP provider name
    const std::wstring& containerName,    // Key container name in KSP
    BYTE** ppPackage,
    DWORD* pcbPackage);

// Pack KERB_CERTIFICATE_UNLOCK_LOGON for workstation unlock
HRESULT PackKerbCertificateUnlockLogon(
    const std::wstring& username,
    const std::wstring& domain,
    const std::wstring& pin,
    const std::wstring& kspName,
    const std::wstring& containerName,
    BYTE** ppPackage,
    DWORD* pcbPackage);

// Implementation

inline HRESULT PackKerbCertificateLogon(
    const std::wstring& username,
    const std::wstring& domain,
    const std::wstring& pin,
    const std::wstring& kspName,
    const std::wstring& containerName,
    BYTE** ppPackage,
    DWORD* pcbPackage)
{
    OutputDebugStringA("[AuthentikCP] PackKerbCertificateLogon\n");
    
    if (!ppPackage || !pcbPackage)
    {
        return E_INVALIDARG;
    }

    *ppPackage = nullptr;
    *pcbPackage = 0;

    // Calculate CSP info size
    // CSP info contains: card name, reader name, container name, CSP name
    // For our KSP, we only need container name and KSP name
    DWORD cbContainerName = (DWORD)((containerName.length() + 1) * sizeof(WCHAR));
    DWORD cbKspName = (DWORD)((kspName.length() + 1) * sizeof(WCHAR));
    
    // CSP info structure with string buffer
    DWORD cbCspInfo = sizeof(KERB_SMARTCARD_CSP_INFO) - sizeof(TCHAR) + cbContainerName + cbKspName;
    cbCspInfo = (cbCspInfo + 7) & ~7; // Align to 8 bytes

    // Calculate string sizes for main structure
    DWORD cbUsername = (DWORD)((username.length() + 1) * sizeof(WCHAR));
    DWORD cbDomain = (DWORD)((domain.length() + 1) * sizeof(WCHAR));
    DWORD cbPin = (DWORD)((pin.length() + 1) * sizeof(WCHAR));

    // Total size: KERB_CERTIFICATE_LOGON + strings + CSP info
    DWORD cbTotal = sizeof(KERB_CERTIFICATE_LOGON) + cbUsername + cbDomain + cbPin + cbCspInfo;

    char logBuf[256];
    sprintf_s(logBuf, "[AuthentikCP] Buffer sizes - Total: %d, CspInfo: %d\n", cbTotal, cbCspInfo);
    OutputDebugStringA(logBuf);

    // Allocate buffer
    BYTE* pBuffer = (BYTE*)CoTaskMemAlloc(cbTotal);
    if (!pBuffer)
    {
        OutputDebugStringA("[AuthentikCP] ERROR: Failed to allocate memory\n");
        return E_OUTOFMEMORY;
    }

    ZeroMemory(pBuffer, cbTotal);

    // Set up pointers
    PKERB_CERTIFICATE_LOGON pKcl = (PKERB_CERTIFICATE_LOGON)pBuffer;
    BYTE* pStringBuffer = pBuffer + sizeof(KERB_CERTIFICATE_LOGON);

    // Message type
    pKcl->MessageType = (KERB_LOGON_SUBMIT_TYPE)KerbCertificateLogon;

    // Copy username
    if (!username.empty())
    {
        DWORD offset = (DWORD)(pStringBuffer - pBuffer);
        memcpy(pStringBuffer, username.c_str(), cbUsername);
        pKcl->UserName.Length = (USHORT)(username.length() * sizeof(WCHAR));
        pKcl->UserName.MaximumLength = (USHORT)cbUsername;
        pKcl->UserName.Buffer = (PWSTR)(ULONG_PTR)offset;
        pStringBuffer += cbUsername;
        
        sprintf_s(logBuf, "[AuthentikCP] Username: %S, offset=%d\n", username.c_str(), offset);
        OutputDebugStringA(logBuf);
    }

    // Copy domain
    if (!domain.empty())
    {
        DWORD offset = (DWORD)(pStringBuffer - pBuffer);
        memcpy(pStringBuffer, domain.c_str(), cbDomain);
        pKcl->DomainName.Length = (USHORT)(domain.length() * sizeof(WCHAR));
        pKcl->DomainName.MaximumLength = (USHORT)cbDomain;
        pKcl->DomainName.Buffer = (PWSTR)(ULONG_PTR)offset;
        pStringBuffer += cbDomain;
        
        sprintf_s(logBuf, "[AuthentikCP] Domain: %S, offset=%d\n", domain.c_str(), offset);
        OutputDebugStringA(logBuf);
    }

    // Copy PIN (can be empty)
    {
        DWORD offset = (DWORD)(pStringBuffer - pBuffer);
        memcpy(pStringBuffer, pin.c_str(), cbPin);
        pKcl->Pin.Length = (USHORT)(pin.length() * sizeof(WCHAR));
        pKcl->Pin.MaximumLength = (USHORT)cbPin;
        pKcl->Pin.Buffer = (PWSTR)(ULONG_PTR)offset;
        pStringBuffer += cbPin;
    }

    // Flags
    pKcl->Flags = 0;

    // Build CSP info
    DWORD cspInfoOffset = (DWORD)(pStringBuffer - pBuffer);
    PKERB_SMARTCARD_CSP_INFO pCspInfo = (PKERB_SMARTCARD_CSP_INFO)pStringBuffer;
    
    pCspInfo->dwCspInfoLen = cbCspInfo;
    pCspInfo->MessageType = 1;
    pCspInfo->ContextInformation = nullptr;
    pCspInfo->flags = 0;
    pCspInfo->KeySpec = AT_KEYEXCHANGE;
    
    // String offsets within CSP info (relative to bBuffer)
    DWORD bufferOffset = 0;
    
    // Container name
    pCspInfo->nContainerNameOffset = bufferOffset;
    memcpy(&pCspInfo->bBuffer[bufferOffset / sizeof(WCHAR)], containerName.c_str(), cbContainerName);
    bufferOffset += cbContainerName;
    
    // CSP/KSP name
    pCspInfo->nCSPNameOffset = bufferOffset;
    memcpy(&pCspInfo->bBuffer[bufferOffset / sizeof(WCHAR)], kspName.c_str(), cbKspName);
    bufferOffset += cbKspName;
    
    // Card name and reader name - not used, set to 0
    pCspInfo->nCardNameOffset = 0;
    pCspInfo->nReaderNameOffset = 0;

    // Set CSP data in main structure (as offset)
    pKcl->CspData = (PUCHAR)(ULONG_PTR)cspInfoOffset;
    pKcl->CspDataLength = cbCspInfo;

    sprintf_s(logBuf, "[AuthentikCP] CSP Info at offset %d, length %d\n", cspInfoOffset, cbCspInfo);
    OutputDebugStringA(logBuf);
    sprintf_s(logBuf, "[AuthentikCP] Container: %S, KSP: %S\n", containerName.c_str(), kspName.c_str());
    OutputDebugStringA(logBuf);

    *ppPackage = pBuffer;
    *pcbPackage = cbTotal;

    sprintf_s(logBuf, "[AuthentikCP] Successfully packed KERB_CERTIFICATE_LOGON - Size: %d bytes\n", cbTotal);
    OutputDebugStringA(logBuf);

    return S_OK;
}

inline HRESULT PackKerbCertificateUnlockLogon(
    const std::wstring& username,
    const std::wstring& domain,
    const std::wstring& pin,
    const std::wstring& kspName,
    const std::wstring& containerName,
    BYTE** ppPackage,
    DWORD* pcbPackage)
{
    OutputDebugStringA("[AuthentikCP] PackKerbCertificateUnlockLogon\n");
    
    if (!ppPackage || !pcbPackage)
    {
        return E_INVALIDARG;
    }

    // For unlock, we use KERB_CERTIFICATE_UNLOCK_LOGON which wraps KERB_CERTIFICATE_LOGON
    // But for simplicity, just use the same packing - Windows handles it
    
    // First pack as regular certificate logon
    BYTE* pInnerPackage = nullptr;
    DWORD cbInnerPackage = 0;
    
    HRESULT hr = PackKerbCertificateLogon(
        username, domain, pin, kspName, containerName,
        &pInnerPackage, &cbInnerPackage);
    
    if (FAILED(hr))
    {
        return hr;
    }

    // Change message type to unlock
    PKERB_CERTIFICATE_LOGON pKcl = (PKERB_CERTIFICATE_LOGON)pInnerPackage;
    pKcl->MessageType = (KERB_LOGON_SUBMIT_TYPE)KerbCertificateUnlockLogon;

    *ppPackage = pInnerPackage;
    *pcbPackage = cbInnerPackage;

    return S_OK;
}
