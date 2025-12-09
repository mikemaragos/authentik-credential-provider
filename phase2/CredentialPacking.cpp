// CredentialPacking.cpp
// Implementation of KERB_CERTIFICATE_LOGON serialization
// Phase 2: Smart Card/Certificate authentication
// December 8, 2025

#include "CredentialPacking.h"
#include "Logger.h"
#include <objbase.h>
#include <strsafe.h>
#include <wctype.h>

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "ole32.lib")

// Helper: Initialize UNICODE_STRING with pointer adjustment for serialization
static void InitUnicodeStringRelative(
    UNICODE_STRING* pus,
    LPWSTR pwszBuffer,
    LPCWSTR pwszSource,
    BYTE* pBaseAddress)
{
    if (pwszSource && *pwszSource)
    {
        size_t len = wcslen(pwszSource);
        wcscpy_s(pwszBuffer, len + 1, pwszSource);
        
        pus->Length = (USHORT)(len * sizeof(WCHAR));
        pus->MaximumLength = (USHORT)((len + 1) * sizeof(WCHAR));
        pus->Buffer = (PWSTR)((BYTE*)pwszBuffer - pBaseAddress);  // Relative offset
    }
    else
    {
        pus->Length = 0;
        pus->MaximumLength = 0;
        pus->Buffer = nullptr;
    }
}

// Build MY_KERB_SMARTCARD_CSP_INFO structure
HRESULT BuildSmartCardCspInfo(
    const VSCInfo& vscInfo,
    BYTE** ppCspInfo,
    DWORD* pcbCspInfo)
{
    LOG("BuildSmartCardCspInfo");
    LOG("  Reader: %S", vscInfo.readerName.c_str());
    LOG("  Container: %S", vscInfo.containerName.c_str());
    LOG("  CSP: %S", vscInfo.cspName.c_str());
    LOG("  Card: %S", vscInfo.cardName.c_str());

    if (!ppCspInfo || !pcbCspInfo)
        return E_INVALIDARG;

    // Calculate string sizes (in bytes, including null terminators)
    DWORD cbCardName = (DWORD)((vscInfo.cardName.length() + 1) * sizeof(WCHAR));
    DWORD cbReaderName = (DWORD)((vscInfo.readerName.length() + 1) * sizeof(WCHAR));
    DWORD cbContainerName = (DWORD)((vscInfo.containerName.length() + 1) * sizeof(WCHAR));
    DWORD cbCspName = (DWORD)((vscInfo.cspName.length() + 1) * sizeof(WCHAR));

    // Calculate total size: structure header + all strings
    // Note: bBuffer[1] is already counted in sizeof, so subtract sizeof(WCHAR)
    DWORD cbHeader = sizeof(MY_KERB_SMARTCARD_CSP_INFO) - sizeof(WCHAR);
    DWORD cbTotal = cbHeader + cbCardName + cbReaderName + cbContainerName + cbCspName;

    LOG("CSP Info sizes: header=%d, card=%d, reader=%d, container=%d, csp=%d, total=%d",
        cbHeader, cbCardName, cbReaderName, cbContainerName, cbCspName, cbTotal);

    // Allocate buffer
    BYTE* pBuffer = (BYTE*)CoTaskMemAlloc(cbTotal);
    if (!pBuffer)
    {
        LOG("ERROR: Failed to allocate CSP info buffer");
        return E_OUTOFMEMORY;
    }

    ZeroMemory(pBuffer, cbTotal);

    // Cast to structure
    MY_KERB_SMARTCARD_CSP_INFO* pCspInfo = (MY_KERB_SMARTCARD_CSP_INFO*)pBuffer;

    // Fill header
    pCspInfo->dwCspInfoLen = cbTotal;
    pCspInfo->MessageType = 1;  // Must be 1
    pCspInfo->ContextInformation = nullptr;
    pCspInfo->flags = 0;
    pCspInfo->KeySpec = AT_KEYEXCHANGE;  // 1

    // Calculate string offsets (relative to start of bBuffer)
    ULONG nOffset = 0;

    // Card name at offset 0
    pCspInfo->nCardNameOffset = nOffset;
    if (!vscInfo.cardName.empty())
    {
        wcscpy_s((LPWSTR)(pCspInfo->bBuffer + nOffset / sizeof(WCHAR)), 
                 vscInfo.cardName.length() + 1, 
                 vscInfo.cardName.c_str());
    }
    nOffset += cbCardName;

    // Reader name
    pCspInfo->nReaderNameOffset = nOffset;
    wcscpy_s((LPWSTR)((BYTE*)pCspInfo->bBuffer + nOffset), 
             (cbTotal - cbHeader - nOffset) / sizeof(WCHAR),
             vscInfo.readerName.c_str());
    nOffset += cbReaderName;

    // Container name
    pCspInfo->nContainerNameOffset = nOffset;
    wcscpy_s((LPWSTR)((BYTE*)pCspInfo->bBuffer + nOffset),
             (cbTotal - cbHeader - nOffset) / sizeof(WCHAR),
             vscInfo.containerName.c_str());
    nOffset += cbContainerName;

    // CSP name
    pCspInfo->nCSPNameOffset = nOffset;
    wcscpy_s((LPWSTR)((BYTE*)pCspInfo->bBuffer + nOffset),
             (cbTotal - cbHeader - nOffset) / sizeof(WCHAR),
             vscInfo.cspName.c_str());

    LOG("CSP Info offsets: card=%d, reader=%d, container=%d, csp=%d",
        pCspInfo->nCardNameOffset, pCspInfo->nReaderNameOffset,
        pCspInfo->nContainerNameOffset, pCspInfo->nCSPNameOffset);

    *ppCspInfo = pBuffer;
    *pcbCspInfo = cbTotal;

    LOG("BuildSmartCardCspInfo: success, size=%d bytes", cbTotal);
    return S_OK;
}

// Pack credentials for smart card certificate logon
HRESULT PackKerbCertificateLogon(
    const std::wstring& username,
    const std::wstring& domain,
    const std::wstring& pin,
    const VSCInfo& vscInfo,
    BYTE** ppPackage,
    DWORD* pcbPackage)
{
    LOG("PackKerbCertificateLogon: user=%S, domain=%S", username.c_str(), domain.c_str());

    if (!ppPackage || !pcbPackage)
        return E_INVALIDARG;

    HRESULT hr;

    // Build CSP info first
    BYTE* pCspInfo = nullptr;
    DWORD cbCspInfo = 0;
    hr = BuildSmartCardCspInfo(vscInfo, &pCspInfo, &cbCspInfo);
    if (FAILED(hr))
    {
        LOG("ERROR: BuildSmartCardCspInfo failed: 0x%08x", hr);
        return hr;
    }

    // Calculate string sizes
    DWORD cbDomain = (DWORD)((domain.length() + 1) * sizeof(WCHAR));
    DWORD cbUsername = (DWORD)((username.length() + 1) * sizeof(WCHAR));
    DWORD cbPin = (DWORD)((pin.length() + 1) * sizeof(WCHAR));

    // Total size: structure + strings + CSP info
    DWORD cbTotal = sizeof(MY_KERB_CERTIFICATE_LOGON) + cbDomain + cbUsername + cbPin + cbCspInfo;

    LOG("Package sizes: struct=%d, domain=%d, user=%d, pin=%d, csp=%d, total=%d",
        (DWORD)sizeof(MY_KERB_CERTIFICATE_LOGON), cbDomain, cbUsername, cbPin, cbCspInfo, cbTotal);

    // Allocate buffer
    BYTE* pBuffer = (BYTE*)CoTaskMemAlloc(cbTotal);
    if (!pBuffer)
    {
        CoTaskMemFree(pCspInfo);
        LOG("ERROR: Failed to allocate package buffer");
        return E_OUTOFMEMORY;
    }

    ZeroMemory(pBuffer, cbTotal);

    // Cast to structure
    MY_KERB_CERTIFICATE_LOGON* pLogon = (MY_KERB_CERTIFICATE_LOGON*)pBuffer;

    // Set message type
    pLogon->MessageType = (KERB_LOGON_SUBMIT_TYPE)KerbCertificateLogon;
    pLogon->Flags = 0;

    LOG("MessageType set to KerbCertificateLogon (%d)", KerbCertificateLogon);

    // String buffer starts after structure
    BYTE* pStringBuffer = pBuffer + sizeof(MY_KERB_CERTIFICATE_LOGON);

    // Convert domain to uppercase for Kerberos realm
    std::wstring upperDomain = domain;
    for (auto& c : upperDomain) {
        c = towupper(c);
    }
    LOG("Domain converted to uppercase: %S", upperDomain.c_str());

    // Copy domain name
    memcpy(pStringBuffer, upperDomain.c_str(), cbDomain);
    pLogon->DomainName.Length = (USHORT)((upperDomain.length()) * sizeof(WCHAR));
    pLogon->DomainName.MaximumLength = (USHORT)cbDomain;
    pLogon->DomainName.Buffer = (PWSTR)pStringBuffer;  // Actual pointer
    pStringBuffer += cbDomain;

    // Copy username
    memcpy(pStringBuffer, username.c_str(), cbUsername);
    pLogon->UserName.Length = (USHORT)((username.length()) * sizeof(WCHAR));
    pLogon->UserName.MaximumLength = (USHORT)cbUsername;
    pLogon->UserName.Buffer = (PWSTR)pStringBuffer;  // Actual pointer
    pStringBuffer += cbUsername;

    // Copy PIN
    memcpy(pStringBuffer, pin.c_str(), cbPin);
    pLogon->Pin.Length = (USHORT)((pin.length()) * sizeof(WCHAR));
    pLogon->Pin.MaximumLength = (USHORT)cbPin;
    pLogon->Pin.Buffer = (PWSTR)pStringBuffer;  // Actual pointer
    pStringBuffer += cbPin;

    // Copy CSP info
    memcpy(pStringBuffer, pCspInfo, cbCspInfo);
    pLogon->CspDataLength = cbCspInfo;
    pLogon->CspData = pStringBuffer;  // Actual pointer

    // Free temporary CSP info buffer
    CoTaskMemFree(pCspInfo);

    *ppPackage = pBuffer;
    *pcbPackage = cbTotal;

    LOG("PackKerbCertificateLogon: success, total size=%d bytes", cbTotal);
    return S_OK;
}

// Pack credentials for smart card certificate unlock
HRESULT PackKerbCertificateUnlockLogon(
    const std::wstring& username,
    const std::wstring& domain,
    const std::wstring& pin,
    const VSCInfo& vscInfo,
    BYTE** ppPackage,
    DWORD* pcbPackage)
{
    LOG("PackKerbCertificateUnlockLogon: user=%S, domain=%S", username.c_str(), domain.c_str());

    if (!ppPackage || !pcbPackage)
        return E_INVALIDARG;

    HRESULT hr;

    // Build CSP info first
    BYTE* pCspInfo = nullptr;
    DWORD cbCspInfo = 0;
    hr = BuildSmartCardCspInfo(vscInfo, &pCspInfo, &cbCspInfo);
    if (FAILED(hr))
    {
        LOG("ERROR: BuildSmartCardCspInfo failed: 0x%08x", hr);
        return hr;
    }

    // Calculate string sizes
    DWORD cbDomain = (DWORD)((domain.length() + 1) * sizeof(WCHAR));
    DWORD cbUsername = (DWORD)((username.length() + 1) * sizeof(WCHAR));
    DWORD cbPin = (DWORD)((pin.length() + 1) * sizeof(WCHAR));

    // Total size: structure + strings + CSP info
    DWORD cbTotal = sizeof(MY_KERB_CERTIFICATE_UNLOCK_LOGON) + cbDomain + cbUsername + cbPin + cbCspInfo;

    LOG("Unlock package sizes: struct=%d, total=%d", 
        (DWORD)sizeof(MY_KERB_CERTIFICATE_UNLOCK_LOGON), cbTotal);

    // Allocate buffer
    BYTE* pBuffer = (BYTE*)CoTaskMemAlloc(cbTotal);
    if (!pBuffer)
    {
        CoTaskMemFree(pCspInfo);
        LOG("ERROR: Failed to allocate package buffer");
        return E_OUTOFMEMORY;
    }

    ZeroMemory(pBuffer, cbTotal);

    // Cast to structure
    MY_KERB_CERTIFICATE_UNLOCK_LOGON* pUnlock = (MY_KERB_CERTIFICATE_UNLOCK_LOGON*)pBuffer;

    // Set message type for unlock
    pUnlock->Logon.MessageType = (KERB_LOGON_SUBMIT_TYPE)KerbCertificateUnlockLogon;
    pUnlock->Logon.Flags = 0;

    // LogonId = 0 for unlock
    pUnlock->LogonId.LowPart = 0;
    pUnlock->LogonId.HighPart = 0;

    // String buffer starts after structure
    BYTE* pStringBuffer = pBuffer + sizeof(MY_KERB_CERTIFICATE_UNLOCK_LOGON);

    // Convert domain to uppercase for Kerberos realm
    std::wstring upperDomain = domain;
    for (auto& c : upperDomain) {
        c = towupper(c);
    }

    // Copy domain name
    memcpy(pStringBuffer, upperDomain.c_str(), cbDomain);
    pUnlock->Logon.DomainName.Length = (USHORT)((upperDomain.length()) * sizeof(WCHAR));
    pUnlock->Logon.DomainName.MaximumLength = (USHORT)cbDomain;
    pUnlock->Logon.DomainName.Buffer = (PWSTR)pStringBuffer;  // Actual pointer
    pStringBuffer += cbDomain;

    // Copy username
    memcpy(pStringBuffer, username.c_str(), cbUsername);
    pUnlock->Logon.UserName.Length = (USHORT)((username.length()) * sizeof(WCHAR));
    pUnlock->Logon.UserName.MaximumLength = (USHORT)cbUsername;
    pUnlock->Logon.UserName.Buffer = (PWSTR)pStringBuffer;  // Actual pointer
    pStringBuffer += cbUsername;

    // Copy PIN
    memcpy(pStringBuffer, pin.c_str(), cbPin);
    pUnlock->Logon.Pin.Length = (USHORT)((pin.length()) * sizeof(WCHAR));
    pUnlock->Logon.Pin.MaximumLength = (USHORT)cbPin;
    pUnlock->Logon.Pin.Buffer = (PWSTR)pStringBuffer;  // Actual pointer
    pStringBuffer += cbPin;

    // Copy CSP info
    memcpy(pStringBuffer, pCspInfo, cbCspInfo);
    pUnlock->Logon.CspDataLength = cbCspInfo;
    pUnlock->Logon.CspData = pStringBuffer;  // Actual pointer

    // Free temporary CSP info buffer
    CoTaskMemFree(pCspInfo);

    *ppPackage = pBuffer;
    *pcbPackage = cbTotal;

    LOG("PackKerbCertificateUnlockLogon: success, total size=%d bytes", cbTotal);
    return S_OK;
}
