// CredentialPacking.cpp
// Implementation of credential serialization - Phase 2 (Smart Card/Certificate)

#include "CredentialPacking.h"
#include "Logger.h"
#include <windows.h>
#include <ntsecapi.h>
#include <NTSecPKG.h>
#include <string>

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Advapi32.lib")

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

// Build KERB_SMARTCARD_CSP_INFO structure
HRESULT BuildSmartCardCspInfo(
    const VSCInfo& vscInfo,
    BYTE** ppCspInfo,
    DWORD* pcbCspInfo)
{
    LOG("BuildSmartCardCspInfo");

    if (!ppCspInfo || !pcbCspInfo)
        return E_INVALIDARG;

    // Calculate sizes (including null terminators)
    DWORD cbCardName = (DWORD)((vscInfo.cardName.length() + 1) * sizeof(WCHAR));
    DWORD cbReaderName = (DWORD)((vscInfo.readerName.length() + 1) * sizeof(WCHAR));
    DWORD cbContainerName = (DWORD)((vscInfo.containerName.length() + 1) * sizeof(WCHAR));
    DWORD cbCspName = (DWORD)((vscInfo.cspName.length() + 1) * sizeof(WCHAR));

    // Calculate total size
    // Structure without bBuffer + all strings
    DWORD cbHeader = sizeof(KERB_SMARTCARD_CSP_INFO) - sizeof(TCHAR); // Subtract bBuffer[1]
    DWORD cbStrings = cbCardName + cbReaderName + cbContainerName + cbCspName;
    DWORD cbTotal = cbHeader + cbStrings;

    LOG("CSP Info sizes - Header: %d, Strings: %d, Total: %d", cbHeader, cbStrings, cbTotal);
    LOG("  CardName: %S (%d bytes)", vscInfo.cardName.c_str(), cbCardName);
    LOG("  ReaderName: %S (%d bytes)", vscInfo.readerName.c_str(), cbReaderName);
    LOG("  ContainerName: %S (%d bytes)", vscInfo.containerName.c_str(), cbContainerName);
    LOG("  CspName: %S (%d bytes)", vscInfo.cspName.c_str(), cbCspName);

    // Allocate buffer
    BYTE* pBuffer = (BYTE*)CoTaskMemAlloc(cbTotal);
    if (!pBuffer)
    {
        LOG("ERROR: Failed to allocate CSP info buffer");
        return E_OUTOFMEMORY;
    }

    ZeroMemory(pBuffer, cbTotal);

    // Cast to structure
    KERB_SMARTCARD_CSP_INFO* pCspInfo = (KERB_SMARTCARD_CSP_INFO*)pBuffer;

    // Fill in header
    pCspInfo->dwCspInfoLen = cbTotal;
    pCspInfo->MessageType = 1;  // Required value
    pCspInfo->ContextInformation = nullptr;
    pCspInfo->flags = 0;
    pCspInfo->KeySpec = AT_KEYEXCHANGE;  // Required for smart card logon

    // Calculate offsets (relative to start of bBuffer)
    ULONG currentOffset = 0;

    // Card name
    pCspInfo->nCardNameOffset = currentOffset;
    memcpy(pCspInfo->bBuffer + currentOffset, vscInfo.cardName.c_str(), cbCardName);
    currentOffset += cbCardName;

    // Reader name
    pCspInfo->nReaderNameOffset = currentOffset;
    memcpy(pCspInfo->bBuffer + currentOffset, vscInfo.readerName.c_str(), cbReaderName);
    currentOffset += cbReaderName;

    // Container name
    pCspInfo->nContainerNameOffset = currentOffset;
    memcpy(pCspInfo->bBuffer + currentOffset, vscInfo.containerName.c_str(), cbContainerName);
    currentOffset += cbContainerName;

    // CSP name
    pCspInfo->nCSPNameOffset = currentOffset;
    memcpy(pCspInfo->bBuffer + currentOffset, vscInfo.cspName.c_str(), cbCspName);

    LOG("CSP Info offsets - Card: %d, Reader: %d, Container: %d, CSP: %d",
        pCspInfo->nCardNameOffset, pCspInfo->nReaderNameOffset,
        pCspInfo->nContainerNameOffset, pCspInfo->nCSPNameOffset);

    *ppCspInfo = pBuffer;
    *pcbCspInfo = cbTotal;

    LOG("CSP Info built successfully: %d bytes", cbTotal);
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

    HRESULT hr = E_FAIL;

    // First, build the CSP info
    BYTE* pCspInfo = nullptr;
    DWORD cbCspInfo = 0;

    hr = BuildSmartCardCspInfo(vscInfo, &pCspInfo, &cbCspInfo);
    if (FAILED(hr))
    {
        LOG("ERROR: Failed to build CSP info: 0x%08x", hr);
        return hr;
    }

    // Calculate string sizes
    DWORD cbDomain = (DWORD)((domain.length() + 1) * sizeof(WCHAR));
    DWORD cbUsername = (DWORD)((username.length() + 1) * sizeof(WCHAR));
    DWORD cbPin = (DWORD)((pin.length() + 1) * sizeof(WCHAR));

    // Total size: KERB_CERTIFICATE_LOGON structure + strings + CSP info
    DWORD cbTotal = sizeof(KERB_CERTIFICATE_LOGON) + cbDomain + cbUsername + cbPin + cbCspInfo;

    LOG("Buffer sizes - Total: %d, Domain: %d, User: %d, PIN: %d, CSP: %d",
        cbTotal, cbDomain, cbUsername, cbPin, cbCspInfo);

    // Allocate buffer
    BYTE* pBuffer = (BYTE*)CoTaskMemAlloc(cbTotal);
    if (!pBuffer)
    {
        LOG("ERROR: Failed to allocate buffer");
        CoTaskMemFree(pCspInfo);
        return E_OUTOFMEMORY;
    }

    ZeroMemory(pBuffer, cbTotal);

    // Cast to structure
    KERB_CERTIFICATE_LOGON* pLogon = (KERB_CERTIFICATE_LOGON*)pBuffer;

    // Set message type
    pLogon->MessageType = (KERB_LOGON_SUBMIT_TYPE)KerbCertificateLogon;
    LOG("MessageType set to KerbCertificateLogon (%d)", KerbCertificateLogon);

    // String buffer starts after the structure
    BYTE* pStringBuffer = pBuffer + sizeof(KERB_CERTIFICATE_LOGON);

    // Copy domain
    if (!domain.empty())
    {
        memcpy(pStringBuffer, domain.c_str(), cbDomain);
        InitUnicodeString(&pLogon->DomainName, (PWSTR)pStringBuffer);
        pStringBuffer += cbDomain;
        LOG("Domain: %S (Length: %d)", pLogon->DomainName.Buffer, pLogon->DomainName.Length);
    }
    else
    {
        InitUnicodeString(&pLogon->DomainName, nullptr);
    }

    // Copy username
    if (!username.empty())
    {
        memcpy(pStringBuffer, username.c_str(), cbUsername);
        InitUnicodeString(&pLogon->UserName, (PWSTR)pStringBuffer);
        pStringBuffer += cbUsername;
        LOG("Username: %S (Length: %d)", pLogon->UserName.Buffer, pLogon->UserName.Length);
    }
    else
    {
        InitUnicodeString(&pLogon->UserName, nullptr);
    }

    // Copy PIN
    if (!pin.empty())
    {
        memcpy(pStringBuffer, pin.c_str(), cbPin);
        InitUnicodeString(&pLogon->Pin, (PWSTR)pStringBuffer);
        pStringBuffer += cbPin;
        LOG("PIN set (Length: %d)", pLogon->Pin.Length);
    }
    else
    {
        InitUnicodeString(&pLogon->Pin, nullptr);
    }

    // Set flags
    pLogon->Flags = 0;

    // Copy CSP info
    pLogon->CspDataLength = cbCspInfo;
    pLogon->CspData = pStringBuffer;
    memcpy(pStringBuffer, pCspInfo, cbCspInfo);

    LOG("CSP data copied at offset %d, length %d", (DWORD)(pStringBuffer - pBuffer), cbCspInfo);

    // Free temporary CSP info buffer
    CoTaskMemFree(pCspInfo);

    // Return the buffer
    *ppPackage = pBuffer;
    *pcbPackage = cbTotal;

    LOG("Successfully packed KERB_CERTIFICATE_LOGON - Size: %d bytes", cbTotal);
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

    HRESULT hr = E_FAIL;

    // First, build the CSP info
    BYTE* pCspInfo = nullptr;
    DWORD cbCspInfo = 0;

    hr = BuildSmartCardCspInfo(vscInfo, &pCspInfo, &cbCspInfo);
    if (FAILED(hr))
    {
        LOG("ERROR: Failed to build CSP info: 0x%08x", hr);
        return hr;
    }

    // Calculate string sizes
    DWORD cbDomain = (DWORD)((domain.length() + 1) * sizeof(WCHAR));
    DWORD cbUsername = (DWORD)((username.length() + 1) * sizeof(WCHAR));
    DWORD cbPin = (DWORD)((pin.length() + 1) * sizeof(WCHAR));

    // Total size: KERB_CERTIFICATE_UNLOCK_LOGON structure + strings + CSP info
    DWORD cbTotal = sizeof(KERB_CERTIFICATE_UNLOCK_LOGON) + cbDomain + cbUsername + cbPin + cbCspInfo;

    LOG("Unlock buffer size: %d", cbTotal);

    // Allocate buffer
    BYTE* pBuffer = (BYTE*)CoTaskMemAlloc(cbTotal);
    if (!pBuffer)
    {
        LOG("ERROR: Failed to allocate buffer");
        CoTaskMemFree(pCspInfo);
        return E_OUTOFMEMORY;
    }

    ZeroMemory(pBuffer, cbTotal);

    // Cast to structure
    KERB_CERTIFICATE_UNLOCK_LOGON* pUnlock = (KERB_CERTIFICATE_UNLOCK_LOGON*)pBuffer;

    // Set message type
    pUnlock->Logon.MessageType = (KERB_LOGON_SUBMIT_TYPE)KerbCertificateUnlockLogon;
    LOG("MessageType set to KerbCertificateUnlockLogon (%d)", KerbCertificateUnlockLogon);

    // String buffer starts after the structure
    BYTE* pStringBuffer = pBuffer + sizeof(KERB_CERTIFICATE_UNLOCK_LOGON);

    // Copy domain
    if (!domain.empty())
    {
        memcpy(pStringBuffer, domain.c_str(), cbDomain);
        InitUnicodeString(&pUnlock->Logon.DomainName, (PWSTR)pStringBuffer);
        pStringBuffer += cbDomain;
    }
    else
    {
        InitUnicodeString(&pUnlock->Logon.DomainName, nullptr);
    }

    // Copy username
    if (!username.empty())
    {
        memcpy(pStringBuffer, username.c_str(), cbUsername);
        InitUnicodeString(&pUnlock->Logon.UserName, (PWSTR)pStringBuffer);
        pStringBuffer += cbUsername;
    }
    else
    {
        InitUnicodeString(&pUnlock->Logon.UserName, nullptr);
    }

    // Copy PIN
    if (!pin.empty())
    {
        memcpy(pStringBuffer, pin.c_str(), cbPin);
        InitUnicodeString(&pUnlock->Logon.Pin, (PWSTR)pStringBuffer);
        pStringBuffer += cbPin;
    }
    else
    {
        InitUnicodeString(&pUnlock->Logon.Pin, nullptr);
    }

    // Set flags
    pUnlock->Logon.Flags = 0;

    // Copy CSP info
    pUnlock->Logon.CspDataLength = cbCspInfo;
    pUnlock->Logon.CspData = pStringBuffer;
    memcpy(pStringBuffer, pCspInfo, cbCspInfo);

    // Set LogonId to zero (required for unlock)
    pUnlock->LogonId.LowPart = 0;
    pUnlock->LogonId.HighPart = 0;

    // Free temporary CSP info buffer
    CoTaskMemFree(pCspInfo);

    // Return the buffer
    *ppPackage = pBuffer;
    *pcbPackage = cbTotal;

    LOG("Successfully packed KERB_CERTIFICATE_UNLOCK_LOGON - Size: %d bytes", cbTotal);
    return S_OK;
}

// ============================================================================
// Legacy functions for password-based auth (kept for compatibility/fallback)
// ============================================================================

HRESULT PackKerbInteractiveLogon(
    const std::wstring& username,
    const std::wstring& password,
    const std::wstring& domain,
    BYTE** ppPackage,
    DWORD* pcbPackage)
{
    LOG("PackKerbInteractiveLogon (legacy): user=%S, domain=%S", username.c_str(), domain.c_str());

    if (!ppPackage || !pcbPackage)
        return E_INVALIDARG;

    // Calculate buffer sizes
    DWORD cbUsername = (DWORD)((username.length() + 1) * sizeof(WCHAR));
    DWORD cbPassword = (DWORD)((password.length() + 1) * sizeof(WCHAR));
    DWORD cbDomain = (DWORD)((domain.length() + 1) * sizeof(WCHAR));

    DWORD cbTotal = sizeof(KERB_INTERACTIVE_LOGON) + cbUsername + cbPassword + cbDomain;

    // Allocate buffer
    BYTE* pBuffer = (BYTE*)CoTaskMemAlloc(cbTotal);
    if (!pBuffer)
        return E_OUTOFMEMORY;

    ZeroMemory(pBuffer, cbTotal);

    KERB_INTERACTIVE_LOGON* pkil = (KERB_INTERACTIVE_LOGON*)pBuffer;
    pkil->MessageType = KerbInteractiveLogon;

    BYTE* pStringBuffer = pBuffer + sizeof(KERB_INTERACTIVE_LOGON);

    // Username
    if (!username.empty())
    {
        memcpy(pStringBuffer, username.c_str(), cbUsername);
        InitUnicodeString(&pkil->UserName, (PWSTR)pStringBuffer);
        pStringBuffer += cbUsername;
    }

    // Password
    if (!password.empty())
    {
        memcpy(pStringBuffer, password.c_str(), cbPassword);
        InitUnicodeString(&pkil->Password, (PWSTR)pStringBuffer);
        pStringBuffer += cbPassword;
    }

    // Domain
    if (!domain.empty())
    {
        memcpy(pStringBuffer, domain.c_str(), cbDomain);
        InitUnicodeString(&pkil->LogonDomainName, (PWSTR)pStringBuffer);
    }

    *ppPackage = pBuffer;
    *pcbPackage = cbTotal;

    return S_OK;
}

HRESULT PackKerbInteractiveUnlockLogon(
    const std::wstring& username,
    const std::wstring& password,
    const std::wstring& domain,
    BYTE** ppPackage,
    DWORD* pcbPackage)
{
    LOG("PackKerbInteractiveUnlockLogon (legacy): user=%S, domain=%S", username.c_str(), domain.c_str());

    if (!ppPackage || !pcbPackage)
        return E_INVALIDARG;

    DWORD cbUsername = (DWORD)((username.length() + 1) * sizeof(WCHAR));
    DWORD cbPassword = (DWORD)((password.length() + 1) * sizeof(WCHAR));
    DWORD cbDomain = (DWORD)((domain.length() + 1) * sizeof(WCHAR));

    DWORD cbTotal = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + cbUsername + cbPassword + cbDomain;

    BYTE* pBuffer = (BYTE*)CoTaskMemAlloc(cbTotal);
    if (!pBuffer)
        return E_OUTOFMEMORY;

    ZeroMemory(pBuffer, cbTotal);

    KERB_INTERACTIVE_UNLOCK_LOGON* pkiul = (KERB_INTERACTIVE_UNLOCK_LOGON*)pBuffer;
    pkiul->Logon.MessageType = KerbWorkstationUnlockLogon;

    BYTE* pStringBuffer = pBuffer + sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);

    if (!username.empty())
    {
        memcpy(pStringBuffer, username.c_str(), cbUsername);
        InitUnicodeString(&pkiul->Logon.UserName, (PWSTR)pStringBuffer);
        pStringBuffer += cbUsername;
    }

    if (!password.empty())
    {
        memcpy(pStringBuffer, password.c_str(), cbPassword);
        InitUnicodeString(&pkiul->Logon.Password, (PWSTR)pStringBuffer);
        pStringBuffer += cbPassword;
    }

    if (!domain.empty())
    {
        memcpy(pStringBuffer, domain.c_str(), cbDomain);
        InitUnicodeString(&pkiul->Logon.LogonDomainName, (PWSTR)pStringBuffer);
    }

    pkiul->LogonId.LowPart = 0;
    pkiul->LogonId.HighPart = 0;

    *ppPackage = pBuffer;
    *pcbPackage = cbTotal;

    return S_OK;
}
