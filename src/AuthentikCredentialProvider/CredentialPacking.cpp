// CredentialPacking.cpp
// Fixed implementation of KERB_INTERACTIVE_LOGON serialization

#include "CredentialPacking.h"
#include "Logger.h"
#include <windows.h>

// Define SECURITY_WIN32 before including security headers
#define SECURITY_WIN32
#include <security.h>
#include <ntsecapi.h>
#include <NTSecPKG.h>
#include <string>

// Link required libraries
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

// Pack credentials into KERB_INTERACTIVE_LOGON structure
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

    HRESULT hr = E_FAIL;

    // Calculate buffer sizes
    DWORD cbUsername = (DWORD)((username.length() + 1) * sizeof(WCHAR));
    DWORD cbPassword = (DWORD)((password.length() + 1) * sizeof(WCHAR));
    DWORD cbDomain = (DWORD)((domain.length() + 1) * sizeof(WCHAR));

    // Total size: structure + all strings
    DWORD cbTotal = sizeof(KERB_INTERACTIVE_LOGON) + cbUsername + cbPassword + cbDomain;

    LOG("Buffer sizes - Total: %d, User: %d, Pass: %d, Domain: %d", cbTotal, cbUsername, cbPassword, cbDomain);

    // Allocate buffer using CoTaskMemAlloc (required for credential providers)
    BYTE* pBuffer = (BYTE*)CoTaskMemAlloc(cbTotal);
    if (!pBuffer)
    {
        LOG("ERROR: Failed to allocate memory");
        return E_OUTOFMEMORY;
    }

    // Zero the buffer
    ZeroMemory(pBuffer, cbTotal);

    // Cast to structure
    KERB_INTERACTIVE_LOGON* pkil = (KERB_INTERACTIVE_LOGON*)pBuffer;

    // Set message type
    pkil->MessageType = KerbInteractiveLogon;

    LOG("Message type set to KerbInteractiveLogon (%d)", KerbInteractiveLogon);

    // String buffer starts after the structure
    BYTE* pStringBuffer = pBuffer + sizeof(KERB_INTERACTIVE_LOGON);

    // Copy and setup username
    if (!username.empty())
    {
        memcpy(pStringBuffer, username.c_str(), cbUsername);
        InitUnicodeString(&pkil->UserName, (PWSTR)pStringBuffer);
        pStringBuffer += cbUsername;
        LOG("Username copied: %S (Length: %d)", pkil->UserName.Buffer, pkil->UserName.Length);
    }
    else
    {
        InitUnicodeString(&pkil->UserName, nullptr);
        LOG("Username is empty");
    }

    // Copy and setup password
    if (!password.empty())
    {
        memcpy(pStringBuffer, password.c_str(), cbPassword);
        InitUnicodeString(&pkil->Password, (PWSTR)pStringBuffer);
        pStringBuffer += cbPassword;
        LOG("Password copied (Length: %d)", pkil->Password.Length);
    }
    else
    {
        InitUnicodeString(&pkil->Password, nullptr);
        LOG("Password is empty");
    }

    // Copy and setup domain
    if (!domain.empty())
    {
        memcpy(pStringBuffer, domain.c_str(), cbDomain);
        InitUnicodeString(&pkil->LogonDomainName, (PWSTR)pStringBuffer);
        pStringBuffer += cbDomain;
        LOG("Domain copied: %S (Length: %d)", pkil->LogonDomainName.Buffer, pkil->LogonDomainName.Length);
    }
    else
    {
        InitUnicodeString(&pkil->LogonDomainName, nullptr);
        LOG("Domain is empty");
    }

    // Verify buffer alignment
    DWORD actualSize = (DWORD)(pStringBuffer - pBuffer);
    if (actualSize != cbTotal)
    {
        LOG("WARNING: Buffer size mismatch - Expected: %d, Actual: %d", cbTotal, actualSize);
    }

    // Return the buffer
    *ppPackage = pBuffer;
    *pcbPackage = cbTotal;

    LOG("Successfully packed KERB_INTERACTIVE_LOGON - Size: %d bytes", cbTotal);

    return S_OK;
}

// Alternative packing function for unlock scenarios
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

    // Total size for unlock logon structure
    DWORD cbTotal = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + cbUsername + cbPassword + cbDomain;

    LOG("Unlock buffer sizes - Total: %d", cbTotal);

    // Allocate buffer
    BYTE* pBuffer = (BYTE*)CoTaskMemAlloc(cbTotal);
    if (!pBuffer)
    {
        LOG("ERROR: Failed to allocate memory for unlock");
        return E_OUTOFMEMORY;
    }

    ZeroMemory(pBuffer, cbTotal);

    // Cast to unlock structure
    KERB_INTERACTIVE_UNLOCK_LOGON* pkiul = (KERB_INTERACTIVE_UNLOCK_LOGON*)pBuffer;

    // Set message type for unlock
    pkiul->Logon.MessageType = KerbWorkstationUnlockLogon;

    LOG("Message type set to KerbWorkstationUnlockLogon");

    // String buffer starts after the structure
    BYTE* pStringBuffer = pBuffer + sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);

    // Copy username
    if (!username.empty())
    {
        memcpy(pStringBuffer, username.c_str(), cbUsername);
        InitUnicodeString(&pkiul->Logon.UserName, (PWSTR)pStringBuffer);
        pStringBuffer += cbUsername;
    }
    else
    {
        InitUnicodeString(&pkiul->Logon.UserName, nullptr);
    }

    // Copy password
    if (!password.empty())
    {
        memcpy(pStringBuffer, password.c_str(), cbPassword);
        InitUnicodeString(&pkiul->Logon.Password, (PWSTR)pStringBuffer);
        pStringBuffer += cbPassword;
    }
    else
    {
        InitUnicodeString(&pkiul->Logon.Password, nullptr);
    }

    // Copy domain
    if (!domain.empty())
    {
        memcpy(pStringBuffer, domain.c_str(), cbDomain);
        InitUnicodeString(&pkiul->Logon.LogonDomainName, (PWSTR)pStringBuffer);
        pStringBuffer += cbDomain;
    }
    else
    {
        InitUnicodeString(&pkiul->Logon.LogonDomainName, nullptr);
    }

    // Set LogonId to zero (required for unlock)
    pkiul->LogonId.LowPart = 0;
    pkiul->LogonId.HighPart = 0;

    // Return the buffer
    *ppPackage = pBuffer;
    *pcbPackage = cbTotal;

    LOG("Successfully packed KERB_INTERACTIVE_UNLOCK_LOGON - Size: %d bytes", cbTotal);

    return S_OK;
}
