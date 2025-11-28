// CredentialPacking.cpp
// Fixed implementation of KERB_INTERACTIVE_LOGON serialization

#include "CredentialPacking.h"
#include "Logger.h"
#include <windows.h>
#include <combaseapi.h>  // For CoTaskMemAlloc

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
    // CRITICAL: Buffer must be OFFSET from structure start, not absolute pointer!
    if (!username.empty())
    {
        memcpy(pStringBuffer, username.c_str(), cbUsername);
        pkil->UserName.Length = (USHORT)(username.length() * sizeof(WCHAR));
        pkil->UserName.MaximumLength = (USHORT)cbUsername;
        pkil->UserName.Buffer = (PWSTR)(pStringBuffer - pBuffer);  // OFFSET, not pointer!
        LOG("Username copied: offset=%d, Length: %d", (int)(pStringBuffer - pBuffer), pkil->UserName.Length);
        pStringBuffer += cbUsername;
    }
    else
    {
        pkil->UserName.Length = 0;
        pkil->UserName.MaximumLength = 0;
        pkil->UserName.Buffer = nullptr;
        LOG("Username is empty");
    }

    // Copy and setup password
    // CRITICAL: Buffer must be OFFSET from structure start, not absolute pointer!
    if (!password.empty())
    {
        memcpy(pStringBuffer, password.c_str(), cbPassword);
        pkil->Password.Length = (USHORT)(password.length() * sizeof(WCHAR));
        pkil->Password.MaximumLength = (USHORT)cbPassword;
        pkil->Password.Buffer = (PWSTR)(pStringBuffer - pBuffer);  // OFFSET, not pointer!
        LOG("Password copied: offset=%d, Length: %d", (int)(pStringBuffer - pBuffer), pkil->Password.Length);
        pStringBuffer += cbPassword;
    }
    else
    {
        pkil->Password.Length = 0;
        pkil->Password.MaximumLength = 0;
        pkil->Password.Buffer = nullptr;
        LOG("Password is empty");
    }

    // Copy and setup domain
    // CRITICAL: Buffer must be OFFSET from structure start, not absolute pointer!
    if (!domain.empty())
    {
        memcpy(pStringBuffer, domain.c_str(), cbDomain);
        pkil->LogonDomainName.Length = (USHORT)(domain.length() * sizeof(WCHAR));
        pkil->LogonDomainName.MaximumLength = (USHORT)cbDomain;
        pkil->LogonDomainName.Buffer = (PWSTR)(pStringBuffer - pBuffer);  // OFFSET, not pointer!
        LOG("Domain copied: offset=%d, Length: %d", (int)(pStringBuffer - pBuffer), pkil->LogonDomainName.Length);
        pStringBuffer += cbDomain;
    }
    else
    {
        pkil->LogonDomainName.Length = 0;
        pkil->LogonDomainName.MaximumLength = 0;
        pkil->LogonDomainName.Buffer = nullptr;
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

    // Copy username - use OFFSET not absolute pointer
    if (!username.empty())
    {
        memcpy(pStringBuffer, username.c_str(), cbUsername);
        pkiul->Logon.UserName.Length = (USHORT)(username.length() * sizeof(WCHAR));
        pkiul->Logon.UserName.MaximumLength = (USHORT)cbUsername;
        pkiul->Logon.UserName.Buffer = (PWSTR)(pStringBuffer - pBuffer);
        pStringBuffer += cbUsername;
    }
    else
    {
        pkiul->Logon.UserName.Length = 0;
        pkiul->Logon.UserName.MaximumLength = 0;
        pkiul->Logon.UserName.Buffer = nullptr;
    }

    // Copy password - use OFFSET not absolute pointer
    if (!password.empty())
    {
        memcpy(pStringBuffer, password.c_str(), cbPassword);
        pkiul->Logon.Password.Length = (USHORT)(password.length() * sizeof(WCHAR));
        pkiul->Logon.Password.MaximumLength = (USHORT)cbPassword;
        pkiul->Logon.Password.Buffer = (PWSTR)(pStringBuffer - pBuffer);
        pStringBuffer += cbPassword;
    }
    else
    {
        pkiul->Logon.Password.Length = 0;
        pkiul->Logon.Password.MaximumLength = 0;
        pkiul->Logon.Password.Buffer = nullptr;
    }

    // Copy domain - use OFFSET not absolute pointer
    if (!domain.empty())
    {
        memcpy(pStringBuffer, domain.c_str(), cbDomain);
        pkiul->Logon.LogonDomainName.Length = (USHORT)(domain.length() * sizeof(WCHAR));
        pkiul->Logon.LogonDomainName.MaximumLength = (USHORT)cbDomain;
        pkiul->Logon.LogonDomainName.Buffer = (PWSTR)(pStringBuffer - pBuffer);
        pStringBuffer += cbDomain;
    }
    else
    {
        pkiul->Logon.LogonDomainName.Length = 0;
        pkiul->Logon.LogonDomainName.MaximumLength = 0;
        pkiul->Logon.LogonDomainName.Buffer = nullptr;
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
