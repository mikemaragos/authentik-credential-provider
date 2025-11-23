// CredentialPacking.h
// Header for credential serialization functions

#pragma once

#include <windows.h>
#include <string>

// Pack credentials for interactive logon
HRESULT PackKerbInteractiveLogon(
    const std::wstring& username,
    const std::wstring& password,
    const std::wstring& domain,
    BYTE** ppPackage,
    DWORD* pcbPackage);

// Pack credentials for workstation unlock
HRESULT PackKerbInteractiveUnlockLogon(
    const std::wstring& username,
    const std::wstring& password,
    const std::wstring& domain,
    BYTE** ppPackage,
    DWORD* pcbPackage);
