// AuthentikCredentialProvider.h
// Header for main credential provider - Phase 2 (Passwordless)
// December 8, 2025

#pragma once

#include <credentialprovider.h>
#include <windows.h>
#include <strsafe.h>
#include <shlguid.h>
#include <NTSecAPI.h>
#include "FieldDescriptors.h"

class CAuthentikCredential;

class CAuthentikProvider : public ICredentialProvider, public ICredentialProviderSetUserArray
{
public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);

    // ICredentialProvider
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags);
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);
    IFACEMETHODIMP Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext);
    IFACEMETHODIMP UnAdvise();
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* pdwCount);
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);
    IFACEMETHODIMP GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault);
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc);

    // ICredentialProviderSetUserArray
    IFACEMETHODIMP SetUserArray(ICredentialProviderUserArray* users);

    friend HRESULT CAuthentikProvider_CreateInstance(REFIID riid, void** ppv);

protected:
    CAuthentikProvider();
    ~CAuthentikProvider();

private:
    HRESULT _GetAuthenticationPackageId();

    LONG _cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;
    CAuthentikCredential* _pCredential;
    UINT_PTR _upAdviseContext;
    ULONG _ulAuthPackage;
};

// Factory function
HRESULT CAuthentikProvider_CreateInstance(REFIID riid, void** ppv);
