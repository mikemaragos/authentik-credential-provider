// AuthentikCredentialProvider.cpp
// Main credential provider implementation for passwordless authentication

#include "AuthentikCredentialProvider.h"
#include "AuthentikCredential.h"
#include "FieldDescriptors.h"
#include "Logger.h"
#include "guid.h"

#include <windows.h>
#include <credentialprovider.h>
#include <ntsecapi.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "secur32.lib")

// NT_SUCCESS macro if not defined
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// DLL reference counting
extern void DllAddRef();
extern void DllRelease();

// Constructor
CAuthentikProvider::CAuthentikProvider() :
    _cRef(1),
    _cpus(CPUS_INVALID),
    _pCredential(nullptr),
    _upAdviseContext(0),
    _ulAuthPackage(0)
{
    DllAddRef();
    LOG("CAuthentikProvider::Constructor");
}

// Destructor
CAuthentikProvider::~CAuthentikProvider()
{
    LOG("CAuthentikProvider::Destructor");
    
    if (_pCredential != nullptr)
    {
        _pCredential->Release();
        _pCredential = nullptr;
    }

    DllRelease();
}

// IUnknown::AddRef
ULONG CAuthentikProvider::AddRef()
{
    return InterlockedIncrement(&_cRef);
}

// IUnknown::Release
ULONG CAuthentikProvider::Release()
{
    LONG cRef = InterlockedDecrement(&_cRef);
    if (!cRef)
    {
        delete this;
    }
    return cRef;
}

// IUnknown::QueryInterface
HRESULT CAuthentikProvider::QueryInterface(REFIID riid, void** ppv)
{
    static const QITAB qit[] =
    {
        QITABENT(CAuthentikProvider, ICredentialProvider),
        QITABENT(CAuthentikProvider, ICredentialProviderSetUserArray),
        {0},
    };
    return QISearch(this, qit, riid, ppv);
}

// Get the authentication package ID (Negotiate/Kerberos)
HRESULT CAuthentikProvider::_GetAuthenticationPackageId()
{
    HRESULT hr = S_OK;
    HANDLE hLsa = nullptr;
    
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (NT_SUCCESS(status))
    {
        LSA_STRING lsaszPackageName;
        lsaszPackageName.Buffer = (PCHAR)"Negotiate";
        lsaszPackageName.Length = (USHORT)strlen(lsaszPackageName.Buffer);
        lsaszPackageName.MaximumLength = lsaszPackageName.Length + 1;

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &_ulAuthPackage);
        if (!NT_SUCCESS(status))
        {
            LOG("LsaLookupAuthenticationPackage failed");
            hr = HRESULT_FROM_NT(status);
        }

        LsaDeregisterLogonProcess(hLsa);
    }
    else
    {
        LOG("LsaConnectUntrusted failed");
        hr = HRESULT_FROM_NT(status);
    }

    return hr;
}

// ICredentialProvider::SetUsageScenario
HRESULT CAuthentikProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD dwFlags)
{
    UNREFERENCED_PARAMETER(dwFlags);
    LOG("CAuthentikProvider::SetUsageScenario");

    HRESULT hr;

    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        _cpus = cpus;
        hr = _GetAuthenticationPackageId();
        break;

    case CPUS_CHANGE_PASSWORD:
    case CPUS_CREDUI:
        hr = E_NOTIMPL;
        break;

    default:
        hr = E_INVALIDARG;
        break;
    }

    return hr;
}

// ICredentialProvider::SetSerialization
HRESULT CAuthentikProvider::SetSerialization(
    const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
    UNREFERENCED_PARAMETER(pcpcs);
    LOG("CAuthentikProvider::SetSerialization");
    return E_NOTIMPL;
}

// ICredentialProvider::Advise
HRESULT CAuthentikProvider::Advise(
    ICredentialProviderEvents* pcpe,
    UINT_PTR upAdviseContext)
{
    UNREFERENCED_PARAMETER(pcpe);
    LOG("CAuthentikProvider::Advise");
    
    _upAdviseContext = upAdviseContext;
    return S_OK;
}

// ICredentialProvider::UnAdvise
HRESULT CAuthentikProvider::UnAdvise()
{
    LOG("CAuthentikProvider::UnAdvise");
    return S_OK;
}

// ICredentialProvider::GetFieldDescriptorCount
HRESULT CAuthentikProvider::GetFieldDescriptorCount(DWORD* pdwCount)
{
    LOG("CAuthentikProvider::GetFieldDescriptorCount");
    
    if (pdwCount == nullptr)
    {
        return E_INVALIDARG;
    }

    *pdwCount = FID_NUM_FIELDS;
    return S_OK;
}

// ICredentialProvider::GetFieldDescriptorAt
HRESULT CAuthentikProvider::GetFieldDescriptorAt(
    DWORD dwIndex,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    LOG("CAuthentikProvider::GetFieldDescriptorAt");

    if (ppcpfd == nullptr)
    {
        return E_INVALIDARG;
    }

    if (dwIndex >= FID_NUM_FIELDS)
    {
        return E_INVALIDARG;
    }

    return FieldDescriptorCoAllocCopy(s_rgFieldDescriptors[dwIndex], ppcpfd);
}

// ICredentialProvider::GetCredentialCount
HRESULT CAuthentikProvider::GetCredentialCount(
    DWORD* pdwCount,
    DWORD* pdwDefault,
    BOOL* pbAutoLogonWithDefault)
{
    LOG("CAuthentikProvider::GetCredentialCount");

    if (pdwCount == nullptr || pdwDefault == nullptr || pbAutoLogonWithDefault == nullptr)
    {
        return E_INVALIDARG;
    }

    *pdwCount = 1;  // We provide one credential tile
    *pdwDefault = 0;
    *pbAutoLogonWithDefault = FALSE;

    return S_OK;
}

// ICredentialProvider::GetCredentialAt
HRESULT CAuthentikProvider::GetCredentialAt(
    DWORD dwIndex,
    ICredentialProviderCredential** ppcpc)
{
    LOG("CAuthentikProvider::GetCredentialAt");

    HRESULT hr = E_INVALIDARG;

    if (dwIndex == 0 && ppcpc != nullptr)
    {
        if (_pCredential == nullptr)
        {
            // Create the credential
            _pCredential = new(std::nothrow) CAuthentikCredential();
            if (_pCredential != nullptr)
            {
                hr = _pCredential->Initialize(
                    _cpus,
                    s_rgFieldDescriptors,
                    s_rgFieldStatePairs,
                    _ulAuthPackage);

                if (FAILED(hr))
                {
                    _pCredential->Release();
                    _pCredential = nullptr;
                }
            }
            else
            {
                hr = E_OUTOFMEMORY;
            }
        }

        if (SUCCEEDED(hr) || _pCredential != nullptr)
        {
            hr = _pCredential->QueryInterface(IID_ICredentialProviderCredential, (void**)ppcpc);
        }
    }

    return hr;
}

// ICredentialProviderSetUserArray::SetUserArray
HRESULT CAuthentikProvider::SetUserArray(ICredentialProviderUserArray* users)
{
    UNREFERENCED_PARAMETER(users);
    LOG("CAuthentikProvider::SetUserArray");
    return S_OK;
}

// Create instance function
HRESULT CAuthentikProvider_CreateInstance(REFIID riid, void** ppv)
{
    LOG("CAuthentikProvider_CreateInstance");

    HRESULT hr;
    CAuthentikProvider* pProvider = new(std::nothrow) CAuthentikProvider();

    if (pProvider)
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}
