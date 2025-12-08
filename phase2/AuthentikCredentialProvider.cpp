// AuthentikCredentialProvider.cpp
// Main credential provider implementation - Phase 2 (Passwordless)
// December 8, 2025

#include "AuthentikCredentialProvider.h"
#include "AuthentikCredential.h"
#include "Logger.h"
#include "guid.h"
#include <shlwapi.h>
#include <new>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "secur32.lib")

// NT_SUCCESS macro
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define NEGOSSP_NAME_A "Negotiate"

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

// IUnknown methods
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

ULONG CAuthentikProvider::AddRef()
{
    return InterlockedIncrement(&_cRef);
}

ULONG CAuthentikProvider::Release()
{
    LONG cRef = InterlockedDecrement(&_cRef);
    if (!cRef)
    {
        delete this;
    }
    return cRef;
}

// ICredentialProvider methods
HRESULT CAuthentikProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD dwFlags)
{
    LOG("CAuthentikProvider::SetUsageScenario cpus=%d, flags=0x%x", cpus, dwFlags);

    HRESULT hr = S_OK;

    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        _cpus = cpus;
        hr = _GetAuthenticationPackageId();
        if (FAILED(hr))
        {
            LOG("Failed to get authentication package ID: 0x%08x", hr);
        }
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

HRESULT CAuthentikProvider::SetSerialization(
    const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
    LOG("CAuthentikProvider::SetSerialization");
    return E_NOTIMPL;
}

HRESULT CAuthentikProvider::Advise(
    ICredentialProviderEvents* pcpe,
    UINT_PTR upAdviseContext)
{
    LOG("CAuthentikProvider::Advise");
    _upAdviseContext = upAdviseContext;
    return S_OK;
}

HRESULT CAuthentikProvider::UnAdvise()
{
    LOG("CAuthentikProvider::UnAdvise");
    _upAdviseContext = 0;
    return S_OK;
}

HRESULT CAuthentikProvider::GetFieldDescriptorCount(DWORD* pdwCount)
{
    LOG("CAuthentikProvider::GetFieldDescriptorCount");
    *pdwCount = FID_NUM_FIELDS;
    return S_OK;
}

HRESULT CAuthentikProvider::GetFieldDescriptorAt(
    DWORD dwIndex,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    LOG("CAuthentikProvider::GetFieldDescriptorAt index=%d", dwIndex);

    if (dwIndex < FID_NUM_FIELDS)
    {
        return FieldDescriptorCoAllocCopy(s_rgFieldDescriptors[dwIndex], ppcpfd);
    }
    return E_INVALIDARG;
}

HRESULT CAuthentikProvider::GetCredentialCount(
    DWORD* pdwCount,
    DWORD* pdwDefault,
    BOOL* pbAutoLogonWithDefault)
{
    LOG("CAuthentikProvider::GetCredentialCount");

    *pdwCount = 1;
    *pdwDefault = 0;
    *pbAutoLogonWithDefault = FALSE;

    return S_OK;
}

HRESULT CAuthentikProvider::GetCredentialAt(
    DWORD dwIndex,
    ICredentialProviderCredential** ppcpc)
{
    LOG("CAuthentikProvider::GetCredentialAt index=%d", dwIndex);

    HRESULT hr = E_INVALIDARG;

    if (dwIndex == 0 && ppcpc != nullptr)
    {
        if (_pCredential == nullptr)
        {
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
                    LOG("Credential initialization failed: 0x%08x", hr);
                    _pCredential->Release();
                    _pCredential = nullptr;
                }
            }
            else
            {
                hr = E_OUTOFMEMORY;
            }
        }

        if (_pCredential != nullptr)
        {
            hr = _pCredential->QueryInterface(IID_PPV_ARGS(ppcpc));
        }
    }

    return hr;
}

// ICredentialProviderSetUserArray
HRESULT CAuthentikProvider::SetUserArray(ICredentialProviderUserArray* users)
{
    LOG("CAuthentikProvider::SetUserArray");
    return S_OK;
}

// Get authentication package ID
HRESULT CAuthentikProvider::_GetAuthenticationPackageId()
{
    LOG("_GetAuthenticationPackageId");

    HRESULT hr = E_FAIL;
    HANDLE hLsa = nullptr;
    LSA_STRING packageName;

    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (NT_SUCCESS(status))
    {
        packageName.Buffer = (PCHAR)NEGOSSP_NAME_A;
        packageName.Length = (USHORT)strlen(packageName.Buffer);
        packageName.MaximumLength = packageName.Length;

        ULONG ulAuthPackage = 0;
        status = LsaLookupAuthenticationPackage(hLsa, &packageName, &ulAuthPackage);

        if (NT_SUCCESS(status))
        {
            _ulAuthPackage = ulAuthPackage;
            hr = S_OK;
            LOG("Authentication package ID: %d", ulAuthPackage);
        }
        else
        {
            LOG("LsaLookupAuthenticationPackage failed: 0x%08x", status);
            hr = HRESULT_FROM_NT(status);
        }

        LsaDeregisterLogonProcess(hLsa);
    }
    else
    {
        LOG("LsaConnectUntrusted failed: 0x%08x", status);
        hr = HRESULT_FROM_NT(status);
    }

    return hr;
}

// Factory function
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
