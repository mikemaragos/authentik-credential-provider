// AuthentikCredentialProvider.cpp
// Main credential provider implementation - Passwordless version

#include "AuthentikCredentialProvider.h"
#include "AuthentikCredential.h"
#include "Logger.h"
#include "guid.h"
#include <credentialprovider.h>
#include <ntsecapi.h>
#include <shlwapi.h>

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Shlwapi.lib")

// Constructor
CAuthentikProvider::CAuthentikProvider() :
    _cRef(1),
    _pkiulSetSerialization(nullptr),
    _dwSetSerializationCred(CREDENTIAL_PROVIDER_NO_DEFAULT),
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

    if (_pkiulSetSerialization)
    {
        HeapFree(GetProcessHeap(), 0, _pkiulSetSerialization);
        _pkiulSetSerialization = nullptr;
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
    LOG("CAuthentikProvider::SetUsageScenario - cpus=%d, flags=%d", cpus, dwFlags);

    HRESULT hr = S_OK;

    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        // Support logon and unlock scenarios
        _cpus = cpus;

        // Get authentication package - try Kerberos first for PKINIT
        hr = _GetAuthenticationPackageId();
        if (FAILED(hr))
        {
            LOG_E("Failed to get authentication package ID: 0x%08x", hr);
        }
        break;

    case CPUS_CHANGE_PASSWORD:
        // Not supported - passwordless doesn't have passwords to change
        LOG("Change password not supported for passwordless");
        hr = E_NOTIMPL;
        break;

    case CPUS_CREDUI:
        // Not supported for now
        LOG("CredUI not supported");
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

    // We don't pre-populate credentials from serialization
    // This is used for things like RDP saved credentials
    return E_NOTIMPL;
}

HRESULT CAuthentikProvider::Advise(
    ICredentialProviderEvents* pcpe,
    UINT_PTR upAdviseContext)
{
    LOG("CAuthentikProvider::Advise");

    if (_upAdviseContext != 0)
    {
        return E_INVALIDARG;
    }

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
    LOG("CAuthentikProvider::GetFieldDescriptorAt - index=%d", dwIndex);

    HRESULT hr = E_INVALIDARG;

    if (dwIndex < FID_NUM_FIELDS)
    {
        hr = FieldDescriptorCoAllocCopy(s_rgFieldDescriptors[dwIndex], ppcpfd);
    }

    return hr;
}

HRESULT CAuthentikProvider::GetCredentialCount(
    DWORD* pdwCount,
    DWORD* pdwDefault,
    BOOL* pbAutoLogonWithDefault)
{
    LOG("CAuthentikProvider::GetCredentialCount");

    *pdwCount = 1;  // Single credential tile
    *pdwDefault = 0;  // Make it default
    *pbAutoLogonWithDefault = FALSE;  // Don't auto-logon

    return S_OK;
}

HRESULT CAuthentikProvider::GetCredentialAt(
    DWORD dwIndex,
    ICredentialProviderCredential** ppcpc)
{
    LOG("CAuthentikProvider::GetCredentialAt - index=%d", dwIndex);

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
                    s_rgFieldStatePairsLogon,
                    _ulAuthPackage);

                if (FAILED(hr))
                {
                    LOG_E("Failed to initialize credential: 0x%08x", hr);
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
    // We don't use the user array for passwordless
    // Could potentially pre-populate username if user is selected
    return S_OK;
}

// Get authentication package ID
// For PKINIT (certificate auth), we need Kerberos
HRESULT CAuthentikProvider::_GetAuthenticationPackageId()
{
    LOG("_GetAuthenticationPackageId");

    HRESULT hr = E_FAIL;
    HANDLE hLsa = nullptr;
    ULONG ulAuthPackage = 0;
    LSA_STRING packageName;

    // Connect to LSA
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (!NT_SUCCESS(status))
    {
        LOG_E("LsaConnectUntrusted failed: 0x%08x", status);
        return HRESULT_FROM_NT(status);
    }

    // Try Kerberos package first (needed for PKINIT certificate auth)
    packageName.Buffer = (PCHAR)MICROSOFT_KERBEROS_NAME_A;
    packageName.Length = (USHORT)strlen(packageName.Buffer);
    packageName.MaximumLength = packageName.Length;

    status = LsaLookupAuthenticationPackage(
        hLsa,
        &packageName,
        &ulAuthPackage);

    if (NT_SUCCESS(status))
    {
        _ulAuthPackage = ulAuthPackage;
        hr = S_OK;
        LOG("Using Kerberos authentication package ID: %d", ulAuthPackage);
    }
    else
    {
        LOG_W("Kerberos package lookup failed: 0x%08x, trying Negotiate", status);

        // Fall back to Negotiate
        packageName.Buffer = (PCHAR)NEGOSSP_NAME_A;
        packageName.Length = (USHORT)strlen(packageName.Buffer);
        packageName.MaximumLength = packageName.Length;

        status = LsaLookupAuthenticationPackage(
            hLsa,
            &packageName,
            &ulAuthPackage);

        if (NT_SUCCESS(status))
        {
            _ulAuthPackage = ulAuthPackage;
            hr = S_OK;
            LOG("Using Negotiate authentication package ID: %d", ulAuthPackage);
        }
        else
        {
            LOG_E("LsaLookupAuthenticationPackage failed: 0x%08x", status);
            hr = HRESULT_FROM_NT(status);
        }
    }

    LsaDeregisterLogonProcess(hLsa);
    return hr;
}

// Class factory
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
