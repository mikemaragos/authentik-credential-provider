// AuthentikCredentialProvider.cpp
// Main credential provider implementation

#include "AuthentikCredentialProvider.h"
#include "AuthentikCredential.h"
#include "Logger.h"
#include "guid.h"
#include <credentialprovider.h>

// Constructor
CAuthentikProvider::CAuthentikProvider() :
    _cRef(1),
    _pkiulSetSerialization(nullptr),
    _dwSetSerializationCred(CREDENTIAL_PROVIDER_NO_DEFAULT),
    _cpus(CPUS_INVALID),
    _pCredential(nullptr),
    _upAdviseContext(nullptr),
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

    // Decide which scenarios to support
    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        // Support these scenarios
        _cpus = cpus;

        // Get authentication package
        hr = _GetAuthenticationPackageId();
        if (FAILED(hr))
        {
            LOG("Failed to get authentication package ID: 0x%08x", hr);
        }
        break;

    case CPUS_CHANGE_PASSWORD:
        // Not supported
        hr = E_NOTIMPL;
        break;

    case CPUS_CREDUI:
        // Not supported
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

    HRESULT hr = E_NOTIMPL;

    // Store the serialization for later use during GetCredentialCount
    if (pcpcs)
    {
        if (_pkiulSetSerialization)
        {
            HeapFree(GetProcessHeap(), 0, _pkiulSetSerialization);
        }

        _pkiulSetSerialization = (KERB_INTERACTIVE_UNLOCK_LOGON*)HeapAlloc(
            GetProcessHeap(), 
            0, 
            pcpcs->cbSerialization);

        if (_pkiulSetSerialization)
        {
            CopyMemory(_pkiulSetSerialization, pcpcs->rgbSerialization, pcpcs->cbSerialization);
            hr = S_OK;
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }

    return hr;
}

HRESULT CAuthentikProvider::Advise(
    ICredentialProviderEvents* pcpe,
    UINT_PTR upAdviseContext)
{
    LOG("CAuthentikProvider::Advise");

    if (_upAdviseContext != 0)
    {
        // Already advised
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
    *pdwCount = ARRAYSIZE(s_rgFieldDescriptors);
    return S_OK;
}

HRESULT CAuthentikProvider::GetFieldDescriptorAt(
    DWORD dwIndex,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    LOG("CAuthentikProvider::GetFieldDescriptorAt - index=%d", dwIndex);

    HRESULT hr = E_INVALIDARG;

    if (dwIndex < ARRAYSIZE(s_rgFieldDescriptors))
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

    *pdwCount = 1; // We provide one credential
    *pdwDefault = 0; // Make it the default
    *pbAutoLogonWithDefault = FALSE; // Don't auto-logon

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
    // We don't use the user array
    return S_OK;
}

// Helper method to get authentication package ID
HRESULT CAuthentikProvider::_GetAuthenticationPackageId()
{
    HRESULT hr = E_FAIL;
    HANDLE hLsa = nullptr;
    ULONG ulAuthPackage = 0;
    LSA_STRING packageName;

    // Connect to LSA
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (NT_SUCCESS(status))
    {
        // Get "Negotiate" package
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
