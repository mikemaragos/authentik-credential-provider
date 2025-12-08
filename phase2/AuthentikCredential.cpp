// AuthentikCredential.cpp
// Individual credential tile implementation - Phase 2 (Passwordless)

#include "AuthentikCredential.h"
#include "Logger.h"
#include "CredentialPacking.h"
#include "AuthentikAPI.h"
#include "VSCManager.h"

// Field state pairs for passwordless logon (username + OTP only)
static const FIELD_STATE_PAIR s_rgFieldStatePairsLogon[] =
{
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_LOGO
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_LARGE_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_SMALL_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },  // FID_USERNAME
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_OTP
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_SUBMIT
};

// Constructor
CAuthentikCredential::CAuthentikCredential() :
    _cRef(1),
    _cpus(CPUS_INVALID),
    _ulAuthPackage(0),
    _pAuthentikAPI(nullptr),
    _pVSCManager(nullptr),
    _pCredentialEvents(nullptr),
    _domain(L"test.local"),
    _vscPin(L"12345678")
{
    DllAddRef();
    LOG("CAuthentikCredential::Constructor (Phase 2 - Passwordless)");

    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
    ZeroMemory(&_rgFieldStatePairs, sizeof(_rgFieldStatePairs));

    // Initialize API client and VSC manager
    _pAuthentikAPI = new AuthentikAPI();
    _pVSCManager = new VSCManager();

    // Load configuration
    _LoadConfiguration();
}

// Destructor
CAuthentikCredential::~CAuthentikCredential()
{
    LOG("CAuthentikCredential::Destructor");

    // Clean up field strings
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        if (_rgFieldStrings[i])
        {
            CoTaskMemFree(_rgFieldStrings[i]);
            _rgFieldStrings[i] = nullptr;
        }
    }

    // Clean up PIN
    SecureZeroMemory(&_vscPin[0], _vscPin.length() * sizeof(wchar_t));

    if (_pAuthentikAPI)
    {
        delete _pAuthentikAPI;
        _pAuthentikAPI = nullptr;
    }

    if (_pVSCManager)
    {
        delete _pVSCManager;
        _pVSCManager = nullptr;
    }

    DllRelease();
}

// Load configuration from registry
void CAuthentikCredential::_LoadConfiguration()
{
    LOG("Loading credential configuration");

    HKEY hKey;
    LONG result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\AuthentikCredentialProvider",
        0,
        KEY_READ,
        &hKey);

    if (result == ERROR_SUCCESS)
    {
        WCHAR buffer[256];
        DWORD bufferSize;

        // Domain
        bufferSize = sizeof(buffer);
        result = RegQueryValueExW(hKey, L"Domain", nullptr, nullptr, (LPBYTE)buffer, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _domain = buffer;
            LOG("Domain: %S", _domain.c_str());
        }

        // VSC PIN (should be stored securely in production!)
        bufferSize = sizeof(buffer);
        result = RegQueryValueExW(hKey, L"VSCPin", nullptr, nullptr, (LPBYTE)buffer, &bufferSize);
        if (result == ERROR_SUCCESS)
        {
            _vscPin = buffer;
            LOG("VSC PIN: (loaded)");
        }

        RegCloseKey(hKey);
    }
}

// IUnknown
HRESULT CAuthentikCredential::QueryInterface(REFIID riid, void** ppv)
{
    static const QITAB qit[] =
    {
        QITABENT(CAuthentikCredential, ICredentialProviderCredential),
        {0},
    };
    return QISearch(this, qit, riid, ppv);
}

ULONG CAuthentikCredential::AddRef()
{
    return InterlockedIncrement(&_cRef);
}

ULONG CAuthentikCredential::Release()
{
    LONG cRef = InterlockedDecrement(&_cRef);
    if (!cRef)
    {
        delete this;
    }
    return cRef;
}

// ICredentialProviderCredential
HRESULT CAuthentikCredential::Initialize(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
    const FIELD_STATE_PAIR* rgfsp,
    ULONG ulAuthPackage)
{
    LOG("CAuthentikCredential::Initialize (Phase 2)");

    _cpus = cpus;
    _ulAuthPackage = ulAuthPackage;

    // Copy field descriptors and initial state
    for (DWORD i = 0; i < ARRAYSIZE(s_rgFieldStatePairsLogon); i++)
    {
        _rgFieldStatePairs[i] = s_rgFieldStatePairsLogon[i];

        if (rgcpfd[i].pszLabel)
        {
            SHStrDupW(rgcpfd[i].pszLabel, &_rgFieldStrings[i]);
        }
    }

    // Set default text
    SHStrDupW(L"Authentik Passwordless", &_rgFieldStrings[FID_LARGE_TEXT]);
    SHStrDupW(L"Enter username and OTP code", &_rgFieldStrings[FID_SMALL_TEXT]);

    return S_OK;
}

HRESULT CAuthentikCredential::Advise(ICredentialProviderCredentialEvents* pcpce)
{
    LOG("CAuthentikCredential::Advise");
    
    if (_pCredentialEvents)
    {
        _pCredentialEvents->Release();
    }
    
    _pCredentialEvents = pcpce;
    _pCredentialEvents->AddRef();
    
    return S_OK;
}

HRESULT CAuthentikCredential::UnAdvise()
{
    LOG("CAuthentikCredential::UnAdvise");
    
    if (_pCredentialEvents)
    {
        _pCredentialEvents->Release();
        _pCredentialEvents = nullptr;
    }
    
    return S_OK;
}

HRESULT CAuthentikCredential::SetSelected(BOOL* pbAutoLogon)
{
    LOG("CAuthentikCredential::SetSelected");
    *pbAutoLogon = FALSE;
    return S_OK;
}

HRESULT CAuthentikCredential::SetDeselected()
{
    LOG("CAuthentikCredential::SetDeselected");
    return S_OK;
}

HRESULT CAuthentikCredential::GetFieldState(
    DWORD dwFieldID,
    CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    if (dwFieldID < ARRAYSIZE(_rgFieldStatePairs))
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        return S_OK;
    }
    return E_INVALIDARG;
}

HRESULT CAuthentikCredential::GetStringValue(DWORD dwFieldID, LPWSTR* ppwsz)
{
    HRESULT hr = E_INVALIDARG;

    if (dwFieldID < ARRAYSIZE(_rgFieldStrings) && ppwsz)
    {
        if (_rgFieldStrings[dwFieldID])
        {
            hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
        }
        else
        {
            *ppwsz = nullptr;
            hr = S_OK;
        }
    }

    return hr;
}

HRESULT CAuthentikCredential::GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp)
{
    if (dwFieldID == FID_LOGO)
    {
        *phbmp = nullptr;
        return S_OK;
    }
    return E_INVALIDARG;
}

HRESULT CAuthentikCredential::GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, LPWSTR* ppwszLabel)
{
    return E_NOTIMPL;
}

HRESULT CAuthentikCredential::GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem)
{
    return E_NOTIMPL;
}

HRESULT CAuthentikCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, LPWSTR* ppwszItem)
{
    return E_NOTIMPL;
}

HRESULT CAuthentikCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo)
{
    if (dwFieldID == FID_SUBMIT)
    {
        *pdwAdjacentTo = FID_OTP;
        return S_OK;
    }
    return E_INVALIDARG;
}

HRESULT CAuthentikCredential::SetStringValue(DWORD dwFieldID, LPCWSTR pwz)
{
    HRESULT hr = E_INVALIDARG;

    if (dwFieldID < ARRAYSIZE(_rgFieldStrings))
    {
        if (_rgFieldStrings[dwFieldID])
        {
            CoTaskMemFree(_rgFieldStrings[dwFieldID]);
        }

        hr = SHStrDupW(pwz, &_rgFieldStrings[dwFieldID]);
        
        LOG("SetStringValue: field=%d", dwFieldID);
    }

    return hr;
}

HRESULT CAuthentikCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
    return E_NOTIMPL;
}

HRESULT CAuthentikCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    return E_NOTIMPL;
}

HRESULT CAuthentikCredential::CommandLinkClicked(DWORD dwFieldID)
{
    return E_NOTIMPL;
}

HRESULT CAuthentikCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    LPWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    LOG("CAuthentikCredential::GetSerialization (Phase 2)");
    return _HandleAuthentication(pcpgsr, pcpcs, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);
}

HRESULT CAuthentikCredential::ReportResult(
    NTSTATUS ntsStatus,
    NTSTATUS ntsSubstatus,
    LPWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    LOG("CAuthentikCredential::ReportResult - status=0x%08x, substatus=0x%08x", ntsStatus, ntsSubstatus);
    
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    return S_OK;
}

// Main authentication handler
HRESULT CAuthentikCredential::_HandleAuthentication(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    LPWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    LOG("_HandleAuthentication (Passwordless)");

    // Get username and OTP
    std::wstring username = _rgFieldStrings[FID_USERNAME] ? _rgFieldStrings[FID_USERNAME] : L"";
    std::wstring otp = _rgFieldStrings[FID_OTP] ? _rgFieldStrings[FID_OTP] : L"";

    // Validate input
    if (username.empty())
    {
        SHStrDupW(L"Please enter a username", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return E_FAIL;
    }

    if (otp.empty())
    {
        SHStrDupW(L"Please enter your OTP code", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return E_FAIL;
    }

    // Update status
    if (_pCredentialEvents)
    {
        _pCredentialEvents->SetFieldString(this, FID_SMALL_TEXT, L"Authenticating...");
    }

    LOG("Authenticating user: %S with OTP", username.c_str());

    // Step 1: Validate OTP and get certificate from Authentik
    CertificateResponse certResponse = _pAuthentikAPI->AuthenticateAndGetCertificate(
        username, otp, _domain);

    if (!certResponse.success)
    {
        LOG("Authentication failed: %S", certResponse.message.c_str());
        SHStrDupW(certResponse.message.c_str(), ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;

        // Clear OTP field
        if (_rgFieldStrings[FID_OTP])
        {
            CoTaskMemFree(_rgFieldStrings[FID_OTP]);
            _rgFieldStrings[FID_OTP] = nullptr;
        }
        if (_pCredentialEvents)
        {
            _pCredentialEvents->SetFieldString(this, FID_OTP, L"");
            _pCredentialEvents->SetFieldString(this, FID_SMALL_TEXT, L"Enter username and OTP code");
        }

        return E_FAIL;
    }

    LOG("OTP validated, certificate received: %d bytes", certResponse.certificateDer.size());

    // Update status
    if (_pCredentialEvents)
    {
        _pCredentialEvents->SetFieldString(this, FID_SMALL_TEXT, L"Importing certificate...");
    }

    // Step 2: Import certificate to VSC
    VSCInfo vscInfo;
    HRESULT hr = _pVSCManager->ImportCertificate(
        certResponse.certificateDer,
        certResponse.privateKeyBlob,
        _vscPin,
        &vscInfo);

    if (FAILED(hr))
    {
        LOG("Failed to import certificate to VSC: 0x%08x", hr);
        SHStrDupW(L"Failed to import certificate", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return hr;
    }

    LOG("Certificate imported to VSC: reader=%S, container=%S",
        vscInfo.readerName.c_str(), vscInfo.containerName.c_str());

    // Update status
    if (_pCredentialEvents)
    {
        _pCredentialEvents->SetFieldString(this, FID_SMALL_TEXT, L"Logging in...");
    }

    // Step 3: Pack smart card credentials for PKINIT
    hr = _PackSmartCardCredentials(
        username, _domain, vscInfo,
        pcpgsr, pcpcs, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);

    return hr;
}

// Pack smart card credentials for PKINIT authentication
HRESULT CAuthentikCredential::_PackSmartCardCredentials(
    const std::wstring& username,
    const std::wstring& domain,
    const VSCInfo& vscInfo,
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    LPWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    LOG("_PackSmartCardCredentials");

    BYTE* pPackage = nullptr;
    DWORD cbPackage = 0;

    // Choose logon vs unlock based on usage scenario
    HRESULT hr;
    if (_cpus == CPUS_UNLOCK_WORKSTATION)
    {
        hr = PackKerbCertificateUnlockLogon(
            username, domain, _vscPin, vscInfo,
            &pPackage, &cbPackage);
    }
    else
    {
        hr = PackKerbCertificateLogon(
            username, domain, _vscPin, vscInfo,
            &pPackage, &cbPackage);
    }

    if (SUCCEEDED(hr))
    {
        // Fill serialization structure
        pcpcs->clsidCredentialProvider = CLSID_AuthentikCredentialProvider;
        pcpcs->rgbSerialization = pPackage;
        pcpcs->cbSerialization = cbPackage;
        pcpcs->ulAuthenticationPackage = _ulAuthPackage;

        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
        *pcpsiOptionalStatusIcon = CPSI_SUCCESS;

        LOG("Smart card credentials packed successfully: %d bytes", cbPackage);
    }
    else
    {
        LOG("Failed to pack smart card credentials: 0x%08x", hr);
        SHStrDupW(L"Failed to prepare credentials", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    }

    return hr;
}
