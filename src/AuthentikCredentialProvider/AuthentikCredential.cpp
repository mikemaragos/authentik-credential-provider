// AuthentikCredential.cpp
// Individual credential tile implementation

#include "AuthentikCredential.h"
#include "Logger.h"
#include "CredentialPacking.h"
#include "AuthentikAPI.h"
#include "guid.h"
#include <wincred.h>

// Field state pairs for different usage scenarios
static const FIELD_STATE_PAIR s_rgFieldStatePairsLogon[] =
{
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },                   // FID_LOGO
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },                   // FID_LARGE_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },                   // FID_SMALL_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },                // FID_USERNAME - focused!
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },                   // FID_PASSWORD
    { CPFS_HIDDEN, CPFIS_NONE },                                     // FID_OTP (hidden initially)
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },                   // FID_SUBMIT
};

// Constructor
CAuthentikCredential::CAuthentikCredential() :
    _cRef(1),
    _cpus(CPUS_INVALID),
    _ulAuthPackage(0),
    _currentStep(AuthStep::STEP_USERNAME_PASSWORD),
    _pAuthentikAPI(nullptr),
    _pCredentialEvents(nullptr)
{
    DllAddRef();
    LOG("CAuthentikCredential::Constructor");

    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
    ZeroMemory(&_rgFieldStatePairs, sizeof(_rgFieldStatePairs));

    // Initialize API client
    _pAuthentikAPI = new AuthentikAPI();
    LOG("CAuthentikCredential::Constructor - API client created");
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

    // Clean up cached password
    SecureZeroMemory(&_cachedPassword[0], _cachedPassword.length() * sizeof(wchar_t));
    _cachedPassword.clear();

    if (_pAuthentikAPI)
    {
        delete _pAuthentikAPI;
        _pAuthentikAPI = nullptr;
    }

    DllRelease();
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
    LOG("CAuthentikCredential::Initialize");

    _cpus = cpus;
    _ulAuthPackage = ulAuthPackage;

    // Copy field descriptors and initial state
    for (DWORD i = 0; i < ARRAYSIZE(s_rgFieldStatePairsLogon); i++)
    {
        _rgFieldStatePairs[i] = s_rgFieldStatePairsLogon[i];

        // Copy field strings
        if (rgcpfd[i].pszLabel)
        {
            SHStrDupW(rgcpfd[i].pszLabel, &_rgFieldStrings[i]);
        }
    }

    // Set default text
    SHStrDupW(L"Authentik OTP Login", &_rgFieldStrings[FID_LARGE_TEXT]);
    SHStrDupW(L"Enter your credentials", &_rgFieldStrings[FID_SMALL_TEXT]);

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
    
    // Reset to initial state
    _currentStep = AuthStep::STEP_USERNAME_PASSWORD;
    
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
    // Return default user icon
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
    LOG("GetSubmitButtonValue: dwFieldID=%d", dwFieldID);
    
    if (dwFieldID == FID_SUBMIT)
    {
        // Submit button is adjacent to password or OTP field depending on step
        if (_currentStep == AuthStep::STEP_USERNAME_PASSWORD)
        {
            *pdwAdjacentTo = FID_PASSWORD;
            LOG("GetSubmitButtonValue: adjacent to PASSWORD field");
        }
        else
        {
            *pdwAdjacentTo = FID_OTP;
            LOG("GetSubmitButtonValue: adjacent to OTP field");
        }
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
        
        LOG("SetStringValue: field=%d, value=%S", dwFieldID, pwz ? pwz : L"(null)");
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
    LOG("CAuthentikCredential::GetSerialization - Step: %d", _currentStep);

    HRESULT hr = E_FAIL;

    if (_currentStep == AuthStep::STEP_USERNAME_PASSWORD)
    {
        // Step 1: Validate username and password, request OTP
        hr = _HandleUsernamePasswordStep(pcpgsr, pcpcs, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);
    }
    else if (_currentStep == AuthStep::STEP_OTP)
    {
        // Step 2: Validate OTP and complete login
        hr = _HandleOTPStep(pcpgsr, pcpcs, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);
    }

    return hr;
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

// Private helper methods
HRESULT CAuthentikCredential::_HandleUsernamePasswordStep(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    LPWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    LOG("_HandleUsernamePasswordStep");

    // Get username and password
    std::wstring username = _rgFieldStrings[FID_USERNAME] ? _rgFieldStrings[FID_USERNAME] : L"";
    std::wstring password = _rgFieldStrings[FID_PASSWORD] ? _rgFieldStrings[FID_PASSWORD] : L"";

    if (username.empty())
    {
        SHStrDupW(L"Please enter a username", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return E_FAIL;
    }

    // Cache password for later use
    _cachedPassword = password;

    // Call Authentik API to initiate authentication
    AuthentikResponse response = _pAuthentikAPI->InitiateAuthentication(username, password);

    if (response.requiresOTP)
    {
        // Store transaction ID
        _transactionId = response.transactionId;

        // Show OTP field
        _rgFieldStatePairs[FID_PASSWORD].cpfs = CPFS_HIDDEN;
        _rgFieldStatePairs[FID_OTP].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        _rgFieldStatePairs[FID_OTP].cpfis = CPFIS_FOCUSED;

        // Update text
        if (_rgFieldStrings[FID_SMALL_TEXT])
        {
            CoTaskMemFree(_rgFieldStrings[FID_SMALL_TEXT]);
        }
        SHStrDupW(L"Enter your OTP code", &_rgFieldStrings[FID_SMALL_TEXT]);

        // Notify UI of field changes
        if (_pCredentialEvents)
        {
            _pCredentialEvents->SetFieldState(this, FID_PASSWORD, CPFS_HIDDEN);
            _pCredentialEvents->SetFieldState(this, FID_OTP, CPFS_DISPLAY_IN_SELECTED_TILE);
            _pCredentialEvents->SetFieldInteractiveState(this, FID_OTP, CPFIS_FOCUSED);
            _pCredentialEvents->SetFieldString(this, FID_SMALL_TEXT, L"Enter your OTP code");
        }

        // Move to OTP step
        _currentStep = AuthStep::STEP_OTP;

        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_FALSE; // Not finished yet
    }
    else if (response.success)
    {
        // Authentication succeeded without OTP (passthrough case)
        return _PackCredentialsAndReturn(username, password, pcpgsr, pcpcs, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);
    }
    else
    {
        // Authentication failed
        SHStrDupW(response.message.c_str(), ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return E_FAIL;
    }
}

HRESULT CAuthentikCredential::_HandleOTPStep(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    LPWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    LOG("_HandleOTPStep");

    // Get OTP value
    std::wstring otp = _rgFieldStrings[FID_OTP] ? _rgFieldStrings[FID_OTP] : L"";
    std::wstring username = _rgFieldStrings[FID_USERNAME] ? _rgFieldStrings[FID_USERNAME] : L"";

    if (otp.empty())
    {
        SHStrDupW(L"Please enter your OTP code", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return E_FAIL;
    }

    // Validate OTP with Authentik
    AuthentikResponse response = _pAuthentikAPI->ValidateOTP(username, otp, _transactionId);

    if (response.success)
    {
        // OTP validated successfully - pack credentials
        return _PackCredentialsAndReturn(
            username, 
            _cachedPassword, 
            pcpgsr, 
            pcpcs, 
            ppwszOptionalStatusText, 
            pcpsiOptionalStatusIcon);
    }
    else
    {
        // OTP validation failed
        SHStrDupW(response.message.c_str(), ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        
        // Clear OTP field
        if (_rgFieldStrings[FID_OTP])
        {
            CoTaskMemFree(_rgFieldStrings[FID_OTP]);
            _rgFieldStrings[FID_OTP] = nullptr;
        }
        
        return E_FAIL;
    }
}

HRESULT CAuthentikCredential::_PackCredentialsAndReturn(
    const std::wstring& username,
    const std::wstring& password,
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    LPWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    LOG("_PackCredentialsAndReturn - UsageScenario: %d", _cpus);

    // Get domain name (you may want to make this configurable)
    std::wstring domain = L"TEST";  // TODO: Get from registry or configuration

    // Pack credentials
    BYTE* pPackage = nullptr;
    DWORD cbPackage = 0;
    HRESULT hr;

    // Use different packing based on usage scenario
    if (_cpus == CPUS_UNLOCK_WORKSTATION)
    {
        LOG("Using UNLOCK_LOGON for workstation unlock");
        hr = PackKerbInteractiveUnlockLogon(
            username,
            password,
            domain,
            &pPackage,
            &cbPackage);
    }
    else
    {
        LOG("Using INTERACTIVE_LOGON for logon");
        hr = PackKerbInteractiveLogon(
            username,
            password,
            domain,
            &pPackage,
            &cbPackage);
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

        LOG("Credentials packed successfully");
    }
    else
    {
        LOG("Failed to pack credentials: 0x%08x", hr);
        SHStrDupW(L"Failed to prepare credentials", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    }

    // Clean up cached password
    SecureZeroMemory(&_cachedPassword[0], _cachedPassword.length() * sizeof(wchar_t));
    _cachedPassword.clear();

    return hr;
}
