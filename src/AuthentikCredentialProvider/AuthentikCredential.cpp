// AuthentikCredential.cpp
// Individual credential tile implementation for passwordless authentication

#include "AuthentikCredential.h"
#include "Logger.h"
#include "CertificateHelper.h"
#include "AuthentikAPI.h"
#include "resource.h"
#include <shlwapi.h>
#include <new>

#pragma comment(lib, "Shlwapi.lib")

// External DLL instance
extern HINSTANCE g_hinst;

// Field state pairs for different usage scenarios
static const FIELD_STATE_PAIR s_rgFieldStatePairsUnlock[] =
{
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_LOGO
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_LARGE_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_SMALL_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },  // FID_USERNAME
    { CPFS_HIDDEN, CPFIS_NONE },                       // FID_OTP
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_SUBMIT
};

// Constructor
CAuthentikCredential::CAuthentikCredential() :
    _cRef(1),
    _cpus(CPUS_INVALID),
    _pCredentialEvents(NULL),
    _currentStep(AuthStep::STEP_USERNAME),
    _pAuthentikAPI(NULL),
    _pCertHelper(NULL),
    _hTileIcon(NULL)
{
    DllAddRef();
    LOG("CAuthentikCredential::Constructor");

    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
    ZeroMemory(&_rgFieldStatePairs, sizeof(_rgFieldStatePairs));

    // Initialize API client
    _pAuthentikAPI = new(std::nothrow) AuthentikAPI();
    
    // Initialize certificate helper
    CertificateHelper_CreateInstance(&_pCertHelper);
    
    // Load tile icon from DLL resources
    _LoadTileIcon();
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
            _rgFieldStrings[i] = NULL;
        }
    }

    // Clean up certificate bundle
    _certBundle.Cleanup();

    if (_pAuthentikAPI)
    {
        delete _pAuthentikAPI;
        _pAuthentikAPI = NULL;
    }

    if (_pCertHelper)
    {
        delete _pCertHelper;
        _pCertHelper = NULL;
    }
    
    // Note: Don't delete _hTileIcon - it's owned by the system after GetBitmapValue returns it

    DllRelease();
}

// Load tile icon from resources
void CAuthentikCredential::_LoadTileIcon()
{
    LOG("Loading tile icon from resources");
    
    // Load icon from DLL resource
    HICON hIcon = (HICON)LoadImageW(
        g_hinst,
        MAKEINTRESOURCEW(IDI_AUTHENTIK_ICON),
        IMAGE_ICON,
        0, 0,  // Use actual size
        LR_DEFAULTCOLOR | LR_SHARED);
    
    if (hIcon)
    {
        LOG("Icon loaded successfully");
        
        // Convert icon to bitmap for credential provider
        ICONINFO iconInfo = {0};
        if (GetIconInfo(hIcon, &iconInfo))
        {
            // Use the color bitmap
            _hTileIcon = iconInfo.hbmColor;
            
            // Clean up the mask bitmap
            if (iconInfo.hbmMask)
            {
                DeleteObject(iconInfo.hbmMask);
            }
            
            LOG("Icon converted to bitmap");
        }
        else
        {
            LOG("Failed to get icon info: %d", GetLastError());
        }
        
        // Don't destroy the icon if loaded with LR_SHARED
    }
    else
    {
        LOG("Failed to load icon: %d", GetLastError());
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
    const FIELD_STATE_PAIR* rgfsp)
{
    UNREFERENCED_PARAMETER(rgcpfd);
    UNREFERENCED_PARAMETER(rgfsp);
    
    LOG("CAuthentikCredential::Initialize cpus=%d", cpus);

    _cpus = cpus;

    // Copy field state pairs
    for (DWORD i = 0; i < FID_NUM_FIELDS; i++)
    {
        _rgFieldStatePairs[i] = s_rgFieldStatePairsUnlock[i];
    }

    // Initialize field strings - NULL means use the label as placeholder
    for (DWORD i = 0; i < FID_NUM_FIELDS; i++)
    {
        _rgFieldStrings[i] = NULL;
    }

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
    if (_pCredentialEvents)
    {
        _pCredentialEvents->AddRef();
    }
    
    return S_OK;
}

HRESULT CAuthentikCredential::UnAdvise()
{
    LOG("CAuthentikCredential::UnAdvise");
    
    if (_pCredentialEvents)
    {
        _pCredentialEvents->Release();
        _pCredentialEvents = NULL;
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
    _currentStep = AuthStep::STEP_USERNAME;
    
    // Clear field values
    for (int i = 0; i < FID_NUM_FIELDS; i++)
    {
        if (_rgFieldStrings[i])
        {
            CoTaskMemFree(_rgFieldStrings[i]);
            _rgFieldStrings[i] = NULL;
        }
    }
    
    // Reset field states
    for (DWORD i = 0; i < FID_NUM_FIELDS; i++)
    {
        _rgFieldStatePairs[i] = s_rgFieldStatePairsUnlock[i];
    }
    
    // Reset API session
    if (_pAuthentikAPI)
    {
        _pAuthentikAPI->ResetSession();
    }
    
    // Clean up certificate bundle
    _certBundle.Cleanup();
    
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
        // Return the current value (may be NULL for empty/placeholder state)
        if (_rgFieldStrings[dwFieldID])
        {
            hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
        }
        else
        {
            // Return empty string - Windows will show the placeholder from pszLabel
            hr = SHStrDupW(L"", ppwsz);
        }
    }

    return hr;
}

HRESULT CAuthentikCredential::GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp)
{
    HRESULT hr = E_INVALIDARG;
    
    if (dwFieldID == FID_LOGO && phbmp)
    {
        if (_hTileIcon)
        {
            // Return a copy of the bitmap
            // The credential provider system will take ownership
            *phbmp = (HBITMAP)CopyImage(_hTileIcon, IMAGE_BITMAP, 0, 0, LR_CREATEDIBSECTION);
            if (*phbmp)
            {
                LOG("Returning tile icon bitmap");
                hr = S_OK;
            }
            else
            {
                LOG("Failed to copy bitmap: %d", GetLastError());
                *phbmp = NULL;
                hr = E_FAIL;
            }
        }
        else
        {
            LOG("No tile icon loaded, returning NULL");
            *phbmp = NULL;
            hr = S_OK; // NULL is acceptable - will use default icon
        }
    }
    
    return hr;
}

HRESULT CAuthentikCredential::GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, LPWSTR* ppwszLabel)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pbChecked);
    UNREFERENCED_PARAMETER(ppwszLabel);
    return E_NOTIMPL;
}

HRESULT CAuthentikCredential::GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pcItems);
    UNREFERENCED_PARAMETER(pdwSelectedItem);
    return E_NOTIMPL;
}

HRESULT CAuthentikCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, LPWSTR* ppwszItem)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(dwItem);
    UNREFERENCED_PARAMETER(ppwszItem);
    return E_NOTIMPL;
}

HRESULT CAuthentikCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo)
{
    if (dwFieldID == FID_SUBMIT)
    {
        // Submit button is adjacent to username or OTP field depending on step
        if (_currentStep == AuthStep::STEP_USERNAME)
        {
            *pdwAdjacentTo = FID_USERNAME;
        }
        else
        {
            *pdwAdjacentTo = FID_OTP;
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
            _rgFieldStrings[dwFieldID] = NULL;
        }

        if (pwz && pwz[0] != L'\0')
        {
            hr = SHStrDupW(pwz, &_rgFieldStrings[dwFieldID]);
        }
        else
        {
            // Empty or null - leave as NULL (shows placeholder)
            hr = S_OK;
        }
        
        LOG("SetStringValue: field=%d, hasValue=%d", dwFieldID, (_rgFieldStrings[dwFieldID] != NULL));
    }

    return hr;
}

HRESULT CAuthentikCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(bChecked);
    return E_NOTIMPL;
}

HRESULT CAuthentikCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(dwSelectedItem);
    return E_NOTIMPL;
}

HRESULT CAuthentikCredential::CommandLinkClicked(DWORD dwFieldID)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    return E_NOTIMPL;
}

HRESULT CAuthentikCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    LPWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    LOG("CAuthentikCredential::GetSerialization - Step: %d", (int)_currentStep);

    // Check configuration first
    if (_pAuthentikAPI && !_pAuthentikAPI->IsConfigurationValid())
    {
        LOG("Configuration error: %S", _pAuthentikAPI->GetConfigurationError().c_str());
        SHStrDupW(_pAuthentikAPI->GetConfigurationError().c_str(), ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_FALSE;
    }

    HRESULT hr = E_FAIL;

    switch (_currentStep)
    {
    case AuthStep::STEP_USERNAME:
        hr = _HandleUsernameStep(pcpgsr, pcpcs, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);
        break;
        
    case AuthStep::STEP_OTP:
        hr = _HandleOTPStep(pcpgsr, pcpcs, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);
        break;
        
    default:
        LOG("Unknown step");
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        break;
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
    
    *ppwszOptionalStatusText = NULL;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    // Reset on failure
    if (ntsStatus != 0)
    {
        _currentStep = AuthStep::STEP_USERNAME;
        if (_pAuthentikAPI)
        {
            _pAuthentikAPI->ResetSession();
        }
    }

    return S_OK;
}

// Private helper methods
HRESULT CAuthentikCredential::_HandleUsernameStep(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    LPWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    LOG("_HandleUsernameStep");

    UNREFERENCED_PARAMETER(pcpcs);

    // Get username
    std::wstring username = _rgFieldStrings[FID_USERNAME] ? _rgFieldStrings[FID_USERNAME] : L"";

    if (username.empty())
    {
        LOG("Username is empty");
        SHStrDupW(L"Please enter your username", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_FALSE;
    }

    LOG("Submitting username: %S", username.c_str());

    // Submit username to Authentik
    AuthentikResponse response = _pAuthentikAPI->SubmitUsername(username);

    LOG("Response status: %d, message: %S", (int)response.status, response.message.c_str());

    if (response.status == AuthStatus::NEED_OTP || 
        response.status == AuthStatus::SUCCESS)
    {
        LOG("Transitioning to OTP step");
        
        // Keep username visible but not editable, show OTP field
        _rgFieldStatePairs[FID_USERNAME].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        _rgFieldStatePairs[FID_USERNAME].cpfis = CPFIS_NONE;
        _rgFieldStatePairs[FID_OTP].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        _rgFieldStatePairs[FID_OTP].cpfis = CPFIS_FOCUSED;

        // Notify UI of field changes
        if (_pCredentialEvents)
        {
            _pCredentialEvents->SetFieldInteractiveState(this, FID_USERNAME, CPFIS_NONE);
            _pCredentialEvents->SetFieldState(this, FID_OTP, CPFS_DISPLAY_IN_SELECTED_TILE);
            _pCredentialEvents->SetFieldInteractiveState(this, FID_OTP, CPFIS_FOCUSED);
            _pCredentialEvents->SetFieldString(this, FID_SMALL_TEXT, L"Enter your verification code");
        }

        _currentStep = AuthStep::STEP_OTP;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        LOG("Now waiting for OTP");
        return S_FALSE;
    }
    else if (response.status == AuthStatus::ERROR_NETWORK)
    {
        LOG("Network error");
        SHStrDupW(L"Cannot connect to authentication server. Check network.", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_FALSE;
    }
    else if (response.status == AuthStatus::ERROR_SERVER)
    {
        LOG("Server error");
        std::wstring msg = L"Server error: " + response.message;
        SHStrDupW(msg.c_str(), ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_FALSE;
    }
    else if (response.status == AuthStatus::ERROR_CONFIG)
    {
        LOG("Configuration error");
        SHStrDupW(response.message.c_str(), ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_FALSE;
    }
    else
    {
        LOG("Authentication failed: %S", response.message.c_str());
        SHStrDupW(response.message.c_str(), ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_FALSE;
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

    if (otp.empty())
    {
        LOG("OTP is empty");
        SHStrDupW(L"Please enter your verification code", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_FALSE;
    }

    LOG("Submitting OTP");

    // Submit OTP to Authentik
    AuthentikResponse response = _pAuthentikAPI->SubmitOTP(otp);

    LOG("OTP response status: %d", (int)response.status);

    if (response.status == AuthStatus::SUCCESS)
    {
        // Check if we have certificate data
        if (!response.certificatePem.empty() && !response.privateKeyPem.empty())
        {
            LOG("Received certificate, building credential");
            
            // Convert wide strings to narrow for certificate bundle
            int certSize = WideCharToMultiByte(CP_UTF8, 0, response.certificatePem.c_str(), -1, NULL, 0, NULL, NULL);
            int keySize = WideCharToMultiByte(CP_UTF8, 0, response.privateKeyPem.c_str(), -1, NULL, 0, NULL, NULL);
            
            if (certSize > 0 && keySize > 0)
            {
                _certBundle.certificate.resize(certSize - 1);
                _certBundle.privateKey.resize(keySize - 1);
                
                WideCharToMultiByte(CP_UTF8, 0, response.certificatePem.c_str(), -1, 
                    &_certBundle.certificate[0], certSize, NULL, NULL);
                WideCharToMultiByte(CP_UTF8, 0, response.privateKeyPem.c_str(), -1,
                    &_certBundle.privateKey[0], keySize, NULL, NULL);
            }
            
            _certBundle.username = response.username;
            _certBundle.domain = response.domain;
            _certBundle.upn = response.upn;
            _certBundle.validMinutes = response.certValidMinutes;

            // Build certificate credential
            return _PackCertificateCredential(pcpgsr, pcpcs, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);
        }
        else
        {
            // OTP validated but no certificate - for testing phase
            LOG("OTP validated but no certificate (testing mode)");
            SHStrDupW(L"OTP verified! Certificate issuance not yet configured.", ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_WARNING;
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            
            // Reset for next attempt
            _currentStep = AuthStep::STEP_USERNAME;
            if (_pAuthentikAPI)
            {
                _pAuthentikAPI->ResetSession();
            }
            
            return S_FALSE;
        }
    }
    else if (response.status == AuthStatus::FAILED)
    {
        LOG("OTP validation failed");
        SHStrDupW(L"Invalid code. Please try again.", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        
        // Clear OTP field for retry
        if (_rgFieldStrings[FID_OTP])
        {
            CoTaskMemFree(_rgFieldStrings[FID_OTP]);
            _rgFieldStrings[FID_OTP] = NULL;
        }
        if (_pCredentialEvents)
        {
            _pCredentialEvents->SetFieldString(this, FID_OTP, L"");
        }
        
        return S_FALSE;
    }
    else
    {
        LOG("OTP error: %S", response.message.c_str());
        SHStrDupW(response.message.c_str(), ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_FALSE;
    }
}

HRESULT CAuthentikCredential::_PackCertificateCredential(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    LPWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    LOG("_PackCertificateCredential");

    HRESULT hr;

    // Parse and import the certificate
    hr = _pCertHelper->ImportCertificateForPKINIT(_certBundle);
    if (FAILED(hr))
    {
        LOG("Failed to import certificate: 0x%08x", hr);
        SHStrDupW(L"Failed to process certificate", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return hr;
    }

    // Build the credential package
    BYTE* pPackage = NULL;
    DWORD cbPackage = 0;

    hr = _pCertHelper->BuildCertificateLogon(_certBundle, &pPackage, &cbPackage);
    if (FAILED(hr))
    {
        LOG("Failed to build certificate logon: 0x%08x", hr);
        SHStrDupW(L"Failed to prepare credentials", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return hr;
    }

    // Fill serialization structure
    pcpcs->clsidCredentialProvider = CLSID_AuthentikCredentialProvider;
    pcpcs->rgbSerialization = pPackage;
    pcpcs->cbSerialization = cbPackage;
    
    // Use Kerberos package for PKINIT
    pcpcs->ulAuthenticationPackage = 0;

    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
    *pcpsiOptionalStatusIcon = CPSI_SUCCESS;

    LOG("Certificate credential packed successfully: %d bytes", cbPackage);

    return S_OK;
}
