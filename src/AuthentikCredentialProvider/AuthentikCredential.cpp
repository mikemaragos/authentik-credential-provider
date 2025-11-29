// AuthentikCredential.cpp
// Individual credential tile implementation for passwordless authentication

#include "AuthentikCredential.h"
#include "Logger.h"
#include "CertificateHelper.h"
#include "AuthentikAPI.h"
#include <shlwapi.h>
#include <new>

#pragma comment(lib, "Shlwapi.lib")

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
    _pCertHelper(NULL)
{
    DllAddRef();
    LOG("CAuthentikCredential::Constructor");

    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
    ZeroMemory(&_rgFieldStatePairs, sizeof(_rgFieldStatePairs));

    // Initialize API client
    _pAuthentikAPI = new(std::nothrow) AuthentikAPI();
    
    // Initialize certificate helper
    CertificateHelper_CreateInstance(&_pCertHelper);
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
    const FIELD_STATE_PAIR* rgfsp)
{
    UNREFERENCED_PARAMETER(rgfsp);
    
    LOG("CAuthentikCredential::Initialize cpus=%d", cpus);

    _cpus = cpus;

    // Copy field descriptors and initial state
    for (DWORD i = 0; i < FID_NUM_FIELDS; i++)
    {
        _rgFieldStatePairs[i] = s_rgFieldStatePairsUnlock[i];

        // Copy field strings
        if (rgcpfd[i].pszLabel)
        {
            SHStrDupW(rgcpfd[i].pszLabel, &_rgFieldStrings[i]);
        }
    }

    // Set default text
    SHStrDupW(L"Authentik Passwordless", &_rgFieldStrings[FID_LARGE_TEXT]);
    SHStrDupW(L"Sign in with OTP", &_rgFieldStrings[FID_SMALL_TEXT]);

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
        if (_rgFieldStrings[dwFieldID])
        {
            hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
        }
        else
        {
            *ppwsz = NULL;
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
        *phbmp = NULL;
        return S_OK;
    }
    return E_INVALIDARG;
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
        }

        hr = SHStrDupW(pwz ? pwz : L"", &_rgFieldStrings[dwFieldID]);
        
        LOG("SetStringValue: field=%d", dwFieldID);
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
        SHStrDupW(L"Please enter a username", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_FALSE;
    }

    // Submit username to Authentik
    AuthentikResponse response = _pAuthentikAPI->SubmitUsername(username);

    if (response.status == AuthStatus::NEED_OTP)
    {
        // Transition to OTP step
        _rgFieldStatePairs[FID_USERNAME].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        _rgFieldStatePairs[FID_USERNAME].cpfis = CPFIS_NONE;
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
            _pCredentialEvents->SetFieldState(this, FID_USERNAME, CPFS_DISPLAY_IN_SELECTED_TILE);
            _pCredentialEvents->SetFieldInteractiveState(this, FID_USERNAME, CPFIS_NONE);
            _pCredentialEvents->SetFieldState(this, FID_OTP, CPFS_DISPLAY_IN_SELECTED_TILE);
            _pCredentialEvents->SetFieldInteractiveState(this, FID_OTP, CPFIS_FOCUSED);
            _pCredentialEvents->SetFieldString(this, FID_SMALL_TEXT, L"Enter your OTP code");
        }

        _currentStep = AuthStep::STEP_OTP;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_FALSE;
    }
    else if (response.status == AuthStatus::FAILED || 
             response.status == AuthStatus::ERROR_NETWORK ||
             response.status == AuthStatus::ERROR_SERVER)
    {
        SHStrDupW(response.message.c_str(), ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return E_FAIL;
    }

    // Unexpected response
    SHStrDupW(L"Unexpected response from server", ppwszOptionalStatusText);
    *pcpsiOptionalStatusIcon = CPSI_ERROR;
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    return E_FAIL;
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
        SHStrDupW(L"Please enter your OTP code", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_FALSE;
    }

    // Submit OTP to Authentik
    AuthentikResponse response = _pAuthentikAPI->SubmitOTP(otp);

    if (response.status == AuthStatus::SUCCESS)
    {
        // Check if we have certificate data
        if (!response.certificatePem.empty() && !response.privateKeyPem.empty())
        {
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
            // No certificate - this shouldn't happen in passwordless flow
            LOG("SUCCESS but no certificate data!");
            SHStrDupW(L"Authentication succeeded but no certificate received", ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            return E_FAIL;
        }
    }
    else if (response.status == AuthStatus::FAILED)
    {
        // OTP validation failed - let user retry
        SHStrDupW(response.message.c_str(), ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        
        // Clear OTP field
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
        // Network or server error
        SHStrDupW(response.message.c_str(), ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return E_FAIL;
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
    pcpcs->ulAuthenticationPackage = 0; // Will be set by provider

    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
    *pcpsiOptionalStatusIcon = CPSI_SUCCESS;

    LOG("Certificate credential packed successfully: %d bytes", cbPackage);

    return S_OK;
}
