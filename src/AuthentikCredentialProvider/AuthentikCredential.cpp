// AuthentikCredential.cpp
// Individual credential tile implementation - Passwordless version with certificate auth

#include "AuthentikCredential.h"
#include "AuthentikAPI.h"
#include "CertificateHelper.h"
#include "Logger.h"
#include "guid.h"
#include <wincred.h>
#include <ntsecapi.h>
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

// Field state pairs for username step (initial)
static const FIELD_STATE_PAIR s_rgFieldStatePairsUsername[] =
{
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_LOGO
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_LARGE_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_SMALL_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },  // FID_USERNAME
    { CPFS_HIDDEN, CPFIS_NONE },                       // FID_OTP - hidden
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_SUBMIT
};

// Field state pairs for OTP step
static const FIELD_STATE_PAIR s_rgFieldStatePairsOTP[] =
{
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_LOGO
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_LARGE_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_SMALL_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_DISABLED }, // FID_USERNAME - shown but disabled
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },  // FID_OTP - shown and focused
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_SUBMIT
};

// Constructor
CAuthentikCredential::CAuthentikCredential() :
    _cRef(1),
    _cpus(CPUS_INVALID),
    _ulAuthPackage(0),
    _pCredentialEvents(nullptr),
    _currentStep(AuthStep::STEP_USERNAME),
    _pAuthentikAPI(nullptr),
    _pCertHelper(nullptr)
{
    DllAddRef();
    LOG("CAuthentikCredential::Constructor");

    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
    ZeroMemory(&_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
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
            // Secure clear OTP field
            if (i == FID_OTP)
            {
                SecureZeroMemory(_rgFieldStrings[i], 
                    wcslen(_rgFieldStrings[i]) * sizeof(wchar_t));
            }
            CoTaskMemFree(_rgFieldStrings[i]);
            _rgFieldStrings[i] = nullptr;
        }
    }

    // Clean up certificate bundle
    if (_pCertHelper)
    {
        _pCertHelper->CleanupCertificate(_certBundle);
        delete _pCertHelper;
        _pCertHelper = nullptr;
    }

    // Clean up API client
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

// Initialize credential
HRESULT CAuthentikCredential::Initialize(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
    const FIELD_STATE_PAIR* rgfsp,
    ULONG ulAuthPackage)
{
    LOG("CAuthentikCredential::Initialize - cpus=%d", cpus);

    _cpus = cpus;
    _ulAuthPackage = ulAuthPackage;

    // Copy field descriptors and initial state
    for (DWORD i = 0; i < FID_NUM_FIELDS; i++)
    {
        _rgFieldStatePairs[i] = s_rgFieldStatePairsUsername[i];

        // Copy field strings
        if (rgcpfd[i].pszLabel)
        {
            SHStrDupW(rgcpfd[i].pszLabel, &_rgFieldStrings[i]);
        }
    }

    // Set default text
    SHStrDupW(L"Authentik Passwordless", &_rgFieldStrings[FID_LARGE_TEXT]);
    SHStrDupW(L"Enter your username to begin", &_rgFieldStrings[FID_SMALL_TEXT]);

    // Initialize API client
    HRESULT hr = AuthentikAPI_CreateInstance(&_pAuthentikAPI);
    if (FAILED(hr))
    {
        LOG_E("Failed to create AuthentikAPI: 0x%08x", hr);
        return hr;
    }

    // Initialize certificate helper
    hr = CertificateHelper_CreateInstance(&_pCertHelper);
    if (FAILED(hr))
    {
        LOG_E("Failed to create CertificateHelper: 0x%08x", hr);
        return hr;
    }

    LOG("CAuthentikCredential initialized successfully");
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
    _ResetToUsernameStep();
    
    return S_OK;
}

HRESULT CAuthentikCredential::GetFieldState(
    DWORD dwFieldID,
    CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    if (dwFieldID < FID_NUM_FIELDS)
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

    if (dwFieldID < FID_NUM_FIELDS && ppwsz)
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
        // TODO: Load custom logo bitmap
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
        // Submit button adjacent to current input field
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

    if (dwFieldID < FID_NUM_FIELDS)
    {
        if (_rgFieldStrings[dwFieldID])
        {
            // Secure clear OTP field before freeing
            if (dwFieldID == FID_OTP)
            {
                SecureZeroMemory(_rgFieldStrings[dwFieldID],
                    wcslen(_rgFieldStrings[dwFieldID]) * sizeof(wchar_t));
            }
            CoTaskMemFree(_rgFieldStrings[dwFieldID]);
        }

        hr = SHStrDupW(pwz ? pwz : L"", &_rgFieldStrings[dwFieldID]);
        
        // Don't log OTP values
        if (dwFieldID != FID_OTP)
        {
            LOG("SetStringValue: field=%d, value=%S", dwFieldID, pwz ? pwz : L"(null)");
        }
        else
        {
            LOG("SetStringValue: field=OTP, value=***");
        }
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

// Main serialization entry point
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
        LOG_E("Invalid authentication step: %d", (int)_currentStep);
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
    
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    // If login failed, reset to username step
    if (!NT_SUCCESS(ntsStatus))
    {
        LOG_W("Login failed, resetting to username step");
        _ResetToUsernameStep();
        
        SHStrDupW(L"Login failed. Please try again.", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
    }

    // Clean up certificate regardless of result
    if (_pCertHelper)
    {
        _pCertHelper->CleanupCertificate(_certBundle);
    }

    return S_OK;
}

// Handle username step
HRESULT CAuthentikCredential::_HandleUsernameStep(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    LPWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    LOG("_HandleUsernameStep");

    // Get username
    std::wstring username = _rgFieldStrings[FID_USERNAME] ? _rgFieldStrings[FID_USERNAME] : L"";

    if (username.empty())
    {
        SHStrDupW(L"Please enter your username", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_FALSE;
    }

    _currentUsername = username;

    // Call Authentik API to initiate authentication
    LOG("Initiating authentication for user: %S", username.c_str());
    AuthentikResponse response = _pAuthentikAPI->InitiateAuthentication(username);

    switch (response.type)
    {
    case AuthResponseType::NEED_OTP:
        // Transition to OTP step
        LOG("OTP required, transitioning to OTP step");
        _TransitionToOTPStep(response.otpPrompt);
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_FALSE;

    case AuthResponseType::SUCCESS_WITH_CERTIFICATE:
        // Unexpected - got certificate without OTP
        LOG_W("Got certificate without OTP - processing anyway");
        return _ProcessCertificateAndPack(response, pcpgsr, pcpcs, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);

    case AuthResponseType::ERROR:
    default:
        LOG_E("Authentication initiation failed: %S", response.message.c_str());
        SHStrDupW(response.message.c_str(), ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return E_FAIL;
    }
}

// Handle OTP step
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
        SHStrDupW(L"Please enter your verification code", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_FALSE;
    }

    // Submit OTP to Authentik
    LOG("Submitting OTP");
    AuthentikResponse response = _pAuthentikAPI->SubmitOTP(otp);

    // Secure clear OTP from field
    if (_rgFieldStrings[FID_OTP])
    {
        SecureZeroMemory(_rgFieldStrings[FID_OTP], 
            wcslen(_rgFieldStrings[FID_OTP]) * sizeof(wchar_t));
    }

    switch (response.type)
    {
    case AuthResponseType::SUCCESS_WITH_CERTIFICATE:
        LOG("OTP validated, certificate received");
        return _ProcessCertificateAndPack(response, pcpgsr, pcpcs, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);

    case AuthResponseType::SUCCESS_REDIRECT:
        // Success but no certificate - this is a problem for passwordless
        LOG_E("Authentication succeeded but no certificate returned");
        SHStrDupW(L"Server did not provide certificate for passwordless login", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return E_FAIL;

    case AuthResponseType::NEED_OTP:
        // Another OTP required (shouldn't happen normally)
        LOG_W("Additional OTP required");
        _ShowError(L"Additional verification required");
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_FALSE;

    case AuthResponseType::ERROR:
    default:
        LOG_E("OTP validation failed: %S", response.message.c_str());
        _ShowError(response.message);
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return E_FAIL;
    }
}

// Process certificate and pack credentials
HRESULT CAuthentikCredential::_ProcessCertificateAndPack(
    const AuthentikResponse& response,
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    LPWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    LOG("_ProcessCertificateAndPack");

    HRESULT hr;

    // Populate certificate bundle from response
    _certBundle.certificate.clear();
    _certBundle.privateKey.clear();
    
    // Convert wide strings to narrow for PEM data
    int certSize = WideCharToMultiByte(CP_UTF8, 0, response.certificatePem.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (certSize > 0)
    {
        _certBundle.certificate.resize(certSize - 1);
        WideCharToMultiByte(CP_UTF8, 0, response.certificatePem.c_str(), -1, &_certBundle.certificate[0], certSize, nullptr, nullptr);
    }

    int keySize = WideCharToMultiByte(CP_UTF8, 0, response.privateKeyPem.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (keySize > 0)
    {
        _certBundle.privateKey.resize(keySize - 1);
        WideCharToMultiByte(CP_UTF8, 0, response.privateKeyPem.c_str(), -1, &_certBundle.privateKey[0], keySize, nullptr, nullptr);
    }

    _certBundle.username = response.username.empty() ? _currentUsername : response.username;
    _certBundle.domain = response.domain.empty() ? _pAuthentikAPI->GetDomain() : response.domain;
    _certBundle.upn = response.upn;
    _certBundle.validMinutes = response.certValidMinutes;

    LOG("Certificate bundle prepared:");
    LOG("  Username: %S", _certBundle.username.c_str());
    LOG("  Domain: %S", _certBundle.domain.c_str());
    LOG("  UPN: %S", _certBundle.upn.c_str());

    // Parse and import certificate
    hr = _pCertHelper->ImportCertificateForPKINIT(_certBundle);
    if (FAILED(hr))
    {
        LOG_E("Failed to import certificate: 0x%08x", hr);
        SHStrDupW(L"Failed to process authentication certificate", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return hr;
    }

    // Build KERB_CERTIFICATE_LOGON structure
    BYTE* pPackage = nullptr;
    DWORD cbPackage = 0;

    hr = _pCertHelper->BuildCertificateLogon(_certBundle, &pPackage, &cbPackage);
    if (FAILED(hr))
    {
        LOG_E("Failed to build certificate logon: 0x%08x", hr);
        SHStrDupW(L"Failed to prepare credentials", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return hr;
    }

    // Fill serialization structure
    pcpcs->clsidCredentialProvider = CLSID_AuthentikPasswordlessCP;
    pcpcs->rgbSerialization = pPackage;
    pcpcs->cbSerialization = cbPackage;
    pcpcs->ulAuthenticationPackage = _ulAuthPackage;

    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
    *pcpsiOptionalStatusIcon = CPSI_SUCCESS;

    LOG("Certificate credentials packed successfully - %d bytes", cbPackage);

    return S_OK;
}

// Transition UI to OTP step
void CAuthentikCredential::_TransitionToOTPStep(const std::wstring& prompt)
{
    LOG("_TransitionToOTPStep: %S", prompt.c_str());

    _currentStep = AuthStep::STEP_OTP;

    // Update field states
    for (DWORD i = 0; i < FID_NUM_FIELDS; i++)
    {
        _rgFieldStatePairs[i] = s_rgFieldStatePairsOTP[i];
    }

    // Update status text
    if (_rgFieldStrings[FID_SMALL_TEXT])
    {
        CoTaskMemFree(_rgFieldStrings[FID_SMALL_TEXT]);
    }
    SHStrDupW(prompt.empty() ? L"Enter your verification code" : prompt.c_str(), 
              &_rgFieldStrings[FID_SMALL_TEXT]);

    // Clear OTP field
    if (_rgFieldStrings[FID_OTP])
    {
        SecureZeroMemory(_rgFieldStrings[FID_OTP], 
            wcslen(_rgFieldStrings[FID_OTP]) * sizeof(wchar_t));
        CoTaskMemFree(_rgFieldStrings[FID_OTP]);
        _rgFieldStrings[FID_OTP] = nullptr;
    }

    // Notify UI of field changes
    if (_pCredentialEvents)
    {
        _pCredentialEvents->SetFieldState(this, FID_USERNAME, CPFS_DISPLAY_IN_SELECTED_TILE);
        _pCredentialEvents->SetFieldInteractiveState(this, FID_USERNAME, CPFIS_DISABLED);
        _pCredentialEvents->SetFieldState(this, FID_OTP, CPFS_DISPLAY_IN_SELECTED_TILE);
        _pCredentialEvents->SetFieldInteractiveState(this, FID_OTP, CPFIS_FOCUSED);
        _pCredentialEvents->SetFieldString(this, FID_SMALL_TEXT, 
            prompt.empty() ? L"Enter your verification code" : prompt.c_str());
    }
}

// Show error message
void CAuthentikCredential::_ShowError(const std::wstring& message)
{
    LOG("_ShowError: %S", message.c_str());

    if (_rgFieldStrings[FID_SMALL_TEXT])
    {
        CoTaskMemFree(_rgFieldStrings[FID_SMALL_TEXT]);
    }
    SHStrDupW(message.c_str(), &_rgFieldStrings[FID_SMALL_TEXT]);

    if (_pCredentialEvents)
    {
        _pCredentialEvents->SetFieldString(this, FID_SMALL_TEXT, message.c_str());
    }
}

// Reset to username step
void CAuthentikCredential::_ResetToUsernameStep()
{
    LOG("_ResetToUsernameStep");

    _currentStep = AuthStep::STEP_USERNAME;
    _currentUsername.clear();

    // Reset field states
    for (DWORD i = 0; i < FID_NUM_FIELDS; i++)
    {
        _rgFieldStatePairs[i] = s_rgFieldStatePairsUsername[i];
    }

    // Update status text
    if (_rgFieldStrings[FID_SMALL_TEXT])
    {
        CoTaskMemFree(_rgFieldStrings[FID_SMALL_TEXT]);
    }
    SHStrDupW(L"Enter your username to begin", &_rgFieldStrings[FID_SMALL_TEXT]);

    // Clear sensitive fields
    if (_rgFieldStrings[FID_OTP])
    {
        SecureZeroMemory(_rgFieldStrings[FID_OTP],
            wcslen(_rgFieldStrings[FID_OTP]) * sizeof(wchar_t));
        CoTaskMemFree(_rgFieldStrings[FID_OTP]);
        _rgFieldStrings[FID_OTP] = nullptr;
    }

    // Reset API flow
    if (_pAuthentikAPI)
    {
        _pAuthentikAPI->ResetFlow();
    }

    // Clean up certificate
    if (_pCertHelper)
    {
        _pCertHelper->CleanupCertificate(_certBundle);
    }

    // Notify UI
    if (_pCredentialEvents)
    {
        _pCredentialEvents->SetFieldState(this, FID_USERNAME, CPFS_DISPLAY_IN_SELECTED_TILE);
        _pCredentialEvents->SetFieldInteractiveState(this, FID_USERNAME, CPFIS_FOCUSED);
        _pCredentialEvents->SetFieldState(this, FID_OTP, CPFS_HIDDEN);
        _pCredentialEvents->SetFieldString(this, FID_SMALL_TEXT, L"Enter your username to begin");
    }
}

// Factory function
HRESULT CAuthentikCredential_CreateInstance(REFIID riid, void** ppv)
{
    LOG("CAuthentikCredential_CreateInstance");

    HRESULT hr;
    CAuthentikCredential* pCredential = new (std::nothrow) CAuthentikCredential();

    if (pCredential)
    {
        hr = pCredential->QueryInterface(riid, ppv);
        pCredential->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}
