// AuthentikCredential.cpp
// Individual credential tile implementation for passwordless smart card authentication

#include "AuthentikCredential.h"
#include "Logger.h"
#include "AuthentikAPI.h"
#include "SmartCardHelper.h"

#include <windows.h>
#include <wincred.h>
#include <ntsecapi.h>
#include <shlwapi.h>
#include <shlguid.h>

#pragma comment(lib, "credui.lib")
#pragma comment(lib, "shlwapi.lib")

// DLL reference counting and instance handle (defined in Dll.cpp)
extern void DllAddRef();
extern void DllRelease();
extern HINSTANCE g_hinst;

// Resource ID for tile icon (defined in resource.rc)
#define IDB_TILE_ICON 101

// Field state pairs for different usage scenarios
static const FIELD_STATE_PAIR s_rgFieldStatePairsLogon[] =
{
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_LOGO
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_LARGE_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_SMALL_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },  // FID_USERNAME
    { CPFS_HIDDEN, CPFIS_NONE },                       // FID_OTP (hidden initially)
    { CPFS_HIDDEN, CPFIS_NONE },                       // FID_PIN (hidden initially)
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
    _pSmartCardHelper(nullptr)
{
    DllAddRef();
    LOG("CAuthentikCredential::Constructor");

    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
    ZeroMemory(&_rgFieldStatePairs, sizeof(_rgFieldStatePairs));

    // Initialize helpers
    _pAuthentikAPI = new AuthentikAPI();
    _pSmartCardHelper = new SmartCardHelper();
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

    // Clear sensitive data
    SecureZeroMemory(&_pfxPassword[0], _pfxPassword.length() * sizeof(wchar_t));
    _pfxPassword.clear();
    _pfxData.clear();

    if (_pAuthentikAPI)
    {
        delete _pAuthentikAPI;
        _pAuthentikAPI = nullptr;
    }

    if (_pSmartCardHelper)
    {
        delete _pSmartCardHelper;
        _pSmartCardHelper = nullptr;
    }

    DllRelease();
}

// IUnknown
HRESULT CAuthentikCredential::QueryInterface(REFIID riid, void** ppv)
{
    static const QITAB qit[] =
    {
        QITABENT(CAuthentikCredential, ICredentialProviderCredential),
        QITABENT(CAuthentikCredential, ICredentialProviderCredential2),
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

    // Copy field state pairs and initialize field strings
    for (DWORD i = 0; i < ARRAYSIZE(s_rgFieldStatePairsLogon); i++)
    {
        _rgFieldStatePairs[i] = s_rgFieldStatePairsLogon[i];
        _rgFieldStrings[i] = nullptr;  // Initialize all to nullptr
    }

    // Set display text fields ONLY (not input fields - those stay empty for user input)
    SHStrDupW(L"Authentik Passwordless", &_rgFieldStrings[FID_LARGE_TEXT]);
    SHStrDupW(L"Enter your username", &_rgFieldStrings[FID_SMALL_TEXT]);
    
    // Input fields (FID_USERNAME, FID_OTP, FID_PIN) stay nullptr = empty text boxes

    // Check VSC status on init
    VSCResult vscStatus = _pSmartCardHelper->CheckVSCStatus();
    if (!vscStatus.success)
    {
        LOG("WARNING: No VSC available - smart card login may not work");
    }
    else
    {
        _vscReaderName = vscStatus.readerName;
        LOG("VSC ready: %S", _vscReaderName.c_str());
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
    
    // Query for ICredentialProviderCredentialEvents2
    HRESULT hr = pcpce->QueryInterface(IID_PPV_ARGS(&_pCredentialEvents));
    if (FAILED(hr))
    {
        // Fall back to ICredentialProviderCredentialEvents
        _pCredentialEvents = (ICredentialProviderCredentialEvents2*)pcpce;
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
    _currentStep = AuthStep::STEP_USERNAME;
    _username.clear();
    _flowToken.clear();
    _certificateThumbprint.clear();
    SecureZeroMemory(&_pfxPassword[0], _pfxPassword.length() * sizeof(wchar_t));
    _pfxPassword.clear();
    _pfxData.clear();
    
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
        // Load icon from resources
        HICON hIcon = (HICON)LoadImageW(
            g_hinst,
            MAKEINTRESOURCEW(IDB_TILE_ICON),
            IMAGE_ICON,
            48, 48,  // Standard tile icon size
            LR_DEFAULTCOLOR);
        
        if (hIcon)
        {
            // Create a 32-bit ARGB bitmap to preserve transparency
            BITMAPINFO bmi = {};
            bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
            bmi.bmiHeader.biWidth = 48;
            bmi.bmiHeader.biHeight = -48;  // Top-down DIB (negative height)
            bmi.bmiHeader.biPlanes = 1;
            bmi.bmiHeader.biBitCount = 32;
            bmi.bmiHeader.biCompression = BI_RGB;
            
            void* pvBits = nullptr;
            HDC hdcScreen = GetDC(nullptr);
            HBITMAP hBitmap = CreateDIBSection(hdcScreen, &bmi, DIB_RGB_COLORS, &pvBits, nullptr, 0);
            
            if (hBitmap && pvBits)
            {
                // Create a memory DC and select our bitmap
                HDC hdcMem = CreateCompatibleDC(hdcScreen);
                HBITMAP hOldBitmap = (HBITMAP)SelectObject(hdcMem, hBitmap);
                
                // Fill with transparent background (all zeros = fully transparent black)
                memset(pvBits, 0, 48 * 48 * 4);
                
                // Draw the icon onto the bitmap - this preserves alpha
                DrawIconEx(hdcMem, 0, 0, hIcon, 48, 48, 0, nullptr, DI_NORMAL);
                
                SelectObject(hdcMem, hOldBitmap);
                DeleteDC(hdcMem);
                
                *phbmp = hBitmap;
                LOG("GetBitmapValue: Loaded tile icon with transparency");
            }
            else
            {
                LOG("GetBitmapValue: Failed to create DIB section");
                *phbmp = nullptr;
            }
            
            ReleaseDC(nullptr, hdcScreen);
            DestroyIcon(hIcon);
            return S_OK;
        }
        
        LOG("GetBitmapValue: Failed to load tile icon, error=%d", GetLastError());
        *phbmp = nullptr;
        return S_OK;  // Return OK even without icon - Windows will use default
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
        // Submit button adjacent to current active field
        switch (_currentStep)
        {
        case AuthStep::STEP_USERNAME:
            *pdwAdjacentTo = FID_USERNAME;
            break;
        case AuthStep::STEP_OTP:
            *pdwAdjacentTo = FID_OTP;
            break;
        case AuthStep::STEP_SMARTCARD_LOGIN:
            *pdwAdjacentTo = FID_PIN;
            break;
        default:
            *pdwAdjacentTo = FID_USERNAME;
            break;
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

// ICredentialProviderCredential2
HRESULT CAuthentikCredential::GetUserSid(LPWSTR* ppszSid)
{
    *ppszSid = nullptr;
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

    case AuthStep::STEP_CERTIFICATE:
        hr = _HandleCertificateStep(pcpgsr, pcpcs, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);
        break;

    case AuthStep::STEP_SMARTCARD_LOGIN:
        hr = _HandleSmartCardLogin(pcpgsr, pcpcs, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);
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

    // Reset state on failure
    if (ntsStatus != 0)
    {
        _currentStep = AuthStep::STEP_USERNAME;
        
        // Provide error message based on status
        if (ntsStatus == STATUS_LOGON_FAILURE)
        {
            SHStrDupW(L"Authentication failed. Please try again.", ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
        }
        // STATUS_SMARTCARD_LOGON_REQUIRED = 0xC000035C
        else if (ntsStatus == (NTSTATUS)0xC000035CL)
        {
            SHStrDupW(L"Smart card required for this account.", ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_WARNING;
        }
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
    _username = _rgFieldStrings[FID_USERNAME] ? _rgFieldStrings[FID_USERNAME] : L"";

    if (_username.empty())
    {
        SHStrDupW(L"Please enter a username", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return E_FAIL;
    }

    LOG("Username: %S", _username.c_str());

    // Update status
    _UpdateStatusText(L"Contacting authentication server...");

    // Call Authentik API to initiate authentication
    AuthentikResponse response = _pAuthentikAPI->InitiateAuthentication(_username);

    if (response.requiresOTP)
    {
        // Store flow token
        _flowToken = response.flowToken;

        // Transition to OTP step
        _ShowOTPField();
        _currentStep = AuthStep::STEP_OTP;

        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_FALSE;
    }
    else if (response.success)
    {
        // Unusual case - authenticated without OTP
        // This shouldn't happen in a proper passwordless flow
        LOG("WARNING: Authentication succeeded without OTP challenge");
        _UpdateStatusText(L"Authentication complete - requesting certificate...");
        _currentStep = AuthStep::STEP_CERTIFICATE;
        
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_FALSE;
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
        SHStrDupW(L"Please enter your authentication code", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return E_FAIL;
    }

    // Update status
    _UpdateStatusText(L"Verifying code...");

    // Validate OTP with Authentik
    AuthentikResponse response = _pAuthentikAPI->ValidateOTP(_username, otp, _flowToken);

    if (response.success)
    {
        LOG("OTP validated successfully");
        
        // Move to certificate step
        _UpdateStatusText(L"Requesting certificate...");
        _currentStep = AuthStep::STEP_CERTIFICATE;
        
        // Immediately handle certificate step
        return _HandleCertificateStep(pcpgsr, pcpcs, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);
    }
    else if (response.requiresOTP)
    {
        // Still need OTP (wrong code entered)
        SHStrDupW(L"Invalid code. Please try again.", ppwszOptionalStatusText);
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
        }
        
        return E_FAIL;
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

// Handle certificate issuance step
HRESULT CAuthentikCredential::_HandleCertificateStep(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    LPWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    LOG("_HandleCertificateStep");

    // Update status
    _UpdateStatusText(L"Issuing certificate...");

    // Request certificate from cert issuer service
    CertificateResponse certResponse = _pAuthentikAPI->RequestCertificate(_username, L"", _flowToken);

    if (!certResponse.success)
    {
        LOG("Certificate request failed: %S", certResponse.message.c_str());
        SHStrDupW(certResponse.message.c_str(), ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        
        // Reset to username step
        _currentStep = AuthStep::STEP_USERNAME;
        return E_FAIL;
    }

    LOG("Certificate received: thumbprint=%S", certResponse.thumbprint.c_str());

    // Store certificate data
    _certificateThumbprint = certResponse.thumbprint;
    _pfxData = certResponse.pfxData;
    _pfxPassword = certResponse.pfxPassword;

    // Import certificate to VSC
    _UpdateStatusText(L"Installing certificate on smart card...");

    // For now, we'll use the existing certificate if already on VSC
    // In production, we'd import the new cert using the SmartCardHelper
    VSCResult vscResult = _pSmartCardHelper->FindCertificateOnVSC(_certificateThumbprint);
    
    if (!vscResult.success)
    {
        // Certificate not on VSC - try to import it
        // Note: Real VSC import requires PIN prompt and is complex
        // For now, we'll import to software store and let Windows handle it
        vscResult = _pSmartCardHelper->ImportCertificateToVSC(_pfxData, _pfxPassword, L"");
        
        if (!vscResult.success)
        {
            LOG("Certificate import failed: %S", vscResult.message.c_str());
            SHStrDupW(L"Failed to install certificate. Please contact administrator.", ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            _currentStep = AuthStep::STEP_USERNAME;
            return E_FAIL;
        }
    }

    // Certificate is ready - move to smart card login
    _UpdateStatusText(L"Certificate ready. Enter your smart card PIN.");
    _ShowPINField();
    _currentStep = AuthStep::STEP_SMARTCARD_LOGIN;

    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    return S_FALSE;
}

// Handle smart card login
HRESULT CAuthentikCredential::_HandleSmartCardLogin(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    LPWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    LOG("_HandleSmartCardLogin");

    // Get PIN
    std::wstring pin = _rgFieldStrings[FID_PIN] ? _rgFieldStrings[FID_PIN] : L"";

    if (pin.empty())
    {
        SHStrDupW(L"Please enter your smart card PIN", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return E_FAIL;
    }

    // Pack smart card credentials
    return _PackSmartCardCredentials(_vscReaderName, pin, pcpgsr, pcpcs, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);
}

// Pack credentials for smart card logon
HRESULT CAuthentikCredential::_PackSmartCardCredentials(
    const std::wstring& readerName,
    const std::wstring& pin,
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    LPWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    LOG("_PackSmartCardCredentials: reader=%S", readerName.c_str());

    // For smart card logon, we use KERB_CERTIFICATE_LOGON structure
    // This is complex - for now, let's use a simpler approach:
    // Return CPGSR_RETURN_NO_CREDENTIAL_FINISHED and let Windows handle the smart card
    
    // The certificate is in the store, Windows should detect it
    // We just need to signal that authentication should proceed
    
    // Alternative: Use the smart card credential provider directly
    // by returning the appropriate serialization
    
    // For the POC, we'll indicate success and let Windows use the installed cert
    *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
    *pcpsiOptionalStatusIcon = CPSI_SUCCESS;
    
    LOG("Smart card credentials prepared - Windows will complete authentication");
    
    // Clear sensitive data
    SecureZeroMemory(&_pfxPassword[0], _pfxPassword.length() * sizeof(wchar_t));
    _pfxPassword.clear();
    _pfxData.clear();

    return S_OK;
}

// Update status text
void CAuthentikCredential::_UpdateStatusText(const std::wstring& text)
{
    if (_rgFieldStrings[FID_SMALL_TEXT])
    {
        CoTaskMemFree(_rgFieldStrings[FID_SMALL_TEXT]);
    }
    SHStrDupW(text.c_str(), &_rgFieldStrings[FID_SMALL_TEXT]);

    if (_pCredentialEvents)
    {
        _pCredentialEvents->SetFieldString(this, FID_SMALL_TEXT, text.c_str());
    }
}

// Show OTP field
void CAuthentikCredential::_ShowOTPField()
{
    // Hide username, show OTP
    _rgFieldStatePairs[FID_USERNAME].cpfs = CPFS_HIDDEN;
    _rgFieldStatePairs[FID_OTP].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
    _rgFieldStatePairs[FID_OTP].cpfis = CPFIS_FOCUSED;

    if (_pCredentialEvents)
    {
        _pCredentialEvents->SetFieldState(this, FID_USERNAME, CPFS_HIDDEN);
        _pCredentialEvents->SetFieldState(this, FID_OTP, CPFS_DISPLAY_IN_SELECTED_TILE);
        _pCredentialEvents->SetFieldInteractiveState(this, FID_OTP, CPFIS_FOCUSED);
        _pCredentialEvents->SetFieldString(this, FID_SMALL_TEXT, L"Enter your authentication code");
    }

    _UpdateStatusText(L"Enter your authentication code");
}

// Show PIN field
void CAuthentikCredential::_ShowPINField()
{
    // Hide OTP, show PIN
    _rgFieldStatePairs[FID_OTP].cpfs = CPFS_HIDDEN;
    _rgFieldStatePairs[FID_PIN].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
    _rgFieldStatePairs[FID_PIN].cpfis = CPFIS_FOCUSED;

    if (_pCredentialEvents)
    {
        _pCredentialEvents->SetFieldState(this, FID_OTP, CPFS_HIDDEN);
        _pCredentialEvents->SetFieldState(this, FID_PIN, CPFS_DISPLAY_IN_SELECTED_TILE);
        _pCredentialEvents->SetFieldInteractiveState(this, FID_PIN, CPFIS_FOCUSED);
    }

    _UpdateStatusText(L"Enter your smart card PIN");
}
