// AuthentikCredential.cpp
// Individual credential tile implementation - Phase 2 (Passwordless)
// December 8, 2025
//
// Flow:
// 1. User enters username + OTP
// 2. Validate OTP with Authentik
// 3. Request certificate from CertIssuer
// 4. Import PFX to VSC
// 5. Pack KERB_CERTIFICATE_LOGON and submit to LSA
// 6. PKINIT authentication completes

#include "AuthentikCredential.h"
#include "AuthentikAPI.h"
#include "VSCManager.h"
#include "CredentialPacking.h"
#include "Logger.h"
#include "guid.h"
#include <shlwapi.h>
#include <wincred.h>

#pragma comment(lib, "shlwapi.lib")

// Constructor
CAuthentikCredential::CAuthentikCredential() :
    _cRef(1),
    _cpus(CPUS_INVALID),
    _ulAuthPackage(0),
    _pCredentialEvents(nullptr),
    _domain(L"test.local"),
    _vscPin(L"12345678"),
    _pAuthentikAPI(nullptr),
    _pVSCManager(nullptr)
{
    DllAddRef();
    LOG("CAuthentikCredential::Constructor");

    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
    ZeroMemory(&_rgFieldStatePairs, sizeof(_rgFieldStatePairs));

    // Initialize API clients
    _pAuthentikAPI = new AuthentikAPI();
    _pVSCManager = new VSCManager();
    
    // Load domain and PIN from registry
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\AuthentikCredentialProvider", 
                      0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        WCHAR buffer[256];
        DWORD bufferSize = sizeof(buffer);
        
        if (RegQueryValueExW(hKey, L"Domain", nullptr, nullptr, 
                            (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS)
        {
            _domain = buffer;
            LOG("Domain: %S", _domain.c_str());
        }
        
        bufferSize = sizeof(buffer);
        if (RegQueryValueExW(hKey, L"VSCPin", nullptr, nullptr,
                            (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS)
        {
            _vscPin = buffer;
            LOG("VSC PIN loaded (%d chars)", _vscPin.length());
        }
        
        RegCloseKey(hKey);
    }
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
            // Secure clear for OTP field
            if (i == FID_OTP)
            {
                SecureZeroMemory(_rgFieldStrings[i], 
                    wcslen(_rgFieldStrings[i]) * sizeof(wchar_t));
            }
            CoTaskMemFree(_rgFieldStrings[i]);
            _rgFieldStrings[i] = nullptr;
        }
    }

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
    LOG("CAuthentikCredential::Initialize cpus=%d", cpus);

    _cpus = cpus;
    _ulAuthPackage = ulAuthPackage;

    // Copy field state pairs
    for (DWORD i = 0; i < FID_NUM_FIELDS && i < ARRAYSIZE(s_rgFieldStatePairs); i++)
    {
        _rgFieldStatePairs[i] = s_rgFieldStatePairs[i];
    }

    // Set default text
    SHStrDupW(L"Authentik Passwordless", &_rgFieldStrings[FID_LARGE_TEXT]);
    SHStrDupW(L"Enter username and OTP code", &_rgFieldStrings[FID_SMALL_TEXT]);

    // Initialize VSC Manager
    _pVSCManager->Initialize();

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
    
    // Clear OTP field for security
    if (_rgFieldStrings[FID_OTP])
    {
        SecureZeroMemory(_rgFieldStrings[FID_OTP],
            wcslen(_rgFieldStrings[FID_OTP]) * sizeof(wchar_t));
        CoTaskMemFree(_rgFieldStrings[FID_OTP]);
        _rgFieldStrings[FID_OTP] = nullptr;
    }
    
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
    if (dwFieldID < FID_NUM_FIELDS && ppwsz)
    {
        if (_rgFieldStrings[dwFieldID])
        {
            return SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
        }
        else
        {
            *ppwsz = nullptr;
            return S_OK;
        }
    }
    return E_INVALIDARG;
}

HRESULT CAuthentikCredential::GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp)
{
    if (dwFieldID == FID_LOGO)
    {
        *phbmp = nullptr;  // Use default
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
    if (dwFieldID < FID_NUM_FIELDS)
    {
        if (_rgFieldStrings[dwFieldID])
        {
            CoTaskMemFree(_rgFieldStrings[dwFieldID]);
        }
        return SHStrDupW(pwz ? pwz : L"", &_rgFieldStrings[dwFieldID]);
    }
    return E_INVALIDARG;
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

// Main serialization - triggers authentication flow
HRESULT CAuthentikCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    LPWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    LOG("CAuthentikCredential::GetSerialization");

    return _DoAuthentication(pcpgsr, pcpcs, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);
}

HRESULT CAuthentikCredential::ReportResult(
    NTSTATUS ntsStatus,
    NTSTATUS ntsSubstatus,
    LPWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    LOG("CAuthentikCredential::ReportResult status=0x%08x, substatus=0x%08x", 
        ntsStatus, ntsSubstatus);
    
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    if (ntsStatus != 0)
    {
        // Authentication failed
        SHStrDupW(L"Authentication failed. Check username and OTP.", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
    }

    return S_OK;
}

// Main authentication flow
HRESULT CAuthentikCredential::_DoAuthentication(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    LPWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    LOG("_DoAuthentication - Phase 2 Passwordless Flow");

    HRESULT hr = E_FAIL;

    // Get username and OTP
    std::wstring username = _rgFieldStrings[FID_USERNAME] ? _rgFieldStrings[FID_USERNAME] : L"";
    std::wstring otp = _rgFieldStrings[FID_OTP] ? _rgFieldStrings[FID_OTP] : L"";

    LOG("Username: %S, OTP length: %d", username.c_str(), otp.length());

    if (username.empty())
    {
        SHStrDupW(L"Please enter a username", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_OK;
    }

    if (otp.empty())
    {
        SHStrDupW(L"Please enter your OTP code", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_OK;
    }

    // Update status
    _SetStatusText(L"Validating OTP...");

    // Step 1 & 2: Validate OTP and get certificate
    LOG("Step 1-2: Authenticating and requesting certificate");
    CertificateResponse certResponse = _pAuthentikAPI->AuthenticateAndGetCertificate(
        username, otp, _domain);

    if (!certResponse.success)
    {
        LOG("Authentication/certificate request failed: %S", certResponse.message.c_str());
        SHStrDupW(certResponse.message.c_str(), ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_OK;
    }

    LOG("Certificate received: %d bytes PFX, SKI=%S", 
        certResponse.pfxData.size(), 
        certResponse.subjectKeyIdentifier.c_str());

    // Update status
    _SetStatusText(L"Importing certificate...");

    // Step 3: Import PFX to VSC
    LOG("Step 3: Importing PFX to VSC");
    VSCInfo vscInfo;
    hr = _pVSCManager->ImportPFX(
        certResponse.pfxData,
        certResponse.pfxPassword,
        _vscPin,
        &vscInfo);

    if (FAILED(hr))
    {
        LOG("PFX import failed: 0x%08x - %S", hr, _pVSCManager->GetLastError().c_str());
        SHStrDupW(L"Failed to import certificate to smart card", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_OK;
    }

    // Fill in VSC info if not already populated
    if (vscInfo.readerName.empty())
        vscInfo.readerName = _pVSCManager->GetReaderName();
    if (vscInfo.cspName.empty())
        vscInfo.cspName = L"Microsoft Base Smart Card Crypto Provider";
    if (vscInfo.containerName.empty())
    {
        // Try to get container from imported cert
        _pVSCManager->GetVSCInfoByThumbprint(certResponse.thumbprint, &vscInfo);
    }

    LOG("VSC Info: reader=%S, container=%S, csp=%S",
        vscInfo.readerName.c_str(),
        vscInfo.containerName.c_str(),
        vscInfo.cspName.c_str());

    // Update status
    _SetStatusText(L"Authenticating...");

    // Step 4: Pack KERB_CERTIFICATE_LOGON
    LOG("Step 4: Packing KERB_CERTIFICATE_LOGON");
    BYTE* pPackage = nullptr;
    DWORD cbPackage = 0;

    if (_cpus == CPUS_UNLOCK_WORKSTATION)
    {
        hr = PackKerbCertificateUnlockLogon(
            username,
            _domain,
            _vscPin,
            vscInfo,
            &pPackage,
            &cbPackage);
    }
    else
    {
        hr = PackKerbCertificateLogon(
            username,
            _domain,
            _vscPin,
            vscInfo,
            &pPackage,
            &cbPackage);
    }

    if (FAILED(hr))
    {
        LOG("Credential packing failed: 0x%08x", hr);
        SHStrDupW(L"Failed to prepare credentials", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return hr;
    }

    // Step 5: Fill serialization structure
    LOG("Step 5: Submitting to LSA for PKINIT");
    pcpcs->clsidCredentialProvider = CLSID_AuthentikCredentialProvider;
    pcpcs->rgbSerialization = pPackage;
    pcpcs->cbSerialization = cbPackage;
    pcpcs->ulAuthenticationPackage = _ulAuthPackage;

    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
    *pcpsiOptionalStatusIcon = CPSI_SUCCESS;

    LOG("Authentication package submitted successfully");

    // Clear OTP from memory
    if (_rgFieldStrings[FID_OTP])
    {
        SecureZeroMemory(_rgFieldStrings[FID_OTP],
            wcslen(_rgFieldStrings[FID_OTP]) * sizeof(wchar_t));
    }

    return S_OK;
}

// Update status text in UI
void CAuthentikCredential::_SetStatusText(LPCWSTR text)
{
    if (_pCredentialEvents && text)
    {
        _pCredentialEvents->SetFieldString(this, FID_SMALL_TEXT, text);
    }
}
