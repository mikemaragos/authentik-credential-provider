// AuthentikCredential.h
// Header for individual credential tile - Passwordless version

#pragma once

#include <credentialprovider.h>
#include <windows.h>
#include <strsafe.h>
#include <shlguid.h>
#include <shlwapi.h>
#include <string>
#include "FieldDescriptors.h"
#include "CertificateHelper.h"

// Forward declarations
class AuthentikAPI;
struct AuthentikResponse;

// Authentication steps for passwordless flow
enum class AuthStep
{
    STEP_USERNAME,      // Enter username
    STEP_OTP,           // Enter OTP code
    STEP_PROCESSING,    // Processing certificate
    STEP_COMPLETE       // Ready to submit credentials
};

class CAuthentikCredential : public ICredentialProviderCredential
{
public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* pcpce);
    IFACEMETHODIMP UnAdvise();
    IFACEMETHODIMP SetSelected(BOOL* pbAutoLogon);
    IFACEMETHODIMP SetDeselected();
    IFACEMETHODIMP GetFieldState(DWORD dwFieldID, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);
    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, LPWSTR* ppwsz);
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp);
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, LPWSTR* ppwszLabel);
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem);
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, LPWSTR* ppwszItem);
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo);
    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, LPCWSTR pwz);
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked);
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem);
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID);
    IFACEMETHODIMP GetSerialization(
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
        LPWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);
    IFACEMETHODIMP ReportResult(
        NTSTATUS ntsStatus,
        NTSTATUS ntsSubstatus,
        LPWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

    // Initialize credential
    HRESULT Initialize(
        CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
        const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
        const FIELD_STATE_PAIR* rgfsp,
        ULONG ulAuthPackage);

    friend HRESULT CAuthentikCredential_CreateInstance(REFIID riid, void** ppv);

protected:
    CAuthentikCredential();
    ~CAuthentikCredential();

private:
    // Step handlers
    HRESULT _HandleUsernameStep(
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
        LPWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);
    
    HRESULT _HandleOTPStep(
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
        LPWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);
    
    // Process certificate and pack credentials
    HRESULT _ProcessCertificateAndPack(
        const AuthentikResponse& response,
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
        LPWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);
    
    // UI update helpers
    void _TransitionToOTPStep(const std::wstring& prompt);
    void _ShowError(const std::wstring& message);
    void _ResetToUsernameStep();

    // Member variables
    LONG _cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;
    LPWSTR _rgFieldStrings[FID_NUM_FIELDS];
    FIELD_STATE_PAIR _rgFieldStatePairs[FID_NUM_FIELDS];
    ULONG _ulAuthPackage;
    ICredentialProviderCredentialEvents* _pCredentialEvents;
    
    // Authentication state
    AuthStep _currentStep;
    std::wstring _currentUsername;
    
    // API and certificate helpers
    AuthentikAPI* _pAuthentikAPI;
    CertificateHelper* _pCertHelper;
    CertificateBundle _certBundle;
};

// Factory function
HRESULT CAuthentikCredential_CreateInstance(REFIID riid, void** ppv);
