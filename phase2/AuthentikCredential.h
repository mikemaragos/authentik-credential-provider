// AuthentikCredential.h
// Header for individual credential tile - Phase 2 (Passwordless)
// December 8, 2025

#pragma once

#include <credentialprovider.h>
#include <windows.h>
#include <strsafe.h>
#include <shlguid.h>
#include <string>
#include "FieldDescriptors.h"

// Forward declarations
class AuthentikAPI;
class VSCManager;

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
    // Main authentication flow
    HRESULT _DoAuthentication(
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
        LPWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

    // Update status text
    void _SetStatusText(LPCWSTR text);

    LONG _cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;
    LPWSTR _rgFieldStrings[FID_NUM_FIELDS];
    FIELD_STATE_PAIR _rgFieldStatePairs[FID_NUM_FIELDS];
    ULONG _ulAuthPackage;
    ICredentialProviderCredentialEvents* _pCredentialEvents;
    
    // Configuration from registry
    std::wstring _domain;
    std::wstring _vscPin;
    
    // API clients
    AuthentikAPI* _pAuthentikAPI;
    VSCManager* _pVSCManager;
};
