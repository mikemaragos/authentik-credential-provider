// VSCManager.h
// Virtual Smart Card Manager - handles PFX import to VSC
// Phase 2: December 8, 2025

#pragma once

#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <string>
#include <vector>

// VSC (Virtual Smart Card) information for KERB_CERTIFICATE_LOGON
struct VSCInfo {
    std::wstring readerName;      // e.g., "Microsoft Virtual Smart Card 0"
    std::wstring containerName;   // Key container name
    std::wstring cspName;         // "Microsoft Base Smart Card Crypto Provider"
    std::wstring cardName;        // Card name
};

class VSCManager
{
public:
    VSCManager();
    ~VSCManager();

    // Initialize and find existing VSC
    HRESULT Initialize();

    // Import PFX to VSC - main method for credential provider
    // Takes PFX data + password, imports to VSC, returns VSCInfo for PKINIT
    HRESULT ImportPFX(
        const std::vector<BYTE>& pfxData,
        const std::wstring& pfxPassword,
        const std::wstring& pin,
        VSCInfo* pVscInfo);

    // Get VSC info for existing certificate by thumbprint
    HRESULT GetVSCInfoByThumbprint(
        const std::wstring& thumbprint,
        VSCInfo* pVscInfo);

    // Check if VSC is available
    bool IsVSCAvailable() const { return _initialized && !_readerName.empty(); }

    // Get the reader name for the VSC
    std::wstring GetReaderName() const { return _readerName; }

    // Get last error message
    std::wstring GetLastError() const { return _lastError; }

private:
    // Find VSC reader
    HRESULT _FindVSCReader();

    // Import PFX using CryptUIWizImport (simple method)
    HRESULT _ImportPFXSimple(
        const std::vector<BYTE>& pfxData,
        const std::wstring& pfxPassword);

    // Import PFX using NCrypt APIs (for VSC targeting)
    HRESULT _ImportPFXToVSC(
        const std::vector<BYTE>& pfxData,
        const std::wstring& pfxPassword,
        const std::wstring& pin);

    // Get container name from imported certificate
    HRESULT _GetContainerFromCert(
        PCCERT_CONTEXT pCertContext,
        std::wstring& containerName,
        std::wstring& cspName);

    // Find certificate in MY store by criteria
    PCCERT_CONTEXT _FindCertificateInStore(
        const std::wstring& upn);

    // Configuration
    std::wstring _readerName;
    std::wstring _cspName;
    std::wstring _lastError;
    bool _initialized;
};
