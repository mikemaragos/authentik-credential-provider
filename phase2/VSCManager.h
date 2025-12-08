// VSCManager.h
// Virtual Smart Card Manager - handles VSC operations for certificate import

#pragma once

#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include "CredentialPacking.h"

// VSC Manager class
class VSCManager
{
public:
    VSCManager();
    ~VSCManager();

    // Initialize and find existing VSC
    HRESULT Initialize();

    // Import certificate and private key to VSC
    // Returns VSCInfo for use with KERB_CERTIFICATE_LOGON
    HRESULT ImportCertificate(
        const std::vector<BYTE>& certificateDer,
        const std::vector<BYTE>& privateKeyBlob,
        const std::wstring& pin,
        VSCInfo* pVscInfo);

    // Get VSC info for existing certificate
    HRESULT GetVSCInfo(const std::wstring& username, VSCInfo* pVscInfo);

    // Check if VSC exists and has valid certificate
    bool HasValidCertificate(const std::wstring& username);

    // Delete certificate from VSC
    HRESULT DeleteCertificate(const std::wstring& containerName);

    // Get the reader name for the VSC
    std::wstring GetReaderName() const { return _readerName; }

private:
    // Find VSC reader
    HRESULT _FindVSCReader();

    // Create container in VSC
    HRESULT _CreateContainer(
        const std::wstring& containerName,
        HCRYPTPROV* phProv);

    // Import private key to container
    HRESULT _ImportPrivateKey(
        HCRYPTPROV hProv,
        const std::vector<BYTE>& privateKeyBlob);

    // Import certificate to MY store with link to container
    HRESULT _ImportCertificateToStore(
        const std::vector<BYTE>& certificateDer,
        const std::wstring& containerName,
        const std::wstring& cspName);

    // Parse PKCS#8 private key to get raw key blob
    HRESULT _ParsePKCS8ToKeyBlob(
        const std::vector<BYTE>& pkcs8,
        std::vector<BYTE>& keyBlob);

    // Configuration
    std::wstring _readerName;
    std::wstring _cspName;
    std::wstring _cardName;
    bool _initialized;
};
