// SmartCardHelper.h
// Helper class for TPM Virtual Smart Card operations

#pragma once

#include <windows.h>
#include <wincrypt.h>
#include <winscard.h>
#include <string>
#include <vector>

#pragma comment(lib, "winscard.lib")
#pragma comment(lib, "crypt32.lib")

// Result structure for VSC operations
struct VSCResult
{
    bool success;
    std::wstring message;
    std::wstring thumbprint;
    std::wstring readerName;
};

class SmartCardHelper
{
public:
    SmartCardHelper();
    ~SmartCardHelper();

    // Check if VSC exists and is ready
    VSCResult CheckVSCStatus();

    // Import PFX certificate to VSC
    VSCResult ImportCertificateToVSC(
        const std::vector<BYTE>& pfxData,
        const std::wstring& pfxPassword,
        const std::wstring& pin);

    // Find certificate on VSC by thumbprint
    VSCResult FindCertificateOnVSC(const std::wstring& thumbprint);

    // Get the smart card reader name for the VSC
    std::wstring GetVSCReaderName();

    // Delete old certificates from VSC (keep only the newest)
    VSCResult CleanupOldCertificates(const std::wstring& keepThumbprint);

private:
    // Find the VSC reader
    bool _FindVSCReader(std::wstring& readerName);

    // Get smart card context
    SCARDCONTEXT _GetContext();

    // Convert bytes to hex string
    std::wstring _BytesToHex(const BYTE* data, DWORD length);

    SCARDCONTEXT _hContext;
};
