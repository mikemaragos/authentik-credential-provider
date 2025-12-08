// VSCManager.cpp
// Virtual Smart Card Manager - handles PFX import to VSC
// Phase 2: December 8, 2025

#include "VSCManager.h"
#include "Logger.h"
#include <winscard.h>
#include <cryptuiapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <objbase.h>
#include <new>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "winscard.lib")
#pragma comment(lib, "cryptui.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")

// Constructor
VSCManager::VSCManager() :
    _cspName(L"Microsoft Base Smart Card Crypto Provider"),
    _initialized(false)
{
    LOG("VSCManager::Constructor");
}

// Destructor
VSCManager::~VSCManager()
{
    LOG("VSCManager::Destructor");
}

// Initialize and find VSC
HRESULT VSCManager::Initialize()
{
    LOG("VSCManager::Initialize");

    HRESULT hr = _FindVSCReader();
    if (SUCCEEDED(hr))
    {
        _initialized = true;
        LOG("VSCManager initialized: reader=%S", _readerName.c_str());
    }
    else
    {
        LOG("VSCManager initialization failed: 0x%08x", hr);
        _lastError = L"No Virtual Smart Card found";
    }

    return hr;
}

// Find VSC reader
HRESULT VSCManager::_FindVSCReader()
{
    LOG("Finding VSC reader");

    SCARDCONTEXT hContext = 0;
    LONG lResult = SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, &hContext);
    if (lResult != SCARD_S_SUCCESS)
    {
        LOG("SCardEstablishContext failed: 0x%08x", lResult);
        return HRESULT_FROM_WIN32(lResult);
    }

    // List readers
    DWORD dwReaders = SCARD_AUTOALLOCATE;
    LPWSTR pszReaders = nullptr;
    lResult = SCardListReadersW(hContext, nullptr, (LPWSTR)&pszReaders, &dwReaders);

    if (lResult != SCARD_S_SUCCESS)
    {
        LOG("SCardListReaders failed: 0x%08x", lResult);
        SCardReleaseContext(hContext);
        return HRESULT_FROM_WIN32(lResult);
    }

    // Find Microsoft Virtual Smart Card reader
    LPWSTR pReader = pszReaders;
    while (pReader && *pReader)
    {
        LOG("Found reader: %S", pReader);
        
        // Look for VSC reader
        if (wcsstr(pReader, L"Virtual Smart Card") != nullptr)
        {
            _readerName = pReader;
            LOG("VSC reader found: %S", _readerName.c_str());
            break;
        }
        
        pReader += wcslen(pReader) + 1;
    }

    SCardFreeMemory(hContext, pszReaders);
    SCardReleaseContext(hContext);

    if (_readerName.empty())
    {
        LOG("No VSC reader found");
        return E_FAIL;
    }

    return S_OK;
}

// Import PFX to VSC
HRESULT VSCManager::ImportPFX(
    const std::vector<BYTE>& pfxData,
    const std::wstring& pfxPassword,
    const std::wstring& pin,
    VSCInfo* pVscInfo)
{
    LOG("ImportPFX: %d bytes, pin length=%d", pfxData.size(), pin.length());

    if (pfxData.empty())
    {
        _lastError = L"Empty PFX data";
        return E_INVALIDARG;
    }

    if (!_initialized)
    {
        HRESULT hr = Initialize();
        if (FAILED(hr))
            return hr;
    }

    // Use certutil method first - it's more reliable for VSC targeting
    // The NCrypt API method has issues targeting the VSC correctly
    LOG("ImportPFX: Using certutil for VSC import");
    HRESULT hr = _ImportPFXSimple(pfxData, pfxPassword);
    
    if (FAILED(hr))
    {
        LOG("certutil import failed, trying NCrypt API fallback");
        hr = _ImportPFXToVSC(pfxData, pfxPassword, pin);
    }

    if (SUCCEEDED(hr) && pVscInfo)
    {
        // Fill in VSC info
        pVscInfo->readerName = _readerName;
        pVscInfo->cspName = _cspName;
        pVscInfo->cardName = L"";  // Will be filled by GetContainerFromCert
        pVscInfo->containerName = L"";  // Will be filled by GetContainerFromCert
        
        LOG("PFX import successful");
    }

    return hr;
}

// Import PFX using certutil (fallback method - reliable)
HRESULT VSCManager::_ImportPFXSimple(
    const std::vector<BYTE>& pfxData,
    const std::wstring& pfxPassword)
{
    LOG("_ImportPFXSimple using certutil");

    // Get PIN from registry (stored in _pin member or passed in)
    std::wstring vscPin = L"12345678";  // Default, should come from config
    
    // Read PIN from registry
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\AuthentikCredentialProvider", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        WCHAR buffer[64];
        DWORD bufferSize = sizeof(buffer);
        if (RegQueryValueExW(hKey, L"VSCPin", nullptr, nullptr, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS)
        {
            vscPin = buffer;
        }
        RegCloseKey(hKey);
    }
    LOG("Using VSC PIN from config");

    // Create temp directory path
    WCHAR tempPath[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tempPath) == 0)
    {
        LOG("GetTempPath failed: %d", ::GetLastError());
        return HRESULT_FROM_WIN32(::GetLastError());
    }

    // Create temp file for PFX
    std::wstring pfxFile = std::wstring(tempPath) + L"auth_temp.pfx";
    
    // Write PFX to temp file using Windows API
    {
        HANDLE hFile = CreateFileW(
            pfxFile.c_str(),
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        
        if (hFile == INVALID_HANDLE_VALUE)
        {
            LOG("Failed to create temp PFX file: %d", ::GetLastError());
            _lastError = L"Failed to create temporary file";
            return E_FAIL;
        }
        
        DWORD dwWritten = 0;
        BOOL bResult = WriteFile(
            hFile,
            pfxData.data(),
            (DWORD)pfxData.size(),
            &dwWritten,
            nullptr);
        
        CloseHandle(hFile);
        
        if (!bResult || dwWritten != pfxData.size())
        {
            LOG("Failed to write PFX file");
            DeleteFileW(pfxFile.c_str());
            _lastError = L"Failed to write temporary file";
            return E_FAIL;
        }
    }

    LOG("PFX written to: %S", pfxFile.c_str());

    // Build certutil command with both PFX password and smart card PIN
    // certutil -csp "Microsoft Base Smart Card Crypto Provider" -pin "vscpin" -p "pfxpwd" -importpfx "file.pfx"
    std::wstring cmdLine = L"certutil -csp \"Microsoft Base Smart Card Crypto Provider\" -pin \"" 
                          + vscPin + L"\" -p \"" + pfxPassword + L"\" -importpfx \"" + pfxFile + L"\"";

    LOG("Executing: certutil -csp ... -pin ... -importpfx");

    // Create process
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    // Need writable command line buffer
    std::vector<wchar_t> cmdBuffer(cmdLine.begin(), cmdLine.end());
    cmdBuffer.push_back(L'\0');

    BOOL bResult = CreateProcessW(
        nullptr,
        &cmdBuffer[0],
        nullptr,
        nullptr,
        FALSE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si,
        &pi);

    if (!bResult)
    {
        LOG("CreateProcess failed: %d", ::GetLastError());
        DeleteFileW(pfxFile.c_str());
        _lastError = L"Failed to execute certutil";
        return HRESULT_FROM_WIN32(::GetLastError());
    }

    // Wait for completion (timeout 30 seconds)
    DWORD waitResult = WaitForSingleObject(pi.hProcess, 30000);
    
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Delete temp file
    DeleteFileW(pfxFile.c_str());

    if (waitResult == WAIT_TIMEOUT)
    {
        LOG("certutil timed out");
        _lastError = L"Certificate import timed out";
        return E_FAIL;
    }

    if (exitCode != 0)
    {
        LOG("certutil failed with exit code: %d", exitCode);
        _lastError = L"Certificate import failed";
        return E_FAIL;
    }

    LOG("certutil import successful");
    return S_OK;
}

// Import PFX using NCrypt APIs (preferred method)
HRESULT VSCManager::_ImportPFXToVSC(
    const std::vector<BYTE>& pfxData,
    const std::wstring& pfxPassword,
    const std::wstring& pin)
{
    LOG("_ImportPFXToVSC using NCrypt APIs");

    // Setup PFX blob
    CRYPT_DATA_BLOB pfxBlob;
    pfxBlob.cbData = (DWORD)pfxData.size();
    pfxBlob.pbData = const_cast<BYTE*>(pfxData.data());

    // Import flags - target smart card CSP
    DWORD dwFlags = CRYPT_USER_KEYSET | PKCS12_ALLOW_OVERWRITE_KEY;

    // For smart card import, we need to use NCrypt provider
    // First, try importing with PKCS12_PREFER_CNG_KSP to use KSP
    NCRYPT_PROV_HANDLE hProvider = 0;
    SECURITY_STATUS status = NCryptOpenStorageProvider(
        &hProvider,
        MS_SMART_CARD_KEY_STORAGE_PROVIDER,
        0);

    if (status != ERROR_SUCCESS)
    {
        LOG("NCryptOpenStorageProvider failed: 0x%08x", status);
        // Fall back to PFXImportCertStore method
        return _ImportPFXWithCertStore(pfxData, pfxPassword);
    }

    // Set PIN for the smart card
    if (!pin.empty())
    {
        status = NCryptSetProperty(
            hProvider,
            NCRYPT_PIN_PROPERTY,
            (PBYTE)pin.c_str(),
            (DWORD)((pin.length() + 1) * sizeof(wchar_t)),
            0);

        if (status != ERROR_SUCCESS)
        {
            LOG("NCryptSetProperty PIN failed: 0x%08x", status);
            // Continue anyway, user may be prompted
        }
    }

    // Import the PFX
    HCERTSTORE hStore = PFXImportCertStore(
        &pfxBlob,
        pfxPassword.c_str(),
        CRYPT_USER_KEYSET | PKCS12_PREFER_CNG_KSP | PKCS12_ALWAYS_CNG_KSP);

    if (!hStore)
    {
        DWORD dwError = ::GetLastError();
        LOG("PFXImportCertStore failed: %d", dwError);
        NCryptFreeObject(hProvider);
        return HRESULT_FROM_WIN32(dwError);
    }

    // Find the imported certificate
    PCCERT_CONTEXT pCert = CertEnumCertificatesInStore(hStore, nullptr);
    if (pCert)
    {
        // Add to MY store
        HCERTSTORE hMyStore = CertOpenStore(
            CERT_STORE_PROV_SYSTEM,
            0,
            0,
            CERT_SYSTEM_STORE_CURRENT_USER,
            L"MY");

        if (hMyStore)
        {
            if (!CertAddCertificateContextToStore(
                hMyStore,
                pCert,
                CERT_STORE_ADD_REPLACE_EXISTING,
                nullptr))
            {
                LOG("CertAddCertificateContextToStore failed: %d", ::GetLastError());
            }
            else
            {
                LOG("Certificate added to MY store");
            }
            CertCloseStore(hMyStore, 0);
        }

        CertFreeCertificateContext(pCert);
    }

    CertCloseStore(hStore, 0);
    NCryptFreeObject(hProvider);

    return S_OK;
}

// Helper: Import PFX using CertStore API
HRESULT VSCManager::_ImportPFXWithCertStore(
    const std::vector<BYTE>& pfxData,
    const std::wstring& pfxPassword)
{
    LOG("_ImportPFXWithCertStore");

    CRYPT_DATA_BLOB pfxBlob;
    pfxBlob.cbData = (DWORD)pfxData.size();
    pfxBlob.pbData = const_cast<BYTE*>(pfxData.data());

    // Import to cert store
    HCERTSTORE hPfxStore = PFXImportCertStore(
        &pfxBlob,
        pfxPassword.c_str(),
        CRYPT_USER_KEYSET | PKCS12_ALLOW_OVERWRITE_KEY);

    if (!hPfxStore)
    {
        DWORD dwError = ::GetLastError();
        LOG("PFXImportCertStore failed: %d", dwError);
        _lastError = L"Failed to import PFX";
        return HRESULT_FROM_WIN32(dwError);
    }

    // The certificate is now in a temporary store
    // We need to copy it to MY store and associate with smart card CSP
    PCCERT_CONTEXT pCert = CertEnumCertificatesInStore(hPfxStore, nullptr);
    
    if (!pCert)
    {
        LOG("No certificate found in PFX");
        CertCloseStore(hPfxStore, 0);
        _lastError = L"No certificate in PFX";
        return E_FAIL;
    }

    // Get private key info
    DWORD cbData = 0;
    CertGetCertificateContextProperty(
        pCert,
        CERT_KEY_PROV_INFO_PROP_ID,
        nullptr,
        &cbData);

    if (cbData > 0)
    {
        std::vector<BYTE> keyProvInfo(cbData);
        if (CertGetCertificateContextProperty(
            pCert,
            CERT_KEY_PROV_INFO_PROP_ID,
            &keyProvInfo[0],
            &cbData))
        {
            CRYPT_KEY_PROV_INFO* pKeyInfo = (CRYPT_KEY_PROV_INFO*)&keyProvInfo[0];
            LOG("Key container: %S, CSP: %S", 
                pKeyInfo->pwszContainerName,
                pKeyInfo->pwszProvName);
        }
    }

    // Add to MY store
    HCERTSTORE hMyStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0,
        0,
        CERT_SYSTEM_STORE_CURRENT_USER,
        L"MY");

    HRESULT hr = E_FAIL;
    if (hMyStore)
    {
        if (CertAddCertificateContextToStore(
            hMyStore,
            pCert,
            CERT_STORE_ADD_REPLACE_EXISTING,
            nullptr))
        {
            LOG("Certificate added to MY store successfully");
            hr = S_OK;
        }
        else
        {
            LOG("Failed to add certificate to MY store: %d", ::GetLastError());
            _lastError = L"Failed to add certificate to store";
        }
        CertCloseStore(hMyStore, 0);
    }

    CertFreeCertificateContext(pCert);
    CertCloseStore(hPfxStore, 0);

    return hr;
}

// Get VSC info by thumbprint
HRESULT VSCManager::GetVSCInfoByThumbprint(
    const std::wstring& thumbprint,
    VSCInfo* pVscInfo)
{
    LOG("GetVSCInfoByThumbprint: %S", thumbprint.c_str());

    if (!pVscInfo)
        return E_INVALIDARG;

    // Open MY store
    HCERTSTORE hStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0,
        0,
        CERT_SYSTEM_STORE_CURRENT_USER,
        L"MY");

    if (!hStore)
    {
        LOG("Failed to open MY store: %d", ::GetLastError());
        return E_FAIL;
    }

    // Convert thumbprint hex string to bytes
    std::vector<BYTE> thumbprintBytes;
    for (size_t i = 0; i < thumbprint.length(); i += 2)
    {
        std::wstring byteStr = thumbprint.substr(i, 2);
        BYTE b = (BYTE)wcstoul(byteStr.c_str(), nullptr, 16);
        thumbprintBytes.push_back(b);
    }

    // Find certificate by thumbprint
    CRYPT_HASH_BLOB hashBlob;
    hashBlob.cbData = (DWORD)thumbprintBytes.size();
    hashBlob.pbData = thumbprintBytes.data();

    PCCERT_CONTEXT pCert = CertFindCertificateInStore(
        hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SHA1_HASH,
        &hashBlob,
        nullptr);

    HRESULT hr = E_FAIL;
    if (pCert)
    {
        hr = _GetContainerFromCert(pCert, pVscInfo->containerName, pVscInfo->cspName);
        if (SUCCEEDED(hr))
        {
            pVscInfo->readerName = _readerName;
            pVscInfo->cardName = L"";
        }
        CertFreeCertificateContext(pCert);
    }
    else
    {
        LOG("Certificate not found by thumbprint");
        _lastError = L"Certificate not found";
    }

    CertCloseStore(hStore, 0);
    return hr;
}

// Get container info from certificate
HRESULT VSCManager::_GetContainerFromCert(
    PCCERT_CONTEXT pCertContext,
    std::wstring& containerName,
    std::wstring& cspName)
{
    LOG("_GetContainerFromCert");

    DWORD cbData = 0;
    if (!CertGetCertificateContextProperty(
        pCertContext,
        CERT_KEY_PROV_INFO_PROP_ID,
        nullptr,
        &cbData))
    {
        LOG("Failed to get key prov info size: %d", ::GetLastError());
        return E_FAIL;
    }

    std::vector<BYTE> buffer(cbData);
    if (!CertGetCertificateContextProperty(
        pCertContext,
        CERT_KEY_PROV_INFO_PROP_ID,
        &buffer[0],
        &cbData))
    {
        LOG("Failed to get key prov info: %d", ::GetLastError());
        return E_FAIL;
    }

    CRYPT_KEY_PROV_INFO* pKeyInfo = (CRYPT_KEY_PROV_INFO*)&buffer[0];
    
    if (pKeyInfo->pwszContainerName)
        containerName = pKeyInfo->pwszContainerName;
    
    if (pKeyInfo->pwszProvName)
        cspName = pKeyInfo->pwszProvName;

    LOG("Container: %S, CSP: %S", containerName.c_str(), cspName.c_str());
    
    return S_OK;
}

// Find certificate by UPN
PCCERT_CONTEXT VSCManager::_FindCertificateInStore(const std::wstring& upn)
{
    LOG("_FindCertificateInStore: upn=%S", upn.c_str());

    HCERTSTORE hStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0,
        0,
        CERT_SYSTEM_STORE_CURRENT_USER,
        L"MY");

    if (!hStore)
        return nullptr;

    // Enumerate and find by UPN in SAN
    PCCERT_CONTEXT pCert = nullptr;
    while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != nullptr)
    {
        // Check for Smart Card Logon EKU
        DWORD cbUsage = 0;
        if (CertGetEnhancedKeyUsage(pCert, 0, nullptr, &cbUsage) && cbUsage > 0)
        {
            std::vector<BYTE> usageBuffer(cbUsage);
            CERT_ENHKEY_USAGE* pUsage = (CERT_ENHKEY_USAGE*)&usageBuffer[0];
            
            if (CertGetEnhancedKeyUsage(pCert, 0, pUsage, &cbUsage))
            {
                for (DWORD i = 0; i < pUsage->cUsageIdentifier; i++)
                {
                    // Smart Card Logon EKU: 1.3.6.1.4.1.311.20.2.2
                    if (strcmp(pUsage->rgpszUsageIdentifier[i], "1.3.6.1.4.1.311.20.2.2") == 0)
                    {
                        LOG("Found certificate with Smart Card Logon EKU");
                        // Don't close store - caller will free context
                        return pCert;
                    }
                }
            }
        }
    }

    CertCloseStore(hStore, 0);
    return nullptr;
}
