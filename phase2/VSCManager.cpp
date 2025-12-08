// VSCManager.cpp
// Virtual Smart Card Manager implementation

#include "VSCManager.h"
#include "Logger.h"
#include <winscard.h>
#include <ncrypt.h>
#include <vector>
#include <sstream>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "winscard.lib")
#pragma comment(lib, "ncrypt.lib")

// Microsoft Base Smart Card Crypto Provider
static const wchar_t* VSC_CSP_NAME = L"Microsoft Base Smart Card Crypto Provider";
static const wchar_t* VSC_CARD_NAME = L"AuthentikVSC";

VSCManager::VSCManager() :
    _initialized(false),
    _cspName(VSC_CSP_NAME),
    _cardName(VSC_CARD_NAME)
{
    LOG("VSCManager::Constructor");
}

VSCManager::~VSCManager()
{
    LOG("VSCManager::Destructor");
}

// Initialize and find VSC
HRESULT VSCManager::Initialize()
{
    LOG("VSCManager::Initialize");

    if (_initialized)
        return S_OK;

    HRESULT hr = _FindVSCReader();
    if (SUCCEEDED(hr))
    {
        _initialized = true;
        LOG("VSC initialized: reader=%S", _readerName.c_str());
    }
    else
    {
        LOG("Failed to find VSC reader: 0x%08x", hr);
    }

    return hr;
}

// Find the Virtual Smart Card reader
HRESULT VSCManager::_FindVSCReader()
{
    LOG("_FindVSCReader");

    SCARDCONTEXT hContext = 0;
    LONG lResult = SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, &hContext);
    
    if (lResult != SCARD_S_SUCCESS)
    {
        LOG("SCardEstablishContext failed: 0x%08x", lResult);
        return HRESULT_FROM_WIN32(lResult);
    }

    // Get list of readers
    DWORD dwReaders = SCARD_AUTOALLOCATE;
    LPWSTR pszReaders = nullptr;

    lResult = SCardListReadersW(hContext, nullptr, (LPWSTR)&pszReaders, &dwReaders);
    
    if (lResult != SCARD_S_SUCCESS)
    {
        LOG("SCardListReaders failed: 0x%08x", lResult);
        SCardReleaseContext(hContext);
        return HRESULT_FROM_WIN32(lResult);
    }

    // Find VSC reader (contains "Virtual Smart Card")
    LPWSTR pReader = pszReaders;
    bool found = false;

    while (*pReader != L'\0')
    {
        LOG("Found reader: %S", pReader);
        
        // Check if this is a virtual smart card reader
        std::wstring readerStr(pReader);
        if (readerStr.find(L"Virtual Smart Card") != std::wstring::npos ||
            readerStr.find(L"TPM") != std::wstring::npos)
        {
            _readerName = readerStr;
            found = true;
            LOG("Selected VSC reader: %S", _readerName.c_str());
            break;
        }

        // Move to next reader
        pReader += wcslen(pReader) + 1;
    }

    SCardFreeMemory(hContext, pszReaders);
    SCardReleaseContext(hContext);

    if (!found)
    {
        LOG("No VSC reader found");
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    }

    return S_OK;
}

// Import certificate and private key to VSC
HRESULT VSCManager::ImportCertificate(
    const std::vector<BYTE>& certificateDer,
    const std::vector<BYTE>& privateKeyBlob,
    const std::wstring& pin,
    VSCInfo* pVscInfo)
{
    LOG("ImportCertificate: certSize=%d, keySize=%d", 
        certificateDer.size(), privateKeyBlob.size());

    if (!_initialized)
    {
        HRESULT hr = Initialize();
        if (FAILED(hr))
            return hr;
    }

    if (certificateDer.empty() || privateKeyBlob.empty() || !pVscInfo)
        return E_INVALIDARG;

    HRESULT hr = S_OK;

    // Parse certificate to get subject name for container
    PCCERT_CONTEXT pCert = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        &certificateDer[0],
        (DWORD)certificateDer.size());

    if (!pCert)
    {
        LOG("Failed to parse certificate: %d", GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }

    // Get subject name for container name
    WCHAR szSubject[256] = {0};
    CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, szSubject, ARRAYSIZE(szSubject));
    
    // Create unique container name
    std::wstring containerName = L"AuthentikCert_";
    containerName += szSubject;
    containerName += L"_";
    containerName += std::to_wstring(GetTickCount64());

    LOG("Container name: %S", containerName.c_str());

    // Use NCrypt to import to smart card
    NCRYPT_PROV_HANDLE hProv = 0;
    NCRYPT_KEY_HANDLE hKey = 0;

    // Open the smart card provider
    SECURITY_STATUS status = NCryptOpenStorageProvider(
        &hProv,
        MS_SMART_CARD_KEY_STORAGE_PROVIDER,
        0);

    if (status != ERROR_SUCCESS)
    {
        LOG("NCryptOpenStorageProvider failed: 0x%08x", status);
        CertFreeCertificateContext(pCert);
        return HRESULT_FROM_WIN32(status);
    }

    // Set the reader name
    std::wstring readerPath = L"\\\\.\\" + _readerName + L"\\";
    status = NCryptSetProperty(
        hProv,
        NCRYPT_READER_PROPERTY,
        (PBYTE)readerPath.c_str(),
        (DWORD)((readerPath.length() + 1) * sizeof(WCHAR)),
        0);

    if (status != ERROR_SUCCESS)
    {
        LOG("NCryptSetProperty (reader) failed: 0x%08x", status);
    }

    // Set PIN for authentication
    if (!pin.empty())
    {
        status = NCryptSetProperty(
            hProv,
            NCRYPT_PIN_PROPERTY,
            (PBYTE)pin.c_str(),
            (DWORD)((pin.length() + 1) * sizeof(WCHAR)),
            0);

        if (status != ERROR_SUCCESS)
        {
            LOG("NCryptSetProperty (PIN) failed: 0x%08x", status);
        }
    }

    // Import the private key
    // First, try to decode as PKCS#8
    CRYPT_DECODE_PARA decodePara = {0};
    decodePara.cbSize = sizeof(decodePara);

    BCRYPT_KEY_BLOB* pKeyBlob = nullptr;
    DWORD cbKeyBlob = 0;

    // Try to import as PKCS#8 private key
    if (CryptDecodeObjectEx(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        PKCS_RSA_PRIVATE_KEY,
        &privateKeyBlob[0],
        (DWORD)privateKeyBlob.size(),
        CRYPT_DECODE_ALLOC_FLAG,
        nullptr,
        &pKeyBlob,
        &cbKeyBlob))
    {
        LOG("Decoded PKCS RSA private key: %d bytes", cbKeyBlob);
    }
    else
    {
        // Try as raw blob
        LOG("Using raw key blob");
    }

    // Import key to smart card
    NCryptBuffer keyBuffer = {0};
    keyBuffer.BufferType = NCRYPTBUFFER_PKCS_KEY_NAME;
    keyBuffer.cbBuffer = (DWORD)((containerName.length() + 1) * sizeof(WCHAR));
    keyBuffer.pvBuffer = (PVOID)containerName.c_str();

    NCryptBufferDesc keyBufferDesc = {0};
    keyBufferDesc.ulVersion = NCRYPTBUFFER_VERSION;
    keyBufferDesc.cBuffers = 1;
    keyBufferDesc.pBuffers = &keyBuffer;

    status = NCryptImportKey(
        hProv,
        0,
        BCRYPT_RSAPRIVATE_BLOB,  // Or NCRYPT_PKCS8_PRIVATE_KEY_BLOB
        &keyBufferDesc,
        &hKey,
        (PBYTE)&privateKeyBlob[0],
        (DWORD)privateKeyBlob.size(),
        NCRYPT_OVERWRITE_KEY_FLAG);

    if (status != ERROR_SUCCESS)
    {
        LOG("NCryptImportKey failed: 0x%08x", status);
        // Try alternative import method
        status = NCryptImportKey(
            hProv,
            0,
            NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
            nullptr,
            &hKey,
            (PBYTE)&privateKeyBlob[0],
            (DWORD)privateKeyBlob.size(),
            NCRYPT_OVERWRITE_KEY_FLAG);

        if (status != ERROR_SUCCESS)
        {
            LOG("NCryptImportKey (PKCS8) also failed: 0x%08x", status);
            NCryptFreeObject(hProv);
            CertFreeCertificateContext(pCert);
            if (pKeyBlob) LocalFree(pKeyBlob);
            return HRESULT_FROM_WIN32(status);
        }
    }

    LOG("Private key imported successfully");

    // Now import the certificate to MY store with link to the key
    HCERTSTORE hStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        0,
        0,
        CERT_SYSTEM_STORE_CURRENT_USER,
        L"MY");

    if (!hStore)
    {
        LOG("CertOpenStore failed: %d", GetLastError());
        NCryptFreeObject(hKey);
        NCryptFreeObject(hProv);
        CertFreeCertificateContext(pCert);
        if (pKeyBlob) LocalFree(pKeyBlob);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    // Set the key provider info on the certificate
    CRYPT_KEY_PROV_INFO keyProvInfo = {0};
    keyProvInfo.pwszContainerName = (LPWSTR)containerName.c_str();
    keyProvInfo.pwszProvName = (LPWSTR)MS_SMART_CARD_KEY_STORAGE_PROVIDER;
    keyProvInfo.dwProvType = 0;  // For CNG
    keyProvInfo.dwFlags = 0;
    keyProvInfo.dwKeySpec = AT_KEYEXCHANGE;

    if (!CertSetCertificateContextProperty(
        pCert,
        CERT_KEY_PROV_INFO_PROP_ID,
        0,
        &keyProvInfo))
    {
        LOG("CertSetCertificateContextProperty failed: %d", GetLastError());
    }

    // Add certificate to store
    PCCERT_CONTEXT pStoreCert = nullptr;
    if (!CertAddCertificateContextToStore(
        hStore,
        pCert,
        CERT_STORE_ADD_REPLACE_EXISTING,
        &pStoreCert))
    {
        LOG("CertAddCertificateContextToStore failed: %d", GetLastError());
        hr = HRESULT_FROM_WIN32(GetLastError());
    }
    else
    {
        LOG("Certificate added to MY store");
        CertFreeCertificateContext(pStoreCert);
        hr = S_OK;
    }

    // Fill in VSC info for caller
    pVscInfo->readerName = _readerName;
    pVscInfo->containerName = containerName;
    pVscInfo->cspName = MS_SMART_CARD_KEY_STORAGE_PROVIDER;
    pVscInfo->cardName = _cardName;

    LOG("VSCInfo: reader=%S, container=%S, csp=%S",
        pVscInfo->readerName.c_str(),
        pVscInfo->containerName.c_str(),
        pVscInfo->cspName.c_str());

    // Cleanup
    CertCloseStore(hStore, 0);
    NCryptFreeObject(hKey);
    NCryptFreeObject(hProv);
    CertFreeCertificateContext(pCert);
    if (pKeyBlob) LocalFree(pKeyBlob);

    return hr;
}

// Get VSC info for existing certificate
HRESULT VSCManager::GetVSCInfo(const std::wstring& username, VSCInfo* pVscInfo)
{
    LOG("GetVSCInfo: user=%S", username.c_str());

    if (!_initialized)
    {
        HRESULT hr = Initialize();
        if (FAILED(hr))
            return hr;
    }

    if (!pVscInfo)
        return E_INVALIDARG;

    // Open MY store and find certificate for user
    HCERTSTORE hStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        0,
        0,
        CERT_SYSTEM_STORE_CURRENT_USER,
        L"MY");

    if (!hStore)
    {
        LOG("CertOpenStore failed: %d", GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }

    // Find certificate with matching subject
    std::wstring searchName = L"CN=" + username;
    PCCERT_CONTEXT pCert = nullptr;
    HRESULT hr = E_NOT_SET;

    while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != nullptr)
    {
        WCHAR szSubject[256] = {0};
        CertGetNameStringW(pCert, CERT_NAME_ATTR_TYPE, 0, (void*)szOID_COMMON_NAME, 
                          szSubject, ARRAYSIZE(szSubject));

        if (_wcsicmp(szSubject, username.c_str()) == 0)
        {
            // Found matching certificate - get key provider info
            DWORD cbData = 0;
            if (CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &cbData))
            {
                std::vector<BYTE> provInfo(cbData);
                if (CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, 
                                                      &provInfo[0], &cbData))
                {
                    CRYPT_KEY_PROV_INFO* pProvInfo = (CRYPT_KEY_PROV_INFO*)&provInfo[0];
                    
                    pVscInfo->containerName = pProvInfo->pwszContainerName ? pProvInfo->pwszContainerName : L"";
                    pVscInfo->cspName = pProvInfo->pwszProvName ? pProvInfo->pwszProvName : _cspName;
                    pVscInfo->readerName = _readerName;
                    pVscInfo->cardName = _cardName;

                    LOG("Found VSC info: container=%S", pVscInfo->containerName.c_str());
                    hr = S_OK;
                    break;
                }
            }
        }
    }

    CertCloseStore(hStore, 0);

    if (FAILED(hr))
    {
        LOG("No matching certificate found for user");
    }

    return hr;
}

// Check if VSC has valid certificate
bool VSCManager::HasValidCertificate(const std::wstring& username)
{
    VSCInfo info;
    return SUCCEEDED(GetVSCInfo(username, &info));
}

// Delete certificate
HRESULT VSCManager::DeleteCertificate(const std::wstring& containerName)
{
    LOG("DeleteCertificate: container=%S", containerName.c_str());

    NCRYPT_PROV_HANDLE hProv = 0;
    SECURITY_STATUS status = NCryptOpenStorageProvider(
        &hProv,
        MS_SMART_CARD_KEY_STORAGE_PROVIDER,
        0);

    if (status != ERROR_SUCCESS)
    {
        return HRESULT_FROM_WIN32(status);
    }

    NCRYPT_KEY_HANDLE hKey = 0;
    status = NCryptOpenKey(
        hProv,
        &hKey,
        containerName.c_str(),
        0,
        0);

    if (status == ERROR_SUCCESS)
    {
        status = NCryptDeleteKey(hKey, 0);
        LOG("Key deleted: 0x%08x", status);
    }

    NCryptFreeObject(hProv);

    return HRESULT_FROM_WIN32(status);
}
