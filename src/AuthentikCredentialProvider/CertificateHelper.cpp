// CertificateHelper.cpp
// Certificate parsing, import, and management for PKINIT authentication

#include "CertificateHelper.h"
#include "Logger.h"
#include <objbase.h>
#include <shlwapi.h>
#include <bcrypt.h>
#include <algorithm>
#include <sstream>
#include <new>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "NCrypt.lib")
#pragma comment(lib, "BCrypt.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Shlwapi.lib")

// Microsoft Software Key Storage Provider
static const WCHAR* MS_KEY_STORAGE_PROVIDER_NAME = L"Microsoft Software Key Storage Provider";

// Constructor
CertificateHelper::CertificateHelper() :
    _hProvider(0)
{
    LOG("CertificateHelper::Constructor");
    
    // Open the key storage provider
    SECURITY_STATUS status = NCryptOpenStorageProvider(
        &_hProvider,
        MS_KEY_STORAGE_PROVIDER_NAME,
        0);
    
    if (status != ERROR_SUCCESS)
    {
        LOG("Failed to open key storage provider: 0x%08x", status);
        _hProvider = 0;
    }
    
    // Generate unique container name for this session
    GUID guid;
    if (SUCCEEDED(CoCreateGuid(&guid)))
    {
        WCHAR guidStr[40];
        StringFromGUID2(guid, guidStr, 40);
        _containerName = L"AuthentikPKINIT_";
        _containerName += guidStr;
    }
    else
    {
        // Fallback to timestamp-based name
        _containerName = L"AuthentikPKINIT_";
        _containerName += std::to_wstring(GetTickCount64());
    }
    
    LOG("Container name: %S", _containerName.c_str());
}

// Destructor
CertificateHelper::~CertificateHelper()
{
    LOG("CertificateHelper::Destructor");
    
    if (_hProvider)
    {
        NCryptFreeObject(_hProvider);
        _hProvider = 0;
    }
}

// Factory function
HRESULT CertificateHelper_CreateInstance(CertificateHelper** ppHelper)
{
    if (!ppHelper)
        return E_INVALIDARG;
    
    *ppHelper = new(std::nothrow) CertificateHelper();
    return (*ppHelper) ? S_OK : E_OUTOFMEMORY;
}

// Parse JSON response from Authentik
HRESULT CertificateHelper::ParseAuthResponseForCertificate(
    const std::wstring& jsonResponse,
    CertificateBundle& bundle)
{
    LOG("ParseAuthResponseForCertificate");
    
    // Parse certificate (PEM format)
    bundle.certificate = ParseJsonStringNarrow(jsonResponse, L"certificate");
    if (bundle.certificate.empty())
    {
        LOG("No certificate in response");
        return E_FAIL;
    }
    
    // Parse private key (PEM format)
    bundle.privateKey = ParseJsonStringNarrow(jsonResponse, L"private_key");
    if (bundle.privateKey.empty())
    {
        LOG("No private key in response");
        return E_FAIL;
    }
    
    // Parse user info
    bundle.username = ParseJsonString(jsonResponse, L"username");
    bundle.domain = ParseJsonString(jsonResponse, L"domain");
    bundle.upn = ParseJsonString(jsonResponse, L"upn");
    
    // Parse validity (optional)
    std::wstring validStr = ParseJsonString(jsonResponse, L"valid_minutes");
    if (!validStr.empty())
    {
        bundle.validMinutes = (DWORD)_wtoi(validStr.c_str());
    }
    
    LOG("Parsed certificate bundle: user=%S, domain=%S, upn=%S",
        bundle.username.c_str(), bundle.domain.c_str(), bundle.upn.c_str());
    
    return S_OK;
}

// Parse PEM certificate and private key
HRESULT CertificateHelper::ParseCertificateBundle(CertificateBundle& bundle)
{
    LOG("ParseCertificateBundle");
    
    HRESULT hr;
    std::vector<BYTE> certDer;
    std::vector<BYTE> keyDer;
    
    // Convert certificate PEM to DER
    hr = PemToDer(bundle.certificate, 
                  "-----BEGIN CERTIFICATE-----",
                  "-----END CERTIFICATE-----",
                  certDer);
    if (FAILED(hr))
    {
        LOG("Failed to parse certificate PEM: 0x%08x", hr);
        return hr;
    }
    
    // Convert private key PEM to DER
    // Try PKCS#8 format first, then RSA format
    hr = PemToDer(bundle.privateKey,
                  "-----BEGIN PRIVATE KEY-----",
                  "-----END PRIVATE KEY-----",
                  keyDer);
    if (FAILED(hr))
    {
        // Try RSA format
        hr = PemToDer(bundle.privateKey,
                      "-----BEGIN RSA PRIVATE KEY-----",
                      "-----END RSA PRIVATE KEY-----",
                      keyDer);
        if (FAILED(hr))
        {
            LOG("Failed to parse private key PEM: 0x%08x", hr);
            return hr;
        }
    }
    
    LOG("Parsed PEM - Cert: %d bytes, Key: %d bytes", (int)certDer.size(), (int)keyDer.size());
    
    // Create in-memory certificate store
    bundle.hMemStore = CertOpenStore(
        CERT_STORE_PROV_MEMORY,
        0,
        0,
        CERT_STORE_CREATE_NEW_FLAG,
        NULL);
    
    if (!bundle.hMemStore)
    {
        LOG("Failed to create memory store: %d", GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }
    
    // Add certificate to store
    if (!CertAddEncodedCertificateToStore(
        bundle.hMemStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        certDer.data(),
        (DWORD)certDer.size(),
        CERT_STORE_ADD_NEW,
        &bundle.pCertContext))
    {
        LOG("Failed to add certificate to store: %d", GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }
    
    LOG("Certificate added to memory store");
    
    // Import private key
    hr = ImportPrivateKey(keyDer, &bundle.hKey);
    if (FAILED(hr))
    {
        LOG("Failed to import private key: 0x%08x", hr);
        return hr;
    }
    
    // Associate key with certificate
    hr = AssociateKeyWithCert(bundle.pCertContext, bundle.hKey);
    if (FAILED(hr))
    {
        LOG("Failed to associate key with certificate: 0x%08x", hr);
        return hr;
    }
    
    LOG("Certificate bundle parsed successfully");
    return S_OK;
}

// Import certificate for PKINIT
HRESULT CertificateHelper::ImportCertificateForPKINIT(CertificateBundle& bundle)
{
    LOG("ImportCertificateForPKINIT");
    
    // First parse the bundle if not already done
    if (!bundle.pCertContext)
    {
        HRESULT hr = ParseCertificateBundle(bundle);
        if (FAILED(hr))
        {
            return hr;
        }
    }
    
    // The certificate is already in our memory store with key associated
    // For PKINIT, Windows will use the key through the certificate context
    
    LOG("Certificate ready for PKINIT");
    return S_OK;
}

// Build KERB_CERTIFICATE_LOGON structure
HRESULT CertificateHelper::BuildCertificateLogon(
    const CertificateBundle& bundle,
    BYTE** ppPackage,
    DWORD* pcbPackage)
{
    LOG("BuildCertificateLogon: user=%S, domain=%S", 
        bundle.username.c_str(), bundle.domain.c_str());
    
    if (!ppPackage || !pcbPackage)
        return E_INVALIDARG;
    
    HRESULT hr;
    
    // Build CSP info structure
    BYTE* pCspInfo = NULL;
    DWORD cbCspInfo = 0;
    
    hr = BuildCspInfo(_containerName, MS_KEY_STORAGE_PROVIDER_NAME, &pCspInfo, &cbCspInfo);
    if (FAILED(hr))
    {
        LOG("Failed to build CSP info: 0x%08x", hr);
        return hr;
    }
    
    // Calculate sizes
    DWORD cbDomain = (DWORD)((bundle.domain.length() + 1) * sizeof(WCHAR));
    DWORD cbUsername = (DWORD)((bundle.username.length() + 1) * sizeof(WCHAR));
    DWORD cbPin = sizeof(WCHAR); // Empty pin (just null terminator)
    
    // Size of base structure (approximation for x64)
    DWORD cbStructure = 64; // Conservative estimate
    DWORD cbTotal = cbStructure + cbDomain + cbUsername + cbPin + cbCspInfo;
    
    LOG("Building certificate logon - Structure: %d, Domain: %d, User: %d, CSP: %d, Total: %d",
        cbStructure, cbDomain, cbUsername, cbCspInfo, cbTotal);
    
    // Allocate buffer
    BYTE* pBuffer = (BYTE*)CoTaskMemAlloc(cbTotal);
    if (!pBuffer)
    {
        CoTaskMemFree(pCspInfo);
        return E_OUTOFMEMORY;
    }
    
    ZeroMemory(pBuffer, cbTotal);
    
    // Set message type at offset 0
    *((DWORD*)pBuffer) = AUTHENTIK_KerbCertificateLogon; // 13 = KerbCertificateLogon
    
    // String data starts after the fixed structure
    BYTE* pStringBuffer = pBuffer + cbStructure;
    
    // Copy domain string
    memcpy(pStringBuffer, bundle.domain.c_str(), cbDomain);
    // Set DomainName UNICODE_STRING (offset 8 on x64)
    UNICODE_STRING* pDomain = (UNICODE_STRING*)(pBuffer + 8);
    pDomain->Length = (USHORT)(bundle.domain.length() * sizeof(WCHAR));
    pDomain->MaximumLength = (USHORT)cbDomain;
    pDomain->Buffer = (PWSTR)pStringBuffer;
    pStringBuffer += cbDomain;
    
    // Copy username string
    memcpy(pStringBuffer, bundle.username.c_str(), cbUsername);
    // Set UserName UNICODE_STRING (offset 24 on x64)
    UNICODE_STRING* pUser = (UNICODE_STRING*)(pBuffer + 24);
    pUser->Length = (USHORT)(bundle.username.length() * sizeof(WCHAR));
    pUser->MaximumLength = (USHORT)cbUsername;
    pUser->Buffer = (PWSTR)pStringBuffer;
    pStringBuffer += cbUsername;
    
    // Pin is empty
    *pStringBuffer = L'\0';
    UNICODE_STRING* pPin = (UNICODE_STRING*)(pBuffer + 40);
    pPin->Length = 0;
    pPin->MaximumLength = (USHORT)cbPin;
    pPin->Buffer = (PWSTR)pStringBuffer;
    pStringBuffer += cbPin;
    
    // Set Flags (offset 56)
    *((ULONG*)(pBuffer + 56)) = KERB_CERTIFICATE_LOGON_FLAG_CHECK_DUPLICATES;
    
    // Set CspDataLength (offset 60)
    *((ULONG*)(pBuffer + 60)) = cbCspInfo;
    
    // Copy CSP data
    memcpy(pStringBuffer, pCspInfo, cbCspInfo);
    
    CoTaskMemFree(pCspInfo);
    
    *ppPackage = pBuffer;
    *pcbPackage = cbTotal;
    
    LOG("Certificate logon structure built: %d bytes", cbTotal);
    
    return S_OK;
}

// Build CSP Info structure
HRESULT CertificateHelper::BuildCspInfo(
    const std::wstring& containerName,
    const std::wstring& providerName,
    BYTE** ppCspInfo,
    DWORD* pcbCspInfo)
{
    LOG("BuildCspInfo: container=%S, provider=%S", 
        containerName.c_str(), providerName.c_str());
    
    if (!ppCspInfo || !pcbCspInfo)
        return E_INVALIDARG;
    
    // Calculate sizes for strings (null-terminated wide strings)
    DWORD cbCardName = sizeof(WCHAR);  // Empty card name
    DWORD cbReaderName = sizeof(WCHAR); // Empty reader name
    DWORD cbContainerName = (DWORD)((containerName.length() + 1) * sizeof(WCHAR));
    DWORD cbProviderName = (DWORD)((providerName.length() + 1) * sizeof(WCHAR));
    
    // Calculate total size
    DWORD cbStrings = cbCardName + cbReaderName + cbContainerName + cbProviderName;
    DWORD cbTotal = sizeof(AUTHENTIK_SMARTCARD_CSP_INFO) - sizeof(WCHAR) + cbStrings;
    
    // Allocate buffer
    BYTE* pBuffer = (BYTE*)CoTaskMemAlloc(cbTotal);
    if (!pBuffer)
        return E_OUTOFMEMORY;
    
    ZeroMemory(pBuffer, cbTotal);
    
    AUTHENTIK_SMARTCARD_CSP_INFO* pCspInfo = (AUTHENTIK_SMARTCARD_CSP_INFO*)pBuffer;
    
    // Fill structure
    pCspInfo->dwCspInfoLen = cbTotal;
    pCspInfo->MessageType = 1;
    pCspInfo->flags = 0;
    pCspInfo->KeySpec = AT_KEYEXCHANGE;
    
    // String offsets are relative to start of bBuffer
    DWORD offset = 0;
    
    // Card name (empty)
    pCspInfo->nCardNameOffset = offset;
    pCspInfo->bBuffer[offset / sizeof(WCHAR)] = L'\0';
    offset += cbCardName;
    
    // Reader name (empty)
    pCspInfo->nReaderNameOffset = offset;
    *((WCHAR*)((BYTE*)pCspInfo->bBuffer + offset)) = L'\0';
    offset += cbReaderName;
    
    // Container name
    pCspInfo->nContainerNameOffset = offset;
    memcpy((BYTE*)pCspInfo->bBuffer + offset, containerName.c_str(), cbContainerName);
    offset += cbContainerName;
    
    // CSP/Provider name
    pCspInfo->nCSPNameOffset = offset;
    memcpy((BYTE*)pCspInfo->bBuffer + offset, providerName.c_str(), cbProviderName);
    
    *ppCspInfo = pBuffer;
    *pcbCspInfo = cbTotal;
    
    LOG("CSP info built: %d bytes", cbTotal);
    
    return S_OK;
}

// Clean up certificate handles
void CertificateHelper::CleanupCertificate(CertificateBundle& bundle)
{
    bundle.Cleanup();
}

// Convert PEM to DER
HRESULT CertificateHelper::PemToDer(
    const std::string& pem,
    const char* pemHeader,
    const char* pemFooter,
    std::vector<BYTE>& der)
{
    // Find header and footer
    size_t headerPos = pem.find(pemHeader);
    size_t footerPos = pem.find(pemFooter);
    
    if (headerPos == std::string::npos || footerPos == std::string::npos)
    {
        LOG("PEM header/footer not found");
        return E_INVALIDARG;
    }
    
    // Extract base64 content
    size_t contentStart = headerPos + strlen(pemHeader);
    std::string base64Content = pem.substr(contentStart, footerPos - contentStart);
    
    // Remove whitespace
    base64Content.erase(
        std::remove_if(base64Content.begin(), base64Content.end(), 
                       [](char c) { return c == '\n' || c == '\r' || c == ' '; }),
        base64Content.end());
    
    // Decode base64
    DWORD cbBinary = 0;
    if (!CryptStringToBinaryA(
        base64Content.c_str(),
        (DWORD)base64Content.length(),
        CRYPT_STRING_BASE64,
        NULL,
        &cbBinary,
        NULL,
        NULL))
    {
        LOG("Failed to get binary size: %d", GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }
    
    der.resize(cbBinary);
    
    if (!CryptStringToBinaryA(
        base64Content.c_str(),
        (DWORD)base64Content.length(),
        CRYPT_STRING_BASE64,
        der.data(),
        &cbBinary,
        NULL,
        NULL))
    {
        LOG("Failed to decode base64: %d", GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }
    
    der.resize(cbBinary);
    return S_OK;
}

// Import private key from DER
HRESULT CertificateHelper::ImportPrivateKey(
    const std::vector<BYTE>& keyDer,
    NCRYPT_KEY_HANDLE* phKey)
{
    LOG("ImportPrivateKey: %d bytes", (int)keyDer.size());
    
    if (!_hProvider)
    {
        LOG("No key storage provider");
        return E_FAIL;
    }
    
    // First, decode the PKCS#8 or RSA key blob
    DWORD cbKeyBlob = 0;
    PCRYPT_PRIVATE_KEY_INFO pKeyInfo = NULL;
    
    // Try to decode as PKCS#8 private key info
    if (!CryptDecodeObjectEx(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        PKCS_PRIVATE_KEY_INFO,
        keyDer.data(),
        (DWORD)keyDer.size(),
        CRYPT_DECODE_ALLOC_FLAG,
        NULL,
        &pKeyInfo,
        &cbKeyBlob))
    {
        // Try as RSA private key directly
        DWORD dwErr = GetLastError();
        LOG("Not PKCS#8, trying RSA format: %d", dwErr);
        
        // For RSA format, we need to import differently
        NCRYPT_KEY_HANDLE hKey = 0;
        
        // Create a new key in the provider
        SECURITY_STATUS status = NCryptCreatePersistedKey(
            _hProvider,
            &hKey,
            BCRYPT_RSA_ALGORITHM,
            _containerName.c_str(),
            0,
            NCRYPT_OVERWRITE_KEY_FLAG);
        
        if (status != ERROR_SUCCESS)
        {
            LOG("Failed to create key: 0x%08x", status);
            return HRESULT_FROM_NT(status);
        }
        
        // For now, we'll need to handle this case differently
        NCryptFreeObject(hKey);
        return E_NOTIMPL;
    }
    
    // We have PKCS#8 key info, now import via NCrypt
    BCRYPT_RSAKEY_BLOB* pRsaBlob = NULL;
    DWORD cbRsaBlob = 0;
    
    // Decode the RSA private key from the PKCS#8 container
    if (!CryptDecodeObjectEx(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        CNG_RSA_PRIVATE_KEY_BLOB,
        pKeyInfo->PrivateKey.pbData,
        pKeyInfo->PrivateKey.cbData,
        CRYPT_DECODE_ALLOC_FLAG,
        NULL,
        &pRsaBlob,
        &cbRsaBlob))
    {
        DWORD dwErr = GetLastError();
        LocalFree(pKeyInfo);
        LOG("Failed to decode RSA key: %d", dwErr);
        return HRESULT_FROM_WIN32(dwErr);
    }
    
    // Import the key into NCrypt
    SECURITY_STATUS status = NCryptImportKey(
        _hProvider,
        0,
        BCRYPT_RSAPRIVATE_BLOB,
        NULL,
        phKey,
        (PBYTE)pRsaBlob,
        cbRsaBlob,
        NCRYPT_DO_NOT_FINALIZE_FLAG);
    
    if (status != ERROR_SUCCESS)
    {
        LocalFree(pRsaBlob);
        LocalFree(pKeyInfo);
        LOG("Failed to import key: 0x%08x", status);
        return HRESULT_FROM_NT(status);
    }
    
    // Set key name for the container
    status = NCryptSetProperty(
        *phKey,
        NCRYPT_NAME_PROPERTY,
        (PBYTE)_containerName.c_str(),
        (DWORD)((_containerName.length() + 1) * sizeof(WCHAR)),
        0);
    
    // Finalize the key
    status = NCryptFinalizeKey(*phKey, 0);
    
    LocalFree(pRsaBlob);
    LocalFree(pKeyInfo);
    
    if (status != ERROR_SUCCESS)
    {
        NCryptFreeObject(*phKey);
        *phKey = 0;
        LOG("Failed to finalize key: 0x%08x", status);
        return HRESULT_FROM_NT(status);
    }
    
    LOG("Private key imported successfully");
    return S_OK;
}

// Associate private key with certificate
HRESULT CertificateHelper::AssociateKeyWithCert(
    PCCERT_CONTEXT pCert,
    NCRYPT_KEY_HANDLE hKey)
{
    LOG("AssociateKeyWithCert");
    
    // Set up the key provider info
    CRYPT_KEY_PROV_INFO keyProvInfo;
    ZeroMemory(&keyProvInfo, sizeof(keyProvInfo));
    keyProvInfo.pwszContainerName = const_cast<LPWSTR>(_containerName.c_str());
    keyProvInfo.pwszProvName = const_cast<LPWSTR>(MS_KEY_STORAGE_PROVIDER_NAME);
    keyProvInfo.dwProvType = 0; // CNG provider
    keyProvInfo.dwFlags = 0;
    keyProvInfo.dwKeySpec = AT_KEYEXCHANGE;
    
    // Set the property on the certificate
    if (!CertSetCertificateContextProperty(
        pCert,
        CERT_KEY_PROV_INFO_PROP_ID,
        0,
        &keyProvInfo))
    {
        LOG("Failed to set key provider info: %d", GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }
    
    // Also set the NCRYPT key handle directly
    CERT_KEY_CONTEXT keyContext;
    ZeroMemory(&keyContext, sizeof(keyContext));
    keyContext.cbSize = sizeof(keyContext);
    keyContext.hNCryptKey = hKey;
    keyContext.dwKeySpec = CERT_NCRYPT_KEY_SPEC;
    
    if (!CertSetCertificateContextProperty(
        pCert,
        CERT_KEY_CONTEXT_PROP_ID,
        0,
        &keyContext))
    {
        LOG("Failed to set key context: %d", GetLastError());
        // Non-fatal, continue
    }
    
    LOG("Key associated with certificate");
    return S_OK;
}

// Parse JSON string value (simple implementation)
std::wstring CertificateHelper::ParseJsonString(
    const std::wstring& json,
    const std::wstring& key)
{
    // Look for "key":"value" or "key": "value"
    std::wstring searchKey = L"\"" + key + L"\"";
    size_t keyPos = json.find(searchKey);
    
    if (keyPos == std::wstring::npos)
        return L"";
    
    // Find the colon
    size_t colonPos = json.find(L':', keyPos + searchKey.length());
    if (colonPos == std::wstring::npos)
        return L"";
    
    // Find the opening quote
    size_t startQuote = json.find(L'"', colonPos + 1);
    if (startQuote == std::wstring::npos)
        return L"";
    
    // Find the closing quote (handle escaped quotes)
    size_t endQuote = startQuote + 1;
    while (endQuote < json.length())
    {
        if (json[endQuote] == L'"' && json[endQuote - 1] != L'\\')
            break;
        endQuote++;
    }
    
    if (endQuote >= json.length())
        return L"";
    
    std::wstring value = json.substr(startQuote + 1, endQuote - startQuote - 1);
    
    // Handle escape sequences
    size_t pos = 0;
    while ((pos = value.find(L"\\n", pos)) != std::wstring::npos)
    {
        value.replace(pos, 2, L"\n");
        pos++;
    }
    pos = 0;
    while ((pos = value.find(L"\\\"", pos)) != std::wstring::npos)
    {
        value.replace(pos, 2, L"\"");
        pos++;
    }
    
    return value;
}

// Parse JSON string to narrow string
std::string CertificateHelper::ParseJsonStringNarrow(
    const std::wstring& json,
    const std::wstring& key)
{
    std::wstring wideValue = ParseJsonString(json, key);
    
    if (wideValue.empty())
        return "";
    
    // Convert to narrow string
    int size = WideCharToMultiByte(CP_UTF8, 0, wideValue.c_str(), -1, NULL, 0, NULL, NULL);
    if (size <= 0)
        return "";
    
    std::string result(size - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wideValue.c_str(), -1, &result[0], size, NULL, NULL);
    
    return result;
}
