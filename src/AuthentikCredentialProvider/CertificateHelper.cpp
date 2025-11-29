// CertificateHelper.cpp
// Certificate parsing, import, and PKINIT credential building

#include "CertificateHelper.h"
#include "Logger.h"
#include <wincrypt.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <sstream>
#include <algorithm>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "NCrypt.lib")
#pragma comment(lib, "BCrypt.lib")

// Microsoft Software Key Storage Provider
#define MS_KEY_STORAGE_PROVIDER L"Microsoft Software Key Storage Provider"

CertificateHelper::CertificateHelper() : _hProvider(0)
{
    LOG("CertificateHelper::Constructor");
    
    // Open the Microsoft Software Key Storage Provider
    SECURITY_STATUS status = NCryptOpenStorageProvider(
        &_hProvider,
        MS_KEY_STORAGE_PROVIDER,
        0);
    
    if (status != ERROR_SUCCESS)
    {
        LOG_E("Failed to open storage provider: 0x%08x", status);
        _hProvider = 0;
    }
    
    // Generate unique container name for this session
    GUID guid;
    CoCreateGuid(&guid);
    WCHAR guidStr[64];
    StringFromGUID2(guid, guidStr, ARRAYSIZE(guidStr));
    _containerName = L"AuthentikPwdless_";
    _containerName += guidStr;
    
    LOG("Container name: %S", _containerName.c_str());
}

CertificateHelper::~CertificateHelper()
{
    LOG("CertificateHelper::Destructor");
    
    if (_hProvider)
    {
        // Try to delete the ephemeral key
        NCRYPT_KEY_HANDLE hKey = 0;
        SECURITY_STATUS status = NCryptOpenKey(
            _hProvider,
            &hKey,
            _containerName.c_str(),
            0,
            0);
        
        if (status == ERROR_SUCCESS && hKey)
        {
            NCryptDeleteKey(hKey, 0);
            // Note: NCryptDeleteKey frees the handle, so don't call NCryptFreeObject
        }
        
        NCryptFreeObject(_hProvider);
        _hProvider = 0;
    }
}

// Parse JSON response from Authentik
HRESULT CertificateHelper::ParseAuthResponseForCertificate(
    const std::wstring& jsonResponse,
    CertificateBundle& bundle)
{
    LOG("ParseAuthResponseForCertificate");
    
    // Check if response contains certificate_bundle
    if (jsonResponse.find(L"certificate_bundle") == std::wstring::npos)
    {
        LOG_E("Response does not contain certificate_bundle");
        return E_FAIL;
    }
    
    // Parse certificate bundle fields
    // Note: This is a simple parser - consider using a proper JSON library
    
    bundle.certificate = ParseJsonStringNarrow(jsonResponse, L"certificate");
    bundle.privateKey = ParseJsonStringNarrow(jsonResponse, L"private_key");
    bundle.username = ParseJsonString(jsonResponse, L"username");
    bundle.domain = ParseJsonString(jsonResponse, L"domain");
    bundle.upn = ParseJsonString(jsonResponse, L"upn");
    
    // Parse valid_minutes if present
    std::wstring validMinStr = ParseJsonString(jsonResponse, L"valid_minutes");
    if (!validMinStr.empty())
    {
        bundle.validMinutes = _wtoi(validMinStr.c_str());
    }
    
    // Parse CA chain (array)
    // For now, we'll handle a single CA cert in the chain
    bundle.caChain.clear();
    std::string caCert = ParseJsonStringNarrow(jsonResponse, L"ca_cert");
    if (!caCert.empty())
    {
        bundle.caChain.push_back(caCert);
    }
    
    LOG("Parsed certificate bundle:");
    LOG("  Username: %S", bundle.username.c_str());
    LOG("  Domain: %S", bundle.domain.c_str());
    LOG("  UPN: %S", bundle.upn.c_str());
    LOG("  Certificate length: %d", bundle.certificate.length());
    LOG("  Private key length: %d", bundle.privateKey.length());
    LOG("  CA chain entries: %d", bundle.caChain.size());
    
    if (bundle.certificate.empty() || bundle.privateKey.empty())
    {
        LOG_E("Missing certificate or private key");
        return E_FAIL;
    }
    
    return S_OK;
}

// Parse PEM certificate and private key
HRESULT CertificateHelper::ParseCertificateBundle(CertificateBundle& bundle)
{
    LOG("ParseCertificateBundle");
    
    HRESULT hr = S_OK;
    
    // Convert certificate from PEM to DER
    std::vector<BYTE> certDer;
    hr = PemToDer(bundle.certificate, 
                  "-----BEGIN CERTIFICATE-----",
                  "-----END CERTIFICATE-----",
                  certDer);
    if (FAILED(hr))
    {
        LOG_E("Failed to convert certificate PEM to DER: 0x%08x", hr);
        return hr;
    }
    
    LOG("Certificate DER size: %d bytes", certDer.size());
    LogHex("Certificate DER (first 64 bytes)", certDer.data(), min(64, (DWORD)certDer.size()));
    
    // Create in-memory certificate store
    bundle.hMemStore = CertOpenStore(
        CERT_STORE_PROV_MEMORY,
        0,
        0,
        CERT_STORE_CREATE_NEW_FLAG,
        NULL);
    
    if (!bundle.hMemStore)
    {
        LOG_E("Failed to create memory certificate store: %d", GetLastError());
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
        LOG_E("Failed to add certificate to store: %d", GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }
    
    LOG("Certificate added to store");
    
    // Parse and import private key
    std::vector<BYTE> keyDer;
    
    // Try PKCS#8 format first
    hr = PemToDer(bundle.privateKey,
                  "-----BEGIN PRIVATE KEY-----",
                  "-----END PRIVATE KEY-----",
                  keyDer);
    
    if (FAILED(hr))
    {
        // Try RSA private key format
        hr = PemToDer(bundle.privateKey,
                      "-----BEGIN RSA PRIVATE KEY-----",
                      "-----END RSA PRIVATE KEY-----",
                      keyDer);
    }
    
    if (FAILED(hr))
    {
        LOG_E("Failed to convert private key PEM to DER: 0x%08x", hr);
        return hr;
    }
    
    LOG("Private key DER size: %d bytes", keyDer.size());
    
    // Import private key
    hr = ImportPrivateKey(keyDer, &bundle.hKey);
    if (FAILED(hr))
    {
        LOG_E("Failed to import private key: 0x%08x", hr);
        return hr;
    }
    
    LOG("Private key imported successfully");
    
    // Associate key with certificate
    hr = AssociateKeyWithCert(bundle.pCertContext, bundle.hKey);
    if (FAILED(hr))
    {
        LOG_E("Failed to associate key with certificate: 0x%08x", hr);
        return hr;
    }
    
    LOG("Key associated with certificate");
    
    // Secure clear the DER buffers
    SecureZeroMemory(keyDer.data(), keyDer.size());
    
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
    
    // Verify the certificate has required EKUs for smart card logon
    PCERT_EXTENSION pEkuExt = CertFindExtension(
        szOID_ENHANCED_KEY_USAGE,
        bundle.pCertContext->pCertInfo->cExtension,
        bundle.pCertContext->pCertInfo->rgExtension);
    
    if (pEkuExt)
    {
        DWORD cbUsage = 0;
        CryptDecodeObject(
            X509_ASN_ENCODING,
            X509_ENHANCED_KEY_USAGE,
            pEkuExt->Value.pbData,
            pEkuExt->Value.cbData,
            0,
            NULL,
            &cbUsage);
        
        if (cbUsage > 0)
        {
            PCERT_ENHKEY_USAGE pUsage = (PCERT_ENHKEY_USAGE)LocalAlloc(LPTR, cbUsage);
            if (pUsage)
            {
                if (CryptDecodeObject(
                        X509_ASN_ENCODING,
                        X509_ENHANCED_KEY_USAGE,
                        pEkuExt->Value.pbData,
                        pEkuExt->Value.cbData,
                        0,
                        pUsage,
                        &cbUsage))
                {
                    LOG("Certificate EKUs:");
                    for (DWORD i = 0; i < pUsage->cUsageIdentifier; i++)
                    {
                        LOG("  %s", pUsage->rgpszUsageIdentifier[i]);
                    }
                }
                LocalFree(pUsage);
            }
        }
    }
    else
    {
        LOG_W("No EKU extension found in certificate");
    }
    
    return S_OK;
}

// Build KERB_CERTIFICATE_LOGON structure
HRESULT CertificateHelper::BuildCertificateLogon(
    const CertificateBundle& bundle,
    BYTE** ppPackage,
    DWORD* pcbPackage)
{
    LOG("BuildCertificateLogon");
    
    if (!ppPackage || !pcbPackage)
    {
        return E_INVALIDARG;
    }
    
    // Build CSP info first
    BYTE* pCspInfo = nullptr;
    DWORD cbCspInfo = 0;
    
    HRESULT hr = BuildCspInfo(
        _containerName,
        MS_KEY_STORAGE_PROVIDER,
        &pCspInfo,
        &cbCspInfo);
    
    if (FAILED(hr))
    {
        LOG_E("Failed to build CSP info: 0x%08x", hr);
        return hr;
    }
    
    // Calculate sizes
    DWORD cbDomain = (DWORD)((bundle.domain.length() + 1) * sizeof(WCHAR));
    DWORD cbUsername = (DWORD)((bundle.username.length() + 1) * sizeof(WCHAR));
    DWORD cbPin = sizeof(WCHAR); // Empty pin (just null terminator)
    
    // Total size: structure + strings + CSP data
    DWORD cbTotal = sizeof(KERB_CERTIFICATE_LOGON) + cbDomain + cbUsername + cbPin + cbCspInfo;
    
    LOG("Building KERB_CERTIFICATE_LOGON:");
    LOG("  Domain: %S (%d bytes)", bundle.domain.c_str(), cbDomain);
    LOG("  Username: %S (%d bytes)", bundle.username.c_str(), cbUsername);
    LOG("  CSP Info: %d bytes", cbCspInfo);
    LOG("  Total: %d bytes", cbTotal);
    
    // Allocate buffer
    BYTE* pBuffer = (BYTE*)CoTaskMemAlloc(cbTotal);
    if (!pBuffer)
    {
        CoTaskMemFree(pCspInfo);
        return E_OUTOFMEMORY;
    }
    
    ZeroMemory(pBuffer, cbTotal);
    
    // Fill structure
    KERB_CERTIFICATE_LOGON* pLogon = (KERB_CERTIFICATE_LOGON*)pBuffer;
    pLogon->MessageType = (KERB_LOGON_SUBMIT_TYPE)KerbCertificateLogon;
    pLogon->Flags = KERB_CERTIFICATE_LOGON_FLAG_CHECK_DUPLICATES;
    
    // String buffer starts after structure
    BYTE* pStrings = pBuffer + sizeof(KERB_CERTIFICATE_LOGON);
    
    // Copy domain name
    memcpy(pStrings, bundle.domain.c_str(), cbDomain);
    pLogon->DomainName.Buffer = (PWSTR)pStrings;
    pLogon->DomainName.Length = (USHORT)(bundle.domain.length() * sizeof(WCHAR));
    pLogon->DomainName.MaximumLength = (USHORT)cbDomain;
    pStrings += cbDomain;
    
    // Copy username
    memcpy(pStrings, bundle.username.c_str(), cbUsername);
    pLogon->UserName.Buffer = (PWSTR)pStrings;
    pLogon->UserName.Length = (USHORT)(bundle.username.length() * sizeof(WCHAR));
    pLogon->UserName.MaximumLength = (USHORT)cbUsername;
    pStrings += cbUsername;
    
    // Empty PIN
    *(WCHAR*)pStrings = L'\0';
    pLogon->Pin.Buffer = (PWSTR)pStrings;
    pLogon->Pin.Length = 0;
    pLogon->Pin.MaximumLength = (USHORT)cbPin;
    pStrings += cbPin;
    
    // Copy CSP data
    memcpy(pStrings, pCspInfo, cbCspInfo);
    pLogon->CspData = pStrings;
    pLogon->CspDataLength = cbCspInfo;
    
    // Free CSP info buffer (we copied it)
    CoTaskMemFree(pCspInfo);
    
    *ppPackage = pBuffer;
    *pcbPackage = cbTotal;
    
    LOG("KERB_CERTIFICATE_LOGON built successfully");
    
    return S_OK;
}

// Build CSP Info structure
HRESULT CertificateHelper::BuildCspInfo(
    const std::wstring& containerName,
    const std::wstring& providerName,
    BYTE** ppCspInfo,
    DWORD* pcbCspInfo)
{
    LOG("BuildCspInfo");
    
    // Card name and reader name can be empty for software keys
    std::wstring cardName = L"";
    std::wstring readerName = L"";
    
    // Calculate sizes (including null terminators)
    DWORD cbCardName = (DWORD)((cardName.length() + 1) * sizeof(WCHAR));
    DWORD cbReaderName = (DWORD)((readerName.length() + 1) * sizeof(WCHAR));
    DWORD cbContainerName = (DWORD)((containerName.length() + 1) * sizeof(WCHAR));
    DWORD cbProviderName = (DWORD)((providerName.length() + 1) * sizeof(WCHAR));
    
    // Total size
    DWORD cbStrings = cbCardName + cbReaderName + cbContainerName + cbProviderName;
    DWORD cbTotal = sizeof(KERB_SMARTCARD_CSP_INFO) - sizeof(WCHAR) + cbStrings;
    
    // Allocate
    BYTE* pBuffer = (BYTE*)CoTaskMemAlloc(cbTotal);
    if (!pBuffer)
    {
        return E_OUTOFMEMORY;
    }
    
    ZeroMemory(pBuffer, cbTotal);
    
    KERB_SMARTCARD_CSP_INFO* pCspInfo = (KERB_SMARTCARD_CSP_INFO*)pBuffer;
    
    pCspInfo->dwCspInfoLen = cbTotal;
    pCspInfo->MessageType = 1;
    pCspInfo->ContextInformation = nullptr;
    pCspInfo->flags = 0;
    pCspInfo->KeySpec = AT_KEYEXCHANGE;
    
    // Set offsets (relative to bBuffer)
    DWORD offset = 0;
    
    // Card name
    pCspInfo->nCardNameOffset = offset;
    memcpy(&pCspInfo->bBuffer[offset / sizeof(WCHAR)], cardName.c_str(), cbCardName);
    offset += cbCardName;
    
    // Reader name  
    pCspInfo->nReaderNameOffset = offset;
    memcpy(&pCspInfo->bBuffer[offset / sizeof(WCHAR)], readerName.c_str(), cbReaderName);
    offset += cbReaderName;
    
    // Container name
    pCspInfo->nContainerNameOffset = offset;
    memcpy(&pCspInfo->bBuffer[offset / sizeof(WCHAR)], containerName.c_str(), cbContainerName);
    offset += cbContainerName;
    
    // CSP/Provider name
    pCspInfo->nCSPNameOffset = offset;
    memcpy(&pCspInfo->bBuffer[offset / sizeof(WCHAR)], providerName.c_str(), cbProviderName);
    
    LOG("CSP Info built:");
    LOG("  Container: %S (offset %d)", containerName.c_str(), pCspInfo->nContainerNameOffset);
    LOG("  Provider: %S (offset %d)", providerName.c_str(), pCspInfo->nCSPNameOffset);
    LOG("  Total size: %d bytes", cbTotal);
    
    *ppCspInfo = pBuffer;
    *pcbCspInfo = cbTotal;
    
    return S_OK;
}

// Clean up certificate handles
void CertificateHelper::CleanupCertificate(CertificateBundle& bundle)
{
    LOG("CleanupCertificate");
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
        LOG_E("PEM header/footer not found");
        return E_FAIL;
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
    DWORD cbDecoded = 0;
    if (!CryptStringToBinaryA(
            base64Content.c_str(),
            (DWORD)base64Content.length(),
            CRYPT_STRING_BASE64,
            NULL,
            &cbDecoded,
            NULL,
            NULL))
    {
        LOG_E("Failed to get base64 decode size: %d", GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }
    
    der.resize(cbDecoded);
    
    if (!CryptStringToBinaryA(
            base64Content.c_str(),
            (DWORD)base64Content.length(),
            CRYPT_STRING_BASE64,
            der.data(),
            &cbDecoded,
            NULL,
            NULL))
    {
        LOG_E("Failed to decode base64: %d", GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }
    
    der.resize(cbDecoded);
    return S_OK;
}

// Import private key from DER
HRESULT CertificateHelper::ImportPrivateKey(
    const std::vector<BYTE>& keyDer,
    NCRYPT_KEY_HANDLE* phKey)
{
    LOG("ImportPrivateKey");
    
    if (!_hProvider)
    {
        LOG_E("Storage provider not initialized");
        return E_FAIL;
    }
    
    // First, decode the PKCS#8 private key info
    DWORD cbKeyInfo = 0;
    
    // Try PKCS#8 format
    BOOL bResult = CryptDecodeObjectEx(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        PKCS_PRIVATE_KEY_INFO,
        keyDer.data(),
        (DWORD)keyDer.size(),
        CRYPT_DECODE_ALLOC_FLAG,
        NULL,
        &cbKeyInfo,
        &cbKeyInfo);
    
    CRYPT_PRIVATE_KEY_INFO* pKeyInfo = nullptr;
    
    if (bResult || GetLastError() == ERROR_MORE_DATA)
    {
        bResult = CryptDecodeObjectEx(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            PKCS_PRIVATE_KEY_INFO,
            keyDer.data(),
            (DWORD)keyDer.size(),
            CRYPT_DECODE_ALLOC_FLAG,
            NULL,
            &pKeyInfo,
            &cbKeyInfo);
    }
    
    if (!bResult)
    {
        LOG_E("Failed to decode private key info: %d", GetLastError());
        
        // Try importing as raw RSA key
        // This handles the case where key is not in PKCS#8 format
        LOG("Attempting direct RSA key import");
        
        // Create ephemeral key
        SECURITY_STATUS status = NCryptCreatePersistedKey(
            _hProvider,
            phKey,
            NCRYPT_RSA_ALGORITHM,
            _containerName.c_str(),
            0,
            NCRYPT_OVERWRITE_KEY_FLAG);
        
        if (status != ERROR_SUCCESS)
        {
            LOG_E("NCryptCreatePersistedKey failed: 0x%08x", status);
            return HRESULT_FROM_NT(status);
        }
        
        // Import the key blob
        BCRYPT_RSAKEY_BLOB* pRsaBlob = nullptr;
        DWORD cbRsaBlob = 0;
        
        // Decode RSA private key
        bResult = CryptDecodeObjectEx(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            CNG_RSA_PRIVATE_KEY_BLOB,
            keyDer.data(),
            (DWORD)keyDer.size(),
            CRYPT_DECODE_ALLOC_FLAG,
            NULL,
            &pRsaBlob,
            &cbRsaBlob);
        
        if (!bResult)
        {
            LOG_E("Failed to decode RSA private key: %d", GetLastError());
            NCryptFreeObject(*phKey);
            *phKey = 0;
            return HRESULT_FROM_WIN32(GetLastError());
        }
        
        // Set the key property
        status = NCryptSetProperty(
            *phKey,
            NCRYPT_RSA_PRIVATE_KEY_BLOB,
            (PBYTE)pRsaBlob,
            cbRsaBlob,
            0);
        
        LocalFree(pRsaBlob);
        
        if (status != ERROR_SUCCESS)
        {
            LOG_E("NCryptSetProperty failed: 0x%08x", status);
            NCryptFreeObject(*phKey);
            *phKey = 0;
            return HRESULT_FROM_NT(status);
        }
        
        // Finalize the key
        status = NCryptFinalizeKey(*phKey, 0);
        if (status != ERROR_SUCCESS)
        {
            LOG_E("NCryptFinalizeKey failed: 0x%08x", status);
            NCryptFreeObject(*phKey);
            *phKey = 0;
            return HRESULT_FROM_NT(status);
        }
        
        LOG("RSA key imported successfully");
        return S_OK;
    }
    
    // Import using CNG
    NCRYPT_KEY_HANDLE hKey = 0;
    
    // Use NCryptImportKey with PKCS8 blob
    SECURITY_STATUS status = NCryptImportKey(
        _hProvider,
        0,
        NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
        NULL,
        &hKey,
        (PBYTE)keyDer.data(),
        (DWORD)keyDer.size(),
        NCRYPT_DO_NOT_FINALIZE_FLAG);
    
    if (pKeyInfo)
    {
        LocalFree(pKeyInfo);
    }
    
    if (status != ERROR_SUCCESS)
    {
        LOG_E("NCryptImportKey failed: 0x%08x", status);
        return HRESULT_FROM_NT(status);
    }
    
    // Set key name
    status = NCryptSetProperty(
        hKey,
        NCRYPT_NAME_PROPERTY,
        (PBYTE)_containerName.c_str(),
        (DWORD)((_containerName.length() + 1) * sizeof(WCHAR)),
        0);
    
    if (status != ERROR_SUCCESS)
    {
        LOG_W("Failed to set key name: 0x%08x", status);
        // Continue anyway
    }
    
    // Finalize the key
    status = NCryptFinalizeKey(hKey, 0);
    if (status != ERROR_SUCCESS)
    {
        LOG_E("NCryptFinalizeKey failed: 0x%08x", status);
        NCryptFreeObject(hKey);
        return HRESULT_FROM_NT(status);
    }
    
    *phKey = hKey;
    LOG("Private key imported and finalized");
    
    return S_OK;
}

// Associate private key with certificate
HRESULT CertificateHelper::AssociateKeyWithCert(
    PCCERT_CONTEXT pCert,
    NCRYPT_KEY_HANDLE hKey)
{
    LOG("AssociateKeyWithCert");
    
    CRYPT_KEY_PROV_INFO keyProvInfo = {0};
    
    keyProvInfo.pwszContainerName = (LPWSTR)_containerName.c_str();
    keyProvInfo.pwszProvName = MS_KEY_STORAGE_PROVIDER;
    keyProvInfo.dwProvType = 0; // CNG provider
    keyProvInfo.dwFlags = NCRYPT_SILENT_FLAG;
    keyProvInfo.dwKeySpec = AT_KEYEXCHANGE;
    
    if (!CertSetCertificateContextProperty(
            pCert,
            CERT_KEY_PROV_INFO_PROP_ID,
            0,
            &keyProvInfo))
    {
        LOG_E("Failed to set key prov info: %d", GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }
    
    // Also set the NCRYPT handle directly
    CERT_KEY_CONTEXT keyContext = {0};
    keyContext.cbSize = sizeof(keyContext);
    keyContext.hNCryptKey = hKey;
    keyContext.dwKeySpec = CERT_NCRYPT_KEY_SPEC;
    
    if (!CertSetCertificateContextProperty(
            pCert,
            CERT_KEY_CONTEXT_PROP_ID,
            0,
            &keyContext))
    {
        LOG_W("Failed to set key context: %d (non-fatal)", GetLastError());
        // Continue anyway - key prov info should be sufficient
    }
    
    LOG("Key associated with certificate");
    return S_OK;
}

// Simple JSON string parser
std::wstring CertificateHelper::ParseJsonString(
    const std::wstring& json,
    const std::wstring& key)
{
    std::wstring searchKey = L"\"" + key + L"\"";
    size_t keyPos = json.find(searchKey);
    
    if (keyPos == std::wstring::npos)
    {
        return L"";
    }
    
    // Find the colon after the key
    size_t colonPos = json.find(L':', keyPos + searchKey.length());
    if (colonPos == std::wstring::npos)
    {
        return L"";
    }
    
    // Find the opening quote
    size_t valueStart = json.find(L'"', colonPos + 1);
    if (valueStart == std::wstring::npos)
    {
        return L"";
    }
    
    // Find the closing quote (handle escaped quotes)
    size_t valueEnd = valueStart + 1;
    while (valueEnd < json.length())
    {
        if (json[valueEnd] == L'"' && json[valueEnd - 1] != L'\\')
        {
            break;
        }
        valueEnd++;
    }
    
    if (valueEnd >= json.length())
    {
        return L"";
    }
    
    std::wstring value = json.substr(valueStart + 1, valueEnd - valueStart - 1);
    
    // Unescape
    size_t pos = 0;
    while ((pos = value.find(L"\\n", pos)) != std::wstring::npos)
    {
        value.replace(pos, 2, L"\n");
        pos += 1;
    }
    pos = 0;
    while ((pos = value.find(L"\\\"", pos)) != std::wstring::npos)
    {
        value.replace(pos, 2, L"\"");
        pos += 1;
    }
    
    return value;
}

std::string CertificateHelper::ParseJsonStringNarrow(
    const std::wstring& json,
    const std::wstring& key)
{
    std::wstring wideValue = ParseJsonString(json, key);
    
    if (wideValue.empty())
    {
        return "";
    }
    
    // Convert to narrow string
    int size = WideCharToMultiByte(CP_UTF8, 0, wideValue.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0)
    {
        return "";
    }
    
    std::string result(size - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wideValue.c_str(), -1, &result[0], size, nullptr, nullptr);
    
    return result;
}

// Factory function
HRESULT CertificateHelper_CreateInstance(CertificateHelper** ppHelper)
{
    if (!ppHelper)
    {
        return E_INVALIDARG;
    }
    
    *ppHelper = new (std::nothrow) CertificateHelper();
    if (!*ppHelper)
    {
        return E_OUTOFMEMORY;
    }
    
    return S_OK;
}
