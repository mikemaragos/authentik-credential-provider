// CertificateHelper.cpp
// Certificate parsing, import, and management for PKINIT authentication
// Updated to use Authentik KSP for key storage

#include "CertificateHelper.h"
#include "Logger.h"
#include <bcrypt.h>
#include <sstream>
#include <algorithm>
#include <objbase.h>  // For CoCreateGuid, CoTaskMemAlloc

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "NCrypt.lib")
#pragma comment(lib, "BCrypt.lib")
#pragma comment(lib, "Ole32.lib")  // For CoCreateGuid

// ============================================================================
// KSP Integration - Store key in shared memory
// ============================================================================

// Store a key in the KSP's shared memory
static HRESULT StoreKeyInKSP(
    LPCWSTR wszContainerName,
    LPCWSTR wszUserName,
    const BYTE* pbPrivateKey,
    DWORD cbPrivateKey,
    const BYTE* pbCertificate,
    DWORD cbCertificate,
    DWORD dwKeySpec,
    DWORD dwValidityMinutes)
{
    LOG("StoreKeyInKSP: container=%S, keyLen=%d, certLen=%d",
        wszContainerName, cbPrivateKey, cbCertificate);

    HANDLE hMutex = NULL;
    HANDLE hSharedMem = NULL;
    PAUTHENTIK_KEY_STORE_HEADER pKeyStore = NULL;
    HRESULT hr = E_FAIL;

    // Create/open mutex
    hMutex = CreateMutexW(NULL, FALSE, AUTHENTIK_MUTEX_NAME);
    if (hMutex == NULL)
    {
        LOG("Failed to create mutex: %d", GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }

    // Create/open shared memory
    hSharedMem = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        AUTHENTIK_SHARED_MEM_SIZE,
        AUTHENTIK_SHARED_MEM_NAME);

    BOOL bCreated = (GetLastError() != ERROR_ALREADY_EXISTS);

    if (hSharedMem == NULL)
    {
        LOG("Failed to create shared memory: %d", GetLastError());
        CloseHandle(hMutex);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    // Map view
    pKeyStore = (PAUTHENTIK_KEY_STORE_HEADER)MapViewOfFile(
        hSharedMem,
        FILE_MAP_ALL_ACCESS,
        0, 0,
        AUTHENTIK_SHARED_MEM_SIZE);

    if (pKeyStore == NULL)
    {
        LOG("Failed to map shared memory: %d", GetLastError());
        CloseHandle(hSharedMem);
        CloseHandle(hMutex);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    WaitForSingleObject(hMutex, INFINITE);

    // Initialize if new
    if (bCreated || pKeyStore->dwMagic != AUTHENTIK_KEY_MAGIC)
    {
        pKeyStore->dwMagic = AUTHENTIK_KEY_MAGIC;
        pKeyStore->dwVersion = 1;
        pKeyStore->cKeys = 0;
        pKeyStore->cbTotalSize = sizeof(AUTHENTIK_KEY_STORE_HEADER);
        LOG("Initialized new key store");
    }

    // Calculate entry size
    DWORD cbEntry = AUTHENTIK_KEY_ENTRY_SIZE(cbPrivateKey, cbCertificate);

    // Check space
    DWORD cbAvailable = AUTHENTIK_SHARED_MEM_SIZE - pKeyStore->cbTotalSize;
    if (cbEntry > cbAvailable)
    {
        LOG("Not enough space in key store");
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    // Add entry
    {
        PAUTHENTIK_KEY_ENTRY pEntry = (PAUTHENTIK_KEY_ENTRY)
            ((PBYTE)pKeyStore + pKeyStore->cbTotalSize);

        pEntry->dwMagic = AUTHENTIK_KEY_MAGIC;
        pEntry->dwFlags = 0;
        pEntry->dwKeySpec = dwKeySpec;

        GetSystemTimeAsFileTime(&pEntry->ftCreated);

        // Calculate expiry
        DWORD validMins = dwValidityMinutes > 0 ? dwValidityMinutes : AUTHENTIK_DEFAULT_KEY_VALIDITY;
        ULARGE_INTEGER expiry;
        expiry.LowPart = pEntry->ftCreated.dwLowDateTime;
        expiry.HighPart = pEntry->ftCreated.dwHighDateTime;
        expiry.QuadPart += (ULONGLONG)validMins * 60 * 10000000;
        pEntry->ftExpires.dwLowDateTime = expiry.LowPart;
        pEntry->ftExpires.dwHighDateTime = expiry.HighPart;

        wcsncpy_s(pEntry->wszContainerName, AUTHENTIK_MAX_CONTAINER_NAME,
                  wszContainerName, _TRUNCATE);
        wcsncpy_s(pEntry->wszUserName, AUTHENTIK_MAX_USERNAME,
                  wszUserName ? wszUserName : L"", _TRUNCATE);

        pEntry->cbPrivateKey = cbPrivateKey;
        pEntry->cbCertificate = cbCertificate;

        memcpy(pEntry->rgbData, pbPrivateKey, cbPrivateKey);
        memcpy(pEntry->rgbData + cbPrivateKey, pbCertificate, cbCertificate);

        pKeyStore->cKeys++;
        pKeyStore->cbTotalSize += cbEntry;

        LOG("Key stored successfully: total keys=%d", pKeyStore->cKeys);
        hr = S_OK;
    }

cleanup:
    ReleaseMutex(hMutex);
    
    if (pKeyStore)
        UnmapViewOfFile(pKeyStore);
    if (hSharedMem)
        CloseHandle(hSharedMem);
    if (hMutex)
        CloseHandle(hMutex);

    return hr;
}

// ============================================================================
// CertificateHelper Implementation
// ============================================================================

CertificateHelper::CertificateHelper() :
    _hProvider(0)
{
    LOG("CertificateHelper::Constructor");

    // Generate unique container name for this session
    GUID guid;
    if (SUCCEEDED(CoCreateGuid(&guid)))
    {
        WCHAR wszGuid[40];
        StringFromGUID2(guid, wszGuid, ARRAYSIZE(wszGuid));
        _containerName = AUTHENTIK_KEY_PREFIX;
        _containerName += wszGuid;
        LOG("Container name: %S", _containerName.c_str());
    }
    else
    {
        // Fallback to tick count
        _containerName = AUTHENTIK_KEY_PREFIX;
        WCHAR wszTick[32];
        _ui64tow_s(GetTickCount64(), wszTick, ARRAYSIZE(wszTick), 16);
        _containerName += wszTick;
        LOG("Container name (fallback): %S", _containerName.c_str());
    }
}

CertificateHelper::~CertificateHelper()
{
    LOG("CertificateHelper::Destructor");

    if (_hProvider)
    {
        NCryptFreeObject(_hProvider);
        _hProvider = 0;
    }
}

HRESULT CertificateHelper::ParseAuthResponseForCertificate(
    const std::wstring& jsonResponse,
    CertificateBundle& bundle)
{
    LOG("ParseAuthResponseForCertificate");

    // Look for PFX data first (preferred)
    bundle.pfxBase64 = ParseJsonString(jsonResponse, L"pfx");
    bundle.pfxPassword = ParseJsonString(jsonResponse, L"pfx_password");

    // Also parse PEM data if available
    bundle.certificate = ParseJsonStringNarrow(jsonResponse, L"certificate");
    bundle.privateKey = ParseJsonStringNarrow(jsonResponse, L"private_key");

    // Parse user info
    bundle.username = ParseJsonString(jsonResponse, L"username");
    bundle.domain = ParseJsonString(jsonResponse, L"domain");
    bundle.upn = ParseJsonString(jsonResponse, L"upn");

    // Parse validity
    std::wstring validStr = ParseJsonString(jsonResponse, L"valid_minutes");
    if (!validStr.empty())
    {
        bundle.validMinutes = (DWORD)_wtoi(validStr.c_str());
        if (bundle.validMinutes == 0)
            bundle.validMinutes = AUTHENTIK_DEFAULT_KEY_VALIDITY;
    }

    if (bundle.HasPfx())
    {
        LOG("Found PFX data in response");
        return S_OK;
    }
    else if (bundle.HasPem())
    {
        LOG("Found PEM data in response");
        return S_OK;
    }
    else
    {
        LOG("No certificate data found in response");
        return E_FAIL;
    }
}


HRESULT CertificateHelper::ParsePfxBundle(CertificateBundle& bundle)
{
    LOG("ParsePfxBundle");

    if (!bundle.HasPfx())
    {
        LOG("No PFX data available");
        return E_INVALIDARG;
    }

    HRESULT hr = E_FAIL;

    // Decode base64 PFX
    std::vector<BYTE> pfxData;
    hr = Base64Decode(bundle.pfxBase64, pfxData);
    if (FAILED(hr))
    {
        LOG("Failed to decode PFX base64: 0x%08x", hr);
        return hr;
    }

    LOG("PFX decoded: %d bytes", (int)pfxData.size());

    // Create PFX blob
    CRYPT_DATA_BLOB pfxBlob;
    pfxBlob.cbData = (DWORD)pfxData.size();
    pfxBlob.pbData = pfxData.data();

    // Import PFX - we need CRYPT_EXPORTABLE to get the key out
    // Use user keyset for temporary storage
    HCERTSTORE hTempStore = PFXImportCertStore(
        &pfxBlob,
        bundle.pfxPassword.c_str(),
        CRYPT_EXPORTABLE | CRYPT_USER_KEYSET);

    if (hTempStore == NULL)
    {
        DWORD err = GetLastError();
        LOG("PFXImportCertStore (user) failed: %d, trying machine keyset", err);
        
        // Try with machine keyset
        hTempStore = PFXImportCertStore(
            &pfxBlob,
            bundle.pfxPassword.c_str(),
            CRYPT_EXPORTABLE | CRYPT_MACHINE_KEYSET);
    }

    if (hTempStore == NULL)
    {
        LOG("PFXImportCertStore failed: %d", GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }

    LOG("PFX imported to temporary store");

    // Find the certificate
    PCCERT_CONTEXT pCert = CertFindCertificateInStore(
        hTempStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_HAS_PRIVATE_KEY,
        NULL,
        NULL);

    if (pCert == NULL)
    {
        LOG("No cert with private key, trying any cert");
        pCert = CertEnumCertificatesInStore(hTempStore, NULL);
    }

    if (pCert == NULL)
    {
        LOG("No certificate found in PFX");
        CertCloseStore(hTempStore, 0);
        return E_FAIL;
    }

    // Log certificate subject
    WCHAR szSubject[256] = {0};
    CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0, NULL, szSubject, ARRAYSIZE(szSubject));
    LOG("Certificate subject: %S", szSubject);

    // Get the private key handle
    NCRYPT_KEY_HANDLE hKey = 0;
    DWORD dwKeySpec = 0;
    BOOL bCallerFreeKey = FALSE;

    BOOL bGotKey = CryptAcquireCertificatePrivateKey(
        pCert,
        CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
        NULL,
        &hKey,
        &dwKeySpec,
        &bCallerFreeKey);

    if (!bGotKey)
    {
        LOG("CryptAcquireCertificatePrivateKey (NCrypt) failed: %d", GetLastError());
        
        // Try without ONLY_NCRYPT flag
        bGotKey = CryptAcquireCertificatePrivateKey(
            pCert,
            CRYPT_ACQUIRE_SILENT_FLAG,
            NULL,
            &hKey,
            &dwKeySpec,
            &bCallerFreeKey);
            
        if (bGotKey)
        {
            LOG("Got key with generic acquire, keySpec=%d", dwKeySpec);
        }
    }

    if (bGotKey && hKey)
    {
        LOG("Got NCrypt key handle: 0x%p, keySpec=%d", (void*)hKey, dwKeySpec);
        bundle.hKey = hKey;
        
        // Export the private key blob for KSP storage
        DWORD cbKeyBlob = 0;
        SECURITY_STATUS status = NCryptExportKey(
            hKey,
            0,
            BCRYPT_RSAPRIVATE_BLOB,
            NULL,
            NULL,
            0,
            &cbKeyBlob,
            0);

        if (status == ERROR_SUCCESS && cbKeyBlob > 0)
        {
            bundle.privateKeyBlob.resize(cbKeyBlob);
            status = NCryptExportKey(
                hKey,
                0,
                BCRYPT_RSAPRIVATE_BLOB,
                NULL,
                bundle.privateKeyBlob.data(),
                cbKeyBlob,
                &cbKeyBlob,
                0);

            if (status == ERROR_SUCCESS)
            {
                LOG("Exported NCrypt private key: %d bytes", cbKeyBlob);
            }
            else
            {
                LOG("NCryptExportKey (data) failed: 0x%08x", status);
                bundle.privateKeyBlob.clear();
            }
        }
        else
        {
            LOG("NCryptExportKey (size) failed: 0x%08x, cbKeyBlob=%d", status, cbKeyBlob);
        }
    }
    else
    {
        LOG("Failed to acquire private key");
    }

    // Copy certificate to bundle
    bundle.pCertContext = CertDuplicateCertificateContext(pCert);
    
    // Create our own memory store
    bundle.hMemStore = CertOpenStore(
        CERT_STORE_PROV_MEMORY,
        0,
        0,
        CERT_STORE_CREATE_NEW_FLAG,
        NULL);

    if (bundle.hMemStore)
    {
        CertAddCertificateContextToStore(bundle.hMemStore, pCert, CERT_STORE_ADD_ALWAYS, NULL);
    }

    // Clean up - DON'T close hKey if we need it, but do close the temp store
    CertFreeCertificateContext(pCert);
    // Note: We keep hTempStore open if we still need hKey from it
    // Actually, the key should persist as long as bundle.hKey is valid
    CertCloseStore(hTempStore, 0);

    // If we got the key blob, we're good
    if (!bundle.privateKeyBlob.empty())
    {
        LOG("ParsePfxBundle succeeded with %d byte key blob", (int)bundle.privateKeyBlob.size());
        return S_OK;
    }

    // If we at least have the key handle, that might work
    if (bundle.hKey)
    {
        LOG("ParsePfxBundle: Have key handle but no blob - will try export later");
        return S_OK;
    }

    LOG("ParsePfxBundle: No private key obtained");
    return E_FAIL;
}
HRESULT CertificateHelper::ParseCertificateBundle(CertificateBundle& bundle)
{
    LOG("ParseCertificateBundle");

    // Prefer PFX if available
    if (bundle.HasPfx())
    {
        return ParsePfxBundle(bundle);
    }

    // Fall back to PEM
    if (!bundle.HasPem())
    {
        LOG("No certificate data available");
        return E_INVALIDARG;
    }

    HRESULT hr = E_FAIL;

    // Convert certificate PEM to DER
    std::vector<BYTE> certDer;
    hr = PemToDer(bundle.certificate,
        "-----BEGIN CERTIFICATE-----",
        "-----END CERTIFICATE-----",
        certDer);

    if (FAILED(hr))
    {
        LOG("Failed to convert certificate PEM to DER: 0x%08x", hr);
        return hr;
    }

    // Create certificate context
    bundle.pCertContext = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        certDer.data(),
        (DWORD)certDer.size());

    if (bundle.pCertContext == NULL)
    {
        LOG("CertCreateCertificateContext failed: %d", GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }

    // Convert private key PEM to DER
    std::vector<BYTE> keyDer;
    hr = PemToDer(bundle.privateKey,
        "-----BEGIN PRIVATE KEY-----",
        "-----END PRIVATE KEY-----",
        keyDer);

    if (FAILED(hr))
    {
        // Try RSA PRIVATE KEY format
        hr = PemToDer(bundle.privateKey,
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----",
            keyDer);
    }

    if (FAILED(hr))
    {
        LOG("Failed to convert private key PEM to DER: 0x%08x", hr);
        return hr;
    }

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
        // Continue anyway - might still work
    }

    return S_OK;
}

HRESULT CertificateHelper::ImportCertificateForPKINIT(CertificateBundle& bundle)
{
    LOG("ImportCertificateForPKINIT");

    // First parse the bundle if not already done
    if (bundle.pCertContext == NULL)
    {
        HRESULT hr = ParseCertificateBundle(bundle);
        if (FAILED(hr))
        {
            return hr;
        }
    }

    return S_OK;
}


HRESULT CertificateHelper::BuildCertificateLogon(
    const CertificateBundle& bundle,
    BYTE** ppPackage,
    DWORD* pcbPackage)
{
    LOG("BuildCertificateLogon - Using Authentik KSP");

    if (ppPackage == NULL || pcbPackage == NULL)
        return E_INVALIDARG;

    if (bundle.pCertContext == NULL)
    {
        LOG("No certificate context");
        return E_INVALIDARG;
    }

    HRESULT hr = E_FAIL;

    // ========================================================================
    // Step 1: Get the private key blob
    // ========================================================================

    std::vector<BYTE> privateKeyBlob;

    // First check if we already have the blob from ParsePfxBundle
    if (!bundle.privateKeyBlob.empty())
    {
        LOG("Using pre-extracted private key blob: %d bytes", (int)bundle.privateKeyBlob.size());
        privateKeyBlob = bundle.privateKeyBlob;
    }
    else if (bundle.hKey)
    {
        // Try to export from NCrypt handle
        LOG("Trying to export from NCrypt handle");
        DWORD cbKeyBlob = 0;
        SECURITY_STATUS status = NCryptExportKey(
            bundle.hKey,
            0,
            BCRYPT_RSAPRIVATE_BLOB,
            NULL,
            NULL,
            0,
            &cbKeyBlob,
            0);

        if (status == ERROR_SUCCESS && cbKeyBlob > 0)
        {
            privateKeyBlob.resize(cbKeyBlob);
            status = NCryptExportKey(
                bundle.hKey,
                0,
                BCRYPT_RSAPRIVATE_BLOB,
                NULL,
                privateKeyBlob.data(),
                cbKeyBlob,
                &cbKeyBlob,
                0);

            if (status != ERROR_SUCCESS)
            {
                LOG("NCryptExportKey failed: 0x%08x", status);
                privateKeyBlob.clear();
            }
            else
            {
                LOG("Exported private key: %d bytes", cbKeyBlob);
            }
        }
        else
        {
            LOG("NCryptExportKey size query failed: 0x%08x", status);
        }
    }

    if (privateKeyBlob.empty())
    {
        LOG("Failed to get private key blob");
        return E_FAIL;
    }

    // ========================================================================
    // Step 2: Get certificate as DER blob
    // ========================================================================

    std::vector<BYTE> certBlob(
        bundle.pCertContext->pbCertEncoded,
        bundle.pCertContext->pbCertEncoded + bundle.pCertContext->cbCertEncoded);

    LOG("Certificate DER: %d bytes", (int)certBlob.size());

    // ========================================================================
    // Step 3: Store key in KSP shared memory
    // ========================================================================

    hr = StoreKeyInKSP(
        _containerName.c_str(),
        bundle.username.c_str(),
        privateKeyBlob.data(),
        (DWORD)privateKeyBlob.size(),
        certBlob.data(),
        (DWORD)certBlob.size(),
        AT_KEYEXCHANGE,
        bundle.validMinutes > 0 ? bundle.validMinutes : AUTHENTIK_DEFAULT_KEY_VALIDITY);

    if (FAILED(hr))
    {
        LOG("Failed to store key in KSP: 0x%08x", hr);
        return hr;
    }

    LOG("Key stored in KSP shared memory");

    // ========================================================================
    // Step 4: Build CSP Info structure
    // ========================================================================

    BYTE* pCspInfo = NULL;
    DWORD cbCspInfo = 0;

    hr = BuildCspInfo(
        _containerName,
        AUTHENTIK_KSP_NAME,
        &pCspInfo,
        &cbCspInfo);

    if (FAILED(hr))
    {
        LOG("Failed to build CSP info: 0x%08x", hr);
        return hr;
    }

    LOG("CSP Info built: %d bytes", cbCspInfo);

    // ========================================================================
    // Step 5: Build KERB_CERTIFICATE_LOGON structure
    // ========================================================================

    // Calculate sizes
    std::wstring domain = bundle.domain.empty() ? L"" : bundle.domain;
    std::wstring username = bundle.username.empty() ? L"" : bundle.username;
    std::wstring pin = L"";  // No PIN needed - OTP was already validated

    DWORD cbDomain = (DWORD)((domain.length() + 1) * sizeof(WCHAR));
    DWORD cbUsername = (DWORD)((username.length() + 1) * sizeof(WCHAR));
    DWORD cbPin = (DWORD)((pin.length() + 1) * sizeof(WCHAR));

    // Total size = structure + strings + CSP info
    DWORD cbTotal = sizeof(KERB_CERTIFICATE_LOGON) + cbDomain + cbUsername + cbPin + cbCspInfo;

    LOG("Building KERB_CERTIFICATE_LOGON: total=%d bytes", cbTotal);

    // Allocate buffer
    BYTE* pBuffer = (BYTE*)CoTaskMemAlloc(cbTotal);
    if (pBuffer == NULL)
    {
        CoTaskMemFree(pCspInfo);
        return E_OUTOFMEMORY;
    }

    ZeroMemory(pBuffer, cbTotal);

    // Fill structure
    KERB_CERTIFICATE_LOGON* pLogon = (KERB_CERTIFICATE_LOGON*)pBuffer;
    pLogon->MessageType = (KERB_LOGON_SUBMIT_TYPE)AUTHENTIK_KerbCertificateLogon;
    pLogon->Flags = 0;
    pLogon->CspDataLength = cbCspInfo;

    // String buffer starts after structure
    BYTE* pStringBuffer = pBuffer + sizeof(KERB_CERTIFICATE_LOGON);

    // Domain name
    if (!domain.empty())
    {
        memcpy(pStringBuffer, domain.c_str(), cbDomain);
        pLogon->DomainName.Length = (USHORT)(domain.length() * sizeof(WCHAR));
        pLogon->DomainName.MaximumLength = (USHORT)cbDomain;
        pLogon->DomainName.Buffer = (PWSTR)(pStringBuffer - pBuffer);  // Offset from base
        pStringBuffer += cbDomain;
    }

    // User name
    if (!username.empty())
    {
        memcpy(pStringBuffer, username.c_str(), cbUsername);
        pLogon->UserName.Length = (USHORT)(username.length() * sizeof(WCHAR));
        pLogon->UserName.MaximumLength = (USHORT)cbUsername;
        pLogon->UserName.Buffer = (PWSTR)(pStringBuffer - pBuffer);
        pStringBuffer += cbUsername;
    }

    // PIN (empty)
    pLogon->Pin.Length = 0;
    pLogon->Pin.MaximumLength = (USHORT)cbPin;
    pLogon->Pin.Buffer = (PWSTR)(pStringBuffer - pBuffer);
    pStringBuffer += cbPin;

    // CSP Data
    memcpy(pStringBuffer, pCspInfo, cbCspInfo);
    pLogon->CspData = (PUCHAR)(pStringBuffer - pBuffer);  // Offset
    pStringBuffer += cbCspInfo;

    CoTaskMemFree(pCspInfo);

    // Verify we used the expected amount
    DWORD cbUsed = (DWORD)(pStringBuffer - pBuffer);
    if (cbUsed != cbTotal)
    {
        LOG("WARNING: Buffer size mismatch - expected %d, used %d", cbTotal, cbUsed);
    }

    *ppPackage = pBuffer;
    *pcbPackage = cbTotal;

    LOG("KERB_CERTIFICATE_LOGON built successfully: %d bytes", cbTotal);

    // Clear sensitive data
    SecureZeroMemory(privateKeyBlob.data(), privateKeyBlob.size());

    return S_OK;
}
HRESULT CertificateHelper::BuildCspInfo(
    const std::wstring& containerName,
    const std::wstring& providerName,
    BYTE** ppCspInfo,
    DWORD* pcbCspInfo)
{
    LOG("BuildCspInfo: container=%S, provider=%S",
        containerName.c_str(), providerName.c_str());

    if (ppCspInfo == NULL || pcbCspInfo == NULL)
        return E_INVALIDARG;

    // String values
    std::wstring cardName = L"Authentik Virtual Card";
    std::wstring readerName = L"Authentik Virtual Reader";

    // Calculate buffer size
    DWORD cbCardName = (DWORD)((cardName.length() + 1) * sizeof(WCHAR));
    DWORD cbReaderName = (DWORD)((readerName.length() + 1) * sizeof(WCHAR));
    DWORD cbContainerName = (DWORD)((containerName.length() + 1) * sizeof(WCHAR));
    DWORD cbProviderName = (DWORD)((providerName.length() + 1) * sizeof(WCHAR));

    DWORD cbTotal = sizeof(AUTHENTIK_SMARTCARD_CSP_INFO) - sizeof(WCHAR) +
                    cbCardName + cbReaderName + cbContainerName + cbProviderName;

    // Allocate buffer
    BYTE* pBuffer = (BYTE*)CoTaskMemAlloc(cbTotal);
    if (pBuffer == NULL)
        return E_OUTOFMEMORY;

    ZeroMemory(pBuffer, cbTotal);

    PAUTHENTIK_SMARTCARD_CSP_INFO pCspInfo = (PAUTHENTIK_SMARTCARD_CSP_INFO)pBuffer;

    // Fill structure
    pCspInfo->dwCspInfoLen = cbTotal;
    pCspInfo->MessageType = 1;
    pCspInfo->ContextInformation = NULL;
    pCspInfo->flags = 0;
    pCspInfo->KeySpec = AT_KEYEXCHANGE;

    // Calculate offsets (from start of bBuffer)
    DWORD offset = 0;

    // Card name
    pCspInfo->nCardNameOffset = offset;
    memcpy(&pCspInfo->bBuffer[offset / sizeof(WCHAR)], cardName.c_str(), cbCardName);
    offset += cbCardName;

    // Reader name
    pCspInfo->nReaderNameOffset = offset;
    memcpy((BYTE*)pCspInfo->bBuffer + offset, readerName.c_str(), cbReaderName);
    offset += cbReaderName;

    // Container name
    pCspInfo->nContainerNameOffset = offset;
    memcpy((BYTE*)pCspInfo->bBuffer + offset, containerName.c_str(), cbContainerName);
    offset += cbContainerName;

    // CSP/KSP name
    pCspInfo->nCSPNameOffset = offset;
    memcpy((BYTE*)pCspInfo->bBuffer + offset, providerName.c_str(), cbProviderName);

    *ppCspInfo = pBuffer;
    *pcbCspInfo = cbTotal;

    LOG("CSP Info built: %d bytes, offsets: card=%d, reader=%d, container=%d, csp=%d",
        cbTotal, pCspInfo->nCardNameOffset, pCspInfo->nReaderNameOffset,
        pCspInfo->nContainerNameOffset, pCspInfo->nCSPNameOffset);

    return S_OK;
}

void CertificateHelper::CleanupCertificate(CertificateBundle& bundle)
{
    LOG("CleanupCertificate");
    bundle.Cleanup();
}

// ============================================================================
// Private Helper Methods
// ============================================================================

HRESULT CertificateHelper::PemToDer(
    const std::string& pem,
    const char* pemHeader,
    const char* pemFooter,
    std::vector<BYTE>& der)
{
    // Find header and footer
    size_t headerPos = pem.find(pemHeader);
    if (headerPos == std::string::npos)
        return E_INVALIDARG;

    size_t footerPos = pem.find(pemFooter);
    if (footerPos == std::string::npos)
        return E_INVALIDARG;

    // Extract base64 content
    size_t startPos = headerPos + strlen(pemHeader);
    std::string base64Content = pem.substr(startPos, footerPos - startPos);

    // Remove whitespace
    base64Content.erase(
        std::remove_if(base64Content.begin(), base64Content.end(), ::isspace),
        base64Content.end());

    // Decode base64
    DWORD cbDecoded = 0;
    if (!CryptStringToBinaryA(
        base64Content.c_str(),
        (DWORD)base64Content.length(),
        CRYPT_STRING_BASE64,
        NULL,
        &cbDecoded,
        NULL, NULL))
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    der.resize(cbDecoded);
    if (!CryptStringToBinaryA(
        base64Content.c_str(),
        (DWORD)base64Content.length(),
        CRYPT_STRING_BASE64,
        der.data(),
        &cbDecoded,
        NULL, NULL))
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    return S_OK;
}

HRESULT CertificateHelper::ImportPrivateKey(
    const std::vector<BYTE>& keyDer,
    NCRYPT_KEY_HANDLE* phKey)
{
    LOG("ImportPrivateKey: %d bytes", (int)keyDer.size());

    // Open storage provider
    if (_hProvider == 0)
    {
        SECURITY_STATUS status = NCryptOpenStorageProvider(
            &_hProvider,
            MS_KEY_STORAGE_PROVIDER,  // Use MS KSP for import
            0);

        if (status != ERROR_SUCCESS)
        {
            LOG("NCryptOpenStorageProvider failed: 0x%08x", status);
            return HRESULT_FROM_NT(status);
        }
    }

    // Try to decode as PKCS#8 first
    CRYPT_PRIVATE_KEY_INFO* pKeyInfo = NULL;
    DWORD cbKeyInfo = 0;

    if (CryptDecodeObjectEx(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        PKCS_PRIVATE_KEY_INFO,
        keyDer.data(),
        (DWORD)keyDer.size(),
        CRYPT_DECODE_ALLOC_FLAG,
        NULL,
        &pKeyInfo,
        &cbKeyInfo))
    {
        LOG("Decoded as PKCS#8");

        // Import using NCrypt
        NCryptBufferDesc bufferDesc = {0};
        NCryptBuffer buffer = {0};

        buffer.BufferType = NCRYPTBUFFER_PKCS_KEY_NAME;
        buffer.cbBuffer = (DWORD)((_containerName.length() + 1) * sizeof(WCHAR));
        buffer.pvBuffer = (PVOID)_containerName.c_str();

        bufferDesc.ulVersion = NCRYPTBUFFER_VERSION;
        bufferDesc.cBuffers = 1;
        bufferDesc.pBuffers = &buffer;

        SECURITY_STATUS status = NCryptImportKey(
            _hProvider,
            0,
            NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
            &bufferDesc,
            phKey,
            (PBYTE)keyDer.data(),
            (DWORD)keyDer.size(),
            NCRYPT_OVERWRITE_KEY_FLAG);

        LocalFree(pKeyInfo);

        if (status == ERROR_SUCCESS)
        {
            LOG("Key imported successfully");
            return S_OK;
        }

        LOG("NCryptImportKey failed: 0x%08x", status);
    }

    // Try as raw RSA key
    LOG("Trying to decode as RSA private key");

    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        LOG("BCryptOpenAlgorithmProvider failed: 0x%08x", status);
        return HRESULT_FROM_NT(status);
    }

    // Try importing as BCRYPT_RSAPRIVATE_BLOB
    BCRYPT_KEY_HANDLE hBcryptKey = NULL;
    status = BCryptImportKeyPair(
        hAlg,
        NULL,
        LEGACY_RSAPRIVATE_BLOB,  // Try legacy format
        &hBcryptKey,
        (PUCHAR)keyDer.data(),
        (ULONG)keyDer.size(),
        0);

    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (BCRYPT_SUCCESS(status))
    {
        // Export and import to NCrypt
        ULONG cbBlob = 0;
        BCryptExportKey(hBcryptKey, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, 0, &cbBlob, 0);

        std::vector<BYTE> blob(cbBlob);
        BCryptExportKey(hBcryptKey, NULL, BCRYPT_RSAPRIVATE_BLOB, blob.data(), cbBlob, &cbBlob, 0);
        BCryptDestroyKey(hBcryptKey);

        SECURITY_STATUS ncStatus = NCryptImportKey(
            _hProvider,
            0,
            BCRYPT_RSAPRIVATE_BLOB,
            NULL,
            phKey,
            blob.data(),
            cbBlob,
            NCRYPT_OVERWRITE_KEY_FLAG);

        if (ncStatus == ERROR_SUCCESS)
        {
            LOG("Key imported via BCrypt->NCrypt");
            return S_OK;
        }
    }

    LOG("Failed to import private key");
    return E_FAIL;
}

HRESULT CertificateHelper::AssociateKeyWithCert(
    PCCERT_CONTEXT pCert,
    NCRYPT_KEY_HANDLE hKey)
{
    LOG("AssociateKeyWithCert");

    CRYPT_KEY_PROV_INFO keyProvInfo = {0};
    keyProvInfo.pwszContainerName = (LPWSTR)_containerName.c_str();
    keyProvInfo.pwszProvName = (LPWSTR)MS_KEY_STORAGE_PROVIDER;
    keyProvInfo.dwProvType = 0;
    keyProvInfo.dwFlags = CRYPT_MACHINE_KEYSET;
    keyProvInfo.dwKeySpec = AT_KEYEXCHANGE;

    if (!CertSetCertificateContextProperty(
        pCert,
        CERT_KEY_PROV_INFO_PROP_ID,
        0,
        &keyProvInfo))
    {
        LOG("CertSetCertificateContextProperty failed: %d", GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }

    return S_OK;
}

std::wstring CertificateHelper::ParseJsonString(
    const std::wstring& json,
    const std::wstring& key)
{
    std::wstring searchKey = L"\"" + key + L"\"";
    size_t keyPos = json.find(searchKey);
    if (keyPos == std::wstring::npos)
        return L"";

    size_t colonPos = json.find(L':', keyPos);
    if (colonPos == std::wstring::npos)
        return L"";

    size_t valueStart = json.find(L'"', colonPos);
    if (valueStart == std::wstring::npos)
        return L"";

    valueStart++;
    size_t valueEnd = json.find(L'"', valueStart);
    if (valueEnd == std::wstring::npos)
        return L"";

    return json.substr(valueStart, valueEnd - valueStart);
}

std::string CertificateHelper::ParseJsonStringNarrow(
    const std::wstring& json,
    const std::wstring& key)
{
    std::wstring wideValue = ParseJsonString(json, key);
    if (wideValue.empty())
        return "";

    int size = WideCharToMultiByte(CP_UTF8, 0, wideValue.c_str(), -1, NULL, 0, NULL, NULL);
    if (size <= 0)
        return "";

    std::string result(size - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wideValue.c_str(), -1, &result[0], size, NULL, NULL);
    return result;
}

HRESULT CertificateHelper::Base64Decode(
    const std::wstring& base64,
    std::vector<BYTE>& decoded)
{
    // Convert wide to narrow
    int size = WideCharToMultiByte(CP_UTF8, 0, base64.c_str(), -1, NULL, 0, NULL, NULL);
    if (size <= 0)
        return E_INVALIDARG;

    std::string base64Narrow(size - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, base64.c_str(), -1, &base64Narrow[0], size, NULL, NULL);

    // Decode
    DWORD cbDecoded = 0;
    if (!CryptStringToBinaryA(
        base64Narrow.c_str(),
        (DWORD)base64Narrow.length(),
        CRYPT_STRING_BASE64,
        NULL,
        &cbDecoded,
        NULL, NULL))
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    decoded.resize(cbDecoded);
    if (!CryptStringToBinaryA(
        base64Narrow.c_str(),
        (DWORD)base64Narrow.length(),
        CRYPT_STRING_BASE64,
        decoded.data(),
        &cbDecoded,
        NULL, NULL))
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    return S_OK;
}

// ============================================================================
// Factory Function
// ============================================================================

HRESULT CertificateHelper_CreateInstance(CertificateHelper** ppHelper)
{
    if (ppHelper == NULL)
        return E_INVALIDARG;

    *ppHelper = new(std::nothrow) CertificateHelper();
    if (*ppHelper == NULL)
        return E_OUTOFMEMORY;

    return S_OK;
}

