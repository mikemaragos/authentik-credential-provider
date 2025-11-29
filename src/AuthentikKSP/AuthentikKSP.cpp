// AuthentikKSP.cpp
// Authentik Key Storage Provider Implementation
// 
// This KSP allows Windows Kerberos to perform PKINIT authentication
// using certificates issued by Authentik without a physical smart card.

#include "AuthentikKSP.h"
#include <stdio.h>
#include <new>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")

// ============================================================================
// Logging
// ============================================================================

#ifdef _DEBUG
#define KSP_LOG(fmt, ...) \
    do { \
        char _buf[1024]; \
        _snprintf_s(_buf, sizeof(_buf), _TRUNCATE, "[AuthentikKSP] " fmt "\n", ##__VA_ARGS__); \
        OutputDebugStringA(_buf); \
    } while(0)
#else
#define KSP_LOG(fmt, ...) ((void)0)
#endif

// ============================================================================
// Global State
// ============================================================================

static HANDLE g_hSharedMem = NULL;
static PAUTHENTIK_KEY_STORE_HEADER g_pKeyStore = NULL;
static HANDLE g_hMutex = NULL;
static BCRYPT_ALG_HANDLE g_hRsaAlg = NULL;

// ============================================================================
// Internal Helper Functions
// ============================================================================

static BOOL InitializeKeyStore()
{
    if (g_pKeyStore != NULL)
        return TRUE;

    KSP_LOG("InitializeKeyStore");

    // Create or open mutex
    g_hMutex = CreateMutexW(NULL, FALSE, AUTHENTIK_MUTEX_NAME);
    if (g_hMutex == NULL)
    {
        KSP_LOG("Failed to create mutex: %d", GetLastError());
        return FALSE;
    }

    // Create or open shared memory
    g_hSharedMem = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        AUTHENTIK_SHARED_MEM_SIZE,
        AUTHENTIK_SHARED_MEM_NAME);

    BOOL bCreated = (GetLastError() != ERROR_ALREADY_EXISTS);

    if (g_hSharedMem == NULL)
    {
        KSP_LOG("Failed to create shared memory: %d", GetLastError());
        return FALSE;
    }

    // Map the view
    g_pKeyStore = (PAUTHENTIK_KEY_STORE_HEADER)MapViewOfFile(
        g_hSharedMem,
        FILE_MAP_ALL_ACCESS,
        0, 0,
        AUTHENTIK_SHARED_MEM_SIZE);

    if (g_pKeyStore == NULL)
    {
        KSP_LOG("Failed to map shared memory: %d", GetLastError());
        CloseHandle(g_hSharedMem);
        g_hSharedMem = NULL;
        return FALSE;
    }

    // Initialize if newly created
    if (bCreated)
    {
        WaitForSingleObject(g_hMutex, INFINITE);
        g_pKeyStore->dwMagic = AUTHENTIK_KEY_MAGIC;
        g_pKeyStore->dwVersion = 1;
        g_pKeyStore->cKeys = 0;
        g_pKeyStore->cbTotalSize = sizeof(AUTHENTIK_KEY_STORE_HEADER);
        ReleaseMutex(g_hMutex);
        KSP_LOG("Initialized new key store");
    }
    else
    {
        KSP_LOG("Opened existing key store with %d keys", g_pKeyStore->cKeys);
    }

    // Initialize BCrypt RSA algorithm
    if (g_hRsaAlg == NULL)
    {
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &g_hRsaAlg,
            BCRYPT_RSA_ALGORITHM,
            NULL,
            0);

        if (!BCRYPT_SUCCESS(status))
        {
            KSP_LOG("Failed to open RSA algorithm: 0x%08x", status);
            return FALSE;
        }
    }

    return TRUE;
}

static PAUTHENTIK_KEY_ENTRY FindKeyEntry(LPCWSTR wszContainerName)
{
    if (g_pKeyStore == NULL || wszContainerName == NULL)
        return NULL;

    WaitForSingleObject(g_hMutex, INFINITE);

    PBYTE pCurrent = (PBYTE)&g_pKeyStore->entries[0];
    PBYTE pEnd = (PBYTE)g_pKeyStore + g_pKeyStore->cbTotalSize;

    for (DWORD i = 0; i < g_pKeyStore->cKeys && pCurrent < pEnd; i++)
    {
        PAUTHENTIK_KEY_ENTRY pEntry = (PAUTHENTIK_KEY_ENTRY)pCurrent;

        if (pEntry->dwMagic == AUTHENTIK_KEY_MAGIC)
        {
            if (_wcsicmp(pEntry->wszContainerName, wszContainerName) == 0)
            {
                // Check if expired
                FILETIME ftNow;
                GetSystemTimeAsFileTime(&ftNow);
                
                if (CompareFileTime(&ftNow, &pEntry->ftExpires) < 0)
                {
                    ReleaseMutex(g_hMutex);
                    KSP_LOG("Found key: %S", wszContainerName);
                    return pEntry;
                }
                else
                {
                    KSP_LOG("Key expired: %S", wszContainerName);
                }
            }

            // Move to next entry
            DWORD cbEntry = sizeof(AUTHENTIK_KEY_ENTRY) - 1 + 
                            pEntry->cbPrivateKey + pEntry->cbCertificate;
            pCurrent += cbEntry;
        }
        else
        {
            break;  // Corrupted store
        }
    }

    ReleaseMutex(g_hMutex);
    return NULL;
}

static BOOL ValidateProviderHandle(NCRYPT_PROV_HANDLE hProvider)
{
    if (hProvider == 0)
        return FALSE;

    PAUTHENTIK_PROVIDER pProvider = (PAUTHENTIK_PROVIDER)hProvider;
    
    __try
    {
        return (pProvider->dwMagic == AUTHENTIK_PROVIDER_MAGIC);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

static BOOL ValidateKeyHandle(NCRYPT_KEY_HANDLE hKey)
{
    if (hKey == 0)
        return FALSE;

    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;
    
    __try
    {
        return (pKey->dwMagic == AUTHENTIK_KEY_HANDLE_MAGIC);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

// ============================================================================
// KSP Function Implementations
// ============================================================================

SECURITY_STATUS WINAPI AuthentikKSPOpenProvider(
    _Out_ NCRYPT_PROV_HANDLE* phProvider,
    _In_opt_ LPCWSTR pszProviderName,
    _In_ DWORD dwFlags)
{
    KSP_LOG("OpenProvider: name=%S, flags=0x%08x", 
            pszProviderName ? pszProviderName : L"(null)", dwFlags);

    if (phProvider == NULL)
        return NTE_INVALID_PARAMETER;

    *phProvider = 0;

    // Initialize key store if needed
    if (!InitializeKeyStore())
    {
        KSP_LOG("Failed to initialize key store");
        return NTE_PROVIDER_DLL_FAIL;
    }

    // Allocate provider context
    PAUTHENTIK_PROVIDER pProvider = new(std::nothrow) AUTHENTIK_PROVIDER;
    if (pProvider == NULL)
        return NTE_NO_MEMORY;

    pProvider->dwMagic = AUTHENTIK_PROVIDER_MAGIC;
    pProvider->dwFlags = dwFlags;

    *phProvider = (NCRYPT_PROV_HANDLE)pProvider;

    KSP_LOG("OpenProvider succeeded: handle=0x%p", pProvider);
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI AuthentikKSPOpenKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _Out_ NCRYPT_KEY_HANDLE* phKey,
    _In_ LPCWSTR pszKeyName,
    _In_opt_ DWORD dwLegacyKeySpec,
    _In_ DWORD dwFlags)
{
    KSP_LOG("OpenKey: name=%S, keySpec=%d, flags=0x%08x",
            pszKeyName ? pszKeyName : L"(null)", dwLegacyKeySpec, dwFlags);

    if (!ValidateProviderHandle(hProvider))
        return NTE_INVALID_HANDLE;

    if (phKey == NULL || pszKeyName == NULL)
        return NTE_INVALID_PARAMETER;

    *phKey = 0;

    PAUTHENTIK_PROVIDER pProvider = (PAUTHENTIK_PROVIDER)hProvider;

    // Look for the key in shared memory
    PAUTHENTIK_KEY_ENTRY pEntry = FindKeyEntry(pszKeyName);
    if (pEntry == NULL)
    {
        KSP_LOG("Key not found: %S", pszKeyName);
        return NTE_BAD_KEYSET;
    }

    // Create key handle
    PAUTHENTIK_KEY pKey = new(std::nothrow) AUTHENTIK_KEY;
    if (pKey == NULL)
        return NTE_NO_MEMORY;

    pKey->dwMagic = AUTHENTIK_KEY_HANDLE_MAGIC;
    pKey->hProvider = hProvider;
    pKey->containerName = pszKeyName;
    pKey->userName = pEntry->wszUserName;
    pKey->dwKeySpec = pEntry->dwKeySpec;
    pKey->dwFlags = dwFlags;
    pKey->hBCryptKey = NULL;

    // Copy private key blob
    pKey->privateKeyBlob.resize(pEntry->cbPrivateKey);
    memcpy(pKey->privateKeyBlob.data(), pEntry->rgbData, pEntry->cbPrivateKey);

    // Copy certificate blob
    pKey->certificateBlob.resize(pEntry->cbCertificate);
    memcpy(pKey->certificateBlob.data(), 
           pEntry->rgbData + pEntry->cbPrivateKey, 
           pEntry->cbCertificate);

    // Import the key into BCrypt for signing operations
    NTSTATUS status = BCryptImportKeyPair(
        g_hRsaAlg,
        NULL,
        BCRYPT_RSAPRIVATE_BLOB,
        &pKey->hBCryptKey,
        pKey->privateKeyBlob.data(),
        (ULONG)pKey->privateKeyBlob.size(),
        0);

    if (!BCRYPT_SUCCESS(status))
    {
        KSP_LOG("Failed to import key into BCrypt: 0x%08x", status);
        delete pKey;
        return NTE_BAD_KEY;
    }

    // Add to provider's key map
    pProvider->keys[pszKeyName] = pKey;

    *phKey = (NCRYPT_KEY_HANDLE)pKey;

    KSP_LOG("OpenKey succeeded: handle=0x%p", pKey);
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI AuthentikKSPCreatePersistedKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _Out_ NCRYPT_KEY_HANDLE* phKey,
    _In_ LPCWSTR pszAlgId,
    _In_opt_ LPCWSTR pszKeyName,
    _In_ DWORD dwLegacyKeySpec,
    _In_ DWORD dwFlags)
{
    KSP_LOG("CreatePersistedKey: alg=%S, name=%S",
            pszAlgId ? pszAlgId : L"(null)",
            pszKeyName ? pszKeyName : L"(null)");

    // We don't support creating new keys through this KSP
    // Keys are only created by the credential provider
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI AuthentikKSPGetProviderProperty(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ LPCWSTR pszProperty,
    _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    _In_ DWORD cbOutput,
    _Out_ DWORD* pcbResult,
    _In_ DWORD dwFlags)
{
    KSP_LOG("GetProviderProperty: %S", pszProperty ? pszProperty : L"(null)");

    if (!ValidateProviderHandle(hProvider))
        return NTE_INVALID_HANDLE;

    if (pszProperty == NULL || pcbResult == NULL)
        return NTE_INVALID_PARAMETER;

    *pcbResult = 0;

    // Handle common properties
    if (wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0)
    {
        DWORD cbName = (DWORD)((wcslen(AUTHENTIK_KSP_NAME) + 1) * sizeof(WCHAR));
        *pcbResult = cbName;

        if (pbOutput == NULL)
            return ERROR_SUCCESS;

        if (cbOutput < cbName)
            return NTE_BUFFER_TOO_SMALL;

        memcpy(pbOutput, AUTHENTIK_KSP_NAME, cbName);
        return ERROR_SUCCESS;
    }
    else if (wcscmp(pszProperty, NCRYPT_IMPL_TYPE_PROPERTY) == 0)
    {
        *pcbResult = sizeof(DWORD);

        if (pbOutput == NULL)
            return ERROR_SUCCESS;

        if (cbOutput < sizeof(DWORD))
            return NTE_BUFFER_TOO_SMALL;

        *(DWORD*)pbOutput = NCRYPT_IMPL_SOFTWARE_FLAG;
        return ERROR_SUCCESS;
    }
    else if (wcscmp(pszProperty, NCRYPT_VERSION_PROPERTY) == 0)
    {
        *pcbResult = sizeof(DWORD);

        if (pbOutput == NULL)
            return ERROR_SUCCESS;

        if (cbOutput < sizeof(DWORD))
            return NTE_BUFFER_TOO_SMALL;

        *(DWORD*)pbOutput = 0x00010000;  // Version 1.0
        return ERROR_SUCCESS;
    }

    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI AuthentikKSPGetKeyProperty(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_KEY_HANDLE hKey,
    _In_ LPCWSTR pszProperty,
    _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    _In_ DWORD cbOutput,
    _Out_ DWORD* pcbResult,
    _In_ DWORD dwFlags)
{
    KSP_LOG("GetKeyProperty: %S", pszProperty ? pszProperty : L"(null)");

    if (!ValidateProviderHandle(hProvider))
        return NTE_INVALID_HANDLE;

    if (!ValidateKeyHandle(hKey))
        return NTE_INVALID_HANDLE;

    if (pszProperty == NULL || pcbResult == NULL)
        return NTE_INVALID_PARAMETER;

    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;
    *pcbResult = 0;

    // Key name
    if (wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0)
    {
        DWORD cbName = (DWORD)((pKey->containerName.length() + 1) * sizeof(WCHAR));
        *pcbResult = cbName;

        if (pbOutput == NULL)
            return ERROR_SUCCESS;

        if (cbOutput < cbName)
            return NTE_BUFFER_TOO_SMALL;

        memcpy(pbOutput, pKey->containerName.c_str(), cbName);
        return ERROR_SUCCESS;
    }
    // Key spec
    else if (wcscmp(pszProperty, NCRYPT_KEY_TYPE_PROPERTY) == 0)
    {
        *pcbResult = sizeof(DWORD);

        if (pbOutput == NULL)
            return ERROR_SUCCESS;

        if (cbOutput < sizeof(DWORD))
            return NTE_BUFFER_TOO_SMALL;

        *(DWORD*)pbOutput = pKey->dwKeySpec;
        return ERROR_SUCCESS;
    }
    // Key length
    else if (wcscmp(pszProperty, NCRYPT_LENGTH_PROPERTY) == 0)
    {
        *pcbResult = sizeof(DWORD);

        if (pbOutput == NULL)
            return ERROR_SUCCESS;

        if (cbOutput < sizeof(DWORD))
            return NTE_BUFFER_TOO_SMALL;

        // Get key length from BCrypt
        DWORD dwKeyLength = 0;
        ULONG cbResult = 0;
        NTSTATUS status = BCryptGetProperty(
            pKey->hBCryptKey,
            BCRYPT_KEY_LENGTH,
            (PUCHAR)&dwKeyLength,
            sizeof(dwKeyLength),
            &cbResult,
            0);

        if (!BCRYPT_SUCCESS(status))
            return NTE_BAD_KEY;

        *(DWORD*)pbOutput = dwKeyLength;
        return ERROR_SUCCESS;
    }
    // Algorithm name
    else if (wcscmp(pszProperty, NCRYPT_ALGORITHM_PROPERTY) == 0)
    {
        DWORD cbAlg = (DWORD)((wcslen(BCRYPT_RSA_ALGORITHM) + 1) * sizeof(WCHAR));
        *pcbResult = cbAlg;

        if (pbOutput == NULL)
            return ERROR_SUCCESS;

        if (cbOutput < cbAlg)
            return NTE_BUFFER_TOO_SMALL;

        memcpy(pbOutput, BCRYPT_RSA_ALGORITHM, cbAlg);
        return ERROR_SUCCESS;
    }
    // Algorithm group
    else if (wcscmp(pszProperty, NCRYPT_ALGORITHM_GROUP_PROPERTY) == 0)
    {
        DWORD cbGroup = (DWORD)((wcslen(NCRYPT_RSA_ALGORITHM_GROUP) + 1) * sizeof(WCHAR));
        *pcbResult = cbGroup;

        if (pbOutput == NULL)
            return ERROR_SUCCESS;

        if (cbOutput < cbGroup)
            return NTE_BUFFER_TOO_SMALL;

        memcpy(pbOutput, NCRYPT_RSA_ALGORITHM_GROUP, cbGroup);
        return ERROR_SUCCESS;
    }
    // Certificate (stored with the key)
    else if (wcscmp(pszProperty, NCRYPT_CERTIFICATE_PROPERTY) == 0)
    {
        *pcbResult = (DWORD)pKey->certificateBlob.size();

        if (pbOutput == NULL)
            return ERROR_SUCCESS;

        if (cbOutput < pKey->certificateBlob.size())
            return NTE_BUFFER_TOO_SMALL;

        memcpy(pbOutput, pKey->certificateBlob.data(), pKey->certificateBlob.size());
        return ERROR_SUCCESS;
    }
    // Provider handle
    else if (wcscmp(pszProperty, NCRYPT_PROVIDER_HANDLE_PROPERTY) == 0)
    {
        *pcbResult = sizeof(NCRYPT_PROV_HANDLE);

        if (pbOutput == NULL)
            return ERROR_SUCCESS;

        if (cbOutput < sizeof(NCRYPT_PROV_HANDLE))
            return NTE_BUFFER_TOO_SMALL;

        *(NCRYPT_PROV_HANDLE*)pbOutput = pKey->hProvider;
        return ERROR_SUCCESS;
    }

    KSP_LOG("Unsupported key property: %S", pszProperty);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI AuthentikKSPSetProviderProperty(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ LPCWSTR pszProperty,
    _In_reads_bytes_(cbInput) PBYTE pbInput,
    _In_ DWORD cbInput,
    _In_ DWORD dwFlags)
{
    KSP_LOG("SetProviderProperty: %S", pszProperty ? pszProperty : L"(null)");

    if (!ValidateProviderHandle(hProvider))
        return NTE_INVALID_HANDLE;

    // We don't support setting provider properties
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI AuthentikKSPSetKeyProperty(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_KEY_HANDLE hKey,
    _In_ LPCWSTR pszProperty,
    _In_reads_bytes_(cbInput) PBYTE pbInput,
    _In_ DWORD cbInput,
    _In_ DWORD dwFlags)
{
    KSP_LOG("SetKeyProperty: %S", pszProperty ? pszProperty : L"(null)");

    if (!ValidateProviderHandle(hProvider))
        return NTE_INVALID_HANDLE;

    if (!ValidateKeyHandle(hKey))
        return NTE_INVALID_HANDLE;

    // We don't support setting key properties (keys are read-only)
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI AuthentikKSPFinalizeKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_KEY_HANDLE hKey,
    _In_ DWORD dwFlags)
{
    KSP_LOG("FinalizeKey");

    // Keys are finalized when stored by credential provider
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI AuthentikKSPDeleteKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _Inout_ NCRYPT_KEY_HANDLE hKey,
    _In_ DWORD dwFlags)
{
    KSP_LOG("DeleteKey");

    if (!ValidateProviderHandle(hProvider))
        return NTE_INVALID_HANDLE;

    if (!ValidateKeyHandle(hKey))
        return NTE_INVALID_HANDLE;

    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;

    // Remove from shared memory
    AuthentikKSP_RemoveKey(pKey->containerName.c_str());

    // Free the key handle
    return AuthentikKSPFreeKey(hProvider, hKey);
}

SECURITY_STATUS WINAPI AuthentikKSPFreeProvider(
    _In_ NCRYPT_PROV_HANDLE hProvider)
{
    KSP_LOG("FreeProvider: handle=0x%p", (void*)hProvider);

    if (!ValidateProviderHandle(hProvider))
        return NTE_INVALID_HANDLE;

    PAUTHENTIK_PROVIDER pProvider = (PAUTHENTIK_PROVIDER)hProvider;

    // Free all keys
    for (auto& pair : pProvider->keys)
    {
        PAUTHENTIK_KEY pKey = pair.second;
        if (pKey->hBCryptKey)
        {
            BCryptDestroyKey(pKey->hBCryptKey);
        }
        pKey->dwMagic = 0;
        delete pKey;
    }

    pProvider->dwMagic = 0;
    delete pProvider;

    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI AuthentikKSPFreeKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_KEY_HANDLE hKey)
{
    KSP_LOG("FreeKey: handle=0x%p", (void*)hKey);

    if (!ValidateKeyHandle(hKey))
        return NTE_INVALID_HANDLE;

    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;

    // Destroy BCrypt key
    if (pKey->hBCryptKey)
    {
        BCryptDestroyKey(pKey->hBCryptKey);
        pKey->hBCryptKey = NULL;
    }

    // Securely clear private key data
    SecureZeroMemory(pKey->privateKeyBlob.data(), pKey->privateKeyBlob.size());

    // Remove from provider's map if provider is valid
    if (ValidateProviderHandle(hProvider))
    {
        PAUTHENTIK_PROVIDER pProvider = (PAUTHENTIK_PROVIDER)hProvider;
        pProvider->keys.erase(pKey->containerName);
    }

    pKey->dwMagic = 0;
    delete pKey;

    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI AuthentikKSPFreeBuffer(
    _Pre_notnull_ PVOID pvInput)
{
    KSP_LOG("FreeBuffer: ptr=0x%p", pvInput);

    if (pvInput)
    {
        free(pvInput);
    }

    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI AuthentikKSPSignHash(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_KEY_HANDLE hKey,
    _In_opt_ VOID* pPaddingInfo,
    _In_reads_bytes_(cbHashValue) PBYTE pbHashValue,
    _In_ DWORD cbHashValue,
    _Out_writes_bytes_to_opt_(cbSignature, *pcbResult) PBYTE pbSignature,
    _In_ DWORD cbSignature,
    _Out_ DWORD* pcbResult,
    _In_ DWORD dwFlags)
{
    KSP_LOG("SignHash: hashLen=%d, sigLen=%d, flags=0x%08x",
            cbHashValue, cbSignature, dwFlags);

    if (!ValidateProviderHandle(hProvider))
        return NTE_INVALID_HANDLE;

    if (!ValidateKeyHandle(hKey))
        return NTE_INVALID_HANDLE;

    if (pbHashValue == NULL || pcbResult == NULL)
        return NTE_INVALID_PARAMETER;

    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;
    *pcbResult = 0;

    // Determine padding mode
    LPCWSTR wszPaddingAlg = NULL;
    DWORD dwBCryptFlags = 0;

    if (dwFlags & BCRYPT_PAD_PKCS1)
    {
        if (pPaddingInfo)
        {
            BCRYPT_PKCS1_PADDING_INFO* pPkcs1 = (BCRYPT_PKCS1_PADDING_INFO*)pPaddingInfo;
            wszPaddingAlg = pPkcs1->pszAlgId;
        }
        dwBCryptFlags = BCRYPT_PAD_PKCS1;
    }
    else if (dwFlags & BCRYPT_PAD_PSS)
    {
        dwBCryptFlags = BCRYPT_PAD_PSS;
    }
    else
    {
        // Default to PKCS1
        dwBCryptFlags = BCRYPT_PAD_PKCS1;
    }

    // Sign the hash
    NTSTATUS status = BCryptSignHash(
        pKey->hBCryptKey,
        pPaddingInfo,
        pbHashValue,
        cbHashValue,
        pbSignature,
        cbSignature,
        (ULONG*)pcbResult,
        dwBCryptFlags);

    if (!BCRYPT_SUCCESS(status))
    {
        KSP_LOG("BCryptSignHash failed: 0x%08x", status);
        return NTE_INTERNAL_ERROR;
    }

    KSP_LOG("SignHash succeeded: resultLen=%d", *pcbResult);
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI AuthentikKSPVerifySignature(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_KEY_HANDLE hKey,
    _In_opt_ VOID* pPaddingInfo,
    _In_reads_bytes_(cbHashValue) PBYTE pbHashValue,
    _In_ DWORD cbHashValue,
    _In_reads_bytes_(cbSignature) PBYTE pbSignature,
    _In_ DWORD cbSignature,
    _In_ DWORD dwFlags)
{
    KSP_LOG("VerifySignature");

    if (!ValidateProviderHandle(hProvider))
        return NTE_INVALID_HANDLE;

    if (!ValidateKeyHandle(hKey))
        return NTE_INVALID_HANDLE;

    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;

    DWORD dwBCryptFlags = 0;
    if (dwFlags & BCRYPT_PAD_PKCS1)
        dwBCryptFlags = BCRYPT_PAD_PKCS1;
    else if (dwFlags & BCRYPT_PAD_PSS)
        dwBCryptFlags = BCRYPT_PAD_PSS;

    NTSTATUS status = BCryptVerifySignature(
        pKey->hBCryptKey,
        pPaddingInfo,
        pbHashValue,
        cbHashValue,
        pbSignature,
        cbSignature,
        dwBCryptFlags);

    return BCRYPT_SUCCESS(status) ? ERROR_SUCCESS : NTE_BAD_SIGNATURE;
}

SECURITY_STATUS WINAPI AuthentikKSPEncrypt(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_KEY_HANDLE hKey,
    _In_reads_bytes_opt_(cbInput) PBYTE pbInput,
    _In_ DWORD cbInput,
    _In_opt_ VOID* pPaddingInfo,
    _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    _In_ DWORD cbOutput,
    _Out_ DWORD* pcbResult,
    _In_ DWORD dwFlags)
{
    KSP_LOG("Encrypt");
    // Not typically used for PKINIT
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI AuthentikKSPDecrypt(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_KEY_HANDLE hKey,
    _In_reads_bytes_opt_(cbInput) PBYTE pbInput,
    _In_ DWORD cbInput,
    _In_opt_ VOID* pPaddingInfo,
    _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    _In_ DWORD cbOutput,
    _Out_ DWORD* pcbResult,
    _In_ DWORD dwFlags)
{
    KSP_LOG("Decrypt");

    if (!ValidateProviderHandle(hProvider))
        return NTE_INVALID_HANDLE;

    if (!ValidateKeyHandle(hKey))
        return NTE_INVALID_HANDLE;

    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;

    DWORD dwBCryptFlags = 0;
    if (dwFlags & NCRYPT_PAD_PKCS1_FLAG)
        dwBCryptFlags = BCRYPT_PAD_PKCS1;
    else if (dwFlags & NCRYPT_PAD_OAEP_FLAG)
        dwBCryptFlags = BCRYPT_PAD_OAEP;

    NTSTATUS status = BCryptDecrypt(
        pKey->hBCryptKey,
        pbInput,
        cbInput,
        pPaddingInfo,
        NULL,
        0,
        pbOutput,
        cbOutput,
        (ULONG*)pcbResult,
        dwBCryptFlags);

    return BCRYPT_SUCCESS(status) ? ERROR_SUCCESS : NTE_INTERNAL_ERROR;
}

SECURITY_STATUS WINAPI AuthentikKSPPromptUser(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_opt_ NCRYPT_KEY_HANDLE hKey,
    _In_ LPCWSTR pszOperation,
    _In_ DWORD dwFlags)
{
    KSP_LOG("PromptUser: %S", pszOperation ? pszOperation : L"(null)");
    // We don't need user prompts - OTP was already validated
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI AuthentikKSPNotifyChangeKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _Inout_ HANDLE* phEvent,
    _In_ DWORD dwFlags)
{
    KSP_LOG("NotifyChangeKey");
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI AuthentikKSPSecretAgreement(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_KEY_HANDLE hPrivKey,
    _In_ NCRYPT_KEY_HANDLE hPubKey,
    _Out_ NCRYPT_SECRET_HANDLE* phAgreedSecret,
    _In_ DWORD dwFlags)
{
    KSP_LOG("SecretAgreement");
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI AuthentikKSPDeriveKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_opt_ NCRYPT_SECRET_HANDLE hSharedSecret,
    _In_ LPCWSTR pwszKDF,
    _In_opt_ NCryptBufferDesc* pParameterList,
    _Out_writes_bytes_to_opt_(cbDerivedKey, *pcbResult) PUCHAR pbDerivedKey,
    _In_ DWORD cbDerivedKey,
    _Out_ DWORD* pcbResult,
    _In_ ULONG dwFlags)
{
    KSP_LOG("DeriveKey");
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI AuthentikKSPFreeSecret(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_SECRET_HANDLE hSharedSecret)
{
    KSP_LOG("FreeSecret");
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI AuthentikKSPImportKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_opt_ NCRYPT_KEY_HANDLE hImportKey,
    _In_ LPCWSTR pszBlobType,
    _In_opt_ NCryptBufferDesc* pParameterList,
    _Out_ NCRYPT_KEY_HANDLE* phKey,
    _In_reads_bytes_(cbData) PBYTE pbData,
    _In_ DWORD cbData,
    _In_ DWORD dwFlags)
{
    KSP_LOG("ImportKey: type=%S", pszBlobType ? pszBlobType : L"(null)");
    // Keys are imported via AuthentikKSP_StoreKey helper
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI AuthentikKSPExportKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_KEY_HANDLE hKey,
    _In_opt_ NCRYPT_KEY_HANDLE hExportKey,
    _In_ LPCWSTR pszBlobType,
    _In_opt_ NCryptBufferDesc* pParameterList,
    _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    _In_ DWORD cbOutput,
    _Out_ DWORD* pcbResult,
    _In_ DWORD dwFlags)
{
    KSP_LOG("ExportKey: type=%S", pszBlobType ? pszBlobType : L"(null)");

    if (!ValidateProviderHandle(hProvider))
        return NTE_INVALID_HANDLE;

    if (!ValidateKeyHandle(hKey))
        return NTE_INVALID_HANDLE;

    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;

    // Only allow public key export
    if (wcscmp(pszBlobType, BCRYPT_RSAPUBLIC_BLOB) == 0 ||
        wcscmp(pszBlobType, BCRYPT_PUBLIC_KEY_BLOB) == 0)
    {
        NTSTATUS status = BCryptExportKey(
            pKey->hBCryptKey,
            NULL,
            BCRYPT_RSAPUBLIC_BLOB,
            pbOutput,
            cbOutput,
            (ULONG*)pcbResult,
            0);

        return BCRYPT_SUCCESS(status) ? ERROR_SUCCESS : NTE_INTERNAL_ERROR;
    }

    // Don't allow private key export
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI AuthentikKSPEnumAlgorithms(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ DWORD dwAlgOperations,
    _Out_ DWORD* pdwAlgCount,
    _Outptr_result_buffer_(*pdwAlgCount) NCryptAlgorithmName** ppAlgList,
    _In_ DWORD dwFlags)
{
    KSP_LOG("EnumAlgorithms: ops=0x%08x", dwAlgOperations);

    if (!ValidateProviderHandle(hProvider))
        return NTE_INVALID_HANDLE;

    if (pdwAlgCount == NULL || ppAlgList == NULL)
        return NTE_INVALID_PARAMETER;

    // We only support RSA
    *pdwAlgCount = 1;

    NCryptAlgorithmName* pAlgList = (NCryptAlgorithmName*)malloc(sizeof(NCryptAlgorithmName));
    if (pAlgList == NULL)
        return NTE_NO_MEMORY;

    pAlgList[0].pszName = _wcsdup(BCRYPT_RSA_ALGORITHM);
    pAlgList[0].dwClass = NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION;
    pAlgList[0].dwAlgOperations = NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION |
                                   NCRYPT_SIGNATURE_OPERATION;
    pAlgList[0].dwFlags = 0;

    *ppAlgList = pAlgList;

    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI AuthentikKSPEnumKeys(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_opt_ LPCWSTR pszScope,
    _Outptr_ NCryptKeyName** ppKeyName,
    _Inout_ PVOID* ppEnumState,
    _In_ DWORD dwFlags)
{
    KSP_LOG("EnumKeys");

    if (!ValidateProviderHandle(hProvider))
        return NTE_INVALID_HANDLE;

    // Enumeration not supported for security reasons
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI AuthentikKSPIsAlgSupported(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ LPCWSTR pszAlgId,
    _In_ DWORD dwFlags)
{
    KSP_LOG("IsAlgSupported: %S", pszAlgId ? pszAlgId : L"(null)");

    if (!ValidateProviderHandle(hProvider))
        return NTE_INVALID_HANDLE;

    if (pszAlgId == NULL)
        return NTE_INVALID_PARAMETER;

    // We only support RSA
    if (wcscmp(pszAlgId, BCRYPT_RSA_ALGORITHM) == 0 ||
        wcscmp(pszAlgId, NCRYPT_RSA_ALGORITHM) == 0)
    {
        return ERROR_SUCCESS;
    }

    return NTE_NOT_SUPPORTED;
}

// ============================================================================
// Helper Functions for Credential Provider
// ============================================================================

HRESULT AuthentikKSP_StoreKey(
    _In_ LPCWSTR wszContainerName,
    _In_ LPCWSTR wszUserName,
    _In_reads_bytes_(cbPrivateKey) const BYTE* pbPrivateKey,
    _In_ DWORD cbPrivateKey,
    _In_reads_bytes_(cbCertificate) const BYTE* pbCertificate,
    _In_ DWORD cbCertificate,
    _In_ DWORD dwKeySpec,
    _In_ DWORD dwValidityMinutes)
{
    KSP_LOG("StoreKey: container=%S, user=%S, keyLen=%d, certLen=%d",
            wszContainerName, wszUserName, cbPrivateKey, cbCertificate);

    if (!InitializeKeyStore())
        return E_FAIL;

    if (wszContainerName == NULL || pbPrivateKey == NULL || cbPrivateKey == 0)
        return E_INVALIDARG;

    WaitForSingleObject(g_hMutex, INFINITE);

    // Calculate entry size
    DWORD cbEntry = sizeof(AUTHENTIK_KEY_ENTRY) - 1 + cbPrivateKey + cbCertificate;

    // Check if we have space
    DWORD cbAvailable = AUTHENTIK_SHARED_MEM_SIZE - g_pKeyStore->cbTotalSize;
    if (cbEntry > cbAvailable)
    {
        KSP_LOG("Not enough space in key store");
        ReleaseMutex(g_hMutex);
        return E_OUTOFMEMORY;
    }

    // Check if key already exists (and remove it)
    // ... (simplified - would need to compact store)

    // Add new entry at end
    PAUTHENTIK_KEY_ENTRY pEntry = (PAUTHENTIK_KEY_ENTRY)
        ((PBYTE)g_pKeyStore + g_pKeyStore->cbTotalSize);

    pEntry->dwMagic = AUTHENTIK_KEY_MAGIC;
    pEntry->dwFlags = 0;
    pEntry->dwKeySpec = dwKeySpec;
    
    GetSystemTimeAsFileTime(&pEntry->ftCreated);
    
    // Calculate expiry time
    ULARGE_INTEGER expiry;
    expiry.LowPart = pEntry->ftCreated.dwLowDateTime;
    expiry.HighPart = pEntry->ftCreated.dwHighDateTime;
    expiry.QuadPart += (ULONGLONG)dwValidityMinutes * 60 * 10000000;
    pEntry->ftExpires.dwLowDateTime = expiry.LowPart;
    pEntry->ftExpires.dwHighDateTime = expiry.HighPart;

    wcsncpy_s(pEntry->wszContainerName, wszContainerName, _TRUNCATE);
    wcsncpy_s(pEntry->wszUserName, wszUserName ? wszUserName : L"", _TRUNCATE);
    
    pEntry->cbPrivateKey = cbPrivateKey;
    pEntry->cbCertificate = cbCertificate;
    
    memcpy(pEntry->rgbData, pbPrivateKey, cbPrivateKey);
    memcpy(pEntry->rgbData + cbPrivateKey, pbCertificate, cbCertificate);

    g_pKeyStore->cKeys++;
    g_pKeyStore->cbTotalSize += cbEntry;

    KSP_LOG("Key stored: total keys=%d, total size=%d",
            g_pKeyStore->cKeys, g_pKeyStore->cbTotalSize);

    ReleaseMutex(g_hMutex);
    return S_OK;
}

HRESULT AuthentikKSP_RemoveKey(
    _In_ LPCWSTR wszContainerName)
{
    KSP_LOG("RemoveKey: %S", wszContainerName);

    if (!InitializeKeyStore())
        return E_FAIL;

    if (wszContainerName == NULL)
        return E_INVALIDARG;

    // For simplicity, we just mark the key as expired
    // A production implementation would compact the store
    PAUTHENTIK_KEY_ENTRY pEntry = FindKeyEntry(wszContainerName);
    if (pEntry)
    {
        WaitForSingleObject(g_hMutex, INFINITE);
        pEntry->ftExpires.dwLowDateTime = 0;
        pEntry->ftExpires.dwHighDateTime = 0;
        ReleaseMutex(g_hMutex);
        return S_OK;
    }

    return E_NOT_SET;
}

BOOL AuthentikKSP_KeyExists(
    _In_ LPCWSTR wszContainerName)
{
    return (FindKeyEntry(wszContainerName) != NULL);
}

LPCWSTR AuthentikKSP_GetProviderName()
{
    return AUTHENTIK_KSP_NAME;
}
