// AuthentikKSP.cpp
// Authentik Key Storage Provider - PURE C IMPLEMENTATION
//
// This version uses NO C++ STL objects (no std::string, std::vector, std::map)
// to avoid blue screens when the KSP is loaded early during Windows boot
// before the C++ runtime is fully initialized.
//
// All memory is allocated using HeapAlloc from the process heap.

#include "AuthentikKSP.h"
#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")

// ============================================================================
// Safe Logging - wrapped in SEH
// ============================================================================

static void SafeLog(const char* msg)
{
    __try {
        OutputDebugStringA(msg);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
    }
}

#define KSP_LOG(fmt, ...) \
    do { \
        __try { \
            char _buf[512]; \
            _snprintf_s(_buf, sizeof(_buf), _TRUNCATE, "[AuthentikKSP] " fmt "\n", ##__VA_ARGS__); \
            OutputDebugStringA(_buf); \
        } __except(EXCEPTION_EXECUTE_HANDLER) { } \
    } while(0)

// ============================================================================
// Global State - All NULL until explicitly initialized
// ============================================================================

static HANDLE g_hSharedMem = NULL;
static PAUTHENTIK_KEY_STORE_HEADER g_pKeyStore = NULL;
static HANDLE g_hMutex = NULL;
static BCRYPT_ALG_HANDLE g_hRsaAlg = NULL;
static volatile LONG g_bInitAttempted = 0;

// ============================================================================
// Lazy Initialization - Only called when actually needed
// ============================================================================

static BOOL TryInitializeKeyStore(void)
{
    // Only try once
    if (InterlockedCompareExchange(&g_bInitAttempted, 1, 0) != 0)
    {
        return (g_pKeyStore != NULL);
    }

    __try
    {
        SafeLog("[AuthentikKSP] TryInitializeKeyStore");

        // Try Global, then Local namespace
        g_hMutex = CreateMutexW(NULL, FALSE, L"Global\\AuthentikKSPMutex");
        if (!g_hMutex)
            g_hMutex = CreateMutexW(NULL, FALSE, L"Local\\AuthentikKSPMutex");
        if (!g_hMutex)
            return FALSE;

        g_hSharedMem = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
            0, AUTHENTIK_SHARED_MEM_SIZE, L"Global\\AuthentikKSPKeyStore");
        if (!g_hSharedMem)
            g_hSharedMem = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                0, AUTHENTIK_SHARED_MEM_SIZE, L"Local\\AuthentikKSPKeyStore");

        BOOL bCreated = (GetLastError() != ERROR_ALREADY_EXISTS);
        if (!g_hSharedMem) return FALSE;

        g_pKeyStore = (PAUTHENTIK_KEY_STORE_HEADER)MapViewOfFile(
            g_hSharedMem, FILE_MAP_ALL_ACCESS, 0, 0, AUTHENTIK_SHARED_MEM_SIZE);
        if (!g_pKeyStore) return FALSE;

        if (bCreated)
        {
            WaitForSingleObject(g_hMutex, 5000);
            g_pKeyStore->dwMagic = AUTHENTIK_KEY_MAGIC;
            g_pKeyStore->dwVersion = 1;
            g_pKeyStore->cKeys = 0;
            g_pKeyStore->cbTotalSize = sizeof(AUTHENTIK_KEY_STORE_HEADER);
            ReleaseMutex(g_hMutex);
        }

        SafeLog("[AuthentikKSP] KeyStore initialized");
        return TRUE;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        SafeLog("[AuthentikKSP] EXCEPTION in TryInitializeKeyStore");
        return FALSE;
    }
}

static BOOL TryInitializeRsa(void)
{
    if (g_hRsaAlg) return TRUE;

    __try
    {
        NTSTATUS status = BCryptOpenAlgorithmProvider(&g_hRsaAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
        return BCRYPT_SUCCESS(status);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

static BOOL ValidateProviderHandle(NCRYPT_PROV_HANDLE hProvider)
{
    __try {
        PAUTHENTIK_PROVIDER p = (PAUTHENTIK_PROVIDER)hProvider;
        return (p && p->dwMagic == AUTHENTIK_PROVIDER_MAGIC);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

static BOOL ValidateKeyHandle(NCRYPT_KEY_HANDLE hKey)
{
    __try {
        PAUTHENTIK_KEY k = (PAUTHENTIK_KEY)hKey;
        return (k && k->dwMagic == AUTHENTIK_KEY_HANDLE_MAGIC);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

static PAUTHENTIK_KEY_ENTRY FindKeyEntry(LPCWSTR wszContainerName)
{
    if (!g_pKeyStore || !wszContainerName) return NULL;

    __try
    {
        WaitForSingleObject(g_hMutex, 5000);

        PBYTE pCurrent = (PBYTE)g_pKeyStore + sizeof(AUTHENTIK_KEY_STORE_HEADER);
        PBYTE pEnd = (PBYTE)g_pKeyStore + g_pKeyStore->cbTotalSize;

        for (DWORD i = 0; i < g_pKeyStore->cKeys && pCurrent < pEnd; i++)
        {
            PAUTHENTIK_KEY_ENTRY pEntry = (PAUTHENTIK_KEY_ENTRY)pCurrent;
            if (pEntry->dwMagic == AUTHENTIK_KEY_MAGIC)
            {
                if (_wcsicmp(pEntry->wszContainerName, wszContainerName) == 0)
                {
                    FILETIME ftNow;
                    GetSystemTimeAsFileTime(&ftNow);
                    if (CompareFileTime(&ftNow, &pEntry->ftExpires) < 0)
                    {
                        ReleaseMutex(g_hMutex);
                        return pEntry;
                    }
                }
                DWORD entrySize = sizeof(AUTHENTIK_KEY_ENTRY) + pEntry->cbPrivateKey + pEntry->cbCertificate;
                pCurrent += entrySize;
            }
            else break;
        }
        ReleaseMutex(g_hMutex);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) { }

    return NULL;
}

// ============================================================================
// NCrypt Provider Functions - Using HeapAlloc, no C++ new operator
// ============================================================================

SECURITY_STATUS WINAPI AuthentikKSPOpenProvider(
    _Out_ NCRYPT_PROV_HANDLE* phProvider,
    _In_opt_ LPCWSTR pszProviderName,
    _In_ DWORD dwFlags)
{
    UNREFERENCED_PARAMETER(pszProviderName);
    
    SafeLog("[AuthentikKSP] OpenProvider");

    if (!phProvider) return NTE_INVALID_PARAMETER;
    *phProvider = 0;

    // DON'T initialize key store here - defer until OpenKey
    // Just allocate provider handle using HeapAlloc (safe at boot time)

    __try
    {
        PAUTHENTIK_PROVIDER pProvider = (PAUTHENTIK_PROVIDER)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(AUTHENTIK_PROVIDER));
        
        if (!pProvider) return NTE_NO_MEMORY;

        pProvider->dwMagic = AUTHENTIK_PROVIDER_MAGIC;
        pProvider->dwFlags = dwFlags;

        *phProvider = (NCRYPT_PROV_HANDLE)pProvider;
        return ERROR_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return NTE_PROVIDER_DLL_FAIL;
    }
}

SECURITY_STATUS WINAPI AuthentikKSPOpenKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _Out_ NCRYPT_KEY_HANDLE* phKey,
    _In_ LPCWSTR pszKeyName,
    _In_opt_ DWORD dwLegacyKeySpec,
    _In_ DWORD dwFlags)
{
    UNREFERENCED_PARAMETER(dwLegacyKeySpec);
    
    KSP_LOG("OpenKey: %S", pszKeyName ? pszKeyName : L"(null)");

    if (!ValidateProviderHandle(hProvider)) return NTE_INVALID_HANDLE;
    if (!phKey || !pszKeyName) return NTE_INVALID_PARAMETER;
    *phKey = 0;

    // NOW initialize key store (lazy)
    if (!TryInitializeKeyStore())
    {
        KSP_LOG("OpenKey: KeyStore init failed");
        return NTE_PROVIDER_DLL_FAIL;
    }

    __try
    {
        PAUTHENTIK_KEY_ENTRY pEntry = FindKeyEntry(pszKeyName);
        if (!pEntry)
        {
            KSP_LOG("OpenKey: Key not found");
            return NTE_BAD_KEYSET;
        }

        // Validate sizes before copying
        if (pEntry->cbPrivateKey > MAX_KEY_BLOB_SIZE ||
            pEntry->cbCertificate > MAX_CERT_BLOB_SIZE)
        {
            KSP_LOG("OpenKey: Key/cert too large");
            return NTE_BAD_KEY;
        }

        // Allocate key handle using HeapAlloc
        PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(AUTHENTIK_KEY));
        
        if (!pKey) return NTE_NO_MEMORY;

        pKey->dwMagic = AUTHENTIK_KEY_HANDLE_MAGIC;
        pKey->hProvider = hProvider;
        wcscpy_s(pKey->wszContainerName, MAX_CONTAINER_NAME, pszKeyName);
        wcscpy_s(pKey->wszUserName, MAX_USER_NAME, pEntry->wszUserName);
        pKey->dwKeySpec = pEntry->dwKeySpec;
        pKey->dwFlags = dwFlags;
        pKey->hBCryptKey = NULL;

        // Copy key and cert data into fixed-size buffers
        pKey->cbPrivateKeyBlob = pEntry->cbPrivateKey;
        memcpy(pKey->rgbPrivateKeyBlob, pEntry->rgbData, pEntry->cbPrivateKey);

        pKey->cbCertificateBlob = pEntry->cbCertificate;
        memcpy(pKey->rgbCertificateBlob, pEntry->rgbData + pEntry->cbPrivateKey, pEntry->cbCertificate);

        // Import to BCrypt
        if (!TryInitializeRsa())
        {
            HeapFree(GetProcessHeap(), 0, pKey);
            return NTE_PROVIDER_DLL_FAIL;
        }

        NTSTATUS status = BCryptImportKeyPair(g_hRsaAlg, NULL, BCRYPT_RSAPRIVATE_BLOB,
            &pKey->hBCryptKey, pKey->rgbPrivateKeyBlob, pKey->cbPrivateKeyBlob, 0);

        if (!BCRYPT_SUCCESS(status))
        {
            KSP_LOG("BCryptImportKeyPair failed: 0x%08x", status);
            HeapFree(GetProcessHeap(), 0, pKey);
            return NTE_BAD_KEY;
        }

        *phKey = (NCRYPT_KEY_HANDLE)pKey;
        KSP_LOG("OpenKey succeeded");
        return ERROR_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return NTE_PROVIDER_DLL_FAIL;
    }
}

SECURITY_STATUS WINAPI AuthentikKSPCreatePersistedKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _Out_ NCRYPT_KEY_HANDLE* phKey,
    _In_ LPCWSTR pszAlgId,
    _In_opt_ LPCWSTR pszKeyName,
    _In_ DWORD dwLegacyKeySpec,
    _In_ DWORD dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(phKey);
    UNREFERENCED_PARAMETER(pszAlgId);
    UNREFERENCED_PARAMETER(pszKeyName);
    UNREFERENCED_PARAMETER(dwLegacyKeySpec);
    UNREFERENCED_PARAMETER(dwFlags);
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
    UNREFERENCED_PARAMETER(dwFlags);
    
    if (!ValidateProviderHandle(hProvider)) return NTE_INVALID_HANDLE;
    if (!pszProperty || !pcbResult) return NTE_INVALID_PARAMETER;

    KSP_LOG("GetProviderProperty: %S", pszProperty);

    if (wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0)
    {
        *pcbResult = (DWORD)((wcslen(AUTHENTIK_KSP_NAME) + 1) * sizeof(WCHAR));
        if (pbOutput)
        {
            if (cbOutput < *pcbResult) return NTE_BUFFER_TOO_SMALL;
            wcscpy_s((LPWSTR)pbOutput, cbOutput / sizeof(WCHAR), AUTHENTIK_KSP_NAME);
        }
        return ERROR_SUCCESS;
    }
    else if (wcscmp(pszProperty, NCRYPT_IMPL_TYPE_PROPERTY) == 0)
    {
        *pcbResult = sizeof(DWORD);
        if (pbOutput)
        {
            if (cbOutput < sizeof(DWORD)) return NTE_BUFFER_TOO_SMALL;
            *(DWORD*)pbOutput = NCRYPT_IMPL_SOFTWARE_FLAG;
        }
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
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(dwFlags);
    
    if (!ValidateKeyHandle(hKey)) return NTE_INVALID_HANDLE;
    if (!pszProperty || !pcbResult) return NTE_INVALID_PARAMETER;

    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;
    KSP_LOG("GetKeyProperty: %S", pszProperty);

    if (wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0)
    {
        *pcbResult = (DWORD)((wcslen(pKey->wszContainerName) + 1) * sizeof(WCHAR));
        if (pbOutput)
        {
            if (cbOutput < *pcbResult) return NTE_BUFFER_TOO_SMALL;
            wcscpy_s((LPWSTR)pbOutput, cbOutput / sizeof(WCHAR), pKey->wszContainerName);
        }
        return ERROR_SUCCESS;
    }
    else if (wcscmp(pszProperty, NCRYPT_ALGORITHM_PROPERTY) == 0)
    {
        *pcbResult = (DWORD)((wcslen(BCRYPT_RSA_ALGORITHM) + 1) * sizeof(WCHAR));
        if (pbOutput)
        {
            if (cbOutput < *pcbResult) return NTE_BUFFER_TOO_SMALL;
            wcscpy_s((LPWSTR)pbOutput, cbOutput / sizeof(WCHAR), BCRYPT_RSA_ALGORITHM);
        }
        return ERROR_SUCCESS;
    }
    else if (wcscmp(pszProperty, NCRYPT_LENGTH_PROPERTY) == 0)
    {
        *pcbResult = sizeof(DWORD);
        if (pbOutput)
        {
            if (cbOutput < sizeof(DWORD)) return NTE_BUFFER_TOO_SMALL;
            // Get key length from BCrypt
            DWORD dwKeyLength = 0;
            ULONG cbResult = 0;
            if (pKey->hBCryptKey)
            {
                BCryptGetProperty(pKey->hBCryptKey, BCRYPT_KEY_LENGTH, (PUCHAR)&dwKeyLength, sizeof(DWORD), &cbResult, 0);
            }
            *(DWORD*)pbOutput = dwKeyLength;
        }
        return ERROR_SUCCESS;
    }
    else if (wcscmp(pszProperty, NCRYPT_CERTIFICATE_PROPERTY) == 0)
    {
        *pcbResult = pKey->cbCertificateBlob;
        if (pbOutput)
        {
            if (cbOutput < pKey->cbCertificateBlob) return NTE_BUFFER_TOO_SMALL;
            memcpy(pbOutput, pKey->rgbCertificateBlob, pKey->cbCertificateBlob);
        }
        return ERROR_SUCCESS;
    }
    else if (wcscmp(pszProperty, NCRYPT_EXPORT_POLICY_PROPERTY) == 0)
    {
        *pcbResult = sizeof(DWORD);
        if (pbOutput)
        {
            if (cbOutput < sizeof(DWORD)) return NTE_BUFFER_TOO_SMALL;
            *(DWORD*)pbOutput = 0; // No export allowed
        }
        return ERROR_SUCCESS;
    }
    else if (wcscmp(pszProperty, NCRYPT_KEY_USAGE_PROPERTY) == 0)
    {
        *pcbResult = sizeof(DWORD);
        if (pbOutput)
        {
            if (cbOutput < sizeof(DWORD)) return NTE_BUFFER_TOO_SMALL;
            *(DWORD*)pbOutput = NCRYPT_ALLOW_SIGNING_FLAG | NCRYPT_ALLOW_DECRYPT_FLAG;
        }
        return ERROR_SUCCESS;
    }
    else if (wcscmp(pszProperty, NCRYPT_UNIQUE_NAME_PROPERTY) == 0)
    {
        *pcbResult = (DWORD)((wcslen(pKey->wszContainerName) + 1) * sizeof(WCHAR));
        if (pbOutput)
        {
            if (cbOutput < *pcbResult) return NTE_BUFFER_TOO_SMALL;
            wcscpy_s((LPWSTR)pbOutput, cbOutput / sizeof(WCHAR), pKey->wszContainerName);
        }
        return ERROR_SUCCESS;
    }

    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI AuthentikKSPSetProviderProperty(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ LPCWSTR pszProperty,
    _In_reads_bytes_(cbInput) PBYTE pbInput,
    _In_ DWORD cbInput,
    _In_ DWORD dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(pszProperty);
    UNREFERENCED_PARAMETER(pbInput);
    UNREFERENCED_PARAMETER(cbInput);
    UNREFERENCED_PARAMETER(dwFlags);
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
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(pszProperty);
    UNREFERENCED_PARAMETER(pbInput);
    UNREFERENCED_PARAMETER(cbInput);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI AuthentikKSPFinalizeKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_KEY_HANDLE hKey,
    _In_ DWORD dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(dwFlags);
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI AuthentikKSPDeleteKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _Inout_ NCRYPT_KEY_HANDLE hKey,
    _In_ DWORD dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(dwFlags);
    
    if (!ValidateKeyHandle(hKey)) return NTE_INVALID_HANDLE;

    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;
    if (pKey->hBCryptKey)
    {
        BCryptDestroyKey(pKey->hBCryptKey);
    }
    SecureZeroMemory(pKey, sizeof(AUTHENTIK_KEY));
    HeapFree(GetProcessHeap(), 0, pKey);

    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI AuthentikKSPFreeProvider(
    _In_ NCRYPT_PROV_HANDLE hProvider)
{
    SafeLog("[AuthentikKSP] FreeProvider");

    if (!ValidateProviderHandle(hProvider)) return NTE_INVALID_HANDLE;

    PAUTHENTIK_PROVIDER pProvider = (PAUTHENTIK_PROVIDER)hProvider;
    SecureZeroMemory(pProvider, sizeof(AUTHENTIK_PROVIDER));
    HeapFree(GetProcessHeap(), 0, pProvider);

    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI AuthentikKSPFreeKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_KEY_HANDLE hKey)
{
    UNREFERENCED_PARAMETER(hProvider);
    
    SafeLog("[AuthentikKSP] FreeKey");

    if (!ValidateKeyHandle(hKey)) return NTE_INVALID_HANDLE;

    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;
    if (pKey->hBCryptKey)
    {
        BCryptDestroyKey(pKey->hBCryptKey);
    }
    SecureZeroMemory(pKey, sizeof(AUTHENTIK_KEY));
    HeapFree(GetProcessHeap(), 0, pKey);

    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI AuthentikKSPFreeBuffer(
    _Pre_notnull_ PVOID pvInput)
{
    if (pvInput)
    {
        HeapFree(GetProcessHeap(), 0, pvInput);
    }
    return ERROR_SUCCESS;
}

// ============================================================================
// NCrypt Key Operations
// ============================================================================

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
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(pbInput);
    UNREFERENCED_PARAMETER(cbInput);
    UNREFERENCED_PARAMETER(pPaddingInfo);
    UNREFERENCED_PARAMETER(pbOutput);
    UNREFERENCED_PARAMETER(cbOutput);
    UNREFERENCED_PARAMETER(pcbResult);
    UNREFERENCED_PARAMETER(dwFlags);
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
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(pbInput);
    UNREFERENCED_PARAMETER(cbInput);
    UNREFERENCED_PARAMETER(pPaddingInfo);
    UNREFERENCED_PARAMETER(pbOutput);
    UNREFERENCED_PARAMETER(cbOutput);
    UNREFERENCED_PARAMETER(pcbResult);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI AuthentikKSPIsAlgSupported(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ LPCWSTR pszAlgId,
    _In_ DWORD dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(dwFlags);
    
    if (pszAlgId && wcscmp(pszAlgId, BCRYPT_RSA_ALGORITHM) == 0)
        return ERROR_SUCCESS;
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI AuthentikKSPEnumAlgorithms(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ DWORD dwAlgOperations,
    _Out_ DWORD* pdwAlgCount,
    _Outptr_result_buffer_(*pdwAlgCount) NCryptAlgorithmName** ppAlgList,
    _In_ DWORD dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(dwAlgOperations);
    UNREFERENCED_PARAMETER(pdwAlgCount);
    UNREFERENCED_PARAMETER(ppAlgList);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI AuthentikKSPEnumKeys(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_opt_ LPCWSTR pszScope,
    _Outptr_ NCryptKeyName** ppKeyName,
    _Inout_ PVOID* ppEnumState,
    _In_ DWORD dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(pszScope);
    UNREFERENCED_PARAMETER(ppKeyName);
    UNREFERENCED_PARAMETER(ppEnumState);
    UNREFERENCED_PARAMETER(dwFlags);
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
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hImportKey);
    UNREFERENCED_PARAMETER(pszBlobType);
    UNREFERENCED_PARAMETER(pParameterList);
    UNREFERENCED_PARAMETER(phKey);
    UNREFERENCED_PARAMETER(pbData);
    UNREFERENCED_PARAMETER(cbData);
    UNREFERENCED_PARAMETER(dwFlags);
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
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(hExportKey);
    UNREFERENCED_PARAMETER(pszBlobType);
    UNREFERENCED_PARAMETER(pParameterList);
    UNREFERENCED_PARAMETER(pbOutput);
    UNREFERENCED_PARAMETER(cbOutput);
    UNREFERENCED_PARAMETER(pcbResult);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
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
    UNREFERENCED_PARAMETER(hProvider);
    
    KSP_LOG("SignHash: hashLen=%d, sigBufLen=%d, flags=0x%x", cbHashValue, cbSignature, dwFlags);

    if (!ValidateKeyHandle(hKey)) return NTE_INVALID_HANDLE;
    if (!pbHashValue || !pcbResult) return NTE_INVALID_PARAMETER;

    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;
    if (!pKey->hBCryptKey) return NTE_BAD_KEY;

    __try
    {
        ULONG cbResult = 0;
        NTSTATUS status;

        if (dwFlags & BCRYPT_PAD_PKCS1)
        {
            status = BCryptSignHash(pKey->hBCryptKey, pPaddingInfo, pbHashValue, cbHashValue,
                pbSignature, cbSignature, &cbResult, dwFlags);
        }
        else
        {
            BCRYPT_PKCS1_PADDING_INFO paddingInfo = { BCRYPT_SHA256_ALGORITHM };
            status = BCryptSignHash(pKey->hBCryptKey, &paddingInfo, pbHashValue, cbHashValue,
                pbSignature, cbSignature, &cbResult, BCRYPT_PAD_PKCS1);
        }

        *pcbResult = cbResult;

        if (status == STATUS_BUFFER_TOO_SMALL) return NTE_BUFFER_TOO_SMALL;
        if (!BCRYPT_SUCCESS(status))
        {
            KSP_LOG("BCryptSignHash failed: 0x%08x", status);
            return NTE_INTERNAL_ERROR;
        }

        KSP_LOG("SignHash succeeded: %d bytes", cbResult);
        return ERROR_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return NTE_FAIL;
    }
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
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(pPaddingInfo);
    UNREFERENCED_PARAMETER(pbHashValue);
    UNREFERENCED_PARAMETER(cbHashValue);
    UNREFERENCED_PARAMETER(pbSignature);
    UNREFERENCED_PARAMETER(cbSignature);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI AuthentikKSPPromptUser(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_opt_ NCRYPT_KEY_HANDLE hKey,
    _In_ LPCWSTR pszOperation,
    _In_ DWORD dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(pszOperation);
    UNREFERENCED_PARAMETER(dwFlags);
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI AuthentikKSPNotifyChangeKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _Inout_ HANDLE* phEvent,
    _In_ DWORD dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(phEvent);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI AuthentikKSPSecretAgreement(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_KEY_HANDLE hPrivKey,
    _In_ NCRYPT_KEY_HANDLE hPubKey,
    _Out_ NCRYPT_SECRET_HANDLE* phSecret,
    _In_ DWORD dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hPrivKey);
    UNREFERENCED_PARAMETER(hPubKey);
    UNREFERENCED_PARAMETER(phSecret);
    UNREFERENCED_PARAMETER(dwFlags);
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
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hSharedSecret);
    UNREFERENCED_PARAMETER(pwszKDF);
    UNREFERENCED_PARAMETER(pParameterList);
    UNREFERENCED_PARAMETER(pbDerivedKey);
    UNREFERENCED_PARAMETER(cbDerivedKey);
    UNREFERENCED_PARAMETER(pcbResult);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI AuthentikKSPFreeSecret(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_SECRET_HANDLE hSharedSecret)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hSharedSecret);
    return NTE_NOT_SUPPORTED;
}

// ============================================================================
// Helper Export for Credential Provider
// ============================================================================

extern "C" __declspec(dllexport)
HRESULT WINAPI AuthentikKSP_StoreKey(
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

    if (!TryInitializeKeyStore())
        return E_FAIL;

    __try
    {
        WaitForSingleObject(g_hMutex, 5000);

        DWORD cbEntry = sizeof(AUTHENTIK_KEY_ENTRY) + cbPrivateKey + cbCertificate;
        DWORD cbNewTotal = g_pKeyStore->cbTotalSize + cbEntry;

        if (cbNewTotal > AUTHENTIK_SHARED_MEM_SIZE)
        {
            ReleaseMutex(g_hMutex);
            return E_OUTOFMEMORY;
        }

        PAUTHENTIK_KEY_ENTRY pEntry = (PAUTHENTIK_KEY_ENTRY)((PBYTE)g_pKeyStore + g_pKeyStore->cbTotalSize);
        pEntry->dwMagic = AUTHENTIK_KEY_MAGIC;
        pEntry->dwFlags = 0;
        pEntry->dwKeySpec = dwKeySpec;
        GetSystemTimeAsFileTime(&pEntry->ftCreated);

        ULARGE_INTEGER expiry;
        expiry.LowPart = pEntry->ftCreated.dwLowDateTime;
        expiry.HighPart = pEntry->ftCreated.dwHighDateTime;
        expiry.QuadPart += (ULONGLONG)dwValidityMinutes * 60 * 10000000;
        pEntry->ftExpires.dwLowDateTime = expiry.LowPart;
        pEntry->ftExpires.dwHighDateTime = expiry.HighPart;

        wcscpy_s(pEntry->wszContainerName, wszContainerName);
        wcscpy_s(pEntry->wszUserName, wszUserName);
        pEntry->cbPrivateKey = cbPrivateKey;
        pEntry->cbCertificate = cbCertificate;

        memcpy(pEntry->rgbData, pbPrivateKey, cbPrivateKey);
        memcpy(pEntry->rgbData + cbPrivateKey, pbCertificate, cbCertificate);

        g_pKeyStore->cKeys++;
        g_pKeyStore->cbTotalSize = cbNewTotal;

        ReleaseMutex(g_hMutex);
        KSP_LOG("Key stored successfully");
        return S_OK;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        ReleaseMutex(g_hMutex);
        return E_FAIL;
    }
}

extern "C" __declspec(dllexport)
LPCWSTR WINAPI AuthentikKSP_GetProviderName(void)
{
    return AUTHENTIK_KSP_NAME;
}

extern "C" __declspec(dllexport)
HRESULT WINAPI AuthentikKSP_RemoveKey(
    _In_ LPCWSTR wszContainerName)
{
    KSP_LOG("RemoveKey: container=%S", wszContainerName ? wszContainerName : L"(null)");

    if (!wszContainerName)
        return E_INVALIDARG;

    if (!TryInitializeKeyStore())
        return E_FAIL;

    __try
    {
        WaitForSingleObject(g_hMutex, 5000);

        // Find and mark the key as expired (simple removal strategy)
        PBYTE pCurrent = (PBYTE)g_pKeyStore + sizeof(AUTHENTIK_KEY_STORE_HEADER);
        PBYTE pEnd = (PBYTE)g_pKeyStore + g_pKeyStore->cbTotalSize;

        for (DWORD i = 0; i < g_pKeyStore->cKeys && pCurrent < pEnd; i++)
        {
            PAUTHENTIK_KEY_ENTRY pEntry = (PAUTHENTIK_KEY_ENTRY)pCurrent;
            if (pEntry->dwMagic == AUTHENTIK_KEY_MAGIC)
            {
                if (_wcsicmp(pEntry->wszContainerName, wszContainerName) == 0)
                {
                    // Mark as expired by setting expiry to past
                    pEntry->ftExpires.dwLowDateTime = 0;
                    pEntry->ftExpires.dwHighDateTime = 0;
                    ReleaseMutex(g_hMutex);
                    KSP_LOG("Key removed (marked expired)");
                    return S_OK;
                }
                DWORD entrySize = sizeof(AUTHENTIK_KEY_ENTRY) + pEntry->cbPrivateKey + pEntry->cbCertificate;
                pCurrent += entrySize;
            }
            else break;
        }

        ReleaseMutex(g_hMutex);
        KSP_LOG("Key not found for removal");
        return S_FALSE;  // Not found, but not an error
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        ReleaseMutex(g_hMutex);
        return E_FAIL;
    }
}

extern "C" __declspec(dllexport)
BOOL WINAPI AuthentikKSP_KeyExists(
    _In_ LPCWSTR wszContainerName)
{
    KSP_LOG("KeyExists: container=%S", wszContainerName ? wszContainerName : L"(null)");

    if (!wszContainerName)
        return FALSE;

    if (!TryInitializeKeyStore())
        return FALSE;

    PAUTHENTIK_KEY_ENTRY pEntry = FindKeyEntry(wszContainerName);
    BOOL exists = (pEntry != NULL);
    
    KSP_LOG("KeyExists: %s", exists ? "YES" : "NO");
    return exists;
}
