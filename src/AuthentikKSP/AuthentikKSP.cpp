// AuthentikKSP.cpp
// Authentik Key Storage Provider - Main Implementation

#include "AuthentikKSP.h"
#include <stdio.h>
#include <stdarg.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")

// Global variables
static long g_cDllRef = 0;
static HINSTANCE g_hInstance = NULL;
static CRITICAL_SECTION g_csKeyStore;
static BOOL g_bInitialized = FALSE;

// Simple key storage (single key for now)
static PAUTHENTIK_KEY g_pCurrentKey = NULL;

// BCrypt algorithm provider
static BCRYPT_ALG_HANDLE g_hRsaAlg = NULL;

// Function table
static AUTHENTIK_KSP_FUNCTION_TABLE g_FunctionTable = {
    sizeof(AUTHENTIK_KSP_FUNCTION_TABLE),
    KSPOpenProvider,
    KSPOpenKey,
    KSPCreatePersistedKey,
    KSPGetProviderProperty,
    KSPGetKeyProperty,
    KSPSetProviderProperty,
    KSPSetKeyProperty,
    KSPFinalizeKey,
    KSPDeleteKey,
    KSPFreeProvider,
    KSPFreeKey,
    KSPFreeBuffer,
    KSPEncrypt,
    KSPDecrypt,
    KSPIsAlgSupported,
    KSPEnumAlgorithms,
    KSPEnumKeys,
    KSPImportKey,
    KSPExportKey,
    KSPSignHash,
    KSPVerifySignature,
    NULL,  // PromptUser - not implemented
    KSPNotifyChangeKey,
    KSPSecretAgreement,
    KSPDeriveKey,
    KSPFreeSecret
};

// Logging function
void KSPLog(const char* format, ...)
{
    char buffer[1024];
    char message[1200];
    
    va_list args;
    va_start(args, format);
    vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
    va_end(args);
    
    _snprintf_s(message, sizeof(message), _TRUNCATE, "[AuthentikKSP] %s\n", buffer);
    OutputDebugStringA(message);
}

// DLL reference counting
void DllAddRef(void)
{
    InterlockedIncrement(&g_cDllRef);
}

void DllRelease(void)
{
    InterlockedDecrement(&g_cDllRef);
}

// Initialize globals
static void InitializeGlobals(void)
{
    if (!g_bInitialized)
    {
        InitializeCriticalSection(&g_csKeyStore);
        g_bInitialized = TRUE;
        KSPLog("Globals initialized");
    }
}

// Validate provider handle
BOOL ValidateProviderHandle(NCRYPT_PROV_HANDLE hProvider)
{
    if (hProvider == 0) return FALSE;
    
    PAUTHENTIK_PROVIDER pProvider = (PAUTHENTIK_PROVIDER)hProvider;
    
    // Simple validation without SEH
    if (IsBadReadPtr(pProvider, sizeof(AUTHENTIK_PROVIDER)))
        return FALSE;
    
    if (pProvider->dwMagic != AUTHENTIK_PROVIDER_MAGIC)
        return FALSE;
    
    return TRUE;
}

// Validate key handle
BOOL ValidateKeyHandle(NCRYPT_KEY_HANDLE hKey)
{
    if (hKey == 0) return FALSE;
    
    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;
    
    if (IsBadReadPtr(pKey, sizeof(AUTHENTIK_KEY)))
        return FALSE;
    
    if (pKey->dwMagic != AUTHENTIK_KEY_MAGIC)
        return FALSE;
    
    return TRUE;
}

// Clean up a key
void CleanupKey(PAUTHENTIK_KEY pKey)
{
    if (pKey == NULL) return;
    
    KSPLog("CleanupKey: %S", pKey->wszKeyName);
    
    if (pKey->hBcryptKey)
    {
        BCryptDestroyKey(pKey->hBcryptKey);
        pKey->hBcryptKey = NULL;
    }
    
    if (pKey->pbCertificate)
    {
        SecureZeroMemory(pKey->pbCertificate, pKey->cbCertificate);
        HeapFree(GetProcessHeap(), 0, pKey->pbCertificate);
        pKey->pbCertificate = NULL;
    }
    
    if (pKey->pbPrivateKeyBlob)
    {
        SecureZeroMemory(pKey->pbPrivateKeyBlob, pKey->cbPrivateKeyBlob);
        HeapFree(GetProcessHeap(), 0, pKey->pbPrivateKeyBlob);
        pKey->pbPrivateKeyBlob = NULL;
    }
    
    SecureZeroMemory(pKey, sizeof(AUTHENTIK_KEY));
    HeapFree(GetProcessHeap(), 0, pKey);
}

// Create key from shared memory
PAUTHENTIK_KEY CreateKeyFromSharedMemory(PAUTHENTIK_PROVIDER pProvider)
{
    KSPLog("CreateKeyFromSharedMemory");
    
    if (pProvider == NULL || pProvider->pSharedData == NULL)
    {
        KSPLog("ERROR: No shared data available");
        return NULL;
    }
    
    // Wait for mutex
    if (pProvider->hMutex)
    {
        DWORD waitResult = WaitForSingleObject(pProvider->hMutex, 5000);
        if (waitResult != WAIT_OBJECT_0)
        {
            KSPLog("ERROR: Failed to acquire mutex");
            return NULL;
        }
    }
    
    PAUTHENTIK_KEY pKey = NULL;
    PAUTHENTIK_SHARED_DATA pData = pProvider->pSharedData;
    
    // Validate magic
    if (pData->dwMagic != AUTHENTIK_SHARED_MAGIC)
    {
        KSPLog("ERROR: Invalid shared memory magic: 0x%08X", pData->dwMagic);
        goto cleanup;
    }
    
    // Check if data is ready
    if (!pData->bDataReady)
    {
        KSPLog("ERROR: Shared data not ready");
        goto cleanup;
    }
    
    // Check if already consumed
    if (pData->bDataConsumed)
    {
        KSPLog("ERROR: Shared data already consumed");
        goto cleanup;
    }
    
    KSPLog("Found shared data for user: %S", pData->wszUsername);
    KSPLog("Certificate size: %d, Private key size: %d", pData->cbCertificate, pData->cbPrivateKey);
    
    // Allocate key structure
    pKey = (PAUTHENTIK_KEY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(AUTHENTIK_KEY));
    if (pKey == NULL)
    {
        KSPLog("ERROR: Failed to allocate key structure");
        goto cleanup;
    }
    
    // Initialize key
    pKey->dwMagic = AUTHENTIK_KEY_MAGIC;
    wcscpy_s(pKey->wszUsername, MAX_USERNAME_SIZE, pData->wszUsername);
    _snwprintf_s(pKey->wszKeyName, 256, _TRUNCATE, L"%s%s", AUTHENTIK_KEY_PREFIX, pData->wszUsername);
    pKey->dwKeySpec = pData->dwKeySpec;
    pKey->bFromSharedMemory = TRUE;
    
    // Copy certificate
    if (pData->cbCertificate > 0 && pData->cbCertificate <= MAX_CERTIFICATE_SIZE)
    {
        pKey->cbCertificate = pData->cbCertificate;
        pKey->pbCertificate = (PBYTE)HeapAlloc(GetProcessHeap(), 0, pData->cbCertificate);
        if (pKey->pbCertificate == NULL)
        {
            KSPLog("ERROR: Failed to allocate certificate buffer");
            goto cleanup_key;
        }
        CopyMemory(pKey->pbCertificate, pData->rgbCertificate, pData->cbCertificate);
        KSPLog("Copied certificate: %d bytes", pKey->cbCertificate);
    }
    
    // Copy and import private key
    if (pData->cbPrivateKey > 0 && pData->cbPrivateKey <= MAX_PRIVATE_KEY_SIZE)
    {
        pKey->cbPrivateKeyBlob = pData->cbPrivateKey;
        pKey->pbPrivateKeyBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, pData->cbPrivateKey);
        if (pKey->pbPrivateKeyBlob == NULL)
        {
            KSPLog("ERROR: Failed to allocate private key buffer");
            goto cleanup_key;
        }
        CopyMemory(pKey->pbPrivateKeyBlob, pData->rgbPrivateKey, pData->cbPrivateKey);
        KSPLog("Copied private key blob: %d bytes", pKey->cbPrivateKeyBlob);
        
        // Open RSA algorithm provider if needed
        if (g_hRsaAlg == NULL)
        {
            NTSTATUS status = BCryptOpenAlgorithmProvider(&g_hRsaAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
            if (!NT_SUCCESS(status))
            {
                KSPLog("ERROR: BCryptOpenAlgorithmProvider failed: 0x%08X", status);
                goto cleanup_key;
            }
        }
        
        // Import the key
        NTSTATUS status = BCryptImportKeyPair(
            g_hRsaAlg,
            NULL,
            BCRYPT_RSAFULLPRIVATE_BLOB,
            &pKey->hBcryptKey,
            pKey->pbPrivateKeyBlob,
            pKey->cbPrivateKeyBlob,
            0);
        
        if (!NT_SUCCESS(status))
        {
            KSPLog("ERROR: BCryptImportKeyPair failed: 0x%08X", status);
            goto cleanup_key;
        }
        
        KSPLog("Successfully imported BCrypt key");
    }
    
    // Mark data as consumed
    pData->bDataConsumed = TRUE;
    
    // Store as current key
    EnterCriticalSection(&g_csKeyStore);
    if (g_pCurrentKey != NULL)
    {
        CleanupKey(g_pCurrentKey);
    }
    g_pCurrentKey = pKey;
    LeaveCriticalSection(&g_csKeyStore);
    
    KSPLog("Key created successfully: %S", pKey->wszKeyName);
    
    if (pProvider->hMutex)
        ReleaseMutex(pProvider->hMutex);
    
    return pKey;

cleanup_key:
    CleanupKey(pKey);
    pKey = NULL;
    
cleanup:
    if (pProvider->hMutex)
        ReleaseMutex(pProvider->hMutex);
    
    return NULL;
}

//
// KSP Implementation
//

SECURITY_STATUS WINAPI KSPOpenProvider(
    NCRYPT_PROV_HANDLE *phProvider,
    LPCWSTR pszProviderName,
    DWORD dwFlags)
{
    KSPLog("KSPOpenProvider: %S", pszProviderName ? pszProviderName : L"(null)");
    
    InitializeGlobals();
    
    if (phProvider == NULL)
        return NTE_INVALID_PARAMETER;
    
    *phProvider = 0;
    
    // Allocate provider structure
    PAUTHENTIK_PROVIDER pProvider = (PAUTHENTIK_PROVIDER)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(AUTHENTIK_PROVIDER));
    
    if (pProvider == NULL)
    {
        KSPLog("ERROR: Failed to allocate provider");
        return NTE_NO_MEMORY;
    }
    
    pProvider->dwMagic = AUTHENTIK_PROVIDER_MAGIC;
    
    // Try to open shared memory
    pProvider->hMutex = OpenMutexW(SYNCHRONIZE, FALSE, AUTHENTIK_MUTEX_NAME);
    if (pProvider->hMutex)
    {
        KSPLog("Opened mutex");
        
        pProvider->hSharedMemory = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, AUTHENTIK_SHARED_MEMORY_NAME);
        if (pProvider->hSharedMemory)
        {
            pProvider->pSharedData = (PAUTHENTIK_SHARED_DATA)MapViewOfFile(
                pProvider->hSharedMemory,
                FILE_MAP_READ | FILE_MAP_WRITE,
                0, 0,
                sizeof(AUTHENTIK_SHARED_DATA));
            
            if (pProvider->pSharedData)
            {
                KSPLog("Mapped shared memory successfully");
            }
            else
            {
                KSPLog("WARNING: Failed to map shared memory: %d", GetLastError());
            }
        }
        else
        {
            KSPLog("WARNING: Failed to open shared memory: %d", GetLastError());
        }
    }
    else
    {
        KSPLog("WARNING: Failed to open mutex: %d (credential provider may not be running)", GetLastError());
    }
    
    DllAddRef();
    *phProvider = (NCRYPT_PROV_HANDLE)pProvider;
    
    KSPLog("Provider opened: 0x%p", pProvider);
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPFreeProvider(NCRYPT_PROV_HANDLE hProvider)
{
    KSPLog("KSPFreeProvider: 0x%p", (void*)hProvider);
    
    if (!ValidateProviderHandle(hProvider))
        return NTE_INVALID_HANDLE;
    
    PAUTHENTIK_PROVIDER pProvider = (PAUTHENTIK_PROVIDER)hProvider;
    
    if (pProvider->pSharedData)
    {
        UnmapViewOfFile(pProvider->pSharedData);
        pProvider->pSharedData = NULL;
    }
    
    if (pProvider->hSharedMemory)
    {
        CloseHandle(pProvider->hSharedMemory);
        pProvider->hSharedMemory = NULL;
    }
    
    if (pProvider->hMutex)
    {
        CloseHandle(pProvider->hMutex);
        pProvider->hMutex = NULL;
    }
    
    SecureZeroMemory(pProvider, sizeof(AUTHENTIK_PROVIDER));
    HeapFree(GetProcessHeap(), 0, pProvider);
    
    DllRelease();
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPOpenKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE *phKey,
    LPCWSTR pszKeyName,
    DWORD dwLegacyKeySpec,
    DWORD dwFlags)
{
    KSPLog("KSPOpenKey: %S, KeySpec: %d", pszKeyName ? pszKeyName : L"(null)", dwLegacyKeySpec);
    
    if (!ValidateProviderHandle(hProvider))
        return NTE_INVALID_HANDLE;
    
    if (phKey == NULL)
        return NTE_INVALID_PARAMETER;
    
    *phKey = 0;
    
    PAUTHENTIK_PROVIDER pProvider = (PAUTHENTIK_PROVIDER)hProvider;
    
    // Try to get key from shared memory
    PAUTHENTIK_KEY pKey = CreateKeyFromSharedMemory(pProvider);
    
    if (pKey == NULL)
    {
        // Check if we have a cached key
        EnterCriticalSection(&g_csKeyStore);
        if (g_pCurrentKey != NULL)
        {
            // Return the cached key (add ref by creating a copy or just return it)
            pKey = g_pCurrentKey;
            KSPLog("Using cached key: %S", pKey->wszKeyName);
        }
        LeaveCriticalSection(&g_csKeyStore);
    }
    
    if (pKey == NULL)
    {
        KSPLog("ERROR: No key available");
        return NTE_BAD_KEYSET;
    }
    
    *phKey = (NCRYPT_KEY_HANDLE)pKey;
    KSPLog("Key opened: 0x%p", pKey);
    
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPCreatePersistedKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE *phKey,
    LPCWSTR pszAlgId,
    LPCWSTR pszKeyName,
    DWORD dwLegacyKeySpec,
    DWORD dwFlags)
{
    KSPLog("KSPCreatePersistedKey: %S (not implemented)", pszKeyName ? pszKeyName : L"(null)");
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPFinalizeKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hKey,
    DWORD dwFlags)
{
    KSPLog("KSPFinalizeKey");
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPDeleteKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hKey,
    DWORD dwFlags)
{
    KSPLog("KSPDeleteKey");
    
    if (!ValidateKeyHandle(hKey))
        return NTE_INVALID_HANDLE;
    
    // Don't actually delete, just return success
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPFreeKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hKey)
{
    KSPLog("KSPFreeKey: 0x%p", (void*)hKey);
    
    // Don't free the cached key
    // Just return success
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPGetProviderProperty(
    NCRYPT_PROV_HANDLE hProvider,
    LPCWSTR pszProperty,
    PBYTE pbOutput,
    DWORD cbOutput,
    DWORD *pcbResult,
    DWORD dwFlags)
{
    KSPLog("KSPGetProviderProperty: %S", pszProperty ? pszProperty : L"(null)");
    
    if (!ValidateProviderHandle(hProvider))
        return NTE_INVALID_HANDLE;
    
    if (pszProperty == NULL || pcbResult == NULL)
        return NTE_INVALID_PARAMETER;
    
    // Handle known properties
    if (wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0)
    {
        DWORD cbName = (DWORD)((wcslen(AUTHENTIK_KSP_NAME) + 1) * sizeof(WCHAR));
        *pcbResult = cbName;
        
        if (pbOutput == NULL)
            return ERROR_SUCCESS;
        
        if (cbOutput < cbName)
            return NTE_BUFFER_TOO_SMALL;
        
        wcscpy_s((LPWSTR)pbOutput, cbOutput / sizeof(WCHAR), AUTHENTIK_KSP_NAME);
        return ERROR_SUCCESS;
    }
    
    if (wcscmp(pszProperty, NCRYPT_IMPL_TYPE_PROPERTY) == 0)
    {
        *pcbResult = sizeof(DWORD);
        
        if (pbOutput == NULL)
            return ERROR_SUCCESS;
        
        if (cbOutput < sizeof(DWORD))
            return NTE_BUFFER_TOO_SMALL;
        
        *(DWORD*)pbOutput = NCRYPT_IMPL_SOFTWARE_FLAG;
        return ERROR_SUCCESS;
    }
    
    KSPLog("Unknown property: %S", pszProperty);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPGetKeyProperty(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hKey,
    LPCWSTR pszProperty,
    PBYTE pbOutput,
    DWORD cbOutput,
    DWORD *pcbResult,
    DWORD dwFlags)
{
    KSPLog("KSPGetKeyProperty: %S", pszProperty ? pszProperty : L"(null)");
    
    if (!ValidateKeyHandle(hKey))
        return NTE_INVALID_HANDLE;
    
    if (pszProperty == NULL || pcbResult == NULL)
        return NTE_INVALID_PARAMETER;
    
    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;
    
    // Certificate property - critical for PKINIT
    if (wcscmp(pszProperty, NCRYPT_CERTIFICATE_PROPERTY) == 0)
    {
        KSPLog("Returning certificate: %d bytes", pKey->cbCertificate);
        
        *pcbResult = pKey->cbCertificate;
        
        if (pbOutput == NULL)
            return ERROR_SUCCESS;
        
        if (cbOutput < pKey->cbCertificate)
            return NTE_BUFFER_TOO_SMALL;
        
        if (pKey->pbCertificate)
        {
            CopyMemory(pbOutput, pKey->pbCertificate, pKey->cbCertificate);
        }
        return ERROR_SUCCESS;
    }
    
    // Key name
    if (wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0)
    {
        DWORD cbName = (DWORD)((wcslen(pKey->wszKeyName) + 1) * sizeof(WCHAR));
        *pcbResult = cbName;
        
        if (pbOutput == NULL)
            return ERROR_SUCCESS;
        
        if (cbOutput < cbName)
            return NTE_BUFFER_TOO_SMALL;
        
        wcscpy_s((LPWSTR)pbOutput, cbOutput / sizeof(WCHAR), pKey->wszKeyName);
        return ERROR_SUCCESS;
    }
    
    // Key length
    if (wcscmp(pszProperty, NCRYPT_LENGTH_PROPERTY) == 0)
    {
        *pcbResult = sizeof(DWORD);
        
        if (pbOutput == NULL)
            return ERROR_SUCCESS;
        
        if (cbOutput < sizeof(DWORD))
            return NTE_BUFFER_TOO_SMALL;
        
        *(DWORD*)pbOutput = 2048;  // Assume 2048-bit key
        return ERROR_SUCCESS;
    }
    
    // Algorithm name
    if (wcscmp(pszProperty, NCRYPT_ALGORITHM_PROPERTY) == 0)
    {
        LPCWSTR pszAlg = BCRYPT_RSA_ALGORITHM;
        DWORD cbAlg = (DWORD)((wcslen(pszAlg) + 1) * sizeof(WCHAR));
        *pcbResult = cbAlg;
        
        if (pbOutput == NULL)
            return ERROR_SUCCESS;
        
        if (cbOutput < cbAlg)
            return NTE_BUFFER_TOO_SMALL;
        
        wcscpy_s((LPWSTR)pbOutput, cbOutput / sizeof(WCHAR), pszAlg);
        return ERROR_SUCCESS;
    }
    
    // Key usage
    if (wcscmp(pszProperty, NCRYPT_KEY_USAGE_PROPERTY) == 0)
    {
        *pcbResult = sizeof(DWORD);
        
        if (pbOutput == NULL)
            return ERROR_SUCCESS;
        
        if (cbOutput < sizeof(DWORD))
            return NTE_BUFFER_TOO_SMALL;
        
        *(DWORD*)pbOutput = NCRYPT_ALLOW_SIGNING_FLAG | NCRYPT_ALLOW_DECRYPT_FLAG;
        return ERROR_SUCCESS;
    }
    
    // Export policy
    if (wcscmp(pszProperty, NCRYPT_EXPORT_POLICY_PROPERTY) == 0)
    {
        *pcbResult = sizeof(DWORD);
        
        if (pbOutput == NULL)
            return ERROR_SUCCESS;
        
        if (cbOutput < sizeof(DWORD))
            return NTE_BUFFER_TOO_SMALL;
        
        *(DWORD*)pbOutput = 0;  // No export allowed
        return ERROR_SUCCESS;
    }
    
    KSPLog("Unknown key property: %S", pszProperty);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPSetProviderProperty(
    NCRYPT_PROV_HANDLE hProvider,
    LPCWSTR pszProperty,
    PBYTE pbInput,
    DWORD cbInput,
    DWORD dwFlags)
{
    KSPLog("KSPSetProviderProperty: %S", pszProperty ? pszProperty : L"(null)");
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPSetKeyProperty(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hKey,
    LPCWSTR pszProperty,
    PBYTE pbInput,
    DWORD cbInput,
    DWORD dwFlags)
{
    KSPLog("KSPSetKeyProperty: %S", pszProperty ? pszProperty : L"(null)");
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPEncrypt(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hKey,
    PBYTE pbInput,
    DWORD cbInput,
    VOID *pPaddingInfo,
    PBYTE pbOutput,
    DWORD cbOutput,
    DWORD *pcbResult,
    DWORD dwFlags)
{
    KSPLog("KSPEncrypt");
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPDecrypt(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hKey,
    PBYTE pbInput,
    DWORD cbInput,
    VOID *pPaddingInfo,
    PBYTE pbOutput,
    DWORD cbOutput,
    DWORD *pcbResult,
    DWORD dwFlags)
{
    KSPLog("KSPDecrypt");
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPSignHash(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hKey,
    VOID *pPaddingInfo,
    PBYTE pbHashValue,
    DWORD cbHashValue,
    PBYTE pbSignature,
    DWORD cbSignature,
    DWORD *pcbResult,
    DWORD dwFlags)
{
    KSPLog("KSPSignHash: HashSize=%d, SigBufSize=%d, Flags=0x%08X", cbHashValue, cbSignature, dwFlags);
    
    if (!ValidateKeyHandle(hKey))
        return NTE_INVALID_HANDLE;
    
    if (pbHashValue == NULL || pcbResult == NULL)
        return NTE_INVALID_PARAMETER;
    
    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;
    
    if (pKey->hBcryptKey == NULL)
    {
        KSPLog("ERROR: No BCrypt key handle");
        return NTE_BAD_KEY;
    }
    
    // Use BCrypt to sign
    ULONG cbResult = 0;
    NTSTATUS status = BCryptSignHash(
        pKey->hBcryptKey,
        pPaddingInfo,
        pbHashValue,
        cbHashValue,
        pbSignature,
        cbSignature,
        &cbResult,
        dwFlags);
    
    *pcbResult = cbResult;
    
    if (!NT_SUCCESS(status))
    {
        KSPLog("ERROR: BCryptSignHash failed: 0x%08X", status);
        return NTE_INTERNAL_ERROR;
    }
    
    KSPLog("Signature created: %d bytes", cbResult);
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPVerifySignature(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hKey,
    VOID *pPaddingInfo,
    PBYTE pbHashValue,
    DWORD cbHashValue,
    PBYTE pbSignature,
    DWORD cbSignature,
    DWORD dwFlags)
{
    KSPLog("KSPVerifySignature");
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPIsAlgSupported(
    NCRYPT_PROV_HANDLE hProvider,
    LPCWSTR pszAlgId,
    DWORD dwFlags)
{
    KSPLog("KSPIsAlgSupported: %S", pszAlgId ? pszAlgId : L"(null)");
    
    if (pszAlgId == NULL)
        return NTE_INVALID_PARAMETER;
    
    if (wcscmp(pszAlgId, BCRYPT_RSA_ALGORITHM) == 0)
        return ERROR_SUCCESS;
    
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPEnumAlgorithms(
    NCRYPT_PROV_HANDLE hProvider,
    DWORD dwAlgOperations,
    DWORD *pdwAlgCount,
    NCryptAlgorithmName **ppAlgList,
    DWORD dwFlags)
{
    KSPLog("KSPEnumAlgorithms");
    
    if (pdwAlgCount == NULL || ppAlgList == NULL)
        return NTE_INVALID_PARAMETER;
    
    // Allocate algorithm list
    NCryptAlgorithmName* pAlgList = (NCryptAlgorithmName*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NCryptAlgorithmName));
    
    if (pAlgList == NULL)
        return NTE_NO_MEMORY;
    
    pAlgList->pszName = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, 16 * sizeof(WCHAR));
    if (pAlgList->pszName)
    {
        wcscpy_s(pAlgList->pszName, 16, BCRYPT_RSA_ALGORITHM);
    }
    pAlgList->dwClass = NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION;
    pAlgList->dwAlgOperations = NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION | NCRYPT_SIGNATURE_OPERATION;
    pAlgList->dwFlags = 0;
    
    *pdwAlgCount = 1;
    *ppAlgList = pAlgList;
    
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPEnumKeys(
    NCRYPT_PROV_HANDLE hProvider,
    LPCWSTR pszScope,
    NCryptKeyName **ppKeyName,
    PVOID *ppEnumState,
    DWORD dwFlags)
{
    KSPLog("KSPEnumKeys");
    
    if (ppKeyName == NULL || ppEnumState == NULL)
        return NTE_INVALID_PARAMETER;
    
    // Check if this is first call
    if (*ppEnumState == NULL)
    {
        // Check if we have a key
        EnterCriticalSection(&g_csKeyStore);
        PAUTHENTIK_KEY pKey = g_pCurrentKey;
        LeaveCriticalSection(&g_csKeyStore);
        
        if (pKey != NULL)
        {
            NCryptKeyName* pKeyName = (NCryptKeyName*)HeapAlloc(
                GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NCryptKeyName));
            
            if (pKeyName == NULL)
                return NTE_NO_MEMORY;
            
            DWORD cbName = (DWORD)((wcslen(pKey->wszKeyName) + 1) * sizeof(WCHAR));
            pKeyName->pszName = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, cbName);
            if (pKeyName->pszName)
            {
                wcscpy_s(pKeyName->pszName, cbName / sizeof(WCHAR), pKey->wszKeyName);
            }
            pKeyName->pszAlgid = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, 16 * sizeof(WCHAR));
            if (pKeyName->pszAlgid)
            {
                wcscpy_s(pKeyName->pszAlgid, 16, BCRYPT_RSA_ALGORITHM);
            }
            pKeyName->dwLegacyKeySpec = pKey->dwKeySpec;
            pKeyName->dwFlags = 0;
            
            *ppKeyName = pKeyName;
            *ppEnumState = (PVOID)1;  // Mark as enumerated
            return ERROR_SUCCESS;
        }
    }
    
    // No more keys
    return NTE_NO_MORE_ITEMS;
}

SECURITY_STATUS WINAPI KSPImportKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hImportKey,
    LPCWSTR pszBlobType,
    NCryptBufferDesc *pParameterList,
    NCRYPT_KEY_HANDLE *phKey,
    PBYTE pbData,
    DWORD cbData,
    DWORD dwFlags)
{
    KSPLog("KSPImportKey: %S", pszBlobType ? pszBlobType : L"(null)");
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPExportKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hKey,
    NCRYPT_KEY_HANDLE hExportKey,
    LPCWSTR pszBlobType,
    NCryptBufferDesc *pParameterList,
    PBYTE pbOutput,
    DWORD cbOutput,
    DWORD *pcbResult,
    DWORD dwFlags)
{
    KSPLog("KSPExportKey: %S", pszBlobType ? pszBlobType : L"(null)");
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPFreeBuffer(PVOID pvInput)
{
    KSPLog("KSPFreeBuffer: 0x%p", pvInput);
    
    if (pvInput)
    {
        HeapFree(GetProcessHeap(), 0, pvInput);
    }
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPNotifyChangeKey(
    NCRYPT_PROV_HANDLE hProvider,
    HANDLE *phEvent,
    DWORD dwFlags)
{
    KSPLog("KSPNotifyChangeKey");
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPSecretAgreement(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hPrivKey,
    NCRYPT_KEY_HANDLE hPubKey,
    NCRYPT_SECRET_HANDLE *phSecret,
    DWORD dwFlags)
{
    KSPLog("KSPSecretAgreement");
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPDeriveKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_SECRET_HANDLE hSharedSecret,
    LPCWSTR pwszKDF,
    NCryptBufferDesc *pParameterList,
    PBYTE pbDerivedKey,
    DWORD cbDerivedKey,
    DWORD *pcbResult,
    ULONG dwFlags)
{
    KSPLog("KSPDeriveKey");
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPFreeSecret(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_SECRET_HANDLE hSharedSecret)
{
    KSPLog("KSPFreeSecret");
    return NTE_NOT_SUPPORTED;
}

// DLL entry point for function table
NTSTATUS WINAPI GetKeyStorageInterface(
    LPCWSTR pszProviderName,
    AUTHENTIK_KSP_FUNCTION_TABLE **ppFunctionTable,
    DWORD dwFlags)
{
    KSPLog("GetKeyStorageInterface: %S", pszProviderName ? pszProviderName : L"(null)");
    
    InitializeGlobals();
    
    if (ppFunctionTable == NULL)
        return STATUS_INVALID_PARAMETER;
    
    *ppFunctionTable = &g_FunctionTable;
    return STATUS_SUCCESS;
}

// DLL Main
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        g_hInstance = hModule;
        DisableThreadLibraryCalls(hModule);
        KSPLog("DLL_PROCESS_ATTACH");
        break;
        
    case DLL_PROCESS_DETACH:
        KSPLog("DLL_PROCESS_DETACH");
        
        // Clean up
        if (g_pCurrentKey)
        {
            CleanupKey(g_pCurrentKey);
            g_pCurrentKey = NULL;
        }
        
        if (g_hRsaAlg)
        {
            BCryptCloseAlgorithmProvider(g_hRsaAlg, 0);
            g_hRsaAlg = NULL;
        }
        
        if (g_bInitialized)
        {
            DeleteCriticalSection(&g_csKeyStore);
            g_bInitialized = FALSE;
        }
        break;
    }
    return TRUE;
}
