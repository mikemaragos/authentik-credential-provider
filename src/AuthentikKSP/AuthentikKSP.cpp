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
static HINSTANCE g_hInstance = nullptr;
static std::mutex g_keyStoreMutex;
static std::map<std::wstring, PAUTHENTIK_KEY> g_keyStore;

// BCrypt algorithm provider
static BCRYPT_ALG_HANDLE g_hRsaAlg = nullptr;

// Function table
static NCRYPT_KEY_STORAGE_FUNCTION_TABLE g_FunctionTable = {
    NCRYPT_KEY_STORAGE_INTERFACE_VERSION,
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
    nullptr,  // PromptUser - not implemented
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
void DllAddRef()
{
    InterlockedIncrement(&g_cDllRef);
}

void DllRelease()
{
    InterlockedDecrement(&g_cDllRef);
}

// Validate provider handle
BOOL ValidateProviderHandle(NCRYPT_PROV_HANDLE hProvider)
{
    if (hProvider == 0) return FALSE;
    
    PAUTHENTIK_PROVIDER pProvider = (PAUTHENTIK_PROVIDER)hProvider;
    
    __try {
        if (pProvider->dwMagic != AUTHENTIK_PROVIDER_MAGIC) {
            return FALSE;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    
    return TRUE;
}

// Validate key handle
BOOL ValidateKeyHandle(NCRYPT_KEY_HANDLE hKey)
{
    if (hKey == 0) return FALSE;
    
    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;
    
    __try {
        if (pKey->dwMagic != AUTHENTIK_KEY_MAGIC) {
            return FALSE;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    
    return TRUE;
}

// Create key from shared memory data
PAUTHENTIK_KEY CreateKeyFromSharedMemory(PAUTHENTIK_PROVIDER pProvider)
{
    KSPLog("CreateKeyFromSharedMemory");
    
    if (!pProvider || !pProvider->pSharedData) {
        KSPLog("ERROR: Invalid provider or shared data");
        return nullptr;
    }
    
    // Wait for mutex
    DWORD waitResult = WaitForSingleObject(pProvider->hMutex, 5000);
    if (waitResult != WAIT_OBJECT_0) {
        KSPLog("ERROR: Failed to acquire mutex: %d", waitResult);
        return nullptr;
    }
    
    PAUTHENTIK_KEY pKey = nullptr;
    
    __try {
        PAUTHENTIK_SHARED_DATA pData = pProvider->pSharedData;
        
        // Validate shared memory
        if (pData->dwMagic != AUTHENTIK_SHARED_MAGIC) {
            KSPLog("ERROR: Invalid shared memory magic: 0x%08X", pData->dwMagic);
            __leave;
        }
        
        if (!pData->bDataReady) {
            KSPLog("ERROR: Shared data not ready");
            __leave;
        }
        
        if (pData->cbCertificate == 0 || pData->cbPrivateKey == 0) {
            KSPLog("ERROR: Empty certificate or private key");
            __leave;
        }
        
        KSPLog("Creating key for user: %S", pData->wszUsername);
        KSPLog("Certificate size: %d, Key size: %d", pData->cbCertificate, pData->cbPrivateKey);
        
        // Allocate key structure
        pKey = new AUTHENTIK_KEY();
        ZeroMemory(pKey, sizeof(AUTHENTIK_KEY));
        
        pKey->dwMagic = AUTHENTIK_KEY_MAGIC;
        pKey->wszUsername = pData->wszUsername;
        pKey->wszKeyName = AUTHENTIK_KEY_PREFIX + pKey->wszUsername;
        pKey->dwKeySpec = pData->dwKeySpec;
        pKey->bFromSharedMemory = TRUE;
        
        // Copy certificate
        pKey->cbCertificate = pData->cbCertificate;
        pKey->pbCertificate = (PBYTE)HeapAlloc(GetProcessHeap(), 0, pData->cbCertificate);
        if (!pKey->pbCertificate) {
            KSPLog("ERROR: Failed to allocate certificate buffer");
            delete pKey;
            pKey = nullptr;
            __leave;
        }
        CopyMemory(pKey->pbCertificate, pData->rgbCertificate, pData->cbCertificate);
        
        // Copy private key blob
        pKey->cbPrivateKeyBlob = pData->cbPrivateKey;
        pKey->pbPrivateKeyBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, pData->cbPrivateKey);
        if (!pKey->pbPrivateKeyBlob) {
            KSPLog("ERROR: Failed to allocate private key buffer");
            HeapFree(GetProcessHeap(), 0, pKey->pbCertificate);
            delete pKey;
            pKey = nullptr;
            __leave;
        }
        CopyMemory(pKey->pbPrivateKeyBlob, pData->rgbPrivateKey, pData->cbPrivateKey);
        
        // Import private key into BCrypt
        if (g_hRsaAlg == nullptr) {
            NTSTATUS status = BCryptOpenAlgorithmProvider(&g_hRsaAlg, BCRYPT_RSA_ALGORITHM, nullptr, 0);
            if (!NT_SUCCESS(status)) {
                KSPLog("ERROR: BCryptOpenAlgorithmProvider failed: 0x%08X", status);
                HeapFree(GetProcessHeap(), 0, pKey->pbCertificate);
                HeapFree(GetProcessHeap(), 0, pKey->pbPrivateKeyBlob);
                delete pKey;
                pKey = nullptr;
                __leave;
            }
        }
        
        NTSTATUS status = BCryptImportKeyPair(
            g_hRsaAlg,
            nullptr,
            BCRYPT_RSAFULLPRIVATE_BLOB,
            &pKey->hBcryptKey,
            pKey->pbPrivateKeyBlob,
            pKey->cbPrivateKeyBlob,
            0);
        
        if (!NT_SUCCESS(status)) {
            KSPLog("ERROR: BCryptImportKeyPair failed: 0x%08X", status);
            HeapFree(GetProcessHeap(), 0, pKey->pbCertificate);
            HeapFree(GetProcessHeap(), 0, pKey->pbPrivateKeyBlob);
            delete pKey;
            pKey = nullptr;
            __leave;
        }
        
        // Mark data as consumed
        pData->bDataConsumed = TRUE;
        pData->bDataReady = FALSE;
        
        // Add to key store
        {
            std::lock_guard<std::mutex> lock(g_keyStoreMutex);
            g_keyStore[pKey->wszKeyName] = pKey;
        }
        
        KSPLog("Key created successfully: %S", pKey->wszKeyName.c_str());
    }
    __finally {
        ReleaseMutex(pProvider->hMutex);
    }
    
    return pKey;
}

// Cleanup key
void CleanupKey(PAUTHENTIK_KEY pKey)
{
    if (!pKey) return;
    
    KSPLog("CleanupKey: %S", pKey->wszKeyName.c_str());
    
    if (pKey->hBcryptKey) {
        BCryptDestroyKey(pKey->hBcryptKey);
        pKey->hBcryptKey = nullptr;
    }
    
    if (pKey->pbCertificate) {
        SecureZeroMemory(pKey->pbCertificate, pKey->cbCertificate);
        HeapFree(GetProcessHeap(), 0, pKey->pbCertificate);
        pKey->pbCertificate = nullptr;
    }
    
    if (pKey->pbPrivateKeyBlob) {
        SecureZeroMemory(pKey->pbPrivateKeyBlob, pKey->cbPrivateKeyBlob);
        HeapFree(GetProcessHeap(), 0, pKey->pbPrivateKeyBlob);
        pKey->pbPrivateKeyBlob = nullptr;
    }
    
    pKey->dwMagic = 0;
    delete pKey;
}

//=============================================================================
// Provider Functions
//=============================================================================

SECURITY_STATUS WINAPI KSPOpenProvider(
    __out   NCRYPT_PROV_HANDLE *phProvider,
    __in    LPCWSTR pszProviderName,
    __in    DWORD dwFlags)
{
    KSPLog("KSPOpenProvider: %S, flags=0x%08X", pszProviderName ? pszProviderName : L"(null)", dwFlags);
    
    if (!phProvider) {
        return NTE_INVALID_PARAMETER;
    }
    
    *phProvider = 0;
    
    // Allocate provider structure
    PAUTHENTIK_PROVIDER pProvider = new AUTHENTIK_PROVIDER();
    ZeroMemory(pProvider, sizeof(AUTHENTIK_PROVIDER));
    pProvider->dwMagic = AUTHENTIK_PROVIDER_MAGIC;
    
    // Open shared memory (created by credential provider)
    pProvider->hSharedMemory = OpenFileMappingW(
        FILE_MAP_ALL_ACCESS,
        FALSE,
        AUTHENTIK_SHARED_MEMORY_NAME);
    
    if (pProvider->hSharedMemory) {
        pProvider->pSharedData = (PAUTHENTIK_SHARED_DATA)MapViewOfFile(
            pProvider->hSharedMemory,
            FILE_MAP_ALL_ACCESS,
            0, 0,
            sizeof(AUTHENTIK_SHARED_DATA));
        
        if (!pProvider->pSharedData) {
            KSPLog("WARNING: Failed to map shared memory: %d", GetLastError());
            CloseHandle(pProvider->hSharedMemory);
            pProvider->hSharedMemory = nullptr;
        }
    } else {
        KSPLog("WARNING: Shared memory not available (credential provider may not have created it yet)");
    }
    
    // Open mutex
    pProvider->hMutex = OpenMutexW(SYNCHRONIZE, FALSE, AUTHENTIK_MUTEX_NAME);
    if (!pProvider->hMutex) {
        KSPLog("WARNING: Mutex not available: %d", GetLastError());
    }
    
    *phProvider = (NCRYPT_PROV_HANDLE)pProvider;
    
    DllAddRef();
    KSPLog("Provider opened: 0x%p", pProvider);
    
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPFreeProvider(
    __in    NCRYPT_PROV_HANDLE hProvider)
{
    KSPLog("KSPFreeProvider: 0x%p", (void*)hProvider);
    
    if (!ValidateProviderHandle(hProvider)) {
        return NTE_INVALID_HANDLE;
    }
    
    PAUTHENTIK_PROVIDER pProvider = (PAUTHENTIK_PROVIDER)hProvider;
    
    if (pProvider->pSharedData) {
        UnmapViewOfFile(pProvider->pSharedData);
        pProvider->pSharedData = nullptr;
    }
    
    if (pProvider->hSharedMemory) {
        CloseHandle(pProvider->hSharedMemory);
        pProvider->hSharedMemory = nullptr;
    }
    
    if (pProvider->hMutex) {
        CloseHandle(pProvider->hMutex);
        pProvider->hMutex = nullptr;
    }
    
    pProvider->dwMagic = 0;
    delete pProvider;
    
    DllRelease();
    
    return ERROR_SUCCESS;
}

//=============================================================================
// Key Functions
//=============================================================================

SECURITY_STATUS WINAPI KSPOpenKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszKeyName,
    __in    DWORD dwLegacyKeySpec,
    __in    DWORD dwFlags)
{
    KSPLog("KSPOpenKey: %S, spec=%d, flags=0x%08X", 
           pszKeyName ? pszKeyName : L"(null)", dwLegacyKeySpec, dwFlags);
    
    if (!ValidateProviderHandle(hProvider) || !phKey) {
        return NTE_INVALID_PARAMETER;
    }
    
    *phKey = 0;
    
    PAUTHENTIK_PROVIDER pProvider = (PAUTHENTIK_PROVIDER)hProvider;
    PAUTHENTIK_KEY pKey = nullptr;
    
    // First check if key exists in our store
    if (pszKeyName) {
        std::lock_guard<std::mutex> lock(g_keyStoreMutex);
        auto it = g_keyStore.find(pszKeyName);
        if (it != g_keyStore.end()) {
            pKey = it->second;
            KSPLog("Found key in store: %S", pszKeyName);
        }
    }
    
    // If not found, try to create from shared memory
    if (!pKey && pProvider->pSharedData) {
        pKey = CreateKeyFromSharedMemory(pProvider);
    }
    
    if (!pKey) {
        KSPLog("Key not found: %S", pszKeyName ? pszKeyName : L"(null)");
        return NTE_BAD_KEYSET;
    }
    
    *phKey = (NCRYPT_KEY_HANDLE)pKey;
    KSPLog("Key opened: 0x%p", pKey);
    
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPCreatePersistedKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszAlgId,
    __in_opt LPCWSTR pszKeyName,
    __in    DWORD dwLegacyKeySpec,
    __in    DWORD dwFlags)
{
    KSPLog("KSPCreatePersistedKey: alg=%S, name=%S", 
           pszAlgId ? pszAlgId : L"(null)",
           pszKeyName ? pszKeyName : L"(null)");
    
    // We don't support creating new keys - only importing
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPFinalizeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    DWORD dwFlags)
{
    KSPLog("KSPFinalizeKey");
    
    if (!ValidateProviderHandle(hProvider) || !ValidateKeyHandle(hKey)) {
        return NTE_INVALID_HANDLE;
    }
    
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPDeleteKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    DWORD dwFlags)
{
    KSPLog("KSPDeleteKey");
    
    if (!ValidateProviderHandle(hProvider) || !ValidateKeyHandle(hKey)) {
        return NTE_INVALID_HANDLE;
    }
    
    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;
    
    // Remove from store
    {
        std::lock_guard<std::mutex> lock(g_keyStoreMutex);
        g_keyStore.erase(pKey->wszKeyName);
    }
    
    CleanupKey(pKey);
    
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPFreeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey)
{
    KSPLog("KSPFreeKey: 0x%p", (void*)hKey);
    
    // Don't actually free the key - it stays in our store
    // Just validate handles
    if (!ValidateProviderHandle(hProvider) || !ValidateKeyHandle(hKey)) {
        return NTE_INVALID_HANDLE;
    }
    
    return ERROR_SUCCESS;
}

//=============================================================================
// Property Functions
//=============================================================================

SECURITY_STATUS WINAPI KSPGetProviderProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags)
{
    KSPLog("KSPGetProviderProperty: %S", pszProperty ? pszProperty : L"(null)");
    
    if (!ValidateProviderHandle(hProvider) || !pszProperty || !pcbResult) {
        return NTE_INVALID_PARAMETER;
    }
    
    *pcbResult = 0;
    
    if (wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0) {
        DWORD cbName = (DWORD)((wcslen(AUTHENTIK_KSP_NAME) + 1) * sizeof(WCHAR));
        *pcbResult = cbName;
        
        if (pbOutput) {
            if (cbOutput < cbName) {
                return NTE_BUFFER_TOO_SMALL;
            }
            CopyMemory(pbOutput, AUTHENTIK_KSP_NAME, cbName);
        }
        return ERROR_SUCCESS;
    }
    
    if (wcscmp(pszProperty, NCRYPT_IMPL_TYPE_PROPERTY) == 0) {
        *pcbResult = sizeof(DWORD);
        if (pbOutput) {
            if (cbOutput < sizeof(DWORD)) {
                return NTE_BUFFER_TOO_SMALL;
            }
            *(DWORD*)pbOutput = NCRYPT_IMPL_SOFTWARE_FLAG;
        }
        return ERROR_SUCCESS;
    }
    
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPGetKeyProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags)
{
    KSPLog("KSPGetKeyProperty: %S", pszProperty ? pszProperty : L"(null)");
    
    if (!ValidateProviderHandle(hProvider) || !ValidateKeyHandle(hKey) || 
        !pszProperty || !pcbResult) {
        return NTE_INVALID_PARAMETER;
    }
    
    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;
    *pcbResult = 0;
    
    // Certificate property - CRITICAL for PKINIT!
    if (wcscmp(pszProperty, NCRYPT_CERTIFICATE_PROPERTY) == 0) {
        KSPLog("Returning certificate, size=%d", pKey->cbCertificate);
        *pcbResult = pKey->cbCertificate;
        
        if (pbOutput) {
            if (cbOutput < pKey->cbCertificate) {
                return NTE_BUFFER_TOO_SMALL;
            }
            CopyMemory(pbOutput, pKey->pbCertificate, pKey->cbCertificate);
        }
        return ERROR_SUCCESS;
    }
    
    // Key name
    if (wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0) {
        DWORD cbName = (DWORD)((pKey->wszKeyName.length() + 1) * sizeof(WCHAR));
        *pcbResult = cbName;
        
        if (pbOutput) {
            if (cbOutput < cbName) {
                return NTE_BUFFER_TOO_SMALL;
            }
            CopyMemory(pbOutput, pKey->wszKeyName.c_str(), cbName);
        }
        return ERROR_SUCCESS;
    }
    
    // Key type
    if (wcscmp(pszProperty, NCRYPT_ALGORITHM_PROPERTY) == 0) {
        DWORD cbAlg = (DWORD)((wcslen(BCRYPT_RSA_ALGORITHM) + 1) * sizeof(WCHAR));
        *pcbResult = cbAlg;
        
        if (pbOutput) {
            if (cbOutput < cbAlg) {
                return NTE_BUFFER_TOO_SMALL;
            }
            CopyMemory(pbOutput, BCRYPT_RSA_ALGORITHM, cbAlg);
        }
        return ERROR_SUCCESS;
    }
    
    // Key length
    if (wcscmp(pszProperty, NCRYPT_LENGTH_PROPERTY) == 0) {
        *pcbResult = sizeof(DWORD);
        
        if (pbOutput) {
            if (cbOutput < sizeof(DWORD)) {
                return NTE_BUFFER_TOO_SMALL;
            }
            // Get key length from BCrypt
            DWORD dwKeyLength = 0;
            ULONG cbResult = 0;
            if (pKey->hBcryptKey) {
                BCryptGetProperty(pKey->hBcryptKey, BCRYPT_KEY_LENGTH, 
                                  (PUCHAR)&dwKeyLength, sizeof(dwKeyLength), &cbResult, 0);
            }
            *(DWORD*)pbOutput = dwKeyLength ? dwKeyLength : 2048;
        }
        return ERROR_SUCCESS;
    }
    
    // Export policy
    if (wcscmp(pszProperty, NCRYPT_EXPORT_POLICY_PROPERTY) == 0) {
        *pcbResult = sizeof(DWORD);
        
        if (pbOutput) {
            if (cbOutput < sizeof(DWORD)) {
                return NTE_BUFFER_TOO_SMALL;
            }
            *(DWORD*)pbOutput = 0; // Not exportable
        }
        return ERROR_SUCCESS;
    }
    
    // Key usage
    if (wcscmp(pszProperty, NCRYPT_KEY_USAGE_PROPERTY) == 0) {
        *pcbResult = sizeof(DWORD);
        
        if (pbOutput) {
            if (cbOutput < sizeof(DWORD)) {
                return NTE_BUFFER_TOO_SMALL;
            }
            *(DWORD*)pbOutput = NCRYPT_ALLOW_SIGNING_FLAG | NCRYPT_ALLOW_DECRYPT_FLAG;
        }
        return ERROR_SUCCESS;
    }
    
    KSPLog("Property not supported: %S", pszProperty);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPSetProviderProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD cbInput,
    __in    DWORD dwFlags)
{
    KSPLog("KSPSetProviderProperty: %S", pszProperty ? pszProperty : L"(null)");
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPSetKeyProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD cbInput,
    __in    DWORD dwFlags)
{
    KSPLog("KSPSetKeyProperty: %S", pszProperty ? pszProperty : L"(null)");
    
    if (!ValidateProviderHandle(hProvider) || !ValidateKeyHandle(hKey)) {
        return NTE_INVALID_HANDLE;
    }
    
    // Accept but ignore most property sets
    return ERROR_SUCCESS;
}

//=============================================================================
// Cryptographic Operations
//=============================================================================

SECURITY_STATUS WINAPI KSPSignHash(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    VOID *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD cbHashValue,
    __out_bcount_part_opt(cbSignature, *pcbResult) PBYTE pbSignature,
    __in    DWORD cbSignature,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags)
{
    KSPLog("KSPSignHash: hashSize=%d, sigSize=%d, flags=0x%08X", cbHashValue, cbSignature, dwFlags);
    
    if (!ValidateProviderHandle(hProvider) || !ValidateKeyHandle(hKey) || !pcbResult) {
        return NTE_INVALID_PARAMETER;
    }
    
    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;
    
    if (!pKey->hBcryptKey) {
        KSPLog("ERROR: No BCrypt key available");
        return NTE_INVALID_HANDLE;
    }
    
    // Determine padding
    LPCWSTR pwszPaddingAlg = nullptr;
    if (dwFlags & BCRYPT_PAD_PKCS1) {
        if (pPaddingInfo) {
            BCRYPT_PKCS1_PADDING_INFO* pPkcs1 = (BCRYPT_PKCS1_PADDING_INFO*)pPaddingInfo;
            pwszPaddingAlg = pPkcs1->pszAlgId;
        }
    }
    
    // Sign using BCrypt
    NTSTATUS status = BCryptSignHash(
        pKey->hBcryptKey,
        pPaddingInfo,
        pbHashValue,
        cbHashValue,
        pbSignature,
        cbSignature,
        (ULONG*)pcbResult,
        dwFlags);
    
    if (!NT_SUCCESS(status)) {
        KSPLog("BCryptSignHash failed: 0x%08X", status);
        return NTE_INTERNAL_ERROR;
    }
    
    KSPLog("Signature created, size=%d", *pcbResult);
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPVerifySignature(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    VOID *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD cbHashValue,
    __in_bcount(cbSignature) PBYTE pbSignature,
    __in    DWORD cbSignature,
    __in    DWORD dwFlags)
{
    KSPLog("KSPVerifySignature");
    
    if (!ValidateProviderHandle(hProvider) || !ValidateKeyHandle(hKey)) {
        return NTE_INVALID_HANDLE;
    }
    
    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;
    
    if (!pKey->hBcryptKey) {
        return NTE_INVALID_HANDLE;
    }
    
    NTSTATUS status = BCryptVerifySignature(
        pKey->hBcryptKey,
        pPaddingInfo,
        pbHashValue,
        cbHashValue,
        pbSignature,
        cbSignature,
        dwFlags);
    
    return NT_SUCCESS(status) ? ERROR_SUCCESS : NTE_BAD_SIGNATURE;
}

SECURITY_STATUS WINAPI KSPEncrypt(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD cbInput,
    __in    VOID *pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags)
{
    KSPLog("KSPEncrypt");
    
    if (!ValidateProviderHandle(hProvider) || !ValidateKeyHandle(hKey) || !pcbResult) {
        return NTE_INVALID_PARAMETER;
    }
    
    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;
    
    if (!pKey->hBcryptKey) {
        return NTE_INVALID_HANDLE;
    }
    
    NTSTATUS status = BCryptEncrypt(
        pKey->hBcryptKey,
        pbInput,
        cbInput,
        pPaddingInfo,
        nullptr, 0,
        pbOutput,
        cbOutput,
        (ULONG*)pcbResult,
        dwFlags);
    
    return NT_SUCCESS(status) ? ERROR_SUCCESS : NTE_INTERNAL_ERROR;
}

SECURITY_STATUS WINAPI KSPDecrypt(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD cbInput,
    __in    VOID *pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags)
{
    KSPLog("KSPDecrypt");
    
    if (!ValidateProviderHandle(hProvider) || !ValidateKeyHandle(hKey) || !pcbResult) {
        return NTE_INVALID_PARAMETER;
    }
    
    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;
    
    if (!pKey->hBcryptKey) {
        return NTE_INVALID_HANDLE;
    }
    
    NTSTATUS status = BCryptDecrypt(
        pKey->hBcryptKey,
        pbInput,
        cbInput,
        pPaddingInfo,
        nullptr, 0,
        pbOutput,
        cbOutput,
        (ULONG*)pcbResult,
        dwFlags);
    
    return NT_SUCCESS(status) ? ERROR_SUCCESS : NTE_INTERNAL_ERROR;
}

//=============================================================================
// Utility Functions
//=============================================================================

SECURITY_STATUS WINAPI KSPIsAlgSupported(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszAlgId,
    __in    DWORD dwFlags)
{
    KSPLog("KSPIsAlgSupported: %S", pszAlgId ? pszAlgId : L"(null)");
    
    if (!pszAlgId) {
        return NTE_INVALID_PARAMETER;
    }
    
    if (wcscmp(pszAlgId, BCRYPT_RSA_ALGORITHM) == 0 ||
        wcscmp(pszAlgId, NCRYPT_RSA_ALGORITHM) == 0) {
        return ERROR_SUCCESS;
    }
    
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPEnumAlgorithms(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    DWORD dwAlgOperations,
    __out   DWORD *pdwAlgCount,
    __out   NCryptAlgorithmName **ppAlgList,
    __in    DWORD dwFlags)
{
    KSPLog("KSPEnumAlgorithms");
    
    if (!pdwAlgCount || !ppAlgList) {
        return NTE_INVALID_PARAMETER;
    }
    
    // Return RSA as the only supported algorithm
    NCryptAlgorithmName* pAlg = (NCryptAlgorithmName*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NCryptAlgorithmName));
    
    if (!pAlg) {
        return NTE_NO_MEMORY;
    }
    
    pAlg->pszName = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, sizeof(BCRYPT_RSA_ALGORITHM));
    if (pAlg->pszName) {
        wcscpy_s(pAlg->pszName, wcslen(BCRYPT_RSA_ALGORITHM) + 1, BCRYPT_RSA_ALGORITHM);
    }
    pAlg->dwClass = NCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE;
    pAlg->dwAlgOperations = NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION | 
                           NCRYPT_SIGNATURE_OPERATION;
    pAlg->dwFlags = 0;
    
    *pdwAlgCount = 1;
    *ppAlgList = pAlg;
    
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPEnumKeys(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt LPCWSTR pszScope,
    __out   NCryptKeyName **ppKeyName,
    __inout PVOID *ppEnumState,
    __in    DWORD dwFlags)
{
    KSPLog("KSPEnumKeys");
    
    if (!ppKeyName) {
        return NTE_INVALID_PARAMETER;
    }
    
    // Get current enumeration index
    DWORD dwIndex = 0;
    if (ppEnumState && *ppEnumState) {
        dwIndex = (DWORD)(UINT_PTR)*ppEnumState;
    }
    
    // Get keys from store
    std::lock_guard<std::mutex> lock(g_keyStoreMutex);
    
    if (dwIndex >= g_keyStore.size()) {
        return NTE_NO_MORE_ITEMS;
    }
    
    // Find key at index
    auto it = g_keyStore.begin();
    std::advance(it, dwIndex);
    
    PAUTHENTIK_KEY pKey = it->second;
    
    // Allocate key name structure
    NCryptKeyName* pKeyName = (NCryptKeyName*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NCryptKeyName));
    
    if (!pKeyName) {
        return NTE_NO_MEMORY;
    }
    
    DWORD cbName = (DWORD)((pKey->wszKeyName.length() + 1) * sizeof(WCHAR));
    pKeyName->pszName = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, cbName);
    if (pKeyName->pszName) {
        wcscpy_s(pKeyName->pszName, pKey->wszKeyName.length() + 1, pKey->wszKeyName.c_str());
    }
    
    DWORD cbAlg = (DWORD)((wcslen(BCRYPT_RSA_ALGORITHM) + 1) * sizeof(WCHAR));
    pKeyName->pszAlgid = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, cbAlg);
    if (pKeyName->pszAlgid) {
        wcscpy_s(pKeyName->pszAlgid, wcslen(BCRYPT_RSA_ALGORITHM) + 1, BCRYPT_RSA_ALGORITHM);
    }
    
    pKeyName->dwLegacyKeySpec = pKey->dwKeySpec;
    pKeyName->dwFlags = 0;
    
    *ppKeyName = pKeyName;
    
    // Update enumeration state
    if (ppEnumState) {
        *ppEnumState = (PVOID)(UINT_PTR)(dwIndex + 1);
    }
    
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPImportKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hImportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in_bcount(cbData) PBYTE pbData,
    __in    DWORD cbData,
    __in    DWORD dwFlags)
{
    KSPLog("KSPImportKey: type=%S, size=%d", pszBlobType ? pszBlobType : L"(null)", cbData);
    
    // For now, we don't support direct import - keys come via shared memory
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPExportKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt NCRYPT_KEY_HANDLE hExportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags)
{
    KSPLog("KSPExportKey: type=%S", pszBlobType ? pszBlobType : L"(null)");
    
    // Don't allow exporting private keys
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPFreeBuffer(
    __deref PVOID pvInput)
{
    KSPLog("KSPFreeBuffer: 0x%p", pvInput);
    
    if (pvInput) {
        HeapFree(GetProcessHeap(), 0, pvInput);
    }
    
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPNotifyChangeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout HANDLE *phEvent,
    __in    DWORD dwFlags)
{
    KSPLog("KSPNotifyChangeKey");
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPSecretAgreement(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hPrivKey,
    __in    NCRYPT_KEY_HANDLE hPubKey,
    __out   NCRYPT_SECRET_HANDLE *phSecret,
    __in    DWORD dwFlags)
{
    KSPLog("KSPSecretAgreement");
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPDeriveKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_SECRET_HANDLE hSharedSecret,
    __in    LPCWSTR pwszKDF,
    __in_opt NCryptBufferDesc *pParameterList,
    __out_bcount_part_opt(cbDerivedKey, *pcbResult) PBYTE pbDerivedKey,
    __in    DWORD cbDerivedKey,
    __out   DWORD *pcbResult,
    __in    ULONG dwFlags)
{
    KSPLog("KSPDeriveKey");
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPFreeSecret(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_SECRET_HANDLE hSharedSecret)
{
    KSPLog("KSPFreeSecret");
    return NTE_NOT_SUPPORTED;
}

//=============================================================================
// DLL Entry Point
//=============================================================================

NTSTATUS WINAPI GetKeyStorageInterface(
    __in    LPCWSTR pszProviderName,
    __out   NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable,
    __in    DWORD dwFlags)
{
    KSPLog("GetKeyStorageInterface: %S", pszProviderName ? pszProviderName : L"(null)");
    
    if (!ppFunctionTable) {
        return STATUS_INVALID_PARAMETER;
    }
    
    *ppFunctionTable = &g_FunctionTable;
    
    return STATUS_SUCCESS;
}

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
        
        // Cleanup all keys
        {
            std::lock_guard<std::mutex> lock(g_keyStoreMutex);
            for (auto& pair : g_keyStore) {
                CleanupKey(pair.second);
            }
            g_keyStore.clear();
        }
        
        // Close BCrypt handle
        if (g_hRsaAlg) {
            BCryptCloseAlgorithmProvider(g_hRsaAlg, 0);
            g_hRsaAlg = nullptr;
        }
        break;
    }
    
    return TRUE;
}
