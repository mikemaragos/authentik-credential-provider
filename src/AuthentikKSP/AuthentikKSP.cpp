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
static PAUTHENTIK_KEY g_pCurrentKey = NULL;
static BCRYPT_ALG_HANDLE g_hRsaAlg = NULL;

// Function table
static AUTHENTIK_FUNCTION_TABLE g_FunctionTable = {
    NCRYPT_KEY_STORAGE_INTERFACE_VERSION,
    (void*)KSPOpenProvider,
    (void*)KSPOpenKey,
    (void*)KSPCreatePersistedKey,
    (void*)KSPGetProviderProperty,
    (void*)KSPGetKeyProperty,
    (void*)KSPSetProviderProperty,
    (void*)KSPSetKeyProperty,
    (void*)KSPFinalizeKey,
    (void*)KSPDeleteKey,
    (void*)KSPFreeProvider,
    (void*)KSPFreeKey,
    (void*)KSPFreeBuffer,
    (void*)KSPEncrypt,
    (void*)KSPDecrypt,
    (void*)KSPIsAlgSupported,
    (void*)KSPEnumAlgorithms,
    (void*)KSPEnumKeys,
    (void*)KSPImportKey,
    (void*)KSPExportKey,
    (void*)KSPSignHash,
    (void*)KSPVerifySignature,
    NULL,  // PromptUser
    (void*)KSPNotifyChangeKey,
    (void*)KSPSecretAgreement,
    (void*)KSPDeriveKey,
    (void*)KSPFreeSecret
};

// Logging
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

void DllAddRef(void) { InterlockedIncrement(&g_cDllRef); }
void DllRelease(void) { InterlockedDecrement(&g_cDllRef); }

static void InitializeGlobals(void)
{
    if (!g_bInitialized) {
        InitializeCriticalSection(&g_csKeyStore);
        g_bInitialized = TRUE;
        KSPLog("Globals initialized");
    }
}

BOOL ValidateProviderHandle(NCRYPT_PROV_HANDLE hProvider)
{
    if (hProvider == 0) return FALSE;
    PAUTHENTIK_PROVIDER pProvider = (PAUTHENTIK_PROVIDER)hProvider;
    if (IsBadReadPtr(pProvider, sizeof(AUTHENTIK_PROVIDER))) return FALSE;
    if (pProvider->dwMagic != AUTHENTIK_PROVIDER_MAGIC) return FALSE;
    return TRUE;
}

BOOL ValidateKeyHandle(NCRYPT_KEY_HANDLE hKey)
{
    if (hKey == 0) return FALSE;
    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;
    if (IsBadReadPtr(pKey, sizeof(AUTHENTIK_KEY))) return FALSE;
    if (pKey->dwMagic != AUTHENTIK_KEY_MAGIC) return FALSE;
    return TRUE;
}

void CleanupKey(PAUTHENTIK_KEY pKey)
{
    if (pKey == NULL) return;
    KSPLog("CleanupKey: %S", pKey->wszKeyName);
    if (pKey->hBcryptKey) { BCryptDestroyKey(pKey->hBcryptKey); pKey->hBcryptKey = NULL; }
    if (pKey->pbCertificate) { SecureZeroMemory(pKey->pbCertificate, pKey->cbCertificate); HeapFree(GetProcessHeap(), 0, pKey->pbCertificate); }
    if (pKey->pbPrivateKeyBlob) { SecureZeroMemory(pKey->pbPrivateKeyBlob, pKey->cbPrivateKeyBlob); HeapFree(GetProcessHeap(), 0, pKey->pbPrivateKeyBlob); }
    SecureZeroMemory(pKey, sizeof(AUTHENTIK_KEY));
    HeapFree(GetProcessHeap(), 0, pKey);
}

PAUTHENTIK_KEY CreateKeyFromSharedMemory(PAUTHENTIK_PROVIDER pProvider)
{
    KSPLog("CreateKeyFromSharedMemory");
    if (pProvider == NULL || pProvider->pSharedData == NULL) {
        KSPLog("ERROR: No shared data");
        return NULL;
    }

    if (pProvider->hMutex) {
        if (WaitForSingleObject(pProvider->hMutex, 5000) != WAIT_OBJECT_0) {
            KSPLog("ERROR: Mutex timeout");
            return NULL;
        }
    }

    PAUTHENTIK_KEY pKey = NULL;
    PAUTHENTIK_SHARED_DATA pData = pProvider->pSharedData;

    if (pData->dwMagic != AUTHENTIK_SHARED_MAGIC) { KSPLog("ERROR: Bad magic"); goto cleanup; }
    if (!pData->bDataReady) { KSPLog("ERROR: Data not ready"); goto cleanup; }
    if (pData->bDataConsumed) { KSPLog("ERROR: Already consumed"); goto cleanup; }

    KSPLog("Found data for: %S, cert=%d, key=%d", pData->wszUsername, pData->cbCertificate, pData->cbPrivateKey);

    pKey = (PAUTHENTIK_KEY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(AUTHENTIK_KEY));
    if (!pKey) { KSPLog("ERROR: Alloc failed"); goto cleanup; }

    pKey->dwMagic = AUTHENTIK_KEY_MAGIC;
    wcscpy_s(pKey->wszUsername, MAX_USERNAME_SIZE, pData->wszUsername);
    _snwprintf_s(pKey->wszKeyName, 256, _TRUNCATE, L"%s%s", AUTHENTIK_KEY_PREFIX, pData->wszUsername);
    pKey->dwKeySpec = pData->dwKeySpec;
    pKey->bFromSharedMemory = TRUE;

    if (pData->cbCertificate > 0 && pData->cbCertificate <= MAX_CERTIFICATE_SIZE) {
        pKey->cbCertificate = pData->cbCertificate;
        pKey->pbCertificate = (PBYTE)HeapAlloc(GetProcessHeap(), 0, pData->cbCertificate);
        if (pKey->pbCertificate) CopyMemory(pKey->pbCertificate, pData->rgbCertificate, pData->cbCertificate);
    }

    if (pData->cbPrivateKey > 0 && pData->cbPrivateKey <= MAX_PRIVATE_KEY_SIZE) {
        pKey->cbPrivateKeyBlob = pData->cbPrivateKey;
        pKey->pbPrivateKeyBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, pData->cbPrivateKey);
        if (pKey->pbPrivateKeyBlob) {
            CopyMemory(pKey->pbPrivateKeyBlob, pData->rgbPrivateKey, pData->cbPrivateKey);
            if (!g_hRsaAlg) BCryptOpenAlgorithmProvider(&g_hRsaAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
            if (g_hRsaAlg) {
                NTSTATUS st = BCryptImportKeyPair(g_hRsaAlg, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, &pKey->hBcryptKey, pKey->pbPrivateKeyBlob, pKey->cbPrivateKeyBlob, 0);
                if (!NT_SUCCESS(st)) KSPLog("ERROR: BCryptImportKeyPair: 0x%08X", st);
            }
        }
    }

    pData->bDataConsumed = TRUE;

    EnterCriticalSection(&g_csKeyStore);
    if (g_pCurrentKey) CleanupKey(g_pCurrentKey);
    g_pCurrentKey = pKey;
    LeaveCriticalSection(&g_csKeyStore);

    KSPLog("Key created: %S", pKey->wszKeyName);
    if (pProvider->hMutex) ReleaseMutex(pProvider->hMutex);
    return pKey;

cleanup:
    if (pKey) CleanupKey(pKey);
    if (pProvider->hMutex) ReleaseMutex(pProvider->hMutex);
    return NULL;
}

// KSP Functions

SECURITY_STATUS WINAPI KSPOpenProvider(NCRYPT_PROV_HANDLE *phProvider, LPCWSTR pszProviderName, DWORD dwFlags)
{
    KSPLog("KSPOpenProvider: %S", pszProviderName ? pszProviderName : L"(null)");
    InitializeGlobals();
    if (!phProvider) return NTE_INVALID_PARAMETER;
    *phProvider = 0;

    PAUTHENTIK_PROVIDER pProvider = (PAUTHENTIK_PROVIDER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(AUTHENTIK_PROVIDER));
    if (!pProvider) return NTE_NO_MEMORY;

    pProvider->dwMagic = AUTHENTIK_PROVIDER_MAGIC;
    pProvider->hMutex = OpenMutexW(SYNCHRONIZE, FALSE, AUTHENTIK_MUTEX_NAME);
    if (pProvider->hMutex) {
        pProvider->hSharedMemory = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, AUTHENTIK_SHARED_MEMORY_NAME);
        if (pProvider->hSharedMemory) {
            pProvider->pSharedData = (PAUTHENTIK_SHARED_DATA)MapViewOfFile(pProvider->hSharedMemory, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(AUTHENTIK_SHARED_DATA));
        }
    }

    DllAddRef();
    *phProvider = (NCRYPT_PROV_HANDLE)pProvider;
    KSPLog("Provider opened: 0x%p", pProvider);
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPFreeProvider(NCRYPT_PROV_HANDLE hProvider)
{
    KSPLog("KSPFreeProvider");
    if (!ValidateProviderHandle(hProvider)) return NTE_INVALID_HANDLE;
    PAUTHENTIK_PROVIDER p = (PAUTHENTIK_PROVIDER)hProvider;
    if (p->pSharedData) UnmapViewOfFile(p->pSharedData);
    if (p->hSharedMemory) CloseHandle(p->hSharedMemory);
    if (p->hMutex) CloseHandle(p->hMutex);
    SecureZeroMemory(p, sizeof(AUTHENTIK_PROVIDER));
    HeapFree(GetProcessHeap(), 0, p);
    DllRelease();
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPOpenKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE *phKey, LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags)
{
    KSPLog("KSPOpenKey: %S", pszKeyName ? pszKeyName : L"(null)");
    if (!ValidateProviderHandle(hProvider) || !phKey) return NTE_INVALID_HANDLE;
    *phKey = 0;

    PAUTHENTIK_KEY pKey = CreateKeyFromSharedMemory((PAUTHENTIK_PROVIDER)hProvider);
    if (!pKey) {
        EnterCriticalSection(&g_csKeyStore);
        pKey = g_pCurrentKey;
        LeaveCriticalSection(&g_csKeyStore);
    }
    if (!pKey) return NTE_BAD_KEYSET;

    *phKey = (NCRYPT_KEY_HANDLE)pKey;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPCreatePersistedKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE *phKey, LPCWSTR pszAlgId, LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags)
{
    KSPLog("KSPCreatePersistedKey (not supported)");
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPFinalizeKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, DWORD dwFlags)
{
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPDeleteKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, DWORD dwFlags)
{
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPFreeKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey)
{
    KSPLog("KSPFreeKey");
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPGetProviderProperty(NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszProperty, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags)
{
    KSPLog("KSPGetProviderProperty: %S", pszProperty ? pszProperty : L"(null)");
    if (!ValidateProviderHandle(hProvider) || !pszProperty || !pcbResult) return NTE_INVALID_PARAMETER;

    if (wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0) {
        DWORD cb = (DWORD)((wcslen(AUTHENTIK_KSP_NAME) + 1) * sizeof(WCHAR));
        *pcbResult = cb;
        if (!pbOutput) return ERROR_SUCCESS;
        if (cbOutput < cb) return NTE_BUFFER_TOO_SMALL;
        wcscpy_s((LPWSTR)pbOutput, cbOutput / sizeof(WCHAR), AUTHENTIK_KSP_NAME);
        return ERROR_SUCCESS;
    }
    if (wcscmp(pszProperty, NCRYPT_IMPL_TYPE_PROPERTY) == 0) {
        *pcbResult = sizeof(DWORD);
        if (!pbOutput) return ERROR_SUCCESS;
        if (cbOutput < sizeof(DWORD)) return NTE_BUFFER_TOO_SMALL;
        *(DWORD*)pbOutput = NCRYPT_IMPL_SOFTWARE_FLAG;
        return ERROR_SUCCESS;
    }
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPGetKeyProperty(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, LPCWSTR pszProperty, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags)
{
    KSPLog("KSPGetKeyProperty: %S", pszProperty ? pszProperty : L"(null)");
    if (!ValidateKeyHandle(hKey) || !pszProperty || !pcbResult) return NTE_INVALID_PARAMETER;
    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;

    if (wcscmp(pszProperty, NCRYPT_CERTIFICATE_PROPERTY) == 0) {
        *pcbResult = pKey->cbCertificate;
        if (!pbOutput) return ERROR_SUCCESS;
        if (cbOutput < pKey->cbCertificate) return NTE_BUFFER_TOO_SMALL;
        if (pKey->pbCertificate) CopyMemory(pbOutput, pKey->pbCertificate, pKey->cbCertificate);
        return ERROR_SUCCESS;
    }
    if (wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0) {
        DWORD cb = (DWORD)((wcslen(pKey->wszKeyName) + 1) * sizeof(WCHAR));
        *pcbResult = cb;
        if (!pbOutput) return ERROR_SUCCESS;
        if (cbOutput < cb) return NTE_BUFFER_TOO_SMALL;
        wcscpy_s((LPWSTR)pbOutput, cbOutput / sizeof(WCHAR), pKey->wszKeyName);
        return ERROR_SUCCESS;
    }
    if (wcscmp(pszProperty, NCRYPT_LENGTH_PROPERTY) == 0) {
        *pcbResult = sizeof(DWORD);
        if (!pbOutput) return ERROR_SUCCESS;
        if (cbOutput < sizeof(DWORD)) return NTE_BUFFER_TOO_SMALL;
        *(DWORD*)pbOutput = 2048;
        return ERROR_SUCCESS;
    }
    if (wcscmp(pszProperty, NCRYPT_ALGORITHM_PROPERTY) == 0) {
        DWORD cb = (DWORD)((wcslen(BCRYPT_RSA_ALGORITHM) + 1) * sizeof(WCHAR));
        *pcbResult = cb;
        if (!pbOutput) return ERROR_SUCCESS;
        if (cbOutput < cb) return NTE_BUFFER_TOO_SMALL;
        wcscpy_s((LPWSTR)pbOutput, cbOutput / sizeof(WCHAR), BCRYPT_RSA_ALGORITHM);
        return ERROR_SUCCESS;
    }
    if (wcscmp(pszProperty, NCRYPT_KEY_USAGE_PROPERTY) == 0) {
        *pcbResult = sizeof(DWORD);
        if (!pbOutput) return ERROR_SUCCESS;
        if (cbOutput < sizeof(DWORD)) return NTE_BUFFER_TOO_SMALL;
        *(DWORD*)pbOutput = NCRYPT_ALLOW_SIGNING_FLAG | NCRYPT_ALLOW_DECRYPT_FLAG;
        return ERROR_SUCCESS;
    }
    if (wcscmp(pszProperty, NCRYPT_EXPORT_POLICY_PROPERTY) == 0) {
        *pcbResult = sizeof(DWORD);
        if (!pbOutput) return ERROR_SUCCESS;
        if (cbOutput < sizeof(DWORD)) return NTE_BUFFER_TOO_SMALL;
        *(DWORD*)pbOutput = 0;
        return ERROR_SUCCESS;
    }
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPSetProviderProperty(NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszProperty, PBYTE pbInput, DWORD cbInput, DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPSetKeyProperty(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, LPCWSTR pszProperty, PBYTE pbInput, DWORD cbInput, DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPEncrypt(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, PBYTE pbInput, DWORD cbInput, VOID *pPaddingInfo, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPDecrypt(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, PBYTE pbInput, DWORD cbInput, VOID *pPaddingInfo, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPSignHash(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, VOID *pPaddingInfo, PBYTE pbHashValue, DWORD cbHashValue, PBYTE pbSignature, DWORD cbSignature, DWORD *pcbResult, DWORD dwFlags)
{
    KSPLog("KSPSignHash: hash=%d, sigbuf=%d", cbHashValue, cbSignature);
    if (!ValidateKeyHandle(hKey) || !pbHashValue || !pcbResult) return NTE_INVALID_PARAMETER;
    PAUTHENTIK_KEY pKey = (PAUTHENTIK_KEY)hKey;
    if (!pKey->hBcryptKey) return NTE_BAD_KEY;

    ULONG cbResult = 0;
    NTSTATUS st = BCryptSignHash(pKey->hBcryptKey, pPaddingInfo, pbHashValue, cbHashValue, pbSignature, cbSignature, &cbResult, dwFlags);
    *pcbResult = cbResult;
    if (!NT_SUCCESS(st)) { KSPLog("ERROR: BCryptSignHash: 0x%08X", st); return NTE_INTERNAL_ERROR; }
    KSPLog("Signed: %d bytes", cbResult);
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPVerifySignature(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, VOID *pPaddingInfo, PBYTE pbHashValue, DWORD cbHashValue, PBYTE pbSignature, DWORD cbSignature, DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPIsAlgSupported(NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszAlgId, DWORD dwFlags)
{
    if (pszAlgId && wcscmp(pszAlgId, BCRYPT_RSA_ALGORITHM) == 0) return ERROR_SUCCESS;
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPEnumAlgorithms(NCRYPT_PROV_HANDLE hProvider, DWORD dwAlgOperations, DWORD *pdwAlgCount, NCryptAlgorithmName **ppAlgList, DWORD dwFlags)
{
    if (!pdwAlgCount || !ppAlgList) return NTE_INVALID_PARAMETER;
    *pdwAlgCount = 1;
    NCryptAlgorithmName* p = (NCryptAlgorithmName*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NCryptAlgorithmName));
    if (!p) return NTE_NO_MEMORY;
    p->pszName = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, 16 * sizeof(WCHAR));
    if (p->pszName) wcscpy_s(p->pszName, 16, BCRYPT_RSA_ALGORITHM);
    p->dwClass = NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION;
    p->dwAlgOperations = NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION | NCRYPT_SIGNATURE_OPERATION;
    *ppAlgList = p;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPEnumKeys(NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszScope, NCryptKeyName **ppKeyName, PVOID *ppEnumState, DWORD dwFlags)
{
    if (!ppKeyName || !ppEnumState) return NTE_INVALID_PARAMETER;
    if (*ppEnumState == NULL && g_pCurrentKey) {
        NCryptKeyName* p = (NCryptKeyName*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NCryptKeyName));
        if (!p) return NTE_NO_MEMORY;
        DWORD cb = (DWORD)((wcslen(g_pCurrentKey->wszKeyName) + 1) * sizeof(WCHAR));
        p->pszName = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, cb);
        if (p->pszName) wcscpy_s(p->pszName, cb / sizeof(WCHAR), g_pCurrentKey->wszKeyName);
        p->pszAlgid = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, 16 * sizeof(WCHAR));
        if (p->pszAlgid) wcscpy_s(p->pszAlgid, 16, BCRYPT_RSA_ALGORITHM);
        p->dwLegacyKeySpec = g_pCurrentKey->dwKeySpec;
        *ppKeyName = p;
        *ppEnumState = (PVOID)1;
        return ERROR_SUCCESS;
    }
    return NTE_NO_MORE_ITEMS;
}

SECURITY_STATUS WINAPI KSPImportKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hImportKey, LPCWSTR pszBlobType, NCryptBufferDesc *pParameterList, NCRYPT_KEY_HANDLE *phKey, PBYTE pbData, DWORD cbData, DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPExportKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, NCRYPT_KEY_HANDLE hExportKey, LPCWSTR pszBlobType, NCryptBufferDesc *pParameterList, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPFreeBuffer(PVOID pvInput)
{
    if (pvInput) HeapFree(GetProcessHeap(), 0, pvInput);
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPNotifyChangeKey(NCRYPT_PROV_HANDLE hProvider, HANDLE *phEvent, DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPSecretAgreement(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hPrivKey, NCRYPT_KEY_HANDLE hPubKey, NCRYPT_SECRET_HANDLE *phSecret, DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPDeriveKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_SECRET_HANDLE hSharedSecret, LPCWSTR pwszKDF, NCryptBufferDesc *pParameterList, PBYTE pbDerivedKey, DWORD cbDerivedKey, DWORD *pcbResult, ULONG dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPFreeSecret(NCRYPT_PROV_HANDLE hProvider, NCRYPT_SECRET_HANDLE hSharedSecret)
{
    return NTE_NOT_SUPPORTED;
}

NTSTATUS WINAPI GetKeyStorageInterface(LPCWSTR pszProviderName, AUTHENTIK_FUNCTION_TABLE **ppFunctionTable, DWORD dwFlags)
{
    KSPLog("GetKeyStorageInterface: %S", pszProviderName ? pszProviderName : L"(null)");
    InitializeGlobals();
    if (!ppFunctionTable) return STATUS_INVALID_PARAMETER;
    *ppFunctionTable = &g_FunctionTable;
    return STATUS_SUCCESS;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        g_hInstance = hModule;
        DisableThreadLibraryCalls(hModule);
        KSPLog("DLL_PROCESS_ATTACH");
        break;
    case DLL_PROCESS_DETACH:
        KSPLog("DLL_PROCESS_DETACH");
        if (g_pCurrentKey) { CleanupKey(g_pCurrentKey); g_pCurrentKey = NULL; }
        if (g_hRsaAlg) { BCryptCloseAlgorithmProvider(g_hRsaAlg, 0); g_hRsaAlg = NULL; }
        if (g_bInitialized) { DeleteCriticalSection(&g_csKeyStore); g_bInitialized = FALSE; }
        break;
    }
    return TRUE;
}
