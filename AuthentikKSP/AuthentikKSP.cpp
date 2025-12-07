// AuthentikKSP.cpp
// MINIMAL SAFE VERSION - Pure passthrough to MS Software KSP
// No std::wstring, no HTTP calls, no dynamic allocation in init

#include <windows.h>
#include <ncrypt.h>
#include <bcrypt.h>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")

// ============================================================================
// Logging
// ============================================================================

static void Log(const char* msg)
{
    OutputDebugStringA("[AuthentikKSP] ");
    OutputDebugStringA(msg);
    OutputDebugStringA("\n");
}

// ============================================================================
// Provider Context - MINIMAL
// ============================================================================

#define PROV_MAGIC 0x41555448

typedef struct _AKSP_PROV {
    DWORD magic;
    NCRYPT_PROV_HANDLE hBase;
} AKSP_PROV;

typedef struct _AKSP_KEY {
    DWORD magic;
    AKSP_PROV* pProv;
    NCRYPT_KEY_HANDLE hBase;
} AKSP_KEY;

// ============================================================================
// Forward Declarations
// ============================================================================

SECURITY_STATUS WINAPI KSPOpenProvider(
    __out NCRYPT_PROV_HANDLE *phProvider,
    __in LPCWSTR pszProviderName,
    __in DWORD dwFlags);

SECURITY_STATUS WINAPI KSPOpenKey(
    __in NCRYPT_PROV_HANDLE hProvider,
    __out NCRYPT_KEY_HANDLE *phKey,
    __in LPCWSTR pszKeyName,
    __in DWORD dwLegacyKeySpec,
    __in DWORD dwFlags);

SECURITY_STATUS WINAPI KSPCreatePersistedKey(
    __in NCRYPT_PROV_HANDLE hProvider,
    __out NCRYPT_KEY_HANDLE *phKey,
    __in LPCWSTR pszAlgId,
    __in_opt LPCWSTR pszKeyName,
    __in DWORD dwLegacyKeySpec,
    __in DWORD dwFlags);

SECURITY_STATUS WINAPI KSPGetProviderProperty(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in DWORD cbOutput,
    __out DWORD *pcbResult,
    __in DWORD dwFlags);

SECURITY_STATUS WINAPI KSPGetKeyProperty(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in NCRYPT_KEY_HANDLE hKey,
    __in LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in DWORD cbOutput,
    __out DWORD *pcbResult,
    __in DWORD dwFlags);

SECURITY_STATUS WINAPI KSPSetProviderProperty(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in DWORD cbInput,
    __in DWORD dwFlags);

SECURITY_STATUS WINAPI KSPSetKeyProperty(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in NCRYPT_KEY_HANDLE hKey,
    __in LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in DWORD cbInput,
    __in DWORD dwFlags);

SECURITY_STATUS WINAPI KSPFinalizeKey(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in NCRYPT_KEY_HANDLE hKey,
    __in DWORD dwFlags);

SECURITY_STATUS WINAPI KSPDeleteKey(
    __in NCRYPT_PROV_HANDLE hProvider,
    __inout NCRYPT_KEY_HANDLE hKey,
    __in DWORD dwFlags);

SECURITY_STATUS WINAPI KSPFreeProvider(
    __in NCRYPT_PROV_HANDLE hProvider);

SECURITY_STATUS WINAPI KSPFreeKey(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in NCRYPT_KEY_HANDLE hKey);

SECURITY_STATUS WINAPI KSPFreeBuffer(
    __deref PVOID pvInput);

SECURITY_STATUS WINAPI KSPEncrypt(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in NCRYPT_KEY_HANDLE hKey,
    __in_bcount(cbInput) PBYTE pbInput,
    __in DWORD cbInput,
    __in VOID *pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in DWORD cbOutput,
    __out DWORD *pcbResult,
    __in DWORD dwFlags);

SECURITY_STATUS WINAPI KSPDecrypt(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in NCRYPT_KEY_HANDLE hKey,
    __in_bcount(cbInput) PBYTE pbInput,
    __in DWORD cbInput,
    __in VOID *pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in DWORD cbOutput,
    __out DWORD *pcbResult,
    __in DWORD dwFlags);

SECURITY_STATUS WINAPI KSPIsAlgSupported(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in LPCWSTR pszAlgId,
    __in DWORD dwFlags);

SECURITY_STATUS WINAPI KSPEnumAlgorithms(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in DWORD dwAlgOperations,
    __out DWORD *pdwAlgCount,
    __deref_out_ecount(*pdwAlgCount) NCryptAlgorithmName **ppAlgList,
    __in DWORD dwFlags);

SECURITY_STATUS WINAPI KSPEnumKeys(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in_opt LPCWSTR pszScope,
    __deref_out NCryptKeyName **ppKeyName,
    __inout PVOID *ppEnumState,
    __in DWORD dwFlags);

SECURITY_STATUS WINAPI KSPImportKey(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hImportKey,
    __in LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out NCRYPT_KEY_HANDLE *phKey,
    __in_bcount(cbData) PBYTE pbData,
    __in DWORD cbData,
    __in DWORD dwFlags);

SECURITY_STATUS WINAPI KSPExportKey(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in NCRYPT_KEY_HANDLE hKey,
    __in_opt NCRYPT_KEY_HANDLE hExportKey,
    __in LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in DWORD cbOutput,
    __out DWORD *pcbResult,
    __in DWORD dwFlags);

SECURITY_STATUS WINAPI KSPSignHash(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in NCRYPT_KEY_HANDLE hKey,
    __in_opt VOID *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in DWORD cbHashValue,
    __out_bcount_part_opt(cbSignature, *pcbResult) PBYTE pbSignature,
    __in DWORD cbSignature,
    __out DWORD *pcbResult,
    __in DWORD dwFlags);

SECURITY_STATUS WINAPI KSPVerifySignature(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in NCRYPT_KEY_HANDLE hKey,
    __in_opt VOID *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in DWORD cbHashValue,
    __in_bcount(cbSignature) PBYTE pbSignature,
    __in DWORD cbSignature,
    __in DWORD dwFlags);

SECURITY_STATUS WINAPI KSPPromptUser(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hKey,
    __in LPCWSTR pszOperation,
    __in DWORD dwFlags);

SECURITY_STATUS WINAPI KSPNotifyChangeKey(
    __in NCRYPT_PROV_HANDLE hProvider,
    __inout HANDLE *phEvent,
    __in DWORD dwFlags);

SECURITY_STATUS WINAPI KSPSecretAgreement(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in NCRYPT_KEY_HANDLE hPrivKey,
    __in NCRYPT_KEY_HANDLE hPubKey,
    __out NCRYPT_SECRET_HANDLE *phSecret,
    __in DWORD dwFlags);

SECURITY_STATUS WINAPI KSPDeriveKey(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_SECRET_HANDLE hSharedSecret,
    __in LPCWSTR pwszKDF,
    __in_opt NCryptBufferDesc *pParameterList,
    __out_bcount_part_opt(cbDerivedKey, *pcbResult) PBYTE pbDerivedKey,
    __in DWORD cbDerivedKey,
    __out DWORD *pcbResult,
    __in ULONG dwFlags);

SECURITY_STATUS WINAPI KSPFreeSecret(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in NCRYPT_SECRET_HANDLE hSharedSecret);

// ============================================================================
// Function Table - use function pointers, not typedefs
// ============================================================================

typedef struct _NCRYPT_KEY_STORAGE_FUNCTION_TABLE_V1 {
    DWORD cbSize;
    void* OpenProvider;
    void* OpenKey;
    void* CreatePersistedKey;
    void* GetProviderProperty;
    void* GetKeyProperty;
    void* SetProviderProperty;
    void* SetKeyProperty;
    void* FinalizeKey;
    void* DeleteKey;
    void* FreeProvider;
    void* FreeKey;
    void* FreeBuffer;
    void* Encrypt;
    void* Decrypt;
    void* IsAlgSupported;
    void* EnumAlgorithms;
    void* EnumKeys;
    void* ImportKey;
    void* ExportKey;
    void* SignHash;
    void* VerifySignature;
    void* PromptUser;
    void* NotifyChangeKey;
    void* SecretAgreement;
    void* DeriveKey;
    void* FreeSecret;
} NCRYPT_KEY_STORAGE_FUNCTION_TABLE_V1;

static NCRYPT_KEY_STORAGE_FUNCTION_TABLE_V1 g_FuncTable = {
    sizeof(NCRYPT_KEY_STORAGE_FUNCTION_TABLE_V1),
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
    KSPPromptUser,
    KSPNotifyChangeKey,
    KSPSecretAgreement,
    KSPDeriveKey,
    KSPFreeSecret
};

// ============================================================================
// DLL Entry
// ============================================================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        Log("DLL_PROCESS_ATTACH");
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        Log("DLL_PROCESS_DETACH");
        break;
    }
    return TRUE;
}

// ============================================================================
// GetKeyStorageInterface - Main Entry Point
// ============================================================================

extern "C" __declspec(dllexport)
NTSTATUS WINAPI GetKeyStorageInterface(
    __in LPCWSTR pszProviderName,
    __out NCRYPT_KEY_STORAGE_FUNCTION_TABLE_V1 **ppFunctionTable,
    __in DWORD dwFlags)
{
    Log("GetKeyStorageInterface called");
    *ppFunctionTable = &g_FuncTable;
    return ERROR_SUCCESS;
}

// ============================================================================
// Provider Functions
// ============================================================================

SECURITY_STATUS WINAPI KSPOpenProvider(
    __out NCRYPT_PROV_HANDLE *phProvider,
    __in LPCWSTR pszProviderName,
    __in DWORD dwFlags)
{
    Log("KSPOpenProvider");
    
    AKSP_PROV* pProv = (AKSP_PROV*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(AKSP_PROV));
    if (!pProv)
        return NTE_NO_MEMORY;
    
    pProv->magic = PROV_MAGIC;
    
    // Open base provider
    SECURITY_STATUS status = NCryptOpenStorageProvider(&pProv->hBase, MS_KEY_STORAGE_PROVIDER, 0);
    if (status != ERROR_SUCCESS)
    {
        Log("Failed to open base provider");
        HeapFree(GetProcessHeap(), 0, pProv);
        return status;
    }
    
    *phProvider = (NCRYPT_PROV_HANDLE)pProv;
    Log("KSPOpenProvider OK");
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPFreeProvider(
    __in NCRYPT_PROV_HANDLE hProvider)
{
    Log("KSPFreeProvider");
    AKSP_PROV* pProv = (AKSP_PROV*)hProvider;
    if (pProv && pProv->magic == PROV_MAGIC)
    {
        if (pProv->hBase)
            NCryptFreeObject(pProv->hBase);
        HeapFree(GetProcessHeap(), 0, pProv);
    }
    return ERROR_SUCCESS;
}

// ============================================================================
// Key Functions
// ============================================================================

SECURITY_STATUS WINAPI KSPOpenKey(
    __in NCRYPT_PROV_HANDLE hProvider,
    __out NCRYPT_KEY_HANDLE *phKey,
    __in LPCWSTR pszKeyName,
    __in DWORD dwLegacyKeySpec,
    __in DWORD dwFlags)
{
    Log("KSPOpenKey");
    AKSP_PROV* pProv = (AKSP_PROV*)hProvider;
    if (!pProv || pProv->magic != PROV_MAGIC)
        return NTE_INVALID_HANDLE;
    
    AKSP_KEY* pKey = (AKSP_KEY*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(AKSP_KEY));
    if (!pKey)
        return NTE_NO_MEMORY;
    
    pKey->magic = PROV_MAGIC;
    pKey->pProv = pProv;
    
    SECURITY_STATUS status = NCryptOpenKey(pProv->hBase, &pKey->hBase, pszKeyName, dwLegacyKeySpec, dwFlags);
    if (status != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, pKey);
        return status;
    }
    
    *phKey = (NCRYPT_KEY_HANDLE)pKey;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPCreatePersistedKey(
    __in NCRYPT_PROV_HANDLE hProvider,
    __out NCRYPT_KEY_HANDLE *phKey,
    __in LPCWSTR pszAlgId,
    __in_opt LPCWSTR pszKeyName,
    __in DWORD dwLegacyKeySpec,
    __in DWORD dwFlags)
{
    Log("KSPCreatePersistedKey");
    AKSP_PROV* pProv = (AKSP_PROV*)hProvider;
    if (!pProv || pProv->magic != PROV_MAGIC)
        return NTE_INVALID_HANDLE;
    
    AKSP_KEY* pKey = (AKSP_KEY*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(AKSP_KEY));
    if (!pKey)
        return NTE_NO_MEMORY;
    
    pKey->magic = PROV_MAGIC;
    pKey->pProv = pProv;
    
    SECURITY_STATUS status = NCryptCreatePersistedKey(pProv->hBase, &pKey->hBase, pszAlgId, pszKeyName, dwLegacyKeySpec, dwFlags);
    if (status != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, pKey);
        return status;
    }
    
    *phKey = (NCRYPT_KEY_HANDLE)pKey;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPFreeKey(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in NCRYPT_KEY_HANDLE hKey)
{
    Log("KSPFreeKey");
    AKSP_KEY* pKey = (AKSP_KEY*)hKey;
    if (pKey && pKey->magic == PROV_MAGIC)
    {
        if (pKey->hBase)
            NCryptFreeObject(pKey->hBase);
        HeapFree(GetProcessHeap(), 0, pKey);
    }
    return ERROR_SUCCESS;
}

// ============================================================================
// Property Functions - Pure Passthrough
// ============================================================================

SECURITY_STATUS WINAPI KSPGetProviderProperty(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in DWORD cbOutput,
    __out DWORD *pcbResult,
    __in DWORD dwFlags)
{
    AKSP_PROV* pProv = (AKSP_PROV*)hProvider;
    if (!pProv || pProv->magic != PROV_MAGIC)
        return NTE_INVALID_HANDLE;
    return NCryptGetProperty(pProv->hBase, pszProperty, pbOutput, cbOutput, pcbResult, dwFlags);
}

SECURITY_STATUS WINAPI KSPGetKeyProperty(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in NCRYPT_KEY_HANDLE hKey,
    __in LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in DWORD cbOutput,
    __out DWORD *pcbResult,
    __in DWORD dwFlags)
{
    AKSP_KEY* pKey = (AKSP_KEY*)hKey;
    if (!pKey || pKey->magic != PROV_MAGIC)
        return NTE_INVALID_HANDLE;
    return NCryptGetProperty(pKey->hBase, pszProperty, pbOutput, cbOutput, pcbResult, dwFlags);
}

SECURITY_STATUS WINAPI KSPSetProviderProperty(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in DWORD cbInput,
    __in DWORD dwFlags)
{
    AKSP_PROV* pProv = (AKSP_PROV*)hProvider;
    if (!pProv || pProv->magic != PROV_MAGIC)
        return NTE_INVALID_HANDLE;
    return NCryptSetProperty(pProv->hBase, pszProperty, pbInput, cbInput, dwFlags);
}

SECURITY_STATUS WINAPI KSPSetKeyProperty(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in NCRYPT_KEY_HANDLE hKey,
    __in LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in DWORD cbInput,
    __in DWORD dwFlags)
{
    Log("KSPSetKeyProperty");
    AKSP_KEY* pKey = (AKSP_KEY*)hKey;
    if (!pKey || pKey->magic != PROV_MAGIC)
        return NTE_INVALID_HANDLE;
    
    // TODO: Intercept NCRYPT_PIN_PROPERTY here for OTP validation
    // For now, just pass through
    
    return NCryptSetProperty(pKey->hBase, pszProperty, pbInput, cbInput, dwFlags);
}

// ============================================================================
// Crypto Functions - Pure Passthrough
// ============================================================================

SECURITY_STATUS WINAPI KSPFinalizeKey(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in NCRYPT_KEY_HANDLE hKey,
    __in DWORD dwFlags)
{
    AKSP_KEY* pKey = (AKSP_KEY*)hKey;
    if (!pKey || pKey->magic != PROV_MAGIC)
        return NTE_INVALID_HANDLE;
    return NCryptFinalizeKey(pKey->hBase, dwFlags);
}

SECURITY_STATUS WINAPI KSPDeleteKey(
    __in NCRYPT_PROV_HANDLE hProvider,
    __inout NCRYPT_KEY_HANDLE hKey,
    __in DWORD dwFlags)
{
    AKSP_KEY* pKey = (AKSP_KEY*)hKey;
    if (!pKey || pKey->magic != PROV_MAGIC)
        return NTE_INVALID_HANDLE;
    return NCryptDeleteKey(pKey->hBase, dwFlags);
}

SECURITY_STATUS WINAPI KSPFreeBuffer(__deref PVOID pvInput)
{
    if (pvInput)
        HeapFree(GetProcessHeap(), 0, pvInput);
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPEncrypt(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in NCRYPT_KEY_HANDLE hKey,
    __in_bcount(cbInput) PBYTE pbInput,
    __in DWORD cbInput,
    __in VOID *pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in DWORD cbOutput,
    __out DWORD *pcbResult,
    __in DWORD dwFlags)
{
    AKSP_KEY* pKey = (AKSP_KEY*)hKey;
    if (!pKey || pKey->magic != PROV_MAGIC)
        return NTE_INVALID_HANDLE;
    return NCryptEncrypt(pKey->hBase, pbInput, cbInput, pPaddingInfo, pbOutput, cbOutput, pcbResult, dwFlags);
}

SECURITY_STATUS WINAPI KSPDecrypt(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in NCRYPT_KEY_HANDLE hKey,
    __in_bcount(cbInput) PBYTE pbInput,
    __in DWORD cbInput,
    __in VOID *pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in DWORD cbOutput,
    __out DWORD *pcbResult,
    __in DWORD dwFlags)
{
    AKSP_KEY* pKey = (AKSP_KEY*)hKey;
    if (!pKey || pKey->magic != PROV_MAGIC)
        return NTE_INVALID_HANDLE;
    return NCryptDecrypt(pKey->hBase, pbInput, cbInput, pPaddingInfo, pbOutput, cbOutput, pcbResult, dwFlags);
}

SECURITY_STATUS WINAPI KSPIsAlgSupported(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in LPCWSTR pszAlgId,
    __in DWORD dwFlags)
{
    AKSP_PROV* pProv = (AKSP_PROV*)hProvider;
    if (!pProv || pProv->magic != PROV_MAGIC)
        return NTE_INVALID_HANDLE;
    return NCryptIsAlgSupported(pProv->hBase, pszAlgId, dwFlags);
}

SECURITY_STATUS WINAPI KSPEnumAlgorithms(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in DWORD dwAlgOperations,
    __out DWORD *pdwAlgCount,
    __deref_out_ecount(*pdwAlgCount) NCryptAlgorithmName **ppAlgList,
    __in DWORD dwFlags)
{
    AKSP_PROV* pProv = (AKSP_PROV*)hProvider;
    if (!pProv || pProv->magic != PROV_MAGIC)
        return NTE_INVALID_HANDLE;
    return NCryptEnumAlgorithms(pProv->hBase, dwAlgOperations, pdwAlgCount, ppAlgList, dwFlags);
}

SECURITY_STATUS WINAPI KSPEnumKeys(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in_opt LPCWSTR pszScope,
    __deref_out NCryptKeyName **ppKeyName,
    __inout PVOID *ppEnumState,
    __in DWORD dwFlags)
{
    AKSP_PROV* pProv = (AKSP_PROV*)hProvider;
    if (!pProv || pProv->magic != PROV_MAGIC)
        return NTE_INVALID_HANDLE;
    return NCryptEnumKeys(pProv->hBase, pszScope, ppKeyName, ppEnumState, dwFlags);
}

SECURITY_STATUS WINAPI KSPImportKey(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hImportKey,
    __in LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out NCRYPT_KEY_HANDLE *phKey,
    __in_bcount(cbData) PBYTE pbData,
    __in DWORD cbData,
    __in DWORD dwFlags)
{
    Log("KSPImportKey");
    AKSP_PROV* pProv = (AKSP_PROV*)hProvider;
    if (!pProv || pProv->magic != PROV_MAGIC)
        return NTE_INVALID_HANDLE;
    
    AKSP_KEY* pKey = (AKSP_KEY*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(AKSP_KEY));
    if (!pKey)
        return NTE_NO_MEMORY;
    
    pKey->magic = PROV_MAGIC;
    pKey->pProv = pProv;
    
    NCRYPT_KEY_HANDLE hImpKey = hImportKey ? ((AKSP_KEY*)hImportKey)->hBase : 0;
    
    SECURITY_STATUS status = NCryptImportKey(pProv->hBase, hImpKey, pszBlobType, pParameterList, &pKey->hBase, pbData, cbData, dwFlags);
    if (status != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, pKey);
        return status;
    }
    
    *phKey = (NCRYPT_KEY_HANDLE)pKey;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPExportKey(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in NCRYPT_KEY_HANDLE hKey,
    __in_opt NCRYPT_KEY_HANDLE hExportKey,
    __in LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in DWORD cbOutput,
    __out DWORD *pcbResult,
    __in DWORD dwFlags)
{
    AKSP_KEY* pKey = (AKSP_KEY*)hKey;
    if (!pKey || pKey->magic != PROV_MAGIC)
        return NTE_INVALID_HANDLE;
    NCRYPT_KEY_HANDLE hExpKey = hExportKey ? ((AKSP_KEY*)hExportKey)->hBase : 0;
    return NCryptExportKey(pKey->hBase, hExpKey, pszBlobType, pParameterList, pbOutput, cbOutput, pcbResult, dwFlags);
}

SECURITY_STATUS WINAPI KSPSignHash(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in NCRYPT_KEY_HANDLE hKey,
    __in_opt VOID *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in DWORD cbHashValue,
    __out_bcount_part_opt(cbSignature, *pcbResult) PBYTE pbSignature,
    __in DWORD cbSignature,
    __out DWORD *pcbResult,
    __in DWORD dwFlags)
{
    Log("KSPSignHash - PASSTHROUGH FOR NOW");
    AKSP_KEY* pKey = (AKSP_KEY*)hKey;
    if (!pKey || pKey->magic != PROV_MAGIC)
        return NTE_INVALID_HANDLE;
    
    // TODO: Add OTP validation here
    // For now, just pass through to base provider
    
    return NCryptSignHash(pKey->hBase, pPaddingInfo, pbHashValue, cbHashValue, pbSignature, cbSignature, pcbResult, dwFlags);
}

SECURITY_STATUS WINAPI KSPVerifySignature(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in NCRYPT_KEY_HANDLE hKey,
    __in_opt VOID *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in DWORD cbHashValue,
    __in_bcount(cbSignature) PBYTE pbSignature,
    __in DWORD cbSignature,
    __in DWORD dwFlags)
{
    AKSP_KEY* pKey = (AKSP_KEY*)hKey;
    if (!pKey || pKey->magic != PROV_MAGIC)
        return NTE_INVALID_HANDLE;
    return NCryptVerifySignature(pKey->hBase, pPaddingInfo, pbHashValue, cbHashValue, pbSignature, cbSignature, dwFlags);
}

SECURITY_STATUS WINAPI KSPPromptUser(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hKey,
    __in LPCWSTR pszOperation,
    __in DWORD dwFlags)
{
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPNotifyChangeKey(
    __in NCRYPT_PROV_HANDLE hProvider,
    __inout HANDLE *phEvent,
    __in DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPSecretAgreement(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in NCRYPT_KEY_HANDLE hPrivKey,
    __in NCRYPT_KEY_HANDLE hPubKey,
    __out NCRYPT_SECRET_HANDLE *phSecret,
    __in DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPDeriveKey(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_SECRET_HANDLE hSharedSecret,
    __in LPCWSTR pwszKDF,
    __in_opt NCryptBufferDesc *pParameterList,
    __out_bcount_part_opt(cbDerivedKey, *pcbResult) PBYTE pbDerivedKey,
    __in DWORD cbDerivedKey,
    __out DWORD *pcbResult,
    __in ULONG dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPFreeSecret(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in NCRYPT_SECRET_HANDLE hSharedSecret)
{
    return NTE_NOT_SUPPORTED;
}
