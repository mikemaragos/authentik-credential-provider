// AuthentikKSPDll.cpp
// DLL entry point and NCrypt function table export

#include "AuthentikKSP.h"

// Define NTSTATUS codes we need (avoid including ntstatus.h which conflicts with windows.h)
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#endif

// ============================================================================
// NCrypt Key Storage Provider Function Table Definition
// 
// This structure must match what NCrypt expects. We define it ourselves
// because the SDK headers can be inconsistent.
// ============================================================================

typedef SECURITY_STATUS (WINAPI *KspOpenProviderFn)(
    NCRYPT_PROV_HANDLE*, LPCWSTR, DWORD);
typedef SECURITY_STATUS (WINAPI *KspOpenKeyFn)(
    NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE*, LPCWSTR, DWORD, DWORD);
typedef SECURITY_STATUS (WINAPI *KspCreatePersistedKeyFn)(
    NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE*, LPCWSTR, LPCWSTR, DWORD, DWORD);
typedef SECURITY_STATUS (WINAPI *KspGetProviderPropertyFn)(
    NCRYPT_PROV_HANDLE, LPCWSTR, PBYTE, DWORD, DWORD*, DWORD);
typedef SECURITY_STATUS (WINAPI *KspGetKeyPropertyFn)(
    NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, PBYTE, DWORD, DWORD*, DWORD);
typedef SECURITY_STATUS (WINAPI *KspSetProviderPropertyFn)(
    NCRYPT_PROV_HANDLE, LPCWSTR, PBYTE, DWORD, DWORD);
typedef SECURITY_STATUS (WINAPI *KspSetKeyPropertyFn)(
    NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, PBYTE, DWORD, DWORD);
typedef SECURITY_STATUS (WINAPI *KspFinalizeKeyFn)(
    NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, DWORD);
typedef SECURITY_STATUS (WINAPI *KspDeleteKeyFn)(
    NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, DWORD);
typedef SECURITY_STATUS (WINAPI *KspFreeProviderFn)(
    NCRYPT_PROV_HANDLE);
typedef SECURITY_STATUS (WINAPI *KspFreeKeyFn)(
    NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE);
typedef SECURITY_STATUS (WINAPI *KspFreeBufferFn)(
    PVOID);
typedef SECURITY_STATUS (WINAPI *KspEncryptFn)(
    NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, PBYTE, DWORD, VOID*, PBYTE, DWORD, DWORD*, DWORD);
typedef SECURITY_STATUS (WINAPI *KspDecryptFn)(
    NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, PBYTE, DWORD, VOID*, PBYTE, DWORD, DWORD*, DWORD);
typedef SECURITY_STATUS (WINAPI *KspIsAlgSupportedFn)(
    NCRYPT_PROV_HANDLE, LPCWSTR, DWORD);
typedef SECURITY_STATUS (WINAPI *KspEnumAlgorithmsFn)(
    NCRYPT_PROV_HANDLE, DWORD, DWORD*, NCryptAlgorithmName**, DWORD);
typedef SECURITY_STATUS (WINAPI *KspEnumKeysFn)(
    NCRYPT_PROV_HANDLE, LPCWSTR, NCryptKeyName**, PVOID*, DWORD);
typedef SECURITY_STATUS (WINAPI *KspImportKeyFn)(
    NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, NCryptBufferDesc*, NCRYPT_KEY_HANDLE*, PBYTE, DWORD, DWORD);
typedef SECURITY_STATUS (WINAPI *KspExportKeyFn)(
    NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, NCryptBufferDesc*, PBYTE, DWORD, DWORD*, DWORD);
typedef SECURITY_STATUS (WINAPI *KspSignHashFn)(
    NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, VOID*, PBYTE, DWORD, PBYTE, DWORD, DWORD*, DWORD);
typedef SECURITY_STATUS (WINAPI *KspVerifySignatureFn)(
    NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, VOID*, PBYTE, DWORD, PBYTE, DWORD, DWORD);
typedef SECURITY_STATUS (WINAPI *KspPromptUserFn)(
    NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, DWORD);
typedef SECURITY_STATUS (WINAPI *KspNotifyChangeKeyFn)(
    NCRYPT_PROV_HANDLE, HANDLE*, DWORD);
typedef SECURITY_STATUS (WINAPI *KspSecretAgreementFn)(
    NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_SECRET_HANDLE*, DWORD);
typedef SECURITY_STATUS (WINAPI *KspDeriveKeyFn)(
    NCRYPT_PROV_HANDLE, NCRYPT_SECRET_HANDLE, LPCWSTR, NCryptBufferDesc*, PUCHAR, DWORD, DWORD*, ULONG);
typedef SECURITY_STATUS (WINAPI *KspFreeSecretFn)(
    NCRYPT_PROV_HANDLE, NCRYPT_SECRET_HANDLE);

// KSP Interface Version
#define NCRYPT_KEY_STORAGE_INTERFACE_VERSION_1  0x00010001

// Our function table structure
typedef struct _AUTHENTIK_KSP_FUNCTION_TABLE {
    DWORD                       Version;
    KspOpenProviderFn           OpenProvider;
    KspOpenKeyFn                OpenKey;
    KspCreatePersistedKeyFn     CreatePersistedKey;
    KspGetProviderPropertyFn    GetProviderProperty;
    KspGetKeyPropertyFn         GetKeyProperty;
    KspSetProviderPropertyFn    SetProviderProperty;
    KspSetKeyPropertyFn         SetKeyProperty;
    KspFinalizeKeyFn            FinalizeKey;
    KspDeleteKeyFn              DeleteKey;
    KspFreeProviderFn           FreeProvider;
    KspFreeKeyFn                FreeKey;
    KspFreeBufferFn             FreeBuffer;
    KspEncryptFn                Encrypt;
    KspDecryptFn                Decrypt;
    KspIsAlgSupportedFn         IsAlgSupported;
    KspEnumAlgorithmsFn         EnumAlgorithms;
    KspEnumKeysFn               EnumKeys;
    KspImportKeyFn              ImportKey;
    KspExportKeyFn              ExportKey;
    KspSignHashFn               SignHash;
    KspVerifySignatureFn        VerifySignature;
    KspPromptUserFn             PromptUser;
    KspNotifyChangeKeyFn        NotifyChangeKey;
    KspSecretAgreementFn        SecretAgreement;
    KspDeriveKeyFn              DeriveKey;
    KspFreeSecretFn             FreeSecret;
} AUTHENTIK_KSP_FUNCTION_TABLE;

// ============================================================================
// DLL Entry Point
// ============================================================================

HINSTANCE g_hInstance = NULL;

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        g_hInstance = hModule;
        DisableThreadLibraryCalls(hModule);
        break;

    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// ============================================================================
// NCrypt Key Storage Provider Function Table
// ============================================================================

// The function table that NCrypt will use to call our provider
static AUTHENTIK_KSP_FUNCTION_TABLE g_FunctionTable = {
    NCRYPT_KEY_STORAGE_INTERFACE_VERSION_1,     // Version

    // Core functions
    AuthentikKSPOpenProvider,                   // OpenProvider
    AuthentikKSPOpenKey,                        // OpenKey
    AuthentikKSPCreatePersistedKey,             // CreatePersistedKey
    AuthentikKSPGetProviderProperty,            // GetProviderProperty
    AuthentikKSPGetKeyProperty,                 // GetKeyProperty
    AuthentikKSPSetProviderProperty,            // SetProviderProperty
    AuthentikKSPSetKeyProperty,                 // SetKeyProperty
    AuthentikKSPFinalizeKey,                    // FinalizeKey
    AuthentikKSPDeleteKey,                      // DeleteKey
    AuthentikKSPFreeProvider,                   // FreeProvider
    AuthentikKSPFreeKey,                        // FreeKey
    AuthentikKSPFreeBuffer,                     // FreeBuffer

    // Crypto operations
    AuthentikKSPEncrypt,                        // Encrypt
    AuthentikKSPDecrypt,                        // Decrypt
    AuthentikKSPIsAlgSupported,                 // IsAlgSupported
    AuthentikKSPEnumAlgorithms,                 // EnumAlgorithms
    AuthentikKSPEnumKeys,                       // EnumKeys
    AuthentikKSPImportKey,                      // ImportKey
    AuthentikKSPExportKey,                      // ExportKey
    AuthentikKSPSignHash,                       // SignHash
    AuthentikKSPVerifySignature,                // VerifySignature
    AuthentikKSPPromptUser,                     // PromptUser
    AuthentikKSPNotifyChangeKey,                // NotifyChangeKey
    AuthentikKSPSecretAgreement,                // SecretAgreement
    AuthentikKSPDeriveKey,                      // DeriveKey
    AuthentikKSPFreeSecret                      // FreeSecret
};

// ============================================================================
// Exported Functions
// ============================================================================

// NCrypt calls this to get our function table
extern "C" __declspec(dllexport)
NTSTATUS WINAPI GetKeyStorageInterface(
    _In_ LPCWSTR pszProviderName,
    _Out_ PVOID* ppFunctionTable,
    _In_ DWORD dwFlags)
{
    if (ppFunctionTable == NULL)
        return STATUS_INVALID_PARAMETER;

    // Return our function table
    *ppFunctionTable = &g_FunctionTable;
    return STATUS_SUCCESS;
}

// Alternative entry point name that some versions of Windows use
extern "C" __declspec(dllexport)
NTSTATUS WINAPI GetKeyStorageInterfaceEx(
    _In_ LPCWSTR pszProviderName,
    _In_ DWORD dwFlags,
    _Out_ PVOID* ppFunctionTable,
    _Out_ DWORD* pdwSize)
{
    if (ppFunctionTable == NULL)
        return STATUS_INVALID_PARAMETER;

    *ppFunctionTable = &g_FunctionTable;
    if (pdwSize)
        *pdwSize = sizeof(AUTHENTIK_KSP_FUNCTION_TABLE);
    return STATUS_SUCCESS;
}
