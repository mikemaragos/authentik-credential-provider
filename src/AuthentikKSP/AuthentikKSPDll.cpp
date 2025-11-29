// AuthentikKSPDll.cpp
// DLL entry point and NCrypt function table export

#include "AuthentikKSP.h"

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
static NCRYPT_KEY_STORAGE_FUNCTION_TABLE g_FunctionTable = {
    NCRYPT_KEY_STORAGE_INTERFACE_VERSION,       // Version

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
    _Out_ NCRYPT_KEY_STORAGE_FUNCTION_TABLE** ppFunctionTable,
    _In_ DWORD dwFlags)
{
    // Return our function table
    *ppFunctionTable = &g_FunctionTable;
    return ERROR_SUCCESS;
}

// Alternative entry point name that some versions of Windows use
extern "C" __declspec(dllexport)
NTSTATUS WINAPI GetKeyStorageInterfaceEx(
    _In_ LPCWSTR pszProviderName,
    _In_ DWORD dwFlags,
    _Out_ NCRYPT_KEY_STORAGE_FUNCTION_TABLE** ppFunctionTable,
    _Out_ DWORD* pdwSize)
{
    *ppFunctionTable = &g_FunctionTable;
    if (pdwSize)
        *pdwSize = sizeof(NCRYPT_KEY_STORAGE_FUNCTION_TABLE);
    return ERROR_SUCCESS;
}
