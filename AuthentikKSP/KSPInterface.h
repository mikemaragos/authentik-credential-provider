// KSPInterface.h
// Key Storage Provider interface definitions
// These structures are typically from CPDK's ncrypt_provider.h
// Defined here for standalone compilation

#pragma once

#include <windows.h>
#include <ncrypt.h>

// KSP Interface Version
#define NCRYPT_KEY_STORAGE_INTERFACE_VERSION        1
#define NCRYPT_KEY_STORAGE_INTERFACE_VERSION_2      2

// Function pointer types for KSP functions
typedef __callback SECURITY_STATUS (WINAPI *NCryptOpenStorageProviderFn)(
    __out   NCRYPT_PROV_HANDLE *phProvider,
    __in    LPCWSTR pszProviderName,
    __in    DWORD dwFlags);

typedef __callback SECURITY_STATUS (WINAPI *NCryptOpenKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszKeyName,
    __in    DWORD dwLegacyKeySpec,
    __in    DWORD dwFlags);

typedef __callback SECURITY_STATUS (WINAPI *NCryptCreatePersistedKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszAlgId,
    __in_opt LPCWSTR pszKeyName,
    __in    DWORD dwLegacyKeySpec,
    __in    DWORD dwFlags);

typedef __callback SECURITY_STATUS (WINAPI *NCryptGetProviderPropertyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags);

typedef __callback SECURITY_STATUS (WINAPI *NCryptGetKeyPropertyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags);

typedef __callback SECURITY_STATUS (WINAPI *NCryptSetProviderPropertyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD cbInput,
    __in    DWORD dwFlags);

typedef __callback SECURITY_STATUS (WINAPI *NCryptSetKeyPropertyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD cbInput,
    __in    DWORD dwFlags);

typedef __callback SECURITY_STATUS (WINAPI *NCryptFinalizeKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    DWORD dwFlags);

typedef __callback SECURITY_STATUS (WINAPI *NCryptDeleteKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout NCRYPT_KEY_HANDLE hKey,
    __in    DWORD dwFlags);

typedef __callback SECURITY_STATUS (WINAPI *NCryptFreeProviderFn)(
    __in    NCRYPT_PROV_HANDLE hProvider);

typedef __callback SECURITY_STATUS (WINAPI *NCryptFreeKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey);

typedef __callback SECURITY_STATUS (WINAPI *NCryptFreeBufferFn)(
    __deref PVOID pvInput);

typedef __callback SECURITY_STATUS (WINAPI *NCryptEncryptFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD cbInput,
    __in    VOID *pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags);

typedef __callback SECURITY_STATUS (WINAPI *NCryptDecryptFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD cbInput,
    __in    VOID *pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags);

typedef __callback SECURITY_STATUS (WINAPI *NCryptIsAlgSupportedFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszAlgId,
    __in    DWORD dwFlags);

typedef __callback SECURITY_STATUS (WINAPI *NCryptEnumAlgorithmsFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    DWORD dwAlgOperations,
    __out   DWORD *pdwAlgCount,
    __deref_out_ecount(*pdwAlgCount) NCryptAlgorithmName **ppAlgList,
    __in    DWORD dwFlags);

typedef __callback SECURITY_STATUS (WINAPI *NCryptEnumKeysFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt LPCWSTR pszScope,
    __deref_out NCryptKeyName **ppKeyName,
    __inout PVOID *ppEnumState,
    __in    DWORD dwFlags);

typedef __callback SECURITY_STATUS (WINAPI *NCryptImportKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hImportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in_bcount(cbData) PBYTE pbData,
    __in    DWORD cbData,
    __in    DWORD dwFlags);

typedef __callback SECURITY_STATUS (WINAPI *NCryptExportKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt NCRYPT_KEY_HANDLE hExportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags);

typedef __callback SECURITY_STATUS (WINAPI *NCryptSignHashFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt VOID *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD cbHashValue,
    __out_bcount_part_opt(cbSignature, *pcbResult) PBYTE pbSignature,
    __in    DWORD cbSignature,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags);

typedef __callback SECURITY_STATUS (WINAPI *NCryptVerifySignatureFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt VOID *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD cbHashValue,
    __in_bcount(cbSignature) PBYTE pbSignature,
    __in    DWORD cbSignature,
    __in    DWORD dwFlags);

typedef __callback SECURITY_STATUS (WINAPI *NCryptPromptUserFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszOperation,
    __in    DWORD dwFlags);

typedef __callback SECURITY_STATUS (WINAPI *NCryptNotifyChangeKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout HANDLE *phEvent,
    __in    DWORD dwFlags);

typedef __callback SECURITY_STATUS (WINAPI *NCryptSecretAgreementFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hPrivKey,
    __in    NCRYPT_KEY_HANDLE hPubKey,
    __out   NCRYPT_SECRET_HANDLE *phSecret,
    __in    DWORD dwFlags);

typedef __callback SECURITY_STATUS (WINAPI *NCryptDeriveKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_SECRET_HANDLE hSharedSecret,
    __in    LPCWSTR pwszKDF,
    __in_opt NCryptBufferDesc *pParameterList,
    __out_bcount_part_opt(cbDerivedKey, *pcbResult) PBYTE pbDerivedKey,
    __in    DWORD cbDerivedKey,
    __out   DWORD *pcbResult,
    __in    ULONG dwFlags);

typedef __callback SECURITY_STATUS (WINAPI *NCryptFreeSecretFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_SECRET_HANDLE hSharedSecret);

// Key Storage Provider Function Table
typedef struct _NCRYPT_KEY_STORAGE_FUNCTION_TABLE {
    DWORD                           cbSize;
    NCryptOpenStorageProviderFn     OpenProvider;
    NCryptOpenKeyFn                 OpenKey;
    NCryptCreatePersistedKeyFn      CreatePersistedKey;
    NCryptGetProviderPropertyFn     GetProviderProperty;
    NCryptGetKeyPropertyFn          GetKeyProperty;
    NCryptSetProviderPropertyFn     SetProviderProperty;
    NCryptSetKeyPropertyFn          SetKeyProperty;
    NCryptFinalizeKeyFn             FinalizeKey;
    NCryptDeleteKeyFn               DeleteKey;
    NCryptFreeProviderFn            FreeProvider;
    NCryptFreeKeyFn                 FreeKey;
    NCryptFreeBufferFn              FreeBuffer;
    NCryptEncryptFn                 Encrypt;
    NCryptDecryptFn                 Decrypt;
    NCryptIsAlgSupportedFn          IsAlgSupported;
    NCryptEnumAlgorithmsFn          EnumAlgorithms;
    NCryptEnumKeysFn                EnumKeys;
    NCryptImportKeyFn               ImportKey;
    NCryptExportKeyFn               ExportKey;
    NCryptSignHashFn                SignHash;
    NCryptVerifySignatureFn         VerifySignature;
    NCryptPromptUserFn              PromptUser;
    NCryptNotifyChangeKeyFn         NotifyChangeKey;
    NCryptSecretAgreementFn         SecretAgreement;
    NCryptDeriveKeyFn               DeriveKey;
    NCryptFreeSecretFn              FreeSecret;
} NCRYPT_KEY_STORAGE_FUNCTION_TABLE;

// GetKeyStorageInterface export function type
typedef NTSTATUS (WINAPI *GetKeyStorageInterfaceFn)(
    __in    LPCWSTR pszProviderName,
    __out   NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable,
    __in    DWORD dwFlags);
