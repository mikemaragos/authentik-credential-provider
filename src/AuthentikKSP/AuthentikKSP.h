// AuthentikKSP.h
// Authentik Key Storage Provider for PKINIT authentication
//
// PURE C IMPLEMENTATION - No C++ STL objects
// This avoids blue screens caused by C++ runtime not being initialized
// when the KSP is loaded early during Windows boot.

#ifndef AUTHENTIK_KSP_H
#define AUTHENTIK_KSP_H

#include <windows.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <wincrypt.h>

// Include shared memory structures
#include "../Shared/SharedMemory.h"

// ============================================================================
// NTSTATUS Codes (avoid including ntstatus.h which conflicts with windows.h)
// ============================================================================

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)
#endif

// ============================================================================
// Internal Handle Structures - PURE C, no STL
// ============================================================================

// Magic values for handle validation
#define AUTHENTIK_PROVIDER_MAGIC    0x50565250  // "PRVP"
#define AUTHENTIK_KEY_HANDLE_MAGIC  0x4B455948  // "KEYH"

// Maximum sizes for fixed buffers
#define MAX_CONTAINER_NAME  256
#define MAX_USER_NAME       256
#define MAX_KEY_BLOB_SIZE   8192   // Enough for 4096-bit RSA keys
#define MAX_CERT_BLOB_SIZE  16384  // Enough for large certificate chains

// Internal key handle structure - FIXED SIZE, NO STL
typedef struct _AUTHENTIK_KEY {
    DWORD dwMagic;                              // Must be AUTHENTIK_KEY_HANDLE_MAGIC
    NCRYPT_PROV_HANDLE hProvider;               // Parent provider
    WCHAR wszContainerName[MAX_CONTAINER_NAME]; // Key container name
    WCHAR wszUserName[MAX_USER_NAME];           // Associated user
    DWORD dwKeySpec;                            // Key specification
    DWORD dwFlags;                              // Key flags
    BYTE  rgbPrivateKeyBlob[MAX_KEY_BLOB_SIZE]; // BCRYPT_RSAPRIVATE_BLOB
    DWORD cbPrivateKeyBlob;                     // Actual size
    BYTE  rgbCertificateBlob[MAX_CERT_BLOB_SIZE]; // DER-encoded certificate
    DWORD cbCertificateBlob;                    // Actual size
    BCRYPT_KEY_HANDLE hBCryptKey;               // BCrypt key handle for operations
} AUTHENTIK_KEY, *PAUTHENTIK_KEY;

// Internal provider handle structure - FIXED SIZE, NO STL
typedef struct _AUTHENTIK_PROVIDER {
    DWORD dwMagic;                              // Must be AUTHENTIK_PROVIDER_MAGIC
    DWORD dwFlags;                              // Provider flags
} AUTHENTIK_PROVIDER, *PAUTHENTIK_PROVIDER;

// ============================================================================
// KSP Function Table
// ============================================================================

#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport) NTSTATUS WINAPI GetKeyStorageInterface(
    _In_ LPCWSTR pszProviderName,
    _Out_ PVOID* ppFunctionTable,
    _In_ DWORD dwFlags);

#ifdef __cplusplus
}
#endif

// ============================================================================
// NCrypt Provider Functions
// ============================================================================

SECURITY_STATUS WINAPI AuthentikKSPOpenProvider(
    _Out_ NCRYPT_PROV_HANDLE* phProvider,
    _In_opt_ LPCWSTR pszProviderName,
    _In_ DWORD dwFlags);

SECURITY_STATUS WINAPI AuthentikKSPOpenKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _Out_ NCRYPT_KEY_HANDLE* phKey,
    _In_ LPCWSTR pszKeyName,
    _In_opt_ DWORD dwLegacyKeySpec,
    _In_ DWORD dwFlags);

SECURITY_STATUS WINAPI AuthentikKSPCreatePersistedKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _Out_ NCRYPT_KEY_HANDLE* phKey,
    _In_ LPCWSTR pszAlgId,
    _In_opt_ LPCWSTR pszKeyName,
    _In_ DWORD dwLegacyKeySpec,
    _In_ DWORD dwFlags);

SECURITY_STATUS WINAPI AuthentikKSPGetProviderProperty(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ LPCWSTR pszProperty,
    _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    _In_ DWORD cbOutput,
    _Out_ DWORD* pcbResult,
    _In_ DWORD dwFlags);

SECURITY_STATUS WINAPI AuthentikKSPGetKeyProperty(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_KEY_HANDLE hKey,
    _In_ LPCWSTR pszProperty,
    _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    _In_ DWORD cbOutput,
    _Out_ DWORD* pcbResult,
    _In_ DWORD dwFlags);

SECURITY_STATUS WINAPI AuthentikKSPSetProviderProperty(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ LPCWSTR pszProperty,
    _In_reads_bytes_(cbInput) PBYTE pbInput,
    _In_ DWORD cbInput,
    _In_ DWORD dwFlags);

SECURITY_STATUS WINAPI AuthentikKSPSetKeyProperty(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_KEY_HANDLE hKey,
    _In_ LPCWSTR pszProperty,
    _In_reads_bytes_(cbInput) PBYTE pbInput,
    _In_ DWORD cbInput,
    _In_ DWORD dwFlags);

SECURITY_STATUS WINAPI AuthentikKSPFinalizeKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_KEY_HANDLE hKey,
    _In_ DWORD dwFlags);

SECURITY_STATUS WINAPI AuthentikKSPDeleteKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _Inout_ NCRYPT_KEY_HANDLE hKey,
    _In_ DWORD dwFlags);

SECURITY_STATUS WINAPI AuthentikKSPFreeProvider(
    _In_ NCRYPT_PROV_HANDLE hProvider);

SECURITY_STATUS WINAPI AuthentikKSPFreeKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_KEY_HANDLE hKey);

SECURITY_STATUS WINAPI AuthentikKSPFreeBuffer(
    _Pre_notnull_ PVOID pvInput);

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
    _In_ DWORD dwFlags);

SECURITY_STATUS WINAPI AuthentikKSPDecrypt(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_KEY_HANDLE hKey,
    _In_reads_bytes_opt_(cbInput) PBYTE pbInput,
    _In_ DWORD cbInput,
    _In_opt_ VOID* pPaddingInfo,
    _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    _In_ DWORD cbOutput,
    _Out_ DWORD* pcbResult,
    _In_ DWORD dwFlags);

SECURITY_STATUS WINAPI AuthentikKSPSignHash(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_KEY_HANDLE hKey,
    _In_opt_ VOID* pPaddingInfo,
    _In_reads_bytes_(cbHashValue) PBYTE pbHashValue,
    _In_ DWORD cbHashValue,
    _Out_writes_bytes_to_opt_(cbSignature, *pcbResult) PBYTE pbSignature,
    _In_ DWORD cbSignature,
    _Out_ DWORD* pcbResult,
    _In_ DWORD dwFlags);

SECURITY_STATUS WINAPI AuthentikKSPVerifySignature(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_KEY_HANDLE hKey,
    _In_opt_ VOID* pPaddingInfo,
    _In_reads_bytes_(cbHashValue) PBYTE pbHashValue,
    _In_ DWORD cbHashValue,
    _In_reads_bytes_(cbSignature) PBYTE pbSignature,
    _In_ DWORD cbSignature,
    _In_ DWORD dwFlags);

SECURITY_STATUS WINAPI AuthentikKSPPromptUser(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_opt_ NCRYPT_KEY_HANDLE hKey,
    _In_ LPCWSTR pszOperation,
    _In_ DWORD dwFlags);

SECURITY_STATUS WINAPI AuthentikKSPNotifyChangeKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _Inout_ HANDLE* phEvent,
    _In_ DWORD dwFlags);

SECURITY_STATUS WINAPI AuthentikKSPSecretAgreement(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_KEY_HANDLE hPrivKey,
    _In_ NCRYPT_KEY_HANDLE hPubKey,
    _Out_ NCRYPT_SECRET_HANDLE* phAgreedSecret,
    _In_ DWORD dwFlags);

SECURITY_STATUS WINAPI AuthentikKSPDeriveKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_opt_ NCRYPT_SECRET_HANDLE hSharedSecret,
    _In_ LPCWSTR pwszKDF,
    _In_opt_ NCryptBufferDesc* pParameterList,
    _Out_writes_bytes_to_opt_(cbDerivedKey, *pcbResult) PUCHAR pbDerivedKey,
    _In_ DWORD cbDerivedKey,
    _Out_ DWORD* pcbResult,
    _In_ ULONG dwFlags);

SECURITY_STATUS WINAPI AuthentikKSPFreeSecret(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_SECRET_HANDLE hSharedSecret);

// ============================================================================
// NCrypt Key Import/Export
// ============================================================================

SECURITY_STATUS WINAPI AuthentikKSPImportKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_opt_ NCRYPT_KEY_HANDLE hImportKey,
    _In_ LPCWSTR pszBlobType,
    _In_opt_ NCryptBufferDesc* pParameterList,
    _Out_ NCRYPT_KEY_HANDLE* phKey,
    _In_reads_bytes_(cbData) PBYTE pbData,
    _In_ DWORD cbData,
    _In_ DWORD dwFlags);

SECURITY_STATUS WINAPI AuthentikKSPExportKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ NCRYPT_KEY_HANDLE hKey,
    _In_opt_ NCRYPT_KEY_HANDLE hExportKey,
    _In_ LPCWSTR pszBlobType,
    _In_opt_ NCryptBufferDesc* pParameterList,
    _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    _In_ DWORD cbOutput,
    _Out_ DWORD* pcbResult,
    _In_ DWORD dwFlags);

SECURITY_STATUS WINAPI AuthentikKSPEnumAlgorithms(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ DWORD dwAlgOperations,
    _Out_ DWORD* pdwAlgCount,
    _Outptr_result_buffer_(*pdwAlgCount) NCryptAlgorithmName** ppAlgList,
    _In_ DWORD dwFlags);

SECURITY_STATUS WINAPI AuthentikKSPEnumKeys(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_opt_ LPCWSTR pszScope,
    _Outptr_ NCryptKeyName** ppKeyName,
    _Inout_ PVOID* ppEnumState,
    _In_ DWORD dwFlags);

SECURITY_STATUS WINAPI AuthentikKSPIsAlgSupported(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _In_ LPCWSTR pszAlgId,
    _In_ DWORD dwFlags);

#endif // AUTHENTIK_KSP_H
