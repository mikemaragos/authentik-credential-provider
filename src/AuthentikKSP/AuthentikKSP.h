// AuthentikKSP.h
// Authentik Key Storage Provider - Header
// Provides certificate-based authentication for PKINIT

#pragma once

#include <windows.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <string>
#include <map>
#include <mutex>

// KSP Provider Name
#define AUTHENTIK_KSP_NAME L"Authentik Key Storage Provider"

// Key container prefix
#define AUTHENTIK_KEY_PREFIX L"AUTHENTIK_"

// Shared memory name for credential provider communication
#define AUTHENTIK_SHARED_MEMORY_NAME L"Global\\AuthentikKSPSharedMemory"
#define AUTHENTIK_MUTEX_NAME L"Global\\AuthentikKSPMutex"

// Maximum certificate/key sizes
#define MAX_CERTIFICATE_SIZE 8192
#define MAX_PRIVATE_KEY_SIZE 4096
#define MAX_USERNAME_SIZE 256

// Shared memory structure for credential provider communication
#pragma pack(push, 1)
typedef struct _AUTHENTIK_SHARED_DATA {
    DWORD dwMagic;                              // Magic number for validation (0x41555448 = "AUTH")
    DWORD dwVersion;                            // Structure version
    BOOL bDataReady;                            // Data is ready to be consumed
    BOOL bDataConsumed;                         // KSP has consumed the data
    WCHAR wszUsername[MAX_USERNAME_SIZE];       // Username
    DWORD cbCertificate;                        // Certificate size in bytes
    BYTE rgbCertificate[MAX_CERTIFICATE_SIZE];  // DER-encoded certificate
    DWORD cbPrivateKey;                         // Private key size
    BYTE rgbPrivateKey[MAX_PRIVATE_KEY_SIZE];   // Private key blob (BCRYPT_RSAFULLPRIVATE_BLOB)
    DWORD dwKeySpec;                            // Key specification (AT_KEYEXCHANGE or AT_SIGNATURE)
    DWORD dwError;                              // Error code if any
} AUTHENTIK_SHARED_DATA, *PAUTHENTIK_SHARED_DATA;
#pragma pack(pop)

#define AUTHENTIK_SHARED_MAGIC 0x41555448

// Internal key handle structure
typedef struct _AUTHENTIK_KEY {
    DWORD dwMagic;                      // Magic for validation
    std::wstring wszKeyName;            // Key container name
    std::wstring wszUsername;           // Associated username
    BCRYPT_KEY_HANDLE hBcryptKey;       // BCrypt key handle for operations
    DWORD dwKeySpec;                    // AT_KEYEXCHANGE or AT_SIGNATURE
    DWORD cbCertificate;                // Certificate size
    PBYTE pbCertificate;                // Certificate data (DER encoded)
    DWORD cbPrivateKeyBlob;             // Private key blob size
    PBYTE pbPrivateKeyBlob;             // Private key blob
    BOOL bFromSharedMemory;             // Key came from credential provider
} AUTHENTIK_KEY, *PAUTHENTIK_KEY;

#define AUTHENTIK_KEY_MAGIC 0x4B455921  // "KEY!"

// Internal provider handle structure
typedef struct _AUTHENTIK_PROVIDER {
    DWORD dwMagic;                      // Magic for validation
    HANDLE hSharedMemory;               // Handle to shared memory
    HANDLE hMutex;                      // Synchronization mutex
    PAUTHENTIK_SHARED_DATA pSharedData; // Pointer to shared memory
} AUTHENTIK_PROVIDER, *PAUTHENTIK_PROVIDER;

#define AUTHENTIK_PROVIDER_MAGIC 0x50525621  // "PRV!"

// KSP Function declarations
extern "C" {

// Provider management
SECURITY_STATUS WINAPI KSPOpenProvider(
    __out   NCRYPT_PROV_HANDLE *phProvider,
    __in    LPCWSTR pszProviderName,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPFreeProvider(
    __in    NCRYPT_PROV_HANDLE hProvider);

// Key management
SECURITY_STATUS WINAPI KSPOpenKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszKeyName,
    __in    DWORD dwLegacyKeySpec,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPCreatePersistedKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszAlgId,
    __in_opt LPCWSTR pszKeyName,
    __in    DWORD dwLegacyKeySpec,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPFinalizeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPDeleteKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPFreeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey);

// Property management
SECURITY_STATUS WINAPI KSPGetProviderProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPGetKeyProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPSetProviderProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD cbInput,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPSetKeyProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD cbInput,
    __in    DWORD dwFlags);

// Cryptographic operations
SECURITY_STATUS WINAPI KSPEncrypt(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD cbInput,
    __in    VOID *pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPDecrypt(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD cbInput,
    __in    VOID *pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPSignHash(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    VOID *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD cbHashValue,
    __out_bcount_part_opt(cbSignature, *pcbResult) PBYTE pbSignature,
    __in    DWORD cbSignature,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPVerifySignature(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    VOID *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD cbHashValue,
    __in_bcount(cbSignature) PBYTE pbSignature,
    __in    DWORD cbSignature,
    __in    DWORD dwFlags);

// Utility functions
SECURITY_STATUS WINAPI KSPIsAlgSupported(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszAlgId,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPEnumAlgorithms(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    DWORD dwAlgOperations,
    __out   DWORD *pdwAlgCount,
    __out   NCryptAlgorithmName **ppAlgList,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPEnumKeys(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt LPCWSTR pszScope,
    __out   NCryptKeyName **ppKeyName,
    __inout PVOID *ppEnumState,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPImportKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hImportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in_bcount(cbData) PBYTE pbData,
    __in    DWORD cbData,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPExportKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt NCRYPT_KEY_HANDLE hExportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPFreeBuffer(
    __deref PVOID pvInput);

// Not implemented but required
SECURITY_STATUS WINAPI KSPNotifyChangeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout HANDLE *phEvent,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPSecretAgreement(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hPrivKey,
    __in    NCRYPT_KEY_HANDLE hPubKey,
    __out   NCRYPT_SECRET_HANDLE *phSecret,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPDeriveKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_SECRET_HANDLE hSharedSecret,
    __in    LPCWSTR pwszKDF,
    __in_opt NCryptBufferDesc *pParameterList,
    __out_bcount_part_opt(cbDerivedKey, *pcbResult) PBYTE pbDerivedKey,
    __in    DWORD cbDerivedKey,
    __out   DWORD *pcbResult,
    __in    ULONG dwFlags);

SECURITY_STATUS WINAPI KSPFreeSecret(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_SECRET_HANDLE hSharedSecret);

// DLL entry point for function table
NTSTATUS WINAPI GetKeyStorageInterface(
    __in    LPCWSTR pszProviderName,
    __out   NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable,
    __in    DWORD dwFlags);

} // extern "C"

// Helper functions
BOOL ValidateProviderHandle(NCRYPT_PROV_HANDLE hProvider);
BOOL ValidateKeyHandle(NCRYPT_KEY_HANDLE hKey);
PAUTHENTIK_KEY CreateKeyFromSharedMemory(PAUTHENTIK_PROVIDER pProvider);
void CleanupKey(PAUTHENTIK_KEY pKey);

// Logging
void KSPLog(const char* format, ...);

// DLL exports
void DllAddRef();
void DllRelease();
