// AuthentikKSP.h
// Authentik Key Storage Provider for PKINIT authentication
// This KSP allows Windows to use certificates issued by Authentik for domain logon

#pragma once

#include <windows.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <string>
#include <map>
#include <mutex>
#include <vector>

// KSP Provider Name - must match registry registration
#define AUTHENTIK_KSP_NAME L"Authentik Key Storage Provider"

// KSP Interface version
#define AUTHENTIK_KSP_INTERFACE_VERSION NCRYPT_KEY_STORAGE_INTERFACE_VERSION

// Key container prefix
#define AUTHENTIK_KEY_PREFIX L"AuthentikPKINIT_"

// Shared memory name for key exchange between credential provider and KSP
#define AUTHENTIK_SHARED_MEM_NAME L"Global\\AuthentikKSPKeyStore"
#define AUTHENTIK_SHARED_MEM_SIZE (1024 * 1024)  // 1MB for keys

// Mutex name for synchronization
#define AUTHENTIK_MUTEX_NAME L"Global\\AuthentikKSPMutex"

// Magic number for validation
#define AUTHENTIK_KEY_MAGIC 0x4B535041  // "AKSP"

// Maximum number of cached keys
#define AUTHENTIK_MAX_CACHED_KEYS 16

// Key entry in shared memory
#pragma pack(push, 1)
typedef struct _AUTHENTIK_KEY_ENTRY {
    DWORD dwMagic;                      // Must be AUTHENTIK_KEY_MAGIC
    DWORD dwFlags;                      // Key flags
    DWORD dwKeySpec;                    // AT_KEYEXCHANGE or AT_SIGNATURE
    FILETIME ftCreated;                 // When the key was stored
    FILETIME ftExpires;                 // When the key expires
    WCHAR wszContainerName[256];        // Container name
    WCHAR wszUserName[256];             // Associated username
    DWORD cbPrivateKey;                 // Size of private key blob
    DWORD cbCertificate;                // Size of certificate blob
    BYTE rgbData[1];                    // Variable: PrivateKey followed by Certificate
} AUTHENTIK_KEY_ENTRY, *PAUTHENTIK_KEY_ENTRY;

typedef struct _AUTHENTIK_KEY_STORE_HEADER {
    DWORD dwMagic;                      // Must be AUTHENTIK_KEY_MAGIC
    DWORD dwVersion;                    // Version number
    DWORD cKeys;                        // Number of keys in store
    DWORD cbTotalSize;                  // Total size used
    AUTHENTIK_KEY_ENTRY entries[1];     // Variable array of entries
} AUTHENTIK_KEY_STORE_HEADER, *PAUTHENTIK_KEY_STORE_HEADER;
#pragma pack(pop)

// Internal key handle structure
typedef struct _AUTHENTIK_KEY {
    DWORD dwMagic;                      // Validation magic
    NCRYPT_PROV_HANDLE hProvider;       // Parent provider
    std::wstring containerName;         // Key container name
    std::wstring userName;              // Associated user
    DWORD dwKeySpec;                    // Key specification
    DWORD dwFlags;                      // Key flags
    std::vector<BYTE> privateKeyBlob;   // BCRYPT_RSAKEY_BLOB
    std::vector<BYTE> certificateBlob;  // DER-encoded certificate
    BCRYPT_KEY_HANDLE hBCryptKey;       // BCrypt key handle for operations
} AUTHENTIK_KEY, *PAUTHENTIK_KEY;

// Internal provider handle structure
typedef struct _AUTHENTIK_PROVIDER {
    DWORD dwMagic;                      // Validation magic
    DWORD dwFlags;                      // Provider flags
    std::map<std::wstring, PAUTHENTIK_KEY> keys;  // Opened keys
} AUTHENTIK_PROVIDER, *PAUTHENTIK_PROVIDER;

// Magic values for handle validation
#define AUTHENTIK_PROVIDER_MAGIC 0x50565250  // "PRVP"
#define AUTHENTIK_KEY_HANDLE_MAGIC 0x4B455948  // "KEYH"

// ============================================================================
// KSP Function Table
// ============================================================================

// Required KSP functions
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

// Additional functions for V2 interface
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

// ============================================================================
// Helper functions for credential provider integration
// ============================================================================

// Store a key in the shared memory for KSP to use
HRESULT AuthentikKSP_StoreKey(
    _In_ LPCWSTR wszContainerName,
    _In_ LPCWSTR wszUserName,
    _In_reads_bytes_(cbPrivateKey) const BYTE* pbPrivateKey,
    _In_ DWORD cbPrivateKey,
    _In_reads_bytes_(cbCertificate) const BYTE* pbCertificate,
    _In_ DWORD cbCertificate,
    _In_ DWORD dwKeySpec,
    _In_ DWORD dwValidityMinutes);

// Remove a key from shared memory
HRESULT AuthentikKSP_RemoveKey(
    _In_ LPCWSTR wszContainerName);

// Check if a key exists
BOOL AuthentikKSP_KeyExists(
    _In_ LPCWSTR wszContainerName);

// Get the KSP name for use in KERB_SMARTCARD_CSP_INFO
LPCWSTR AuthentikKSP_GetProviderName();

#endif // AUTHENTIK_KSP_H
