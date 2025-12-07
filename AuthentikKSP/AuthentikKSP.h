// AuthentikKSP.h
// Authentik Key Storage Provider - OTP-based certificate unlock
//
// This KSP intercepts PIN verification and validates OTP with Authentik
// instead of checking a traditional PIN.

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>

// C++ headers
#include <string>
#include <new>

// KSP Provider name
#define AUTHENTIK_KSP_PROVIDER_NAME L"Authentik Key Storage Provider"

// Magic values for validation
#define AUTHENTIK_PROVIDER_MAGIC    0x41555448  // "AUTH"
#define AUTHENTIK_KEY_MAGIC         0x414B4559  // "AKEY"

// Forward declarations
typedef struct _AUTHENTIK_PROVIDER AUTHENTIK_PROVIDER;
typedef struct _AUTHENTIK_KEY AUTHENTIK_KEY;

// Provider context structure
typedef struct _AUTHENTIK_PROVIDER {
    DWORD cbLength;                      // Structure size
    DWORD dwMagic;                       // AUTHENTIK_PROVIDER_MAGIC
    NCRYPT_PROV_HANDLE hBaseProvider;    // Handle to underlying MS Software KSP
    std::wstring authentikUrl;           // Authentik server URL
    DWORD authentikPort;                 // Authentik port
    std::wstring flowSlug;               // Authentication flow slug
    BOOL useHttps;                       // Use HTTPS
} AUTHENTIK_PROVIDER;

// Key context structure
typedef struct _AUTHENTIK_KEY {
    DWORD cbLength;                      // Structure size
    DWORD dwMagic;                       // AUTHENTIK_KEY_MAGIC
    AUTHENTIK_PROVIDER* pProvider;       // Back-pointer to provider
    NCRYPT_KEY_HANDLE hBaseKey;          // Handle to underlying key
    std::wstring keyName;                // Key container name
    std::wstring username;               // UPN extracted from certificate
    std::wstring currentOtp;             // OTP passed as "PIN"
    BOOL otpValidated;                   // Has OTP been validated this session?
} AUTHENTIK_KEY;

// ============================================================================
// KSP Function Prototypes (must match NCRYPT_KEY_STORAGE_FUNCTION_TABLE)
// ============================================================================

SECURITY_STATUS WINAPI KSPOpenProvider(
    __out   NCRYPT_PROV_HANDLE *phProvider,
    __in    LPCWSTR pszProviderName,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPFreeProvider(
    __in    NCRYPT_PROV_HANDLE hProvider);

SECURITY_STATUS WINAPI KSPOpenKey(
    __inout NCRYPT_PROV_HANDLE hProvider,
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

SECURITY_STATUS WINAPI KSPGetProviderProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __out   PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPGetKeyProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __out   PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPSetProviderProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __in    PBYTE pbInput,
    __in    DWORD cbInput,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPSetKeyProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __in    PBYTE pbInput,
    __in    DWORD cbInput,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPFinalizeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPDeleteKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout NCRYPT_KEY_HANDLE hKey,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPFreeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey);

SECURITY_STATUS WINAPI KSPFreeBuffer(
    __in    PVOID pvInput);

SECURITY_STATUS WINAPI KSPEncrypt(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    PBYTE pbInput,
    __in    DWORD cbInput,
    __in    VOID *pPaddingInfo,
    __out   PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPDecrypt(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    PBYTE pbInput,
    __in    DWORD cbInput,
    __in    VOID *pPaddingInfo,
    __out   PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags);

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
    __in    PBYTE pbData,
    __in    DWORD cbData,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPExportKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt NCRYPT_KEY_HANDLE hExportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out   PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags);

// ============================================================================
// KEY FUNCTION: SignHash - This is where OTP validation happens!
// ============================================================================
SECURITY_STATUS WINAPI KSPSignHash(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt VOID *pPaddingInfo,
    __in    PBYTE pbHashValue,
    __in    DWORD cbHashValue,
    __out   PBYTE pbSignature,
    __in    DWORD cbSignature,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPVerifySignature(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt VOID *pPaddingInfo,
    __in    PBYTE pbHashValue,
    __in    DWORD cbHashValue,
    __in    PBYTE pbSignature,
    __in    DWORD cbSignature,
    __in    DWORD dwFlags);

SECURITY_STATUS WINAPI KSPPromptUser(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszOperation,
    __in    DWORD dwFlags);

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
    __out   PBYTE pbDerivedKey,
    __in    DWORD cbDerivedKey,
    __out   DWORD *pcbResult,
    __in    ULONG dwFlags);

SECURITY_STATUS WINAPI KSPFreeSecret(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_SECRET_HANDLE hSharedSecret);

// ============================================================================
// Helper Functions
// ============================================================================

// Validate OTP with Authentik server
BOOL ValidateOTPWithAuthentik(
    __in    AUTHENTIK_PROVIDER* pProvider,
    __in    LPCWSTR pszUsername,
    __in    LPCWSTR pszOtp);

// Load configuration from registry
HRESULT LoadConfiguration(
    __out   AUTHENTIK_PROVIDER* pProvider);

// Validate provider handle
BOOL IsValidProviderHandle(
    __in    NCRYPT_PROV_HANDLE hProvider);

// Validate key handle  
BOOL IsValidKeyHandle(
    __in    NCRYPT_KEY_HANDLE hKey);

// Extract UPN from certificate
HRESULT ExtractUPNFromKey(
    __in    NCRYPT_KEY_HANDLE hKey,
    __out   std::wstring& upn);

// ============================================================================
// DLL Exports
// ============================================================================

// Get the KSP function table
NTSTATUS WINAPI GetKeyStorageInterface(
    __in    LPCWSTR pszProviderName,
    __out   NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable,
    __in    DWORD dwFlags);

// Registration functions
NTSTATUS RegisterProvider();
NTSTATUS UnregisterProvider();
