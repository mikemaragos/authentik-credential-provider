// AuthentikKSP.h
// Authentik Key Storage Provider - Header
// Provides certificate-based authentication for PKINIT

#pragma once

#define WIN32_LEAN_AND_MEAN
#define UMDF_USING_NTSTATUS

#include <windows.h>
#include <ntstatus.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <wincrypt.h>

// NT_SUCCESS macro if not defined
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

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
    DWORD dwMagic;
    DWORD dwVersion;
    BOOL bDataReady;
    BOOL bDataConsumed;
    WCHAR wszUsername[MAX_USERNAME_SIZE];
    DWORD cbCertificate;
    BYTE rgbCertificate[MAX_CERTIFICATE_SIZE];
    DWORD cbPrivateKey;
    BYTE rgbPrivateKey[MAX_PRIVATE_KEY_SIZE];
    DWORD dwKeySpec;
    DWORD dwError;
} AUTHENTIK_SHARED_DATA, *PAUTHENTIK_SHARED_DATA;
#pragma pack(pop)

#define AUTHENTIK_SHARED_MAGIC 0x41555448

// Internal key handle structure
typedef struct _AUTHENTIK_KEY {
    DWORD dwMagic;
    WCHAR wszKeyName[256];
    WCHAR wszUsername[MAX_USERNAME_SIZE];
    BCRYPT_KEY_HANDLE hBcryptKey;
    DWORD dwKeySpec;
    DWORD cbCertificate;
    PBYTE pbCertificate;
    DWORD cbPrivateKeyBlob;
    PBYTE pbPrivateKeyBlob;
    BOOL bFromSharedMemory;
} AUTHENTIK_KEY, *PAUTHENTIK_KEY;

#define AUTHENTIK_KEY_MAGIC 0x4B455921

// Internal provider handle structure
typedef struct _AUTHENTIK_PROVIDER {
    DWORD dwMagic;
    HANDLE hSharedMemory;
    HANDLE hMutex;
    PAUTHENTIK_SHARED_DATA pSharedData;
} AUTHENTIK_PROVIDER, *PAUTHENTIK_PROVIDER;

#define AUTHENTIK_PROVIDER_MAGIC 0x50525621

// Define the KSP function table structure
typedef struct _NCRYPT_KEY_STORAGE_FUNCTION_TABLE_V1 {
    DWORD Version;
    SECURITY_STATUS (WINAPI *OpenProvider)(NCRYPT_PROV_HANDLE*, LPCWSTR, DWORD);
    SECURITY_STATUS (WINAPI *OpenKey)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE*, LPCWSTR, DWORD, DWORD);
    SECURITY_STATUS (WINAPI *CreatePersistedKey)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE*, LPCWSTR, LPCWSTR, DWORD, DWORD);
    SECURITY_STATUS (WINAPI *GetProviderProperty)(NCRYPT_PROV_HANDLE, LPCWSTR, PBYTE, DWORD, DWORD*, DWORD);
    SECURITY_STATUS (WINAPI *GetKeyProperty)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, PBYTE, DWORD, DWORD*, DWORD);
    SECURITY_STATUS (WINAPI *SetProviderProperty)(NCRYPT_PROV_HANDLE, LPCWSTR, PBYTE, DWORD, DWORD);
    SECURITY_STATUS (WINAPI *SetKeyProperty)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, PBYTE, DWORD, DWORD);
    SECURITY_STATUS (WINAPI *FinalizeKey)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, DWORD);
    SECURITY_STATUS (WINAPI *DeleteKey)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, DWORD);
    SECURITY_STATUS (WINAPI *FreeProvider)(NCRYPT_PROV_HANDLE);
    SECURITY_STATUS (WINAPI *FreeKey)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE);
    SECURITY_STATUS (WINAPI *FreeBuffer)(PVOID);
    SECURITY_STATUS (WINAPI *Encrypt)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, PBYTE, DWORD, VOID*, PBYTE, DWORD, DWORD*, DWORD);
    SECURITY_STATUS (WINAPI *Decrypt)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, PBYTE, DWORD, VOID*, PBYTE, DWORD, DWORD*, DWORD);
    SECURITY_STATUS (WINAPI *IsAlgSupported)(NCRYPT_PROV_HANDLE, LPCWSTR, DWORD);
    SECURITY_STATUS (WINAPI *EnumAlgorithms)(NCRYPT_PROV_HANDLE, DWORD, DWORD*, NCryptAlgorithmName**, DWORD);
    SECURITY_STATUS (WINAPI *EnumKeys)(NCRYPT_PROV_HANDLE, LPCWSTR, NCryptKeyName**, PVOID*, DWORD);
    SECURITY_STATUS (WINAPI *ImportKey)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, NCryptBufferDesc*, NCRYPT_KEY_HANDLE*, PBYTE, DWORD, DWORD);
    SECURITY_STATUS (WINAPI *ExportKey)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, NCryptBufferDesc*, PBYTE, DWORD, DWORD*, DWORD);
    SECURITY_STATUS (WINAPI *SignHash)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, VOID*, PBYTE, DWORD, PBYTE, DWORD, DWORD*, DWORD);
    SECURITY_STATUS (WINAPI *VerifySignature)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, VOID*, PBYTE, DWORD, PBYTE, DWORD, DWORD);
    SECURITY_STATUS (WINAPI *PromptUser)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR, DWORD);
    SECURITY_STATUS (WINAPI *NotifyChangeKey)(NCRYPT_PROV_HANDLE, HANDLE*, DWORD);
    SECURITY_STATUS (WINAPI *SecretAgreement)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_SECRET_HANDLE*, DWORD);
    SECURITY_STATUS (WINAPI *DeriveKey)(NCRYPT_PROV_HANDLE, NCRYPT_SECRET_HANDLE, LPCWSTR, NCryptBufferDesc*, PBYTE, DWORD, DWORD*, ULONG);
    SECURITY_STATUS (WINAPI *FreeSecret)(NCRYPT_PROV_HANDLE, NCRYPT_SECRET_HANDLE);
} NCRYPT_KEY_STORAGE_FUNCTION_TABLE_V1;

// Use our own type name to avoid conflicts
typedef NCRYPT_KEY_STORAGE_FUNCTION_TABLE_V1 AUTHENTIK_KSP_FUNCTION_TABLE;

#ifndef NCRYPT_KEY_STORAGE_INTERFACE_VERSION
#define NCRYPT_KEY_STORAGE_INTERFACE_VERSION (0x00010000)
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Provider management
SECURITY_STATUS WINAPI KSPOpenProvider(NCRYPT_PROV_HANDLE *phProvider, LPCWSTR pszProviderName, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPFreeProvider(NCRYPT_PROV_HANDLE hProvider);

// Key management
SECURITY_STATUS WINAPI KSPOpenKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE *phKey, LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPCreatePersistedKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE *phKey, LPCWSTR pszAlgId, LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPFinalizeKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPDeleteKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPFreeKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey);

// Property management
SECURITY_STATUS WINAPI KSPGetProviderProperty(NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszProperty, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPGetKeyProperty(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, LPCWSTR pszProperty, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPSetProviderProperty(NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszProperty, PBYTE pbInput, DWORD cbInput, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPSetKeyProperty(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, LPCWSTR pszProperty, PBYTE pbInput, DWORD cbInput, DWORD dwFlags);

// Cryptographic operations
SECURITY_STATUS WINAPI KSPEncrypt(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, PBYTE pbInput, DWORD cbInput, VOID *pPaddingInfo, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPDecrypt(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, PBYTE pbInput, DWORD cbInput, VOID *pPaddingInfo, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPSignHash(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, VOID *pPaddingInfo, PBYTE pbHashValue, DWORD cbHashValue, PBYTE pbSignature, DWORD cbSignature, DWORD *pcbResult, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPVerifySignature(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, VOID *pPaddingInfo, PBYTE pbHashValue, DWORD cbHashValue, PBYTE pbSignature, DWORD cbSignature, DWORD dwFlags);

// Utility functions
SECURITY_STATUS WINAPI KSPIsAlgSupported(NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszAlgId, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPEnumAlgorithms(NCRYPT_PROV_HANDLE hProvider, DWORD dwAlgOperations, DWORD *pdwAlgCount, NCryptAlgorithmName **ppAlgList, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPEnumKeys(NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszScope, NCryptKeyName **ppKeyName, PVOID *ppEnumState, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPImportKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hImportKey, LPCWSTR pszBlobType, NCryptBufferDesc *pParameterList, NCRYPT_KEY_HANDLE *phKey, PBYTE pbData, DWORD cbData, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPExportKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, NCRYPT_KEY_HANDLE hExportKey, LPCWSTR pszBlobType, NCryptBufferDesc *pParameterList, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPFreeBuffer(PVOID pvInput);
SECURITY_STATUS WINAPI KSPNotifyChangeKey(NCRYPT_PROV_HANDLE hProvider, HANDLE *phEvent, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPSecretAgreement(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hPrivKey, NCRYPT_KEY_HANDLE hPubKey, NCRYPT_SECRET_HANDLE *phSecret, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPDeriveKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_SECRET_HANDLE hSharedSecret, LPCWSTR pwszKDF, NCryptBufferDesc *pParameterList, PBYTE pbDerivedKey, DWORD cbDerivedKey, DWORD *pcbResult, ULONG dwFlags);
SECURITY_STATUS WINAPI KSPFreeSecret(NCRYPT_PROV_HANDLE hProvider, NCRYPT_SECRET_HANDLE hSharedSecret);

// DLL entry point for function table
NTSTATUS WINAPI GetKeyStorageInterface(LPCWSTR pszProviderName, AUTHENTIK_KSP_FUNCTION_TABLE **ppFunctionTable, DWORD dwFlags);

#ifdef __cplusplus
}
#endif

// Helper functions
BOOL ValidateProviderHandle(NCRYPT_PROV_HANDLE hProvider);
BOOL ValidateKeyHandle(NCRYPT_KEY_HANDLE hKey);
PAUTHENTIK_KEY CreateKeyFromSharedMemory(PAUTHENTIK_PROVIDER pProvider);
void CleanupKey(PAUTHENTIK_KEY pKey);
void KSPLog(const char* format, ...);
void DllAddRef(void);
void DllRelease(void);
