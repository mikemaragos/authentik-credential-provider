// AuthentikKSP.h
// Authentik Key Storage Provider - Header

#pragma once

#ifndef UMDF_USING_NTSTATUS
#define UMDF_USING_NTSTATUS
#endif

#include <windows.h>
#include <ntstatus.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <wincrypt.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// KSP Provider Name
#define AUTHENTIK_KSP_NAME L"Authentik Key Storage Provider"
#define AUTHENTIK_KEY_PREFIX L"AUTHENTIK_"

// Shared memory names
#define AUTHENTIK_SHARED_MEMORY_NAME L"Global\\AuthentikKSPSharedMemory"
#define AUTHENTIK_MUTEX_NAME L"Global\\AuthentikKSPMutex"

// Maximum sizes
#define MAX_CERTIFICATE_SIZE 8192
#define MAX_PRIVATE_KEY_SIZE 4096
#define MAX_USERNAME_SIZE 256

// Shared memory structure
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

// Key handle structure
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

// Provider handle structure
typedef struct _AUTHENTIK_PROVIDER {
    DWORD dwMagic;
    HANDLE hSharedMemory;
    HANDLE hMutex;
    PAUTHENTIK_SHARED_DATA pSharedData;
} AUTHENTIK_PROVIDER, *PAUTHENTIK_PROVIDER;

#define AUTHENTIK_PROVIDER_MAGIC 0x50525621

// KSP Function table - use void* to avoid type conflicts
typedef struct _AUTHENTIK_FUNCTION_TABLE {
    DWORD Version;
    void* pfnOpenProvider;
    void* pfnOpenKey;
    void* pfnCreatePersistedKey;
    void* pfnGetProviderProperty;
    void* pfnGetKeyProperty;
    void* pfnSetProviderProperty;
    void* pfnSetKeyProperty;
    void* pfnFinalizeKey;
    void* pfnDeleteKey;
    void* pfnFreeProvider;
    void* pfnFreeKey;
    void* pfnFreeBuffer;
    void* pfnEncrypt;
    void* pfnDecrypt;
    void* pfnIsAlgSupported;
    void* pfnEnumAlgorithms;
    void* pfnEnumKeys;
    void* pfnImportKey;
    void* pfnExportKey;
    void* pfnSignHash;
    void* pfnVerifySignature;
    void* pfnPromptUser;
    void* pfnNotifyChangeKey;
    void* pfnSecretAgreement;
    void* pfnDeriveKey;
    void* pfnFreeSecret;
} AUTHENTIK_FUNCTION_TABLE;

#ifndef NCRYPT_KEY_STORAGE_INTERFACE_VERSION
#define NCRYPT_KEY_STORAGE_INTERFACE_VERSION 0x00010000
#endif

#ifdef __cplusplus
extern "C" {
#endif

// KSP Functions
SECURITY_STATUS WINAPI KSPOpenProvider(NCRYPT_PROV_HANDLE *phProvider, LPCWSTR pszProviderName, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPFreeProvider(NCRYPT_PROV_HANDLE hProvider);
SECURITY_STATUS WINAPI KSPOpenKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE *phKey, LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPCreatePersistedKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE *phKey, LPCWSTR pszAlgId, LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPFinalizeKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPDeleteKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPFreeKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey);
SECURITY_STATUS WINAPI KSPGetProviderProperty(NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszProperty, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPGetKeyProperty(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, LPCWSTR pszProperty, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPSetProviderProperty(NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszProperty, PBYTE pbInput, DWORD cbInput, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPSetKeyProperty(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, LPCWSTR pszProperty, PBYTE pbInput, DWORD cbInput, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPEncrypt(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, PBYTE pbInput, DWORD cbInput, VOID *pPaddingInfo, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPDecrypt(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, PBYTE pbInput, DWORD cbInput, VOID *pPaddingInfo, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPSignHash(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, VOID *pPaddingInfo, PBYTE pbHashValue, DWORD cbHashValue, PBYTE pbSignature, DWORD cbSignature, DWORD *pcbResult, DWORD dwFlags);
SECURITY_STATUS WINAPI KSPVerifySignature(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, VOID *pPaddingInfo, PBYTE pbHashValue, DWORD cbHashValue, PBYTE pbSignature, DWORD cbSignature, DWORD dwFlags);
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
NTSTATUS WINAPI GetKeyStorageInterface(LPCWSTR pszProviderName, AUTHENTIK_FUNCTION_TABLE **ppFunctionTable, DWORD dwFlags);

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
