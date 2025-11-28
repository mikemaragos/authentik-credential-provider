// AuthentikKSP.h
#pragma once

#define UMDF_USING_NTSTATUS
#include <windows.h>
#include <ntstatus.h>
#include <ncrypt.h>
#include <bcrypt.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define AUTHENTIK_KSP_NAME L"Authentik Key Storage Provider"
#define AUTHENTIK_SHARED_MEMORY_NAME L"Global\\AuthentikKSPSharedMemory"
#define AUTHENTIK_MUTEX_NAME L"Global\\AuthentikKSPMutex"
#define MAX_CERTIFICATE_SIZE 8192
#define MAX_PRIVATE_KEY_SIZE 4096
#define MAX_USERNAME_SIZE 256
#define AUTHENTIK_SHARED_MAGIC 0x41555448
#define AUTHENTIK_KEY_MAGIC 0x4B455921
#define AUTHENTIK_PROVIDER_MAGIC 0x50525621

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
} AUTHENTIK_KEY, *PAUTHENTIK_KEY;

typedef struct _AUTHENTIK_PROVIDER {
    DWORD dwMagic;
    HANDLE hSharedMemory;
    HANDLE hMutex;
    PAUTHENTIK_SHARED_DATA pSharedData;
} AUTHENTIK_PROVIDER, *PAUTHENTIK_PROVIDER;

#ifdef __cplusplus
extern "C" {
#endif

NTSTATUS WINAPI GetKeyStorageInterface(LPCWSTR pszProviderName, void **ppFunctionTable, DWORD dwFlags);

#ifdef __cplusplus
}
#endif
