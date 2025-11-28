// AuthentikKSP.cpp
#include "AuthentikKSP.h"
#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")

static long g_cRef = 0;
static CRITICAL_SECTION g_cs;
static BOOL g_bInit = FALSE;
static PAUTHENTIK_KEY g_pKey = NULL;
static BCRYPT_ALG_HANDLE g_hAlg = NULL;

static void Log(const char* msg) { 
    char buf[512]; 
    _snprintf_s(buf, 512, "[AuthentikKSP] %s\n", msg); 
    OutputDebugStringA(buf); 
}

static BOOL ValidProvider(NCRYPT_PROV_HANDLE h) {
    if (!h) return FALSE;
    PAUTHENTIK_PROVIDER p = (PAUTHENTIK_PROVIDER)h;
    return (p->dwMagic == AUTHENTIK_PROVIDER_MAGIC);
}

static BOOL ValidKey(NCRYPT_KEY_HANDLE h) {
    if (!h) return FALSE;
    PAUTHENTIK_KEY k = (PAUTHENTIK_KEY)h;
    return (k->dwMagic == AUTHENTIK_KEY_MAGIC);
}

SECURITY_STATUS WINAPI KSPOpenProvider(NCRYPT_PROV_HANDLE *ph, LPCWSTR name, DWORD flags) {
    Log("OpenProvider");
    if (!ph) return NTE_INVALID_PARAMETER;
    PAUTHENTIK_PROVIDER p = (PAUTHENTIK_PROVIDER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(AUTHENTIK_PROVIDER));
    if (!p) return NTE_NO_MEMORY;
    p->dwMagic = AUTHENTIK_PROVIDER_MAGIC;
    p->hMutex = OpenMutexW(SYNCHRONIZE, FALSE, AUTHENTIK_MUTEX_NAME);
    if (p->hMutex) {
        p->hSharedMemory = OpenFileMappingW(FILE_MAP_READ|FILE_MAP_WRITE, FALSE, AUTHENTIK_SHARED_MEMORY_NAME);
        if (p->hSharedMemory)
            p->pSharedData = (PAUTHENTIK_SHARED_DATA)MapViewOfFile(p->hSharedMemory, FILE_MAP_READ|FILE_MAP_WRITE, 0, 0, sizeof(AUTHENTIK_SHARED_DATA));
    }
    InterlockedIncrement(&g_cRef);
    *ph = (NCRYPT_PROV_HANDLE)p;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPFreeProvider(NCRYPT_PROV_HANDLE h) {
    Log("FreeProvider");
    if (!ValidProvider(h)) return NTE_INVALID_HANDLE;
    PAUTHENTIK_PROVIDER p = (PAUTHENTIK_PROVIDER)h;
    if (p->pSharedData) UnmapViewOfFile(p->pSharedData);
    if (p->hSharedMemory) CloseHandle(p->hSharedMemory);
    if (p->hMutex) CloseHandle(p->hMutex);
    HeapFree(GetProcessHeap(), 0, p);
    InterlockedDecrement(&g_cRef);
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPOpenKey(NCRYPT_PROV_HANDLE hProv, NCRYPT_KEY_HANDLE *phKey, LPCWSTR name, DWORD spec, DWORD flags) {
    Log("OpenKey");
    if (!ValidProvider(hProv) || !phKey) return NTE_INVALID_PARAMETER;
    PAUTHENTIK_PROVIDER prov = (PAUTHENTIK_PROVIDER)hProv;
    
    EnterCriticalSection(&g_cs);
    if (g_pKey) { *phKey = (NCRYPT_KEY_HANDLE)g_pKey; LeaveCriticalSection(&g_cs); return ERROR_SUCCESS; }
    
    if (prov->pSharedData && prov->pSharedData->dwMagic == AUTHENTIK_SHARED_MAGIC && prov->pSharedData->bDataReady && !prov->pSharedData->bDataConsumed) {
        PAUTHENTIK_KEY k = (PAUTHENTIK_KEY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(AUTHENTIK_KEY));
        if (k) {
            k->dwMagic = AUTHENTIK_KEY_MAGIC;
            wcscpy_s(k->wszUsername, MAX_USERNAME_SIZE, prov->pSharedData->wszUsername);
            _snwprintf_s(k->wszKeyName, 256, L"AUTHENTIK_%s", prov->pSharedData->wszUsername);
            if (prov->pSharedData->cbCertificate > 0) {
                k->cbCertificate = prov->pSharedData->cbCertificate;
                k->pbCertificate = (PBYTE)HeapAlloc(GetProcessHeap(), 0, k->cbCertificate);
                if (k->pbCertificate) CopyMemory(k->pbCertificate, prov->pSharedData->rgbCertificate, k->cbCertificate);
            }
            if (prov->pSharedData->cbPrivateKey > 0) {
                k->cbPrivateKeyBlob = prov->pSharedData->cbPrivateKey;
                k->pbPrivateKeyBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, k->cbPrivateKeyBlob);
                if (k->pbPrivateKeyBlob) {
                    CopyMemory(k->pbPrivateKeyBlob, prov->pSharedData->rgbPrivateKey, k->cbPrivateKeyBlob);
                    if (!g_hAlg) BCryptOpenAlgorithmProvider(&g_hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
                    if (g_hAlg) BCryptImportKeyPair(g_hAlg, NULL, BCRYPT_RSAPRIVATE_BLOB, &k->hBcryptKey, k->pbPrivateKeyBlob, k->cbPrivateKeyBlob, 0);
                }
            }
            prov->pSharedData->bDataConsumed = TRUE;
            g_pKey = k;
            *phKey = (NCRYPT_KEY_HANDLE)k;
            LeaveCriticalSection(&g_cs);
            return ERROR_SUCCESS;
        }
    }
    LeaveCriticalSection(&g_cs);
    return NTE_BAD_KEYSET;
}

SECURITY_STATUS WINAPI KSPCreatePersistedKey(NCRYPT_PROV_HANDLE h, NCRYPT_KEY_HANDLE *pk, LPCWSTR alg, LPCWSTR name, DWORD spec, DWORD flags) { return NTE_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI KSPFinalizeKey(NCRYPT_PROV_HANDLE h, NCRYPT_KEY_HANDLE k, DWORD f) { return ERROR_SUCCESS; }
SECURITY_STATUS WINAPI KSPDeleteKey(NCRYPT_PROV_HANDLE h, NCRYPT_KEY_HANDLE k, DWORD f) { return ERROR_SUCCESS; }
SECURITY_STATUS WINAPI KSPFreeKey(NCRYPT_PROV_HANDLE h, NCRYPT_KEY_HANDLE k) { return ERROR_SUCCESS; }

SECURITY_STATUS WINAPI KSPGetProviderProperty(NCRYPT_PROV_HANDLE h, LPCWSTR prop, PBYTE out, DWORD cbOut, DWORD *pcb, DWORD flags) {
    if (!ValidProvider(h) || !prop || !pcb) return NTE_INVALID_PARAMETER;
    if (wcscmp(prop, NCRYPT_NAME_PROPERTY) == 0) {
        *pcb = (DWORD)((wcslen(AUTHENTIK_KSP_NAME)+1)*sizeof(WCHAR));
        if (!out) return ERROR_SUCCESS;
        if (cbOut < *pcb) return NTE_BUFFER_TOO_SMALL;
        wcscpy_s((LPWSTR)out, cbOut/sizeof(WCHAR), AUTHENTIK_KSP_NAME);
        return ERROR_SUCCESS;
    }
    if (wcscmp(prop, NCRYPT_IMPL_TYPE_PROPERTY) == 0) {
        *pcb = sizeof(DWORD);
        if (!out) return ERROR_SUCCESS;
        if (cbOut < sizeof(DWORD)) return NTE_BUFFER_TOO_SMALL;
        *(DWORD*)out = NCRYPT_IMPL_SOFTWARE_FLAG;
        return ERROR_SUCCESS;
    }
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPGetKeyProperty(NCRYPT_PROV_HANDLE hProv, NCRYPT_KEY_HANDLE hKey, LPCWSTR prop, PBYTE out, DWORD cbOut, DWORD *pcb, DWORD flags) {
    if (!ValidKey(hKey) || !prop || !pcb) return NTE_INVALID_PARAMETER;
    PAUTHENTIK_KEY k = (PAUTHENTIK_KEY)hKey;
    if (wcscmp(prop, NCRYPT_CERTIFICATE_PROPERTY) == 0) {
        *pcb = k->cbCertificate;
        if (!out) return ERROR_SUCCESS;
        if (cbOut < k->cbCertificate) return NTE_BUFFER_TOO_SMALL;
        if (k->pbCertificate) CopyMemory(out, k->pbCertificate, k->cbCertificate);
        return ERROR_SUCCESS;
    }
    if (wcscmp(prop, NCRYPT_NAME_PROPERTY) == 0) {
        *pcb = (DWORD)((wcslen(k->wszKeyName)+1)*sizeof(WCHAR));
        if (!out) return ERROR_SUCCESS;
        if (cbOut < *pcb) return NTE_BUFFER_TOO_SMALL;
        wcscpy_s((LPWSTR)out, cbOut/sizeof(WCHAR), k->wszKeyName);
        return ERROR_SUCCESS;
    }
    if (wcscmp(prop, NCRYPT_LENGTH_PROPERTY) == 0) {
        *pcb = sizeof(DWORD); if (!out) return ERROR_SUCCESS;
        if (cbOut < sizeof(DWORD)) return NTE_BUFFER_TOO_SMALL;
        *(DWORD*)out = 2048; return ERROR_SUCCESS;
    }
    if (wcscmp(prop, NCRYPT_ALGORITHM_PROPERTY) == 0) {
        *pcb = (DWORD)((wcslen(BCRYPT_RSA_ALGORITHM)+1)*sizeof(WCHAR));
        if (!out) return ERROR_SUCCESS;
        if (cbOut < *pcb) return NTE_BUFFER_TOO_SMALL;
        wcscpy_s((LPWSTR)out, cbOut/sizeof(WCHAR), BCRYPT_RSA_ALGORITHM);
        return ERROR_SUCCESS;
    }
    if (wcscmp(prop, NCRYPT_KEY_USAGE_PROPERTY) == 0) {
        *pcb = sizeof(DWORD); if (!out) return ERROR_SUCCESS;
        if (cbOut < sizeof(DWORD)) return NTE_BUFFER_TOO_SMALL;
        *(DWORD*)out = NCRYPT_ALLOW_SIGNING_FLAG | NCRYPT_ALLOW_DECRYPT_FLAG;
        return ERROR_SUCCESS;
    }
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPSetProviderProperty(NCRYPT_PROV_HANDLE h, LPCWSTR p, PBYTE in, DWORD cb, DWORD f) { return NTE_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI KSPSetKeyProperty(NCRYPT_PROV_HANDLE h, NCRYPT_KEY_HANDLE k, LPCWSTR p, PBYTE in, DWORD cb, DWORD f) { return NTE_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI KSPEncrypt(NCRYPT_PROV_HANDLE h, NCRYPT_KEY_HANDLE k, PBYTE in, DWORD cbIn, VOID *pad, PBYTE out, DWORD cbOut, DWORD *pcb, DWORD f) { return NTE_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI KSPDecrypt(NCRYPT_PROV_HANDLE h, NCRYPT_KEY_HANDLE k, PBYTE in, DWORD cbIn, VOID *pad, PBYTE out, DWORD cbOut, DWORD *pcb, DWORD f) { return NTE_NOT_SUPPORTED; }

SECURITY_STATUS WINAPI KSPSignHash(NCRYPT_PROV_HANDLE hProv, NCRYPT_KEY_HANDLE hKey, VOID *pad, PBYTE hash, DWORD cbHash, PBYTE sig, DWORD cbSig, DWORD *pcb, DWORD flags) {
    Log("SignHash");
    if (!ValidKey(hKey) || !hash || !pcb) return NTE_INVALID_PARAMETER;
    PAUTHENTIK_KEY k = (PAUTHENTIK_KEY)hKey;
    if (!k->hBcryptKey) return NTE_BAD_KEY;
    ULONG cb = 0;
    NTSTATUS st = BCryptSignHash(k->hBcryptKey, pad, hash, cbHash, sig, cbSig, &cb, flags);
    *pcb = cb;
    return NT_SUCCESS(st) ? ERROR_SUCCESS : NTE_INTERNAL_ERROR;
}

SECURITY_STATUS WINAPI KSPVerifySignature(NCRYPT_PROV_HANDLE h, NCRYPT_KEY_HANDLE k, VOID *pad, PBYTE hash, DWORD cbHash, PBYTE sig, DWORD cbSig, DWORD f) { return NTE_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI KSPIsAlgSupported(NCRYPT_PROV_HANDLE h, LPCWSTR alg, DWORD f) { return (alg && wcscmp(alg, BCRYPT_RSA_ALGORITHM)==0) ? ERROR_SUCCESS : NTE_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI KSPEnumAlgorithms(NCRYPT_PROV_HANDLE h, DWORD ops, DWORD *cnt, NCryptAlgorithmName **list, DWORD f) { if(cnt) *cnt=0; return NTE_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI KSPEnumKeys(NCRYPT_PROV_HANDLE h, LPCWSTR scope, NCryptKeyName **name, PVOID *state, DWORD f) { return NTE_NO_MORE_ITEMS; }
SECURITY_STATUS WINAPI KSPImportKey(NCRYPT_PROV_HANDLE h, NCRYPT_KEY_HANDLE ik, LPCWSTR type, NCryptBufferDesc *params, NCRYPT_KEY_HANDLE *pk, PBYTE data, DWORD cb, DWORD f) { return NTE_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI KSPExportKey(NCRYPT_PROV_HANDLE h, NCRYPT_KEY_HANDLE k, NCRYPT_KEY_HANDLE ek, LPCWSTR type, NCryptBufferDesc *params, PBYTE out, DWORD cbOut, DWORD *pcb, DWORD f) { return NTE_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI KSPFreeBuffer(PVOID p) { if(p) HeapFree(GetProcessHeap(),0,p); return ERROR_SUCCESS; }
SECURITY_STATUS WINAPI KSPNotifyChangeKey(NCRYPT_PROV_HANDLE h, HANDLE *ev, DWORD f) { return NTE_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI KSPSecretAgreement(NCRYPT_PROV_HANDLE h, NCRYPT_KEY_HANDLE priv, NCRYPT_KEY_HANDLE pub, NCRYPT_SECRET_HANDLE *sec, DWORD f) { return NTE_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI KSPDeriveKey(NCRYPT_PROV_HANDLE h, NCRYPT_SECRET_HANDLE sec, LPCWSTR kdf, NCryptBufferDesc *params, PBYTE key, DWORD cbKey, DWORD *pcb, ULONG f) { return NTE_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI KSPFreeSecret(NCRYPT_PROV_HANDLE h, NCRYPT_SECRET_HANDLE sec) { return NTE_NOT_SUPPORTED; }

// Function table with correct layout
typedef struct _KSP_FUNCTION_TABLE {
    ULONG_PTR Version;  // Must be pointer-sized for alignment
    void* OpenProvider;
    void* OpenKey;
    void* CreatePersistedKey;
    void* GetProviderProperty;
    void* GetKeyProperty;
    void* SetProviderProperty;
    void* SetKeyProperty;
    void* FinalizeKey;
    void* DeleteKey;
    void* FreeProvider;
    void* FreeKey;
    void* FreeBuffer;
    void* Encrypt;
    void* Decrypt;
    void* IsAlgSupported;
    void* EnumAlgorithms;
    void* EnumKeys;
    void* ImportKey;
    void* ExportKey;
    void* SignHash;
    void* VerifySignature;
    void* PromptUser;
    void* NotifyChangeKey;
    void* SecretAgreement;
    void* DeriveKey;
    void* FreeSecret;
} KSP_FUNCTION_TABLE;

static KSP_FUNCTION_TABLE g_FunctionTable = {0};

NTSTATUS WINAPI GetKeyStorageInterface(LPCWSTR pszProviderName, void **ppFunctionTable, DWORD dwFlags) {
    Log("GetKeyStorageInterface");
    if (!g_bInit) { InitializeCriticalSection(&g_cs); g_bInit = TRUE; }
    if (!ppFunctionTable) return STATUS_INVALID_PARAMETER;
    
    g_FunctionTable.Version = sizeof(KSP_FUNCTION_TABLE);  // cbSize, not version
    g_FunctionTable.OpenProvider = (void*)KSPOpenProvider;
    g_FunctionTable.OpenKey = (void*)KSPOpenKey;
    g_FunctionTable.CreatePersistedKey = (void*)KSPCreatePersistedKey;
    g_FunctionTable.GetProviderProperty = (void*)KSPGetProviderProperty;
    g_FunctionTable.GetKeyProperty = (void*)KSPGetKeyProperty;
    g_FunctionTable.SetProviderProperty = (void*)KSPSetProviderProperty;
    g_FunctionTable.SetKeyProperty = (void*)KSPSetKeyProperty;
    g_FunctionTable.FinalizeKey = (void*)KSPFinalizeKey;
    g_FunctionTable.DeleteKey = (void*)KSPDeleteKey;
    g_FunctionTable.FreeProvider = (void*)KSPFreeProvider;
    g_FunctionTable.FreeKey = (void*)KSPFreeKey;
    g_FunctionTable.FreeBuffer = (void*)KSPFreeBuffer;
    g_FunctionTable.Encrypt = (void*)KSPEncrypt;
    g_FunctionTable.Decrypt = (void*)KSPDecrypt;
    g_FunctionTable.IsAlgSupported = (void*)KSPIsAlgSupported;
    g_FunctionTable.EnumAlgorithms = (void*)KSPEnumAlgorithms;
    g_FunctionTable.EnumKeys = (void*)KSPEnumKeys;
    g_FunctionTable.ImportKey = (void*)KSPImportKey;
    g_FunctionTable.ExportKey = (void*)KSPExportKey;
    g_FunctionTable.SignHash = (void*)KSPSignHash;
    g_FunctionTable.VerifySignature = (void*)KSPVerifySignature;
    g_FunctionTable.PromptUser = NULL;
    g_FunctionTable.NotifyChangeKey = (void*)KSPNotifyChangeKey;
    g_FunctionTable.SecretAgreement = (void*)KSPSecretAgreement;
    g_FunctionTable.DeriveKey = (void*)KSPDeriveKey;
    g_FunctionTable.FreeSecret = (void*)KSPFreeSecret;
    
    *ppFunctionTable = &g_FunctionTable;
    return STATUS_SUCCESS;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(hModule); Log("ATTACH"); }
    if (reason == DLL_PROCESS_DETACH) { 
        Log("DETACH");
        if (g_hAlg) BCryptCloseAlgorithmProvider(g_hAlg, 0);
        if (g_bInit) DeleteCriticalSection(&g_cs);
    }
    return TRUE;
}
