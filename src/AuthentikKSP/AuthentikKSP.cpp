// AuthentikKSP.cpp
// ULTRA-MINIMAL BOOT-SAFE KSP
//
// Key insight: During boot, Windows only calls OpenProvider, not OpenKey.
// So we use a STATIC provider handle - no heap allocation during boot at all.
// All real work (shared memory, BCrypt, heap allocation) only happens during
// OpenKey, which is called during authentication (not boot).

#include "AuthentikKSP.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")

// ============================================================================
// STATIC Provider Handle - NO ALLOCATION DURING BOOT
// ============================================================================

static AUTHENTIK_PROVIDER g_StaticProvider = {
    AUTHENTIK_PROVIDER_MAGIC,
    0
};

// ============================================================================
// Global State - Initialized ONLY during OpenKey (authentication time)
// ============================================================================

static HANDLE g_hSharedMem = NULL;
static PAUTHENTIK_KEY_STORE_HEADER g_pKeyStore = NULL;
static HANDLE g_hMutex = NULL;
static BCRYPT_ALG_HANDLE g_hRsaAlg = NULL;
static volatile LONG g_bKeyStoreInit = 0;
static volatile LONG g_bRsaInit = 0;

// ============================================================================
// Deferred Init - ONLY called during authentication, never during boot
// ============================================================================

static BOOL InitKeyStore(void)
{
    if (g_pKeyStore) return TRUE;
    
    if (InterlockedCompareExchange(&g_bKeyStoreInit, 1, 0) != 0)
    {
        while (g_bKeyStoreInit == 1 && !g_pKeyStore) Sleep(1);
        return (g_pKeyStore != NULL);
    }

    g_hMutex = CreateMutexW(NULL, FALSE, L"Global\\AuthentikKSPMutex");
    if (!g_hMutex) g_hMutex = CreateMutexW(NULL, FALSE, L"Local\\AuthentikKSPMutex");
    if (!g_hMutex) { g_bKeyStoreInit = 0; return FALSE; }

    g_hSharedMem = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
        0, AUTHENTIK_SHARED_MEM_SIZE, L"Global\\AuthentikKSPKeyStore");
    if (!g_hSharedMem)
        g_hSharedMem = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
            0, AUTHENTIK_SHARED_MEM_SIZE, L"Local\\AuthentikKSPKeyStore");

    BOOL bNew = (GetLastError() != ERROR_ALREADY_EXISTS);
    if (!g_hSharedMem) { CloseHandle(g_hMutex); g_hMutex = NULL; g_bKeyStoreInit = 0; return FALSE; }

    g_pKeyStore = (PAUTHENTIK_KEY_STORE_HEADER)MapViewOfFile(g_hSharedMem, FILE_MAP_ALL_ACCESS, 0, 0, AUTHENTIK_SHARED_MEM_SIZE);
    if (!g_pKeyStore) { CloseHandle(g_hSharedMem); CloseHandle(g_hMutex); g_hSharedMem = NULL; g_hMutex = NULL; g_bKeyStoreInit = 0; return FALSE; }

    if (bNew)
    {
        WaitForSingleObject(g_hMutex, 5000);
        g_pKeyStore->dwMagic = AUTHENTIK_KEY_MAGIC;
        g_pKeyStore->dwVersion = 1;
        g_pKeyStore->cKeys = 0;
        g_pKeyStore->cbTotalSize = sizeof(AUTHENTIK_KEY_STORE_HEADER);
        ReleaseMutex(g_hMutex);
    }

    g_bKeyStoreInit = 2;
    return TRUE;
}

static BOOL InitRsa(void)
{
    if (g_hRsaAlg) return TRUE;
    if (InterlockedCompareExchange(&g_bRsaInit, 1, 0) != 0)
    {
        while (g_bRsaInit == 1 && !g_hRsaAlg) Sleep(1);
        return (g_hRsaAlg != NULL);
    }
    NTSTATUS s = BCryptOpenAlgorithmProvider(&g_hRsaAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(s)) { g_bRsaInit = 0; return FALSE; }
    g_bRsaInit = 2;
    return TRUE;
}

// ============================================================================
// Helpers
// ============================================================================

static PAUTHENTIK_KEY_ENTRY FindKey(LPCWSTR name)
{
    if (!g_pKeyStore || !name || !g_hMutex) return NULL;
    WaitForSingleObject(g_hMutex, 5000);

    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER now; now.LowPart = ft.dwLowDateTime; now.HighPart = ft.dwHighDateTime;

    PBYTE p = (PBYTE)g_pKeyStore + sizeof(AUTHENTIK_KEY_STORE_HEADER);
    PBYTE end = (PBYTE)g_pKeyStore + g_pKeyStore->cbTotalSize;
    PAUTHENTIK_KEY_ENTRY found = NULL;

    for (DWORD i = 0; i < g_pKeyStore->cKeys && p < end; i++)
    {
        PAUTHENTIK_KEY_ENTRY e = (PAUTHENTIK_KEY_ENTRY)p;
        if (e->dwMagic != AUTHENTIK_KEY_MAGIC) break;
        ULARGE_INTEGER exp; exp.LowPart = e->ftExpires.dwLowDateTime; exp.HighPart = e->ftExpires.dwHighDateTime;
        if (exp.QuadPart > now.QuadPart && _wcsicmp(e->wszContainerName, name) == 0) { found = e; break; }
        p += AUTHENTIK_KEY_ENTRY_SIZE(e->cbPrivateKey, e->cbCertificate);
    }

    ReleaseMutex(g_hMutex);
    return found;
}

#define VALID_PROV(h) ((h) == (NCRYPT_PROV_HANDLE)&g_StaticProvider)
#define VALID_KEY(h) ((h) && ((PAUTHENTIK_KEY)(h))->dwMagic == AUTHENTIK_KEY_HANDLE_MAGIC)

// ============================================================================
// Core Functions - OpenProvider uses STATIC handle (boot-safe)
// ============================================================================

SECURITY_STATUS WINAPI AuthentikKSPOpenProvider(
    _Out_ NCRYPT_PROV_HANDLE* phProvider,
    _In_opt_ LPCWSTR pszProviderName,
    _In_ DWORD dwFlags)
{
    (void)pszProviderName; (void)dwFlags;
    if (!phProvider) return NTE_INVALID_PARAMETER;
    *phProvider = (NCRYPT_PROV_HANDLE)&g_StaticProvider;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI AuthentikKSPFreeProvider(_In_ NCRYPT_PROV_HANDLE hProvider)
{
    return VALID_PROV(hProvider) ? ERROR_SUCCESS : NTE_INVALID_HANDLE;
}

SECURITY_STATUS WINAPI AuthentikKSPOpenKey(
    _In_ NCRYPT_PROV_HANDLE hProvider,
    _Out_ NCRYPT_KEY_HANDLE* phKey,
    _In_ LPCWSTR pszKeyName,
    _In_opt_ DWORD dwLegacyKeySpec,
    _In_ DWORD dwFlags)
{
    (void)dwLegacyKeySpec; (void)dwFlags;
    if (!VALID_PROV(hProvider) || !phKey || !pszKeyName) return NTE_INVALID_PARAMETER;
    *phKey = 0;

    // NOW we initialize - during authentication, not boot
    if (!InitKeyStore()) return NTE_PROVIDER_DLL_FAIL;
    if (!InitRsa()) return NTE_PROVIDER_DLL_FAIL;

    PAUTHENTIK_KEY_ENTRY e = FindKey(pszKeyName);
    if (!e) return NTE_BAD_KEYSET;
    if (e->cbPrivateKey > MAX_KEY_BLOB_SIZE || e->cbCertificate > MAX_CERT_BLOB_SIZE) return NTE_BAD_KEY;

    PAUTHENTIK_KEY k = (PAUTHENTIK_KEY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(AUTHENTIK_KEY));
    if (!k) return NTE_NO_MEMORY;

    k->dwMagic = AUTHENTIK_KEY_HANDLE_MAGIC;
    k->hProvider = hProvider;
    k->dwKeySpec = e->dwKeySpec;
    wcscpy_s(k->wszContainerName, MAX_CONTAINER_NAME, e->wszContainerName);
    wcscpy_s(k->wszUserName, MAX_USER_NAME, e->wszUserName);
    k->cbPrivateKeyBlob = e->cbPrivateKey;
    memcpy(k->rgbPrivateKeyBlob, e->rgbData, e->cbPrivateKey);
    k->cbCertificateBlob = e->cbCertificate;
    memcpy(k->rgbCertificateBlob, e->rgbData + e->cbPrivateKey, e->cbCertificate);

    NTSTATUS s = BCryptImportKeyPair(g_hRsaAlg, NULL, BCRYPT_RSAPRIVATE_BLOB, &k->hBCryptKey, k->rgbPrivateKeyBlob, k->cbPrivateKeyBlob, 0);
    if (!BCRYPT_SUCCESS(s)) { HeapFree(GetProcessHeap(), 0, k); return NTE_BAD_KEY; }

    *phKey = (NCRYPT_KEY_HANDLE)k;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI AuthentikKSPFreeKey(_In_ NCRYPT_PROV_HANDLE hProvider, _In_ NCRYPT_KEY_HANDLE hKey)
{
    (void)hProvider;
    if (!VALID_KEY(hKey)) return NTE_INVALID_HANDLE;
    PAUTHENTIK_KEY k = (PAUTHENTIK_KEY)hKey;
    if (k->hBCryptKey) BCryptDestroyKey(k->hBCryptKey);
    SecureZeroMemory(k, sizeof(AUTHENTIK_KEY));
    HeapFree(GetProcessHeap(), 0, k);
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI AuthentikKSPFreeBuffer(_Pre_notnull_ PVOID pvInput)
{
    if (pvInput) HeapFree(GetProcessHeap(), 0, pvInput);
    return ERROR_SUCCESS;
}

// ============================================================================
// Properties
// ============================================================================

SECURITY_STATUS WINAPI AuthentikKSPGetProviderProperty(
    _In_ NCRYPT_PROV_HANDLE hProvider, _In_ LPCWSTR pszProperty,
    _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    _In_ DWORD cbOutput, _Out_ DWORD* pcbResult, _In_ DWORD dwFlags)
{
    (void)dwFlags;
    if (!VALID_PROV(hProvider) || !pszProperty || !pcbResult) return NTE_INVALID_PARAMETER;

    if (wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0)
    {
        DWORD cb = (DWORD)((wcslen(AUTHENTIK_KSP_NAME) + 1) * sizeof(WCHAR));
        *pcbResult = cb;
        if (pbOutput) { if (cbOutput < cb) return NTE_BUFFER_TOO_SMALL; memcpy(pbOutput, AUTHENTIK_KSP_NAME, cb); }
        return ERROR_SUCCESS;
    }
    if (wcscmp(pszProperty, NCRYPT_IMPL_TYPE_PROPERTY) == 0)
    {
        *pcbResult = sizeof(DWORD);
        if (pbOutput) { if (cbOutput < sizeof(DWORD)) return NTE_BUFFER_TOO_SMALL; *(DWORD*)pbOutput = NCRYPT_IMPL_SOFTWARE_FLAG; }
        return ERROR_SUCCESS;
    }
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI AuthentikKSPGetKeyProperty(
    _In_ NCRYPT_PROV_HANDLE hProvider, _In_ NCRYPT_KEY_HANDLE hKey, _In_ LPCWSTR pszProperty,
    _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    _In_ DWORD cbOutput, _Out_ DWORD* pcbResult, _In_ DWORD dwFlags)
{
    (void)hProvider; (void)dwFlags;
    if (!VALID_KEY(hKey) || !pszProperty || !pcbResult) return NTE_INVALID_PARAMETER;
    PAUTHENTIK_KEY k = (PAUTHENTIK_KEY)hKey;

    if (wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0 || wcscmp(pszProperty, NCRYPT_UNIQUE_NAME_PROPERTY) == 0)
    {
        DWORD cb = (DWORD)((wcslen(k->wszContainerName) + 1) * sizeof(WCHAR));
        *pcbResult = cb;
        if (pbOutput) { if (cbOutput < cb) return NTE_BUFFER_TOO_SMALL; memcpy(pbOutput, k->wszContainerName, cb); }
        return ERROR_SUCCESS;
    }
    if (wcscmp(pszProperty, NCRYPT_ALGORITHM_PROPERTY) == 0)
    {
        DWORD cb = (DWORD)((wcslen(BCRYPT_RSA_ALGORITHM) + 1) * sizeof(WCHAR));
        *pcbResult = cb;
        if (pbOutput) { if (cbOutput < cb) return NTE_BUFFER_TOO_SMALL; memcpy(pbOutput, BCRYPT_RSA_ALGORITHM, cb); }
        return ERROR_SUCCESS;
    }
    if (wcscmp(pszProperty, NCRYPT_LENGTH_PROPERTY) == 0)
    {
        *pcbResult = sizeof(DWORD);
        if (pbOutput) {
            if (cbOutput < sizeof(DWORD)) return NTE_BUFFER_TOO_SMALL;
            DWORD len = 0; ULONG r = 0;
            if (k->hBCryptKey) BCryptGetProperty(k->hBCryptKey, BCRYPT_KEY_LENGTH, (PUCHAR)&len, sizeof(len), &r, 0);
            *(DWORD*)pbOutput = len;
        }
        return ERROR_SUCCESS;
    }
    if (wcscmp(pszProperty, NCRYPT_CERTIFICATE_PROPERTY) == 0)
    {
        *pcbResult = k->cbCertificateBlob;
        if (pbOutput) { if (cbOutput < k->cbCertificateBlob) return NTE_BUFFER_TOO_SMALL; memcpy(pbOutput, k->rgbCertificateBlob, k->cbCertificateBlob); }
        return ERROR_SUCCESS;
    }
    if (wcscmp(pszProperty, NCRYPT_EXPORT_POLICY_PROPERTY) == 0)
    {
        *pcbResult = sizeof(DWORD);
        if (pbOutput) { if (cbOutput < sizeof(DWORD)) return NTE_BUFFER_TOO_SMALL; *(DWORD*)pbOutput = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG; }
        return ERROR_SUCCESS;
    }
    if (wcscmp(pszProperty, NCRYPT_KEY_USAGE_PROPERTY) == 0)
    {
        *pcbResult = sizeof(DWORD);
        if (pbOutput) { if (cbOutput < sizeof(DWORD)) return NTE_BUFFER_TOO_SMALL; *(DWORD*)pbOutput = NCRYPT_ALLOW_SIGNING_FLAG | NCRYPT_ALLOW_DECRYPT_FLAG; }
        return ERROR_SUCCESS;
    }
    return NTE_NOT_SUPPORTED;
}

// ============================================================================
// SignHash - Critical for PKINIT
// ============================================================================

SECURITY_STATUS WINAPI AuthentikKSPSignHash(
    _In_ NCRYPT_PROV_HANDLE hProvider, _In_ NCRYPT_KEY_HANDLE hKey,
    _In_opt_ VOID* pPaddingInfo, _In_reads_bytes_(cbHashValue) PBYTE pbHashValue,
    _In_ DWORD cbHashValue, _Out_writes_bytes_to_opt_(cbSignature, *pcbResult) PBYTE pbSignature,
    _In_ DWORD cbSignature, _Out_ DWORD* pcbResult, _In_ DWORD dwFlags)
{
    (void)hProvider;
    if (!VALID_KEY(hKey) || !pbHashValue || !pcbResult) return NTE_INVALID_PARAMETER;
    PAUTHENTIK_KEY k = (PAUTHENTIK_KEY)hKey;
    if (!k->hBCryptKey) return NTE_BAD_KEY;

    ULONG cbRes = 0;
    NTSTATUS s;
    if (dwFlags & BCRYPT_PAD_PKCS1)
        s = BCryptSignHash(k->hBCryptKey, pPaddingInfo, pbHashValue, cbHashValue, pbSignature, cbSignature, &cbRes, BCRYPT_PAD_PKCS1);
    else {
        BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
        s = BCryptSignHash(k->hBCryptKey, &pi, pbHashValue, cbHashValue, pbSignature, cbSignature, &cbRes, BCRYPT_PAD_PKCS1);
    }
    *pcbResult = cbRes;
    if (s == STATUS_BUFFER_TOO_SMALL) return NTE_BUFFER_TOO_SMALL;
    return BCRYPT_SUCCESS(s) ? ERROR_SUCCESS : NTE_INTERNAL_ERROR;
}

// ============================================================================
// Stubs
// ============================================================================

#define STUB_NOT_SUPPORTED return NTE_NOT_SUPPORTED

SECURITY_STATUS WINAPI AuthentikKSPCreatePersistedKey(_In_ NCRYPT_PROV_HANDLE h, _Out_ NCRYPT_KEY_HANDLE* pk, _In_ LPCWSTR a, _In_opt_ LPCWSTR n, _In_ DWORD l, _In_ DWORD f) { (void)h;(void)pk;(void)a;(void)n;(void)l;(void)f; STUB_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI AuthentikKSPSetProviderProperty(_In_ NCRYPT_PROV_HANDLE h, _In_ LPCWSTR p, _In_reads_bytes_(c) PBYTE b, _In_ DWORD c, _In_ DWORD f) { (void)h;(void)p;(void)b;(void)c;(void)f; STUB_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI AuthentikKSPSetKeyProperty(_In_ NCRYPT_PROV_HANDLE h, _In_ NCRYPT_KEY_HANDLE k, _In_ LPCWSTR p, _In_reads_bytes_(c) PBYTE b, _In_ DWORD c, _In_ DWORD f) { (void)h;(void)k;(void)p;(void)b;(void)c;(void)f; STUB_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI AuthentikKSPFinalizeKey(_In_ NCRYPT_PROV_HANDLE h, _In_ NCRYPT_KEY_HANDLE k, _In_ DWORD f) { (void)h;(void)k;(void)f; return ERROR_SUCCESS; }
SECURITY_STATUS WINAPI AuthentikKSPDeleteKey(_In_ NCRYPT_PROV_HANDLE h, _Inout_ NCRYPT_KEY_HANDLE k, _In_ DWORD f) { (void)h;(void)k;(void)f; STUB_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI AuthentikKSPEncrypt(_In_ NCRYPT_PROV_HANDLE h, _In_ NCRYPT_KEY_HANDLE k, _In_reads_bytes_opt_(ci) PBYTE i, _In_ DWORD ci, _In_opt_ VOID* p, _Out_writes_bytes_to_opt_(co, *r) PBYTE o, _In_ DWORD co, _Out_ DWORD* r, _In_ DWORD f) { (void)h;(void)k;(void)i;(void)ci;(void)p;(void)o;(void)co;(void)r;(void)f; STUB_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI AuthentikKSPDecrypt(_In_ NCRYPT_PROV_HANDLE h, _In_ NCRYPT_KEY_HANDLE k, _In_reads_bytes_opt_(ci) PBYTE i, _In_ DWORD ci, _In_opt_ VOID* p, _Out_writes_bytes_to_opt_(co, *r) PBYTE o, _In_ DWORD co, _Out_ DWORD* r, _In_ DWORD f) { (void)h;(void)k;(void)i;(void)ci;(void)p;(void)o;(void)co;(void)r;(void)f; STUB_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI AuthentikKSPVerifySignature(_In_ NCRYPT_PROV_HANDLE h, _In_ NCRYPT_KEY_HANDLE k, _In_opt_ VOID* p, _In_reads_bytes_(ch) PBYTE hv, _In_ DWORD ch, _In_reads_bytes_(cs) PBYTE s, _In_ DWORD cs, _In_ DWORD f) { (void)h;(void)k;(void)p;(void)hv;(void)ch;(void)s;(void)cs;(void)f; STUB_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI AuthentikKSPPromptUser(_In_ NCRYPT_PROV_HANDLE h, _In_opt_ NCRYPT_KEY_HANDLE k, _In_ LPCWSTR o, _In_ DWORD f) { (void)h;(void)k;(void)o;(void)f; return ERROR_SUCCESS; }
SECURITY_STATUS WINAPI AuthentikKSPNotifyChangeKey(_In_ NCRYPT_PROV_HANDLE h, _Inout_ HANDLE* e, _In_ DWORD f) { (void)h;(void)e;(void)f; STUB_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI AuthentikKSPSecretAgreement(_In_ NCRYPT_PROV_HANDLE h, _In_ NCRYPT_KEY_HANDLE pk, _In_ NCRYPT_KEY_HANDLE uk, _Out_ NCRYPT_SECRET_HANDLE* s, _In_ DWORD f) { (void)h;(void)pk;(void)uk;(void)s;(void)f; STUB_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI AuthentikKSPDeriveKey(_In_ NCRYPT_PROV_HANDLE h, _In_opt_ NCRYPT_SECRET_HANDLE s, _In_ LPCWSTR k, _In_opt_ NCryptBufferDesc* p, _Out_writes_bytes_to_opt_(cd, *r) PUCHAR d, _In_ DWORD cd, _Out_ DWORD* r, _In_ ULONG f) { (void)h;(void)s;(void)k;(void)p;(void)d;(void)cd;(void)r;(void)f; STUB_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI AuthentikKSPFreeSecret(_In_ NCRYPT_PROV_HANDLE h, _In_ NCRYPT_SECRET_HANDLE s) { (void)h;(void)s; STUB_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI AuthentikKSPImportKey(_In_ NCRYPT_PROV_HANDLE h, _In_opt_ NCRYPT_KEY_HANDLE ik, _In_ LPCWSTR t, _In_opt_ NCryptBufferDesc* p, _Out_ NCRYPT_KEY_HANDLE* pk, _In_reads_bytes_(cd) PBYTE d, _In_ DWORD cd, _In_ DWORD f) { (void)h;(void)ik;(void)t;(void)p;(void)pk;(void)d;(void)cd;(void)f; STUB_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI AuthentikKSPExportKey(_In_ NCRYPT_PROV_HANDLE h, _In_ NCRYPT_KEY_HANDLE k, _In_opt_ NCRYPT_KEY_HANDLE ek, _In_ LPCWSTR t, _In_opt_ NCryptBufferDesc* p, _Out_writes_bytes_to_opt_(co, *r) PBYTE o, _In_ DWORD co, _Out_ DWORD* r, _In_ DWORD f) { (void)h;(void)k;(void)ek;(void)t;(void)p;(void)o;(void)co;(void)r;(void)f; STUB_NOT_SUPPORTED; }
SECURITY_STATUS WINAPI AuthentikKSPEnumAlgorithms(_In_ NCRYPT_PROV_HANDLE h, _In_ DWORD o, _Out_ DWORD* c, _Outptr_result_buffer_(*c) NCryptAlgorithmName** l, _In_ DWORD f) { (void)h;(void)o;(void)f; if(!c||!l)return NTE_INVALID_PARAMETER; *c=0;*l=NULL; return ERROR_SUCCESS; }
SECURITY_STATUS WINAPI AuthentikKSPEnumKeys(_In_ NCRYPT_PROV_HANDLE h, _In_opt_ LPCWSTR s, _Outptr_ NCryptKeyName** n, _Inout_ PVOID* e, _In_ DWORD f) { (void)h;(void)s;(void)n;(void)e;(void)f; return NTE_NO_MORE_ITEMS; }
SECURITY_STATUS WINAPI AuthentikKSPIsAlgSupported(_In_ NCRYPT_PROV_HANDLE h, _In_ LPCWSTR a, _In_ DWORD f) { (void)h;(void)f; if(!a)return NTE_INVALID_PARAMETER; return wcscmp(a,BCRYPT_RSA_ALGORITHM)==0?ERROR_SUCCESS:NTE_NOT_SUPPORTED; }

// ============================================================================
// Exported Helpers
// ============================================================================

extern "C" __declspec(dllexport) HRESULT WINAPI AuthentikKSP_StoreKey(
    _In_ LPCWSTR cn, _In_ LPCWSTR un,
    _In_reads_bytes_(cpk) const BYTE* pk, _In_ DWORD cpk,
    _In_reads_bytes_(cc) const BYTE* c, _In_ DWORD cc,
    _In_ DWORD ks, _In_ DWORD vm)
{
    if (!cn || !un || !pk || !c) return E_INVALIDARG;
    if (cpk > MAX_KEY_BLOB_SIZE || cc > MAX_CERT_BLOB_SIZE) return E_INVALIDARG;
    if (!InitKeyStore()) return E_FAIL;

    WaitForSingleObject(g_hMutex, 5000);
    DWORD cbE = AUTHENTIK_KEY_ENTRY_SIZE(cpk, cc);
    DWORD cbNew = g_pKeyStore->cbTotalSize + cbE;
    if (cbNew > AUTHENTIK_SHARED_MEM_SIZE) { ReleaseMutex(g_hMutex); return E_OUTOFMEMORY; }

    PAUTHENTIK_KEY_ENTRY e = (PAUTHENTIK_KEY_ENTRY)((PBYTE)g_pKeyStore + g_pKeyStore->cbTotalSize);
    e->dwMagic = AUTHENTIK_KEY_MAGIC;
    e->dwFlags = 0;
    e->dwKeySpec = ks;
    GetSystemTimeAsFileTime(&e->ftCreated);
    ULARGE_INTEGER x; x.LowPart = e->ftCreated.dwLowDateTime; x.HighPart = e->ftCreated.dwHighDateTime;
    x.QuadPart += (ULONGLONG)vm * 60 * 10000000;
    e->ftExpires.dwLowDateTime = x.LowPart; e->ftExpires.dwHighDateTime = x.HighPart;
    wcscpy_s(e->wszContainerName, MAX_CONTAINER_NAME, cn);
    wcscpy_s(e->wszUserName, MAX_USER_NAME, un);
    e->cbPrivateKey = cpk; e->cbCertificate = cc;
    memcpy(e->rgbData, pk, cpk);
    memcpy(e->rgbData + cpk, c, cc);
    g_pKeyStore->cKeys++;
    g_pKeyStore->cbTotalSize = cbNew;
    ReleaseMutex(g_hMutex);
    return S_OK;
}

extern "C" __declspec(dllexport) LPCWSTR WINAPI AuthentikKSP_GetProviderName(void) { return AUTHENTIK_KSP_NAME; }

extern "C" __declspec(dllexport) HRESULT WINAPI AuthentikKSP_RemoveKey(_In_ LPCWSTR cn)
{
    if (!cn) return E_INVALIDARG;
    if (!InitKeyStore()) return E_FAIL;
    WaitForSingleObject(g_hMutex, 5000);
    PBYTE p = (PBYTE)g_pKeyStore + sizeof(AUTHENTIK_KEY_STORE_HEADER);
    PBYTE end = (PBYTE)g_pKeyStore + g_pKeyStore->cbTotalSize;
    for (DWORD i = 0; i < g_pKeyStore->cKeys && p < end; i++) {
        PAUTHENTIK_KEY_ENTRY e = (PAUTHENTIK_KEY_ENTRY)p;
        if (e->dwMagic != AUTHENTIK_KEY_MAGIC) break;
        if (_wcsicmp(e->wszContainerName, cn) == 0) { e->ftExpires.dwLowDateTime = 0; e->ftExpires.dwHighDateTime = 0; ReleaseMutex(g_hMutex); return S_OK; }
        p += AUTHENTIK_KEY_ENTRY_SIZE(e->cbPrivateKey, e->cbCertificate);
    }
    ReleaseMutex(g_hMutex);
    return S_FALSE;
}

extern "C" __declspec(dllexport) BOOL WINAPI AuthentikKSP_KeyExists(_In_ LPCWSTR cn)
{
    if (!cn) return FALSE;
    if (!InitKeyStore()) return FALSE;
    return FindKey(cn) != NULL;
}
