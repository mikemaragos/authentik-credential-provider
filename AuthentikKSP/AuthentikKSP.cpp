// AuthentikKSP.cpp
// Authentik Key Storage Provider - Main Implementation
//
// This KSP wraps the Microsoft Software KSP and adds OTP validation
// before allowing cryptographic operations.

#include "AuthentikKSP.h"
#include <winhttp.h>
#include <sstream>
#include <vector>
#include <cstdio>
#include <cstdarg>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "winhttp.lib")

// ============================================================================
// Logging (Enable for all builds during development)
// ============================================================================

inline void KSPLog(const char* fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    OutputDebugStringA(buf);
}

#define LOG(fmt, ...) KSPLog("[AuthentikKSP] " fmt "\n", ##__VA_ARGS__)

// ============================================================================
// KSP Function Table
// ============================================================================

NCRYPT_KEY_STORAGE_FUNCTION_TABLE g_AuthentikKSPFunctionTable = {
    sizeof(NCRYPT_KEY_STORAGE_FUNCTION_TABLE),  // cbSize - MUST be size of structure
    KSPOpenProvider,
    KSPOpenKey,
    KSPCreatePersistedKey,
    KSPGetProviderProperty,
    KSPGetKeyProperty,
    KSPSetProviderProperty,
    KSPSetKeyProperty,
    KSPFinalizeKey,
    KSPDeleteKey,
    KSPFreeProvider,
    KSPFreeKey,
    KSPFreeBuffer,
    KSPEncrypt,
    KSPDecrypt,
    KSPIsAlgSupported,
    KSPEnumAlgorithms,
    KSPEnumKeys,
    KSPImportKey,
    KSPExportKey,
    KSPSignHash,           // <-- OTP validation happens here!
    KSPVerifySignature,
    KSPPromptUser,
    KSPNotifyChangeKey,
    KSPSecretAgreement,
    KSPDeriveKey,
    KSPFreeSecret
};

// ============================================================================
// DLL Entry Point
// ============================================================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        LOG("DLL_PROCESS_ATTACH");
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        LOG("DLL_PROCESS_DETACH");
        break;
    }
    return TRUE;
}

// ============================================================================
// GetKeyStorageInterface - Main entry point for CNG
// ============================================================================

NTSTATUS WINAPI GetKeyStorageInterface(
    __in    LPCWSTR pszProviderName,
    __out   NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable,
    __in    DWORD dwFlags)
{
    LOG("GetKeyStorageInterface called");
    
    UNREFERENCED_PARAMETER(pszProviderName);
    UNREFERENCED_PARAMETER(dwFlags);
    
    *ppFunctionTable = &g_AuthentikKSPFunctionTable;
    return ERROR_SUCCESS;
}

// ============================================================================
// Provider Functions
// ============================================================================

SECURITY_STATUS WINAPI KSPOpenProvider(
    __out   NCRYPT_PROV_HANDLE *phProvider,
    __in    LPCWSTR pszProviderName,
    __in    DWORD dwFlags)
{
    LOG("KSPOpenProvider: %S", pszProviderName);
    
    SECURITY_STATUS status = NTE_INTERNAL_ERROR;
    AUTHENTIK_PROVIDER* pProvider = nullptr;
    
    // Allocate provider context
    pProvider = new (std::nothrow) AUTHENTIK_PROVIDER();
    if (!pProvider)
    {
        return NTE_NO_MEMORY;
    }
    
    // Initialize
    pProvider->cbLength = sizeof(AUTHENTIK_PROVIDER);
    pProvider->dwMagic = AUTHENTIK_PROVIDER_MAGIC;
    pProvider->hBaseProvider = NULL;
    
    // Load configuration from registry
    if (FAILED(LoadConfiguration(pProvider)))
    {
        LOG("Failed to load configuration, using defaults");
        pProvider->authentikUrl = L"authentik.test.local";
        pProvider->authentikPort = 443;
        pProvider->flowSlug = L"windows-otp-auth";
        pProvider->useHttps = TRUE;
    }
    
    // Open the underlying Microsoft Software KSP
    status = NCryptOpenStorageProvider(
        &pProvider->hBaseProvider,
        MS_KEY_STORAGE_PROVIDER,
        0);
    
    if (status != ERROR_SUCCESS)
    {
        LOG("Failed to open base provider: 0x%08x", status);
        delete pProvider;
        return status;
    }
    
    *phProvider = (NCRYPT_PROV_HANDLE)pProvider;
    LOG("Provider opened successfully");
    
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPFreeProvider(
    __in    NCRYPT_PROV_HANDLE hProvider)
{
    LOG("KSPFreeProvider");
    
    if (!IsValidProviderHandle(hProvider))
    {
        return NTE_INVALID_HANDLE;
    }
    
    AUTHENTIK_PROVIDER* pProvider = (AUTHENTIK_PROVIDER*)hProvider;
    
    // Close base provider
    if (pProvider->hBaseProvider)
    {
        NCryptFreeObject(pProvider->hBaseProvider);
    }
    
    // Clear and delete
    SecureZeroMemory(pProvider, sizeof(AUTHENTIK_PROVIDER));
    delete pProvider;
    
    return ERROR_SUCCESS;
}

// ============================================================================
// Key Functions
// ============================================================================

SECURITY_STATUS WINAPI KSPOpenKey(
    __inout NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszKeyName,
    __in    DWORD dwLegacyKeySpec,
    __in    DWORD dwFlags)
{
    LOG("KSPOpenKey: %S", pszKeyName);
    
    if (!IsValidProviderHandle(hProvider))
    {
        return NTE_INVALID_HANDLE;
    }
    
    AUTHENTIK_PROVIDER* pProvider = (AUTHENTIK_PROVIDER*)hProvider;
    AUTHENTIK_KEY* pKey = nullptr;
    SECURITY_STATUS status;
    
    // Allocate key context
    pKey = new (std::nothrow) AUTHENTIK_KEY();
    if (!pKey)
    {
        return NTE_NO_MEMORY;
    }
    
    // Initialize
    pKey->cbLength = sizeof(AUTHENTIK_KEY);
    pKey->dwMagic = AUTHENTIK_KEY_MAGIC;
    pKey->pProvider = pProvider;
    pKey->keyName = pszKeyName ? pszKeyName : L"";
    pKey->otpValidated = FALSE;
    
    // Open the key in the base provider
    status = NCryptOpenKey(
        pProvider->hBaseProvider,
        &pKey->hBaseKey,
        pszKeyName,
        dwLegacyKeySpec,
        dwFlags);
    
    if (status != ERROR_SUCCESS)
    {
        LOG("Failed to open base key: 0x%08x", status);
        delete pKey;
        return status;
    }
    
    // Try to extract UPN from associated certificate
    ExtractUPNFromKey(pKey->hBaseKey, pKey->username);
    LOG("Key opened for user: %S", pKey->username.c_str());
    
    *phKey = (NCRYPT_KEY_HANDLE)pKey;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPCreatePersistedKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszAlgId,
    __in_opt LPCWSTR pszKeyName,
    __in    DWORD dwLegacyKeySpec,
    __in    DWORD dwFlags)
{
    LOG("KSPCreatePersistedKey: %S", pszKeyName ? pszKeyName : L"(null)");
    
    if (!IsValidProviderHandle(hProvider))
    {
        return NTE_INVALID_HANDLE;
    }
    
    AUTHENTIK_PROVIDER* pProvider = (AUTHENTIK_PROVIDER*)hProvider;
    AUTHENTIK_KEY* pKey = nullptr;
    SECURITY_STATUS status;
    
    // Allocate key context
    pKey = new (std::nothrow) AUTHENTIK_KEY();
    if (!pKey)
    {
        return NTE_NO_MEMORY;
    }
    
    // Initialize
    pKey->cbLength = sizeof(AUTHENTIK_KEY);
    pKey->dwMagic = AUTHENTIK_KEY_MAGIC;
    pKey->pProvider = pProvider;
    pKey->keyName = pszKeyName ? pszKeyName : L"";
    pKey->otpValidated = FALSE;
    
    // Create the key in the base provider
    status = NCryptCreatePersistedKey(
        pProvider->hBaseProvider,
        &pKey->hBaseKey,
        pszAlgId,
        pszKeyName,
        dwLegacyKeySpec,
        dwFlags);
    
    if (status != ERROR_SUCCESS)
    {
        LOG("Failed to create base key: 0x%08x", status);
        delete pKey;
        return status;
    }
    
    *phKey = (NCRYPT_KEY_HANDLE)pKey;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPFreeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey)
{
    LOG("KSPFreeKey");
    
    UNREFERENCED_PARAMETER(hProvider);
    
    if (!IsValidKeyHandle(hKey))
    {
        return NTE_INVALID_HANDLE;
    }
    
    AUTHENTIK_KEY* pKey = (AUTHENTIK_KEY*)hKey;
    
    // Free base key
    if (pKey->hBaseKey)
    {
        NCryptFreeObject(pKey->hBaseKey);
    }
    
    // Clear sensitive data
    SecureZeroMemory(&pKey->currentOtp[0], pKey->currentOtp.length() * sizeof(wchar_t));
    
    delete pKey;
    return ERROR_SUCCESS;
}

// ============================================================================
// Property Functions
// ============================================================================

SECURITY_STATUS WINAPI KSPSetKeyProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __in    PBYTE pbInput,
    __in    DWORD cbInput,
    __in    DWORD dwFlags)
{
    LOG("KSPSetKeyProperty: %S", pszProperty);
    
    if (!IsValidKeyHandle(hKey))
    {
        return NTE_INVALID_HANDLE;
    }
    
    AUTHENTIK_KEY* pKey = (AUTHENTIK_KEY*)hKey;
    
    // =========================================================================
    // INTERCEPT PIN PROPERTY - This is how we capture the OTP!
    // =========================================================================
    if (wcscmp(pszProperty, NCRYPT_PIN_PROPERTY) == 0)
    {
        LOG("PIN property intercepted - storing as OTP");
        
        // The "PIN" is actually the OTP code from the user
        if (pbInput && cbInput > 0)
        {
            pKey->currentOtp = std::wstring((LPCWSTR)pbInput);
            pKey->otpValidated = FALSE;  // Needs validation
            LOG("OTP captured: %d characters", pKey->currentOtp.length());
        }
        
        return ERROR_SUCCESS;  // Don't pass to base provider
    }
    
    // Pass through to base provider for other properties
    return NCryptSetProperty(
        pKey->hBaseKey,
        pszProperty,
        pbInput,
        cbInput,
        dwFlags);
}

SECURITY_STATUS WINAPI KSPGetKeyProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __out   PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags)
{
    LOG("KSPGetKeyProperty: %S", pszProperty);
    
    if (!IsValidKeyHandle(hKey))
    {
        return NTE_INVALID_HANDLE;
    }
    
    AUTHENTIK_KEY* pKey = (AUTHENTIK_KEY*)hKey;
    
    // Pass through to base provider
    return NCryptGetProperty(
        pKey->hBaseKey,
        pszProperty,
        pbOutput,
        cbOutput,
        pcbResult,
        dwFlags);
}

SECURITY_STATUS WINAPI KSPGetProviderProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __out   PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags)
{
    LOG("KSPGetProviderProperty: %S", pszProperty);
    
    if (!IsValidProviderHandle(hProvider))
    {
        return NTE_INVALID_HANDLE;
    }
    
    AUTHENTIK_PROVIDER* pProvider = (AUTHENTIK_PROVIDER*)hProvider;
    
    // Handle provider name
    if (wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0)
    {
        DWORD cbName = (DWORD)((wcslen(AUTHENTIK_KSP_PROVIDER_NAME) + 1) * sizeof(WCHAR));
        
        if (pcbResult)
        {
            *pcbResult = cbName;
        }
        
        if (pbOutput == NULL)
        {
            return ERROR_SUCCESS;
        }
        
        if (cbOutput < cbName)
        {
            return NTE_BUFFER_TOO_SMALL;
        }
        
        memcpy(pbOutput, AUTHENTIK_KSP_PROVIDER_NAME, cbName);
        return ERROR_SUCCESS;
    }
    
    // Pass through to base provider
    return NCryptGetProperty(
        pProvider->hBaseProvider,
        pszProperty,
        pbOutput,
        cbOutput,
        pcbResult,
        dwFlags);
}

SECURITY_STATUS WINAPI KSPSetProviderProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __in    PBYTE pbInput,
    __in    DWORD cbInput,
    __in    DWORD dwFlags)
{
    LOG("KSPSetProviderProperty: %S", pszProperty);
    
    if (!IsValidProviderHandle(hProvider))
    {
        return NTE_INVALID_HANDLE;
    }
    
    AUTHENTIK_PROVIDER* pProvider = (AUTHENTIK_PROVIDER*)hProvider;
    
    return NCryptSetProperty(
        pProvider->hBaseProvider,
        pszProperty,
        pbInput,
        cbInput,
        dwFlags);
}

// ============================================================================
// CRITICAL FUNCTION: SignHash - OTP validation happens here!
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
    __in    DWORD dwFlags)
{
    LOG("KSPSignHash - THIS IS WHERE THE MAGIC HAPPENS!");
    
    if (!IsValidKeyHandle(hKey))
    {
        return NTE_INVALID_HANDLE;
    }
    
    AUTHENTIK_KEY* pKey = (AUTHENTIK_KEY*)hKey;
    
    // =========================================================================
    // OTP VALIDATION - The core of our KSP!
    // =========================================================================
    
    // Check if we have an OTP to validate
    if (pKey->currentOtp.empty())
    {
        LOG("ERROR: No OTP provided!");
        return NTE_BAD_KEYSET;  // Or SCARD_W_WRONG_CHV
    }
    
    // Check if already validated this session
    if (!pKey->otpValidated)
    {
        LOG("Validating OTP with Authentik for user: %S", pKey->username.c_str());
        
        // Validate OTP with Authentik
        BOOL valid = ValidateOTPWithAuthentik(
            pKey->pProvider,
            pKey->username.c_str(),
            pKey->currentOtp.c_str());
        
        if (!valid)
        {
            LOG("OTP VALIDATION FAILED!");
            
            // Clear the invalid OTP
            SecureZeroMemory(&pKey->currentOtp[0], pKey->currentOtp.length() * sizeof(wchar_t));
            pKey->currentOtp.clear();
            
            return NTE_BAD_KEYSET;  // Login will fail
        }
        
        LOG("OTP VALIDATED SUCCESSFULLY!");
        pKey->otpValidated = TRUE;
    }
    
    // =========================================================================
    // OTP was valid - perform the actual signature
    // =========================================================================
    
    LOG("Performing signature with base provider");
    
    return NCryptSignHash(
        pKey->hBaseKey,
        pPaddingInfo,
        pbHashValue,
        cbHashValue,
        pbSignature,
        cbSignature,
        pcbResult,
        dwFlags);
}

// ============================================================================
// Other Cryptographic Functions (passthrough to base)
// ============================================================================

SECURITY_STATUS WINAPI KSPVerifySignature(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt VOID *pPaddingInfo,
    __in    PBYTE pbHashValue,
    __in    DWORD cbHashValue,
    __in    PBYTE pbSignature,
    __in    DWORD cbSignature,
    __in    DWORD dwFlags)
{
    if (!IsValidKeyHandle(hKey))
        return NTE_INVALID_HANDLE;
    
    AUTHENTIK_KEY* pKey = (AUTHENTIK_KEY*)hKey;
    return NCryptVerifySignature(pKey->hBaseKey, pPaddingInfo, pbHashValue, cbHashValue, pbSignature, cbSignature, dwFlags);
}

SECURITY_STATUS WINAPI KSPEncrypt(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    PBYTE pbInput,
    __in    DWORD cbInput,
    __in    VOID *pPaddingInfo,
    __out   PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags)
{
    if (!IsValidKeyHandle(hKey))
        return NTE_INVALID_HANDLE;
    
    AUTHENTIK_KEY* pKey = (AUTHENTIK_KEY*)hKey;
    return NCryptEncrypt(pKey->hBaseKey, pbInput, cbInput, pPaddingInfo, pbOutput, cbOutput, pcbResult, dwFlags);
}

SECURITY_STATUS WINAPI KSPDecrypt(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    PBYTE pbInput,
    __in    DWORD cbInput,
    __in    VOID *pPaddingInfo,
    __out   PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags)
{
    if (!IsValidKeyHandle(hKey))
        return NTE_INVALID_HANDLE;
    
    AUTHENTIK_KEY* pKey = (AUTHENTIK_KEY*)hKey;
    return NCryptDecrypt(pKey->hBaseKey, pbInput, cbInput, pPaddingInfo, pbOutput, cbOutput, pcbResult, dwFlags);
}

SECURITY_STATUS WINAPI KSPFinalizeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    DWORD dwFlags)
{
    if (!IsValidKeyHandle(hKey))
        return NTE_INVALID_HANDLE;
    
    AUTHENTIK_KEY* pKey = (AUTHENTIK_KEY*)hKey;
    return NCryptFinalizeKey(pKey->hBaseKey, dwFlags);
}

SECURITY_STATUS WINAPI KSPDeleteKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout NCRYPT_KEY_HANDLE hKey,
    __in    DWORD dwFlags)
{
    if (!IsValidKeyHandle(hKey))
        return NTE_INVALID_HANDLE;
    
    AUTHENTIK_KEY* pKey = (AUTHENTIK_KEY*)hKey;
    return NCryptDeleteKey(pKey->hBaseKey, dwFlags);
}

SECURITY_STATUS WINAPI KSPFreeBuffer(__in PVOID pvInput)
{
    if (pvInput)
    {
        HeapFree(GetProcessHeap(), 0, pvInput);
    }
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPIsAlgSupported(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszAlgId,
    __in    DWORD dwFlags)
{
    if (!IsValidProviderHandle(hProvider))
        return NTE_INVALID_HANDLE;
    
    AUTHENTIK_PROVIDER* pProvider = (AUTHENTIK_PROVIDER*)hProvider;
    return NCryptIsAlgSupported(pProvider->hBaseProvider, pszAlgId, dwFlags);
}

SECURITY_STATUS WINAPI KSPEnumAlgorithms(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    DWORD dwAlgOperations,
    __out   DWORD *pdwAlgCount,
    __out   NCryptAlgorithmName **ppAlgList,
    __in    DWORD dwFlags)
{
    if (!IsValidProviderHandle(hProvider))
        return NTE_INVALID_HANDLE;
    
    AUTHENTIK_PROVIDER* pProvider = (AUTHENTIK_PROVIDER*)hProvider;
    return NCryptEnumAlgorithms(pProvider->hBaseProvider, dwAlgOperations, pdwAlgCount, ppAlgList, dwFlags);
}

SECURITY_STATUS WINAPI KSPEnumKeys(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt LPCWSTR pszScope,
    __out   NCryptKeyName **ppKeyName,
    __inout PVOID *ppEnumState,
    __in    DWORD dwFlags)
{
    if (!IsValidProviderHandle(hProvider))
        return NTE_INVALID_HANDLE;
    
    AUTHENTIK_PROVIDER* pProvider = (AUTHENTIK_PROVIDER*)hProvider;
    return NCryptEnumKeys(pProvider->hBaseProvider, pszScope, ppKeyName, ppEnumState, dwFlags);
}

SECURITY_STATUS WINAPI KSPImportKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hImportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    PBYTE pbData,
    __in    DWORD cbData,
    __in    DWORD dwFlags)
{
    // TODO: Implement properly with key context wrapping
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPExportKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt NCRYPT_KEY_HANDLE hExportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out   PBYTE pbOutput,
    __in    DWORD cbOutput,
    __out   DWORD *pcbResult,
    __in    DWORD dwFlags)
{
    if (!IsValidKeyHandle(hKey))
        return NTE_INVALID_HANDLE;
    
    AUTHENTIK_KEY* pKey = (AUTHENTIK_KEY*)hKey;
    return NCryptExportKey(pKey->hBaseKey, hExportKey, pszBlobType, pParameterList, pbOutput, cbOutput, pcbResult, dwFlags);
}

SECURITY_STATUS WINAPI KSPPromptUser(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszOperation,
    __in    DWORD dwFlags)
{
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI KSPNotifyChangeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout HANDLE *phEvent,
    __in    DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPSecretAgreement(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hPrivKey,
    __in    NCRYPT_KEY_HANDLE hPubKey,
    __out   NCRYPT_SECRET_HANDLE *phSecret,
    __in    DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPDeriveKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_SECRET_HANDLE hSharedSecret,
    __in    LPCWSTR pwszKDF,
    __in_opt NCryptBufferDesc *pParameterList,
    __out   PBYTE pbDerivedKey,
    __in    DWORD cbDerivedKey,
    __out   DWORD *pcbResult,
    __in    ULONG dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSPFreeSecret(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_SECRET_HANDLE hSharedSecret)
{
    return NTE_NOT_SUPPORTED;
}

// ============================================================================
// Helper Functions
// ============================================================================

BOOL IsValidProviderHandle(NCRYPT_PROV_HANDLE hProvider)
{
    if (!hProvider)
        return FALSE;
    
    AUTHENTIK_PROVIDER* pProvider = (AUTHENTIK_PROVIDER*)hProvider;
    
    __try
    {
        if (pProvider->dwMagic != AUTHENTIK_PROVIDER_MAGIC)
            return FALSE;
        if (pProvider->cbLength != sizeof(AUTHENTIK_PROVIDER))
            return FALSE;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
    
    return TRUE;
}

BOOL IsValidKeyHandle(NCRYPT_KEY_HANDLE hKey)
{
    if (!hKey)
        return FALSE;
    
    AUTHENTIK_KEY* pKey = (AUTHENTIK_KEY*)hKey;
    
    __try
    {
        if (pKey->dwMagic != AUTHENTIK_KEY_MAGIC)
            return FALSE;
        if (pKey->cbLength != sizeof(AUTHENTIK_KEY))
            return FALSE;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
    
    return TRUE;
}

HRESULT LoadConfiguration(AUTHENTIK_PROVIDER* pProvider)
{
    LOG("Loading configuration from registry");
    
    HKEY hKey;
    LONG result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\AuthentikKSP",
        0,
        KEY_READ,
        &hKey);
    
    if (result != ERROR_SUCCESS)
    {
        return HRESULT_FROM_WIN32(result);
    }
    
    WCHAR buffer[256];
    DWORD bufferSize;
    
    // ServerUrl
    bufferSize = sizeof(buffer);
    result = RegQueryValueExW(hKey, L"ServerUrl", nullptr, nullptr, (LPBYTE)buffer, &bufferSize);
    if (result == ERROR_SUCCESS)
    {
        pProvider->authentikUrl = buffer;
    }
    
    // ServerPort
    DWORD port = 443;
    bufferSize = sizeof(DWORD);
    result = RegQueryValueExW(hKey, L"ServerPort", nullptr, nullptr, (LPBYTE)&port, &bufferSize);
    pProvider->authentikPort = port;
    
    // FlowSlug
    bufferSize = sizeof(buffer);
    result = RegQueryValueExW(hKey, L"FlowSlug", nullptr, nullptr, (LPBYTE)buffer, &bufferSize);
    if (result == ERROR_SUCCESS)
    {
        pProvider->flowSlug = buffer;
    }
    
    // UseHttps
    DWORD useHttps = 1;
    bufferSize = sizeof(DWORD);
    result = RegQueryValueExW(hKey, L"UseHttps", nullptr, nullptr, (LPBYTE)&useHttps, &bufferSize);
    pProvider->useHttps = (useHttps != 0);
    
    RegCloseKey(hKey);
    
    LOG("Config: Server=%S:%d, Flow=%S, HTTPS=%d",
        pProvider->authentikUrl.c_str(),
        pProvider->authentikPort,
        pProvider->flowSlug.c_str(),
        pProvider->useHttps);
    
    return S_OK;
}

HRESULT ExtractUPNFromKey(NCRYPT_KEY_HANDLE hKey, std::wstring& upn)
{
    // Try to get the certificate associated with this key
    // and extract the UPN from the SAN
    
    DWORD cbCert = 0;
    SECURITY_STATUS status = NCryptGetProperty(
        hKey,
        NCRYPT_CERTIFICATE_PROPERTY,
        nullptr,
        0,
        &cbCert,
        0);
    
    if (status != ERROR_SUCCESS || cbCert == 0)
    {
        LOG("No certificate associated with key");
        upn = L"unknown";
        return E_FAIL;
    }
    
    // TODO: Parse certificate to extract UPN from SAN
    // For now, use key name as username hint
    upn = L"unknown";
    
    return S_OK;
}

// ============================================================================
// OTP Validation with Authentik
// ============================================================================

BOOL ValidateOTPWithAuthentik(
    AUTHENTIK_PROVIDER* pProvider,
    LPCWSTR pszUsername,
    LPCWSTR pszOtp)
{
    LOG("ValidateOTPWithAuthentik: user=%S", pszUsername);
    
    BOOL result = FALSE;
    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;
    HINTERNET hRequest = nullptr;
    
    // Open WinHTTP session
    hSession = WinHttpOpen(
        L"AuthentikKSP/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    
    if (!hSession)
    {
        LOG("WinHttpOpen failed: %d", GetLastError());
        return FALSE;
    }
    
    // Connect to Authentik server
    hConnect = WinHttpConnect(
        hSession,
        pProvider->authentikUrl.c_str(),
        (INTERNET_PORT)pProvider->authentikPort,
        0);
    
    if (!hConnect)
    {
        LOG("WinHttpConnect failed: %d", GetLastError());
        WinHttpCloseHandle(hSession);
        return FALSE;
    }
    
    // Build URL
    std::wstring url = L"/api/v3/flows/executor/" + pProvider->flowSlug + L"/";
    
    // Create request
    DWORD dwFlags = pProvider->useHttps ? WINHTTP_FLAG_SECURE : 0;
    
    hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",
        url.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        dwFlags);
    
    if (!hRequest)
    {
        LOG("WinHttpOpenRequest failed: %d", GetLastError());
        goto cleanup;
    }
    
    // Disable SSL validation for testing (REMOVE IN PRODUCTION!)
    if (pProvider->useHttps)
    {
        DWORD dwSecFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwSecFlags, sizeof(dwSecFlags));
    }
    
    // Build JSON payload
    std::wstring payload = L"{\"uid_field\":\"" + std::wstring(pszUsername) + 
                          L"\",\"code\":\"" + std::wstring(pszOtp) + L"\"}";
    
    // Convert to UTF-8
    int size = WideCharToMultiByte(CP_UTF8, 0, payload.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::vector<char> payloadUtf8(size);
    WideCharToMultiByte(CP_UTF8, 0, payload.c_str(), -1, &payloadUtf8[0], size, nullptr, nullptr);
    
    // Set headers
    WinHttpAddRequestHeaders(
        hRequest,
        L"Content-Type: application/json\r\n",
        (DWORD)-1,
        WINHTTP_ADDREQ_FLAG_ADD);
    
    // Send request
    if (!WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        &payloadUtf8[0],
        (DWORD)payloadUtf8.size() - 1,
        (DWORD)payloadUtf8.size() - 1,
        0))
    {
        LOG("WinHttpSendRequest failed: %d", GetLastError());
        goto cleanup;
    }
    
    // Receive response
    if (!WinHttpReceiveResponse(hRequest, nullptr))
    {
        LOG("WinHttpReceiveResponse failed: %d", GetLastError());
        goto cleanup;
    }
    
    // Read response
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    std::vector<char> responseBuffer;
    
    do
    {
        dwSize = 0;
        WinHttpQueryDataAvailable(hRequest, &dwSize);
        
        if (dwSize == 0)
            break;
        
        std::vector<char> temp(dwSize + 1);
        WinHttpReadData(hRequest, &temp[0], dwSize, &dwDownloaded);
        responseBuffer.insert(responseBuffer.end(), temp.begin(), temp.begin() + dwDownloaded);
        
    } while (dwSize > 0);
    
    // Check response for success
    if (!responseBuffer.empty())
    {
        responseBuffer.push_back('\0');
        std::string response(&responseBuffer[0]);
        
        LOG("Authentik response: %s", response.c_str());
        
        // Check for success indicators
        // "type":"redirect" indicates successful authentication
        if (response.find("\"type\":\"redirect\"") != std::string::npos)
        {
            LOG("OTP validation SUCCESS");
            result = TRUE;
        }
        else
        {
            LOG("OTP validation FAILED");
            result = FALSE;
        }
    }
    
cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    
    return result;
}
