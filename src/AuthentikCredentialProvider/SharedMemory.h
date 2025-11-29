// SharedMemory.h
// Shared memory structures for communication between Credential Provider and KSP
// 
// This header defines the shared memory layout used to pass private keys
// from the credential provider to the KSP for PKINIT authentication.
//
// Include this file in both:
// - src/AuthentikCredentialProvider/
// - src/AuthentikKSP/

#pragma once

#include <windows.h>

// ============================================================================
// Configuration Constants
// ============================================================================

// KSP Provider Name - must match registry registration
#define AUTHENTIK_KSP_NAME              L"Authentik Key Storage Provider"

// Shared memory configuration
#define AUTHENTIK_SHARED_MEM_NAME       L"Global\\AuthentikKSPKeyStore"
#define AUTHENTIK_SHARED_MEM_SIZE       (1024 * 1024)  // 1MB

// Mutex for synchronization
#define AUTHENTIK_MUTEX_NAME            L"Global\\AuthentikKSPMutex"

// Magic number for structure validation
#define AUTHENTIK_KEY_MAGIC             0x4B535041  // "AKSP" in little-endian

// Key container prefix (used when generating container names)
#define AUTHENTIK_KEY_PREFIX            L"AuthentikPKINIT_"

// Maximum values
#define AUTHENTIK_MAX_CONTAINER_NAME    256
#define AUTHENTIK_MAX_USERNAME          256
#define AUTHENTIK_MAX_CACHED_KEYS       16

// Default key validity in minutes
#define AUTHENTIK_DEFAULT_KEY_VALIDITY  60

// ============================================================================
// Shared Memory Structures
// ============================================================================

#pragma pack(push, 1)

//
// AUTHENTIK_KEY_ENTRY
// 
// Represents a single key stored in the shared memory key store.
// Keys are stored sequentially after the header.
//
typedef struct _AUTHENTIK_KEY_ENTRY {
    DWORD dwMagic;                                  // Must be AUTHENTIK_KEY_MAGIC
    DWORD dwFlags;                                  // Reserved for future use
    DWORD dwKeySpec;                                // AT_KEYEXCHANGE (1) or AT_SIGNATURE (2)
    FILETIME ftCreated;                             // When the key was stored
    FILETIME ftExpires;                             // When the key expires (auto-cleanup)
    WCHAR wszContainerName[AUTHENTIK_MAX_CONTAINER_NAME];  // Unique container name
    WCHAR wszUserName[AUTHENTIK_MAX_USERNAME];      // Associated username (for logging)
    DWORD cbPrivateKey;                             // Size of private key blob in bytes
    DWORD cbCertificate;                            // Size of certificate blob in bytes
    BYTE rgbData[1];                                // Variable: PrivateKey followed by Certificate
    
    // The rgbData field contains:
    // - BCRYPT_RSAPRIVATE_BLOB (cbPrivateKey bytes)
    // - DER-encoded X.509 certificate (cbCertificate bytes)
    
} AUTHENTIK_KEY_ENTRY, *PAUTHENTIK_KEY_ENTRY;

//
// AUTHENTIK_KEY_STORE_HEADER
//
// Header at the start of the shared memory region.
// Followed by zero or more AUTHENTIK_KEY_ENTRY structures.
//
typedef struct _AUTHENTIK_KEY_STORE_HEADER {
    DWORD dwMagic;                                  // Must be AUTHENTIK_KEY_MAGIC
    DWORD dwVersion;                                // Structure version (currently 1)
    DWORD cKeys;                                    // Number of keys currently stored
    DWORD cbTotalSize;                              // Total bytes used (header + all entries)
    
    // Keys follow immediately after this header
    // First key is at offset sizeof(AUTHENTIK_KEY_STORE_HEADER)
    
} AUTHENTIK_KEY_STORE_HEADER, *PAUTHENTIK_KEY_STORE_HEADER;

#pragma pack(pop)

// ============================================================================
// Helper Macros
// ============================================================================

// Calculate the size of a key entry given the data sizes
#define AUTHENTIK_KEY_ENTRY_SIZE(cbPrivateKey, cbCertificate) \
    (sizeof(AUTHENTIK_KEY_ENTRY) - 1 + (cbPrivateKey) + (cbCertificate))

// Get pointer to the first key entry after the header
#define AUTHENTIK_FIRST_KEY_ENTRY(pHeader) \
    ((PAUTHENTIK_KEY_ENTRY)((PBYTE)(pHeader) + sizeof(AUTHENTIK_KEY_STORE_HEADER)))

// Check if a pointer is within the valid key store region
#define AUTHENTIK_IS_VALID_PTR(pHeader, ptr) \
    ((PBYTE)(ptr) >= (PBYTE)(pHeader) && \
     (PBYTE)(ptr) < (PBYTE)(pHeader) + (pHeader)->cbTotalSize)

// ============================================================================
// Smart Card CSP Info Structure
// ============================================================================

//
// AUTHENTIK_SMARTCARD_CSP_INFO
//
// This structure is embedded in KERB_CERTIFICATE_LOGON.CspData
// It tells Windows how to find the private key for PKINIT signing.
//
#pragma pack(push, 1)
typedef struct _AUTHENTIK_SMARTCARD_CSP_INFO {
    DWORD dwCspInfoLen;                             // Total size of this structure
    DWORD MessageType;                              // Must be 1
    union {
        PVOID ContextInformation;                   // Not used
        ULONG64 SpaceHolderForWow64;                // Alignment for 32/64-bit
    };
    DWORD flags;                                    // Reserved (0)
    DWORD KeySpec;                                  // AT_KEYEXCHANGE (1) or AT_SIGNATURE (2)
    ULONG nCardNameOffset;                          // Offset to card name in bBuffer
    ULONG nReaderNameOffset;                        // Offset to reader name in bBuffer
    ULONG nContainerNameOffset;                     // Offset to container name in bBuffer
    ULONG nCSPNameOffset;                           // Offset to CSP/KSP name in bBuffer
    WCHAR bBuffer[1];                               // Variable: null-terminated strings
    
    // bBuffer layout (all strings are null-terminated WCHAR):
    // - Card name (e.g., "Authentik Virtual Card")
    // - Reader name (e.g., "Authentik Virtual Reader")
    // - Container name (e.g., "AuthentikPKINIT_{GUID}")
    // - CSP/KSP name (e.g., "Authentik Key Storage Provider")
    
} AUTHENTIK_SMARTCARD_CSP_INFO, *PAUTHENTIK_SMARTCARD_CSP_INFO;
#pragma pack(pop)

// ============================================================================
// KERB_CERTIFICATE_LOGON Constants
// ============================================================================

// Message type values for KERB_LOGON_SUBMIT_TYPE
#define AUTHENTIK_KerbCertificateLogon          13
#define AUTHENTIK_KerbCertificateUnlockLogon    15

// Flags for KERB_CERTIFICATE_LOGON
#ifndef KERB_CERTIFICATE_LOGON_FLAG_CHECK_DUPLICATES
#define KERB_CERTIFICATE_LOGON_FLAG_CHECK_DUPLICATES        0x1
#endif

#ifndef KERB_CERTIFICATE_LOGON_FLAG_USE_CERTIFICATE_INFO
#define KERB_CERTIFICATE_LOGON_FLAG_USE_CERTIFICATE_INFO    0x2
#endif

// ============================================================================
// Function Declarations (implemented in AuthentikKSP.dll)
// ============================================================================

#ifdef AUTHENTIK_KSP_EXPORTS
#define AUTHENTIK_API __declspec(dllexport)
#else
#define AUTHENTIK_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

//
// AuthentikKSP_StoreKey
//
// Stores a private key and certificate in the shared memory key store.
// Called by the credential provider after receiving a certificate.
//
// Parameters:
//   wszContainerName - Unique container name (e.g., "AuthentikPKINIT_{GUID}")
//   wszUserName      - Username for logging (optional, can be NULL)
//   pbPrivateKey     - BCRYPT_RSAPRIVATE_BLOB containing the private key
//   cbPrivateKey     - Size of private key blob in bytes
//   pbCertificate    - DER-encoded X.509 certificate
//   cbCertificate    - Size of certificate in bytes
//   dwKeySpec        - Key specification (AT_KEYEXCHANGE or AT_SIGNATURE)
//   dwValidityMinutes- How long the key should be valid (0 = default)
//
// Returns:
//   S_OK on success, error HRESULT on failure
//
AUTHENTIK_API HRESULT AuthentikKSP_StoreKey(
    _In_ LPCWSTR wszContainerName,
    _In_opt_ LPCWSTR wszUserName,
    _In_reads_bytes_(cbPrivateKey) const BYTE* pbPrivateKey,
    _In_ DWORD cbPrivateKey,
    _In_reads_bytes_(cbCertificate) const BYTE* pbCertificate,
    _In_ DWORD cbCertificate,
    _In_ DWORD dwKeySpec,
    _In_ DWORD dwValidityMinutes);

//
// AuthentikKSP_RemoveKey
//
// Removes a key from the shared memory key store.
// Called when authentication completes or fails.
//
AUTHENTIK_API HRESULT AuthentikKSP_RemoveKey(
    _In_ LPCWSTR wszContainerName);

//
// AuthentikKSP_KeyExists
//
// Checks if a key with the given container name exists and is not expired.
//
AUTHENTIK_API BOOL AuthentikKSP_KeyExists(
    _In_ LPCWSTR wszContainerName);

//
// AuthentikKSP_GetProviderName
//
// Returns the KSP provider name for use in KERB_SMARTCARD_CSP_INFO.
//
AUTHENTIK_API LPCWSTR AuthentikKSP_GetProviderName(void);

#ifdef __cplusplus
}
#endif

// ============================================================================
// Version Information
// ============================================================================

#define AUTHENTIK_SHARED_MEMORY_VERSION     1
#define AUTHENTIK_KSP_VERSION_MAJOR         1
#define AUTHENTIK_KSP_VERSION_MINOR         0

