// KSPSharedMemory.h
// Helper class for Credential Provider to communicate with KSP via shared memory

#pragma once

#include <windows.h>
#include <string>

// Shared memory name for credential provider communication
#define AUTHENTIK_SHARED_MEMORY_NAME L"Global\\AuthentikKSPSharedMemory"
#define AUTHENTIK_MUTEX_NAME L"Global\\AuthentikKSPMutex"

// Maximum certificate/key sizes
#define MAX_CERTIFICATE_SIZE 8192
#define MAX_PRIVATE_KEY_SIZE 4096
#define MAX_USERNAME_SIZE 256

// Shared memory structure
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
#define AUTHENTIK_SHARED_VERSION 1

class CKSPSharedMemory
{
public:
    CKSPSharedMemory();
    ~CKSPSharedMemory();

    // Initialize shared memory (call from credential provider)
    HRESULT Initialize();

    // Set certificate and key data for KSP to use
    HRESULT SetCertificateData(
        const std::wstring& username,
        const BYTE* pbCertificate,
        DWORD cbCertificate,
        const BYTE* pbPrivateKey,
        DWORD cbPrivateKey,
        DWORD dwKeySpec);

    // Wait for KSP to consume the data
    HRESULT WaitForConsumption(DWORD dwTimeoutMs = 5000);

    // Clear shared memory
    void Clear();

    // Check if data was consumed
    BOOL WasDataConsumed() const;

private:
    HANDLE m_hSharedMemory;
    HANDLE m_hMutex;
    PAUTHENTIK_SHARED_DATA m_pData;
    BOOL m_bInitialized;
};

// Implementation

inline CKSPSharedMemory::CKSPSharedMemory() :
    m_hSharedMemory(nullptr),
    m_hMutex(nullptr),
    m_pData(nullptr),
    m_bInitialized(FALSE)
{
}

inline CKSPSharedMemory::~CKSPSharedMemory()
{
    Clear();

    if (m_pData)
    {
        UnmapViewOfFile(m_pData);
        m_pData = nullptr;
    }

    if (m_hSharedMemory)
    {
        CloseHandle(m_hSharedMemory);
        m_hSharedMemory = nullptr;
    }

    if (m_hMutex)
    {
        CloseHandle(m_hMutex);
        m_hMutex = nullptr;
    }
}

inline HRESULT CKSPSharedMemory::Initialize()
{
    if (m_bInitialized)
    {
        return S_OK;
    }

    // Create security attributes for shared memory
    // Need to allow access from SYSTEM (where LSA runs)
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE); // Allow all access

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;

    // Create mutex
    m_hMutex = CreateMutexW(&sa, FALSE, AUTHENTIK_MUTEX_NAME);
    if (!m_hMutex)
    {
        DWORD dwError = GetLastError();
        if (dwError == ERROR_ACCESS_DENIED)
        {
            // Try to open existing
            m_hMutex = OpenMutexW(SYNCHRONIZE, FALSE, AUTHENTIK_MUTEX_NAME);
        }
        
        if (!m_hMutex)
        {
            return HRESULT_FROM_WIN32(GetLastError());
        }
    }

    // Create shared memory
    m_hSharedMemory = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        &sa,
        PAGE_READWRITE,
        0,
        sizeof(AUTHENTIK_SHARED_DATA),
        AUTHENTIK_SHARED_MEMORY_NAME);

    if (!m_hSharedMemory)
    {
        DWORD dwError = GetLastError();
        CloseHandle(m_hMutex);
        m_hMutex = nullptr;
        return HRESULT_FROM_WIN32(dwError);
    }

    // Map view
    m_pData = (PAUTHENTIK_SHARED_DATA)MapViewOfFile(
        m_hSharedMemory,
        FILE_MAP_ALL_ACCESS,
        0, 0,
        sizeof(AUTHENTIK_SHARED_DATA));

    if (!m_pData)
    {
        DWORD dwError = GetLastError();
        CloseHandle(m_hSharedMemory);
        m_hSharedMemory = nullptr;
        CloseHandle(m_hMutex);
        m_hMutex = nullptr;
        return HRESULT_FROM_WIN32(dwError);
    }

    // Initialize structure
    ZeroMemory(m_pData, sizeof(AUTHENTIK_SHARED_DATA));
    m_pData->dwMagic = AUTHENTIK_SHARED_MAGIC;
    m_pData->dwVersion = AUTHENTIK_SHARED_VERSION;

    m_bInitialized = TRUE;
    return S_OK;
}

inline HRESULT CKSPSharedMemory::SetCertificateData(
    const std::wstring& username,
    const BYTE* pbCertificate,
    DWORD cbCertificate,
    const BYTE* pbPrivateKey,
    DWORD cbPrivateKey,
    DWORD dwKeySpec)
{
    if (!m_bInitialized)
    {
        HRESULT hr = Initialize();
        if (FAILED(hr)) return hr;
    }

    if (cbCertificate > MAX_CERTIFICATE_SIZE || cbPrivateKey > MAX_PRIVATE_KEY_SIZE)
    {
        return E_INVALIDARG;
    }

    // Wait for mutex
    DWORD waitResult = WaitForSingleObject(m_hMutex, 5000);
    if (waitResult != WAIT_OBJECT_0)
    {
        return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
    }

    __try
    {
        // Clear previous data
        ZeroMemory(m_pData->rgbCertificate, sizeof(m_pData->rgbCertificate));
        ZeroMemory(m_pData->rgbPrivateKey, sizeof(m_pData->rgbPrivateKey));
        ZeroMemory(m_pData->wszUsername, sizeof(m_pData->wszUsername));

        // Set new data
        wcsncpy_s(m_pData->wszUsername, MAX_USERNAME_SIZE, username.c_str(), _TRUNCATE);
        
        CopyMemory(m_pData->rgbCertificate, pbCertificate, cbCertificate);
        m_pData->cbCertificate = cbCertificate;
        
        CopyMemory(m_pData->rgbPrivateKey, pbPrivateKey, cbPrivateKey);
        m_pData->cbPrivateKey = cbPrivateKey;
        
        m_pData->dwKeySpec = dwKeySpec;
        m_pData->dwError = 0;
        m_pData->bDataConsumed = FALSE;
        
        // Mark data as ready (this signals KSP)
        m_pData->bDataReady = TRUE;
    }
    __finally
    {
        ReleaseMutex(m_hMutex);
    }

    return S_OK;
}

inline HRESULT CKSPSharedMemory::WaitForConsumption(DWORD dwTimeoutMs)
{
    if (!m_bInitialized || !m_pData)
    {
        return E_FAIL;
    }

    DWORD dwStartTime = GetTickCount();
    
    while ((GetTickCount() - dwStartTime) < dwTimeoutMs)
    {
        if (m_pData->bDataConsumed)
        {
            return S_OK;
        }
        Sleep(50);
    }

    return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
}

inline void CKSPSharedMemory::Clear()
{
    if (!m_bInitialized || !m_pData)
    {
        return;
    }

    DWORD waitResult = WaitForSingleObject(m_hMutex, 1000);
    if (waitResult == WAIT_OBJECT_0)
    {
        SecureZeroMemory(m_pData->rgbPrivateKey, sizeof(m_pData->rgbPrivateKey));
        SecureZeroMemory(m_pData->rgbCertificate, sizeof(m_pData->rgbCertificate));
        m_pData->bDataReady = FALSE;
        m_pData->bDataConsumed = FALSE;
        
        ReleaseMutex(m_hMutex);
    }
}

inline BOOL CKSPSharedMemory::WasDataConsumed() const
{
    return m_pData && m_pData->bDataConsumed;
}
