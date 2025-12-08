// Dll.cpp
// DLL entry point and COM registration - Phase 2 (Passwordless)
// December 8, 2025

// INITGUID must be defined before guiddef.h to instantiate GUIDs
#define INITGUID

#include <windows.h>
#include <initguid.h>
#include <unknwn.h>
#include <shlwapi.h>
#include <objbase.h>
#include <credentialprovider.h>
#include <strsafe.h>
#include <new>
#include "AuthentikCredentialProvider.h"
#include "Logger.h"
#include "guid.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")

// Global DLL instance handle
HINSTANCE g_hinst = nullptr;

// DLL reference count
long g_cDllRef = 0;

// DllMain
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        g_hinst = hModule;
        DisableThreadLibraryCalls(hModule);
        LOG("DLL_PROCESS_ATTACH - Phase 2 Passwordless CP");
        break;

    case DLL_PROCESS_DETACH:
        LOG("DLL_PROCESS_DETACH");
        break;
    }
    return TRUE;
}

// DLL reference counting
void DllAddRef()
{
    InterlockedIncrement(&g_cDllRef);
}

void DllRelease()
{
    InterlockedDecrement(&g_cDllRef);
}

// Class factory
class CClassFactory : public IClassFactory
{
public:
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv)
    {
        static const QITAB qit[] =
        {
            QITABENT(CClassFactory, IClassFactory),
            {0},
        };
        return QISearch(this, qit, riid, ppv);
    }

    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return InterlockedIncrement(&_cRef);
    }

    IFACEMETHODIMP_(ULONG) Release()
    {
        LONG cRef = InterlockedDecrement(&_cRef);
        if (!cRef)
        {
            delete this;
        }
        return cRef;
    }

    IFACEMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv)
    {
        HRESULT hr;
        if (!pUnkOuter)
        {
            hr = CAuthentikProvider_CreateInstance(riid, ppv);
        }
        else
        {
            *ppv = nullptr;
            hr = CLASS_E_NOAGGREGATION;
        }
        return hr;
    }

    IFACEMETHODIMP LockServer(BOOL bLock)
    {
        if (bLock)
        {
            DllAddRef();
        }
        else
        {
            DllRelease();
        }
        return S_OK;
    }

    CClassFactory() : _cRef(1)
    {
        DllAddRef();
    }

    ~CClassFactory()
    {
        DllRelease();
    }

private:
    LONG _cRef;
};

// DllGetClassObject
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    LOG("DllGetClassObject");

    HRESULT hr;
    if (rclsid == CLSID_AuthentikCredentialProvider)
    {
        CClassFactory* pClassFactory = new(std::nothrow) CClassFactory();
        if (pClassFactory)
        {
            hr = pClassFactory->QueryInterface(riid, ppv);
            pClassFactory->Release();
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    else
    {
        *ppv = nullptr;
        hr = CLASS_E_CLASSNOTAVAILABLE;
    }

    return hr;
}

// DllCanUnloadNow
STDAPI DllCanUnloadNow()
{
    return (g_cDllRef > 0) ? S_FALSE : S_OK;
}

// Helper to set registry key
static HRESULT SetRegistryKeyValue(
    HKEY hKeyRoot,
    PCWSTR pszKeyPath,
    PCWSTR pszValueName,
    PCWSTR pszData)
{
    HKEY hKey = nullptr;
    LONG lResult = RegCreateKeyExW(
        hKeyRoot, pszKeyPath, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);

    if (lResult == ERROR_SUCCESS)
    {
        if (pszData)
        {
            DWORD cbData = (DWORD)((wcslen(pszData) + 1) * sizeof(WCHAR));
            lResult = RegSetValueExW(hKey, pszValueName, 0, REG_SZ, (BYTE*)pszData, cbData);
        }
        RegCloseKey(hKey);
    }

    return HRESULT_FROM_WIN32(lResult);
}

// DllRegisterServer
STDAPI DllRegisterServer()
{
    LOG("DllRegisterServer");

    WCHAR szModule[MAX_PATH];
    if (GetModuleFileNameW(g_hinst, szModule, ARRAYSIZE(szModule)) == 0)
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    WCHAR szCLSID[64];
    StringFromGUID2(CLSID_AuthentikCredentialProvider, szCLSID, ARRAYSIZE(szCLSID));

    WCHAR szSubkey[MAX_PATH];
    HRESULT hr;

    // Register CLSID
    StringCchPrintfW(szSubkey, ARRAYSIZE(szSubkey), L"CLSID\\%s", szCLSID);
    hr = SetRegistryKeyValue(HKEY_CLASSES_ROOT, szSubkey, nullptr, L"AuthentikCredentialProviderV2");
    
    if (SUCCEEDED(hr))
    {
        StringCchPrintfW(szSubkey, ARRAYSIZE(szSubkey), L"CLSID\\%s\\InprocServer32", szCLSID);
        hr = SetRegistryKeyValue(HKEY_CLASSES_ROOT, szSubkey, nullptr, szModule);
        
        if (SUCCEEDED(hr))
        {
            hr = SetRegistryKeyValue(HKEY_CLASSES_ROOT, szSubkey, L"ThreadingModel", L"Apartment");
        }
    }

    // Register as credential provider
    if (SUCCEEDED(hr))
    {
        StringCchPrintfW(szSubkey, ARRAYSIZE(szSubkey),
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\%s",
            szCLSID);
        hr = SetRegistryKeyValue(HKEY_LOCAL_MACHINE, szSubkey, nullptr, L"AuthentikCredentialProviderV2");
    }

    // Create default configuration
    if (SUCCEEDED(hr))
    {
        HKEY hKey;
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\AuthentikCredentialProvider",
            0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr) == ERROR_SUCCESS)
        {
            // Only set defaults if not already configured
            DWORD dwType;
            DWORD dwSize = 0;
            if (RegQueryValueExW(hKey, L"CertIssuerServer", nullptr, &dwType, nullptr, &dwSize) != ERROR_SUCCESS)
            {
                // Set defaults
                RegSetValueExW(hKey, L"AuthentikServer", 0, REG_SZ, 
                    (BYTE*)L"authentik.test.local", 44);
                
                DWORD port = 443;
                RegSetValueExW(hKey, L"AuthentikPort", 0, REG_DWORD, (BYTE*)&port, sizeof(DWORD));
                
                RegSetValueExW(hKey, L"FlowSlug", 0, REG_SZ, 
                    (BYTE*)L"windows-otp-auth", 34);
                
                DWORD useHttps = 1;
                RegSetValueExW(hKey, L"UseHttps", 0, REG_DWORD, (BYTE*)&useHttps, sizeof(DWORD));
                
                RegSetValueExW(hKey, L"CertIssuerServer", 0, REG_SZ, 
                    (BYTE*)L"192.168.1.101", 28);
                
                port = 8443;
                RegSetValueExW(hKey, L"CertIssuerPort", 0, REG_DWORD, (BYTE*)&port, sizeof(DWORD));
                
                RegSetValueExW(hKey, L"Domain", 0, REG_SZ, 
                    (BYTE*)L"test.local", 22);
                
                RegSetValueExW(hKey, L"VSCPin", 0, REG_SZ, 
                    (BYTE*)L"12345678", 18);
                
                LOG("Default configuration created");
            }
            RegCloseKey(hKey);
        }
    }

    LOG("DllRegisterServer: 0x%08x", hr);
    return hr;
}

// DllUnregisterServer
STDAPI DllUnregisterServer()
{
    LOG("DllUnregisterServer");

    WCHAR szCLSID[64];
    StringFromGUID2(CLSID_AuthentikCredentialProvider, szCLSID, ARRAYSIZE(szCLSID));

    WCHAR szSubkey[MAX_PATH];

    // Unregister credential provider
    StringCchPrintfW(szSubkey, ARRAYSIZE(szSubkey),
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\%s",
        szCLSID);
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, szSubkey);

    // Unregister CLSID
    StringCchPrintfW(szSubkey, ARRAYSIZE(szSubkey), L"CLSID\\%s", szCLSID);
    RegDeleteTreeW(HKEY_CLASSES_ROOT, szSubkey);

    return S_OK;
}
