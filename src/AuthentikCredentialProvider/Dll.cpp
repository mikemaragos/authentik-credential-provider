// Dll.cpp
// DLL entry point and COM registration

#include <windows.h>
#include <unknwn.h>
#include <credentialprovider.h>
#include "AuthentikCredentialProvider.h"
#include "Logger.h"
#include "guid.h"

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
        LOG("DLL_PROCESS_ATTACH");
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
    // IUnknown
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

    // IClassFactory
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

// DllGetClassObject - Called by COM to get class factory
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    LOG("DllGetClassObject called");

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

    LOG("DllGetClassObject returning 0x%08x", hr);
    return hr;
}

// DllCanUnloadNow - Called by COM to determine if DLL can be unloaded
STDAPI DllCanUnloadNow()
{
    HRESULT hr = (g_cDllRef > 0) ? S_FALSE : S_OK;
    LOG("DllCanUnloadNow: ref count = %d, returning 0x%08x", g_cDllRef, hr);
    return hr;
}

// Helper function to set registry key value
static HRESULT SetRegistryKeyValue(
    HKEY hKeyRoot,
    PCWSTR pszKeyPath,
    PCWSTR pszValueName,
    PCWSTR pszData)
{
    HRESULT hr;
    HKEY hKey = nullptr;

    LONG lResult = RegCreateKeyExW(
        hKeyRoot,
        pszKeyPath,
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        nullptr,
        &hKey,
        nullptr);

    if (lResult == ERROR_SUCCESS)
    {
        if (pszData)
        {
            DWORD cbData = (DWORD)((wcslen(pszData) + 1) * sizeof(WCHAR));
            lResult = RegSetValueExW(
                hKey,
                pszValueName,
                0,
                REG_SZ,
                (BYTE*)pszData,
                cbData);
        }

        RegCloseKey(hKey);
        hr = HRESULT_FROM_WIN32(lResult);
    }
    else
    {
        hr = HRESULT_FROM_WIN32(lResult);
    }

    return hr;
}

// DllRegisterServer - Register the COM server and credential provider
STDAPI DllRegisterServer()
{
    LOG("DllRegisterServer");

    HRESULT hr;

    // Get module file name
    WCHAR szModule[MAX_PATH];
    if (GetModuleFileNameW(g_hinst, szModule, ARRAYSIZE(szModule)) == 0)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        return hr;
    }

    // Register CLSID
    WCHAR szCLSID[MAX_PATH];
    StringFromGUID2(CLSID_AuthentikCredentialProvider, szCLSID, ARRAYSIZE(szCLSID));

    WCHAR szSubkey[MAX_PATH];
    StringCchPrintfW(szSubkey, ARRAYSIZE(szSubkey), L"CLSID\\%s", szCLSID);

    hr = SetRegistryKeyValue(HKEY_CLASSES_ROOT, szSubkey, nullptr, L"AuthentikCredentialProvider");
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
        
        hr = SetRegistryKeyValue(HKEY_LOCAL_MACHINE, szSubkey, nullptr, L"AuthentikCredentialProvider");
    }

    LOG("DllRegisterServer returning 0x%08x", hr);
    return hr;
}

// DllUnregisterServer - Unregister the COM server and credential provider
STDAPI DllUnregisterServer()
{
    LOG("DllUnregisterServer");

    HRESULT hr = S_OK;

    WCHAR szCLSID[MAX_PATH];
    StringFromGUID2(CLSID_AuthentikCredentialProvider, szCLSID, ARRAYSIZE(szCLSID));

    // Unregister credential provider
    WCHAR szSubkey[MAX_PATH];
    StringCchPrintfW(szSubkey, ARRAYSIZE(szSubkey),
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\%s",
        szCLSID);
    
    LONG lResult = RegDeleteTreeW(HKEY_LOCAL_MACHINE, szSubkey);
    if (lResult != ERROR_SUCCESS && lResult != ERROR_FILE_NOT_FOUND)
    {
        hr = HRESULT_FROM_WIN32(lResult);
    }

    // Unregister CLSID
    StringCchPrintfW(szSubkey, ARRAYSIZE(szSubkey), L"CLSID\\%s", szCLSID);
    lResult = RegDeleteTreeW(HKEY_CLASSES_ROOT, szSubkey);
    if (lResult != ERROR_SUCCESS && lResult != ERROR_FILE_NOT_FOUND)
    {
        hr = HRESULT_FROM_WIN32(lResult);
    }

    LOG("DllUnregisterServer returning 0x%08x", hr);
    return hr;
}
