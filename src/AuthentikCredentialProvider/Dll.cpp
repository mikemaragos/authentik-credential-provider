// Dll.cpp
// DLL entry point and COM registration for Authentik Passwordless Credential Provider

#include <windows.h>
#include <unknwn.h>
#include <credentialprovider.h>
#include <strsafe.h>
#include <shlwapi.h>
#include "AuthentikCredentialProvider.h"
#include "Logger.h"
#include "guid.h"

#pragma comment(lib, "Shlwapi.lib")

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
        LOG("DLL_PROCESS_ATTACH - Authentik Passwordless Credential Provider");
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
    if (rclsid == CLSID_AuthentikPasswordlessCP)
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
    }

    return HRESULT_FROM_WIN32(lResult);
}

static HRESULT SetRegistryKeyValueDword(
    HKEY hKeyRoot,
    PCWSTR pszKeyPath,
    PCWSTR pszValueName,
    DWORD dwData)
{
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
        lResult = RegSetValueExW(
            hKey,
            pszValueName,
            0,
            REG_DWORD,
            (BYTE*)&dwData,
            sizeof(DWORD));

        RegCloseKey(hKey);
    }

    return HRESULT_FROM_WIN32(lResult);
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
        LOG_E("GetModuleFileName failed: 0x%08x", hr);
        return hr;
    }

    // Get CLSID string
    WCHAR szCLSID[64];
    StringFromGUID2(CLSID_AuthentikPasswordlessCP, szCLSID, ARRAYSIZE(szCLSID));

    WCHAR szSubkey[MAX_PATH];

    // Register CLSID
    StringCchPrintfW(szSubkey, ARRAYSIZE(szSubkey), L"CLSID\\%s", szCLSID);

    hr = SetRegistryKeyValue(HKEY_CLASSES_ROOT, szSubkey, nullptr, L"Authentik Passwordless Credential Provider");
    if (FAILED(hr))
    {
        LOG_E("Failed to register CLSID: 0x%08x", hr);
        return hr;
    }

    StringCchPrintfW(szSubkey, ARRAYSIZE(szSubkey), L"CLSID\\%s\\InprocServer32", szCLSID);
    hr = SetRegistryKeyValue(HKEY_CLASSES_ROOT, szSubkey, nullptr, szModule);
    if (FAILED(hr))
    {
        LOG_E("Failed to register InprocServer32: 0x%08x", hr);
        return hr;
    }

    hr = SetRegistryKeyValue(HKEY_CLASSES_ROOT, szSubkey, L"ThreadingModel", L"Apartment");
    if (FAILED(hr))
    {
        LOG_E("Failed to set ThreadingModel: 0x%08x", hr);
        return hr;
    }

    // Register as credential provider
    StringCchPrintfW(szSubkey, ARRAYSIZE(szSubkey),
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\%s",
        szCLSID);

    hr = SetRegistryKeyValue(HKEY_LOCAL_MACHINE, szSubkey, nullptr, L"Authentik Passwordless Credential Provider");
    if (FAILED(hr))
    {
        LOG_E("Failed to register as credential provider: 0x%08x", hr);
        return hr;
    }

    // Create default configuration
    hr = SetRegistryKeyValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\AuthentikPasswordlessCP", L"ServerUrl", L"authentik.test.local");
    if (SUCCEEDED(hr))
    {
        SetRegistryKeyValueDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\AuthentikPasswordlessCP", L"ServerPort", 443);
        SetRegistryKeyValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\AuthentikPasswordlessCP", L"FlowSlug", L"windows-passwordless");
        SetRegistryKeyValueDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\AuthentikPasswordlessCP", L"UseHttps", 1);
        SetRegistryKeyValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\AuthentikPasswordlessCP", L"Domain", L"TEST");
        SetRegistryKeyValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\AuthentikPasswordlessCP", L"DomainFQDN", L"test.local");
        SetRegistryKeyValueDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\AuthentikPasswordlessCP", L"CertValidMinutes", 5);
        SetRegistryKeyValueDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\AuthentikPasswordlessCP", L"IgnoreCertErrors", 1);
    }

    LOG("DllRegisterServer succeeded - CLSID: %S", szCLSID);
    return S_OK;
}

// DllUnregisterServer - Unregister the COM server and credential provider
STDAPI DllUnregisterServer()
{
    LOG("DllUnregisterServer");

    HRESULT hr = S_OK;

    WCHAR szCLSID[64];
    StringFromGUID2(CLSID_AuthentikPasswordlessCP, szCLSID, ARRAYSIZE(szCLSID));

    // Unregister credential provider
    WCHAR szSubkey[MAX_PATH];
    StringCchPrintfW(szSubkey, ARRAYSIZE(szSubkey),
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\%s",
        szCLSID);

    LONG lResult = RegDeleteTreeW(HKEY_LOCAL_MACHINE, szSubkey);
    if (lResult != ERROR_SUCCESS && lResult != ERROR_FILE_NOT_FOUND)
    {
        hr = HRESULT_FROM_WIN32(lResult);
        LOG_W("Failed to unregister credential provider: 0x%08x", hr);
    }

    // Unregister CLSID
    StringCchPrintfW(szSubkey, ARRAYSIZE(szSubkey), L"CLSID\\%s", szCLSID);
    lResult = RegDeleteTreeW(HKEY_CLASSES_ROOT, szSubkey);
    if (lResult != ERROR_SUCCESS && lResult != ERROR_FILE_NOT_FOUND)
    {
        hr = HRESULT_FROM_WIN32(lResult);
        LOG_W("Failed to unregister CLSID: 0x%08x", hr);
    }

    // Optionally remove configuration
    // RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\AuthentikPasswordlessCP");

    LOG("DllUnregisterServer returning 0x%08x", hr);
    return hr;
}
