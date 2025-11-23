// ConfigurationManager.h
// Centralized configuration management with validation and secure storage

#pragma once

#include <windows.h>
#include <string>
#include <map>
#include <shared_mutex>
#include <functional>
#include <dpapi.h>

#pragma comment(lib, "Crypt32.lib")

/// <summary>
/// Centralized configuration manager
/// Provides validated, type-safe access to configuration settings
/// Supports hot-reload and secure storage of sensitive values
/// </summary>
class ConfigurationManager {
public:
    /// <summary>
    /// Get singleton instance
    /// </summary>
    static ConfigurationManager& Instance();

    /// <summary>
    /// Load configuration from registry
    /// </summary>
    HRESULT Load();

    /// <summary>
    /// Save configuration to registry
    /// </summary>
    HRESULT Save();

    /// <summary>
    /// Reload configuration (hot reload)
    /// </summary>
    HRESULT Reload();

    /// <summary>
    /// Validate current configuration
    /// </summary>
    bool Validate() const;

    // Configuration getters
    std::wstring GetServerUrl() const;
    INTERNET_PORT GetServerPort() const;
    std::wstring GetFlowSlug() const;
    bool GetUseHttps() const;
    DWORD GetRequestTimeout() const;
    int GetMaxRetries() const;

    // Configuration setters (with validation)
    HRESULT SetServerUrl(const std::wstring& url);
    HRESULT SetServerPort(INTERNET_PORT port);
    HRESULT SetFlowSlug(const std::wstring& slug);
    HRESULT SetUseHttps(bool useHttps);
    HRESULT SetRequestTimeout(DWORD timeoutMs);
    HRESULT SetMaxRetries(int maxRetries);

    /// <summary>
    /// Get secure (encrypted) configuration value
    /// </summary>
    HRESULT GetSecureValue(const std::wstring& key, std::wstring& value);

    /// <summary>
    /// Set secure (encrypted) configuration value
    /// </summary>
    HRESULT SetSecureValue(const std::wstring& key, const std::wstring& value);

    /// <summary>
    /// Register callback for configuration changes
    /// </summary>
    void RegisterChangeCallback(std::function<void()> callback);

private:
    ConfigurationManager();
    ~ConfigurationManager();

    // Prevent copying
    ConfigurationManager(const ConfigurationManager&) = delete;
    ConfigurationManager& operator=(const ConfigurationManager&) = delete;

    struct Configuration {
        std::wstring serverUrl;
        INTERNET_PORT serverPort;
        std::wstring flowSlug;
        bool useHttps;
        DWORD requestTimeout;
        int maxRetries;
    };

    Configuration _config;
    mutable std::shared_mutex _configMutex;
    std::vector<std::function<void()>> _changeCallbacks;

    static const wchar_t* REGISTRY_PATH;
    static const wchar_t* SECURE_REGISTRY_PATH;

    /// <summary>
    /// Load value from registry
    /// </summary>
    HRESULT LoadStringValue(HKEY hKey, const wchar_t* valueName, std::wstring& output);
    HRESULT LoadDwordValue(HKEY hKey, const wchar_t* valueName, DWORD& output);

    /// <summary>
    /// Save value to registry
    /// </summary>
    HRESULT SaveStringValue(HKEY hKey, const wchar_t* valueName, const std::wstring& value);
    HRESULT SaveDwordValue(HKEY hKey, const wchar_t* valueName, DWORD value);

    /// <summary>
    /// Encrypt/decrypt using DPAPI
    /// </summary>
    HRESULT EncryptData(const BYTE* pData, DWORD cbData, std::vector<BYTE>& encrypted);
    HRESULT DecryptData(const BYTE* pEncrypted, DWORD cbEncrypted, std::vector<BYTE>& decrypted);

    /// <summary>
    /// Validate individual settings
    /// </summary>
    bool ValidateServerUrl(const std::wstring& url) const;
    bool ValidateServerPort(INTERNET_PORT port) const;
    bool ValidateFlowSlug(const std::wstring& slug) const;

    /// <summary>
    /// Notify change callbacks
    /// </summary>
    void NotifyConfigurationChanged();
};

// Registry paths
const wchar_t* ConfigurationManager::REGISTRY_PATH = L"SOFTWARE\\AuthentikCredentialProvider";
const wchar_t* ConfigurationManager::SECURE_REGISTRY_PATH = L"SOFTWARE\\AuthentikCredentialProvider\\Secure";

// Singleton instance
inline ConfigurationManager& ConfigurationManager::Instance()
{
    static ConfigurationManager instance;
    return instance;
}

// Constructor
inline ConfigurationManager::ConfigurationManager()
{
    // Set defaults
    _config.serverUrl = L"authentik.test.local";
    _config.serverPort = 443;
    _config.flowSlug = L"windows-otp-auth";
    _config.useHttps = true;
    _config.requestTimeout = 30000; // 30 seconds
    _config.maxRetries = 3;
}

// Destructor
inline ConfigurationManager::~ConfigurationManager()
{
}

// Load configuration
inline HRESULT ConfigurationManager::Load()
{
    std::unique_lock<std::shared_mutex> lock(_configMutex);

    HKEY hKey = nullptr;
    LONG result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        REGISTRY_PATH,
        0,
        KEY_READ,
        &hKey);

    if (result != ERROR_SUCCESS) {
        // Registry key doesn't exist - use defaults
        return S_FALSE;
    }

    HRESULT hr = S_OK;

    // Load configuration values
    LoadStringValue(hKey, L"ServerUrl", _config.serverUrl);
    
    DWORD port = 443;
    if (SUCCEEDED(LoadDwordValue(hKey, L"ServerPort", port))) {
        _config.serverPort = (INTERNET_PORT)port;
    }

    LoadStringValue(hKey, L"FlowSlug", _config.flowSlug);

    DWORD useHttps = 1;
    if (SUCCEEDED(LoadDwordValue(hKey, L"UseHttps", useHttps))) {
        _config.useHttps = (useHttps != 0);
    }

    DWORD timeout = 30000;
    if (SUCCEEDED(LoadDwordValue(hKey, L"RequestTimeout", timeout))) {
        _config.requestTimeout = timeout;
    }

    DWORD maxRetries = 3;
    if (SUCCEEDED(LoadDwordValue(hKey, L"MaxRetries", maxRetries))) {
        _config.maxRetries = (int)maxRetries;
    }

    RegCloseKey(hKey);

    // Validate loaded configuration
    if (!Validate()) {
        return E_FAIL;
    }

    return hr;
}

// Save configuration
inline HRESULT ConfigurationManager::Save()
{
    std::shared_lock<std::shared_mutex> lock(_configMutex);

    HKEY hKey = nullptr;
    LONG result = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        REGISTRY_PATH,
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        nullptr,
        &hKey,
        nullptr);

    if (result != ERROR_SUCCESS) {
        return HRESULT_FROM_WIN32(result);
    }

    HRESULT hr = S_OK;

    // Save values
    hr = SaveStringValue(hKey, L"ServerUrl", _config.serverUrl);
    if (FAILED(hr)) goto cleanup;

    hr = SaveDwordValue(hKey, L"ServerPort", _config.serverPort);
    if (FAILED(hr)) goto cleanup;

    hr = SaveStringValue(hKey, L"FlowSlug", _config.flowSlug);
    if (FAILED(hr)) goto cleanup;

    hr = SaveDwordValue(hKey, L"UseHttps", _config.useHttps ? 1 : 0);
    if (FAILED(hr)) goto cleanup;

    hr = SaveDwordValue(hKey, L"RequestTimeout", _config.requestTimeout);
    if (FAILED(hr)) goto cleanup;

    hr = SaveDwordValue(hKey, L"MaxRetries", _config.maxRetries);
    if (FAILED(hr)) goto cleanup;

cleanup:
    RegCloseKey(hKey);
    return hr;
}

// Reload configuration
inline HRESULT ConfigurationManager::Reload()
{
    HRESULT hr = Load();
    if (SUCCEEDED(hr)) {
        NotifyConfigurationChanged();
    }
    return hr;
}

// Validate configuration
inline bool ConfigurationManager::Validate() const
{
    std::shared_lock<std::shared_mutex> lock(_configMutex);

    if (!ValidateServerUrl(_config.serverUrl)) return false;
    if (!ValidateServerPort(_config.serverPort)) return false;
    if (!ValidateFlowSlug(_config.flowSlug)) return false;
    if (_config.requestTimeout == 0 || _config.requestTimeout > 300000) return false;
    if (_config.maxRetries < 0 || _config.maxRetries > 10) return false;

    return true;
}

// Getters
inline std::wstring ConfigurationManager::GetServerUrl() const
{
    std::shared_lock<std::shared_mutex> lock(_configMutex);
    return _config.serverUrl;
}

inline INTERNET_PORT ConfigurationManager::GetServerPort() const
{
    std::shared_lock<std::shared_mutex> lock(_configMutex);
    return _config.serverPort;
}

inline std::wstring ConfigurationManager::GetFlowSlug() const
{
    std::shared_lock<std::shared_mutex> lock(_configMutex);
    return _config.flowSlug;
}

inline bool ConfigurationManager::GetUseHttps() const
{
    std::shared_lock<std::shared_mutex> lock(_configMutex);
    return _config.useHttps;
}

inline DWORD ConfigurationManager::GetRequestTimeout() const
{
    std::shared_lock<std::shared_mutex> lock(_configMutex);
    return _config.requestTimeout;
}

inline int ConfigurationManager::GetMaxRetries() const
{
    std::shared_lock<std::shared_mutex> lock(_configMutex);
    return _config.maxRetries;
}

// Setters with validation
inline HRESULT ConfigurationManager::SetServerUrl(const std::wstring& url)
{
    if (!ValidateServerUrl(url)) {
        return E_INVALIDARG;
    }

    std::unique_lock<std::shared_mutex> lock(_configMutex);
    _config.serverUrl = url;
    NotifyConfigurationChanged();
    
    return S_OK;
}

inline HRESULT ConfigurationManager::SetServerPort(INTERNET_PORT port)
{
    if (!ValidateServerPort(port)) {
        return E_INVALIDARG;
    }

    std::unique_lock<std::shared_mutex> lock(_configMutex);
    _config.serverPort = port;
    NotifyConfigurationChanged();
    
    return S_OK;
}

inline HRESULT ConfigurationManager::SetFlowSlug(const std::wstring& slug)
{
    if (!ValidateFlowSlug(slug)) {
        return E_INVALIDARG;
    }

    std::unique_lock<std::shared_mutex> lock(_configMutex);
    _config.flowSlug = slug;
    NotifyConfigurationChanged();
    
    return S_OK;
}

inline HRESULT ConfigurationManager::SetUseHttps(bool useHttps)
{
    std::unique_lock<std::shared_mutex> lock(_configMutex);
    _config.useHttps = useHttps;
    NotifyConfigurationChanged();
    
    return S_OK;
}

inline HRESULT ConfigurationManager::SetRequestTimeout(DWORD timeoutMs)
{
    if (timeoutMs == 0 || timeoutMs > 300000) {
        return E_INVALIDARG;
    }

    std::unique_lock<std::shared_mutex> lock(_configMutex);
    _config.requestTimeout = timeoutMs;
    NotifyConfigurationChanged();
    
    return S_OK;
}

inline HRESULT ConfigurationManager::SetMaxRetries(int maxRetries)
{
    if (maxRetries < 0 || maxRetries > 10) {
        return E_INVALIDARG;
    }

    std::unique_lock<std::shared_mutex> lock(_configMutex);
    _config.maxRetries = maxRetries;
    NotifyConfigurationChanged();
    
    return S_OK;
}

// Secure value management
inline HRESULT ConfigurationManager::GetSecureValue(const std::wstring& key, std::wstring& value)
{
    HKEY hKey = nullptr;
    LONG result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        SECURE_REGISTRY_PATH,
        0,
        KEY_READ,
        &hKey);

    if (result != ERROR_SUCCESS) {
        return HRESULT_FROM_WIN32(result);
    }

    // Read encrypted data
    DWORD cbData = 0;
    result = RegQueryValueExW(hKey, key.c_str(), nullptr, nullptr, nullptr, &cbData);
    
    if (result != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return HRESULT_FROM_WIN32(result);
    }

    std::vector<BYTE> encryptedData(cbData);
    result = RegQueryValueExW(hKey, key.c_str(), nullptr, nullptr, &encryptedData[0], &cbData);
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        return HRESULT_FROM_WIN32(result);
    }

    // Decrypt
    std::vector<BYTE> decrypted;
    HRESULT hr = DecryptData(&encryptedData[0], cbData, decrypted);
    
    if (FAILED(hr)) {
        return hr;
    }

    // Convert to string
    value = std::wstring((wchar_t*)&decrypted[0], decrypted.size() / sizeof(wchar_t));
    
    return S_OK;
}

inline HRESULT ConfigurationManager::SetSecureValue(const std::wstring& key, const std::wstring& value)
{
    // Encrypt data
    std::vector<BYTE> encrypted;
    HRESULT hr = EncryptData(
        (const BYTE*)value.c_str(),
        (DWORD)(value.length() * sizeof(wchar_t)),
        encrypted);

    if (FAILED(hr)) {
        return hr;
    }

    // Create/open registry key
    HKEY hKey = nullptr;
    LONG result = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        SECURE_REGISTRY_PATH,
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        nullptr,
        &hKey,
        nullptr);

    if (result != ERROR_SUCCESS) {
        return HRESULT_FROM_WIN32(result);
    }

    // Write encrypted data
    result = RegSetValueExW(
        hKey,
        key.c_str(),
        0,
        REG_BINARY,
        &encrypted[0],
        (DWORD)encrypted.size());

    RegCloseKey(hKey);

    return HRESULT_FROM_WIN32(result);
}

// Helper functions
inline HRESULT ConfigurationManager::LoadStringValue(HKEY hKey, const wchar_t* valueName, std::wstring& output)
{
    WCHAR buffer[256];
    DWORD bufferSize = sizeof(buffer);
    
    LONG result = RegQueryValueExW(hKey, valueName, nullptr, nullptr, (LPBYTE)buffer, &bufferSize);
    
    if (result == ERROR_SUCCESS) {
        output = buffer;
        return S_OK;
    }
    
    return HRESULT_FROM_WIN32(result);
}

inline HRESULT ConfigurationManager::LoadDwordValue(HKEY hKey, const wchar_t* valueName, DWORD& output)
{
    DWORD value;
    DWORD valueSize = sizeof(DWORD);
    
    LONG result = RegQueryValueExW(hKey, valueName, nullptr, nullptr, (LPBYTE)&value, &valueSize);
    
    if (result == ERROR_SUCCESS) {
        output = value;
        return S_OK;
    }
    
    return HRESULT_FROM_WIN32(result);
}

inline HRESULT ConfigurationManager::SaveStringValue(HKEY hKey, const wchar_t* valueName, const std::wstring& value)
{
    DWORD cbData = (DWORD)((value.length() + 1) * sizeof(wchar_t));
    
    LONG result = RegSetValueExW(
        hKey,
        valueName,
        0,
        REG_SZ,
        (const BYTE*)value.c_str(),
        cbData);
    
    return HRESULT_FROM_WIN32(result);
}

inline HRESULT ConfigurationManager::SaveDwordValue(HKEY hKey, const wchar_t* valueName, DWORD value)
{
    LONG result = RegSetValueExW(
        hKey,
        valueName,
        0,
        REG_DWORD,
        (const BYTE*)&value,
        sizeof(DWORD));
    
    return HRESULT_FROM_WIN32(result);
}

inline HRESULT ConfigurationManager::EncryptData(const BYTE* pData, DWORD cbData, std::vector<BYTE>& encrypted)
{
    DATA_BLOB dataIn;
    dataIn.pbData = const_cast<BYTE*>(pData);
    dataIn.cbData = cbData;

    DATA_BLOB dataOut;
    
    if (!CryptProtectData(
        &dataIn,
        L"AuthentikCredentialProvider",
        nullptr,
        nullptr,
        nullptr,
        CRYPTPROTECT_LOCAL_MACHINE,
        &dataOut))
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    encrypted.assign(dataOut.pbData, dataOut.pbData + dataOut.cbData);
    LocalFree(dataOut.pbData);

    return S_OK;
}

inline HRESULT ConfigurationManager::DecryptData(const BYTE* pEncrypted, DWORD cbEncrypted, std::vector<BYTE>& decrypted)
{
    DATA_BLOB dataIn;
    dataIn.pbData = const_cast<BYTE*>(pEncrypted);
    dataIn.cbData = cbEncrypted;

    DATA_BLOB dataOut;
    
    if (!CryptUnprotectData(
        &dataIn,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        CRYPTPROTECT_LOCAL_MACHINE,
        &dataOut))
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    decrypted.assign(dataOut.pbData, dataOut.pbData + dataOut.cbData);
    LocalFree(dataOut.pbData);

    return S_OK;
}

inline bool ConfigurationManager::ValidateServerUrl(const std::wstring& url) const
{
    if (url.empty() || url.length() > 255) {
        return false;
    }

    // Basic validation - should not contain invalid characters
    for (wchar_t c : url) {
        if (c == L'\0' || c == L' ' || c == L'\n' || c == L'\r') {
            return false;
        }
    }

    return true;
}

inline bool ConfigurationManager::ValidateServerPort(INTERNET_PORT port) const
{
    return port > 0 && port <= 65535;
}

inline bool ConfigurationManager::ValidateFlowSlug(const std::wstring& slug) const
{
    if (slug.empty() || slug.length() > 100) {
        return false;
    }

    // Flow slug should be alphanumeric with hyphens
    for (wchar_t c : slug) {
        if (!iswalnum(c) && c != L'-' && c != L'_') {
            return false;
        }
    }

    return true;
}

inline void ConfigurationManager::RegisterChangeCallback(std::function<void()> callback)
{
    _changeCallbacks.push_back(callback);
}

inline void ConfigurationManager::NotifyConfigurationChanged()
{
    for (auto& callback : _changeCallbacks) {
        callback();
    }
}
