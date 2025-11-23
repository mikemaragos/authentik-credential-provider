// SecureString.h
// Secure string implementation that zeros memory on destruction
// Prevents password exposure in memory dumps

#pragma once

#include <windows.h>
#include <string>
#include <memory>

/// <summary>
/// Secure string class that automatically clears sensitive data from memory
/// Use this for passwords, OTP codes, and other sensitive strings
/// </summary>
class SecureString {
public:
    /// <summary>
    /// Default constructor - creates empty secure string
    /// </summary>
    SecureString();

    /// <summary>
    /// Construct from regular wide string
    /// </summary>
    /// <param name="str">Source string to copy</param>
    explicit SecureString(const std::wstring& str);

    /// <summary>
    /// Construct from C-style string
    /// </summary>
    /// <param name="str">Null-terminated wide character string</param>
    explicit SecureString(const wchar_t* str);

    /// <summary>
    /// Destructor - securely clears memory
    /// </summary>
    ~SecureString();

    // Prevent copying (to avoid accidental uncleared copies)
    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;

    // Allow moving
    SecureString(SecureString&& other) noexcept;
    SecureString& operator=(SecureString&& other) noexcept;

    /// <summary>
    /// Get C-style string (use with caution)
    /// </summary>
    const wchar_t* c_str() const;

    /// <summary>
    /// Get length in characters
    /// </summary>
    size_t length() const;

    /// <summary>
    /// Check if string is empty
    /// </summary>
    bool empty() const;

    /// <summary>
    /// Manually clear the string
    /// </summary>
    void clear();

    /// <summary>
    /// Compare with another secure string
    /// </summary>
    bool operator==(const SecureString& other) const;

    /// <summary>
    /// Compare with regular string (use with caution)
    /// </summary>
    bool operator==(const std::wstring& other) const;

private:
    wchar_t* _data;
    size_t _length;
    size_t _capacity;

    /// <summary>
    /// Securely zero memory
    /// </summary>
    void SecureClear();

    /// <summary>
    /// Allocate buffer
    /// </summary>
    void Allocate(size_t capacity);
};

// Implementation

inline SecureString::SecureString() 
    : _data(nullptr), _length(0), _capacity(0)
{
}

inline SecureString::SecureString(const std::wstring& str)
    : _data(nullptr), _length(0), _capacity(0)
{
    if (!str.empty()) {
        _length = str.length();
        Allocate(_length + 1);
        wmemcpy_s(_data, _capacity, str.c_str(), _length);
        _data[_length] = L'\0';
    }
}

inline SecureString::SecureString(const wchar_t* str)
    : _data(nullptr), _length(0), _capacity(0)
{
    if (str) {
        _length = wcslen(str);
        Allocate(_length + 1);
        wmemcpy_s(_data, _capacity, str, _length);
        _data[_length] = L'\0';
    }
}

inline SecureString::~SecureString()
{
    SecureClear();
}

inline SecureString::SecureString(SecureString&& other) noexcept
    : _data(other._data), _length(other._length), _capacity(other._capacity)
{
    other._data = nullptr;
    other._length = 0;
    other._capacity = 0;
}

inline SecureString& SecureString::operator=(SecureString&& other) noexcept
{
    if (this != &other) {
        SecureClear();
        
        _data = other._data;
        _length = other._length;
        _capacity = other._capacity;
        
        other._data = nullptr;
        other._length = 0;
        other._capacity = 0;
    }
    return *this;
}

inline const wchar_t* SecureString::c_str() const
{
    return _data ? _data : L"";
}

inline size_t SecureString::length() const
{
    return _length;
}

inline bool SecureString::empty() const
{
    return _length == 0;
}

inline void SecureString::clear()
{
    SecureClear();
}

inline bool SecureString::operator==(const SecureString& other) const
{
    if (_length != other._length) return false;
    if (_data == nullptr && other._data == nullptr) return true;
    if (_data == nullptr || other._data == nullptr) return false;
    return wmemcmp(_data, other._data, _length) == 0;
}

inline bool SecureString::operator==(const std::wstring& other) const
{
    if (_length != other.length()) return false;
    if (_data == nullptr && other.empty()) return true;
    if (_data == nullptr) return false;
    return wmemcmp(_data, other.c_str(), _length) == 0;
}

inline void SecureString::SecureClear()
{
    if (_data) {
        // Use SecureZeroMemory to prevent compiler optimization
        SecureZeroMemory(_data, _capacity * sizeof(wchar_t));
        delete[] _data;
        _data = nullptr;
    }
    _length = 0;
    _capacity = 0;
}

inline void SecureString::Allocate(size_t capacity)
{
    SecureClear();
    _capacity = capacity;
    _data = new wchar_t[_capacity];
    SecureZeroMemory(_data, _capacity * sizeof(wchar_t));
}
