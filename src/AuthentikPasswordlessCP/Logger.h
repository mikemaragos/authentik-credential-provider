// Logger.h
// Debug logging using OutputDebugString
// View logs with DebugView (Sysinternals) or Visual Studio debugger

#pragma once

#include <windows.h>
#include <stdio.h>
#include <strsafe.h>

// Always enable logging for now (disable in final production build)
#define ENABLE_LOGGING 1

// Log levels
enum LogLevel {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARN = 2,
    LOG_ERROR = 3
};

// Log macro shortcuts
#if ENABLE_LOGGING
#define LOG_D(format, ...) LogMessage(LOG_DEBUG, __FUNCTION__, __LINE__, format, __VA_ARGS__)
#define LOG_I(format, ...) LogMessage(LOG_INFO, __FUNCTION__, __LINE__, format, __VA_ARGS__)
#define LOG_W(format, ...) LogMessage(LOG_WARN, __FUNCTION__, __LINE__, format, __VA_ARGS__)
#define LOG_E(format, ...) LogMessage(LOG_ERROR, __FUNCTION__, __LINE__, format, __VA_ARGS__)
#define LOG(format, ...) LogMessage(LOG_INFO, __FUNCTION__, __LINE__, format, __VA_ARGS__)
#else
#define LOG_D(format, ...) ((void)0)
#define LOG_I(format, ...) ((void)0)
#define LOG_W(format, ...) ((void)0)
#define LOG_E(format, ...) ((void)0)
#define LOG(format, ...) ((void)0)
#endif

// Log function implementation
inline void LogMessage(LogLevel level, const char* function, int line, const char* format, ...)
{
#if ENABLE_LOGGING
    const char* levelStr;
    switch (level) {
        case LOG_DEBUG: levelStr = "DEBUG"; break;
        case LOG_INFO:  levelStr = "INFO "; break;
        case LOG_WARN:  levelStr = "WARN "; break;
        case LOG_ERROR: levelStr = "ERROR"; break;
        default:        levelStr = "?????"; break;
    }

    char buffer[2048];
    char message[2200];
    
    va_list args;
    va_start(args, format);
    vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
    va_end(args);
    
    // Get current time
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    _snprintf_s(message, sizeof(message), _TRUNCATE, 
        "[AuthentikPwdlessCP][%02d:%02d:%02d.%03d][%s] %s:%d - %s\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        levelStr, function, line, buffer);
    
    OutputDebugStringA(message);
#endif
}

// Log wide string helper
inline void LogMessageW(LogLevel level, const char* function, int line, const wchar_t* format, ...)
{
#if ENABLE_LOGGING
    const char* levelStr;
    switch (level) {
        case LOG_DEBUG: levelStr = "DEBUG"; break;
        case LOG_INFO:  levelStr = "INFO "; break;
        case LOG_WARN:  levelStr = "WARN "; break;
        case LOG_ERROR: levelStr = "ERROR"; break;
        default:        levelStr = "?????"; break;
    }

    wchar_t buffer[2048];
    char message[4400];
    char narrowBuffer[4096];
    
    va_list args;
    va_start(args, format);
    _vsnwprintf_s(buffer, ARRAYSIZE(buffer), _TRUNCATE, format, args);
    va_end(args);
    
    // Convert wide to narrow
    WideCharToMultiByte(CP_UTF8, 0, buffer, -1, narrowBuffer, sizeof(narrowBuffer), NULL, NULL);
    
    // Get current time
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    _snprintf_s(message, sizeof(message), _TRUNCATE, 
        "[AuthentikPwdlessCP][%02d:%02d:%02d.%03d][%s] %s:%d - %s\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        levelStr, function, line, narrowBuffer);
    
    OutputDebugStringA(message);
#endif
}

#define LOG_W_STR(format, ...) LogMessageW(LOG_INFO, __FUNCTION__, __LINE__, format, __VA_ARGS__)

// Log binary data as hex (useful for certificate debugging)
inline void LogHex(const char* label, const BYTE* data, DWORD length)
{
#if ENABLE_LOGGING
    if (length > 64) length = 64; // Limit output
    
    char hex[200];
    char* p = hex;
    for (DWORD i = 0; i < length && (p - hex) < sizeof(hex) - 4; i++) {
        sprintf_s(p, 4, "%02X ", data[i]);
        p += 3;
    }
    
    LOG_D("%s (%d bytes): %s%s", label, length, hex, length > 64 ? "..." : "");
#endif
}
