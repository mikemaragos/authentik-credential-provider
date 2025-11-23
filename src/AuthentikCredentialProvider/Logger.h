// Logger.h
// Simple debug logging using OutputDebugString

#pragma once

#include <windows.h>
#include <stdio.h>
#include <strsafe.h>

// Enable logging in debug builds
#ifdef _DEBUG
#define ENABLE_LOGGING 1
#else
#define ENABLE_LOGGING 0
#endif

// Log macro
#if ENABLE_LOGGING
#define LOG(format, ...) LogMessage(__FUNCTION__, __LINE__, format, __VA_ARGS__)
#else
#define LOG(format, ...) ((void)0)
#endif

// Log function
inline void LogMessage(const char* function, int line, const char* format, ...)
{
#if ENABLE_LOGGING
    char buffer[1024];
    char message[1200];
    
    va_list args;
    va_start(args, format);
    vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
    va_end(args);
    
    _snprintf_s(message, sizeof(message), _TRUNCATE, 
        "[AuthentikCP] %s:%d - %s\n", function, line, buffer);
    
    OutputDebugStringA(message);
#endif
}
