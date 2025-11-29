// guid.h
// GUID definitions for the Authentik Passwordless Credential Provider

#pragma once

#include <guiddef.h>

// {A1B2C3D4-E5F6-4A5B-9C8D-7E6F5A4B3C2D}
// Authentik Passwordless Credential Provider CLSID
DEFINE_GUID(CLSID_AuthentikPasswordlessCP,
    0xa1b2c3d4, 0xe5f6, 0x4a5b, 0x9c, 0x8d, 0x7e, 0x6f, 0x5a, 0x4b, 0x3c, 0x2d);

// DLL reference counting
void DllAddRef();
void DllRelease();

// Global DLL instance
extern HINSTANCE g_hinst;
