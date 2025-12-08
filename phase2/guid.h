// guid.h
// GUID definitions for the Phase 2 credential provider (Passwordless)
// December 8, 2025

#pragma once

#include <guiddef.h>

// {A1B2C3D4-E5F6-4789-ABCD-EF0123456789}
// Phase 2: Passwordless certificate-based authentication
DEFINE_GUID(CLSID_AuthentikCredentialProvider,
    0xa1b2c3d4, 0xe5f6, 0x4789, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89);

// DLL reference counting
void DllAddRef();
void DllRelease();
