// guid.cpp
// GUID definition for the credential provider

#include <windows.h>
#include <initguid.h>

// {8B7C4F9E-2A3D-4E5F-9C1B-7D8E6F4A5B3C}
// Explicitly define the GUID here
DEFINE_GUID(CLSID_AuthentikCredentialProvider,
    0x8b7c4f9e, 0x2a3d, 0x4e5f, 0x9c, 0x1b, 0x7d, 0x8e, 0x6f, 0x4a, 0x5b, 0x3c);
