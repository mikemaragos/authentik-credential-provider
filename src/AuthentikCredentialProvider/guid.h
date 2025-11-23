// guid.h
// GUID definitions for the credential provider

#pragma once

#include <guiddef.h>

// {8B7C4F9E-2A3D-4E5F-9C1B-7D8E6F4A5B3C}
// Declared here, defined in guid.cpp
extern "C" const GUID CLSID_AuthentikCredentialProvider;

// DLL reference counting
void DllAddRef();
void DllRelease();
