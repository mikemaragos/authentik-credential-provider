// guid.cpp
// GUID definition for the credential provider

#include <windows.h>

// Define INITGUID before including guid.h to actually define the GUID
#define INITGUID
#include <guiddef.h>
#include "guid.h"

// The GUID is defined here because INITGUID is defined
// This creates the actual storage for CLSID_AuthentikCredentialProvider
