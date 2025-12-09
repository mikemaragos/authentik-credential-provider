# Phase 2: Smart Card PKINIT Authentication

This folder contains the complete working credential provider source code.

## Files

### Core Components
| File | Purpose |
|------|---------|
| `AuthentikCredential.cpp/h` | Credential tile UI and authentication flow |
| `CredentialPacking.cpp/h` | KERB_CERTIFICATE_LOGON serialization |
| `VSCManager.cpp/h` | Virtual Smart Card management |
| `AuthentikAPI.cpp/h` | HTTP client for CertIssuer API |
| `AuthentikCredentialProvider.cpp/h` | Main credential provider implementation |
| `Dll.cpp` | DLL entry and COM registration |

### Supporting Files
| File | Purpose |
|------|---------|
| `FieldDescriptors.h` | UI field definitions |
| `Logger.h` | Debug logging macros |
| `guid.h` | COM GUID definitions |
| `phase2-config.reg` | Registry configuration template |

### Build Files
| File | Purpose |
|------|---------|
| `AuthentikCredentialProvider.sln` | Visual Studio solution |
| `AuthentikCredentialProvider.vcxproj` | Project file |
| `AuthentikCredentialProvider.def` | DLL exports |

## Build

```powershell
# Open solution
start AuthentikCredentialProvider.sln

# Build: Release x64
# Output: x64\Release\AuthentikCredentialProvider.dll
```

## Key Technical Details

### KERB_SMARTCARD_CSP_INFO Structure
```c
#pragma pack(push, 1)  // CRITICAL: 1-byte packing
// MessageType = 1 (always, not logon type)
// String offsets = CHARACTER COUNT (not bytes)
#pragma pack(pop)
```

### Credential Provider Serialization
```c
// UNICODE_STRING.Buffer = BYTE OFFSET from buffer start
// Not a pointer!
pLogon->UserName.Buffer = (PWSTR)(ULONG_PTR)offsetToString;
```

See `CredentialPacking.cpp` for complete implementation.
