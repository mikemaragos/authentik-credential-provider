# Authentik Credential Provider - Phase 2 (Passwordless)

## Overview

This credential provider enables true passwordless Windows domain authentication using:
- Username + OTP (no password!)
- Authentik for OTP validation
- CertIssuer for automatic certificate issuance
- Virtual Smart Card for PKINIT authentication

## Flow

```
User enters: username + OTP
           ↓
Credential Provider validates OTP with Authentik
           ↓
Credential Provider requests certificate from CertIssuer
           ↓
CertIssuer issues cert via AD CS + updates AD mapping
           ↓
Credential Provider imports PFX to VSC
           ↓
KERB_CERTIFICATE_LOGON → LSA → PKINIT → Login!
```

## Files

| File | Purpose |
|------|---------|
| AuthentikCredential.cpp/h | Main credential tile, orchestrates auth flow |
| AuthentikCredentialProvider.cpp/h | Provider registration |
| AuthentikAPI.cpp/h | HTTP client for Authentik + CertIssuer |
| VSCManager.cpp/h | Virtual Smart Card management |
| CredentialPacking.cpp/h | KERB_CERTIFICATE_LOGON serialization |
| FieldDescriptors.h | UI field definitions |
| Logger.h | Debug logging |
| guid.h | COM GUID |
| Dll.cpp | DLL entry point |

## Building

### Prerequisites
- Visual Studio 2019 or 2022
- Windows SDK 10.0.19041.0+
- Target: x64

### Project Settings

**C/C++ → General:**
- Additional Include Directories: `$(ProjectDir)`

**C/C++ → Preprocessor:**
- Definitions: `WIN32_LEAN_AND_MEAN;UNICODE;_UNICODE;_DEBUG` (for debug)

**Linker → Input:**
- Additional Dependencies: `Secur32.lib;Advapi32.lib;Shlwapi.lib;Winhttp.lib;NCrypt.lib;Crypt32.lib;WinSCard.lib;Cryptui.lib`

**Linker → Input:**
- Module Definition File: `AuthentikCredentialProvider.def`

### Build Command

```cmd
msbuild AuthentikCredentialProvider.vcxproj /p:Configuration=Release /p:Platform=x64
```

## Installation

### 1. Prerequisites

**On DC:**
- CertIssuer service running on port 8443
- AD CS configured with AuthentikSmartcard template
- StrongCertificateBindingEnforcement = 0

**On Workstation:**
- Virtual Smart Card created: `tpmvscmgr.exe create /name VSC /pin default /adminkey random /generate`
- Smart Card Credential Provider enabled

### 2. Deploy DLL

```cmd
copy AuthentikCredentialProvider.dll C:\Windows\System32\
regsvr32 C:\Windows\System32\AuthentikCredentialProvider.dll
```

### 3. Configure Registry

```cmd
reg import phase2-config.reg
```

Or manually set:
```
HKLM\SOFTWARE\AuthentikCredentialProvider
    AuthentikServer = "authentik.test.local"
    AuthentikPort = 443 (DWORD)
    FlowSlug = "windows-otp-auth"
    UseHttps = 1 (DWORD)
    CertIssuerServer = "192.168.1.101"
    CertIssuerPort = 8443 (DWORD)
    CertIssuerApiToken = "<your-token>"
    Domain = "test.local"
    VSCPin = "12345678"
```

### 4. Reboot

```cmd
shutdown /r /t 0
```

## Testing

1. Run DebugView as Administrator
2. Lock workstation (Win+L)
3. Look for "Authentik Passwordless" tile
4. Enter username and OTP code
5. Watch debug output for flow progress
6. Should authenticate via PKINIT!

## Troubleshooting

### Credential provider doesn't appear
- Check registration: `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers" /s`
- Verify DLL in System32
- Reboot

### OTP validation fails
- Check Authentik server reachable
- Verify flow slug correct
- Check DebugView for HTTP errors

### Certificate request fails
- Verify CertIssuer service running
- Check API token in registry
- Review CertIssuer logs

### PKINIT fails
- Verify VSC exists and has PIN 12345678
- Check certificate imported correctly
- Review DC event logs

## Security Notes

⚠️ **For Testing Only:**
- SSL validation is disabled
- API token stored in plain text
- Remove debug logging in production

## Version

Phase 2 - December 8, 2025
