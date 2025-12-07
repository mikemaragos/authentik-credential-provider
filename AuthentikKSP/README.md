# Authentik Key Storage Provider (KSP)

A custom Windows CNG Key Storage Provider that validates OTP codes with Authentik before allowing cryptographic operations.

## Overview

This KSP wraps the Microsoft Software KSP and intercepts PIN verification. Instead of checking a traditional PIN, it validates the provided "PIN" as an OTP code with Authentik.

```
User enters OTP as "PIN"
         │
         ▼
┌─────────────────────┐
│   AuthentikKSP      │
│                     │
│   SetKeyProperty    │ ← Captures OTP from NCRYPT_PIN_PROPERTY
│   (PIN = OTP)       │
│                     │
│   SignHash          │ ← Validates OTP with Authentik before signing
│                     │
└─────────────────────┘
         │
         ▼ If OTP valid
┌─────────────────────┐
│  MS Software KSP    │ ← Actual cryptographic operations
└─────────────────────┘
```

## Building

### Prerequisites

1. Visual Studio 2019 or 2022
2. Windows SDK 10.0+
3. **Cryptographic Provider Development Kit (CPDK)**
   - Download: https://www.microsoft.com/en-us/download/details.aspx?id=30688
   - Required for `bcrypt_provider.h` header

### Project Setup

1. Create a new DLL project in Visual Studio
2. Add CPDK to include paths:
   ```
   $(WindowsSdkDir)Cryptographic Provider Development Kit\Include
   ```
3. Add source files:
   - AuthentikKSP.cpp
   - AuthentikKSP.h
   - AuthentikKSP.def
4. Configure linker:
   - Module Definition File: AuthentikKSP.def
   - Additional Dependencies: ncrypt.lib;bcrypt.lib;winhttp.lib
5. Build for x64 Release

### Build Command (MSBuild)

```cmd
msbuild AuthentikKSP.vcxproj /p:Configuration=Release /p:Platform=x64
```

## Installation

### 1. Copy DLL

```powershell
Copy-Item AuthentikKSP.dll C:\Windows\System32\
```

### 2. Register KSP

```powershell
# Create registry key
$kspPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\Authentik Key Storage Provider"
New-Item -Path $kspPath -Force

# Set properties
Set-ItemProperty -Path $kspPath -Name "Image Path" -Value "C:\Windows\System32\AuthentikKSP.dll"
Set-ItemProperty -Path $kspPath -Name "Type" -Value 1 -Type DWord
```

### 3. Configure Authentik Settings

```powershell
# Create configuration key
$configPath = "HKLM:\SOFTWARE\AuthentikKSP"
New-Item -Path $configPath -Force

# Set Authentik server settings
Set-ItemProperty -Path $configPath -Name "ServerUrl" -Value "authentik.test.local"
Set-ItemProperty -Path $configPath -Name "ServerPort" -Value 443 -Type DWord
Set-ItemProperty -Path $configPath -Name "FlowSlug" -Value "windows-otp-auth"
Set-ItemProperty -Path $configPath -Name "UseHttps" -Value 1 -Type DWord
```

## Usage

### Enrolling Certificates

Create certificate request specifying this KSP:

```ini
; request.inf
[NewRequest]
Subject = "CN=mike"
KeySpec = 1
KeyLength = 2048
Exportable = FALSE
MachineKeySet = FALSE
ProviderName = "Authentik Key Storage Provider"
ProviderType = 1
RequestType = PKCS10
KeyUsage = 0xa0

[EnhancedKeyUsageExtension]
OID=1.3.6.1.4.1.311.20.2.2 ; Smart Card Logon
OID=1.3.6.1.5.5.7.3.2     ; Client Auth

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "upn=mike@test.local"
```

Then:
```cmd
certreq -new request.inf request.req
certreq -submit -config "CA\Name" request.req cert.cer
certreq -accept cert.cer
```

### Using with Credential Provider

The Credential Provider should:
1. Get username and OTP from user
2. Build KERB_CERTIFICATE_LOGON structure
3. Set OTP as the PIN field
4. Specify "Authentik Key Storage Provider" as the CSP

```cpp
// In Credential Provider
KERB_CERTIFICATE_LOGON logon;
logon.Pin.Buffer = otpCode;  // OTP goes here!
// ... rest of structure
```

When Windows performs PKINIT:
1. It calls NCryptSetProperty with NCRYPT_PIN_PROPERTY (OTP)
2. It calls NCryptSignHash to sign pre-auth data
3. Our KSP validates OTP with Authentik
4. If valid, signature proceeds
5. PKINIT completes, user logged in

## Registry Configuration

### KSP Registration
```
HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\Authentik Key Storage Provider
    Image Path = C:\Windows\System32\AuthentikKSP.dll
    Type = 1 (REG_DWORD)
```

### KSP Settings
```
HKLM\SOFTWARE\AuthentikKSP
    ServerUrl = authentik.test.local (REG_SZ)
    ServerPort = 443 (REG_DWORD)
    FlowSlug = windows-otp-auth (REG_SZ)
    UseHttps = 1 (REG_DWORD)
```

## Testing

### Verify Registration

```powershell
# List registered providers
certutil -csplist

# Should show "Authentik Key Storage Provider"
```

### Test Key Creation

```powershell
# Create a test key
$provider = [System.Security.Cryptography.CngProvider]::new("Authentik Key Storage Provider")
$keyParams = [System.Security.Cryptography.CngKeyCreationParameters]::new()
$keyParams.Provider = $provider
$key = [System.Security.Cryptography.CngKey]::Create(
    [System.Security.Cryptography.CngAlgorithm]::Rsa,
    "TestKey",
    $keyParams)

# Clean up
$key.Delete()
```

### Debug Logging

In debug builds, use DebugView to see:
- `[AuthentikKSP] KSPOpenProvider`
- `[AuthentikKSP] PIN property intercepted - storing as OTP`
- `[AuthentikKSP] KSPSignHash - THIS IS WHERE THE MAGIC HAPPENS!`
- `[AuthentikKSP] OTP VALIDATED SUCCESSFULLY!`

## Security Considerations

### Production Checklist

- [ ] Enable SSL certificate validation (remove SECURITY_FLAG_IGNORE_* flags)
- [ ] Implement certificate pinning for Authentik server
- [ ] Add rate limiting for OTP validation attempts
- [ ] Code sign the DLL
- [ ] Use SecureZeroMemory for all sensitive data
- [ ] Audit log all authentication attempts

### Attack Vectors to Consider

1. **DLL Injection** - KSP runs in LSASS, ensure DLL is signed
2. **Network MITM** - Enable proper TLS validation
3. **OTP Replay** - Authentik handles this server-side
4. **Brute Force** - Add rate limiting in KSP or rely on Authentik

## Troubleshooting

### KSP Not Loading

1. Check registry path is correct
2. Verify DLL is in System32
3. Check Event Viewer for loading errors
4. Run as Administrator

### OTP Validation Fails

1. Check network connectivity to Authentik
2. Verify FlowSlug is correct
3. Check Authentik flow is configured for OTP
4. Enable debug logging

### Certificate Enrollment Fails

1. Verify KSP is registered
2. Check CA is accessible
3. Verify template allows the KSP

## File Structure

```
AuthentikKSP/
├── AuthentikKSP.h       # Header with structures and prototypes
├── AuthentikKSP.cpp     # Main implementation
├── AuthentikKSP.def     # DLL exports
└── README.md            # This file
```

## License

Part of the Authentik Credential Provider project.

## Version History

- **v1.0** - Initial implementation
  - Basic KSP wrapper
  - OTP interception via PIN property
  - Authentik HTTP validation
