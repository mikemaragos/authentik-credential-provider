# Authentik Passwordless Authentication - KSP Deployment Guide

## Overview

This guide covers the complete deployment of the Authentik Credential Provider with custom Key Storage Provider (KSP) for true passwordless Windows domain authentication.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AUTHENTICATION FLOW                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │   Windows   │    │  Authentik  │    │    Cert     │    │   Active    │  │
│  │  Workstation│◄──►│   Server    │◄──►│   Issuer    │◄──►│  Directory  │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│        │                                      │                  │          │
│        │                                      │                  │          │
│        ▼                                      ▼                  ▼          │
│  ┌─────────────┐                        ┌─────────────┐   ┌─────────────┐  │
│  │ Credential  │                        │   AD CS     │   │   Domain    │  │
│  │  Provider   │                        │    (CA)     │   │ Controller  │  │
│  └─────────────┘                        └─────────────┘   └─────────────┘  │
│        │                                                                    │
│        ▼                                                                    │
│  ┌─────────────┐                                                           │
│  │ Authentik   │  ◄── Stores keys, provides them for PKINIT signing        │
│  │    KSP      │                                                           │
│  └─────────────┘                                                           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Components

1. **Authentik Server** - Handles OTP validation (already configured)
2. **Certificate Issuer Service** - Issues certificates from AD CS (already configured)
3. **Authentik Credential Provider** - Windows logon UI integration
4. **Authentik KSP** - Custom Key Storage Provider for PKINIT

## Prerequisites

- [ ] Authentik server running and accessible
- [ ] Certificate Issuer service running on DC
- [ ] AD CS configured with SmartcardLogon template
- [ ] CA certificate in NTAuth store
- [ ] Visual Studio 2022 on build machine

## Build Instructions

### 1. Build the KSP

```cmd
cd src\AuthentikKSP
msbuild AuthentikKSP.vcxproj /p:Configuration=Release /p:Platform=x64
```

Output: `x64\Release\AuthentikKSP.dll`

### 2. Build the Credential Provider

```cmd
cd src\AuthentikCredentialProvider
msbuild AuthentikCredentialProvider.vcxproj /p:Configuration=Release /p:Platform=x64
```

Output: `x64\Release\AuthentikCredentialProvider.dll`

## Installation (on each workstation)

### Step 1: Install the KSP

```powershell
# Run as Administrator

# Copy DLL
Copy-Item "AuthentikKSP.dll" "C:\Windows\System32\" -Force

# Register KSP
$ProviderName = "Authentik Key Storage Provider"
$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\$ProviderName"

# Create registry entries
New-Item -Path $RegistryPath -Force | Out-Null
Set-ItemProperty -Path $RegistryPath -Name "Image Path" -Value "C:\Windows\System32\AuthentikKSP.dll"
Set-ItemProperty -Path $RegistryPath -Name "Type" -Value 1

$FunctionsPath = "$RegistryPath\Functions"
New-Item -Path $FunctionsPath -Force | Out-Null
Set-ItemProperty -Path $FunctionsPath -Name "KeyStorageInterface" -Value "GetKeyStorageInterface"

Write-Host "KSP registered successfully" -ForegroundColor Green
```

### Step 2: Install the Credential Provider

```powershell
# Run as Administrator

# Copy DLL
Copy-Item "AuthentikCredentialProvider.dll" "C:\Windows\System32\" -Force

# Register
regsvr32 C:\Windows\System32\AuthentikCredentialProvider.dll
```

### Step 3: Configure Registry Settings

```powershell
# Run as Administrator

$RegPath = "HKLM:\SOFTWARE\AuthentikCredentialProvider"
New-Item -Path $RegPath -Force | Out-Null

# Authentik server settings
Set-ItemProperty -Path $RegPath -Name "ServerUrl" -Value "authentik.test.local"
Set-ItemProperty -Path $RegPath -Name "ServerPort" -Value 443 -Type DWord
Set-ItemProperty -Path $RegPath -Name "FlowSlug" -Value "windows-passwordless"
Set-ItemProperty -Path $RegPath -Name "UseHttps" -Value 1 -Type DWord

# Certificate issuer settings
Set-ItemProperty -Path $RegPath -Name "CertIssuerUrl" -Value "http://192.168.1.101:8443"
Set-ItemProperty -Path $RegPath -Name "CertIssuerToken" -Value "726ca6c60f8840acb97be6979c261eac"

# Domain settings
Set-ItemProperty -Path $RegPath -Name "Domain" -Value "TEST"
Set-ItemProperty -Path $RegPath -Name "DomainFQDN" -Value "test.local"

Write-Host "Configuration complete" -ForegroundColor Green
```

### Step 4: Reboot

```powershell
Restart-Computer
```

## Verification

### 1. Verify KSP Registration

```cmd
certutil -csplist
```

Look for "Authentik Key Storage Provider" in the list.

### 2. Verify Credential Provider Registration

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers"
```

Look for `{8B7C4F9E-2A3D-4E5F-9C1B-7D8E6F4A5B3C}`.

### 3. Test Login

1. Lock the workstation (Win+L)
2. Look for "Authentik Passwordless Login" tile
3. Enter username
4. Enter OTP from authenticator app
5. Observe PKINIT authentication

## Debugging

### Enable Debug Logging

1. Download DebugView from Sysinternals
2. Run as Administrator
3. Enable "Capture Global Win32"
4. Filter: `[AuthentikCP]` and `[AuthentikKSP]`

### Check Event Logs

```powershell
# On Domain Controller
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4768} -MaxEvents 10 |
    Select-Object TimeCreated, Message | Format-List
```

Look for:
- Pre-Authentication Type: Should be 16 or 17 (PKINIT), not 2 (password)
- Certificate Issuer Name: Should show your CA
- Certificate Thumbprint: Should be populated

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| KSP not in csplist | Registration failed | Re-run registration, check registry |
| NTE_BAD_KEYSET | Key not found | Check shared memory creation, verify timing |
| Pre-Auth Type 2 | Falling back to password | Check KSP is working, verify CSP info structure |
| STATUS_ACCOUNT_RESTRICTION | Certificate trust issue | Verify CA in NTAuth, check certificate EKUs |

## Security Hardening (Production)

### 1. Code Sign the DLLs

```powershell
# Sign with your code signing certificate
signtool sign /f cert.pfx /p password /t http://timestamp.digicert.com AuthentikKSP.dll
signtool sign /f cert.pfx /p password /t http://timestamp.digicert.com AuthentikCredentialProvider.dll
```

### 2. Enable SSL Certificate Validation

Edit `AuthentikAPI.cpp` and remove:
```cpp
DWORD dwSecFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
```

### 3. Encrypt Configuration

Use DPAPI to encrypt sensitive registry values:
```cpp
CryptProtectData(&dataIn, L"ApiToken", NULL, NULL, NULL, 0, &dataOut);
```

### 4. Restrict Registry Permissions

```powershell
$acl = Get-Acl "HKLM:\SOFTWARE\AuthentikCredentialProvider"
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.RegistryAccessRule(
    "SYSTEM", "FullControl", "Allow")
$acl.AddAccessRule($rule)
Set-Acl "HKLM:\SOFTWARE\AuthentikCredentialProvider" $acl
```

## Uninstallation

```powershell
# Run as Administrator

# Unregister Credential Provider
regsvr32 /u C:\Windows\System32\AuthentikCredentialProvider.dll

# Remove KSP registration
$ProviderName = "Authentik Key Storage Provider"
Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\$ProviderName" -Recurse -Force

# Remove DLLs
Remove-Item C:\Windows\System32\AuthentikCredentialProvider.dll -Force
Remove-Item C:\Windows\System32\AuthentikKSP.dll -Force

# Remove configuration
Remove-Item "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Recurse -Force

# Reboot
Restart-Computer
```

## Deployment at Scale

### Group Policy MSI Deployment

1. Package both DLLs and registration scripts into an MSI
2. Deploy via Group Policy Software Installation
3. Use GPO preferences for registry configuration

### SCCM/Intune Deployment

1. Create application package
2. Detection rule: Check for DLL and registry keys
3. Install command: PowerShell deployment script
4. Uninstall command: PowerShell removal script

## Support

- Check DebugView logs for `[AuthentikCP]` and `[AuthentikKSP]` messages
- Review Kerberos events on Domain Controller (Event ID 4768)
- Verify certificate chain trust with `certutil -verify`
- Test Authentik flow via web browser first

## Version History

- **v2.0** - Added custom KSP for true PKINIT support
- **v1.0** - Initial release with OTP + password flow
