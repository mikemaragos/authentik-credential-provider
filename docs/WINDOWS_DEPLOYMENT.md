# Windows Deployment Guide

This guide covers deploying the Authentik Passwordless Credential Provider to Windows workstations.

## Prerequisites

- Windows 10/11 or Windows Server 2016+
- Domain-joined computer
- Administrator access
- Visual C++ Redistributable 2019 or later
- Network access to Authentik server

## Quick Start

### 1. Install Visual C++ Redistributable

If not already installed:
```powershell
# Download and install
Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile "vc_redist.x64.exe"
Start-Process -Wait -FilePath ".\vc_redist.x64.exe" -ArgumentList "/install", "/quiet", "/norestart"
```

### 2. Copy DLL

```powershell
# Run as Administrator
Copy-Item "AuthentikCredentialProvider.dll" -Destination "C:\Windows\System32\"
```

### 3. Register DLL

```powershell
# Run as Administrator
regsvr32 C:\Windows\System32\AuthentikCredentialProvider.dll
```

Expected output: "DllRegisterServer in AuthentikCredentialProvider.dll succeeded."

### 4. Configure Registry

```powershell
# Run as Administrator

# Required settings
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v ServerUrl /t REG_SZ /d "authentik.yourdomain.com" /f
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v ServerPort /t REG_DWORD /d 443 /f
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v FlowSlug /t REG_SZ /d "windows-passwordless" /f
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v UseHttps /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v Domain /t REG_SZ /d "YOURDOMAIN" /f
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v DomainFQDN /t REG_SZ /d "yourdomain.local" /f

# For testing only (disable in production)
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v IgnoreCertErrors /t REG_DWORD /d 1 /f
```

### 5. Test

1. Lock your workstation (Win + L)
2. Look for "Authentik Passwordless Login" tile
3. Enter your username and press Enter
4. Enter your OTP code and press Enter

## Registry Settings Reference

| Key | Type | Description | Example |
|-----|------|-------------|---------|
| ServerUrl | REG_SZ | Authentik server hostname | `authentik.company.com` |
| ServerPort | REG_DWORD | HTTPS port | `443` |
| FlowSlug | REG_SZ | Authentik flow slug | `windows-passwordless` |
| UseHttps | REG_DWORD | Use HTTPS (1=yes, 0=no) | `1` |
| Domain | REG_SZ | NetBIOS domain name | `COMPANY` |
| DomainFQDN | REG_SZ | Full domain name | `company.local` |
| IgnoreCertErrors | REG_DWORD | Skip SSL validation (testing only) | `0` |

## Uninstallation

```powershell
# Run as Administrator

# Unregister DLL
regsvr32 /u C:\Windows\System32\AuthentikCredentialProvider.dll

# Delete DLL
Remove-Item C:\Windows\System32\AuthentikCredentialProvider.dll

# Remove registry settings (optional)
reg delete "HKLM\SOFTWARE\AuthentikPasswordlessCP" /f
```

## Group Policy Deployment

### Create MSI Package

For enterprise deployment, wrap the DLL in an MSI:

1. Use WiX Toolset or Advanced Installer
2. Include:
   - DLL copy to System32
   - DLL registration
   - Default registry settings
   - VC++ Redistributable merge module

### Deploy via GPO

1. Create a Software Installation GPO
2. Add the MSI package
3. Configure registry settings via Group Policy Preferences
4. Link to target OUs

### Registry via GPO

**Computer Configuration → Preferences → Windows Settings → Registry**

Create registry items for each setting:
- Action: Update
- Hive: HKEY_LOCAL_MACHINE
- Key path: SOFTWARE\AuthentikPasswordlessCP
- Value name: (as per table above)

## Troubleshooting

### Credential Provider Not Appearing

1. **Check registration:**
   ```powershell
   reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers" /s | findstr "Authentik"
   ```

2. **Check DLL exists:**
   ```powershell
   Test-Path C:\Windows\System32\AuthentikCredentialProvider.dll
   ```

3. **Reboot** - Windows caches credential providers

### Debug Logging

1. Download [DebugView](https://docs.microsoft.com/en-us/sysinternals/downloads/debugview)
2. Run as Administrator
3. Enable **Capture → Capture Global Win32**
4. Lock/unlock workstation
5. Look for `[AuthentikPwdlessCP]` messages

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| HTTP 405 | Wrong flow slug | Verify FlowSlug matches Authentik |
| HTTP 404 | Flow not found | Create flow in Authentik |
| HTTP 403 | CSRF/Auth error | Check cookies are being sent |
| SSL Error | Certificate invalid | Set IgnoreCertErrors=1 for testing |
| No tile shown | Registration failed | Re-register DLL, reboot |

### Event Viewer

Check for errors in:
- Windows Logs → Application
- Windows Logs → System

Filter for source: "AuthentikCredentialProvider"

## Recovery

If locked out of the system:

### Option 1: Safe Mode
1. Hold Shift while clicking Restart
2. Troubleshoot → Advanced Options → Startup Settings
3. Select Safe Mode
4. Log in with local admin account
5. Unregister the credential provider

### Option 2: Recovery Environment
1. Boot from Windows installation media
2. Open Command Prompt
3. Navigate to System32
4. Rename or delete the DLL:
   ```cmd
   ren AuthentikCredentialProvider.dll AuthentikCredentialProvider.dll.bak
   ```
5. Reboot normally

### Option 3: Keep Alternate Login Method
Always ensure another login method is available:
- Local administrator account
- Another domain admin account
- Standard Windows credential provider remains active

## Security Hardening

### Production Checklist

- [ ] Set `IgnoreCertErrors` to `0`
- [ ] Use valid SSL certificate on Authentik
- [ ] Restrict registry key permissions
- [ ] Code sign the DLL
- [ ] Enable audit logging
- [ ] Test recovery procedures
- [ ] Document deployment

### Registry Permissions

Restrict who can modify settings:
```powershell
$acl = Get-Acl "HKLM:\SOFTWARE\AuthentikPasswordlessCP"
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.RegistryAccessRule("BUILTIN\Administrators", "FullControl", "Allow")
$acl.SetAccessRule($rule)
$rule = New-Object System.Security.AccessControl.RegistryAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "Allow")
$acl.SetAccessRule($rule)
Set-Acl "HKLM:\SOFTWARE\AuthentikPasswordlessCP" $acl
```

## Support

For issues:
1. Check DebugView logs
2. Verify Authentik flow works in browser
3. Check network connectivity to Authentik
4. Review this troubleshooting guide
5. Open issue on GitHub repository
