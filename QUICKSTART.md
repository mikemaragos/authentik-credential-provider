# Quick Start Guide

## Building the Credential Provider

### Option 1: Using Visual Studio (Recommended)

1. **Open the project:**
   - Double-click `AuthentikCredentialProvider.vcxproj`
   - Or open Visual Studio â†’ File â†’ Open â†’ Project/Solution

2. **Select configuration:**
   - Configuration: Release
   - Platform: x64

3. **Build:**
   - Build â†’ Build Solution (Ctrl+Shift+B)
   - Output: `x64\Release\AuthentikCredentialProvider.dll`

### Option 2: Using MSBuild (Command Line)

```cmd
"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" AuthentikCredentialProvider.vcxproj /p:Configuration=Release /p:Platform=x64
```

## Installation Steps

### 1. Copy DLL

```cmd
# Run as Administrator
copy x64\Release\AuthentikCredentialProvider.dll C:\Windows\System32\
```

### 2. Register DLL

```cmd
# Run as Administrator
regsvr32 C:\Windows\System32\AuthentikCredentialProvider.dll
```

Expected output: "DllRegisterServer in AuthentikCredentialProvider.dll succeeded."

### 3. Configure Settings

Create `config.reg`:

```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\AuthentikCredentialProvider]
"ServerUrl"="authentik.test.local"
"ServerPort"=dword:000001bb
"FlowSlug"="windows-otp-auth"
"UseHttps"=dword:00000001
```

Double-click to import, or:

```cmd
reg import config.reg
```

### 4. Reboot

```cmd
shutdown /r /t 0
```

## Testing

### 1. Enable Debug Logging

- Download [DebugView](https://docs.microsoft.com/en-us/sysinternals/downloads/debugview)
- Run as Administrator
- Look for `[AuthentikCP]` messages

### 2. Lock Screen

- Press Win+L
- Look for "Authentik OTP Login" tile

### 3. Test Authentication

**Two-Step Mode:**
1. Username: `mike`
2. Password: `YourPassword`
3. Press Enter
4. OTP: `123456`
5. Press Enter

## Troubleshooting

### Credential Provider Not Showing

**Check Registration:**
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers" /s
```

Look for `{8B7C4F9E-2A3D-4E5F-9C1B-7D8E6F4A5B3C}`

**Check File:**
```cmd
dir C:\Windows\System32\AuthentikCredentialProvider.dll
```

**Reboot:**
Windows caches credential providers.

### Build Errors

**LNK2019: unresolved external symbol**
- Ensure `Secur32.lib;Advapi32.lib;Shlwapi.lib;Winhttp.lib` are in Additional Dependencies
- Check Platform is x64

**Cannot open include file**
- Verify Windows SDK is installed
- Check project properties â†’ VC++ Directories

### Authentication Fails

**Check Authentik:**
```powershell
Invoke-WebRequest -Uri "https://authentik.test.local" -SkipCertificateCheck
```

**Check Registry:**
```cmd
reg query HKLM\SOFTWARE\AuthentikCredentialProvider
```

**Check Logs:**
- Open DebugView as Administrator
- Attempt login
- Look for error messages

## Uninstallation

```cmd
# Run as Administrator
regsvr32 /u C:\Windows\System32\AuthentikCredentialProvider.dll
del C:\Windows\System32\AuthentikCredentialProvider.dll
```

Reboot.

## Next Steps

1. **Configure Authentik Flow**
   - Create flow with OTP validation stage
   - Test flow via web browser first

2. **Security Hardening**
   - Enable SSL certificate validation
   - Implement certificate pinning
   - Use proper API authentication

3. **Production Deployment**
   - Test thoroughly in lab environment
   - Deploy via Group Policy
   - Monitor logs for issues

## Common Issues

| Issue | Solution |
|-------|----------|
| DLL won't register | Run as Admin, check architecture (x64) |
| CP doesn't appear | Reboot, check registry, check Event Viewer |
| Auth fails | Verify Authentik reachable, check credentials |
| SSL errors | Check certificate, or disable validation for testing |

## Support

Review:
1. DebugView logs (`[AuthentikCP]` messages)
2. Windows Event Viewer (Application log)
3. Authentik server logs
4. README.md for detailed documentation
