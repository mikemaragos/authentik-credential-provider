# Quick Start Guide

## Prerequisites

### Domain Controller
- Windows Server 2019+ with AD CS role
- CertIssuer service installed and running
- `StrongCertificateBindingEnforcement = 0` in registry

### Workstation  
- Windows 10/11 Pro, domain-joined
- TPM 2.0 enabled
- Virtual Smart Card created

### Development
- Visual Studio 2022
- Windows SDK

---

## Build

1. **Clone repository:**
   ```powershell
   git clone https://github.com/mikemaragos/authentik-credential-provider.git
   cd authentik-credential-provider
   ```

2. **Open in Visual Studio:**
   ```
   phase2/AuthentikCredentialProvider.sln
   ```

3. **Build:**
   - Configuration: `Release`
   - Platform: `x64`
   - Build → Build Solution (Ctrl+Shift+B)

---

## Deploy

### 1. Copy DLL (as Administrator)
```powershell
copy phase2\x64\Release\AuthentikCredentialProvider.dll C:\Windows\System32\
```

### 2. Register DLL
```powershell
regsvr32 C:\Windows\System32\AuthentikCredentialProvider.dll
```

### 3. Configure Registry
```powershell
# Import configuration
reg import phase2\phase2-config.reg

# Or manually set:
# HKLM\SOFTWARE\AuthentikCredentialProvider
#   ServerUrl = "your-dc.domain.com"
#   ServerPort = 8443 (DWORD)
#   Domain = "YOURDOMAIN"
#   VSCReaderName = "Microsoft Virtual Smart Card 0"
```

### 4. Reboot
```powershell
shutdown /r /t 0
```

---

## Test

1. Press **Win+L** to lock
2. Select **Authentik OTP Login** tile
3. Enter **username** and **OTP code**
4. Click **Sign in**

### Debug Logging
- Download [DebugView](https://docs.microsoft.com/en-us/sysinternals/downloads/debugview)
- Run as Administrator
- Filter: `[AuthentikCP]`

---

## Uninstall

```powershell
regsvr32 /u C:\Windows\System32\AuthentikCredentialProvider.dll
del C:\Windows\System32\AuthentikCredentialProvider.dll
shutdown /r /t 0
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| CP not visible | Reboot, verify regsvr32 succeeded |
| OTP validation fails | Check CertIssuer service on DC |
| Certificate import fails | Verify VSC exists, check PIN |
| PKINIT fails | Check DC `StrongCertificateBindingEnforcement` |

See [KNOWLEDGE_BASE.md](KNOWLEDGE_BASE.md) for detailed troubleshooting.
