# Authentik Passwordless Credential Provider for Windows

A Windows Credential Provider that enables **true passwordless domain authentication** using Authentik for identity verification and AD CS (Active Directory Certificate Services) for certificate-based Kerberos PKINIT authentication.

## 🎯 What This Does

Instead of typing a password, users:
1. Enter their **username**
2. Enter a **one-time code** (TOTP, push notification, etc.)
3. Authentik requests a certificate from **AD CS**
4. Windows receives the **certificate** from Authentik
5. Certificate is used for **Kerberos PKINIT authentication**
6. User is logged in - **no password needed!**

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Windows Login Screen                          │
│                                                                  │
│    ┌──────────────────────────────────────────────────────┐     │
│    │         Authentik Passwordless Login                  │     │
│    │                                                       │     │
│    │    Username: [mike                    ]               │     │
│    │    OTP Code: [123456                  ]               │     │
│    │                                                       │     │
│    │    [Sign In]                                          │     │
│    └──────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTPS API
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Authentik Server                           │
│                                                                  │
│   1. Validate username (LDAP)                                   │
│   2. Challenge OTP (TOTP/Push/WebAuthn)                         │
│   3. Request certificate from AD CS                             │
│   4. Return certificate + private key to client                 │
└────────────────────────────┬────────────────────────────────────┘
                             │
              Certificate    │
              Request        ▼
┌─────────────────────────────────────────────────────────────────┐
│              AD CS (Certificate Authority)                       │
│              Running on Domain Controller                        │
│                                                                  │
│   - Issues short-lived certificate (1 hour)                     │
│   - Smart Card Logon template                                   │
│   - Automatic trust (Enterprise CA)                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ PKINIT (Certificate)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Domain Controller (KDC)                         │
│                                                                  │
│   - Validate certificate (auto-trusted from Enterprise CA)      │
│   - Map certificate UPN to AD user                              │
│   - Issue Kerberos TGT                                          │
│   - User logged in!                                             │
└─────────────────────────────────────────────────────────────────┘
```

## 📋 Prerequisites

### Server Side
- **Authentik** server with LDAP integration
- **AD CS** (Enterprise CA) on domain controller
- Certificate template configured for Smart Card Logon
- Service account for Authentik to request certificates

### Client Side
- Windows 10/11 or Windows Server 2016+
- Domain-joined machine
- Network access to Authentik server

| File | Description |
|------|-------------|
| `AuthentikCredentialProvider.cpp/h` | Main credential provider (COM interface) |
| `AuthentikCredential.cpp/h` | Login tile UI and authentication flow |
| `AuthentikAPI.cpp/h` | HTTP client for Authentik communication |
| `CertificateHelper.cpp/h` | Certificate parsing and PKINIT credential packing |
| `FieldDescriptors.h` | UI field definitions (username, OTP) |
| `Dll.cpp` | DLL entry point and COM registration |
| `guid.h` | GUID definitions |
| `Logger.h` | Debug logging (view with DebugView) |

## 🔧 Building

### Prerequisites

- Visual Studio 2022 (or 2019)
- Windows SDK 10.0.19041 or later
- x64 platform target

### Build Steps

1. Open `AuthentikPasswordlessCP.vcxproj` in Visual Studio
2. Select **Release | x64** configuration
3. Build → Build Solution (Ctrl+Shift+B)
4. Output: `x64\Release\AuthentikPasswordlessCP.dll`

### Command Line Build

```cmd
"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" ^
    AuthentikPasswordlessCP.vcxproj /p:Configuration=Release /p:Platform=x64
```

## 📦 Installation

### 1. Copy DLL to System32

```cmd
copy x64\Release\AuthentikPasswordlessCP.dll C:\Windows\System32\
```

### 2. Register DLL

```cmd
regsvr32 C:\Windows\System32\AuthentikPasswordlessCP.dll
```

### 3. Configure Registry

The installer creates default configuration. Modify as needed:

```
HKEY_LOCAL_MACHINE\SOFTWARE\AuthentikPasswordlessCP
├── ServerUrl (REG_SZ) = "authentik.example.com"
├── ServerPort (REG_DWORD) = 443
├── FlowSlug (REG_SZ) = "windows-passwordless"
├── UseHttps (REG_DWORD) = 1
├── Domain (REG_SZ) = "YOURDOMAIN"
├── DomainFQDN (REG_SZ) = "yourdomain.local"
├── CertValidMinutes (REG_DWORD) = 5
└── IgnoreCertErrors (REG_DWORD) = 0   ← Set to 0 for production!
```

### 4. Reboot

```cmd
shutdown /r /t 0
```

## ⚙️ Configuration

### Registry Settings

| Key | Type | Description |
|-----|------|-------------|
| `ServerUrl` | REG_SZ | Authentik server hostname |
| `ServerPort` | REG_DWORD | Server port (default: 443) |
| `FlowSlug` | REG_SZ | Authentik flow slug for passwordless auth |
| `UseHttps` | REG_DWORD | Use HTTPS (1) or HTTP (0) |
| `Domain` | REG_SZ | NetBIOS domain name |
| `DomainFQDN` | REG_SZ | Fully qualified domain name |
| `CertValidMinutes` | REG_DWORD | Certificate validity period |
| `IgnoreCertErrors` | REG_DWORD | Ignore SSL cert errors (testing only!) |

## 🔐 AD CS Setup (Certificate Authority)

Since you're using AD CS on your domain controller, the certificates will be automatically trusted. See **ADCS_SETUP.md** for detailed instructions.

### Quick Summary

1. **Create Certificate Template** based on "Smartcard Logon":
   - Template name: `AuthentikPasswordlessLogon`
   - Validity: 1 hour
   - Allow private key export: Yes
   - Subject name: Supply in request
   - EKUs: Smart Card Logon + Client Authentication

2. **Publish Template** to your CA:
   ```powershell
   # In certsrv.msc → Certificate Templates → New → Certificate Template to Issue
   ```

3. **Create Service Account** for Authentik:
   ```powershell
   New-ADUser -Name "svc_authentik_cert" -Enabled $true ...
   # Grant Enroll permission on the template
   ```

4. **Configure Authentik** to request certificates from AD CS after OTP validation

### Certificate Requirements (Handled by AD CS Template)

The template ensures certificates have:
- Subject Alternative Name with UPN
- Smart Card Logon EKU (1.3.6.1.4.1.311.20.2.2)
- Client Authentication EKU (1.3.6.1.5.5.7.3.2)
- Digital Signature key usage

## 🔗 Authentik Server Setup

### Required Flow Stages

1. **Identification Stage** - Username capture
2. **Authenticator Validation Stage** - OTP verification  
3. **Certificate Issuance Stage** - Custom stage that:
   - Generates key pair
   - Requests certificate from AD CS
   - Returns cert + private key to client

### API Response Format

After successful OTP validation, Authentik must return:

```json
{
    "type": "redirect",
    "to": "...",
    "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
    "username": "mike",
    "domain": "TEST",
    "upn": "mike@test.local",
    "valid_minutes": 60
}
```

### Integration Options

See **ARCHITECTURE_ADCS.md** for detailed integration options:
- Certificate Enrollment Web Service (CEP/CES)
- Direct RPC/DCOM to CA
- PowerShell Remoting
- External certificate service

## 🖥️ Active Directory Configuration

### Enterprise CA Benefits

Since you're using an Enterprise CA:
- ✅ Certificates are **automatically trusted** by all domain members
- ✅ No need to manually add CA to NTAuth store
- ✅ Certificate templates provide fine-grained control
- ✅ Built-in auditing and logging

### Verify CA Trust

```powershell
# Verify Enterprise CA is in NTAuth (should be automatic)
certutil -viewstore "ldap:///CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=yourdomain,DC=local?cACertificate"
```

### PKINIT Requirements

PKINIT is enabled by default on modern DCs. Verify:

```powershell
# Check Kerberos policy
Get-ADDefaultDomainPasswordPolicy
```

### 3. Certificate Mapping

Ensure users have UPN attributes set:

```powershell
# Verify user UPN
Get-ADUser -Identity mike -Properties userPrincipalName
```

## 🧪 Testing

### Enable Debug Logging

1. Download [DebugView](https://docs.microsoft.com/en-us/sysinternals/downloads/debugview)
2. Run as Administrator
3. Filter: `AuthentikPwdlessCP`
4. Lock screen (Win+L) and attempt login

### Test Flow

1. At login screen, select "Authentik Passwordless Login"
2. Enter username
3. Press Enter or click "Sign In"
4. Wait for OTP prompt
5. Enter verification code
6. Press Enter
7. Should log in without password!

### Verify Certificate Auth

```powershell
# Check Kerberos tickets
klist

# Should show TGT obtained via PKINIT
```

## 🔧 Troubleshooting

### Credential Provider Not Appearing

1. Verify DLL registration:
   ```cmd
   reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers" /s | findstr "Authentik"
   ```

2. Check file exists:
   ```cmd
   dir C:\Windows\System32\AuthentikPasswordlessCP.dll
   ```

3. Reboot (Windows caches providers)

### Authentication Fails

1. Check Authentik server is reachable:
   ```powershell
   Test-NetConnection -ComputerName authentik.example.com -Port 443
   ```

2. Check registry configuration
3. Review DebugView logs for `[AuthentikPwdlessCP]` messages

### Certificate Issues

1. Verify certificate chain:
   ```powershell
   certutil -verify cert.pem
   ```

2. Check NTAuth store:
   ```powershell
   certutil -viewstore "ldap:///CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local?cACertificate"
   ```

### PKINIT Fails

1. Check DC Kerberos event logs
2. Verify UPN mapping
3. Test with:
   ```cmd
   runas /smartcard /user:domain\user cmd.exe
   ```

## 🗑️ Uninstallation

```cmd
regsvr32 /u C:\Windows\System32\AuthentikPasswordlessCP.dll
del C:\Windows\System32\AuthentikPasswordlessCP.dll
reg delete "HKLM\SOFTWARE\AuthentikPasswordlessCP" /f
shutdown /r /t 0
```

## 🔒 Security Considerations

### Production Checklist

- [ ] Set `IgnoreCertErrors` to `0`
- [ ] Use valid SSL certificate on Authentik server
- [ ] Implement certificate pinning (code modification required)
- [ ] Use short certificate validity (5 minutes or less)
- [ ] Enable audit logging on Authentik
- [ ] Monitor DC Kerberos event logs
- [ ] Code sign the DLL

### Security Best Practices

1. **Certificate Validity**: Keep certificates short-lived (5 minutes)
2. **TLS**: Always use TLS 1.3 with valid certificates
3. **Audit**: Enable comprehensive logging on Authentik
4. **Revocation**: Implement CRL/OCSP for certificate revocation
5. **Recovery**: Keep password-based fallback available

## 📚 References

- [Microsoft: Credential Providers](https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
- [Microsoft: PKINIT](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pkca/)
- [Microsoft: Smart Card Logon](https://docs.microsoft.com/en-us/windows/security/identity-protection/smart-cards/)
- [Authentik Documentation](https://goauthentik.io/docs/)

## 📜 License

This project is provided as-is for educational and testing purposes.

## 🆘 Support

For issues:
1. Check DebugView logs
2. Review Authentik server logs
3. Check Windows Event Viewer (Security, Kerberos-Key-Distribution)
4. Review AD DC event logs

---

**⚠️ WARNING**: This is for testing and development. For production use, implement all security recommendations and thoroughly test in a lab environment first.
