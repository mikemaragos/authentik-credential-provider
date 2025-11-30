# Authentik Credential Provider for Windows - Passwordless Smart Card Edition

A Windows Credential Provider that enables **true passwordless** domain authentication by integrating:
- **Authentik** for user authentication and OTP validation
- **Active Directory Certificate Services (AD CS)** for certificate issuance
- **TPM Virtual Smart Cards (VSC)** for secure certificate storage
- **Kerberos PKINIT** for domain authentication

## 🎯 How It Works

```
┌─────────────────┐                      ┌──────────────┐
│   Windows       │  1. Username + OTP   │   Authentik  │
│   Login Screen  │─────────────────────▶│   Server     │
│                 │  2. OTP Validated    │              │
│                 │◀─────────────────────│              │
└────────┬────────┘                      └──────────────┘
         │
         │ 3. Request Certificate
         ▼
┌─────────────────┐                      ┌──────────────┐
│   Certificate   │  4. Issue Cert       │   AD CS      │
│   Issuer Svc    │─────────────────────▶│   (CA)       │
│                 │  5. Certificate      │              │
│                 │◀─────────────────────│              │
└────────┬────────┘                      └──────────────┘
         │
         │ 6. Install to VSC
         ▼
┌─────────────────┐                      ┌──────────────┐
│   TPM Virtual   │  7. PKINIT Auth      │   Domain     │
│   Smart Card    │─────────────────────▶│   Controller │
│                 │  8. TGT Issued       │              │
│                 │◀─────────────────────│              │
└─────────────────┘                      └──────────────┘
```

**User Experience:**
1. Enter username
2. Enter OTP (from authenticator app)
3. Enter smart card PIN
4. Logged in! (No password required)

## 📋 Prerequisites

### Domain Environment
- Windows Server 2016+ Domain Controller
- Active Directory Certificate Services (AD CS) configured
- Domain-joined workstations with TPM 2.0

### Software Requirements
- Visual Studio 2019/2022 with C++ Desktop Development
- Windows SDK 10.0.19041.0 or later
- PowerShell 5.1+ with ActiveDirectory module
- Authentik server (v2023.x or later)

### Certificate Template
A properly configured certificate template with:
- `CT_FLAG_SUBJECT_ALT_REQUIRE_UPN` flag (0x02000000)
- Smart Card Logon EKU
- Client Authentication EKU

## 🚀 Quick Start

### 1. Configure Certificate Template

On Domain Controller:
```powershell
# Configure template with UPN in SAN (required for PKINIT)
.\tools\Configure-SmartCardTemplate.ps1 -TemplateName "AuthentikSmartcard"
```

### 2. Start Certificate Issuer Service

On DC or CA server:
```powershell
# Start the REST API that issues certificates
.\tools\cert-issuer\CertIssuerService.ps1 `
    -Port 8443 `
    -ApiToken "YOUR-SECRET-TOKEN" `
    -CAConfig "DC.domain.local\CA-Name" `
    -CertTemplate "AuthentikSmartcard" `
    -AllowHttp
```

### 3. Create Virtual Smart Card on Workstation

From Proxmox/physical console (NOT RDP):
```powershell
tpmvscmgr create /name "Authentik VSC" /pin PROMPT /adminkey random /generate
# Enter PIN: 12345678
```

### 4. Build and Install Credential Provider

```powershell
# Build (from Visual Studio or MSBuild)
msbuild AuthentikCredentialProvider.vcxproj /p:Configuration=Release /p:Platform=x64

# Install
copy x64\Release\AuthentikCredentialProvider.dll C:\Windows\System32\
regsvr32 C:\Windows\System32\AuthentikCredentialProvider.dll
```

### 5. Configure Registry

```powershell
# Create configuration
New-Item -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Name "ServerUrl" -Value "authentik.domain.local"
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Name "ServerPort" -Value 443 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Name "FlowSlug" -Value "windows-smartcard-auth"
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Name "UseHttps" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Name "CertIssuerUrl" -Value "dc.domain.local"
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Name "CertIssuerPort" -Value 8443 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Name "CertIssuerToken" -Value "YOUR-SECRET-TOKEN"
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Name "Domain" -Value "domain.local"
Set-ItemProperty -Path "HKLM:\SOFTWARE\AuthentikCredentialProvider" -Name "UPNSuffix" -Value "@domain.local"
```

### 6. Reboot and Test

```powershell
shutdown /r /t 0
```

## 📁 Project Structure

```
authentik-credential-provider/
├── src/                          # Source code
│   ├── AuthentikAPI.cpp/h        # Authentik + Cert API client
│   ├── AuthentikCredential.cpp/h # Credential tile (passwordless flow)
│   ├── AuthentikCredentialProvider.cpp/h  # Main provider
│   ├── SmartCardHelper.cpp/h     # VSC operations
│   ├── CredentialPacking.cpp/h   # Kerberos credential packing
│   ├── FieldDescriptors.h        # UI field definitions
│   ├── Dll.cpp                   # DLL entry and COM registration
│   ├── Logger.h                  # Debug logging
│   └── guid.h                    # Provider GUID
├── tools/
│   ├── cert-issuer/
│   │   └── CertIssuerService.ps1 # Certificate issuer REST API
│   ├── Configure-SmartCardTemplate.ps1  # Template setup
│   ├── Enroll-SmartCardCertificate.ps1  # Manual cert enrollment
│   └── Diagnose-SmartCardAuth.ps1       # Troubleshooting
├── docs/
│   └── PKINIT_SMARTCARD_GUIDE.md # Detailed PKINIT guide
├── KNOWLEDGE_BASE.md             # Complete project knowledge
├── QUICKSTART.md                 # Quick setup guide
└── README.md                     # This file
```

## 🔧 Configuration Reference

### Registry Settings

| Key | Type | Description | Example |
|-----|------|-------------|---------|
| ServerUrl | REG_SZ | Authentik server hostname | `authentik.domain.local` |
| ServerPort | REG_DWORD | Authentik server port | `443` |
| FlowSlug | REG_SZ | Authentik flow slug | `windows-smartcard-auth` |
| UseHttps | REG_DWORD | Use HTTPS (1) or HTTP (0) | `1` |
| CertIssuerUrl | REG_SZ | Certificate issuer hostname | `dc.domain.local` |
| CertIssuerPort | REG_DWORD | Certificate issuer port | `8443` |
| CertIssuerToken | REG_SZ | API authentication token | `secret-token` |
| Domain | REG_SZ | AD domain name | `domain.local` |
| UPNSuffix | REG_SZ | UPN suffix for users | `@domain.local` |

### Certificate Template Requirements

| Setting | Value |
|---------|-------|
| msPKI-Certificate-Name-Flag | `0x62000000` |
| Key Usage | Digital Signature, Key Encipherment |
| Enhanced Key Usage | Smart Card Logon, Client Authentication |
| Subject Name | Build from AD (CN) |
| Subject Alternative Name | UPN from AD (CRITICAL!) |

## 🔍 Troubleshooting

### Run Diagnostics

```powershell
# On workstation
.\tools\Diagnose-SmartCardAuth.ps1 -Target Workstation -Username shop

# On DC
.\tools\Diagnose-SmartCardAuth.ps1 -Target DC -Username shop
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "Certificate mapping failed" (Event 39) | No UPN in SAN | Reconfigure template with UPN flag |
| "Credentials could not be verified" | Multiple certs on VSC | Recreate VSC with single cert |
| tpmvscmgr fails | Running over RDP | Use physical/Proxmox console |
| Certificate not issued | Template permissions | Grant Enroll to Authenticated Users |

### Enable Debug Logging

1. Build Debug configuration
2. Run DebugView as Administrator
3. Filter for `[AuthentikCP]` messages

## 🔒 Security Considerations

### Production Checklist

- [ ] Enable SSL certificate validation (remove ignore flags)
- [ ] Use strong API token for certificate issuer
- [ ] Implement certificate pinning
- [ ] Enable StrongCertificateBindingEnforcement on DC
- [ ] Code sign the credential provider DLL
- [ ] Restrict certificate template permissions
- [ ] Implement certificate lifecycle management
- [ ] Monitor for Event 39 errors on DC

### Key Security Features

- **No passwords transmitted** - OTP + certificate-based auth
- **TPM-protected keys** - Private keys never leave VSC
- **Short-lived certificates** - Optionally issue per-session certs
- **Kerberos PKINIT** - Industry-standard protocol

## 📚 Additional Documentation

- [PKINIT Smart Card Guide](docs/PKINIT_SMARTCARD_GUIDE.md) - Detailed implementation guide
- [Knowledge Base](KNOWLEDGE_BASE.md) - Complete project knowledge
- [Quick Start](QUICKSTART.md) - Fast setup instructions

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- Microsoft Credential Provider samples
- Authentik project
- PrivacyIDEA credential provider (inspiration)

---

**Status:** ✅ PKINIT Smart Card Login Working (November 30, 2025)
