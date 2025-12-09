# Authentik Credential Provider for Windows

A Windows Credential Provider that enables **passwordless domain authentication** using Authentik OTP validation and certificate-based PKINIT.

## 🎯 What It Does

Users authenticate to Windows domain computers using:
1. **Username** - Domain user account
2. **OTP Code** - From Authentik (TOTP, push notification, etc.)

No password required! The system:
1. Validates OTP with Authentik
2. Requests a short-lived certificate from AD CS
3. Imports certificate to Virtual Smart Card
4. Performs PKINIT Kerberos authentication

## 📁 Project Structure

```
├── phase2/                      # Main credential provider source code
│   ├── AuthentikCredentialProvider.sln  # Visual Studio solution
│   ├── AuthentikCredential.cpp          # Credential tile implementation
│   ├── CredentialPacking.cpp            # PKINIT structure serialization
│   ├── VSCManager.cpp                   # Virtual Smart Card management
│   └── AuthentikAPI.cpp                 # Authentik/CertIssuer API client
├── certissuer/                  # Certificate issuer service (runs on DC)
├── scripts/                     # Setup and diagnostic PowerShell scripts
├── docs/                        # Documentation
└── tools/                       # Helper utilities
```

## 🚀 Quick Start

### Prerequisites
- Windows Server 2019+ Domain Controller with AD CS
- Windows 10/11 Pro domain-joined workstation with TPM
- Authentik identity provider
- Visual Studio 2022 for building

### Build
```powershell
# Open solution in Visual Studio 2022
# Build > Build Solution (Release x64)
```

### Deploy
```powershell
# On workstation (as Admin):
copy AuthentikCredentialProvider.dll C:\Windows\System32\
regsvr32 C:\Windows\System32\AuthentikCredentialProvider.dll
# Reboot
```

### Configure
See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for registry settings.

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [QUICKSTART.md](QUICKSTART.md) | Step-by-step setup guide |
| [KNOWLEDGE_BASE.md](KNOWLEDGE_BASE.md) | Complete technical reference |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture |
| [docs/SMARTCARD_CREDENTIAL_RESEARCH.md](docs/SMARTCARD_CREDENTIAL_RESEARCH.md) | PKINIT structure details |

## 🔧 Key Technical Details

### PKINIT Structure Requirements (Critical!)

The credential provider uses `KERB_CERTIFICATE_LOGON` with embedded `KERB_SMARTCARD_CSP_INFO`:

```c
// KERB_SMARTCARD_CSP_INFO requires:
#pragma pack(push, 1)  // 1-byte packing (CRITICAL!)
// MessageType = 1 (always, NOT the logon type!)
// String offsets = CHARACTER COUNT (not bytes!)
#pragma pack(pop)

// For credential providers:
// UNICODE_STRING.Buffer = BYTE OFFSET (not pointer!)
```

See [docs/SMARTCARD_CREDENTIAL_RESEARCH.md](docs/SMARTCARD_CREDENTIAL_RESEARCH.md) for details.

### Environment Requirements

**Domain Controller:**
- `StrongCertificateBindingEnforcement = 0` (or use SKI mapping)
- CertIssuer service running on port 8443

**Workstation:**
- TPM enabled for Virtual Smart Card
- Smart Card Credential Provider enabled

## 📋 Status

✅ **Working**: Full OTP → Certificate → VSC → PKINIT authentication flow

## 🔗 References

- [Microsoft Credential Provider Documentation](https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
- [IDRIX Smart Card Logon Samples](http://www.idrix.fr/Root/Samples/)
- [Authentik Documentation](https://goauthentik.io/docs/)

## 📄 License

MIT License - See [LICENSE](LICENSE)
