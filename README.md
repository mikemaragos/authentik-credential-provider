# Authentik Passwordless Credential Provider for Windows

A Windows Credential Provider that enables **true passwordless domain authentication** using Authentik for identity verification and AD CS certificates for Kerberos PKINIT.

## How It Works

```
User enters username → Authentik sends OTP challenge → User enters OTP → 
Authentik requests certificate from AD CS → Windows uses certificate for PKINIT → 
User logged in (no password!)
```

## Prerequisites

- Windows 10/11 or Windows Server 2016+ (domain-joined)
- Authentik server with LDAP integration
- AD CS (Active Directory Certificate Services) - Enterprise CA
- Visual Studio 2022 (for building)

## Quick Start

### 1. Build

```powershell
cd src
msbuild AuthentikCredentialProvider.sln /p:Configuration=Release /p:Platform=x64
```

### 2. Install

```powershell
# Run as Administrator
copy x64\Release\AuthentikCredentialProvider.dll C:\Windows\System32\
regsvr32 C:\Windows\System32\AuthentikCredentialProvider.dll
```

### 3. Configure

```
HKEY_LOCAL_MACHINE\SOFTWARE\AuthentikPasswordlessCP
├── ServerUrl (REG_SZ) = "authentik.yourdomain.com"
├── ServerPort (REG_DWORD) = 443
├── FlowSlug (REG_SZ) = "windows-passwordless"
├── UseHttps (REG_DWORD) = 1
├── Domain (REG_SZ) = "YOURDOMAIN"
├── DomainFQDN (REG_SZ) = "yourdomain.local"
└── IgnoreCertErrors (REG_DWORD) = 0
```

### 4. Reboot

```powershell
shutdown /r /t 0
```

## Documentation

| Document | Description |
|----------|-------------|
| [docs/ADCS_SETUP.md](docs/ADCS_SETUP.md) | AD CS certificate template configuration |
| [docs/AUTHENTIK_SETUP.md](docs/AUTHENTIK_SETUP.md) | Authentik flow configuration |
| [docs/INSTALLATION.md](docs/INSTALLATION.md) | Detailed installation guide |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Registry settings reference |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common issues and solutions |

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Windows   │     │  Authentik  │     │   AD CS     │     │   Domain    │
│   Client    │     │   Server    │     │    (CA)     │     │ Controller  │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │                   │
       │ 1. Username       │                   │                   │
       │──────────────────►│                   │                   │
       │                   │                   │                   │
       │ 2. OTP Challenge  │                   │                   │
       │◄──────────────────│                   │                   │
       │                   │                   │                   │
       │ 3. OTP Code       │                   │                   │
       │──────────────────►│                   │                   │
       │                   │                   │                   │
       │                   │ 4. Cert Request   │                   │
       │                   │──────────────────►│                   │
       │                   │                   │                   │
       │                   │ 5. Certificate    │                   │
       │                   │◄──────────────────│                   │
       │                   │                   │                   │
       │ 6. Cert + Key     │                   │                   │
       │◄──────────────────│                   │                   │
       │                   │                   │                   │
       │ 7. PKINIT ────────────────────────────────────────────────►
       │                   │                   │                   │
       │ 8. Kerberos TGT ◄─────────────────────────────────────────│
       │                   │                   │                   │
    Logged In!
```

## Source Files

| File | Description |
|------|-------------|
| `AuthentikAPI.cpp/h` | HTTP client with session/cookie management |
| `AuthentikCredential.cpp/h` | Login UI - username then OTP flow |
| `AuthentikCredentialProvider.cpp/h` | COM credential provider interface |
| `CertificateHelper.cpp/h` | Certificate parsing, PKINIT credential packing |
| `Dll.cpp` | DLL entry point, COM registration |
| `FieldDescriptors.h` | UI field definitions (username, OTP) |
| `Logger.h` | Debug logging (use DebugView to monitor) |

## Security Notes

- Certificates are short-lived (configurable, default 1 hour)
- Private keys are ephemeral (never written to disk)
- Set `IgnoreCertErrors=0` in production
- Use valid SSL certificates for Authentik

## License

MIT License - See [LICENSE](LICENSE)
