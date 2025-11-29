# Authentik Passwordless Credential Provider for Windows

A Windows Credential Provider that enables passwordless domain authentication using Authentik and PKINIT certificates.

## Overview

This credential provider allows Windows domain users to authenticate without passwords by:
1. Entering their username
2. Providing an OTP code (TOTP, push notification, etc.)
3. Receiving a short-lived certificate from AD CS
4. Authenticating via Kerberos PKINIT

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Windows   │────▶│  Authentik  │────▶│   AD CS     │────▶│   Domain    │
│   Login     │     │  (OTP)      │     │  (Cert)     │     │ Controller  │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
```

## Features

- **Passwordless Authentication** - No password required for domain login
- **Multi-Factor** - OTP verification through Authentik
- **Short-Lived Certificates** - 15-minute certificates minimize risk
- **Standard Kerberos** - Uses native Windows PKINIT
- **Enterprise Ready** - GPO deployment, logging, recovery options

## Documentation

| Document | Description |
|----------|-------------|
| [Authentik Setup](docs/AUTHENTIK_SETUP.md) | Configure Authentik server and flows |
| [Windows Deployment](docs/WINDOWS_DEPLOYMENT.md) | Deploy to Windows workstations |
| [AD CS Setup](docs/ADCS_SETUP.md) | Configure certificate services |
| [Architecture](docs/ARCHITECTURE_ADCS.md) | Technical architecture details |

## Quick Start

### Prerequisites

- Authentik server (2023.x+)
- Windows Server with AD CS
- Domain-joined Windows 10/11 workstations
- Users with TOTP configured in Authentik

### 1. Build the Credential Provider

```powershell
# Open in Visual Studio 2022
# Build → Build Solution (Release/x64)
```

### 2. Deploy to Workstation

```powershell
# Copy DLL
copy x64\Release\AuthentikCredentialProvider.dll C:\Windows\System32\

# Register
regsvr32 C:\Windows\System32\AuthentikCredentialProvider.dll

# Configure
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v ServerUrl /t REG_SZ /d "authentik.company.com" /f
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v FlowSlug /t REG_SZ /d "windows-passwordless" /f
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v Domain /t REG_SZ /d "COMPANY" /f
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v DomainFQDN /t REG_SZ /d "company.local" /f
```

### 3. Configure Authentik

See [Authentik Setup Guide](docs/AUTHENTIK_SETUP.md) for complete instructions.

### 4. Test

1. Lock workstation (Win + L)
2. Select "Authentik Passwordless Login"
3. Enter username → Enter OTP
4. Authenticate!

## Project Structure

```
├── src/
│   └── AuthentikCredentialProvider/
│       ├── AuthentikAPI.cpp/h         # HTTP client for Authentik
│       ├── AuthentikCredential.cpp/h  # Credential tile implementation
│       ├── AuthentikCredentialProvider.cpp/h  # Main provider
│       ├── CertificateHelper.cpp/h    # Certificate handling
│       ├── FieldDescriptors.h         # UI field definitions
│       ├── Dll.cpp                    # DLL entry point
│       ├── guid.cpp/h                 # COM GUID
│       └── Logger.h                   # Debug logging
├── docs/
│   ├── AUTHENTIK_SETUP.md            # Authentik configuration
│   ├── WINDOWS_DEPLOYMENT.md         # Windows deployment
│   ├── ADCS_SETUP.md                 # AD CS configuration
│   └── ARCHITECTURE_ADCS.md          # Technical architecture
└── README.md
```

## Registry Configuration

| Setting | Type | Description |
|---------|------|-------------|
| ServerUrl | REG_SZ | Authentik server hostname |
| ServerPort | REG_DWORD | HTTPS port (default: 443) |
| FlowSlug | REG_SZ | Authentik flow slug |
| UseHttps | REG_DWORD | Use HTTPS (1=yes) |
| Domain | REG_SZ | NetBIOS domain name |
| DomainFQDN | REG_SZ | Full domain name |
| IgnoreCertErrors | REG_DWORD | Skip SSL validation (testing only) |

## Troubleshooting

### Debug Logging

Use [DebugView](https://docs.microsoft.com/en-us/sysinternals/downloads/debugview) to see real-time logs:
1. Run DebugView as Administrator
2. Enable Capture → Capture Global Win32
3. Filter for `[AuthentikPwdlessCP]`

### Common Issues

| Issue | Solution |
|-------|----------|
| Tile not showing | Re-register DLL, reboot |
| HTTP 405 error | Check FlowSlug matches Authentik |
| SSL errors | Set IgnoreCertErrors=1 for testing |
| Login fails | Check DebugView for detailed error |

See [Windows Deployment Guide](docs/WINDOWS_DEPLOYMENT.md) for more troubleshooting.

## Security Considerations

- **Testing**: `IgnoreCertErrors=1` is acceptable
- **Production**: Use valid SSL certificates, set `IgnoreCertErrors=0`
- **Certificates**: Keep validity short (15 minutes recommended)
- **Recovery**: Always maintain alternate login method

## Requirements

### Build Requirements
- Visual Studio 2022
- Windows SDK 10.0.19041.0+
- C++ Desktop Development workload

### Runtime Requirements
- Windows 10/11 or Server 2016+
- Visual C++ Redistributable 2019+
- Domain membership
- Network access to Authentik

## License

This project is provided for educational and testing purposes.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Acknowledgments

- Microsoft Credential Provider samples
- Authentik project
- PrivacyIDEA Credential Provider (inspiration)
