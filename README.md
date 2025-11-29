# Authentik Credential Provider for Windows

A Windows Credential Provider that integrates with Authentik for passwordless domain authentication using certificates and PKINIT.

## Features

- **True Passwordless**: No AD password required at the Windows logon screen
- **OTP Validation**: Authenticate with username + OTP only
- **Certificate-Based**: Uses X.509 certificates for Kerberos PKINIT authentication
- **Custom KSP**: Includes a Key Storage Provider for certificate-based Windows logon
- **Enterprise Ready**: Integrates with Active Directory Certificate Services (AD CS)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    AUTHENTICATION FLOW                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. User enters username + OTP at Windows logon                  │
│  2. Credential Provider validates OTP with Authentik             │
│  3. Authentik triggers certificate issuance from AD CS           │
│  4. Certificate + private key returned to workstation            │
│  5. Key stored in Authentik KSP shared memory                    │
│  6. KERB_CERTIFICATE_LOGON sent to Windows LSA                   │
│  7. Kerberos uses our KSP to sign PKINIT request                 │
│  8. Domain Controller validates certificate, issues TGT          │
│  9. User logged in - no password used!                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Components

| Component | Description | Location |
|-----------|-------------|----------|
| **AuthentikCredentialProvider.dll** | Windows Credential Provider | `src/AuthentikCredentialProvider/` |
| **AuthentikKSP.dll** | Custom Key Storage Provider | `src/AuthentikKSP/` |
| **CertIssuerService.ps1** | Certificate issuer service | `tools/cert-issuer/` |
| **Test-PKINITAuth.ps1** | Diagnostic tool | `tools/diagnostics/` |

## Prerequisites

- Windows 10/11 or Windows Server 2016+
- Active Directory domain
- Active Directory Certificate Services (AD CS)
- Authentik server with OTP configured
- Visual Studio 2022 (for building)

## Quick Start

See [DEPLOYMENT.md](docs/DEPLOYMENT.md) for detailed installation instructions.

### Build

```cmd
# Build KSP
cd src\AuthentikKSP
msbuild AuthentikKSP.vcxproj /p:Configuration=Release /p:Platform=x64

# Build Credential Provider
cd src\AuthentikCredentialProvider
msbuild AuthentikCredentialProvider.vcxproj /p:Configuration=Release /p:Platform=x64
```

### Install

```powershell
# Copy DLLs
Copy-Item "AuthentikKSP.dll" "C:\Windows\System32\"
Copy-Item "AuthentikCredentialProvider.dll" "C:\Windows\System32\"

# Register KSP (see docs/DEPLOYMENT.md for full script)
# Register Credential Provider
regsvr32 C:\Windows\System32\AuthentikCredentialProvider.dll

# Configure (see docs/DEPLOYMENT.md)
# Reboot
```

## Configuration

Registry settings at `HKLM\SOFTWARE\AuthentikCredentialProvider`:

| Key | Type | Description |
|-----|------|-------------|
| ServerUrl | REG_SZ | Authentik server hostname |
| ServerPort | REG_DWORD | Server port (default: 443) |
| FlowSlug | REG_SZ | Authentik flow slug |
| UseHttps | REG_DWORD | Use HTTPS (1) or HTTP (0) |
| CertIssuerUrl | REG_SZ | Certificate issuer service URL |
| CertIssuerToken | REG_SZ | API token for cert issuer |
| Domain | REG_SZ | NetBIOS domain name |
| DomainFQDN | REG_SZ | FQDN of domain |

## Documentation

- [Deployment Guide](docs/DEPLOYMENT.md) - Complete installation instructions
- [KSP README](src/AuthentikKSP/README.md) - Key Storage Provider details
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Common issues and solutions

## How It Works

### The Custom KSP

Windows Kerberos expects private keys to be available through a Key Storage Provider (KSP). 
Normally, this is handled by a smart card or TPM. Our custom KSP:

1. Stores certificates and private keys in secure shared memory
2. Provides keys to Kerberos when it needs to sign PKINIT requests
3. Cleans up keys after a configurable timeout

### PKINIT Authentication

Instead of sending a password hash to the Domain Controller, PKINIT:

1. Signs an authentication request with the user's private key
2. Includes the user's certificate in the request
3. The DC verifies the certificate chain and signature
4. Issues a TGT if valid (no password needed!)

## Security Considerations

- Keys are stored temporarily in memory (not on disk)
- Keys auto-expire after configurable timeout
- OTP provides the "something you have" factor
- Certificate provides cryptographic proof of identity
- No passwords stored or transmitted

### Production Hardening

- Enable SSL certificate validation
- Code sign the DLLs
- Encrypt sensitive registry values with DPAPI
- Restrict registry permissions

## Troubleshooting

### Debug Logging

Use DebugView to capture logs:
- Filter: `[AuthentikCP]` for credential provider
- Filter: `[AuthentikKSP]` for KSP

### Common Issues

| Issue | Solution |
|-------|----------|
| Credential provider not showing | Reboot, check registration |
| "Key not found" errors | Verify KSP is registered |
| Pre-Auth Type 2 in logs | KSP not being called, check CSP info |
| Certificate trust errors | Verify CA in NTAuth store |

## License

This project is provided as-is for educational and enterprise use.

## Acknowledgments

- Microsoft Windows Credential Provider samples
- Authentik project
- PrivacyIDEA credential provider for inspiration
