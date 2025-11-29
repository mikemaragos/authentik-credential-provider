# Authentik Windows Credential Provider

Windows Credential Providers for domain authentication with Authentik identity provider.

## Projects

This repository contains two credential provider implementations:

### 1. Password + OTP Credential Provider (Original)
**Location:** `src/AuthentikCredentialProvider/`

Traditional authentication flow:
- Username + Password + OTP
- OTP validated by Authentik
- Password used for Kerberos authentication
- **Use case:** Add OTP to existing password-based authentication

### 2. Passwordless Credential Provider (New) ⭐
**Location:** `src/AuthentikPasswordlessCP/`

True passwordless authentication:
- Username + OTP only (no password!)
- Authentik validates identity and requests certificate from AD CS
- Certificate used for Kerberos PKINIT authentication
- **Use case:** Eliminate passwords entirely

## Architecture Comparison

| Feature | Password + OTP | Passwordless |
|---------|---------------|--------------|
| User enters password | ✅ Yes | ❌ No |
| OTP required | ✅ Yes | ✅ Yes |
| Authentication method | Kerberos (password) | PKINIT (certificate) |
| AD CS required | ❌ No | ✅ Yes |
| Credential type | `KERB_INTERACTIVE_LOGON` | `KERB_CERTIFICATE_LOGON` |

## Passwordless Authentication Flow

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Windows    │     │   Authentik  │     │    AD CS     │     │   Domain     │
│   Client     │     │    Server    │     │     (CA)     │     │  Controller  │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │                    │
       │ 1. Username        │                    │                    │
       │───────────────────►│                    │                    │
       │                    │                    │                    │
       │ 2. OTP Challenge   │                    │                    │
       │◄───────────────────│                    │                    │
       │                    │                    │                    │
       │ 3. OTP Code        │                    │                    │
       │───────────────────►│                    │                    │
       │                    │                    │                    │
       │                    │ 4. Request Cert    │                    │
       │                    │───────────────────►│                    │
       │                    │                    │                    │
       │                    │ 5. Certificate     │                    │
       │                    │◄───────────────────│                    │
       │                    │                    │                    │
       │ 6. Cert + Key      │                    │                    │
       │◄───────────────────│                    │                    │
       │                    │                    │                    │
       │ 7. PKINIT (Certificate-based Kerberos)  │                    │
       │─────────────────────────────────────────────────────────────►│
       │                    │                    │                    │
       │ 8. Kerberos TGT    │                    │                    │
       │◄─────────────────────────────────────────────────────────────│
       │                    │                    │                    │
       ▼                    ▼                    ▼                    ▼
   User Logged In!
```

## Quick Start

### Passwordless (Recommended)

1. **Configure AD CS** - See [ADCS_SETUP.md](docs/PasswordlessCP_ADCS_SETUP.md)
2. **Configure Authentik** - Add certificate issuance stage to your flow
3. **Build & Install**:
   ```powershell
   # Build
   msbuild src\AuthentikPasswordlessCP\AuthentikPasswordlessCP.vcxproj /p:Configuration=Release /p:Platform=x64
   
   # Install (Admin)
   copy x64\Release\AuthentikPasswordlessCP.dll C:\Windows\System32\
   regsvr32 C:\Windows\System32\AuthentikPasswordlessCP.dll
   ```
4. **Configure Registry**:
   ```
   HKLM\SOFTWARE\AuthentikPasswordlessCP
   ├── ServerUrl = "authentik.example.com"
   ├── Domain = "YOURDOMAIN"
   └── ...
   ```
5. **Reboot**

### Password + OTP (Original)

See [original documentation](docs/README.md)

## Prerequisites

### Client
- Windows 10/11 or Windows Server 2016+
- Domain-joined machine
- Visual Studio 2022 for building

### Server (Passwordless)
- Authentik server with LDAP integration
- AD CS (Enterprise CA) on domain controller
- Certificate template for Smart Card Logon

## Documentation

### Passwordless Credential Provider
- [README](docs/PasswordlessCP_README.md) - Full documentation
- [Quick Start](docs/PasswordlessCP_QUICKSTART.md) - 5-minute setup
- [AD CS Setup](docs/PasswordlessCP_ADCS_SETUP.md) - Certificate Authority configuration
- [Architecture](docs/PasswordlessCP_ARCHITECTURE_ADCS.md) - Detailed architecture with AD CS
- [Knowledge Base](docs/PasswordlessCP_KNOWLEDGE_BASE.md) - Technical reference

### Original Password + OTP Provider
- [README](docs/README.md)
- [Knowledge Base](KNOWLEDGE_BASE.md)

## Repository Structure

```
authentik-credential-provider/
├── src/
│   ├── AuthentikCredentialProvider/     # Original: Password + OTP
│   │   ├── AuthentikAPI.cpp/h
│   │   ├── AuthentikCredential.cpp/h
│   │   ├── AuthentikCredentialProvider.cpp/h
│   │   ├── CredentialPacking.cpp/h      # KERB_INTERACTIVE_LOGON
│   │   └── ...
│   │
│   └── AuthentikPasswordlessCP/         # New: Passwordless + Certificate
│       ├── AuthentikAPI.cpp/h           # HTTP client with session management
│       ├── AuthentikCredential.cpp/h    # Username → OTP flow
│       ├── AuthentikCredentialProvider.cpp/h
│       ├── CertificateHelper.cpp/h      # Certificate parsing, PKINIT packing
│       └── ...
│
├── docs/
│   ├── PasswordlessCP_*.md              # Passwordless documentation
│   └── *.md                             # Original documentation
│
└── tools/
    └── *.ps1                            # Deployment scripts
```

## Security Considerations

### Production Checklist
- [ ] Use valid SSL certificates (disable `IgnoreCertErrors`)
- [ ] Use short-lived certificates (1 hour or less)
- [ ] Limit AD CS template enrollment to service account
- [ ] Enable audit logging on Authentik and AD CS
- [ ] Code sign the DLL
- [ ] Test in isolated environment before production

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

MIT License - See [LICENSE](LICENSE)

## Support

- Review debug logs (DebugView for `[AuthentikPwdlessCP]` messages)
- Check Authentik server logs
- Check Windows Event Viewer (Security, Kerberos-Key-Distribution-Center)
- Check AD CS certificate issuance logs

---

**⚠️ Note:** Always test in a lab environment before deploying to production. Keep recovery access available (Safe Mode, local admin account).
