# Authentik Credential Provider for Windows

A Windows Credential Provider that enables passwordless authentication using Authentik as the identity provider.

## Current Status: Research Phase

**Important Discovery:** Windows PKINIT (certificate-based Kerberos authentication) requires a **smart card-compatible Key Storage Provider**. Software-based certificate storage does NOT work for domain logon, even with correctly structured KERB_CERTIFICATE_LOGON.

### What Works
- OTP authentication flow with Authentik API
- Certificate issuance from Authentik/internal CA
- Certificate storage in Windows certificate stores
- TPM Virtual Smart Card creation and certificate enrollment

### What Doesn't Work (Yet)
- PKINIT with software-based KSP (Microsoft Software KSP, Passport KSP)
- Direct KERB_CERTIFICATE_LOGON without smart card hardware/VSC

## Recommended Approach

Use **TPM Virtual Smart Card** for true PKINIT authentication. See [VSC-PKINIT-GUIDE.md](VSC-PKINIT-GUIDE.md) for complete instructions.

## Architecture Options

### Option 1: VSC + CSR-based Enrollment (Recommended)
1. User authenticates with Authentik (OTP)
2. Credential provider generates key on VSC
3. CSR sent to Authentik for signing
4. Certificate imported to VSC
5. PKINIT logon with VSC

### Option 2: Password Caching (Fallback)
1. User authenticates with Authentik (OTP)
2. Cached domain password used for Kerberos
3. Less secure but simpler implementation

### Option 3: AD FS Integration
1. Configure AD FS with Authentik as claims provider
2. Use existing smart card infrastructure
3. Requires AD FS deployment

## Building

### Prerequisites
- Visual Studio 2019 or later
- Windows SDK
- C++ Desktop Development workload

### Build Steps
1. Open `AuthentikCredentialProvider.sln` in Visual Studio
2. Select Release/x64 configuration
3. Build solution
4. Copy DLL to `C:\Windows\System32\`
5. Register with `regsvr32 AuthentikCredentialProvider.dll`

## Configuration

Edit `%PROGRAMDATA%\AuthentikCredentialProvider\config.json`:

```json
{
  "authentik_url": "https://authentik.example.com",
  "client_id": "your-client-id",
  "flow_slug": "your-flow-slug"
}
```

## Project Structure

```
src/
├── AuthentikCredentialProvider/
│   ├── AuthentikCredential.cpp      # Main credential implementation
│   ├── AuthentikProvider.cpp        # Provider registration
│   ├── CertificateHelper.cpp        # Certificate operations
│   ├── AuthentikAPI.cpp             # Authentik API client
│   └── ...
├── AuthentikKSP/                    # Custom KSP (experimental)
└── Shared/                          # Shared utilities
```

## Key Files

- `CertificateHelper.cpp` - Certificate import, CSP info building, PKINIT structures
- `AuthentikCredential.cpp` - Logon flow, credential packaging
- `VSC-PKINIT-GUIDE.md` - Complete guide for VSC-based authentication

## Technical Notes

### Why Software KSP Fails for PKINIT

The Windows Kerberos SSP validates that certificates used for PKINIT come from smart card-compatible providers. When using KERB_CERTIFICATE_LOGON with software-based keys:

1. Kerberos SSP receives the logon request
2. Checks the CSP/KSP provider type
3. Rejects non-smart-card providers
4. Falls back to password authentication (which fails with empty password)

Evidence in Kerberos debug logs:
```
Error Code: 0x19 KDC_ERR_PREAUTH_REQUIRED
Client Realm: (empty)
Client Name: (empty)
```

Empty client realm/name indicates PKINIT was not attempted.

### Certificate Requirements for Smart Card Logon

1. **EKUs:**
   - Smart Card Logon (1.3.6.1.4.1.311.20.2.2)
   - Client Authentication (1.3.6.1.5.5.7.3.2)

2. **Subject Alternative Name:**
   - Must contain UPN matching AD user's userPrincipalName
   - Format: `shop@test.local`

3. **Key Storage:**
   - Must be on smart card or TPM Virtual Smart Card
   - Private key never exportable

4. **Trust Chain:**
   - CA must be in NTAuth store
   - DC must have valid KDC certificate

## Contributing

This is an experimental project. Contributions welcome, especially:
- VSC integration code
- CSR generation on smart card
- Authentik CSR signing endpoint

## License

MIT License
