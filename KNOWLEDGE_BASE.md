# Authentik Passwordless Credential Provider - Knowledge Base

## Document Purpose

This document captures ALL technical decisions, architecture details, and implementation knowledge for the Authentik Passwordless Windows Credential Provider project. Use this as the authoritative reference when resuming or extending this project.

**Last Updated:** November 2025  
**Project Status:** Core implementation complete, ready for testing  
**Key Architecture:** Passwordless with AD CS certificate-based PKINIT

---

## Project Evolution

### Previous Version (Password + OTP)
- User entered username + password + OTP
- OTP validated by Authentik
- Password still used for Windows Kerberos auth
- **Limitation:** Still required password

### Current Version (Passwordless + AD CS Certificate)
- User enters username + OTP only
- Authentik validates identity via OTP
- Authentik requests certificate from **AD CS (Enterprise CA)**
- Certificate used for PKINIT (certificate-based Kerberos)
- **Advantage:** True passwordless, leverages existing AD CS infrastructure

---

## Architecture Decisions

### Why AD CS Instead of Authentik-Generated Certificates?

| Approach | Pros | Cons |
|----------|------|------|
| Authentik-generated | Simple, self-contained | Must configure NTAuth trust manually |
| **AD CS (Enterprise CA)** | Auto-trusted, existing infrastructure, audit logging | Requires AD CS integration code |

We chose AD CS because:
- Enterprise CA certificates are **automatically trusted** by all domain members
- No manual NTAuth store configuration needed
- Leverages existing PKI infrastructure
- Built-in auditing and certificate lifecycle management
- Template-based control over certificate properties

---

## Critical Technical Details

### Certificate Requirements for PKINIT

For Windows to accept a certificate for domain logon:

```
1. SUBJECT ALTERNATIVE NAME (CRITICAL)
   - Must contain: otherName:1.3.6.1.4.1.311.20.2.3;UTF8:user@domain.local
   - This is the UPN (User Principal Name)
   - Must match user's AD userPrincipalName attribute

2. EXTENDED KEY USAGE
   - Smart Card Logon: 1.3.6.1.4.1.311.20.2.2 (REQUIRED)
   - Client Authentication: 1.3.6.1.5.5.7.3.2 (Recommended)

3. KEY USAGE
   - Digital Signature (REQUIRED)
   - Key Encipherment (Recommended)

4. CERTIFICATE CHAIN
   - Must chain to a CA in the NTAuth store
   - Cannot be self-signed
```

### NTAuth Store

The CA certificate **must** be published to NTAuth:

```powershell
# Publish to NTAuth (required for PKINIT)
certutil -dspublish -f authentik-ca.crt NTAuthCA

# Verify
certutil -viewstore "ldap:///CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=yourdomain,DC=local?cACertificate"
```

Without this, the DC will reject the certificate with `KDC_ERR_CLIENT_NOT_TRUSTED`.

### KERB_CERTIFICATE_LOGON Structure

```cpp
typedef struct _KERB_CERTIFICATE_LOGON {
    KERB_LOGON_SUBMIT_TYPE MessageType;  // = 13 (KerbCertificateLogon)
    UNICODE_STRING DomainName;           // NetBIOS domain
    UNICODE_STRING UserName;             // SAM account name
    UNICODE_STRING Pin;                  // Empty for us
    ULONG Flags;                         // KERB_CERTIFICATE_LOGON_FLAG_CHECK_DUPLICATES
    ULONG CspDataLength;                 // Size of CSP info
    PUCHAR CspData;                      // KERB_SMARTCARD_CSP_INFO
} KERB_CERTIFICATE_LOGON;
```

The `CspData` contains information about where to find the certificate and key:
- Provider name (Microsoft Software Key Storage Provider)
- Container name (our ephemeral key container)
- Reader name (empty for software keys)
- Card name (empty for software keys)

### Memory Allocation

**Critical:** Use `CoTaskMemAlloc` for all credential serialization buffers. The Windows credential system expects COM-allocated memory and will call `CoTaskMemFree` to release it.

### Cookie/Session Management

Authentik uses session cookies for multi-step flows. The API implementation:
1. Saves `Set-Cookie` headers after each response
2. Sends stored cookies with subsequent requests
3. This maintains the authentication flow state server-side

---

## Authentication Flow Details

### Step 1: Username Submission

```
Client → Authentik: POST /api/v3/flows/executor/{flow}/
                    {"uid_field": "mike"}

Authentik → Client: {
    "type": "native",
    "component": "ak-stage-authenticator-validate",
    ...
}
```

### Step 2: OTP Submission

```
Client → Authentik: POST /api/v3/flows/executor/{flow}/
                    {"code": "123456"}
                    Cookie: authentik_session=...

Authentik → Client: {
    "type": "redirect",
    "certificate": "-----BEGIN CERTIFICATE-----...",
    "private_key": "-----BEGIN PRIVATE KEY-----...",
    "username": "mike",
    "domain": "TEST",
    "upn": "mike@test.local"
}
```

### Step 3: Certificate Processing

1. Parse PEM certificate and private key
2. Convert to DER format
3. Import private key to ephemeral NCrypt container
4. Create PCCERT_CONTEXT with certificate
5. Associate key handle with certificate
6. Build KERB_CERTIFICATE_LOGON structure
7. Return serialized credentials to Windows

### Step 4: Windows PKINIT

Windows handles:
1. Connecting to Domain Controller
2. Sending PKINIT AS-REQ with certificate
3. DC validates certificate chain, UPN mapping
4. DC issues Kerberos TGT
5. User logged in

---

## File Structure

```
AuthentikPasswordlessCP/
├── AuthentikAPI.cpp/h           # HTTP client with session management
├── AuthentikCredential.cpp/h    # Login tile, UI flow, step handling
├── AuthentikCredentialProvider.cpp/h  # COM interface, provider registration
├── CertificateHelper.cpp/h      # PEM parsing, key import, PKINIT packing
├── FieldDescriptors.h           # UI fields (username, OTP only)
├── Dll.cpp                      # DLL entry, COM class factory, registration
├── guid.h                       # CLSID definition
├── Logger.h                     # Debug logging via OutputDebugString
├── AuthentikPasswordlessCP.def  # DLL exports
├── AuthentikPasswordlessCP.vcxproj  # Visual Studio project
├── README.md                    # User documentation
├── QUICKSTART.md                # Quick setup guide
├── ARCHITECTURE.md              # Detailed architecture diagram
└── KNOWLEDGE_BASE.md            # This file
```

---

## Known Issues and Limitations

### Current Limitations

1. **No Offline Support** - Requires network connectivity to Authentik
2. **Simple JSON Parsing** - Uses string matching (consider proper JSON library)
3. **Single Domain** - Configured for one domain (could be extended)
4. **No Push Notification Wait** - User must manually enter code

### Potential Issues

1. **Certificate Timing** - If certificate expires during login, auth fails
2. **Clock Skew** - Kerberos sensitive to time differences
3. **DC Connectivity** - Credential provider assumes DC is reachable

---

## Security Considerations

### Implemented

- Private key never stored on disk
- SecureZeroMemory for sensitive data cleanup
- Short-lived certificates (5 minutes default)
- TLS for Authentik communication

### TODO for Production

- [ ] Enable SSL certificate validation (`IgnoreCertErrors = 0`)
- [ ] Implement certificate pinning
- [ ] Code sign the DLL
- [ ] Implement proper error sanitization (don't leak internal errors)
- [ ] Add Windows Event Log integration
- [ ] Implement certificate revocation checking

---

## Testing Checklist

### Build Verification

- [ ] Compiles without errors/warnings
- [ ] DLL loads without missing dependencies
- [ ] Registration succeeds (`regsvr32`)
- [ ] Provider appears after reboot

### Functional Testing

- [ ] Username step displays correctly
- [ ] API call reaches Authentik
- [ ] OTP step displays after username
- [ ] Certificate received after OTP
- [ ] Login succeeds with certificate
- [ ] Kerberos TGT obtained (verify with `klist`)

### Error Handling

- [ ] Empty username shows error
- [ ] Empty OTP shows error
- [ ] Invalid OTP shows error (and allows retry)
- [ ] Network failure shows appropriate message
- [ ] Certificate parsing failure handled
- [ ] Invalid certificate (wrong CA) handled

### Security Testing

- [ ] OTP not logged (check DebugView)
- [ ] Private key cleared from memory
- [ ] Failed auth resets state properly
- [ ] Certificate not persisted to disk

---

## Deployment

### Prerequisites on Target Machines

1. Visual C++ Redistributable (if not statically linked)
2. Windows 10/11 or Server 2016+
3. Domain-joined
4. Network access to Authentik server
5. Network access to Domain Controller

### Deployment Options

1. **Manual**: Copy DLL + regsvr32
2. **GPO**: Deploy via Group Policy
3. **SCCM/Intune**: Package as application
4. **PowerShell**: Scripted deployment

### Registry Configuration Template

```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\AuthentikPasswordlessCP]
"ServerUrl"="authentik.example.com"
"ServerPort"=dword:000001bb
"FlowSlug"="windows-passwordless"
"UseHttps"=dword:00000001
"Domain"="YOURDOMAIN"
"DomainFQDN"="yourdomain.local"
"CertValidMinutes"=dword:00000005
"IgnoreCertErrors"=dword:00000000
```

---

## Authentik Server Configuration

### Required Custom Development

Authentik does not natively issue certificates for PKINIT. You need:

1. **Custom Stage** or **Policy** that:
   - Generates RSA 2048 or ECDSA P-256 key pair
   - Creates CSR with proper SAN (UPN)
   - Signs with your CA
   - Returns certificate + private key in JSON response

2. **Internal CA** that:
   - Is trusted by AD (NTAuth)
   - Can issue short-lived certs
   - Has Smart Card Logon EKU in template

### Alternative: AD CS Integration

Instead of Authentik issuing certs:
1. Authentik authenticates user
2. Authentik calls AD CS web enrollment
3. AD CS issues certificate
4. Authentik returns cert to client

This is more complex but leverages existing AD CS infrastructure.

---

## Comparison with Previous Password+OTP Version

| Aspect | Password+OTP | Passwordless (Certificate) |
|--------|-------------|---------------------------|
| User Experience | Username + Password + OTP | Username + OTP only |
| Password Required | Yes | No |
| Credential Type | KERB_INTERACTIVE_LOGON | KERB_CERTIFICATE_LOGON |
| Server Requirement | OTP validation only | OTP + Certificate issuance |
| AD Requirement | Standard | NTAuth CA trust |
| Complexity | Lower | Higher |
| Security | Password exposure | No password exposure |

---

## Future Enhancements

### Priority 1 (Should Have)

- [ ] Push notification support with polling
- [ ] WebAuthn/FIDO2 support
- [ ] Proper JSON parsing library
- [ ] Windows Event Log integration

### Priority 2 (Nice to Have)

- [ ] Offline authentication with cached short-lived cert
- [ ] Multiple domain support
- [ ] Device certificate binding
- [ ] Custom branding/logo

### Priority 3 (Future)

- [ ] Integration with Windows Hello
- [ ] TPM-backed key generation
- [ ] Certificate auto-renewal background service

---

## References

### Microsoft Documentation
- [Credential Providers](https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
- [PKINIT Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pkca/)
- [Smart Card Architecture](https://docs.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-architecture)
- [NTAuth Store](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/requirements-smart-card-logon)

### Sample Code
- [Windows SDK Credential Provider Sample](https://github.com/Microsoft/Windows-classic-samples/tree/master/Samples/CredentialProvider)
- [PrivacyIDEA Credential Provider](https://github.com/privacyidea/privacyidea-credential-provider)

### Specifications
- [RFC 4556 - PKINIT](https://datatracker.ietf.org/doc/html/rfc4556)
- [RFC 5280 - X.509 PKI](https://datatracker.ietf.org/doc/html/rfc5280)

---

**Document Version:** 2.0 (Passwordless Certificate-Based)  
**Last Updated:** November 2025
