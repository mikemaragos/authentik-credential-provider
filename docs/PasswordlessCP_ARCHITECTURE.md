# Authentik Passwordless Credential Provider - Architecture

## Overview

This credential provider enables **true passwordless Windows domain authentication** using:
- **Authentik** for identity verification (username + OTP)
- **Short-lived certificates** for Kerberos PKINIT authentication
- **No password required** - certificate replaces password for domain auth

## Authentication Flow

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                            WINDOWS LOGIN SCREEN                               │
│                                                                               │
│    ┌────────────────────────────────────────────────────────────────────┐    │
│    │                  Authentik Passwordless Login                       │    │
│    │                                                                     │    │
│    │    Username: [mike                    ]                             │    │
│    │                                                                     │    │
│    │    [Sign In]                                                        │    │
│    │                                                                     │    │
│    └────────────────────────────────────────────────────────────────────┘    │
│                                          │                                    │
└──────────────────────────────────────────┼────────────────────────────────────┘
                                           │
                    Step 1: Initiate Auth  │  POST /api/v3/flows/executor/{flow}/
                         (username)        │
                                           ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                              AUTHENTIK SERVER                                 │
│                                                                               │
│   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────────────┐ │
│   │  Identification │───►│  OTP Challenge  │───►│  Certificate Issuance   │ │
│   │     Stage       │    │     Stage       │    │        Stage            │ │
│   │                 │    │                 │    │                         │ │
│   │  - LDAP Lookup  │    │  - TOTP         │    │  - Generate Key Pair    │ │
│   │  - User Valid?  │    │  - Push         │    │  - Create CSR           │ │
│   │                 │    │  - WebAuthn     │    │  - Sign with CA         │ │
│   │                 │    │  - SMS/Email    │    │  - Return Cert + Key    │ │
│   └─────────────────┘    └─────────────────┘    └─────────────────────────┘ │
│                                                                               │
└───────────────────────────────────────────┬──────────────────────────────────┘
                                            │
                    Step 2: OTP Challenge   │  Response: {type: "native", 
                                            │             component: "ak-stage-authenticator"}
                                            ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                            WINDOWS LOGIN SCREEN                               │
│                                                                               │
│    ┌────────────────────────────────────────────────────────────────────┐    │
│    │                  Authentik Passwordless Login                       │    │
│    │                                                                     │    │
│    │    Username: mike                                                   │    │
│    │                                                                     │    │
│    │    OTP Code: [123456]                                               │    │
│    │                                                                     │    │
│    │    [Verify]                                                         │    │
│    │                                                                     │    │
│    └────────────────────────────────────────────────────────────────────┘    │
│                                          │                                    │
└──────────────────────────────────────────┼────────────────────────────────────┘
                                           │
                    Step 3: Submit OTP     │  POST /api/v3/flows/executor/{flow}/
                                           │       {code: "123456"}
                                           ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                              AUTHENTIK SERVER                                 │
│                                                                               │
│   OTP Valid? ──► YES ──► Generate Certificate:                               │
│                          {                                                    │
│                            "certificate": "-----BEGIN CERTIFICATE-----...",  │
│                            "private_key": "-----BEGIN PRIVATE KEY-----...",  │
│                            "ca_chain": ["-----BEGIN CERTIFICATE-----..."],   │
│                            "username": "mike",                                │
│                            "domain": "TEST.LOCAL",                            │
│                            "upn": "mike@test.local",                          │
│                            "valid_minutes": 5                                 │
│                          }                                                    │
│                                                                               │
└───────────────────────────────────────────┬──────────────────────────────────┘
                                            │
                    Step 4: Receive Cert    │  Response includes certificate bundle
                                            ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                         CREDENTIAL PROVIDER                                   │
│                                                                               │
│   1. Parse certificate response                                              │
│   2. Import certificate + private key to temporary store                     │
│   3. Build KERB_CERTIFICATE_LOGON structure                                  │
│   4. Return serialization to LogonUI                                         │
│                                                                               │
└───────────────────────────────────────────┬──────────────────────────────────┘
                                            │
                    Step 5: PKINIT          │  Certificate-based Kerberos
                                            ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                        ACTIVE DIRECTORY DOMAIN CONTROLLER                     │
│                                                                               │
│   1. Receive PKINIT request with certificate                                 │
│   2. Validate certificate:                                                   │
│      - Chain to trusted CA (Enterprise CA or trusted root)                   │
│      - Not expired                                                           │
│      - Not revoked (CRL/OCSP)                                                │
│      - Has Smart Card Logon EKU (1.3.6.1.4.1.311.20.2.2)                     │
│   3. Map certificate to user:                                                │
│      - UPN in SAN matches AD user's UPN                                      │
│      - Or explicit certificate mapping                                       │
│   4. Issue Kerberos TGT                                                      │
│   5. User logged in!                                                         │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Certificate Requirements

### For PKINIT to work, the certificate MUST have:

1. **Subject Alternative Name (SAN)**
   - `otherName:1.3.6.1.4.1.311.20.2.3;UTF8:user@domain.local` (UPN)

2. **Extended Key Usage (EKU)**
   - Smart Card Logon: `1.3.6.1.4.1.311.20.2.2`
   - Client Authentication: `1.3.6.1.5.5.7.3.2`

3. **Key Usage**
   - Digital Signature
   - Key Encipherment

4. **Trusted Certificate Chain**
   - Must chain to a CA trusted by the domain
   - Options:
     - AD CS Enterprise CA (automatic trust)
     - Standalone CA added to NTAuth store
     - Authentik as subordinate CA

### Certificate Template (AD CS equivalent)

```
Template Name: Authentik Smart Card Logon
Key Usage: Digital Signature, Key Encipherment
Enhanced Key Usage: 
  - Smart Card Logon (1.3.6.1.4.1.311.20.2.2)
  - Client Authentication (1.3.6.1.5.5.7.3.2)
Subject Name: Supply in request
SAN: Include UPN from request
Validity: 5-15 minutes (short-lived)
Key Size: 2048-bit RSA or P-256 ECDSA
```

## Components

### 1. Credential Provider (Windows Client)

```
AuthentikPasswordlessCP/
├── AuthentikCredentialProvider.cpp/h    # Main provider (ICredentialProvider)
├── AuthentikCredential.cpp/h            # Credential tile (ICredentialProviderCredential)
├── AuthentikAPI.cpp/h                   # HTTP client for Authentik
├── CertificateHelper.cpp/h              # Certificate parsing and import
├── CredentialPacking.cpp/h              # KERB_CERTIFICATE_LOGON serialization
├── FieldDescriptors.h                   # UI field definitions
├── Dll.cpp                              # COM registration
├── guid.h                               # GUIDs
└── Logger.h                             # Debug logging
```

### 2. Authentik Server (Backend)

Required components:
- **Custom Stage or Policy** for certificate generation
- **Internal CA** or connection to AD CS
- **API endpoint** returning certificate bundle

### 3. Active Directory Configuration

Required setup:
- **NTAuth Store** must trust the signing CA
- **Certificate Mapping** (UPN or explicit)
- **PKINIT enabled** on domain controllers

## Data Structures

### KERB_CERTIFICATE_LOGON (Windows)

```cpp
typedef struct _KERB_CERTIFICATE_LOGON {
    KERB_LOGON_SUBMIT_TYPE MessageType;  // KerbCertificateLogon (13)
    UNICODE_STRING DomainName;
    UNICODE_STRING UserName;
    UNICODE_STRING Pin;                   // Empty for our use case
    ULONG Flags;                          // KERB_CERTIFICATE_LOGON_FLAG_CHECK_DUPLICATES
    ULONG CspDataLength;
    PUCHAR CspData;                       // KERB_SMARTCARD_CSP_INFO structure
} KERB_CERTIFICATE_LOGON, *PKERB_CERTIFICATE_LOGON;
```

### KERB_SMARTCARD_CSP_INFO

```cpp
typedef struct _KERB_SMARTCARD_CSP_INFO {
    DWORD dwCspInfoLen;
    DWORD MessageType;                    // 1
    union {
        PVOID ContextInformation;
        ULONG64 SpaceHolderForWow64;
    };
    DWORD flags;
    DWORD KeySpec;                        // AT_KEYEXCHANGE
    ULONG nCardNameOffset;
    ULONG nReaderNameOffset;
    ULONG nContainerNameOffset;
    ULONG nCSPNameOffset;
    TCHAR bBuffer[ANYSIZE_ARRAY];         // Card, Reader, Container, CSP names
} KERB_SMARTCARD_CSP_INFO;
```

### Authentik Certificate Response (JSON)

```json
{
    "type": "redirect",
    "to": "...",
    "certificate_bundle": {
        "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
        "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
        "ca_chain": [
            "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
        ],
        "username": "mike",
        "domain": "TEST",
        "upn": "mike@test.local",
        "valid_until": "2025-11-22T15:30:00Z"
    }
}
```

## Security Considerations

### Certificate Security
1. **Short validity** - 5-15 minutes maximum
2. **One-time use** - Revoke after successful login (optional)
3. **Encrypted transport** - TLS 1.3 for API communication
4. **Private key protection** - Never stored on disk, memory-only
5. **Secure cleanup** - SecureZeroMemory for all sensitive data

### Authentication Security
1. **OTP required** - No password fallback
2. **Rate limiting** - Prevent brute force on OTP
3. **Audit logging** - Log all authentication attempts
4. **Device binding** - Optional machine certificate for device trust

### Transport Security
1. **TLS 1.3** - Modern encryption only
2. **Certificate pinning** - Pin Authentik server certificate
3. **No fallback** - Fail if security requirements not met

## Registry Configuration

```
HKEY_LOCAL_MACHINE\SOFTWARE\AuthentikPasswordlessCP
├── ServerUrl (REG_SZ) = "authentik.example.com"
├── ServerPort (REG_DWORD) = 443
├── FlowSlug (REG_SZ) = "windows-passwordless"
├── UseHttps (REG_DWORD) = 1
├── CertValidityMinutes (REG_DWORD) = 5
├── Domain (REG_SZ) = "TEST"
├── DomainFQDN (REG_SZ) = "test.local"
└── RequireDeviceCert (REG_DWORD) = 0
```

## Implementation Phases

### Phase 1: Basic Certificate Logon
- [ ] Modify credential provider for username + OTP only
- [ ] Implement certificate parsing from Authentik response
- [ ] Implement KERB_CERTIFICATE_LOGON packing
- [ ] Test with pre-generated certificates

### Phase 2: Authentik Integration
- [ ] Create Authentik flow for certificate issuance
- [ ] Configure Authentik CA (or AD CS integration)
- [ ] Implement certificate response handling
- [ ] End-to-end testing

### Phase 3: Security Hardening
- [ ] Enable certificate pinning
- [ ] Implement secure memory handling
- [ ] Add certificate revocation checking
- [ ] Audit logging integration

### Phase 4: Production Features
- [ ] Offline caching (optional)
- [ ] Device certificate binding
- [ ] Group Policy configuration
- [ ] MSI installer

## Dependencies

### Windows Client
- Windows 10/11 or Windows Server 2016+
- Visual Studio 2019/2022
- Windows SDK 10.0.19041+
- Libraries: NCrypt, CNG, WinHTTP, Crypt32

### Authentik Server
- Authentik 2024.x+
- Python 3.11+
- cryptography library
- Custom stage/policy for cert issuance

### Active Directory
- Windows Server 2016+ Domain Controllers
- PKINIT enabled
- NTAuth store configured
- Certificate mapping configured

## References

- [MS-PKCA: PKINIT Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pkca/)
- [Credential Provider Technical Reference](https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
- [Smart Card Logon](https://docs.microsoft.com/en-us/windows/security/identity-protection/smart-cards/)
- [Certificate Autoenrollment](https://docs.microsoft.com/en-us/windows-server/networking/core-network-guide/cncg/server-certs/server-certificate-deployment)
- [Authentik Documentation](https://goauthentik.io/docs/)
