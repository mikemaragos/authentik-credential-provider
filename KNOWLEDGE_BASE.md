# Authentik Credential Provider - Knowledge Base

## Document Purpose

Complete technical reference for the Authentik Windows Credential Provider project. This document captures all critical knowledge, configurations, and lessons learned.

**Last Updated:** December 8, 2025  
**Status:** ✅ WORKING - Full PKINIT authentication flow operational

---

## System Overview

### What It Does
Enables passwordless Windows domain authentication:
1. User enters username + OTP code
2. Authentik validates OTP
3. CertIssuer generates short-lived certificate
4. Certificate imported to Virtual Smart Card
5. PKINIT Kerberos authentication to domain

### Architecture
```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Workstation   │     │  Domain Controller │   │    Authentik    │
│                 │     │                   │     │                 │
│ Credential      │────▶│ CertIssuer API    │────▶│ OTP Validation  │
│ Provider DLL    │     │ (Port 8443)       │     │                 │
│       │         │     │       │           │     └─────────────────┘
│       ▼         │     │       ▼           │
│ Virtual Smart   │     │ AD CS (Cert Gen)  │
│ Card (TPM)      │     │       │           │
│       │         │     │       ▼           │
│       └─────────┼────▶│ KDC (PKINIT)      │
└─────────────────┘     └─────────────────────┘
```

---

## Critical Technical Details

### KERB_SMARTCARD_CSP_INFO Structure

**CRITICAL FIXES APPLIED (December 2025):**

| Requirement | Correct Implementation |
|-------------|----------------------|
| Structure packing | `#pragma pack(push, 1)` |
| MessageType | Always `1` (NOT logon type!) |
| String offsets | CHARACTER COUNT (WCHAR units) |
| UNICODE_STRING.Buffer | BYTE OFFSET from buffer start |

```c
#pragma pack(push, 1)  // CRITICAL!
typedef struct _KERB_SMARTCARD_CSP_INFO {   
    DWORD dwCspInfoLen;       // Total size in BYTES
    DWORD MessageType;        // MUST be 1
    union {     
        PVOID ContextInformation;
        ULONG64 SpaceHolderForWow64;
    }; 
    DWORD flags;              // 0
    DWORD KeySpec;            // AT_KEYEXCHANGE (1)
    ULONG nCardNameOffset;    // CHARACTER offset
    ULONG nReaderNameOffset;  // CHARACTER offset
    ULONG nContainerNameOffset;
    ULONG nCSPNameOffset;
    TCHAR bBuffer;
} KERB_SMARTCARD_CSP_INFO;
#pragma pack(pop)
```

### KERB_CERTIFICATE_LOGON Packing

For credential providers, UNICODE_STRING.Buffer is a **BYTE OFFSET**, not a pointer:

```c
// Buffer layout:
// [KERB_CERTIFICATE_LOGON struct]
// [Domain string]
// [Username string]  
// [PIN string]
// [KERB_SMARTCARD_CSP_INFO + strings]

pLogon->DomainName.Buffer = (PWSTR)(ULONG_PTR)offsetDomain;  // BYTE OFFSET!
pLogon->DomainName.Length = domainLength * sizeof(WCHAR);    // BYTES, no null
```

### Certificate Requirements

| Attribute | Value |
|-----------|-------|
| EKU | Smart Card Logon (1.3.6.1.4.1.311.20.2.2) |
| SAN | UPN (user@domain.com) |
| Key Usage | Digital Signature |
| KeySpec | AT_KEYEXCHANGE (1) |

### Certificate Mapping (KB5014754)

UPN mapping is weak. Use **X509:<SKI>** mapping instead:

```powershell
# Get SKI from certificate
$ski = $cert.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.14"} | ForEach-Object {$_.Format(0)}
# Set AD attribute
Set-ADUser username -Replace @{altSecurityIdentities="X509:<SKI>$ski"}
```

---

## Environment Configuration

### Domain Controller

**Registry:**
```
HKLM\SYSTEM\CurrentControlSet\Services\Kdc
StrongCertificateBindingEnforcement = 0 (DWORD)
```

**CertIssuer Service:**
- Port: 8443
- API Token: `dkWSmvx1aE6EiPGU9GJ2nNAMN5YczqeC`

### Workstation

**Registry - Enable Smart Card CP:**
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8FD7E19C-3BF7-489B-A72C-846AB3678C96}
(Default) = "Smart Card Credential Provider"
```

**Virtual Smart Card:**
- PIN: `12345678`
- Reader: `Microsoft Virtual Smart Card 0`
- CSP: `Microsoft Base Smart Card Crypto Provider`

---

## File Structure

### Source Code (phase2/)
| File | Purpose |
|------|---------|
| CredentialPacking.cpp/h | PKINIT structure serialization |
| AuthentikCredential.cpp/h | Credential tile UI logic |
| VSCManager.cpp/h | Virtual Smart Card operations |
| AuthentikAPI.cpp/h | HTTP client for Authentik/CertIssuer |
| AuthentikCredentialProvider.cpp/h | Main CP implementation |

### Key Functions
- `PackKerbCertificateLogon()` - Builds KERB_CERTIFICATE_LOGON with CSP data
- `BuildSmartCardCspInfo()` - Builds KERB_SMARTCARD_CSP_INFO structure
- `VSCManager::ImportPFX()` - Imports certificate to VSC

---

## Troubleshooting

### STATUS_INVALID_PARAMETER
- Check KERB_SMARTCARD_CSP_INFO packing (must be 1-byte)
- Verify MessageType = 1 (not logon type)
- Confirm offsets are character count, not bytes

### DC Shows Pre-Auth Type 2 (Password) Instead of 16 (PKINIT)
- Kerberos SSP not receiving valid CSP data
- Check container name matches certificate
- Verify reader name is correct

### View Smart Card Info
```powershell
certutil -scinfo
certutil -csp "Microsoft Base Smart Card Crypto Provider" -key
```

---

## References

1. [Microsoft KERB_CERTIFICATE_LOGON](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_certificate_logon)
2. [Microsoft KERB_SMARTCARD_CSP_INFO](https://learn.microsoft.com/en-us/windows/win32/secauthn/kerb-smartcard-csp-info)
3. [IDRIX LsaSmartCardLogon.cpp](http://www.idrix.fr/Root/Samples/LsaSmartCardLogon.cpp)
4. [Microsoft CP Sample helpers.cpp](https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/CredentialProvider/cpp/helpers.cpp)

---

**Document Version:** 3.0  
**Status:** Production Ready
