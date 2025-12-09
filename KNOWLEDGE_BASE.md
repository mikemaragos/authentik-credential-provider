# Windows Credential Provider with Smart Card Authentication - Complete Knowledge Base

## Document Purpose

This document captures ALL knowledge, decisions, challenges, solutions, and technical details from the Authentik Windows Credential Provider project with smart card/PKINIT authentication. Use this as the single source of truth when resuming or expanding this project.

**Last Updated:** December 8, 2025  
**Project Status:** Phase 2 - Smart Card Integration (PKINIT research complete, implementation pending)  
**Current Focus:** Fix KERB_SMARTCARD_CSP_INFO structure bugs identified through research

---

## Critical Research Findings (December 8, 2025)

### KERB_SMARTCARD_CSP_INFO Structure Bugs IDENTIFIED

After deep research into Microsoft documentation, IDRIX working samples, and credential provider implementations, we identified **multiple critical bugs** in our structure implementation:

| Issue | Our Implementation | Correct Implementation |
|-------|-------------------|----------------------|
| Structure packing | `#pragma pack(push, 8)` | **`#pragma pack(push, 1)`** |
| MessageType value | Logon type (13) | **Always 1** |
| String offsets | Byte offsets | **Character count (WCHAR units)** |
| WOW64 compatibility | Missing | **Union with ULONG64** |

### Correct Structure Definition

```c
#pragma pack(push, 1)  // CRITICAL: 1-byte packing!
typedef struct _KERB_SMARTCARD_CSP_INFO {
    DWORD dwCspInfoLen;       // Total size in BYTES
    DWORD MessageType;        // MUST be 1 (not logon type!)
    union {
        PVOID ContextInformation;
        ULONG64 SpaceHolderForWow64;  // For 32/64-bit compatibility
    };
    DWORD flags;              // Usually 0
    DWORD KeySpec;            // AT_KEYEXCHANGE (1) or AT_SIGNATURE (2)
    ULONG nCardNameOffset;    // Offset in CHARACTER COUNT (WCHAR units)
    ULONG nReaderNameOffset;  // Offset in CHARACTER COUNT
    ULONG nContainerNameOffset; // Offset in CHARACTER COUNT
    ULONG nCSPNameOffset;     // Offset in CHARACTER COUNT
    TCHAR bBuffer;            // Start of string buffer
} KERB_SMARTCARD_CSP_INFO;
#pragma pack(pop)
```

### Credential Provider Buffer Handling

**CRITICAL**: In credential providers, `UNICODE_STRING.Buffer` is a **BYTE OFFSET**, not a pointer!

From Microsoft's helpers.cpp:
> "WinLogon and LSA consume 'packed' KERB_INTERACTIVE_UNLOCK_LOGONs. In these, the PWSTR members of each UNICODE_STRING are not actually pointers but byte offsets into the overall buffer"

### Working Reference Implementations

- **IDRIX LsaSmartCardLogon.cpp**: http://www.idrix.fr/Root/Samples/LsaSmartCardLogon.cpp (KERB_CERTIFICATE_LOGON)
- **IDRIX LsaSmartCardLogon2.cpp**: http://www.idrix.fr/Root/Samples/LsaSmartCardLogon2.cpp (KERB_SMART_CARD_LOGON)
- **Microsoft helpers.cpp**: https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/CredentialProvider/cpp/helpers.cpp

---

## Project Phases

### Phase 1: Basic VSC + PKINIT ✅ WORKING
- Manual VSC creation with tpmvscmgr.exe
- Manual certificate import via certutil
- Manual PKINIT login via Windows Smart Card CP
- **VALIDATED**: DC + Workstation correctly configured

### Phase 2: Automated Certificate Flow ✅ VALIDATED (manual), 🔧 IN PROGRESS (CP integration)
- CertIssuer service issues certificates via API
- PFX import to VSC works manually
- **STATUS**: CP integration failing with STATUS_INVALID_PARAMETER
- **ROOT CAUSE**: KERB_SMARTCARD_CSP_INFO structure bugs (identified via research)

### Phase 3: Full Authentik Integration (PENDING)
- Authentik OTP validation triggers certificate issuance
- Complete passwordless flow

---

## Environment Configuration

### Domain Controller (DC)
- **Hostname**: dc.test.local
- **Services**: AD DS, AD CS (CertIssuer), DNS
- **CertIssuer API**: Port 8443, Token: dkWSmvx1aE6EiPGU9GJ2nNAMN5YczqeC
- **Registry Setting**: `StrongCertificateBindingEnforcement = 0`

### Workstation
- **Domain**: TEST.LOCAL
- **Smart Card CP Enabled**: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8FD7E19C-3BF7-489B-A72C-846AB3678C96}
- **VSC PIN**: 12345678
- **Reader Name**: "Microsoft Virtual Smart Card 0"
- **CSP Name**: "Microsoft Base Smart Card Crypto Provider"

### Certificate Requirements
- **EKU**: Smart Card Logon (1.3.6.1.4.1.311.20.2.2)
- **SAN**: UPN (user@domain format)
- **Key Usage**: Digital Signature
- **KeySpec**: AT_KEYEXCHANGE (1)

### Certificate Mapping (KB5014754)
- UPN mapping is weak and fails with enforcement
- Use **X509:<SKI>** mapping instead
- Get SKI: `$cert.Extensions|Where{$_.Oid.Value -eq "2.5.29.14"}|%{$_.Format(0)}`

---

## Authentication Structures

### KERB_CERTIFICATE_LOGON (MessageType = 13)
- Includes DomainName and UserName (optional but helpful)
- Best for domain logon scenarios
- Contains PIN and CspData

### KERB_SMART_CARD_LOGON (MessageType = 6)
- Simpler, no username/domain fields
- User identity from certificate UPN
- Contains PIN and CspData only

### Buffer Layout for Credential Provider
```
[KERB_CERTIFICATE_LOGON structure]
[Domain string (null-terminated WCHAR)]
[Username string (null-terminated WCHAR)]
[PIN string (null-terminated WCHAR)]
[KERB_SMARTCARD_CSP_INFO + string data]
```

---

## Files Structure

### Root Directory (Phase 1 - Basic OTP)
- AuthentikCredentialProvider.cpp/h
- AuthentikCredential.cpp/h
- CredentialPacking.cpp/h
- AuthentikAPI.cpp/h
- Dll.cpp, FieldDescriptors.h, guid.h, Logger.h

### Phase 2 Directory (Smart Card)
- AuthentikCredentialProvider.cpp/h - Uses Kerberos package
- AuthentikCredential.cpp/h - Smart card flow
- CredentialPacking.cpp/h - **NEEDS FIX** per research findings
- SmartCardHelper.cpp/h - VSC enumeration and cert discovery

---

## Next Steps

1. **Fix CredentialPacking.cpp** with correct structure:
   - 1-byte packing for KERB_SMARTCARD_CSP_INFO
   - MessageType = 1 for CSP INFO
   - Character count for string offsets
   - Byte offsets for UNICODE_STRING.Buffer

2. **Test with corrected structures**
   - Build and deploy updated DLL
   - Verify DC logs show Pre-Auth Type 16 (PKINIT)
   - Confirm successful login

3. **Integrate with Authentik**
   - Add OTP validation step before certificate issuance
   - Complete passwordless flow

---

## Troubleshooting

### STATUS_INVALID_PARAMETER (0xC000000D)
- Check structure packing
- Verify MessageType values
- Confirm offset calculations
- Review buffer layout

### DC Shows Pre-Auth Type 2 (Password) Instead of 16 (PKINIT)
- Kerberos SSP not receiving valid certificate data
- Check KERB_SMARTCARD_CSP_INFO structure
- Verify CSP/reader/container names match VSC

### View Smart Card Info
```powershell
certutil -scinfo
```

### View VSC Containers
```powershell
certutil -csp "Microsoft Base Smart Card Crypto Provider" -key
```

---

## References

1. Microsoft KERB_CERTIFICATE_LOGON: https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_certificate_logon
2. Microsoft KERB_SMARTCARD_CSP_INFO: https://learn.microsoft.com/en-us/windows/win32/secauthn/kerb-smartcard-csp-info
3. IDRIX Samples: http://www.idrix.fr/Root/Samples/
4. Microsoft CP Sample: https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/CredentialProvider
5. Smart Card Architecture: https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-architecture

---

**Document Version:** 2.0  
**Last Updated:** December 8, 2025  

This knowledge base ensures no knowledge is lost when resuming this project.
