# Windows Credential Provider with OTP Authentication - Complete Knowledge Base

## Document Purpose

This document captures ALL knowledge, decisions, challenges, solutions, and technical details from the Authentik Windows Credential Provider OTP authentication project. Use this as the single source of truth when starting a new project or resuming this one.

**Last Updated:** December 2025  
**Project Status:** Phase 1 Complete, Phase 2 In Progress  
**Current Implementation:** Smart Card PKINIT authentication verified working

---

## Project Phases

### Phase 1: VSC + PKINIT Verification ✅ COMPLETE
Verified that Virtual Smart Card with PKINIT authentication works in the environment.

### Phase 2: Authentik Integration 🔄 IN PROGRESS  
Custom Credential Provider that validates OTP with Authentik, issues certificate, and performs PKINIT.

### Phase 3: Production Hardening (Future)
Security hardening, logging, deployment automation.

---

## Phase 1 Results - Critical Findings

### KB5014754 Strong Certificate Mapping (CRITICAL)

Microsoft's KB5014754 (May 2022) fundamentally changed certificate-based authentication. As of February 2025, **strong mapping is enforced by default**.

**What This Means:**
- UPN-only mapping is now considered "weak" and FAILS
- Certificates must either:
  1. Contain SID extension (OID `1.3.6.1.4.1.311.25.2`), OR
  2. Have explicit `altSecurityIdentities` mapping in AD

**Why Our Certificates Lack SID Extension:**
- SID extension is auto-added only when template uses "Build from this Active Directory information"
- Our template uses "Supply in the request" (required for Authentik/third-party integration)
- Therefore, explicit mapping is REQUIRED

**Strong vs Weak Mapping:**
| Mapping Type | Strength | Our Use |
|--------------|----------|---------|
| SID Extension in cert | Strong | Not available (Supply in Request template) |
| X509:\<SKI\> | Strong | ✅ Using this |
| X509:\<I\>\<SR\> (Issuer+Serial) | Strong | Alternative option |
| UPN in SAN | Weak | ❌ No longer works |
| Subject only | Weak | ❌ No longer works |

### Explicit SKI Mapping Requirement

Every certificate issued requires AD to be updated with SKI mapping:

```powershell
# Get SKI from certificate
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -eq "CN=username"}
$ski = $cert.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.14"}
$skiHash = $ski.Format(0)  # Returns something like "a1b2c3d4..."

# Set mapping in AD
Set-ADUser username -Add @{altSecurityIdentities="X509:<SKI>$skiHash"}
```

### Working Phase 1 Configuration

| Component | Setting | Value |
|-----------|---------|-------|
| DC | StrongCertificateBindingEnforcement | 0 |
| DC | UseSubjectAltName | 1 |
| DC | altSecurityIdentities | X509:\<SKI\>[hash] per user |
| Workstation | Smart Card CP Registry | Enabled (GUID below) |
| VSC | PIN | 12345678 |
| Cert Template | Name | AuthentikSmartcard |
| Cert Template | Subject Name | Supply in the request |

**Smart Card Credential Provider GUID:**
```
{8FD7E19C-3BF7-489B-A72C-846AB3678C96}
```

**Enable Smart Card CP:**
```powershell
$path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8FD7E19C-3BF7-489B-A72C-846AB3678C96}"
if (!(Test-Path $path)) { New-Item -Path $path -Force }
Set-ItemProperty -Path $path -Name "Disabled" -Value 0 -Type DWord
```

---

## Phase 2 Architecture

### Design Decision: Option A - Authentik Controls Certificate Issuance

**Rationale:** Centralized control over certificate lifecycle, Authentik manages everything.

**Alternative Considered:** Option B - Workstation enrolls directly from AD CS after OTP validation. Simpler for certificates (auto SID), but less control.

### Authentication Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                     PHASE 2 AUTHENTICATION FLOW                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. User enters Username + OTP at Windows Login                     │
│                           │                                          │
│                           ▼                                          │
│  2. Credential Provider ──────► Authentik (validate OTP)            │
│                           │                                          │
│                           ▼                                          │
│  3. Authentik ──────► CertIssuer ──────► AD CS (issue certificate)  │
│                           │                                          │
│                           ▼                                          │
│  4. CertIssuer ──────► AD via LDAP (update altSecurityIdentities)   │
│                           │                                          │
│                           ▼                                          │
│  5. Certificate returned to Credential Provider                      │
│                           │                                          │
│                           ▼                                          │
│  6. Credential Provider ──────► Import certificate to VSC           │
│                           │                                          │
│                           ▼                                          │
│  7. Build KERB_CERTIFICATE_LOGON ──────► LSA ──────► PKINIT         │
│                           │                                          │
│                           ▼                                          │
│  8. KDC validates certificate ──────► TGT issued ──────► SUCCESS    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### CertIssuer Requirements

After issuing each certificate, CertIssuer MUST:

1. **Extract SKI** from issued certificate:
   ```python
   from cryptography import x509
   from cryptography.x509.oid import ExtensionOID
   
   cert = x509.load_pem_x509_certificate(cert_pem)
   ski_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
   ski_hex = ski_ext.value.digest.hex()
   ```

2. **Update AD via LDAP**:
   ```python
   import ldap3
   
   conn = ldap3.Connection(server, user=admin_dn, password=admin_pw)
   conn.modify(user_dn, {
       'altSecurityIdentities': [(ldap3.MODIFY_REPLACE, [f'X509:<SKI>{ski_hex}'])]
   })
   ```

### Certificate Requirements

| Attribute | Requirement |
|-----------|-------------|
| EKU | Smart Card Logon (1.3.6.1.4.1.311.20.2.2) |
| SAN | UPN: user@domain.local |
| Key Usage | Digital Signature |
| KeySpec | AT_KEYEXCHANGE (1) |
| Subject | CN=username |

### Credential Provider Changes

The credential provider must be modified to:

1. **Remove password field** - OTP only
2. **Call Authentik API** with username + OTP
3. **Receive certificate** from Authentik/CertIssuer
4. **Import to VSC** using CertEnroll or minidriver APIs
5. **Build KERB_CERTIFICATE_LOGON** structure (not KERB_INTERACTIVE_LOGON)
6. **Set CSP info** pointing to VSC

### KERB_CERTIFICATE_LOGON Structure

```cpp
typedef struct _KERB_CERTIFICATE_LOGON {
    KERB_LOGON_SUBMIT_TYPE MessageType;  // KerbCertificateLogon = 11
    UNICODE_STRING DomainName;
    UNICODE_STRING UserName;
    UNICODE_STRING Pin;
    ULONG Flags;
    ULONG CspDataLength;
    PUCHAR CspData;  // KERB_SMARTCARD_CSP_INFO
} KERB_CERTIFICATE_LOGON, *PKERB_CERTIFICATE_LOGON;

typedef struct _KERB_SMARTCARD_CSP_INFO {
    DWORD dwCspInfoLen;
    DWORD MessageType;        // Must be 1
    union {
        PVOID ContextInformation;
        ULONG64 SpaceHolderForWow64;
    };
    DWORD flags;
    DWORD KeySpec;            // AT_KEYEXCHANGE = 1
    ULONG nCardNameOffset;
    ULONG nReaderNameOffset;
    ULONG nContainerNameOffset;
    ULONG nCSPNameOffset;
    TCHAR bBuffer[];          // Variable length buffer with names
} KERB_SMARTCARD_CSP_INFO;
```

---

## Environment Details

### Network
| Host | IP | Role |
|------|----|----- |
| authentik.test.local | 192.168.1.114 | Identity Provider |
| WIN-6DP39D0OLI8.test.local | 192.168.1.101 | Domain Controller |

### Domain
- NetBIOS: TEST
- FQDN: test.local
- Test User: shop (UPN: shop@test.local)

### Services
- Authentik: HTTPS on 443
- CertIssuer: HTTPS on 8443

---

## Common Issues & Solutions

### Phase 1 Issues

**Issue: Smart card tile doesn't appear at login**
- Solution: Enable Smart Card CP via registry (see GUID above)
- Reboot required

**Issue: PKINIT fails with "cannot find certificate"**
- Solution: Verify altSecurityIdentities contains correct X509:\<SKI\> mapping
- Check: `Get-ADUser username -Properties altSecurityIdentities`

**Issue: Certificate chain validation fails**
- Solution: Ensure CA cert is in NTAuth store and propagated via GPO
- Run: `certutil -viewstore -enterprise NTAuth`

**Issue: Event 39 on DC (no strong mapping)**
- Solution: This is expected without SID extension - use explicit SKI mapping

### Build Issues

**Issue: LNK2019 unresolved external symbol**
- Solution: Add to linker: `Secur32.lib;Advapi32.lib;Shlwapi.lib;Winhttp.lib`

**Issue: Credential provider doesn't appear**
- Solution: Reboot after regsvr32, check registry, verify x64 build

---

## Security Considerations

### Current (Development)
- ⚠️ SSL certificate validation disabled
- ⚠️ StrongCertificateBindingEnforcement = 0
- ⚠️ Hardcoded test values

### Production Requirements
- [ ] Enable SSL certificate validation
- [ ] Set StrongCertificateBindingEnforcement = 1 (after Sept 2025, no choice)
- [ ] Implement certificate pinning
- [ ] Use DPAPI for storing sensitive configuration
- [ ] Code sign the DLL
- [ ] Enable Windows Event Log integration
- [ ] Implement certificate revocation checking

---

## Diagnostic Commands

### Workstation
```powershell
# List certificates
Get-ChildItem Cert:\CurrentUser\My | Format-Table Subject, Thumbprint, NotAfter

# Check certificate details
$cert = Get-ChildItem Cert:\CurrentUser\My | Where {$_.Subject -eq "CN=shop"}
$cert | Format-List *

# Check for SID extension (will be empty for our certs)
$cert.Extensions | Where {$_.Oid.Value -eq "1.3.6.1.4.1.311.25.2"}

# Check SKI
$cert.Extensions | Where {$_.Oid.Value -eq "2.5.29.14"} | % {$_.Format(0)}

# VSC status
certutil -scinfo

# Test smart card logon
runas /smartcard /user:shop@test.local cmd.exe
```

### Domain Controller
```powershell
# Check user's certificate mapping
Get-ADUser shop -Properties altSecurityIdentities, userPrincipalName | 
    Select Name, userPrincipalName, altSecurityIdentities

# Check KDC registry
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" | 
    Select StrongCertificateBindingEnforcement, UseSubjectAltName

# PKINIT events
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4768} -MaxEvents 10

# NTAuth store
certutil -viewstore -enterprise NTAuth
```

---

## Resources

- [KB5014754 - Certificate Strong Mapping](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Microsoft Credential Provider Documentation](https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
- [Smart Card Certificate Requirements](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
- [Authentik Documentation](https://goauthentik.io/docs/)
- [altSecurityIdentities Mapping](https://blogs.msdn.microsoft.com/spatdsg/2010/06/18/howto-map-a-user-to-a-certificate-via-all-the-methods-available-in-the-altsecurityidentities-attribute/)

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | Nov 2025 | Initial release - OTP with password |
| 2.0 | Dec 2025 | Phase 1 complete - VSC+PKINIT verified |
| 2.1 | Dec 2025 | Phase 2 architecture defined |

---

**This knowledge base ensures no knowledge is lost when resuming or restarting this project.**
