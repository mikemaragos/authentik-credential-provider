# Windows Credential Provider with OTP Authentication - Complete Knowledge Base

## Document Purpose

This document captures ALL knowledge, decisions, challenges, solutions, and technical details from the Authentik Windows Credential Provider OTP authentication project. Use this as the single source of truth when starting a new project or resuming this one.

**Last Updated:** December 8, 2025  
**Project Status:** Phase 2 in progress - CertIssuer working, credential provider integration next  
**Current Implementation:** Phase 1 complete (VSC+PKINIT verified), Phase 2 CertIssuer operational

---

## Project Phases

### Phase 1: Manual VSC + PKINIT ✅ COMPLETE
- Virtual Smart Card creation and certificate enrollment
- PKINIT authentication to domain controller
- KB5014754 strong certificate mapping (X509:<SKI>)

### Phase 2: Automated Certificate Flow 🔄 IN PROGRESS
- CertIssuer service ✅ WORKING
- Credential Provider integration (next step)
- Full passwordless OTP→Certificate→PKINIT flow

---

## Critical Discovery: KB5014754 Strong Certificate Mapping

**Root Cause:** Microsoft KB5014754 (May 2022) enforces strong certificate mapping as of February 2025. UPN-only mapping is now "weak" and fails authentication.

**Why Our Certificates Lack SID Extension:**
- SID extension (OID 1.3.6.1.4.1.311.25.2) auto-added only when template uses "Build from this Active Directory information"
- Our template uses "Supply in the request" (required for Authentik/third-party integration)
- Therefore explicit altSecurityIdentities mapping is REQUIRED

### Mapping Types

| Type | Strength | Status |
|------|----------|--------|
| SID extension in cert | Strong | Not available (Supply in Request) |
| X509:<SKI> | Strong | ✅ Using this |
| X509:<I><SR> (Issuer+Serial) | Strong | Alternative |
| UPN in SAN | Weak | ❌ Fails since Feb 2025 |

### Required SKI Mapping Format
```powershell
# Extract SKI from certificate
$cert = Get-ChildItem Cert:\CurrentUser\My | Where {$_.Subject -eq "CN=username"}
$ski = $cert.Extensions | Where {$_.Oid.Value -eq "2.5.29.14"}
$skiHash = $ski.Format(0) -replace '\s',''

# Set in AD (CertIssuer does this automatically now)
Set-ADUser username -Replace @{altSecurityIdentities="X509:<SKI>$skiHash"}
```

---

## CertIssuer Service ✅ WORKING

### Service Details
- **Location:** DC (WIN-6DP39D0OLI8.test.local)
- **Port:** 8443 (HTTP)
- **API Token:** (stored in Claude memory)
- **Install Path:** `C:\CertIssuer`
- **Service Name:** CertIssuer (NSSM-managed)
- **Logs:** `C:\CertIssuer\logs\`

### API Endpoints

**Health Check:**
```
GET http://localhost:8443/api/v1/health
```

**Issue Certificate:**
```
POST http://localhost:8443/api/v1/certificate/issue
Authorization: Bearer dkWSmvx1aE6EiPGU9GJ2nNAMN5YczqeC
Content-Type: application/json

{"username": "shop", "domain": "test.local"}
```

**Response:**
```json
{
  "success": true,
  "certificate": "<base64 DER>",
  "pfx": "<base64 PFX>",
  "pfx_password": "<random GUID>",
  "ski": "5D8430AE3AC9F81039D2491092B57B8687EFDCF3",
  "thumbprint": "E4F3F4ED58C12241A92B13236D482C95DBD7BDC3",
  "expires": "2026-12-08T12:42:16Z",
  "upn": "shop@test.local",
  "ad_mapping_updated": true
}
```

### What CertIssuer Does Automatically
1. Generates CSR with Smart Card Logon EKU + UPN in SAN
2. Submits to AD CS using certreq
3. Extracts SKI from issued certificate
4. **Updates AD altSecurityIdentities with X509:<SKI> mapping**
5. Returns cert + PFX + metadata

### Service Management
```powershell
Get-Service CertIssuer
Stop-Service CertIssuer
Start-Service CertIssuer
Restart-Service CertIssuer

# View logs
Get-Content C:\CertIssuer\logs\certissuer_*.log -Tail 50
```

---

## Phase 2 Authentication Flow

```
User enters Username + OTP
        ↓
Credential Provider → Authentik (validate OTP)
        ↓
Credential Provider → CertIssuer (issue certificate)
        ↓
CertIssuer → AD CS (certreq) → Certificate issued
        ↓
CertIssuer → AD LDAP (set altSecurityIdentities with SKI)
        ↓
Certificate + PFX returned to Credential Provider
        ↓
Credential Provider → Import to VSC (NCrypt APIs)
        ↓
Build KERB_CERTIFICATE_LOGON → LSA → PKINIT
        ↓
KDC validates certificate → TGT issued → SUCCESS
```

---

## Environment Configuration

### Domain Controller (WIN-6DP39D0OLI8.test.local)
| Setting | Value |
|---------|-------|
| IP | 192.168.1.101 |
| Domain | TEST / test.local |
| StrongCertificateBindingEnforcement | 0 (compatibility mode) |
| UseSubjectAltName | 1 |
| CertIssuer | Port 8443, running |

### Authentik Server
| Setting | Value |
|---------|-------|
| Hostname | authentik.test.local |
| IP | 192.168.1.114 |
| Flow | windows-otp-auth |

### Test User
| Attribute | Value |
|-----------|-------|
| Username | shop |
| UPN | shop@test.local |
| altSecurityIdentities | X509:<SKI>5D8430AE3AC9F81039D2491092B57B8687EFDCF3 |

### Workstation Configuration
```powershell
# Enable Smart Card Credential Provider
$path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8FD7E19C-3BF7-489B-A72C-846AB3678C96}"
if (!(Test-Path $path)) { New-Item -Path $path -Force }
Set-ItemProperty -Path $path -Name "Disabled" -Value 0 -Type DWord
```

### VSC Configuration
- **PIN:** 12345678
- **Reader:** Microsoft Virtual Smart Card 0

---

## Certificate Template Requirements

Template Name: **AuthentikSmartcard**

| Setting | Value |
|---------|-------|
| Key Usage | Digital Signature |
| Extended Key Usage | Smart Card Logon (1.3.6.1.4.1.311.20.2.2), Client Authentication |
| Subject Name | Supply in the request |
| SAN | Supply in the request |
| Key Size | 2048-bit RSA |
| Validity | 1 year (configurable) |

---

## KERB_CERTIFICATE_LOGON Structure

```cpp
typedef struct _KERB_CERTIFICATE_LOGON {
    KERB_LOGON_SUBMIT_TYPE MessageType;  // KerbCertificateLogon = 11
    UNICODE_STRING DomainName;
    UNICODE_STRING UserName;
    UNICODE_STRING Pin;
    ULONG Flags;
    ULONG CspDataLength;
    PUCHAR CspData;  // Points to KERB_SMARTCARD_CSP_INFO
} KERB_CERTIFICATE_LOGON;

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

## Diagnostic Commands

### Check DC Configuration
```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" | 
    Select StrongCertificateBindingEnforcement, UseSubjectAltName
```

### Check User Certificate Mapping
```powershell
Get-ADUser shop -Properties altSecurityIdentities | Select altSecurityIdentities
```

### Check for Kerberos Event 39 (mapping failure)
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Kdcsvc'; Id=39} -MaxEvents 5
```

### Test CertIssuer
```powershell
# Health check
Invoke-RestMethod http://localhost:8443/api/v1/health

# Issue certificate (replace YOUR_TOKEN with actual token)
$headers = @{Authorization = "Bearer YOUR_API_TOKEN"}
$body = @{username="shop"; domain="test.local"} | ConvertTo-Json
Invoke-RestMethod http://localhost:8443/api/v1/certificate/issue -Method POST -Body $body -ContentType "application/json" -Headers $headers
```

### Verify Certificate in Store
```powershell
Get-ChildItem Cert:\CurrentUser\My | Where {$_.Subject -like "*shop*"} | 
    Select Subject, Thumbprint, NotAfter, @{N='SKI';E={($_.Extensions | Where {$_.Oid.Value -eq "2.5.29.14"}).Format(0)}}
```

---

## GitHub Repository

**Repository:** mikemaragos/authentik-credential-provider  
**Token:** (stored in Claude memory - do not commit to repo)

### Directory Structure
```
├── src/                    # Phase 1 credential provider (password+OTP)
├── phase2/                 # Phase 2 credential provider (OTP→cert→PKINIT)
├── certissuer/             # CertIssuer service (Python + PowerShell)
├── scripts/                # Deployment and utility scripts
├── docs/                   # Additional documentation
├── KNOWLEDGE_BASE.md       # This file
└── README.md               # Project overview
```

---

## Next Steps

1. **Update Phase 2 Credential Provider** - Integrate with CertIssuer API
2. **Test VSC Import** - Import PFX to VSC programmatically
3. **Build KERB_CERTIFICATE_LOGON** - Pack credentials for PKINIT
4. **End-to-End Testing** - Full OTP→Certificate→PKINIT flow

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | Nov 22, 2025 | Initial Phase 1 implementation |
| 2.0 | Dec 1, 2025 | KB5014754 discovery, SKI mapping |
| 2.1 | Dec 8, 2025 | Phase 2 architecture, code scaffolding |
| 2.2 | Dec 8, 2025 | **CertIssuer service working**, AD mapping verified |

---

**Document Version:** 2.2  
**Last Updated:** December 8, 2025
