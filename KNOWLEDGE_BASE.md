# Windows Credential Provider with OTP Authentication - Complete Knowledge Base

## Document Purpose

This document captures ALL knowledge, decisions, challenges, solutions, and technical details from the Authentik Windows Credential Provider OTP authentication project. Use this as the single source of truth when starting a new project or resuming this one.

**Last Updated:** December 8, 2025  
**Project Status:** Phase 2 VALIDATED - Full PKINIT flow working, credential provider integration next  
**Current Implementation:** CertIssuer→PFX→VSC→PKINIT login verified

---

## Project Phases

### Phase 1: Manual VSC + PKINIT ✅ COMPLETE
- Virtual Smart Card creation and certificate enrollment
- PKINIT authentication to domain controller
- KB5014754 strong certificate mapping (X509:<SKI>)

### Phase 2: Automated Certificate Flow ✅ VALIDATED
- CertIssuer service ✅ WORKING
- PFX import to VSC ✅ WORKING  
- PKINIT login ✅ WORKING
- Credential Provider integration (next step)

---

## Critical Discovery: KB5014754 Strong Certificate Mapping

**Root Cause:** Microsoft KB5014754 (May 2022) enforces strong certificate mapping as of February 2025. UPN-only mapping is now "weak" and fails authentication.

### Mapping Types

| Type | Strength | Status |
|------|----------|--------|
| SID extension in cert | Strong | Not available (Supply in Request) |
| X509:<SKI> | Strong | ✅ Using this |
| X509:<I><SR> (Issuer+Serial) | Strong | Alternative |
| UPN in SAN | Weak | ❌ Fails since Feb 2025 |

---

## CertIssuer Service ✅ WORKING

### Service Details
- **Location:** DC (WIN-6DP39D0OLI8.test.local)
- **Port:** 8443 (HTTP)
- **API Token:** (stored in Claude memory)
- **Install Path:** `C:\CertIssuer`
- **Service Name:** CertIssuer (NSSM-managed)

### API: Issue Certificate
```
POST http://192.168.1.101:8443/api/v1/certificate/issue
Authorization: Bearer <token>
Content-Type: application/json

{"username": "shop", "domain": "test.local"}
```

### Response includes:
- `certificate` - Base64 DER
- `pfx` - Base64 PFX with private key
- `pfx_password` - Random GUID password
- `ski` - Subject Key Identifier
- `ad_mapping_updated` - Confirms altSecurityIdentities set

---

## Validated Test Flow (December 8, 2025)

```powershell
# 1. Get certificate from CertIssuer
$headers = @{Authorization = "Bearer <token>"}
$body = @{username="shop"; domain="test.local"} | ConvertTo-Json
$result = Invoke-RestMethod "http://192.168.1.101:8443/api/v1/certificate/issue" -Method POST -Body $body -ContentType "application/json" -Headers $headers

# 2. Save PFX
$pfxBytes = [Convert]::FromBase64String($result.pfx)
[IO.File]::WriteAllBytes("C:\temp\shop.pfx", $pfxBytes)

# 3. Import to VSC (use $result.pfx_password when prompted)
certutil -csp "Microsoft Base Smart Card Crypto Provider" -importpfx "C:\temp\shop.pfx"

# 4. Lock screen (Win+L), select smart card, enter PIN: 12345678
# Result: SUCCESSFUL LOGIN as shop@test.local
```

---

## Environment Configuration

### Domain Controller (WIN-6DP39D0OLI8.test.local)
| Setting | Value |
|---------|-------|
| IP | 192.168.1.101 |
| Domain | TEST / test.local |
| StrongCertificateBindingEnforcement | 0 |
| CertIssuer | Port 8443, running |

### Workstation
| Setting | Value |
|---------|-------|
| Smart Card CP | Enabled |
| VSC PIN | 12345678 |

### Test User
| Attribute | Value |
|-----------|-------|
| Username | shop |
| UPN | shop@test.local |
| altSecurityIdentities | X509:<SKI>... (auto-set by CertIssuer) |

---

## Next Steps

1. **Update Phase 2 Credential Provider** - Call CertIssuer after OTP validation
2. **Programmatic VSC Import** - Use NCrypt APIs instead of certutil
3. **Build KERB_CERTIFICATE_LOGON** - Submit to LSA for PKINIT
4. **End-to-End Testing** - Full automated OTP→Login flow

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | Nov 22, 2025 | Initial Phase 1 |
| 2.0 | Dec 1, 2025 | KB5014754 discovery |
| 2.1 | Dec 8, 2025 | CertIssuer service working |
| 2.3 | Dec 8, 2025 | **Full PKINIT flow validated** |

---

**Document Version:** 2.3  
**Last Updated:** December 8, 2025
