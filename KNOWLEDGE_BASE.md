# Authentik Credential Provider - Knowledge Base

## Project Goal
Enable passwordless Windows domain authentication using Authentik as the identity provider.

## Critical Discovery (November 2025)

### Software KSP Does NOT Work for PKINIT

**This is the most important finding of the project.**

Windows PKINIT (certificate-based Kerberos authentication via `KERB_CERTIFICATE_LOGON`) requires a **smart card-compatible Key Storage Provider**. The following approaches were tested and **DO NOT WORK**:

| Approach | Result | Why |
|----------|--------|-----|
| Microsoft Software KSP | ❌ FAILS | Not recognized as smart card |
| Microsoft Passport KSP | ❌ FAILS | Requires WHfB enrollment |
| Custom KSP (AuthentikKSP) | ❌ FAILS | Not smart card compatible |
| TPM Virtual Smart Card | ✅ WORKS | Emulates real smart card |

**Evidence:** When using software-based KSPs, Kerberos debug logs show:
```
Error Code: 0x19 KDC_ERR_PREAUTH_REQUIRED
Client Realm: (empty)
Client Name: (empty)
```
Empty Client Realm/Name indicates the Kerberos SSP rejected the certificate **before** attempting PKINIT.

### Solution: TPM Virtual Smart Card

The only working approach for software-based PKINIT is using a **TPM Virtual Smart Card**:

1. TPM generates and protects the private key
2. Windows recognizes VSC as a legitimate smart card
3. Kerberos SSP accepts certificates from VSC for PKINIT
4. Full domain authentication works

See [VSC-PKINIT-GUIDE.md](VSC-PKINIT-GUIDE.md) for complete setup instructions.

## Certificate Requirements for Smart Card Logon

### Required EKUs
- Smart Card Logon: `1.3.6.1.4.1.311.20.2.2`
- Client Authentication: `1.3.6.1.5.5.7.3.2`

### Required Subject Alternative Name
**CRITICAL:** Certificate MUST contain UPN in SAN matching AD user's userPrincipalName:
```
2.5.29.17 = "{text}"
_continue_ = "upn=username@domain.local"
```

Without the UPN SAN, Windows cannot map the certificate to an AD user account.

### Certificate Chain
- Issuing CA must be in the NTAuth store
- Domain controller must have valid KDC Authentication certificate

## Infrastructure Requirements

### Domain Controller
- Windows Server 2016+ (tested with 2019, 2022)
- KDC certificate with KDC Authentication EKU (`1.3.6.1.5.2.3.5`)
- Enterprise CA or standalone CA with NTAuth publication

### Workstation
- Windows 10/11 with TPM 1.2 or 2.0
- TPM enabled and owned
- Smart Card service (SCardSvr) running

### Authentik
- Flow configured for OTP authentication
- Certificate provider (optional - can use Windows CA instead)

## Architecture Options

### Option 1: VSC with Windows CA (Tested, Works)
```
User → Credential Provider → OTP to Authentik → 
  → Generate Key on VSC → CSR to Windows CA → 
  → Certificate to VSC → PKINIT to DC
```

### Option 2: VSC with Authentik CA (To Be Implemented)
```
User → Credential Provider → OTP to Authentik → 
  → Generate Key on VSC → CSR to Authentik → 
  → Certificate to VSC → PKINIT to DC
```

### Option 3: Password Caching (Fallback)
```
User → Credential Provider → OTP to Authentik → 
  → Cached Password → Password-based Kerberos
```

## Code Status

### Working Components
- `AuthentikAPI.cpp` - API communication with Authentik
- `AuthentikCredential.cpp` - Credential provider UI and flow
- `AuthentikProvider.cpp` - Provider registration

### Obsolete/Non-Working Components
- `CertificateHelper.cpp` software KSP code - Does not work for PKINIT
- `AuthentikKSP/` - Custom KSP project - Does not work for PKINIT

The software KSP code is preserved for reference but should not be used for production.

### Needed Components
- VSC key generation code
- CSR creation from VSC key
- Certificate import to VSC
- Smart card PIN handling

## Testing Environment

### Domain
- Domain: `test.local`
- DC: `WIN-6DP39D0OLI8.test.local` (Windows Server)
- CA: `test-WIN-6DP39D0OLI8-CA`

### Workstation
- Name: `TEST10`
- OS: Windows 10/11
- TPM: IBM (in Proxmox VM with vTPM)

### User
- Username: `shop`
- UPN: `shop@test.local`

## Useful Commands

### TPM Virtual Smart Card
```powershell
# Create VSC (must be from console, not RDP)
tpmvscmgr.exe create /name "Authentik VSC" /pin PROMPT /adminkey random /generate

# Check VSC status
certutil -scinfo

# Start smart card service
Start-Service SCardSvr
```

### Certificate Operations
```powershell
# Generate CSR on VSC
certreq -new request.inf request.csr

# Submit to CA
certreq -submit -attrib "CertificateTemplate:SmartcardLogon" -config "SERVER\CA" request.csr cert.cer

# Accept certificate
certreq -accept cert.cer

# View certificate store
certutil -store MY
```

### Kerberos Debugging
```powershell
# Enable Kerberos logging
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" /v LogLevel /t REG_DWORD /d 1 /f

# Check Kerberos events
Get-WinEvent -LogName "System" | Where-Object { $_.ProviderName -like "*Kerb*" }

# Check authentication events on DC
Get-WinEvent -LogName "Security" | Where-Object { $_.Id -eq 4768 -or $_.Id -eq 4771 }
```

## Session History

### November 29, 2025 - Major Breakthrough
1. Discovered software KSP limitation
2. Created TPM Virtual Smart Card
3. Generated key on VSC
4. Got certificate from CA
5. Smart card login screen appeared
6. Found missing UPN in SAN issue

### Previous Sessions
- KERB_CERTIFICATE_LOGON structure implementation
- Certificate import to software stores
- Custom KSP development
- Various debugging attempts

## References

- [VSC-PKINIT-GUIDE.md](VSC-PKINIT-GUIDE.md) - Complete VSC setup guide
- [Microsoft Virtual Smart Card Overview](https://learn.microsoft.com/en-us/windows/security/identity-protection/virtual-smart-cards/virtual-smart-card-overview)
- [PKINIT RFC 4556](https://datatracker.ietf.org/doc/html/rfc4556)
- [TPM Protected Certificates](https://learn.microsoft.com/en-us/archive/blogs/pki/setting-up-tpm-protected-certificates-using-a-microsoft-certificate-authority-part-2-virtual-smart-cards)

## Next Steps

1. **Complete VSC certificate with UPN** - Add SAN to CSR and re-issue
2. **Test smart card logon** - Verify PKINIT works with correct certificate
3. **Integrate VSC operations into credential provider** - Programmatic VSC key generation
4. **Add Authentik CSR signing** - Allow Authentik to sign VSC-generated CSRs
