# Authentik Credential Provider - Knowledge Base

## Project Status: ACTIVE DEVELOPMENT
**Last Updated:** November 30, 2025

---

## 🎉 MAJOR MILESTONES ACHIEVED

### 1. PKINIT Smart Card Authentication ✅
Successfully implemented certificate-based Kerberos authentication (PKINIT) using TPM Virtual Smart Cards.

**Key Discovery:** Certificate template MUST have `CT_FLAG_SUBJECT_ALT_REQUIRE_UPN` (0x02000000) flag to include UPN in Subject Alternative Name extension.

### 2. Certificate Issuer Service ✅
REST API service that issues smart card certificates from AD CS.

- **Port:** 8443
- **API Token:** `dkWSmvx1aE6EiPGU9GJ2nNAMN5YczqeC`
- **Status:** Running as Windows Service with auto-start

### 3. Authentik Branding ✅
- Logo updated to Authentik coral style (#FD4B2D)
- ICO file with multiple sizes (16, 32, 48, 256)

---

## Test Environment

| Component | Value |
|-----------|-------|
| Domain | test.local |
| DC | WIN-6DP39D0OLI8.test.local |
| CA | test-WIN-6DP39D0OLI8-CA |
| Workstation | TEST10 |
| Test User | shop@test.local |
| VSC PIN | 12345678 |

---

## Certificate Template Configuration

**Template Name:** AuthentikSmartcard

```powershell
# Critical flag for UPN in SAN
msPKI-Certificate-Name-Flag = 0x62000000

# Includes:
# CT_FLAG_SUBJECT_ALT_REQUIRE_UPN (0x02000000)
# CT_FLAG_SUBJECT_REQUIRE_EMAIL (0x20000000)  
# CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME (0x40000000)
```

**Configure with:**
```powershell
$templateName = "AuthentikSmartcard"
$configNC = (Get-ADRootDSE).configurationNamingContext
$templateDN = "CN=$templateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
Set-ADObject -Identity $templateDN -Replace @{'msPKI-Certificate-Name-Flag'=0x62000000}
Restart-Service certsvc
```

---

## Certificate Issuer Service

### Configuration File
`C:\ProgramData\Authentik\CertIssuer\config.json`

```json
{
  "Port": 8443,
  "ApiToken": "dkWSmvx1aE6EiPGU9GJ2nNAMN5YczqeC",
  "CAConfig": "WIN-6DP39D0OLI8.test.local\\test-WIN-6DP39D0OLI8-CA",
  "CertTemplate": "AuthentikSmartcard",
  "UseHttps": false
}
```

### Service Management
```powershell
# Check status
Get-Service AuthentikCertIssuer

# Health check
Invoke-RestMethod http://localhost:8443/health

# Issue certificate
$headers = @{ Authorization = "Bearer dkWSmvx1aE6EiPGU9GJ2nNAMN5YczqeC" }
$body = @{ username = "shop" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:8443/api/v1/issue-certificate" -Method POST -Headers $headers -Body $body -ContentType "application/json"

# Restart service
Restart-Service AuthentikCertIssuer

# View logs
Get-Content "C:\ProgramData\Authentik\CertIssuer\Logs\service_*.log" -Tail 50
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/v1/issue-certificate` | POST | Issue certificate |

### Issue Certificate Request
```json
{
  "username": "shop",
  "upn": "shop@test.local"  // Optional - retrieved from AD if not provided
}
```

### Issue Certificate Response
```json
{
  "success": true,
  "thumbprint": "7BBF84834AA450F19173A5174A5496E5942E8268",
  "pfx_base64": "MIIKyQIBAzC...",
  "pfx_password": "59e88abde0de46d5",
  "subject": "CN=shop",
  "upn": "shop@test.local",
  "not_before": "2025-11-30T17:12:36.0000000-06:00",
  "not_after": "2026-11-30T17:12:36.0000000-06:00"
}
```

---

## Credential Provider Architecture

### Passwordless Flow
1. User enters username (no password)
2. Credential provider calls Authentik for OTP challenge
3. User enters OTP code
4. After validation, request certificate from CertIssuer service
5. Import certificate to TPM Virtual Smart Card
6. Use KERB_CERTIFICATE_LOGON for PKINIT authentication
7. User logged in without password

### Source Files

| File | Purpose |
|------|---------|
| AuthentikAPI.cpp/h | API client for Authentik + Cert Issuer |
| AuthentikCredential.cpp/h | Credential tile with multi-step flow |
| SmartCardHelper.cpp/h | VSC operations |
| FieldDescriptors.h | UI field definitions (passwordless) |
| CredentialPacking.cpp/h | Kerberos credential serialization |

### Registry Configuration
`HKLM\SOFTWARE\AuthentikCredentialProvider`

| Key | Type | Value |
|-----|------|-------|
| ServerUrl | REG_SZ | authentik.test.local |
| ServerPort | REG_DWORD | 443 |
| FlowSlug | REG_SZ | windows-smartcard-auth |
| UseHttps | REG_DWORD | 1 |
| CertIssuerUrl | REG_SZ | WIN-6DP39D0OLI8.test.local |
| CertIssuerPort | REG_DWORD | 8443 |
| CertIssuerToken | REG_SZ | dkWSmvx1aE6EiPGU9GJ2nNAMN5YczqeC |
| Domain | REG_SZ | test.local |
| UPNSuffix | REG_SZ | @test.local |

---

## Virtual Smart Card Commands

### Create VSC (from physical/Proxmox console, NOT RDP)
```powershell
tpmvscmgr create /name "Authentik VSC" /pin PROMPT /adminkey random /generate
# Enter PIN: 12345678
```

### List VSC
```powershell
certutil -scinfo
```

### Delete VSC
```powershell
tpmvscmgr destroy /instance ROOT\SMARTCARDREADER\0000
```

---

## Troubleshooting

### Event 39 on DC - Certificate Mapping Failed
**Cause:** Certificate missing UPN in Subject Alternative Name
**Fix:** Reconfigure template with `msPKI-Certificate-Name-Flag = 0x62000000`

### Multiple Certificates on VSC
**Cause:** Previous certificates not cleaned up
**Fix:** Delete and recreate VSC, or use `certutil -delkey` to remove old keys

### tpmvscmgr Fails
**Cause:** Running over RDP
**Fix:** Use physical console or Proxmox console

### Port 8443 Already in Use
```powershell
netstat -ano | findstr "8443"
# Kill the process or use different port
```

---

## Files and Locations

### DC/CA Server
- `C:\ProgramData\Authentik\CertIssuer\` - Service files
- `C:\ProgramData\Authentik\CertIssuer\config.json` - Configuration
- `C:\ProgramData\Authentik\CertIssuer\Logs\` - Service logs
- `C:\ProgramData\Authentik\CertIssuer\FullCertService.ps1` - Main service script

### Workstation
- `C:\Windows\System32\AuthentikCredentialProvider.dll` - Credential provider
- Registry: `HKLM\SOFTWARE\AuthentikCredentialProvider`

### GitHub Repository
https://github.com/mikemaragos/authentik-credential-provider

---

## Next Steps

1. **Build Credential Provider** - Compile in Visual Studio
2. **Configure Authentik Flow** - OTP authentication
3. **Test End-to-End** - Full passwordless login
4. **Production Hardening** - SSL, code signing, etc.

---

## References

- [PKINIT Smart Card Guide](PKINIT_SMARTCARD_GUIDE.md)
- [Microsoft KB5014754](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Credential Provider Technical Reference](https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-provider-technical-reference)
