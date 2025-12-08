# CertIssuer Service

Certificate issuance service for the Authentik Windows Credential Provider.

## Overview

CertIssuer provides a REST API that:
1. Issues certificates from AD CS
2. Extracts Subject Key Identifier (SKI)
3. Updates AD user's `altSecurityIdentities` attribute
4. Returns certificate + private key to caller

This enables the Phase 2 passwordless flow:
```
User+OTP → Authentik → CertIssuer → AD CS → Certificate → VSC → PKINIT → Success
```

## Deployment Options

### Option 1: Windows PowerShell (Recommended)

Run directly on a Windows server with AD CS access:

```powershell
# Run as Administrator
.\CertIssuer-Windows.ps1 -Port 8443 -CAServer "WIN-6DP39D0OLI8.test.local" -CAName "test-WIN-6DP39D0OLI8-CA" -ApiToken "your-secret-token"
```

**Requirements:**
- Windows Server with certreq.exe
- Active Directory PowerShell module
- Network access from Authentik server
- Admin rights for HTTP listener

**Setup HTTPS listener:**
```powershell
# Create self-signed cert for HTTPS
$cert = New-SelfSignedCertificate -DnsName "certissuer.test.local" -CertStoreLocation Cert:\LocalMachine\My

# Bind to port
netsh http add sslcert ipport=0.0.0.0:8443 certhash=$($cert.Thumbprint) appid='{00000000-0000-0000-0000-000000000000}'

# Allow URL reservation
netsh http add urlacl url=https://+:8443/ user=Everyone
```

### Option 2: Python Flask (Linux/Docker)

```bash
# Install dependencies
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env with your settings

# Run
python certissuer.py
```

**Note:** Python version requires certsrv web enrollment or remote PowerShell for certificate issuance.

## API Endpoints

### Health Check
```
GET /api/v1/health

Response:
{
    "status": "healthy",
    "timestamp": "2024-12-08T12:00:00Z",
    "ca_server": "WIN-6DP39D0OLI8.test.local"
}
```

### Issue Certificate
```
POST /api/v1/certificate/issue
Authorization: Bearer <api-token>
Content-Type: application/json

Request:
{
    "username": "shop",
    "domain": "test.local",
    "template": "AuthentikSmartcard"
}

Response:
{
    "success": true,
    "certificate": "<base64 DER>",
    "pfx": "<base64 PFX>",
    "pfx_password": "<random password>",
    "ski": "A1B2C3D4...",
    "thumbprint": "E5F6G7H8...",
    "expires": "2024-12-08T20:00:00Z",
    "upn": "shop@test.local",
    "ad_mapping_updated": true
}
```

### Get User Mapping
```
GET /api/v1/user/mapping?username=shop
Authorization: Bearer <api-token>

Response:
{
    "success": true,
    "username": "shop",
    "altSecurityIdentities": ["X509:<SKI>A1B2C3D4..."]
}
```

## Certificate Template Requirements

The AD CS template must have:

| Setting | Value |
|---------|-------|
| Template Name | AuthentikSmartcard |
| Key Usage | Digital Signature |
| Extended Key Usage | Smart Card Logon (1.3.6.1.4.1.311.20.2.2), Client Authentication |
| Subject Name | Supply in the request |
| SAN | Supply in the request |
| Validity | 8 hours (or as needed) |
| Enroll permissions | Computers or service account |

## Security Considerations

1. **API Token**: Use a strong, random token
2. **HTTPS**: Always use TLS in production
3. **Network**: Restrict access to Authentik server only
4. **Credentials**: Store LDAP password securely (DPAPI on Windows)
5. **Audit**: Enable logging for all certificate issuance

## Testing

```powershell
# Test health endpoint
Invoke-RestMethod -Uri "https://certissuer:8443/api/v1/health" -SkipCertificateCheck

# Test certificate issuance
$headers = @{ Authorization = "Bearer your-secret-token" }
$body = @{ username = "shop"; domain = "test.local" } | ConvertTo-Json

Invoke-RestMethod -Uri "https://certissuer:8443/api/v1/certificate/issue" `
    -Method POST `
    -Headers $headers `
    -Body $body `
    -ContentType "application/json" `
    -SkipCertificateCheck
```

## Troubleshooting

### certreq fails with "Access Denied"
- Ensure service account has Enroll permissions on template
- Check CA is accessible: `certutil -ping -config "server\CA"`

### LDAP connection fails
- Verify LDAP credentials
- Check firewall allows port 389/636
- Test: `Get-ADUser -Identity shop`

### Certificate not valid for Smart Card Logon
- Verify template has correct EKU
- Check SAN contains UPN
- Verify template allows "Supply in request"

### KB5014754 mapping fails
- Use SKI mapping: `X509:<SKI>hexvalue`
- Verify SKI is uppercase hex without spaces
- Check DC has `StrongCertificateBindingEnforcement=0` during testing

## Integration with Credential Provider

The credential provider calls CertIssuer after OTP validation:

```cpp
// In AuthentikAPI.cpp
CertResponse response = RequestCertificate(username, domain);
if (response.success) {
    // Import to VSC
    VSCManager::ImportCertificate(response.certificate, response.privateKey);
    // Build KERB_CERTIFICATE_LOGON
    PackKerbCertificateLogon(...);
}
```

## Files

- `certissuer.py` - Main Flask application (Python)
- `cert_generator.py` - Certificate generation module
- `ad_manager.py` - Active Directory LDAP module
- `CertIssuer-Windows.ps1` - PowerShell version (Windows)
- `.env.example` - Configuration template
- `requirements.txt` - Python dependencies
