# Authentik Certificate Issuer Service

A REST API service that issues smart card certificates from Active Directory Certificate Services (AD CS) for passwordless Windows domain authentication.

## Overview

This service runs on the Domain Controller and provides an API endpoint for the Authentik Credential Provider to request certificates on-demand during user authentication.

## Architecture

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────┐
│   Workstation   │────▶│  Certificate Issuer  │────▶│   AD CS     │
│  (Credential    │     │  Service (Port 8443) │     │   (CA)      │
│   Provider)     │◀────│                      │◀────│             │
└─────────────────┘     └──────────────────────┘     └─────────────┘
```

## Features

- REST API on configurable port (default: 8443)
- Bearer token authentication
- Issues certificates using AD CS `certreq` command
- Exports certificates as PFX with random password
- Automatic UPN lookup from Active Directory
- Logging to daily log files
- CORS support for cross-origin requests
- Runs as Windows Service (via NSSM)

## Requirements

- Windows Server with AD CS role installed
- Domain Controller (or member server with AD CS access)
- PowerShell 5.1 or later
- NSSM (Non-Sucking Service Manager) for service installation
- Certificate template configured for smart card authentication

## Installation

### Step 1: Create Directory Structure

```powershell
# Create directories
New-Item -ItemType Directory -Path "C:\ProgramData\Authentik\CertIssuer" -Force
New-Item -ItemType Directory -Path "C:\ProgramData\Authentik\CertIssuer\Logs" -Force
New-Item -ItemType Directory -Path "C:\ProgramData\Authentik\CertIssuer\Temp" -Force
```

### Step 2: Download Files

```powershell
# Download service script
$baseUrl = "https://raw.githubusercontent.com/mikemaragos/authentik-credential-provider/main/tools"
Invoke-WebRequest -Uri "$baseUrl/FullCertService.ps1" -OutFile "C:\ProgramData\Authentik\CertIssuer\FullCertService.ps1"

# Download NSSM (from https://nssm.cc/download)
# Extract nssm.exe to C:\ProgramData\Authentik\CertIssuer\
```

### Step 3: Create Configuration

Create `C:\ProgramData\Authentik\CertIssuer\config.json`:

```json
{
  "Port": 8443,
  "ApiToken": "YOUR_SECURE_RANDOM_TOKEN_HERE",
  "CAConfig": "YOUR-DC.domain.local\\Your-CA-Name",
  "CertTemplate": "AuthentikSmartcard",
  "UseHttps": false
}
```

**Configuration Options:**

| Option | Type | Description |
|--------|------|-------------|
| Port | Integer | TCP port to listen on (default: 8443) |
| ApiToken | String | Bearer token for API authentication (32+ chars recommended) |
| CAConfig | String | CA configuration string: `hostname\CA-name` |
| CertTemplate | String | Name of the certificate template in AD CS |
| UseHttps | Boolean | Enable HTTPS (requires certificate binding) |

**Generate a secure token:**
```powershell
# Generate random 32-character token
-join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object {[char]$_})
```

### Step 4: Find Your CA Configuration

```powershell
# List available CAs
certutil -config - -ping

# Or check CA name in Certificate Authority MMC
# Format: hostname.domain.local\CA-Name
```

### Step 5: Install as Windows Service

```powershell
cd C:\ProgramData\Authentik\CertIssuer

# Install service using NSSM
.\nssm.exe install AuthentikCertIssuer "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "-ExecutionPolicy Bypass -File `"C:\ProgramData\Authentik\CertIssuer\FullCertService.ps1`""

# Configure service
.\nssm.exe set AuthentikCertIssuer DisplayName "Authentik Certificate Issuer"
.\nssm.exe set AuthentikCertIssuer Description "Issues smart card certificates for Authentik passwordless authentication"
.\nssm.exe set AuthentikCertIssuer Start SERVICE_AUTO_START
.\nssm.exe set AuthentikCertIssuer AppDirectory "C:\ProgramData\Authentik\CertIssuer"
.\nssm.exe set AuthentikCertIssuer AppStdout "C:\ProgramData\Authentik\CertIssuer\Logs\service_stdout.log"
.\nssm.exe set AuthentikCertIssuer AppStderr "C:\ProgramData\Authentik\CertIssuer\Logs\service_stderr.log"

# Start service
.\nssm.exe start AuthentikCertIssuer
```

### Step 6: Verify Installation

```powershell
# Check service status
Get-Service AuthentikCertIssuer

# Test health endpoint
Invoke-RestMethod http://localhost:8443/health
```

## API Reference

### Health Check

```
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "port": 8443,
  "ca": "DC01.test.local\\test-DC01-CA",
  "template": "AuthentikSmartcard"
}
```

### Issue Certificate

```
POST /api/v1/issue-certificate
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "username": "jsmith",
  "upn": "jsmith@domain.local"  // Optional - looked up from AD if not provided
}
```

**Success Response (200):**
```json
{
  "success": true,
  "thumbprint": "A1B2C3D4E5F6...",
  "pfx_base64": "MIIKyQIBAzCC...",
  "pfx_password": "randompassword123",
  "subject": "CN=jsmith",
  "upn": "jsmith@domain.local",
  "not_before": "2025-11-30T12:00:00.0000000-06:00",
  "not_after": "2026-11-30T12:00:00.0000000-06:00"
}
```

**Error Response (401):**
```json
{
  "success": false,
  "error": "Unauthorized"
}
```

**Error Response (500):**
```json
{
  "success": false,
  "error": "certreq -submit failed: ..."
}
```

## Certificate Template Requirements

The certificate template must be configured with:

1. **Template Name:** `AuthentikSmartcard` (or as configured)
2. **msPKI-Certificate-Name-Flag:** `0x62000000`
   - Includes `CT_FLAG_SUBJECT_ALT_REQUIRE_UPN` (0x02000000)
   - Required for PKINIT authentication

**Configure template flag:**
```powershell
$templateName = "AuthentikSmartcard"
$configNC = (Get-ADRootDSE).configurationNamingContext
$templateDN = "CN=$templateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
Set-ADObject -Identity $templateDN -Replace @{'msPKI-Certificate-Name-Flag'=0x62000000}
Restart-Service certsvc
```

**Verify template:**
```powershell
certutil -dstemplate AuthentikSmartcard msPKI-Certificate-Name-Flag
# Should show: 0x62000000
```

## Service Management

```powershell
# Start service
.\nssm.exe start AuthentikCertIssuer

# Stop service
.\nssm.exe stop AuthentikCertIssuer

# Restart service
.\nssm.exe restart AuthentikCertIssuer

# Check status
Get-Service AuthentikCertIssuer

# View logs
Get-Content "C:\ProgramData\Authentik\CertIssuer\Logs\service_*.log" -Tail 50

# Uninstall service
.\nssm.exe stop AuthentikCertIssuer
.\nssm.exe remove AuthentikCertIssuer confirm
```

## Running Interactively (for Testing)

```powershell
cd C:\ProgramData\Authentik\CertIssuer
.\FullCertService.ps1
```

Press Ctrl+C to stop.

## Testing

### Test Health Endpoint

```powershell
Invoke-RestMethod http://localhost:8443/health
```

### Test Certificate Issuance

```powershell
$headers = @{ Authorization = "Bearer YOUR_TOKEN_HERE" }
$body = @{ username = "testuser" } | ConvertTo-Json

$result = Invoke-RestMethod -Uri "http://localhost:8443/api/v1/issue-certificate" `
    -Method POST -Headers $headers -Body $body -ContentType "application/json"

$result | Format-List
```

### Verify Certificate

```powershell
# Decode and inspect the certificate
$pfxBytes = [Convert]::FromBase64String($result.pfx_base64)
$pfxPath = "$env:TEMP\test.pfx"
[IO.File]::WriteAllBytes($pfxPath, $pfxBytes)

$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
    $pfxPath, 
    $result.pfx_password,
    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
)

$cert | Format-List Subject, Thumbprint, NotBefore, NotAfter
$cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" } | ForEach-Object { $_.Format($true) }

Remove-Item $pfxPath
```

## Troubleshooting

### Service Won't Start

1. Check Windows Event Log for errors
2. Run interactively to see error messages:
   ```powershell
   .\FullCertService.ps1
   ```

### Port Already in Use

```powershell
# Check what's using the port
netstat -ano | findstr "8443"

# Change port in config.json
```

### Certificate Issuance Fails

1. Verify CA is accessible:
   ```powershell
   certutil -config "DC01.domain.local\CA-Name" -ping
   ```

2. Check template permissions:
   - User running service needs Enroll permission on template

3. Check template is published:
   ```powershell
   certutil -catemplates
   ```

### Unauthorized Errors

- Verify token in config.json matches the one used in requests
- Check Authorization header format: `Bearer <token>`

## Firewall Configuration

If accessing from other machines:

```powershell
# Allow inbound on port 8443
New-NetFirewallRule -DisplayName "Authentik Cert Issuer" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
```

## Security Considerations

1. **Use a strong API token** (32+ random characters)
2. **Enable HTTPS** in production (requires certificate binding)
3. **Restrict network access** to only the machines that need it
4. **Monitor logs** for unauthorized access attempts
5. **Run service** with minimum required permissions

## Files

| File | Description |
|------|-------------|
| `FullCertService.ps1` | Main service script |
| `config.json` | Configuration file |
| `nssm.exe` | Service wrapper |
| `Logs/` | Log files directory |
| `Temp/` | Temporary files (auto-cleaned) |

## License

Part of the Authentik Credential Provider project.
https://github.com/mikemaragos/authentik-credential-provider
