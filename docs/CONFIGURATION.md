# Configuration Guide

## Credential Provider Registry Settings

**Location:** `HKEY_LOCAL_MACHINE\SOFTWARE\AuthentikCredentialProvider`

| Key | Type | Description | Example |
|-----|------|-------------|---------|
| `ServerUrl` | REG_SZ | CertIssuer server hostname | `dc01.test.local` |
| `ServerPort` | REG_DWORD | CertIssuer API port | `8443` |
| `Domain` | REG_SZ | Windows domain name | `TEST` |
| `VSCReaderName` | REG_SZ | Virtual Smart Card reader | `Microsoft Virtual Smart Card 0` |
| `VSCPin` | REG_SZ | VSC PIN (optional, can prompt) | `12345678` |
| `CertIssuerToken` | REG_SZ | API authentication token | `dkWSmvx1aE6EiPGU9GJ2nNAMN5YczqeC` |

### Sample Registry File

```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\AuthentikCredentialProvider]
"ServerUrl"="dc01.test.local"
"ServerPort"=dword:000020fb
"Domain"="TEST"
"VSCReaderName"="Microsoft Virtual Smart Card 0"
"VSCPin"="12345678"
"CertIssuerToken"="dkWSmvx1aE6EiPGU9GJ2nNAMN5YczqeC"
```

---

## Domain Controller Configuration

### 1. Certificate Binding Enforcement

**Required for compatibility mode:**
```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" `
    -Name "StrongCertificateBindingEnforcement" -Value 0 -Type DWord
Restart-Service KDC
```

### 2. CertIssuer Service

**Configuration file:** `certissuer/config.json`
```json
{
    "port": 8443,
    "api_token": "dkWSmvx1aE6EiPGU9GJ2nNAMN5YczqeC",
    "authentik_url": "https://authentik.test.local",
    "ca_name": "TEST-DC01-CA",
    "template_name": "AuthentikSmartCardLogon",
    "cert_validity_minutes": 60
}
```

### 3. Certificate Template

Required settings for AD CS template:
- **EKU:** Smart Card Logon (1.3.6.1.4.1.311.20.2.2)
- **SAN:** Include UPN
- **Key Usage:** Digital Signature
- **Key Size:** 2048-bit minimum
- **Validity:** 1 hour (short-lived)

---

## Workstation Configuration

### 1. Enable Smart Card Credential Provider

```powershell
# Ensure built-in Smart Card CP is enabled
$path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8FD7E19C-3BF7-489B-A72C-846AB3678C96}"
if (-not (Test-Path $path)) {
    New-Item -Path $path -Force
}
Set-ItemProperty -Path $path -Name "(Default)" -Value "Smart Card Credential Provider"
```

### 2. Create Virtual Smart Card

```powershell
# Create TPM Virtual Smart Card
tpmvscmgr.exe create /name "AuthentikVSC" /pin default /adminkey random /generate

# Default PIN: 12345678
# Default Admin Key: Random (managed by TPM)
```

### 3. Verify VSC

```powershell
# List smart card readers
certutil -scinfo

# Check certificate stores
certutil -store My
```

---

## Authentik Configuration

### 1. Create Flow

Create a flow in Authentik for Windows authentication:
1. **Identification Stage** - Username input
2. **Authenticator Validation** - OTP validation

### 2. API Access

Configure API token for CertIssuer to validate OTP:
- Create service account in Authentik
- Generate API token with authentication permissions

---

## Certificate Mapping

### Option 1: UPN Mapping (Simple)
Certificate UPN matches AD `userPrincipalName`. Works with `StrongCertificateBindingEnforcement = 0`.

### Option 2: SKI Mapping (Recommended for Production)

```powershell
# Get Subject Key Identifier from certificate
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -like "*username*"}
$ski = ($cert.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.14"}).Format(0)

# Set AD user attribute
Set-ADUser username -Replace @{altSecurityIdentities="X509:<SKI>$ski"}
```

This allows `StrongCertificateBindingEnforcement = 1` for better security.
