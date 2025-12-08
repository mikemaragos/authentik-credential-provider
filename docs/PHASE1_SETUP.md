# Phase 1: Smart Card PKINIT Authentication Setup

## Overview

This document provides reproducible steps to configure Windows smart card authentication using Virtual Smart Cards (VSC) with AD CS certificates.

**Status:** ✅ VERIFIED WORKING (December 2025)

## Architecture

```
User → VSC (PIN) → Certificate → PKINIT → Domain Controller → TGT → Windows Logon
```

## Requirements

| Component | Requirement |
|-----------|-------------|
| Domain Controller | Windows Server with AD CS |
| Workstation | Windows 10/11 with TPM 2.0 |
| Certificate Template | Smart Card Logon EKU, UPN in SAN |

## Critical Findings

### ⚠️ Implicit UPN Mapping Does NOT Work

Even with `StrongCertificateBindingEnforcement=0`, implicit UPN-based certificate mapping **does not work reliably**. 

**You MUST use explicit SKI (Subject Key Identifier) mapping:**

```powershell
Set-ADUser [username] -Add @{altSecurityIdentities="X509:<SKI>[ski_hash]"}
```

### Smart Card Credential Provider Must Be Enabled

The Windows Smart Card Credential Provider tile won't appear at login unless explicitly enabled:

```powershell
$path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8FD7E19C-3BF7-489B-A72C-846AB3678C96}"
New-Item -Path $path -Force | Out-Null
Set-ItemProperty -Path $path -Name "Disabled" -Value 0 -Type DWord
```

## Setup Procedure

### Step 1: Domain Controller Configuration (One-Time)

Run `Setup-DC.ps1` or manually:

```powershell
# Disable Strong Certificate Binding Enforcement
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "StrongCertificateBindingEnforcement" -Value 0 -Type DWord

# Restart KDC service
Restart-Service kdc
```

### Step 2: Workstation Setup

Run `Setup-Workstation.ps1` or manually:

```powershell
# 1. Cleanup previous certs
Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -like "*shop*"} | Remove-Item -Force

# 2. Destroy any existing VSC
tpmvscmgr.exe destroy /instance ROOT\SMARTCARDREADER\0000 2>$null

# 3. Create VSC (PIN: 12345678)
tpmvscmgr.exe create /name "AuthentikVSC" /pin PROMPT /adminkey random /generate

# 4. Enroll certificate
certreq -enroll -user "AuthentikSmartcard"

# 5. Verify cert on VSC
certutil -scinfo

# 6. Get SKI for AD mapping
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -eq "CN=shop"}
$ski = $cert.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.14"}
$skiHash = $ski.Format(0)
Write-Host "SKI Hash: $skiHash" -ForegroundColor Green
Write-Host "Run on DC: Set-ADUser shop -Add @{altSecurityIdentities=`"X509:<SKI>$skiHash`"}" -ForegroundColor Yellow
```

### Step 3: Set AD Mapping (On DC)

```powershell
# Clear any existing mappings
Set-ADUser shop -Clear altSecurityIdentities

# Add SKI mapping (paste SKI from workstation output)
Set-ADUser shop -Add @{altSecurityIdentities="X509:<SKI>PASTE_SKI_HERE"}

# Verify
Get-ADUser shop -Properties altSecurityIdentities
```

### Step 4: Enable Smart Card Credential Provider (On Workstation)

```powershell
$path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8FD7E19C-3BF7-489B-A72C-846AB3678C96}"
if (!(Test-Path $path)) { New-Item -Path $path -Force }
Set-ItemProperty -Path $path -Name "Disabled" -Value 0 -Type DWord
```

### Step 5: Test

```powershell
# Quick test
runas /smartcard /user:shop@test.local cmd.exe
# PIN: 12345678

# Full test
# Press Win+L, select smart card tile, enter PIN
```

## Troubleshooting

### Error 1326: Username or password incorrect

1. **Check DC Security Log** - Is there a 4768 event for the user?
   - If NO event: Problem is client-side (NTAuth, certificate chain)
   - If event with error: Check Result Code

2. **Verify SKI mapping is set:**
   ```powershell
   Get-ADUser shop -Properties altSecurityIdentities
   ```

3. **Verify NTAuth on workstation:**
   ```powershell
   Get-ChildItem "HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates\NTAuth\Certificates"
   gpupdate /force
   ```

### No Smart Card Tile at Login

Enable the credential provider:
```powershell
$path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8FD7E19C-3BF7-489B-A72C-846AB3678C96}"
Set-ItemProperty -Path $path -Name "Disabled" -Value 0 -Type DWord
```

### Certificate Chain Validation Fails

```powershell
# Full chain verification
certutil -scinfo

# Check for errors
certutil -verify -urlfetch [cert_file]
```

## Certificate Requirements

| Attribute | Value |
|-----------|-------|
| EKU | Smart Card Logon (1.3.6.1.4.1.311.20.2.2) |
| EKU | Client Authentication (1.3.6.1.5.5.7.3.2) |
| SAN | UPN: user@domain.local |
| Key Usage | Digital Signature |
| KeySpec | AT_KEYEXCHANGE (1) |
| Key Size | 2048-bit RSA minimum |

## Phase 2: Authentik Integration

For Phase 2, the Authentik integration must:

1. Issue certificates with correct EKU/SAN
2. **Update AD altSecurityIdentities with SKI** (critical!)
3. Import certificate to VSC
4. Trigger PKINIT authentication

The credential provider flow:
```
User enters OTP → Authentik validates → Cert issued → AD mapping updated → Cert to VSC → PKINIT → Login
```
