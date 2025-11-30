# PKINIT Smart Card Authentication Guide

## Overview

This guide documents the complete process for implementing passwordless Windows domain authentication using TPM Virtual Smart Cards (VSC) and PKINIT (Public Key Cryptography for Initial Authentication in Kerberos).

**Status:** ✅ WORKING (November 30, 2025)

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Workstation   │     │  Domain Controller│     │   Certificate   │
│    (TEST10)     │────▶│  (WIN-6DP39D0OLI8)│     │   Authority     │
│                 │     │                  │     │                 │
│  TPM VSC ───────┼─────┼──▶ KDC (PKINIT) │     │  AD CS          │
│  Certificate    │     │     │            │     │                 │
│  Private Key    │     │     ▼            │     │                 │
│                 │     │  TGT Issued      │◀────│  Issues Certs   │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

## Test Environment

| Component | Value |
|-----------|-------|
| Domain | test.local |
| Domain Controller | WIN-6DP39D0OLI8.test.local |
| Certificate Authority | test-WIN-6DP39D0OLI8-CA |
| Workstation | TEST10 |
| Test User | shop@test.local |
| VSC PIN | 12345678 |

## Critical Success Factors

### 1. Certificate Template Configuration

The certificate template **MUST** have `CT_FLAG_SUBJECT_ALT_REQUIRE_UPN` flag set to include the User Principal Name in the Subject Alternative Name extension.

**Required Template Flags:**
```
msPKI-Certificate-Name-Flag = 0x62000000
  CT_FLAG_SUBJECT_ALT_REQUIRE_UPN    = 0x02000000 (33554432)   ← CRITICAL
  CT_FLAG_SUBJECT_REQUIRE_EMAIL      = 0x20000000 (536870912)
  CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME = 0x40000000 (1073741824)
```

**PowerShell to configure:**
```powershell
$templateName = "AuthentikSmartcard"
$configNC = (Get-ADRootDSE).configurationNamingContext
$templateDN = "CN=$templateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
Set-ADObject -Identity $templateDN -Replace @{'msPKI-Certificate-Name-Flag'=0x62000000}
Restart-Service certsvc
```

### 2. Single Certificate on VSC

**CRITICAL:** Windows will fail to authenticate if multiple certificates exist on the Virtual Smart Card. The KDC may select the wrong certificate.

**Solution:** Always destroy and recreate VSC before issuing new certificates:
```powershell
# Must run from physical/Proxmox console, NOT RDP
tpmvscmgr destroy /instance ROOT\SMARTCARDREADER\0000
tpmvscmgr create /name "Authentik VSC" /pin PROMPT /adminkey random /generate
```

### 3. UPN in Subject Alternative Name

The certificate **MUST** contain the UPN in the Subject Alternative Name extension:
```
Subject Alternative Name:
  Other Name:
    Principal Name=shop@test.local
```

Without this, the KDC cannot map the certificate to an AD user account (KB5014754 requirement).

### 4. User Account Configuration

The AD user account must have:
- `userPrincipalName` set (e.g., shop@test.local)
- `mail` attribute set (e.g., shop@test.local)

```powershell
Set-ADUser -Identity shop -UserPrincipalName "shop@test.local"
Set-ADUser -Identity shop -EmailAddress "shop@test.local"
```

## Certificate Template Setup

### Create Custom Smart Card Template

1. Open Certificate Authority MMC
2. Right-click Certificate Templates → Manage
3. Find "Smartcard Logon" template → Duplicate
4. Configure the duplicate:

**General Tab:**
- Template display name: AuthentikSmartcard

**Request Handling Tab:**
- Purpose: Signature and encryption
- ✓ Allow private key to be exported: NO

**Cryptography Tab:**
- Provider Category: Key Storage Provider
- Algorithm name: RSA
- Minimum key size: 2048

**Subject Name Tab:**
- ✓ Build from this Active Directory information
- Subject name format: Common name
- ✓ Include e-mail name in subject name
- ✓ Include e-mail name in alternate subject name
- ✓ User principal name (UPN)

**Extensions Tab:**
- Application Policies: Smart Card Logon, Client Authentication

**Security Tab:**
- Add "Authenticated Users" with Enroll permission

### Enable Template on CA

```powershell
certutil -SetCATemplates +AuthentikSmartcard
```

### Configure Template via PowerShell (if GUI unavailable)

```powershell
$templateName = "AuthentikSmartcard"
$configNC = (Get-ADRootDSE).configurationNamingContext
$templateDN = "CN=$templateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

# Set flags for UPN in SAN
Set-ADObject -Identity $templateDN -Replace @{'msPKI-Certificate-Name-Flag'=0x62000000}

# Grant Authenticated Users enroll permission
dsacls $templateDN /G "Authenticated Users:CA;Enroll"

# Restart CA
Restart-Service certsvc
```

## Certificate Enrollment Process

### Step 1: Create Virtual Smart Card

From Proxmox/physical console (NOT RDP):
```powershell
tpmvscmgr create /name "Authentik VSC" /pin PROMPT /adminkey random /generate
# Enter PIN: 12345678
# Confirm PIN: 12345678
```

### Step 2: Create Certificate Request

```powershell
@"
[NewRequest]
Subject = "CN=shop"
ProviderName = "Microsoft Base Smart Card Crypto Provider"
KeySpec = 1
KeyLength = 2048
Exportable = FALSE
MachineKeySet = FALSE
RequestType = PKCS10

[RequestAttributes]
CertificateTemplate = AuthentikSmartcard
"@ | Out-File -FilePath C:\temp\smartcard.inf -Encoding ASCII

certreq -new C:\temp\smartcard.inf C:\temp\smartcard.csr
# Enter PIN when prompted
```

### Step 3: Submit to CA

```powershell
certreq -submit -config "WIN-6DP39D0OLI8.test.local\test-WIN-6DP39D0OLI8-CA" C:\temp\smartcard.csr C:\temp\smartcard.cer
```

### Step 4: Accept Certificate

```powershell
certreq -accept C:\temp\smartcard.cer
```

### Step 5: Verify Certificate

```powershell
# Check certificate exists
Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*shop*" }

# Verify UPN in SAN
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*shop*" }
$san = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
$san.Format($true)
# Should show: Other Name: Principal Name=shop@test.local
```

## Domain Controller Configuration

### Required Registry Settings

```powershell
# Enable SAN usage for certificate mapping
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "UseSubjectAltName" -Value 1 -PropertyType DWord -Force

# Disable strong certificate binding enforcement (for testing)
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "StrongCertificateBindingEnforcement" -Value 0 -PropertyType DWord -Force

# Restart KDC
Restart-Service kdc
```

### CA Configuration

```powershell
# Enable SAN from request attributes
certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
Restart-Service certsvc
```

### Verify NTAuth Store

The CA certificate must be in the NTAuth store:
```powershell
certutil -viewstore -enterprise NTAuth
```

If missing:
```powershell
certutil -dspublish -f <CA_cert.cer> NTAuth
```

## Troubleshooting

### Event 39 on DC: Certificate Mapping Failed

**Symptom:** KDC Event ID 39 "certificate could not be mapped to a user in a secure way"

**Cause:** Certificate doesn't have UPN in SAN, or multiple certificates causing wrong selection

**Solution:**
1. Verify certificate has UPN in SAN extension
2. Destroy VSC and recreate with single certificate
3. Use template with `CT_FLAG_SUBJECT_ALT_REQUIRE_UPN`

### Kerberos Error 0x19 KDC_ERR_PREAUTH_REQUIRED with Empty Client

**Symptom:** Kerberos error with empty Client Realm and Client Name

**Cause:** PKINIT not being used, certificate not on smart card provider

**Solution:**
1. Verify certificate is on VSC (not software KSP)
2. Check ProviderName = "Microsoft Base Smart Card Crypto Provider"
3. Verify private key is on VSC: `certutil -scinfo`

### "Credentials could not be verified" Error

**Symptom:** Login screen shows error after PIN entry

**Cause:** KDC cannot map certificate to user

**Solution:**
1. Check DC System log for Event 39
2. Verify altSecurityIdentities on user (optional but helps)
3. Ensure UPN in certificate matches AD userPrincipalName

### Multiple Certificates on VSC

**Symptom:** Inconsistent authentication failures

**Solution:**
```powershell
# From Proxmox console
tpmvscmgr destroy /instance ROOT\SMARTCARDREADER\0000
tpmvscmgr create /name "Authentik VSC" /pin PROMPT /adminkey random /generate
# Re-enroll single certificate
```

### Ghost Certificates in Store

**Symptom:** Certificates appear after deletion

**Solution:**
```powershell
# Delete from software store
Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq "THUMBPRINT" } | Remove-Item -Force

# If persists, reboot workstation
```

## Diagnostic Commands

### On Workstation

```powershell
# Check VSC status
certutil -scinfo

# List certificates with private keys
Get-ChildItem Cert:\CurrentUser\My | ForEach-Object { 
    Write-Host $_.Thumbprint "HasPrivateKey:" $_.HasPrivateKey "Subject:" $_.Subject 
}

# Check certificate extensions
$cert = Get-ChildItem Cert:\CurrentUser\My\<THUMBPRINT>
$cert.Extensions | ForEach-Object { 
    Write-Host "OID:" $_.Oid.FriendlyName
    Write-Host $_.Format($true)
    Write-Host "---" 
}

# Check Kerberos errors
Get-WinEvent -LogName "System" -MaxEvents 20 | Where-Object { $_.ProviderName -like "*Kerb*" }

# Enable CAPI2 logging
wevtutil sl Microsoft-Windows-CAPI2/Operational /e:true
```

### On Domain Controller

```powershell
# Check for certificate mapping errors
Get-WinEvent -LogName "System" -MaxEvents 10 | Where-Object { $_.Id -eq 39 }

# Check TGT requests
Get-WinEvent -LogName "Security" -MaxEvents 20 | Where-Object { $_.Id -eq 4768 }

# Check user's altSecurityIdentities
Get-ADUser -Identity shop -Properties altSecurityIdentities | Select-Object -ExpandProperty altSecurityIdentities

# Verify template configuration
certutil -dstemplate AuthentikSmartcard msPKI-Certificate-Name-Flag

# Check CA templates
certutil -catemplates
```

## altSecurityIdentities Mappings (Optional)

While not required when UPN is in SAN, explicit mappings can help:

```powershell
# Get certificate public key hash
$cert = Get-ChildItem Cert:\CurrentUser\My\<THUMBPRINT>
$pubKeyHash = [System.Security.Cryptography.SHA1]::Create().ComputeHash($cert.PublicKey.EncodedKeyValue.RawData)
$pubKeyHashString = [BitConverter]::ToString($pubKeyHash) -replace '-',''

# Add mappings on DC
Set-ADUser -Identity shop -Add @{altSecurityIdentities="X509:<SHA1-PUKEY>$pubKeyHashString"}
Set-ADUser -Identity shop -Add @{altSecurityIdentities="X509:<I>CN=test-WIN-6DP39D0OLI8-CA, DC=test, DC=local<S>CN=shop"}
Set-ADUser -Identity shop -Add @{altSecurityIdentities="X509:<RFC822>shop@test.local"}
```

## Working Configuration Summary

| Setting | Value |
|---------|-------|
| Template Name | AuthentikSmartcard |
| msPKI-Certificate-Name-Flag | 0x62000000 |
| Certificate Subject | E=shop@test.local, CN=shop |
| Certificate SAN | Principal Name=shop@test.local |
| VSC Provider | Microsoft Base Smart Card Crypto Provider |
| Key Length | 2048 |
| EKUs | Smart Card Logon, Client Authentication |

## References

- [KB5014754 - Certificate-based authentication changes](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Microsoft Credential Provider Documentation](https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
- [Smart Card Technical Reference](https://docs.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-technical-reference)
- [PKINIT Technical Reference](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pkca/)

---

**Document Version:** 1.0  
**Last Updated:** November 30, 2025  
**Status:** ✅ Verified Working
