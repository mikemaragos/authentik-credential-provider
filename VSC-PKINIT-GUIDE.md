# Virtual Smart Card PKINIT Authentication Guide

## Overview

This document describes how to achieve true PKINIT (certificate-based) Kerberos authentication on Windows using TPM Virtual Smart Cards. This is the recommended approach for passwordless domain authentication.

## Key Discovery

**Windows Kerberos SSP requires a smart card-compatible Key Storage Provider for KERB_CERTIFICATE_LOGON.** Software-based KSPs (Microsoft Software KSP, Passport KSP without WHfB enrollment) are NOT recognized for PKINIT authentication.

Evidence: Kerberos logs show `Client Realm: (empty)` and `Client Name: (empty)` when using software KSPs, indicating the Kerberos SSP isn't processing the certificate logon as PKINIT.

## Solution: TPM Virtual Smart Card

### Prerequisites

1. TPM 1.2 or 2.0 present and enabled
2. Windows 10/11 or Windows Server 2016+
3. Enterprise CA with smart card logon template
4. Domain user account

### Step 1: Create Virtual Smart Card

**Must be run from physical console (not RDP):**

```powershell
tpmvscmgr.exe create /name "Authentik VSC" /pin PROMPT /adminkey random /generate
```

Enter a PIN when prompted (e.g., `12345678`).

Output should show:
```
TPM Smart Card created.
Smart Card Reader Device Instance ID = ROOT\SMARTCARDREADER\0000
```

### Step 2: Start Smart Card Service

```powershell
Start-Service SCardSvr
Set-Service SCardSvr -StartupType Automatic
```

### Step 3: Verify VSC is Available

```powershell
certutil -scinfo
```

Should show:
```
Readers: 1
  0: Microsoft Virtual Smart Card 0
--- Status: The card is available for use.
```

### Step 4: Create Certificate Request INF

**CRITICAL: Must include UPN in Subject Alternative Name**

```powershell
$inf = @"
[NewRequest]
Subject = "CN=username"
KeySpec = 1
KeyLength = 2048
Exportable = FALSE
MachineKeySet = FALSE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft Base Smart Card Crypto Provider"
ProviderType = 1
RequestType = PKCS10
KeyUsage = 0xa0

[EnhancedKeyUsageExtension]
OID=1.3.6.1.4.1.311.20.2.2
OID=1.3.6.1.5.5.7.3.2

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "upn=username@domain.local"
"@

$inf | Out-File -FilePath "C:\temp\vsc-request.inf" -Encoding ASCII
```

### Step 5: Generate CSR on VSC

```powershell
certreq -new "C:\temp\vsc-request.inf" "C:\temp\vsc-request.csr"
```

This generates the key pair ON the TPM - private key never leaves the hardware.

### Step 6: Submit CSR to CA

```powershell
certreq -submit -attrib "CertificateTemplate:SmartcardLogon" -config "CA-SERVER\CA-NAME" C:\temp\vsc-request.csr C:\temp\vsc-cert.cer
```

### Step 7: Import Certificate to VSC

```powershell
certreq -accept C:\temp\vsc-cert.cer
```

### Step 8: Verify Certificate on VSC

```powershell
certutil -scinfo
```

Should show certificate with:
- Smart Card Logon EKU (1.3.6.1.4.1.311.20.2.2)
- Client Authentication EKU (1.3.6.1.5.5.7.3.2)
- Public key matching test succeeded
- Private key verifies
- Chain validates

### Step 9: Test Smart Card Logon

Lock workstation and use smart card sign-in option with VSC PIN.

## Certificate Requirements

For PKINIT to work, the certificate MUST have:

1. **Smart Card Logon EKU** (1.3.6.1.4.1.311.20.2.2)
2. **Client Authentication EKU** (1.3.6.1.5.5.7.3.2)
3. **Subject Alternative Name with UPN** matching AD user's userPrincipalName
4. **Valid certificate chain** to CA in NTAuth store
5. **Key generated on smart card** (not imported from software KSP)

## Troubleshooting

### "Credentials could not be verified"

- Check certificate has UPN in SAN matching AD user
- Verify CA is in NTAuth store: `certutil -viewstore -enterprise NTAuth`
- Check DC has valid KDC certificate

### VSC operations fail over RDP

- TPM Virtual Smart Card management requires physical console access
- Use VM console (Proxmox/Hyper-V) or physical access

### Smart Card service not running

```powershell
Get-Service SCardSvr
Start-Service SCardSvr
```

### Check DC for authentication errors

```powershell
Get-WinEvent -LogName "Security" -MaxEvents 50 | Where-Object { $_.Id -eq 4768 -or $_.Id -eq 4771 }
```

## Integration with Authentik Credential Provider

The credential provider can be modified to:

1. Generate key pair on VSC during enrollment
2. Create CSR from VSC key
3. Submit CSR to Authentik for signing
4. Import signed certificate to VSC
5. Use VSC for PKINIT authentication

This requires significant code changes but provides true passwordless PKINIT.

## Why Software KSP Doesn't Work

Windows PKINIT was designed for smart cards. The Kerberos SSP checks for:
- Smart card CSP/KSP provider
- Hardware-protected key
- Interactive PIN entry

Software-based keys (even with correct KERB_CERTIFICATE_LOGON structure) are rejected at the Kerberos SSP level before reaching the KDC.

## References

- [Setting up TPM protected certificates](https://learn.microsoft.com/en-us/archive/blogs/pki/setting-up-tpm-protected-certificates-using-a-microsoft-certificate-authority-part-2-virtual-smart-cards)
- [Virtual Smart Card Overview](https://learn.microsoft.com/en-us/windows/security/identity-protection/virtual-smart-cards/virtual-smart-card-overview)
- [PKINIT RFC 4556](https://datatracker.ietf.org/doc/html/rfc4556)
