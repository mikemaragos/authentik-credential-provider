# Authentik Passwordless Credential Provider - Architecture with AD CS

## Overview

This credential provider enables **true passwordless Windows domain authentication** using:
- **Authentik** for identity verification (username + OTP)
- **AD CS (Active Directory Certificate Services)** for certificate issuance
- **PKINIT** for Kerberos authentication with the certificate

## Architecture with AD CS

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Windows Login Screen                                 │
│                                                                              │
│    ┌──────────────────────────────────────────────────────────────────┐     │
│    │              Authentik Passwordless Login                         │     │
│    │                                                                   │     │
│    │    Username: [mike                    ]                           │     │
│    │                                                                   │     │
│    │    [Sign In]                                                      │     │
│    └──────────────────────────────────────────────────────────────────┘     │
│                                          │                                   │
└──────────────────────────────────────────┼───────────────────────────────────┘
                                           │
                    Step 1: Username       │  POST /api/v3/flows/executor/{flow}/
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            AUTHENTIK SERVER                                  │
│                                                                              │
│   ┌─────────────────┐    ┌─────────────────┐                                │
│   │  Identification │───►│  OTP Challenge  │                                │
│   │     Stage       │    │     Stage       │                                │
│   │                 │    │                 │                                │
│   │  - LDAP Lookup  │    │  - TOTP         │                                │
│   │  - User Valid?  │    │  - Push/WebAuthn│                                │
│   └─────────────────┘    └────────┬────────┘                                │
│                                   │                                          │
└───────────────────────────────────┼──────────────────────────────────────────┘
                                    │
                    Step 2: OTP     │  Response: OTP Challenge
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Windows Login Screen                                 │
│                                                                              │
│    ┌──────────────────────────────────────────────────────────────────┐     │
│    │              Authentik Passwordless Login                         │     │
│    │                                                                   │     │
│    │    Username: mike                                                 │     │
│    │    OTP Code: [123456]                                             │     │
│    │                                                                   │     │
│    │    [Verify]                                                       │     │
│    └──────────────────────────────────────────────────────────────────┘     │
│                                          │                                   │
└──────────────────────────────────────────┼───────────────────────────────────┘
                                           │
                    Step 3: Submit OTP     │  POST /api/v3/flows/executor/{flow}/
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            AUTHENTIK SERVER                                  │
│                                                                              │
│   OTP Valid? ──► YES ──► Request Certificate from AD CS                     │
│                          (via Certificate Enrollment Web Service or         │
│                           direct DCOM/RPC to CA)                            │
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  Certificate Issuance Stage (Custom)                                 │   │
│   │                                                                      │   │
│   │  1. Generate RSA 2048 key pair                                       │   │
│   │  2. Create CSR with:                                                 │   │
│   │     - CN = mike                                                      │   │
│   │     - SAN: UPN = mike@test.local                                     │   │
│   │  3. Submit CSR to AD CS                                              │   │
│   │  4. Receive signed certificate                                       │   │
│   │  5. Return cert + private key to client                              │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└───────────────────────────────────────────┬──────────────────────────────────┘
                                            │
                                            │  Certificate Request
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AD CS (Certificate Authority)                             │
│                    Running on Domain Controller                              │
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  Certificate Template: "Authentik Smart Card Logon"                  │   │
│   │                                                                      │   │
│   │  - Key Usage: Digital Signature, Key Encipherment                    │   │
│   │  - Enhanced Key Usage:                                               │   │
│   │      • Smart Card Logon (1.3.6.1.4.1.311.20.2.2)                     │   │
│   │      • Client Authentication (1.3.6.1.5.5.7.3.2)                     │   │
│   │  - Subject Name: Supplied in request                                 │   │
│   │  - SAN: UPN from request                                             │   │
│   │  - Validity: 1 hour (short-lived)                                    │   │
│   │  - Authorized Requesters: Authentik service account                  │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│   Issues Certificate ──────────────────────────────────────────────────────► │
│                                                                              │
└───────────────────────────────────────────┬──────────────────────────────────┘
                                            │
                    Step 4: Certificate     │  JSON Response with cert + key
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       CREDENTIAL PROVIDER                                    │
│                                                                              │
│   1. Parse certificate + private key from response                          │
│   2. Import to ephemeral NCrypt key container                               │
│   3. Build KERB_CERTIFICATE_LOGON structure                                 │
│   4. Return serialized credentials to LogonUI                               │
│                                                                              │
└───────────────────────────────────────────┬──────────────────────────────────┘
                                            │
                    Step 5: PKINIT          │  Certificate-based Kerberos
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DOMAIN CONTROLLER (KDC)                                   │
│                                                                              │
│   1. Receive PKINIT AS-REQ with certificate                                 │
│   2. Validate certificate:                                                  │
│      ✓ Chain to Enterprise CA (automatic trust)                             │
│      ✓ Not expired                                                          │
│      ✓ Has Smart Card Logon EKU                                             │
│      ✓ Template allows smart card logon                                     │
│   3. Map certificate UPN to AD user                                         │
│   4. Issue Kerberos TGT                                                     │
│   5. User logged in!                                                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## AD CS Integration Options

### Option 1: Certificate Enrollment Web Service (CEP/CES)

Authentik calls the AD CS web enrollment service:

```
Authentik ──HTTPS──► Certificate Enrollment Web Service ──► AD CS
                     (certsrv or CEP/CES)
```

**Pros:**
- Standard Microsoft interface
- Well-documented
- Supports templates

**Cons:**
- Requires IIS + web enrollment role
- More complex setup

### Option 2: Direct DCOM/RPC to CA

Authentik uses Windows RPC to communicate with CA:

```
Authentik ──RPC/DCOM──► AD CS (certsvc)
```

**Pros:**
- No additional services needed
- Direct communication

**Cons:**
- Requires Authentik on Windows or complex RPC implementation
- Firewall considerations

### Option 3: Authentik as Registration Authority (Recommended)

Authentik generates the key pair and CSR, submits to AD CS, returns cert:

```
┌─────────────────────────────────────────────────────────────┐
│                    AUTHENTIK SERVER                          │
│                                                              │
│  1. Generate key pair (RSA 2048 or ECDSA P-256)             │
│  2. Create CSR with user's UPN                               │
│  3. Submit CSR to AD CS via:                                 │
│     - certreq.exe (if Authentik on Windows)                  │
│     - PowerShell remoting                                    │
│     - Custom Python AD CS client                             │
│  4. Receive signed certificate                               │
│  5. Return certificate + private key to credential provider  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Pros:**
- Key pair generated fresh each authentication
- Short-lived certificates
- Authentik controls the flow

**Cons:**
- Requires implementation of AD CS client in Authentik

## AD CS Configuration Requirements

### 1. Certificate Template Setup

Create a new template based on "Smartcard Logon":

```powershell
# Open Certificate Templates MMC
certtmpl.msc

# Duplicate "Smartcard Logon" template
# Configure as follows:
```

**General Tab:**
- Template display name: `Authentik Passwordless Logon`
- Validity period: `1 hour`
- Renewal period: `0`

**Request Handling Tab:**
- Purpose: `Signature and encryption`
- [x] Allow private key to be exported (for Authentik to return to client)

**Cryptography Tab:**
- Provider Category: `Key Storage Provider`
- Algorithm: `RSA`
- Minimum key size: `2048`

**Subject Name Tab:**
- [x] Supply in the request
- (Do NOT use "Build from AD" - Authentik provides the subject)

**Extensions Tab:**
- Application Policies:
  - Smart Card Logon (1.3.6.1.4.1.311.20.2.2)
  - Client Authentication (1.3.6.1.5.5.7.3.2)

**Security Tab:**
- Add Authentik service account
- Grant: `Read`, `Enroll`

**Issuance Requirements Tab:**
- [x] CA certificate manager approval: `No` (auto-issue)
- OR configure authorized enrollment agent

### 2. Publish Template to CA

```powershell
# On the CA server
certsrv.msc
# Right-click "Certificate Templates" → New → Certificate Template to Issue
# Select "Authentik Passwordless Logon"
```

### 3. Service Account for Authentik

Create a service account that can request certificates:

```powershell
# Create service account
New-ADUser -Name "svc_authentik_cert" `
           -SamAccountName "svc_authentik_cert" `
           -UserPrincipalName "svc_authentik_cert@test.local" `
           -AccountPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force) `
           -Enabled $true `
           -PasswordNeverExpires $true

# Grant enrollment permissions on template (done in template security tab)
```

### 4. Verify CA is in NTAuth Store

Enterprise CAs are automatically added, but verify:

```powershell
# Check NTAuth store
certutil -viewstore "ldap:///CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=local?cACertificate"

# Should show your Enterprise CA
```

## Authentik Server-Side Implementation

### Python Example: Request Certificate from AD CS

```python
# authentik_adcs_client.py
# Example implementation for Authentik custom stage

import subprocess
import tempfile
import os
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

class ADCSClient:
    def __init__(self, ca_server: str, ca_name: str, template: str):
        self.ca_server = ca_server
        self.ca_name = ca_name
        self.template = template
    
    def request_certificate(self, username: str, domain: str) -> tuple[str, str]:
        """
        Request a certificate from AD CS for the given user.
        Returns (certificate_pem, private_key_pem)
        """
        # Generate key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Build CSR
        upn = f"{username}@{domain}"
        
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, username),
            ])
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.OtherName(
                    x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),  # UPN OID
                    upn.encode('utf-8')
                ),
            ]),
            critical=False
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        # Write CSR to temp file
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.csr', delete=False) as f:
            csr_path = f.name
            f.write(csr.public_bytes(serialization.Encoding.PEM))
        
        cert_path = csr_path.replace('.csr', '.cer')
        
        try:
            # Submit to AD CS using certreq
            # This requires Authentik server to have certreq.exe or use PowerShell remoting
            result = subprocess.run([
                'certreq',
                '-submit',
                '-config', f'{self.ca_server}\\{self.ca_name}',
                '-attrib', f'CertificateTemplate:{self.template}',
                csr_path,
                cert_path
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                raise Exception(f"certreq failed: {result.stderr}")
            
            # Read issued certificate
            with open(cert_path, 'rb') as f:
                cert_pem = f.read().decode('utf-8')
            
            # Export private key
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            return cert_pem, private_key_pem
            
        finally:
            # Cleanup temp files
            if os.path.exists(csr_path):
                os.unlink(csr_path)
            if os.path.exists(cert_path):
                os.unlink(cert_path)
```

### PowerShell Remoting Alternative

If Authentik is on Linux, use PowerShell remoting:

```python
import winrm

def request_cert_via_winrm(username: str, domain: str, 
                           ca_server: str, ca_name: str,
                           winrm_host: str, winrm_user: str, winrm_pass: str):
    """Request certificate via PowerShell remoting to a Windows host"""
    
    session = winrm.Session(
        winrm_host,
        auth=(winrm_user, winrm_pass),
        transport='ntlm'
    )
    
    # PowerShell script to generate CSR and submit to CA
    ps_script = f'''
    $upn = "{username}@{domain}"
    
    # Create certificate request
    $inf = @"
[Version]
Signature = "$Windows NT$"

[NewRequest]
Subject = "CN={username}"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = FALSE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0

[EnhancedKeyUsageExtension]
OID=1.3.6.1.4.1.311.20.2.2
OID=1.3.6.1.5.5.7.3.2

[Extensions]
2.5.29.17 = "{{text}}"
_continue_ = "upn=$upn"
"@

    $infPath = "$env:TEMP\\certreq_$([guid]::NewGuid()).inf"
    $csrPath = "$env:TEMP\\certreq_$([guid]::NewGuid()).csr"
    $cerPath = "$env:TEMP\\certreq_$([guid]::NewGuid()).cer"
    
    $inf | Out-File -FilePath $infPath -Encoding ascii
    
    # Generate CSR
    certreq -new $infPath $csrPath
    
    # Submit to CA
    certreq -submit -config "{ca_server}\\{ca_name}" -attrib "CertificateTemplate:AuthentikPasswordlessLogon" $csrPath $cerPath
    
    # Read certificate
    $cert = Get-Content $cerPath -Raw
    
    # Export private key (from user store)
    # ... additional logic needed
    
    # Cleanup
    Remove-Item $infPath, $csrPath, $cerPath -Force
    
    return $cert
    '''
    
    result = session.run_ps(ps_script)
    return result.std_out.decode('utf-8')
```

## Certificate Response Format

The credential provider expects this JSON structure:

```json
{
    "type": "redirect",
    "to": "/application/launch/...",
    "certificate": "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
    "username": "mike",
    "domain": "TEST",
    "upn": "mike@test.local",
    "valid_minutes": 60
}
```

## Security Considerations

### Certificate Template Security

1. **Limit who can enroll**: Only Authentik service account
2. **Short validity**: 1 hour or less
3. **No archival**: Don't archive private keys on CA
4. **Audit**: Enable certificate issuance auditing

### Private Key Protection

1. Key generated on Authentik server (not exposed to user)
2. Transmitted over TLS to credential provider
3. Imported to ephemeral NCrypt container
4. Cleared from memory after use
5. Never written to disk on client

### Authentik Service Account

1. Use dedicated service account for AD CS enrollment
2. Minimal permissions (only enroll on specific template)
3. Monitor for unusual certificate requests
4. Consider time-based restrictions

## Troubleshooting

### Certificate Request Fails

```powershell
# Check CA event logs
Get-WinEvent -LogName "Application" -FilterXPath "*[System[Provider[@Name='Microsoft-Windows-CertificationAuthority']]]" | Select-Object -First 10

# Verify template is published
certutil -CATemplates

# Test certificate request manually
certreq -new request.inf request.csr
certreq -submit -config "DC01\Test-CA" request.csr
```

### PKINIT Fails

```powershell
# Check Kerberos event logs on DC
Get-WinEvent -LogName "System" -FilterXPath "*[System[Provider[@Name='Microsoft-Windows-Kerberos-Key-Distribution-Center']]]" | Select-Object -First 10

# Verify certificate has correct EKUs
certutil -dump certificate.cer

# Check UPN mapping
Get-ADUser -Identity mike -Properties Certificates,userPrincipalName
```

## Summary

Using AD CS provides:
- ✅ Automatic trust (Enterprise CA)
- ✅ No NTAuth configuration needed
- ✅ Standard Microsoft tooling
- ✅ Existing PKI infrastructure
- ✅ Audit and compliance logging
- ✅ Certificate template controls

The main work is:
1. Create certificate template on AD CS
2. Implement certificate request logic in Authentik
3. Configure Authentik flow to call AD CS after OTP validation
