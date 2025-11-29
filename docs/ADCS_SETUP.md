# AD CS Configuration Guide for Authentik Passwordless Login

This guide walks you through setting up AD CS to issue short-lived certificates for passwordless Windows authentication with Authentik.

## Prerequisites

- Windows Server with AD CS role installed (Enterprise CA)
- Domain Admin or CA Admin privileges
- Authentik server configured with LDAP integration

## Step 1: Create Certificate Template

### Open Certificate Templates Console

```powershell
# On the CA server
certtmpl.msc
```

### Duplicate Smartcard Logon Template

1. Find **Smartcard Logon** template
2. Right-click → **Duplicate Template**
3. Select **Windows Server 2016** (or your minimum DC version)

### Configure Template Properties

#### General Tab
| Setting | Value |
|---------|-------|
| Template display name | `Authentik Passwordless Logon` |
| Template name | `AuthentikPasswordlessLogon` |
| Validity period | `1 hour` |
| Renewal period | `0 minutes` |

#### Request Handling Tab
| Setting | Value |
|---------|-------|
| Purpose | `Signature and encryption` |
| Allow private key to be exported | `✓ Checked` |
| Include symmetric algorithms | `✓ Checked` |

> **Note:** We allow export so Authentik can send the private key to the credential provider.

#### Cryptography Tab
| Setting | Value |
|---------|-------|
| Provider Category | `Key Storage Provider` |
| Algorithm name | `RSA` |
| Minimum key size | `2048` |
| Request hash | `SHA256` |

#### Subject Name Tab
| Setting | Value |
|---------|-------|
| Supply in the request | `✓ Selected` |

> **Important:** Do NOT select "Build from Active Directory information" - Authentik will supply the subject.

#### Extensions Tab

**Application Policies:**
1. Click **Edit**
2. Ensure these are present:
   - `Smart Card Logon` (1.3.6.1.4.1.311.20.2.2)
   - `Client Authentication` (1.3.6.1.5.5.7.3.2)

#### Security Tab

Add permissions for Authentik service account:

| Principal | Permissions |
|-----------|-------------|
| `svc_authentik_cert` | Read, Enroll |
| Domain Admins | Full Control |
| Enterprise Admins | Full Control |

#### Issuance Requirements Tab
| Setting | Value |
|---------|-------|
| CA certificate manager approval | `Not required` |
| Number of authorized signatures | `0` |

> For production, consider requiring enrollment agent signature.

### Save Template

Click **OK** to save the template.

## Step 2: Publish Template to CA

### Open Certification Authority Console

```powershell
certsrv.msc
```

### Issue New Template

1. Expand your CA
2. Right-click **Certificate Templates**
3. Click **New** → **Certificate Template to Issue**
4. Select **Authentik Passwordless Logon**
5. Click **OK**

### Verify Template is Published

```powershell
# List published templates
certutil -CATemplates

# Should show:
# AuthentikPasswordlessLogon -- Authentik Passwordless Logon
```

## Step 3: Create Authentik Service Account

### Create AD User

```powershell
# Create service account
New-ADUser -Name "svc_authentik_cert" `
    -SamAccountName "svc_authentik_cert" `
    -UserPrincipalName "svc_authentik_cert@test.local" `
    -Description "Authentik certificate enrollment service account" `
    -AccountPassword (Read-Host -AsSecureString "Enter Password") `
    -Enabled $true `
    -PasswordNeverExpires $true `
    -CannotChangePassword $true

# Add to appropriate group if using enrollment agents
# Add-ADGroupMember -Identity "Certificate Service DCOM Access" -Members "svc_authentik_cert"
```

### Verify Enrollment Permissions

```powershell
# Test enrollment (will fail without private key, but verifies permissions)
$templateOid = "1.3.6.1.4.1.311.21.8.X.X.X.X.X.X.X"  # Get from template properties

# Or use certutil
certutil -config "DC01\Test-CA" -CATemplates | findstr "Authentik"
```

## Step 4: Configure AD CS for Remote Requests

### Option A: Certificate Enrollment Web Service (Recommended)

Install and configure CEP/CES for HTTPS-based enrollment:

```powershell
# Install Web Enrollment role
Install-WindowsFeature ADCS-Web-Enrollment -IncludeManagementTools

# Install Certificate Enrollment Web Service
Install-WindowsFeature ADCS-Enroll-Web-Svc -IncludeManagementTools

# Install Certificate Enrollment Policy Web Service  
Install-WindowsFeature ADCS-Enroll-Web-Pol -IncludeManagementTools

# Configure (run on CA or separate server)
Install-AdcsEnrollmentWebService -AuthenticationType Username -SSLCertThumbprint "THUMBPRINT"
Install-AdcsEnrollmentPolicyWebService -AuthenticationType Username -SSLCertThumbprint "THUMBPRINT"
```

### Option B: DCOM/RPC Access

For direct RPC access from Authentik (if on Windows):

```powershell
# Grant DCOM access to service account
# Open dcomcnfg.exe → Component Services → Computers → My Computer
# Properties → COM Security → Access Permissions → Edit Limits
# Add svc_authentik_cert with Local Access and Remote Access
```

### Option C: PowerShell Remoting

Enable WinRM for certificate requests from Authentik:

```powershell
# On CA server
Enable-PSRemoting -Force

# Allow service account to connect
Set-PSSessionConfiguration -Name Microsoft.PowerShell -ShowSecurityDescriptorUI

# Add svc_authentik_cert with Execute(Invoke) permission
```

## Step 5: Test Certificate Enrollment

### Manual Test with certreq

Create test request file `test.inf`:

```ini
[Version]
Signature = "$Windows NT$"

[NewRequest]
Subject = "CN=testuser"
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
2.5.29.17 = "{text}"
_continue_ = "upn=testuser@test.local"

[RequestAttributes]
CertificateTemplate = AuthentikPasswordlessLogon
```

Run test:

```powershell
# Generate CSR
certreq -new test.inf test.csr

# Submit to CA (replace DC01\Test-CA with your CA)
certreq -submit -config "DC01\Test-CA" test.csr test.cer

# Verify certificate
certutil -dump test.cer
```

### Verify Certificate Properties

```powershell
# Check EKUs
certutil -dump test.cer | findstr "Smart Card"

# Check SAN/UPN
certutil -dump test.cer | findstr "Principal"

# Should show:
#     Smart Card Logon (1.3.6.1.4.1.311.20.2.2)
#     Other Name: Principal Name=testuser@test.local
```

## Step 6: Configure Authentik

### Create Custom Stage or Flow

You'll need to implement certificate request logic in Authentik. Options:

1. **Custom Stage (Python)**: Write a custom Authentik stage that calls AD CS
2. **Expression Policy + API**: Use Authentik's expression policies with external API calls
3. **External Service**: Separate microservice that Authentik calls

### Example: External Certificate Service

Create a small service that Authentik can call:

```python
# cert_service.py - Flask app for certificate requests
from flask import Flask, request, jsonify
import subprocess
import tempfile
import os

app = Flask(__name__)

CA_CONFIG = "DC01\\Test-CA"  # Your CA
TEMPLATE = "AuthentikPasswordlessLogon"

@app.route('/request-cert', methods=['POST'])
def request_cert():
    data = request.json
    username = data['username']
    domain = data['domain']
    upn = f"{username}@{domain}"
    
    # Create INF file
    inf_content = f'''[Version]
Signature = "$Windows NT$"

[NewRequest]
Subject = "CN={username}"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = FALSE
RequestType = PKCS10
KeyUsage = 0xa0

[EnhancedKeyUsageExtension]
OID=1.3.6.1.4.1.311.20.2.2
OID=1.3.6.1.5.5.7.3.2

[Extensions]
2.5.29.17 = "{{text}}"
_continue_ = "upn={upn}"

[RequestAttributes]
CertificateTemplate = {TEMPLATE}
'''
    
    with tempfile.TemporaryDirectory() as tmpdir:
        inf_path = os.path.join(tmpdir, 'req.inf')
        csr_path = os.path.join(tmpdir, 'req.csr')
        cer_path = os.path.join(tmpdir, 'req.cer')
        pfx_path = os.path.join(tmpdir, 'req.pfx')
        
        # Write INF
        with open(inf_path, 'w') as f:
            f.write(inf_content)
        
        # Generate CSR (creates private key in user store)
        result = subprocess.run(
            ['certreq', '-new', '-f', inf_path, csr_path],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            return jsonify({'error': f'CSR generation failed: {result.stderr}'}), 500
        
        # Submit to CA
        result = subprocess.run(
            ['certreq', '-submit', '-config', CA_CONFIG, csr_path, cer_path],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            return jsonify({'error': f'CA submission failed: {result.stderr}'}), 500
        
        # Accept certificate (installs to store)
        result = subprocess.run(
            ['certreq', '-accept', cer_path],
            capture_output=True, text=True
        )
        
        # Export as PFX (includes private key)
        # Find the cert by subject
        result = subprocess.run(
            ['certutil', '-user', '-exportpfx', '-p', '', f'CN={username}', pfx_path],
            capture_output=True, text=True
        )
        
        # Read PFX and convert to PEM
        # ... (use cryptography library to convert)
        
        # Read certificate
        with open(cer_path, 'r') as f:
            cert_pem = f.read()
        
        # Delete from user store (cleanup)
        subprocess.run(['certutil', '-user', '-delstore', 'My', f'CN={username}'])
        
        return jsonify({
            'certificate': cert_pem,
            'private_key': private_key_pem,  # From PFX conversion
            'username': username,
            'domain': domain.split('.')[0].upper(),
            'upn': upn
        })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')
```

### Authentik Flow Configuration

1. **Identification Stage**: Capture username
2. **Authenticator Validation Stage**: Validate OTP
3. **Custom Stage/Policy**: Call certificate service, include cert in response

## Step 7: Verify End-to-End

### Test Sequence

1. Lock Windows workstation (Win+L)
2. Select "Authentik Passwordless Login"
3. Enter username → Submit
4. Enter OTP code → Submit
5. Watch DebugView for certificate processing
6. Should log in without password!

### Verification Commands

```powershell
# On logged-in workstation, verify Kerberos ticket
klist

# Should show TGT obtained via PKINIT:
# Client: mike @ TEST.LOCAL
# Server: krbtgt/TEST.LOCAL @ TEST.LOCAL
# KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
# ... 
# Auth method: PKINIT
```

## Troubleshooting

### Certificate Request Denied

```powershell
# Check CA logs
Get-WinEvent -LogName "Application" -FilterXPath "*[System[Provider[@Name='Microsoft-Windows-CertificationAuthority']]]" -MaxEvents 20

# Common issues:
# - Template not published
# - Service account doesn't have Enroll permission
# - Template name mismatch
```

### PKINIT Fails at DC

```powershell
# Check KDC logs
Get-WinEvent -LogName "System" -FilterXPath "*[System[Provider[@Name='Microsoft-Windows-Kerberos-Key-Distribution-Center']]]" -MaxEvents 20

# Common issues:
# - Certificate doesn't have Smart Card Logon EKU
# - UPN doesn't match AD user
# - Certificate expired
```

### Certificate Not Trusted

```powershell
# Verify CA is Enterprise CA
certutil -CAInfo

# Should show:
# CA type: Enterprise Root CA
# or
# CA type: Enterprise Subordinate CA
```

## Security Hardening

### Limit Template Enrollment

Only allow Authentik service account:

```powershell
# Remove "Authenticated Users" from template security
# Add only svc_authentik_cert with Read + Enroll
```

### Enable Auditing

```powershell
# On CA server
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
```

### Monitor Certificate Issuance

```powershell
# Alert on unusual certificate requests
Get-WinEvent -LogName "Security" -FilterXPath "*[System[EventID=4887]]" | 
    Where-Object { $_.Properties[5].Value -like "*Authentik*" }
```

## Summary

| Component | Status |
|-----------|--------|
| Certificate Template | ✅ Created and published |
| Service Account | ✅ Created with Enroll permission |
| CA Access | ✅ Configured (Web Service/RPC/WinRM) |
| Authentik Integration | 🔧 Implement certificate request logic |
| Credential Provider | ✅ Ready to receive certificates |
