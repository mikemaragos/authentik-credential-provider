# Authentik Setup Guide for Windows Passwordless Authentication

This guide covers the complete setup of Authentik to work with the Windows Passwordless Credential Provider.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Phase 1: Basic OTP Flow (Testing)](#phase-1-basic-otp-flow-testing)
4. [Phase 2: Certificate Issuance (Production)](#phase-2-certificate-issuance-production)
5. [AD CS Configuration](#ad-cs-configuration)
6. [Troubleshooting](#troubleshooting)

---

## Overview

The Windows Passwordless Credential Provider authenticates users through this flow:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Windows Login  │────▶│    Authentik    │────▶│     AD CS       │
│  (Credential    │     │  (OTP Verify)   │     │  (Issue Cert)   │
│   Provider)     │◀────│                 │◀────│                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                                               │
        │              ┌─────────────────┐              │
        └─────────────▶│ Active Directory│◀─────────────┘
                       │    (PKINIT)     │
                       └─────────────────┘
```

1. User enters username → Credential Provider sends to Authentik
2. Authentik prompts for OTP → User enters OTP
3. Authentik validates OTP → Requests certificate from AD CS
4. Authentik returns certificate → Credential Provider uses for PKINIT
5. Windows authenticates user via Kerberos with certificate

---

## Prerequisites

### Authentik Server
- Authentik 2023.x or later
- HTTPS enabled (self-signed OK for testing)
- Network accessible from Windows workstations

### Active Directory
- Windows Server 2016+ Domain Controller
- AD CS (Certificate Services) role installed
- Users with UPN configured

### Windows Workstation
- Windows 10/11 or Windows Server 2016+
- Domain-joined
- Visual C++ Redistributable installed

---

## Phase 1: Basic OTP Flow (Testing)

Start with a simple flow to verify the credential provider works before adding certificate issuance.

### Step 1: Create the Flow

1. Go to **Authentik Admin** → **Flows & Stages** → **Flows**
2. Click **Create**

| Setting | Value |
|---------|-------|
| Name | Windows Passwordless Login |
| Slug | `windows-passwordless` |
| Title | Windows Passwordless Login |
| Designation | Authentication |

3. Click **Create**

### Step 2: Create Identification Stage

1. Go to **Flows & Stages** → **Stages** → **Create**
2. Select **Identification Stage**

| Setting | Value |
|---------|-------|
| Name | windows-identification |
| User fields | Username |
| Password stage | (leave empty) |
| Show matched user | No |
| Enrollment flow | (leave empty) |
| Recovery flow | (leave empty) |

3. Click **Create**

### Step 3: Create OTP Validation Stage

1. Go to **Flows & Stages** → **Stages** → **Create**
2. Select **Authenticator Validation Stage**

| Setting | Value |
|---------|-------|
| Name | windows-otp-validation |
| Device classes | TOTP Authenticators |
| Not configured action | Deny |
| Configuration stages | (leave empty for now) |

3. Click **Create**

### Step 4: Bind Stages to Flow

1. Go to **Flows & Stages** → **Flows**
2. Click on **windows-passwordless**
3. Click **Stage Bindings** tab
4. Click **Bind Stage**

**First binding:**
| Setting | Value |
|---------|-------|
| Stage | windows-identification |
| Order | 10 |

**Second binding:**
| Setting | Value |
|---------|-------|
| Stage | windows-otp-validation |
| Order | 20 |

### Step 5: Configure Users with TOTP

1. Each user needs TOTP configured
2. Go to **Directory** → **Users** → Select user
3. Click **Authenticators** tab
4. Add **TOTP Authenticator**

### Step 6: Test the Flow

Test via browser first:
```
https://your-authentik-server/if/flow/windows-passwordless/
```

You should see:
1. Username prompt
2. OTP prompt
3. Success redirect

### Step 7: Configure Windows Registry

On your Windows workstation:

```powershell
# Run as Administrator
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v ServerUrl /t REG_SZ /d "your-authentik-server.com" /f
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v ServerPort /t REG_DWORD /d 443 /f
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v FlowSlug /t REG_SZ /d "windows-passwordless" /f
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v UseHttps /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v Domain /t REG_SZ /d "YOURDOMAIN" /f
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v DomainFQDN /t REG_SZ /d "yourdomain.local" /f
reg add "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v IgnoreCertErrors /t REG_DWORD /d 1 /f
```

---

## Phase 2: Certificate Issuance (Production)

For true passwordless authentication, Authentik must issue certificates after OTP validation.

### Option A: Authentik Expression Stage + External Service

This approach uses an external certificate issuance service.

#### 1. Deploy Certificate Issuance Service

Create a service on a Windows server with AD CS tools:

**cert_issuer_service.py:**
```python
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import subprocess
import tempfile
import os
import secrets

app = FastAPI(title="Certificate Issuance Service")
security = HTTPBearer()

# Configuration
API_TOKEN = os.environ.get("API_TOKEN", "your-secret-token-here")
CA_CONFIG = os.environ.get("CA_CONFIG", "CA01.yourdomain.local\\YourDomain-CA")
CERT_TEMPLATE = os.environ.get("CERT_TEMPLATE", "AuthentikSmartcardLogon")

class CertRequest(BaseModel):
    username: str
    upn: str
    domain: str

class CertResponse(BaseModel):
    certificate: str
    private_key: str
    valid_minutes: int
    username: str
    domain: str
    upn: str

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials.credentials != API_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")
    return credentials.credentials

@app.post("/api/issue-certificate", response_model=CertResponse)
async def issue_certificate(req: CertRequest, token: str = Depends(verify_token)):
    """Issue a short-lived certificate for Windows PKINIT authentication"""
    
    try:
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Create CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, req.username),
        ])).add_extension(
            x509.SubjectAlternativeName([
                x509.OtherName(
                    x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),  # UPN OID
                    req.upn.encode()
                ),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Write CSR to temp file
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.req', delete=False) as f:
            csr_path = f.name
            f.write(csr.public_bytes(serialization.Encoding.PEM))
        
        cert_path = csr_path.replace('.req', '.cer')
        
        # Submit to AD CS using certreq
        result = subprocess.run([
            "certreq",
            "-submit",
            "-attrib", f"CertificateTemplate:{CERT_TEMPLATE}",
            "-config", CA_CONFIG,
            csr_path,
            cert_path
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            raise HTTPException(
                status_code=500, 
                detail=f"Certificate request failed: {result.stderr}"
            )
        
        # Read issued certificate
        with open(cert_path, 'r') as f:
            cert_pem = f.read()
        
        # Get private key as PEM
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        # Cleanup temp files
        os.unlink(csr_path)
        os.unlink(cert_path)
        
        return CertResponse(
            certificate=cert_pem,
            private_key=private_key_pem,
            valid_minutes=15,
            username=req.username,
            domain=req.domain,
            upn=req.upn
        )
        
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Certificate request timed out")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health():
    return {"status": "healthy"}
```

**Run the service:**
```powershell
# Install dependencies
pip install fastapi uvicorn cryptography

# Set environment variables
$env:API_TOKEN = "your-secret-token-here"
$env:CA_CONFIG = "CA01.yourdomain.local\YourDomain-CA"
$env:CERT_TEMPLATE = "AuthentikSmartcardLogon"

# Run
uvicorn cert_issuer_service:app --host 0.0.0.0 --port 8443 --ssl-keyfile key.pem --ssl-certfile cert.pem
```

#### 2. Create Authentik Webhook Stage

1. Go to **Flows & Stages** → **Stages** → **Create**
2. Select **Webhook Stage** (or use Expression Stage with HTTP)

**Using Property Mapping + Expression Stage:**

Create a **Property Mapping** for certificate issuance:

```python
# Property Mapping: certificate-request
import requests

response = requests.post(
    "https://cert-issuer.yourdomain.local:8443/api/issue-certificate",
    json={
        "username": request.user.username,
        "upn": request.user.email,  # or custom attribute
        "domain": "YOURDOMAIN"
    },
    headers={
        "Authorization": "Bearer your-secret-token-here"
    },
    verify=False,  # For self-signed certs
    timeout=30
)

if response.status_code == 200:
    return response.json()
else:
    raise Exception(f"Certificate issuance failed: {response.text}")
```

#### 3. Modify Flow Response

The credential provider expects this JSON structure on success:

```json
{
    "type": "redirect",
    "to": "...",
    "certificate": "-----BEGIN CERTIFICATE-----\n...",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...",
    "username": "jsmith",
    "domain": "YOURDOMAIN", 
    "upn": "jsmith@yourdomain.local",
    "valid_minutes": 15
}
```

### Option B: Custom Authentik Stage (Advanced)

For production, consider creating a custom Authentik stage:

1. Fork Authentik repository
2. Create new stage type in `authentik/stages/`
3. Implement certificate issuance logic
4. Build and deploy custom Authentik image

See Authentik documentation: https://goauthentik.io/developer-docs/

---

## AD CS Configuration

### 1. Install AD CS Role

```powershell
# On your CA server
Install-WindowsFeature -Name AD-Certificate -IncludeManagementTools
Install-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools
Install-WindowsFeature -Name ADCS-Web-Enrollment -IncludeManagementTools
```

### 2. Create Certificate Template

1. Open **Certificate Templates Console** (`certtmpl.msc`)
2. Right-click **Smartcard Logon** → **Duplicate Template**
3. Configure the new template:

**General Tab:**
| Setting | Value |
|---------|-------|
| Template display name | Authentik Smartcard Logon |
| Template name | AuthentikSmartcardLogon |
| Validity period | 1 hour |
| Renewal period | 0 |

**Request Handling Tab:**
| Setting | Value |
|---------|-------|
| Purpose | Signature and encryption |
| Allow private key to be exported | Yes |

**Subject Name Tab:**
| Setting | Value |
|---------|-------|
| Supply in the request | Selected |
| Use subject information from existing certificates | Unchecked |

**Extensions Tab:**
- Ensure **Smart Card Logon** (1.3.6.1.4.1.311.20.2.2) is in Application Policies
- Ensure **Client Authentication** (1.3.6.1.5.5.7.3.2) is in Application Policies

**Security Tab:**
| Principal | Permissions |
|-----------|-------------|
| Domain Computers | Read, Enroll |
| svc_authentik_cert | Read, Enroll |

### 3. Publish Template

1. Open **Certification Authority** (`certsrv.msc`)
2. Expand your CA → Right-click **Certificate Templates**
3. Click **New** → **Certificate Template to Issue**
4. Select **Authentik Smartcard Logon**

### 4. Create Service Account

```powershell
# Create service account for certificate requests
New-ADUser -Name "svc_authentik_cert" `
    -SamAccountName "svc_authentik_cert" `
    -UserPrincipalName "svc_authentik_cert@yourdomain.local" `
    -Path "OU=Service Accounts,DC=yourdomain,DC=local" `
    -AccountPassword (ConvertTo-SecureString "SecureP@ssw0rd!" -AsPlainText -Force) `
    -Enabled $true `
    -PasswordNeverExpires $true
```

### 5. Configure Domain Controller for PKINIT

Ensure your DCs have certificates for Kerberos:

```powershell
# Check DC certificates
Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.EnhancedKeyUsageList -match "KDC Authentication"
}
```

If missing, request a **Domain Controller Authentication** certificate.

---

## Troubleshooting

### Common Issues

#### 1. HTTP 405 Error
**Cause:** Flow slug doesn't exist or wrong endpoint

**Fix:**
```powershell
# Verify flow exists in Authentik
# Check registry setting matches exactly
reg query "HKLM\SOFTWARE\AuthentikPasswordlessCP" /v FlowSlug
```

#### 2. HTTP 403 Error
**Cause:** CSRF token missing or invalid

**Fix:** Ensure the credential provider sends cookies from previous requests

#### 3. Certificate Issuance Fails
**Cause:** Template permissions or AD CS configuration

**Fix:**
```powershell
# Test certificate request manually
certreq -submit -attrib "CertificateTemplate:AuthentikSmartcardLogon" request.req
```

#### 4. PKINIT Authentication Fails
**Cause:** Certificate doesn't have correct EKU or UPN

**Fix:**
```powershell
# Verify certificate has Smart Card Logon EKU
certutil -dump certificate.cer | findstr "Smart Card"

# Verify UPN in certificate matches AD user
certutil -dump certificate.cer | findstr "Principal Name"
```

### Debug Logging

**Windows Credential Provider:**
1. Run DebugView as Administrator
2. Enable Capture → Capture Global Win32
3. Filter for `[AuthentikPwdlessCP]`

**Authentik:**
```bash
# View Authentik logs
docker logs authentik-server -f

# Or for Kubernetes
kubectl logs -f deployment/authentik-server
```

**AD CS:**
```powershell
# View certificate request log
Get-EventLog -LogName Application -Source CertificationAuthority -Newest 20
```

### Test Commands

```powershell
# Test Authentik connectivity
Invoke-WebRequest -Uri "https://your-authentik-server/api/v3/flows/instances/" -SkipCertificateCheck

# Test flow endpoint
Invoke-WebRequest -Uri "https://your-authentik-server/api/v3/flows/executor/windows-passwordless/" -SkipCertificateCheck

# Test certificate issuance service
Invoke-WebRequest -Uri "https://cert-issuer:8443/health" -SkipCertificateCheck
```

---

## Security Considerations

### Production Checklist

- [ ] Use valid SSL certificates (not self-signed)
- [ ] Set `IgnoreCertErrors` to `0` in registry
- [ ] Use strong API tokens for certificate service
- [ ] Limit certificate validity to 15 minutes or less
- [ ] Audit certificate issuance logs
- [ ] Restrict network access to certificate service
- [ ] Use service account with minimal permissions
- [ ] Enable logging on all components
- [ ] Implement rate limiting on certificate service
- [ ] Regular security reviews of custom code

### Network Diagram

```
                         ┌─────────────────┐
                         │   Firewall      │
                         └────────┬────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
        ▼                         ▼                         ▼
┌───────────────┐      ┌─────────────────┐      ┌─────────────────┐
│   Windows     │      │    Authentik    │      │   Cert Issuer   │
│  Workstation  │─────▶│    (DMZ)        │─────▶│   (Internal)    │
│  (Internal)   │ 443  │                 │ 8443 │                 │
└───────────────┘      └─────────────────┘      └────────┬────────┘
        │                                                 │
        │                                                 │
        │              ┌─────────────────┐               │
        └─────────────▶│  Domain         │◀──────────────┘
              88/389   │  Controller     │    RPC/DCOM
                       │  + AD CS        │
                       └─────────────────┘
```

---

## Next Steps

1. Start with Phase 1 (OTP only) to verify basic connectivity
2. Set up AD CS with the certificate template
3. Deploy the certificate issuance service
4. Integrate certificate issuance into Authentik flow
5. Test complete passwordless authentication
6. Harden for production use

For questions or issues, see the [GitHub repository](https://github.com/mikemaragos/authentik-credential-provider).
