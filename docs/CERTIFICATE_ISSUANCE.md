# Certificate Issuance Implementation Guide

This guide details how to set up certificate issuance for the Authentik Windows Passwordless Credential Provider.

## Overview

After OTP validation, Authentik needs to:
1. Request a certificate from AD CS
2. Return the certificate + private key to the credential provider
3. The credential provider uses the certificate for PKINIT authentication

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Windows    │     │   Authentik  │     │  Cert Issuer │     │    AD CS     │
│  Workstation │────▶│   Server     │────▶│   Service    │────▶│   (CA)       │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
       │                    │                    │                    │
       │  1. Username       │                    │                    │
       │────────────────────▶                    │                    │
       │                    │                    │                    │
       │  2. OTP Challenge  │                    │                    │
       │◀────────────────────                    │                    │
       │                    │                    │                    │
       │  3. OTP Code       │                    │                    │
       │────────────────────▶                    │                    │
       │                    │  4. Request Cert   │                    │
       │                    │────────────────────▶                    │
       │                    │                    │  5. CSR Submit     │
       │                    │                    │────────────────────▶
       │                    │                    │                    │
       │                    │                    │  6. Certificate    │
       │                    │                    │◀────────────────────
       │                    │  7. Cert + Key     │                    │
       │                    │◀────────────────────                    │
       │  8. Cert + Key     │                    │                    │
       │◀────────────────────                    │                    │
       │                    │                    │                    │
       │  9. PKINIT ────────────────────────────────────────────────▶│
       │                                                    (to DC)   │
```

## Step 1: AD CS Configuration

### 1.1 Create Certificate Template

On your CA server, open **Certificate Templates Console** (`certtmpl.msc`):

1. Right-click **Smartcard Logon** template → **Duplicate Template**
2. Configure the template:

**General Tab:**
```
Template display name: Authentik Smartcard Logon
Template name: AuthentikSmartcardLogon
Validity period: 1 hour
Renewal period: 0 hours
```

**Cryptography Tab:**
```
Provider Category: Key Storage Provider
Algorithm name: RSA
Minimum key size: 2048
```

**Request Handling Tab:**
```
Purpose: Signature and encryption
Allow private key to be exported: Yes (checked)
```

**Subject Name Tab:**
```
Supply in the request: Selected
```

**Extensions Tab:**
Ensure these are present in Application Policies:
- Smart Card Logon (1.3.6.1.4.1.311.20.2.2)
- Client Authentication (1.3.6.1.5.5.7.3.2)

**Security Tab:**
Add permissions:
| Principal | Permissions |
|-----------|-------------|
| Domain Computers | Read |
| svc_authentik_cert | Read, Enroll |

### 1.2 Publish the Template

1. Open **Certification Authority** (`certsrv.msc`)
2. Expand your CA → Right-click **Certificate Templates**
3. Click **New** → **Certificate Template to Issue**
4. Select **Authentik Smartcard Logon**
5. Click **OK**

### 1.3 Create Service Account

```powershell
# Create service account
New-ADUser -Name "svc_authentik_cert" `
    -SamAccountName "svc_authentik_cert" `
    -UserPrincipalName "svc_authentik_cert@yourdomain.local" `
    -Path "OU=Service Accounts,DC=yourdomain,DC=local" `
    -AccountPassword (ConvertTo-SecureString "ComplexP@ssw0rd!" -AsPlainText -Force) `
    -Enabled $true `
    -PasswordNeverExpires $true `
    -CannotChangePassword $true

# Add to appropriate group if needed
Add-ADGroupMember -Identity "Cert Publishers" -Members "svc_authentik_cert"
```

### 1.4 Verify Configuration

```powershell
# Test certificate request
certreq -new -q test.inf test.req

# Submit to CA
certreq -submit -attrib "CertificateTemplate:AuthentikSmartcardLogon" -config "CA01.yourdomain.local\YourDomain-CA" test.req test.cer
```

## Step 2: Certificate Issuer Service

Deploy this service on a Windows server with AD CS tools installed.

### 2.1 Install Prerequisites

```powershell
# Install Python
winget install Python.Python.3.11

# Install dependencies
pip install fastapi uvicorn cryptography pywin32
```

### 2.2 Certificate Issuer Service Code

Create `cert_issuer.py`:

```python
"""
Certificate Issuer Service for Authentik Windows Passwordless Authentication
Runs on a Windows server with AD CS tools (certreq.exe) available
"""

import os
import tempfile
import subprocess
import secrets
import logging
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration from environment
API_TOKEN = os.environ.get("CERT_API_TOKEN", "change-this-secret-token")
CA_CONFIG = os.environ.get("CA_CONFIG", "CA01.yourdomain.local\\YourDomain-CA")
CERT_TEMPLATE = os.environ.get("CERT_TEMPLATE", "AuthentikSmartcardLogon")
CERT_VALIDITY_MINUTES = int(os.environ.get("CERT_VALIDITY_MINUTES", "15"))

app = FastAPI(
    title="Authentik Certificate Issuer",
    description="Issues short-lived certificates for Windows PKINIT authentication",
    version="1.0.0"
)

security = HTTPBearer()


class CertificateRequest(BaseModel):
    """Request for a new certificate"""
    username: str
    upn: str
    domain: str


class CertificateResponse(BaseModel):
    """Response containing certificate and private key"""
    certificate: str
    private_key: str
    valid_minutes: int
    username: str
    domain: str
    upn: str


def verify_token(authorization: str = Header(...)) -> bool:
    """Verify the API token"""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    
    token = authorization[7:]
    if token != API_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid API token")
    
    return True


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "ca_config": CA_CONFIG,
        "template": CERT_TEMPLATE
    }


@app.post("/api/v1/issue-certificate", response_model=CertificateResponse)
async def issue_certificate(
    request: CertificateRequest,
    authorized: bool = Depends(verify_token)
):
    """
    Issue a short-lived certificate for Windows PKINIT authentication.
    
    The certificate will be valid for the configured number of minutes
    and can be used for Smart Card Logon.
    """
    logger.info(f"Certificate request for user: {request.username}@{request.domain}")
    
    try:
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Build the subject name
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, request.username),
        ])
        
        # Create CSR with UPN in SAN
        # The UPN must be in the correct format for PKINIT
        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(subject)
        
        # Add UPN as otherName in SAN (required for Smart Card Logon)
        # OID 1.3.6.1.4.1.311.20.2.3 is the Microsoft UPN OID
        # Note: This is simplified - actual UPN encoding is more complex
        
        csr = csr_builder.sign(private_key, hashes.SHA256())
        
        # Write CSR to temporary file
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.req', delete=False) as f:
            csr_path = f.name
            f.write(csr_pem)
        
        cert_path = csr_path.replace('.req', '.cer')
        
        try:
            # Submit CSR to AD CS using certreq
            cmd = [
                "certreq",
                "-submit",
                "-q",  # Quiet mode
                "-attrib", f"CertificateTemplate:{CERT_TEMPLATE}\\nSAN:upn={request.upn}",
                "-config", CA_CONFIG,
                csr_path,
                cert_path
            ]
            
            logger.info(f"Running certreq: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                logger.error(f"certreq failed: {result.stderr}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Certificate request failed: {result.stderr}"
                )
            
            # Read the issued certificate
            with open(cert_path, 'r') as f:
                cert_pem = f.read()
            
            # Get private key as PEM
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            logger.info(f"Certificate issued successfully for {request.username}")
            
            return CertificateResponse(
                certificate=cert_pem,
                private_key=private_key_pem,
                valid_minutes=CERT_VALIDITY_MINUTES,
                username=request.username,
                domain=request.domain,
                upn=request.upn
            )
            
        finally:
            # Clean up temporary files
            try:
                os.unlink(csr_path)
            except:
                pass
            try:
                os.unlink(cert_path)
            except:
                pass
                
    except subprocess.TimeoutExpired:
        logger.error("Certificate request timed out")
        raise HTTPException(status_code=504, detail="Certificate request timed out")
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error during certificate issuance")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    
    # Run with: python cert_issuer.py
    # Or: uvicorn cert_issuer:app --host 0.0.0.0 --port 8443 --ssl-keyfile key.pem --ssl-certfile cert.pem
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8443,
        ssl_keyfile="server-key.pem",
        ssl_certfile="server-cert.pem"
    )
```

### 2.3 Run the Service

```powershell
# Set environment variables
$env:CERT_API_TOKEN = "your-secure-token-here"
$env:CA_CONFIG = "CA01.yourdomain.local\YourDomain-CA"
$env:CERT_TEMPLATE = "AuthentikSmartcardLogon"
$env:CERT_VALIDITY_MINUTES = "15"

# Generate self-signed cert for HTTPS (or use real certs)
openssl req -x509 -newkey rsa:4096 -keyout server-key.pem -out server-cert.pem -days 365 -nodes -subj "/CN=cert-issuer.yourdomain.local"

# Run the service
python cert_issuer.py
```

### 2.4 Create Windows Service (Optional)

```powershell
# Install as Windows service using NSSM
nssm install AuthentikCertIssuer "C:\Python311\python.exe" "C:\CertIssuer\cert_issuer.py"
nssm set AuthentikCertIssuer AppDirectory "C:\CertIssuer"
nssm set AuthentikCertIssuer AppEnvironmentExtra "CERT_API_TOKEN=your-token" "CA_CONFIG=CA01\YourCA"
nssm start AuthentikCertIssuer
```

## Step 3: Authentik Integration

### 3.1 Create Property Mapping

In Authentik Admin → Customization → Property Mappings → Create:

**Name:** `certificate-request`
**Expression:**
```python
import requests
import json

# Certificate issuer service URL
CERT_ISSUER_URL = "https://cert-issuer.yourdomain.local:8443"
API_TOKEN = "your-secure-token-here"

# Get user info
username = request.user.username
upn = request.user.email  # or use a custom attribute
domain = "YOURDOMAIN"

# Request certificate
try:
    response = requests.post(
        f"{CERT_ISSUER_URL}/api/v1/issue-certificate",
        json={
            "username": username,
            "upn": upn,
            "domain": domain
        },
        headers={
            "Authorization": f"Bearer {API_TOKEN}",
            "Content-Type": "application/json"
        },
        verify=False,  # Set to True in production with valid certs
        timeout=30
    )
    
    if response.status_code == 200:
        return response.json()
    else:
        ak_logger.warning(f"Certificate request failed: {response.text}")
        return None
except Exception as e:
    ak_logger.error(f"Certificate request error: {e}")
    return None
```

### 3.2 Create Custom Stage (Advanced)

For a cleaner integration, create a custom Authentik stage:

1. Fork Authentik repository
2. Create `authentik/stages/certificate_issue/`
3. Implement stage that calls the certificate issuer service
4. Build custom Authentik Docker image

### 3.3 Modify Flow Response

The credential provider expects this JSON structure:

```json
{
    "type": "redirect",
    "to": "/",
    "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
    "username": "jsmith",
    "domain": "YOURDOMAIN",
    "upn": "jsmith@yourdomain.local",
    "valid_minutes": 15
}
```

## Step 4: Testing

### 4.1 Test Certificate Issuer

```powershell
# Test health endpoint
Invoke-RestMethod -Uri "https://cert-issuer.yourdomain.local:8443/health" -SkipCertificateCheck

# Test certificate issuance
$body = @{
    username = "testuser"
    upn = "testuser@yourdomain.local"
    domain = "YOURDOMAIN"
} | ConvertTo-Json

$headers = @{
    "Authorization" = "Bearer your-secure-token-here"
    "Content-Type" = "application/json"
}

$response = Invoke-RestMethod -Uri "https://cert-issuer.yourdomain.local:8443/api/v1/issue-certificate" `
    -Method Post -Body $body -Headers $headers -SkipCertificateCheck

# Check the certificate
$response.certificate | Out-File cert.pem
certutil -dump cert.pem
```

### 4.2 Test Full Flow

1. Lock Windows workstation
2. Select Authentik Login tile
3. Enter username → OTP
4. Check DebugView for certificate handling
5. Verify PKINIT authentication in DC logs

### 4.3 Verify in Event Viewer

On Domain Controller:
```
Event Viewer → Windows Logs → Security
Event ID 4768: Kerberos TGT Request
Look for: Certificate Information
```

## Security Considerations

### Production Checklist

- [ ] Use valid SSL certificates (not self-signed)
- [ ] Secure the API token (use secrets management)
- [ ] Limit network access to certificate issuer
- [ ] Enable TLS 1.2+ only
- [ ] Implement rate limiting
- [ ] Set short certificate validity (15 minutes max)
- [ ] Audit all certificate issuance
- [ ] Use dedicated service account with minimal permissions
- [ ] Regularly rotate API tokens
- [ ] Monitor for unusual certificate requests

### Network Security

```
Firewall Rules:
- Authentik → Cert Issuer: TCP 8443 (HTTPS)
- Cert Issuer → AD CS: RPC/DCOM
- Workstations → Domain Controllers: Kerberos (88/TCP, UDP)
```

## Troubleshooting

### Certificate Issuance Fails

```powershell
# Check AD CS logs
Get-EventLog -LogName Application -Source CertificationAuthority -Newest 20

# Test certreq manually
certreq -submit -attrib "CertificateTemplate:AuthentikSmartcardLogon" -config "CA01\YourCA" test.req
```

### PKINIT Fails

```powershell
# Check DC has KDC certificate
Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.EnhancedKeyUsageList -match "KDC Authentication"
}

# Check smart card logon EKU in issued cert
certutil -dump issued-cert.pem | findstr "Smart Card"
```

### Credential Provider Debug

1. Run DebugView as Administrator
2. Lock/unlock workstation
3. Look for `[AuthentikPwdlessCP]` messages
4. Check for certificate parsing errors

## Next Steps

1. Test certificate issuance manually
2. Integrate with Authentik flow
3. Test end-to-end authentication
4. Harden for production
5. Deploy to pilot users
