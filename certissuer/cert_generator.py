"""
Certificate Generator Module
Handles key pair generation, CSR creation, and AD CS communication.
"""

import os
import subprocess
import tempfile
import logging
from typing import Tuple, Optional
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger('CertIssuer.CertGenerator')


class CertificateGenerator:
    """Handles certificate generation and AD CS communication."""
    
    # Smart Card Logon OID
    OID_SMART_CARD_LOGON = '1.3.6.1.4.1.311.20.2.2'
    
    # UPN OID for SAN
    OID_UPN = '1.3.6.1.4.1.311.20.2.3'
    
    def __init__(self, ca_server: str, ca_name: str, template: str = 'AuthentikSmartcard'):
        self.ca_server = ca_server
        self.ca_name = ca_name
        self.template = template
        logger.info(f"CertificateGenerator initialized: CA={ca_server}\\{ca_name}, Template={template}")
    
    def generate_csr(self, common_name: str, upn: str) -> Tuple[rsa.RSAPrivateKey, x509.CertificateSigningRequest]:
        """
        Generate a key pair and CSR with proper attributes for smart card logon.
        
        Args:
            common_name: CN for the certificate (usually username)
            upn: User Principal Name (user@domain.local)
        
        Returns:
            Tuple of (private_key, csr)
        """
        logger.info(f"Generating CSR for CN={common_name}, UPN={upn}")
        
        # Generate RSA key pair (2048-bit for compatibility)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Build subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        # Build CSR with extensions
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(subject)
        
        # Add Subject Alternative Name with UPN
        # UPN must be encoded as OtherName with specific OID
        san = x509.SubjectAlternativeName([
            x509.OtherName(
                x509.ObjectIdentifier(self.OID_UPN),
                self._encode_upn(upn)
            )
        ])
        builder = builder.add_extension(san, critical=False)
        
        # Add Key Usage
        key_usage = x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )
        builder = builder.add_extension(key_usage, critical=True)
        
        # Add Extended Key Usage (Smart Card Logon + Client Auth)
        eku = x509.ExtendedKeyUsage([
            x509.ObjectIdentifier(self.OID_SMART_CARD_LOGON),
            ExtendedKeyUsageOID.CLIENT_AUTH
        ])
        builder = builder.add_extension(eku, critical=False)
        
        # Sign the CSR
        csr = builder.sign(private_key, hashes.SHA256(), default_backend())
        
        logger.info("CSR generated successfully")
        return private_key, csr
    
    def _encode_upn(self, upn: str) -> bytes:
        """Encode UPN as ASN.1 UTF8String for OtherName."""
        # UPN in SAN OtherName must be UTF8String
        # Format: 0x0C (UTF8String tag) + length + UTF8 bytes
        upn_bytes = upn.encode('utf-8')
        length = len(upn_bytes)
        
        if length < 128:
            return bytes([0x0C, length]) + upn_bytes
        elif length < 256:
            return bytes([0x0C, 0x81, length]) + upn_bytes
        else:
            return bytes([0x0C, 0x82, (length >> 8) & 0xFF, length & 0xFF]) + upn_bytes
    
    def submit_csr_to_ca(self, csr: x509.CertificateSigningRequest, template: str = None) -> Optional[x509.Certificate]:
        """
        Submit CSR to AD CS and retrieve the issued certificate.
        
        Uses certreq.exe on Windows or REST API on Linux.
        
        Args:
            csr: The CSR to submit
            template: Certificate template name (defaults to self.template)
        
        Returns:
            Issued certificate or None on failure
        """
        template = template or self.template
        logger.info(f"Submitting CSR to CA {self.ca_server}\\{self.ca_name} with template {template}")
        
        # Export CSR to PEM
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        
        # Try Windows certreq first
        if os.name == 'nt':
            return self._submit_via_certreq(csr_pem, template)
        else:
            # On Linux, try REST API or remote execution
            return self._submit_via_certsrv(csr_pem, template)
    
    def _submit_via_certreq(self, csr_pem: bytes, template: str) -> Optional[x509.Certificate]:
        """Submit CSR using Windows certreq.exe."""
        try:
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.req', delete=False) as req_file:
                req_file.write(csr_pem)
                req_path = req_file.name
            
            cert_path = req_path.replace('.req', '.cer')
            
            # Build certreq command
            ca_config = f"{self.ca_server}\\{self.ca_name}"
            
            cmd = [
                'certreq',
                '-submit',
                '-config', ca_config,
                '-attrib', f'CertificateTemplate:{template}',
                req_path,
                cert_path
            ]
            
            logger.info(f"Running certreq: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                logger.error(f"certreq failed: {result.stderr}")
                return None
            
            logger.info(f"certreq succeeded: {result.stdout}")
            
            # Read issued certificate
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            
            # Clean up temp files
            os.unlink(req_path)
            os.unlink(cert_path)
            
            # Parse certificate (try DER first, then PEM)
            try:
                return x509.load_der_x509_certificate(cert_data, default_backend())
            except:
                return x509.load_pem_x509_certificate(cert_data, default_backend())
                
        except subprocess.TimeoutExpired:
            logger.error("certreq timed out")
            return None
        except Exception as e:
            logger.exception(f"certreq error: {e}")
            return None
    
    def _submit_via_certsrv(self, csr_pem: bytes, template: str) -> Optional[x509.Certificate]:
        """
        Submit CSR via AD CS Web Enrollment (certsrv).
        This works from Linux hosts.
        """
        try:
            import requests
            from requests_ntlm import HttpNtlmAuth
        except ImportError:
            logger.error("requests and requests_ntlm required for certsrv submission")
            return None
        
        try:
            # Build certsrv URL
            base_url = f"https://{self.ca_server}/certsrv"
            submit_url = f"{base_url}/certfnsh.asp"
            
            # Prepare form data
            # Convert PEM to base64 without headers
            csr_b64 = csr_pem.decode('ascii')
            csr_b64 = csr_b64.replace('-----BEGIN CERTIFICATE REQUEST-----', '')
            csr_b64 = csr_b64.replace('-----END CERTIFICATE REQUEST-----', '')
            csr_b64 = csr_b64.replace('\n', '')
            
            data = {
                'Mode': 'newreq',
                'CertRequest': csr_b64,
                'CertAttrib': f'CertificateTemplate:{template}',
                'TargetStoreFlags': '0',
                'SaveCert': 'yes'
            }
            
            # Get credentials from environment
            username = os.environ.get('CERTSRV_USER', 'Administrator')
            password = os.environ.get('CERTSRV_PASSWORD', '')
            domain = os.environ.get('CERTSRV_DOMAIN', 'TEST')
            
            auth = HttpNtlmAuth(f'{domain}\\{username}', password)
            
            # Submit request
            response = requests.post(
                submit_url,
                data=data,
                auth=auth,
                verify=False,  # Disable cert verification for self-signed
                timeout=60
            )
            
            if response.status_code != 200:
                logger.error(f"certsrv submission failed: {response.status_code}")
                return None
            
            # Parse response for request ID
            # Response HTML contains the request ID or certificate
            # This is simplified - real implementation needs HTML parsing
            
            logger.info("certsrv submission - response received")
            # TODO: Parse certificate from response
            
            return None  # Placeholder
            
        except Exception as e:
            logger.exception(f"certsrv error: {e}")
            return None
    
    def get_subject_key_identifier(self, cert: x509.Certificate) -> str:
        """Extract Subject Key Identifier from certificate as hex string."""
        try:
            ski_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            ski_bytes = ski_ext.value.digest
            return ski_bytes.hex().upper()
        except x509.ExtensionNotFound:
            logger.warning("Certificate has no SKI extension")
            # Generate from public key hash as fallback
            from cryptography.hazmat.primitives.hashes import SHA1
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            pub_key_bytes = cert.public_key().public_bytes(
                Encoding.DER,
                PublicFormat.SubjectPublicKeyInfo
            )
            digest = hashes.Hash(SHA1(), default_backend())
            digest.update(pub_key_bytes)
            return digest.finalize().hex().upper()
    
    def get_thumbprint(self, cert: x509.Certificate) -> str:
        """Get certificate thumbprint (SHA1 hash of DER)."""
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        digest = hashes.Hash(hashes.SHA1(), default_backend())
        digest.update(cert_der)
        return digest.finalize().hex().upper()
    
    def certificate_to_der(self, cert: x509.Certificate) -> bytes:
        """Export certificate to DER format."""
        return cert.public_bytes(serialization.Encoding.DER)
    
    def certificate_to_pem(self, cert: x509.Certificate) -> bytes:
        """Export certificate to PEM format."""
        return cert.public_bytes(serialization.Encoding.PEM)
    
    def private_key_to_pkcs8(self, key: rsa.RSAPrivateKey, password: bytes = None) -> bytes:
        """Export private key to PKCS#8 DER format."""
        if password:
            encryption = serialization.BestAvailableEncryption(password)
        else:
            encryption = serialization.NoEncryption()
        
        return key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
    
    def private_key_to_pem(self, key: rsa.RSAPrivateKey, password: bytes = None) -> bytes:
        """Export private key to PEM format."""
        if password:
            encryption = serialization.BestAvailableEncryption(password)
        else:
            encryption = serialization.NoEncryption()
        
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
