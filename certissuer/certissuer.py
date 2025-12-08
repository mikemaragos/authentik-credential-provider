#!/usr/bin/env python3
"""
CertIssuer Service
Issues certificates via AD CS and updates AD mapping for PKINIT authentication.

Endpoints:
  POST /api/v1/certificate/issue - Issue certificate for user
  GET /api/v1/health - Health check

Requirements:
  pip install flask cryptography pyad ldap3 requests
"""

import os
import sys
import json
import logging
import subprocess
import tempfile
import base64
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from functools import wraps

# Import our modules
from cert_generator import CertificateGenerator
from ad_manager import ADManager

# Configuration
CONFIG = {
    # AD CS Configuration
    'CA_SERVER': os.environ.get('CA_SERVER', 'WIN-6DP39D0OLI8.test.local'),
    'CA_NAME': os.environ.get('CA_NAME', 'test-WIN-6DP39D0OLI8-CA'),
    'CERT_TEMPLATE': os.environ.get('CERT_TEMPLATE', 'AuthentikSmartcard'),
    
    # LDAP Configuration
    'LDAP_SERVER': os.environ.get('LDAP_SERVER', 'ldap://WIN-6DP39D0OLI8.test.local'),
    'LDAP_BASE_DN': os.environ.get('LDAP_BASE_DN', 'DC=test,DC=local'),
    'LDAP_BIND_USER': os.environ.get('LDAP_BIND_USER', 'CN=Administrator,CN=Users,DC=test,DC=local'),
    'LDAP_BIND_PASSWORD': os.environ.get('LDAP_BIND_PASSWORD', ''),
    
    # API Configuration
    'API_TOKEN': os.environ.get('API_TOKEN', 'your-secret-token'),
    'LISTEN_HOST': os.environ.get('LISTEN_HOST', '0.0.0.0'),
    'LISTEN_PORT': int(os.environ.get('LISTEN_PORT', '8443')),
    
    # Certificate Configuration
    'CERT_VALIDITY_HOURS': int(os.environ.get('CERT_VALIDITY_HOURS', '8')),
}

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('CertIssuer')

# Flask app
app = Flask(__name__)

# Initialize managers
cert_generator = None
ad_manager = None


def init_managers():
    """Initialize certificate generator and AD manager."""
    global cert_generator, ad_manager
    
    cert_generator = CertificateGenerator(
        ca_server=CONFIG['CA_SERVER'],
        ca_name=CONFIG['CA_NAME'],
        template=CONFIG['CERT_TEMPLATE']
    )
    
    ad_manager = ADManager(
        server=CONFIG['LDAP_SERVER'],
        base_dn=CONFIG['LDAP_BASE_DN'],
        bind_user=CONFIG['LDAP_BIND_USER'],
        bind_password=CONFIG['LDAP_BIND_PASSWORD']
    )
    
    logger.info("Managers initialized")


def require_api_token(f):
    """Decorator to require API token authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '')
        if token.startswith('Bearer '):
            token = token[7:]
        
        if token != CONFIG['API_TOKEN']:
            logger.warning(f"Invalid API token from {request.remote_addr}")
            return jsonify({'success': False, 'error': 'Invalid API token'}), 401
        
        return f(*args, **kwargs)
    return decorated


@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'ca_server': CONFIG['CA_SERVER'],
        'ldap_server': CONFIG['LDAP_SERVER']
    })


@app.route('/api/v1/certificate/issue', methods=['POST'])
@require_api_token
def issue_certificate():
    """
    Issue a certificate for the specified user.
    
    Request JSON:
    {
        "username": "shop",
        "domain": "test.local",
        "template": "AuthentikSmartcard"  (optional)
    }
    
    Response JSON:
    {
        "success": true,
        "certificate": "<base64 DER>",
        "private_key": "<base64 PKCS8>",
        "ski": "<hex SKI>",
        "thumbprint": "<hex thumbprint>",
        "expires": "2024-12-08T12:00:00Z"
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No JSON data provided'}), 400
        
        username = data.get('username', '').strip()
        domain = data.get('domain', 'test.local').strip()
        template = data.get('template', CONFIG['CERT_TEMPLATE'])
        
        if not username:
            return jsonify({'success': False, 'error': 'Username is required'}), 400
        
        logger.info(f"Certificate request for user: {username}@{domain}")
        
        # Step 1: Generate key pair and CSR
        logger.info("Generating key pair and CSR...")
        upn = f"{username}@{domain}"
        key_pair, csr = cert_generator.generate_csr(
            common_name=username,
            upn=upn
        )
        
        # Step 2: Submit CSR to AD CS and get certificate
        logger.info(f"Submitting CSR to CA: {CONFIG['CA_SERVER']}...")
        certificate = cert_generator.submit_csr_to_ca(csr, template)
        
        if not certificate:
            return jsonify({'success': False, 'error': 'Failed to issue certificate from CA'}), 500
        
        # Step 3: Extract SKI from certificate
        ski = cert_generator.get_subject_key_identifier(certificate)
        thumbprint = cert_generator.get_thumbprint(certificate)
        
        logger.info(f"Certificate issued - SKI: {ski}, Thumbprint: {thumbprint}")
        
        # Step 4: Update AD altSecurityIdentities
        logger.info(f"Updating AD mapping for user: {username}")
        mapping_value = f"X509:<SKI>{ski}"
        
        success = ad_manager.set_alt_security_identity(username, mapping_value)
        if not success:
            logger.warning(f"Failed to update AD mapping for {username}")
            # Continue anyway - cert is still valid, mapping can be done manually
        
        # Step 5: Prepare response
        cert_der = cert_generator.certificate_to_der(certificate)
        key_pkcs8 = cert_generator.private_key_to_pkcs8(key_pair)
        
        expires = datetime.utcnow() + timedelta(hours=CONFIG['CERT_VALIDITY_HOURS'])
        
        response = {
            'success': True,
            'certificate': base64.b64encode(cert_der).decode('ascii'),
            'private_key': base64.b64encode(key_pkcs8).decode('ascii'),
            'ski': ski,
            'thumbprint': thumbprint,
            'expires': expires.isoformat() + 'Z',
            'upn': upn,
            'ad_mapping_updated': success
        }
        
        logger.info(f"Certificate issued successfully for {username}")
        return jsonify(response)
        
    except Exception as e:
        logger.exception(f"Error issuing certificate: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/v1/certificate/revoke', methods=['POST'])
@require_api_token
def revoke_certificate():
    """
    Revoke a certificate by thumbprint or serial number.
    
    Request JSON:
    {
        "thumbprint": "<hex>",  (or)
        "serial": "<hex>"
    }
    """
    try:
        data = request.get_json()
        thumbprint = data.get('thumbprint')
        serial = data.get('serial')
        
        if not thumbprint and not serial:
            return jsonify({'success': False, 'error': 'thumbprint or serial required'}), 400
        
        # TODO: Implement revocation via certutil or AD CS API
        logger.info(f"Revocation requested - thumbprint: {thumbprint}, serial: {serial}")
        
        return jsonify({
            'success': True,
            'message': 'Revocation submitted'
        })
        
    except Exception as e:
        logger.exception(f"Error revoking certificate: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/v1/user/mapping', methods=['GET'])
@require_api_token
def get_user_mapping():
    """Get current altSecurityIdentities for a user."""
    username = request.args.get('username')
    if not username:
        return jsonify({'success': False, 'error': 'username parameter required'}), 400
    
    try:
        mapping = ad_manager.get_alt_security_identities(username)
        return jsonify({
            'success': True,
            'username': username,
            'altSecurityIdentities': mapping
        })
    except Exception as e:
        logger.exception(f"Error getting user mapping: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/v1/user/mapping', methods=['POST'])
@require_api_token  
def set_user_mapping():
    """Manually set altSecurityIdentities for a user."""
    try:
        data = request.get_json()
        username = data.get('username')
        mapping = data.get('mapping')
        
        if not username or not mapping:
            return jsonify({'success': False, 'error': 'username and mapping required'}), 400
        
        success = ad_manager.set_alt_security_identity(username, mapping)
        
        return jsonify({
            'success': success,
            'username': username,
            'mapping': mapping
        })
    except Exception as e:
        logger.exception(f"Error setting user mapping: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


def main():
    """Main entry point."""
    logger.info("=" * 60)
    logger.info("CertIssuer Service Starting")
    logger.info("=" * 60)
    logger.info(f"CA Server: {CONFIG['CA_SERVER']}")
    logger.info(f"CA Name: {CONFIG['CA_NAME']}")
    logger.info(f"LDAP Server: {CONFIG['LDAP_SERVER']}")
    logger.info(f"Listen: {CONFIG['LISTEN_HOST']}:{CONFIG['LISTEN_PORT']}")
    logger.info("=" * 60)
    
    init_managers()
    
    # Run with SSL in production
    # For development, use HTTP or self-signed cert
    app.run(
        host=CONFIG['LISTEN_HOST'],
        port=CONFIG['LISTEN_PORT'],
        debug=False,
        ssl_context='adhoc'  # Use 'adhoc' for self-signed, or provide cert/key paths
    )


if __name__ == '__main__':
    main()
