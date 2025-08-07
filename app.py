#!/usr/bin/env python3
"""
qPKI Web Application

Flask-based web interface for managing hybrid post-quantum certificates
with support for both RSA and ECC classical algorithms combined with Dilithium.
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file
import os
import sys
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import traceback

# Add the source directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

from qpki.crypto import FlexibleHybridCrypto, ECCCrypto, RSACrypto, DilithiumCrypto

app = Flask(__name__)
app.secret_key = 'qpki-development-key-change-in-production'

# Global configuration
CERT_STORAGE_DIR = os.path.join(os.path.dirname(__file__), 'certificates')
CA_STORAGE_DIR = os.path.join(os.path.dirname(__file__), 'ca')

# Ensure directories exist
os.makedirs(CERT_STORAGE_DIR, exist_ok=True)
os.makedirs(CA_STORAGE_DIR, exist_ok=True)

@app.route('/')
def index():
    """Main dashboard showing system overview."""
    try:
        # Count existing CAs and certificates
        ca_count = len([f for f in os.listdir(CA_STORAGE_DIR) if f.endswith('.json')])
        cert_count = len([f for f in os.listdir(CERT_STORAGE_DIR) if f.endswith('.json')])
        
        return render_template('index.html', ca_count=ca_count, cert_count=cert_count)
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'error')
        return render_template('index.html', ca_count=0, cert_count=0)

@app.route('/create_ca')
def create_ca_form():
    """Show form for creating a new Certificate Authority."""
    # Get available cryptographic options
    ecc_curves = ECCCrypto.get_supported_curves()
    rsa_key_sizes = [2048, 3072, 4096]
    dilithium_variants = [2, 3, 5]
    
    return render_template('create_ca.html', 
                         ecc_curves=ecc_curves,
                         rsa_key_sizes=rsa_key_sizes,
                         dilithium_variants=dilithium_variants)

@app.route('/create_ca', methods=['POST'])
def create_ca():
    """Create a new Certificate Authority."""
    try:
        # Extract form data
        ca_data = {
            'common_name': request.form.get('common_name'),
            'organization': request.form.get('organization'),
            'organizational_unit': request.form.get('organizational_unit'),
            'country': request.form.get('country'),
            'state': request.form.get('state'),
            'locality': request.form.get('locality'),
            'email': request.form.get('email')
        }
        
        # Cryptographic parameters
        classical_algorithm = request.form.get('classical_algorithm')
        dilithium_variant = int(request.form.get('dilithium_variant'))
        validity_years = int(request.form.get('validity_years', 10))
        
        # Algorithm-specific parameters
        if classical_algorithm == 'RSA':
            rsa_key_size = int(request.form.get('rsa_key_size'))
            hybrid_crypto = FlexibleHybridCrypto(
                classical_algorithm='RSA',
                rsa_key_size=rsa_key_size,
                dilithium_variant=dilithium_variant
            )
        else:  # ECC
            ecc_curve = request.form.get('ecc_curve')
            hybrid_crypto = FlexibleHybridCrypto(
                classical_algorithm='ECC',
                ecc_curve=ecc_curve,
                dilithium_variant=dilithium_variant
            )
        
        # Generate CA key pair
        ca_keys = hybrid_crypto.generate_hybrid_key_pair()
        
        # Create self-signed CA certificate data
        not_before = datetime.utcnow()
        not_after = not_before + timedelta(days=validity_years * 365)
        
        ca_cert_data = {
            "version": "v3",
            "serial_number": str(uuid.uuid4().int)[:16],
            "signature_algorithm": "hybrid",
            "issuer": ca_data,
            "subject": ca_data,
            "validity": {
                "not_before": not_before.isoformat() + "Z",
                "not_after": not_after.isoformat() + "Z"
            },
            "extensions": {
                "basic_constraints": {"ca": True, "path_len_constraint": None},
                "key_usage": ["digital_signature", "key_cert_sign", "crl_sign"]
            }
        }
        
        # Get cryptographic info
        key_info = hybrid_crypto.get_hybrid_key_info(ca_keys)
        ca_cert_data["cryptographic_info"] = key_info
        
        # Create signature data and sign
        signing_data = json.dumps(ca_cert_data, sort_keys=True).encode()
        signature = hybrid_crypto.sign_data_hybrid(ca_keys, signing_data)
        
        # Export public keys
        public_keys = hybrid_crypto.export_public_keys_only(ca_keys)
        ca_cert_data["public_keys"] = public_keys
        ca_cert_data["signature"] = signature.to_dict()
        
        # Generate fingerprint
        fingerprint = hybrid_crypto.create_key_fingerprint(ca_keys)
        ca_cert_data["fingerprint"] = fingerprint
        
        # Store private keys separately (in a real implementation, these would be secured)
        ca_private_keys = hybrid_crypto.serialize_hybrid_keys(ca_keys)
        
        ca_cert = {
            "certificate": ca_cert_data,
            "private_keys": ca_private_keys  # WARNING: In production, store securely!
        }
        
        # Generate filename based on CA common name
        ca_filename = f"ca_{ca_data['common_name'].lower().replace(' ', '_').replace('.', '_')}.json"
        ca_filepath = os.path.join(CA_STORAGE_DIR, ca_filename)
        
        # Save CA certificate
        with open(ca_filepath, 'w') as f:
            json.dump(ca_cert, f, indent=2)
        
        flash(f'Certificate Authority "{ca_data["common_name"]}" created successfully!', 'success')
        return redirect(url_for('list_cas'))
        
    except Exception as e:
        flash(f'Error creating CA: {str(e)}', 'error')
        return redirect(url_for('create_ca_form'))

@app.route('/cas')
def list_cas():
    """List all Certificate Authorities."""
    cas = []
    try:
        for filename in os.listdir(CA_STORAGE_DIR):
            if filename.endswith('.json'):
                filepath = os.path.join(CA_STORAGE_DIR, filename)
                with open(filepath, 'r') as f:
                    ca_data = json.load(f)
                    certificate = ca_data.get('certificate', ca_data)  # Handle both old and new format
                    cas.append({
                        'filename': filename,
                        'common_name': certificate.get('subject', {}).get('common_name', 'Unknown'),
                        'organization': certificate.get('subject', {}).get('organization', 'Unknown'),
                        'algorithm': certificate.get('cryptographic_info', {}).get('hybrid_key_info', {}).get('type', 'Unknown'),
                        'created': certificate.get('validity', {}).get('not_before', 'Unknown'),
                        'expires': certificate.get('validity', {}).get('not_after', 'Unknown')
                    })
    except Exception as e:
        flash(f'Error loading CAs: {str(e)}', 'error')
    
    return render_template('list_cas.html', cas=cas)

@app.route('/ca/<filename>')
def view_ca(filename):
    """View detailed information about a specific CA."""
    try:
        filepath = os.path.join(CA_STORAGE_DIR, filename)
        with open(filepath, 'r') as f:
            ca_data = json.load(f)
        return render_template('view_ca.html', ca_data=ca_data, filename=filename)
    except Exception as e:
        flash(f'Error loading CA: {str(e)}', 'error')
        return redirect(url_for('list_cas'))

@app.route('/create_cert')
def create_cert_form():
    """Show form for creating a new certificate."""
    # Load available CAs
    cas = []
    try:
        for filename in os.listdir(CA_STORAGE_DIR):
            if filename.endswith('.json'):
                filepath = os.path.join(CA_STORAGE_DIR, filename)
                with open(filepath, 'r') as f:
                    ca_data = json.load(f)
                    certificate = ca_data.get('certificate', ca_data)  # Handle both old and new format
                    cas.append({
                        'filename': filename,
                        'common_name': certificate.get('subject', {}).get('common_name', 'Unknown')
                    })
    except Exception as e:
        flash(f'Error loading CAs: {str(e)}', 'error')
    
    if not cas:
        flash('No Certificate Authorities found. Please create a CA first.', 'warning')
        return redirect(url_for('create_ca_form'))
    
    return render_template('create_cert.html', cas=cas)

@app.route('/create_cert', methods=['POST'])
def create_cert():
    """Create a new certificate signed by a CA."""
    try:
        # Extract form data
        cert_data = {
            'common_name': request.form.get('common_name'),
            'organization': request.form.get('organization'),
            'organizational_unit': request.form.get('organizational_unit'),
            'country': request.form.get('country'),
            'state': request.form.get('state'),
            'locality': request.form.get('locality'),
            'email': request.form.get('email')
        }
        
        ca_filename = request.form.get('ca_filename')
        validity_days = int(request.form.get('validity_days', 365))
        
        # Load CA
        ca_filepath = os.path.join(CA_STORAGE_DIR, ca_filename)
        with open(ca_filepath, 'r') as f:
            ca_data = json.load(f)
        
        # Determine the CA's cryptographic algorithm
        ca_algorithm_type = ca_data.get('cryptographic_info', {}).get('hybrid_key_info', {}).get('type', '')
        
        # Create appropriate hybrid crypto instance based on CA's algorithm
        if 'RSA' in ca_algorithm_type:
            # Extract RSA key size from CA data
            rsa_key_size = ca_data.get('cryptographic_info', {}).get('hybrid_key_info', {}).get('classical_algorithm', {}).get('key_size', 2048)
            hybrid_crypto = FlexibleHybridCrypto(
                classical_algorithm='RSA',
                rsa_key_size=rsa_key_size,
                dilithium_variant=2  # Default for certificates
            )
        else:  # ECC
            # Extract ECC curve from CA data
            ecc_curve = ca_data.get('cryptographic_info', {}).get('hybrid_key_info', {}).get('classical_algorithm', {}).get('curve', 'secp256r1')
            hybrid_crypto = FlexibleHybridCrypto(
                classical_algorithm='ECC',
                ecc_curve=ecc_curve,
                dilithium_variant=2  # Default for certificates
            )
        
        # Certificate creation is temporarily disabled
        flash('Certificate creation feature is under development. Please use CA management for now.', 'info')
        return redirect(url_for('create_cert_form'))
        
    except Exception as e:
        flash(f'Error creating certificate: {str(e)}', 'error')
        traceback.print_exc()
        return redirect(url_for('create_cert_form'))

@app.route('/certificates')
def list_certs():
    """List all certificates."""
    certs = []
    try:
        for filename in os.listdir(CERT_STORAGE_DIR):
            if filename.endswith('.json'):
                filepath = os.path.join(CERT_STORAGE_DIR, filename)
                with open(filepath, 'r') as f:
                    cert_data = json.load(f)
                    certs.append({
                        'filename': filename,
                        'common_name': cert_data.get('subject', {}).get('common_name', 'Unknown'),
                        'organization': cert_data.get('subject', {}).get('organization', 'Unknown'),
                        'issuer': cert_data.get('issuer', {}).get('common_name', 'Unknown'),
                        'algorithm': cert_data.get('cryptographic_info', {}).get('hybrid_key_info', {}).get('type', 'Unknown'),
                        'created': cert_data.get('validity', {}).get('not_before', 'Unknown'),
                        'expires': cert_data.get('validity', {}).get('not_after', 'Unknown')
                    })
    except Exception as e:
        flash(f'Error loading certificates: {str(e)}', 'error')
    
    return render_template('list_certs.html', certs=certs)

@app.route('/certificate/<filename>')
def view_cert(filename):
    """View detailed information about a specific certificate."""
    try:
        filepath = os.path.join(CERT_STORAGE_DIR, filename)
        with open(filepath, 'r') as f:
            cert_data = json.load(f)
        return render_template('view_cert.html', cert_data=cert_data, filename=filename)
    except Exception as e:
        flash(f'Error loading certificate: {str(e)}', 'error')
        return redirect(url_for('list_certs'))

@app.route('/download/<cert_type>/<filename>')
def download_cert(cert_type, filename):
    """Download certificate or CA in JSON format."""
    try:
        if cert_type == 'ca':
            filepath = os.path.join(CA_STORAGE_DIR, filename)
        else:  # certificate
            filepath = os.path.join(CERT_STORAGE_DIR, filename)
        
        return send_file(filepath, as_attachment=True, download_name=filename)
    except Exception as e:
        flash(f'Error downloading file: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/api/algorithms')
def api_algorithms():
    """API endpoint to get available cryptographic algorithms and parameters."""
    return jsonify({
        'classical_algorithms': ['RSA', 'ECC'],
        'rsa_key_sizes': [2048, 3072, 4096],
        'ecc_curves': ECCCrypto.get_supported_curves(),
        'dilithium_variants': [2, 3, 5]
    })

@app.route('/api/verify/<cert_type>/<filename>')
def api_verify(cert_type, filename):
    """API endpoint to verify a certificate or CA signature."""
    try:
        if cert_type == 'ca':
            filepath = os.path.join(CA_STORAGE_DIR, filename)
        else:
            filepath = os.path.join(CERT_STORAGE_DIR, filename)
        
        with open(filepath, 'r') as f:
            cert_data = json.load(f)
        
        # For now, return basic validation info
        # In a full implementation, this would verify the actual signature
        result = {
            'valid': True,  # Placeholder
            'algorithm': cert_data.get('cryptographic_info', {}).get('hybrid_key_info', {}).get('type', 'Unknown'),
            'fingerprint': cert_data.get('fingerprint', 'Unknown'),
            'expires': cert_data.get('validity', {}).get('not_after', 'Unknown')
        }
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e), 'valid': False}), 400

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return render_template('error.html', 
                         error_code=404, 
                         error_message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    return render_template('error.html', 
                         error_code=500, 
                         error_message="Internal server error"), 500

if __name__ == '__main__':
    print("Starting qPKI Web Application...")
    print(f"Certificate storage: {CERT_STORAGE_DIR}")
    print(f"CA storage: {CA_STORAGE_DIR}")
    print("Access the application at: http://localhost:9090")
    
    app.run(debug=True, host='0.0.0.0', port=9090)
