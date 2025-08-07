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
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
import traceback

# Add the source directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

from qpki.crypto import FlexibleHybridCrypto, ECCCrypto, RSACrypto, DilithiumCrypto
from qpki.email_notifier import EmailNotificationService

app = Flask(__name__)
app.secret_key = 'qpki-development-key-change-in-production'

# Global configuration
CERT_STORAGE_DIR = os.path.join(os.path.dirname(__file__), 'certificates')
CA_STORAGE_DIR = os.path.join(os.path.dirname(__file__), 'ca')
CRL_STORAGE_DIR = os.path.join(os.path.dirname(__file__), 'crl')

# Ensure directories exist
os.makedirs(CERT_STORAGE_DIR, exist_ok=True)
os.makedirs(CA_STORAGE_DIR, exist_ok=True)
os.makedirs(CRL_STORAGE_DIR, exist_ok=True)

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
    
    # Load available root CAs for subordinate CA creation
    root_cas = []
    try:
        for filename in os.listdir(CA_STORAGE_DIR):
            if filename.endswith('.json'):
                filepath = os.path.join(CA_STORAGE_DIR, filename)
                with open(filepath, 'r') as f:
                    ca_data = json.load(f)
                    certificate = ca_data.get('certificate', ca_data)
                    
                    # Check if this is a root CA (issuer == subject)
                    issuer = certificate.get('issuer', {})
                    subject = certificate.get('subject', {})
                    is_root = (issuer.get('common_name') == subject.get('common_name') and 
                              issuer.get('organization') == subject.get('organization'))
                    
                    if is_root:
                        root_cas.append({
                            'filename': filename,
                            'common_name': subject.get('common_name', 'Unknown'),
                            'organization': subject.get('organization', 'Unknown')
                        })
    except Exception as e:
        flash(f'Error loading root CAs: {str(e)}', 'error')
    
    return render_template('create_ca.html', 
                         ecc_curves=ecc_curves,
                         rsa_key_sizes=rsa_key_sizes,
                         dilithium_variants=dilithium_variants,
                         root_cas=root_cas)

def _get_ca_crypto_info(ca_data):
    """Extract cryptographic info from CA data to create compatible crypto instance."""
    certificate = ca_data.get('certificate', ca_data)
    crypto_info = certificate.get('cryptographic_info', {})
    hybrid_info = crypto_info.get('hybrid_key_info', {})
    classical_info = hybrid_info.get('classical_algorithm', {})
    pq_info = hybrid_info.get('post_quantum_algorithm', {})
    
    # Determine algorithm type
    if 'RSA' in hybrid_info.get('type', ''):
        return {
            'algorithm': 'RSA',
            'rsa_key_size': classical_info.get('key_size', 2048),
            'dilithium_variant': pq_info.get('variant', 2)
        }
    else:
        return {
            'algorithm': 'ECC',
            'ecc_curve': classical_info.get('curve', 'secp256r1'),
            'dilithium_variant': pq_info.get('variant', 2)
        }

def _create_hybrid_crypto_from_params(algorithm, **params):
    """Create FlexibleHybridCrypto instance from parameters."""
    if algorithm == 'RSA':
        return FlexibleHybridCrypto(
            classical_algorithm='RSA',
            rsa_key_size=params.get('rsa_key_size', 2048),
            dilithium_variant=params.get('dilithium_variant', 2)
        )
    else:  # ECC
        return FlexibleHybridCrypto(
            classical_algorithm='ECC',
            ecc_curve=params.get('ecc_curve', 'secp256r1'),
            dilithium_variant=params.get('dilithium_variant', 2)
        )

def is_certificate_expired(not_after_str):
    """Check if a certificate is expired."""
    try:
        not_after = datetime.fromisoformat(not_after_str.replace('Z', '+00:00'))
        return datetime.now(timezone.utc) > not_after
    except:
        return False

def get_days_until_expiry(not_after_str):
    """Calculate days until certificate expiry. Returns negative for expired certificates."""
    try:
        not_after = datetime.fromisoformat(not_after_str.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        delta = not_after - now
        return delta.days
    except:
        return None

def get_certificate_status(cert_data):
    """Get the status of a certificate (valid, expired, revoked)."""
    certificate = cert_data.get('certificate', cert_data)
    
    # Check if revoked
    if cert_data.get('revoked'):
        return 'revoked'
    
    # Check if expired
    not_after = certificate.get('validity', {}).get('not_after', '')
    if is_certificate_expired(not_after):
        return 'expired'
    
    return 'valid'

def get_certificate_type(cert_data):
    """Determine the type of certificate (Hybrid, RSA, ECC, or ML-DSA)."""
    certificate = cert_data.get('certificate', cert_data)
    
    # Check for explicit certificate_type field (new certificates)
    cert_type = certificate.get('certificate_type')
    if cert_type == 'classic':
        # For classic certificates, determine if RSA or ECC
        crypto_info = certificate.get('cryptographic_info', {})
        classical_info = crypto_info.get('classical_algorithm_info', {})
        
        if 'RSA' in classical_info.get('type', ''):
            return 'RSA'
        elif 'ECC' in classical_info.get('type', ''):
            return 'ECC'
        else:
            # Fallback: check public keys
            public_keys = certificate.get('public_keys', {})
            if 'rsa_public_key' in public_keys:
                return 'RSA'
            elif 'ecc_public_key' in public_keys:
                return 'ECC'
    elif cert_type == 'hybrid':
        return 'Hybrid'
    
    # Legacy certificate detection (older certificates)
    crypto_info = certificate.get('cryptographic_info', {})
    
    # Check for hybrid key info (hybrid certificates)
    if 'hybrid_key_info' in crypto_info:
        hybrid_info = crypto_info['hybrid_key_info']
        if 'classical_algorithm' in hybrid_info and 'post_quantum_algorithm' in hybrid_info:
            return 'Hybrid'
    
    # Check for pure post-quantum (ML-DSA only)
    if 'post_quantum_algorithm' in crypto_info and 'classical_algorithm' not in crypto_info:
        return 'ML-DSA'
    
    # Check algorithm string patterns (fallback)
    algorithm_str = crypto_info.get('hybrid_key_info', {}).get('type', '')
    if 'Hybrid' in algorithm_str:
        return 'Hybrid'
    elif 'RSA' in algorithm_str and 'Dilithium' not in algorithm_str:
        return 'RSA'
    elif 'ECC' in algorithm_str and 'Dilithium' not in algorithm_str:
        return 'ECC'
    elif 'Dilithium' in algorithm_str and 'RSA' not in algorithm_str and 'ECC' not in algorithm_str:
        return 'ML-DSA'
    
    # Final fallback: check public keys
    public_keys = certificate.get('public_keys', {})
    if 'dilithium_public_key' in public_keys:
        if 'rsa_public_key' in public_keys or 'ecc_public_key' in public_keys:
            return 'Hybrid'
        else:
            return 'ML-DSA'
    elif 'rsa_public_key' in public_keys:
        return 'RSA'
    elif 'ecc_public_key' in public_keys:
        return 'ECC'
    
    return 'Unknown'

def load_crl_for_ca(ca_filename):
    """Load CRL for a specific CA."""
    crl_filename = f"crl_{ca_filename.replace('.json', '.json')}"
    crl_filepath = os.path.join(CRL_STORAGE_DIR, crl_filename)
    
    if not os.path.exists(crl_filepath):
        return None
    
    try:
        with open(crl_filepath, 'r') as f:
            return json.load(f)
    except:
        return None

def save_crl_for_ca(ca_filename, crl_data):
    """Save CRL for a specific CA."""
    crl_filename = f"crl_{ca_filename.replace('.json', '.json')}"
    crl_filepath = os.path.join(CRL_STORAGE_DIR, crl_filename)
    
    with open(crl_filepath, 'w') as f:
        json.dump(crl_data, f, indent=2)

def add_certificate_to_crl(ca_filename, cert_serial, revocation_reason='unspecified'):
    """Add a certificate to the CA's CRL."""
    # Load existing CRL or create new one
    crl_data = load_crl_for_ca(ca_filename)
    if not crl_data:
        crl_data = {
            "version": "v2",
            "issuer_ca": ca_filename,
            "this_update": datetime.utcnow().isoformat() + "Z",
            "next_update": (datetime.utcnow() + timedelta(days=7)).isoformat() + "Z",
            "revoked_certificates": []
        }
    
    # Check if certificate is already revoked
    for revoked_cert in crl_data["revoked_certificates"]:
        if revoked_cert["serial_number"] == cert_serial:
            return False  # Already revoked
    
    # Add certificate to CRL
    revoked_entry = {
        "serial_number": cert_serial,
        "revocation_date": datetime.utcnow().isoformat() + "Z",
        "reason": revocation_reason
    }
    
    crl_data["revoked_certificates"].append(revoked_entry)
    crl_data["this_update"] = datetime.utcnow().isoformat() + "Z"
    
    # Save updated CRL
    save_crl_for_ca(ca_filename, crl_data)
    return True

@app.route('/create_ca', methods=['POST'])
def create_ca():
    """Create a new Certificate Authority (root or subordinate)."""
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
        
        # Determine if this is a root or subordinate CA
        ca_type = request.form.get('ca_type', 'root')
        parent_ca_filename = request.form.get('parent_ca_filename')
        
        # Cryptographic parameters
        classical_algorithm = request.form.get('classical_algorithm')
        dilithium_variant = int(request.form.get('dilithium_variant'))
        validity_years = int(request.form.get('validity_years', 10))
        
        # Load parent CA if creating subordinate CA
        parent_ca_data = None
        signing_crypto = None
        signing_keys = None
        issuer_data = ca_data  # Default to self-signed
        
        if ca_type == 'subordinate' and parent_ca_filename:
            parent_ca_path = os.path.join(CA_STORAGE_DIR, parent_ca_filename)
            with open(parent_ca_path, 'r') as f:
                parent_ca_data = json.load(f)
            
            # Get parent CA certificate info
            parent_cert = parent_ca_data.get('certificate', parent_ca_data)
            issuer_data = parent_cert.get('subject', {})
            
            # Create compatible crypto instance for parent CA
            parent_crypto_info = _get_ca_crypto_info(parent_ca_data)
            signing_crypto = _create_hybrid_crypto_from_params(**parent_crypto_info)
            
            # Deserialize parent CA keys for signing
            parent_keys_data = parent_ca_data.get('private_keys', {})
            signing_keys = signing_crypto.deserialize_hybrid_keys(parent_keys_data)
        
        # Algorithm-specific parameters for new CA
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
        
        # Generate new CA key pair
        ca_keys = hybrid_crypto.generate_hybrid_key_pair()
        
        # Create CA certificate data
        not_before = datetime.utcnow()
        not_after = not_before + timedelta(days=validity_years * 365)
        
        # Set path length constraint based on CA type
        path_len_constraint = None if ca_type == 'root' else 0
        
        ca_cert_data = {
            "version": "v3",
            "serial_number": str(uuid.uuid4().int)[:16],
            "signature_algorithm": "hybrid",
            "issuer": issuer_data,
            "subject": ca_data,
            "validity": {
                "not_before": not_before.isoformat() + "Z",
                "not_after": not_after.isoformat() + "Z"
            },
            "extensions": {
                "basic_constraints": {"ca": True, "path_len_constraint": path_len_constraint},
                "key_usage": ["digital_signature", "key_cert_sign", "crl_sign"]
            },
            "ca_type": ca_type
        }
        
        # If subordinate, add parent CA reference
        if ca_type == 'subordinate' and parent_ca_filename:
            ca_cert_data["parent_ca"] = {
                "filename": parent_ca_filename,
                "common_name": issuer_data.get('common_name')
            }
        
        # Get cryptographic info
        key_info = hybrid_crypto.get_hybrid_key_info(ca_keys)
        ca_cert_data["cryptographic_info"] = key_info
        
        # Export public keys
        public_keys = hybrid_crypto.export_public_keys_only(ca_keys)
        ca_cert_data["public_keys"] = public_keys
        
        # Sign the certificate
        signing_data = json.dumps(ca_cert_data, sort_keys=True).encode()
        
        if ca_type == 'subordinate' and signing_crypto and signing_keys:
            # Sign with parent CA keys
            signature = signing_crypto.sign_data_hybrid(signing_keys, signing_data)
        else:
            # Self-sign for root CA
            signature = hybrid_crypto.sign_data_hybrid(ca_keys, signing_data)
        
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
        
        # Generate filename based on CA common name and type
        ca_type_prefix = "root" if ca_type == 'root' else "sub"
        ca_filename = f"{ca_type_prefix}_ca_{ca_data['common_name'].lower().replace(' ', '_').replace('.', '_')}.json"
        ca_filepath = os.path.join(CA_STORAGE_DIR, ca_filename)
        
        # Save CA certificate
        with open(ca_filepath, 'w') as f:
            json.dump(ca_cert, f, indent=2)
        
        ca_type_str = "Root" if ca_type == 'root' else "Subordinate"
        flash(f'{ca_type_str} Certificate Authority "{ca_data["common_name"]}" created successfully!', 'success')
        return redirect(url_for('list_cas'))
        
    except Exception as e:
        flash(f'Error creating CA: {str(e)}', 'error')
        traceback.print_exc()
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
                    
                    # Determine CA type - check if issuer and subject are the same (self-signed = root)
                    issuer = certificate.get('issuer', {})
                    subject = certificate.get('subject', {})
                    ca_type = certificate.get('ca_type')
                    
                    # Fallback logic if ca_type is not explicitly set
                    if not ca_type:
                        is_self_signed = (issuer.get('common_name') == subject.get('common_name') and 
                                        issuer.get('organization') == subject.get('organization'))
                        ca_type = 'root' if is_self_signed else 'subordinate'
                    
                    cas.append({
                        'filename': filename,
                        'common_name': certificate.get('subject', {}).get('common_name', 'Unknown'),
                        'organization': certificate.get('subject', {}).get('organization', 'Unknown'),
                        'ca_type': ca_type,
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
        cert_type = request.form.get('cert_type', 'hybrid')  # Get certificate type
        
        # Extract key usage from form data
        key_usage = request.form.getlist('key_usage')
        if not key_usage:  # Default if none selected
            key_usage = ['digital_signature']
        
        # Load CA
        ca_filepath = os.path.join(CA_STORAGE_DIR, ca_filename)
        with open(ca_filepath, 'r') as f:
            ca_data = json.load(f)
        
        # Create appropriate crypto instance based on certificate type
        if cert_type == 'classic':
            # Classic certificate - use only traditional cryptography
            classic_algorithm = request.form.get('classic_algorithm', 'RSA')
            
            if classic_algorithm == 'RSA':
                rsa_key_size = int(request.form.get('classic_rsa_key_size', 2048))
                crypto_instance = RSACrypto(key_size=rsa_key_size)
                cert_keys = crypto_instance.generate_key_pair()
                algorithm_info = {
                    'type': f'RSA-{rsa_key_size}',
                    'classical_algorithm': {
                        'algorithm': 'RSA',
                        'key_size': rsa_key_size
                    }
                }
            else:  # ECC
                ecc_curve = request.form.get('classic_ecc_curve', 'secp256r1')
                crypto_instance = ECCCrypto(curve=ecc_curve)
                cert_keys = crypto_instance.generate_key_pair()
                algorithm_info = {
                    'type': f'ECC-{ecc_curve}',
                    'classical_algorithm': {
                        'algorithm': 'ECC',
                        'curve': ecc_curve
                    }
                }
            
            # For classic certificates, we need to adapt to CA signing
            ca_algorithm_type = ca_data.get('cryptographic_info', {}).get('hybrid_key_info', {}).get('type', '')
            if 'RSA' in ca_algorithm_type:
                ca_rsa_key_size = ca_data.get('cryptographic_info', {}).get('hybrid_key_info', {}).get('classical_algorithm', {}).get('key_size', 2048)
                ca_crypto = FlexibleHybridCrypto(
                    classical_algorithm='RSA',
                    rsa_key_size=ca_rsa_key_size,
                    dilithium_variant=2
                )
            else:
                ca_ecc_curve = ca_data.get('cryptographic_info', {}).get('hybrid_key_info', {}).get('classical_algorithm', {}).get('curve', 'secp256r1')
                ca_crypto = FlexibleHybridCrypto(
                    classical_algorithm='ECC',
                    ecc_curve=ca_ecc_curve,
                    dilithium_variant=2
                )
        else:
            # Hybrid certificate - use the CA's algorithm settings
            ca_algorithm_type = ca_data.get('cryptographic_info', {}).get('hybrid_key_info', {}).get('type', '')
            
            if 'RSA' in ca_algorithm_type:
                # Extract RSA key size from CA data
                rsa_key_size = ca_data.get('cryptographic_info', {}).get('hybrid_key_info', {}).get('classical_algorithm', {}).get('key_size', 2048)
                crypto_instance = FlexibleHybridCrypto(
                    classical_algorithm='RSA',
                    rsa_key_size=rsa_key_size,
                    dilithium_variant=2  # Default for certificates
                )
            else:  # ECC
                # Extract ECC curve from CA data
                ecc_curve = ca_data.get('cryptographic_info', {}).get('hybrid_key_info', {}).get('classical_algorithm', {}).get('curve', 'secp256r1')
                crypto_instance = FlexibleHybridCrypto(
                    classical_algorithm='ECC',
                    ecc_curve=ecc_curve,
                    dilithium_variant=2  # Default for certificates
                )
            
            ca_crypto = crypto_instance
            cert_keys = crypto_instance.generate_hybrid_key_pair()
            algorithm_info = crypto_instance.get_hybrid_key_info(cert_keys)
        
        # Create certificate data
        not_before = datetime.utcnow()
        not_after = not_before + timedelta(days=validity_days)
        
        cert_data_obj = {
            "version": "v3",
            "serial_number": str(uuid.uuid4().int)[:16],
            "signature_algorithm": "hybrid" if cert_type == 'hybrid' else "classic",
            "issuer": ca_data.get('certificate', ca_data).get('subject', {}),
            "subject": cert_data,
            "validity": {
                "not_before": not_before.isoformat() + "Z",
                "not_after": not_after.isoformat() + "Z"
            },
            "extensions": {
                "basic_constraints": {"ca": False},
                "key_usage": key_usage
            },
            "certificate_type": cert_type
        }
        
        # Handle different certificate types
        if cert_type == 'classic':
            # Classic certificate - store algorithm info and public key
            cert_data_obj["cryptographic_info"] = {"classical_algorithm_info": algorithm_info}
            
            if classic_algorithm == 'RSA':
                public_key_pem = crypto_instance.export_public_key_pem(cert_keys)
                cert_data_obj["public_keys"] = {"rsa_public_key": public_key_pem}
            else:  # ECC
                public_key_pem = crypto_instance.export_public_key_pem(cert_keys)
                cert_data_obj["public_keys"] = {"ecc_public_key": public_key_pem}
            
            # For classic certificates, use a simple hash as fingerprint
            import hashlib
            fingerprint_data = f"{cert_data_obj['subject']['common_name']}{cert_data_obj['serial_number']}"
            cert_data_obj["fingerprint"] = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]
            
            # For signing, we adapt the classic key to work with CA
            cert_private_keys = crypto_instance.serialize_private_key(cert_keys)
        else:
            # Hybrid certificate - use existing hybrid logic
            cert_data_obj["cryptographic_info"] = algorithm_info
            public_keys = crypto_instance.export_public_keys_only(cert_keys)
            cert_data_obj["public_keys"] = public_keys
            
            # Generate fingerprint
            fingerprint = crypto_instance.create_key_fingerprint(cert_keys)
            cert_data_obj["fingerprint"] = fingerprint
            
            cert_private_keys = crypto_instance.serialize_hybrid_keys(cert_keys)
        
        # Load CA keys for signing
        ca_keys_data = ca_data.get('private_keys', {})
        ca_keys = ca_crypto.deserialize_hybrid_keys(ca_keys_data)
        
        # Sign the certificate with CA keys (always hybrid signature from CA)
        signing_data = json.dumps(cert_data_obj, sort_keys=True).encode()
        signature = ca_crypto.sign_data_hybrid(ca_keys, signing_data)
        cert_data_obj["signature"] = signature.to_dict()
        
        # Store certificate with private keys
        cert_with_keys = {
            "certificate": cert_data_obj,
            "private_keys": cert_private_keys,
            "issuer_ca": {
                "filename": ca_filename,
                "common_name": ca_data.get('certificate', ca_data).get('subject', {}).get('common_name', 'Unknown')
            }
        }
        
        # Generate filename based on certificate common name and timestamp (allows duplicates)
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        safe_common_name = cert_data['common_name'].lower().replace(' ', '_').replace('.', '_')
        cert_filename = f"cert_{safe_common_name}_{timestamp}.json"
        cert_filepath = os.path.join(CERT_STORAGE_DIR, cert_filename)
        
        # Save certificate
        with open(cert_filepath, 'w') as f:
            json.dump(cert_with_keys, f, indent=2)
        
        flash(f'Certificate for "{cert_data["common_name"]}" created successfully!', 'success')
        return redirect(url_for('list_certs'))
        
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
                    certificate = cert_data.get('certificate', cert_data)  # Handle nested structure
                    
                    # Get certificate status, type, and days until expiry
                    status = get_certificate_status(cert_data)
                    cert_type = get_certificate_type(cert_data)
                    not_after = certificate.get('validity', {}).get('not_after', 'Unknown')
                    days_until_expiry = get_days_until_expiry(not_after) if not_after != 'Unknown' else None
                    
                    certs.append({
                        'filename': filename,
                        'common_name': certificate.get('subject', {}).get('common_name', 'Unknown'),
                        'organization': certificate.get('subject', {}).get('organization', 'Unknown'),
                        'issuer': certificate.get('issuer', {}).get('common_name', 'Unknown'),
                        'algorithm': certificate.get('cryptographic_info', {}).get('hybrid_key_info', {}).get('type', 'Unknown'),
                        'cert_type': cert_type,
                        'created': certificate.get('validity', {}).get('not_before', 'Unknown'),
                        'expires': not_after,
                        'days_until_expiry': days_until_expiry,
                        'status': status
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
        
        # Get certificate status
        status = get_certificate_status(cert_data)
        
        return render_template('view_cert.html', 
                             cert_data=cert_data, 
                             filename=filename, 
                             status=status)
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

@app.route('/revoke_certificate/<filename>', methods=['POST'])
def revoke_certificate(filename):
    """Revoke a certificate and add it to the CA's CRL."""
    try:
        # Load certificate
        cert_filepath = os.path.join(CERT_STORAGE_DIR, filename)
        with open(cert_filepath, 'r') as f:
            cert_data = json.load(f)
        
        certificate = cert_data.get('certificate', cert_data)
        issuer_ca_filename = cert_data.get('issuer_ca', {}).get('filename')
        
        if not issuer_ca_filename:
            flash('Cannot revoke certificate: issuer CA not found', 'error')
            return redirect(url_for('list_certs'))
        
        # Get revocation reason from form
        revocation_reason = request.form.get('reason', 'unspecified')
        
        # Add to CRL
        success = add_certificate_to_crl(
            issuer_ca_filename, 
            certificate.get('serial_number'),
            revocation_reason
        )
        
        if success:
            # Mark certificate as revoked
            cert_data['revoked'] = {
                'date': datetime.utcnow().isoformat() + "Z",
                'reason': revocation_reason
            }
            
            # Save updated certificate
            with open(cert_filepath, 'w') as f:
                json.dump(cert_data, f, indent=2)
            
            flash(f'Certificate "{certificate.get("subject", {}).get("common_name", "Unknown")}" revoked successfully!', 'success')
        else:
            flash('Certificate was already revoked', 'warning')
        
        return redirect(url_for('list_certs'))
        
    except Exception as e:
        flash(f'Error revoking certificate: {str(e)}', 'error')
        return redirect(url_for('list_certs'))

@app.route('/crl/<ca_filename>')
def view_crl(ca_filename):
    """View CRL for a specific CA."""
    try:
        crl_data = load_crl_for_ca(ca_filename)
        
        if not crl_data:
            # Create empty CRL
            crl_data = {
                "version": "v2",
                "issuer_ca": ca_filename,
                "this_update": datetime.utcnow().isoformat() + "Z",
                "next_update": (datetime.utcnow() + timedelta(days=7)).isoformat() + "Z",
                "revoked_certificates": []
            }
        
        # Load CA info for display
        ca_filepath = os.path.join(CA_STORAGE_DIR, ca_filename)
        with open(ca_filepath, 'r') as f:
            ca_data = json.load(f)
        
        return render_template('view_crl.html', 
                             crl_data=crl_data, 
                             ca_data=ca_data, 
                             ca_filename=ca_filename)
    except Exception as e:
        flash(f'Error loading CRL: {str(e)}', 'error')
        return redirect(url_for('list_cas'))

@app.route('/generate_crl/<ca_filename>', methods=['POST'])
def generate_crl(ca_filename):
    """Generate/update CRL for a specific CA."""
    try:
        # Load CA
        ca_filepath = os.path.join(CA_STORAGE_DIR, ca_filename)
        with open(ca_filepath, 'r') as f:
            ca_data = json.load(f)
        
        # Create CRL with current timestamp
        crl_data = {
            "version": "v2",
            "issuer_ca": ca_filename,
            "issuer": ca_data.get('certificate', ca_data).get('subject', {}),
            "this_update": datetime.utcnow().isoformat() + "Z",
            "next_update": (datetime.utcnow() + timedelta(days=7)).isoformat() + "Z",
            "crl_number": str(int(datetime.utcnow().timestamp())),
            "revoked_certificates": []
        }
        
        # Find all revoked certificates for this CA
        for filename in os.listdir(CERT_STORAGE_DIR):
            if filename.endswith('.json'):
                cert_filepath = os.path.join(CERT_STORAGE_DIR, filename)
                try:
                    with open(cert_filepath, 'r') as f:
                        cert_data = json.load(f)
                    
                    # Check if certificate is issued by this CA and revoked
                    if (cert_data.get('issuer_ca', {}).get('filename') == ca_filename and 
                        cert_data.get('revoked')):
                        
                        certificate = cert_data.get('certificate', cert_data)
                        revocation_info = cert_data.get('revoked', {})
                        
                        revoked_entry = {
                            "serial_number": certificate.get('serial_number'),
                            "revocation_date": revocation_info.get('date'),
                            "reason": revocation_info.get('reason', 'unspecified')
                        }
                        crl_data["revoked_certificates"].append(revoked_entry)
                except:
                    continue
        
        # Create hybrid crypto for signing CRL
        ca_crypto_info = _get_ca_crypto_info(ca_data)
        hybrid_crypto = _create_hybrid_crypto_from_params(**ca_crypto_info)
        
        # Load CA keys
        ca_keys_data = ca_data.get('private_keys', {})
        ca_keys = hybrid_crypto.deserialize_hybrid_keys(ca_keys_data)
        
        # Sign CRL
        crl_signing_data = json.dumps({
            "issuer": crl_data["issuer"],
            "this_update": crl_data["this_update"],
            "next_update": crl_data["next_update"],
            "revoked_certificates": crl_data["revoked_certificates"]
        }, sort_keys=True).encode()
        
        signature = hybrid_crypto.sign_data_hybrid(ca_keys, crl_signing_data)
        crl_data["signature"] = signature.to_dict()
        
        # Save CRL
        save_crl_for_ca(ca_filename, crl_data)
        
        flash(f'CRL generated successfully for CA "{ca_data.get("certificate", ca_data).get("subject", {}).get("common_name", "Unknown")}"', 'success')
        return redirect(url_for('view_crl', ca_filename=ca_filename))
        
    except Exception as e:
        flash(f'Error generating CRL: {str(e)}', 'error')
        traceback.print_exc()
        return redirect(url_for('list_cas'))

@app.route('/download_crl/<ca_filename>')
def download_crl(ca_filename):
    """Download CRL for a specific CA."""
    try:
        crl_filename = f"crl_{ca_filename.replace('.json', '.json')}"
        crl_filepath = os.path.join(CRL_STORAGE_DIR, crl_filename)
        
        if not os.path.exists(crl_filepath):
            flash('CRL not found. Generate CRL first.', 'warning')
            return redirect(url_for('list_cas'))
        
        return send_file(crl_filepath, as_attachment=True, download_name=crl_filename)
    except Exception as e:
        flash(f'Error downloading CRL: {str(e)}', 'error')
        return redirect(url_for('list_cas'))

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
        
        # Check certificate status
        status = get_certificate_status(cert_data)
        certificate = cert_data.get('certificate', cert_data)
        
        result = {
            'valid': status == 'valid',
            'status': status,
            'algorithm': certificate.get('cryptographic_info', {}).get('hybrid_key_info', {}).get('type', 'Unknown'),
            'fingerprint': certificate.get('fingerprint', 'Unknown'),
            'expires': certificate.get('validity', {}).get('not_after', 'Unknown')
        }
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e), 'valid': False}), 400

# Email Notification Routes

@app.route('/notifications')
def notification_settings():
    """Show email notification configuration page."""
    try:
        email_service = EmailNotificationService(app_dir=os.path.dirname(__file__))
        config = email_service.config
        return render_template('notification_settings.html', config=config)
    except Exception as e:
        flash(f'Error loading notification settings: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/notifications/settings', methods=['POST'])
def update_notification_settings():
    """Update email notification settings."""
    try:
        email_service = EmailNotificationService(app_dir=os.path.dirname(__file__))
        
        # Extract form data
        config = {
            'enabled': 'enabled' in request.form,
            'test_mode': 'test_mode' in request.form,
            'smtp_server': request.form.get('smtp_server', 'localhost'),
            'smtp_port': int(request.form.get('smtp_port', 587)),
            'smtp_security': request.form.get('smtp_security', 'TLS'),
            'smtp_username': request.form.get('smtp_username', ''),
            'smtp_password': request.form.get('smtp_password', ''),
            'from_email': request.form.get('from_email', 'noreply@qpki.local'),
            'from_name': request.form.get('from_name', 'qPKI Notification System'),
            'log_notifications': 'log_notifications' in request.form,
            'max_retry_attempts': int(request.form.get('max_retry_attempts', 3)),
            'retry_delay_minutes': int(request.form.get('retry_delay_minutes', 15)),
            'notification_intervals': email_service.config.get('notification_intervals', []),
            'email_templates': email_service.config.get('email_templates', {})
        }
        
        # Update intervals from form
        for interval in config['notification_intervals']:
            interval_name = interval['name']
            interval['enabled'] = f"interval_{interval_name}" in request.form
            interval['subject'] = request.form.get(f"subject_{interval_name}", interval['subject'])
        
        success = email_service.update_config(config)
        
        if success:
            flash('Email notification settings updated successfully!', 'success')
        else:
            flash('Error updating notification settings', 'error')
        
        return redirect(url_for('notification_settings'))
    except Exception as e:
        flash(f'Error updating notification settings: {str(e)}', 'error')
        return redirect(url_for('notification_settings'))

@app.route('/notifications/test', methods=['POST'])
def test_email_notification():
    """Send a test email notification."""
    try:
        email_service = EmailNotificationService(app_dir=os.path.dirname(__file__))
        test_email = request.form.get('test_email')
        
        if not test_email:
            flash('Please provide a test email address', 'error')
            return redirect(url_for('notification_settings'))
        
        success = email_service.test_email_configuration(test_email)
        
        if success:
            flash(f'Test email sent successfully to {test_email}!', 'success')
        else:
            flash('Failed to send test email. Check your configuration.', 'error')
        
        return redirect(url_for('notification_settings'))
    except Exception as e:
        flash(f'Error sending test email: {str(e)}', 'error')
        return redirect(url_for('notification_settings'))

@app.route('/notifications/check', methods=['POST'])
def check_notifications_now():
    """Manually trigger certificate expiration check."""
    try:
        email_service = EmailNotificationService(app_dir=os.path.dirname(__file__))
        results = email_service.check_and_send_notifications(CERT_STORAGE_DIR)
        
        flash(
            f"Notification check complete: {results['checked']} certificates checked, "
            f"{results['notifications_sent']} notifications sent, "
            f"{results['skipped']} skipped, {results['errors']} errors",
            'info'
        )
        
        return redirect(url_for('notification_settings'))
    except Exception as e:
        flash(f'Error checking notifications: {str(e)}', 'error')
        return redirect(url_for('notification_settings'))

@app.route('/notifications/history')
def notification_history():
    """View notification history."""
    try:
        email_service = EmailNotificationService(app_dir=os.path.dirname(__file__))
        history = email_service.get_notification_history(50)
        return render_template('notification_history.html', history=history)
    except Exception as e:
        flash(f'Error loading notification history: {str(e)}', 'error')
        return redirect(url_for('index'))

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
