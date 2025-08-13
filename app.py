#!/usr/bin/env python3
"""
qPKI Web Application

Flask-based web interface for managing hybrid post-quantum certificates
with support for both RSA and ECC classical algorithms combined with Dilithium.
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file, g, session
import os
import sys
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
import traceback

# Add the source directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

from qpki.crypto import FlexibleHybridCrypto, ECCCrypto, RSACrypto, DilithiumCrypto, PQCCrypto
from qpki.email_notifier import EmailNotificationService
from qpki.logging_config import setup_logging, get_web_logger, log_activity
from qpki.database import DatabaseManager, DatabaseConfig
from qpki.auth import AuthenticationManager, login_required, admin_required, auth_bp
from qpki.utils.enhanced_cert_formats import EnhancedCertificateFormatConverter

app = Flask(__name__)
app.secret_key = os.environ.get('QPKI_SECRET_KEY', 'qpki-development-key-change-in-production')

# Initialize centralized logging
setup_logging(log_level="INFO", console_output=True)
logger = get_web_logger()

# Initialize database and authentication
try:
    db_config = DatabaseConfig.from_env()
    
    # Try to initialize the database
    db_manager = DatabaseManager(db_config)
    
    # Test connection
    if not db_manager.check_connection():
        raise ConnectionError("Could not connect to configured database")
    
    app.db_manager = db_manager
    
    # Initialize authentication manager
    auth_manager = AuthenticationManager(db_manager)
    app.auth_manager = auth_manager
    
    # Create database tables
    db_manager.migrate_database()
    
    # Create default admin user if no users exist
    success, message = auth_manager.create_default_admin()
    if success:
        logger.info(f"Default admin user created: {message}")
    
except Exception as e:
    logger.warning(f"Database initialization failed, trying SQLite fallback: {e}")
    
    # Try SQLite as fallback
    try:
        # Force SQLite configuration
        import os
        os.environ['QPKI_DB_TYPE'] = 'sqlite'
        db_config = DatabaseConfig.from_env()
        db_manager = DatabaseManager(db_config)
        
        if db_manager.check_connection():
            app.db_manager = db_manager
            auth_manager = AuthenticationManager(db_manager)
            app.auth_manager = auth_manager
            
            # Create database tables
            db_manager.migrate_database()
            
            # Create default admin user if no users exist
            success, message = auth_manager.create_default_admin()
            if success:
                logger.info(f"SQLite fallback successful - {message}")
            else:
                logger.info(f"SQLite fallback successful - {message}")
        else:
            raise ConnectionError("SQLite fallback failed")
            
    except Exception as sqlite_error:
        logger.error(f"SQLite fallback also failed: {sqlite_error}")
        logger.warning("Running in file-based mode without authentication")
        app.db_manager = None
        app.auth_manager = None

# Register authentication blueprint
app.register_blueprint(auth_bp)

# Global configuration
CERT_STORAGE_DIR = os.path.join(os.path.dirname(__file__), 'certificates')
CA_STORAGE_DIR = os.path.join(os.path.dirname(__file__), 'ca')
CRL_STORAGE_DIR = os.path.join(os.path.dirname(__file__), 'crl')

# Ensure directories exist
os.makedirs(CERT_STORAGE_DIR, exist_ok=True)
os.makedirs(CA_STORAGE_DIR, exist_ok=True)
os.makedirs(CRL_STORAGE_DIR, exist_ok=True)

# Log application startup
log_activity(logger, "web_app_startup", {
    'description': 'qPKI Web Application starting',
    'cert_storage': CERT_STORAGE_DIR,
    'ca_storage': CA_STORAGE_DIR,
    'crl_storage': CRL_STORAGE_DIR
})

@app.route('/')
@login_required()
def index():
    """Main dashboard showing system overview."""
    try:
        # Count existing CAs and certificates
        ca_count = len([f for f in os.listdir(CA_STORAGE_DIR) if f.endswith('.json')])
        cert_count = len([f for f in os.listdir(CERT_STORAGE_DIR) if f.endswith('.json')])
        
        # Get user info
        user = g.current_user
        
        return render_template('index.html', 
                             ca_count=ca_count, 
                             cert_count=cert_count,
                             user=user)
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'error')
        return render_template('index.html', ca_count=0, cert_count=0, user=g.current_user)

@app.route('/create_ca')
@login_required('ca.create')
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
    
    # Extract Dilithium variant - check multiple possible locations
    dilithium_variant = pq_info.get('variant')
    if dilithium_variant is None:
        # Try alternative location or parse from algorithm string
        algo_str = pq_info.get('algorithm', '')
        if 'Dilithium3' in algo_str:
            dilithium_variant = 3
        elif 'Dilithium5' in algo_str:
            dilithium_variant = 5
        else:
            dilithium_variant = 2  # Default fallback
    
    # Determine algorithm type
    if 'RSA' in hybrid_info.get('type', ''):
        return {
            'algorithm': 'RSA',
            'rsa_key_size': classical_info.get('key_size', 2048),
            'dilithium_variant': dilithium_variant
        }
    else:
        return {
            'algorithm': 'ECC',
            'ecc_curve': classical_info.get('curve', 'secp256r1'),
            'dilithium_variant': dilithium_variant
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
        # Handle various date formats with timezone info
        if not_after_str.endswith('Z'):
            if '+00:00' in not_after_str:
                # Remove trailing Z if timezone is already present
                not_after_str = not_after_str[:-1]
            else:
                # Replace Z with +00:00
                not_after_str = not_after_str.replace('Z', '+00:00')
        not_after = datetime.fromisoformat(not_after_str)
        return datetime.now(timezone.utc) > not_after
    except Exception as e:
        print(f"Error parsing date {not_after_str}: {e}")
        return False

def get_days_until_expiry(not_after_str):
    """Calculate days until certificate expiry. Returns negative for expired certificates."""
    try:
        # Handle various date formats with timezone info
        if not_after_str.endswith('Z'):
            if '+00:00' in not_after_str:
                # Remove trailing Z if timezone is already present
                not_after_str = not_after_str[:-1]
            else:
                # Replace Z with +00:00
                not_after_str = not_after_str.replace('Z', '+00:00')
        not_after = datetime.fromisoformat(not_after_str)
        now = datetime.now(timezone.utc)
        delta = not_after - now
        return delta.days
    except Exception as e:
        print(f"Error parsing date {not_after_str}: {e}")
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
            "this_update": datetime.now(timezone.utc).isoformat() + "Z",
            "next_update": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat() + "Z",
            "revoked_certificates": []
        }
    
    # Check if certificate is already revoked
    for revoked_cert in crl_data["revoked_certificates"]:
        if revoked_cert["serial_number"] == cert_serial:
            return False  # Already revoked
    
    # Add certificate to CRL
        revoked_entry = {
        "serial_number": cert_serial,
        "revocation_date": datetime.now(timezone.utc).isoformat() + "Z",
        "reason": revocation_reason
    }
    
    crl_data["revoked_certificates"].append(revoked_entry)
    crl_data["this_update"] = datetime.now(timezone.utc).isoformat() + "Z"
    
    # Save updated CRL
    save_crl_for_ca(ca_filename, crl_data)
    return True

@app.route('/create_ca', methods=['POST'])
@login_required('ca.create')
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
            
            # Check if parent CA has private keys (needed for signing subordinate CA)
            parent_keys_data = parent_ca_data.get('private_keys')
            if not parent_keys_data:
                raise ValueError(
                    f"Parent CA '{parent_ca_filename}' does not contain private keys. "
                    "This CA was likely created with an older version that didn't store private keys. "
                    "Please recreate the parent CA with the current version to enable subordinate CA creation."
                )
            
            # Deserialize parent CA keys for signing
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
        not_before = datetime.now(timezone.utc)
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
        
        # Log CA creation activity
        log_activity(logger, "ca_created", {
            'description': f'{ca_type_str} CA created: {ca_data["common_name"]}',
            'ca_type': ca_type,
            'common_name': ca_data['common_name'],
            'organization': ca_data['organization'],
            'algorithm': classical_algorithm,
            'dilithium_variant': dilithium_variant,
            'validity_years': validity_years,
            'ca_filename': ca_filename,
            'serial_number': ca_cert_data["serial_number"],
            'user_ip': request.environ.get('REMOTE_ADDR', 'unknown')
        })
        
        flash(f'{ca_type_str} Certificate Authority "{ca_data["common_name"]}" created successfully!', 'success')
        return redirect(url_for('list_cas'))
        
    except Exception as e:
        flash(f'Error creating CA: {str(e)}', 'error')
        traceback.print_exc()
        return redirect(url_for('create_ca_form'))

@app.route('/cas')
@login_required('ca.view')
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
@login_required('ca.view')
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
@login_required('cert.create')
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
@login_required('cert.create')
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
                crypto_instance = ECCCrypto(curve_name=ecc_curve)
                cert_keys = crypto_instance.generate_key_pair()
                algorithm_info = {
                    'type': f'ECC-{ecc_curve}',
                    'classical_algorithm': {
                        'algorithm': 'ECC',
                        'curve': ecc_curve
                    }
                }
            
            # For classic certificates, we need to adapt to CA signing
            # Use the CA's actual Dilithium variant for proper signing
            ca_crypto_info = _get_ca_crypto_info(ca_data)
            ca_crypto = _create_hybrid_crypto_from_params(**ca_crypto_info)
        elif cert_type == 'pqc':
            # Pure Post-Quantum Certificate - use only Dilithium
            dilithium_variant = int(request.form.get('pqc_dilithium_variant', 3))
            crypto_instance = PQCCrypto(dilithium_variant=dilithium_variant)
            cert_keys = crypto_instance.generate_key_pair()
            algorithm_info = crypto_instance.get_algorithm_info()
            
            # For PQC certificates, still need CA for signing (CA can sign any cert type)
            ca_crypto_info = _get_ca_crypto_info(ca_data)
            ca_crypto = _create_hybrid_crypto_from_params(**ca_crypto_info)
        else:
            # Hybrid certificate - use the CA's algorithm settings with proper Dilithium variant
            ca_crypto_info = _get_ca_crypto_info(ca_data)
            crypto_instance = _create_hybrid_crypto_from_params(**ca_crypto_info)
            
            ca_crypto = crypto_instance
            cert_keys = crypto_instance.generate_hybrid_key_pair()
            algorithm_info = crypto_instance.get_hybrid_key_info(cert_keys)
        
        # Create certificate data
        not_before = datetime.now(timezone.utc)
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
                public_key_pem = crypto_instance.serialize_public_key(cert_keys[1])  # cert_keys is (private, public)
                cert_data_obj["public_keys"] = {"rsa_public_key": public_key_pem.decode('utf-8')}
            else:  # ECC
                public_key_pem = crypto_instance.serialize_public_key(cert_keys[1])  # cert_keys is (private, public)
                cert_data_obj["public_keys"] = {"ecc_public_key": public_key_pem.decode('utf-8')}
            
            # For classic certificates, use a simple hash as fingerprint
            import hashlib
            fingerprint_data = f"{cert_data_obj['subject']['common_name']}{cert_data_obj['serial_number']}"
            cert_data_obj["fingerprint"] = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]
            
            # For signing, we adapt the classic key to work with CA
            if classic_algorithm == 'RSA':
                cert_private_keys = {
                    "rsa_private_key": crypto_instance.serialize_private_key(cert_keys[0]).decode('utf-8')
                }
            else:  # ECC
                cert_private_keys = {
                    "ecc_private_key": crypto_instance.serialize_private_key(cert_keys[0]).decode('utf-8')
                }
        elif cert_type == 'pqc':
            # Pure Post-Quantum certificate - store PQC-specific info
            cert_data_obj["cryptographic_info"] = algorithm_info
            
            # Store Dilithium public key
            dilithium_public_key = crypto_instance.dilithium_crypto.serialize_public_key(cert_keys.dilithium_public)
            cert_data_obj["public_keys"] = {"dilithium_public_key": dilithium_public_key}
            
            # Generate PQC fingerprint
            cert_data_obj["fingerprint"] = crypto_instance.get_public_key_fingerprint(cert_keys)
            
            # Serialize PQC private keys
            cert_private_keys = {
                "dilithium_private_key": crypto_instance.dilithium_crypto.serialize_private_key(cert_keys.dilithium_private),
                "dilithium_variant": cert_keys.variant
            }
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
        ca_keys_data = ca_data.get('private_keys')
        
        if not ca_keys_data:
            raise ValueError(
                f"CA file '{ca_filename}' does not contain private keys. "
                "This CA was likely created with an older version that didn't store private keys. "
                "Please recreate the CA with the current version to enable certificate signing."
            )
        
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
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        safe_common_name = cert_data['common_name'].lower().replace(' ', '_').replace('.', '_')
        cert_filename = f"cert_{safe_common_name}_{timestamp}.json"
        cert_filepath = os.path.join(CERT_STORAGE_DIR, cert_filename)
        
        # Save certificate
        with open(cert_filepath, 'w') as f:
            json.dump(cert_with_keys, f, indent=2)
        
        # Log certificate creation activity
        log_activity(logger, "certificate_created", {
            'description': f'Certificate created for {cert_data["common_name"]}',
            'common_name': cert_data['common_name'],
            'organization': cert_data['organization'],
            'cert_type': cert_type,
            'key_usage': key_usage,
            'validity_days': validity_days,
            'issuer_ca': ca_filename,
            'cert_filename': cert_filename,
            'serial_number': cert_data_obj["serial_number"],
            'user_ip': request.environ.get('REMOTE_ADDR', 'unknown')
        })
        
        flash(f'Certificate for "{cert_data["common_name"]}" created successfully!', 'success')
        return redirect(url_for('list_certs'))
        
    except Exception as e:
        # Log the error with full context
        logger.error(f"Certificate creation failed: {str(e)}", exc_info=True)
        
        log_activity(logger, "certificate_creation_failed", {
            'description': f'Failed to create certificate for {cert_data.get("common_name", "unknown")}',
            'error_message': str(e),
            'error_type': type(e).__name__,
            'cert_type': cert_type if 'cert_type' in locals() else 'unknown',
            'ca_filename': ca_filename if 'ca_filename' in locals() else 'unknown',
            'user_ip': request.environ.get('REMOTE_ADDR', 'unknown')
        }, level="ERROR")
        
        flash(f'Error creating certificate: {str(e)}', 'error')
        traceback.print_exc()
        return redirect(url_for('create_cert_form'))

@app.route('/certificates')
@login_required('cert.view')
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
                    
                    # Get key usage information
                    key_usage = certificate.get('extensions', {}).get('key_usage', [])
                    if not key_usage:
                        key_usage = ['Unknown']
                    
                    certs.append({
                        'filename': filename,
                        'common_name': certificate.get('subject', {}).get('common_name', 'Unknown'),
                        'organization': certificate.get('subject', {}).get('organization', 'Unknown'),
                        'issuer': certificate.get('issuer', {}).get('common_name', 'Unknown'),
                        'key_usage': key_usage,
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
@login_required('cert.view')
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
@app.route('/download/<cert_type>/<filename>/<format_type>')
@login_required('cert.view')
def download_cert(cert_type, filename, format_type='json'):
    """Download certificate or CA in various formats."""
    try:
        # Log download request for debugging
        logger.info(f"Download request: cert_type={cert_type}, filename={filename}, format_type={format_type}")
        
        if cert_type == 'ca':
            filepath = os.path.join(CA_STORAGE_DIR, filename)
        else:  # certificate
            filepath = os.path.join(CERT_STORAGE_DIR, filename)
        
        # Check if file exists
        if not os.path.exists(filepath):
            flash(f'File not found: {filename}', 'error')
            return redirect(url_for('list_certs'))
        
        # For JSON format or CA files, return as-is
        if format_type == 'json' or cert_type == 'ca':
            logger.info(f"Returning file as JSON: {filepath}")
            return send_file(filepath, as_attachment=True, download_name=filename)
        
        # For certificates, check if format conversion is requested
        if format_type in ['pem', 'der', 'crt', 'cer']:
            logger.info(f"Format conversion requested: {format_type}")
            
            # Load certificate data
            with open(filepath, 'r') as f:
                cert_data = json.load(f)
            
            logger.info(f"Certificate data loaded, keys: {list(cert_data.keys())}")
            
            # Initialize format converter
            converter = EnhancedCertificateFormatConverter()
            
            # Detect certificate type
            cert_type_detected = converter.detect_certificate_type(cert_data)
            logger.info(f"Detected certificate type: {cert_type_detected}")
            
            if cert_type_detected == 'classical':
                logger.info(f"Converting classical certificate to {format_type}")
                
                # Convert classical certificate to X.509 format
                cert_format = 'PEM' if format_type in ['pem', 'crt'] else 'DER'
                x509_data = converter.create_x509_from_classical(cert_data, cert_format)
                
                if x509_data:
                    logger.info(f"X.509 conversion successful, data length: {len(x509_data)}")
                    
                    # Determine file extension and content type
                    if format_type in ['pem', 'crt']:
                        file_ext = '.crt' if format_type == 'crt' else '.pem'
                        content_type = 'application/x-pem-file'
                    else:  # der, cer
                        file_ext = '.cer' if format_type == 'cer' else '.der'
                        content_type = 'application/x-x509-ca-cert'
                    
                    # Create download filename
                    base_name = filename.replace('.json', '')
                    download_filename = f"{base_name}{file_ext}"
                    
                    logger.info(f"Sending converted certificate: {download_filename}")
                    
                    # Create temporary file for download
                    import io
                    
                    if cert_format == 'PEM':
                        # Return PEM as text
                        return send_file(
                            io.BytesIO(x509_data.encode('utf-8')),
                            as_attachment=True,
                            download_name=download_filename,
                            mimetype=content_type
                        )
                    else:
                        # Return DER as binary
                        return send_file(
                            io.BytesIO(x509_data),
                            as_attachment=True,
                            download_name=download_filename,
                            mimetype=content_type
                        )
                else:
                    logger.error("X.509 conversion failed")
                    flash('Unable to convert certificate to requested format', 'error')
                    return redirect(url_for('list_certs'))
            else:
                logger.info(f"Non-classical certificate ({cert_type_detected}), returning as JSON")
                # For hybrid and PQC certificates, only JSON format is supported
                flash(f'{cert_type_detected.title()} certificates can only be downloaded in JSON format', 'warning')
                return send_file(filepath, as_attachment=True, download_name=filename)
        
        # Default to JSON format
        logger.info(f"Defaulting to JSON format for: {filepath}")
        return send_file(filepath, as_attachment=True, download_name=filename)
        
    except Exception as e:
        logger.error(f"Error in download_cert: {str(e)}", exc_info=True)
        flash(f'Error downloading file: {str(e)}', 'error')
        traceback.print_exc()
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
@login_required('cert.revoke')
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
                'date': datetime.now(timezone.utc).isoformat() + "Z",
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
@login_required('crl.view')
def view_crl(ca_filename):
    """View CRL for a specific CA."""
    try:
        crl_data = load_crl_for_ca(ca_filename)
        
        if not crl_data:
            # Create empty CRL
            crl_data = {
                "version": "v2",
                "issuer_ca": ca_filename,
                "this_update": datetime.now(timezone.utc).isoformat() + "Z",
                "next_update": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat() + "Z",
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
@login_required('crl.generate')
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
            "this_update": datetime.now(timezone.utc).isoformat() + "Z",
            "next_update": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat() + "Z",
            "crl_number": str(int(datetime.now(timezone.utc).timestamp())),
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
        ca_keys_data = ca_data.get('private_keys')
        
        if not ca_keys_data:
            raise ValueError(
                f"CA file '{ca_filename}' does not contain private keys. "
                "This CA was likely created with an older version that didn't store private keys. "
                "Please recreate the CA with the current version to enable CRL generation."
            )
        
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
@login_required('crl.view')
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
@login_required('cert.view')
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
@login_required('notifications.view')
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
@login_required('notifications.view')
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
@login_required('notifications.view')
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
@login_required('notifications.view')
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
@login_required('notifications.view')
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

# Add context processor for authentication
@app.context_processor
def inject_auth_context():
    """Inject authentication context into all templates."""
    if hasattr(g, 'current_user') and g.current_user:
        return {
            'current_user': g.current_user,
            'is_authenticated': True
        }
    return {
        'current_user': None,
        'is_authenticated': False
    }

# Session cleanup before each request
@app.before_request
def cleanup_sessions():
    """Clean up expired sessions periodically."""
    if app.auth_manager and hasattr(request, 'endpoint'):
        # Only cleanup on main page requests, not for static files or API calls
        if request.endpoint and not request.endpoint.startswith(('static', 'api')):
            try:
                app.auth_manager.cleanup_expired_sessions()
            except Exception as e:
                logger.debug(f"Session cleanup error: {e}")

if __name__ == '__main__':
    print("Starting qPKI Web Application...")
    print(f"Certificate storage: {CERT_STORAGE_DIR}")
    print(f"CA storage: {CA_STORAGE_DIR}")
    
    if app.auth_manager:
        print("✓ Database authentication enabled")
        try:
            # Try to create default admin if needed
            success, message = app.auth_manager.create_default_admin()
            if success:
                print(f"  {message}")
        except:
            pass
    else:
        print("⚠ File-based mode (no authentication)")
    
    print("Access the application at: http://localhost:9090")
    print("Login page: http://localhost:9090/auth/login")
    
    app.run(debug=True, host='0.0.0.0', port=9090)
