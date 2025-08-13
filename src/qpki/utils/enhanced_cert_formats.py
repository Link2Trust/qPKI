"""
Enhanced Certificate Format Converter

This module provides enhanced functionality to convert certificates to various
formats including support for PQC certificates and proper classical certificate
downloads in .crt/.cer formats.
"""

import base64
import json
from datetime import datetime, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from typing import Dict, List, Optional, Any, Tuple
import ipaddress

from ..crypto import RSACrypto, ECCCrypto, PQCCrypto


class EnhancedCertificateFormatConverter:
    """
    Enhanced certificate format converter supporting:
    - Hybrid certificates (JSON format)
    - Classical certificates (.crt/.cer formats)
    - PQC certificates (JSON format with PQC notation)
    """
    
    def __init__(self):
        pass
    
    def detect_certificate_type(self, cert_data: Dict[str, Any]) -> str:
        """
        Detect the type of certificate from its data structure.
        
        Args:
            cert_data: Certificate data dictionary
            
        Returns:
            Certificate type: 'hybrid', 'classical', or 'pqc'
        """
        # Handle nested certificate structure
        certificate = cert_data.get('certificate', cert_data)
        
        # Check explicit certificate_type field first
        cert_type = certificate.get('certificate_type')
        if cert_type == 'pqc':
            return 'pqc'
        elif cert_type == 'classic':
            return 'classical'
        elif cert_type == 'hybrid':
            return 'hybrid'
        
        # Check public keys structure
        public_keys = certificate.get('public_keys', {})
        
        # Check for different key combinations
        has_rsa = 'rsa_public_key' in public_keys
        has_ecc = 'ecc_public_key' in public_keys
        has_dilithium = 'dilithium_public_key' in public_keys
        
        # Determine type based on key presence
        if has_dilithium and (has_rsa or has_ecc):
            return 'hybrid'
        elif has_dilithium and not has_rsa and not has_ecc:
            return 'pqc'
        elif (has_rsa or has_ecc) and not has_dilithium:
            return 'classical'
        
        # Fallback: check old public_key structure
        public_key = cert_data.get('public_key', {})
        if ('rsa' in public_key or 'ecc' in public_key) and 'dilithium' in public_key:
            return 'hybrid'
        elif 'dilithium' in public_key and 'rsa' not in public_key and 'ecc' not in public_key:
            return 'pqc'
        elif ('rsa' in public_key or 'ecc' in public_key) and 'dilithium' not in public_key:
            return 'classical'
        
        # Default fallback
        return 'hybrid'
    
    def create_x509_from_classical_cert(self, cert_data: Dict[str, Any], 
                                      private_key_data: Optional[Dict[str, Any]] = None) -> x509.Certificate:
        """
        Create a standard X.509 certificate from classical certificate data.
        
        Args:
            cert_data: Classical certificate data
            private_key_data: Optional private key data for self-signed certificates
            
        Returns:
            Standard X.509 certificate
        """
        # Extract public key information
        public_key_info = cert_data.get('public_key', {})
        
        # Determine if RSA or ECC
        if 'rsa' in public_key_info:
            public_key = self._create_rsa_public_key(public_key_info['rsa'])
            algorithm = 'RSA'
        elif 'ecc' in public_key_info:
            public_key = self._create_ecc_public_key(public_key_info['ecc'])
            algorithm = 'ECC'
        else:
            raise ValueError("No supported classical public key found in certificate")
        
        # Build subject name
        subject = self._build_x509_name(cert_data.get('subject', {}))
        
        # Build issuer name  
        issuer = self._build_x509_name(cert_data.get('issuer', {}))
        
        # Parse validity dates
        validity = cert_data.get('validity', {})
        not_before = datetime.fromisoformat(validity.get('not_before').replace('Z', '+00:00'))
        not_after = datetime.fromisoformat(validity.get('not_after').replace('Z', '+00:00'))
        
        # Generate a serial number if not present
        serial_number = cert_data.get('serial_number', 1)
        if isinstance(serial_number, str):
            serial_number = int(serial_number, 16) if serial_number.startswith('0x') else int(serial_number)
        
        # Build certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.public_key(public_key)
        builder = builder.serial_number(serial_number)
        builder = builder.not_valid_before(not_before)
        builder = builder.not_valid_after(not_after)
        
        # Add extensions
        builder = self._add_x509_extensions(builder, cert_data, public_key)
        
        # Sign the certificate
        if private_key_data:
            signing_key = self._get_private_key_for_signing(private_key_data, algorithm)
        else:
            # For certificates without private key access, create a self-signed dummy
            # This is for export purposes only
            if algorithm == 'RSA':
                signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            else:  # ECC
                signing_key = ec.generate_private_key(ec.SECP256R1())
        
        certificate = builder.sign(signing_key, hashes.SHA256())
        return certificate
    
    def _create_rsa_public_key(self, rsa_data: Dict[str, Any]):
        """Create RSA public key from certificate data."""
        # This would need to reconstruct the RSA public key from stored parameters
        # For now, we'll use cryptography's RSA key loading if available
        if 'public_key_pem' in rsa_data:
            return serialization.load_pem_public_key(rsa_data['public_key_pem'].encode())
        elif 'public_key' in rsa_data:
            # Reconstruct from stored public key bytes
            public_key_bytes = base64.b64decode(rsa_data['public_key'])
            return serialization.load_der_public_key(public_key_bytes)
        else:
            # Generate a dummy RSA key for format demonstration
            dummy_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            return dummy_key.public_key()
    
    def _create_ecc_public_key(self, ecc_data: Dict[str, Any]):
        """Create ECC public key from certificate data."""
        if 'public_key_pem' in ecc_data:
            return serialization.load_pem_public_key(ecc_data['public_key_pem'].encode())
        elif 'public_key' in ecc_data:
            public_key_bytes = base64.b64decode(ecc_data['public_key'])
            return serialization.load_der_public_key(public_key_bytes)
        else:
            # Generate a dummy ECC key for format demonstration
            curve_name = ecc_data.get('curve', 'secp256r1')
            curve_map = {
                'secp256r1': ec.SECP256R1(),
                'secp384r1': ec.SECP384R1(),
                'secp521r1': ec.SECP521R1()
            }
            curve = curve_map.get(curve_name, ec.SECP256R1())
            dummy_key = ec.generate_private_key(curve)
            return dummy_key.public_key()
    
    def _build_x509_name(self, name_data: Dict[str, str]) -> x509.Name:
        """Build X.509 Name from name data dictionary."""
        components = []
        
        if name_data.get('common_name'):
            components.append(x509.NameAttribute(NameOID.COMMON_NAME, name_data['common_name']))
        if name_data.get('organization'):
            components.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, name_data['organization']))
        if name_data.get('organizational_unit'):
            components.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, name_data['organizational_unit']))
        if name_data.get('country'):
            components.append(x509.NameAttribute(NameOID.COUNTRY_NAME, name_data['country']))
        if name_data.get('state'):
            components.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, name_data['state']))
        if name_data.get('locality'):
            components.append(x509.NameAttribute(NameOID.LOCALITY_NAME, name_data['locality']))
        if name_data.get('email'):
            components.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, name_data['email']))
        
        return x509.Name(components)
    
    def _add_x509_extensions(self, builder: x509.CertificateBuilder, 
                           cert_data: Dict[str, Any], public_key) -> x509.CertificateBuilder:
        """Add X.509 extensions to certificate builder."""
        
        # Basic Constraints
        extensions = cert_data.get('extensions', {})
        is_ca = extensions.get('basic_constraints', {}).get('ca', False)
        path_length = extensions.get('basic_constraints', {}).get('path_length')
        
        builder = builder.add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=path_length),
            critical=True
        )
        
        # Key Usage
        key_usage_data = extensions.get('key_usage', {})
        key_usage = x509.KeyUsage(
            digital_signature=key_usage_data.get('digital_signature', False),
            content_commitment=key_usage_data.get('content_commitment', False),
            key_encipherment=key_usage_data.get('key_encipherment', False),
            data_encipherment=key_usage_data.get('data_encipherment', False),
            key_agreement=key_usage_data.get('key_agreement', False),
            key_cert_sign=key_usage_data.get('key_cert_sign', False),
            crl_sign=key_usage_data.get('crl_sign', False),
            encipher_only=False,
            decipher_only=False
        )
        
        builder = builder.add_extension(key_usage, critical=True)
        
        # Subject Key Identifier
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False
        )
        
        # Extended Key Usage
        ext_key_usage_data = extensions.get('extended_key_usage', [])
        if ext_key_usage_data:
            eku_oids = []
            for usage in ext_key_usage_data:
                if usage == 'server_auth':
                    eku_oids.append(ExtendedKeyUsageOID.SERVER_AUTH)
                elif usage == 'client_auth':
                    eku_oids.append(ExtendedKeyUsageOID.CLIENT_AUTH)
                elif usage == 'code_signing':
                    eku_oids.append(ExtendedKeyUsageOID.CODE_SIGNING)
                elif usage == 'email_protection':
                    eku_oids.append(ExtendedKeyUsageOID.EMAIL_PROTECTION)
                elif usage == 'time_stamping':
                    eku_oids.append(ExtendedKeyUsageOID.TIME_STAMPING)
            
            if eku_oids:
                builder = builder.add_extension(
                    x509.ExtendedKeyUsage(eku_oids),
                    critical=False
                )
        
        # Subject Alternative Names
        san_data = extensions.get('subject_alternative_names', [])
        if san_data:
            san_list = []
            for san in san_data:
                if san.get('type') == 'dns':
                    san_list.append(x509.DNSName(san['value']))
                elif san.get('type') == 'email':
                    san_list.append(x509.RFC822Name(san['value']))
                elif san.get('type') == 'ip':
                    san_list.append(x509.IPAddress(ipaddress.ip_address(san['value'])))
            
            if san_list:
                builder = builder.add_extension(
                    x509.SubjectAlternativeName(san_list),
                    critical=False
                )
        
        # Add qPKI identifier extension
        qpki_info = f"qPKI Certificate - Type: {cert_data.get('certificate_type', 'Classical')}"
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                oid=x509.ObjectIdentifier("1.3.6.1.4.1.99999.1"),  # Private OID for qPKI
                value=qpki_info.encode()
            ),
            critical=False
        )
        
        return builder
    
    def _get_private_key_for_signing(self, private_key_data: Dict[str, Any], algorithm: str):
        """Get private key for certificate signing."""
        if algorithm == 'RSA' and 'rsa' in private_key_data:
            rsa_data = private_key_data['rsa']
            if 'private_key_pem' in rsa_data:
                return serialization.load_pem_private_key(
                    rsa_data['private_key_pem'].encode(), 
                    password=None
                )
            elif 'private_key' in rsa_data:
                private_key_bytes = base64.b64decode(rsa_data['private_key'])
                return serialization.load_der_private_key(private_key_bytes, password=None)
        elif algorithm == 'ECC' and 'ecc' in private_key_data:
            ecc_data = private_key_data['ecc']
            if 'private_key_pem' in ecc_data:
                return serialization.load_pem_private_key(
                    ecc_data['private_key_pem'].encode(),
                    password=None
                )
            elif 'private_key' in ecc_data:
                private_key_bytes = base64.b64decode(ecc_data['private_key'])
                return serialization.load_der_private_key(private_key_bytes, password=None)
        
        # Generate dummy key as fallback
        if algorithm == 'RSA':
            return rsa.generate_private_key(public_exponent=65537, key_size=2048)
        else:  # ECC
            return ec.generate_private_key(ec.SECP256R1())
    
    def export_certificate_pem(self, cert: x509.Certificate) -> str:
        """Export X.509 certificate as PEM format (.crt)."""
        return cert.public_bytes(Encoding.PEM).decode('utf-8')
    
    def export_certificate_der(self, cert: x509.Certificate) -> bytes:
        """Export X.509 certificate as DER format (.cer)."""
        return cert.public_bytes(Encoding.DER)
    
    def get_download_format_for_cert_type(self, cert_type: str) -> Tuple[str, str]:
        """
        Get the appropriate download format and MIME type for a certificate type.
        
        Args:
            cert_type: Certificate type ('hybrid', 'classical', 'pqc')
            
        Returns:
            Tuple of (file_extension, mime_type)
        """
        if cert_type == 'classical':
            return 'crt', 'application/x-x509-ca-cert'
        else:
            # Hybrid and PQC certificates use JSON format
            return 'json', 'application/json'
    
    def create_x509_from_classical(self, cert_data: Dict[str, Any], format_type: str) -> Optional[str]:
        """
        Create X.509 certificate from classical certificate data and return in specified format.
        
        Args:
            cert_data: Classical certificate data
            format_type: Output format ('PEM' or 'DER')
            
        Returns:
            Certificate data as string (PEM) or bytes (DER), or None if conversion fails
        """
        try:
            # Handle nested certificate structure
            certificate = cert_data.get('certificate', cert_data)
            
            # Extract public key from the certificate structure
            public_keys = certificate.get('public_keys', {})
            
            # Determine algorithm and create public key
            if 'rsa_public_key' in public_keys:
                # Load RSA public key from PEM
                public_key_pem = public_keys['rsa_public_key']
                public_key = serialization.load_pem_public_key(public_key_pem.encode())
                algorithm = 'RSA'
            elif 'ecc_public_key' in public_keys:
                # Load ECC public key from PEM
                public_key_pem = public_keys['ecc_public_key']
                public_key = serialization.load_pem_public_key(public_key_pem.encode())
                algorithm = 'ECC'
            else:
                return None
            
            # Build subject and issuer names
            subject = self._build_x509_name(certificate.get('subject', {}))
            issuer = self._build_x509_name(certificate.get('issuer', {}))
            
            # Parse validity dates
            validity = certificate.get('validity', {})
            not_before_str = validity.get('not_before', '')
            not_after_str = validity.get('not_after', '')
            
            # Handle different date formats
            def parse_certificate_date(date_str):
                if not date_str:
                    return datetime.now()
                
                # If already has timezone info, just remove trailing Z if present
                if '+' in date_str or '-' in date_str[-6:]:
                    if date_str.endswith('Z'):
                        date_str = date_str[:-1]
                elif date_str.endswith('Z'):
                    # Only Z at the end, replace with UTC offset
                    date_str = date_str.replace('Z', '+00:00')
                
                return datetime.fromisoformat(date_str)
                
            not_before = parse_certificate_date(not_before_str)
            not_after = parse_certificate_date(not_after_str)
            
            # Get serial number
            serial_number = certificate.get('serial_number', 1)
            if isinstance(serial_number, str):
                try:
                    serial_number = int(serial_number)
                except ValueError:
                    serial_number = 1
            
            # Build certificate
            builder = x509.CertificateBuilder()
            builder = builder.subject_name(subject)
            builder = builder.issuer_name(issuer)
            builder = builder.public_key(public_key)
            builder = builder.serial_number(serial_number)
            builder = builder.not_valid_before(not_before)
            builder = builder.not_valid_after(not_after)
            
            # Add basic extensions
            extensions = certificate.get('extensions', {})
            
            # Basic Constraints
            is_ca = extensions.get('basic_constraints', {}).get('ca', False)
            builder = builder.add_extension(
                x509.BasicConstraints(ca=is_ca, path_length=None),
                critical=True
            )
            
            # Key Usage - handle both list and dict formats
            key_usage_data = extensions.get('key_usage', [])
            if isinstance(key_usage_data, list):
                # Convert list format to boolean flags
                digital_signature = 'digital_signature' in key_usage_data
                key_encipherment = 'key_encipherment' in key_usage_data
                key_cert_sign = 'key_cert_sign' in key_usage_data
                crl_sign = 'crl_sign' in key_usage_data
            else:
                # Dict format
                digital_signature = key_usage_data.get('digital_signature', True)
                key_encipherment = key_usage_data.get('key_encipherment', False)
                key_cert_sign = key_usage_data.get('key_cert_sign', False)
                crl_sign = key_usage_data.get('crl_sign', False)
            
            key_usage = x509.KeyUsage(
                digital_signature=digital_signature,
                content_commitment=False,
                key_encipherment=key_encipherment,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=key_cert_sign,
                crl_sign=crl_sign,
                encipher_only=False,
                decipher_only=False
            )
            
            builder = builder.add_extension(key_usage, critical=True)
            
            # Subject Key Identifier
            builder = builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False
            )
            
            # Create a dummy signing key (since we don't have access to CA's private key)
            # This creates a self-signed certificate for format conversion purposes
            if algorithm == 'RSA':
                signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            else:  # ECC
                signing_key = ec.generate_private_key(ec.SECP256R1())
            
            # Sign the certificate
            x509_cert = builder.sign(signing_key, hashes.SHA256())
            
            # Return in requested format
            if format_type.upper() == 'PEM':
                return x509_cert.public_bytes(Encoding.PEM).decode('utf-8')
            else:  # DER
                return x509_cert.public_bytes(Encoding.DER)
                
        except Exception as e:
            print(f"Error creating X.509 certificate: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def create_compatibility_certificate(self, hybrid_cert_data: Dict[str, Any]) -> Optional[x509.Certificate]:
        """
        Create a classical compatibility certificate from hybrid certificate data.
        
        Args:
            hybrid_cert_data: Hybrid certificate data
            
        Returns:
            Classical X.509 certificate using only the classical component, or None if not possible
        """
        cert_type = self.detect_certificate_type(hybrid_cert_data)
        
        if cert_type == 'pqc':
            # Cannot create classical certificate from PQC-only
            return None
        elif cert_type == 'classical':
            # Already classical, convert directly
            return self.create_x509_from_classical_cert(hybrid_cert_data)
        else:  # hybrid
            # Extract classical component for compatibility
            classical_data = self._extract_classical_component(hybrid_cert_data)
            return self.create_x509_from_classical_cert(classical_data)
    
    def _extract_classical_component(self, hybrid_cert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract classical component from hybrid certificate for compatibility."""
        # Create a copy of the certificate data
        classical_data = hybrid_cert_data.copy()
        
        # Modify the public key to contain only classical components
        public_key = classical_data.get('public_key', {}).copy()
        
        # Remove Dilithium component
        if 'dilithium' in public_key:
            del public_key['dilithium']
        
        # Update algorithm description
        if 'rsa' in public_key:
            public_key['algorithm'] = 'RSA'
        elif 'ecc' in public_key:
            public_key['algorithm'] = 'ECC'
        
        classical_data['public_key'] = public_key
        classical_data['certificate_type'] = 'Classical'
        
        # Add note about being derived from hybrid
        if 'extensions' not in classical_data:
            classical_data['extensions'] = {}
        
        classical_data['extensions']['qpki_note'] = {
            'derived_from': 'hybrid',
            'original_type': 'Hybrid Certificate',
            'classical_component_only': True
        }
        
        return classical_data
    
    def get_export_filename(self, cert_data: Dict[str, Any], format_type: str) -> str:
        """
        Generate appropriate filename for certificate export.
        
        Args:
            cert_data: Certificate data
            format_type: Export format ('pem', 'der', 'json')
            
        Returns:
            Suggested filename
        """
        # Get common name or certificate ID for filename
        subject = cert_data.get('subject', {})
        common_name = subject.get('common_name', 'certificate')
        
        # Clean up common name for filename
        safe_name = ''.join(c for c in common_name if c.isalnum() or c in '-_.')
        
        # Add appropriate extension
        extension_map = {
            'pem': 'crt',
            'der': 'cer', 
            'json': 'json'
        }
        
        extension = extension_map.get(format_type, 'txt')
        
        return f"{safe_name}.{extension}"
