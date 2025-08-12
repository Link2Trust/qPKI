"""
Certificate Format Converter

This module provides functionality to convert hybrid certificates to various
standard formats where possible, while maintaining the JSON format as the
primary storage for full hybrid information.
"""

import base64
from datetime import datetime, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from typing import Dict, List, Optional, Any
import ipaddress

from ..ca.certificate import HybridCertificate


class CertificateFormatConverter:
    """
    Convert hybrid certificates to standard formats where possible.
    
    Note: Standard X.509 formats cannot contain Dilithium signatures,
    so this creates RSA-only versions for compatibility while preserving
    the full hybrid certificate in JSON format.
    """
    
    def __init__(self):
        pass
    
    def create_x509_certificate(self, hybrid_cert: HybridCertificate, 
                               rsa_private_key, rsa_public_key,
                               issuer_private_key=None) -> x509.Certificate:
        """
        Create a standard X.509 certificate from hybrid certificate (RSA portion only).
        
        Args:
            hybrid_cert: Hybrid certificate to convert
            rsa_private_key: RSA private key for the certificate
            rsa_public_key: RSA public key for the certificate  
            issuer_private_key: RSA private key of the issuer (for signing)
            
        Returns:
            Standard X.509 certificate with RSA signature only
        """
        # Build subject name
        subject_name_components = []
        if hybrid_cert.subject.get('common_name'):
            subject_name_components.append(
                x509.NameAttribute(NameOID.COMMON_NAME, hybrid_cert.subject['common_name'])
            )
        if hybrid_cert.subject.get('organization'):
            subject_name_components.append(
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, hybrid_cert.subject['organization'])
            )
        if hybrid_cert.subject.get('country'):
            subject_name_components.append(
                x509.NameAttribute(NameOID.COUNTRY_NAME, hybrid_cert.subject['country'])
            )
        
        # Build issuer name
        issuer_name_components = []
        if hybrid_cert.issuer.get('common_name'):
            issuer_name_components.append(
                x509.NameAttribute(NameOID.COMMON_NAME, hybrid_cert.issuer['common_name'])
            )
        if hybrid_cert.issuer.get('organization'):
            issuer_name_components.append(
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, hybrid_cert.issuer['organization'])
            )
        if hybrid_cert.issuer.get('country'):
            issuer_name_components.append(
                x509.NameAttribute(NameOID.COUNTRY_NAME, hybrid_cert.issuer['country'])
            )
        
        subject = x509.Name(subject_name_components)
        issuer = x509.Name(issuer_name_components)
        
        # Build certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.public_key(rsa_public_key)
        builder = builder.serial_number(int(hybrid_cert.serial_number))
        builder = builder.not_valid_before(hybrid_cert.not_before)
        builder = builder.not_valid_after(hybrid_cert.not_after)
        
        # Add extensions
        
        # Key Usage
        key_usage_map = {
            'digital_signature': 'digital_signature',
            'key_encipherment': 'key_encipherment',
            'data_encipherment': 'data_encipherment',
            'key_agreement': 'key_agreement',
            'cert_signing': 'key_cert_sign',
            'crl_signing': 'crl_sign'
        }
        
        key_usage_kwargs = {}
        for usage in hybrid_cert.key_usage:
            if usage in key_usage_map:
                x509_usage = key_usage_map[usage]
                key_usage_kwargs[x509_usage] = True
        
        # Set defaults for unused key usages
        all_usages = ['digital_signature', 'content_commitment', 'key_encipherment', 
                     'data_encipherment', 'key_agreement', 'key_cert_sign', 'crl_sign', 'encipher_only', 'decipher_only']
        for usage in all_usages:
            if usage not in key_usage_kwargs:
                key_usage_kwargs[usage] = False
        
        builder = builder.add_extension(
            x509.KeyUsage(**key_usage_kwargs),
            critical=True
        )
        
        # Basic Constraints
        builder = builder.add_extension(
            x509.BasicConstraints(ca=hybrid_cert.is_ca, path_length=None),
            critical=True
        )
        
        # Subject Key Identifier
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(rsa_public_key),
            critical=False
        )
        
        # Extended Key Usage (if applicable)
        extended_key_usage = []
        for usage in hybrid_cert.key_usage:
            if usage == 'server_auth':
                extended_key_usage.append(ExtendedKeyUsageOID.SERVER_AUTH)
            elif usage == 'client_auth':
                extended_key_usage.append(ExtendedKeyUsageOID.CLIENT_AUTH)
        
        if extended_key_usage:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage(extended_key_usage),
                critical=False
            )
        
        # Add custom extension noting this is derived from a hybrid certificate
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                oid=x509.ObjectIdentifier("1.3.6.1.4.1.99999.1"),  # Private OID
                value=f"qPKI Hybrid Certificate {hybrid_cert.cert_id}".encode()
            ),
            critical=False
        )
        
        # Sign the certificate
        signing_key = issuer_private_key if issuer_private_key else rsa_private_key
        certificate = builder.sign(signing_key, hashes.SHA256())
        
        return certificate
    
    def export_certificate_pem(self, cert: x509.Certificate) -> str:
        """
        Export X.509 certificate as PEM format.
        
        Args:
            cert: X.509 certificate
            
        Returns:
            PEM-encoded certificate string
        """
        return cert.public_bytes(Encoding.PEM).decode('utf-8')
    
    def export_certificate_der(self, cert: x509.Certificate) -> bytes:
        """
        Export X.509 certificate as DER format.
        
        Args:
            cert: X.509 certificate
            
        Returns:
            DER-encoded certificate bytes
        """
        return cert.public_bytes(Encoding.DER)
    
    def create_compatibility_note(self, hybrid_cert: HybridCertificate) -> str:
        """
        Create a text note explaining the format conversion.
        
        Args:
            hybrid_cert: Original hybrid certificate
            
        Returns:
            Explanatory text for the conversion
        """
        return f"""
Certificate Format Conversion Notice
====================================

This certificate was derived from a qPKI Hybrid Certificate:
- Original Certificate ID: {hybrid_cert.cert_id}
- Original Format: JSON with hybrid RSA + Dilithium signatures
- Converted Format: Standard X.509 with RSA signature only

IMPORTANT: This standard format certificate contains only the RSA signature
portion of the original hybrid certificate. The post-quantum Dilithium
signature has been omitted due to X.509 format limitations.

For full quantum-resistant verification, use the original JSON format
certificate with the qPKI validation tools.

Conversion Date: {datetime.now(timezone.utc).isoformat()}Z
qPKI Version: 0.1.0
"""
    
    def export_hybrid_certificate_bundle(self, hybrid_cert: HybridCertificate,
                                       rsa_private_key, rsa_public_key,
                                       issuer_private_key=None, 
                                       output_prefix: str = "cert") -> Dict[str, str]:
        """
        Export a complete certificate bundle in multiple formats.
        
        Args:
            hybrid_cert: Hybrid certificate to export
            rsa_private_key: RSA private key
            rsa_public_key: RSA public key
            issuer_private_key: Issuer RSA private key for signing
            output_prefix: Prefix for output filenames
            
        Returns:
            Dictionary with filenames and content for each format
        """
        bundle = {}
        
        # Original hybrid certificate (full security)
        bundle[f"{output_prefix}.json"] = {
            "content": hybrid_cert.to_dict(),
            "description": "Full hybrid certificate with RSA + Dilithium signatures",
            "security": "Quantum-resistant (hybrid)"
        }
        
        # Standard X.509 certificate (compatibility)
        x509_cert = self.create_x509_certificate(
            hybrid_cert, rsa_private_key, rsa_public_key, issuer_private_key
        )
        
        bundle[f"{output_prefix}.pem"] = {
            "content": self.export_certificate_pem(x509_cert),
            "description": "Standard X.509 certificate (RSA signature only)",
            "security": "Classical cryptography only"
        }
        
        bundle[f"{output_prefix}.crt"] = {
            "content": self.export_certificate_der(x509_cert),
            "description": "Standard X.509 certificate in DER format",
            "security": "Classical cryptography only"
        }
        
        # Compatibility note
        bundle[f"{output_prefix}.README.txt"] = {
            "content": self.create_compatibility_note(hybrid_cert),
            "description": "Important information about format conversion",
            "security": "Documentation"
        }
        
        return bundle
