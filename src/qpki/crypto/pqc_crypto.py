"""
Pure Post-Quantum Certificate (PQC) Cryptographic Operations

This module provides pure post-quantum cryptographic operations using only
Dilithium (ML-DSA) signatures for certificates that are fully quantum-safe.
"""

import json
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Tuple, Optional
from .dilithium_crypto import DilithiumCrypto


class PQCKeyPair:
    """Pure post-quantum key pair containing only Dilithium keys."""
    
    def __init__(self, dilithium_private: bytes, dilithium_public: bytes, variant: int = 2):
        """
        Initialize PQC key pair.
        
        Args:
            dilithium_private: Dilithium private key bytes
            dilithium_public: Dilithium public key bytes  
            variant: Dilithium variant (2, 3, or 5)
        """
        self.dilithium_private = dilithium_private
        self.dilithium_public = dilithium_public
        self.variant = variant
        
        # Initialize Dilithium crypto instance for this variant
        self.dilithium_crypto = DilithiumCrypto(variant)


class PQCSignature:
    """Pure post-quantum signature containing only Dilithium signature."""
    
    def __init__(self, dilithium_sig: bytes, variant: int = 2):
        """
        Initialize PQC signature.
        
        Args:
            dilithium_sig: Dilithium signature bytes
            variant: Dilithium variant used
        """
        self.dilithium_signature = dilithium_sig
        self.variant = variant


class PQCCrypto:
    """
    Pure Post-Quantum Certificate cryptographic operations.
    
    This class handles:
    - Pure Dilithium key pair generation
    - Pure Dilithium signing  
    - Pure Dilithium signature verification
    - PQC certificate creation and management
    """
    
    def __init__(self, dilithium_variant: int = 3):
        """
        Initialize PQC crypto operations.
        
        Args:
            dilithium_variant: Dilithium variant to use (2, 3, or 5, default: 3)
        """
        self.dilithium_variant = dilithium_variant
        self.dilithium_crypto = DilithiumCrypto(dilithium_variant)
    
    def generate_key_pair(self) -> PQCKeyPair:
        """
        Generate a pure post-quantum key pair.
        
        Returns:
            PQCKeyPair with Dilithium keys only
        """
        dilithium_private, dilithium_public = self.dilithium_crypto.generate_key_pair()
        
        return PQCKeyPair(
            dilithium_private=dilithium_private,
            dilithium_public=dilithium_public,
            variant=self.dilithium_variant
        )
    
    def sign_data(self, key_pair: PQCKeyPair, data: bytes) -> PQCSignature:
        """
        Sign data using pure post-quantum cryptography.
        
        Args:
            key_pair: PQC key pair
            data: Data to sign
            
        Returns:
            PQC signature
        """
        # Sign with Dilithium only
        dilithium_signature = self.dilithium_crypto.sign_data(key_pair.dilithium_private, data)
        
        return PQCSignature(
            dilithium_sig=dilithium_signature,
            variant=self.dilithium_variant
        )
    
    def verify_signature(self, public_key_bytes: bytes, data: bytes, signature: PQCSignature) -> bool:
        """
        Verify a pure post-quantum signature.
        
        Args:
            public_key_bytes: Dilithium public key bytes
            data: Original data that was signed
            signature: PQC signature to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Verify using Dilithium only
            return self.dilithium_crypto.verify_signature(
                public_key_bytes, 
                data, 
                signature.dilithium_signature
            )
        except Exception:
            return False
    
    def serialize_key_pair(self, key_pair: PQCKeyPair) -> Dict[str, Any]:
        """
        Serialize PQC key pair to dictionary format.
        
        Args:
            key_pair: PQC key pair to serialize
            
        Returns:
            Dictionary representation of the key pair
        """
        return {
            "type": "PQC",
            "algorithm": "Pure Post-Quantum",
            "variant": key_pair.variant,
            "dilithium": {
                "variant": key_pair.variant,
                "private_key": self.dilithium_crypto.serialize_private_key(key_pair.dilithium_private),
                "public_key": self.dilithium_crypto.serialize_public_key(key_pair.dilithium_public),
                "algorithm": f"ML-DSA-{DilithiumCrypto.DILITHIUM_VARIANTS[key_pair.variant]['name'].split('-')[-1]}"
            },
            "security_info": {
                "post_quantum_safe": True,
                "classical_security": False,
                "quantum_resistant": True,
                "security_level": DilithiumCrypto.DILITHIUM_VARIANTS[key_pair.variant]['security_level']
            }
        }
    
    def deserialize_key_pair(self, key_data: Dict[str, Any]) -> PQCKeyPair:
        """
        Deserialize PQC key pair from dictionary format.
        
        Args:
            key_data: Dictionary representation of key pair
            
        Returns:
            PQCKeyPair object
        """
        if key_data.get("type") != "PQC":
            raise ValueError("Invalid key type for PQC deserialization")
        
        dilithium_data = key_data["dilithium"]
        variant = dilithium_data["variant"]
        
        # Initialize correct Dilithium crypto for this variant
        dilithium_crypto = DilithiumCrypto(variant)
        
        dilithium_private = dilithium_crypto.deserialize_private_key(dilithium_data["private_key"])
        dilithium_public = dilithium_crypto.deserialize_public_key(dilithium_data["public_key"])
        
        return PQCKeyPair(
            dilithium_private=dilithium_private,
            dilithium_public=dilithium_public,
            variant=variant
        )
    
    def serialize_signature(self, signature: PQCSignature) -> Dict[str, Any]:
        """
        Serialize PQC signature to dictionary format.
        
        Args:
            signature: PQC signature to serialize
            
        Returns:
            Dictionary representation of the signature
        """
        return {
            "type": "PQC",
            "algorithm": "Pure Post-Quantum",
            "variant": signature.variant,
            "dilithium_signature": self.dilithium_crypto.serialize_signature(signature.dilithium_signature),
            "signature_info": {
                "post_quantum_safe": True,
                "classical_component": False,
                "quantum_resistant": True
            }
        }
    
    def deserialize_signature(self, signature_data: Dict[str, Any]) -> PQCSignature:
        """
        Deserialize PQC signature from dictionary format.
        
        Args:
            signature_data: Dictionary representation of signature
            
        Returns:
            PQCSignature object
        """
        if signature_data.get("type") != "PQC":
            raise ValueError("Invalid signature type for PQC deserialization")
        
        variant = signature_data["variant"]
        
        # Initialize correct Dilithium crypto for this variant
        dilithium_crypto = DilithiumCrypto(variant)
        
        dilithium_signature = dilithium_crypto.deserialize_signature(
            signature_data["dilithium_signature"]
        )
        
        return PQCSignature(
            dilithium_sig=dilithium_signature,
            variant=variant
        )
    
    def get_public_key_fingerprint(self, key_pair: PQCKeyPair) -> str:
        """
        Generate a fingerprint for the PQC public key.
        
        Args:
            key_pair: PQC key pair
            
        Returns:
            Hex string fingerprint of the public key
        """
        # Create fingerprint from Dilithium public key only
        hash_obj = hashlib.sha256()
        hash_obj.update(key_pair.dilithium_public)
        return hash_obj.hexdigest()
    
    def get_algorithm_info(self) -> Dict[str, Any]:
        """
        Get information about the PQC algorithms used.
        
        Returns:
            Dictionary with algorithm information
        """
        dilithium_info = DilithiumCrypto.DILITHIUM_VARIANTS[self.dilithium_variant]
        
        return {
            "type": "Pure Post-Quantum Certificate (PQC)",
            "post_quantum_algorithm": {
                "name": dilithium_info['name'],
                "variant": self.dilithium_variant,
                "security_level": dilithium_info['security_level'],
                "signature_size": dilithium_info['signature_size'],
                "public_key_size": dilithium_info['public_key_size'],
                "quantum_resistant": True
            },
            "classical_algorithm": None,
            "security_properties": {
                "post_quantum_safe": True,
                "classical_security": False,
                "hybrid": False,
                "quantum_resistant": True
            },
            "use_cases": [
                "Pure post-quantum environments",
                "Maximum quantum security",
                "Future-proof certificates",
                "Research and development"
            ],
            "advantages": [
                "100% quantum-safe",
                "No classical crypto dependencies", 
                "Future-proof against quantum computers",
                "Standardized ML-DSA algorithms"
            ],
            "considerations": [
                "Larger signature sizes than classical",
                "No backward compatibility with classical-only systems",
                "Newer technology with less field deployment"
            ]
        }
    
    @staticmethod
    def get_supported_variants() -> Dict[int, Dict[str, Any]]:
        """
        Get information about supported Dilithium variants.
        
        Returns:
            Dictionary mapping variant numbers to their information
        """
        return DilithiumCrypto.DILITHIUM_VARIANTS.copy()
    
    def create_certificate_data(self, subject: Dict[str, str], issuer: Dict[str, str], 
                              key_pair: PQCKeyPair, validity_days: int = 365,
                              extensions: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Create certificate data structure for a PQC certificate.
        
        Args:
            subject: Certificate subject information
            issuer: Certificate issuer information
            key_pair: PQC key pair for the certificate
            validity_days: Certificate validity period in days
            extensions: Optional certificate extensions
            
        Returns:
            Dictionary containing certificate data
        """
        now = datetime.now(timezone.utc)
        not_after = now.replace(microsecond=0) + timedelta(days=validity_days)
        
        # Create the certificate data structure
        cert_data = {
            "version": 3,
            "subject": subject,
            "issuer": issuer,
            "validity": {
                "not_before": now.replace(microsecond=0).isoformat(),
                "not_after": not_after.isoformat()
            },
            "public_key": {
                "algorithm": "Pure Post-Quantum",
                "dilithium": {
                    "variant": key_pair.variant,
                    "algorithm": f"ML-DSA-{DilithiumCrypto.DILITHIUM_VARIANTS[key_pair.variant]['name'].split('-')[-1]}",
                    "public_key": self.dilithium_crypto.serialize_public_key(key_pair.dilithium_public),
                    "security_level": DilithiumCrypto.DILITHIUM_VARIANTS[key_pair.variant]['security_level']
                }
            },
            "extensions": extensions or {},
            "certificate_type": "PQC",
            "algorithm_info": self.get_algorithm_info(),
            "fingerprint": self.get_public_key_fingerprint(key_pair),
            "created_at": now.isoformat()
        }
        
        return cert_data
