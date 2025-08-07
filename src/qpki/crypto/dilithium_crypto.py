"""
ML-DSA (Dilithium) Post-Quantum Cryptographic Operations

This module provides ML-DSA (standardized Dilithium) key generation, signing, 
and verification operations for the post-quantum component of the hybrid PKI system.
"""

import pqcrypto.sign.ml_dsa_44 as ml_dsa_44
import pqcrypto.sign.ml_dsa_65 as ml_dsa_65  
import pqcrypto.sign.ml_dsa_87 as ml_dsa_87
from typing import Tuple, Dict, Any
import base64


class DilithiumCrypto:
    """
    Dilithium cryptographic operations for post-quantum digital signatures.
    
    This class handles:
    - Dilithium key pair generation (levels 2, 3, 5)
    - Dilithium signing
    - Dilithium signature verification
    - Key serialization and deserialization
    """
    
    # ML-DSA variants (standardized Dilithium) with their corresponding modules and security levels
    DILITHIUM_VARIANTS = {
        2: {
            'module': ml_dsa_44,
            'security_level': 'NIST Level 2',
            'public_key_size': ml_dsa_44.PUBLIC_KEY_SIZE,
            'private_key_size': ml_dsa_44.SECRET_KEY_SIZE,
            'signature_size': ml_dsa_44.SIGNATURE_SIZE,
            'name': 'ML-DSA-44'
        },
        3: {
            'module': ml_dsa_65,
            'security_level': 'NIST Level 3', 
            'public_key_size': ml_dsa_65.PUBLIC_KEY_SIZE,
            'private_key_size': ml_dsa_65.SECRET_KEY_SIZE,
            'signature_size': ml_dsa_65.SIGNATURE_SIZE,
            'name': 'ML-DSA-65'
        },
        5: {
            'module': ml_dsa_87,
            'security_level': 'NIST Level 5',
            'public_key_size': ml_dsa_87.PUBLIC_KEY_SIZE,
            'private_key_size': ml_dsa_87.SECRET_KEY_SIZE,
            'signature_size': ml_dsa_87.SIGNATURE_SIZE,
            'name': 'ML-DSA-87'
        }
    }
    
    def __init__(self, variant: int = 2):
        """
        Initialize Dilithium crypto operations.
        
        Args:
            variant: Dilithium variant (2, 3, or 5, default: 2)
        """
        if variant not in self.DILITHIUM_VARIANTS:
            raise ValueError(f"Unsupported Dilithium variant: {variant}. Supported variants: {list(self.DILITHIUM_VARIANTS.keys())}")
        
        self.variant = variant
        self.dilithium_module = self.DILITHIUM_VARIANTS[variant]['module']
        self.variant_info = self.DILITHIUM_VARIANTS[variant]
    
    def generate_key_pair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new Dilithium key pair.
        
        Returns:
            Tuple of (private_key_bytes, public_key_bytes)
        """
        public_key, private_key = self.dilithium_module.generate_keypair()
        return private_key, public_key
    
    def sign_data(self, private_key: bytes, data: bytes) -> bytes:
        """
        Sign data using Dilithium.
        
        Args:
            private_key: Dilithium private key bytes
            data: Data to sign
            
        Returns:
            Dilithium signature bytes
        """
        signature = self.dilithium_module.sign(private_key, data)
        return signature
    
    def verify_signature(self, public_key: bytes, data: bytes, signature: bytes) -> bool:
        """
        Verify Dilithium signature.
        
        Args:
            public_key: Dilithium public key bytes
            data: Original data that was signed
            signature: Dilithium signature to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # ML-DSA verify returns True if valid, raises exception if not
            result = self.dilithium_module.verify(public_key, data, signature)
            return result
        except Exception:
            return False
    
    def serialize_private_key(self, private_key: bytes) -> str:
        """
        Serialize Dilithium private key to Base64 string.
        
        Args:
            private_key: Dilithium private key bytes
            
        Returns:
            Base64-encoded private key string
        """
        return base64.b64encode(private_key).decode('utf-8')
    
    def serialize_public_key(self, public_key: bytes) -> str:
        """
        Serialize Dilithium public key to Base64 string.
        
        Args:
            public_key: Dilithium public key bytes
            
        Returns:
            Base64-encoded public key string
        """
        return base64.b64encode(public_key).decode('utf-8')
    
    def deserialize_private_key(self, key_data: str) -> bytes:
        """
        Deserialize Dilithium private key from Base64 string.
        
        Args:
            key_data: Base64-encoded private key string
            
        Returns:
            Dilithium private key bytes
        """
        return base64.b64decode(key_data.encode('utf-8'))
    
    def deserialize_public_key(self, key_data: str) -> bytes:
        """
        Deserialize Dilithium public key from Base64 string.
        
        Args:
            key_data: Base64-encoded public key string
            
        Returns:
            Dilithium public key bytes
        """
        return base64.b64decode(key_data.encode('utf-8'))
    
    def get_key_info(self, private_key: bytes) -> Dict[str, Any]:
        """
        Get information about a Dilithium key.
        
        Args:
            private_key: Dilithium private key bytes
            
        Returns:
            Dictionary with key information
        """
        return {
            "algorithm": f"Dilithium{self.variant}",
            "variant": self.variant,
            "security_level": self.variant_info['security_level'],
            "public_key_size": self.variant_info['public_key_size'],
            "private_key_size": self.variant_info['private_key_size'],
            "signature_size": self.variant_info['signature_size'],
            "type": "Post-Quantum Digital Signature"
        }
    
    def serialize_signature(self, signature: bytes) -> str:
        """
        Serialize Dilithium signature to Base64 string.
        
        Args:
            signature: Dilithium signature bytes
            
        Returns:
            Base64-encoded signature string
        """
        return base64.b64encode(signature).decode('utf-8')
    
    def deserialize_signature(self, signature_data: str) -> bytes:
        """
        Deserialize Dilithium signature from Base64 string.
        
        Args:
            signature_data: Base64-encoded signature string
            
        Returns:
            Dilithium signature bytes
        """
        return base64.b64decode(signature_data.encode('utf-8'))
    
    @classmethod
    def get_supported_variants(cls) -> Dict[int, Dict[str, Any]]:
        """
        Get information about all supported Dilithium variants.
        
        Returns:
            Dictionary mapping variant numbers to their information
        """
        return cls.DILITHIUM_VARIANTS.copy()
