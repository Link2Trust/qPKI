"""
ECC Cryptographic Operations

This module provides Elliptic Curve Cryptography operations including ECDSA
for the classical component of the hybrid PKI system.
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from typing import Tuple, Optional, Dict, Any
import os


class ECCCrypto:
    """
    ECC cryptographic operations for classical public key cryptography.
    
    This class handles:
    - ECDSA key pair generation
    - ECDSA signing with SHA-256
    - ECDSA signature verification
    - Key serialization and deserialization
    """
    
    # Supported ECC curves with their properties
    SUPPORTED_CURVES = {
        "secp256r1": {
            "curve": ec.SECP256R1(),
            "key_size": 256,
            "security_level": "128-bit",
            "name": "P-256 (secp256r1)",
            "description": "NIST P-256, widely supported"
        },
        "secp384r1": {
            "curve": ec.SECP384R1(),
            "key_size": 384,
            "security_level": "192-bit",
            "name": "P-384 (secp384r1)",
            "description": "NIST P-384, high security"
        },
        "secp521r1": {
            "curve": ec.SECP521R1(),
            "key_size": 521,
            "security_level": "256-bit",
            "name": "P-521 (secp521r1)",
            "description": "NIST P-521, highest security"
        }
    }
    
    def __init__(self, curve_name: str = "secp256r1"):
        """
        Initialize ECC crypto operations.
        
        Args:
            curve_name: ECC curve name (default: secp256r1)
        """
        if curve_name not in self.SUPPORTED_CURVES:
            raise ValueError(f"Unsupported curve: {curve_name}. Supported curves: {list(self.SUPPORTED_CURVES.keys())}")
        
        self.curve_name = curve_name
        self.curve = self.SUPPORTED_CURVES[curve_name]["curve"]
        self.curve_info = self.SUPPORTED_CURVES[curve_name]
        self.hash_algorithm = hashes.SHA256()
    
    def generate_key_pair(self) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        """
        Generate a new ECC key pair.
        
        Returns:
            Tuple of (private_key, public_key)
        """
        private_key = ec.generate_private_key(self.curve)
        public_key = private_key.public_key()
        
        return private_key, public_key
    
    def sign_data(self, private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
        """
        Sign data using ECDSA.
        
        Args:
            private_key: ECC private key for signing
            data: Data to sign
            
        Returns:
            ECDSA signature bytes
        """
        signature = private_key.sign(
            data,
            ec.ECDSA(self.hash_algorithm)
        )
        return signature
    
    def verify_signature(self, public_key: ec.EllipticCurvePublicKey, data: bytes, signature: bytes) -> bool:
        """
        Verify ECDSA signature.
        
        Args:
            public_key: ECC public key for verification
            data: Original data that was signed
            signature: ECDSA signature to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            public_key.verify(
                signature,
                data,
                ec.ECDSA(self.hash_algorithm)
            )
            return True
        except Exception:
            return False
    
    def serialize_private_key(self, private_key: ec.EllipticCurvePrivateKey, password: Optional[str] = None) -> bytes:
        """
        Serialize ECC private key to PEM format.
        
        Args:
            private_key: ECC private key to serialize
            password: Optional password for key encryption
            
        Returns:
            PEM-encoded private key bytes
        """
        encryption_algorithm = NoEncryption()
        if password:
            from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
            encryption_algorithm = BestAvailableEncryption(password.encode())
        
        return private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
    
    def serialize_public_key(self, public_key: ec.EllipticCurvePublicKey) -> bytes:
        """
        Serialize ECC public key to PEM format.
        
        Args:
            public_key: ECC public key to serialize
            
        Returns:
            PEM-encoded public key bytes
        """
        return public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
    
    def deserialize_private_key(self, key_data: bytes, password: Optional[str] = None) -> ec.EllipticCurvePrivateKey:
        """
        Deserialize ECC private key from PEM format.
        
        Args:
            key_data: PEM-encoded private key bytes
            password: Optional password for key decryption
            
        Returns:
            ECC private key object
        """
        password_bytes = password.encode() if password else None
        return serialization.load_pem_private_key(
            key_data,
            password=password_bytes
        )
    
    def deserialize_public_key(self, key_data: bytes) -> ec.EllipticCurvePublicKey:
        """
        Deserialize ECC public key from PEM format.
        
        Args:
            key_data: PEM-encoded public key bytes
            
        Returns:
            ECC public key object
        """
        return serialization.load_pem_public_key(key_data)
    
    def get_key_info(self, private_key: ec.EllipticCurvePrivateKey) -> Dict[str, Any]:
        """
        Get information about an ECC key.
        
        Args:
            private_key: ECC private key
            
        Returns:
            Dictionary with key information
        """
        return {
            "algorithm": "ECDSA",
            "curve": self.curve_name,
            "curve_name": self.curve_info["name"],
            "key_size": self.curve_info["key_size"],
            "security_level": self.curve_info["security_level"],
            "hash_algorithm": "SHA-256",
            "description": self.curve_info["description"]
        }
    
    @classmethod
    def get_supported_curves(cls) -> Dict[str, Dict[str, Any]]:
        """
        Get information about all supported ECC curves.
        
        Returns:
            Dictionary mapping curve names to their information
        """
        return cls.SUPPORTED_CURVES.copy()
