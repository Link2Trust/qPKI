"""
RSA Cryptographic Operations

This module provides RSA key generation, signing, and verification operations
for the classical component of the hybrid PKI system.
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from typing import Tuple, Optional
import os


class RSACrypto:
    """
    RSA cryptographic operations for classical public key cryptography.
    
    This class handles:
    - RSA key pair generation
    - RSA-PSS signing with SHA-256
    - RSA-PSS signature verification
    - Key serialization and deserialization
    """
    
    def __init__(self, key_size: int = 2048):
        """
        Initialize RSA crypto operations.
        
        Args:
            key_size: RSA key size in bits (default: 2048)
        """
        self.key_size = key_size
        self.hash_algorithm = hashes.SHA256()
        self.padding_config = padding.PSS(
            mgf=padding.MGF1(self.hash_algorithm),
            salt_length=padding.PSS.MAX_LENGTH
        )
    
    def generate_key_pair(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Generate a new RSA key pair.
        
        Returns:
            Tuple of (private_key, public_key)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size
        )
        public_key = private_key.public_key()
        
        return private_key, public_key
    
    def sign_data(self, private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
        """
        Sign data using RSA-PSS.
        
        Args:
            private_key: RSA private key for signing
            data: Data to sign
            
        Returns:
            RSA signature bytes
        """
        signature = private_key.sign(
            data,
            self.padding_config,
            self.hash_algorithm
        )
        return signature
    
    def verify_signature(self, public_key: rsa.RSAPublicKey, data: bytes, signature: bytes) -> bool:
        """
        Verify RSA-PSS signature.
        
        Args:
            public_key: RSA public key for verification
            data: Original data that was signed
            signature: RSA signature to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            public_key.verify(
                signature,
                data,
                self.padding_config,
                self.hash_algorithm
            )
            return True
        except Exception:
            return False
    
    def serialize_private_key(self, private_key: rsa.RSAPrivateKey, password: Optional[str] = None) -> bytes:
        """
        Serialize RSA private key to PEM format.
        
        Args:
            private_key: RSA private key to serialize
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
    
    def serialize_public_key(self, public_key: rsa.RSAPublicKey) -> bytes:
        """
        Serialize RSA public key to PEM format.
        
        Args:
            public_key: RSA public key to serialize
            
        Returns:
            PEM-encoded public key bytes
        """
        return public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
    
    def deserialize_private_key(self, key_data: bytes, password: Optional[str] = None) -> rsa.RSAPrivateKey:
        """
        Deserialize RSA private key from PEM format.
        
        Args:
            key_data: PEM-encoded private key bytes
            password: Optional password for key decryption
            
        Returns:
            RSA private key object
        """
        password_bytes = password.encode() if password else None
        return serialization.load_pem_private_key(
            key_data,
            password=password_bytes
        )
    
    def deserialize_public_key(self, key_data: bytes) -> rsa.RSAPublicKey:
        """
        Deserialize RSA public key from PEM format.
        
        Args:
            key_data: PEM-encoded public key bytes
            
        Returns:
            RSA public key object
        """
        return serialization.load_pem_public_key(key_data)
    
    def get_key_info(self, private_key: rsa.RSAPrivateKey) -> dict:
        """
        Get information about an RSA key.
        
        Args:
            private_key: RSA private key
            
        Returns:
            Dictionary with key information
        """
        public_key = private_key.public_key()
        return {
            "algorithm": "RSA",
            "key_size": private_key.key_size,
            "public_exponent": public_key.public_numbers().e,
            "hash_algorithm": "SHA-256",
            "padding": "PSS"
        }
