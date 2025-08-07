"""
Hybrid Cryptographic Operations

This module combines classical (RSA/ECC) and Dilithium cryptographic operations to provide
hybrid signatures that are both classically secure and quantum-resistant.
"""

from .rsa_crypto import RSACrypto
from .ecc_crypto import ECCCrypto
from .dilithium_crypto import DilithiumCrypto
from typing import Tuple, Dict, Any, Optional, Union
import json
import hashlib


class HybridKeyPair:
    """
    Container for hybrid key pairs containing both RSA and Dilithium keys.
    """
    
    def __init__(self, rsa_private, rsa_public, dilithium_private: bytes, dilithium_public: bytes):
        self.rsa_private = rsa_private
        self.rsa_public = rsa_public
        self.dilithium_private = dilithium_private
        self.dilithium_public = dilithium_public


class HybridSignature:
    """
    Container for hybrid signatures containing both RSA and Dilithium signatures.
    """
    
    def __init__(self, rsa_signature: bytes, dilithium_signature: bytes):
        self.rsa_signature = rsa_signature
        self.dilithium_signature = dilithium_signature
    
    def to_dict(self) -> Dict[str, str]:
        """Convert hybrid signature to dictionary format."""
        import base64
        return {
            "rsa_signature": base64.b64encode(self.rsa_signature).decode('utf-8'),
            "dilithium_signature": base64.b64encode(self.dilithium_signature).decode('utf-8')
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> 'HybridSignature':
        """Create hybrid signature from dictionary format."""
        import base64
        return cls(
            rsa_signature=base64.b64decode(data["rsa_signature"]),
            dilithium_signature=base64.b64decode(data["dilithium_signature"])
        )


class HybridCrypto:
    """
    Hybrid cryptographic operations combining RSA and Dilithium algorithms.
    
    This class provides:
    - Hybrid key pair generation
    - Hybrid signing (both RSA and Dilithium signatures)
    - Hybrid signature verification
    - Key serialization and management
    """
    
    def __init__(self, rsa_key_size: int = 2048, dilithium_variant: int = 2):
        """
        Initialize hybrid crypto operations.
        
        Args:
            rsa_key_size: RSA key size in bits (default: 2048)
            dilithium_variant: Dilithium variant (2, 3, or 5, default: 2)
        """
        self.rsa_crypto = RSACrypto(key_size=rsa_key_size)
        self.dilithium_crypto = DilithiumCrypto(variant=dilithium_variant)
    
    def generate_hybrid_key_pair(self) -> HybridKeyPair:
        """
        Generate a hybrid key pair containing both RSA and Dilithium keys.
        
        Returns:
            HybridKeyPair containing both classical and post-quantum keys
        """
        # Generate RSA key pair
        rsa_private, rsa_public = self.rsa_crypto.generate_key_pair()
        
        # Generate Dilithium key pair
        dilithium_private, dilithium_public = self.dilithium_crypto.generate_key_pair()
        
        return HybridKeyPair(rsa_private, rsa_public, dilithium_private, dilithium_public)
    
    def sign_data_hybrid(self, hybrid_keys: HybridKeyPair, data: bytes) -> HybridSignature:
        """
        Sign data using both RSA and Dilithium algorithms.
        
        Args:
            hybrid_keys: Hybrid key pair for signing
            data: Data to sign
            
        Returns:
            HybridSignature containing both RSA and Dilithium signatures
        """
        # Create a hash of the data for consistent signing
        data_hash = hashlib.sha256(data).digest()
        
        # Sign with RSA
        rsa_signature = self.rsa_crypto.sign_data(hybrid_keys.rsa_private, data_hash)
        
        # Sign with Dilithium
        dilithium_signature = self.dilithium_crypto.sign_data(hybrid_keys.dilithium_private, data_hash)
        
        return HybridSignature(rsa_signature, dilithium_signature)
    
    def verify_hybrid_signature(self, hybrid_keys: HybridKeyPair, data: bytes, 
                               signature: HybridSignature, require_both: bool = True) -> Dict[str, bool]:
        """
        Verify hybrid signature using both RSA and Dilithium algorithms.
        
        Args:
            hybrid_keys: Hybrid key pair for verification (using public keys)
            data: Original data that was signed
            signature: HybridSignature to verify
            require_both: If True, both signatures must be valid; if False, either is sufficient
            
        Returns:
            Dictionary with verification results for each algorithm and overall result
        """
        # Create a hash of the data for consistent verification
        data_hash = hashlib.sha256(data).digest()
        
        # Verify RSA signature
        rsa_valid = self.rsa_crypto.verify_signature(
            hybrid_keys.rsa_public, data_hash, signature.rsa_signature
        )
        
        # Verify Dilithium signature
        dilithium_valid = self.dilithium_crypto.verify_signature(
            hybrid_keys.dilithium_public, data_hash, signature.dilithium_signature
        )
        
        # Determine overall validity
        if require_both:
            overall_valid = rsa_valid and dilithium_valid
        else:
            overall_valid = rsa_valid or dilithium_valid
        
        return {
            "rsa_valid": rsa_valid,
            "dilithium_valid": dilithium_valid,
            "overall_valid": overall_valid,
            "require_both": require_both
        }
    
    def serialize_hybrid_keys(self, hybrid_keys: HybridKeyPair, password: Optional[str] = None) -> Dict[str, str]:
        """
        Serialize hybrid key pair to dictionary format.
        
        Args:
            hybrid_keys: Hybrid key pair to serialize
            password: Optional password for RSA key encryption
            
        Returns:
            Dictionary containing serialized keys
        """
        return {
            "rsa_private_key": self.rsa_crypto.serialize_private_key(
                hybrid_keys.rsa_private, password
            ).decode('utf-8'),
            "rsa_public_key": self.rsa_crypto.serialize_public_key(
                hybrid_keys.rsa_public
            ).decode('utf-8'),
            "dilithium_private_key": self.dilithium_crypto.serialize_private_key(
                hybrid_keys.dilithium_private
            ),
            "dilithium_public_key": self.dilithium_crypto.serialize_public_key(
                hybrid_keys.dilithium_public
            )
        }
    
    def deserialize_hybrid_keys(self, key_data: Dict[str, str], password: Optional[str] = None) -> HybridKeyPair:
        """
        Deserialize hybrid key pair from dictionary format.
        
        Args:
            key_data: Dictionary containing serialized keys
            password: Optional password for RSA key decryption
            
        Returns:
            HybridKeyPair containing deserialized keys
        """
        rsa_private = self.rsa_crypto.deserialize_private_key(
            key_data["rsa_private_key"].encode('utf-8'), password
        )
        rsa_public = self.rsa_crypto.deserialize_public_key(
            key_data["rsa_public_key"].encode('utf-8')
        )
        dilithium_private = self.dilithium_crypto.deserialize_private_key(
            key_data["dilithium_private_key"]
        )
        dilithium_public = self.dilithium_crypto.deserialize_public_key(
            key_data["dilithium_public_key"]
        )
        
        return HybridKeyPair(rsa_private, rsa_public, dilithium_private, dilithium_public)
    
    def get_hybrid_key_info(self, hybrid_keys: HybridKeyPair) -> Dict[str, Any]:
        """
        Get information about hybrid key pair.
        
        Args:
            hybrid_keys: Hybrid key pair to analyze
            
        Returns:
            Dictionary with comprehensive key information
        """
        rsa_info = self.rsa_crypto.get_key_info(hybrid_keys.rsa_private)
        dilithium_info = self.dilithium_crypto.get_key_info(hybrid_keys.dilithium_private)
        
        return {
            "hybrid_key_info": {
                "type": "Hybrid (Classical + Post-Quantum)",
                "classical_algorithm": rsa_info,
                "post_quantum_algorithm": dilithium_info,
                "security_model": "Defense in depth - secure against both classical and quantum attacks"
            }
        }
    
    def export_public_keys_only(self, hybrid_keys: HybridKeyPair) -> Dict[str, str]:
        """
        Export only the public keys from a hybrid key pair.
        
        Args:
            hybrid_keys: Hybrid key pair
            
        Returns:
            Dictionary containing only public keys
        """
        return {
            "rsa_public_key": self.rsa_crypto.serialize_public_key(
                hybrid_keys.rsa_public
            ).decode('utf-8'),
            "dilithium_public_key": self.dilithium_crypto.serialize_public_key(
                hybrid_keys.dilithium_public
            )
        }
    
    def create_key_fingerprint(self, hybrid_keys: HybridKeyPair) -> str:
        """
        Create a unique fingerprint for the hybrid key pair.
        
        Args:
            hybrid_keys: Hybrid key pair
            
        Returns:
            SHA-256 hash of both public keys as fingerprint
        """
        rsa_pub_bytes = self.rsa_crypto.serialize_public_key(hybrid_keys.rsa_public)
        dilithium_pub_bytes = hybrid_keys.dilithium_public
        
        combined_keys = rsa_pub_bytes + dilithium_pub_bytes
        fingerprint = hashlib.sha256(combined_keys).hexdigest()
        
        # Format as typical key fingerprint
        return ':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))[:47]  # First 24 bytes


class FlexibleHybridKeyPair:
    """
    Container for flexible hybrid key pairs supporting both RSA and ECC as classical algorithms.
    """
    
    def __init__(self, classical_private, classical_public, dilithium_private: bytes, 
                 dilithium_public: bytes, classical_algorithm: str):
        self.classical_private = classical_private
        self.classical_public = classical_public
        self.dilithium_private = dilithium_private
        self.dilithium_public = dilithium_public
        self.classical_algorithm = classical_algorithm  # "RSA" or "ECC"


class FlexibleHybridSignature:
    """
    Container for flexible hybrid signatures supporting both RSA and ECC as classical algorithms.
    """
    
    def __init__(self, classical_signature: bytes, dilithium_signature: bytes, classical_algorithm: str):
        self.classical_signature = classical_signature
        self.dilithium_signature = dilithium_signature
        self.classical_algorithm = classical_algorithm  # "RSA" or "ECC"
    
    def to_dict(self) -> Dict[str, str]:
        """Convert flexible hybrid signature to dictionary format."""
        import base64
        return {
            "classical_signature": base64.b64encode(self.classical_signature).decode('utf-8'),
            "dilithium_signature": base64.b64encode(self.dilithium_signature).decode('utf-8'),
            "classical_algorithm": self.classical_algorithm
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> 'FlexibleHybridSignature':
        """Create flexible hybrid signature from dictionary format."""
        import base64
        return cls(
            classical_signature=base64.b64decode(data["classical_signature"]),
            dilithium_signature=base64.b64decode(data["dilithium_signature"]),
            classical_algorithm=data["classical_algorithm"]
        )


class FlexibleHybridCrypto:
    """
    Flexible hybrid cryptographic operations supporting both RSA/ECC and Dilithium algorithms.
    
    This class provides:
    - Flexible hybrid key pair generation (RSA+Dilithium or ECC+Dilithium)
    - Hybrid signing with chosen classical algorithm
    - Hybrid signature verification
    - Key serialization and management
    """
    
    def __init__(self, classical_algorithm: str = "RSA", rsa_key_size: int = 2048, 
                 ecc_curve: str = "secp256r1", dilithium_variant: int = 2):
        """
        Initialize flexible hybrid crypto operations.
        
        Args:
            classical_algorithm: "RSA" or "ECC" (default: "RSA")
            rsa_key_size: RSA key size in bits (default: 2048)
            ecc_curve: ECC curve name (default: "secp256r1")
            dilithium_variant: Dilithium variant (2, 3, or 5, default: 2)
        """
        if classical_algorithm not in ["RSA", "ECC"]:
            raise ValueError(f"Unsupported classical algorithm: {classical_algorithm}. Use 'RSA' or 'ECC'.")
        
        self.classical_algorithm = classical_algorithm
        
        if classical_algorithm == "RSA":
            self.classical_crypto = RSACrypto(key_size=rsa_key_size)
        else:  # ECC
            self.classical_crypto = ECCCrypto(curve_name=ecc_curve)
            
        self.dilithium_crypto = DilithiumCrypto(variant=dilithium_variant)
    
    def generate_hybrid_key_pair(self) -> FlexibleHybridKeyPair:
        """
        Generate a flexible hybrid key pair containing classical (RSA/ECC) and Dilithium keys.
        
        Returns:
            FlexibleHybridKeyPair containing both classical and post-quantum keys
        """
        # Generate classical key pair
        classical_private, classical_public = self.classical_crypto.generate_key_pair()
        
        # Generate Dilithium key pair
        dilithium_private, dilithium_public = self.dilithium_crypto.generate_key_pair()
        
        return FlexibleHybridKeyPair(classical_private, classical_public, 
                                   dilithium_private, dilithium_public, self.classical_algorithm)
    
    def sign_data_hybrid(self, hybrid_keys: FlexibleHybridKeyPair, data: bytes) -> FlexibleHybridSignature:
        """
        Sign data using both classical (RSA/ECC) and Dilithium algorithms.
        
        Args:
            hybrid_keys: Flexible hybrid key pair for signing
            data: Data to sign
            
        Returns:
            FlexibleHybridSignature containing both classical and Dilithium signatures
        """
        # Create a hash of the data for consistent signing
        data_hash = hashlib.sha256(data).digest()
        
        # Sign with classical algorithm
        classical_signature = self.classical_crypto.sign_data(hybrid_keys.classical_private, data_hash)
        
        # Sign with Dilithium
        dilithium_signature = self.dilithium_crypto.sign_data(hybrid_keys.dilithium_private, data_hash)
        
        return FlexibleHybridSignature(classical_signature, dilithium_signature, self.classical_algorithm)
    
    def verify_hybrid_signature(self, hybrid_keys: FlexibleHybridKeyPair, data: bytes, 
                               signature: FlexibleHybridSignature, require_both: bool = True) -> Dict[str, bool]:
        """
        Verify flexible hybrid signature using both classical and Dilithium algorithms.
        
        Args:
            hybrid_keys: Flexible hybrid key pair for verification (using public keys)
            data: Original data that was signed
            signature: FlexibleHybridSignature to verify
            require_both: If True, both signatures must be valid; if False, either is sufficient
            
        Returns:
            Dictionary with verification results for each algorithm and overall result
        """
        # Create a hash of the data for consistent verification
        data_hash = hashlib.sha256(data).digest()
        
        # Verify classical signature
        classical_valid = self.classical_crypto.verify_signature(
            hybrid_keys.classical_public, data_hash, signature.classical_signature
        )
        
        # Verify Dilithium signature
        dilithium_valid = self.dilithium_crypto.verify_signature(
            hybrid_keys.dilithium_public, data_hash, signature.dilithium_signature
        )
        
        # Determine overall validity
        if require_both:
            overall_valid = classical_valid and dilithium_valid
        else:
            overall_valid = classical_valid or dilithium_valid
        
        return {
            f"{self.classical_algorithm.lower()}_valid": classical_valid,
            "dilithium_valid": dilithium_valid,
            "overall_valid": overall_valid,
            "require_both": require_both,
            "classical_algorithm": self.classical_algorithm
        }
    
    def serialize_hybrid_keys(self, hybrid_keys: FlexibleHybridKeyPair, password: Optional[str] = None) -> Dict[str, str]:
        """
        Serialize flexible hybrid key pair to dictionary format.
        
        Args:
            hybrid_keys: Flexible hybrid key pair to serialize
            password: Optional password for classical key encryption
            
        Returns:
            Dictionary containing serialized keys
        """
        return {
            "classical_private_key": self.classical_crypto.serialize_private_key(
                hybrid_keys.classical_private, password
            ).decode('utf-8'),
            "classical_public_key": self.classical_crypto.serialize_public_key(
                hybrid_keys.classical_public
            ).decode('utf-8'),
            "dilithium_private_key": self.dilithium_crypto.serialize_private_key(
                hybrid_keys.dilithium_private
            ),
            "dilithium_public_key": self.dilithium_crypto.serialize_public_key(
                hybrid_keys.dilithium_public
            ),
            "classical_algorithm": hybrid_keys.classical_algorithm
        }
    
    def deserialize_hybrid_keys(self, key_data: Dict[str, str], password: Optional[str] = None) -> FlexibleHybridKeyPair:
        """
        Deserialize flexible hybrid key pair from dictionary format.
        
        Args:
            key_data: Dictionary containing serialized keys
            password: Optional password for classical key decryption
            
        Returns:
            FlexibleHybridKeyPair containing deserialized keys
        """
        classical_algorithm = key_data.get("classical_algorithm", "RSA")
        
        # Use appropriate crypto instance based on the algorithm stored in the data
        if classical_algorithm == "RSA":
            crypto_instance = RSACrypto() if classical_algorithm != self.classical_algorithm else self.classical_crypto
        else:  # ECC
            crypto_instance = ECCCrypto() if classical_algorithm != self.classical_algorithm else self.classical_crypto
        
        classical_private = crypto_instance.deserialize_private_key(
            key_data["classical_private_key"].encode('utf-8'), password
        )
        classical_public = crypto_instance.deserialize_public_key(
            key_data["classical_public_key"].encode('utf-8')
        )
        dilithium_private = self.dilithium_crypto.deserialize_private_key(
            key_data["dilithium_private_key"]
        )
        dilithium_public = self.dilithium_crypto.deserialize_public_key(
            key_data["dilithium_public_key"]
        )
        
        return FlexibleHybridKeyPair(classical_private, classical_public, 
                                   dilithium_private, dilithium_public, classical_algorithm)
    
    def get_hybrid_key_info(self, hybrid_keys: FlexibleHybridKeyPair) -> Dict[str, Any]:
        """
        Get information about flexible hybrid key pair.
        
        Args:
            hybrid_keys: Flexible hybrid key pair to analyze
            
        Returns:
            Dictionary with comprehensive key information
        """
        classical_info = self.classical_crypto.get_key_info(hybrid_keys.classical_private)
        dilithium_info = self.dilithium_crypto.get_key_info(hybrid_keys.dilithium_private)
        
        return {
            "hybrid_key_info": {
                "type": f"Hybrid ({hybrid_keys.classical_algorithm} + Post-Quantum)",
                "classical_algorithm": classical_info,
                "post_quantum_algorithm": dilithium_info,
                "security_model": "Defense in depth - secure against both classical and quantum attacks"
            }
        }
    
    def export_public_keys_only(self, hybrid_keys: FlexibleHybridKeyPair) -> Dict[str, str]:
        """
        Export only the public keys from a flexible hybrid key pair.
        
        Args:
            hybrid_keys: Flexible hybrid key pair
            
        Returns:
            Dictionary containing only public keys
        """
        return {
            "classical_public_key": self.classical_crypto.serialize_public_key(
                hybrid_keys.classical_public
            ).decode('utf-8'),
            "dilithium_public_key": self.dilithium_crypto.serialize_public_key(
                hybrid_keys.dilithium_public
            ),
            "classical_algorithm": hybrid_keys.classical_algorithm
        }
    
    def create_key_fingerprint(self, hybrid_keys: FlexibleHybridKeyPair) -> str:
        """
        Create a unique fingerprint for the flexible hybrid key pair.
        
        Args:
            hybrid_keys: Flexible hybrid key pair
            
        Returns:
            SHA-256 hash of both public keys as fingerprint
        """
        classical_pub_bytes = self.classical_crypto.serialize_public_key(hybrid_keys.classical_public)
        dilithium_pub_bytes = hybrid_keys.dilithium_public
        
        combined_keys = classical_pub_bytes + dilithium_pub_bytes
        fingerprint = hashlib.sha256(combined_keys).hexdigest()
        
        # Format as typical key fingerprint
        return ':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))[:47]  # First 24 bytes
