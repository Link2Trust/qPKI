#!/usr/bin/env python3
"""
Tests for Hybrid Cryptographic Operations

This module contains basic tests for the hybrid crypto functionality
to verify that RSA and Dilithium operations work correctly together.
"""

import unittest
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from qpki.crypto import HybridCrypto, RSACrypto, DilithiumCrypto


class TestHybridCrypto(unittest.TestCase):
    """Test cases for hybrid cryptographic operations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.hybrid_crypto = HybridCrypto(rsa_key_size=2048, dilithium_variant=2)
        self.test_data = b"This is test data for hybrid cryptographic operations"
    
    def test_hybrid_key_generation(self):
        """Test hybrid key pair generation."""
        hybrid_keys = self.hybrid_crypto.generate_hybrid_key_pair()
        
        # Verify all keys are present
        self.assertIsNotNone(hybrid_keys.rsa_private)
        self.assertIsNotNone(hybrid_keys.rsa_public)
        self.assertIsNotNone(hybrid_keys.dilithium_private)
        self.assertIsNotNone(hybrid_keys.dilithium_public)
        
        # Check key types
        self.assertIsInstance(hybrid_keys.dilithium_private, bytes)
        self.assertIsInstance(hybrid_keys.dilithium_public, bytes)
    
    def test_hybrid_signing_and_verification(self):
        """Test hybrid signing and verification."""
        # Generate keys
        hybrid_keys = self.hybrid_crypto.generate_hybrid_key_pair()
        
        # Sign data
        hybrid_signature = self.hybrid_crypto.sign_data_hybrid(hybrid_keys, self.test_data)
        
        # Verify both signatures are present
        self.assertIsNotNone(hybrid_signature.rsa_signature)
        self.assertIsNotNone(hybrid_signature.dilithium_signature)
        
        # Verify signature (require both)
        verification_result = self.hybrid_crypto.verify_hybrid_signature(
            hybrid_keys, self.test_data, hybrid_signature, require_both=True
        )
        
        self.assertTrue(verification_result['rsa_valid'])
        self.assertTrue(verification_result['dilithium_valid'])
        self.assertTrue(verification_result['overall_valid'])
        self.assertTrue(verification_result['require_both'])
    
    def test_hybrid_signature_serialization(self):
        """Test hybrid signature serialization."""
        hybrid_keys = self.hybrid_crypto.generate_hybrid_key_pair()
        hybrid_signature = self.hybrid_crypto.sign_data_hybrid(hybrid_keys, self.test_data)
        
        # Serialize to dictionary
        sig_dict = hybrid_signature.to_dict()
        self.assertIn('rsa_signature', sig_dict)
        self.assertIn('dilithium_signature', sig_dict)
        
        # Deserialize from dictionary
        reconstructed_signature = hybrid_signature.from_dict(sig_dict)
        
        # Verify reconstructed signature works
        verification_result = self.hybrid_crypto.verify_hybrid_signature(
            hybrid_keys, self.test_data, reconstructed_signature, require_both=True
        )
        
        self.assertTrue(verification_result['overall_valid'])
    
    def test_key_serialization(self):
        """Test hybrid key serialization and deserialization."""
        hybrid_keys = self.hybrid_crypto.generate_hybrid_key_pair()
        
        # Serialize keys
        serialized_keys = self.hybrid_crypto.serialize_hybrid_keys(hybrid_keys)
        
        # Check all components are present
        self.assertIn('rsa_private_key', serialized_keys)
        self.assertIn('rsa_public_key', serialized_keys)
        self.assertIn('dilithium_private_key', serialized_keys)
        self.assertIn('dilithium_public_key', serialized_keys)
        
        # Deserialize keys
        deserialized_keys = self.hybrid_crypto.deserialize_hybrid_keys(serialized_keys)
        
        # Test that deserialized keys work
        signature = self.hybrid_crypto.sign_data_hybrid(deserialized_keys, self.test_data)
        verification_result = self.hybrid_crypto.verify_hybrid_signature(
            deserialized_keys, self.test_data, signature
        )
        
        self.assertTrue(verification_result['overall_valid'])
    
    def test_key_fingerprint(self):
        """Test key fingerprint generation."""
        hybrid_keys = self.hybrid_crypto.generate_hybrid_key_pair()
        fingerprint = self.hybrid_crypto.create_key_fingerprint(hybrid_keys)
        
        # Check fingerprint format (should be hex with colons)
        self.assertRegex(fingerprint, r'^[0-9a-f]{2}(:[0-9a-f]{2})*$')
        
        # Fingerprints should be consistent
        fingerprint2 = self.hybrid_crypto.create_key_fingerprint(hybrid_keys)
        self.assertEqual(fingerprint, fingerprint2)
        
        # Different keys should have different fingerprints
        different_keys = self.hybrid_crypto.generate_hybrid_key_pair()
        different_fingerprint = self.hybrid_crypto.create_key_fingerprint(different_keys)
        self.assertNotEqual(fingerprint, different_fingerprint)


class TestRSACrypto(unittest.TestCase):
    """Test cases for RSA cryptographic operations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.rsa_crypto = RSACrypto(key_size=2048)
        self.test_data = b"RSA test data"
    
    def test_rsa_key_generation(self):
        """Test RSA key pair generation."""
        private_key, public_key = self.rsa_crypto.generate_key_pair()
        
        # Verify key properties
        self.assertEqual(private_key.key_size, 2048)
        self.assertEqual(public_key.key_size, 2048)
    
    def test_rsa_signing_and_verification(self):
        """Test RSA signing and verification."""
        private_key, public_key = self.rsa_crypto.generate_key_pair()
        
        # Sign data
        signature = self.rsa_crypto.sign_data(private_key, self.test_data)
        
        # Verify signature
        is_valid = self.rsa_crypto.verify_signature(public_key, self.test_data, signature)
        self.assertTrue(is_valid)
        
        # Verify with wrong data fails
        wrong_data = b"Wrong data"
        is_valid_wrong = self.rsa_crypto.verify_signature(public_key, wrong_data, signature)
        self.assertFalse(is_valid_wrong)


class TestDilithiumCrypto(unittest.TestCase):
    """Test cases for Dilithium cryptographic operations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.dilithium_crypto = DilithiumCrypto(variant=2)
        self.test_data = b"Dilithium test data"
    
    def test_dilithium_key_generation(self):
        """Test Dilithium key pair generation."""
        private_key, public_key = self.dilithium_crypto.generate_key_pair()
        
        # Verify key properties
        self.assertIsInstance(private_key, bytes)
        self.assertIsInstance(public_key, bytes)
        self.assertEqual(len(public_key), 1312)  # ML-DSA-44 public key size
        self.assertEqual(len(private_key), 2560)  # ML-DSA-44 private key size
    
    def test_dilithium_signing_and_verification(self):
        """Test Dilithium signing and verification."""
        private_key, public_key = self.dilithium_crypto.generate_key_pair()
        
        # Sign data
        signature = self.dilithium_crypto.sign_data(private_key, self.test_data)
        
        # Verify signature
        is_valid = self.dilithium_crypto.verify_signature(public_key, self.test_data, signature)
        self.assertTrue(is_valid)
        
        # Verify with wrong data fails
        wrong_data = b"Wrong data"
        is_valid_wrong = self.dilithium_crypto.verify_signature(public_key, wrong_data, signature)
        self.assertFalse(is_valid_wrong)
    
    def test_dilithium_serialization(self):
        """Test Dilithium key serialization."""
        private_key, public_key = self.dilithium_crypto.generate_key_pair()
        
        # Serialize keys
        private_b64 = self.dilithium_crypto.serialize_private_key(private_key)
        public_b64 = self.dilithium_crypto.serialize_public_key(public_key)
        
        # Deserialize keys
        deserialized_private = self.dilithium_crypto.deserialize_private_key(private_b64)
        deserialized_public = self.dilithium_crypto.deserialize_public_key(public_b64)
        
        # Test that deserialized keys work
        signature = self.dilithium_crypto.sign_data(deserialized_private, self.test_data)
        is_valid = self.dilithium_crypto.verify_signature(deserialized_public, self.test_data, signature)
        self.assertTrue(is_valid)


if __name__ == '__main__':
    print("🧪 Running qPKI Hybrid Cryptography Tests")
    print("=" * 50)
    
    unittest.main(verbosity=2)
