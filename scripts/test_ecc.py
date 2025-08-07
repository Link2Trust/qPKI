#!/usr/bin/env python3
"""
ECC Cryptography Test Script

This script tests the ECC cryptographic operations including key generation,
signing, verification, and hybrid operations with ECC.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from qpki.crypto import ECCCrypto, FlexibleHybridCrypto
import json

def test_ecc_basic_operations():
    """Test basic ECC operations."""
    print("=== Testing Basic ECC Operations ===")
    
    # Test different curves
    for curve_name in ["secp256r1", "secp384r1", "secp521r1"]:
        print(f"\nTesting curve: {curve_name}")
        
        # Initialize ECC crypto
        ecc = ECCCrypto(curve_name=curve_name)
        
        # Generate key pair
        private_key, public_key = ecc.generate_key_pair()
        print(f"✓ Generated {curve_name} key pair")
        
        # Test signing and verification
        test_data = b"Hello, ECC World!"
        signature = ecc.sign_data(private_key, test_data)
        
        # Verify signature
        is_valid = ecc.verify_signature(public_key, test_data, signature)
        print(f"✓ Signature verification: {'PASSED' if is_valid else 'FAILED'}")
        
        # Test with wrong data (should fail)
        wrong_data = b"Hello, Wrong World!"
        is_invalid = ecc.verify_signature(public_key, wrong_data, signature)
        print(f"✓ Invalid signature test: {'PASSED' if not is_invalid else 'FAILED'}")
        
        # Test key serialization
        private_pem = ecc.serialize_private_key(private_key)
        public_pem = ecc.serialize_public_key(public_key)
        
        # Test key deserialization
        restored_private = ecc.deserialize_private_key(private_pem)
        restored_public = ecc.deserialize_public_key(public_pem)
        
        # Test signature with restored keys
        signature2 = ecc.sign_data(restored_private, test_data)
        is_valid2 = ecc.verify_signature(restored_public, test_data, signature2)
        print(f"✓ Restored key signature verification: {'PASSED' if is_valid2 else 'FAILED'}")
        
        # Get key info
        key_info = ecc.get_key_info(private_key)
        print(f"✓ Key info: {key_info['algorithm']} {key_info['curve_name']}")


def test_hybrid_ecc_operations():
    """Test hybrid operations with ECC."""
    print("\n=== Testing Hybrid ECC+Dilithium Operations ===")
    
    # Test with ECC
    hybrid_ecc = FlexibleHybridCrypto(
        classical_algorithm="ECC", 
        ecc_curve="secp256r1",
        dilithium_variant=2
    )
    
    # Generate hybrid key pair
    hybrid_keys = hybrid_ecc.generate_hybrid_key_pair()
    print("✓ Generated ECC+Dilithium hybrid key pair")
    
    # Test hybrid signing
    test_data = b"Hello, Hybrid ECC World!"
    hybrid_signature = hybrid_ecc.sign_data_hybrid(hybrid_keys, test_data)
    print("✓ Created hybrid signature")
    
    # Verify hybrid signature
    verification_result = hybrid_ecc.verify_hybrid_signature(
        hybrid_keys, test_data, hybrid_signature
    )
    print(f"✓ ECC verification: {'PASSED' if verification_result['ecc_valid'] else 'FAILED'}")
    print(f"✓ Dilithium verification: {'PASSED' if verification_result['dilithium_valid'] else 'FAILED'}")
    print(f"✓ Overall verification: {'PASSED' if verification_result['overall_valid'] else 'FAILED'}")
    
    # Test serialization
    serialized_keys = hybrid_ecc.serialize_hybrid_keys(hybrid_keys)
    print("✓ Serialized hybrid keys")
    
    # Test deserialization
    restored_keys = hybrid_ecc.deserialize_hybrid_keys(serialized_keys)
    print("✓ Deserialized hybrid keys")
    
    # Test signature with restored keys
    signature2 = hybrid_ecc.sign_data_hybrid(restored_keys, test_data)
    verification_result2 = hybrid_ecc.verify_hybrid_signature(
        restored_keys, test_data, signature2
    )
    print(f"✓ Restored keys verification: {'PASSED' if verification_result2['overall_valid'] else 'FAILED'}")
    
    # Get key info
    key_info = hybrid_ecc.get_hybrid_key_info(hybrid_keys)
    print(f"✓ Hybrid key type: {key_info['hybrid_key_info']['type']}")
    
    # Create fingerprint
    fingerprint = hybrid_ecc.create_key_fingerprint(hybrid_keys)
    print(f"✓ Key fingerprint: {fingerprint}")


def test_curve_comparison():
    """Compare different ECC curves."""
    print("\n=== ECC Curve Comparison ===")
    
    curves = ECCCrypto.get_supported_curves()
    print(f"{'Curve':<15} {'Key Size':<10} {'Security Level':<15} {'Description'}")
    print("-" * 70)
    
    for curve_name, curve_info in curves.items():
        print(f"{curve_name:<15} {curve_info['key_size']:<10} {curve_info['security_level']:<15} {curve_info['description']}")


def test_rsa_vs_ecc_hybrid():
    """Compare RSA vs ECC in hybrid mode."""
    print("\n=== RSA vs ECC Hybrid Comparison ===")
    
    test_data = b"Performance test data for hybrid signatures"
    
    # Test RSA hybrid
    hybrid_rsa = FlexibleHybridCrypto(classical_algorithm="RSA", rsa_key_size=2048)
    rsa_keys = hybrid_rsa.generate_hybrid_key_pair()
    rsa_signature = hybrid_rsa.sign_data_hybrid(rsa_keys, test_data)
    rsa_verification = hybrid_rsa.verify_hybrid_signature(rsa_keys, test_data, rsa_signature)
    
    # Test ECC hybrid
    hybrid_ecc = FlexibleHybridCrypto(classical_algorithm="ECC", ecc_curve="secp256r1")
    ecc_keys = hybrid_ecc.generate_hybrid_key_pair()
    ecc_signature = hybrid_ecc.sign_data_hybrid(ecc_keys, test_data)
    ecc_verification = hybrid_ecc.verify_hybrid_signature(ecc_keys, test_data, ecc_signature)
    
    print(f"RSA Hybrid - Valid: {rsa_verification['overall_valid']}")
    print(f"ECC Hybrid - Valid: {ecc_verification['overall_valid']}")
    
    # Compare key info
    rsa_info = hybrid_rsa.get_hybrid_key_info(rsa_keys)
    ecc_info = hybrid_ecc.get_hybrid_key_info(ecc_keys)
    
    print(f"RSA Classical: {rsa_info['hybrid_key_info']['classical_algorithm']['algorithm']} "
          f"{rsa_info['hybrid_key_info']['classical_algorithm']['key_size']} bits")
    print(f"ECC Classical: {ecc_info['hybrid_key_info']['classical_algorithm']['algorithm']} "
          f"{ecc_info['hybrid_key_info']['classical_algorithm']['curve_name']}")


if __name__ == "__main__":
    print("qPKI ECC Cryptography Test Suite")
    print("=" * 50)
    
    try:
        test_ecc_basic_operations()
        test_hybrid_ecc_operations()
        test_curve_comparison()
        test_rsa_vs_ecc_hybrid()
        
        print("\n" + "=" * 50)
        print("✓ All ECC tests completed successfully!")
        
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
