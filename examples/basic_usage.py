#!/usr/bin/env python3
"""
Basic Usage Example for qPKI

This script demonstrates the basic functionality of the hybrid PKI system,
including CA setup, key generation, certificate issuance, and validation.
"""

import sys
import os

# Add the src directory to the path so we can import qpki
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from qpki import HybridCA, KeyManager
from qpki.crypto import HybridCrypto


def main():
    print("🔐 qPKI Basic Usage Example")
    print("=" * 40)
    
    try:
        # 1. Initialize a Certificate Authority
        print("\n1. Initializing Certificate Authority...")
        ca = HybridCA("ExampleCA")
        ca_key_id = ca.initialize_ca(
            organization="Example Organization",
            country="US",
            rsa_key_size=2048,
            dilithium_variant=2,
            validity_years=5
        )
        print(f"✅ CA initialized with key ID: {ca_key_id}")
        
        # 2. Generate a key pair for a client
        print("\n2. Generating client key pair...")
        key_manager = KeyManager()
        client_key_id = key_manager.generate_key_pair(
            key_name="client-example",
            owner="CN=client.example.com, O=Example Client Corp",
            rsa_key_size=2048,
            dilithium_variant=2,
            validity_days=365
        )
        print(f"✅ Client key pair generated with ID: {client_key_id}")
        
        # 3. Issue a certificate for the client
        print("\n3. Issuing certificate...")
        subject = {
            "common_name": "client.example.com",
            "organization": "Example Client Corp",
            "country": "US"
        }
        
        cert_id = ca.issue_certificate(
            subject=subject,
            ca_key_identifier=f"CA-ExampleCA",
            validity_days=365,
            key_usage=["digital_signature", "key_encipherment", "client_auth"]
        )
        print(f"✅ Certificate issued with ID: {cert_id}")
        
        # 4. Validate the certificate
        print("\n4. Validating certificate...")
        validation_result = ca.validate_certificate(cert_id)
        
        if validation_result['valid']:
            print("✅ Certificate is VALID!")
            print(f"   RSA signature: {'✅' if validation_result['signature_verification']['rsa_valid'] else '❌'}")
            print(f"   Dilithium signature: {'✅' if validation_result['signature_verification']['dilithium_valid'] else '❌'}")
            print(f"   Time validity: {'✅' if validation_result['time_valid'] else '❌'}")
            print(f"   Not revoked: {'✅' if not validation_result['revoked'] else '❌'}")
        else:
            print("❌ Certificate validation failed!")
            if 'error' in validation_result:
                print(f"   Error: {validation_result['error']}")
        
        # 5. Demonstrate hybrid signature/verification
        print("\n5. Demonstrating hybrid cryptographic operations...")
        
        # Load client keys
        client_keys, client_metadata = key_manager.load_key_pair("client-example")
        
        # Create hybrid crypto instance
        hybrid_crypto = HybridCrypto(2048, 2)  # RSA 2048, Dilithium2
        
        # Sign some data
        test_data = b"This is a test message for hybrid signing"
        hybrid_signature = hybrid_crypto.sign_data_hybrid(client_keys, test_data)
        print("✅ Data signed with hybrid signature")
        
        # Verify the signature
        verification_result = hybrid_crypto.verify_hybrid_signature(
            client_keys, test_data, hybrid_signature, require_both=True
        )
        
        if verification_result['overall_valid']:
            print("✅ Hybrid signature verification successful!")
        else:
            print("❌ Hybrid signature verification failed!")
        
        # 6. Display key information
        print("\n6. Key Information Summary:")
        keys = key_manager.list_keys()
        
        for key in keys:
            print(f"\nKey: {key['key_name']}")
            print(f"  Owner: {key['owner']}")
            print(f"  RSA Size: {key['rsa_key_size']} bits")
            print(f"  Dilithium: Variant {key['dilithium_variant']}")
            print(f"  Fingerprint: {key['fingerprint'][:32]}...")
            print(f"  Status: {key['status']}")
        
        # 7. Display certificate information
        print("\n7. Certificate Information:")
        certificates = ca.list_certificates()
        
        for cert in certificates:
            print(f"\nCertificate: {cert['cert_id'][:16]}...")
            print(f"  Subject: {cert['subject'].get('common_name', 'N/A')}")
            print(f"  Issuer: {cert['issuer'].get('common_name', 'N/A')}")
            print(f"  Status: {cert['status']}")
            print(f"  Valid from: {cert['not_before'][:19]}")
            print(f"  Valid until: {cert['not_after'][:19]}")
            print(f"  Key usage: {', '.join(cert.get('key_usage', []))}")
        
        print("\n🎉 Example completed successfully!")
        print("\nNext steps:")
        print("- Try the CLI: python -m qpki --help")
        print("- Run the demo: python -m qpki demo")
        print("- Explore the source code in src/qpki/")
        
    except Exception as e:
        print(f"\n❌ Example failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
