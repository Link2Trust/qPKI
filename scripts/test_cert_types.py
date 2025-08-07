#!/usr/bin/env python3
"""
Certificate Type Detection Test Script

This script tests the get_certificate_type function to ensure it correctly
identifies different certificate types (Hybrid, RSA, ECC, ML-DSA).
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import get_certificate_type
import json

def test_certificate_type_detection():
    """Test certificate type detection with various certificate formats."""
    print("🧪 Testing Certificate Type Detection")
    print("=" * 50)
    
    # Test case 1: Classic RSA certificate (new format)
    classic_rsa_cert = {
        "certificate": {
            "certificate_type": "classic",
            "cryptographic_info": {
                "classical_algorithm_info": {
                    "type": "RSA-2048",
                    "classical_algorithm": {
                        "algorithm": "RSA",
                        "key_size": 2048
                    }
                }
            },
            "public_keys": {
                "rsa_public_key": "-----BEGIN PUBLIC KEY-----\n..."
            }
        }
    }
    
    result = get_certificate_type(classic_rsa_cert)
    print(f"✓ Classic RSA Certificate: {result}")
    assert result == "RSA", f"Expected 'RSA', got '{result}'"
    
    # Test case 2: Classic ECC certificate (new format)
    classic_ecc_cert = {
        "certificate": {
            "certificate_type": "classic",
            "cryptographic_info": {
                "classical_algorithm_info": {
                    "type": "ECC-secp256r1",
                    "classical_algorithm": {
                        "algorithm": "ECC",
                        "curve": "secp256r1"
                    }
                }
            },
            "public_keys": {
                "ecc_public_key": "-----BEGIN PUBLIC KEY-----\n..."
            }
        }
    }
    
    result = get_certificate_type(classic_ecc_cert)
    print(f"✓ Classic ECC Certificate: {result}")
    assert result == "ECC", f"Expected 'ECC', got '{result}'"
    
    # Test case 3: Hybrid certificate (new format)
    hybrid_cert = {
        "certificate": {
            "certificate_type": "hybrid",
            "cryptographic_info": {
                "hybrid_key_info": {
                    "type": "Hybrid (RSA + Post-Quantum)",
                    "classical_algorithm": {
                        "algorithm": "RSA",
                        "key_size": 2048
                    },
                    "post_quantum_algorithm": {
                        "algorithm": "ML-DSA-44",
                        "variant": 2
                    }
                }
            },
            "public_keys": {
                "rsa_public_key": "-----BEGIN PUBLIC KEY-----\n...",
                "dilithium_public_key": "base64encoded..."
            }
        }
    }
    
    result = get_certificate_type(hybrid_cert)
    print(f"✓ Hybrid Certificate: {result}")
    assert result == "Hybrid", f"Expected 'Hybrid', got '{result}'"
    
    # Test case 4: Legacy hybrid certificate (old format)
    legacy_hybrid_cert = {
        "certificate": {
            "cryptographic_info": {
                "hybrid_key_info": {
                    "type": "Hybrid (ECC + Post-Quantum)",
                    "classical_algorithm": {
                        "algorithm": "ECDSA",
                        "curve": "secp256r1"
                    },
                    "post_quantum_algorithm": {
                        "algorithm": "ML-DSA-44",
                        "variant": 2
                    }
                }
            },
            "public_keys": {
                "ecc_public_key": "-----BEGIN PUBLIC KEY-----\n...",
                "dilithium_public_key": "base64encoded..."
            }
        }
    }
    
    result = get_certificate_type(legacy_hybrid_cert)
    print(f"✓ Legacy Hybrid Certificate: {result}")
    assert result == "Hybrid", f"Expected 'Hybrid', got '{result}'"
    
    # Test case 5: Pure ML-DSA certificate (theoretical)
    ml_dsa_cert = {
        "certificate": {
            "cryptographic_info": {
                "post_quantum_algorithm": {
                    "algorithm": "ML-DSA-44",
                    "variant": 2
                }
            },
            "public_keys": {
                "dilithium_public_key": "base64encoded..."
            }
        }
    }
    
    result = get_certificate_type(ml_dsa_cert)
    print(f"✓ Pure ML-DSA Certificate: {result}")
    assert result == "ML-DSA", f"Expected 'ML-DSA', got '{result}'"
    
    # Test case 6: Unknown/malformed certificate
    unknown_cert = {
        "certificate": {
            "cryptographic_info": {},
            "public_keys": {}
        }
    }
    
    result = get_certificate_type(unknown_cert)
    print(f"✓ Unknown Certificate: {result}")
    assert result == "Unknown", f"Expected 'Unknown', got '{result}'"
    
    # Test case 7: RSA certificate detected by public key fallback
    rsa_fallback_cert = {
        "certificate": {
            "public_keys": {
                "rsa_public_key": "-----BEGIN PUBLIC KEY-----\n..."
            }
        }
    }
    
    result = get_certificate_type(rsa_fallback_cert)
    print(f"✓ RSA Fallback Detection: {result}")
    assert result == "RSA", f"Expected 'RSA', got '{result}'"
    
    print("\n" + "=" * 50)
    print("✅ All certificate type detection tests passed!")
    return True

def test_with_real_certificates():
    """Test with real certificate files if they exist."""
    print("\n🔍 Testing with Real Certificate Files")
    print("=" * 50)
    
    cert_dir = os.path.join(os.path.dirname(__file__), '..', 'certificates')
    
    if not os.path.exists(cert_dir):
        print("No certificate directory found - skipping real file tests")
        return
    
    cert_files = [f for f in os.listdir(cert_dir) if f.endswith('.json')]
    
    if not cert_files:
        print("No certificate files found - skipping real file tests")
        return
    
    print(f"Found {len(cert_files)} certificate files:")
    
    for filename in cert_files[:5]:  # Test first 5 files
        filepath = os.path.join(cert_dir, filename)
        try:
            with open(filepath, 'r') as f:
                cert_data = json.load(f)
            
            cert_type = get_certificate_type(cert_data)
            cert_name = cert_data.get('certificate', {}).get('subject', {}).get('common_name', 'Unknown')
            
            print(f"  • {filename}: {cert_name} → {cert_type}")
            
        except Exception as e:
            print(f"  ✗ {filename}: Error reading file - {str(e)}")

if __name__ == "__main__":
    print("Certificate Type Detection Test Suite")
    print("=" * 60)
    
    try:
        # Run the tests
        test_certificate_type_detection()
        test_with_real_certificates()
        
        print(f"\n🎉 All tests completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
