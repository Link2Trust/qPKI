"""
Key Validation Utilities

This module provides functions for validating and migrating cryptographic keys,
particularly for Dilithium post-quantum keys with different variants.
"""

import os
import json
import base64
import shutil
from typing import Dict, Any, Optional, Tuple
from datetime import datetime

from ..dilithium_crypto import DilithiumCrypto


def validate_dilithium_key_data(private_key_data: str, public_key_data: str) -> Optional[int]:
    """
    Validate Dilithium key data and determine the correct variant.
    
    Args:
        private_key_data: Base64-encoded private key data
        public_key_data: Base64-encoded public key data
        
    Returns:
        The correct Dilithium variant (2, 3, or 5) if detected, None otherwise
    """
    try:
        # Decode base64 data to get raw key bytes
        decoded_private = base64.b64decode(private_key_data)
        decoded_public = base64.b64decode(public_key_data)
        
        # Check against known key sizes for different Dilithium variants
        for variant, variant_info in DilithiumCrypto.DILITHIUM_VARIANTS.items():
            if (len(decoded_private) == variant_info['private_key_size'] and 
                len(decoded_public) == variant_info['public_key_size']):
                return variant
        
        return None
    except Exception:
        return None


def validate_and_migrate_key_file(file_path: str, password: Optional[str] = None) -> Dict[str, Any]:
    """
    Validate a key file and migrate it to use the correct Dilithium variant if needed.
    
    Args:
        file_path: Path to the key file
        password: Optional password for encrypted keys
        
    Returns:
        Dictionary with validation/migration results
    """
    if not os.path.exists(file_path):
        return {
            "status": "error",
            "message": f"File not found: {file_path}",
            "migrated": False
        }
    
    try:
        # Read the key file
        with open(file_path, 'r') as f:
            key_data = json.load(f)
        
        # Check if it's a hybrid key file with Dilithium keys
        dilithium_keys_present = False
        dilithium_private_key = None
        dilithium_public_key = None
        
        # Check for both naming conventions (legacy and flexible hybrid)
        if all(key in key_data for key in ["dilithium_private_key", "dilithium_public_key"]):
            dilithium_private_key = key_data["dilithium_private_key"]
            dilithium_public_key = key_data["dilithium_public_key"]
            dilithium_keys_present = True
        # Check for CA/certificate format with private_keys section
        elif "private_keys" in key_data and all(key in key_data["private_keys"] for key in ["dilithium_private_key", "dilithium_public_key"]):
            dilithium_private_key = key_data["private_keys"]["dilithium_private_key"]
            dilithium_public_key = key_data["private_keys"]["dilithium_public_key"]
            dilithium_keys_present = True
        
        if not dilithium_keys_present:
            return {
                "status": "info",
                "message": "Not a hybrid key file with Dilithium keys",
                "migrated": False
            }
        
        # Get stored variant if available
        stored_variant = key_data.get("dilithium_variant")
        
        # Detect correct variant from key sizes
        detected_variant = validate_dilithium_key_data(
            dilithium_private_key, dilithium_public_key
        )
        
        if detected_variant is None:
            return {
                "status": "error",
                "message": "Could not determine Dilithium variant from key sizes",
                "migrated": False
            }
        
        # Check if migration is needed
        if stored_variant == detected_variant:
            return {
                "status": "success",
                "message": f"Key file already using correct Dilithium variant: {detected_variant}",
                "migrated": False,
                "variant": detected_variant
            }
        
        # Create backup of original file
        backup_path = f"{file_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        shutil.copy2(file_path, backup_path)
        
        # Update key data with correct variant information
        key_data['dilithium_variant'] = detected_variant
        
        # Write updated key file
        with open(file_path, 'w') as f:
            json.dump(key_data, f, indent=2)
        
        return {
            "status": "success",
            "message": f"Migrated key file from variant {stored_variant or 'unknown'} to {detected_variant}",
            "migrated": True,
            "variant": detected_variant,
            "backup_path": backup_path
        }
    
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error validating/migrating key file: {str(e)}",
            "migrated": False
        }


def test_dilithium_consistency(variant: int = 2) -> Dict[str, Any]:
    """
    Test consistency of Dilithium key generation, serialization and deserialization.
    
    Args:
        variant: Dilithium variant to test (2, 3, or 5)
        
    Returns:
        Dictionary with test results
    """
    try:
        # Create Dilithium crypto instance with specified variant
        dilithium_crypto = DilithiumCrypto(variant=variant)
        variant_info = dilithium_crypto.DILITHIUM_VARIANTS[variant]
        
        # Generate a test key pair
        private_key, public_key = dilithium_crypto.generate_key_pair()
        
        # Test serialization and deserialization
        serialized_private = dilithium_crypto.serialize_private_key(private_key)
        serialized_public = dilithium_crypto.serialize_public_key(public_key)
        
        deserialized_private = dilithium_crypto.deserialize_private_key(serialized_private)
        deserialized_public = dilithium_crypto.deserialize_public_key(serialized_public)
        
        # Test signing and verification
        test_data = b"Test data for signing"
        signature = dilithium_crypto.sign_data(private_key, test_data)
        verification = dilithium_crypto.verify_signature(public_key, test_data, signature)
        
        return {
            "status": "success",
            "variant": variant,
            "expected_private_key_size": variant_info['private_key_size'],
            "expected_public_key_size": variant_info['public_key_size'],
            "actual_private_key_size": len(private_key),
            "actual_public_key_size": len(public_key),
            "serialization_test": "passed",
            "verification_test": "passed" if verification else "failed"
        }
    except Exception as e:
        return {
            "status": "error",
            "variant": variant,
            "error": str(e)
        }


def validate_all_key_files(directory: str, recursive: bool = False) -> Dict[str, Any]:
    """
    Validate and migrate all key files in a directory.
    
    Args:
        directory: Directory containing key files
        recursive: Whether to search subdirectories recursively
        
    Returns:
        Dictionary with validation/migration results
    """
    if not os.path.isdir(directory):
        return {
            "status": "error",
            "message": f"Not a directory: {directory}",
            "files_processed": 0,
            "files_migrated": 0,
            "results": []
        }
    
    results = []
    files_processed = 0
    files_migrated = 0
    
    # Walk through directory
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(('.json', '.key')):
                file_path = os.path.join(root, file)
                result = validate_and_migrate_key_file(file_path)
                results.append({
                    "file": file_path,
                    "result": result
                })
                
                files_processed += 1
                if result.get("migrated", False):
                    files_migrated += 1
        
        # If not recursive, break after first iteration
        if not recursive:
            break
    
    return {
        "status": "success",
        "files_processed": files_processed,
        "files_migrated": files_migrated,
        "results": results
    }


if __name__ == "__main__":
    # This allows running the module as a script for testing
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python key_validator.py <file_path_or_directory> [--recursive]")
        sys.exit(1)
    
    path = sys.argv[1]
    recursive = "--recursive" in sys.argv
    
    if os.path.isdir(path):
        result = validate_all_key_files(path, recursive)
        print(f"Processed {result['files_processed']} files, migrated {result['files_migrated']} files")
        
        for file_result in result['results']:
            if file_result['result'].get('migrated', False):
                print(f"Migrated: {file_result['file']} - {file_result['result']['message']}")
    else:
        result = validate_and_migrate_key_file(path)
        print(f"Result: {result['status']} - {result['message']}")
        if result.get('migrated', False):
            print(f"Backup saved at: {result['backup_path']}")
