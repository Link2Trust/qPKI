#!/usr/bin/env python3
"""
Fix Certificate Validity Structure

This script updates existing certificate JSON files to use the validity structure
expected by the email notifier component.

Changes:
- Move 'not_before' and 'not_after' fields inside a 'validity' object
"""

import json
import os
import shutil
import glob
from datetime import datetime


def fix_certificate_structure(cert_file_path):
    """Fix the structure of a single certificate file."""
    try:
        # Read the certificate file
        with open(cert_file_path, 'r') as f:
            cert_data = json.load(f)
        
        certificate = cert_data.get('certificate', {})
        
        # Check if already has correct structure
        if 'validity' in certificate and 'not_after' in certificate['validity']:
            print(f"✓ {os.path.basename(cert_file_path)} already has correct structure")
            return True
        
        # Check if has old structure
        if 'not_before' not in certificate or 'not_after' not in certificate:
            print(f"⚠ {os.path.basename(cert_file_path)} missing validity fields")
            return False
        
        # Create backup
        backup_path = cert_file_path + '.backup'
        shutil.copy2(cert_file_path, backup_path)
        
        # Move validity fields into validity object
        validity = {
            'not_before': certificate.pop('not_before'),
            'not_after': certificate.pop('not_after')
        }
        certificate['validity'] = validity
        
        # Write updated certificate
        with open(cert_file_path, 'w') as f:
            json.dump(cert_data, f, indent=2)
        
        print(f"✓ Fixed {os.path.basename(cert_file_path)}")
        return True
        
    except Exception as e:
        print(f"✗ Error fixing {os.path.basename(cert_file_path)}: {e}")
        return False


def fix_ca_structure(ca_file_path):
    """Fix the structure of a single CA file."""
    try:
        # Read the CA file
        with open(ca_file_path, 'r') as f:
            ca_data = json.load(f)
        
        certificate = ca_data.get('certificate', {})
        
        # Check if already has correct structure
        if 'validity' in certificate and 'not_after' in certificate['validity']:
            print(f"✓ {os.path.basename(ca_file_path)} already has correct structure")
            return True
        
        # Check if has old structure in certificate object
        if 'not_before' not in certificate or 'not_after' not in certificate:
            print(f"⚠ {os.path.basename(ca_file_path)} missing validity fields")
            return False
        
        # Create backup
        backup_path = ca_file_path + '.backup'
        shutil.copy2(ca_file_path, backup_path)
        
        # Move validity fields into validity object
        validity = {
            'not_before': certificate.pop('not_before'),
            'not_after': certificate.pop('not_after')
        }
        certificate['validity'] = validity
        
        # Write updated CA file
        with open(ca_file_path, 'w') as f:
            json.dump(ca_data, f, indent=2)
        
        print(f"✓ Fixed {os.path.basename(ca_file_path)}")
        return True
        
    except Exception as e:
        print(f"✗ Error fixing {os.path.basename(ca_file_path)}: {e}")
        return False


def main():
    """Main function to fix all certificate and CA files."""
    print("🔧 Fixing certificate validity structure for email notifier compatibility...")
    print()
    
    # Fix certificates
    print("📄 Processing certificates...")
    cert_files = glob.glob('certificates/*.json')
    cert_success = 0
    
    for cert_file in cert_files:
        if fix_certificate_structure(cert_file):
            cert_success += 1
    
    print(f"   Fixed {cert_success}/{len(cert_files)} certificate files")
    print()
    
    # Fix CAs
    print("🏛️ Processing CA files...")
    ca_files = glob.glob('ca/*.json')
    ca_success = 0
    
    for ca_file in ca_files:
        if fix_ca_structure(ca_file):
            ca_success += 1
    
    print(f"   Fixed {ca_success}/{len(ca_files)} CA files")
    print()
    
    total_files = len(cert_files) + len(ca_files)
    total_success = cert_success + ca_success
    
    print(f"✅ Summary: Successfully fixed {total_success}/{total_files} files")
    
    if total_success > 0:
        print()
        print("📝 Note: Backup files (.backup) have been created for all modified files")
        print("🔍 You can now test the email notifier - it should no longer show 'Invalid expiry date format' errors")


if __name__ == '__main__':
    main()
