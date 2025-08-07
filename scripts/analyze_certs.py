#!/usr/bin/env python3
"""
Certificate Analysis Script

This script analyzes certificates to check expiry dates, email addresses,
and notification eligibility.
"""

import sys
import os
import json
from datetime import datetime, timezone
import glob

def analyze_certificates():
    """Analyze all certificates for expiry and email information."""
    cert_dir = os.path.join(os.path.dirname(__file__), '..', 'certificates')
    cert_files = glob.glob(os.path.join(cert_dir, '*.json'))
    
    print("🔍 Certificate Analysis")
    print("=" * 60)
    
    for cert_file in sorted(cert_files):
        filename = os.path.basename(cert_file)
        
        try:
            with open(cert_file, 'r') as f:
                cert_data = json.load(f)
            
            cert = cert_data.get('certificate', cert_data)
            subject = cert.get('subject', {})
            validity = cert.get('validity', {})
            
            common_name = subject.get('common_name', 'Unknown')
            email = subject.get('email', None)
            not_after = validity.get('not_after', 'Unknown')
            
            print(f"\n📄 {filename}")
            print(f"   CN: {common_name}")
            print(f"   Email: {email or 'NO EMAIL'}")
            
            if not_after != 'Unknown':
                try:
                    expiry_date = datetime.fromisoformat(not_after.replace('Z', '+00:00'))
                    now = datetime.now(timezone.utc)
                    days_until_expiry = (expiry_date - now).days
                    
                    print(f"   Expires: {not_after}")
                    print(f"   Days until expiry: {days_until_expiry}")
                    
                    # Check notification eligibility
                    if email:
                        if days_until_expiry <= 90 and days_until_expiry >= -30:
                            print(f"   📧 ELIGIBLE for notifications (has email, expires in {days_until_expiry} days)")
                        else:
                            print(f"   ⏰ Outside notification window ({days_until_expiry} days)")
                    else:
                        print(f"   ❌ NOT ELIGIBLE (no email address)")
                        
                except Exception as e:
                    print(f"   ❌ Error parsing expiry date: {e}")
            else:
                print(f"   ❌ No expiry date found")
                
        except Exception as e:
            print(f"   ❌ Error reading certificate: {e}")

if __name__ == "__main__":
    analyze_certificates()
