#!/usr/bin/env python3
"""
Test script to verify the date parsing fix for email notifications.

This tests the scenarios that were causing the original AttributeError.
"""

import sys
import os
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

def test_date_parsing():
    """Test the date parsing logic that was fixed in email_notifier.py"""
    
    test_dates = [
        "2024-12-31T23:59:59Z",                    # Normal Z format
        "2024-12-31T23:59:59+00:00Z",              # Timezone + Z (invalid format that was causing issues)
        "2024-12-31T23:59:59-05:00Z",              # Different timezone + Z
        "2024-12-31T23:59:59+00:00",               # Normal timezone format
        "2024-12-31T23:59:59-05:00",               # Different timezone format
    ]
    
    for date_str in test_dates:
        print(f"Testing date: {date_str}")
        
        try:
            # Apply the same logic from the fixed email_notifier.py
            not_after_str = date_str
            
            if not_after_str.endswith('Z'):
                # Check if there's already timezone info before the Z
                if '+' in not_after_str[:-1] or (len(not_after_str) > 6 and '-' in not_after_str[-7:-1]):
                    # Remove trailing Z if timezone already present
                    not_after_str = not_after_str[:-1]
                    print(f"  → Fixed format: {not_after_str}")
                else:
                    # Replace Z with UTC offset if no timezone info
                    not_after_str = not_after_str.replace('Z', '+00:00')
                    print(f"  → Fixed format: {not_after_str}")
            
            # Parse the date
            parsed_date = datetime.fromisoformat(not_after_str)
            print(f"  ✓ Successfully parsed: {parsed_date}")
            
        except Exception as e:
            print(f"  ✗ Failed to parse: {e}")
        
        print()

if __name__ == "__main__":
    print("Testing date parsing fix for email notifications\n")
    print("=" * 50)
    test_date_parsing()
    print("=" * 50)
    print("Date parsing test completed!")
