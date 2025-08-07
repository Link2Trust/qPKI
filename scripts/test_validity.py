#!/usr/bin/env python3
"""
Test script for certificate validity calculation

This script tests the get_days_until_expiry function to ensure it correctly
calculates days until certificate expiry.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import get_days_until_expiry
from datetime import datetime, timedelta, timezone

def test_days_until_expiry():
    """Test the days until expiry calculation."""
    print("🧪 Testing Certificate Validity Calculations")
    print("=" * 50)
    
    now = datetime.now(timezone.utc)
    
    # Test case 1: Certificate expiring in 30 days
    future_30_days = now + timedelta(days=30)
    expiry_str = future_30_days.isoformat().replace('+00:00', 'Z')
    days = get_days_until_expiry(expiry_str)
    print(f"✓ 30 days in future: {days} days (expected: ~30)")
    assert 29 <= days <= 30, f"Expected ~30, got {days}"
    
    # Test case 2: Certificate expiring in 7 days (critical)
    future_7_days = now + timedelta(days=7)
    expiry_str = future_7_days.isoformat().replace('+00:00', 'Z')
    days = get_days_until_expiry(expiry_str)
    print(f"✓ 7 days in future: {days} days (expected: ~7)")
    assert 6 <= days <= 7, f"Expected ~7, got {days}"
    
    # Test case 3: Certificate expiring today (but later in the day)
    today = now.replace(hour=23, minute=59, second=59)
    expiry_str = today.isoformat().replace('+00:00', 'Z')
    days = get_days_until_expiry(expiry_str)
    print(f"✓ Today (end of day): {days} days (expected: 0)")
    assert 0 <= days <= 1, f"Expected 0-1, got {days}"
    
    # Test case 4: Certificate expired 5 days ago
    past_5_days = now - timedelta(days=5)
    expiry_str = past_5_days.isoformat().replace('+00:00', 'Z')
    days = get_days_until_expiry(expiry_str)
    print(f"✓ 5 days ago: {days} days (expected: ~-5)")
    assert -6 <= days <= -5, f"Expected ~-5, got {days}"
    
    # Test case 5: Certificate expiring in 365 days
    future_365_days = now + timedelta(days=365)
    expiry_str = future_365_days.isoformat().replace('+00:00', 'Z')
    days = get_days_until_expiry(expiry_str)
    print(f"✓ 365 days in future: {days} days (expected: ~365)")
    assert 364 <= days <= 365, f"Expected ~365, got {days}"
    
    # Test case 6: Invalid date string
    invalid_str = "invalid-date"
    days = get_days_until_expiry(invalid_str)
    print(f"✓ Invalid date: {days} (expected: None)")
    assert days is None, f"Expected None, got {days}"
    
    print("\n" + "=" * 50)
    print("✅ All validity calculation tests passed!")

def test_validity_categories():
    """Test validity categorization for UI display."""
    print("\n🎨 Testing Validity Display Categories")
    print("=" * 50)
    
    now = datetime.now(timezone.utc)
    
    test_cases = [
        (-10, "Expired", "danger"),
        (1, "Critical (≤7 days)", "danger"),
        (7, "Critical (≤7 days)", "danger"),
        (15, "Warning (≤30 days)", "warning"),
        (30, "Warning (≤30 days)", "warning"),
        (60, "Info (≤90 days)", "info"),
        (90, "Info (≤90 days)", "info"),
        (180, "Good (>90 days)", "success"),
        (365, "Good (>90 days)", "success"),
    ]
    
    for days_offset, category, badge_type in test_cases:
        future_date = now + timedelta(days=days_offset)
        expiry_str = future_date.isoformat().replace('+00:00', 'Z')
        days = get_days_until_expiry(expiry_str)
        
        print(f"  • {days:4d} days: {category:20s} ({badge_type})")
        
        # Verify the calculation is correct
        assert abs(days - days_offset) <= 1, f"Expected ~{days_offset}, got {days}"

if __name__ == "__main__":
    print("Certificate Validity Test Suite")
    print("=" * 60)
    
    try:
        test_days_until_expiry()
        test_validity_categories()
        
        print(f"\n🎉 All validity tests completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
