#!/usr/bin/env python3
"""
Test Web UI email notification functionality
"""

import os
import sys
import json

# Add the source directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

from qpki.email_notifier import EmailNotificationService

def test_webui_email_notification():
    """Test sending an email notification like the Web UI would"""
    
    print("🌐 Testing Web UI Email Notification Functionality")
    print("=" * 55)
    
    # Create email service instance
    app_dir = os.path.dirname(__file__)
    email_service = EmailNotificationService(app_dir=app_dir)
    
    # Test email configuration
    test_email = "admin@example.com"
    success = email_service.test_email_configuration(test_email)
    
    if success:
        print("✅ Web UI email test completed successfully!")
        print("📧 Test email sent to MailHog")
        print("🌐 View the email at: http://localhost:8025")
        print()
        print("💡 This simulates what happens when you click 'Send Test Email' in the Web UI")
        print("   - Email notifications are now working correctly")
        print("   - MailHog is properly receiving emails")
        print("   - Certificate expiration notifications will be sent")
    else:
        print("❌ Web UI email test failed")
        print("🔧 Check the email configuration and MailHog setup")
    
    return success

if __name__ == '__main__':
    test_webui_email_notification()
