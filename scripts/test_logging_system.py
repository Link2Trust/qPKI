#!/usr/bin/env python3
"""
qPKI Logging System Demo

This script demonstrates the comprehensive logging system 
that tracks all activity across the qPKI platform.
"""

import sys
import os
import time
from datetime import datetime

# Add the source directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from qpki.logging_config import (
    setup_logging, 
    get_logger, 
    get_web_logger, 
    get_crypto_logger, 
    get_email_logger, 
    get_cli_logger,
    log_activity,
    log_function_call
)

def demo_basic_logging():
    """Demonstrate basic logging functionality."""
    print("🔧 Testing Basic Logging...")
    
    # Setup logging
    logger = setup_logging(log_level="INFO", json_format=False, console_output=True)
    
    # Test different log levels
    logger.debug("This is a DEBUG message")
    logger.info("This is an INFO message")
    logger.warning("This is a WARNING message")
    logger.error("This is an ERROR message")
    
    print("✅ Basic logging test complete")
    print()

def demo_component_loggers():
    """Demonstrate component-specific loggers."""
    print("🏗️ Testing Component Loggers...")
    
    # Get different component loggers
    web_logger = get_web_logger()
    crypto_logger = get_crypto_logger()
    email_logger = get_email_logger()
    cli_logger = get_cli_logger()
    
    # Log from different components
    web_logger.info("Web server started on port 9090")
    crypto_logger.info("Generated new RSA key pair (2048-bit)")
    email_logger.info("Certificate expiry notification sent")
    cli_logger.info("CLI command executed: list-certificates")
    
    print("✅ Component loggers test complete")
    print()

def demo_activity_logging():
    """Demonstrate structured activity logging."""
    print("📊 Testing Activity Logging...")
    
    logger = get_logger()
    
    # Log various activities
    log_activity(logger, "ca_creation", {
        'description': 'Root CA created for development environment',
        'ca_name': 'Dev Root CA',
        'algorithm': 'ECC + Dilithium-2',
        'validity_years': 10,
        'created_by': 'admin'
    })
    
    log_activity(logger, "certificate_issued", {
        'description': 'SSL certificate issued for web server',
        'common_name': 'www.example.com',
        'issuer': 'Dev Root CA',
        'validity_days': 365,
        'key_usage': ['digital_signature', 'key_encipherment']
    })
    
    log_activity(logger, "certificate_revoked", {
        'description': 'Certificate revoked due to key compromise',
        'serial_number': '123456789',
        'reason': 'key_compromise',
        'revoked_by': 'security_admin'
    }, level="WARNING")
    
    log_activity(logger, "system_backup", {
        'description': 'Daily system backup completed',
        'backup_type': 'incremental',
        'files_backed_up': 1547,
        'backup_size_mb': 234,
        'duration_seconds': 120
    })
    
    print("✅ Activity logging test complete")
    print()

@log_function_call
def sample_function(param1, param2="default"):
    """Sample function to demonstrate function call logging."""
    time.sleep(0.1)  # Simulate some work
    return f"Result: {param1} + {param2}"

def demo_function_logging():
    """Demonstrate function call logging."""
    print("🔍 Testing Function Call Logging...")
    
    result = sample_function("test", param2="value")
    print(f"Function returned: {result}")
    
    print("✅ Function logging test complete")
    print()

def demo_error_logging():
    """Demonstrate error and exception logging."""
    print("❌ Testing Error Logging...")
    
    logger = get_logger()
    
    try:
        # Simulate an error
        raise ValueError("This is a simulated error for testing")
    except Exception as e:
        logger.error("An error occurred during certificate processing", exc_info=True)
        
        # Log with additional context
        log_activity(logger, "error_occurred", {
            'description': 'Error during certificate processing',
            'error_type': type(e).__name__,
            'error_message': str(e),
            'operation': 'certificate_validation'
        }, level="ERROR")
    
    print("✅ Error logging test complete")
    print()

def demo_json_logging():
    """Demonstrate JSON format logging."""
    print("📋 Testing JSON Logging...")
    
    # Setup logging with JSON format
    logger = setup_logging(log_level="INFO", json_format=True, console_output=False)
    
    # Log various activities in JSON format
    log_activity(logger, "json_test", {
        'description': 'Testing JSON formatted logging',
        'format': 'JSON',
        'structured': True,
        'parseable': True,
        'metrics': {
            'response_time_ms': 45,
            'memory_usage_mb': 128,
            'cpu_percent': 12.5
        }
    })
    
    logger.info("JSON logging test message")
    
    print("✅ JSON logging test complete (check log file for JSON output)")
    print()

def show_log_file():
    """Show recent log entries."""
    print("📁 Recent Log Entries:")
    print("=" * 60)
    
    log_file = f"logs/qpki_{datetime.now().strftime('%Y%m%d')}.log"
    
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()
            # Show last 10 lines
            for line in lines[-10:]:
                print(line.strip())
    except FileNotFoundError:
        print(f"Log file {log_file} not found")
    
    print("=" * 60)
    print()

def main():
    """Main demo function."""
    print("🚀 qPKI Comprehensive Logging System Demo")
    print("=" * 50)
    print()
    
    # Run all demos
    demo_basic_logging()
    demo_component_loggers()
    demo_activity_logging()
    demo_function_logging()
    demo_error_logging()
    demo_json_logging()
    
    # Show log file contents
    show_log_file()
    
    print("🎉 Logging system demo complete!")
    print()
    print("📊 Key Features Demonstrated:")
    print("  ✅ Centralized logging configuration")
    print("  ✅ Component-specific loggers (web, crypto, email, cli)")
    print("  ✅ Structured activity logging with metadata")
    print("  ✅ Function call logging with parameters")
    print("  ✅ Error logging with stack traces")
    print("  ✅ JSON format logging for parsing")
    print("  ✅ Log rotation and file management")
    print("  ✅ Console and file output")
    print()
    print("🔍 Check the logs/ directory for detailed log files")
    print("📊 All qPKI system activities are now comprehensively logged!")

if __name__ == '__main__':
    main()
