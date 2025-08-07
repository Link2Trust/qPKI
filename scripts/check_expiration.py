#!/usr/bin/env python3
"""
qPKI Certificate Expiration Checker Script

This script can be run as a scheduled task (cron job) to automatically
check certificate expiration and send email notifications.

Usage:
  python check_expiration.py [--config CONFIG_PATH] [--certs CERTS_DIR]

Example cron entry (check daily at 9 AM):
  0 9 * * * /usr/bin/python3 /path/to/qPKI/scripts/check_expiration.py
"""

import os
import sys
import argparse
import logging
from datetime import datetime

# Add qPKI source directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
qpki_dir = os.path.dirname(script_dir)
sys.path.insert(0, os.path.join(qpki_dir, 'src'))

from qpki.email_notifier import EmailNotificationService

def setup_logging(log_dir):
    """Setup logging for the scheduled task."""
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, 'expiration_check.log')
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    return logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(
        description='qPKI Certificate Expiration Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Check certificates with default configuration:
    python check_expiration.py

  Use custom configuration and certificate directory:
    python check_expiration.py --config /path/to/config.json --certs /path/to/certificates

  Dry run (test mode only):
    python check_expiration.py --dry-run
"""
    )
    
    parser.add_argument(
        '--config', 
        help='Path to email configuration file',
        default=None
    )
    
    parser.add_argument(
        '--certs', 
        help='Path to certificates directory',
        default=os.path.join(qpki_dir, 'certificates')
    )
    
    parser.add_argument(
        '--dry-run', 
        action='store_true',
        help='Enable test mode (log only, don\'t send emails)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    log_dir = os.path.join(qpki_dir, 'logs')
    logger = setup_logging(log_dir)
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    logger.info("Starting qPKI certificate expiration check")
    logger.info(f"Certificate directory: {args.certs}")
    logger.info(f"Configuration: {args.config or 'default'}")
    logger.info(f"Dry run mode: {args.dry_run}")
    
    try:
        # Initialize email notification service
        email_service = EmailNotificationService(
            config_path=args.config,
            app_dir=qpki_dir
        )
        
        # Force test mode if dry-run requested
        if args.dry_run:
            original_test_mode = email_service.config.get('test_mode', True)
            email_service.config['test_mode'] = True
            logger.info("Dry run mode enabled - no emails will be sent")
        
        # Check if email notifications are enabled
        if not email_service.config.get('enabled', False):
            logger.warning("Email notifications are disabled in configuration")
            if not args.dry_run:
                logger.info("Exiting without checking certificates")
                return 0
        
        # Check certificates directory exists
        if not os.path.isdir(args.certs):
            logger.error(f"Certificate directory does not exist: {args.certs}")
            return 1
        
        # Count certificates
        cert_files = [f for f in os.listdir(args.certs) if f.endswith('.json')]
        logger.info(f"Found {len(cert_files)} certificate files")
        
        if len(cert_files) == 0:
            logger.info("No certificates found - nothing to check")
            return 0
        
        # Perform the check
        logger.info("Checking certificates for expiration notifications...")
        results = email_service.check_and_send_notifications(args.certs)
        
        # Log results
        logger.info(f"Check completed successfully:")
        logger.info(f"  - Certificates checked: {results['checked']}")
        logger.info(f"  - Notifications sent: {results['notifications_sent']}")
        logger.info(f"  - Certificates skipped: {results['skipped']}")
        logger.info(f"  - Errors encountered: {results['errors']}")
        
        # Log individual notifications if in verbose mode
        if args.verbose and results['notifications_sent'] > 0:
            logger.info("Recent notifications:")
            history = email_service.get_notification_history(10)
            for record in history:
                logger.info(f"  - {record['sent_date']}: {record['notification_type']} -> {record['email_address']}")
        
        # Return appropriate exit code
        return 1 if results['errors'] > 0 else 0
        
    except Exception as e:
        logger.error(f"Unexpected error during certificate check: {e}")
        logger.debug("Full error details:", exc_info=True)
        return 1

if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
