#!/usr/bin/env python3
"""
qPKI Email Notification System

Handles automatic certificate expiration notifications via email.
Supports configurable notification intervals and customizable email templates.
"""

import os
import json
import smtplib
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from jinja2 import Environment, FileSystemLoader
import sqlite3

# Import centralized logging
try:
    from .logging_config import get_email_logger, log_activity
except ImportError:
    # Fallback in case centralized logging is not available
    get_email_logger = None
    log_activity = None

class EmailNotificationService:
    """Service for sending certificate expiration notifications."""
    
    def __init__(self, config_path: str = None, app_dir: str = None):
        """Initialize the email notification service.
        
        Args:
            config_path: Path to email configuration file
            app_dir: Application root directory
        """
        self.app_dir = app_dir or os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        self.config_path = config_path or os.path.join(self.app_dir, 'config', 'email_config.json')
        self.config = self._load_config()
        self.logger = self._setup_logging()
        self.db_path = os.path.join(self.app_dir, 'notifications.db')
        self._setup_database()
        
        # Setup Jinja2 environment for email templates
        template_dir = os.path.join(self.app_dir, 'templates', 'email')
        self.jinja_env = Environment(loader=FileSystemLoader(template_dir))
    
    def _load_config(self) -> Dict:
        """Load email configuration from JSON file."""
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            self.logger.error(f"Email configuration file not found: {self.config_path}")
            return self._get_default_config()
        except json.JSONDecodeError:
            self.logger.error(f"Invalid JSON in email configuration: {self.config_path}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Get default email configuration."""
        return {
            "enabled": False,
            "test_mode": True,
            "log_notifications": True,
            "notification_intervals": [],
            "email_templates": {}
        }
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for email notifications."""
        logger = logging.getLogger('qpki.email_notifier')
        logger.setLevel(logging.INFO)
        
        # Create file handler
        log_dir = os.path.join(self.app_dir, 'logs')
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, 'email_notifications.log')
        
        handler = logging.FileHandler(log_file)
        handler.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        
        logger.addHandler(handler)
        return logger
    
    def _setup_database(self):
        """Setup SQLite database for tracking sent notifications."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sent_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                certificate_serial TEXT NOT NULL,
                notification_type TEXT NOT NULL,
                email_address TEXT NOT NULL,
                sent_date TEXT NOT NULL,
                days_before_expiry INTEGER NOT NULL,
                UNIQUE(certificate_serial, notification_type, email_address)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _has_notification_been_sent(self, cert_serial: str, notification_type: str, email: str) -> bool:
        """Check if a notification has already been sent."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) FROM sent_notifications 
            WHERE certificate_serial = ? AND notification_type = ? AND email_address = ?
        ''', (cert_serial, notification_type, email))
        
        count = cursor.fetchone()[0]
        conn.close()
        
        return count > 0
    
    def _record_notification_sent(self, cert_serial: str, notification_type: str, 
                                email: str, days_before_expiry: int):
        """Record that a notification has been sent."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO sent_notifications 
                (certificate_serial, notification_type, email_address, sent_date, days_before_expiry)
                VALUES (?, ?, ?, ?, ?)
            ''', (cert_serial, notification_type, email, 
                  datetime.now(timezone.utc).isoformat(), days_before_expiry))
            
            conn.commit()
        except sqlite3.Error as e:
            self.logger.error(f"Error recording notification: {e}")
        finally:
            conn.close()
    
    def _send_email(self, to_email: str, subject: str, html_body: str, text_body: str) -> bool:
        """Send an email using SMTP."""
        if not self.config.get('enabled', False):
            self.logger.info(f"Email disabled - would send to {to_email}: {subject}")
            return False
        
        if self.config.get('test_mode', True):
            self.logger.info(f"TEST MODE - Email to {to_email}: {subject}")
            self.logger.info(f"Body: {text_body[:200]}...")
            return True
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{self.config.get('from_name', 'qPKI')} <{self.config.get('from_email')}>"
            msg['To'] = to_email
            
            # Attach parts
            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))
            
            # Connect to SMTP server
            server = smtplib.SMTP(self.config.get('smtp_server'), self.config.get('smtp_port', 587))
            
            if self.config.get('smtp_security') == 'TLS':
                server.starttls()
            
            # Login if credentials provided
            username = self.config.get('smtp_username')
            password = self.config.get('smtp_password')
            if username and password:
                server.login(username, password)
            
            # Send email
            text = msg.as_string()
            server.sendmail(self.config.get('from_email'), to_email, text)
            server.quit()
            
            self.logger.info(f"Email sent successfully to {to_email}: {subject}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send email to {to_email}: {e}")
            return False
    
    def _render_email_template(self, template_name: str, context: Dict) -> Tuple[str, str]:
        """Render email template with context data."""
        template_config = self.config.get('email_templates', {}).get(template_name, {})
        
        # Render HTML template
        html_body = ""
        html_template_path = template_config.get('html')
        if html_template_path:
            try:
                html_template = self.jinja_env.get_template(os.path.basename(html_template_path))
                html_body = html_template.render(**context)
            except Exception as e:
                self.logger.error(f"Error rendering HTML template {html_template_path}: {e}")
        
        # Render text template
        text_body = ""
        text_template_path = template_config.get('text')
        if text_template_path:
            try:
                text_template = self.jinja_env.get_template(os.path.basename(text_template_path))
                text_body = text_template.render(**context)
            except Exception as e:
                self.logger.error(f"Error rendering text template {text_template_path}: {e}")
        
        # Fallback if templates not found
        if not html_body and not text_body:
            text_body = self._generate_default_text_body(context)
            html_body = self._generate_default_html_body(context)
        
        return html_body, text_body
    
    def _generate_default_text_body(self, context: Dict) -> str:
        """Generate default text email body."""
        cert_name = context.get('certificate_name', 'Unknown')
        days_left = context.get('days_until_expiry', 0)
        expiry_date = context.get('expiry_date', 'Unknown')
        
        if days_left > 0:
            return f"""
Certificate Expiration Notification

Certificate: {cert_name}
Days until expiry: {days_left}
Expiration date: {expiry_date}

Please renew this certificate before it expires to avoid service interruption.

This is an automated message from qPKI.
"""
        else:
            return f"""
Certificate Expired Notification

Certificate: {cert_name}
Expiration date: {expiry_date}

This certificate has expired. Please renew it immediately to restore service.

This is an automated message from qPKI.
"""
    
    def _generate_default_html_body(self, context: Dict) -> str:
        """Generate default HTML email body."""
        cert_name = context.get('certificate_name', 'Unknown')
        days_left = context.get('days_until_expiry', 0)
        expiry_date = context.get('expiry_date', 'Unknown')
        urgency_color = "red" if days_left <= 7 else "orange" if days_left <= 30 else "blue"
        
        if days_left > 0:
            return f"""
<html>
<body>
    <h2 style="color: {urgency_color};">Certificate Expiration Notification</h2>
    <p><strong>Certificate:</strong> {cert_name}</p>
    <p><strong>Days until expiry:</strong> <span style="color: {urgency_color}; font-weight: bold;">{days_left}</span></p>
    <p><strong>Expiration date:</strong> {expiry_date}</p>
    
    <p>Please renew this certificate before it expires to avoid service interruption.</p>
    
    <hr>
    <p><em>This is an automated message from qPKI.</em></p>
</body>
</html>
"""
        else:
            return f"""
<html>
<body>
    <h2 style="color: red;">Certificate Expired Notification</h2>
    <p><strong>Certificate:</strong> {cert_name}</p>
    <p><strong>Expiration date:</strong> {expiry_date}</p>
    
    <p style="color: red; font-weight: bold;">This certificate has expired. Please renew it immediately to restore service.</p>
    
    <hr>
    <p><em>This is an automated message from qPKI.</em></p>
</body>
</html>
"""
    
    def check_and_send_notifications(self, certificates_dir: str) -> Dict:
        """Check all certificates and send expiration notifications."""
        results = {
            'checked': 0,
            'notifications_sent': 0,
            'errors': 0,
            'skipped': 0
        }
        
        if not self.config.get('enabled', False) and not self.config.get('test_mode', False):
            self.logger.info("Email notifications disabled")
            return results
        
        for filename in os.listdir(certificates_dir):
            if not filename.endswith('.json'):
                continue
            
            results['checked'] += 1
            
            try:
                filepath = os.path.join(certificates_dir, filename)
                with open(filepath, 'r') as f:
                    cert_data = json.load(f)
                
                notification_result = self._check_certificate_for_notifications(cert_data, filename)
                results['notifications_sent'] += notification_result.get('sent', 0)
                results['errors'] += notification_result.get('errors', 0)
                results['skipped'] += notification_result.get('skipped', 0)
                
            except Exception as e:
                self.logger.error(f"Error processing certificate {filename}: {e}")
                results['errors'] += 1
        
        self.logger.info(f"Notification check complete: {results}")
        return results
    
    def _check_certificate_for_notifications(self, cert_data: Dict, filename: str) -> Dict:
        """Check a single certificate for expiration notifications."""
        result = {'sent': 0, 'errors': 0, 'skipped': 0}
        
        certificate = cert_data.get('certificate', cert_data)
        
        # Skip if certificate is revoked
        if cert_data.get('revoked'):
            result['skipped'] += 1
            return result
        
        # Get certificate info
        subject = certificate.get('subject', {})
        email_address = subject.get('email')
        
        if not email_address:
            self.logger.warning(f"No email address found for certificate {filename}")
            result['skipped'] += 1
            return result
        
        # Parse expiry date
        validity = certificate.get('validity', {})
        not_after_str = validity.get('not_after', '')
        
        try:
            # Handle different date formats properly
            if not_after_str:
                # If already has timezone info, just remove trailing Z if present
                if '+' in not_after_str or '-' in not_after_str[-6:]:
                    if not_after_str.endswith('Z'):
                        not_after_str = not_after_str[:-1]
                elif not_after_str.endswith('Z'):
                    # Only Z at the end, replace with UTC offset
                    not_after_str = not_after_str.replace('Z', '+00:00')
                
                not_after = datetime.fromisoformat(not_after_str)
            else:
                self.logger.error(f"Empty expiry date in {filename}")
                result['errors'] += 1
                return result
        except Exception as e:
            self.logger.error(f"Invalid expiry date format in {filename}: {not_after_str} - {e}")
            result['errors'] += 1
            return result
        
        # Calculate days until expiry
        now = datetime.now(timezone.utc)
        days_until_expiry = (not_after - now).days
        
        # Check each notification interval (sorted by days_before_expiry in descending order)
        intervals = sorted(self.config.get('notification_intervals', []), 
                          key=lambda x: x.get('days_before_expiry', 0), reverse=True)
        
        for interval in intervals:
            if not interval.get('enabled', True):
                continue
            
            target_days = interval.get('days_before_expiry', 0)
            notification_type = interval.get('name', 'unknown')
            
            # Check if notification already sent for this type
            if self._has_notification_been_sent(certificate.get('serial_number', filename), 
                                                notification_type, email_address):
                continue
            
            # Check if we should send notification for this interval
            should_send = False
            if target_days == 0:
                # For expiry day notifications, send if certificate has expired or expires today
                should_send = days_until_expiry <= 0
            else:
                # For advance notifications, send if we're at or past the notification point
                # but haven't sent a more urgent notification yet
                should_send = days_until_expiry <= target_days
                
                # Don't send if we've already sent a more urgent notification
                for other_interval in intervals:
                    if other_interval == interval:
                        break
                    other_target = other_interval.get('days_before_expiry', 0)
                    other_type = other_interval.get('name', 'unknown')
                    if (other_target < target_days and 
                        self._has_notification_been_sent(certificate.get('serial_number', filename), 
                                                         other_type, email_address)):
                        should_send = False
                        break
            
            if should_send:
                notification_sent = self._send_certificate_notification(
                    cert_data, filename, interval, email_address, days_until_expiry
                )
                
                if notification_sent:
                    result['sent'] += 1
                    # Only send one notification per run to avoid spam
                    break
                else:
                    result['errors'] += 1
        
        return result
    
    def _send_certificate_notification(self, cert_data: Dict, filename: str, 
                                     interval: Dict, email_address: str, 
                                     days_until_expiry: int) -> bool:
        """Send a certificate expiration notification."""
        certificate = cert_data.get('certificate', cert_data)
        serial_number = certificate.get('serial_number', filename)
        notification_type = interval.get('name', 'unknown')
        
        # Check if notification already sent
        if self._has_notification_been_sent(serial_number, notification_type, email_address):
            self.logger.debug(f"Notification {notification_type} already sent for {serial_number}")
            return False
        
        # Prepare template context
        subject_info = certificate.get('subject', {})
        validity = certificate.get('validity', {})
        
        context = {
            'certificate_name': subject_info.get('common_name', 'Unknown Certificate'),
            'certificate_organization': subject_info.get('organization', ''),
            'certificate_email': email_address,
            'serial_number': serial_number,
            'days_until_expiry': days_until_expiry,
            'expiry_date': validity.get('not_after', 'Unknown'),
            'issue_date': validity.get('not_before', 'Unknown'),
            'issuer_name': certificate.get('issuer', {}).get('common_name', 'Unknown CA'),
            'certificate_filename': filename,
            'notification_type': notification_type,
            'urgency_level': self._get_urgency_level(days_until_expiry)
        }
        
        # Render email templates
        template_name = interval.get('template', 'default')
        html_body, text_body = self._render_email_template(template_name, context)
        
        # Send email
        subject = interval.get('subject', f'Certificate Expiration Notice - {days_until_expiry} days')
        success = self._send_email(email_address, subject, html_body, text_body)
        
        if success:
            # Record notification as sent
            self._record_notification_sent(
                serial_number, notification_type, email_address, 
                interval.get('days_before_expiry', 0)
            )
            
            self.logger.info(
                f"Sent {notification_type} notification for certificate {serial_number} "
                f"to {email_address} ({days_until_expiry} days until expiry)"
            )
        
        return success
    
    def _get_urgency_level(self, days_until_expiry: int) -> str:
        """Get urgency level based on days until expiry."""
        if days_until_expiry <= 0:
            return "CRITICAL"
        elif days_until_expiry <= 7:
            return "HIGH"
        elif days_until_expiry <= 30:
            return "MEDIUM"
        else:
            return "LOW"
    
    def test_email_configuration(self, test_email: str) -> bool:
        """Test email configuration by sending a test email."""
        context = {
            'certificate_name': 'Test Certificate',
            'certificate_organization': 'qPKI Test',
            'certificate_email': test_email,
            'serial_number': '12345',
            'days_until_expiry': 30,
            'expiry_date': '2024-12-31T23:59:59Z',
            'issue_date': '2024-01-01T00:00:00Z',
            'issuer_name': 'Test CA',
            'certificate_filename': 'test.json',
            'notification_type': 'test',
            'urgency_level': 'LOW'
        }
        
        html_body, text_body = self._render_email_template('cert_expiry_30days', context)
        if not html_body and not text_body:
            html_body = self._generate_default_html_body(context)
            text_body = self._generate_default_text_body(context)
        
        subject = "qPKI Email Configuration Test"
        return self._send_email(test_email, subject, html_body, text_body)
    
    def update_config(self, new_config: Dict) -> bool:
        """Update email configuration."""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(new_config, f, indent=2)
            
            self.config = new_config
            self.logger.info("Email configuration updated successfully")
            return True
        except Exception as e:
            self.logger.error(f"Failed to update email configuration: {e}")
            return False
    
    def get_notification_history(self, limit: int = 100) -> List[Dict]:
        """Get notification history from database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT certificate_serial, notification_type, email_address, 
                   sent_date, days_before_expiry
            FROM sent_notifications 
            ORDER BY sent_date DESC 
            LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                'certificate_serial': row[0],
                'notification_type': row[1],
                'email_address': row[2],
                'sent_date': row[3],
                'days_before_expiry': row[4]
            }
            for row in rows
        ]


def main():
    """Command line interface for email notification service."""
    import argparse
    
    parser = argparse.ArgumentParser(description='qPKI Email Notification Service')
    parser.add_argument('--config', help='Path to email configuration file')
    parser.add_argument('--certificates', help='Path to certificates directory', 
                       default='/Users/GitHub/Link2Trust/qPKI/certificates')
    parser.add_argument('--test-email', help='Send a test email to this address')
    parser.add_argument('--check-now', action='store_true', 
                       help='Check all certificates and send notifications')
    parser.add_argument('--history', action='store_true', 
                       help='Show notification history')
    
    args = parser.parse_args()
    
    service = EmailNotificationService(config_path=args.config)
    
    if args.test_email:
        print(f"Sending test email to {args.test_email}...")
        success = service.test_email_configuration(args.test_email)
        print(f"Test email {'sent successfully' if success else 'failed'}")
    
    elif args.check_now:
        print("Checking certificates for expiration notifications...")
        results = service.check_and_send_notifications(args.certificates)
        print(f"Results: {results}")
    
    elif args.history:
        print("Notification history:")
        history = service.get_notification_history()
        for record in history:
            print(f"  {record['sent_date']}: {record['notification_type']} -> {record['email_address']} "
                  f"(cert: {record['certificate_serial'][:8]}...)")
    
    else:
        print("No action specified. Use --help for options.")


if __name__ == '__main__':
    main()
