# Email Notification System

The qPKI email notification system automatically monitors certificate expiration dates and sends timely reminders to certificate owners. This comprehensive guide covers setup, configuration, automation, and troubleshooting.

## 🎯 Overview

### Key Features
- **Multi-interval notifications**: Configurable alerts at 90, 60, 30, 14, 7, and 1 days before expiration
- **Post-expiration alerts**: Immediate notification when certificates expire
- **Duplicate prevention**: Automatic tracking prevents sending duplicate notifications
- **Professional templates**: Rich HTML and plain text email formats
- **Test mode**: Safe configuration testing without sending actual emails
- **Comprehensive logging**: Detailed logs for monitoring and troubleshooting

### How It Works
```
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│   Certificate   │───▶│  Expiration  │───▶│ Email Reminder  │
│   Database      │    │   Monitor    │    │   Service       │
└─────────────────┘    └──────────────┘    └─────────────────┘
         │                       │                    │
         ▼                       ▼                    ▼
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│  Check Validity │    │  Determine   │    │  Send Email &   │
│  & Parse Dates  │    │ Notification │    │  Track Status   │
└─────────────────┘    └──────────────┘    └─────────────────┘
```

---

## 🚀 Quick Setup

### Prerequisites
- ✅ qPKI system installed and running
- ✅ Certificates with email addresses in subject fields
- ✅ Access to SMTP server (Gmail, Outlook, or corporate mail server)
- ✅ Web interface access for configuration

### 5-Minute Setup
1. **Navigate to Notifications**: `http://localhost:9090/notifications`
2. **Enable Test Mode**: Toggle "Test Mode" ON (for initial setup)
3. **Configure SMTP**:
   ```
   SMTP Server: smtp.gmail.com
   SMTP Port: 587
   Security: TLS
   Username: your-email@gmail.com
   Password: your-app-password
   ```
4. **Set From Address**: `noreply@yourcompany.com`
5. **Enable Notifications**: Toggle "Enabled" ON
6. **Test Configuration**: Send test email to verify setup
7. **Schedule Automatic Checks**: Set up cron job for daily checking

---

## ⚙️ SMTP Configuration

### Popular Email Providers

#### Gmail Configuration
```json
{
  "smtp_server": "smtp.gmail.com",
  "smtp_port": 587,
  "smtp_security": "TLS",
  "smtp_username": "your-email@gmail.com",
  "smtp_password": "your-app-password",
  "from_email": "noreply@yourcompany.com",
  "from_name": "qPKI Certificate Notifications"
}
```

**Gmail Setup Steps**:
1. **Enable 2-Factor Authentication** on your Google account
2. **Generate App Password**: Google Account → Security → 2-Step Verification → App passwords
3. **Use App Password**: Not your regular Gmail password

#### Microsoft Outlook/Office 365
```json
{
  "smtp_server": "smtp.live.com",
  "smtp_port": 587,
  "smtp_security": "TLS",
  "smtp_username": "your-email@outlook.com",
  "smtp_password": "your-password"
}
```

#### Corporate Exchange Server
```json
{
  "smtp_server": "mail.yourcompany.com",
  "smtp_port": 587,
  "smtp_security": "TLS",
  "smtp_username": "qpki-notifications@yourcompany.com",
  "smtp_password": "secure-password"
}
```

#### SendGrid (Production Recommended)
```json
{
  "smtp_server": "smtp.sendgrid.net",
  "smtp_port": 587,
  "smtp_security": "TLS",
  "smtp_username": "apikey",
  "smtp_password": "your-sendgrid-api-key"
}
```

### Security Considerations

#### SMTP Security Options
- **TLS (Recommended)**: Encrypted connection, port 587
- **SSL**: Encrypted connection, port 465
- **None**: Unencrypted (only for testing/internal networks)

#### Best Practices
- **Use dedicated email account** for qPKI notifications
- **Enable app-specific passwords** when available
- **Store passwords securely** (environment variables in production)
- **Test connectivity** before relying on notifications
- **Monitor delivery rates** to ensure emails reach recipients

---

## 📅 Notification Intervals

### Default Schedule
The system sends notifications at these intervals before certificate expiration:

| Interval | Purpose | Email Subject | Urgency Level |
|----------|---------|---------------|---------------|
| **90 days** | Early planning notice | Certificate Expiration Notice - 90 Days | LOW |
| **60 days** | Begin renewal process | Certificate Expiration Warning - 60 Days | LOW |
| **30 days** | Renewal reminder | Certificate Expiration Warning - 30 Days | MEDIUM |
| **14 days** | Urgent action required | Certificate Expiration Alert - 14 Days | MEDIUM |
| **7 days** | Critical alert | URGENT: Certificate Expiring in 7 Days | HIGH |
| **1 day** | Final warning | CRITICAL: Certificate Expires Tomorrow | HIGH |
| **0 days** | Expiration notice | EXPIRED: Certificate Expired Today | CRITICAL |

### Customizing Intervals

#### Via Web Interface
1. **Navigate** to `Notifications` settings
2. **Scroll to Notification Intervals** section
3. **Configure each interval**:
   - Enable/disable individual intervals
   - Customize email subjects
   - Select email templates
4. **Save configuration**

#### Via Configuration File
```json
{
  "notification_intervals": [
    {
      "name": "90_days_before",
      "days_before_expiry": 90,
      "enabled": true,
      "subject": "Certificate Expiration Notice - 90 Days",
      "template": "cert_expiry_90days"
    },
    {
      "name": "custom_interval",
      "days_before_expiry": 45,
      "enabled": true,
      "subject": "Custom 45-Day Notice",
      "template": "cert_expiry_30days"
    }
  ]
}
```

### Notification Logic

#### Smart Duplicate Prevention
- **Database tracking**: Each notification type is tracked per certificate
- **No duplicate emails**: Same notification type never sent twice
- **Progressive urgency**: Only sends more urgent notifications as expiry approaches

#### Example Timeline
```
Certificate expires in 89 days:
├── Day 1: Send "90_days_before" notification ✅
├── Day 2-30: No notifications (90-day already sent)
├── Day 31: Send "60_days_before" notification ✅
├── Day 32-60: No notifications (60-day already sent)
├── Day 61: Send "30_days_before" notification ✅
└── Continue pattern...
```

---

## 🔄 Automation & Scheduling

### Setting Up Automatic Checking

#### Recommended: Daily Cron Job
```bash
# Edit crontab
crontab -e

# Add daily check at 9:00 AM
0 9 * * * /usr/bin/python3 /path/to/qPKI/scripts/check_expiration.py

# Verify cron job is added
crontab -l
```

#### Production: Multiple Daily Checks
```bash
# Check twice daily (9 AM and 9 PM)
0 9,21 * * * /usr/bin/python3 /path/to/qPKI/scripts/check_expiration.py

# Business hours checking (every 4 hours, weekdays only)
0 9,13,17 * * 1-5 /usr/bin/python3 /path/to/qPKI/scripts/check_expiration.py
```

#### Development: Frequent Testing
```bash
# Every hour during business hours (testing only)
0 9-17 * * 1-5 /usr/bin/python3 /path/to/qPKI/scripts/check_expiration.py --dry-run
```

### Manual Checking

#### Web Interface
1. **Navigate** to `Notifications`
2. **Click** "Check Certificates Now"
3. **Review results** in notification history
4. **Check logs** for detailed information

#### Command Line
```bash
# Basic check (uses configuration file settings)
python3 scripts/check_expiration.py

# Dry run (test mode, no emails sent)
python3 scripts/check_expiration.py --dry-run

# Verbose output
python3 scripts/check_expiration.py --dry-run --verbose

# Custom certificate directory
python3 scripts/check_expiration.py --certs /path/to/certificates

# Custom configuration file
python3 scripts/check_expiration.py --config /path/to/email_config.json
```

---

## 📧 Email Templates

### Template System
The notification system uses Jinja2 templating engine for customizable email content.

#### Available Variables
```python
Template Variables:
├── certificate_name: Common name (e.g., "www.example.com")
├── certificate_organization: Organization name
├── certificate_email: Contact email address
├── serial_number: Certificate serial number
├── days_until_expiry: Days remaining (integer)
├── expiry_date: Full expiration date/time
├── issue_date: Certificate issue date
├── issuer_name: Name of issuing CA
├── certificate_filename: Certificate file name
├── notification_type: Notification type (e.g., "30_days_before")
└── urgency_level: LOW/MEDIUM/HIGH/CRITICAL
```

### Default Email Templates

#### 30-Day Notice Example
```html
<!DOCTYPE html>
<html>
<head>
    <title>Certificate Expiration Notice</title>
</head>
<body>
    <h2 style="color: orange;">Certificate Expiration Warning</h2>
    <p>Dear {{ certificate_organization }},</p>
    
    <p>Your certificate is scheduled to expire in <strong>{{ days_until_expiry }} days</strong>.</p>
    
    <table>
        <tr><td><strong>Certificate Name:</strong></td><td>{{ certificate_name }}</td></tr>
        <tr><td><strong>Expiration Date:</strong></td><td>{{ expiry_date[:19] }}</td></tr>
        <tr><td><strong>Serial Number:</strong></td><td>{{ serial_number }}</td></tr>
        <tr><td><strong>Issued By:</strong></td><td>{{ issuer_name }}</td></tr>
    </table>
    
    <p style="color: orange; font-weight: bold;">
        Action Required: Please renew this certificate before it expires to avoid service disruption.
    </p>
    
    <hr>
    <p><em>This is an automated message from qPKI Certificate Management System.</em></p>
</body>
</html>
```

#### Critical Warning Example
```html
<!DOCTYPE html>
<html>
<head>
    <title>CRITICAL: Certificate Expires Tomorrow</title>
</head>
<body>
    <h1 style="color: red;">🚨 CRITICAL ALERT 🚨</h1>
    <h2 style="color: red;">Certificate Expires in {{ days_until_expiry }} Day(s)</h2>
    
    <div style="border: 2px solid red; padding: 15px; background-color: #ffe6e6;">
        <p><strong>Certificate:</strong> {{ certificate_name }}</p>
        <p><strong>Expires:</strong> {{ expiry_date[:19] }}</p>
        <p style="color: red; font-size: 18px; font-weight: bold;">
            IMMEDIATE ACTION REQUIRED
        </p>
    </div>
    
    <p>This certificate will expire very soon. Services using this certificate may become unavailable if not renewed immediately.</p>
</body>
</html>
```

### Creating Custom Templates

#### 1. Create Template Files
```bash
# Create template directory if it doesn't exist
mkdir -p templates/email

# Create HTML template
cat > templates/email/custom_warning.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Custom Certificate Notice</title>
</head>
<body>
    <h1>{{ certificate_name }} Certificate Notice</h1>
    <p>Dear {{ certificate_organization }},</p>
    <p>Your certificate expires in {{ days_until_expiry }} days.</p>
    <p>Please take appropriate action.</p>
</body>
</html>
EOF

# Create text template
cat > templates/email/custom_warning.txt << EOF
{{ certificate_name }} Certificate Notice

Dear {{ certificate_organization }},

Your certificate expires in {{ days_until_expiry }} days on {{ expiry_date[:10] }}.

Certificate Details:
- Name: {{ certificate_name }}
- Serial: {{ serial_number }}
- Issuer: {{ issuer_name }}

Please renew this certificate promptly.

This is an automated message from qPKI.
EOF
```

#### 2. Update Configuration
```json
{
  "email_templates": {
    "custom_warning": {
      "html": "templates/email/custom_warning.html",
      "text": "templates/email/custom_warning.txt"
    }
  },
  "notification_intervals": [
    {
      "name": "30_days_before",
      "days_before_expiry": 30,
      "enabled": true,
      "subject": "Custom Certificate Warning",
      "template": "custom_warning"
    }
  ]
}
```

---

## 📊 Monitoring & Logging

### Notification History

#### Web Interface
1. **Navigate** to `Notifications` → `History`
2. **View sent notifications**:
   - Date and time sent
   - Certificate name and serial
   - Notification type
   - Email address
   - Delivery status
3. **Filter and search** notifications
4. **Export history** for reporting

#### Database Query
```sql
-- View recent notifications
SELECT 
    certificate_serial,
    notification_type,
    email_address,
    sent_date,
    days_before_expiry
FROM sent_notifications 
ORDER BY sent_date DESC 
LIMIT 20;

-- Count notifications by type
SELECT 
    notification_type,
    COUNT(*) as count
FROM sent_notifications 
GROUP BY notification_type;
```

### Log Files

#### Email Notification Logs
```bash
# View recent email notification activity
tail -f logs/email_notifications.log

# Search for specific certificate
grep "certificate_serial_number" logs/email_notifications.log

# Check for errors
grep "ERROR" logs/email_notifications.log
```

#### Scheduled Check Logs
```bash
# View expiration check logs
tail -f logs/expiration_check.log

# Check cron job execution
grep "check_expiration.py" /var/log/syslog
```

### Monitoring Commands

#### Check Notification Status
```bash
# View notification statistics
python3 -c "
import sys, os
sys.path.insert(0, 'src')
from qpki.email_notifier import EmailNotificationService

service = EmailNotificationService(app_dir='.')
history = service.get_notification_history(10)
print('Recent notifications:', len(history))
for h in history:
    print(f'  {h[\"sent_date\"]}: {h[\"notification_type\"]} -> {h[\"email_address\"]}')
"

# Test email configuration
python3 scripts/check_expiration.py --dry-run --verbose
```

---

## 🛠️ Troubleshooting

### Common Issues

#### No Emails Being Sent

**Symptoms**: Notifications show as sent in logs but no emails received.

**Solutions**:
1. **Check SMTP configuration**:
   ```bash
   # Test SMTP connectivity
   python3 -c "
   import smtplib
   server = smtplib.SMTP('smtp.gmail.com', 587)
   server.starttls()
   server.login('your-email@gmail.com', 'your-app-password')
   print('SMTP connection successful')
   server.quit()
   "
   ```

2. **Verify test mode settings**:
   - Check if test mode is enabled (no actual emails sent)
   - Review logs for "TEST MODE" messages

3. **Check email provider settings**:
   - Gmail: Use App Passwords, not regular password
   - Outlook: Verify account settings
   - Corporate: Check firewall and authentication

4. **Review spam filters**:
   - Check recipient spam/junk folders
   - Whitelist sender address
   - Check email reputation

#### Certificates Being Skipped

**Symptoms**: Notifications show certificates as "skipped" in results.

**Solutions**:
1. **Check email addresses**:
   ```bash
   # Verify certificates have email addresses
   python3 -c "
   import json, os
   for f in os.listdir('certificates'):
       if f.endswith('.json'):
           with open(f'certificates/{f}') as file:
               cert = json.load(file)
               email = cert.get('certificate', {}).get('subject', {}).get('email')
               print(f'{f}: {email or \"NO EMAIL\"}')
   "
   ```

2. **Check certificate status**:
   - Ensure certificates are not revoked
   - Verify certificate files are readable
   - Check certificate expiry dates are valid

3. **Review notification intervals**:
   - Ensure intervals are enabled
   - Check if notifications already sent for certificate
   - Verify certificate falls within notification window

#### Authentication Errors

**Symptoms**: SMTP authentication failures in logs.

**Solutions**:
1. **Gmail troubleshooting**:
   ```bash
   # Check Gmail security settings
   # - Enable 2-Factor Authentication
   # - Generate App Password
   # - Use App Password in configuration
   ```

2. **Test credentials manually**:
   ```bash
   # Test SMTP login
   python3 scripts/test_smtp.py --server smtp.gmail.com --port 587 --username your-email@gmail.com
   ```

3. **Check account security**:
   - Enable "Less secure app access" if required
   - Review account security settings
   - Check for account lockouts

### Debugging Tools

#### Enable Verbose Logging
```bash
# Run with maximum verbosity
python3 scripts/check_expiration.py --dry-run --verbose

# Check specific certificate
python3 -c "
import sys, os, json
sys.path.insert(0, 'src')
from qpki.email_notifier import EmailNotificationService

service = EmailNotificationService(app_dir='.')
with open('certificates/your_certificate.json') as f:
    cert_data = json.load(f)
    
result = service._check_certificate_for_notifications(cert_data, 'your_certificate.json')
print('Result:', result)
"
```

#### Test Individual Components
```bash
# Test SMTP configuration
python3 -c "
import sys
sys.path.insert(0, 'src')
from qpki.email_notifier import EmailNotificationService

service = EmailNotificationService(app_dir='.')
success = service.test_email_configuration('your-email@example.com')
print('Email test:', 'SUCCESS' if success else 'FAILED')
"

# Check certificate parsing
python3 -c "
import json
from datetime import datetime, timezone

with open('certificates/your_certificate.json') as f:
    cert_data = json.load(f)
    
cert = cert_data.get('certificate', cert_data)
expiry = cert.get('validity', {}).get('not_after', '')
print('Certificate expiry:', expiry)

# Parse date
if '+' in expiry and expiry.endswith('Z'):
    expiry = expiry[:-1]
elif expiry.endswith('Z'):
    expiry = expiry.replace('Z', '+00:00')

expiry_date = datetime.fromisoformat(expiry)
days_left = (expiry_date - datetime.now(timezone.utc)).days
print('Days until expiry:', days_left)
"
```

### Performance Optimization

#### Large Certificate Databases
```bash
# For systems with many certificates, consider:

1. # Parallel processing (future enhancement)
   python3 scripts/check_expiration.py --parallel --workers 4

2. # Filter certificates by expiry range
   python3 scripts/check_expiration.py --max-days 180

3. # Process specific certificate batches
   python3 scripts/check_expiration.py --batch-size 100
```

#### Database Optimization
```sql
-- Create indexes for faster notification queries
CREATE INDEX idx_sent_notifications_serial ON sent_notifications(certificate_serial);
CREATE INDEX idx_sent_notifications_type ON sent_notifications(notification_type);
CREATE INDEX idx_sent_notifications_date ON sent_notifications(sent_date);
```

---

## 🏭 Production Deployment

### High Availability Setup

#### Multiple SMTP Servers
```json
{
  "smtp_servers": [
    {
      "primary": true,
      "smtp_server": "smtp-primary.yourcompany.com",
      "smtp_port": 587,
      "smtp_security": "TLS"
    },
    {
      "fallback": true,
      "smtp_server": "smtp-backup.yourcompany.com", 
      "smtp_port": 587,
      "smtp_security": "TLS"
    }
  ]
}
```

#### Load Balancing
- **Multiple qPKI instances**: Distribute notification checking
- **Database clustering**: Shared notification tracking
- **Queue management**: Handle high-volume notifications

### Security Hardening

#### Configuration Security
```bash
# Secure configuration file permissions
chmod 600 config/email_config.json
chown qpki:qpki config/email_config.json

# Use environment variables for passwords
export QPKI_SMTP_PASSWORD="your-secure-password"

# Encrypt configuration files
gpg --encrypt config/email_config.json
```

#### Network Security
- **TLS/SSL encryption**: Always use encrypted SMTP
- **Firewall rules**: Restrict SMTP access to authorized servers
- **VPN/Private networks**: Route email traffic through secure networks
- **Authentication**: Use strong, unique passwords for SMTP accounts

### Monitoring & Alerting

#### Health Checks
```bash
# Create monitoring script
cat > scripts/monitor_notifications.sh << 'EOF'
#!/bin/bash
# Check if notifications are working properly

RESULT=$(python3 scripts/check_expiration.py --dry-run 2>&1)
if [[ $? -eq 0 ]]; then
    echo "OK: Notification system healthy"
    exit 0
else
    echo "CRITICAL: Notification system failure"
    echo "$RESULT"
    exit 2
fi
EOF

chmod +x scripts/monitor_notifications.sh

# Add to monitoring system (Nagios, Zabbix, etc.)
```

#### Alerting Integration
```bash
# Send alerts for notification failures
python3 scripts/check_expiration.py || {
    # Send alert to monitoring system
    curl -X POST "https://alerts.yourcompany.com/webhook" \
         -d '{"alert":"qPKI notification system failure","severity":"critical"}'
}
```

---

## ❓ Frequently Asked Questions

### **Q: How often should I run the expiration check?**
A: **Daily is recommended** for most environments. Production systems may benefit from twice-daily checks. Avoid checking more than every 4 hours to prevent spam.

### **Q: Can I customize the email subjects and content?**
A: **Yes, completely**. You can customize email subjects in the notification intervals configuration and create custom email templates with your own branding and content.

### **Q: What happens if the SMTP server is down?**
A: **The system logs the failure** and continues operation. Notifications will be attempted again on the next check cycle. Consider setting up backup SMTP servers for high availability.

### **Q: Why are some certificates being skipped?**
A: **Common reasons include**:
- Missing email address in certificate subject
- Certificate is already revoked
- Notification already sent for that interval
- Certificate doesn't fall within any notification windows

### **Q: Can I send notifications to multiple email addresses?**
A: **Currently, each certificate sends to one email address** (from the certificate subject). For multiple recipients, consider setting up email distribution lists or aliases.

### **Q: How do I know if emails are actually being delivered?**
A: **Monitor the notification history** and logs. For production systems, consider using email delivery services (SendGrid, Amazon SES) that provide delivery confirmation and bounce handling.

### **Q: Can I disable specific notification intervals?**
A: **Yes**, each notification interval can be individually enabled or disabled through the web interface or configuration file.

### **Q: What's the difference between test mode and production mode?**
A: **Test mode logs notifications** without actually sending emails, perfect for testing configuration. **Production mode sends real emails** to recipients.

---

**Next Steps**: 
- [Set up automated scheduling](./automation.md)
- [Configure SMTP settings](./smtp-setup.md)
- [Learn about certificate lifecycle management](./certificate-workflow.md)
