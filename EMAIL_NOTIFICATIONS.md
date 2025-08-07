# Email Notification System

The qPKI system includes an automated email notification system that monitors certificate expiration dates and sends timely reminders to certificate owners.

## Features

### 📧 Automatic Email Notifications
- **Multi-interval notifications**: Configurable reminders at 90, 60, 30, 14, 7, and 1 days before expiration
- **Post-expiration alerts**: Immediate notification when certificates expire
- **Rich email templates**: Professional HTML and plain text email formats
- **Duplicate prevention**: Automatic tracking to prevent sending duplicate notifications

### 🛠️ Configuration Management
- **Web interface**: Easy configuration through the qPKI web application
- **SMTP support**: Compatible with any SMTP server (Gmail, Outlook, custom servers)
- **Test mode**: Safe testing without sending actual emails
- **Flexible settings**: Customizable intervals, subjects, and templates

### 📊 Monitoring and Tracking
- **Notification history**: Complete log of all sent notifications
- **Statistics dashboard**: Track notification metrics and certificate health
- **Error logging**: Detailed logs for troubleshooting
- **Manual checks**: On-demand certificate expiration scanning

## Setup

### 1. Email Address Requirement

**Important**: Starting now, all new certificates **must** include an email address. This email is used for expiration notifications.

When creating certificates through the web interface, the email field is now mandatory and will be validated.

### 2. SMTP Configuration

Access the notification settings at: `http://localhost:9090/notifications`

Configure your SMTP settings:

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

#### Popular SMTP Settings

**Gmail:**
- Server: `smtp.gmail.com`
- Port: `587`
- Security: `TLS`
- Note: Use App Passwords for authentication

**Outlook/Hotmail:**
- Server: `smtp.live.com`
- Port: `587`
- Security: `TLS`

**Custom SMTP:**
- Configure according to your email provider's documentation

### 3. Notification Intervals

Default notification schedule:
- **90 days before**: Early planning notice
- **60 days before**: Begin renewal process
- **30 days before**: Renewal reminder
- **14 days before**: Urgent action required
- **7 days before**: Critical alert
- **1 day before**: Final warning
- **Day of expiry**: Expiration notice

Each interval can be:
- Enabled/disabled individually
- Have customized email subjects
- Use different templates

### 4. Test Mode

Enable test mode to:
- Log notifications without sending emails
- Verify configuration and templates
- Test the system safely

## Usage

### Web Interface

1. **Configure Settings**: Navigate to `Notifications` in the main menu
2. **Test Configuration**: Send a test email to verify SMTP settings
3. **Manual Check**: Trigger immediate certificate scanning
4. **View History**: Check notification logs and statistics

### Command Line

Use the automated checking script:

```bash
# Basic check (dry run mode)
python3 scripts/check_expiration.py --dry-run

# Verbose output
python3 scripts/check_expiration.py --dry-run --verbose

# Production check
python3 scripts/check_expiration.py

# Custom configuration
python3 scripts/check_expiration.py --config /path/to/config.json
```

### Scheduled Automation

Setup a cron job for automatic checking:

```bash
# Edit crontab
crontab -e

# Add daily check at 9:00 AM
0 9 * * * /usr/bin/python3 /path/to/qPKI/scripts/check_expiration.py

# Add multiple checks per day
0 9,21 * * * /usr/bin/python3 /path/to/qPKI/scripts/check_expiration.py
```

## Email Templates

### Template System

The system uses Jinja2 templating with the following variables:

- `certificate_name`: Common name of the certificate
- `certificate_organization`: Organization name
- `certificate_email`: Contact email address
- `serial_number`: Certificate serial number
- `days_until_expiry`: Days remaining until expiration
- `expiry_date`: Full expiration date/time
- `issue_date`: Certificate issue date
- `issuer_name`: Name of issuing CA
- `certificate_filename`: Certificate file name
- `notification_type`: Type of notification
- `urgency_level`: LOW/MEDIUM/HIGH/CRITICAL

### Available Templates

1. **90-day notice**: Early planning reminder
2. **60-day warning**: Begin renewal process
3. **30-day warning**: Standard renewal reminder
4. **14-day alert**: Urgent action required
5. **7-day alert**: Critical warning
6. **1-day alert**: Final warning
7. **Expired notice**: Certificate has expired

### Custom Templates

To create custom templates:

1. Create HTML and text files in `templates/email/`
2. Use Jinja2 syntax for dynamic content
3. Update `email_config.json` to reference new templates
4. Test with the web interface

Example custom template:
```html
<!DOCTYPE html>
<html>
<head>
    <title>Custom Certificate Notice</title>
</head>
<body>
    <h1>Certificate Expiration Alert</h1>
    <p>Dear {{ certificate_organization }},</p>
    <p>Your certificate "{{ certificate_name }}" expires in {{ days_until_expiry }} days.</p>
    <p>Expiration Date: {{ expiry_date[:10] }}</p>
</body>
</html>
```

## Security Considerations

### SMTP Security

- **Use TLS/SSL**: Always enable encryption for SMTP connections
- **App Passwords**: Use application-specific passwords instead of main account passwords
- **Secure Storage**: In production, store SMTP passwords securely (environment variables, key management)
- **Firewall Rules**: Ensure SMTP ports are accessible but secured

### Email Content

- **No Sensitive Data**: Email templates don't include private keys or sensitive certificate details
- **Certificate Identification**: Only includes non-sensitive identifiers (serial numbers, common names)
- **Secure Links**: If including links, ensure they use HTTPS

## Troubleshooting

### Common Issues

**No emails being sent:**
1. Check if notifications are enabled in configuration
2. Verify SMTP settings are correct
3. Test SMTP connectivity manually
4. Check firewall and network connectivity
5. Review logs in `logs/email_notifications.log`

**Certificates being skipped:**
1. Ensure certificates have email addresses in the subject
2. Check certificate status (not revoked)
3. Verify certificate files are readable

**Authentication errors:**
1. Use app-specific passwords for Gmail/Outlook
2. Verify username/password are correct
3. Check if 2FA is properly configured

**Template errors:**
1. Verify template files exist and are readable
2. Check Jinja2 syntax in templates
3. Test with default templates first

### Debugging

Enable verbose logging:
```bash
python3 scripts/check_expiration.py --verbose --dry-run
```

Check log files:
- `logs/email_notifications.log`: Email service logs
- `logs/expiration_check.log`: Scheduled task logs

## Production Deployment

### Recommended Setup

1. **Dedicated SMTP Service**: Use a reliable SMTP service (SendGrid, Amazon SES, etc.)
2. **Environment Variables**: Store sensitive configuration in environment variables
3. **Monitoring**: Set up monitoring for the notification system itself
4. **Backup Notifications**: Consider multiple notification channels
5. **Log Rotation**: Implement log rotation for notification logs

### Security Hardening

```bash
# Restrict config file permissions
chmod 600 config/email_config.json

# Create dedicated user for qPKI
useradd -r -s /bin/false qpki

# Set appropriate file ownership
chown -R qpki:qpki /path/to/qPKI/
```

### High Availability

- **Multiple SMTP Servers**: Configure fallback SMTP servers
- **Database Backup**: Regularly backup the notification database
- **Health Checks**: Implement health checking for the notification service
- **Alerting**: Set up alerts if notifications fail consistently

## API Integration

The notification system can be integrated with external systems:

```python
from qpki.email_notifier import EmailNotificationService

# Initialize service
email_service = EmailNotificationService()

# Check certificates programmatically
results = email_service.check_and_send_notifications('/path/to/certificates')

# Get notification history
history = email_service.get_notification_history(limit=100)

# Test configuration
success = email_service.test_email_configuration('test@example.com')
```

## Support

For additional support:

1. Check the main qPKI documentation
2. Review configuration examples in `config/`
3. Examine email templates in `templates/email/`
4. Test with the web interface first
5. Use verbose logging for troubleshooting

The email notification system ensures that certificate expiration never catches you off guard, providing timely, professional notifications to keep your PKI infrastructure secure and up-to-date.
