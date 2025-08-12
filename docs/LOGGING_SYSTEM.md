# qPKI Comprehensive Logging System

## Overview

The qPKI system now includes a comprehensive, centralized logging system that tracks all activity across the entire platform. This provides complete audit trails, debugging capabilities, and system monitoring.

## 🎯 Key Features

### ✅ **Centralized Configuration**
- Single configuration point for all logging
- Consistent formatting across components
- Easy configuration changes

### ✅ **Component-Specific Loggers**
- **Web Logger**: Flask web application activities
- **Crypto Logger**: Cryptographic operations (key generation, signing, etc.)
- **Email Logger**: Email notification system activities
- **Database Logger**: Database operations and queries
- **CLI Logger**: Command-line interface operations

### ✅ **Structured Activity Logging**
- Standardized activity logging with metadata
- JSON format support for log parsing and analysis
- Hierarchical activity tracking

### ✅ **Multiple Output Formats**
- **Readable Format**: Human-readable logs for development
- **JSON Format**: Structured logs for automated processing
- **Console Output**: Real-time monitoring during development
- **File Output**: Persistent logging with rotation

### ✅ **Advanced Features**
- Function call logging with parameters and return values
- Exception logging with full stack traces
- Log rotation (50MB files, 10 backups)
- Thread and process ID tracking

## 📁 Log File Structure

```
logs/
├── qpki_YYYYMMDD.log          # Main application log (daily rotation)
└── email_notifications.log    # Email system specific log
```

## 🔧 Configuration

The logging system is configured in `src/qpki/logging_config.py` with these options:

```python
setup_logging(
    log_level="INFO",           # DEBUG, INFO, WARNING, ERROR, CRITICAL
    log_file=None,             # Auto-generated: qpki_YYYYMMDD.log
    log_dir="logs",            # Directory for log files
    max_file_size=50MB,        # Max file size before rotation
    backup_count=10,           # Number of backup files to keep
    json_format=False,         # Use JSON format for structured logs
    console_output=True        # Also output to console
)
```

## 🚀 Usage Examples

### Basic Logging
```python
from qpki.logging_config import get_logger

logger = get_logger()
logger.info("System started")
logger.warning("Low disk space")
logger.error("Failed to connect to database")
```

### Component-Specific Logging
```python
from qpki.logging_config import get_web_logger, get_crypto_logger

web_logger = get_web_logger()
crypto_logger = get_crypto_logger()

web_logger.info("HTTP request received: POST /certificates")
crypto_logger.info("Generated RSA key pair (4096-bit)")
```

### Activity Logging
```python
from qpki.logging_config import log_activity

log_activity(logger, "certificate_created", {
    'description': 'New SSL certificate issued',
    'common_name': 'www.example.com',
    'issuer': 'Production CA',
    'validity_days': 365,
    'algorithm': 'RSA-4096 + Dilithium-5',
    'serial_number': '123456789ABCDEF',
    'user_id': 'admin@company.com',
    'user_ip': '192.168.1.100'
})
```

### Function Call Logging
```python
from qpki.logging_config import log_function_call

@log_function_call
def generate_certificate(common_name, validity_days=365):
    # Function automatically logs entry, parameters, and results
    return create_cert(common_name, validity_days)
```

## 📊 Activity Types

The system logs various activity types with structured metadata:

### Certificate Activities
- `certificate_created` - New certificates issued
- `certificate_revoked` - Certificate revocation
- `certificate_renewed` - Certificate renewal
- `certificate_exported` - Certificate downloads/exports

### CA Activities
- `ca_created` - New Certificate Authority creation
- `ca_configured` - CA configuration changes
- `crl_generated` - Certificate Revocation List updates

### System Activities
- `web_app_startup` - Application startup
- `user_login` - User authentication
- `config_changed` - Configuration updates
- `backup_completed` - System backups

### Email Activities
- `notification_sent` - Email notifications sent
- `email_config_updated` - Email settings changed
- `notification_failed` - Failed email deliveries

## 🔍 Log Analysis

### JSON Format Logs
When `json_format=True`, logs are structured for easy parsing:

```json
{
  "timestamp": "2025-08-11T16:16:44.141471+00:00",
  "level": "INFO",
  "logger": "qpki.web",
  "message": "Activity: certificate_created - SSL certificate issued",
  "module": "app",
  "function": "create_cert",
  "line": 705,
  "thread_id": 140704556776896,
  "process_id": 17032,
  "activity_type": "certificate_created",
  "common_name": "www.example.com",
  "issuer": "Production CA",
  "validity_days": 365,
  "user_ip": "192.168.1.100"
}
```

### Querying Logs
Use tools like `jq` for JSON log analysis:

```bash
# Find all certificate creation activities
cat logs/qpki_20250811.log | grep '"activity_type": "certificate_created"' | jq .

# Count activities by type
cat logs/qpki_20250811.log | jq -s 'group_by(.activity_type) | map({activity: .[0].activity_type, count: length})'

# Find errors in the last hour
cat logs/qpki_20250811.log | jq 'select(.level == "ERROR")'
```

## 🛠️ Integration Status

The logging system has been integrated into:

### ✅ **Flask Web Application** (`app.py`)
- Application startup logging
- CA creation activities
- Certificate creation activities
- User request tracking with IP addresses

### ✅ **Email Notification System** (`email_notifier.py`)
- Email sending activities
- Notification failures
- Configuration changes

### ⚠️ **Pending Integration**
- CLI commands (`cli.py`)
- Cryptographic operations (`crypto.py`)
- Database operations (`database/`)

## 🔐 Security Considerations

- **No Sensitive Data**: Private keys, passwords, and secrets are never logged
- **User Privacy**: Personal information is logged only when necessary for audit trails
- **Access Control**: Log files should have appropriate file permissions
- **Retention Policy**: Implement log retention policies for compliance

## 🚀 Production Deployment

For production deployment:

1. **Configure Log Rotation**:
   ```python
   setup_logging(
       log_level="WARNING",      # Reduce verbosity
       json_format=True,         # Enable structured logging
       console_output=False,     # Disable console in production
       max_file_size=100*1024*1024,  # 100MB files
       backup_count=50           # Keep more backups
   )
   ```

2. **Set Up Log Monitoring**:
   - Use log aggregation tools (ELK Stack, Splunk, etc.)
   - Set up alerts for ERROR level messages
   - Monitor disk space for log directories

3. **Security**:
   ```bash
   # Secure log directory permissions
   chmod 750 logs/
   chown qpki:qpki logs/
   ```

## 🧪 Testing

Run the comprehensive logging demo:

```bash
cd /path/to/qPKI
python scripts/test_logging_system.py
```

This demonstrates all logging features and creates sample log entries.

## 📈 Benefits

### For Developers
- **Debugging**: Detailed error logs with stack traces
- **Development**: Real-time console output during development
- **Testing**: Function call logging for testing verification

### For System Administrators
- **Monitoring**: Comprehensive activity tracking
- **Auditing**: Complete audit trails for compliance
- **Troubleshooting**: Structured error information

### For Security Teams
- **Audit Trails**: Complete record of all PKI activities
- **Incident Response**: Detailed logs for security investigations
- **Compliance**: Structured logging for regulatory requirements

## 📞 Support

For logging system support:
- Check `logs/qpki_YYYYMMDD.log` for system activities
- Use JSON format for automated log analysis
- Enable DEBUG level for detailed troubleshooting
- Review `src/qpki/logging_config.py` for configuration options

---

**The qPKI logging system provides comprehensive visibility into all system activities, enabling better debugging, monitoring, and security auditing.**
