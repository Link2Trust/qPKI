# Troubleshooting Guide

This comprehensive troubleshooting guide helps you diagnose and resolve common issues with the qPKI system. Use the table of contents to quickly find solutions to specific problems.

## 📋 Quick Issue Index

| Problem | Section |
|---------|---------|
| Can't access web interface | [Web Interface Issues](#-web-interface-issues) |
| CA creation fails | [Certificate Authority Issues](#-certificate-authority-issues) |
| Certificate creation errors | [Certificate Creation Issues](#-certificate-creation-issues) |
| Download not working | [Certificate Download Issues](#-certificate-download-issues) |
| Email notifications not sent | [Email Notification Issues](#-email-notification-issues) |
| Database connection errors | [Database Issues](#-database-issues) |
| Permission denied errors | [File Permission Issues](#-file-permission-issues) |
| Performance problems | [Performance Issues](#-performance-issues) |
| Authentication failures | [Authentication Issues](#-authentication-issues) |
| MFA/2FA problems | [Multi-Factor Authentication Issues](#-multi-factor-authentication-issues) |
| User template errors | [Template and Session Issues](#-template-and-session-issues) |

---

## 🌐 Web Interface Issues

### Cannot Access Web Interface

#### Problem: Browser shows "Connection refused" or "Site can't be reached"

**Symptoms**:
- Cannot access `http://localhost:9090`
- Browser timeout or connection error
- "ERR_CONNECTION_REFUSED" in Chrome

**Solutions**:

1. **Check if qPKI is running**:
   ```bash
   # Check if Python process is running
   ps aux | grep "app.py"
   
   # Check if port 9090 is in use
   lsof -i :9090
   netstat -an | grep 9090
   ```

2. **Start qPKI if not running**:
   ```bash
   cd /path/to/qPKI
   python3 app.py
   ```

3. **Check for port conflicts**:
   ```bash
   # If port 9090 is busy, find what's using it
   sudo lsof -i :9090
   
   # Kill the process if necessary
   sudo kill -9 <PID>
   ```

4. **Try alternative ports**:
   ```bash
   # Edit app.py to use different port
   # Change: app.run(debug=True, host='0.0.0.0', port=9090)
   # To:     app.run(debug=True, host='0.0.0.0', port=8080)
   ```

5. **Check firewall settings**:
   ```bash
   # macOS
   sudo pfctl -sr | grep 9090
   
   # Linux
   sudo ufw status
   sudo iptables -L | grep 9090
   ```

#### Problem: "Address already in use" error

**Solution**:
```bash
# Find and kill existing qPKI process
ps aux | grep "app.py" | grep -v grep
kill <PID>

# Or kill all Python processes on port 9090
sudo lsof -ti:9090 | xargs kill -9

# Start qPKI again
python3 app.py
```

### Login Issues

#### Problem: Default credentials don't work

**Symptoms**:
- `admin/admin` login fails
- "Invalid credentials" message
- Redirect loop after login

**Solutions**:

1. **Check database initialization**:
   ```bash
   # Check if users table exists and has admin user
   python3 -c "
   import sys
   sys.path.insert(0, 'src')
   from qpki.database import DatabaseManager, DatabaseConfig
   
   db_config = DatabaseConfig.from_env()
   db_manager = DatabaseManager(db_config)
   
   conn = db_manager.get_connection()
   cursor = conn.cursor()
   cursor.execute('SELECT username FROM users')
   users = cursor.fetchall()
   print('Existing users:', users)
   conn.close()
   "
   ```

2. **Reset admin user**:
   ```bash
   python3 -c "
   import sys
   sys.path.insert(0, 'src')
   from qpki.auth import AuthenticationManager
   from qpki.database import DatabaseManager, DatabaseConfig
   
   db_config = DatabaseConfig.from_env()
   db_manager = DatabaseManager(db_config)
   auth_manager = AuthenticationManager(db_manager)
   
   # Create new admin user
   success, message = auth_manager.create_default_admin()
   print('Admin user creation:', message)
   "
   ```

3. **Check session configuration**:
   ```bash
   # Verify secret key is set
   python3 -c "
   import os
   print('Secret key:', os.environ.get('QPKI_SECRET_KEY', 'default'))
   "
   ```

---

## 🏛️ Certificate Authority Issues

### CA Creation Fails

#### Problem: "No supported classical public key found in certificate"

**Symptoms**:
- CA creation form submits but fails
- Error in logs about missing public key
- Certificate creation depends on CA

**Solutions**:

1. **Check algorithm selection**:
   - Ensure RSA or ECC algorithm is properly selected
   - Verify key size/curve parameters are valid
   - Check Dilithium variant selection for hybrid CAs

2. **Validate form data**:
   ```bash
   # Check browser developer console for JavaScript errors
   # Verify all required fields are filled
   ```

3. **Check crypto library installation**:
   ```bash
   python3 -c "
   import sys
   sys.path.insert(0, 'src')
   from qpki.crypto import FlexibleHybridCrypto, RSACrypto, ECCCrypto
   
   # Test RSA
   try:
       rsa_crypto = RSACrypto(key_size=2048)
       print('RSA crypto: OK')
   except Exception as e:
       print('RSA crypto error:', e)
   
   # Test ECC
   try:
       ecc_crypto = ECCCrypto(curve_name='secp256r1')
       print('ECC crypto: OK')
   except Exception as e:
       print('ECC crypto error:', e)
   "
   ```

#### Problem: "Parent CA does not contain private keys"

**Solution**:
This indicates you're trying to create a subordinate CA using an old CA that doesn't have stored private keys.

```bash
# Option 1: Recreate the parent CA with the current version
# Option 2: Convert to root CA instead of subordinate CA
# Option 3: Use a different parent CA that has private keys
```

---

## 📜 Certificate Creation Issues

### Certificate Creation Errors

#### Problem: "ECCCrypto.__init__() got an unexpected keyword argument 'curve'"

**Solution**:
This is a known issue that's been fixed. Update your code:

```bash
# The issue is in the certificate creation code where 'curve' should be 'curve_name'
# This has been fixed in the latest version
```

#### Problem: "No Certificate Authorities found"

**Solutions**:

1. **Create a CA first**:
   ```bash
   # Navigate to Certificate Authorities → Create CA
   # Create at least one CA before creating certificates
   ```

2. **Check CA directory**:
   ```bash
   ls -la ca/
   # Should show .json files for CAs
   
   # If empty, CAs were not created successfully
   # Check logs for CA creation errors
   ```

#### Problem: Certificate creation hangs or times out

**Solutions**:

1. **Check key generation performance**:
   ```bash
   # Test key generation speed
   python3 -c "
   import time
   import sys
   sys.path.insert(0, 'src')
   from qpki.crypto import FlexibleHybridCrypto
   
   start = time.time()
   crypto = FlexibleHybridCrypto('RSA', rsa_key_size=2048, dilithium_variant=2)
   keys = crypto.generate_hybrid_key_pair()
   end = time.time()
   print(f'Key generation took: {end-start:.2f} seconds')
   "
   ```

2. **Check system resources**:
   ```bash
   # Check CPU and memory usage
   top
   free -h
   df -h
   ```

---

## 📥 Certificate Download Issues

### Download Not Working

#### Problem: "Unable to convert certificate to requested format"

This was a known issue with date parsing that has been fixed.

**Solutions**:

1. **Verify certificate type**:
   ```bash
   # Check what type of certificate you're trying to download
   python3 -c "
   import json
   import sys
   sys.path.insert(0, 'src')
   from qpki.utils.enhanced_cert_formats import EnhancedCertificateFormatConverter
   
   with open('certificates/your_cert.json') as f:
       cert_data = json.load(f)
   
   converter = EnhancedCertificateFormatConverter()
   cert_type = converter.detect_certificate_type(cert_data)
   print('Certificate type:', cert_type)
   
   if cert_type == 'classical':
       print('Should support PEM/DER download')
   else:
       print('Only supports JSON download')
   "
   ```

2. **Test format conversion**:
   ```bash
   # Test certificate conversion
   python3 -c "
   import json
   import sys
   sys.path.insert(0, 'src')
   from qpki.utils.enhanced_cert_formats import EnhancedCertificateFormatConverter
   
   with open('certificates/your_cert.json') as f:
       cert_data = json.load(f)
   
   converter = EnhancedCertificateFormatConverter()
   pem_result = converter.create_x509_from_classical(cert_data, 'PEM')
   
   if pem_result:
       print('Conversion successful, length:', len(pem_result))
   else:
       print('Conversion failed')
   "
   ```

#### Problem: Downloads always return JSON files

**Cause**: Only classical certificates support PEM/DER formats. Hybrid and PQC certificates only support JSON format.

**Solution**: 
- For **classical certificates**: Should download as PEM/DER
- For **hybrid/PQC certificates**: Only JSON format is available
- Check certificate type in the certificate details page

---

## 📧 Email Notification Issues

### Notifications Not Sent

#### Problem: "Email notifications disabled" or no notifications sent

**Solutions**:

1. **Check notification configuration**:
   ```bash
   # Verify email notifications are enabled
   python3 -c "
   import json
   with open('config/email_config.json') as f:
       config = json.load(f)
   print('Enabled:', config.get('enabled'))
   print('Test mode:', config.get('test_mode'))
   print('SMTP server:', config.get('smtp_server'))
   "
   ```

2. **Check certificate email addresses**:
   ```bash
   # Verify certificates have email addresses
   python3 -c "
   import json
   import os
   
   for filename in os.listdir('certificates'):
       if filename.endswith('.json'):
           with open(f'certificates/{filename}') as f:
               cert_data = json.load(f)
           
           certificate = cert_data.get('certificate', cert_data)
           email = certificate.get('subject', {}).get('email')
           
           print(f'{filename}: {email or \"NO EMAIL\"}')
   "
   ```

3. **Test email configuration**:
   ```bash
   # Test SMTP connectivity
   python3 -c "
   import sys
   sys.path.insert(0, 'src')
   from qpki.email_notifier import EmailNotificationService
   
   service = EmailNotificationService(app_dir='.')
   success = service.test_email_configuration('your-test@email.com')
   print('Email test result:', 'SUCCESS' if success else 'FAILED')
   "
   ```

4. **Check notification intervals**:
   ```bash
   # Run manual notification check
   python3 scripts/check_expiration.py --dry-run --verbose
   ```

#### Problem: Gmail authentication fails

**Solutions**:

1. **Use App Passwords**:
   - Enable 2-Factor Authentication on Gmail
   - Generate App Password in Google Account settings
   - Use App Password instead of regular password

2. **Check Gmail security settings**:
   ```bash
   # Test Gmail SMTP connection
   python3 -c "
   import smtplib
   try:
       server = smtplib.SMTP('smtp.gmail.com', 587)
       server.starttls()
       server.login('your-email@gmail.com', 'your-app-password')
       print('Gmail SMTP: SUCCESS')
       server.quit()
   except Exception as e:
       print('Gmail SMTP error:', e)
   "
   ```

---

## 🗄️ Database Issues

### Database Connection Errors

#### Problem: "Could not connect to configured database"

**Solutions**:

1. **Check database configuration**:
   ```bash
   # Check environment variables
   echo "DB_TYPE: $QPKI_DB_TYPE"
   echo "DB_HOST: $QPKI_DB_HOST"
   echo "DB_NAME: $QPKI_DB_NAME"
   echo "DB_USER: $QPKI_DB_USER"
   ```

2. **Test database connectivity**:
   ```bash
   # Test SQLite (default)
   python3 -c "
   import sqlite3
   import os
   
   db_path = 'qpki.db'
   if os.path.exists(db_path):
       print('SQLite database exists')
       conn = sqlite3.connect(db_path)
       cursor = conn.cursor()
       cursor.execute('SELECT name FROM sqlite_master WHERE type=\"table\"')
       tables = cursor.fetchall()
       print('Tables:', [t[0] for t in tables])
       conn.close()
   else:
       print('SQLite database not found')
   "
   ```

3. **Force SQLite fallback**:
   ```bash
   # Force SQLite mode
   export QPKI_DB_TYPE=sqlite
   python3 app.py
   ```

#### Problem: Database migration fails

**Solutions**:

1. **Check database permissions**:
   ```bash
   ls -la qpki.db
   # Ensure qPKI process can read/write database file
   ```

2. **Recreate database**:
   ```bash
   # Backup existing database
   cp qpki.db qpki.db.backup
   
   # Delete and recreate
   rm qpki.db
   python3 app.py
   # Database will be recreated automatically
   ```

---

## 📂 File Permission Issues

### Permission Denied Errors

#### Problem: Cannot create certificates or CAs

**Solutions**:

1. **Check directory permissions**:
   ```bash
   ls -la certificates/ ca/ crl/
   
   # Fix permissions if needed
   chmod 755 certificates/ ca/ crl/
   chmod 644 certificates/*.json ca/*.json crl/*.json
   ```

2. **Check file ownership**:
   ```bash
   # Change ownership if needed
   sudo chown -R $USER:$USER certificates/ ca/ crl/
   ```

3. **Create missing directories**:
   ```bash
   mkdir -p certificates ca crl logs
   chmod 755 certificates ca crl logs
   ```

---

## ⚡ Performance Issues

### Slow Certificate Creation

#### Problem: Certificate/CA creation takes very long time

**Solutions**:

1. **Check system resources**:
   ```bash
   # Monitor system during key generation
   top
   iostat 1
   ```

2. **Use smaller key sizes for testing**:
   - RSA: Use 2048 bits instead of 4096
   - Dilithium: Use variant 2 instead of 5
   - ECC: Use secp256r1 instead of secp521r1

3. **Check entropy availability**:
   ```bash
   # Linux: Check entropy pool
   cat /proc/sys/kernel/random/entropy_avail
   
   # If low, install rng-tools
   sudo apt-get install rng-tools
   ```

### Web Interface Slow

#### Problem: Web pages load slowly

**Solutions**:

1. **Check certificate count**:
   ```bash
   # Count certificates and CAs
   echo "Certificates: $(ls certificates/*.json 2>/dev/null | wc -l)"
   echo "CAs: $(ls ca/*.json 2>/dev/null | wc -l)"
   ```

2. **Enable pagination** (future enhancement):
   - Large numbers of certificates can slow page loads
   - Consider archiving old certificates

3. **Check browser developer tools**:
   - Look for slow network requests
   - Check for JavaScript errors
   - Monitor memory usage

---

## 🔐 Authentication Issues

### Cannot Login

#### Problem: Authentication system not working

**Solutions**:

1. **Check authentication mode**:
   ```bash
   # See if running with authentication disabled
   grep -i "file-based mode" logs/qpki.log
   ```

2. **Reset authentication**:
   ```bash
   # Delete and recreate user database
   rm qpki.db
   python3 app.py
   # Default admin user will be recreated
   ```

3. **Check session configuration**:
   ```bash
   # Verify session secret key
   python3 -c "
   import os
   from flask import Flask
   app = Flask(__name__)
   app.secret_key = os.environ.get('QPKI_SECRET_KEY', 'default')
   print('Session key configured:', bool(app.secret_key))
   "
   ```

---

## 🔒 Multi-Factor Authentication Issues

### MFA Setup Problems

#### Problem: "'moment' is undefined" Error During MFA Setup

**Symptoms**:
- Error after entering authenticator code
- JavaScript/template error in backup codes page
- UndefinedError in Jinja2 template

**Solution**:
This was a template issue that has been fixed in the latest version.

```bash
# Verify the fix is applied
grep -n "moment()" templates/auth/mfa_backup_codes.html
# Should return no results if fixed

grep -n "current_date" templates/auth/mfa_backup_codes.html  
# Should show the corrected template
```

#### Problem: QR Code Won't Display or Scan

**Solutions**:

1. **Check dependencies**:
   ```bash
   # Verify required packages are installed
   pip3 list | grep -E "(pyotp|qrcode|Pillow)"
   
   # Install if missing
   pip3 install pyotp qrcode[pil] Pillow
   ```

2. **Test QR code generation**:
   ```bash
   python3 -c "
   import sys
   sys.path.insert(0, 'src')
   from qpki.auth.mfa import MFAManager
   
   mfa = MFAManager()
   secret = mfa.generate_secret_key()
   uri = mfa.get_provisioning_uri('test@example.com', secret)
   qr_buffer = mfa.generate_qr_code(uri)
   print('QR code generation: SUCCESS' if qr_buffer else 'FAILED')
   "
   ```

3. **Manual secret entry**:
   - If QR code fails, use manual entry in authenticator app
   - Secret key is displayed below the QR code

#### Problem: "Invalid verification code" During Setup

**Solutions**:

1. **Check time synchronization**:
   ```bash
   # Check system time
   date
   
   # Synchronize time (Linux)
   sudo ntpdate -s time.nist.gov
   
   # Synchronize time (macOS)
   sudo sntp -sS time.apple.com
   ```

2. **Verify TOTP generation**:
   ```bash
   python3 -c "
   import sys
   sys.path.insert(0, 'src')
   from qpki.auth.mfa import MFAManager
   
   mfa = MFAManager()
   secret = 'YOUR_SECRET_KEY_HERE'
   code = mfa.generate_totp_code(secret)
   print('Generated TOTP code:', code)
   "
   ```

### MFA Login Issues

#### Problem: Cannot Login After Enabling MFA

**Solutions**:

1. **Use backup codes**:
   - Enter a backup code instead of TOTP code
   - Each backup code can only be used once

2. **Admin disable MFA**:
   ```bash
   # Emergency MFA disable via database
   python3 -c "
   import sys
   sys.path.insert(0, 'src')
   from qpki.auth import AuthenticationManager
   from qpki.database import DatabaseManager, DatabaseConfig
   
   db_config = DatabaseConfig.from_env()
   db_manager = DatabaseManager(db_config)
   auth_manager = AuthenticationManager(db_manager)
   
   success, message = auth_manager.disable_mfa_for_user(USER_ID, admin_action=True)
   print('MFA disable result:', message)
   "
   ```

#### Problem: Backup Codes Not Working

**Solutions**:

1. **Verify backup code format**:
   - Backup codes are 8-character alphanumeric
   - Case sensitive
   - No spaces or special characters

2. **Check remaining backup codes**:
   ```bash
   python3 -c "
   import sys
   sys.path.insert(0, 'src')
   from qpki.auth import AuthenticationManager
   from qpki.database import DatabaseManager, DatabaseConfig
   
   db_config = DatabaseConfig.from_env()
   db_manager = DatabaseManager(db_config)
   auth_manager = AuthenticationManager(db_manager)
   
   success, count, message = auth_manager.get_backup_codes_info(USER_ID)
   print(f'Remaining backup codes: {count}')
   "
   ```

---

## 🖼️ Template and Session Issues

### Template Errors

#### Problem: "'bool' object is not callable" Error

**Symptoms**:
- Template errors when accessing user profiles
- TypeError about calling boolean values
- Issues with `user.is_password_expired()` calls

**Cause**:
This occurs when templates try to call methods on dictionary objects that contain boolean values.

**Solution**:
This has been fixed in recent versions. The templates now access boolean values directly:

```bash
# Check if templates are fixed
grep -r "is_password_expired()" templates/
# Should return no results if fixed

grep -r "is_password_expired" templates/
# Should show access without parentheses
```

#### Problem: "TemplateNotFound" Errors

**Solutions**:

1. **Check template files exist**:
   ```bash
   # Verify all auth templates exist
   ls -la templates/auth/
   
   # Should include:
   # - edit_user.html
   # - mfa_backup_codes.html
   # - mfa_setup.html
   # - mfa_verify.html
   # - profile.html
   ```

2. **Check template syntax**:
   ```bash
   # Validate Jinja2 syntax in templates
   python3 -c "
   from jinja2 import Template, TemplateError
   import os
   
   for root, dirs, files in os.walk('templates'):
       for file in files:
           if file.endswith('.html'):
               path = os.path.join(root, file)
               with open(path) as f:
                   try:
                       Template(f.read())
                       print(f'✓ {path}')
                   except TemplateError as e:
                       print(f'✗ {path}: {e}')
   "
   ```

### Session Issues

#### Problem: "DetachedInstanceError" in SQLAlchemy

**Symptoms**:
- Errors when creating or updating users
- "Instance is not bound to a Session" errors
- Issues accessing user object attributes

**Cause**:
This occurs when SQLAlchemy objects are accessed after their database session has closed.

**Solution**:
This has been fixed by returning dictionary objects instead of SQLAlchemy objects:

```bash
# Verify the fix is in place
grep -n "user_data_dict" src/qpki/auth/auth_manager.py
# Should show methods returning dictionaries
```

#### Problem: Session Timeout Issues

**Solutions**:

1. **Check session configuration**:
   ```bash
   python3 -c "
   import os
   print('Session timeout configured:', 
         os.environ.get('QPKI_SESSION_TIMEOUT', 'default'))
   "
   ```

2. **Verify session cleanup**:
   ```bash
   # Check for expired sessions
   python3 -c "
   import sys
   sys.path.insert(0, 'src')
   from qpki.auth import AuthenticationManager
   from qpki.database import DatabaseManager, DatabaseConfig
   
   db_config = DatabaseConfig.from_env()
   db_manager = DatabaseManager(db_config)
   auth_manager = AuthenticationManager(db_manager)
   
   count = auth_manager.cleanup_expired_sessions()
   print(f'Cleaned up {count} expired sessions')
   "
   ```

---

## 🔍 Debug Tools and Commands

### General Debugging

#### Enable Verbose Logging
```bash
# Run with debug mode
python3 app.py --debug

# Check specific component
python3 -c "
import sys
import logging
sys.path.insert(0, 'src')

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

# Test specific functionality
from qpki.crypto import FlexibleHybridCrypto
crypto = FlexibleHybridCrypto('RSA', rsa_key_size=2048, dilithium_variant=2)
print('Crypto instance created successfully')
"
```

#### Check System Information
```bash
# Python version and packages
python3 --version
pip list | grep -E "(cryptography|flask|jinja2|werkzeug)"

# System resources
df -h
free -h
uptime
```

#### Validate Installation
```bash
# Check all required directories exist
for dir in certificates ca crl logs config templates; do
    if [ -d "$dir" ]; then
        echo "✓ $dir directory exists"
    else
        echo "✗ $dir directory missing"
    fi
done

# Check configuration files
for file in config/email_config.json; do
    if [ -f "$file" ]; then
        echo "✓ $file exists"
    else
        echo "✗ $file missing"
    fi
done

# Test core imports
python3 -c "
try:
    import sys
    sys.path.insert(0, 'src')
    from qpki.crypto import FlexibleHybridCrypto
    from qpki.database import DatabaseManager
    from qpki.auth import AuthenticationManager
    from qpki.email_notifier import EmailNotificationService
    print('✓ All core modules import successfully')
except Exception as e:
    print('✗ Import error:', e)
"
```

---

## 📞 Getting Help

### Before Seeking Help

1. **Check logs**:
   ```bash
   # Application logs
   tail -50 qpki.log
   
   # Email notification logs
   tail -50 logs/email_notifications.log
   
   # System logs (Linux)
   tail -50 /var/log/syslog | grep qpki
   ```

2. **Gather system information**:
   ```bash
   echo "OS: $(uname -a)"
   echo "Python: $(python3 --version)"
   echo "qPKI directory: $(pwd)"
   echo "Disk space: $(df -h . | tail -1)"
   echo "Memory: $(free -h | head -2)"
   ```

3. **Test basic functionality**:
   ```bash
   # Test web interface access
   curl -I http://localhost:9090
   
   # Test database access
   python3 -c "
   import sys
   sys.path.insert(0, 'src')
   from qpki.database import DatabaseManager, DatabaseConfig
   try:
       db_config = DatabaseConfig.from_env()
       db_manager = DatabaseManager(db_config)
       print('Database connection: OK')
   except Exception as e:
       print('Database connection error:', e)
   "
   ```

### Information to Include

When reporting issues, include:

1. **Error message** (exact text)
2. **Steps to reproduce** the issue
3. **System information** (OS, Python version)
4. **Log excerpts** (relevant error logs)
5. **Configuration details** (without sensitive data)
6. **Screenshots** (if applicable)

### Common Log Locations

```bash
# Application logs
qpki.log
logs/email_notifications.log
logs/expiration_check.log

# System logs
/var/log/syslog (Linux)
/var/log/system.log (macOS)

# Web server logs (if using nginx/apache)
/var/log/nginx/error.log
/var/log/apache2/error.log
```

---

## 🔧 Emergency Recovery

### Complete System Reset

If the system is completely broken and you need to start fresh:

```bash
# 1. Backup existing certificates (if recoverable)
mkdir -p backup/$(date +%Y%m%d_%H%M%S)
cp -r certificates/ ca/ crl/ backup/$(date +%Y%m%d_%H%M%S)/ 2>/dev/null || true

# 2. Stop qPKI
pkill -f "app.py"

# 3. Clean slate
rm -f qpki.db qpki.log notifications.db
rm -rf logs/

# 4. Recreate directories
mkdir -p certificates ca crl logs config templates/email

# 5. Restart qPKI
python3 app.py

# 6. Recreate certificates using backup data if needed
```

### Certificate Recovery

If certificates are corrupted but files exist:

```bash
# Check certificate file integrity
for cert in certificates/*.json; do
    if python3 -c "import json; json.load(open('$cert'))" 2>/dev/null; then
        echo "✓ $cert is valid JSON"
    else
        echo "✗ $cert is corrupted"
    fi
done

# Recover from backup
cp backup/certificates/*.json certificates/ 2>/dev/null || echo "No backup found"
```

---

**Remember**: When in doubt, check the logs first! Most issues leave clear error messages in the log files that point to the root cause.

**Next Steps**: If you can't find a solution here, check the [complete documentation](./README.md) or [configuration reference](./config-reference.md) for more detailed information.
