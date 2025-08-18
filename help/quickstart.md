# Quick Start Guide

Get up and running with qPKI in 10 minutes! This guide will walk you through the essential steps to create your first Certificate Authority and issue your first certificate.

## 📋 Prerequisites

Before starting, ensure you have:
- ✅ qPKI installed and running
- ✅ Access to the web interface at `http://localhost:9090`
- ✅ Valid login credentials (default: admin/admin)

## 🚀 Step 1: First Login

1. **Open your browser** and navigate to: `http://localhost:9090`
2. **Login** with default credentials:
   - Username: `admin`
   - Password: `admin`
3. **Change default password** (highly recommended for security)

## 🏛️ Step 2: Create Your First Certificate Authority (CA)

### Root CA Creation
1. **Navigate** to `Certificate Authorities` → `Create CA`
2. **Fill in CA Details**:
   ```
   Common Name: My Company Root CA
   Organization: My Company Ltd
   Country: US (or your country code)
   State: Your State
   Locality: Your City
   Email: ca-admin@yourcompany.com
   ```
3. **Select Algorithm**:
   - **Recommended**: RSA-3072 + Dilithium-3 (Hybrid)
   - **Classical Only**: RSA-3072 or ECC-secp256r1
   - **PQC Only**: Dilithium-3
4. **Set Validity**: 10 years (default)
5. **Click** `Create CA`

✅ **Success!** Your Root CA is now created and ready to issue certificates.

## 📜 Step 3: Issue Your First Certificate

### Create an End-Entity Certificate
1. **Navigate** to `Certificates` → `Create Certificate`
2. **Select your CA** from the dropdown
3. **Fill in Certificate Details**:
   ```
   Common Name: www.yourcompany.com
   Organization: My Company Ltd
   Email: admin@yourcompany.com  ⚠️ REQUIRED for notifications
   Country: US
   ```
4. **Choose Certificate Type**:
   - **Hybrid** (Recommended): Classical + Post-Quantum
   - **Classical**: Traditional RSA/ECC only
   - **PQC**: Post-Quantum only
5. **Set Key Usage**:
   - ✅ Digital Signature
   - ✅ Key Encipherment (for web servers)
6. **Set Validity**: 90 days (for testing)
7. **Click** `Create Certificate`

✅ **Success!** Your first certificate is now issued.

## 📥 Step 4: Download Your Certificate

1. **Navigate** to `Certificates` (list view)
2. **Find your certificate** in the list
3. **Use the download dropdown**:
   - **JSON Format**: Complete qPKI format (all certificate types)
   - **PEM (.crt)**: Standard format for Classical certificates
   - **DER (.cer)**: Binary format for Classical certificates

## 📧 Step 5: Set Up Email Notifications (Optional but Recommended)

### Quick Email Setup
1. **Navigate** to `Notifications`
2. **Enable Test Mode** (for now)
3. **Configure Basic Settings**:
   ```
   From Email: noreply@yourcompany.com
   SMTP Server: smtp.gmail.com (or your server)
   SMTP Port: 587
   Security: TLS
   ```
4. **Enable Notifications**: Toggle `Enabled`
5. **Test Configuration**: Enter your email and click `Send Test Email`
6. **Check logs** to verify test email was "sent" (in test mode)

### Set Up Automatic Checking
```bash
# Add to crontab for daily checks at 9 AM
crontab -e

# Add this line:
0 9 * * * /usr/bin/python3 /path/to/qPKI/scripts/check_expiration.py
```

## 🎯 Step 6: Verify Everything Works

### Test Certificate Creation Flow
1. **Create a second certificate** with different settings
2. **Export in different formats** to test download functionality
3. **Check the dashboard** to see your certificate counts
4. **View certificate details** to understand the data structure

### Test Notification System
1. **Navigate** to `Notifications` → `Check Now`
2. **View notification history** to see any alerts
3. **Check logs** in `logs/email_notifications.log`

## 🎉 Congratulations!

You've successfully:
- ✅ Created your first Certificate Authority
- ✅ Issued your first certificate
- ✅ Set up email notifications
- ✅ Learned the basic qPKI workflow

## 🔄 Next Steps

Now that you have the basics working, consider:

### Security Hardening
- [Change default passwords](./security.md#password-security)
- [Set up proper user accounts](./authentication.md#user-management)
- [Configure database authentication](./database.md#authentication)

### Production Setup
- [Configure production SMTP](./smtp-setup.md)
- [Set up automated backups](./backup-recovery.md)
- [Implement monitoring](./dashboard.md#monitoring)

### Advanced Features
- [Create subordinate CAs](./certificate-authorities.md#subordinate-cas)
- [Implement certificate templates](./certificate-workflow.md#templates)
- [Set up certificate renewal procedures](./renewal.md)

## 🚨 Common Issues

### "No CAs Found" Error
- **Solution**: Create a CA first before trying to issue certificates

### Email Notifications Not Working
- **Check**: Email address is present in certificate subject
- **Verify**: SMTP configuration is correct
- **Test**: Use "Send Test Email" feature

### Certificate Download Issues
- **Classical Certificates**: Can download as PEM/DER
- **Hybrid/PQC Certificates**: Only available as JSON
- **Check browser**: Ensure downloads aren't blocked

### Permission Errors
- **Web Interface**: Check user roles and permissions
- **File System**: Ensure proper file permissions on directories

## 📚 Learn More

- **[Complete Web Interface Guide](./web-interface.md)**: Detailed web UI documentation
- **[Certificate Types Guide](./certificate-types.md)**: Understanding different certificate types
- **[Security Best Practices](./security.md)**: Securing your qPKI deployment
- **[Troubleshooting Guide](./troubleshooting.md)**: Solutions to common problems

---

**Need Help?** Check the [troubleshooting guide](./troubleshooting.md) or [complete documentation](./README.md) for more detailed information.
