# Multi-Factor Authentication (MFA) Implementation

## Overview

The qPKI system now supports **Two-Factor Authentication (2FA)** using Time-based One-Time Passwords (TOTP) compatible with popular authenticator apps like Google Authenticator, Microsoft Authenticator, and Authy.

## Features

### 🔐 **TOTP-Based Authentication**
- **Time-based codes**: 6-digit codes that refresh every 30 seconds
- **Wide compatibility**: Works with Google Authenticator, Microsoft Authenticator, Authy, 1Password, and more
- **QR code setup**: Easy enrollment with QR code scanning
- **Manual entry**: Fallback secret key for manual setup

### 🔑 **Backup Recovery Codes**
- **8 single-use codes** for account recovery
- **Encrypted storage** using Fernet symmetric encryption
- **Secure download/print** options
- **Automatic tracking** of remaining codes

### 🛡️ **Security Features**
- **Secure key generation** using cryptographically secure random
- **Encrypted backup codes** with AES-128 in CBC mode
- **Session-based setup** with automatic cleanup
- **Comprehensive audit logging** for all MFA events
- **Admin override** capabilities for emergency access

## User Experience

### **Setup Process**
1. **Enable 2FA**: Navigate to Profile → Account Security → Enable 2FA
2. **Scan QR Code**: Use authenticator app to scan the displayed QR code
3. **Verify Setup**: Enter the 6-digit code from your app
4. **Save Backup Codes**: Download/print the 8 backup recovery codes

### **Login Flow**
1. **Standard Login**: Enter username and password
2. **MFA Challenge**: If 2FA is enabled, enter authentication code
3. **Code Options**: Use TOTP code (6 digits) or backup code (8 characters)
4. **Access Granted**: Successfully authenticated with both factors

### **Management**
- **Backup Codes**: View remaining count, regenerate new codes
- **Disable 2FA**: Secure disable with password confirmation
- **Admin Controls**: Administrators can disable 2FA for users

## Technical Implementation

### **Architecture**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   User Login    │────│  MFA Challenge  │────│  Session Create │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Password Auth   │    │ TOTP/Backup     │    │ Full Access     │
│   (Factor 1)    │    │ Code Verify     │    │   Granted       │
│                 │    │   (Factor 2)    │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### **Database Schema**

The User model includes the following MFA fields:
- `totp_secret`: Encrypted TOTP secret key
- `backup_codes`: Encrypted JSON of backup codes
- `two_factor_enabled`: Boolean MFA status flag

### **Key Components**

1. **MFAManager** (`src/qpki/auth/mfa.py`)
   - TOTP generation and verification
   - QR code generation
   - Backup code management
   - Encryption/decryption utilities

2. **Authentication Integration** (`src/qpki/auth/auth_manager.py`)
   - MFA setup and verification methods
   - User management integration
   - Session handling

3. **Web Routes** (`src/qpki/auth/routes.py`)
   - Setup wizard (`/auth/mfa/setup`)
   - Login verification (`/auth/mfa/verify`)
   - Management pages (`/auth/mfa/backup-codes`)

4. **Templates**
   - Setup wizard with QR code
   - Verification form
   - Backup codes display and management
   - Profile integration

## Setup Instructions

### **1. Install Dependencies**

```bash
pip install pyotp qrcode Pillow
```

### **2. Database Migration**

The required database schema is already included in the User model. Run database migration if needed:

```bash
python -c "from app import app; app.db_manager.migrate_database()"
```

### **3. Configuration**

No additional configuration is required. The system automatically:
- Creates encryption keys on first use (stored in `.mfa_key`)
- Generates QR codes dynamically
- Handles all MFA state management

## Usage Guide

### **For Users**

#### **Enabling 2FA**
1. Go to **Profile** → **Account Security**
2. Click **"Enable Two-Factor Authentication"**
3. Scan the QR code with your authenticator app
4. Enter the verification code to complete setup
5. Save your backup codes securely

#### **Logging in with 2FA**
1. Enter your username and password
2. You'll be redirected to the MFA verification page
3. Enter the 6-digit code from your authenticator app
4. Or use a backup code if your app is unavailable

#### **Managing Backup Codes**
1. Go to **Profile** → **Backup Codes**
2. View remaining code count
3. Regenerate new codes if needed (invalidates old ones)

#### **Disabling 2FA**
1. Go to **Profile** → **Account Security**
2. Click **"Disable 2FA"**
3. Enter your password to confirm
4. 2FA will be disabled (not recommended)

### **For Administrators**

#### **User Management**
- View users with 2FA enabled in the user list
- Disable 2FA for users in emergency situations
- Monitor MFA-related activities in audit logs

#### **Emergency Access**
If a user loses access to both their authenticator and backup codes:
1. Verify user identity through alternative means
2. Use admin panel to disable 2FA for the user
3. User can then log in with password only
4. Recommend immediate re-enabling of 2FA

## Security Considerations

### **Encryption**
- **TOTP secrets**: Stored encrypted in the database
- **Backup codes**: Encrypted using Fernet (AES-128 CBC)
- **Encryption key**: Stored in `.mfa_key` with restrictive permissions

### **Session Management**
- **Setup sessions**: Temporary (15-minute expiry)
- **Automatic cleanup**: Expired sessions are cleaned up
- **State isolation**: Setup state is isolated from login state

### **Audit Trail**
All MFA activities are logged:
- MFA enablement/disablement
- Login attempts with 2FA
- Backup code usage
- Admin interventions

### **Best Practices**
1. **Backup codes**: Store in secure, offline location
2. **Device security**: Protect authenticator device
3. **Regular rotation**: Regenerate backup codes periodically
4. **Admin controls**: Monitor and manage user 2FA status

## Troubleshooting

### **Common Issues**

#### **QR Code Won't Scan**
- Use manual entry with the provided secret key
- Check that your device's camera has permission
- Ensure good lighting and focus

#### **Codes Don't Work**
- Check device time synchronization
- Ensure 6-digit codes (not 8-character backup codes)
- Try waiting for the next 30-second cycle

#### **Lost Authenticator Device**
- Use backup codes to log in
- Once logged in, disable and re-enable 2FA
- Generate new backup codes

#### **Lost Backup Codes**
- If you can still access your authenticator:
  1. Log in normally
  2. Go to Profile → Backup Codes
  3. Regenerate new codes
- If you've lost both:
  - Contact your administrator for MFA reset

### **Error Messages**

- **"Invalid verification code"**: Code expired or incorrect
- **"Setup session expired"**: Restart the setup process
- **"MFA not enabled"**: User doesn't have 2FA activated
- **"Backup code already used"**: Each code can only be used once

## API Integration

The MFA system is fully integrated with the existing authentication API:

```python
# Check if user has MFA enabled
user = auth_manager.get_user(user_id=user_id)
if user.two_factor_enabled:
    # Require MFA verification
    pass

# Verify MFA code
success, message = auth_manager.verify_mfa_code(user_id, code)
```

## Future Enhancements

Potential improvements for future versions:
- **SMS backup codes**: SMS-based backup option
- **Hardware keys**: Support for FIDO2/WebAuthn
- **Push notifications**: Mobile app push notifications
- **Risk-based auth**: Conditional 2FA based on login context
- **Admin policies**: Require 2FA for specific roles or actions

## Support

For questions or issues with MFA:
1. Check this documentation
2. Review the troubleshooting section
3. Check system logs for detailed error information
4. Contact your system administrator

---

**Security Note**: Two-factor authentication significantly improves account security. Users are strongly encouraged to enable 2FA and keep backup codes in a secure location.
