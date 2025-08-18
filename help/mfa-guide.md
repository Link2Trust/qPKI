# Multi-Factor Authentication (MFA) Guide

This guide covers the complete setup, management, and troubleshooting of Multi-Factor Authentication in qPKI.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [User Setup](#user-setup)
- [Administrator Management](#administrator-management)
- [Backup Codes](#backup-codes)
- [Troubleshooting](#troubleshooting)
- [Security Best Practices](#security-best-practices)
- [Technical Details](#technical-details)

---

## Overview

qPKI implements Time-based One-Time Password (TOTP) multi-factor authentication to provide an additional layer of security for user accounts. MFA is fully integrated with the web interface and provides enterprise-grade security features.

### Features

- **TOTP Authentication**: Compatible with Google Authenticator, Authy, Microsoft Authenticator, and other TOTP apps
- **Backup Codes**: Single-use recovery codes for emergency access
- **User Self-Service**: Users can enable/disable MFA independently
- **Admin Controls**: Administrators can manage MFA for all users
- **Session Management**: MFA integrates with the existing session system
- **Audit Logging**: Complete logging of MFA activities

### Supported Authenticator Apps

- Google Authenticator (iOS/Android)
- Microsoft Authenticator (iOS/Android)
- Authy (iOS/Android/Desktop)
- 1Password (with TOTP support)
- Bitwarden (with TOTP support)
- Any RFC 6238 compliant TOTP application

---

## Prerequisites

### System Requirements

- qPKI version 2.0.0 or later
- Active user account with valid email address
- Compatible authenticator app installed on mobile device or computer

### Dependencies

The following Python packages are required (automatically installed):
- `pyotp>=2.6.0` - TOTP generation and verification
- `qrcode>=7.0.0` - QR code generation for setup
- `Pillow>=8.0.0` - Image processing for QR codes

---

## User Setup

### Step 1: Accessing MFA Setup

1. Log into qPKI web interface
2. Navigate to your profile page
3. Locate the "Two-Factor Authentication" section
4. Click "Enable Two-Factor Authentication"

### Step 2: QR Code Setup

1. Click "Start Setup" to begin the process
2. A QR code will be displayed on screen
3. Open your authenticator app
4. Scan the QR code or manually enter the secret key
5. The app will start generating 6-digit codes every 30 seconds

### Step 3: Verification

1. Enter the current 6-digit code from your authenticator app
2. Click "Verify and Enable MFA"
3. If successful, backup codes will be displayed
4. **Important**: Save your backup codes securely

### Step 4: Save Backup Codes

After successful setup, you'll see your backup codes. You can:

- **Download as Text File**: Save codes to a file
- **Copy to Clipboard**: Copy all codes for pasting elsewhere  
- **Print**: Generate a printable version
- **Take Screenshot**: For digital storage (not recommended for security)

**⚠️ Security Warning**: Store backup codes securely and treat them like passwords. Each code can only be used once.

---

## Backup Codes

### What are Backup Codes?

Backup codes are single-use recovery codes that allow you to log in if you lose access to your authenticator device. Each account gets 10 backup codes when MFA is first enabled.

### Using Backup Codes

1. At the MFA verification prompt, enter a backup code instead of the TOTP code
2. The code will be immediately invalidated after use
3. You'll be logged in normally

### Managing Backup Codes

#### Viewing Remaining Codes
1. Go to Profile → Two-Factor Authentication
2. Click "View Backup Codes"
3. See how many codes remain unused

#### Regenerating Codes
1. From your profile, click "Regenerate Backup Codes"
2. Enter your current password to confirm
3. New codes will be generated (old codes become invalid)
4. Save the new codes securely

### Best Practices for Backup Codes

- **Secure Storage**: Store in a password manager or secure physical location
- **Multiple Copies**: Keep copies in separate secure locations
- **Regular Updates**: Regenerate codes periodically or after use
- **Access Control**: Don't share codes with others
- **Monitoring**: Check remaining code count regularly

---

## Administrator Management

### Admin MFA Overview

Administrators have additional capabilities for managing MFA across the organization:

- View MFA status for all users
- Force disable MFA for users (emergency access)
- Monitor MFA-related audit logs
- Enforce MFA policies (if implemented)

### Viewing User MFA Status

1. Navigate to Administration → User Management
2. View the user list - MFA status is displayed for each user
3. Click on a user to see detailed MFA information including:
   - MFA enabled date
   - Remaining backup codes
   - Last MFA login

### Emergency MFA Disable

If a user loses access to both their authenticator and backup codes:

1. Navigate to the specific user's profile
2. Click "Disable MFA" in the admin section
3. Confirm the action
4. The user can now log in with username/password only
5. Recommend the user re-enable MFA immediately after login

### MFA-Related Audit Logs

Monitor MFA activities through system logs:

- **MFA Setup**: When users enable MFA
- **MFA Verification**: Successful/failed MFA attempts
- **Backup Code Usage**: When backup codes are used
- **MFA Disable**: When MFA is disabled (user or admin action)
- **Code Regeneration**: When backup codes are regenerated

---

## Login Process with MFA

### Standard Login Flow

1. Enter username and password
2. If credentials are correct and MFA is enabled:
   - Redirected to MFA verification page
   - Enter 6-digit code from authenticator app
   - Click "Verify"
3. Upon successful verification, logged into the system

### Using Backup Codes

1. At the MFA verification screen
2. Enter a backup code in the verification field
3. Click "Verify"
4. The backup code is consumed and login proceeds

### Remember Me Functionality

The "Remember Me" option on the login page works with MFA:
- Session duration is extended for successful MFA logins
- MFA is still required for each login session
- Does not bypass MFA requirement

---

## Troubleshooting

### Common Issues

#### "Invalid verification code" Error

**Possible Causes:**
- Clock synchronization issues
- Incorrect secret key in authenticator
- Code already used (TOTP codes are time-sensitive)

**Solutions:**
1. **Check Time Sync**: Ensure device clocks are synchronized
2. **Re-setup MFA**: Remove and re-add the account in your authenticator
3. **Wait for New Code**: TOTP codes change every 30 seconds
4. **Use Backup Code**: Use a backup code if available

#### Lost Access to Authenticator Device

**Solutions:**
1. **Use Backup Codes**: Enter a backup code to log in
2. **Contact Administrator**: Admin can disable MFA temporarily
3. **Re-setup MFA**: After regaining access, set up MFA again

#### No Backup Codes Available

**If you have current access:**
1. Log in normally
2. Go to Profile → Regenerate Backup Codes
3. Save new codes securely

**If you don't have access:**
1. Contact your administrator
2. Admin can disable MFA temporarily
3. Re-enable MFA and generate new backup codes

#### QR Code Won't Scan

**Solutions:**
1. **Manual Entry**: Use the text secret key instead
2. **Lighting**: Ensure good lighting for scanning
3. **App Updates**: Update your authenticator app
4. **Alternative App**: Try a different authenticator app

### Error Messages

#### "Setup session expired. Please start over."
- **Cause**: MFA setup took too long
- **Solution**: Return to profile and start MFA setup again

#### "Current password is required to disable MFA."
- **Cause**: Security check failed
- **Solution**: Enter your current account password

#### "MFA is already enabled for your account."
- **Cause**: Trying to enable already active MFA
- **Solution**: Go to profile to manage existing MFA settings

### Recovery Procedures

#### Complete MFA Lockout (User)
1. Contact system administrator immediately
2. Provide identity verification as requested
3. Administrator will temporarily disable MFA
4. Change password after regaining access
5. Re-enable MFA with new authenticator setup

#### Administrator Recovery
1. Use database access to disable MFA:
   ```sql
   UPDATE users SET two_factor_enabled = FALSE, totp_secret = NULL, backup_codes = NULL WHERE username = 'locked_user';
   ```
2. Notify user to change password
3. User should re-enable MFA immediately

---

## Security Best Practices

### For Users

1. **Secure Authenticator**: Use PIN/biometric lock on authenticator device
2. **Multiple Devices**: Set up TOTP on multiple trusted devices
3. **Backup Codes Security**: Store backup codes as securely as passwords
4. **Regular Monitoring**: Check login notifications and audit logs
5. **Immediate Reporting**: Report lost devices or suspected compromise

### For Administrators

1. **MFA Enforcement**: Require MFA for all administrative accounts
2. **Regular Audits**: Review MFA usage and disable patterns
3. **Incident Response**: Have procedures for MFA-related lockouts
4. **User Education**: Train users on MFA best practices
5. **Backup Access**: Ensure administrative access during emergencies

### General Security

1. **HTTPS Only**: Always access qPKI over encrypted connections
2. **Trusted Networks**: Set up MFA from trusted networks when possible
3. **Device Security**: Keep authenticator devices updated and secure
4. **Clock Sync**: Ensure server and client clocks are synchronized
5. **Session Management**: Set appropriate session timeouts

---

## Technical Details

### TOTP Implementation

- **Algorithm**: SHA-1 (RFC 6238 standard)
- **Code Length**: 6 digits
- **Time Window**: 30-second intervals
- **Clock Tolerance**: ±1 window for clock drift

### Backup Codes

- **Format**: 8-character alphanumeric codes
- **Quantity**: 10 codes per user
- **Encryption**: Stored encrypted in database
- **Validation**: Single-use codes with secure verification

### Database Schema

MFA data is stored in the users table:
- `totp_secret`: Encrypted TOTP secret key
- `backup_codes`: Encrypted backup codes
- `two_factor_enabled`: Boolean MFA status
- `mfa_enabled_at`: Timestamp of MFA activation

### Session Integration

- MFA verification creates standard user sessions
- Session duration follows normal timeout policies
- MFA status is checked during session validation
- Failed MFA attempts are logged and monitored

### Security Features

- **Rate Limiting**: Prevents brute force attacks on MFA codes
- **Audit Logging**: Complete logging of all MFA activities
- **Secure Storage**: All secrets encrypted at rest
- **Session Validation**: Regular session integrity checks
- **Emergency Access**: Administrative override capabilities

---

## API Integration

### MFA Status Check
```python
GET /auth/api/mfa-status
Headers: Authorization: Bearer <session_token>
```

### MFA Setup
```python
POST /auth/mfa/setup
Content-Type: application/json
{
    "action": "start_setup"
}
```

### MFA Verification
```python
POST /auth/mfa/verify
Content-Type: application/x-www-form-urlencoded
verification_code=123456
```

---

## Conclusion

Multi-Factor Authentication in qPKI provides robust security enhancement while maintaining user-friendly operation. Proper setup, management, and user education are key to successful MFA implementation.

For additional support or advanced configuration options, consult the main qPKI documentation or contact your system administrator.

---

**Document Version**: 1.0  
**Last Updated**: August 13, 2025  
**qPKI Version**: 2.0.0+
