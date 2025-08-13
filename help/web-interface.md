# Web Interface Guide

The qPKI web interface provides a complete graphical interface for managing your post-quantum PKI infrastructure. This guide covers all features and workflows available through the web UI.

## 🌐 Accessing the Web Interface

### Default Access
- **URL**: `http://localhost:9090`
- **Default Login**: 
  - Username: `admin`
  - Password: `admin`
- **HTTPS**: Not enabled by default (configure SSL for production)

### First Login Steps
1. **Navigate** to `http://localhost:9090`
2. **Login** with default credentials
3. **Change default password** immediately
4. **Configure your profile** and preferences

---

## 🏠 Dashboard Overview

The main dashboard provides a comprehensive system overview:

### 📊 System Statistics
- **Certificate Count**: Total active certificates
- **CA Count**: Number of Certificate Authorities
- **Expiring Soon**: Certificates requiring attention
- **System Status**: Overall health indicators

### 📈 Quick Metrics
- **Certificate Types**: Breakdown of Hybrid/Classical/PQC certificates
- **Algorithm Distribution**: Usage statistics by algorithm
- **Validity Status**: Valid/Expired/Revoked certificate counts
- **Recent Activity**: Latest certificate operations

### 🎯 Quick Actions
- **Create Certificate**: Direct access to certificate creation
- **Create CA**: Quick CA creation link
- **View Notifications**: Check email notification status
- **System Health**: Access monitoring tools

---

## 🏛️ Certificate Authority Management

### CA List View (`/cas`)
Comprehensive view of all Certificate Authorities:

#### 📋 CA Information Display
```
CA Name | Type | Algorithm | Created | Expires | Status | Actions
--------|------|-----------|---------|---------|--------|--------
Root CA | Root | RSA+Dil3 | 2024-01-01 | 2034-01-01 | Active | View | Download
```

#### 🔧 Available Actions
- **View**: Detailed CA information and certificates
- **Download**: Export CA certificate
- **Generate CRL**: Create/update Certificate Revocation List

### CA Creation (`/create_ca`)

#### 🏗️ CA Types
- **Root CA**: Self-signed, top-level authority
- **Subordinate CA**: Signed by parent CA, limited scope

#### 📝 Required Information
```
Identity Information:
├── Common Name: CA display name
├── Organization: Legal entity name
├── Organizational Unit: Department/division
├── Country: Two-letter country code
├── State/Province: Full state name
├── Locality: City name
└── Email Address: CA contact email
```

#### 🔐 Cryptographic Options
```
Classical Algorithms:
├── RSA: 2048, 3072, 4096 bits
└── ECC: secp256r1, secp384r1, secp521r1

Post-Quantum Algorithms:
├── Dilithium-2: Fast, smaller keys
├── Dilithium-3: Balanced (recommended)
└── Dilithium-5: Maximum security

Certificate Types:
├── Hybrid: Classical + PQC (recommended)
├── Classical: RSA or ECC only  
└── PQC: Dilithium only
```

#### ⏱️ Validity Settings
- **Default**: 10 years for Root CA, 5 years for Subordinate CA
- **Recommended**: Align with security policy requirements
- **Maximum**: No system-imposed limits

### CA Detail View (`/ca/<filename>`)

#### 📄 Certificate Information
- **Subject Details**: Complete identity information
- **Validity Period**: Issue and expiry dates
- **Cryptographic Info**: Algorithm details and key parameters
- **Extensions**: Basic constraints, key usage, etc.

#### 🔑 Key Information
- **Public Keys**: Algorithm-specific public key data
- **Key Fingerprints**: Unique identifiers
- **Algorithm Parameters**: Key sizes, curves, variants

#### 📜 Issued Certificates
- **Certificate List**: All certificates issued by this CA
- **Search/Filter**: Find specific certificates
- **Batch Operations**: Revoke multiple certificates

---

## 📜 Certificate Management

### Certificate List View (`/certificates`)

#### 📊 Certificate Table
```
Name | Type | Issuer | Key Usage | Created | Expires | Status | Actions
-----|------|--------|-----------|---------|---------|--------|--------
www.example.com | RSA | Root CA | TLS Server | 2024-01-01 | 2024-04-01 | Valid | View | Download | Revoke
```

#### 🔍 Filtering Options
- **By Status**: Valid, Expired, Revoked
- **By Type**: Hybrid, Classical, PQC
- **By CA**: Filter by issuing CA
- **By Expiry**: Expiring soon, expired
- **Search**: By common name, organization, serial number

#### 📋 Status Indicators
- 🟢 **Valid**: Active and not expired
- 🟡 **Expiring Soon**: Within notification window
- 🔴 **Expired**: Past expiration date
- ⚫ **Revoked**: Certificate has been revoked

### Certificate Creation (`/create_cert`)

#### 📝 Certificate Information
```
Subject Information:
├── Common Name: Certificate primary identifier (required)
├── Organization: Entity name
├── Organizational Unit: Department
├── Country: Two-letter code  
├── State/Province: Full name
├── Locality: City
└── Email Address: Contact email (required for notifications)
```

#### 🎯 Certificate Types
1. **Hybrid Certificate** (Recommended):
   ```
   ✅ Classical Algorithm: RSA or ECC
   ✅ Post-Quantum Algorithm: Dilithium variant
   ✅ Future-proof and current compatible
   ```

2. **Classical Certificate**:
   ```
   ✅ RSA: 2048, 3072, 4096 bits
   ✅ ECC: secp256r1, secp384r1, secp521r1  
   ✅ Universal compatibility
   ```

3. **PQC Certificate**:
   ```
   ✅ Dilithium-2/3/5 only
   ✅ Quantum-resistant
   ⚠️ Limited current compatibility
   ```

#### 🔐 Key Usage Selection
- **Digital Signature**: For authentication and integrity
- **Key Encipherment**: For encrypting symmetric keys
- **Key Agreement**: For key exchange protocols
- **Certificate Sign**: For CA certificates only
- **CRL Sign**: For CRL signing authority

#### ⏱️ Validity Configuration
- **Default**: 365 days (1 year)
- **Recommended**: 90 days for testing, 1-2 years for production
- **Security Consideration**: Shorter validity = better security

### Certificate Detail View (`/certificate/<filename>`)

#### 📋 Certificate Overview
- **Subject Information**: Complete identity details
- **Issuer Information**: CA that signed the certificate
- **Validity Period**: Valid from/to dates
- **Serial Number**: Unique certificate identifier

#### 🔐 Cryptographic Details
- **Algorithm Information**: Detailed crypto parameters
- **Public Key Data**: Algorithm-specific key information
- **Signature Information**: Signature algorithm and data
- **Key Fingerprint**: Unique key identifier

#### 📊 Certificate Extensions
- **Basic Constraints**: CA/end-entity designation
- **Key Usage**: Permitted cryptographic operations
- **Subject Alternative Names**: Additional identifiers
- **Certificate Policies**: Policy information

#### 📁 Download Options
```
Available Formats:
├── JSON: qPKI native format (all certificate types)
├── PEM (.crt): X.509 PEM format (Classical certificates only)
├── DER (.cer): X.509 DER format (Classical certificates only)  
└── PKCS#12 (.p12): Certificate + private key (future feature)
```

---

## 📧 Email Notification System

### Notification Settings (`/notifications`)

#### ⚙️ SMTP Configuration
```
Server Settings:
├── SMTP Server: mail.yourcompany.com
├── SMTP Port: 587 (TLS) or 465 (SSL)
├── Security: TLS, SSL, or None
├── Username: SMTP authentication username
└── Password: SMTP authentication password

From Address:
├── From Email: noreply@yourcompany.com
└── From Name: qPKI Certificate System
```

#### 📅 Notification Intervals
```
Default Schedule:
├── 90 days before expiry: Early planning notice
├── 60 days before expiry: Begin renewal process  
├── 30 days before expiry: Renewal reminder
├── 14 days before expiry: Urgent action required
├── 7 days before expiry: Critical alert
├── 1 day before expiry: Final warning
└── Day of expiry: Expiration notice
```

#### 🎛️ Configuration Options
- **Enable/Disable**: Toggle entire notification system
- **Test Mode**: Log notifications without sending emails
- **Individual Intervals**: Enable/disable specific notification types
- **Custom Subjects**: Personalize email subject lines
- **Template Selection**: Choose email templates

### Notification Testing

#### 🧪 Test Email Function
1. **Enter test email address**
2. **Click "Send Test Email"**
3. **Check email inbox** (or logs in test mode)
4. **Verify SMTP configuration** is working

#### 📊 Manual Certificate Check
1. **Click "Check Certificates Now"**
2. **Review results** in notification history
3. **Check logs** for detailed information
4. **Verify notifications** were sent correctly

### Notification History (`/notifications/history`)

#### 📋 Sent Notifications
```
Date | Certificate | Notification Type | Email | Status
-----|-------------|------------------|--------|--------
2024-01-01 | www.example.com | 30_days_before | admin@example.com | Sent
```

#### 🔍 History Features
- **Search**: Find specific notifications
- **Filter**: By date, certificate, or type
- **Export**: Download notification history
- **Statistics**: Notification success rates

---

## 🔒 Authentication & Security

### User Management (`/auth/users`)

#### 👥 User Accounts
- **Admin Users**: Full system access
- **CA Operators**: Certificate Authority management
- **Certificate Users**: Certificate creation and management
- **Viewers**: Read-only access

#### 🛡️ Role-Based Permissions
```
Permission Structure:
├── ca.create: Create Certificate Authorities
├── ca.view: View CA information
├── cert.create: Create certificates  
├── cert.view: View certificates
├── cert.revoke: Revoke certificates
├── crl.generate: Generate/manage CRLs
├── notifications.view: Access notification system
└── admin: Full administrative access
```

### Login & Session Management

#### 🔐 Authentication Features
- **Username/Password**: Standard login
- **Session Management**: Automatic session cleanup
- **Password Policies**: Configurable password requirements
- **Account Lockout**: Protection against brute force

#### 🛡️ Security Features  
- **CSRF Protection**: Cross-site request forgery prevention
- **Input Validation**: Sanitized user inputs
- **Audit Logging**: Complete activity logging
- **Secure Headers**: Security-focused HTTP headers

---

## 📊 Certificate Lifecycle Management

### Certificate Revocation

#### 🚫 Revocation Process
1. **Navigate** to certificate details
2. **Click "Revoke Certificate"**  
3. **Select revocation reason**:
   - Key Compromise
   - CA Compromise
   - Change of Affiliation
   - Superseded
   - Cessation of Operation
   - Privilege Withdrawn
   - Unspecified
4. **Confirm revocation**
5. **Certificate is marked as revoked**

#### 📋 CRL Management
- **Automatic CRL Updates**: Revoked certificates added automatically
- **Manual CRL Generation**: Force CRL regeneration
- **CRL Download**: Export Certificate Revocation Lists
- **CRL Validation**: Verify CRL integrity

### Certificate Renewal (Future Feature)
- **Automatic Renewal Detection**: Identify certificates needing renewal
- **Renewal Workflows**: Streamlined renewal process
- **Key Rollover**: Automated key rotation procedures

---

## 🔧 System Administration

### Configuration Management

#### ⚙️ System Settings
- **Database Configuration**: Connection and authentication
- **File Storage**: Certificate and key storage locations
- **Logging Configuration**: Log levels and destinations
- **Security Settings**: Authentication and authorization

#### 🔧 Advanced Configuration
- **Algorithm Parameters**: Cryptographic settings
- **Certificate Templates**: Pre-configured certificate profiles
- **Validation Rules**: Certificate creation policies
- **Integration Settings**: External system connections

### Monitoring & Maintenance

#### 📊 System Health
- **Certificate Statistics**: Comprehensive certificate metrics
- **Performance Monitoring**: System performance indicators
- **Error Reporting**: System error tracking
- **Activity Logs**: Complete operation logging

#### 🧹 Maintenance Tasks
- **Database Cleanup**: Remove expired data
- **Log Rotation**: Manage log file sizes
- **Backup Operations**: Data protection procedures
- **Update Management**: System update procedures

---

## 📱 Mobile & Responsive Design

### Mobile Compatibility
- **Responsive Design**: Works on tablets and phones
- **Touch-Friendly**: Optimized for touch interfaces
- **Essential Features**: Core functionality available
- **Simplified Navigation**: Mobile-optimized menus

### Browser Compatibility
- **Modern Browsers**: Chrome, Firefox, Safari, Edge
- **JavaScript Required**: Enhanced functionality needs JS
- **Progressive Enhancement**: Basic functionality without JS
- **Accessibility**: WCAG compliance features

---

## 🎯 Best Practices

### Navigation Efficiency
1. **Use breadcrumbs** to understand current location
2. **Bookmark frequently used pages** for quick access
3. **Use search functionality** to find specific certificates
4. **Leverage quick actions** from the dashboard

### Security Practices
1. **Change default passwords** immediately
2. **Use strong passwords** for all accounts
3. **Log out when finished** to protect sessions
4. **Review audit logs** regularly for suspicious activity

### Certificate Management
1. **Use descriptive common names** for easy identification
2. **Include email addresses** for notification functionality
3. **Set appropriate validity periods** based on security requirements
4. **Document certificate purposes** in organization fields

### Notification Management
1. **Test email configuration** before relying on notifications
2. **Monitor notification history** to ensure delivery
3. **Set up automated checking** via cron jobs
4. **Use test mode** during initial setup

---

## ❓ Frequently Asked Questions

### **Q: Can I use the web interface on mobile devices?**
A: Yes, the interface is responsive and works on tablets and phones, though some advanced features work better on desktop.

### **Q: How do I backup my certificates through the web interface?**
A: Use the bulk download feature to export all certificates, or use the database backup procedures documented in the admin guide.

### **Q: Can I customize the web interface appearance?**
A: Basic customization is possible through CSS modifications. Advanced customization requires code changes.

### **Q: Is the web interface secure for production use?**
A: Yes, with proper HTTPS configuration, strong authentication, and following security best practices outlined in the security guide.

### **Q: Can multiple users access the system simultaneously?**
A: Yes, the system supports multiple concurrent users with role-based access control.

### **Q: How do I integrate the web interface with existing systems?**
A: The web interface includes API endpoints for integration. See the API documentation for details.

---

**Next Steps**: Learn about [certificate creation workflow](./certificate-workflow.md) or [email notification setup](./email-notifications.md).
