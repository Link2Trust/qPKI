# qPKI Web User Interface

## Overview

The qPKI Web UI provides a comprehensive Flask-based interface for managing hybrid post-quantum certificates. The system supports both RSA and ECC classical algorithms combined with Dilithium post-quantum signatures, ensuring certificates remain secure against both classical and quantum computer attacks.

## Features

### 🔐 Cryptographic Support
- **Classical Algorithms:**
  - RSA (2048, 3072, 4096 bits)
  - ECC (P-256, P-384, P-521 curves)
- **Post-Quantum Algorithm:**
  - Dilithium (variants 2, 3, 5)
- **Hybrid Signatures:** Every certificate contains both classical and post-quantum signatures

### 🏛️ Certificate Authority Management
- Create Root CAs and Subordinate CAs
- Support for both RSA and ECC-based CAs with Dilithium
- Hierarchical CA structure with proper trust chains
- Flexible validity periods (1-20 years)
- Complete X.509v3 certificate information
- CA details view with cryptographic information

### 📄 Certificate Management
- **Full Certificate Lifecycle:**
  - Issue certificates signed by managed CAs
  - Support for server and client certificates
  - Mandatory email addresses for expiration notifications
  - Certificate type selection (Root CA, Subordinate CA, End-entity)
  - Configurable validity periods
  - Certificate revocation support
- **Certificate Viewing:**
  - Detailed certificate information display
  - Certificate status (valid, expired, revoked)
  - Days until expiration with color-coded badges
  - Download certificates in JSON format

### 📧 Email Notification System
- **Automated Expiration Monitoring:**
  - Configurable notification intervals (90, 60, 30, 14, 7, 1 days before expiry)
  - Professional HTML and plain text email templates
  - SMTP integration with popular email providers
  - Duplicate notification prevention
- **Management Interface:**
  - Web-based notification settings configuration
  - Test email functionality
  - Manual certificate expiration checks
  - Notification history and statistics

### 🔄 Certificate Revocation
- **Certificate Revocation Lists (CRL):**
  - Revoke certificates with reason codes
  - Generate and maintain CRLs per CA
  - CRL viewing and download
  - Certificate status tracking

### 🖥️ Web Interface Features
- Modern Bootstrap 5 responsive design
- Intuitive dashboard with system overview and statistics
- Form-based CA and certificate creation with validation
- Certificate and CA listing with search and filtering
- Detailed certificate and CA views
- Real-time cryptographic parameter selection
- Certificate status indicators and expiration warnings
- Error handling and user feedback
- Email notification management interface

## Quick Start

### Prerequisites

Ensure you have the required dependencies:

```bash
pip install -r requirements.txt
```

### Starting the Web Application

```bash
python3 app.py
```

The application will start on `http://localhost:9090`

### Directory Structure

The web application automatically creates:
- `./ca/` - Certificate Authority storage
- `./certificates/` - Certificate storage

## Usage Guide

### 1. Create Your First Certificate Authority

1. Navigate to **Certificate Authorities > Create CA**
2. Fill in the CA information:
   - **Common Name:** Your CA name (e.g., "MyCompany Root CA")
   - **Organization:** Your organization name
   - **Country:** Two-letter country code
3. Select cryptographic parameters:
   - **Classical Algorithm:** Choose RSA or ECC
   - **RSA Key Size:** 2048, 3072, or 4096 bits (if RSA selected)
   - **ECC Curve:** P-256, P-384, or P-521 (if ECC selected)
   - **Dilithium Variant:** 2, 3, or 5 (higher = more secure)
   - **Validity Period:** 5-20 years
4. Click **Create Certificate Authority**

### 2. View Certificate Authorities

1. Navigate to **Certificate Authorities > List CAs**
2. View all created CAs with:
   - Common name and organization
   - Cryptographic algorithm type
   - Creation and expiration dates
   - Actions (view details, download)

### 3. Certificate Creation

1. Navigate to **Certificates > Create Certificate**
2. Select the issuing CA from the dropdown
3. Fill in the certificate information:
   - **Common Name:** The certificate subject (e.g., "www.example.com")
   - **Organization:** Subject organization
   - **Email:** **Required** - Contact email for expiration notifications
   - **Certificate Type:** Root CA, Subordinate CA, or End-entity certificate
4. The cryptographic parameters are inherited from the selected CA
5. Set the validity period (1-10 years)
6. Click **Create Certificate**

### 4. Certificate Management

- **View Certificates:** Navigate to **Certificates > List Certificates**
- **Certificate Details:** Click on any certificate to view full details
- **Certificate Status:** Certificates show their status (Valid, Expired, Revoked)
- **Expiration Monitoring:** Days until expiration with color-coded urgency
- **Certificate Revocation:** Revoke certificates with reason codes

### 5. Email Notifications

1. Navigate to **Notifications** in the main menu
2. Configure SMTP settings for your email provider
3. Set up notification intervals and customize email templates
4. Test email functionality
5. Enable automatic monitoring or run manual checks

### 6. Certificate Revocation Lists (CRL)

- **Revoke Certificates:** Use the revoke button in certificate details
- **View CRLs:** Navigate to CRL section for each CA
- **Download CRLs:** Export CRL files for external use

## Technical Details

### Certificate Format

qPKI stores certificates in JSON format containing:

```json
{
  "certificate": {
    "version": "v3",
    "serial_number": "...",
    "signature_algorithm": "hybrid",
    "issuer": { "common_name": "...", "organization": "..." },
    "subject": { "common_name": "...", "organization": "..." },
    "validity": {
      "not_before": "2024-01-01T00:00:00Z",
      "not_after": "2034-01-01T00:00:00Z"
    },
    "cryptographic_info": {
      "hybrid_key_info": {
        "type": "Hybrid (RSA + Post-Quantum)",
        "classical_algorithm": { ... },
        "post_quantum_algorithm": { ... }
      }
    },
    "public_keys": { ... },
    "signature": {
      "classical_signature": "...",
      "dilithium_signature": "...",
      "classical_algorithm": "RSA"
    },
    "fingerprint": "..."
  },
  "private_keys": { ... }
}
```

### Security Notes

⚠️ **Important:** In the current implementation, private keys are stored alongside certificates for demonstration purposes. In a production environment:

- Private keys should be stored securely (HSM, encrypted storage)
- Access controls should be implemented
- Key backup and recovery procedures should be established
- Certificate revocation lists should be maintained

### API Endpoints

The web application provides REST API endpoints:

- `GET /api/algorithms` - Available cryptographic algorithms
- `GET /api/verify/<cert_type>/<filename>` - Certificate validation

## Architecture

### Components

1. **Flask Web Application** (`app.py`)
   - Routes and view functions
   - Form processing and validation
   - File management and storage

2. **Cryptographic Layer** (`src/qpki/crypto/`)
   - `FlexibleHybridCrypto` - Main hybrid crypto class
   - `ECCCrypto` - ECC operations
   - `RSACrypto` - RSA operations  
   - `DilithiumCrypto` - Post-quantum signatures

3. **Templates** (`templates/`)
   - Bootstrap 5 responsive HTML templates
   - Form-based user interfaces
   - Error handling pages

### Dependencies

- **Flask** - Web framework
- **cryptography** - Classical cryptography (RSA, ECC)
- **pqcrypto** - Post-quantum cryptography (Dilithium)
- **Bootstrap 5** - Frontend styling
- **Font Awesome** - Icons

## Development

### Adding New Features

The modular architecture makes it easy to extend:

1. **New Cryptographic Algorithms:**
   - Add crypto modules in `src/qpki/crypto/`
   - Update `FlexibleHybridCrypto` to support new algorithms
   - Update web forms and validation

2. **Certificate Extensions:**
   - Modify certificate creation logic in `app.py`
   - Add form fields in templates
   - Update certificate parsing for display

3. **Additional Certificate Types:**
   - Extend certificate creation logic
   - Add specialized templates
   - Update navigation and routing

### Testing

Test the cryptographic components:

```bash
python3 test_ecc.py
```

## Implemented Features ✅

- [x] **Complete certificate creation functionality** - Full certificate lifecycle management
- [x] **Certificate revocation lists (CRL)** - Full CRL support with generation and management
- [x] **Email notification system** - Automated expiration monitoring with SMTP integration
- [x] **Certificate status tracking** - Real-time status monitoring and expiration warnings
- [x] **Web interface for PKI management** - Complete Flask-based UI
- [x] **Hybrid cryptography support** - RSA/ECC + Dilithium combinations
- [x] **Certificate hierarchy** - Root CA and Subordinate CA support

## Future Enhancements

- [ ] OCSP responder integration
- [ ] Hardware Security Module (HSM) support
- [ ] X.509 PEM/DER export (partial implementation available)
- [ ] Advanced certificate validation and path verification
- [ ] Multi-user authentication and authorization
- [ ] Certificate templates and profiles
- [ ] Automated certificate renewal
- [ ] Integration with external CAs
- [ ] REST API for certificate operations
- [ ] Certificate backup and restore functionality

## Support

For questions, issues, or contributions, please refer to the main qPKI documentation and repository.

---

**qPKI Web UI** - Quantum-Safe Certificate Management Made Simple
