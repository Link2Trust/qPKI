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
- Create self-signed root CAs with configurable cryptographic parameters
- Support for both RSA and ECC-based CAs
- Flexible validity periods (5-20 years)
- Complete X.509v3 certificate information
- Quantum-safe signatures

### 📄 Certificate Management
- Issue certificates signed by managed CAs
- Support for server and client certificates
- Configurable validity periods
- Inherit cryptographic algorithms from signing CA
- JSON format for full hybrid signature support

### 🖥️ Web Interface Features
- Modern Bootstrap 5 responsive design
- Intuitive dashboard with system overview
- Form-based CA and certificate creation
- Certificate listing and detailed views
- Download certificates in JSON format
- Real-time cryptographic parameter selection
- Error handling and user feedback

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

The application will start on `http://localhost:5000`

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

### 3. Certificate Creation (Future Feature)

Certificate creation is currently under development. The interface is ready but will be implemented in future versions.

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

## Future Enhancements

- [ ] Complete certificate creation functionality
- [ ] Certificate revocation lists (CRL)
- [ ] OCSP responder integration
- [ ] Hardware Security Module (HSM) support
- [ ] X.509 PEM/DER export
- [ ] Certificate validation and verification
- [ ] Multi-user authentication and authorization
- [ ] Certificate templates and profiles
- [ ] Automated certificate renewal
- [ ] Integration with external CAs

## Support

For questions, issues, or contributions, please refer to the main qPKI documentation and repository.

---

**qPKI Web UI** - Quantum-Safe Certificate Management Made Simple
