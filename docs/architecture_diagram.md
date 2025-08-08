# qPKI Application Architecture Diagram

## Overview
The qPKI (Quantum-Safe Public Key Infrastructure) application is a hybrid PKI system that combines classical cryptography (RSA/ECC) with post-quantum cryptography (Dilithium) to provide quantum-resistant certificate management.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                               qPKI System                                       │
│                         Quantum-Safe PKI Solution                              │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│                              User Interfaces                                   │
├─────────────────────────────┬───────────────────────────────────────────────────┤
│       Web Interface         │              Command Line Interface              │
│    (Flask Application)      │                   (CLI Tool)                     │
│                             │                                                   │
│  • Bootstrap Frontend       │  • Click-based CLI                              │
│  • HTML Templates           │  • Colorama for colored output                  │
│  • REST API Endpoints       │  • Tabulate for formatted tables               │
│  • Dashboard & Management   │  • Interactive CA/Cert operations              │
└─────────────────────────────┴───────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           Application Layer (app.py)                           │
├─────────────────────────────────────────────────────────────────────────────────┤
│  • Flask Routes & Request Handling                                             │
│  • Certificate & CA Management Logic                                           │
│  • API Endpoints (/api/*)                                                      │
│  • Template Rendering & Form Processing                                        │
│  • Error Handling & Flash Messages                                             │
└─────────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              Core Services                                     │
├───────────────────┬─────────────────────┬───────────────────────────────────────┤
│   Hybrid CA       │   Key Manager       │   Email Notification Service         │
│   (hybrid_ca.py)  │   (key_manager.py)  │   (email_notifier.py)               │
│                   │                     │                                       │
│ • CA Operations   │ • Key Pair Gen      │ • Expiration Monitoring              │
│ • Cert Issuance   │ • Key Storage       │ • SMTP Email Delivery                │
│ • Cert Validation │ • Key Retrieval     │ • Template Rendering                 │
│ • CRL Management  │ • Key Lifecycle     │ • Notification History               │
│ • Serial Numbers  │ • Metadata Mgmt     │ • SQLite Tracking                    │
└───────────────────┴─────────────────────┴───────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           Cryptographic Layer                                  │
├──────────────────┬─────────────────┬─────────────────┬──────────────────────────┤
│  Hybrid Crypto   │   RSA Crypto    │   ECC Crypto    │   Dilithium Crypto       │
│  (hybrid_crypto  │   (rsa_crypto   │   (ecc_crypto   │   (dilithium_crypto      │
│   .py)           │   .py)          │   .py)          │   .py)                   │
│                  │                 │                 │                          │
│ • Dual Signing   │ • RSA Key Ops   │ • ECC Key Ops   │ • Post-Quantum Sigs     │
│ • Hybrid Keys    │ • PKCS#1/OAEP   │ • P-256/384/521 │ • Dilithium2/3/5        │
│ • Signature      │ • SHA-256 Hash  │ • ECDSA Signing │ • NIST Submission       │
│   Verification   │ • PEM/DER       │ • SEC1 Format   │ • Pure Python Impl      │
│ • Key Mgmt       │   Support       │ • Curve Params  │ • Stateless Signatures  │
└──────────────────┴─────────────────┴─────────────────┴──────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           Utility Services                                     │
├─────────────────────────────────────┬───────────────────────────────────────────┤
│       Certificate Formats           │            File System Storage           │
│       (cert_formats.py)             │               (JSON Files)               │
│                                     │                                           │
│ • Hybrid → Standard X.509 Export    │ • CA Certificates (/ca/*.json)          │
│ • PEM/DER Format Conversion         │ • End Entity Certs (/certificates/)     │
│ • Legacy PKI Compatibility         │ • Certificate Revocation Lists (/crl/)  │
│ • Format Validation                 │ • Private Keys (Encrypted Storage)       │
│ • Metadata Extraction              │ • Public Key Repository                  │
└─────────────────────────────────────┴───────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              Data Layer                                        │
├─────────────────┬─────────────────┬─────────────────┬───────────────────────────┤
│  JSON Storage   │  SQLite Database │  Configuration  │    Template System        │
│                 │                  │    Files        │                           │
│ • Certificates  │ • Notification   │ • email_config  │ • Jinja2 Templates       │
│ • CA Metadata   │   History        │   .json         │ • Email Templates        │
│ • Public Keys   │ • Sent Emails    │ • App Config    │   (HTML/Plain Text)      │
│ • Private Keys  │   Tracking       │ • Logging       │ • Web UI Templates       │
│ • CRLs          │ • Email Queue    │   Config        │ • Form Templates         │
└─────────────────┴─────────────────┴─────────────────┴───────────────────────────┘
```

## Component Details

### 1. User Interfaces

#### Web Interface (Flask)
- **Port**: 9090 (default)
- **Framework**: Flask with Bootstrap 5 frontend
- **Features**:
  - Dashboard with system overview
  - CA creation and management
  - Certificate issuance and lifecycle
  - CRL generation and management
  - Email notification configuration
  - Certificate and CA listing/searching
  - Download capabilities (JSON, PEM, DER formats)

#### Command Line Interface
- **Tool**: Click-based CLI with colored output
- **Commands**:
  - `qpki ca` - CA operations
  - `qpki keys` - Key management
  - `qpki cert` - Certificate operations
- **Features**: Interactive prompts, tabulated output, verbose logging

### 2. Core Services

#### Hybrid Certificate Authority (`HybridCA`)
- **Purpose**: Central PKI authority management
- **Functions**:
  - Self-signed root CA creation
  - Subordinate CA management
  - Certificate issuance with hybrid signatures
  - Certificate validation and verification
  - Certificate revocation and CRL generation
  - Serial number management

#### Key Manager (`KeyManager`)
- **Purpose**: Cryptographic key lifecycle management
- **Functions**:
  - Hybrid key pair generation (RSA/ECC + Dilithium)
  - Secure key storage with optional encryption
  - Key metadata management
  - Key retrieval and deserialization
  - Key expiration tracking
  - Fingerprint generation

#### Email Notification Service (`EmailNotificationService`)
- **Purpose**: Automated certificate lifecycle notifications
- **Features**:
  - Configurable notification intervals (90, 60, 30, 14, 7, 1 days before expiry)
  - HTML and plain text email templates
  - SMTP server integration
  - SQLite-based notification history tracking
  - Duplicate notification prevention
  - Test mode for development

### 3. Cryptographic Layer

#### Hybrid Cryptography (`HybridCrypto`)
- **Purpose**: Combines classical and post-quantum signatures
- **Features**:
  - Dual signing (RSA/ECC + Dilithium)
  - Hybrid key pair management
  - Signature verification with configurable requirements
  - Key serialization/deserialization

#### Classical Cryptography
- **RSA Crypto**: PKCS#1, OAEP, 2048/3072/4096-bit keys
- **ECC Crypto**: NIST curves (P-256, P-384, P-521), ECDSA signatures

#### Post-Quantum Cryptography
- **Dilithium**: NIST submission, variants 2/3/5, stateless signatures
- **Library**: pqcrypto (pure Python implementation)

### 4. Data Storage

#### File System Structure
```
qPKI/
├── ca/                     # Certificate Authority certificates
├── certificates/           # End entity certificates  
├── crl/                   # Certificate Revocation Lists
├── config/                # Configuration files
│   └── email_config.json  # Email notification settings
├── logs/                  # Application logs
└── notifications.db       # SQLite database for email tracking
```

#### Certificate Format
- **Primary**: JSON format (supports full hybrid structure)
- **Export**: PEM/DER formats (classical signature only for compatibility)
- **Fields**: Subject/issuer, public keys, signatures, validity, key usage, extensions

### 5. External Dependencies

#### Python Libraries
- **Flask**: Web application framework
- **cryptography**: Classical cryptography (RSA, ECC, X.509)
- **pqcrypto**: Post-quantum cryptography (Dilithium)
- **Click**: Command-line interface
- **Jinja2**: Template engine
- **SQLite3**: Notification tracking database

#### Frontend Dependencies
- **Bootstrap 5**: Responsive web design
- **Font Awesome**: Icons and visual elements
- **JavaScript**: Form interactions and AJAX calls

## Data Flow

### Certificate Issuance Flow
```
User Request → Web/CLI Interface → HybridCA.issue_certificate() →
KeyManager.generate_key_pair() → HybridCrypto.sign_data_hybrid() →
JSON Storage → Email Notification (if configured)
```

### Certificate Validation Flow
```
Certificate ID → HybridCA.validate_certificate() →
KeyManager.load_key_pair() → HybridCrypto.verify_hybrid_signature() →
Validation Result
```

### Email Notification Flow
```
Scheduled Check → EmailNotificationService.check_expiring_certificates() →
Template Rendering → SMTP Delivery → SQLite History Tracking
```

## Security Considerations

1. **Quantum Resistance**: Dilithium post-quantum signatures provide security against quantum computers
2. **Classical Security**: RSA/ECC signatures maintain current PKI compatibility
3. **Key Storage**: Private keys stored with optional password encryption
4. **Signature Verification**: Configurable dual-signature requirement
5. **Access Control**: Web interface session management
6. **Secure Communication**: HTTPS recommended for production deployment

## Deployment Architecture

### Development Mode
- Single Flask instance on localhost:9090
- File-based storage (JSON files)
- SQLite database for notifications
- Local SMTP server (Mailhog) for testing

### Production Recommendations
- Reverse proxy (nginx) with SSL/TLS
- Process manager (gunicorn/uwsgi)
- Centralized logging
- Backup strategies for certificate storage
- Hardware Security Module (HSM) integration for CA keys
- Database clustering for high availability

## Extensibility Points

1. **Cryptographic Algorithms**: Modular crypto layer supports additional algorithms
2. **Storage Backends**: Abstract storage interface allows database integration
3. **Authentication**: Pluggable authentication providers
4. **Notification Channels**: Extensible notification system (SMS, webhooks)
5. **Certificate Extensions**: Support for custom X.509 extensions
6. **Import/Export Formats**: Additional format converters

This architecture provides a solid foundation for quantum-safe PKI operations while maintaining compatibility with existing PKI infrastructure and standards.
