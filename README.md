# qPKI - Quantum-Safe Hybrid Public Key Infrastructure

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-educational-orange)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Version](https://img.shields.io/badge/version-v1.3-blue)

A **comprehensive hybrid Public Key Infrastructure (PKI)** implementation that combines:
- **Classical cryptography**: RSA and ECC for traditional compatibility
- **Post-quantum cryptography**: Dilithium for quantum-resistant security
- **Modern web interface**: Flask-based UI for certificate management
- **Enterprise features**: Database integration, OCSP, audit logging
- **Email notifications**: Automated certificate expiration management

This project is designed for **educational purposes** to demonstrate quantum-safe cryptographic transitions and hybrid certificate systems with production-like features.

## 🔑 Key Features

### Core PKI Features
- **Hybrid Certificate Authority (CA)**: Issues certificates with both classical and Dilithium signatures
- **Flexible Classical Crypto**: Support for both RSA (2048/3072/4096-bit) and ECC (P-256, P-384, P-521)
- **Certificate Types**: Hybrid (RSA/ECC + Dilithium), Classical (RSA/ECC only), Pure Post-Quantum
- **Complete Certificate Lifecycle**: Generate, validate, revoke, and manage certificates
- **Certificate Revocation Lists (CRL)**: Full CRL generation and management
- **Subordinate CAs**: Create hierarchical CA structures

### Web Interface & User Experience
- **Modern Flask-based UI**: Intuitive web interface for all PKI operations
- **Dashboard**: System overview with certificate counts and status
- **Certificate Management**: Create, view, download, and revoke certificates
- **CA Management**: Create and manage Certificate Authorities
- **Real-time Validation**: Certificate status checking and validation

### Enterprise Features
- **Database Integration**: SQLAlchemy ORM with support for SQLite, PostgreSQL, MySQL
- **Audit Logging**: Comprehensive RFC 3647 compliant audit trail
- **OCSP Support**: Online Certificate Status Protocol implementation
- **Email Notifications**: Automated certificate expiration reminders with MailHog testing
- **API Endpoints**: RESTful API for programmatic access
- **Configuration Management**: Flexible configuration system

### Developer & Educational Features
- **CLI Interface**: Command-line tools for all PKI operations
- **Educational Focus**: Clear code structure with extensive documentation
- **Format Conversion**: Export to standard X.509 formats for compatibility
- **Testing Support**: Comprehensive test suite and MailHog integration
- **Development Tools**: Hot reload, debugging support

## 🏗️ Architecture

```
qPKI/
├── app.py                    # Flask web application
├── src/qpki/
│   ├── __init__.py
│   ├── cli.py                # Command-line interface
│   ├── crypto/               # Cryptographic operations
│   │   ├── __init__.py
│   │   ├── rsa_crypto.py     # RSA operations
│   │   ├── ecc_crypto.py     # ECC operations
│   │   ├── dilithium_crypto.py # Dilithium operations
│   │   └── hybrid_crypto.py  # Combined operations
│   ├── database/             # Database layer
│   │   ├── __init__.py
│   │   ├── config.py         # Database configuration
│   │   ├── models.py         # SQLAlchemy models
│   │   └── manager.py        # Database manager
│   ├── audit/                # Audit system
│   │   ├── __init__.py
│   │   └── events.py         # Audit event definitions
│   ├── ocsp/                 # OCSP implementation
│   │   ├── __init__.py
│   │   └── models.py         # OCSP data models
│   ├── api/                  # REST API
│   │   ├── __init__.py
│   │   └── app.py            # API endpoints
│   ├── utils/                # Utilities
│   │   ├── __init__.py
│   │   └── cert_formats.py   # Certificate format conversion
│   └── email_notifier.py     # Email notification system
├── templates/                # Web UI templates
│   ├── base.html            # Base template
│   ├── index.html           # Dashboard
│   ├── create_ca.html       # CA creation form
│   ├── list_cas.html        # CA listing
│   ├── create_cert.html     # Certificate creation
│   ├── list_certs.html      # Certificate listing
│   ├── notification_*.html  # Email notification templates
│   └── *.html               # Other web templates
├── config/                   # Configuration files
│   ├── email_config.json    # Email configuration
│   └── database_config.json # Database configuration
├── tests/                    # Unit tests
├── examples/                 # Usage examples
├── docs/                     # Documentation
├── scripts/                  # Utility scripts
├── architecture/             # Architecture diagrams
├── logs/                     # Application logs (gitignored)
├── keys/                     # Generated keys (gitignored)
├── ca/                       # CA certificates (gitignored)
├── certificates/             # Certificates (gitignored)
├── crl/                      # Certificate revocation lists (gitignored)
└── docker/                   # Docker configurations
```

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Link2Trust/qPKI.git
cd qPKI

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install the package in development mode
pip install -e .
```

### Email Testing Setup with MailHog

For testing email notifications, we recommend using MailHog:

```bash
# Install MailHog (macOS)
brew install mailhog

# Or download from GitHub releases
# https://github.com/mailhog/MailHog/releases

# Start MailHog
mailhog

# MailHog will be available at:
# SMTP: localhost:1025
# Web UI: http://localhost:8025
```

Configure email settings in the web interface or via config file:
```json
{
  "enabled": true,
  "test_mode": false,
  "smtp_server": "localhost",
  "smtp_port": 1025,
  "from_email": "qpki@example.com"
}
```

### Basic Usage

```bash
# Initialize a new hybrid CA
qpki ca init --name "Hybrid-CA" --org "Link2Trust Educational"

# Generate a hybrid certificate
qpki cert generate --subject "CN=example.com" --ca-name "Hybrid-CA"

# List certificates
qpki cert list

# Validate a certificate
qpki cert validate --cert-file certs/example.com.pem
```

### Web Interface

For a user-friendly experience, start the web interface:

```bash
# Start the Flask web application
python3 app.py

# Or with debugging enabled
FLASK_ENV=development python3 app.py
```

Then visit `http://localhost:9090` to access the comprehensive web interface:

#### Dashboard Features
- System overview with certificate and CA counts
- Quick access to all major functions
- Status indicators for certificates nearing expiration

#### Certificate Authority Management
- Create Root and Subordinate CAs
- Support for RSA (2048/3072/4096-bit) and ECC (P-256/P-384/P-521)
- Hybrid signatures with Dilithium variants (2/3/5)
- CA certificate chain visualization
- CRL generation and management

#### Certificate Management
- Generate certificates with flexible key usage
- Support for hybrid, classical, and pure post-quantum certificates
- Certificate validation and status checking
- Certificate revocation with reason codes
- Download certificates in multiple formats (JSON, PEM, DER)

#### Email Notification System
- Configurable expiration warnings (30, 7, 1 day)
- Custom email templates
- Integration with MailHog for testing
- Notification history and retry management

#### Advanced Features
- Audit log viewer with comprehensive event tracking
- API endpoints for programmatic access
- Certificate format conversion utilities
- OCSP responder status

See [README_WEB_UI.md](README_WEB_UI.md) for detailed web interface documentation.

## 🔬 Educational Components

This implementation demonstrates:

1. **Hybrid Signatures**: How to combine classical and post-quantum signatures in a single certificate
2. **Certificate Chaining**: Building trust chains with dual algorithms and subordinate CAs
3. **Key Management**: Secure storage and handling of multiple key types (RSA, ECC, Dilithium)
4. **Transition Strategy**: How organizations can migrate to quantum-safe cryptography
5. **Compatibility**: Maintaining backward compatibility during crypto-agility transitions
6. **Enterprise PKI**: Database integration, audit logging, and OCSP implementation
7. **Certificate Lifecycle**: Complete certificate management from generation to revocation
8. **Notification Systems**: Automated monitoring and alerting for certificate expiration
9. **API Design**: RESTful interfaces for PKI automation and integration
10. **Standards Compliance**: RFC 3647 audit requirements and X.509 certificate formats

## 🛡️ Cryptographic Algorithms

### Classical: RSA
- **Key Sizes**: 2048, 3072, 4096 bits
- **Padding**: PKCS#1 v2.1 PSS with SHA-256
- **Signature**: RSA-PSS
- **Use**: Backward compatibility, widespread support
- **Security**: Classical security assumptions

### Classical: ECC (Elliptic Curve)
- **Curves**: 
  - P-256 (secp256r1) - 256-bit security level
  - P-384 (secp384r1) - 384-bit security level  
  - P-521 (secp521r1) - 521-bit security level
- **Signature**: ECDSA with SHA-256/384/512
- **Use**: Modern efficiency, smaller keys, faster operations
- **Security**: Discrete logarithm problem in elliptic curves

### Post-Quantum: Dilithium (CRYSTALS-Dilithium)
- **Variants**:
  - Dilithium2 - NIST Security Level 2 (~ AES-128)
  - Dilithium3 - NIST Security Level 3 (~ AES-192)
  - Dilithium5 - NIST Security Level 5 (~ AES-256)
- **Algorithm**: Module-LWE based signatures
- **Use**: Quantum-resistant digital signatures
- **Security**: Resistant to both classical and quantum attacks

### Hybrid Approach
- **Combination**: Classical + Post-Quantum signatures in single certificate
- **Verification**: Requires both signatures to be valid
- **Transition**: Provides security during quantum transition period
- **Compatibility**: Maintains interoperability with existing systems

## 📸 Screenshots

### Dashboard
<img width="1738" height="797" alt="image" src="https://github.com/user-attachments/assets/28f79779-e7cf-44df-a85c-d5a237692add" />

### Certificate Authority List
<img width="1743" height="551" alt="image" src="https://github.com/user-attachments/assets/d94ecf50-c2d0-4c4e-b28f-e674a21eedac" />

### Certificate Authority Detail View
<img width="1724" height="856" alt="image" src="https://github.com/user-attachments/assets/d8f910d1-69ac-4304-b5d4-22649766736d" />

### CRL Detail View
<img width="1735" height="784" alt="image" src="https://github.com/user-attachments/assets/459553fe-5c97-47f2-8145-0251771fc06c" />

### Certificate Creation View
<img width="1714" height="1281" alt="image" src="https://github.com/user-attachments/assets/b01152c0-a29b-4a67-8f6c-0a306e053609" />

### Certificate List
<img width="1739" height="766" alt="image" src="https://github.com/user-attachments/assets/bc23d356-4c1c-4f87-be99-3a3c0b465cd3" />

### Certificate Detail View
<img width="1721" height="864" alt="image" src="https://github.com/user-attachments/assets/539dfcc2-f6aa-4c5e-99a5-5c4132698a74" />







## 🧪 Testing & Development

### Email Testing with MailHog

qPKI includes comprehensive email notification testing:

```bash
# Start MailHog for email testing
mailhog &

# Run the application
python3 app.py

# Configure email settings in web interface
# SMTP Server: localhost:1025
# Web Interface: http://localhost:8025
```

### Running Tests

```bash
# Run all tests
python -m pytest tests/

# Run specific test categories
python -m pytest tests/test_crypto.py
python -m pytest tests/test_database.py
python -m pytest tests/test_notifications.py

# Run with coverage
python -m pytest --cov=qpki tests/
```

### Development Setup

```bash
# Enable development mode
export FLASK_ENV=development
export FLASK_DEBUG=1

# Start with hot reload
python3 app.py
```

## 🔧 Configuration

### Database Configuration

```json
{
  "db_type": "sqlite",
  "connection_string": "sqlite:///qpki.db",
  "auto_migrate": true
}
```

### Email Configuration

```json
{
  "enabled": true,
  "smtp_server": "localhost",
  "smtp_port": 1025,
  "from_email": "qpki@example.com",
  "notification_intervals": [
    {"name": "30_days", "days_before_expiry": 30, "enabled": true},
    {"name": "7_days", "days_before_expiry": 7, "enabled": true},
    {"name": "1_day", "days_before_expiry": 1, "enabled": true}
  ]
}
```

## 📊 Monitoring & Observability

- **Audit Logging**: Comprehensive RFC 3647 compliant audit trail
- **Certificate Monitoring**: Automated expiration tracking
- **Health Checks**: System status and database connectivity
- **Metrics**: Certificate counts, CA statistics, notification history

## 🐳 Docker Support

```bash
# Build Docker image
docker build -t qpki .

# Run with Docker Compose (includes MailHog)
docker-compose up -d

# Access services
# qPKI: http://localhost:9090
# MailHog: http://localhost:8025
```

## 🔒 Security Considerations

### For Educational Use
- Private keys stored in plaintext JSON (educational purposes only)
- No hardware security module (HSM) integration
- Simplified access controls
- Basic audit logging

### Production Readiness Features
- Database integration for persistent storage
- Comprehensive audit logging
- Certificate revocation lists
- Email notification system
- API authentication ready

## 📈 Future Roadmap

- [ ] Hardware Security Module (HSM) integration
- [ ] Advanced access control and user management
- [ ] Key escrow and recovery mechanisms
- [ ] Additional post-quantum algorithms (Falcon, Sphincs+)
- [ ] Certificate Transparency (CT) log integration
- [ ] Advanced OCSP responder features
- [ ] Mobile device certificate enrollment
- [ ] Integration with cloud KMS services

## ⚠️ Educational Disclaimer

This implementation is designed for **educational and research purposes**. While it includes production-like features for learning purposes, do not use in production environments without:

- Comprehensive security review
- Key management security hardening
- Access control implementation
- HSM integration for key protection
- Professional cryptographic audit

## 📚 Learning Resources

### Post-Quantum Cryptography
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [CRYSTALS-Dilithium Specification](https://pq-crystals.org/dilithium/)
- [Open Quantum Safe Project](https://openquantumsafe.org/)

### PKI and X.509
- [RFC 5280 - X.509 Public Key Infrastructure](https://tools.ietf.org/html/rfc5280)
- [RFC 3647 - Certificate Policy and Certification Practice](https://tools.ietf.org/html/rfc3647)
- [RFC 6960 - Online Certificate Status Protocol (OCSP)](https://tools.ietf.org/html/rfc6960)

### Cryptographic Agility
- [NIST Cryptographic Agility Guidelines](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)
- [Hybrid Certificates RFC Draft](https://datatracker.ietf.org/doc/html/draft-ounsworth-pq-composite-sigs)

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Areas for Contribution
- Additional post-quantum algorithms
- Enhanced web interface features
- Mobile applications
- Integration examples
- Documentation improvements
- Security enhancements

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- NIST for post-quantum cryptography standardization
- Open Quantum Safe project for PQC implementations  
- CRYSTALS team for the Dilithium algorithm
- Python cryptography library maintainers

---

*Built with ❤️ for cryptographic education and quantum-safe transitions by Link2Trust*
