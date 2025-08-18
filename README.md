# qPKI - Quantum-Safe Hybrid Public Key Infrastructure

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-educational-orange)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Version](https://img.shields.io/badge/version-v2.0.1-blue)

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
- **User Authentication & Authorization**: Role-based access control (Admin, Operator, Auditor, Viewer)
- **Multi-Factor Authentication (MFA)**: TOTP-based 2FA with backup recovery codes
- **Session Management**: Secure session handling with automatic cleanup
- **Password Security**: Bcrypt hashing, expiration policies, and strength validation
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

### Database Initialization

```bash
# Initialize the database and create default admin user
python3 scripts/init_database.py

# Initialize with sample users (optional)
python3 scripts/init_database.py --sample-users
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

## 🐧 Linux Deployment

### System Requirements

**Minimum Requirements:**
- Ubuntu 20.04+ / Debian 11+ / CentOS 8+ / RHEL 8+ / Fedora 35+
- Python 3.8 or higher
- 2GB RAM (4GB recommended)
- 10GB disk space
- Network connectivity for package installation

**Recommended for Production:**
- 4GB+ RAM
- 50GB+ disk space (for certificate storage)
- Dedicated user account for security
- Reverse proxy (nginx) for SSL/TLS termination
- Firewall configuration

### Installation Methods

#### Method 1: Manual Installation

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y  # Ubuntu/Debian
# sudo yum update -y                    # CentOS/RHEL
# sudo dnf update -y                    # Fedora

# Install system dependencies
sudo apt install -y python3 python3-pip python3-venv git build-essential libffi-dev libssl-dev

# Create dedicated user for qPKI
sudo useradd -r -s /bin/bash -d /opt/qpki qpki
sudo mkdir -p /opt/qpki
sudo chown qpki:qpki /opt/qpki

# Switch to qpki user
sudo -u qpki bash
cd /opt/qpki

# Clone repository
git clone https://github.com/Link2Trust/qPKI.git .

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

# Create necessary directories
mkdir -p certificates ca crl keys logs

# Initialize database
python3 scripts/init_database.py

# Test installation
qpki --version
python app.py &
# Test at http://localhost:9090
```

#### Method 2: Systemd Service Installation

After completing Method 1, set up qPKI as a system service:

```bash
# Copy service file (as root)
sudo cp qpki.service /etc/systemd/system/

# Reload systemd configuration
sudo systemctl daemon-reload

# Enable and start qPKI service
sudo systemctl enable qpki
sudo systemctl start qpki

# Check service status
sudo systemctl status qpki

# View logs
sudo journalctl -u qpki -f
```

#### Method 3: Docker Deployment

**Quick Start with Docker:**

```bash
# Clone repository
git clone https://github.com/Link2Trust/qPKI.git
cd qPKI

# Build and run with Docker Compose
docker-compose up -d

# Check status
docker-compose logs -f qpki

# Access application at http://localhost:9090
```

**Manual Docker Build:**

```bash
# Build Docker image
docker build -t qpki:latest .

# Run container
docker run -d \
  --name qpki-app \
  -p 9090:9090 \
  -v qpki_data:/opt/qpki/certificates \
  -v qpki_ca:/opt/qpki/ca \
  --restart unless-stopped \
  qpki:latest

# View logs
docker logs -f qpki-app
```

### Security Configuration

#### Firewall Setup (UFW - Ubuntu/Debian)

```bash
# Install and enable UFW
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (adjust port as needed)
sudo ufw allow 22/tcp

# Allow qPKI web interface (adjust as needed)
sudo ufw allow 9090/tcp

# Or allow only from specific networks
# sudo ufw allow from 192.168.1.0/24 to any port 9090

# Enable firewall
sudo ufw enable
sudo ufw status
```

#### Reverse Proxy with Nginx + SSL/TLS

**Install Nginx:**

```bash
sudo apt install nginx certbot python3-certbot-nginx
```

**Configure Nginx (`/etc/nginx/sites-available/qpki`):**

```nginx
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    # SSL Configuration (use certbot for Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    
    # Proxy to qPKI
    location / {
        proxy_pass http://127.0.0.1:9090;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300;
        proxy_connect_timeout 300;
    }
}
```

**Enable site and SSL:**

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/qpki /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# Get SSL certificate (Let's Encrypt)
sudo certbot --nginx -d your-domain.com

# Test auto-renewal
sudo certbot renew --dry-run
```

#### File Permissions and Security

```bash
# Set proper ownership and permissions
sudo chown -R qpki:qpki /opt/qpki
sudo chmod -R 750 /opt/qpki
sudo chmod -R 700 /opt/qpki/keys
sudo chmod -R 700 /opt/qpki/ca

# Secure service file
sudo chmod 644 /etc/systemd/system/qpki.service
sudo chown root:root /etc/systemd/system/qpki.service
```

### Environment Variables

Create `/opt/qpki/.env` for configuration:

```bash
# Application settings
WEB_PORT=9090
FLASK_ENV=production
SECRET_KEY=your-very-secure-secret-key-change-this

# Security settings
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax

# Database settings
DATABASE_URL=sqlite:///qpki.db
# For PostgreSQL: postgresql://qpki:password@localhost/qpki_production

# Email notifications
SMTP_SERVER=localhost
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
```

### Monitoring and Logging

#### System Logs

```bash
# View qPKI service logs
sudo journalctl -u qpki -f --since today

# View nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
```

#### Log Rotation

Create `/etc/logrotate.d/qpki`:

```bash
/opt/qpki/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 qpki qpki
    postrotate
        systemctl reload qpki
    endscript
}
```

### Backup and Recovery

#### Automated Backup Script

```bash
#!/bin/bash
# /opt/qpki/backup.sh

BACKUP_DIR="/opt/qpki/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="qpki_backup_${DATE}.tar.gz"

mkdir -p $BACKUP_DIR

# Create backup
tar -czf "${BACKUP_DIR}/${BACKUP_FILE}" \
    certificates/ ca/ crl/ keys/ qpki.db config/ \
    --exclude='*.pyc' --exclude='__pycache__'

# Keep only last 30 days of backups
find $BACKUP_DIR -name "qpki_backup_*.tar.gz" -mtime +30 -delete

echo "Backup created: ${BACKUP_FILE}"
```

#### Cron Job for Automated Backups

```bash
# Edit cron as qpki user
sudo -u qpki crontab -e

# Add daily backup at 2 AM
0 2 * * * /opt/qpki/backup.sh
```

### Troubleshooting

#### Common Issues

**Service won't start:**
```bash
# Check service status and logs
sudo systemctl status qpki
sudo journalctl -u qpki -n 50

# Check Python environment
sudo -u qpki bash
source /opt/qpki/venv/bin/activate
qpki --version
```

**Port already in use:**
```bash
# Check what's using port 9090
sudo netstat -tlnp | grep 9090
sudo lsof -i :9090

# Change port in .env file
echo "WEB_PORT=9091" >> /opt/qpki/.env
sudo systemctl restart qpki
```

**Permission denied errors:**
```bash
# Reset permissions
sudo chown -R qpki:qpki /opt/qpki
sudo chmod -R 750 /opt/qpki
sudo chmod -R 700 /opt/qpki/keys /opt/qpki/ca
```

**Database issues:**
```bash
# Reset database
sudo -u qpki bash
cd /opt/qpki
source venv/bin/activate
python3 scripts/init_database.py --reset
```

### Production Checklist

- [ ] Dedicated user account created
- [ ] Proper file permissions set
- [ ] Firewall configured
- [ ] SSL/TLS certificate installed
- [ ] Reverse proxy configured
- [ ] Environment variables secured
- [ ] Database initialized
- [ ] Logging configured
- [ ] Backup strategy implemented
- [ ] Monitoring set up
- [ ] Service auto-start enabled
- [ ] Security headers configured
- [ ] Regular security updates scheduled

## 📚 Complete Documentation

For comprehensive documentation including setup guides, troubleshooting, and recent updates:

- **[Complete User Documentation](help/README.md)** - Full documentation index
- **[Multi-Factor Authentication Guide](help/mfa-guide.md)** - Complete MFA setup and management
- **[Troubleshooting Guide](help/troubleshooting.md)** - Common issues and solutions
- **[Recent Updates](help/recent-updates.md)** - Latest features, bug fixes, and improvements

## 🔐 Authentication & User Management

### User Roles & Permissions

qPKI implements a comprehensive role-based access control system:

| Role | Permissions | Description |
|------|------------|-------------|
| **Admin** | Full system access | User management, system configuration, all PKI operations |
| **Operator** | Certificate operations | Create, revoke certificates and CAs, manage CRLs |
| **Auditor** | Read-only access + audit logs | View certificates, CAs, system logs, compliance reports |
| **Viewer** | Read-only access | View certificates and CAs only |

### Authentication Features

- **Secure Password Hashing**: Bcrypt with configurable rounds
- **Multi-Factor Authentication (MFA)**: TOTP-based 2FA with Google Authenticator, Authy, Microsoft Authenticator support
- **Backup Recovery Codes**: 10 single-use codes for MFA account recovery
- **Password Policies**: Minimum length, complexity requirements, expiration
- **Session Management**: Secure tokens, automatic timeout, concurrent session control
- **Account Security**: Login attempt limiting, account lockout protection
- **Forced Password Changes**: Admin-initiated password resets with mandatory change

### User Management

```bash
# List all users
python3 scripts/reset_password.py --list

# Reset user password
python3 scripts/reset_password.py --username operator --force-change

# Reset with custom password
python3 scripts/reset_password.py --username operator --password "NewSecurePass123!"
```

### Web Interface Authentication

- **Login Page**: Clean, responsive design with client-side validation
- **Profile Management**: Users can update personal information and passwords
- **Admin Panel**: Complete user lifecycle management (create, edit, disable, delete)
- **Session Monitoring**: View and manage active user sessions
- **Security Indicators**: Password strength meter, expiration warnings

### Default Credentials

After database initialization, use the generated admin credentials:

```bash
# The init script will display:
# ✅ Default admin created. Username: admin, Password: [random-password]
```

For security, change the default password immediately after first login.

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

### Certificate Expiry Notification Mails
#### Notification for 90 days
<img width="498" height="822" alt="image" src="https://github.com/user-attachments/assets/4348d56e-9e1e-48c5-90cf-e66978347a35" />

#### Notification for 30 days
<img width="505" height="941" alt="image" src="https://github.com/user-attachments/assets/3f9d1f34-90a6-4df7-8354-e6af77de2005" />

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
