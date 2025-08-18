# qPKI - Quantum-Safe Hybrid Public Key Infrastructure

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-educational-orange)

A **hybrid Public Key Infrastructure (PKI)** implementation that combines:
- **Classical cryptography**: RSA and ECC for traditional compatibility
- **Post-quantum cryptography**: Dilithium for quantum-resistant security
- **Modern web interface**: Flask-based UI for certificate management

This project is designed for **educational purposes** to demonstrate quantum-safe cryptographic transitions and hybrid certificate systems.

## 🔑 Key Features

- **Hybrid Certificate Authority (CA)**: Issues certificates with both classical and Dilithium signatures
- **Flexible Classical Crypto**: Support for both RSA and ECC (P-256, P-384, P-521)
- **Web Interface**: Modern Flask-based UI for certificate management
- **Email Notifications**: Automated certificate expiration reminders
- **Certificate Lifecycle**: Complete certificate and CA lifecycle management
- **Certificate Revocation**: CRL (Certificate Revocation List) support
- **Dual Key Generation**: Creates classical and post-quantum key pairs
- **Certificate Management**: Generate, validate, and manage hybrid certificates
- **Educational Focus**: Clear code structure with extensive documentation
- **CLI Interface**: Easy-to-use command-line tools for PKI operations

## 🏗️ Architecture

```
qPKI/
├── app.py                  # Flask web application
├── src/qpki/
│   ├── __init__.py
│   ├── cli.py              # Command-line interface
│   ├── ca/                 # Certificate Authority logic
│   │   ├── __init__.py
│   │   ├── hybrid_ca.py    # Main CA implementation
│   │   └── certificate.py  # Certificate handling
│   ├── crypto/             # Cryptographic operations
│   │   ├── __init__.py
│   │   ├── rsa_crypto.py   # RSA operations
│   │   ├── ecc_crypto.py   # ECC operations
│   │   ├── dilithium_crypto.py # Dilithium operations
│   │   └── hybrid_crypto.py    # Combined operations
│   ├── keys/               # Key management
│   │   ├── __init__.py
│   │   ├── key_manager.py  # Key generation and storage
│   │   └── key_store.py    # Secure key storage
│   └── utils/              # Utilities
│       ├── __init__.py
│       ├── config.py       # Configuration management
│       └── logger.py       # Logging utilities
├── templates/              # Web UI templates
│   ├── base.html          # Base template
│   ├── index.html         # Dashboard
│   ├── create_ca.html     # CA creation form
│   ├── list_cas.html      # CA listing
│   └── *.html             # Other web templates
├── tests/                  # Unit tests
├── examples/               # Usage examples
├── test_ecc.py            # ECC functionality tests
├── keys/                   # Generated keys (gitignored)
├── ca/                     # CA certificates (gitignored)
└── certificates/           # Certificates (gitignored)
```

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Link2Trust/qPKI.git
cd qPKI

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
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
```

Then visit `http://localhost:9090` to:
- Create Certificate Authorities with RSA or ECC + Dilithium
- Manage certificates through a modern web interface
- Download certificates in hybrid JSON format
- View detailed cryptographic information

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

#### Database Security (Optional - if using external DB)

For production deployments with external databases:

```bash
# PostgreSQL example
sudo -u postgres createuser --no-createdb --no-createrole --no-superuser qpki
sudo -u postgres createdb --owner=qpki qpki_production
sudo -u postgres psql -c "ALTER USER qpki WITH PASSWORD 'secure_password';"

# Update qPKI configuration for database connection
# (Implementation depends on your specific requirements)
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

# Database settings (if applicable)
# DATABASE_URL=postgresql://qpki:password@localhost/qpki_production

# Email notifications (if configured)
# SMTP_SERVER=localhost
# SMTP_PORT=587
# SMTP_USERNAME=
# SMTP_PASSWORD=
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
    certificates/ ca/ crl/ keys/ \
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

**Dependencies issues:**
```bash
# Reinstall dependencies
sudo -u qpki bash
source /opt/qpki/venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt --force-reinstall
```

#### Performance Tuning

**For high-traffic deployments:**

```bash
# Use Gunicorn WSGI server
sudo -u qpki bash
source /opt/qpki/venv/bin/activate
pip install gunicorn

# Update systemd service to use Gunicorn
# ExecStart=/opt/qpki/venv/bin/gunicorn -w 4 -b 0.0.0.0:9090 app:app
```

### Production Checklist

- [ ] Dedicated user account created
- [ ] Proper file permissions set
- [ ] Firewall configured
- [ ] SSL/TLS certificate installed
- [ ] Reverse proxy configured
- [ ] Environment variables secured
- [ ] Logging configured
- [ ] Backup strategy implemented
- [ ] Monitoring set up
- [ ] Service auto-start enabled
- [ ] Security headers configured
- [ ] Database secured (if applicable)
- [ ] Regular security updates scheduled

## 🔬 Educational Components

This implementation demonstrates:

1. **Hybrid Signatures**: How to combine classical and post-quantum signatures
2. **Certificate Chaining**: Building trust chains with dual algorithms
3. **Key Management**: Secure storage and handling of multiple key types
4. **Transition Strategy**: How organizations can migrate to quantum-safe crypto
5. **Compatibility**: Maintaining backward compatibility during transitions

## 🛡️ Cryptographic Algorithms

### Classical: RSA
- **Key Size**: 2048/3072/4096 bits
- **Padding**: PSS with SHA-256
- **Use**: Backward compatibility, current standards compliance

### Classical: ECC (Elliptic Curve)
- **Curves**: P-256 (secp256r1), P-384 (secp384r1), P-521 (secp521r1)
- **Signature**: ECDSA with SHA-256
- **Use**: Modern efficiency, smaller key sizes, faster operations

### Post-Quantum: Dilithium
- **Variant**: Dilithium2/3/5 (CRYSTALS-Dilithium)
- **Security Level**: NIST Level 2/3/5
- **Use**: Quantum-resistant digital signatures

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







## ⚠️ Educational Disclaimer

This implementation is designed for **educational and research purposes only**. Do not use in production environments without thorough security review and testing.

## 📚 Learning Resources

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [CRYSTALS-Dilithium Specification](https://pq-crystals.org/dilithium/)
- [RFC 5280 - X.509 Certificates](https://tools.ietf.org/html/rfc5280)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

*Built with ❤️ for cryptographic education by Link2Trust*
