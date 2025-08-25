# qPKI Production Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying qPKI in a production environment with TLS security, proper authentication, and enterprise-grade security measures.

## Prerequisites

- Ubuntu 20.04 LTS or newer (recommended)
- Root access or sudo privileges
- Domain name (optional, use your own domain or localhost for testing)
- PostgreSQL database server
- Redis server for rate limiting and session storage

## Quick Start

For automated production deployment, run the setup script:

```bash
# Clone the repository
git clone https://github.com/yourusername/qPKI.git
cd qPKI

# Set domain name (optional)
export QPKI_DOMAIN=your-domain.com

# Run automated setup (requires sudo)
sudo ./scripts/setup_production.sh
```

## Manual Installation Steps

### 1. System Dependencies

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    nginx \
    postgresql \
    postgresql-contrib \
    redis-server \
    certbot \
    python3-certbot-nginx \
    ufw \
    fail2ban \
    git \
    supervisor
```

### 2. Database Setup

```bash
# Switch to postgres user
sudo -u postgres psql

# Create database and user
CREATE DATABASE qpki_production;
CREATE USER qpki_user WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE qpki_production TO qpki_user;
\q
```

### 3. Create System User

```bash
# Create qpki user
sudo useradd -r -s /bin/bash -d /opt/qpki qpki

# Create directories
sudo mkdir -p /opt/qpki/{app,data,logs,backups}
sudo mkdir -p /opt/qpki/data/{certificates,ca,crl,keys}

# Set ownership
sudo chown -R qpki:qpki /opt/qpki
sudo chmod 700 /opt/qpki/data/keys
```

### 4. Application Deployment

```bash
# Copy application files
sudo cp -r . /opt/qpki/app/
sudo chown -R qpki:qpki /opt/qpki/app

# Create Python virtual environment
sudo -u qpki python3 -m venv /opt/qpki/venv

# Install dependencies
sudo -u qpki /opt/qpki/venv/bin/pip install -r /opt/qpki/app/requirements.txt
sudo -u qpki /opt/qpki/venv/bin/pip install gunicorn psycopg2-binary redis
```

### 5. SSL/TLS Configuration

#### Option A: Let's Encrypt (Recommended for production)

```bash
# Stop nginx if running
sudo systemctl stop nginx

# Get SSL certificate
sudo certbot certonly --standalone -d your-domain.com

# Copy certificates
sudo mkdir -p /etc/ssl/qpki
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem /etc/ssl/qpki/qpki.crt
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem /etc/ssl/qpki/qpki.key
sudo chmod 600 /etc/ssl/qpki/qpki.key

# Set up auto-renewal
echo "0 12 * * * /usr/bin/certbot renew --quiet" | sudo crontab -
```

#### Option B: Self-signed Certificate (Development/Testing)

```bash
sudo mkdir -p /etc/ssl/qpki
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/qpki/qpki.key \
    -out /etc/ssl/qpki/qpki.crt \
    -subj "/C=US/ST=Development/L=Development/O=qPKI/CN=qpki.link2trust.be"
sudo chmod 600 /etc/ssl/qpki/qpki.key
```

### 6. Environment Configuration

```bash
# Copy production environment file
sudo cp /opt/qpki/app/.env.production /opt/qpki/app/.env

# Edit configuration (update database URL, secret keys, etc.)
sudo nano /opt/qpki/app/.env
```

**Important Configuration Updates:**
- `DATABASE_URL`: Update with your PostgreSQL credentials
- `SECRET_KEY`: Generate a secure random key
- `SMTP_*`: Configure email settings
- `SECURITY_PASSWORD_SALT`: Generate unique salt

### 7. Database Initialization

```bash
# Initialize database
sudo -u qpki bash -c "
    source /opt/qpki/venv/bin/activate
    cd /opt/qpki/app
    python scripts/init_database.py
"
```

### 8. Nginx Configuration

Create nginx configuration file at `/etc/nginx/sites-available/qpki`:

```nginx
# qPKI Production Configuration
upstream qpki_app {
    server 127.0.0.1:9090;
    keepalive 32;
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

# HTTPS Server
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL Configuration
    ssl_certificate /etc/ssl/qpki/qpki.crt;
    ssl_certificate_key /etc/ssl/qpki/qpki.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

    # Main proxy configuration
    location / {
        proxy_pass http://qpki_app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Login endpoint with rate limiting
    location /auth/login {
        limit_req zone=login burst=3 nodelay;
        proxy_pass http://qpki_app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/qpki /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
```

### 9. Systemd Service

Create systemd service file at `/etc/systemd/system/qpki.service`:

```ini
[Unit]
Description=qPKI - Quantum-Safe PKI Application
After=network.target postgresql.service redis.service
Wants=postgresql.service redis.service

[Service]
Type=exec
User=qpki
Group=qpki
WorkingDirectory=/opt/qpki/app
Environment=PATH=/opt/qpki/venv/bin
Environment=FLASK_APP=app_production.py
ExecStart=/opt/qpki/venv/bin/gunicorn --config gunicorn.conf.py app_production:app
ExecReload=/bin/kill -s HUP $MAINPID
Restart=on-failure
RestartSec=10

# Security settings
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/qpki

[Install]
WantedBy=multi-user.target
```

Enable and start services:

```bash
sudo systemctl daemon-reload
sudo systemctl enable qpki
sudo systemctl enable nginx
sudo systemctl enable redis-server
```

### 10. Security Configuration

#### Firewall Setup

```bash
# Configure UFW
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable
```

#### Fail2ban Configuration

Create `/etc/fail2ban/jail.local`:

```ini
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true

[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
```

Enable fail2ban:

```bash
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### 11. Start Services

```bash
# Start all services
sudo systemctl start redis-server
sudo systemctl start qpki
sudo systemctl start nginx
sudo systemctl start fail2ban

# Check status
sudo systemctl status qpki
sudo systemctl status nginx
```

## Security Features

### Authentication
- Demo user: `demo/demo` (for initial access)
- Strong password hashing with PBKDF2
- Account lockout after failed attempts
- Session management with secure cookies

### Network Security
- TLS 1.2/1.3 encryption
- HSTS headers
- Rate limiting on login and API endpoints
- Fail2ban protection

### Application Security
- CSRF protection
- Content Security Policy (CSP)
- Security headers (XSS protection, frame options)
- Input validation and sanitization

### Infrastructure Security
- Dedicated system user with minimal privileges
- File system permissions
- Process isolation
- Log monitoring

## Monitoring & Maintenance

### Health Checks
- Health endpoint: `https://your-domain.com/health`
- Service status: `sudo systemctl status qpki`

### Log Files
- Application logs: `/opt/qpki/logs/qpki.log`
- Access logs: `/opt/qpki/logs/access.log`
- Nginx logs: `/var/log/nginx/`
- System logs: `sudo journalctl -u qpki`

### Regular Maintenance
1. Monitor disk space: `/opt/qpki/data/`
2. Check log rotation: `/etc/logrotate.d/qpki`
3. Update SSL certificates (automatic with Let's Encrypt)
4. Monitor system resources
5. Regular security updates

### Backup Procedures
1. Database backup: `pg_dump qpki_production`
2. Certificate data: `/opt/qpki/data/`
3. Configuration files: `/opt/qpki/app/.env`

## Troubleshooting

### Common Issues

1. **Service won't start**
   ```bash
   sudo journalctl -u qpki -f
   sudo systemctl status qpki -l
   ```

2. **Database connection errors**
   - Check PostgreSQL service: `sudo systemctl status postgresql`
   - Verify connection string in `.env`
   - Test connection: `psql -h qpki.link2trust.be -U qpki_user qpki_production`

3. **SSL certificate issues**
   - Check certificate validity: `openssl x509 -in /etc/ssl/qpki/qpki.crt -text -noout`
   - Verify nginx config: `sudo nginx -t`

4. **Permission errors**
   ```bash
   sudo chown -R qpki:qpki /opt/qpki/
   sudo chmod 700 /opt/qpki/data/keys/
   ```

### Performance Tuning

1. **Gunicorn workers**: Adjust `GUNICORN_WORKERS` in `.env`
2. **Database connections**: Tune `DATABASE_POOL_SIZE`
3. **Redis memory**: Configure Redis memory limit
4. **Nginx buffers**: Adjust proxy buffer sizes

## Security Checklist

- [ ] Change all default passwords
- [ ] Generate secure secret keys
- [ ] Configure proper TLS certificates
- [ ] Enable firewall rules
- [ ] Configure fail2ban
- [ ] Set up log monitoring
- [ ] Regular security updates
- [ ] Monitor access logs
- [ ] Backup procedures in place
- [ ] Test disaster recovery

## Support

For production deployment support:
- Review logs: `/opt/qpki/logs/`
- Check system status: `sudo systemctl status qpki`
- Monitor health: `https://your-domain.com/health`
- Documentation: [GitHub Repository](https://github.com/yourusername/qPKI)

---

**Important**: This is a quantum-safe PKI system. Regular security audits and updates are essential for production environments.
