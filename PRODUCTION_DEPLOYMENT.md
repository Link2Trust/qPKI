# qPKI Production Deployment Guide

This document provides comprehensive instructions for deploying qPKI in a production environment with enterprise-grade security.

## 🔒 Security Overview

qPKI in production includes:
- ✅ **Secure Flask Configuration** with disabled debug mode and secure session handling
- ✅ **PostgreSQL Database** with connection pooling and proper permissions
- ✅ **Redis Rate Limiting** to prevent abuse and DoS attacks
- ✅ **Nginx Reverse Proxy** with SSL/TLS termination and security headers
- ✅ **Comprehensive Security Headers** including CSP, HSTS, and XSS protection
- ✅ **Rate Limiting** for authentication and API endpoints
- ✅ **Fail2Ban Integration** for intrusion prevention
- ✅ **Automated Backups** with encryption
- ✅ **Comprehensive Logging** and monitoring
- ✅ **File Permission Hardening** with minimal access principles

## 📋 Prerequisites

### System Requirements
- **OS**: Ubuntu 20.04 LTS+ / Debian 11+ / CentOS 8+ / RHEL 8+
- **Memory**: Minimum 4GB RAM (8GB recommended)
- **Storage**: 50GB+ available disk space
- **CPU**: 2+ cores recommended
- **Network**: Static IP address and domain name

### Software Dependencies
- Python 3.8+
- PostgreSQL 13+
- Redis 6+
- Nginx 1.18+
- Supervisor
- Fail2Ban

## 🚀 Automated Deployment

### Option 1: One-Click Deployment Script

```bash
# Download qPKI
git clone https://github.com/Link2Trust/qPKI.git
cd qPKI

# Run the automated deployment script
sudo ./deploy-production.sh
```

The script will:
1. Install all system dependencies
2. Create dedicated user and secure directories
3. Configure PostgreSQL, Redis, and Nginx
4. Set up firewall and security measures
5. Deploy the application with Gunicorn
6. Configure monitoring and backups

### Option 2: Manual Deployment

Follow the step-by-step instructions below for customized deployment.

## 📝 Manual Deployment Steps

### Step 1: System Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3 python3-pip python3-venv python3-dev \
    postgresql postgresql-contrib redis-server nginx supervisor \
    fail2ban ufw git build-essential libffi-dev libssl-dev
```

### Step 2: Create qPKI User and Directory Structure

```bash
# Create system user
sudo useradd -r -m -s /bin/bash -d /opt/qpki qpki

# Create directory structure
sudo mkdir -p /opt/qpki/{data/{certificates,ca,crl,keys},logs,backups,run,tmp}

# Set permissions
sudo chown -R qpki:qpki /opt/qpki
sudo chmod -R 750 /opt/qpki
sudo chmod -R 700 /opt/qpki/data/keys
sudo chmod -R 700 /opt/qpki/data/ca
```

### Step 3: Database Configuration

```bash
# Start PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database and user
sudo -u postgres psql << EOF
CREATE USER qpki_user WITH PASSWORD 'YOUR_SECURE_PASSWORD';
CREATE DATABASE qpki_production OWNER qpki_user;
GRANT ALL PRIVILEGES ON DATABASE qpki_production TO qpki_user;
\\q
EOF
```

### Step 4: Install qPKI Application

```bash
# Switch to qPKI user
sudo -u qpki bash

# Clone application (or copy your source)
cd /opt/qpki
git clone https://github.com/Link2Trust/qPKI.git source

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r source/requirements.txt
cd source && pip install -e .
```

### Step 5: Configure Environment

```bash
# Copy and customize production environment
sudo -u qpki cp source/.env.production /opt/qpki/.env.production

# Generate secure keys
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
PASSWORD_SALT=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")

# Update environment file with your settings
sudo -u qpki vim /opt/qpki/.env.production
```

### Step 6: Initialize Database

```bash
sudo -u qpki bash << 'EOF'
cd /opt/qpki/source
source /opt/qpki/venv/bin/activate
source /opt/qpki/.env.production
python3 scripts/init_database.py
EOF
```

### Step 7: Configure Nginx

```bash
# Copy nginx configuration
sudo cp source/nginx-qpki.conf /etc/nginx/sites-available/qpki
sudo ln -s /etc/nginx/sites-available/qpki /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default

# Test and restart nginx
sudo nginx -t
sudo systemctl restart nginx
sudo systemctl enable nginx
```

### Step 8: Configure Supervisor

```bash
# Copy supervisor configuration
sudo cp source/supervisor-qpki.conf /etc/supervisor/conf.d/qpki.conf

# Restart supervisor
sudo systemctl restart supervisor
sudo systemctl enable supervisor
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start qpki
```

## 🔐 Security Configuration

### SSL/TLS Certificate Setup

#### Option 1: Let's Encrypt (Recommended)

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d your-domain.com

# Test auto-renewal
sudo certbot renew --dry-run
```

#### Option 2: Self-Signed Certificate

```bash
# Generate self-signed certificate (for testing)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/qpki.key \
    -out /etc/ssl/certs/qpki.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=your-domain.com"
```

### Firewall Configuration

```bash
# Configure UFW firewall
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw --force enable
```

### Fail2Ban Configuration

Fail2Ban is automatically configured by the deployment script to:
- Monitor qPKI authentication logs
- Ban IPs after 5 failed login attempts
- Ban duration: 1 hour
- Monitor nginx authentication failures

## 📊 Monitoring and Maintenance

### Health Checks

```bash
# Check application health
curl -k https://your-domain.com/health

# Check service status
sudo systemctl status qpki-app
sudo supervisorctl status qpki

# View logs
sudo tail -f /opt/qpki/logs/qpki.log
sudo tail -f /opt/qpki/logs/access.log
```

### Log Management

Logs are automatically rotated by the application configuration:
- **Application logs**: `/opt/qpki/logs/qpki.log` (10MB max, 10 backups)
- **Access logs**: `/opt/qpki/logs/access.log` (10MB max, 10 backups)
- **Audit logs**: `/opt/qpki/logs/audit.log`

### Backup and Recovery

#### Automated Backups

The deployment script sets up automated daily backups:

```bash
# Manual backup
sudo -u qpki /opt/qpki/backup-qpki.sh

# View backup files
sudo -u qpki ls -la /opt/qpki/backups/
```

#### Restore from Backup

```bash
# Stop application
sudo supervisorctl stop qpki

# Restore from encrypted backup
cd /opt/qpki
sudo -u qpki openssl enc -aes-256-cbc -d -salt \
    -k "${BACKUP_ENCRYPTION_KEY}" \
    -in backups/qpki_backup_YYYYMMDD_HHMMSS.tar.gz.enc | \
    sudo -u qpki tar -xzf -

# Restart application
sudo supervisorctl start qpki
```

### Database Maintenance

```bash
# Database backup
sudo -u postgres pg_dump qpki_production > qpki_backup.sql

# Vacuum and analyze (monthly maintenance)
sudo -u postgres psql qpki_production -c "VACUUM ANALYZE;"
```

## 🔧 Configuration Management

### Environment Variables

Key production environment variables in `/opt/qpki/.env.production`:

```bash
# Application
FLASK_ENV=production
FLASK_DEBUG=False
SECRET_KEY=your-secure-secret-key

# Database
DATABASE_URL=postgresql://qpki_user:password@localhost/qpki_production

# Security
SESSION_COOKIE_SECURE=True
WTF_CSRF_ENABLED=True
FORCE_HTTPS=True

# Rate Limiting
RATELIMIT_ENABLED=True
MAX_LOGIN_ATTEMPTS=5

# Logging
LOG_LEVEL=INFO
AUDIT_LOG_PATH=/opt/qpki/logs/audit.log
```

### Application Updates

```bash
# Stop application
sudo supervisorctl stop qpki

# Update code
sudo -u qpki bash << 'EOF'
cd /opt/qpki/source
git pull origin main
source /opt/qpki/venv/bin/activate
pip install -r requirements.txt
EOF

# Restart application
sudo supervisorctl start qpki
```

## 📈 Performance Tuning

### Gunicorn Configuration

Adjust worker processes in `gunicorn.conf.py`:

```python
# Rule of thumb: (2 x CPU cores) + 1
workers = 4  # For 2-core system
worker_class = 'sync'
timeout = 120
keepalive = 5
max_requests = 1000
```

### Database Performance

```sql
-- PostgreSQL performance settings
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET random_page_cost = 1.1;
SELECT pg_reload_conf();
```

### Redis Performance

```bash
# Edit Redis configuration
sudo vim /etc/redis/redis.conf

# Key settings:
maxmemory 256mb
maxmemory-policy allkeys-lru
save 900 1
```

## 🚨 Troubleshooting

### Common Issues

#### Application Won't Start

```bash
# Check logs
sudo tail -f /opt/qpki/logs/qpki.log
sudo supervisorctl tail -f qpki

# Check configuration
sudo -u qpki bash << 'EOF'
cd /opt/qpki/source
source /opt/qpki/venv/bin/activate
python3 -c "from app_production import create_app; create_app()"
EOF
```

#### Database Connection Issues

```bash
# Test database connection
sudo -u qpki psql -h localhost -U qpki_user -d qpki_production -c "SELECT version();"

# Check PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-13-main.log
```

#### SSL Certificate Issues

```bash
# Check certificate validity
openssl x509 -in /etc/ssl/certs/qpki.crt -text -noout

# Test SSL configuration
sudo nginx -t
curl -I https://your-domain.com
```

#### High Memory Usage

```bash
# Check process memory usage
sudo ps aux | grep -E '(gunicorn|qpki)'

# Monitor with htop
sudo htop

# Restart application
sudo supervisorctl restart qpki
```

### Performance Issues

```bash
# Check system resources
free -h
df -h
iostat 1 5

# Check application metrics
curl -k https://your-domain.com/metrics

# Monitor database performance
sudo -u postgres psql qpki_production -c "
SELECT pid, now() - pg_stat_activity.query_start AS duration, query 
FROM pg_stat_activity 
WHERE (now() - pg_stat_activity.query_start) > interval '5 minutes';
"
```

## 📋 Production Checklist

### Pre-Deployment
- [ ] DNS configured and pointing to server
- [ ] SSL certificates obtained and installed
- [ ] Firewall configured and tested
- [ ] Database created with secure password
- [ ] Environment variables configured
- [ ] Backup procedures tested

### Post-Deployment
- [ ] Health check endpoint responding
- [ ] User authentication working
- [ ] Certificate generation tested
- [ ] Email notifications configured
- [ ] Logs being written correctly
- [ ] Automated backups running
- [ ] Monitoring alerts configured

### Security Verification
- [ ] Debug mode disabled
- [ ] Secure session configuration
- [ ] CSRF protection enabled
- [ ] Rate limiting active
- [ ] Security headers present
- [ ] File permissions secured
- [ ] Fail2Ban monitoring
- [ ] Regular security updates scheduled

### Performance Verification
- [ ] Response times acceptable (< 2s)
- [ ] Database queries optimized
- [ ] Static files served efficiently
- [ ] Memory usage reasonable
- [ ] CPU usage stable
- [ ] Log rotation working

## 🔄 Maintenance Schedule

### Daily
- Check application status
- Monitor error logs
- Verify backup completion

### Weekly
- Review security logs
- Check system resource usage
- Update system packages

### Monthly
- Database maintenance (VACUUM)
- Certificate expiry checks
- Security assessment
- Performance review

### Quarterly
- Full system backup test
- Disaster recovery drill
- Security configuration review
- Update documentation

---

## Support and Contacts

For production support:
- Check logs first: `/opt/qpki/logs/`
- Review this documentation
- Check GitHub issues
- Contact your system administrator

**Remember**: This is a production PKI system. Always test changes in a staging environment first!
