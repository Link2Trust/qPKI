# qPKI Security Guide

This document provides comprehensive security guidelines, best practices, and incident response procedures for qPKI in production.

## 🛡️ Security Architecture Overview

qPKI implements defense-in-depth security with multiple layers:

```
┌─────────────────────────────────────────────────────┐
│                  Internet/DMZ                        │
├─────────────────────────────────────────────────────┤
│  Nginx Reverse Proxy (SSL/TLS, Security Headers)    │
├─────────────────────────────────────────────────────┤
│  Firewall (UFW) + Fail2Ban (Intrusion Prevention)   │
├─────────────────────────────────────────────────────┤
│  Flask Application (Rate Limiting, CSRF Protection)  │
├─────────────────────────────────────────────────────┤
│  Database Layer (PostgreSQL with encrypted data)     │
├─────────────────────────────────────────────────────┤
│  File System (Encrypted storage, strict permissions) │
└─────────────────────────────────────────────────────┘
```

## 🔒 Core Security Features

### Authentication & Authorization
- **Multi-factor Authentication** (TOTP, hardware tokens)
- **Role-based Access Control** (RBAC) with principle of least privilege
- **Session Management** with secure cookies and timeout
- **Password Policies** with complexity requirements and history
- **Account Lockout** protection against brute force attacks

### Data Protection
- **Encryption at Rest** for sensitive data and private keys
- **Encryption in Transit** with TLS 1.3
- **Key Management** with HSM support and key rotation
- **Secure Storage** with file permissions and directory restrictions
- **Data Integrity** with checksums and digital signatures

### Network Security
- **SSL/TLS Termination** with strong cipher suites
- **Security Headers** (HSTS, CSP, X-Frame-Options, etc.)
- **Rate Limiting** to prevent abuse and DoS attacks
- **IP Whitelisting** for administrative access
- **Network Segmentation** recommendations

### Monitoring & Auditing
- **Comprehensive Logging** of all security events
- **Real-time Monitoring** with alerts for suspicious activity
- **Audit Trail** for compliance and forensic analysis
- **Intrusion Detection** with Fail2Ban integration
- **Security Metrics** and reporting

## 📋 Security Configuration Checklist

### Initial Setup
- [ ] **Change default passwords** for all accounts
- [ ] **Generate secure keys** using cryptographically secure random generators
- [ ] **Configure SSL/TLS** with valid certificates and strong ciphers
- [ ] **Enable firewall** with minimal open ports
- [ ] **Set up Fail2Ban** with custom qPKI rules
- [ ] **Configure secure file permissions** (root CA keys: 600, application: 640)
- [ ] **Enable audit logging** for all administrative actions
- [ ] **Set up backup encryption** with separate key management

### Application Security
- [ ] **Disable debug mode** in production (FLASK_DEBUG=False)
- [ ] **Enable CSRF protection** (WTF_CSRF_ENABLED=True)
- [ ] **Configure secure sessions** (SESSION_COOKIE_SECURE=True)
- [ ] **Set strong session timeout** (15-30 minutes for admin)
- [ ] **Enable rate limiting** for all endpoints
- [ ] **Configure security headers** via flask-talisman
- [ ] **Set up content security policy** (CSP)
- [ ] **Enable HTTP security headers** (HSTS, X-Content-Type-Options, etc.)

### Database Security
- [ ] **Use dedicated database user** with minimal privileges
- [ ] **Enable SSL for database connections**
- [ ] **Configure connection limits** and timeouts
- [ ] **Set up database auditing**
- [ ] **Enable query logging** for sensitive operations
- [ ] **Configure automatic backups** with encryption
- [ ] **Implement database connection pooling**
- [ ] **Regular security updates** for PostgreSQL

### Network Security
- [ ] **Configure UFW firewall** with restrictive rules
- [ ] **Disable unused services** and ports
- [ ] **Set up VPN access** for remote administration
- [ ] **Configure network monitoring**
- [ ] **Implement DDoS protection**
- [ ] **Set up intrusion detection system**
- [ ] **Configure log shipping** to SIEM system
- [ ] **Regular vulnerability scanning**

## 🔐 Cryptographic Standards

### Supported Algorithms
- **RSA**: 2048-bit minimum, 4096-bit recommended
- **ECC**: P-256, P-384, P-521 curves
- **Hash Functions**: SHA-256, SHA-384, SHA-512
- **Symmetric Encryption**: AES-256-GCM, AES-256-CBC
- **Key Derivation**: PBKDF2, scrypt, Argon2

### Certificate Profiles

#### Root CA Certificate
```
Key Usage: Certificate Sign, CRL Sign
Basic Constraints: CA:TRUE, pathlen:1
Key Length: RSA 4096 or ECC P-384
Validity: 10-20 years
```

#### Intermediate CA Certificate
```
Key Usage: Certificate Sign, CRL Sign
Basic Constraints: CA:TRUE, pathlen:0
Key Length: RSA 3072 or ECC P-256
Validity: 5-10 years
```

#### End Entity Certificate
```
Key Usage: Digital Signature, Key Encipherment
Extended Key Usage: Server Auth, Client Auth
Key Length: RSA 2048 or ECC P-256
Validity: 1-3 years
```

### Key Management Best Practices
- **Generate keys on secure hardware** (HSM recommended)
- **Use separate keys** for signing and encryption
- **Implement key rotation** policies
- **Secure key backup** and escrow procedures
- **Key ceremony** documentation for root CA operations
- **Multi-person authorization** for sensitive operations

## 🚨 Incident Response Procedures

### Security Incident Classification

#### Level 1 - Low Impact
- Single failed login attempt
- Minor configuration issues
- Non-critical service warnings

#### Level 2 - Medium Impact
- Multiple failed login attempts from same IP
- Unauthorized access attempts
- Service degradation
- Certificate validation errors

#### Level 3 - High Impact
- Successful unauthorized access
- Data breach suspicion
- System compromise indicators
- Critical service failure
- CA private key compromise suspicion

#### Level 4 - Critical Impact
- Confirmed data breach
- Root CA private key compromise
- Complete system compromise
- Regulatory notification required

### Incident Response Steps

#### Immediate Response (0-30 minutes)
1. **Identify and contain** the threat
2. **Preserve evidence** and logs
3. **Notify security team** and management
4. **Document** initial findings
5. **Implement** emergency countermeasures

#### Short-term Response (30 minutes - 4 hours)
1. **Analyze** the scope of impact
2. **Collect** forensic evidence
3. **Implement** additional security measures
4. **Communicate** with stakeholders
5. **Begin** recovery procedures

#### Recovery (4 hours - days)
1. **Restore** services from clean backups
2. **Apply** security patches and updates
3. **Monitor** for additional threats
4. **Update** security configurations
5. **Test** system functionality

#### Post-Incident (days - weeks)
1. **Conduct** thorough investigation
2. **Prepare** incident report
3. **Implement** lessons learned
4. **Update** procedures and documentation
5. **Notify** regulatory bodies if required

### Emergency Contacts

```bash
# Security Team
Security Manager: +1-xxx-xxx-xxxx
Security Engineer: +1-xxx-xxx-xxxx
On-call SIRT: security@yourorg.com

# Management
IT Director: +1-xxx-xxx-xxxx
CISO: +1-xxx-xxx-xxxx
Legal Counsel: legal@yourorg.com

# External
Local FBI Cyber Unit: +1-xxx-xxx-xxxx
Cyber Insurance: +1-xxx-xxx-xxxx
Regulatory Body: +1-xxx-xxx-xxxx
```

## 🔍 Security Monitoring

### Key Metrics to Monitor

#### Authentication Events
- Failed login attempts per IP/user
- Successful logins from new locations
- Account lockouts and password resets
- Privilege escalation attempts
- Session anomalies

#### Certificate Operations
- Certificate issuance patterns
- Revocation requests
- Key generation failures
- Unusual certificate requests
- CA operations (signing, revocation list updates)

#### System Health
- CPU, memory, disk usage
- Network traffic patterns
- Database query performance
- Application response times
- Error rates and patterns

### Security Alerts Configuration

#### High Priority Alerts
```bash
# Multiple failed logins (>5 in 5 minutes)
# New admin user creation
# Root CA private key access
# System file modifications
# Unusual network traffic patterns
```

#### Medium Priority Alerts
```bash
# Certificate revocation requests
# Failed database connections
# SSL/TLS handshake failures
# Resource usage spikes
# Backup failures
```

#### Low Priority Alerts
```bash
# Single failed login
# Certificate expiration warnings
# Log rotation events
# Routine maintenance notifications
```

### Log Analysis Commands

#### Check Authentication Logs
```bash
# Recent failed logins
grep "Failed login" /opt/qpki/logs/qpki.log | tail -20

# Login attempts by IP
grep "login attempt" /opt/qpki/logs/qpki.log | \
    awk '{print $NF}' | sort | uniq -c | sort -nr

# Account lockouts
grep "Account locked" /opt/qpki/logs/audit.log
```

#### Monitor Certificate Operations
```bash
# Recent certificate issuance
grep "Certificate issued" /opt/qpki/logs/audit.log | tail -10

# Revocation events
grep "Certificate revoked" /opt/qpki/logs/audit.log

# CA operations
grep "CA operation" /opt/qpki/logs/audit.log | tail -5
```

#### System Health Checks
```bash
# Check for errors
grep -i error /opt/qpki/logs/qpki.log | tail -20

# Monitor resource usage
top -b -n1 | head -20

# Check disk space
df -h | grep -E "(qpki|opt)"

# Monitor network connections
netstat -tulpn | grep -E "(443|5432|6379)"
```

## 🔧 Security Maintenance Tasks

### Daily Tasks
- [ ] Review security logs for anomalies
- [ ] Check system resource usage
- [ ] Verify backup completion
- [ ] Monitor failed login attempts
- [ ] Check certificate expiration alerts

### Weekly Tasks
- [ ] Review Fail2Ban logs and banned IPs
- [ ] Analyze security metrics trends
- [ ] Check for security updates
- [ ] Review user access logs
- [ ] Validate SSL certificate status

### Monthly Tasks
- [ ] Full security log analysis
- [ ] Update security policies
- [ ] Review user accounts and permissions
- [ ] Test backup restoration procedures
- [ ] Security awareness training updates
- [ ] Vulnerability assessment

### Quarterly Tasks
- [ ] Penetration testing
- [ ] Security configuration review
- [ ] Disaster recovery testing
- [ ] Security documentation updates
- [ ] Risk assessment review
- [ ] Third-party security audit

## 🚨 Common Security Issues and Solutions

### Issue: High Number of Failed Login Attempts

#### Symptoms
```bash
# Check for patterns
grep "Failed login" /opt/qpki/logs/qpki.log | \
    grep "$(date '+%Y-%m-%d')" | wc -l
```

#### Investigation
```bash
# Top attacking IPs
grep "Failed login" /opt/qpki/logs/qpki.log | \
    grep "$(date '+%Y-%m-%d')" | \
    awk '{print $(NF-2)}' | sort | uniq -c | sort -nr | head -10

# Geographic analysis (if GeoIP available)
grep "Failed login" /opt/qpki/logs/qpki.log | \
    awk '{print $(NF-2)}' | sort -u | \
    while read ip; do echo "$ip $(geoiplookup $ip)"; done
```

#### Mitigation
```bash
# Temporarily ban specific IPs
sudo fail2ban-client set qpki-auth banip <IP_ADDRESS>

# Adjust rate limiting
# Edit /opt/qpki/.env.production
MAX_LOGIN_ATTEMPTS=3
LOCKOUT_DURATION=3600

# Restart application
sudo supervisorctl restart qpki
```

### Issue: Suspicious Certificate Requests

#### Detection
```bash
# Monitor for unusual patterns
grep "Certificate request" /opt/qpki/logs/audit.log | \
    grep "$(date '+%Y-%m-%d')" | \
    awk '{print $6}' | sort | uniq -c | sort -nr
```

#### Investigation
```bash
# Check specific user activity
grep "user:suspicious_user" /opt/qpki/logs/audit.log

# Review certificate details
openssl x509 -in /path/to/suspicious/cert.pem -text -noout
```

#### Response
```bash
# Immediately revoke suspicious certificates
python3 manage.py revoke-certificate --serial-number <SERIAL>

# Disable user account
python3 manage.py disable-user --username <USERNAME>

# Generate new CRL
python3 manage.py update-crl
```

### Issue: Database Connection Failures

#### Symptoms
```bash
# Check database errors
grep -i "database" /opt/qpki/logs/qpki.log | grep -i error

# Test connection
sudo -u qpki psql -h localhost -U qpki_user -d qpki_production -c "SELECT 1;"
```

#### Investigation
```bash
# Check PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-*-main.log

# Monitor connections
sudo -u postgres psql -c "SELECT * FROM pg_stat_activity WHERE datname='qpki_production';"
```

#### Resolution
```bash
# Restart PostgreSQL
sudo systemctl restart postgresql

# Check disk space
df -h /var/lib/postgresql/

# Optimize database
sudo -u postgres psql qpki_production -c "VACUUM ANALYZE;"
```

### Issue: SSL Certificate Problems

#### Check Certificate Status
```bash
# Verify certificate
openssl x509 -in /etc/ssl/certs/qpki.crt -text -noout

# Check certificate chain
openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/qpki.crt

# Test SSL handshake
openssl s_client -connect your-domain.com:443 -servername your-domain.com
```

#### Renewal Procedures
```bash
# Let's Encrypt renewal
sudo certbot renew --dry-run
sudo certbot renew

# Manual certificate update
sudo systemctl stop nginx
# Replace certificate files
sudo systemctl start nginx
```

## 📊 Security Reporting

### Daily Security Report Template

```bash
#!/bin/bash
# Daily security report generator

DATE=$(date '+%Y-%m-%d')
REPORT_FILE="/opt/qpki/reports/security_${DATE}.txt"

echo "qPKI Security Report - $DATE" > $REPORT_FILE
echo "=================================" >> $REPORT_FILE

# Failed logins
FAILED_LOGINS=$(grep "Failed login" /opt/qpki/logs/qpki.log | grep "$DATE" | wc -l)
echo "Failed Login Attempts: $FAILED_LOGINS" >> $REPORT_FILE

# Certificate operations
CERTS_ISSUED=$(grep "Certificate issued" /opt/qpki/logs/audit.log | grep "$DATE" | wc -l)
echo "Certificates Issued: $CERTS_ISSUED" >> $REPORT_FILE

CERTS_REVOKED=$(grep "Certificate revoked" /opt/qpki/logs/audit.log | grep "$DATE" | wc -l)
echo "Certificates Revoked: $CERTS_REVOKED" >> $REPORT_FILE

# System status
SYSTEM_ERRORS=$(grep -i error /opt/qpki/logs/qpki.log | grep "$DATE" | wc -l)
echo "System Errors: $SYSTEM_ERRORS" >> $REPORT_FILE

# Send report
mail -s "qPKI Security Report - $DATE" security@yourorg.com < $REPORT_FILE
```

### Weekly Security Assessment

```bash
#!/bin/bash
# Weekly security assessment

WEEK_START=$(date -d '7 days ago' '+%Y-%m-%d')
CURRENT_DATE=$(date '+%Y-%m-%d')

echo "=== qPKI Weekly Security Assessment ==="
echo "Period: $WEEK_START to $CURRENT_DATE"
echo

# Authentication analysis
echo "Authentication Summary:"
echo "======================"
grep "Failed login" /opt/qpki/logs/qpki.log | \
    awk -v start="$WEEK_START" -v end="$CURRENT_DATE" \
    '$1" "$2 >= start && $1" "$2 <= end' | \
    awk '{print $NF}' | sort | uniq -c | sort -nr | head -10

# Certificate activity
echo -e "\nCertificate Activity:"
echo "===================="
echo "Issued: $(grep "Certificate issued" /opt/qpki/logs/audit.log | \
    awk -v start="$WEEK_START" -v end="$CURRENT_DATE" \
    '$1" "$2 >= start && $1" "$2 <= end' | wc -l)"
    
echo "Revoked: $(grep "Certificate revoked" /opt/qpki/logs/audit.log | \
    awk -v start="$WEEK_START" -v end="$CURRENT_DATE" \
    '$1" "$2 >= start && $1" "$2 <= end' | wc -l)"

# Security events
echo -e "\nSecurity Events:"
echo "================"
grep -i "security\|breach\|attack\|intrusion" /opt/qpki/logs/qpki.log | \
    awk -v start="$WEEK_START" -v end="$CURRENT_DATE" \
    '$1" "$2 >= start && $1" "$2 <= end'
```

## 🔄 Security Update Procedures

### Emergency Security Patch

```bash
#!/bin/bash
# Emergency security patch procedure

echo "Starting emergency security patch..."

# Stop services
sudo supervisorctl stop qpki
sudo systemctl stop nginx

# Backup current state
sudo -u qpki cp -r /opt/qpki/source /opt/qpki/backup_$(date +%Y%m%d_%H%M%S)

# Apply security patch
cd /opt/qpki/source
git fetch origin
git checkout security-patch-branch
source /opt/qpki/venv/bin/activate
pip install -r requirements.txt

# Test configuration
python3 -c "from app_production import create_app; create_app()"

# Restart services
sudo systemctl start nginx
sudo supervisorctl start qpki

# Verify functionality
curl -k https://localhost/health

echo "Emergency patch completed. Monitor logs closely."
```

### Regular Security Updates

```bash
#!/bin/bash
# Regular security update procedure

# System updates
sudo apt update
sudo apt list --upgradable | grep -i security
sudo apt upgrade -y

# Python package updates
cd /opt/qpki/source
source /opt/qpki/venv/bin/activate
pip list --outdated
pip install --upgrade pip
pip-audit  # Check for vulnerabilities

# PostgreSQL updates
sudo apt list --upgradable | grep postgresql

# Nginx updates
sudo apt list --upgradable | grep nginx

# Restart services if needed
sudo systemctl reload nginx
sudo supervisorctl restart qpki
```

---

## 📞 Emergency Response

### Suspected Compromise Checklist

1. **Immediate Actions**
   - [ ] Document current time and observations
   - [ ] Do NOT turn off the system (preserve evidence)
   - [ ] Isolate the network connection if possible
   - [ ] Notify incident response team
   - [ ] Begin evidence collection

2. **Evidence Collection**
   - [ ] Copy all log files to secure location
   - [ ] Take system memory dump if possible
   - [ ] Document all running processes
   - [ ] Capture network traffic
   - [ ] Preserve database state

3. **Communication**
   - [ ] Notify management immediately
   - [ ] Prepare external communication plan
   - [ ] Contact legal counsel
   - [ ] Notify law enforcement if required
   - [ ] Prepare regulatory notifications

**Remember**: Security is everyone's responsibility. When in doubt, err on the side of caution and contact the security team immediately.
