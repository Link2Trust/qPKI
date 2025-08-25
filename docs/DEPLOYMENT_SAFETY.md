# qPKI Deployment Safety Guide

## Overview

This guide covers safe deployment practices for qPKI, including handling existing installations, configuration management, and data preservation.

## Pre-Deployment Safety Check

Before deploying or updating qPKI, always run the safety check script:

```bash
./scripts/check_deployment.sh
```

This script will:
- ✅ Detect existing qPKI installations
- ⚠️ Identify critical data that could be overwritten
- 📋 Provide deployment recommendations
- 🔍 Show backup instructions

## Safety Features in Deployment Scripts

### Configuration File Protection

The deployment scripts include several safety mechanisms:

1. **Existing Configuration Detection**
   - Checks for existing `.env` files
   - Creates timestamped backups before changes
   - Preserves custom settings during updates

2. **Data Directory Protection**
   - Backs up existing application files
   - Preserves certificate and CA data
   - Maintains database files

3. **Interactive Confirmation**
   - Prompts before overwriting existing installations
   - Allows cancellation if critical data is detected
   - Provides clear information about what will be changed

### Example Safety Flow

```bash
# 1. Check existing installation
./scripts/check_deployment.sh

# 2. If existing installation found, the script will show:
[FOUND] qPKI user exists
[FOUND] Application directory with 156 files
[CRITICAL] Found 23 certificate/CA files in data directory
[FOUND] Existing configuration file

# 3. Backup recommendations will be displayed
=== BACKUP RECOMMENDATIONS ===
1. PKI Data:
   sudo tar -czf qpki-data-backup-$(date +%Y%m%d_%H%M%S).tar.gz -C /opt/qpki data/

# 4. Deployment options will be provided
=== DEPLOYMENT OPTIONS ===
1. Fresh Installation: Remove everything and start clean
2. Upgrade/Update: Keep data, update application
3. Manual Configuration: Custom selective update
```

## Manual Safety Procedures

### Before Deployment

1. **Create Comprehensive Backup**
   ```bash
   # Full system backup
   sudo tar -czf qpki-full-backup-$(date +%Y%m%d_%H%M%S).tar.gz \
     /opt/qpki \
     /etc/nginx/sites-available/qpki \
     /etc/systemd/system/qpki.service \
     /etc/ssl/qpki

   # Configuration backup
   sudo cp /opt/qpki/app/.env qpki-config-$(date +%Y%m%d_%H%M%S).backup
   ```

2. **Document Current Configuration**
   ```bash
   # Record current domain and settings
   grep -E "^(QPKI_DOMAIN|DATABASE_URL|SMTP_)" /opt/qpki/app/.env > current-config.txt
   
   # Record running services
   systemctl status qpki nginx redis-server > service-status.txt
   ```

3. **Test Database Connection**
   ```bash
   # For SQLite
   sudo -u qpki sqlite3 /opt/qpki/app/qpki ".tables"
   
   # For PostgreSQL
   sudo -u qpki psql "$(grep DATABASE_URL /opt/qpki/app/.env | cut -d= -f2)" -c "\dt"
   ```

### During Deployment

1. **Monitor the Process**
   - Watch for error messages during file copying
   - Verify that backups are created successfully
   - Check that services restart properly

2. **Validate Configuration**
   ```bash
   # Check if .env was preserved/updated correctly
   sudo diff /opt/qpki/app/.env /opt/qpki/app/.env.example
   
   # Verify nginx configuration
   sudo nginx -t
   
   # Check systemd service
   sudo systemctl status qpki
   ```

### After Deployment

1. **Verify Functionality**
   ```bash
   # Test web interface
   curl -k https://your-domain.com/health
   
   # Check authentication
   curl -k https://your-domain.com/auth/login
   
   # Verify database connectivity
   sudo -u qpki /opt/qpki/venv/bin/python -c "
   import sys; sys.path.append('/opt/qpki/app/src')
   from qpki.database import DatabaseManager, DatabaseConfig
   db = DatabaseManager(DatabaseConfig.from_env())
   print('Database OK' if db.check_connection() else 'Database ERROR')
   "
   ```

2. **Test User Login**
   - Try logging in with existing users
   - Verify that demo user still works
   - Check that certificates and CAs are accessible

## Recovery Procedures

### Configuration Recovery

If configuration is corrupted during deployment:

```bash
# Restore from backup
sudo cp qpki-config-TIMESTAMP.backup /opt/qpki/app/.env

# Restart services
sudo systemctl restart qpki nginx

# Check status
sudo systemctl status qpki
```

### Data Recovery

If PKI data is accidentally overwritten:

```bash
# Stop services
sudo systemctl stop qpki nginx

# Restore data
sudo tar -xzf qpki-data-backup-TIMESTAMP.tar.gz -C /opt/qpki

# Fix permissions
sudo chown -R qpki:qpki /opt/qpki/data

# Restart services
sudo systemctl start qpki nginx
```

### Full System Recovery

For complete system recovery:

```bash
# Stop all services
sudo systemctl stop qpki nginx

# Remove current installation
sudo rm -rf /opt/qpki

# Restore from full backup
sudo tar -xzf qpki-full-backup-TIMESTAMP.tar.gz -C /

# Reload systemd and restart services
sudo systemctl daemon-reload
sudo systemctl start qpki nginx
```

## Best Practices

### Development vs Production

1. **Development Deployments**
   - Use `localhost` or test domains
   - Self-signed certificates are acceptable
   - Fresh installations are often preferred

2. **Production Deployments**
   - Always run safety checks first
   - Create comprehensive backups
   - Test configuration changes in staging first
   - Use proper SSL certificates (Let's Encrypt)

### Configuration Management

1. **Environment-Specific Configs**
   ```bash
   # Keep environment-specific configs separate
   cp .env.example .env.production.local
   cp .env.example .env.staging.local
   
   # Use during deployment
   cp .env.production.local /opt/qpki/app/.env
   ```

2. **Version Control**
   - Never commit actual `.env` files
   - Keep template files updated
   - Document configuration changes

### Monitoring After Deployment

1. **Service Health**
   ```bash
   # Create monitoring script
   #!/bin/bash
   systemctl is-active qpki nginx redis-server
   curl -s -k https://your-domain.com/health | jq .status
   ```

2. **Log Monitoring**
   ```bash
   # Watch application logs
   sudo tail -f /opt/qpki/logs/qpki.log
   
   # Watch nginx logs
   sudo tail -f /var/log/nginx/qpki_access.log
   ```

## Emergency Contacts

If deployment issues occur in production:

1. **Rollback Steps**
   - Stop new services: `sudo systemctl stop qpki`
   - Restore from backup (see Recovery Procedures above)
   - Verify restoration: Test login and certificate access

2. **Support Information**
   - Keep backup locations documented
   - Document custom configuration changes
   - Maintain contact information for database/DNS providers

## Checklist

Before any production deployment:

- [ ] Full system backup created
- [ ] Configuration backup created
- [ ] Database backup verified
- [ ] Safety check script executed
- [ ] Deployment plan reviewed
- [ ] Rollback procedure tested
- [ ] Monitoring tools ready
- [ ] Emergency contacts notified

After deployment:
- [ ] Services status verified
- [ ] Web interface accessible
- [ ] User authentication tested
- [ ] Certificate operations tested
- [ ] Logs checked for errors
- [ ] Performance baseline established
