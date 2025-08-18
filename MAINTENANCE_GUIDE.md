# qPKI Maintenance Guide

This document provides comprehensive maintenance procedures, troubleshooting guides, and operational best practices for qPKI in production.

## 📅 Maintenance Schedule

### Daily Operations (5-10 minutes)

```bash
#!/bin/bash
# Daily maintenance script

echo "=== qPKI Daily Maintenance - $(date) ==="

# Check service status
echo "Checking service status..."
sudo systemctl status nginx --no-pager -l
sudo supervisorctl status qpki

# Check disk space
echo -e "\nDisk space check:"
df -h | grep -E "(qpki|opt|var)"

# Review error logs
echo -e "\nRecent errors (last 24 hours):"
grep -i error /opt/qpki/logs/qpki.log | tail -10

# Check backup completion
echo -e "\nBackup status:"
ls -la /opt/qpki/backups/ | tail -3

# Memory usage
echo -e "\nMemory usage:"
free -h

# Database connections
echo -e "\nDatabase connections:"
sudo -u postgres psql -c "SELECT count(*) as active_connections FROM pg_stat_activity WHERE datname='qpki_production';"

echo "=== Daily maintenance completed ==="
```

### Weekly Operations (30-60 minutes)

```bash
#!/bin/bash
# Weekly maintenance script

echo "=== qPKI Weekly Maintenance - $(date) ==="

# System updates check
echo "Checking for system updates..."
sudo apt update
sudo apt list --upgradable

# Log analysis
echo -e "\nAnalyzing logs for patterns..."
echo "Failed login attempts this week:"
grep "Failed login" /opt/qpki/logs/qpki.log | \
    grep "$(date -d '7 days ago' '+%Y-%m-%d')" | wc -l

echo "Certificates issued this week:"
grep "Certificate issued" /opt/qpki/logs/audit.log | \
    grep "$(date -d '7 days ago' '+%Y-%m-%d')" | wc -l

# Database maintenance
echo -e "\nDatabase maintenance..."
sudo -u postgres psql qpki_production << EOF
-- Update table statistics
ANALYZE;
-- Check for bloat
SELECT schemaname, tablename, attname, n_distinct, correlation 
FROM pg_stats 
WHERE tablename IN ('users', 'certificates', 'certificate_requests') 
LIMIT 10;
EOF

# Certificate expiration check
echo -e "\nChecking certificate expirations (next 30 days)..."
find /opt/qpki/data/certificates -name "*.pem" -exec openssl x509 -in {} -checkend 2592000 -noout \; 2>/dev/null || echo "Some certificates expire within 30 days"

# Security log review
echo -e "\nSecurity events this week:"
grep -i "security\|breach\|attack" /opt/qpki/logs/qpki.log | \
    grep "$(date -d '7 days ago' '+%Y-%m-%d')" | wc -l

echo "=== Weekly maintenance completed ==="
```

### Monthly Operations (2-4 hours)

```bash
#!/bin/bash
# Monthly maintenance script

echo "=== qPKI Monthly Maintenance - $(date) ==="

# Full system backup
echo "Creating monthly system backup..."
sudo -u qpki /opt/qpki/backup-qpki.sh

# Database optimization
echo -e "\nDatabase optimization..."
sudo -u postgres psql qpki_production << EOF
-- Full vacuum and analyze
VACUUM ANALYZE;
-- Reindex critical tables
REINDEX TABLE users;
REINDEX TABLE certificates;
REINDEX TABLE certificate_requests;
-- Check database size
SELECT pg_size_pretty(pg_database_size('qpki_production')) as database_size;
EOF

# Certificate Authority health check
echo -e "\nCA health check..."
# Verify root CA certificate
openssl x509 -in /opt/qpki/data/ca/root-ca.crt -text -noout | grep "Validity" -A 2

# Check intermediate CA certificates
find /opt/qpki/data/ca -name "intermediate-*.crt" -exec openssl x509 -in {} -text -noout \; | grep "Subject:"

# Security assessment
echo -e "\nSecurity assessment..."
# Check file permissions
find /opt/qpki -type f -name "*.key" ! -perm 600 | head -5
find /opt/qpki/data/ca -type f ! -user qpki | head -5

# SSL certificate check
echo -e "\nSSL certificate verification..."
echo | openssl s_client -servername localhost -connect localhost:443 2>/dev/null | openssl x509 -noout -dates

# Performance metrics
echo -e "\nPerformance metrics..."
echo "Average response time (last 1000 requests):"
tail -1000 /opt/qpki/logs/access.log | awk '{print $NF}' | awk '{sum+=$1} END {print sum/NR "ms"}'

echo "Top slowest endpoints:"
tail -1000 /opt/qpki/logs/access.log | awk '{print $(NF-1), $NF}' | sort -k2 -nr | head -5

# Log rotation and cleanup
echo -e "\nLog cleanup..."
find /opt/qpki/logs -name "*.log.*" -mtime +30 -delete

echo "=== Monthly maintenance completed ==="
```

## 🔧 Troubleshooting Guide

### Common Issues and Solutions

#### 1. Application Won't Start

**Symptoms:**
- Service fails to start
- HTTP 502/503 errors
- Connection refused errors

**Diagnosis:**
```bash
# Check service status
sudo supervisorctl status qpki
sudo systemctl status nginx

# Check application logs
sudo tail -f /opt/qpki/logs/qpki.log

# Check system resources
free -h
df -h
```

**Solutions:**
```bash
# Restart services
sudo supervisorctl restart qpki
sudo systemctl restart nginx

# Check configuration
sudo -u qpki bash << 'EOF'
cd /opt/qpki/source
source /opt/qpki/venv/bin/activate
python3 -c "from app_production import create_app; app = create_app(); print('Configuration OK')"
EOF

# Clear temporary files
sudo -u qpki rm -rf /opt/qpki/tmp/*
sudo -u qpki rm -rf /opt/qpki/run/*
```

#### 2. Database Connection Issues

**Symptoms:**
- Database connection errors
- Slow query performance
- Connection pool exhaustion

**Diagnosis:**
```bash
# Test database connection
sudo -u qpki psql -h localhost -U qpki_user -d qpki_production -c "SELECT version();"

# Check active connections
sudo -u postgres psql -c "SELECT count(*) FROM pg_stat_activity WHERE datname='qpki_production';"

# Check database logs
sudo tail -f /var/log/postgresql/postgresql-*-main.log
```

**Solutions:**
```bash
# Restart PostgreSQL
sudo systemctl restart postgresql

# Optimize database
sudo -u postgres psql qpki_production -c "VACUUM ANALYZE;"

# Kill long-running queries
sudo -u postgres psql -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='qpki_production' AND query_start < now() - interval '5 minutes';"

# Check disk space
df -h /var/lib/postgresql/
```

#### 3. SSL/TLS Certificate Problems

**Symptoms:**
- Browser security warnings
- Certificate validation errors
- HTTPS connection failures

**Diagnosis:**
```bash
# Check certificate validity
openssl x509 -in /etc/ssl/certs/qpki.crt -text -noout | grep -A 2 "Validity"

# Test SSL handshake
echo | openssl s_client -servername your-domain.com -connect your-domain.com:443 2>/dev/null | openssl x509 -noout -subject -dates

# Check Nginx SSL configuration
sudo nginx -t
```

**Solutions:**
```bash
# Renew Let's Encrypt certificate
sudo certbot renew --force-renewal

# Restart Nginx
sudo systemctl restart nginx

# Generate new self-signed certificate (if needed)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/qpki.key \
    -out /etc/ssl/certs/qpki.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=your-domain.com"
```

#### 4. High Memory Usage

**Symptoms:**
- System slowdown
- Out of memory errors
- High swap usage

**Diagnosis:**
```bash
# Check memory usage
free -h
sudo ps aux --sort=-%mem | head -10

# Check for memory leaks
sudo pmap -d $(pgrep -f qpki)

# Monitor memory usage over time
while true; do
    echo "$(date): $(free -m | grep Mem: | awk '{print $3}')"
    sleep 60
done
```

**Solutions:**
```bash
# Restart application to clear memory
sudo supervisorctl restart qpki

# Adjust Gunicorn worker count
sudo vim /opt/qpki/source/gunicorn.conf.py
# Reduce workers or switch to different worker class

# Clear system cache
sudo sync && echo 3 | sudo tee /proc/sys/vm/drop_caches

# Add more swap space (if needed)
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

#### 5. Disk Space Issues

**Symptoms:**
- Disk full errors
- Log writing failures
- Database errors

**Diagnosis:**
```bash
# Check disk usage
df -h
du -sh /opt/qpki/* | sort -hr

# Find large files
find /opt/qpki -type f -size +100M -exec ls -lh {} \;

# Check log sizes
du -sh /opt/qpki/logs/*
```

**Solutions:**
```bash
# Rotate logs manually
sudo logrotate -f /etc/logrotate.conf

# Clean up old backups
find /opt/qpki/backups -name "*.tar.gz*" -mtime +30 -delete

# Clean up old certificates (if safe)
find /opt/qpki/data/certificates -name "*.pem" -mtime +365 -delete

# Compress old logs
gzip /opt/qpki/logs/*.log.*
```

#### 6. Performance Issues

**Symptoms:**
- Slow response times
- High CPU usage
- Database query timeouts

**Diagnosis:**
```bash
# Monitor system performance
top -b -n 1
iostat -x 1 5

# Check slow queries
sudo -u postgres psql qpki_production -c "SELECT query, query_start, now() - query_start AS runtime FROM pg_stat_activity WHERE now() - query_start > interval '2 seconds';"

# Analyze access logs
tail -1000 /opt/qpki/logs/access.log | awk '{print $7, $NF}' | sort | uniq -c | sort -nr
```

**Solutions:**
```bash
# Restart application
sudo supervisorctl restart qpki

# Optimize database
sudo -u postgres psql qpki_production -c "REINDEX DATABASE qpki_production;"

# Adjust Gunicorn configuration
# Increase worker count for CPU-bound tasks
# Use async workers for I/O-bound tasks

# Enable database query caching
# Add Redis for session storage and caching
```

## 🔄 Backup and Recovery Procedures

### Backup Verification

```bash
#!/bin/bash
# Backup verification script

echo "=== Backup Verification - $(date) ==="

LATEST_BACKUP=$(ls -t /opt/qpki/backups/qpki_backup_*.tar.gz.enc | head -1)

if [ -z "$LATEST_BACKUP" ]; then
    echo "ERROR: No backup files found!"
    exit 1
fi

echo "Latest backup: $LATEST_BACKUP"

# Check backup file integrity
if [ -f "$LATEST_BACKUP" ]; then
    echo "Backup file exists and is readable"
    echo "Backup size: $(du -sh $LATEST_BACKUP | cut -f1)"
    echo "Backup date: $(stat -c %y $LATEST_BACKUP)"
else
    echo "ERROR: Backup file is not accessible!"
    exit 1
fi

# Test decryption (without extracting)
if openssl enc -aes-256-cbc -d -in "$LATEST_BACKUP" -k "test_key" >/dev/null 2>&1; then
    echo "Backup decryption test: PASSED"
else
    echo "WARNING: Backup decryption test failed - check encryption key"
fi

echo "=== Backup verification completed ==="
```

### Disaster Recovery Test

```bash
#!/bin/bash
# Disaster recovery test procedure

echo "=== Disaster Recovery Test - $(date) ==="

# WARNING: This script is for testing disaster recovery procedures
# DO NOT run this on production systems!

BACKUP_PATH="/opt/qpki/backups"
TEST_RESTORE_PATH="/tmp/qpki_recovery_test"
LATEST_BACKUP=$(ls -t $BACKUP_PATH/qpki_backup_*.tar.gz.enc | head -1)

# Create test environment
mkdir -p $TEST_RESTORE_PATH
cd $TEST_RESTORE_PATH

# Decrypt and extract backup
echo "Decrypting backup..."
openssl enc -aes-256-cbc -d -salt -k "${BACKUP_ENCRYPTION_KEY}" -in $LATEST_BACKUP | tar -xzf -

# Verify critical files
echo "Verifying critical files..."
critical_files=(
    "data/ca/root-ca.crt"
    "data/ca/root-ca.key"
    ".env.production"
    "database_dump.sql"
)

for file in "${critical_files[@]}"; do
    if [ -f "$file" ]; then
        echo "✓ $file found"
    else
        echo "✗ $file MISSING"
    fi
done

# Test database restoration (to temporary database)
echo "Testing database restoration..."
createdb qpki_recovery_test
psql qpki_recovery_test < database_dump.sql

if [ $? -eq 0 ]; then
    echo "✓ Database restoration test: PASSED"
    dropdb qpki_recovery_test
else
    echo "✗ Database restoration test: FAILED"
fi

# Cleanup
cd /
rm -rf $TEST_RESTORE_PATH

echo "=== Disaster recovery test completed ==="
```

### Point-in-Time Recovery

```bash
#!/bin/bash
# Point-in-time recovery procedure

RECOVERY_TIME="$1"  # Format: YYYY-MM-DD HH:MM:SS

if [ -z "$RECOVERY_TIME" ]; then
    echo "Usage: $0 'YYYY-MM-DD HH:MM:SS'"
    echo "Example: $0 '2024-01-15 14:30:00'"
    exit 1
fi

echo "=== Point-in-Time Recovery to $RECOVERY_TIME ==="

# Stop services
echo "Stopping services..."
sudo supervisorctl stop qpki
sudo systemctl stop postgresql

# Create recovery directory
RECOVERY_DIR="/opt/qpki/recovery_$(date +%Y%m%d_%H%M%S)"
sudo mkdir -p $RECOVERY_DIR

# Find appropriate backup
echo "Finding backup before $RECOVERY_TIME..."
# Implementation depends on backup naming convention and WAL archiving

# Restore base backup
echo "Restoring base backup..."
# sudo -u postgres pg_basebackup commands...

# Apply WAL files up to recovery time
echo "Applying WAL files..."
# Configure recovery.conf with target time

# Start PostgreSQL in recovery mode
echo "Starting PostgreSQL in recovery mode..."
sudo systemctl start postgresql

# Wait for recovery completion
echo "Waiting for recovery to complete..."
# Monitor PostgreSQL logs

echo "=== Point-in-time recovery completed ==="
```

## 📊 Performance Monitoring

### Application Performance Metrics

```bash
#!/bin/bash
# Performance monitoring script

echo "=== qPKI Performance Report - $(date) ==="

# Response time analysis
echo "Response Time Analysis (last 1000 requests):"
tail -1000 /opt/qpki/logs/access.log | awk '{print $NF}' | awk '
{
    sum += $1
    if ($1 > max) max = $1
    if (!min || $1 < min) min = $1
}
END {
    print "Average: " sum/NR "ms"
    print "Maximum: " max "ms"
    print "Minimum: " min "ms"
}'

# Request patterns
echo -e "\nTop 10 requested endpoints:"
tail -1000 /opt/qpki/logs/access.log | awk '{print $7}' | sort | uniq -c | sort -nr | head -10

# Error rate analysis
echo -e "\nError rate (4xx/5xx responses):"
total_requests=$(tail -1000 /opt/qpki/logs/access.log | wc -l)
error_requests=$(tail -1000 /opt/qpki/logs/access.log | awk '$9 >= 400 {count++} END {print count+0}')
error_rate=$(echo "scale=2; $error_requests * 100 / $total_requests" | bc)
echo "Total requests: $total_requests"
echo "Error requests: $error_requests"
echo "Error rate: $error_rate%"

# Database performance
echo -e "\nDatabase Performance:"
sudo -u postgres psql qpki_production -c "
SELECT 
    schemaname,
    tablename,
    seq_scan,
    seq_tup_read,
    idx_scan,
    idx_tup_fetch,
    n_tup_ins,
    n_tup_upd,
    n_tup_del
FROM pg_stat_user_tables 
ORDER BY seq_tup_read DESC 
LIMIT 5;
"

# System resources
echo -e "\nSystem Resources:"
echo "CPU Usage:"
top -b -n1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1

echo "Memory Usage:"
free -h | grep Mem | awk '{print "Used: " $3 "/" $2 " (" $3/$2*100 "%)"}'

echo "Disk Usage:"
df -h | grep -E "(qpki|opt)" | awk '{print $6 ": " $3 "/" $2 " (" $5 ")"}'

echo "=== Performance report completed ==="
```

### Database Health Check

```bash
#!/bin/bash
# Database health check script

echo "=== Database Health Check - $(date) ==="

# Connection test
echo "Testing database connection..."
if sudo -u qpki psql -h localhost -U qpki_user -d qpki_production -c "SELECT 1;" >/dev/null 2>&1; then
    echo "✓ Database connection: OK"
else
    echo "✗ Database connection: FAILED"
    exit 1
fi

# Check database size
echo -e "\nDatabase size information:"
sudo -u postgres psql qpki_production -c "
SELECT 
    pg_size_pretty(pg_database_size('qpki_production')) as database_size,
    pg_size_pretty(pg_total_relation_size('users')) as users_table_size,
    pg_size_pretty(pg_total_relation_size('certificates')) as certificates_table_size;
"

# Check for bloated tables
echo -e "\nTable statistics:"
sudo -u postgres psql qpki_production -c "
SELECT 
    tablename,
    n_live_tup as live_rows,
    n_dead_tup as dead_rows,
    round(n_dead_tup * 100.0 / NULLIF(n_live_tup + n_dead_tup, 0), 2) as dead_row_percentage
FROM pg_stat_user_tables 
WHERE n_dead_tup > 0
ORDER BY dead_row_percentage DESC;
"

# Check for long-running queries
echo -e "\nLong-running queries:"
sudo -u postgres psql qpki_production -c "
SELECT 
    pid,
    now() - query_start as duration,
    query 
FROM pg_stat_activity 
WHERE query_start < now() - interval '1 minute' 
    AND state = 'active'
    AND query NOT LIKE '%pg_stat_activity%';
"

# Check index usage
echo -e "\nIndex usage statistics:"
sudo -u postgres psql qpki_production -c "
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_scan,
    idx_tup_read,
    idx_tup_fetch
FROM pg_stat_user_indexes 
ORDER BY idx_scan DESC 
LIMIT 10;
"

# Check for unused indexes
echo -e "\nPotentially unused indexes:"
sudo -u postgres psql qpki_production -c "
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_scan
FROM pg_stat_user_indexes 
WHERE idx_scan = 0 
    AND indexname NOT LIKE '%_pkey';
"

echo "=== Database health check completed ==="
```

## 🔍 Log Analysis Tools

### Log Parser Script

```bash
#!/bin/bash
# Advanced log analysis script

LOG_FILE="${1:-/opt/qpki/logs/qpki.log}"
DAYS="${2:-7}"

echo "=== Log Analysis for $LOG_FILE (last $DAYS days) ==="

# Date range
START_DATE=$(date -d "$DAYS days ago" '+%Y-%m-%d')
END_DATE=$(date '+%Y-%m-%d')

echo "Analysis period: $START_DATE to $END_DATE"
echo

# Error analysis
echo "Error Summary:"
echo "=============="
awk -v start="$START_DATE" -v end="$END_DATE" '
$1 >= start && $1 <= end && /ERROR|CRITICAL|FATAL/ {
    errors[$4]++
}
END {
    for (error in errors) {
        print error ": " errors[error]
    }
}' "$LOG_FILE" | sort -k2 -nr

# User activity
echo -e "\nTop Active Users:"
echo "================"
awk -v start="$START_DATE" -v end="$END_DATE" '
$1 >= start && $1 <= end && /user:/ {
    match($0, /user:([a-zA-Z0-9_]+)/, arr)
    if (arr[1]) users[arr[1]]++
}
END {
    for (user in users) {
        print user ": " users[user]
    }
}' "$LOG_FILE" | sort -k2 -nr | head -10

# Certificate operations
echo -e "\nCertificate Operations:"
echo "======================"
awk -v start="$START_DATE" -v end="$END_DATE" '
$1 >= start && $1 <= end {
    if (/Certificate issued/) issued++
    if (/Certificate revoked/) revoked++
    if (/Certificate request/) requests++
}
END {
    print "Requests: " (requests ? requests : 0)
    print "Issued: " (issued ? issued : 0)
    print "Revoked: " (revoked ? revoked : 0)
}' "$LOG_FILE"

# Hourly activity pattern
echo -e "\nHourly Activity Pattern:"
echo "======================="
awk -v start="$START_DATE" -v end="$END_DATE" '
$1 >= start && $1 <= end {
    hour = substr($2, 1, 2)
    activity[hour]++
}
END {
    for (i = 0; i < 24; i++) {
        printf "%02d:00 ", i
        count = activity[sprintf("%02d", i)]
        for (j = 0; j < count/10; j++) printf "█"
        printf " (%d)\n", (count ? count : 0)
    }
}' "$LOG_FILE"

echo "=== Log analysis completed ==="
```

### Real-time Log Monitoring

```bash
#!/bin/bash
# Real-time log monitoring with alerts

LOG_FILE="/opt/qpki/logs/qpki.log"
ALERT_EMAIL="admin@yourorg.com"

echo "Starting real-time log monitoring..."
echo "Watching: $LOG_FILE"

tail -f "$LOG_FILE" | while read line; do
    # Check for critical errors
    if echo "$line" | grep -qi "critical\|fatal\|emergency"; then
        echo "🚨 CRITICAL: $line"
        echo "Critical error detected: $line" | mail -s "qPKI Critical Alert" "$ALERT_EMAIL"
    fi
    
    # Check for security events
    if echo "$line" | grep -qi "security\|breach\|attack\|intrusion"; then
        echo "⚠️  SECURITY: $line"
        echo "Security event detected: $line" | mail -s "qPKI Security Alert" "$ALERT_EMAIL"
    fi
    
    # Check for authentication failures
    if echo "$line" | grep -qi "failed login"; then
        echo "🔒 AUTH: $line"
        # Count failed logins in last 5 minutes
        recent_failures=$(grep "Failed login" "$LOG_FILE" | \
            grep "$(date -d '5 minutes ago' '+%Y-%m-%d %H:%M')" | wc -l)
        if [ "$recent_failures" -gt 10 ]; then
            echo "High number of failed logins: $recent_failures" | \
                mail -s "qPKI Authentication Alert" "$ALERT_EMAIL"
        fi
    fi
    
    # Check for database errors
    if echo "$line" | grep -qi "database.*error\|connection.*failed"; then
        echo "💾 DATABASE: $line"
        echo "Database error detected: $line" | mail -s "qPKI Database Alert" "$ALERT_EMAIL"
    fi
    
    # Normal logging (optional)
    if echo "$line" | grep -qi "info"; then
        echo "ℹ️  INFO: $line"
    fi
done
```

## 🔄 Update Procedures

### Application Update Checklist

```bash
#!/bin/bash
# Application update procedure

NEW_VERSION="$1"

if [ -z "$NEW_VERSION" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 v2.1.0"
    exit 1
fi

echo "=== qPKI Update to $NEW_VERSION ==="

# Pre-update backup
echo "Creating pre-update backup..."
sudo -u qpki /opt/qpki/backup-qpki.sh

# Stop services
echo "Stopping services..."
sudo supervisorctl stop qpki

# Backup current version
echo "Backing up current version..."
sudo -u qpki cp -r /opt/qpki/source /opt/qpki/source.backup.$(date +%Y%m%d_%H%M%S)

# Update code
echo "Updating application code..."
cd /opt/qpki/source
sudo -u qpki git fetch --all
sudo -u qpki git checkout $NEW_VERSION

# Update dependencies
echo "Updating dependencies..."
sudo -u qpki bash << 'EOF'
source /opt/qpki/venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
EOF

# Run database migrations (if any)
echo "Running database migrations..."
sudo -u qpki bash << 'EOF'
cd /opt/qpki/source
source /opt/qpki/venv/bin/activate
source /opt/qpki/.env.production
python3 scripts/migrate_database.py
EOF

# Test configuration
echo "Testing configuration..."
sudo -u qpki bash << 'EOF'
cd /opt/qpki/source
source /opt/qpki/venv/bin/activate
source /opt/qpki/.env.production
python3 -c "from app_production import create_app; app = create_app(); print('Configuration test: PASSED')"
EOF

if [ $? -ne 0 ]; then
    echo "Configuration test failed. Rolling back..."
    sudo -u qpki git checkout -
    sudo supervisorctl start qpki
    exit 1
fi

# Start services
echo "Starting services..."
sudo supervisorctl start qpki

# Verify update
echo "Verifying update..."
sleep 5
curl -k https://localhost/health

if [ $? -eq 0 ]; then
    echo "✓ Update completed successfully"
    echo "New version: $NEW_VERSION"
else
    echo "✗ Update verification failed"
    echo "Manual intervention required"
fi

echo "=== Update procedure completed ==="
```

---

## 📞 Emergency Procedures

### Service Recovery

```bash
#!/bin/bash
# Emergency service recovery script

echo "=== Emergency Service Recovery - $(date) ==="

# Check what's running
echo "Checking service status..."
sudo supervisorctl status
sudo systemctl status nginx postgresql redis

# Try to restart services
echo "Attempting service restart..."
sudo systemctl restart postgresql
sudo systemctl restart redis
sudo systemctl restart nginx
sudo supervisorctl restart qpki

# Wait and test
echo "Waiting for services to stabilize..."
sleep 10

# Health check
if curl -k https://localhost/health >/dev/null 2>&1; then
    echo "✓ Service recovery successful"
else
    echo "✗ Service recovery failed - manual intervention required"
    
    # Emergency diagnostic
    echo "Emergency diagnostic information:"
    echo "================================"
    
    # Disk space
    echo "Disk space:"
    df -h | grep -E "(qpki|opt|var|tmp)"
    
    # Memory
    echo -e "\nMemory:"
    free -h
    
    # Recent errors
    echo -e "\nRecent errors:"
    tail -20 /opt/qpki/logs/qpki.log | grep -i error
    
    # Process status
    echo -e "\nProcess status:"
    ps aux | grep -E "(gunicorn|nginx|postgres|redis)" | grep -v grep
fi

echo "=== Emergency recovery completed ==="
```

**Remember**: Always test maintenance procedures in a staging environment first!

**Emergency contacts**: Keep this information updated and accessible to all team members.
