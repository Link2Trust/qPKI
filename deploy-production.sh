#!/bin/bash
#
# qPKI Production Deployment Script
# 
# This script sets up qPKI for production deployment with all security measures
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
QPKI_USER="qpki"
QPKI_HOME="/opt/qpki"
PYTHON_VERSION="3.9"
POSTGRES_VERSION="13"

echo -e "${BLUE}🚀 qPKI Production Deployment Script${NC}"
echo "=================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Function to log messages
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

# Step 1: System Updates and Dependencies
log "Installing system dependencies..."
apt update && apt upgrade -y

# Install required packages
apt install -y \
    python3 python3-pip python3-venv python3-dev \
    postgresql postgresql-contrib \
    redis-server \
    nginx \
    git \
    build-essential \
    libffi-dev \
    libssl-dev \
    pkg-config \
    supervisor \
    fail2ban \
    ufw \
    htop \
    curl \
    wget \
    unzip

# Step 2: Create qPKI User and Directories
log "Creating qPKI user and directories..."
if ! id "$QPKI_USER" &>/dev/null; then
    useradd -r -m -s /bin/bash -d "$QPKI_HOME" "$QPKI_USER"
    log "Created user: $QPKI_USER"
else
    log "User $QPKI_USER already exists"
fi

# Create directory structure
mkdir -p "$QPKI_HOME"/{data/{certificates,ca,crl,keys},logs,backups,run,tmp}
mkdir -p /etc/qpki

# Set proper ownership and permissions
chown -R "$QPKI_USER":"$QPKI_USER" "$QPKI_HOME"
chmod -R 750 "$QPKI_HOME"
chmod -R 700 "$QPKI_HOME"/data/keys
chmod -R 700 "$QPKI_HOME"/data/ca
chmod 755 "$QPKI_HOME"

# Step 3: Setup PostgreSQL
log "Configuring PostgreSQL..."
systemctl start postgresql
systemctl enable postgresql

# Create qPKI database and user
sudo -u postgres psql -c "CREATE USER qpki_user WITH PASSWORD 'CHANGE_THIS_PASSWORD';" || true
sudo -u postgres psql -c "CREATE DATABASE qpki_production OWNER qpki_user;" || true
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE qpki_production TO qpki_user;" || true

# Step 4: Configure Redis
log "Configuring Redis..."
systemctl start redis-server
systemctl enable redis-server

# Configure Redis for qPKI (basic security)
cat > /etc/redis/redis-qpki.conf << 'EOF'
port 0
unixsocket /var/run/redis/redis-qpki.sock
unixsocketperm 770
bind 127.0.0.1
protected-mode yes
timeout 300
databases 16
save 900 1
save 300 10
save 60 10000
maxmemory 256mb
maxmemory-policy allkeys-lru
EOF

# Step 5: Firewall Configuration
log "Configuring firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Allow SSH (adjust port as needed)
ufw allow 22/tcp

# Allow HTTP and HTTPS
ufw allow 80/tcp
ufw allow 443/tcp

# Enable firewall
ufw --force enable

# Step 6: Configure Fail2Ban
log "Configuring Fail2Ban..."
cat > /etc/fail2ban/jail.d/qpki.conf << 'EOF'
[qpki-auth]
enabled = true
filter = qpki-auth
logpath = /opt/qpki/logs/qpki.log
maxretry = 5
bantime = 3600
findtime = 600
action = iptables[name=qpki, port=http,https]

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 5
bantime = 3600
findtime = 600
EOF

# Create custom fail2ban filter
cat > /etc/fail2ban/filter.d/qpki-auth.conf << 'EOF'
[Definition]
failregex = ^.*Authentication failed for user .* from <HOST>.*$
            ^.*Failed login attempt from <HOST>.*$
            ^.*Invalid login credentials from <HOST>.*$
ignoreregex =
EOF

systemctl restart fail2ban
systemctl enable fail2ban

# Step 7: Generate Secure Configuration
log "Generating secure configuration..."
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
PASSWORD_SALT=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")
BACKUP_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

# Generate production environment file
cat > "$QPKI_HOME"/.env.production << EOF
# qPKI Production Environment Configuration
# Generated on $(date)

# Flask Application Settings
FLASK_ENV=production
FLASK_DEBUG=False
WEB_PORT=9090
SECRET_KEY=${SECRET_KEY}

# Database Configuration
DATABASE_URL=postgresql://qpki_user:CHANGE_THIS_PASSWORD@localhost:5432/qpki_production
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=30

# Security Settings
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax
WTF_CSRF_ENABLED=True
SECURITY_PASSWORD_SALT=${PASSWORD_SALT}

# File Storage Paths
CERTIFICATE_STORAGE_DIR=${QPKI_HOME}/data/certificates
CA_STORAGE_DIR=${QPKI_HOME}/data/ca
CRL_STORAGE_DIR=${QPKI_HOME}/data/crl
KEY_STORAGE_DIR=${QPKI_HOME}/data/keys
BACKUP_STORAGE_DIR=${QPKI_HOME}/backups

# Logging
LOG_LEVEL=INFO
LOG_FILE_PATH=${QPKI_HOME}/logs/qpki.log
AUDIT_LOG_PATH=${QPKI_HOME}/logs/audit.log

# Rate Limiting
RATELIMIT_STORAGE_URL=unix:///var/run/redis/redis-qpki.sock
RATELIMIT_ENABLED=True

# Backup
BACKUP_ENABLED=True
BACKUP_ENCRYPTION_KEY=${BACKUP_KEY}

# Security Headers
FORCE_HTTPS=True
HSTS_MAX_AGE=31536000
EOF

chown "$QPKI_USER":"$QPKI_USER" "$QPKI_HOME"/.env.production
chmod 600 "$QPKI_HOME"/.env.production

# Step 8: Install qPKI Application
log "Installing qPKI application..."
if [ -d "$QPKI_HOME/qpki-source" ]; then
    rm -rf "$QPKI_HOME/qpki-source"
fi

# Copy application files (assuming they're in current directory)
if [ -d "./src" ]; then
    cp -r . "$QPKI_HOME/qpki-source/"
    chown -R "$QPKI_USER":"$QPKI_USER" "$QPKI_HOME/qpki-source"
    
    # Create virtual environment and install
    sudo -u "$QPKI_USER" bash -c "
        cd $QPKI_HOME/qpki-source
        python3 -m venv $QPKI_HOME/venv
        source $QPKI_HOME/venv/bin/activate
        pip install --upgrade pip
        pip install -r requirements.txt
        pip install gunicorn flask-limiter flask-talisman python-dotenv psycopg2-binary
        pip install -e .
    "
else
    warn "qPKI source code not found in current directory. Please copy manually."
fi

# Step 9: Configure Supervisor
log "Configuring Supervisor..."
cat > /etc/supervisor/conf.d/qpki.conf << EOF
[program:qpki]
command=$QPKI_HOME/venv/bin/gunicorn -c $QPKI_HOME/qpki-source/gunicorn.conf.py app_production:create_app()
directory=$QPKI_HOME/qpki-source
user=$QPKI_USER
group=$QPKI_USER
autostart=true
autorestart=true
startsecs=10
startretries=3
redirect_stderr=true
stdout_logfile=$QPKI_HOME/logs/supervisor.log
stdout_logfile_maxbytes=50MB
stdout_logfile_backups=10
environment=PATH="$QPKI_HOME/venv/bin",FLASK_ENV="production"
EOF

# Step 10: Configure Nginx
log "Configuring Nginx..."
cat > /etc/nginx/sites-available/qpki << 'EOF'
# qPKI Production Nginx Configuration

# Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name _;
    return 301 https://$host$request_uri;
}

# HTTPS Server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name _;

    # SSL Configuration (Update with your certificates)
    ssl_certificate /etc/ssl/certs/qpki.crt;
    ssl_certificate_key /etc/ssl/private/qpki.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; font-src 'self' cdnjs.cloudflare.com; img-src 'self' data:;" always;

    # Hide Nginx version
    server_tokens off;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/m;

    # Proxy settings
    location / {
        proxy_pass http://127.0.0.1:9090;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300;
        proxy_connect_timeout 300;
        proxy_send_timeout 300;
    }

    # Rate limiting for auth endpoints
    location ~ ^/auth/(login|mfa) {
        limit_req zone=login burst=3 nodelay;
        proxy_pass http://127.0.0.1:9090;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Rate limiting for API endpoints
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://127.0.0.1:9090;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Health check endpoint
    location /health {
        proxy_pass http://127.0.0.1:9090;
        access_log off;
    }

    # Block common attack patterns
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    location ~ ~$ {
        deny all;
        access_log off;
        log_not_found off;
    }
}
EOF

# Enable site
ln -sf /etc/nginx/sites-available/qpki /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test nginx configuration
nginx -t

# Step 11: Generate Self-Signed Certificate (for testing)
log "Generating self-signed SSL certificate..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/qpki.key \
    -out /etc/ssl/certs/qpki.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=qpki.local"

chmod 600 /etc/ssl/private/qpki.key
chmod 644 /etc/ssl/certs/qpki.crt

# Step 12: Create Backup Script
log "Creating backup script..."
cat > "$QPKI_HOME/backup-qpki.sh" << 'EOF'
#!/bin/bash
# qPKI Production Backup Script

BACKUP_DIR="/opt/qpki/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="qpki_backup_${DATE}.tar.gz.enc"

# Create backup
cd /opt/qpki
tar -czf - data/ logs/ .env.production | \
openssl enc -aes-256-cbc -salt -k "${BACKUP_ENCRYPTION_KEY}" > "${BACKUP_DIR}/${BACKUP_FILE}"

# Clean old backups (keep 30 days)
find "${BACKUP_DIR}" -name "qpki_backup_*.tar.gz.enc" -mtime +30 -delete

echo "Backup completed: ${BACKUP_FILE}"
EOF

chmod +x "$QPKI_HOME/backup-qpki.sh"
chown "$QPKI_USER":"$QPKI_USER" "$QPKI_HOME/backup-qpki.sh"

# Add to crontab
echo "0 2 * * * $QPKI_HOME/backup-qpki.sh" | sudo -u "$QPKI_USER" crontab -

# Step 13: Initialize Database
log "Initializing database..."
if [ -f "$QPKI_HOME/qpki-source/scripts/init_database.py" ]; then
    sudo -u "$QPKI_USER" bash -c "
        cd $QPKI_HOME/qpki-source
        source $QPKI_HOME/venv/bin/activate
        source .env.production
        python3 scripts/init_database.py
    "
else
    warn "Database initialization script not found. Please run manually."
fi

# Step 14: Start Services
log "Starting services..."
systemctl restart supervisor
systemctl enable supervisor

systemctl restart nginx
systemctl enable nginx

supervisorctl reread
supervisorctl update
supervisorctl start qpki

# Step 15: Final Security Check
log "Performing final security checks..."

# Check file permissions
find "$QPKI_HOME" -type f -perm /o+w -exec echo "World-writable file found: {}" \;
find "$QPKI_HOME" -type d -perm /o+w -exec echo "World-writable directory found: {}" \;

# Display status
echo
echo -e "${GREEN}================================"
echo "🎉 qPKI Production Deployment Complete!"
echo "================================${NC}"
echo
echo "Services Status:"
echo "- PostgreSQL: $(systemctl is-active postgresql)"
echo "- Redis: $(systemctl is-active redis-server)"
echo "- Nginx: $(systemctl is-active nginx)"
echo "- Supervisor: $(systemctl is-active supervisor)"
echo "- qPKI: $(supervisorctl status qpki | awk '{print $2}')"
echo
echo -e "${YELLOW}IMPORTANT SECURITY TASKS:${NC}"
echo "1. Update database password in .env.production"
echo "2. Install proper SSL certificates"
echo "3. Configure DNS for your domain"
echo "4. Review and update firewall rules"
echo "5. Set up monitoring and log rotation"
echo "6. Test backup and restore procedures"
echo
echo "Access your qPKI installation at: https://your-domain.com"
echo "Health check: https://your-domain.com/health"

log "Deployment completed successfully!"
