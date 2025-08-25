#!/bin/bash
# =============================================================================
# qPKI Production Deployment Setup Script
# =============================================================================
# This script sets up the production environment for qPKI with TLS support

set -euo pipefail

# Configuration
QPKI_USER="qpki"
QPKI_GROUP="qpki"
QPKI_HOME="/opt/qpki"
QPKI_VENV="/opt/qpki/venv"
NGINX_CONFIG_DIR="/etc/nginx/sites-available"
NGINX_ENABLED_DIR="/etc/nginx/sites-enabled"
SYSTEMD_DIR="/etc/systemd/system"
LOG_DIR="/var/log/qpki"
SSL_DIR="/etc/ssl/qpki"
DOMAIN="${QPKI_DOMAIN:-localhost}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
    fi
}

# Install system dependencies
install_dependencies() {
    log_info "Installing system dependencies..."
    
    apt-get update
    apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        nginx \
        postgresql-client \
        redis-server \
        certbot \
        python3-certbot-nginx \
        ufw \
        fail2ban \
        logrotate \
        supervisor
    
    log_success "System dependencies installed"
}

# Create system user and directories
setup_user_and_dirs() {
    log_info "Setting up qPKI user and directories..."
    
    # Create qpki user if it doesn't exist
    if ! id "$QPKI_USER" &>/dev/null; then
        useradd -r -s /bin/bash -d "$QPKI_HOME" "$QPKI_USER"
        log_success "Created qPKI user: $QPKI_USER"
    fi
    
    # Create directories
    mkdir -p "$QPKI_HOME"/{app,data,logs,backups,ssl}
    mkdir -p "$QPKI_HOME/data"/{certificates,ca,crl,keys}
    mkdir -p "$LOG_DIR"
    mkdir -p "$SSL_DIR"
    
    # Set ownership
    chown -R "$QPKI_USER:$QPKI_GROUP" "$QPKI_HOME"
    chown -R "$QPKI_USER:$QPKI_GROUP" "$LOG_DIR"
    
    # Set permissions
    chmod 755 "$QPKI_HOME"
    chmod 750 "$QPKI_HOME/data"
    chmod 700 "$QPKI_HOME/data/keys"
    chmod 755 "$LOG_DIR"
    
    log_success "User and directories configured"
}

# Setup Python virtual environment
setup_python_env() {
    log_info "Setting up Python virtual environment..."
    
    # Create virtual environment
    python3 -m venv "$QPKI_VENV"
    
    # Activate and install requirements
    source "$QPKI_VENV/bin/activate"
    pip install --upgrade pip
    pip install -r "$PWD/requirements.txt"
    pip install gunicorn psycopg2-binary redis
    
    # Set ownership
    chown -R "$QPKI_USER:$QPKI_GROUP" "$QPKI_VENV"
    
    log_success "Python environment configured"
}

# Copy application files with safety checks
deploy_application() {
    log_info "Deploying qPKI application..."
    
    # Check if application directory already exists
    if [[ -d "$QPKI_HOME/app" ]] && [[ "$(ls -A $QPKI_HOME/app 2>/dev/null)" ]]; then
        log_warning "Application directory already contains files"
        read -p "Do you want to backup existing files and continue? (y/N): " -r
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_error "Deployment cancelled by user"
        fi
        
        # Create backup
        BACKUP_DIR="$QPKI_HOME/backups/app_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$BACKUP_DIR"
        cp -r "$QPKI_HOME/app"/* "$BACKUP_DIR/" 2>/dev/null || true
        log_info "Existing files backed up to: $BACKUP_DIR"
    fi
    
    # Copy application files
    mkdir -p "$QPKI_HOME/app"
    cp -r "$PWD"/* "$QPKI_HOME/app/"
    
    # Handle configuration file safely
    deploy_configuration
    
    # Set ownership
    chown -R "$QPKI_USER:$QPKI_GROUP" "$QPKI_HOME/app"
    
    # Set executable permissions for scripts
    chmod +x "$QPKI_HOME/app/scripts"/*.py 2>/dev/null || true
    
    log_success "Application deployed"
}

# Deploy configuration with safety checks
deploy_configuration() {
    log_info "Setting up configuration files..."
    
    local env_file="$QPKI_HOME/app/.env"
    local env_example="$PWD/.env.example"
    
    # Check if .env already exists
    if [[ -f "$env_file" ]]; then
        log_warning "Configuration file already exists: $env_file"
        log_info "Creating backup and preserving existing configuration"
        
        # Create backup
        cp "$env_file" "$env_file.backup.$(date +%Y%m%d_%H%M%S)"
        log_info "Existing configuration backed up"
        
        # Show differences with example
        if [[ -f "$env_example" ]]; then
            log_info "You may want to review new configuration options in .env.example"
        fi
    else
        # Create new configuration from example
        if [[ -f "$env_example" ]]; then
            cp "$env_example" "$env_file"
            log_info "Configuration created from .env.example"
            log_warning "IMPORTANT: Edit $env_file to customize your deployment"
        else
            log_error "No configuration template found (.env.example missing)"
        fi
    fi
}

# Generate or setup SSL certificates
setup_ssl_certificates() {
    log_info "Setting up SSL certificates..."
    
    if [[ "$DOMAIN" != "localhost" ]]; then
        log_info "Setting up Let's Encrypt certificate for domain: $DOMAIN"
        
        # Stop nginx temporarily
        systemctl stop nginx || true
        
        # Get Let's Encrypt certificate
        certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos --email admin@"$DOMAIN"
        
        # Copy certificates to qPKI SSL directory
        cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$SSL_DIR/qpki.crt"
        cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$SSL_DIR/qpki.key"
        
        # Set up automatic renewal
        echo "0 12 * * * /usr/bin/certbot renew --quiet" | crontab -
        
    else
        log_info "Generating self-signed certificate for localhost..."
        
        # Generate self-signed certificate for localhost/development
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$SSL_DIR/qpki.key" \
            -out "$SSL_DIR/qpki.crt" \
            -subj "/C=US/ST=Development/L=Development/O=qPKI/OU=Development/CN=localhost"
    fi
    
    # Set proper permissions
    chown root:root "$SSL_DIR"/*
    chmod 644 "$SSL_DIR/qpki.crt"
    chmod 600 "$SSL_DIR/qpki.key"
    
    log_success "SSL certificates configured"
}

# Configure Nginx
setup_nginx() {
    log_info "Configuring Nginx web server..."
    
    # Create nginx configuration
    cat > "$NGINX_CONFIG_DIR/qpki" << EOF
# qPKI Production Configuration
upstream qpki_app {
    server 127.0.0.1:9090;
    keepalive 32;
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

# HTTPS Server
server {
    listen 443 ssl http2;
    server_name $DOMAIN;

    # SSL Configuration
    ssl_certificate $SSL_DIR/qpki.crt;
    ssl_certificate_key $SSL_DIR/qpki.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 24h;
    ssl_session_tickets off;

    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; font-src 'self' cdnjs.cloudflare.com; img-src 'self' data:;" always;

    # Logging
    access_log /var/log/nginx/qpki_access.log;
    error_log /var/log/nginx/qpki_error.log warn;

    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=login:10m rate=5r/m;
    limit_req_zone \$binary_remote_addr zone=api:10m rate=100r/m;

    # General settings
    client_max_body_size 50M;
    client_body_timeout 60s;
    client_header_timeout 60s;
    keepalive_timeout 65s;
    send_timeout 60s;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/json application/xml+rss;

    # Static files
    location /static/ {
        alias $QPKI_HOME/app/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Health check endpoint
    location /health {
        proxy_pass http://qpki_app;
        access_log off;
    }

    # API endpoints with rate limiting
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://qpki_app;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Login endpoint with strict rate limiting
    location /auth/login {
        limit_req zone=login burst=3 nodelay;
        proxy_pass http://qpki_app;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # All other requests
    location / {
        proxy_pass http://qpki_app;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
    }

    # Security: Deny access to sensitive files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    location ~ \.(env|config)$ {
        deny all;
        access_log off;
        log_not_found off;
    }
}
EOF

    # Enable the site
    ln -sf "$NGINX_CONFIG_DIR/qpki" "$NGINX_ENABLED_DIR/qpki"
    
    # Remove default nginx site
    rm -f "$NGINX_ENABLED_DIR/default"
    
    # Test nginx configuration
    nginx -t
    
    log_success "Nginx configured"
}

# Setup systemd service
setup_systemd_service() {
    log_info "Setting up systemd service..."
    
    cat > "$SYSTEMD_DIR/qpki.service" << EOF
[Unit]
Description=qPKI - Quantum-Safe PKI Application
After=network.target postgresql.service redis.service
Wants=postgresql.service redis.service

[Service]
Type=exec
User=$QPKI_USER
Group=$QPKI_GROUP
WorkingDirectory=$QPKI_HOME/app
Environment=PATH=$QPKI_VENV/bin
Environment=FLASK_APP=app_production.py
ExecStart=$QPKI_VENV/bin/gunicorn --config gunicorn.conf.py app_production:app
ExecReload=/bin/kill -s HUP \$MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true
Restart=on-failure
RestartSec=10

# Security settings
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$QPKI_HOME $LOG_DIR
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable qpki
    
    log_success "Systemd service configured"
}

# Setup logging
setup_logging() {
    log_info "Setting up logging configuration..."
    
    # Create logrotate configuration
    cat > "/etc/logrotate.d/qpki" << EOF
$LOG_DIR/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 $QPKI_USER $QPKI_GROUP
    postrotate
        systemctl reload qpki
    endscript
}

/var/log/nginx/qpki_*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 www-data adm
    postrotate
        systemctl reload nginx
    endscript
}
EOF

    log_success "Logging configured"
}

# Setup firewall
setup_firewall() {
    log_info "Configuring firewall..."
    
    # Configure UFW
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH
    ufw allow ssh
    
    # Allow HTTP and HTTPS
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # Enable firewall
    ufw --force enable
    
    log_success "Firewall configured"
}

# Setup fail2ban
setup_fail2ban() {
    log_info "Setting up fail2ban..."
    
    cat > "/etc/fail2ban/jail.local" << EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd

[sshd]
enabled = true

[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/qpki_error.log

[nginx-noscript]
enabled = true
port = http,https
logpath = /var/log/nginx/qpki_access.log
maxretry = 6

[nginx-badbots]
enabled = true
port = http,https
logpath = /var/log/nginx/qpki_access.log
maxretry = 2

[nginx-noproxy]
enabled = true
port = http,https
logpath = /var/log/nginx/qpki_access.log
maxretry = 2
EOF

    systemctl enable fail2ban
    systemctl start fail2ban
    
    log_success "Fail2ban configured"
}

# Initialize database
initialize_database() {
    log_info "Initializing database..."
    
    # Run database initialization as qpki user
    sudo -u "$QPKI_USER" bash -c "
        source $QPKI_VENV/bin/activate
        cd $QPKI_HOME/app
        python scripts/init_database.py
    "
    
    log_success "Database initialized"
}

# Start services
start_services() {
    log_info "Starting services..."
    
    systemctl start redis-server
    systemctl start qpki
    systemctl start nginx
    systemctl start fail2ban
    
    # Wait a moment for services to start
    sleep 5
    
    # Check service status
    systemctl is-active --quiet qpki && log_success "qPKI service started" || log_error "qPKI service failed to start"
    systemctl is-active --quiet nginx && log_success "Nginx service started" || log_error "Nginx service failed to start"
    systemctl is-active --quiet redis-server && log_success "Redis service started" || log_error "Redis service failed to start"
    systemctl is-active --quiet fail2ban && log_success "Fail2ban service started" || log_error "Fail2ban service failed to start"
}

# Display final information
show_completion_info() {
    echo ""
    log_success "=== qPKI Production Deployment Complete ==="
    echo ""
    echo "Services Status:"
    systemctl status qpki --no-pager -l || true
    echo ""
    echo "Access Information:"
    echo "  - Web Interface: https://$DOMAIN/"
    echo "  - Demo Credentials: demo/demo"
    echo ""
    echo "Configuration Files:"
    echo "  - Application: $QPKI_HOME/app/.env"
    echo "  - Nginx: $NGINX_CONFIG_DIR/qpki"
    echo "  - Systemd: $SYSTEMD_DIR/qpki.service"
    echo "  - SSL Certificates: $SSL_DIR/"
    echo ""
    echo "Log Files:"
    echo "  - Application: $LOG_DIR/"
    echo "  - Nginx Access: /var/log/nginx/qpki_access.log"
    echo "  - Nginx Error: /var/log/nginx/qpki_error.log"
    echo ""
    echo "Management Commands:"
    echo "  - Restart qPKI: sudo systemctl restart qpki"
    echo "  - View logs: sudo journalctl -u qpki -f"
    echo "  - Check status: sudo systemctl status qpki"
    echo ""
    log_warning "IMPORTANT: Update the .env file with your actual database and SMTP settings!"
    log_warning "Default passwords and keys should be changed before production use!"
}

# Main execution
main() {
    log_info "Starting qPKI Production Deployment..."
    
    check_root
    install_dependencies
    setup_user_and_dirs
    setup_python_env
    deploy_application
    setup_ssl_certificates
    setup_nginx
    setup_systemd_service
    setup_logging
    setup_firewall
    setup_fail2ban
    initialize_database
    start_services
    show_completion_info
}

# Run main function
main "$@"
