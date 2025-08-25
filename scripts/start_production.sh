#!/bin/bash
# =============================================================================
# qPKI Production Startup Script
# =============================================================================
# Quick start script for production deployment options

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DOMAIN="${QPKI_DOMAIN:-localhost}"
DEPLOYMENT_TYPE="${1:-native}"

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

# Display usage information
show_usage() {
    cat << EOF
qPKI Production Deployment Script

Usage: $0 [DEPLOYMENT_TYPE] [OPTIONS]

Deployment Types:
  native     - Native system deployment (default)
  docker     - Docker containerized deployment
  help       - Show this help message

Options:
  --domain DOMAIN     Set domain name (default: localhost)
  --ssl-self-signed  Use self-signed SSL certificate
  --ssl-letsencrypt  Use Let's Encrypt SSL certificate
  --skip-db-init     Skip database initialization
  --skip-ssl         Skip SSL setup (development only)

Environment Variables:
  QPKI_DOMAIN        Domain name for SSL certificate
  POSTGRES_PASSWORD  Database password
  SECRET_KEY         Flask secret key
  SMTP_*             Email configuration

Examples:
  $0 native --domain example.com --ssl-letsencrypt
  $0 docker --domain localhost --ssl-self-signed
  QPKI_DOMAIN=myqpki.com $0 native

EOF
}

# Check system requirements
check_requirements() {
    log_info "Checking system requirements..."
    
    case "$DEPLOYMENT_TYPE" in
        "native")
            # Check for required commands
            local required_commands=("python3" "pip3" "systemctl" "nginx")
            for cmd in "${required_commands[@]}"; do
                if ! command -v "$cmd" &> /dev/null; then
                    log_error "Required command '$cmd' not found"
                fi
            done
            ;;
        "docker")
            # Check for Docker and Docker Compose
            if ! command -v docker &> /dev/null; then
                log_error "Docker not found. Please install Docker first."
            fi
            if ! command -v docker-compose &> /dev/null; then
                log_error "Docker Compose not found. Please install Docker Compose first."
            fi
            ;;
    esac
    
    log_success "System requirements check passed"
}

# Generate secure random passwords and keys
generate_secrets() {
    log_info "Generating secure secrets..."
    
    export SECRET_KEY=${SECRET_KEY:-$(python3 -c "import secrets; print(secrets.token_urlsafe(64))")}
    export POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")}
    export REDIS_PASSWORD=${REDIS_PASSWORD:-$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")}
    
    log_success "Secrets generated"
}

# Create SSL certificates
setup_ssl_certificates() {
    local ssl_type="$1"
    log_info "Setting up SSL certificates ($ssl_type)..."
    
    case "$ssl_type" in
        "self-signed")
            mkdir -p "$PROJECT_DIR/ssl"
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout "$PROJECT_DIR/ssl/qpki.key" \
                -out "$PROJECT_DIR/ssl/qpki.crt" \
                -subj "/C=US/ST=Development/L=Development/O=qPKI/CN=$DOMAIN"
            chmod 600 "$PROJECT_DIR/ssl/qpki.key"
            log_success "Self-signed SSL certificate created"
            ;;
        "letsencrypt")
            if [[ "$DOMAIN" == "localhost" ]]; then
                log_error "Cannot use Let's Encrypt with localhost domain"
            fi
            # Let's Encrypt setup would go here
            log_warning "Let's Encrypt setup requires manual configuration"
            ;;
        "skip")
            log_warning "Skipping SSL setup - HTTPS will not work"
            ;;
    esac
}

# Deploy using native system installation
deploy_native() {
    log_info "Starting native system deployment..."
    
    if [[ $EUID -ne 0 ]]; then
        log_error "Native deployment requires root privileges. Use sudo."
    fi
    
    # Run the full setup script
    "$SCRIPT_DIR/setup_production.sh"
}

# Deploy using Docker
deploy_docker() {
    log_info "Starting Docker deployment..."
    
    cd "$PROJECT_DIR"
    
    # Create docker environment file
    cat > .env.docker << EOF
# Docker Production Environment
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
REDIS_PASSWORD=$REDIS_PASSWORD
SECRET_KEY=$SECRET_KEY
APP_VERSION=latest

# Domain Configuration
QPKI_DOMAIN=$DOMAIN

# Email Configuration (update these)
SMTP_SERVER=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=qpki@example.com
SMTP_PASSWORD=changeme_email_password
FROM_EMAIL=qpki@example.com

# Gunicorn Settings
GUNICORN_WORKERS=4

# Timezone
TZ=UTC
EOF

    # Build and start services
    log_info "Building Docker images..."
    docker-compose -f docker-compose.production.yml --env-file .env.docker build
    
    log_info "Starting Docker services..."
    docker-compose -f docker-compose.production.yml --env-file .env.docker up -d
    
    # Wait for services to be ready
    log_info "Waiting for services to start..."
    sleep 30
    
    # Initialize database
    log_info "Initializing database..."
    docker-compose -f docker-compose.production.yml exec qpki python scripts/init_database.py
    
    log_success "Docker deployment completed"
}

# Create nginx configuration for Docker
create_nginx_config() {
    log_info "Creating Nginx configuration..."
    
    mkdir -p "$PROJECT_DIR/nginx"
    
    cat > "$PROJECT_DIR/nginx/qpki.conf" << EOF
upstream qpki_app {
    server qpki:9090;
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
    ssl_certificate /etc/ssl/qpki/qpki.crt;
    ssl_certificate_key /etc/ssl/qpki/qpki.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 24h;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=login:10m rate=5r/m;
    limit_req_zone \$binary_remote_addr zone=api:10m rate=100r/m;

    # Health check endpoint
    location /health {
        proxy_pass http://qpki_app;
        access_log off;
    }

    # Login endpoint with rate limiting
    location /auth/login {
        limit_req zone=login burst=3 nodelay;
        proxy_pass http://qpki_app;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Main proxy configuration
    location / {
        proxy_pass http://qpki_app;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        proxy_buffering on;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
    }
}
EOF

    # Basic nginx.conf
    cat > "$PROJECT_DIR/nginx/nginx.conf" << EOF
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Logging
    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for"';
    
    access_log /var/log/nginx/access.log main;
    
    # Performance
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 50M;
    
    # Gzip
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/json;
    
    # Include configurations
    include /etc/nginx/conf.d/*.conf;
}
EOF

    log_success "Nginx configuration created"
}

# Display final information
show_completion_info() {
    echo ""
    log_success "=== qPKI Production Deployment Complete ==="
    echo ""
    echo "Deployment Type: $DEPLOYMENT_TYPE"
    echo "Domain: $DOMAIN"
    echo ""
    case "$DEPLOYMENT_TYPE" in
        "native")
            echo "Access URLs:"
            echo "  - HTTPS: https://$DOMAIN/"
            echo "  - HTTP: http://$DOMAIN/ (redirects to HTTPS)"
            echo ""
            echo "Management Commands:"
            echo "  - Status: sudo systemctl status qpki"
            echo "  - Logs: sudo journalctl -u qpki -f"
            echo "  - Restart: sudo systemctl restart qpki"
            ;;
        "docker")
            echo "Access URLs:"
            echo "  - HTTPS: https://$DOMAIN/"
            echo "  - HTTP: http://$DOMAIN/ (redirects to HTTPS)"
            echo ""
            echo "Docker Commands:"
            echo "  - Status: docker-compose -f docker-compose.production.yml ps"
            echo "  - Logs: docker-compose -f docker-compose.production.yml logs -f"
            echo "  - Restart: docker-compose -f docker-compose.production.yml restart"
            echo "  - Stop: docker-compose -f docker-compose.production.yml down"
            ;;
    esac
    echo ""
    echo "Demo Login:"
    echo "  - Username: demo"
    echo "  - Password: demo"
    echo ""
    echo "Configuration Files:"
    case "$DEPLOYMENT_TYPE" in
        "native")
            echo "  - Application: /opt/qpki/app/.env"
            echo "  - Nginx: /etc/nginx/sites-available/qpki"
            echo "  - SSL: /etc/ssl/qpki/"
            ;;
        "docker")
            echo "  - Docker Environment: .env.docker"
            echo "  - Nginx: nginx/qpki.conf"
            echo "  - SSL: ssl/"
            ;;
    esac
    echo ""
    log_warning "IMPORTANT: Update email and database settings for production use!"
    log_warning "Change default passwords and secrets before exposing to the internet!"
}

# Main execution function
main() {
    log_info "qPKI Production Deployment Starting..."
    
    # Parse arguments
    SSL_TYPE="self-signed"
    SKIP_DB_INIT=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --domain)
                DOMAIN="$2"
                export QPKI_DOMAIN="$DOMAIN"
                shift 2
                ;;
            --ssl-self-signed)
                SSL_TYPE="self-signed"
                shift
                ;;
            --ssl-letsencrypt)
                SSL_TYPE="letsencrypt"
                shift
                ;;
            --skip-ssl)
                SSL_TYPE="skip"
                shift
                ;;
            --skip-db-init)
                SKIP_DB_INIT="true"
                shift
                ;;
            help|--help|-h)
                show_usage
                exit 0
                ;;
            *)
                if [[ -z "${DEPLOYMENT_TYPE_SET:-}" ]]; then
                    DEPLOYMENT_TYPE="$1"
                    DEPLOYMENT_TYPE_SET="true"
                fi
                shift
                ;;
        esac
    done
    
    case "$DEPLOYMENT_TYPE" in
        "native"|"docker")
            check_requirements
            generate_secrets
            
            if [[ "$SSL_TYPE" != "skip" ]]; then
                setup_ssl_certificates "$SSL_TYPE"
            fi
            
            if [[ "$DEPLOYMENT_TYPE" == "docker" ]]; then
                create_nginx_config
                deploy_docker
            else
                deploy_native
            fi
            
            show_completion_info
            ;;
        "help")
            show_usage
            ;;
        *)
            log_error "Invalid deployment type: $DEPLOYMENT_TYPE"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
