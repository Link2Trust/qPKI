#!/bin/bash
# =============================================================================
# qPKI Deployment Safety Check Script
# =============================================================================
# This script checks for existing qPKI installations and provides safe upgrade paths

set -euo pipefail

# Configuration
QPKI_HOME="/opt/qpki"
QPKI_USER="qpki"
NGINX_CONFIG="/etc/nginx/sites-available/qpki"
SYSTEMD_SERVICE="/etc/systemd/system/qpki.service"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check functions
check_user_exists() {
    if id "$QPKI_USER" &>/dev/null; then
        echo -e "${YELLOW}[FOUND]${NC} qPKI user exists"
        return 0
    else
        echo -e "${GREEN}[OK]${NC} No existing qPKI user"
        return 1
    fi
}

check_directories() {
    local found=0
    
    if [[ -d "$QPKI_HOME" ]]; then
        echo -e "${YELLOW}[FOUND]${NC} qPKI home directory: $QPKI_HOME"
        
        if [[ -d "$QPKI_HOME/app" ]]; then
            echo -e "${YELLOW}[FOUND]${NC} Application directory with $(ls -1 $QPKI_HOME/app | wc -l) files"
            found=1
        fi
        
        if [[ -d "$QPKI_HOME/data" ]]; then
            echo -e "${YELLOW}[FOUND]${NC} Data directory"
            
            # Check for certificates and CA data
            local cert_count=$(find "$QPKI_HOME/data" -name "*.json" -o -name "*.pem" -o -name "*.crt" 2>/dev/null | wc -l)
            if [[ $cert_count -gt 0 ]]; then
                echo -e "${RED}[CRITICAL]${NC} Found $cert_count certificate/CA files in data directory"
                echo -e "${RED}           Deployment will preserve existing PKI data${NC}"
                found=1
            fi
        fi
        
        if [[ -f "$QPKI_HOME/app/.env" ]]; then
            echo -e "${YELLOW}[FOUND]${NC} Existing configuration file"
            found=1
        fi
    else
        echo -e "${GREEN}[OK]${NC} No existing qPKI directory"
    fi
    
    return $found
}

check_services() {
    local found=0
    
    # Check systemd service
    if [[ -f "$SYSTEMD_SERVICE" ]]; then
        echo -e "${YELLOW}[FOUND]${NC} Systemd service file"
        
        if systemctl is-active --quiet qpki 2>/dev/null; then
            echo -e "${YELLOW}[RUNNING]${NC} qPKI service is currently active"
            found=1
        elif systemctl is-enabled --quiet qpki 2>/dev/null; then
            echo -e "${YELLOW}[ENABLED]${NC} qPKI service is enabled but not running"
        fi
    else
        echo -e "${GREEN}[OK]${NC} No existing qPKI service"
    fi
    
    # Check nginx configuration
    if [[ -f "$NGINX_CONFIG" ]]; then
        echo -e "${YELLOW}[FOUND]${NC} Nginx configuration file"
        
        if [[ -L "/etc/nginx/sites-enabled/qpki" ]]; then
            echo -e "${YELLOW}[ENABLED]${NC} Nginx site is enabled"
            found=1
        fi
    else
        echo -e "${GREEN}[OK]${NC} No existing Nginx configuration"
    fi
    
    return $found
}

check_database() {
    # Check for SQLite databases
    local db_found=0
    
    if [[ -f "$QPKI_HOME/app/qpki" ]] || [[ -f "$QPKI_HOME/app/qpki.db" ]]; then
        echo -e "${RED}[CRITICAL]${NC} Found existing SQLite database"
        echo -e "${RED}           Contains user accounts and certificates${NC}"
        db_found=1
    fi
    
    # Check for PostgreSQL connection (if configured)
    if [[ -f "$QPKI_HOME/app/.env" ]]; then
        local db_url=$(grep -E "^DATABASE_URL=" "$QPKI_HOME/app/.env" 2>/dev/null | cut -d= -f2- | tr -d '"')
        if [[ "$db_url" == postgresql* ]]; then
            echo -e "${YELLOW}[FOUND]${NC} PostgreSQL database configured"
            echo -e "${YELLOW}         Connection: ${db_url%%:*}://****${NC}"
            db_found=1
        fi
    fi
    
    if [[ $db_found -eq 0 ]]; then
        echo -e "${GREEN}[OK]${NC} No existing database found"
    fi
    
    return $db_found
}

check_ssl_certificates() {
    local ssl_found=0
    
    if [[ -f "/etc/ssl/qpki/qpki.crt" ]] && [[ -f "/etc/ssl/qpki/qpki.key" ]]; then
        echo -e "${YELLOW}[FOUND]${NC} SSL certificates in /etc/ssl/qpki/"
        
        # Check certificate validity
        local expiry=$(openssl x509 -in "/etc/ssl/qpki/qpki.crt" -noout -enddate 2>/dev/null | cut -d= -f2)
        if [[ -n "$expiry" ]]; then
            echo -e "${BLUE}[INFO]${NC} Certificate expires: $expiry"
        fi
        ssl_found=1
    fi
    
    # Check for Let's Encrypt certificates
    if [[ -d "/etc/letsencrypt/live" ]]; then
        local le_domains=$(ls /etc/letsencrypt/live 2>/dev/null | grep -v README | wc -l)
        if [[ $le_domains -gt 0 ]]; then
            echo -e "${YELLOW}[FOUND]${NC} $le_domains Let's Encrypt certificate(s)"
            ssl_found=1
        fi
    fi
    
    if [[ $ssl_found -eq 0 ]]; then
        echo -e "${GREEN}[OK]${NC} No existing SSL certificates"
    fi
    
    return $ssl_found
}

show_backup_recommendations() {
    echo ""
    echo -e "${BLUE}=== BACKUP RECOMMENDATIONS ===${NC}"
    echo ""
    echo "Before proceeding with deployment, consider backing up:"
    echo ""
    
    if [[ -d "$QPKI_HOME/data" ]]; then
        echo -e "${YELLOW}1. PKI Data:${NC}"
        echo "   sudo tar -czf qpki-data-backup-\$(date +%Y%m%d_%H%M%S).tar.gz -C $QPKI_HOME data/"
        echo ""
    fi
    
    if [[ -f "$QPKI_HOME/app/.env" ]]; then
        echo -e "${YELLOW}2. Configuration:${NC}"
        echo "   sudo cp $QPKI_HOME/app/.env qpki-config-backup-\$(date +%Y%m%d_%H%M%S).env"
        echo ""
    fi
    
    if [[ -f "$QPKI_HOME/app/qpki" ]] || [[ -f "$QPKI_HOME/app/qpki.db" ]]; then
        echo -e "${YELLOW}3. Database:${NC}"
        echo "   sudo cp $QPKI_HOME/app/qpki* qpki-db-backup-\$(date +%Y%m%d_%H%M%S)/"
        echo ""
    fi
    
    if [[ -d "/etc/ssl/qpki" ]]; then
        echo -e "${YELLOW}4. SSL Certificates:${NC}"
        echo "   sudo tar -czf qpki-ssl-backup-\$(date +%Y%m%d_%H%M%S).tar.gz -C /etc/ssl qpki/"
        echo ""
    fi
}

show_deployment_options() {
    echo ""
    echo -e "${BLUE}=== DEPLOYMENT OPTIONS ===${NC}"
    echo ""
    echo "Based on the existing installation, you have these options:"
    echo ""
    echo -e "${GREEN}1. Fresh Installation:${NC}"
    echo "   - Remove existing installation completely"
    echo "   - Start with clean environment"
    echo "   - Command: sudo ./scripts/remove_qpki.sh && sudo ./scripts/setup_production.sh"
    echo ""
    echo -e "${YELLOW}2. Upgrade/Update:${NC}"
    echo "   - Keep existing data and configuration"
    echo "   - Update application code only"
    echo "   - Command: sudo ./scripts/setup_production.sh"
    echo "   - (The script will prompt for backup confirmation)"
    echo ""
    echo -e "${BLUE}3. Manual Configuration:${NC}"
    echo "   - Review and update configuration manually"
    echo "   - Copy new files selectively"
    echo "   - Recommended for production systems with custom configurations"
    echo ""
}

main() {
    echo -e "${BLUE}=== qPKI Deployment Safety Check ===${NC}"
    echo ""
    echo "Checking for existing qPKI installation..."
    echo ""
    
    local existing_install=0
    local critical_data=0
    
    # Run all checks
    if check_user_exists; then existing_install=1; fi
    if check_directories; then 
        existing_install=1
        critical_data=1
    fi
    if check_services; then existing_install=1; fi
    if check_database; then critical_data=1; fi
    if check_ssl_certificates; then existing_install=1; fi
    
    echo ""
    
    # Summary
    if [[ $existing_install -eq 0 ]]; then
        echo -e "${GREEN}=== RESULT: Clean System ===${NC}"
        echo "No existing qPKI installation detected."
        echo "Safe to proceed with fresh installation."
        echo ""
        echo "Run: sudo ./scripts/setup_production.sh"
    else
        echo -e "${YELLOW}=== RESULT: Existing Installation Detected ===${NC}"
        
        if [[ $critical_data -eq 1 ]]; then
            echo -e "${RED}⚠️  CRITICAL: Existing PKI data or database found${NC}"
            echo "This installation contains certificates, keys, or user data."
            echo "Proceeding will preserve existing data but may overwrite configuration."
        fi
        
        show_backup_recommendations
        show_deployment_options
    fi
    
    return $existing_install
}

# Run the check
main "$@"
