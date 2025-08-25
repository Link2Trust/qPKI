#!/bin/bash
# =============================================================================
# qPKI Production Deployment Example Script
# Customize this script for your own deployment environment
# =============================================================================

set -euo pipefail

# Configuration - CHANGE THESE VALUES FOR YOUR DEPLOYMENT
DOMAIN="your-domain.com"  # Replace with your actual domain
DEPLOYMENT_TYPE="${1:-native}"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}🚀 Deploying qPKI for domain: ${DOMAIN}${NC}"
echo -e "${BLUE}📋 Deployment type: ${DEPLOYMENT_TYPE}${NC}"
echo ""

# Run safety check first
echo -e "${YELLOW}🔍 Running deployment safety check...${NC}"
if ./scripts/check_deployment.sh; then
    echo ""
    read -p "Existing installation detected. Continue with deployment? (y/N): " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Deployment cancelled by user."
        exit 0
    fi
    echo ""
fi

# Export domain for scripts
export QPKI_DOMAIN="$DOMAIN"

case "$DEPLOYMENT_TYPE" in
    "native")
        echo -e "${BLUE}🔧 Starting native deployment with Let's Encrypt SSL...${NC}"
        sudo QPKI_DOMAIN="$DOMAIN" ./scripts/setup_production.sh
        ;;
    "docker")
        echo -e "${BLUE}🐳 Starting Docker deployment...${NC}"
        QPKI_DOMAIN="$DOMAIN" ./scripts/start_production.sh docker --domain "$DOMAIN" --ssl-letsencrypt
        ;;
    "test")
        echo -e "${YELLOW}🧪 Starting test deployment with self-signed SSL...${NC}"
        sudo QPKI_DOMAIN="$DOMAIN" ./scripts/start_production.sh native --domain "$DOMAIN" --ssl-self-signed
        ;;
    *)
        echo "Usage: $0 [native|docker|test]"
        echo ""
        echo "Deployment options:"
        echo "  native - Full production deployment with Let's Encrypt"
        echo "  docker - Containerized deployment"
        echo "  test   - Test deployment with self-signed certificates"
        echo ""
        echo "Examples:"
        echo "  $0 native    # Production deployment"
        echo "  $0 docker    # Docker deployment"
        echo "  $0 test      # Test deployment"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}✅ Deployment completed!${NC}"
echo ""
echo -e "${GREEN}🌐 Access your qPKI instance at:${NC}"
echo -e "${GREEN}   https://${DOMAIN}/${NC}"
echo ""
echo -e "${GREEN}🔑 Demo Login:${NC}"
echo -e "${GREEN}   Username: demo${NC}"
echo -e "${GREEN}   Password: demo${NC}"
echo ""
echo -e "${YELLOW}⚠️  Next steps:${NC}"
echo -e "${YELLOW}   1. Update email settings in .env${NC}"
echo -e "${YELLOW}   2. Configure SMTP credentials for your email provider${NC}"
echo -e "${YELLOW}   3. Create additional admin users${NC}"
echo -e "${YELLOW}   4. Review security settings${NC}"
