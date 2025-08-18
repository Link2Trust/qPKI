#!/bin/bash
#
# qPKI Deployment Cleanup Script
# 
# This script removes development artifacts and generated files while preserving
# certificates and CA folder contents for deployment preparation.
#
# Usage: ./clean_for_deployment.sh
#

set -e

echo "🧹 qPKI Deployment Cleanup Script"
echo "=================================="
echo ""
echo "This script will clean development artifacts while preserving:"
echo "  ✅ certificates/ folder contents"
echo "  ✅ ca/ folder contents"
echo "  ✅ Core application files"
echo ""

# Confirm before proceeding
read -p "Continue with cleanup? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Cleanup cancelled."
    exit 0
fi

echo "🚀 Starting cleanup..."

# Remove Python cache and build artifacts
echo "  📦 Removing Python cache and build artifacts..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true
find . -type f -name "*.pyo" -delete 2>/dev/null || true
find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
rm -rf build/ dist/ 2>/dev/null || true

# Remove virtual environment
echo "  🐍 Removing virtual environment..."
rm -rf venv/ 2>/dev/null || true

# Remove development environment files
echo "  ⚙️ Removing development environment files..."
rm -f .env 2>/dev/null || true

# Remove macOS specific files
echo "  🍎 Removing macOS specific files..."
find . -name ".DS_Store" -delete 2>/dev/null || true
find . -name "._*" -delete 2>/dev/null || true

# Remove log files (but keep the logs directory structure)
echo "  📝 Removing log files..."
rm -f *.log 2>/dev/null || true
rm -f logs/*.log 2>/dev/null || true
rm -f api.log 2>/dev/null || true

# Remove development scripts
echo "  📜 Removing development-specific scripts..."
rm -f start_api.sh 2>/dev/null || true
rm -f start_webui.sh 2>/dev/null || true
rm -f cleanup_for_github.sh 2>/dev/null || true

# Remove development documentation (keep essential README.md)
echo "  📚 Removing development documentation..."
rm -f PHASE1_IMPLEMENTATION.md 2>/dev/null || true
rm -f README_MACOS.md 2>/dev/null || true
rm -f SETUP_SUMMARY.md 2>/dev/null || true
rm -f EMAIL_FIX_SUMMARY.md 2>/dev/null || true

# Clean generated configuration files (keep examples)
echo "  🔧 Cleaning generated configuration files..."
if [ -f "config/email_config.json" ]; then
    echo "    ℹ️  Preserving config/email_config.json (contains user configuration)"
fi
# Remove any .db files from config
rm -f config/*.db 2>/dev/null || true

# Clear CRL directory contents (will be regenerated)
echo "  📋 Clearing CRL directory contents..."
rm -f crl/*.json 2>/dev/null || true

# Remove test and temporary files
echo "  🧪 Removing test and temporary files..."
rm -rf temp/ tmp/ test_certs/ 2>/dev/null || true
rm -f test_*.py 2>/dev/null || true

# Remove IDE and editor files
echo "  💻 Removing IDE and editor files..."
rm -rf .idea/ .vscode/ 2>/dev/null || true
find . -name "*.swp" -delete 2>/dev/null || true
find . -name "*.swo" -delete 2>/dev/null || true
find . -name "*~" -delete 2>/dev/null || true
find . -name "*.sublime-*" -delete 2>/dev/null || true

# Remove pytest cache and coverage files
echo "  🔍 Removing test artifacts..."
rm -rf .pytest_cache/ 2>/dev/null || true
rm -f .coverage coverage.xml 2>/dev/null || true
rm -rf htmlcov/ 2>/dev/null || true

echo ""
echo "✅ Cleanup completed successfully!"
echo ""
echo "📋 Preserved directories and their contents:"
echo "  📁 ca/ - $(ls -1 ca/ | grep -v README.md | wc -l | tr -d ' ') CA files preserved"
echo "  📁 certificates/ - $(ls -1 certificates/ | grep -v README.md | wc -l | tr -d ' ') certificate files preserved"
echo "  📁 src/ - Core application source code"
echo "  📁 templates/ - Web UI templates"
echo "  📁 examples/ - Usage examples"
echo ""

# Show current directory size
echo "📊 Current directory size:"
du -sh . 2>/dev/null || echo "  Unable to calculate directory size"
echo ""

echo "🚀 Ready for deployment!"
echo ""
echo "Next steps for deployment:"
echo "  1. Create virtual environment: python3 -m venv venv"
echo "  2. Activate environment: source venv/bin/activate"
echo "  3. Install dependencies: pip install -r requirements.txt"
echo "  4. Install package: pip install -e ."
echo "  5. Run application: python app.py"
echo ""
echo "Or use Docker: docker-compose up -d"
