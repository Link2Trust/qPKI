#!/bin/bash

# qPKI Development Setup Script
# This script sets up the development environment with MailHog for email testing

set -e  # Exit on any error

echo "🔧 qPKI Development Setup"
echo "========================="

# Check if we're in the right directory
if [[ ! -f "app.py" || ! -d "src/qpki" ]]; then
    echo "❌ Error: Please run this script from the qPKI root directory"
    exit 1
fi

# Check Python version
python_version=$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+')
required_version="3.8"

if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
    echo "❌ Error: Python 3.8+ is required. Found: $(python3 --version)"
    exit 1
fi

echo "✅ Python version check passed"

# Create virtual environment if it doesn't exist
if [[ ! -d "venv" ]]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment already exists"
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "🔄 Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "📚 Installing dependencies..."
pip install -r requirements.txt

# Install package in development mode
echo "📦 Installing qPKI in development mode..."
pip install -e .

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p certificates ca crl logs config templates/email

# Install MailHog for email testing
echo "📧 Setting up MailHog for email testing..."
if command -v brew &> /dev/null; then
    if ! command -v mailhog &> /dev/null; then
        echo "🔄 Installing MailHog via Homebrew..."
        brew install mailhog
        echo "✅ MailHog installed"
    else
        echo "✅ MailHog already installed"
    fi
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if ! command -v mailhog &> /dev/null; then
        echo "🔄 Installing MailHog for Linux..."
        # Download MailHog binary
        curl -L https://github.com/mailhog/MailHog/releases/download/v1.0.1/MailHog_linux_amd64 -o mailhog
        chmod +x mailhog
        sudo mv mailhog /usr/local/bin/
        echo "✅ MailHog installed"
    else
        echo "✅ MailHog already installed"
    fi
else
    echo "⚠️  Please install MailHog manually from: https://github.com/mailhog/MailHog/releases"
fi

# Check if email config exists and is configured for MailHog
if [[ -f "config/email_config.json" ]]; then
    if grep -q '"smtp_port": 1025' config/email_config.json; then
        echo "✅ Email configuration already set for MailHog"
    else
        echo "⚠️  Please configure email settings in config/email_config.json for MailHog"
    fi
else
    echo "⚠️  Email configuration file not found"
fi

echo ""
echo "🎉 Development setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. Activate the virtual environment: source venv/bin/activate"
echo "2. Start MailHog: mailhog"
echo "3. Start qPKI: python3 app.py"
echo "4. Open qPKI: http://localhost:9090"
echo "5. Open MailHog: http://localhost:8025"
echo ""
echo "💡 Tips:"
echo "- Configure email settings in the web interface (/notifications)"
echo "- Use SMTP server: localhost:1025 for MailHog"
echo "- Check MailHog web interface for test emails"
echo "- Enable development mode: export FLASK_ENV=development"
echo ""
echo "🚀 Happy developing!"
