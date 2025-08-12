#!/bin/bash

echo "🚀 Starting qPKI Web Application..."
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Creating one..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    pip install -e .
else
    echo "✅ Activating virtual environment..."
    source venv/bin/activate
fi

echo ""
echo "🌐 Starting qPKI Web Application on http://localhost:9090"
echo ""
echo "📋 To create your first CA:"
echo "   1. Open http://localhost:9090 in your browser"
echo "   2. Click 'Create Certificate Authority'"
echo "   3. Fill in organization details"
echo "   4. Choose RSA or ECC + Dilithium (hybrid quantum-safe)"
echo ""
echo "📧 Email notifications are configured for MailHog:"
echo "   • SMTP: localhost:1025"
echo "   • Web UI: http://localhost:8025 (if using Docker)"
echo ""
echo "🐳 Alternative: Use Docker Compose"
echo "   • Run: docker-compose up -d"
echo "   • Access qPKI at http://localhost:9090"
echo "   • Access MailHog at http://localhost:8025"
echo ""
echo "Starting application..."
echo ""

python app.py
