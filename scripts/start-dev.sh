#!/bin/bash

# qPKI Development Start Script
# Starts MailHog and qPKI for development

echo "🚀 Starting qPKI Development Environment"
echo "========================================"

# Check if we're in the right directory
if [[ ! -f "app.py" ]]; then
    echo "❌ Error: Please run this script from the qPKI root directory"
    exit 1
fi

# Check if virtual environment exists
if [[ ! -d "venv" ]]; then
    echo "❌ Error: Virtual environment not found. Run scripts/dev-setup.sh first"
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Function to cleanup background processes
cleanup() {
    echo ""
    echo "🛑 Shutting down services..."
    
    # Kill MailHog if we started it
    if [[ -n "$MAILHOG_PID" ]]; then
        kill $MAILHOG_PID 2>/dev/null || true
        echo "✅ MailHog stopped"
    fi
    
    # Kill qPKI if we started it  
    if [[ -n "$QPKI_PID" ]]; then
        kill $QPKI_PID 2>/dev/null || true
        echo "✅ qPKI stopped"
    fi
    
    echo "👋 Goodbye!"
    exit 0
}

# Set up signal handlers for cleanup
trap cleanup SIGINT SIGTERM

# Start MailHog in background
if ! pgrep -f mailhog > /dev/null; then
    echo "📧 Starting MailHog..."
    if command -v mailhog &> /dev/null; then
        mailhog > /dev/null 2>&1 &
        MAILHOG_PID=$!
        echo "✅ MailHog started (PID: $MAILHOG_PID)"
        echo "   SMTP: http://localhost:1025"
        echo "   Web:  http://localhost:8025"
    else
        echo "⚠️  MailHog not found. Install it with: brew install mailhog"
        echo "   Continuing without MailHog..."
    fi
else
    echo "✅ MailHog already running"
fi

echo ""

# Set development environment variables
export FLASK_ENV=development
export FLASK_DEBUG=1

# Start qPKI
echo "🎯 Starting qPKI..."
echo "   Web Interface: http://localhost:9090"
echo ""
echo "💡 Tips:"
echo "   - Configure email settings at: http://localhost:9090/notifications"
echo "   - Use SMTP server: localhost:1025"
echo "   - Check emails at: http://localhost:8025"
echo "   - Press Ctrl+C to stop all services"
echo ""

# Start qPKI in foreground so we can see logs and handle Ctrl+C
python3 app.py &
QPKI_PID=$!

# Wait for qPKI process
wait $QPKI_PID
