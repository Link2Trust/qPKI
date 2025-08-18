#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
source .env
export $(cat .env | grep -v '^#' | xargs)
export WEB_PORT=9090
echo "🌐 Starting qPKI Web UI on http://localhost:9090"
echo "📋 Access your PKI dashboard at: http://localhost:9090"
echo ""
python app.py
