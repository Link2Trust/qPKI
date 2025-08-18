#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
source .env
export $(cat .env | grep -v '^#' | xargs)
export API_PORT=9091
echo "🔌 Starting qPKI REST API on http://localhost:9091"
echo "📚 API Documentation: http://localhost:9091/api/v1/docs/"
echo "💚 Health Check: http://localhost:9091/health"
echo ""
# Add src to Python path and run simplified app
export PYTHONPATH="$PWD/src:$PYTHONPATH"
cd src
python -m qpki.api.simple_app
