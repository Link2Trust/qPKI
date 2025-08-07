# qPKI - Quantum-Safe Hybrid Public Key Infrastructure
# Makefile for project management

.PHONY: help install dev-install test demo clean setup check

# Default target
help:
	@echo "🔐 qPKI - Quantum-Safe Hybrid PKI"
	@echo "=================================="
	@echo ""
	@echo "Available targets:"
	@echo "  install     - Install qPKI and dependencies"
	@echo "  dev-install - Install in development mode with editable install"
	@echo "  test        - Run the test suite"
	@echo "  demo        - Run the built-in demo"
	@echo "  example     - Run the basic usage example"
	@echo "  setup       - Set up development environment"
	@echo "  check       - Check dependencies and installation"
	@echo "  clean       - Clean generated files and directories"
	@echo ""
	@echo "Quick start:"
	@echo "  make setup && make example"

# Install the package
install:
	@echo "📦 Installing qPKI..."
	pip install -r requirements.txt
	pip install .

# Install in development mode
dev-install: 
	@echo "🔧 Installing qPKI in development mode..."
	pip install -r requirements.txt
	pip install -e .

# Set up development environment
setup: dev-install
	@echo "✅ Development environment set up!"
	@echo "Try: make example"

# Run tests
test:
	@echo "🧪 Running tests..."
	cd tests && python test_hybrid_crypto.py

# Run the built-in demo
demo:
	@echo "🚀 Running qPKI demo..."
	python -m qpki demo

# Run the basic usage example
example:
	@echo "📚 Running basic usage example..."
	cd examples && python basic_usage.py

# Check installation and dependencies
check:
	@echo "🔍 Checking qPKI installation..."
	python -c "import qpki; print(f'qPKI version: {qpki.__version__}')"
	@echo "Checking CLI..."
	python -m qpki --version
	@echo "Checking algorithm support..."
	python -m qpki info

# Clean generated files
clean:
	@echo "🧹 Cleaning up..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ 2>/dev/null || true
	rm -rf keys/ certs/ 2>/dev/null || true
	@echo "✅ Cleanup complete!"

# Show project structure
structure:
	@echo "📁 qPKI Project Structure:"
	tree -I '__pycache__|*.pyc|*.egg-info|venv|.git' . || \
	find . -type f -name "*.py" | head -20
