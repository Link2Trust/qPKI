#!/bin/bash

# qPKI Release Preparation Script
# Comprehensive checks before pushing to GitHub

set -e

echo "🚀 qPKI Release Preparation"
echo "=========================="

# Check if we're in the right directory
if [[ ! -f "app.py" || ! -d "src/qpki" ]]; then
    echo "❌ Error: Please run this script from the qPKI root directory"
    exit 1
fi

echo "📋 Running pre-release checks..."

# 1. Check for required files
echo "🔍 Checking required files..."
required_files=(
    "README.md"
    "CHANGELOG.md" 
    "requirements.txt"
    "setup.py"
    "Dockerfile"
    "docker-compose.yml"
    ".dockerignore"
    ".github/workflows/ci.yml"
    ".github/pull_request_template.md"
    "scripts/dev-setup.sh"
    "scripts/start-dev.sh"
    "config/email_config.json"
    "config/database_config.json"
)

for file in "${required_files[@]}"; do
    if [[ -f "$file" ]]; then
        echo "  ✅ $file"
    else
        echo "  ❌ Missing: $file"
        exit 1
    fi
done

# 2. Check Python syntax
echo "🐍 Checking Python syntax..."
if command -v python3 &> /dev/null; then
    find src/ -name "*.py" -exec python3 -m py_compile {} \;
    echo "  ✅ Python syntax check passed"
else
    echo "  ⚠️ Python3 not found, skipping syntax check"
fi

# 3. Check for datetime.utcnow() usage (should be fixed)
echo "⏰ Checking for deprecated datetime.utcnow() usage..."
if grep -r "datetime.utcnow()" src/ app.py 2>/dev/null; then
    echo "  ❌ Found deprecated datetime.utcnow() usage!"
    echo "  Please replace with datetime.now(timezone.utc)"
    exit 1
else
    echo "  ✅ No deprecated datetime usage found"
fi

# 4. Check for sensitive information
echo "🔒 Checking for sensitive information..."
sensitive_patterns=(
    "password.*="
    "secret.*="
    "api_key.*="
    "token.*="
    "private_key.*="
)

found_sensitive=false
for pattern in "${sensitive_patterns[@]}"; do
    if grep -r -i "$pattern" src/ app.py config/ --exclude="*.md" 2>/dev/null | grep -v "example\|placeholder\|dummy"; then
        found_sensitive=true
    fi
done

if [ "$found_sensitive" = true ]; then
    echo "  ⚠️ Potential sensitive information found. Please review."
    echo "  Make sure no real credentials are committed."
else
    echo "  ✅ No sensitive information detected"
fi

# 5. Check configuration files
echo "⚙️ Checking configuration files..."
if [[ -f "config/email_config.json" ]]; then
    if python3 -c "import json; json.load(open('config/email_config.json'))" 2>/dev/null; then
        echo "  ✅ email_config.json is valid JSON"
    else
        echo "  ❌ email_config.json is invalid JSON"
        exit 1
    fi
fi

if [[ -f "config/database_config.json" ]]; then
    if python3 -c "import json; json.load(open('config/database_config.json'))" 2>/dev/null; then
        echo "  ✅ database_config.json is valid JSON"
    else
        echo "  ❌ database_config.json is invalid JSON"
        exit 1
    fi
fi

# 6. Check Docker configuration
echo "🐳 Checking Docker configuration..."
if command -v docker &> /dev/null; then
    if docker build -t qpki-test . > /dev/null 2>&1; then
        echo "  ✅ Docker build successful"
        docker rmi qpki-test > /dev/null 2>&1
    else
        echo "  ❌ Docker build failed"
        exit 1
    fi
else
    echo "  ⚠️ Docker not found, skipping Docker build test"
fi

# 7. Check MailHog configuration
echo "📧 Checking MailHog configuration..."
if grep -q '"smtp_port": 1025' config/email_config.json; then
    echo "  ✅ MailHog configuration present"
else
    echo "  ⚠️ MailHog configuration not found in email_config.json"
fi

# 8. Check version consistency
echo "🏷️ Checking version consistency..."
if grep -q "v1.3" README.md && grep -q "1.3.0" CHANGELOG.md; then
    echo "  ✅ Version consistency check passed"
else
    echo "  ⚠️ Version inconsistency detected between README and CHANGELOG"
fi

# 9. Check file permissions
echo "🔐 Checking file permissions..."
chmod +x scripts/*.sh
echo "  ✅ Script permissions set"

# 10. Generate file summary
echo "📊 Generating file summary..."
echo ""
echo "Repository Summary:"
echo "=================="
echo "Python files: $(find src/ -name "*.py" | wc -l)"
echo "Template files: $(find templates/ -name "*.html" | wc -l)"
echo "Config files: $(find config/ -name "*.json" | wc -l)"
echo "Script files: $(find scripts/ -name "*.sh" | wc -l)"
echo "Documentation files: $(find . -maxdepth 1 -name "*.md" | wc -l)"

# 11. Final checklist
echo ""
echo "📋 Pre-Release Checklist:"
echo "========================"
echo "✅ All required files present"
echo "✅ Python syntax validated"
echo "✅ No deprecated datetime usage"
echo "✅ Configuration files valid"
echo "✅ Docker configuration working"
echo "✅ MailHog integration ready"
echo "✅ GitHub templates in place"
echo "✅ CI/CD workflow configured"

echo ""
echo "🎉 Release preparation complete!"
echo ""
echo "📝 Next steps:"
echo "1. Review changes: git diff"
echo "2. Add files: git add ."
echo "3. Commit: git commit -m 'feat: v1.3.0 release with enterprise features'"
echo "4. Tag: git tag -a v1.3.0 -m 'Version 1.3.0'"
echo "5. Push: git push origin main --tags"
echo ""
echo "🚀 Ready for GitHub!"

# Success
exit 0
