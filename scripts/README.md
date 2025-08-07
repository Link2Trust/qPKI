# qPKI Scripts

This directory contains utility and test scripts for the qPKI system.

## Scripts Overview

### Test Scripts

#### `test_ecc.py`
Comprehensive test script for ECC (Elliptic Curve Cryptography) operations.

**Features:**
- Tests basic ECC operations (key generation, signing, verification)
- Tests hybrid ECC+Dilithium operations  
- Compares different ECC curves (P-256, P-384, P-521)
- Tests key serialization/deserialization
- Compares RSA vs ECC performance in hybrid mode

**Usage:**
```bash
python3 scripts/test_ecc.py
# or
./scripts/test_ecc.py
```

#### `test_hybrid_crypto.py` 
Unit test suite for hybrid cryptographic operations using unittest framework.

**Features:**
- Unit tests for `HybridCrypto`, `RSACrypto`, and `DilithiumCrypto` classes
- Tests key generation, signing, verification
- Tests serialization/deserialization of keys and signatures
- Tests key fingerprint generation
- Comprehensive coverage of edge cases

**Usage:**
```bash
python3 scripts/test_hybrid_crypto.py
# or
./scripts/test_hybrid_crypto.py
```

#### `test_cert_types.py`
Test script for certificate type detection functionality.

**Features:**
- Tests certificate type detection for Hybrid, RSA, ECC, and ML-DSA certificates
- Tests both new and legacy certificate formats
- Validates fallback detection mechanisms
- Tests with real certificate files if available
- Comprehensive assertion-based testing

**Usage:**
```bash
python3 scripts/test_cert_types.py
# or
./scripts/test_cert_types.py
```

#### `test_validity.py`
Test script for certificate validity/expiry calculation functionality.

**Features:**
- Tests days-until-expiry calculation with various time scenarios
- Validates expired certificate handling (negative days)
- Tests future expiration dates (positive days)
- Validates invalid date string handling
- Tests UI categorization logic for validity badges
- Comprehensive edge case coverage

**Usage:**
```bash
python3 scripts/test_validity.py
# or
./scripts/test_validity.py
```

### Utility Scripts

#### `analyze_certs.py`
Certificate analysis and statistics utility.

**Features:**
- Analyzes all certificates in the certificate directory
- Generates statistics on certificate types, algorithms, and expiration status
- Provides detailed breakdown of cryptographic parameters
- Identifies certificates approaching expiration
- Useful for certificate inventory and health monitoring

**Usage:**
```bash
# Analyze all certificates
python3 scripts/analyze_certs.py

# Analyze certificates in custom directory
python3 scripts/analyze_certs.py --cert-dir /path/to/certificates

# Verbose output with detailed certificate information
python3 scripts/analyze_certs.py --verbose
```

#### `check_expiration.py`
Automated certificate expiration checker and email notification sender.

**Features:**
- Checks all certificates for upcoming expiration
- Sends email notifications at configurable intervals
- Supports dry-run mode for testing
- Integrates with qPKI email notification system
- Can be scheduled via cron for automated monitoring

**Usage:**
```bash
# Dry run (test mode)
python3 scripts/check_expiration.py --dry-run

# Send actual notifications
python3 scripts/check_expiration.py

# Custom certificate directory
python3 scripts/check_expiration.py --cert-dir /path/to/certificates

# Verbose output
python3 scripts/check_expiration.py --verbose
```

**Cron Schedule Examples:**
```bash
# Check daily at 9 AM
0 9 * * * cd /path/to/qPKI && python3 scripts/check_expiration.py

# Check twice daily (9 AM and 6 PM)  
0 9,18 * * * cd /path/to/qPKI && python3 scripts/check_expiration.py

# Weekly check on Mondays at 8 AM
0 8 * * 1 cd /path/to/qPKI && python3 scripts/check_expiration.py
```

## Running Tests

### Run Individual Test Scripts
```bash
# ECC functionality tests
python3 scripts/test_ecc.py

# Hybrid crypto unit tests
python3 scripts/test_hybrid_crypto.py
```

### Run All Tests
```bash
# Run both test scripts
python3 scripts/test_ecc.py && python3 scripts/test_hybrid_crypto.py
```

## Script Requirements

All scripts require:
- Python 3.8+
- qPKI dependencies (cryptography, pqcrypto-dilithium, etc.)
- Access to the qPKI source code (`src/` directory)

For email notification scripts:
- Valid email configuration in `email_config.json`
- SMTP server access
- Jinja2 for email templating

## Adding New Scripts

When adding new scripts to this directory:

1. Make them executable: `chmod +x script_name.py`
2. Include proper shebang: `#!/usr/bin/env python3`
3. Add appropriate path setup for qPKI modules:
   ```python
   import sys
   import os
   sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
   ```
4. Include comprehensive docstrings and error handling
5. Update this README with script documentation

## Security Notes

- Test scripts are safe to run and do not modify production data
- `check_expiration.py` only reads certificate files and sends notifications
- All scripts respect the qPKI configuration and security boundaries
- Scripts use the same cryptographic libraries as the main application
