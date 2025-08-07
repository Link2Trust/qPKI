# qPKI - Quantum-Safe Hybrid Public Key Infrastructure

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-educational-orange)

A **hybrid Public Key Infrastructure (PKI)** implementation that combines:
- **Classical cryptography**: RSA and ECC for traditional compatibility
- **Post-quantum cryptography**: Dilithium for quantum-resistant security
- **Modern web interface**: Flask-based UI for certificate management

This project is designed for **educational purposes** to demonstrate quantum-safe cryptographic transitions and hybrid certificate systems.

## 🔑 Key Features

- **Hybrid Certificate Authority (CA)**: Issues certificates with both classical and Dilithium signatures
- **Flexible Classical Crypto**: Support for both RSA and ECC (P-256, P-384, P-521)
- **Web Interface**: Modern Flask-based UI for certificate management
- **Dual Key Generation**: Creates classical and post-quantum key pairs
- **Certificate Management**: Generate, validate, and manage hybrid certificates
- **Educational Focus**: Clear code structure with extensive documentation
- **CLI Interface**: Easy-to-use command-line tools for PKI operations

## 🏗️ Architecture

```
qPKI/
├── app.py                  # Flask web application
├── src/qpki/
│   ├── __init__.py
│   ├── cli.py              # Command-line interface
│   ├── ca/                 # Certificate Authority logic
│   │   ├── __init__.py
│   │   ├── hybrid_ca.py    # Main CA implementation
│   │   └── certificate.py  # Certificate handling
│   ├── crypto/             # Cryptographic operations
│   │   ├── __init__.py
│   │   ├── rsa_crypto.py   # RSA operations
│   │   ├── ecc_crypto.py   # ECC operations
│   │   ├── dilithium_crypto.py # Dilithium operations
│   │   └── hybrid_crypto.py    # Combined operations
│   ├── keys/               # Key management
│   │   ├── __init__.py
│   │   ├── key_manager.py  # Key generation and storage
│   │   └── key_store.py    # Secure key storage
│   └── utils/              # Utilities
│       ├── __init__.py
│       ├── config.py       # Configuration management
│       └── logger.py       # Logging utilities
├── templates/              # Web UI templates
│   ├── base.html          # Base template
│   ├── index.html         # Dashboard
│   ├── create_ca.html     # CA creation form
│   ├── list_cas.html      # CA listing
│   └── *.html             # Other web templates
├── tests/                  # Unit tests
├── examples/               # Usage examples
├── test_ecc.py            # ECC functionality tests
├── keys/                   # Generated keys (gitignored)
├── ca/                     # CA certificates (gitignored)
└── certificates/           # Certificates (gitignored)
```

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Link2Trust/qPKI.git
cd qPKI

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

### Basic Usage

```bash
# Initialize a new hybrid CA
qpki ca init --name "Hybrid-CA" --org "Link2Trust Educational"

# Generate a hybrid certificate
qpki cert generate --subject "CN=example.com" --ca-name "Hybrid-CA"

# List certificates
qpki cert list

# Validate a certificate
qpki cert validate --cert-file certs/example.com.pem
```

### Web Interface

For a user-friendly experience, start the web interface:

```bash
# Start the Flask web application
python3 app.py
```

Then visit `http://localhost:5000` to:
- Create Certificate Authorities with RSA or ECC + Dilithium
- Manage certificates through a modern web interface
- Download certificates in hybrid JSON format
- View detailed cryptographic information

See [README_WEB_UI.md](README_WEB_UI.md) for detailed web interface documentation.

## 🔬 Educational Components

This implementation demonstrates:

1. **Hybrid Signatures**: How to combine classical and post-quantum signatures
2. **Certificate Chaining**: Building trust chains with dual algorithms
3. **Key Management**: Secure storage and handling of multiple key types
4. **Transition Strategy**: How organizations can migrate to quantum-safe crypto
5. **Compatibility**: Maintaining backward compatibility during transitions

## 🛡️ Cryptographic Algorithms

### Classical: RSA
- **Key Size**: 2048/3072/4096 bits
- **Padding**: PSS with SHA-256
- **Use**: Backward compatibility, current standards compliance

### Classical: ECC (Elliptic Curve)
- **Curves**: P-256 (secp256r1), P-384 (secp384r1), P-521 (secp521r1)
- **Signature**: ECDSA with SHA-256
- **Use**: Modern efficiency, smaller key sizes, faster operations

### Post-Quantum: Dilithium
- **Variant**: Dilithium2/3/5 (CRYSTALS-Dilithium)
- **Security Level**: NIST Level 2/3/5
- **Use**: Quantum-resistant digital signatures

## ⚠️ Educational Disclaimer

This implementation is designed for **educational and research purposes only**. Do not use in production environments without thorough security review and testing.

## 📚 Learning Resources

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [CRYSTALS-Dilithium Specification](https://pq-crystals.org/dilithium/)
- [RFC 5280 - X.509 Certificates](https://tools.ietf.org/html/rfc5280)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

*Built with ❤️ for cryptographic education by Link2Trust*
