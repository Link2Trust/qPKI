# Changelog

All notable changes to the qPKI project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **ECC Support**: Complete Elliptic Curve Cryptography implementation
  - Support for P-256 (secp256r1), P-384 (secp384r1), P-521 (secp521r1) curves
  - ECDSA signature operations with SHA-256
  - Full key lifecycle management (generation, serialization, deserialization)
  - Comprehensive test suite for all ECC operations

- **Flexible Hybrid Cryptography**: Enhanced hybrid system supporting both RSA and ECC
  - `FlexibleHybridCrypto` class supporting RSA+Dilithium or ECC+Dilithium combinations
  - Dynamic algorithm selection based on user preferences
  - Backward compatibility with existing RSA-only implementations

- **Modern Web User Interface**: Complete Flask-based web application
  - Professional Bootstrap 5 responsive design
  - Certificate Authority creation and management
  - Interactive forms with real-time cryptographic parameter selection
  - Dashboard with system overview and statistics
  - Download functionality for certificates in JSON format
  - Modern UX with quantum-themed styling and animations

- **Web UI Templates**: Comprehensive template system
  - `base.html`: Navigation and layout foundation
  - `index.html`: Dashboard with system overview
  - `create_ca.html`: CA creation form with algorithm selection
  - `list_cas.html`: CA management interface
  - `create_cert.html`: Certificate creation form (framework)
  - `list_certs.html`: Certificate listing interface
  - `error.html`: Professional error handling pages

- **Enhanced Documentation**:
  - `README_WEB_UI.md`: Comprehensive web interface documentation
  - Updated main README with ECC and web UI information
  - Detailed usage guides and examples
  - Architecture diagrams reflecting current structure

- **Testing and Validation**:
  - `test_ecc.py`: Comprehensive ECC testing suite
  - Cross-algorithm compatibility testing
  - Hybrid signature validation tests
  - Performance comparison between RSA and ECC

### Enhanced
- **Cryptographic Module Structure**: Improved organization and modularity
  - Separated ECC operations into dedicated module
  - Enhanced hybrid crypto system with algorithm flexibility
  - Better abstraction for adding new algorithms in the future

- **Dependencies**: Updated requirements to include Flask and web dependencies
  - Flask framework for web interface
  - Bootstrap 5 for modern UI styling
  - Font Awesome for professional icons

### Technical Details

#### ECC Implementation
- **Curves Supported**: 
  - secp256r1 (P-256): 256-bit keys, 128-bit security
  - secp384r1 (P-384): 384-bit keys, 192-bit security  
  - secp521r1 (P-521): 521-bit keys, 256-bit security
- **Operations**: Key generation, ECDSA signing/verification, PEM serialization
- **Integration**: Full hybrid support with Dilithium post-quantum signatures

#### Web Interface Features
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Real-time Validation**: Form validation with user-friendly error messages
- **Dynamic UI**: Algorithm-specific form fields shown/hidden based on selection
- **Professional Styling**: Quantum-themed gradients and modern icons
- **Security Conscious**: Warnings about key storage and production use

#### Architecture Improvements
- **Modular Design**: Clear separation of concerns between crypto, web, and CLI components
- **Extensible**: Easy to add new algorithms, certificate types, or UI features
- **Educational Focus**: Clear code structure with comprehensive documentation

### Security Notes
- Private keys are stored in JSON format for demonstration purposes
- Production deployments should use secure key storage (HSM, encrypted storage)
- Web interface includes appropriate security warnings and disclaimers

### Testing
- All ECC curves tested with key generation, signing, and verification
- Hybrid signatures tested with both RSA+Dilithium and ECC+Dilithium
- Cross-compatibility verified between different algorithm combinations
- Web interface manually tested for usability and error handling

---

## Previous Versions

### [0.1.0] - Initial Release
- Basic hybrid PKI implementation with RSA and Dilithium
- Command-line interface for certificate management
- Certificate Authority functionality
- Educational documentation and examples
