# Changelog

All notable changes to the qPKI project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Complete Certificate Management System**: Full certificate lifecycle implementation
  - Certificate creation, viewing, and management through web interface
  - Certificate type selection (Root CA, Subordinate CA, End-entity)
  - Certificate status tracking (Valid, Expired, Revoked) with visual indicators
  - Days-until-expiration monitoring with color-coded urgency levels
  - Certificate revocation with reason codes
  - Hierarchical CA structure supporting Root and Subordinate CAs

- **Email Notification System**: Automated certificate expiration monitoring
  - Configurable notification intervals (90, 60, 30, 14, 7, 1 days before expiry + day of expiry)
  - Professional HTML and plain text email templates with Jinja2 templating
  - SMTP integration supporting Gmail, Outlook, and custom email providers
  - Duplicate notification prevention with SQLite tracking database
  - Web-based notification configuration and management
  - Test email functionality and notification history
  - Manual certificate expiration checks
  - Automated script for cron-based scheduling

- **Certificate Revocation Lists (CRL)**: Complete CRL support
  - Certificate revocation with standardized reason codes
  - CRL generation and maintenance per Certificate Authority
  - CRL viewing interface with revoked certificate details
  - CRL download functionality for external use
  - Integration with certificate status checking

- **Enhanced Web User Interface**: Production-ready Flask application
  - Modern Bootstrap 5 responsive design with mobile support
  - Certificate Authority creation and management (Root + Subordinate CAs)
  - Complete certificate lifecycle management interface
  - Interactive forms with real-time validation and feedback
  - Dashboard with comprehensive statistics and system overview
  - Certificate and CA listing with status indicators
  - Email notification management interface
  - CRL management and viewing interfaces
  - Professional error handling and user feedback

- **ECC Support**: Complete Elliptic Curve Cryptography implementation
  - Support for P-256 (secp256r1), P-384 (secp384r1), P-521 (secp521r1) curves
  - ECDSA signature operations with SHA-256
  - Full key lifecycle management (generation, serialization, deserialization)
  - Comprehensive test suite for all ECC operations

- **Flexible Hybrid Cryptography**: Enhanced hybrid system supporting both RSA and ECC
  - `FlexibleHybridCrypto` class supporting RSA+Dilithium or ECC+Dilithium combinations
  - Dynamic algorithm selection based on user preferences
  - Backward compatibility with existing RSA-only implementations

- **Comprehensive Template System**: Complete web interface templates
  - `base.html`: Navigation and layout foundation with notification links
  - `index.html`: Dashboard with system overview and statistics
  - `create_ca.html`: CA creation form with algorithm selection
  - `list_cas.html`: CA management interface with status indicators
  - `view_ca.html`: Detailed CA information display
  - `create_cert.html`: Complete certificate creation form
  - `list_certs.html`: Certificate listing with status and expiration monitoring
  - `view_cert.html`: Detailed certificate view with revocation capability
  - `notifications.html`: Email notification management interface
  - `view_crl.html`: CRL viewing and management interface
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
