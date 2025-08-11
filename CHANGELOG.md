# Changelog

All notable changes to the qPKI project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.3.0] - 2024-08-11

### Added
- **Enterprise-Grade Database Integration**
  - SQLAlchemy ORM with comprehensive data models
  - Support for SQLite (default), PostgreSQL, and MySQL
  - Automatic database migration and schema management
  - Comprehensive audit logging with RFC 3647 compliance
  - Certificate, CA, CRL, and notification history tracking
  - Database health checks and statistics

- **OCSP Implementation**
  - Online Certificate Status Protocol support
  - OCSP request/response data structures
  - Certificate status validation infrastructure
  - Extensible for full OCSP responder implementation

- **Advanced Email Notification System**
  - MailHog integration for development and testing
  - Comprehensive email templates with HTML/text versions
  - Configurable notification intervals (90, 60, 30, 14, 7, 1 days + expired)
  - Email retry logic with exponential backoff
  - Notification deduplication and history tracking
  - Professional email templates with urgency-based styling

- **API and Automation Features**
  - RESTful API endpoints for programmatic access
  - Certificate validation API endpoints
  - Algorithm information API
  - JSON-based configuration management
  - Automated testing infrastructure

- **Development and Deployment Tools**
  - Docker and Docker Compose configurations
  - Development setup scripts with MailHog integration
  - Comprehensive development environment setup
  - Hot reload and debugging support
  - Production-ready containerization

- **Advanced Certificate Features**
  - Multiple certificate types: Hybrid, Classical, Pure Post-Quantum
  - Enhanced certificate format conversion
  - X.509 compatibility layer for legacy systems
  - Certificate fingerprinting and validation
  - Advanced key usage and extension support

- **Security and Compliance Features**
  - Comprehensive audit event system
  - RFC 3647 compliant audit logging
  - Detailed security event tracking
  - Certificate lifecycle compliance monitoring
  - Professional security disclaimers and warnings

### Enhanced

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
- **Python Compatibility**
  - Fixed all `datetime.utcnow()` deprecation warnings
  - Updated to use timezone-aware `datetime.now(timezone.utc)` throughout
  - Future-proof datetime handling for Python 3.12+
  - Enhanced type hints and documentation

- **Web Interface Improvements**
  - Enhanced dashboard with real-time statistics
  - Improved certificate and CA management workflows
  - Better error handling and user feedback
  - Mobile-responsive design improvements
  - Professional notification management interface

- **Configuration Management**
  - JSON-based configuration files
  - Environment-specific settings
  - Database connection configuration
  - Email notification configuration
  - Development vs production settings

- **Testing and Quality Assurance**
  - MailHog integration for email testing
  - Comprehensive development scripts
  - Automated setup and deployment tools
  - Enhanced error handling and logging

### Technical Details

#### Database Architecture
- **Models**: Comprehensive SQLAlchemy models for CA, Certificate, CRL, Audit, Notifications
- **Relationships**: Proper foreign key relationships and cascading deletes
- **Migrations**: Automatic schema migration and version management
- **Performance**: Optimized queries with proper indexing
- **Backup**: Configuration for automated database backups

#### Email System Architecture
- **Templates**: Jinja2-based HTML and text email templates
- **Scheduling**: Configurable notification intervals with deduplication
- **Retry Logic**: Exponential backoff for failed email delivery
- **Testing**: MailHog integration for development email testing
- **History**: Complete notification history and tracking

#### API Design
- **RESTful**: Standard HTTP methods and status codes
- **JSON**: Consistent JSON request/response format
- **Validation**: Input validation and error handling
- **Documentation**: Clear API endpoint documentation
- **Security**: Ready for authentication integration

#### Development Workflow
- **Scripts**: Automated setup and development scripts
- **Docker**: Complete containerization with service dependencies
- **Testing**: MailHog integration for email testing workflows
- **Configuration**: Environment-based configuration management
- **Debugging**: Enhanced logging and error tracking

#### Security Enhancements
- **Audit Trail**: Complete RFC 3647 compliant audit logging
- **Event Tracking**: Comprehensive security event monitoring
- **Compliance**: Certificate lifecycle compliance tracking
- **Warnings**: Clear security warnings for educational use
- **Future-Ready**: Architecture ready for HSM and advanced security features

### Security Notes
- **Educational Purpose**: Designed for learning and research, not production use
- **Key Storage**: Private keys stored in JSON format for demonstration
- **Production Requirements**: Would need HSM integration, encrypted storage, access controls
- **Audit Compliance**: Includes RFC 3647 compliant audit logging framework
- **Future Security**: Architecture ready for production security enhancements

### Testing and Quality
- **Email Testing**: Complete MailHog integration for email notification testing
- **Database Testing**: SQLAlchemy model testing and migration verification
- **API Testing**: RESTful API endpoint validation
- **Cross-Platform**: Docker-based testing across different environments
- **Automated Setup**: Scripts for consistent development environment setup

### Development Experience
- **One-Command Setup**: `./scripts/dev-setup.sh` for complete environment setup
- **Integrated Testing**: MailHog automatically configured for email testing
- **Hot Reload**: Development server with automatic restart on code changes
- **Comprehensive Logging**: Detailed logging for debugging and monitoring
- **Docker Support**: Complete containerization with all dependencies

---

## Previous Versions

### [0.1.0] - Initial Release
- Basic hybrid PKI implementation with RSA and Dilithium
- Command-line interface for certificate management
- Certificate Authority functionality
- Educational documentation and examples
