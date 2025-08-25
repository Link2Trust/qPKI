# qPKI Application Architecture Diagram

## Overview
The qPKI (Quantum-Safe Public Key Infrastructure) application is a comprehensive hybrid PKI system that combines classical cryptography (RSA/ECC) with post-quantum cryptography (Dilithium) to provide quantum-resistant certificate management. The system includes enterprise features such as database integration, role-based access control, multi-factor authentication, demo user isolation, deployment safety mechanisms, and comprehensive audit logging.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                               qPKI System v3.0                                  │
│              Production-Ready Quantum-Safe PKI Solution                         │
│           with Enterprise Features & Deployment Safety                          │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│                              User Interfaces                                    │
├───────────────────────────────┬─────────────────────────────────────────────────┤
│         Web Interface         │            Command Line Interface               │
│      (Flask Application)      │                 (CLI Tool)                      │
│                               │                                                 │
│ • Authentication & MFA        │ • Click-based CLI                              │
│ • Role-based Access Control   │ • Colorama for colored output                  │
│ • Bootstrap 5 Frontend        │ • Tabulate for formatted tables                │
│ • REST API Endpoints          │ • Interactive CA/Cert operations               │
│ • Dashboard & Management      │ • Deployment safety commands                   │
│ • Audit Log Viewer            │ • Configuration management                     │
└───────────────────────────────┴─────────────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    Security & Authentication Layer                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│ • Authentication Manager (RBAC: Admin/Operator/Auditor/Viewer)                 │
│ • Multi-Factor Authentication (TOTP + Backup Recovery Codes)                   │
│ • Session Management & Security                                                 │
│ • Demo User Isolation (Database Router)                                        │
│ • Password Policies & Account Security                                          │
│ • Audit Logging (RFC 3647 Compliant)                                          │
└─────────────────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                       Application Layer (app.py)                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│ • Flask Routes & Request Handling                                              │
│ • Certificate & CA Management Logic                                            │
│ • API Endpoints (/api/*, /health)                                              │
│ • Template Rendering & Form Processing                                         │
│ • Error Handling & Flash Messages                                              │
│ • Demo/Production Data Routing                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            Core Services                                        │
├─────────────────┬─────────────────┬─────────────────┬───────────────────────────┤
│   Hybrid CA     │  Database Layer │ Email Service   │  Deployment Safety        │
│   (PKI Core)    │   (SQLAlchemy)  │ (Notifications) │   (Backup & Config)       │
│                 │                 │                 │                           │
│ • CA Operations │ • Multi-DB      │ • Expiration    │ • Pre-deployment         │
│ • Cert Issuance │   Support       │   Monitoring    │   Safety Checks          │
│ • Cert Types:   │ • SQLite,       │ • SMTP Email    │ • Automatic Backups      │
│   - Hybrid      │   PostgreSQL,   │   Delivery      │ • Configuration          │
│   - Classical   │   MySQL         │ • Template      │   Protection              │
│   - Pure PQC    │ • Demo/Prod     │   Rendering     │ • Interactive             │
│ • CRL Mgmt      │   Isolation     │ • History       │   Deployment             │
│ • Validation    │ • User Mgmt     │   Tracking      │ • Rollback Support       │
└─────────────────┴─────────────────┴─────────────────┴───────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           Cryptographic Layer                                   │
├─────────────┬─────────────┬─────────────┬─────────────┬───────────────────────────┤
│Hybrid Crypto│  RSA Crypto │  ECC Crypto │ Dilithium   │     PQC Crypto            │
│(Flexible    │  (Classical)│ (Classical) │  (Post-Q)   │   (Pure Post-Q)           │
│ Hybrid)     │             │             │             │                           │
│             │             │             │             │                           │
│• Dual Sign  │• RSA Keys   │• ECC Keys   │• Dilithium  │• Pure Dilithium           │
│• RSA+Dil    │• PKCS#1     │• P-256/384  │  2/3/5      │• No Classical             │
│• ECC+Dil    │• OAEP       │• P-521      │• NIST PQC   │• Quantum-Safe Only       │
│• Key Mgmt   │• 2048/3072  │• ECDSA      │• Stateless  │• Future Migration Path    │
│• Validation │  /4096 bits │• SHA-256/   │• Pure       │• Research & Testing       │
│• Export     │• SHA-256    │  384/512    │  Python     │• Standards Compliance     │
└─────────────┴─────────────┴─────────────┴─────────────┴───────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           Utility Services                                      │
├─────────────────────────┬───────────────────────────┬───────────────────────────┤
│   Certificate Formats   │     Configuration Mgmt    │    Deployment Scripts     │
│   (Enhanced Formats)    │     (Template-Based)      │    (Safety & Automation)  │
│                         │                           │                           │
│ • X.509 Export (PEM,    │ • .env.example Template   │ • check_deployment.sh     │
│   DER, CRT, CER)        │ • deployment.conf.example │ • setup_production.sh     │
│ • Classical Compat      │ • Generic Configuration   │ • deploy_example.sh       │
│ • Hybrid → Standard     │ • Environment-Specific    │ • Backup Automation       │
│ • Format Detection      │ • Safe Config Updates     │ • Service Management      │
│ • Metadata Extraction   │ • Template Merging        │ • Safety Confirmations   │
└─────────────────────────┴───────────────────────────┴───────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              Data Layer                                         │
├──────────────┬──────────────┬──────────────┬──────────────┬────────────────────┤
│ Database     │ JSON Storage │Configuration │ Template     │ Deployment Data    │
│ (Multi-Type) │ (Hybrid PKI) │   System     │  System      │    (Safety)        │
│              │              │              │              │                    │
│• SQLAlchemy  │• Certificates│• .env files  │• Jinja2      │• Backup Archives   │
│  ORM Support │• CA Metadata │• JSON Config │  Templates   │• Configuration     │
│• SQLite      │• Public Keys │• YAML Config │• Email       │  History           │
│  (Default)   │• Private Keys│• INI Support │  Templates   │• Deployment Logs   │
│• PostgreSQL  │• CRLs        │• Env Vars    │• Web UI      │• Recovery Data     │
│  (Production)│• Audit Logs  │• Validation  │  Templates   │• Safety Metadata  │
│• MySQL       │• Hybrid      │• Defaults    │• Form        │• Rollback Info    │
│  Support     │  Structure   │• Overrides   │  Templates   │• Version Tracking │
│• Demo/Prod   │• JSON Schema │• Security    │• Error       │• Change Detection │
│  Isolation   │  Validation  │  Hardening   │  Templates   │• Backup Schedules │
└──────────────┴──────────────┴──────────────┴──────────────┴────────────────────┘
```

## Component Details

### 1. User Interfaces

#### Web Interface (Flask)
- **Port**: 9090 (default)
- **Framework**: Flask with Bootstrap 5 frontend
- **Features**:
  - Dashboard with system overview
  - CA creation and management
  - Certificate issuance and lifecycle
  - CRL generation and management
  - Email notification configuration
  - Certificate and CA listing/searching
  - Download capabilities (JSON, PEM, DER formats)

#### Command Line Interface
- **Tool**: Click-based CLI with colored output
- **Commands**:
  - `qpki ca` - CA operations
  - `qpki keys` - Key management
  - `qpki cert` - Certificate operations
- **Features**: Interactive prompts, tabulated output, verbose logging

### 2. Security & Authentication Layer

#### Authentication Manager (`AuthenticationManager`)
- **Purpose**: Comprehensive user management and access control
- **Features**:
  - Role-Based Access Control (RBAC) with 4 roles:
    - **Admin**: Full system access, user management
    - **Operator**: Certificate operations, CA management
    - **Auditor**: Read-only access plus audit logs
    - **Viewer**: Read-only certificate/CA viewing
  - Multi-Factor Authentication (MFA) with TOTP support
  - Backup recovery codes (10 single-use codes)
  - Password policies with complexity requirements
  - Account lockout protection and session management
  - Force password change capabilities

#### Demo User Isolation (`DemoRouter`)
- **Purpose**: Separate demo users from production data
- **Features**:
  - Database routing based on username
  - Demo users (`demo`, `admin-demo`) → demo database
  - Production users → production database
  - Complete data isolation for demonstrations
  - Seamless integration with authentication system

#### Session Security
- **Session Management**: Secure token-based sessions
- **Automatic Cleanup**: Expired session removal
- **Concurrent Session Control**: Multiple session handling
- **Security Headers**: CSRF protection, XSS prevention

### 3. Core Services

#### Hybrid Certificate Authority (`HybridCA`)
- **Purpose**: Central PKI authority management
- **Functions**:
  - Self-signed root CA creation
  - Subordinate CA management
  - Certificate issuance with hybrid signatures
  - Multiple certificate types:
    - **Hybrid**: RSA/ECC + Dilithium dual signatures
    - **Classical**: RSA or ECC only for compatibility
    - **Pure PQC**: Dilithium-only for research
  - Certificate validation and verification
  - Certificate revocation and CRL generation
  - Serial number management
  - Certificate lifecycle management

#### Database Layer (`DatabaseManager` + `DatabaseConfig`)
- **Purpose**: Enterprise-grade data persistence
- **Features**:
  - SQLAlchemy ORM abstraction
  - Multi-database support:
    - **SQLite**: Default/development
    - **PostgreSQL**: Production recommended
    - **MySQL**: Enterprise compatibility
  - Database migration system
  - Connection pooling and optimization
  - Backup and recovery support
  - Demo/production data isolation

#### Email Notification Service (`EmailNotificationService`)
- **Purpose**: Automated certificate lifecycle notifications
- **Features**:
  - Configurable notification intervals (90, 60, 30, 14, 7, 1 days)
  - HTML and plain text email templates
  - SMTP server integration with authentication
  - Notification history tracking in database
  - Duplicate notification prevention
  - Retry mechanisms with backoff
  - Test mode for development (MailHog integration)
  - Notification management interface

#### Deployment Safety System
- **Purpose**: Safe production deployments and upgrades
- **Features**:
  - Pre-deployment safety checks (`check_deployment.sh`)
  - Existing installation detection
  - Automatic backup creation before changes
  - Configuration preservation during updates
  - Interactive confirmation prompts
  - Rollback support and recovery procedures
  - Service management and health checks

### 3. Cryptographic Layer

#### Hybrid Cryptography (`HybridCrypto`)
- **Purpose**: Combines classical and post-quantum signatures
- **Features**:
  - Dual signing (RSA/ECC + Dilithium)
  - Hybrid key pair management
  - Signature verification with configurable requirements
  - Key serialization/deserialization

#### Classical Cryptography
- **RSA Crypto**: PKCS#1, OAEP, 2048/3072/4096-bit keys
- **ECC Crypto**: NIST curves (P-256, P-384, P-521), ECDSA signatures

#### Post-Quantum Cryptography
- **Dilithium**: NIST submission, variants 2/3/5, stateless signatures
- **Library**: pqcrypto (pure Python implementation)

### 4. Data Storage

#### File System Structure
```
qPKI/
├── ca/                     # Certificate Authority certificates
├── certificates/           # End entity certificates  
├── crl/                   # Certificate Revocation Lists
├── config/                # Configuration files
│   └── email_config.json  # Email notification settings
├── logs/                  # Application logs
└── notifications.db       # SQLite database for email tracking
```

#### Certificate Format
- **Primary**: JSON format (supports full hybrid structure)
- **Export**: PEM/DER formats (classical signature only for compatibility)
- **Fields**: Subject/issuer, public keys, signatures, validity, key usage, extensions

### 5. External Dependencies

#### Python Libraries
- **Flask**: Web application framework
- **cryptography**: Classical cryptography (RSA, ECC, X.509)
- **pqcrypto**: Post-quantum cryptography (Dilithium)
- **Click**: Command-line interface
- **Jinja2**: Template engine
- **SQLite3**: Notification tracking database

#### Frontend Dependencies
- **Bootstrap 5**: Responsive web design
- **Font Awesome**: Icons and visual elements
- **JavaScript**: Form interactions and AJAX calls

## Data Flow

### Certificate Issuance Flow
```
User Request → Web/CLI Interface → HybridCA.issue_certificate() →
KeyManager.generate_key_pair() → HybridCrypto.sign_data_hybrid() →
JSON Storage → Email Notification (if configured)
```

### Certificate Validation Flow
```
Certificate ID → HybridCA.validate_certificate() →
KeyManager.load_key_pair() → HybridCrypto.verify_hybrid_signature() →
Validation Result
```

### Email Notification Flow
```
Scheduled Check → EmailNotificationService.check_expiring_certificates() →
Template Rendering → SMTP Delivery → SQLite History Tracking
```

## Security Considerations

1. **Quantum Resistance**: Dilithium post-quantum signatures provide security against quantum computers
2. **Classical Security**: RSA/ECC signatures maintain current PKI compatibility
3. **Key Storage**: Private keys stored with optional password encryption
4. **Signature Verification**: Configurable dual-signature requirement
5. **Access Control**: Web interface session management
6. **Secure Communication**: HTTPS recommended for production deployment

## Deployment Architecture

### Development Mode
- Single Flask instance on localhost:9090
- File-based storage (JSON files)
- SQLite database for authentication and notifications
- Local SMTP server (MailHog) for testing
- Demo user isolation for safe testing
- Configuration template system

### Production Architecture

#### Automated Deployment Pipeline
```
Safety Check → Backup Creation → Configuration Update → 
Service Deployment → Health Verification → Rollback (if needed)
```

#### Production Components
- **Reverse Proxy**: Nginx with SSL/TLS termination
- **Application Server**: Gunicorn WSGI server with multiple workers
- **Database**: PostgreSQL with connection pooling
- **Caching**: Redis for session storage and rate limiting
- **Security**: Fail2ban, UFW firewall, SSL certificates
- **Monitoring**: System logs, health checks, audit trails
- **Backup**: Automated database and certificate backup system

#### Deployment Safety Features

**Pre-deployment Checks:**
- Existing installation detection
- Critical data identification (certificates, CAs, databases)
- Backup space verification
- Service dependency validation
- Configuration compatibility checks

**Safe Deployment Process:**
1. **Safety Assessment**: `./scripts/check_deployment.sh`
2. **Interactive Confirmation**: User approval for detected changes
3. **Automatic Backups**: Timestamped archives of all critical data
4. **Configuration Preservation**: Merge new options with existing settings
5. **Selective Updates**: Update application code, preserve user data
6. **Service Verification**: Health checks post-deployment
7. **Rollback Readiness**: Recovery procedures and rollback scripts

#### Production File Structure
```
/opt/qpki/
├── app/                    # Application code
│   ├── .env               # Production configuration
│   ├── app.py             # Main application
│   └── src/               # Source modules
├── data/                  # Certificate and CA data
│   ├── certificates/      # End entity certificates
│   ├── ca/               # Certificate authorities
│   ├── crl/              # Revocation lists
│   └── keys/             # Private keys (secured)
├── logs/                  # Application logs
├── backups/              # Automated backups
│   ├── app_20250825_143052/    # Application backups
│   ├── data_20250825_143100/   # Data backups
│   └── config_20250825_143055/ # Config backups
└── venv/                 # Python virtual environment
```

#### Security Architecture

**Network Security:**
- UFW firewall with restrictive rules
- Fail2ban for intrusion prevention
- SSL/TLS with Let's Encrypt certificates
- Rate limiting via nginx and Redis

**Application Security:**
- RBAC with 4 distinct user roles
- Multi-factor authentication (TOTP)
- Session security with automatic cleanup
- CSRF protection and secure headers
- SQL injection prevention via ORM
- XSS protection with CSP headers

**Data Security:**
- Demo/production data isolation
- Encrypted database connections
- Private key protection
- Audit logging for compliance
- Secure password hashing (bcrypt)

#### High Availability Recommendations
- **Load Balancing**: Multiple application instances
- **Database Clustering**: PostgreSQL master/slave setup
- **Shared Storage**: Network-attached storage for certificates
- **Service Redundancy**: Multiple nginx instances
- **Monitoring**: Prometheus/Grafana for system metrics
- **Alerting**: Email/SMS notifications for system issues

## Extensibility Points

1. **Cryptographic Algorithms**: Modular crypto layer supports additional algorithms
2. **Storage Backends**: Abstract storage interface allows database integration
3. **Authentication**: Pluggable authentication providers
4. **Notification Channels**: Extensible notification system (SMS, webhooks)
5. **Certificate Extensions**: Support for custom X.509 extensions
6. **Import/Export Formats**: Additional format converters

This architecture provides a solid foundation for quantum-safe PKI operations while maintaining compatibility with existing PKI infrastructure and standards.
