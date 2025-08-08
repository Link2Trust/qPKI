# qPKI Architecture Documentation

This directory contains comprehensive architectural documentation for the qPKI (Quantum-Safe Public Key Infrastructure) system. The documentation includes visual diagrams, detailed component descriptions, and system design specifications.

## 📁 Contents

### Documentation Files
- **[architecture_diagram.md](./architecture_diagram.md)** - Detailed text-based architecture documentation with ASCII diagrams and comprehensive component descriptions

### Visual Architecture Diagrams
- **[qPKI - Basic System Architecture.png](./qPKI%20-%20Basic%20System%20Architecture.png)** - High-level overview of the qPKI system components and their relationships
- **[qPKI - Quantum-Safe Hybrid PKI System Architecture.png](./qPKI%20-%20Quantum-Safe%20Hybrid%20PKI%20System%20Architecture.png)** - Detailed view of the hybrid cryptographic architecture combining classical and post-quantum cryptography
- **[qPKI System - Component Architecture.png](./qPKI%20System%20-%20Component%20Architecture.png)** - Breakdown of individual system components and modules
- **[qPKI System - Deployment Architecture.png](./qPKI%20System%20-%20Deployment%20Architecture.png)** - Production and development deployment configurations
- **[qPKI System - Key Operational Flows.png](./qPKI%20System%20-%20Key%20Operational%20Flows.png)** - Process flows for key operations like certificate issuance and validation

## 🏗️ System Overview

The qPKI system is a revolutionary hybrid Public Key Infrastructure that combines:

- **Classical Cryptography** (RSA/ECC) for current compatibility
- **Post-Quantum Cryptography** (Dilithium) for quantum resistance
- **Dual Signature Approach** providing both current security and future-proofing

## 🔍 Key Architectural Components

### User Interfaces
- **Web Interface**: Flask-based application with Bootstrap 5 frontend
- **Command Line Interface**: Click-based CLI tool with colored output

### Core Services
- **Hybrid Certificate Authority**: Central PKI management and certificate issuance
- **Key Manager**: Cryptographic key lifecycle management
- **Email Notification Service**: Automated certificate expiration monitoring

### Cryptographic Layer
- **Hybrid Cryptography**: Dual signing with classical and post-quantum algorithms
- **RSA/ECC Support**: Traditional public key cryptography
- **Dilithium Implementation**: NIST post-quantum digital signatures

### Data Storage
- **JSON-based Certificate Storage**: Flexible schema supporting hybrid certificates
- **SQLite Database**: Email notification tracking and history
- **File System Organization**: Structured storage for CAs, certificates, and CRLs

## 🚀 Getting Started with Architecture

1. **Start with the Overview**: Read [architecture_diagram.md](./architecture_diagram.md) for a comprehensive understanding
2. **Visual Learning**: Review the PNG diagrams to visualize system relationships
3. **Deep Dive**: Focus on specific diagrams based on your area of interest:
   - **Developers**: Component Architecture and Key Operational Flows
   - **DevOps/SysAdmins**: Deployment Architecture
   - **Security Teams**: Quantum-Safe Hybrid PKI System Architecture

## 🔐 Security Architecture Highlights

- **Quantum Resistance**: Future-proof against quantum computer attacks
- **Backwards Compatibility**: Maintains interoperability with existing PKI systems
- **Hybrid Signatures**: Dual signing provides defense in depth
- **Modular Design**: Easy to update cryptographic algorithms as standards evolve

## 📊 Architecture Diagrams Guide

| Diagram | Purpose | Audience |
|---------|---------|----------|
| Basic System Architecture | High-level system overview | All stakeholders |
| Quantum-Safe Hybrid PKI | Cryptographic architecture details | Security architects, developers |
| Component Architecture | Module breakdown and relationships | Developers, maintainers |
| Deployment Architecture | Production and development setups | DevOps, system administrators |
| Key Operational Flows | Process workflows and data flows | Developers, business analysts |

## 🛠️ Development and Contribution

When modifying the qPKI system:

1. **Update Architecture Documentation**: Ensure changes are reflected in the architectural diagrams and documentation
2. **Maintain Visual Consistency**: Update relevant PNG diagrams when system components change
3. **Document Dependencies**: Include any new architectural dependencies or relationships
4. **Security Review**: Consider quantum-safe implications of architectural changes

## 📚 Additional Resources

- **Main Project Documentation**: See the root project README.md
- **API Documentation**: Check the web interface and CLI documentation
- **Security Considerations**: Review the security architecture sections in the detailed documentation

---

**Note**: This architecture supports both current PKI requirements and prepares for the post-quantum cryptographic era. The hybrid approach ensures a smooth transition as quantum-safe standards mature and gain widespread adoption.
