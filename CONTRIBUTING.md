# Contributing to qPKI

Thank you for your interest in contributing to the qPKI project! This document provides guidelines and information for contributors.

## 🎯 Project Goals

qPKI is an **educational project** designed to:
- Demonstrate hybrid post-quantum cryptography implementations
- Show how organizations can transition to quantum-safe cryptography
- Provide hands-on learning with both classical and post-quantum algorithms
- Illustrate modern PKI management through web interfaces

## 🚀 How to Contribute

### Reporting Issues

1. **Check existing issues** before creating a new one
2. **Use descriptive titles** that clearly summarize the problem
3. **Provide detailed information**:
   - Steps to reproduce the issue
   - Expected vs actual behavior
   - System information (OS, Python version)
   - Error messages or logs

### Suggesting Enhancements

1. **Check existing feature requests** to avoid duplicates
2. **Describe the enhancement** in detail:
   - What problem does it solve?
   - How would it work?
   - Why would it be useful for education/learning?

### Code Contributions

#### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/Link2Trust/qPKI.git
cd qPKI

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies and development tools
pip install -r requirements.txt
pip install -e .

# Run tests to verify setup
python3 test_ecc.py
```

#### Making Changes

1. **Fork the repository** on GitHub
2. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes** following the coding standards
4. **Test your changes** thoroughly
5. **Commit with clear messages**:
   ```bash
   git commit -m "Add: Brief description of what you added"
   git commit -m "Fix: Brief description of what you fixed"
   git commit -m "Update: Brief description of what you updated"
   ```

#### Pull Request Process

1. **Update documentation** if your changes affect user-facing features
2. **Add tests** for new functionality when applicable
3. **Run the test suite** to ensure nothing is broken
4. **Create a pull request** with:
   - Clear title describing the change
   - Detailed description of what was changed and why
   - References to any related issues

## 📋 Coding Standards

### Python Code Style

- **Follow PEP 8** style guidelines
- **Use type hints** where appropriate
- **Document functions and classes** with docstrings
- **Keep functions focused** and reasonably sized
- **Use meaningful variable names**

### Cryptographic Code

- **Security first**: Follow cryptographic best practices
- **Document security considerations** in comments
- **Add educational comments** explaining cryptographic concepts
- **Test thoroughly** with various inputs
- **Reference standards** (RFCs, NIST documents) where applicable

### Web Interface

- **Responsive design**: Ensure compatibility across devices
- **Accessibility**: Follow web accessibility guidelines
- **User feedback**: Provide clear error messages and success feedback
- **Security warnings**: Include appropriate disclaimers for educational use

## 🧪 Testing Guidelines

### Running Tests

```bash
# Run ECC cryptography tests
python3 test_ecc.py

# Run web application (manual testing)
python3 app.py
# Then visit http://localhost:9090
```

### Writing Tests

- **Test edge cases** and error conditions
- **Include both positive and negative test cases**
- **Test cryptographic operations** with known vectors when possible
- **Document test purposes** with clear comments

## 📚 Documentation

### Code Documentation

- **Docstrings**: Use clear, comprehensive docstrings for all public functions
- **Comments**: Explain complex cryptographic operations
- **Type hints**: Help users understand expected inputs/outputs

### User Documentation

- **Keep README files updated** with new features
- **Include usage examples** for new functionality
- **Educational content**: Explain cryptographic concepts when introducing new features

## 🌟 Areas for Contribution

### High Priority

- **OCSP responder integration**: Online Certificate Status Protocol support
- **Hardware Security Module (HSM)**: Integration with HSM devices
- **Additional post-quantum algorithms**: Implement other NIST candidates (SPHINCS+, etc.)
- **REST API**: Programmatic access to certificate operations
- **Multi-user authentication**: User management and role-based access

### Medium Priority

- **Certificate templates**: Pre-configured certificate types
- **Bulk operations**: Import/export multiple certificates
- **Automated certificate renewal**: Auto-renewal before expiration
- **Enhanced CLI**: More comprehensive command-line tools
- **Performance optimization**: Faster cryptographic operations
- **Advanced certificate validation**: Path validation and constraint checking

### Nice to Have

- **Additional ECC curves**: Support for more elliptic curves
- **Hardware security modules**: HSM integration
- **API extensions**: REST API for programmatic access
- **Performance optimizations**: Faster cryptographic operations

## ❓ Questions and Support

- **GitHub Issues**: For bug reports and feature requests
- **Discussions**: Use GitHub Discussions for questions and ideas
- **Educational Focus**: Remember this is primarily an educational project

## 📄 License

By contributing to qPKI, you agree that your contributions will be licensed under the MIT License.

## 🙏 Recognition

Contributors will be recognized in:
- The project README
- Release notes for significant contributions
- The project's contributor list

---

Thank you for helping make qPKI a valuable educational resource for the cryptographic community!
