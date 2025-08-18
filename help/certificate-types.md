# Certificate Types Guide

qPKI supports three distinct types of certificates, each designed for different security requirements and compatibility needs. This guide explains when and how to use each type.

## 🔍 Overview of Certificate Types

| Type | Classical Algorithms | Post-Quantum Algorithms | Use Case |
|------|---------------------|------------------------|----------|
| **Hybrid** | ✅ RSA/ECC | ✅ Dilithium | Future-proof, maximum security |
| **Classical** | ✅ RSA/ECC | ❌ None | Current compatibility, legacy systems |
| **PQC** | ❌ None | ✅ Dilithium | Post-quantum only, future systems |

---

## 🔄 Hybrid Certificates (Recommended)

**Best of both worlds**: Combines classical and post-quantum cryptography for maximum security and compatibility.

### 🎯 When to Use Hybrid Certificates
- **New deployments** where future-proofing is important
- **High-security environments** requiring quantum resistance
- **Systems that need both current and future compatibility**
- **Long-term certificates** (5+ years validity)

### ✅ Advantages
- **Quantum-resistant**: Protected against future quantum attacks
- **Current compatibility**: Works with existing systems via classical component
- **Migration path**: Smooth transition to post-quantum cryptography
- **Defense in depth**: Multiple cryptographic layers

### ❌ Disadvantages
- **Larger certificate size**: Contains both classical and PQC keys
- **Increased complexity**: More complex signature verification
- **Performance impact**: Slightly slower operations

### 🔧 Technical Details
```
Structure:
├── Classical Component (RSA-3072 or ECC-secp256r1)
├── Post-Quantum Component (Dilithium-2/3/5)
├── Dual Signatures (both algorithms sign the same data)
└── Hybrid Public Keys (both keys included)

File Formats:
- JSON: ✅ Full hybrid certificate with all data
- PEM/DER: ❌ Not supported (no standard format exists)
```

### 📋 Configuration Options
```yaml
Classical Algorithms:
- RSA: 2048, 3072, 4096 bits
- ECC: secp256r1, secp384r1, secp521r1

Post-Quantum Algorithms:
- Dilithium-2: Fast, smaller signatures
- Dilithium-3: Balanced security/performance (recommended)
- Dilithium-5: Maximum security, larger signatures
```

---

## 🏛️ Classical Certificates

**Traditional PKI**: Uses only classical algorithms (RSA/ECC) without post-quantum components.

### 🎯 When to Use Classical Certificates
- **Legacy system integration** that doesn't support new formats
- **Immediate compatibility** with existing infrastructure
- **Short-term certificates** (< 2 years) where quantum threat is minimal
- **Resource-constrained environments** where size/performance matters

### ✅ Advantages
- **Universal compatibility**: Works with all existing PKI systems
- **Smaller size**: Traditional certificate sizes
- **High performance**: Fast signature generation and verification
- **Standard formats**: Full PEM/DER/PKCS#12 support

### ❌ Disadvantages
- **No quantum resistance**: Vulnerable to future quantum attacks
- **Limited future-proofing**: Will need replacement when quantum computers arrive
- **Migration complexity**: Requires full replacement for quantum resistance

### 🔧 Technical Details
```
Structure:
├── Single Classical Algorithm (RSA or ECC)
├── Traditional X.509 Certificate Structure
├── Standard Extensions (Key Usage, Basic Constraints, etc.)
└── Classical Signature (RSA-SHA256 or ECDSA-SHA256)

File Formats:
- JSON: ✅ qPKI native format
- PEM (.crt): ✅ Standard X.509 PEM format
- DER (.cer): ✅ Standard X.509 DER format
- PKCS#12 (.p12): ✅ With private key export
```

### 📋 Configuration Options
```yaml
RSA Options:
- 2048 bits: Minimum security, fast
- 3072 bits: Recommended for most uses
- 4096 bits: High security, slower

ECC Options:
- secp256r1 (P-256): Fast, widely supported
- secp384r1 (P-384): Higher security
- secp521r1 (P-521): Maximum classical security
```

---

## 🔮 Post-Quantum Cryptography (PQC) Certificates

**Future-ready**: Uses only post-quantum algorithms without classical components.

### 🎯 When to Use PQC Certificates
- **Research environments** testing post-quantum cryptography
- **Future systems** designed specifically for post-quantum era
- **High-security environments** where classical crypto is considered compromised
- **Specialized applications** requiring pure post-quantum security

### ✅ Advantages
- **Quantum-resistant**: Completely immune to quantum attacks
- **Future-proof**: Ready for post-quantum era
- **Pure PQC**: No classical crypto dependencies
- **Research-friendly**: Perfect for PQC testing and validation

### ❌ Disadvantages
- **Limited compatibility**: Not supported by current PKI infrastructure
- **Large signatures**: Dilithium signatures are significantly larger
- **No classical fallback**: Incompatible with existing systems
- **Experimental**: Still evolving standard

### 🔧 Technical Details
```
Structure:
├── Dilithium Algorithm Only
├── Post-Quantum Public Key
├── Dilithium Signature
└── qPKI-specific Extensions

File Formats:
- JSON: ✅ qPKI native format only
- PEM/DER: ❌ Not supported (no standard exists yet)
```

### 📋 Configuration Options
```yaml
Dilithium Variants:
- Dilithium-2:
  * Security Level: ~AES-128
  * Signature Size: ~2.4KB
  * Speed: Fastest
  * Use Case: Performance-critical applications

- Dilithium-3:
  * Security Level: ~AES-192
  * Signature Size: ~3.3KB
  * Speed: Balanced
  * Use Case: Recommended for most applications

- Dilithium-5:
  * Security Level: ~AES-256
  * Signature Size: ~4.6KB
  * Speed: Slower
  * Use Case: Maximum security applications
```

---

## 🤔 Which Certificate Type Should You Choose?

### 🎯 Decision Matrix

| Requirement | Hybrid | Classical | PQC |
|-------------|--------|-----------|-----|
| **Current compatibility needed** | ✅ Yes | ✅ Yes | ❌ No |
| **Quantum resistance needed** | ✅ Yes | ❌ No | ✅ Yes |
| **Long-term use (5+ years)** | ✅ Best | ⚠️ Risky | ✅ Good |
| **Legacy system integration** | ⚠️ Partial | ✅ Full | ❌ None |
| **Certificate size matters** | ⚠️ Large | ✅ Small | ❌ Large |
| **Performance critical** | ⚠️ Slower | ✅ Fast | ❌ Slow |
| **Future-proofing** | ✅ Excellent | ❌ Poor | ✅ Excellent |

### 🎯 Recommendations by Use Case

#### **Web Servers & TLS**
- **Current**: Classical (RSA-3072 or ECC-secp256r1)
- **Recommended**: Hybrid (RSA-3072 + Dilithium-3)
- **Future**: Hybrid → PQC migration path

#### **Code Signing**
- **Current**: Classical (RSA-3072 for compatibility)
- **Recommended**: Hybrid (RSA-3072 + Dilithium-3)
- **Future**: PQC (Dilithium-3)

#### **Email Encryption (S/MIME)**
- **Current**: Classical (RSA-3072 or ECC-secp256r1)
- **Recommended**: Hybrid (for future-proofing)
- **Future**: PQC (when email clients support it)

#### **IoT/Embedded Devices**
- **Current**: Classical (ECC-secp256r1 for size)
- **Recommended**: Classical → Hybrid migration
- **Future**: Evaluate PQC when hardware supports it

#### **Enterprise CA**
- **Root CA**: Hybrid (RSA-4096 + Dilithium-5)
- **Intermediate CA**: Hybrid (RSA-3072 + Dilithium-3)
- **End Entity**: Hybrid or Classical based on needs

---

## 🔄 Certificate Migration Strategies

### 📋 Migration Path: Classical → Hybrid
1. **Create hybrid CA** alongside existing classical CA
2. **Issue hybrid certificates** for new systems
3. **Replace classical certificates** at renewal time
4. **Decommission classical CA** when all certificates migrated

### 📋 Migration Path: Hybrid → PQC
1. **Test PQC certificates** in development environment
2. **Upgrade systems** to support PQC-only certificates
3. **Issue PQC certificates** for quantum-ready systems
4. **Maintain hybrid certificates** for legacy compatibility

---

## 🔧 Creating Different Certificate Types

### Web Interface
1. **Navigate** to `Certificates` → `Create Certificate`
2. **Select Certificate Type**:
   - `Hybrid`: Choose classical algorithm + Dilithium variant
   - `Classical`: Choose RSA or ECC algorithm only
   - `PQC`: Choose Dilithium variant only
3. **Configure algorithm parameters** based on security requirements
4. **Set appropriate validity period** based on certificate type

### Command Line
```bash
# Create Hybrid Certificate
python3 scripts/create_certificate.py --type hybrid --classical rsa-3072 --pqc dilithium-3

# Create Classical Certificate  
python3 scripts/create_certificate.py --type classical --algorithm rsa-3072

# Create PQC Certificate
python3 scripts/create_certificate.py --type pqc --algorithm dilithium-3
```

---

## 📊 Performance Comparison

| Operation | Classical | Hybrid | PQC |
|-----------|-----------|--------|-----|
| **Key Generation** | Fast | Medium | Medium |
| **Signing** | Fast | Medium | Slow |
| **Verification** | Fast | Medium | Slow |
| **Certificate Size** | Small | Large | Medium |
| **Signature Size** | Small | Large | Large |

### 📋 Typical Sizes
```
Certificate Sizes:
- Classical (RSA-3072): ~1.2KB
- Classical (ECC-secp256r1): ~0.8KB  
- Hybrid (RSA+Dilithium-3): ~4.5KB
- PQC (Dilithium-3): ~3.8KB

Signature Sizes:
- RSA-3072: 384 bytes
- ECC-secp256r1: 64 bytes
- Dilithium-3: ~3.3KB
- Hybrid: ~3.7KB (both signatures)
```

---

## 🔍 Verifying Certificate Types

### Web Interface
1. **Navigate** to certificate details
2. **Check "Certificate Type"** field
3. **Review "Cryptographic Info"** section
4. **Examine "Public Keys"** to see which algorithms are present

### Command Line
```bash
# Verify certificate type
python3 scripts/verify_certificate.py --file certificate.json --show-type

# Check algorithm details
python3 scripts/cert_info.py --file certificate.json --verbose
```

---

## ❓ Frequently Asked Questions

### **Q: Can I convert between certificate types?**
A: No, certificate types are determined at creation time. You must create new certificates of the desired type.

### **Q: Do hybrid certificates work with existing web browsers?**
A: The classical component works with browsers, but full hybrid verification requires PQC-aware software.

### **Q: How do I know if my application supports PQC certificates?**
A: Test in a development environment. Most current applications only support classical certificates.

### **Q: Which Dilithium variant should I choose?**
A: Dilithium-3 offers the best balance of security and performance for most applications.

### **Q: Can I use different certificate types within the same CA?**
A: Yes, a single CA can issue certificates of all types, as long as the CA itself supports the required algorithms.

### **Q: Are PQC certificates compatible with standard PKI tools?**
A: Currently no, PQC certificates use qPKI-specific formats. Standard PKCS#10, X.509 PQC support is still evolving.

---

**Next Steps**: Learn about [cryptographic algorithms](./algorithms.md) or [certificate creation workflow](./certificate-workflow.md).
