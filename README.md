# Supply Chain Security Through Cryptographic Package Integrity

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-cryptographic-green.svg)](https://github.com/yourusername/supply-chain-security)

A comprehensive framework for ensuring software supply chain security through cryptographic verification of package integrity. This project provides tools and libraries to sign, verify, and audit software packages across the entire development and deployment pipeline.

## 🎯 Overview

Modern software development relies heavily on third-party dependencies, creating potential attack vectors in the supply chain. This project implements a cryptographic verification system that ensures:

- **Package Authenticity**: Verify that packages come from trusted sources
- **Integrity Protection**: Detect any tampering with package contents
- **Provenance Tracking**: Maintain a cryptographic audit trail
- **Automated Verification**: Integrate security checks into CI/CD pipelines

## ✨ Features

- **Multi-Algorithm Support**: SHA-256, SHA-512, BLAKE2b hash algorithms
- **Digital Signatures**: RSA and Ed25519 signature schemes
- **Manifest Generation**: Automatic creation of signed package manifests
- **Verification API**: Simple API for package verification
- **CLI Tools**: Command-line utilities for signing and verification
- **Plugin Architecture**: Extensible for custom verification logic
- **CI/CD Integration**: GitHub Actions, GitLab CI, Jenkins support
- **Compliance Reporting**: Generate audit reports for security compliance

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/supply-chain-security.git
cd supply-chain-security

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

### Basic Usage

#### Signing a Package

```python
from supply_chain_security import PackageSigner

# Initialize signer with your private key
signer = PackageSigner(private_key_path='keys/private.pem')

# Sign a package
manifest = signer.sign_package('my-package-1.0.0.tar.gz')
manifest.save('my-package-1.0.0.manifest')
```

#### Verifying a Package

```python
from supply_chain_security import PackageVerifier

# Initialize verifier with trusted public keys
verifier = PackageVerifier(public_key_path='keys/public.pem')

# Verify package integrity
result = verifier.verify_package(
    package_path='my-package-1.0.0.tar.gz',
    manifest_path='my-package-1.0.0.manifest'
)

if result.is_valid:
    print("✓ Package verified successfully")
else:
    print(f"✗ Verification failed: {result.error}")
```

## 📋 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Package Producer                        │
│  ┌────────────┐     ┌──────────────┐     ┌──────────────┐  │
│  │   Build    │ --> │ Sign Package │ --> │   Publish    │  │
│  └────────────┘     └──────────────┘     └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ Signed Package + Manifest
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Package Registry                          │
│              (with manifest storage)                         │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ Download
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     Package Consumer                         │
│  ┌────────────┐     ┌──────────────┐     ┌──────────────┐  │
│  │  Download  │ --> │   Verify     │ --> │   Install    │  │
│  └────────────┘     └──────────────┘     └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 🔧 Configuration

Create a `.supply-chain-security.yaml` file in your project root:

```yaml
# Hash algorithm (sha256, sha512, blake2b)
hash_algorithm: sha256

# Signature algorithm (rsa, ed25519)
signature_algorithm: ed25519

# Key storage
keys:
  private: ~/.supply-chain-security/private.pem
  public: ~/.supply-chain-security/public.pem

# Verification settings
verification:
  strict_mode: true
  check_timestamp: true
  max_age_days: 90

# Trusted publishers
trusted_publishers:
  - publisher_id: "org.example"
    public_key_fingerprint: "SHA256:abc123..."
```

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [User Guide](docs/user-guide.md)
- [API Reference](docs/api-reference.md)
- [Security Best Practices](docs/security-practices.md)
- [CI/CD Integration](docs/ci-cd-integration.md)
- [Contributing Guidelines](CONTRIBUTING.md)

## 🛠️ Development

### Setting Up Development Environment

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=supply_chain_security tests/

# Run specific test file
pytest tests/test_signer.py
```

### Code Quality

```bash
# Format code
black src/ tests/

# Lint code
flake8 src/ tests/
pylint src/

# Type checking
mypy src/
```

## 🔒 Security Considerations

This project implements several security best practices:

1. **Key Management**: Never commit private keys to version control
2. **Algorithm Selection**: Uses modern, secure cryptographic algorithms
3. **Time-based Validation**: Prevents replay attacks with timestamp verification
4. **Secure Defaults**: Strict verification mode enabled by default
5. **Audit Trail**: All verification attempts are logged for compliance

For detailed security information, see [SECURITY.md](SECURITY.md).

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details on:

- Code of Conduct
- Development workflow
- Pull request process
- Testing requirements

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by [Sigstore](https://www.sigstore.dev/) and [in-toto](https://in-toto.io/)
- Built with [cryptography](https://cryptography.io/) library
- Thanks to all [contributors](https://github.com/yourusername/supply-chain-security/graphs/contributors)

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/supply-chain-security/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/supply-chain-security/discussions)
- **Security**: See [SECURITY.md](SECURITY.md) for reporting vulnerabilities

## 🗺️ Roadmap

- [ ] Support for additional signature algorithms (ECDSA)
- [ ] Integration with hardware security modules (HSM)
- [ ] Transparency log implementation
- [ ] Web UI for package verification
- [ ] Plugin system for custom verifiers
- [ ] Support for container image signing
- [ ] Integration with SBOM (Software Bill of Materials)

---

**Made with ❤️ for supply chain security**
