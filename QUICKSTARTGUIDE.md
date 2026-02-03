# Supply Chain Security - Quick Start Guide

Get up and running with Supply Chain Security in 5 minutes!

## Installation

```bash
cd supply-chain-security
pip install -r requirements.txt
pip install -e .
```

## 1. Generate Keys (30 seconds)

```bash
# Generate a new key pair
python src/cli.py keygen --output ./keys

# This creates:
# - keys/private_key.pem (keep secret!)
# - keys/public_key.pem (share with users)
```

## 2. Sign Your First Package (30 seconds)

```bash
# Create a test package
echo "Hello, secure world!" > test-package.txt

# Sign it
python src/cli.py sign \
    --key ./keys/private_key.pem \
    --package test-package.txt \
    --name my-first-package \
    --version 1.0.0

# This creates: test-package.txt.manifest
```

## 3. Verify the Package (30 seconds)

```bash
# Verify package integrity
python src/cli.py verify \
    --key ./keys/public_key.pem \
    --package test-package.txt \
    --manifest test-package.txt.manifest

# You should see: ✓ Package verified successfully
```

## 4. Test Tamper Detection (1 minute)

```bash
# Modify the package
echo "Tampered content" > test-package.txt

# Try to verify again
python src/cli.py verify \
    --key ./keys/public_key.pem \
    --package test-package.txt \
    --manifest test-package.txt.manifest

# You should see: ✗ Verification failed: Hash mismatch
```

## 5. Python API Usage (2 minutes)

Create `quick_test.py`:

```python
from src.signer import PackageSigner
from src.verifier import PackageVerifier

# Sign a package
signer = PackageSigner(private_key_path='./keys/private_key.pem')
manifest = signer.sign_package('test-package.txt')
manifest.save('test.manifest')

# Verify it
verifier = PackageVerifier(public_key_path='./keys/public_key.pem')
result = verifier.verify_package('test-package.txt', 'test.manifest')

print(f"Valid: {result.is_valid}")
print(f"Package: {result.package_name} v{result.version}")
```

Run it:

```bash
python quick_test.py
```

## Next Steps

- Read the [User Guide](docs/user-guide.md) for comprehensive documentation
- Check [examples/usage_examples.py](examples/usage_examples.py) for more examples
- Review [SECURITY.md](SECURITY.md) for security best practices
- Explore the [API Reference](docs/api-reference.md)

## Common Commands

```bash
# Generate keys
python src/cli.py keygen --output ./keys

# Sign a package
python src/cli.py sign --key ./keys/private_key.pem --package myapp.tar.gz

# Verify a package
python src/cli.py verify --key ./keys/public_key.pem --package myapp.tar.gz

# Show manifest info
python src/cli.py info --manifest myapp.tar.gz.manifest

# Run tests
pytest tests/

# Run examples
python examples/usage_examples.py
```

## Troubleshooting

**"No module named 'cryptography'"**
```bash
pip install cryptography
```

**"Permission denied: private_key.pem"**
```bash
chmod 600 keys/private_key.pem
```

**"Verification failed: Invalid signature"**
- Ensure you're using the matching public key
- Check that the package hasn't been modified

## Repository Structure

```
supply-chain-security/
├── src/                    # Source code
│   ├── signer.py          # Package signing
│   ├── verifier.py        # Package verification
│   └── cli.py             # Command-line interface
├── tests/                  # Test suite
├── examples/               # Usage examples
├── docs/                   # Documentation
├── .github/workflows/      # CI/CD pipelines
└── README.md              # Project overview
```

## Help & Support

- **Documentation**: Check the `docs/` directory
- **Examples**: See `examples/usage_examples.py`
- **Issues**: Open an issue on GitHub
- **Security**: Report to security@example.com

---

**Congratulations!** You've successfully set up Supply Chain Security. 🎉

For production use, make sure to:
- ✓ Store private keys securely
- ✓ Use strong passwords for key encryption
- ✓ Enable strict mode in verification
- ✓ Set appropriate manifest age limits
- ✓ Integrate into your CI/CD pipeline
