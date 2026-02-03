# API Reference

Complete API documentation for Supply Chain Security library.

## Table of Contents

- [PackageSigner](#packagesigner)
- [PackageVerifier](#packageverifier)
- [PackageManifest](#packagemanifest)
- [VerificationResult](#verificationresult)
- [Enumerations](#enumerations)

---

## PackageSigner

The `PackageSigner` class handles cryptographic signing of packages.

### Constructor

```python
PackageSigner(
    private_key_path: Optional[Union[str, Path]] = None,
    private_key: Optional[bytes] = None,
    algorithm: str = SignatureAlgorithm.ED25519,
    hash_algorithm: str = HashAlgorithm.SHA256
)
```

**Parameters:**
- `private_key_path` (str | Path, optional): Path to PEM-encoded private key file
- `private_key` (bytes, optional): Raw private key bytes
- `algorithm` (str): Signature algorithm ("rsa" or "ed25519")
- `hash_algorithm` (str): Hash algorithm ("sha256", "sha512", or "blake2b")

If no key is provided, a new key pair is automatically generated.

### Methods

#### sign_package()

```python
sign_package(
    package_path: Union[str, Path],
    package_name: Optional[str] = None,
    version: Optional[str] = None,
    metadata: Optional[Dict] = None
) -> PackageManifest
```

Sign a package and generate an integrity manifest.

**Parameters:**
- `package_path` (str | Path): Path to package file or directory
- `package_name` (str, optional): Package name (derived from path if not provided)
- `version` (str, optional): Package version (default: "1.0.0")
- `metadata` (dict, optional): Additional metadata to include

**Returns:**
- `PackageManifest`: Signed manifest object

**Example:**
```python
signer = PackageSigner(private_key_path='private.pem')
manifest = signer.sign_package(
    package_path='myapp.tar.gz',
    package_name='myapp',
    version='1.0.0',
    metadata={'author': 'John Doe'}
)
```

#### export_public_key()

```python
export_public_key(path: Union[str, Path]) -> None
```

Export the public key to a PEM file.

**Parameters:**
- `path` (str | Path): Output path for public key file

**Example:**
```python
signer.export_public_key('public_key.pem')
```

#### export_private_key()

```python
export_private_key(
    path: Union[str, Path],
    password: Optional[bytes] = None
) -> None
```

Export the private key to a PEM file.

**Parameters:**
- `path` (str | Path): Output path for private key file
- `password` (bytes, optional): Password to encrypt the key

**Example:**
```python
signer.export_private_key('private_key.pem', password=b'my-password')
```

---

## PackageVerifier

The `PackageVerifier` class handles cryptographic verification of packages.

### Constructor

```python
PackageVerifier(
    public_key_path: Optional[Union[str, Path]] = None,
    public_key: Optional[bytes] = None,
    trusted_keys: Optional[List[bytes]] = None,
    strict_mode: bool = True,
    max_age_days: Optional[int] = None
)
```

**Parameters:**
- `public_key_path` (str | Path, optional): Path to PEM-encoded public key
- `public_key` (bytes, optional): Raw public key bytes
- `trusted_keys` (list[bytes], optional): List of trusted public keys
- `strict_mode` (bool): Enforce strict verification rules (default: True)
- `max_age_days` (int, optional): Maximum manifest age in days

At least one trusted public key must be provided.

### Methods

#### verify_package()

```python
verify_package(
    package_path: Union[str, Path],
    manifest_path: Optional[Union[str, Path]] = None,
    manifest: Optional[PackageManifest] = None
) -> VerificationResult
```

Verify package integrity against its manifest.

**Parameters:**
- `package_path` (str | Path): Path to package file or directory
- `manifest_path` (str | Path, optional): Path to manifest file
- `manifest` (PackageManifest, optional): Manifest object (if not loading from file)

**Returns:**
- `VerificationResult`: Result object with validation status

**Example:**
```python
verifier = PackageVerifier(
    public_key_path='public.pem',
    strict_mode=True,
    max_age_days=90
)

result = verifier.verify_package(
    package_path='myapp.tar.gz',
    manifest_path='myapp.tar.gz.manifest'
)

if result.is_valid:
    print(f"✓ Verified: {result.package_name} v{result.version}")
else:
    print(f"✗ Failed: {result.error}")
```

#### add_trusted_key()

```python
add_trusted_key(key_path: Union[str, Path]) -> None
```

Add a trusted public key.

**Parameters:**
- `key_path` (str | Path): Path to public key file

**Example:**
```python
verifier.add_trusted_key('another_public_key.pem')
```

#### batch_verify()

```python
batch_verify(packages: List[tuple]) -> Dict[str, VerificationResult]
```

Verify multiple packages efficiently.

**Parameters:**
- `packages` (list[tuple]): List of (package_path, manifest_path) tuples

**Returns:**
- `dict`: Mapping of package paths to verification results

**Example:**
```python
packages = [
    ('pkg1.tar.gz', 'pkg1.manifest'),
    ('pkg2.tar.gz', 'pkg2.manifest'),
]

results = verifier.batch_verify(packages)

for path, result in results.items():
    status = "✓" if result.is_valid else "✗"
    print(f"{status} {path}")
```

---

## PackageManifest

Represents a package integrity manifest with signature.

### Constructor

```python
PackageManifest(
    package_name: str,
    version: str,
    files: Dict[str, str],
    signature: str,
    algorithm: str,
    hash_algorithm: str,
    timestamp: str,
    metadata: Optional[Dict] = None
)
```

**Parameters:**
- `package_name` (str): Name of the package
- `version` (str): Package version
- `files` (dict): Mapping of file paths to their hashes
- `signature` (str): Base64-encoded signature
- `algorithm` (str): Signature algorithm used
- `hash_algorithm` (str): Hash algorithm used
- `timestamp` (str): ISO 8601 timestamp
- `metadata` (dict, optional): Additional metadata

### Methods

#### save()

```python
save(path: Union[str, Path]) -> None
```

Save manifest to a JSON file.

**Parameters:**
- `path` (str | Path): Output file path

**Example:**
```python
manifest.save('myapp.manifest')
```

#### load()

```python
@classmethod
load(cls, path: Union[str, Path]) -> 'PackageManifest'
```

Load manifest from a JSON file.

**Parameters:**
- `path` (str | Path): Manifest file path

**Returns:**
- `PackageManifest`: Loaded manifest object

**Example:**
```python
manifest = PackageManifest.load('myapp.manifest')
```

#### to_dict()

```python
to_dict() -> Dict
```

Convert manifest to dictionary.

**Returns:**
- `dict`: Dictionary representation of manifest

**Example:**
```python
data = manifest.to_dict()
print(data['package_name'])
```

### Attributes

- `package_name` (str): Package name
- `version` (str): Package version
- `files` (dict): File path to hash mapping
- `signature` (str): Digital signature
- `algorithm` (str): Signature algorithm
- `hash_algorithm` (str): Hash algorithm
- `timestamp` (str): Creation timestamp
- `metadata` (dict): Additional metadata

---

## VerificationResult

Result of package verification with detailed information.

### Constructor

```python
VerificationResult(
    is_valid: bool,
    package_name: str,
    version: str,
    error: Optional[str] = None,
    warnings: Optional[List[str]] = None,
    details: Optional[Dict] = None
)
```

**Parameters:**
- `is_valid` (bool): Whether verification passed
- `package_name` (str): Package name
- `version` (str): Package version
- `error` (str, optional): Error message if verification failed
- `warnings` (list[str], optional): Non-fatal warnings
- `details` (dict, optional): Additional verification details

### Attributes

- `is_valid` (bool): Verification status
- `package_name` (str): Package name
- `version` (str): Package version
- `error` (str | None): Error message
- `warnings` (list[str]): Warning messages
- `details` (dict): Additional details

### Methods

#### __str__()

Returns a formatted string representation of the result.

**Example:**
```python
result = verifier.verify_package(...)
print(result)  # Prints formatted verification result
```

---

## Enumerations

### SignatureAlgorithm

Supported signature algorithms.

```python
class SignatureAlgorithm:
    RSA = "rsa"        # RSA-4096 with PSS padding
    ED25519 = "ed25519"  # Ed25519 (recommended)
```

**Usage:**
```python
from supply_chain_security import SignatureAlgorithm

signer = PackageSigner(algorithm=SignatureAlgorithm.ED25519)
```

### HashAlgorithm

Supported hash algorithms.

```python
class HashAlgorithm:
    SHA256 = "sha256"    # SHA-256 (recommended)
    SHA512 = "sha512"    # SHA-512
    BLAKE2B = "blake2b"  # BLAKE2b
```

**Usage:**
```python
from supply_chain_security import HashAlgorithm

signer = PackageSigner(hash_algorithm=HashAlgorithm.SHA256)
```

---

## Complete Examples

### Basic Signing and Verification

```python
from supply_chain_security import (
    PackageSigner,
    PackageVerifier,
    SignatureAlgorithm,
    HashAlgorithm
)

# Create signer
signer = PackageSigner(
    algorithm=SignatureAlgorithm.ED25519,
    hash_algorithm=HashAlgorithm.SHA256
)

# Export keys
signer.export_private_key('private.pem')
signer.export_public_key('public.pem')

# Sign package
manifest = signer.sign_package(
    package_path='myapp-1.0.0.tar.gz',
    package_name='myapp',
    version='1.0.0'
)
manifest.save('myapp-1.0.0.manifest')

# Create verifier
verifier = PackageVerifier(
    public_key_path='public.pem',
    strict_mode=True,
    max_age_days=90
)

# Verify package
result = verifier.verify_package(
    package_path='myapp-1.0.0.tar.gz',
    manifest_path='myapp-1.0.0.manifest'
)

if result.is_valid:
    print(f"✓ Package verified: {result.package_name} v{result.version}")
else:
    print(f"✗ Verification failed: {result.error}")
```

### Advanced Usage with Multiple Keys

```python
from supply_chain_security import PackageVerifier

# Create verifier with multiple trusted keys
verifier = PackageVerifier(
    public_key_path='key1.pem',
    trusted_keys=[
        open('key2.pem', 'rb').read(),
        open('key3.pem', 'rb').read()
    ],
    strict_mode=True
)

# Add another trusted key dynamically
verifier.add_trusted_key('key4.pem')

# Verify will succeed if signed by any trusted key
result = verifier.verify_package('package.tar.gz')
```

### Error Handling

```python
from supply_chain_security import PackageVerifier

try:
    verifier = PackageVerifier(public_key_path='public.pem')
    result = verifier.verify_package('package.tar.gz')
    
    if not result.is_valid:
        # Handle verification failure
        if "Hash mismatch" in result.error:
            print("Package has been tampered with!")
        elif "signature" in result.error.lower():
            print("Invalid signature - wrong key or compromised package")
        else:
            print(f"Verification error: {result.error}")
    
    # Check for warnings even if valid
    if result.warnings:
        for warning in result.warnings:
            print(f"Warning: {warning}")

except FileNotFoundError as e:
    print(f"File not found: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

---

## Type Hints

All functions include comprehensive type hints for better IDE support:

```python
from typing import Optional, Union, Dict, List
from pathlib import Path

def sign_package(
    package_path: Union[str, Path],
    package_name: Optional[str] = None,
    version: Optional[str] = None,
    metadata: Optional[Dict] = None
) -> PackageManifest:
    ...
```

---

## Constants and Defaults

```python
# Default algorithms
DEFAULT_SIGNATURE_ALGORITHM = SignatureAlgorithm.ED25519
DEFAULT_HASH_ALGORITHM = HashAlgorithm.SHA256

# Default verification settings
DEFAULT_STRICT_MODE = True
DEFAULT_MAX_AGE_DAYS = None  # No limit

# Default version
DEFAULT_PACKAGE_VERSION = "1.0.0"
```
