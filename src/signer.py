"""
Package signing module for cryptographic verification.

This module provides functionality to sign software packages using
cryptographic signatures and generate integrity manifests.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ed25519
from cryptography.exceptions import InvalidSignature


class SignatureAlgorithm:
    """Supported signature algorithms."""
    RSA = "rsa"
    ED25519 = "ed25519"


class HashAlgorithm:
    """Supported hash algorithms."""
    SHA256 = "sha256"
    SHA512 = "sha512"
    BLAKE2B = "blake2b"


class PackageManifest:
    """Represents a package integrity manifest."""
    
    def __init__(
        self,
        package_name: str,
        version: str,
        files: Dict[str, str],
        signature: str,
        algorithm: str,
        hash_algorithm: str,
        timestamp: str,
        metadata: Optional[Dict] = None
    ):
        self.package_name = package_name
        self.version = version
        self.files = files
        self.signature = signature
        self.algorithm = algorithm
        self.hash_algorithm = hash_algorithm
        self.timestamp = timestamp
        self.metadata = metadata or {}
    
    def to_dict(self) -> Dict:
        """Convert manifest to dictionary."""
        return {
            "package_name": self.package_name,
            "version": self.version,
            "files": self.files,
            "signature": self.signature,
            "algorithm": self.algorithm,
            "hash_algorithm": self.hash_algorithm,
            "timestamp": self.timestamp,
            "metadata": self.metadata
        }
    
    def save(self, path: Union[str, Path]) -> None:
        """Save manifest to file."""
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
    
    @classmethod
    def load(cls, path: Union[str, Path]) -> 'PackageManifest':
        """Load manifest from file."""
        with open(path, 'r') as f:
            data = json.load(f)
        return cls(**data)


class PackageSigner:
    """Signs packages and generates integrity manifests."""
    
    def __init__(
        self,
        private_key_path: Optional[Union[str, Path]] = None,
        private_key: Optional[bytes] = None,
        algorithm: str = SignatureAlgorithm.ED25519,
        hash_algorithm: str = HashAlgorithm.SHA256
    ):
        """
        Initialize package signer.
        
        Args:
            private_key_path: Path to PEM-encoded private key file
            private_key: Raw private key bytes
            algorithm: Signature algorithm to use
            hash_algorithm: Hash algorithm for file integrity
        """
        self.algorithm = algorithm
        self.hash_algorithm = hash_algorithm
        
        if private_key_path:
            self.private_key = self._load_private_key(private_key_path)
        elif private_key:
            self.private_key = private_key
        else:
            # Generate new key pair if none provided
            self.private_key = self._generate_key_pair()
    
    def _load_private_key(self, path: Union[str, Path]):
        """Load private key from PEM file."""
        with open(path, 'rb') as f:
            key_data = f.read()
        
        if self.algorithm == SignatureAlgorithm.RSA:
            return serialization.load_pem_private_key(key_data, password=None)
        elif self.algorithm == SignatureAlgorithm.ED25519:
            return serialization.load_pem_private_key(key_data, password=None)
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
    
    def _generate_key_pair(self):
        """Generate new key pair."""
        if self.algorithm == SignatureAlgorithm.RSA:
            return rsa.generate_private_key(public_exponent=65537, key_size=4096)
        elif self.algorithm == SignatureAlgorithm.ED25519:
            return ed25519.Ed25519PrivateKey.generate()
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
    
    def _hash_file(self, file_path: Union[str, Path]) -> str:
        """Compute hash of a file."""
        if self.hash_algorithm == HashAlgorithm.SHA256:
            hasher = hashlib.sha256()
        elif self.hash_algorithm == HashAlgorithm.SHA512:
            hasher = hashlib.sha512()
        elif self.hash_algorithm == HashAlgorithm.BLAKE2B:
            hasher = hashlib.blake2b()
        else:
            raise ValueError(f"Unsupported hash algorithm: {self.hash_algorithm}")
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        
        return hasher.hexdigest()
    
    def _hash_directory(self, dir_path: Union[str, Path]) -> Dict[str, str]:
        """Compute hashes for all files in a directory."""
        dir_path = Path(dir_path)
        file_hashes = {}
        
        for file_path in sorted(dir_path.rglob('*')):
            if file_path.is_file():
                relative_path = file_path.relative_to(dir_path)
                file_hashes[str(relative_path)] = self._hash_file(file_path)
        
        return file_hashes
    
    def _sign_data(self, data: bytes) -> str:
        """Sign data and return base64-encoded signature."""
        import base64
        
        if self.algorithm == SignatureAlgorithm.RSA:
            signature = self.private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif self.algorithm == SignatureAlgorithm.ED25519:
            signature = self.private_key.sign(data)
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
        
        return base64.b64encode(signature).decode('utf-8')
    
    def sign_package(
        self,
        package_path: Union[str, Path],
        package_name: Optional[str] = None,
        version: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> PackageManifest:
        """
        Sign a package and generate integrity manifest.
        
        Args:
            package_path: Path to package file or directory
            package_name: Package name (derived from path if not provided)
            version: Package version
            metadata: Additional metadata to include in manifest
            
        Returns:
            PackageManifest object
        """
        package_path = Path(package_path)
        
        # Extract package info
        if package_name is None:
            package_name = package_path.stem
        if version is None:
            version = "1.0.0"
        
        # Compute file hashes
        if package_path.is_file():
            file_hashes = {package_path.name: self._hash_file(package_path)}
        else:
            file_hashes = self._hash_directory(package_path)
        
        # Create canonical representation for signing
        canonical_data = json.dumps({
            "package_name": package_name,
            "version": version,
            "files": file_hashes,
            "hash_algorithm": self.hash_algorithm
        }, sort_keys=True).encode('utf-8')
        
        # Sign the data
        signature = self._sign_data(canonical_data)
        
        # Create manifest
        manifest = PackageManifest(
            package_name=package_name,
            version=version,
            files=file_hashes,
            signature=signature,
            algorithm=self.algorithm,
            hash_algorithm=self.hash_algorithm,
            timestamp=datetime.now(timezone.utc).isoformat(),
            metadata=metadata
        )
        
        return manifest
    
    def export_public_key(self, path: Union[str, Path]) -> None:
        """Export public key to PEM file."""
        public_key = self.private_key.public_key()
        
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(path, 'wb') as f:
            f.write(pem)
    
    def export_private_key(self, path: Union[str, Path], password: Optional[bytes] = None) -> None:
        """Export private key to PEM file."""
        if password:
            encryption = serialization.BestAvailableEncryption(password)
        else:
            encryption = serialization.NoEncryption()
        
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        
        with open(path, 'wb') as f:
            f.write(pem)


if __name__ == "__main__":
    # Example usage
    signer = PackageSigner()
    
    # Export keys
    signer.export_public_key("public_key.pem")
    signer.export_private_key("private_key.pem")
    
    print("Keys generated successfully!")
