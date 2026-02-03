"""
Package verification module for cryptographic integrity checking.

This module provides functionality to verify signed packages against
their integrity manifests.
"""

import base64
import hashlib
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ed25519
from cryptography.exceptions import InvalidSignature

from .signer import PackageManifest, SignatureAlgorithm, HashAlgorithm


class VerificationResult:
    """Result of package verification."""
    
    def __init__(
        self,
        is_valid: bool,
        package_name: str,
        version: str,
        error: Optional[str] = None,
        warnings: Optional[List[str]] = None,
        details: Optional[Dict] = None
    ):
        self.is_valid = is_valid
        self.package_name = package_name
        self.version = version
        self.error = error
        self.warnings = warnings or []
        self.details = details or {}
    
    def __str__(self) -> str:
        status = "VALID" if self.is_valid else "INVALID"
        result = f"Verification Result: {status}\n"
        result += f"Package: {self.package_name} v{self.version}\n"
        
        if self.error:
            result += f"Error: {self.error}\n"
        
        if self.warnings:
            result += "Warnings:\n"
            for warning in self.warnings:
                result += f"  - {warning}\n"
        
        return result


class PackageVerifier:
    """Verifies package integrity using cryptographic signatures."""
    
    def __init__(
        self,
        public_key_path: Optional[Union[str, Path]] = None,
        public_key: Optional[bytes] = None,
        trusted_keys: Optional[List[bytes]] = None,
        strict_mode: bool = True,
        max_age_days: Optional[int] = None
    ):
        """
        Initialize package verifier.
        
        Args:
            public_key_path: Path to PEM-encoded public key file
            public_key: Raw public key bytes
            trusted_keys: List of trusted public keys
            strict_mode: Enforce strict verification rules
            max_age_days: Maximum age of manifest in days (None = no limit)
        """
        self.strict_mode = strict_mode
        self.max_age_days = max_age_days
        self.trusted_keys = []
        
        if public_key_path:
            self.trusted_keys.append(self._load_public_key(public_key_path))
        elif public_key:
            self.trusted_keys.append(public_key)
        
        if trusted_keys:
            self.trusted_keys.extend(trusted_keys)
        
        if not self.trusted_keys:
            raise ValueError("At least one trusted public key must be provided")
    
    def _load_public_key(self, path: Union[str, Path]):
        """Load public key from PEM file."""
        with open(path, 'rb') as f:
            key_data = f.read()
        
        return serialization.load_pem_public_key(key_data)
    
    def _hash_file(self, file_path: Union[str, Path], algorithm: str) -> str:
        """Compute hash of a file."""
        if algorithm == HashAlgorithm.SHA256:
            hasher = hashlib.sha256()
        elif algorithm == HashAlgorithm.SHA512:
            hasher = hashlib.sha512()
        elif algorithm == HashAlgorithm.BLAKE2B:
            hasher = hashlib.blake2b()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        
        return hasher.hexdigest()
    
    def _verify_signature(
        self,
        data: bytes,
        signature: str,
        algorithm: str,
        public_key
    ) -> bool:
        """Verify signature against data."""
        try:
            signature_bytes = base64.b64decode(signature)
            
            if algorithm == SignatureAlgorithm.RSA:
                public_key.verify(
                    signature_bytes,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            elif algorithm == SignatureAlgorithm.ED25519:
                public_key.verify(signature_bytes, data)
            else:
                return False
            
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False
    
    def _check_timestamp(self, timestamp: str) -> Optional[str]:
        """Check if manifest timestamp is within acceptable range."""
        try:
            manifest_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            current_time = datetime.now(timezone.utc)
            
            # Check if timestamp is in the future
            if manifest_time > current_time + timedelta(minutes=5):
                return "Manifest timestamp is in the future"
            
            # Check maximum age
            if self.max_age_days:
                age = current_time - manifest_time
                if age > timedelta(days=self.max_age_days):
                    return f"Manifest is too old ({age.days} days)"
            
            return None
        except Exception as e:
            return f"Invalid timestamp format: {str(e)}"
    
    def verify_package(
        self,
        package_path: Union[str, Path],
        manifest_path: Optional[Union[str, Path]] = None,
        manifest: Optional[PackageManifest] = None
    ) -> VerificationResult:
        """
        Verify package integrity against its manifest.
        
        Args:
            package_path: Path to package file or directory
            manifest_path: Path to manifest file (if not provided directly)
            manifest: PackageManifest object (if not loading from file)
            
        Returns:
            VerificationResult object
        """
        package_path = Path(package_path)
        warnings = []
        
        # Load manifest
        if manifest is None:
            if manifest_path is None:
                return VerificationResult(
                    is_valid=False,
                    package_name="unknown",
                    version="unknown",
                    error="No manifest provided"
                )
            manifest = PackageManifest.load(manifest_path)
        
        # Check timestamp
        if self.max_age_days or self.strict_mode:
            timestamp_error = self._check_timestamp(manifest.timestamp)
            if timestamp_error:
                if self.strict_mode:
                    return VerificationResult(
                        is_valid=False,
                        package_name=manifest.package_name,
                        version=manifest.version,
                        error=timestamp_error
                    )
                else:
                    warnings.append(timestamp_error)
        
        # Verify file hashes
        if package_path.is_file():
            expected_hash = manifest.files.get(package_path.name)
            if expected_hash is None:
                return VerificationResult(
                    is_valid=False,
                    package_name=manifest.package_name,
                    version=manifest.version,
                    error=f"File {package_path.name} not found in manifest"
                )
            
            actual_hash = self._hash_file(package_path, manifest.hash_algorithm)
            if actual_hash != expected_hash:
                return VerificationResult(
                    is_valid=False,
                    package_name=manifest.package_name,
                    version=manifest.version,
                    error=f"Hash mismatch for {package_path.name}"
                )
        else:
            # Verify directory contents
            for relative_path, expected_hash in manifest.files.items():
                file_path = package_path / relative_path
                if not file_path.exists():
                    return VerificationResult(
                        is_valid=False,
                        package_name=manifest.package_name,
                        version=manifest.version,
                        error=f"Missing file: {relative_path}"
                    )
                
                actual_hash = self._hash_file(file_path, manifest.hash_algorithm)
                if actual_hash != expected_hash:
                    return VerificationResult(
                        is_valid=False,
                        package_name=manifest.package_name,
                        version=manifest.version,
                        error=f"Hash mismatch for {relative_path}"
                    )
        
        # Verify signature with trusted keys
        canonical_data = json.dumps({
            "package_name": manifest.package_name,
            "version": manifest.version,
            "files": manifest.files,
            "hash_algorithm": manifest.hash_algorithm
        }, sort_keys=True).encode('utf-8')
        
        signature_valid = False
        for public_key in self.trusted_keys:
            if self._verify_signature(
                canonical_data,
                manifest.signature,
                manifest.algorithm,
                public_key
            ):
                signature_valid = True
                break
        
        if not signature_valid:
            return VerificationResult(
                is_valid=False,
                package_name=manifest.package_name,
                version=manifest.version,
                error="Invalid signature - not signed by trusted key"
            )
        
        # All checks passed
        return VerificationResult(
            is_valid=True,
            package_name=manifest.package_name,
            version=manifest.version,
            warnings=warnings,
            details={
                "algorithm": manifest.algorithm,
                "hash_algorithm": manifest.hash_algorithm,
                "timestamp": manifest.timestamp,
                "files_verified": len(manifest.files)
            }
        )
    
    def add_trusted_key(self, key_path: Union[str, Path]) -> None:
        """Add a trusted public key."""
        public_key = self._load_public_key(key_path)
        self.trusted_keys.append(public_key)
    
    def batch_verify(
        self,
        packages: List[tuple]
    ) -> Dict[str, VerificationResult]:
        """
        Verify multiple packages.
        
        Args:
            packages: List of (package_path, manifest_path) tuples
            
        Returns:
            Dictionary mapping package paths to verification results
        """
        results = {}
        
        for package_path, manifest_path in packages:
            result = self.verify_package(package_path, manifest_path)
            results[str(package_path)] = result
        
        return results


if __name__ == "__main__":
    # Example usage
    verifier = PackageVerifier(public_key_path="public_key.pem")
    
    result = verifier.verify_package(
        package_path="my-package.tar.gz",
        manifest_path="my-package.manifest"
    )
    
    print(result)
