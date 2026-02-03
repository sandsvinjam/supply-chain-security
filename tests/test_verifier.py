"""
Tests for the package verification module.
"""

import os
import tempfile
import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from signer import PackageSigner, PackageManifest, SignatureAlgorithm
from verifier import PackageVerifier, VerificationResult


class TestPackageVerifier:
    """Test cases for PackageVerifier class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.signer = PackageSigner()
    
    def test_verify_valid_package(self):
        """Test verification of a valid signed package."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create and sign a package
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("Test content")
            
            manifest = self.signer.sign_package(test_file)
            
            # Export public key
            public_key_path = Path(tmpdir) / "public.pem"
            self.signer.export_public_key(public_key_path)
            
            # Verify the package
            verifier = PackageVerifier(public_key_path=public_key_path)
            result = verifier.verify_package(test_file, manifest=manifest)
            
            assert result.is_valid
            assert result.error is None
    
    def test_verify_tampered_package(self):
        """Test verification of a tampered package."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create and sign a package
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("Original content")
            
            manifest = self.signer.sign_package(test_file)
            
            # Export public key
            public_key_path = Path(tmpdir) / "public.pem"
            self.signer.export_public_key(public_key_path)
            
            # Tamper with the file
            test_file.write_text("Modified content")
            
            # Verify should fail
            verifier = PackageVerifier(public_key_path=public_key_path)
            result = verifier.verify_package(test_file, manifest=manifest)
            
            assert not result.is_valid
            assert "Hash mismatch" in result.error
    
    def test_verify_wrong_signature(self):
        """Test verification with wrong signature key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create and sign a package
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("Test content")
            
            manifest = self.signer.sign_package(test_file)
            
            # Create a different key pair
            different_signer = PackageSigner()
            public_key_path = Path(tmpdir) / "public.pem"
            different_signer.export_public_key(public_key_path)
            
            # Verification should fail
            verifier = PackageVerifier(public_key_path=public_key_path)
            result = verifier.verify_package(test_file, manifest=manifest)
            
            assert not result.is_valid
            assert "signature" in result.error.lower()
    
    def test_verify_missing_file(self):
        """Test verification when referenced file is missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create and sign a package
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("Test content")
            
            manifest = self.signer.sign_package(test_file)
            
            # Export public key
            public_key_path = Path(tmpdir) / "public.pem"
            self.signer.export_public_key(public_key_path)
            
            # Delete the file
            test_file.unlink()
            
            # Verification should fail
            verifier = PackageVerifier(public_key_path=public_key_path)
            result = verifier.verify_package(test_file, manifest=manifest)
            
            assert not result.is_valid
    
    def test_verify_directory(self):
        """Test verification of a directory package."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create package directory
            package_dir = Path(tmpdir) / "package"
            package_dir.mkdir()
            
            (package_dir / "file1.txt").write_text("Content 1")
            (package_dir / "file2.txt").write_text("Content 2")
            
            # Sign the directory
            manifest = self.signer.sign_package(package_dir)
            
            # Export public key
            public_key_path = Path(tmpdir) / "public.pem"
            self.signer.export_public_key(public_key_path)
            
            # Verify
            verifier = PackageVerifier(public_key_path=public_key_path)
            result = verifier.verify_package(package_dir, manifest=manifest)
            
            assert result.is_valid
            assert result.details["files_verified"] == 2
    
    def test_manifest_age_check(self):
        """Test verification with manifest age checking."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("Test content")
            
            # Create manifest with old timestamp
            manifest = self.signer.sign_package(test_file)
            old_timestamp = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
            manifest.timestamp = old_timestamp
            
            # Export public key
            public_key_path = Path(tmpdir) / "public.pem"
            self.signer.export_public_key(public_key_path)
            
            # Verify with max age limit
            verifier = PackageVerifier(
                public_key_path=public_key_path,
                max_age_days=30
            )
            result = verifier.verify_package(test_file, manifest=manifest)
            
            assert not result.is_valid
            assert "too old" in result.error.lower()
    
    def test_strict_mode(self):
        """Test strict mode verification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("Test content")
            
            manifest = self.signer.sign_package(test_file)
            
            # Set future timestamp
            future_timestamp = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
            manifest.timestamp = future_timestamp
            
            public_key_path = Path(tmpdir) / "public.pem"
            self.signer.export_public_key(public_key_path)
            
            # Strict mode should reject
            verifier = PackageVerifier(
                public_key_path=public_key_path,
                strict_mode=True
            )
            result = verifier.verify_package(test_file, manifest=manifest)
            
            assert not result.is_valid
    
    def test_multiple_trusted_keys(self):
        """Test verification with multiple trusted keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("Test content")
            
            # Sign with first key
            signer1 = PackageSigner()
            manifest = signer1.sign_package(test_file)
            
            # Export both keys
            key1_path = Path(tmpdir) / "key1.pem"
            key2_path = Path(tmpdir) / "key2.pem"
            
            signer1.export_public_key(key1_path)
            
            signer2 = PackageSigner()
            signer2.export_public_key(key2_path)
            
            # Verify with multiple keys
            verifier = PackageVerifier(public_key_path=key1_path)
            verifier.add_trusted_key(key2_path)
            
            result = verifier.verify_package(test_file, manifest=manifest)
            assert result.is_valid
    
    def test_batch_verification(self):
        """Test batch verification of multiple packages."""
        with tempfile.TemporaryDirectory() as tmpdir:
            packages = []
            
            # Create multiple packages
            for i in range(3):
                test_file = Path(tmpdir) / f"test{i}.txt"
                test_file.write_text(f"Content {i}")
                
                manifest = self.signer.sign_package(test_file)
                manifest_path = Path(tmpdir) / f"test{i}.manifest"
                manifest.save(manifest_path)
                
                packages.append((test_file, manifest_path))
            
            # Export public key
            public_key_path = Path(tmpdir) / "public.pem"
            self.signer.export_public_key(public_key_path)
            
            # Batch verify
            verifier = PackageVerifier(public_key_path=public_key_path)
            results = verifier.batch_verify(packages)
            
            assert len(results) == 3
            assert all(result.is_valid for result in results.values())


class TestVerificationResult:
    """Test cases for VerificationResult class."""
    
    def test_result_creation(self):
        """Test verification result creation."""
        result = VerificationResult(
            is_valid=True,
            package_name="test",
            version="1.0.0"
        )
        
        assert result.is_valid
        assert result.package_name == "test"
        assert result.version == "1.0.0"
    
    def test_result_with_error(self):
        """Test result with error message."""
        result = VerificationResult(
            is_valid=False,
            package_name="test",
            version="1.0.0",
            error="Verification failed"
        )
        
        assert not result.is_valid
        assert result.error == "Verification failed"
    
    def test_result_string_representation(self):
        """Test string representation of result."""
        result = VerificationResult(
            is_valid=True,
            package_name="test",
            version="1.0.0"
        )
        
        result_str = str(result)
        assert "VALID" in result_str
        assert "test" in result_str


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
