"""
Tests for the package signing module.
"""

import os
import tempfile
import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from signer import PackageSigner, PackageManifest, SignatureAlgorithm, HashAlgorithm


class TestPackageSigner:
    """Test cases for PackageSigner class."""
    
    def test_key_generation(self):
        """Test automatic key generation."""
        signer = PackageSigner(algorithm=SignatureAlgorithm.ED25519)
        assert signer.private_key is not None
    
    def test_rsa_key_generation(self):
        """Test RSA key generation."""
        signer = PackageSigner(algorithm=SignatureAlgorithm.RSA)
        assert signer.private_key is not None
    
    def test_sign_single_file(self):
        """Test signing a single file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test file
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("Hello, World!")
            
            # Sign the file
            signer = PackageSigner()
            manifest = signer.sign_package(
                package_path=test_file,
                package_name="test-package",
                version="1.0.0"
            )
            
            assert manifest.package_name == "test-package"
            assert manifest.version == "1.0.0"
            assert "test.txt" in manifest.files
            assert manifest.signature is not None
    
    def test_sign_directory(self):
        """Test signing a directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test directory structure
            package_dir = Path(tmpdir) / "package"
            package_dir.mkdir()
            
            (package_dir / "file1.txt").write_text("Content 1")
            (package_dir / "file2.txt").write_text("Content 2")
            
            subdir = package_dir / "subdir"
            subdir.mkdir()
            (subdir / "file3.txt").write_text("Content 3")
            
            # Sign the directory
            signer = PackageSigner()
            manifest = signer.sign_package(package_path=package_dir)
            
            assert len(manifest.files) == 3
            assert "file1.txt" in manifest.files
            assert "file2.txt" in manifest.files
            assert str(Path("subdir") / "file3.txt") in manifest.files
    
    def test_manifest_save_load(self):
        """Test manifest serialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("Test content")
            
            signer = PackageSigner()
            manifest = signer.sign_package(test_file)
            
            # Save manifest
            manifest_path = Path(tmpdir) / "manifest.json"
            manifest.save(manifest_path)
            
            # Load manifest
            loaded_manifest = PackageManifest.load(manifest_path)
            
            assert loaded_manifest.package_name == manifest.package_name
            assert loaded_manifest.version == manifest.version
            assert loaded_manifest.signature == manifest.signature
            assert loaded_manifest.files == manifest.files
    
    def test_key_export(self):
        """Test key export functionality."""
        with tempfile.TemporaryDirectory() as tmpdir:
            signer = PackageSigner()
            
            private_key_path = Path(tmpdir) / "private.pem"
            public_key_path = Path(tmpdir) / "public.pem"
            
            signer.export_private_key(private_key_path)
            signer.export_public_key(public_key_path)
            
            assert private_key_path.exists()
            assert public_key_path.exists()
            
            # Verify we can load the exported key
            new_signer = PackageSigner(private_key_path=private_key_path)
            assert new_signer.private_key is not None
    
    def test_different_hash_algorithms(self):
        """Test different hash algorithms."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("Test content")
            
            for hash_algo in [HashAlgorithm.SHA256, HashAlgorithm.SHA512, HashAlgorithm.BLAKE2B]:
                signer = PackageSigner(hash_algorithm=hash_algo)
                manifest = signer.sign_package(test_file)
                
                assert manifest.hash_algorithm == hash_algo
                assert len(manifest.files["test.txt"]) > 0
    
    def test_metadata_inclusion(self):
        """Test including metadata in manifest."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("Test content")
            
            metadata = {
                "author": "Test Author",
                "license": "MIT",
                "description": "Test package"
            }
            
            signer = PackageSigner()
            manifest = signer.sign_package(
                test_file,
                metadata=metadata
            )
            
            assert manifest.metadata == metadata


class TestPackageManifest:
    """Test cases for PackageManifest class."""
    
    def test_manifest_creation(self):
        """Test manifest object creation."""
        manifest = PackageManifest(
            package_name="test",
            version="1.0.0",
            files={"file.txt": "abc123"},
            signature="signature_data",
            algorithm=SignatureAlgorithm.ED25519,
            hash_algorithm=HashAlgorithm.SHA256,
            timestamp="2024-01-01T00:00:00Z"
        )
        
        assert manifest.package_name == "test"
        assert manifest.version == "1.0.0"
    
    def test_manifest_to_dict(self):
        """Test manifest serialization to dictionary."""
        manifest = PackageManifest(
            package_name="test",
            version="1.0.0",
            files={"file.txt": "abc123"},
            signature="signature_data",
            algorithm=SignatureAlgorithm.ED25519,
            hash_algorithm=HashAlgorithm.SHA256,
            timestamp="2024-01-01T00:00:00Z"
        )
        
        data = manifest.to_dict()
        
        assert isinstance(data, dict)
        assert data["package_name"] == "test"
        assert "files" in data
        assert "signature" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
