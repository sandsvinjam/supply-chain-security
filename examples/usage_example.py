#!/usr/bin/env python3
"""
Example usage of the supply chain security library.

This script demonstrates the basic workflow of:
1. Generating keys
2. Signing packages
3. Verifying packages
"""

import sys
import tempfile
from pathlib import Path

# Add src to path for direct execution
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from signer import PackageSigner, SignatureAlgorithm, HashAlgorithm
from verifier import PackageVerifier


def example_basic_workflow():
    """Demonstrate basic signing and verification workflow."""
    print("=" * 60)
    print("Basic Workflow Example")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Step 1: Generate keys
        print("\n1. Generating key pair...")
        signer = PackageSigner(algorithm=SignatureAlgorithm.ED25519)
        
        private_key_path = tmpdir / "private_key.pem"
        public_key_path = tmpdir / "public_key.pem"
        
        signer.export_private_key(private_key_path)
        signer.export_public_key(public_key_path)
        print(f"   ✓ Private key: {private_key_path}")
        print(f"   ✓ Public key: {public_key_path}")
        
        # Step 2: Create a test package
        print("\n2. Creating test package...")
        package_dir = tmpdir / "my-package"
        package_dir.mkdir()
        
        (package_dir / "README.md").write_text("# My Package\n\nThis is a test package.")
        (package_dir / "main.py").write_text("def main():\n    print('Hello, World!')\n")
        print(f"   ✓ Package created: {package_dir}")
        
        # Step 3: Sign the package
        print("\n3. Signing package...")
        manifest = signer.sign_package(
            package_path=package_dir,
            package_name="my-package",
            version="1.0.0",
            metadata={
                "author": "Example Developer",
                "license": "MIT"
            }
        )
        
        manifest_path = tmpdir / "my-package.manifest"
        manifest.save(manifest_path)
        print(f"   ✓ Manifest created: {manifest_path}")
        print(f"   ✓ Signed {len(manifest.files)} files")
        
        # Step 4: Verify the package
        print("\n4. Verifying package...")
        verifier = PackageVerifier(
            public_key_path=public_key_path,
            strict_mode=True
        )
        
        result = verifier.verify_package(
            package_path=package_dir,
            manifest_path=manifest_path
        )
        
        if result.is_valid:
            print("   ✓ Package verification PASSED")
            print(f"   ✓ Verified: {result.package_name} v{result.version}")
        else:
            print(f"   ✗ Package verification FAILED: {result.error}")
        
        # Step 5: Demonstrate tampering detection
        print("\n5. Testing tampering detection...")
        (package_dir / "main.py").write_text("def main():\n    print('Tampered!')\n")
        
        result = verifier.verify_package(
            package_path=package_dir,
            manifest_path=manifest_path
        )
        
        if not result.is_valid:
            print(f"   ✓ Tampering detected: {result.error}")
        else:
            print("   ✗ Tampering not detected (unexpected)")


def example_multiple_algorithms():
    """Demonstrate different signature and hash algorithms."""
    print("\n" + "=" * 60)
    print("Multiple Algorithms Example")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        test_file = tmpdir / "test.txt"
        test_file.write_text("Test content for algorithm comparison")
        
        algorithms = [
            (SignatureAlgorithm.ED25519, HashAlgorithm.SHA256),
            (SignatureAlgorithm.ED25519, HashAlgorithm.SHA512),
            (SignatureAlgorithm.RSA, HashAlgorithm.SHA256),
        ]
        
        for sig_algo, hash_algo in algorithms:
            print(f"\n{sig_algo.upper()} + {hash_algo.upper()}:")
            
            signer = PackageSigner(
                algorithm=sig_algo,
                hash_algorithm=hash_algo
            )
            
            manifest = signer.sign_package(test_file)
            
            public_key_path = tmpdir / f"public_{sig_algo}.pem"
            signer.export_public_key(public_key_path)
            
            verifier = PackageVerifier(public_key_path=public_key_path)
            result = verifier.verify_package(test_file, manifest=manifest)
            
            status = "✓ VALID" if result.is_valid else "✗ INVALID"
            print(f"   {status}")
            print(f"   Signature length: {len(manifest.signature)} chars")
            print(f"   Hash length: {len(list(manifest.files.values())[0])} chars")


def example_batch_verification():
    """Demonstrate batch verification of multiple packages."""
    print("\n" + "=" * 60)
    print("Batch Verification Example")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Create multiple packages
        print("\nCreating and signing multiple packages...")
        signer = PackageSigner()
        packages = []
        
        for i in range(5):
            package_file = tmpdir / f"package-{i}.txt"
            package_file.write_text(f"Package {i} content")
            
            manifest = signer.sign_package(
                package_path=package_file,
                package_name=f"package-{i}",
                version=f"1.0.{i}"
            )
            
            manifest_path = tmpdir / f"package-{i}.manifest"
            manifest.save(manifest_path)
            
            packages.append((package_file, manifest_path))
            print(f"   ✓ Created package-{i}")
        
        # Batch verify
        print("\nBatch verifying packages...")
        public_key_path = tmpdir / "public.pem"
        signer.export_public_key(public_key_path)
        
        verifier = PackageVerifier(public_key_path=public_key_path)
        results = verifier.batch_verify(packages)
        
        print("\nResults:")
        for package_path, result in results.items():
            status = "✓" if result.is_valid else "✗"
            print(f"   {status} {Path(package_path).name}: {result.package_name}")


def example_ci_cd_integration():
    """Demonstrate CI/CD integration patterns."""
    print("\n" + "=" * 60)
    print("CI/CD Integration Example")
    print("=" * 60)
    
    print("\n1. Build Phase (sign artifacts):")
    print("""
    # In your CI/CD pipeline
    supply-chain-security sign \\
        --key $SIGNING_KEY_PATH \\
        --package ./dist/my-app-1.0.0.tar.gz \\
        --name my-app \\
        --version 1.0.0 \\
        --metadata author="CI Bot" \\
        --metadata build_id="$CI_BUILD_ID"
    """)
    
    print("\n2. Deployment Phase (verify artifacts):")
    print("""
    # Before deploying
    supply-chain-security verify \\
        --key $PUBLIC_KEY_PATH \\
        --package ./my-app-1.0.0.tar.gz \\
        --manifest ./my-app-1.0.0.tar.gz.manifest \\
        --strict \\
        --max-age 30
    
    # Only proceed if exit code is 0
    if [ $? -eq 0 ]; then
        echo "Package verified, proceeding with deployment"
        deploy_application
    else
        echo "Package verification failed, aborting"
        exit 1
    fi
    """)
    
    print("\n3. Python Integration:")
    print("""
    from supply_chain_security import PackageVerifier
    
    def safe_install(package_path, manifest_path, trusted_key):
        verifier = PackageVerifier(
            public_key_path=trusted_key,
            strict_mode=True,
            max_age_days=30
        )
        
        result = verifier.verify_package(package_path, manifest_path)
        
        if result.is_valid:
            # Proceed with installation
            subprocess.run(['pip', 'install', package_path])
            return True
        else:
            logging.error(f"Verification failed: {result.error}")
            return False
    """)


def main():
    """Run all examples."""
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║  Supply Chain Security - Example Usage Demonstrations  ║")
    print("╚" + "=" * 58 + "╝")
    
    try:
        example_basic_workflow()
        example_multiple_algorithms()
        example_batch_verification()
        example_ci_cd_integration()
        
        print("\n" + "=" * 60)
        print("All examples completed successfully!")
        print("=" * 60 + "\n")
        
    except Exception as e:
        print(f"\n✗ Error running examples: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
