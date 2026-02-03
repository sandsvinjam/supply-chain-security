#!/usr/bin/env python3
"""
Command-line interface for supply chain security tools.

Provides commands for signing and verifying packages.
"""

import argparse
import sys
from pathlib import Path

from signer import PackageSigner, SignatureAlgorithm, HashAlgorithm
from verifier import PackageVerifier


def cmd_keygen(args):
    """Generate new key pair."""
    algorithm = args.algorithm
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    signer = PackageSigner(algorithm=algorithm)
    
    private_key_path = output_dir / "private_key.pem"
    public_key_path = output_dir / "public_key.pem"
    
    password = None
    if args.password:
        password = args.password.encode('utf-8')
    
    signer.export_private_key(private_key_path, password=password)
    signer.export_public_key(public_key_path)
    
    print(f"✓ Key pair generated successfully!")
    print(f"  Private key: {private_key_path}")
    print(f"  Public key: {public_key_path}")
    print()
    print("⚠️  Keep your private key secure and never commit it to version control!")


def cmd_sign(args):
    """Sign a package."""
    private_key_path = args.key
    package_path = Path(args.package)
    output_path = args.output or f"{package_path}.manifest"
    
    if not package_path.exists():
        print(f"✗ Error: Package not found: {package_path}", file=sys.stderr)
        sys.exit(1)
    
    if not Path(private_key_path).exists():
        print(f"✗ Error: Private key not found: {private_key_path}", file=sys.stderr)
        sys.exit(1)
    
    signer = PackageSigner(
        private_key_path=private_key_path,
        algorithm=args.algorithm,
        hash_algorithm=args.hash_algorithm
    )
    
    metadata = {}
    if args.name:
        package_name = args.name
    else:
        package_name = package_path.stem
    
    if args.version:
        version = args.version
    else:
        version = "1.0.0"
    
    if args.metadata:
        for item in args.metadata:
            key, value = item.split('=', 1)
            metadata[key] = value
    
    print(f"Signing package: {package_path}")
    manifest = signer.sign_package(
        package_path=package_path,
        package_name=package_name,
        version=version,
        metadata=metadata
    )
    
    manifest.save(output_path)
    print(f"✓ Package signed successfully!")
    print(f"  Manifest: {output_path}")
    print(f"  Algorithm: {args.algorithm}")
    print(f"  Hash: {args.hash_algorithm}")
    print(f"  Files: {len(manifest.files)}")


def cmd_verify(args):
    """Verify a package."""
    public_key_path = args.key
    package_path = Path(args.package)
    manifest_path = args.manifest or f"{package_path}.manifest"
    
    if not package_path.exists():
        print(f"✗ Error: Package not found: {package_path}", file=sys.stderr)
        sys.exit(1)
    
    if not Path(manifest_path).exists():
        print(f"✗ Error: Manifest not found: {manifest_path}", file=sys.stderr)
        sys.exit(1)
    
    if not Path(public_key_path).exists():
        print(f"✗ Error: Public key not found: {public_key_path}", file=sys.stderr)
        sys.exit(1)
    
    verifier = PackageVerifier(
        public_key_path=public_key_path,
        strict_mode=args.strict,
        max_age_days=args.max_age
    )
    
    print(f"Verifying package: {package_path}")
    result = verifier.verify_package(
        package_path=package_path,
        manifest_path=manifest_path
    )
    
    print()
    print(result)
    
    if result.warnings:
        print("⚠️  Warnings detected:")
        for warning in result.warnings:
            print(f"  - {warning}")
    
    if result.details:
        print("\nDetails:")
        for key, value in result.details.items():
            print(f"  {key}: {value}")
    
    sys.exit(0 if result.is_valid else 1)


def cmd_info(args):
    """Display manifest information."""
    from signer import PackageManifest
    
    manifest_path = Path(args.manifest)
    
    if not manifest_path.exists():
        print(f"✗ Error: Manifest not found: {manifest_path}", file=sys.stderr)
        sys.exit(1)
    
    manifest = PackageManifest.load(manifest_path)
    
    print("Manifest Information")
    print("=" * 60)
    print(f"Package Name: {manifest.package_name}")
    print(f"Version: {manifest.version}")
    print(f"Signature Algorithm: {manifest.algorithm}")
    print(f"Hash Algorithm: {manifest.hash_algorithm}")
    print(f"Timestamp: {manifest.timestamp}")
    print(f"Files: {len(manifest.files)}")
    
    if manifest.metadata:
        print("\nMetadata:")
        for key, value in manifest.metadata.items():
            print(f"  {key}: {value}")
    
    if args.verbose:
        print("\nFile Hashes:")
        for file_path, file_hash in manifest.files.items():
            print(f"  {file_path}")
            print(f"    {file_hash}")


def main():
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description="Supply Chain Security Tools - Cryptographic Package Integrity",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate a new key pair
  %(prog)s keygen --output ./keys
  
  # Sign a package
  %(prog)s sign --key ./keys/private_key.pem --package mypackage.tar.gz
  
  # Verify a package
  %(prog)s verify --key ./keys/public_key.pem --package mypackage.tar.gz
  
  # Display manifest info
  %(prog)s info --manifest mypackage.tar.gz.manifest
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # keygen command
    keygen_parser = subparsers.add_parser('keygen', help='Generate new key pair')
    keygen_parser.add_argument(
        '--output', '-o',
        default='./keys',
        help='Output directory for keys (default: ./keys)'
    )
    keygen_parser.add_argument(
        '--algorithm', '-a',
        choices=[SignatureAlgorithm.RSA, SignatureAlgorithm.ED25519],
        default=SignatureAlgorithm.ED25519,
        help='Signature algorithm (default: ed25519)'
    )
    keygen_parser.add_argument(
        '--password', '-p',
        help='Password to encrypt private key (optional)'
    )
    
    # sign command
    sign_parser = subparsers.add_parser('sign', help='Sign a package')
    sign_parser.add_argument(
        '--key', '-k',
        required=True,
        help='Path to private key file'
    )
    sign_parser.add_argument(
        '--package', '-p',
        required=True,
        help='Path to package file or directory'
    )
    sign_parser.add_argument(
        '--output', '-o',
        help='Output path for manifest (default: <package>.manifest)'
    )
    sign_parser.add_argument(
        '--name', '-n',
        help='Package name (default: derived from filename)'
    )
    sign_parser.add_argument(
        '--version', '-v',
        help='Package version (default: 1.0.0)'
    )
    sign_parser.add_argument(
        '--algorithm', '-a',
        choices=[SignatureAlgorithm.RSA, SignatureAlgorithm.ED25519],
        default=SignatureAlgorithm.ED25519,
        help='Signature algorithm (default: ed25519)'
    )
    sign_parser.add_argument(
        '--hash-algorithm',
        choices=[HashAlgorithm.SHA256, HashAlgorithm.SHA512, HashAlgorithm.BLAKE2B],
        default=HashAlgorithm.SHA256,
        help='Hash algorithm (default: sha256)'
    )
    sign_parser.add_argument(
        '--metadata', '-m',
        action='append',
        help='Additional metadata (key=value format, can be specified multiple times)'
    )
    
    # verify command
    verify_parser = subparsers.add_parser('verify', help='Verify a package')
    verify_parser.add_argument(
        '--key', '-k',
        required=True,
        help='Path to public key file'
    )
    verify_parser.add_argument(
        '--package', '-p',
        required=True,
        help='Path to package file or directory'
    )
    verify_parser.add_argument(
        '--manifest', '-m',
        help='Path to manifest file (default: <package>.manifest)'
    )
    verify_parser.add_argument(
        '--strict',
        action='store_true',
        default=True,
        help='Enable strict mode (default: enabled)'
    )
    verify_parser.add_argument(
        '--max-age',
        type=int,
        help='Maximum manifest age in days'
    )
    
    # info command
    info_parser = subparsers.add_parser('info', help='Display manifest information')
    info_parser.add_argument(
        '--manifest', '-m',
        required=True,
        help='Path to manifest file'
    )
    info_parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed file hashes'
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        if args.command == 'keygen':
            cmd_keygen(args)
        elif args.command == 'sign':
            cmd_sign(args)
        elif args.command == 'verify':
            cmd_verify(args)
        elif args.command == 'info':
            cmd_info(args)
    except Exception as e:
        print(f"✗ Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
