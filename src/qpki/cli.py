#!/usr/bin/env python3
"""
qPKI Command Line Interface

This module provides a comprehensive CLI for managing the hybrid PKI system,
including CA operations, key management, and certificate operations.
"""

import click
import json
import sys
from pathlib import Path
from tabulate import tabulate
from colorama import init, Fore, Style

from .ca.hybrid_ca import HybridCA
from .keys.key_manager import KeyManager
from .crypto.dilithium_crypto import DilithiumCrypto

# Initialize colorama for cross-platform colored output
init(autoreset=True)


@click.group()
@click.version_option(version="0.1.0", prog_name="qpki")
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.pass_context
def main(ctx, verbose):
    """
    qPKI - Quantum-Safe Hybrid Public Key Infrastructure
    
    A hybrid PKI system combining RSA and Dilithium for quantum-resistant security.
    """
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    
    if verbose:
        click.echo(f"{Fore.CYAN}🔐 qPKI - Quantum-Safe Hybrid PKI v0.1.0")
        click.echo(f"{Style.DIM}Educational implementation for cryptographic learning")


@main.group()
def ca():
    """Certificate Authority operations."""
    pass


@main.group()  
def keys():
    """Key management operations."""
    pass


@main.group()
def cert():
    """Certificate operations."""
    pass


# === CA Commands ===

@ca.command('init')
@click.option('--name', required=True, help='CA name')
@click.option('--organization', '-o', required=True, help='Organization name')
@click.option('--country', '-c', default='US', help='Country code (default: US)')
@click.option('--rsa-size', default=2048, help='RSA key size in bits (default: 2048)')
@click.option('--dilithium-variant', default=2, type=click.Choice(['2', '3', '5']), 
              help='Dilithium variant (default: 2)')
@click.option('--validity-years', default=10, help='CA certificate validity in years (default: 10)')
def ca_init(name, organization, country, rsa_size, dilithium_variant, validity_years):
    """Initialize a new Certificate Authority."""
    try:
        click.echo(f"{Fore.YELLOW}🏛️  Initializing CA '{name}'...")
        
        ca = HybridCA(name)
        ca_key_id = ca.initialize_ca(
            organization=organization,
            country=country,
            rsa_key_size=rsa_size,
            dilithium_variant=int(dilithium_variant),
            validity_years=validity_years
        )
        
        click.echo(f"{Fore.GREEN}✅ CA '{name}' initialized successfully!")
        click.echo(f"{Fore.CYAN}📋 CA Key ID: {ca_key_id}")
        
    except Exception as e:
        click.echo(f"{Fore.RED}❌ Error initializing CA: {e}")
        sys.exit(1)


@ca.command('list-certs')
@click.option('--ca-name', required=True, help='CA name')
def ca_list_certs(ca_name):
    """List all certificates issued by the CA."""
    try:
        ca = HybridCA(ca_name)
        certificates = ca.list_certificates()
        
        if not certificates:
            click.echo(f"{Fore.YELLOW}📋 No certificates found for CA '{ca_name}'")
            return
        
        # Format for display
        headers = ["Cert ID", "Subject CN", "Status", "Issued", "Expires", "Key Usage"]
        rows = []
        
        for cert in certificates:
            subject_cn = cert['subject'].get('common_name', 'N/A')
            issued = cert['issued_at'][:19]  # Remove microseconds
            expires = cert['not_after'][:19]
            key_usage = ', '.join(cert.get('key_usage', []))
            
            rows.append([
                cert['cert_id'][:8] + '...',
                subject_cn,
                cert['status'],
                issued,
                expires,
                key_usage
            ])
        
        click.echo(f"{Fore.CYAN}📄 Certificates for CA '{ca_name}':")
        click.echo(tabulate(rows, headers=headers, tablefmt='grid'))
        
    except Exception as e:
        click.echo(f"{Fore.RED}❌ Error listing certificates: {e}")


# === Key Commands ===

@keys.command('generate')
@click.option('--name', required=True, help='Key pair name')
@click.option('--owner', required=True, help='Key owner/subject')
@click.option('--rsa-size', default=2048, help='RSA key size in bits (default: 2048)')
@click.option('--dilithium-variant', default=2, type=click.Choice(['2', '3', '5']),
              help='Dilithium variant (default: 2)')
@click.option('--validity-days', default=365, help='Key validity in days (default: 365)')
@click.option('--password', help='Password to encrypt private key')
def keys_generate(name, owner, rsa_size, dilithium_variant, validity_days, password):
    """Generate a new hybrid key pair."""
    try:
        click.echo(f"{Fore.YELLOW}🔑 Generating hybrid key pair '{name}'...")
        
        key_manager = KeyManager()
        key_id = key_manager.generate_key_pair(
            key_name=name,
            owner=owner,
            rsa_key_size=rsa_size,
            dilithium_variant=int(dilithium_variant),
            validity_days=validity_days,
            password=password
        )
        
        click.echo(f"{Fore.GREEN}✅ Key pair '{name}' generated successfully!")
        
    except Exception as e:
        click.echo(f"{Fore.RED}❌ Error generating keys: {e}")
        sys.exit(1)


@keys.command('list')
def keys_list():
    """List all stored key pairs."""
    try:
        key_manager = KeyManager()
        keys_list = key_manager.list_keys()
        
        if not keys_list:
            click.echo(f"{Fore.YELLOW}📋 No keys found")
            return
        
        headers = ["Key Name", "Owner", "Created", "Expires", "RSA Size", "Dilithium", "Fingerprint"]
        rows = []
        
        for key in keys_list:
            created = key['created_at'][:19]
            expires = key['expires_at'][:19]
            rsa_size = key['rsa_key_size']
            dilithium_var = f"Dilithium{key['dilithium_variant']}"
            fingerprint = key['fingerprint'][:24] + '...'
            
            rows.append([
                key['key_name'],
                key['owner'][:30] + ('...' if len(key['owner']) > 30 else ''),
                created,
                expires,
                f"{rsa_size}-bit",
                dilithium_var,
                fingerprint
            ])
        
        click.echo(f"{Fore.CYAN}🔑 Stored Key Pairs:")
        click.echo(tabulate(rows, headers=headers, tablefmt='grid'))
        
    except Exception as e:
        click.echo(f"{Fore.RED}❌ Error listing keys: {e}")


@keys.command('info')
@click.argument('key_name')
def keys_info(key_name):
    """Show detailed information about a key pair."""
    try:
        key_manager = KeyManager()
        keys_list = key_manager.list_keys()
        
        # Find the key
        key_info = None
        for key in keys_list:
            if key['key_name'] == key_name:
                key_info = key
                break
        
        if not key_info:
            click.echo(f"{Fore.RED}❌ Key '{key_name}' not found")
            sys.exit(1)
        
        # Display detailed information
        click.echo(f"{Fore.CYAN}🔑 Key Information: {key_name}")
        click.echo(f"{Style.DIM}{'='*50}")
        
        click.echo(f"Key ID: {key_info['key_id']}")
        click.echo(f"Owner: {key_info['owner']}")
        click.echo(f"Status: {key_info['status']}")
        click.echo(f"Created: {key_info['created_at']}")
        click.echo(f"Expires: {key_info['expires_at']}")
        click.echo(f"RSA Key Size: {key_info['rsa_key_size']} bits")
        click.echo(f"Dilithium Variant: {key_info['dilithium_variant']}")
        click.echo(f"Fingerprint: {key_info['fingerprint']}")
        
        # Algorithm details
        algo_info = key_info['algorithm_info']['hybrid_key_info']
        click.echo(f"\n{Fore.CYAN}Algorithm Details:")
        click.echo(f"Security Model: {algo_info['security_model']}")
        
        classical = algo_info['classical_algorithm']
        click.echo(f"\nClassical Algorithm (RSA):")
        click.echo(f"  Key Size: {classical['key_size']} bits")
        click.echo(f"  Hash: {classical['hash_algorithm']}")
        click.echo(f"  Padding: {classical['padding']}")
        
        pq = algo_info['post_quantum_algorithm']
        click.echo(f"\nPost-Quantum Algorithm (Dilithium):")
        click.echo(f"  Variant: {pq['algorithm']}")
        click.echo(f"  Security Level: {pq['security_level']}")
        click.echo(f"  Public Key Size: {pq['public_key_size']} bytes")
        click.echo(f"  Signature Size: {pq['signature_size']} bytes")
        
    except Exception as e:
        click.echo(f"{Fore.RED}❌ Error retrieving key info: {e}")


@keys.command('delete')
@click.argument('key_name')
@click.confirmation_option(prompt='Are you sure you want to delete this key pair?')
def keys_delete(key_name):
    """Delete a key pair."""
    try:
        key_manager = KeyManager()
        success = key_manager.delete_key(key_name)
        
        if success:
            click.echo(f"{Fore.GREEN}✅ Key pair '{key_name}' deleted successfully")
        else:
            click.echo(f"{Fore.RED}❌ Key pair '{key_name}' not found")
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"{Fore.RED}❌ Error deleting key: {e}")


# === Certificate Commands ===

@cert.command('generate')
@click.option('--subject', required=True, help='Certificate subject (e.g., "CN=example.com,O=MyOrg")')
@click.option('--ca-name', required=True, help='CA name for signing')
@click.option('--validity-days', default=365, help='Certificate validity in days (default: 365)')
@click.option('--key-usage', default='digital_signature,key_encipherment',
              help='Key usage (comma-separated, default: digital_signature,key_encipherment)')
def cert_generate(subject, ca_name, validity_days, key_usage):
    """Generate a new certificate signed by the CA."""
    try:
        # Parse subject string
        subject_dict = {}
        for part in subject.split(','):
            if '=' in part:
                key, value = part.strip().split('=', 1)
                if key.upper() == 'CN':
                    subject_dict['common_name'] = value
                elif key.upper() == 'O':
                    subject_dict['organization'] = value
                elif key.upper() == 'C':
                    subject_dict['country'] = value
        
        if 'common_name' not in subject_dict:
            click.echo(f"{Fore.RED}❌ Subject must include CN (Common Name)")
            sys.exit(1)
        
        # Parse key usage
        key_usage_list = [usage.strip() for usage in key_usage.split(',')]
        
        click.echo(f"{Fore.YELLOW}📄 Generating certificate for '{subject_dict['common_name']}'...")
        
        ca = HybridCA(ca_name)
        ca_key_name = f"CA-{ca_name}"
        
        cert_id = ca.issue_certificate(
            subject=subject_dict,
            ca_key_identifier=ca_key_name,
            validity_days=validity_days,
            key_usage=key_usage_list
        )
        
        click.echo(f"{Fore.GREEN}✅ Certificate generated successfully!")
        click.echo(f"{Fore.CYAN}📋 Certificate ID: {cert_id}")
        
    except Exception as e:
        click.echo(f"{Fore.RED}❌ Error generating certificate: {e}")
        sys.exit(1)


@cert.command('validate')
@click.argument('cert_id')
@click.option('--ca-name', help='CA name (auto-detected if not provided)')
def cert_validate(cert_id, ca_name):
    """Validate a certificate."""
    try:
        if not ca_name:
            click.echo(f"{Fore.YELLOW}🔍 Attempting to auto-detect CA...")
            # Simple auto-detection - look for CA directories
            cert_dirs = list(Path('certs').glob('*'))
            if cert_dirs:
                ca_name = cert_dirs[0].name
                click.echo(f"{Fore.CYAN}📋 Using CA: {ca_name}")
            else:
                click.echo(f"{Fore.RED}❌ No CA found. Please specify --ca-name")
                sys.exit(1)
        
        ca = HybridCA(ca_name)
        validation_result = ca.validate_certificate(cert_id)
        
        click.echo(f"{Fore.CYAN}🔍 Certificate Validation Result:")
        click.echo(f"{Style.DIM}{'='*40}")
        
        if validation_result['valid']:
            click.echo(f"{Fore.GREEN}✅ Certificate is VALID")
        else:
            click.echo(f"{Fore.RED}❌ Certificate is INVALID")
        
        if 'error' in validation_result:
            click.echo(f"Error: {validation_result['error']}")
        else:
            sig_result = validation_result['signature_verification']
            click.echo(f"RSA Signature: {'✅ Valid' if sig_result['rsa_valid'] else '❌ Invalid'}")
            click.echo(f"Dilithium Signature: {'✅ Valid' if sig_result['dilithium_valid'] else '❌ Invalid'}")
            click.echo(f"Time Valid: {'✅ Yes' if validation_result['time_valid'] else '❌ No'}")
            click.echo(f"Revoked: {'❌ Yes' if validation_result['revoked'] else '✅ No'}")
            click.echo(f"Valid From: {validation_result['not_before']}")
            click.echo(f"Valid Until: {validation_result['not_after']}")
        
    except Exception as e:
        click.echo(f"{Fore.RED}❌ Error validating certificate: {e}")


@cert.command('export')
@click.argument('cert_id')
@click.option('--ca-name', required=True, help='CA name')
@click.option('--format', type=click.Choice(['pem', 'der', 'json', 'bundle']), 
              default='bundle', help='Export format (default: bundle)')
@click.option('--output-dir', default='exported_certs', help='Output directory')
def cert_export(cert_id, ca_name, format, output_dir):
    """Export certificate in standard formats (PEM/DER) for compatibility."""
    try:
        from .utils.cert_formats import CertificateFormatConverter
        from pathlib import Path
        import json
        
        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Load the hybrid certificate
        ca = HybridCA(ca_name)
        cert = ca._load_certificate(cert_id)
        if not cert:
            click.echo(f"{Fore.RED}❌ Certificate {cert_id} not found")
            sys.exit(1)
        
        # Load certificate keys  
        cert_data_file = ca.cert_store_path / "issued" / f"{cert_id}.json"
        with open(cert_data_file, 'r') as f:
            cert_data = json.load(f)
        
        subject_key_id = cert_data.get('subject_key_id')
        if not subject_key_id:
            click.echo(f"{Fore.RED}❌ Subject key ID not found for certificate")
            sys.exit(1)
        
        # Load the RSA keys
        key_manager = KeyManager()
        hybrid_keys, metadata = key_manager.load_key_pair(subject_key_id)
        
        # Load CA keys for signing
        ca_key_name = f"CA-{ca_name}"
        ca_keys, ca_metadata = key_manager.load_key_pair(ca_key_name)
        
        # Convert certificate
        converter = CertificateFormatConverter()
        
        if format == 'bundle':
            # Export complete bundle
            bundle = converter.export_hybrid_certificate_bundle(
                cert, 
                hybrid_keys.rsa_private, 
                hybrid_keys.rsa_public,
                ca_keys.rsa_private,
                f"{cert.subject.get('common_name', 'certificate')}"
            )
            
            for filename, file_info in bundle.items():
                output_file = output_path / filename
                content = file_info['content']
                
                if filename.endswith('.json'):
                    with open(output_file, 'w') as f:
                        json.dump(content, f, indent=2)
                elif filename.endswith('.crt'):
                    with open(output_file, 'wb') as f:
                        f.write(content)
                else:
                    with open(output_file, 'w') as f:
                        f.write(content)
                
                click.echo(f"{Fore.GREEN}📄 Exported {filename}")
                click.echo(f"{Style.DIM}   {file_info['description']}")
                click.echo(f"{Style.DIM}   Security: {file_info['security']}")
            
        else:
            # Export single format
            x509_cert = converter.create_x509_certificate(
                cert, hybrid_keys.rsa_private, hybrid_keys.rsa_public, ca_keys.rsa_private
            )
            
            filename = f"{cert.subject.get('common_name', 'certificate')}.{format}"
            output_file = output_path / filename
            
            if format == 'pem':
                content = converter.export_certificate_pem(x509_cert)
                with open(output_file, 'w') as f:
                    f.write(content)
            elif format == 'der':
                content = converter.export_certificate_der(x509_cert)
                with open(output_file, 'wb') as f:
                    f.write(content)
            elif format == 'json':
                with open(output_file, 'w') as f:
                    json.dump(cert.to_dict(), f, indent=2)
            
            click.echo(f"{Fore.GREEN}📄 Exported certificate as {filename}")
            
            # Add warning for non-JSON formats
            if format != 'json':
                click.echo(f"{Fore.YELLOW}⚠️  Warning: {format.upper()} format contains RSA signature only")
                click.echo(f"{Style.DIM}   Dilithium signature omitted due to format limitations")
                click.echo(f"{Style.DIM}   Use JSON format for full quantum-resistant validation")
        
        click.echo(f"{Fore.CYAN}📂 Files exported to: {output_path.absolute()}")
        
    except Exception as e:
        click.echo(f"{Fore.RED}❌ Error exporting certificate: {e}")
        import traceback
        if click.get_current_context().obj.get('verbose', False):
            traceback.print_exc()


@cert.command('revoke')
@click.argument('cert_id')
@click.option('--ca-name', required=True, help='CA name')
@click.option('--reason', default='unspecified', help='Revocation reason')
@click.confirmation_option(prompt='Are you sure you want to revoke this certificate?')
def cert_revoke(cert_id, ca_name, reason):
    """Revoke a certificate."""
    try:
        ca = HybridCA(ca_name)
        success = ca.revoke_certificate(cert_id, reason)
        
        if success:
            click.echo(f"{Fore.GREEN}✅ Certificate {cert_id} revoked successfully")
        else:
            click.echo(f"{Fore.RED}❌ Certificate {cert_id} not found")
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"{Fore.RED}❌ Error revoking certificate: {e}")


# === Utility Commands ===

@main.command('info')
def info():
    """Display information about supported algorithms."""
    click.echo(f"{Fore.CYAN}📋 qPKI Algorithm Information")
    click.echo(f"{Style.DIM}{'='*50}")
    
    click.echo(f"\n{Fore.YELLOW}Classical Cryptography:")
    click.echo("• RSA with PSS padding")
    click.echo("• Key sizes: 2048, 3072, 4096 bits")
    click.echo("• Hash algorithm: SHA-256")
    click.echo("• Use: Backward compatibility, current standards")
    
    click.echo(f"\n{Fore.YELLOW}Post-Quantum Cryptography:")
    click.echo("• CRYSTALS-Dilithium digital signatures")
    
    # Get Dilithium variant information
    dilithium_info = DilithiumCrypto.get_supported_variants()
    
    for variant, info in dilithium_info.items():
        click.echo(f"  - Dilithium{variant}:")
        click.echo(f"    Security Level: {info['security_level']}")
        click.echo(f"    Public Key: {info['public_key_size']} bytes")
        click.echo(f"    Signature: {info['signature_size']} bytes")
    
    click.echo(f"\n{Fore.YELLOW}Hybrid Approach:")
    click.echo("• Combines both RSA and Dilithium signatures")
    click.echo("• Defense in depth against classical and quantum attacks")
    click.echo("• Suitable for cryptographic transition periods")


@main.command('demo')
def demo():
    """Run a quick demonstration of qPKI functionality."""
    click.echo(f"{Fore.CYAN}🚀 qPKI Quick Demo")
    click.echo(f"{Style.DIM}{'='*30}")
    
    try:
        # Initialize demo CA
        click.echo(f"{Fore.YELLOW}1. Initializing demo CA...")
        ca = HybridCA("DemoCA")
        ca_key_id = ca.initialize_ca(
            organization="Link2Trust Educational",
            country="US"
        )
        
        # Issue a demo certificate
        click.echo(f"{Fore.YELLOW}2. Issuing demo certificate...")
        subject = {"common_name": "demo.example.com", "organization": "Demo Corp"}
        cert_id = ca.issue_certificate(
            subject=subject,
            ca_key_identifier=f"CA-DemoCA",
            validity_days=30
        )
        
        # Validate the certificate
        click.echo(f"{Fore.YELLOW}3. Validating certificate...")
        validation_result = ca.validate_certificate(cert_id)
        
        if validation_result['valid']:
            click.echo(f"{Fore.GREEN}✅ Demo completed successfully!")
            click.echo(f"{Fore.CYAN}📋 Certificate ID: {cert_id}")
            click.echo(f"{Style.DIM}Use 'qpki cert validate {cert_id} --ca-name DemoCA' to validate again")
        else:
            click.echo(f"{Fore.RED}❌ Demo validation failed")
        
    except Exception as e:
        click.echo(f"{Fore.RED}❌ Demo failed: {e}")


if __name__ == '__main__':
    main()
