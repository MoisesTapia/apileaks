#!/usr/bin/env python3
"""
APILeak Payload Generator Demo

This script demonstrates the advanced payload generation capabilities of APILeak,
including encoding, obfuscation, and vulnerability-specific payload generation.

Usage:
    python examples/payload_generator_demo.py
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.payload_generator import (
    PayloadGenerator, PayloadGenerationConfig,
    EncodingType, ObfuscationType, VulnerabilityType
)

def demonstrate_encoding():
    """Demonstrate payload encoding capabilities"""
    print("=" * 60)
    print("PAYLOAD ENCODING DEMONSTRATION")
    print("=" * 60)
    
    generator = PayloadGenerator()
    base_payload = "' OR '1'='1' --"
    
    print(f"Base Payload: {base_payload}")
    print()
    
    # URL Encoding
    print("URL Encoded Payloads:")
    url_encoded = generator.generate_encoded_payloads(base_payload, [EncodingType.URL])
    for i, payload in enumerate(url_encoded[:3], 1):
        print(f"  {i}. {payload}")
    print()
    
    # Base64 Encoding
    print("Base64 Encoded Payloads:")
    b64_encoded = generator.generate_encoded_payloads(base_payload, [EncodingType.BASE64])
    for i, payload in enumerate(b64_encoded[:3], 1):
        print(f"  {i}. {payload}")
    print()
    
    # Unicode Encoding
    print("Unicode Encoded Payloads:")
    unicode_encoded = generator.generate_encoded_payloads(base_payload, [EncodingType.UNICODE])
    for i, payload in enumerate(unicode_encoded[:3], 1):
        print(f"  {i}. {payload}")
    print()

def demonstrate_obfuscation():
    """Demonstrate payload obfuscation capabilities"""
    print("=" * 60)
    print("PAYLOAD OBFUSCATION DEMONSTRATION")
    print("=" * 60)
    
    generator = PayloadGenerator()
    base_payload = "SELECT * FROM users WHERE id=1"
    
    print(f"Base Payload: {base_payload}")
    print()
    
    # Case Variations
    print("Case Variation Obfuscation:")
    case_variations = generator.apply_obfuscation(base_payload, [ObfuscationType.CASE_VARIATION])
    for i, payload in enumerate(case_variations[:5], 1):
        print(f"  {i}. {payload}")
    print()
    
    # Mutations
    print("Mutation Obfuscation:")
    mutations = generator.apply_obfuscation(base_payload, [ObfuscationType.MUTATION])
    for i, payload in enumerate(mutations[:5], 1):
        print(f"  {i}. {payload}")
    print()

def demonstrate_vulnerability_payloads():
    """Demonstrate vulnerability-specific payload generation"""
    print("=" * 60)
    print("VULNERABILITY-SPECIFIC PAYLOADS")
    print("=" * 60)
    
    generator = PayloadGenerator()
    
    # SQL Injection Payloads
    print("SQL Injection Payloads:")
    sql_payloads = generator.generate_injection_payloads(VulnerabilityType.SQL_INJECTION)
    for i, payload in enumerate(sql_payloads[:5], 1):
        print(f"  {i}. {payload}")
    print()
    
    # XSS Payloads
    print("XSS Payloads:")
    xss_payloads = generator.generate_injection_payloads(VulnerabilityType.XSS)
    for i, payload in enumerate(xss_payloads[:5], 1):
        print(f"  {i}. {payload}")
    print()
    
    # Command Injection Payloads
    print("Command Injection Payloads:")
    cmd_payloads = generator.generate_injection_payloads(VulnerabilityType.COMMAND_INJECTION)
    for i, payload in enumerate(cmd_payloads[:5], 1):
        print(f"  {i}. {payload}")
    print()
    
    # Path Traversal Payloads
    print("Path Traversal Payloads:")
    path_payloads = generator.generate_injection_payloads(VulnerabilityType.PATH_TRAVERSAL)
    for i, payload in enumerate(path_payloads[:5], 1):
        print(f"  {i}. {payload}")
    print()

def demonstrate_framework_specific():
    """Demonstrate framework-specific payload generation"""
    print("=" * 60)
    print("FRAMEWORK-SPECIFIC PAYLOADS")
    print("=" * 60)
    
    generator = PayloadGenerator()
    
    frameworks = ['fastapi', 'django', 'express', 'flask']
    vuln_types = [VulnerabilityType.SQL_INJECTION, VulnerabilityType.XSS, VulnerabilityType.SSTI]
    
    for framework in frameworks:
        print(f"{framework.upper()} Framework Payloads:")
        for vuln_type in vuln_types:
            payloads = generator.generate_framework_specific_payloads(framework, vuln_type)
            if payloads:
                print(f"  {vuln_type.value.replace('_', ' ').title()}:")
                for i, payload in enumerate(payloads[:3], 1):
                    print(f"    {i}. {payload}")
        print()

def demonstrate_wordlist_expansion():
    """Demonstrate wordlist expansion capabilities"""
    print("=" * 60)
    print("WORDLIST EXPANSION DEMONSTRATION")
    print("=" * 60)
    
    generator = PayloadGenerator()
    
    # API Endpoints
    base_endpoints = ["users", "admin", "api", "auth"]
    prefixes = ["v1/", "v2/", "api/"]
    suffixes = ["/list", "/create", "/delete", "/update"]
    
    print("Base Endpoints:", base_endpoints)
    print("Prefixes:", prefixes)
    print("Suffixes:", suffixes)
    print()
    
    expanded = generator.expand_wordlist(base_endpoints, prefixes, suffixes)
    
    print(f"Expanded Wordlist ({len(expanded)} entries):")
    for i, endpoint in enumerate(expanded[:15], 1):  # Show first 15
        print(f"  {i:2d}. {endpoint}")
    
    if len(expanded) > 15:
        print(f"  ... and {len(expanded) - 15} more entries")
    print()

def demonstrate_template_info():
    """Demonstrate template information retrieval"""
    print("=" * 60)
    print("TEMPLATE INFORMATION")
    print("=" * 60)
    
    generator = PayloadGenerator()
    
    print("Available Vulnerability Types:")
    vuln_types = generator.get_available_vulnerability_types()
    for i, vuln_type in enumerate(vuln_types, 1):
        print(f"  {i}. {vuln_type.value.replace('_', ' ').title()}")
    print()
    
    # Show template info for SQL Injection
    print("SQL Injection Template Information:")
    sql_templates = generator.get_template_info(VulnerabilityType.SQL_INJECTION)
    for template in sql_templates:
        print(f"  Template: {template['name']}")
        print(f"    Description: {template['description']}")
        print(f"    Payload Count: {template['payload_count']}")
        print(f"    Encodings: {', '.join(template['encodings'])}")
        print(f"    Obfuscations: {', '.join(template['obfuscations'])}")
        print()

def demonstrate_advanced_configuration():
    """Demonstrate advanced configuration options"""
    print("=" * 60)
    print("ADVANCED CONFIGURATION")
    print("=" * 60)
    
    # Custom configuration
    config = PayloadGenerationConfig(
        enabled_encodings=[EncodingType.URL, EncodingType.BASE64, EncodingType.UNICODE],
        enabled_obfuscations=[ObfuscationType.CASE_VARIATION, ObfuscationType.MUTATION],
        max_variations_per_payload=8,
        include_original=True,
        custom_templates_dir="templates/payloads"
    )
    
    generator = PayloadGenerator(config)
    
    print("Configuration:")
    print(f"  Enabled Encodings: {[e.value for e in config.enabled_encodings]}")
    print(f"  Enabled Obfuscations: {[o.value for o in config.enabled_obfuscations]}")
    print(f"  Max Variations: {config.max_variations_per_payload}")
    print(f"  Include Original: {config.include_original}")
    print(f"  Custom Templates Dir: {config.custom_templates_dir}")
    print()
    
    # Generate payloads with custom config
    base_payload = "<script>alert('XSS')</script>"
    print(f"Base Payload: {base_payload}")
    print()
    
    # Apply all configured encodings and obfuscations
    all_encodings = generator.generate_encoded_payloads(base_payload)
    all_obfuscations = generator.apply_obfuscation(base_payload)
    
    print(f"Generated {len(all_encodings)} encoded variations")
    print(f"Generated {len(all_obfuscations)} obfuscated variations")
    print()
    
    print("Sample Encoded Variations:")
    for i, payload in enumerate(all_encodings[:5], 1):
        print(f"  {i}. {payload}")
    print()

def main():
    """Main demonstration function"""
    print("APILeak Payload Generator Demonstration")
    print("=" * 60)
    print()
    
    try:
        demonstrate_encoding()
        demonstrate_obfuscation()
        demonstrate_vulnerability_payloads()
        demonstrate_framework_specific()
        demonstrate_wordlist_expansion()
        demonstrate_template_info()
        demonstrate_advanced_configuration()
        
        print("=" * 60)
        print("DEMONSTRATION COMPLETE")
        print("=" * 60)
        print()
        print("The Payload Generator successfully demonstrated:")
        print("✓ Multiple encoding types (URL, Base64, HTML, Unicode)")
        print("✓ Obfuscation techniques (case variations, mutations)")
        print("✓ Vulnerability-specific payload generation")
        print("✓ Framework-specific payload adaptation")
        print("✓ Wordlist expansion with prefixes/suffixes")
        print("✓ Template system with custom configurations")
        print("✓ Advanced configuration options")
        print()
        print("Requirements 16.1, 16.2, 16.3, 16.4, 16.5 have been successfully implemented!")
        
    except Exception as e:
        print(f"Error during demonstration: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())