#!/usr/bin/env python3
"""
Framework Detection and Version Fuzzing Demo
Demonstrates the advanced capabilities of APILeak for framework detection and API version discovery
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from modules.advanced.framework_detector import FrameworkDetector, FrameworkDetectionConfig
from modules.advanced.version_fuzzer import VersionFuzzer, VersionFuzzingConfig
from modules.advanced.advanced_discovery_engine import AdvancedDiscoveryEngine, AdvancedDiscoveryConfig
from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig
from core.config import RateLimitConfig
from core.logging import setup_logging, get_logger


async def demo_framework_detection():
    """Demonstrate framework detection capabilities"""
    print("\n" + "="*60)
    print("FRAMEWORK DETECTION DEMO")
    print("="*60)
    
    # Setup HTTP client
    rate_config = RateLimitConfig(requests_per_second=5, burst_size=10)
    rate_limiter = RateLimiter(rate_config)
    retry_config = RetryConfig(max_attempts=2)
    http_client = HTTPRequestEngine(rate_limiter, retry_config, timeout=10.0)
    
    # Configure framework detector
    config = FrameworkDetectionConfig(
        enabled=True,
        adapt_payloads=True,
        test_framework_endpoints=True,
        max_error_requests=3,
        timeout=8.0,
        confidence_threshold=0.5  # Lower threshold for demo
    )
    
    detector = FrameworkDetector(config, http_client)
    
    # Test targets with known frameworks
    test_targets = [
        ("https://httpbin.org", "Testing service (Flask-based)"),
        ("https://jsonplaceholder.typicode.com", "JSON API service"),
        ("https://api.github.com", "GitHub API"),
    ]
    
    for target_url, description in test_targets:
        print(f"\n🎯 Testing: {target_url}")
        print(f"   Description: {description}")
        
        try:
            framework = await detector.detect_framework(target_url)
            
            if framework:
                print(f"✅ Framework detected: {framework.name}")
                print(f"   Confidence: {framework.confidence:.2f}")
                print(f"   Detection method: {framework.detection_method}")
                print(f"   Known vulnerabilities: {len(framework.specific_vulnerabilities)}")
                
                # Show framework-specific payloads
                payloads = detector.get_framework_specific_payloads(framework)
                if payloads:
                    print(f"   Framework-specific payloads: {len(payloads)}")
                    print(f"   Example payload: {payloads[0][:50]}...")
                
                # Show specific vulnerabilities
                if framework.specific_vulnerabilities:
                    print("   Vulnerability categories:")
                    for vuln in framework.specific_vulnerabilities[:3]:
                        print(f"     - {vuln}")
                    if len(framework.specific_vulnerabilities) > 3:
                        print(f"     ... and {len(framework.specific_vulnerabilities) - 3} more")
            else:
                print("❌ No framework detected with sufficient confidence")
                
        except Exception as e:
            print(f"❌ Error testing {target_url}: {e}")
    
    # Generate findings
    findings = detector.generate_findings()
    print(f"\n📊 Total findings generated: {len(findings)}")
    
    for finding in findings:
        print(f"   - {finding.category}: {finding.severity.value}")
        print(f"     Evidence: {finding.evidence[:80]}...")


async def demo_version_fuzzing():
    """Demonstrate API version fuzzing capabilities"""
    print("\n" + "="*60)
    print("API VERSION FUZZING DEMO")
    print("="*60)
    
    # Setup HTTP client
    rate_config = RateLimitConfig(requests_per_second=5, burst_size=10)
    rate_limiter = RateLimiter(rate_config)
    retry_config = RetryConfig(max_attempts=2)
    http_client = HTTPRequestEngine(rate_limiter, retry_config, timeout=10.0)
    
    # Configure version fuzzer
    config = VersionFuzzingConfig(
        enabled=True,
        version_patterns=[
            "/v1", "/v2", "/v3",
            "/api/v1", "/api/v2", "/api/v3",
            "/api/1", "/api/2"
        ],
        test_endpoints=["/", "/health", "/status"],
        max_concurrent_requests=3,
        timeout=8.0,
        compare_endpoints=True,
        detect_deprecated=True
    )
    
    fuzzer = VersionFuzzer(config, http_client)
    
    # Test targets
    test_targets = [
        ("https://httpbin.org", "Testing service"),
        ("https://jsonplaceholder.typicode.com", "JSON API service"),
    ]
    
    for target_url, description in test_targets:
        print(f"\n🎯 Testing: {target_url}")
        print(f"   Description: {description}")
        
        try:
            versions = await fuzzer.fuzz_api_versions(target_url)
            
            print(f"✅ Version discovery completed")
            print(f"   Versions found: {len(versions)}")
            
            if versions:
                for version in versions:
                    status_icon = "🟢" if version.accessible else "🔴"
                    print(f"   {status_icon} {version.version}: {version.status}")
                    print(f"      Status code: {version.status_code}")
                    print(f"      Response time: {version.response_time:.2f}s")
                    print(f"      Endpoints found: {len(version.endpoints_found)}")
                    
                    if version.version_info:
                        print(f"      Version info: {list(version.version_info.keys())}")
                
                # Show version comparison
                comparison = fuzzer.get_version_comparison()
                if comparison and len(comparison.versions) > 1:
                    print(f"\n📊 Version Comparison:")
                    print(f"   Common endpoints: {len(comparison.common_endpoints)}")
                    print(f"   Versions with unique endpoints: {len(comparison.unique_endpoints)}")
                    
                    if comparison.deprecated_versions:
                        print(f"   ⚠️  Deprecated versions: {', '.join(comparison.deprecated_versions)}")
                    
                    if comparison.development_versions:
                        print(f"   🚧 Development versions: {', '.join(comparison.development_versions)}")
            else:
                print("❌ No API versions found")
                
        except Exception as e:
            print(f"❌ Error testing {target_url}: {e}")
    
    # Generate findings
    findings = fuzzer.generate_findings()
    print(f"\n📊 Total findings generated: {len(findings)}")
    
    for finding in findings:
        print(f"   - {finding.category}: {finding.severity.value}")
        print(f"     Evidence: {finding.evidence[:80]}...")


async def demo_integrated_discovery():
    """Demonstrate integrated advanced discovery engine"""
    print("\n" + "="*60)
    print("INTEGRATED ADVANCED DISCOVERY DEMO")
    print("="*60)
    
    # Setup HTTP client
    rate_config = RateLimitConfig(requests_per_second=3, burst_size=8)
    rate_limiter = RateLimiter(rate_config)
    retry_config = RetryConfig(max_attempts=2)
    http_client = HTTPRequestEngine(rate_limiter, retry_config, timeout=10.0)
    
    # Configure advanced discovery engine
    config = AdvancedDiscoveryConfig()
    config.framework_detection.enabled = True
    config.framework_detection.confidence_threshold = 0.5
    config.version_fuzzing.enabled = True
    config.version_fuzzing.version_patterns = ["/v1", "/v2", "/api/v1", "/api/v2"]
    config.subdomain_discovery.enabled = False  # Disable for demo
    config.cors_analysis.enabled = False  # Disable for demo
    config.security_headers.enabled = False  # Disable for demo
    
    engine = AdvancedDiscoveryEngine(config, http_client)
    
    # Test target
    target_url = "https://httpbin.org"
    print(f"\n🎯 Comprehensive analysis of: {target_url}")
    
    try:
        attack_surface = await engine.map_attack_surface(target_url)
        
        print(f"\n✅ Attack surface mapping completed")
        print(f"   Target domain: {attack_surface.target_domain}")
        print(f"   Total findings: {attack_surface.total_findings}")
        print(f"   High risk findings: {attack_surface.high_risk_findings}")
        
        # Framework detection results
        if attack_surface.detected_framework:
            fw = attack_surface.detected_framework
            print(f"\n🔍 Framework Detection:")
            print(f"   Framework: {fw.name}")
            print(f"   Confidence: {fw.confidence:.2f}")
            print(f"   Detection method: {fw.detection_method}")
        
        # Version discovery results
        if attack_surface.api_versions:
            print(f"\n📊 API Versions:")
            for version in attack_surface.api_versions:
                print(f"   - {version.version}: {version.status} (accessible: {version.accessible})")
        
        # Version comparison
        if attack_surface.version_comparison:
            comp = attack_surface.version_comparison
            print(f"\n🔄 Version Comparison:")
            print(f"   Versions analyzed: {len(comp.versions)}")
            print(f"   Common endpoints: {len(comp.common_endpoints)}")
            print(f"   Unique endpoint sets: {len(comp.unique_endpoints)}")
        
        # All findings
        all_findings = engine.get_findings()
        print(f"\n📋 Detailed Findings:")
        
        findings_by_category = {}
        for finding in all_findings:
            category = finding.category
            if category not in findings_by_category:
                findings_by_category[category] = []
            findings_by_category[category].append(finding)
        
        for category, findings in findings_by_category.items():
            print(f"   {category}: {len(findings)} findings")
            for finding in findings[:2]:  # Show first 2 per category
                print(f"     - {finding.severity.value}: {finding.evidence[:60]}...")
        
        # Statistics
        stats = engine.get_statistics()
        print(f"\n📈 Statistics:")
        print(f"   Attack surface mapped: {stats['attack_surface_mapped']}")
        print(f"   Total findings: {stats['total_findings']}")
        print(f"   High risk findings: {stats['high_risk_findings']}")
        
        if 'framework_detection' in stats:
            fw_stats = stats['framework_detection']
            print(f"   Frameworks detected: {fw_stats['frameworks_detected']}")
        
        if 'version_fuzzing' in stats:
            ver_stats = stats['version_fuzzing']
            print(f"   API versions discovered: {ver_stats['versions_discovered']}")
            print(f"   Accessible versions: {ver_stats['accessible_versions']}")
        
    except Exception as e:
        print(f"❌ Error in integrated discovery: {e}")


async def main():
    """Main demo function"""
    print("APILeak Framework Detection & Version Fuzzing Demo")
    print("=" * 60)
    print("This demo showcases the advanced capabilities for:")
    print("- Automatic framework detection (FastAPI, Express, Django, Flask, etc.)")
    print("- API version discovery and comparison")
    print("- Integrated attack surface mapping")
    print("- Framework-specific payload generation")
    
    # Setup logging
    setup_logging(level="INFO")
    logger = get_logger("demo")
    
    try:
        # Run individual demos
        await demo_framework_detection()
        await demo_version_fuzzing()
        await demo_integrated_discovery()
        
        print("\n" + "="*60)
        print("DEMO COMPLETED SUCCESSFULLY")
        print("="*60)
        print("\nKey takeaways:")
        print("✅ Framework detection works across multiple technologies")
        print("✅ Version fuzzing discovers API versioning schemes")
        print("✅ Integrated discovery provides comprehensive attack surface mapping")
        print("✅ Framework-specific payloads improve testing effectiveness")
        
        print("\nNext steps:")
        print("🔧 Try with your own APIs using the CLI flags:")
        print("   python apileaks.py full --target YOUR_API --detect-framework --fuzz-versions")
        print("🔧 Customize configuration files for specific testing scenarios")
        print("🔧 Integrate into CI/CD pipelines for continuous security testing")
        
    except Exception as e:
        logger.error("Demo failed", error=str(e))
        print(f"\n❌ Demo failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())