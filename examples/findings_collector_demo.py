#!/usr/bin/env python3
"""
FindingsCollector Demo
Demonstrates the enhanced FindingsCollector functionality including:
- Automatic severity classification
- OWASP categorization
- Deduplication
- Prioritization
- Coverage analysis
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.findings import FindingsCollector, Finding
from core.config import Severity
from uuid import uuid4
import json


def main():
    """Demonstrate FindingsCollector functionality"""
    print("=== APILeak FindingsCollector Demo ===\n")
    
    # Initialize collector
    scan_id = str(uuid4())
    collector = FindingsCollector(scan_id)
    
    print(f"Initialized FindingsCollector for scan: {scan_id}\n")
    
    # Add various findings to demonstrate classification
    print("1. Adding findings with automatic classification...")
    
    findings_to_add = [
        ("BOLA_ANONYMOUS_ACCESS", "/api/users/123", "GET", "User 123 accessible without authentication"),
        ("AUTH_BYPASS", "/api/admin/users", "POST", "Admin endpoint accessible without proper authentication"),
        ("WEAK_JWT_ALGORITHM", "/api/auth/token", "POST", "JWT using 'none' algorithm detected"),
        ("MASS_ASSIGNMENT", "/api/users/profile", "PUT", "User can modify 'is_admin' field"),
        ("MISSING_RATE_LIMITING", "/api/search", "GET", "No rate limiting detected on search endpoint"),
        ("SSRF_INTERNAL_ACCESS", "/api/fetch", "POST", "SSRF to internal service 127.0.0.1:8080"),
        ("CORS_MISCONFIGURATION", "/api/data", "GET", "CORS allows wildcard origin with credentials"),
        ("ENDPOINT_DISCOVERED", "/api/v2/hidden", "GET", "Undocumented endpoint discovered"),
        ("INFORMATION_DISCLOSURE", "/api/debug", "GET", "Debug information exposed in response"),
        ("FRAMEWORK_DETECTED", "/", "GET", "FastAPI framework detected via headers")
    ]
    
    for category, endpoint, method, evidence in findings_to_add:
        finding = collector.add_finding(
            category=category,
            severity=None,  # Auto-classify
            endpoint=endpoint,
            method=method,
            evidence=evidence,
            recommendation=f"Fix {category.lower().replace('_', ' ')} vulnerability"
        )
        print(f"  Added: {category} -> {finding.severity.value} ({finding.owasp_category or 'No OWASP mapping'})")
    
    print(f"\nTotal findings added: {len(collector.findings)}")
    
    # Demonstrate deduplication
    print("\n2. Testing deduplication...")
    initial_count = len(collector.findings)
    
    # Try to add duplicate
    collector.add_finding(
        category="BOLA_ANONYMOUS_ACCESS",
        severity=None,
        endpoint="/api/users/123",
        method="GET",
        evidence="User 123 accessible without authentication",  # Same evidence
        recommendation="Fix BOLA vulnerability"
    )
    
    print(f"  Attempted to add duplicate - Count remained: {len(collector.findings)} (was {initial_count})")
    
    # Show statistics
    print("\n3. Findings Statistics:")
    stats = collector.get_statistics()
    print(f"  Total findings: {stats['total_findings']}")
    print(f"  Critical: {stats['critical_findings']}")
    print(f"  High: {stats['high_findings']}")
    print(f"  Medium: {stats['medium_findings']}")
    print(f"  Low: {stats['low_findings']}")
    print(f"  Info: {stats['info_findings']}")
    print(f"  Unique endpoints: {stats['unique_endpoints']}")
    print(f"  OWASP categories tested: {stats['owasp_categories_tested']}")
    print(f"  OWASP coverage: {stats['owasp_coverage_percentage']:.1f}%")
    
    # Show OWASP coverage analysis
    print("\n4. OWASP API Security Top 10 Coverage:")
    coverage = collector.get_owasp_coverage()
    
    for category, data in coverage["categories"].items():
        status = "✓" if data["tested"] else "✗"
        risk = data["risk_level"]
        findings_count = data["findings_count"]
        print(f"  {status} {category}: {data['description']}")
        if data["tested"]:
            print(f"    Risk Level: {risk}, Findings: {findings_count}")
    
    print(f"\nOverall Coverage: {coverage['coverage_percentage']:.1f}% ({coverage['tested_categories']}/{coverage['total_categories']} categories)")
    
    # Show prioritized findings
    print("\n5. Top 5 Prioritized Findings:")
    prioritized = collector.get_prioritized_findings(limit=5)
    
    for i, finding in enumerate(prioritized, 1):
        print(f"  {i}. [{finding.severity.value}] {finding.category}")
        print(f"     {finding.endpoint} ({finding.method})")
        print(f"     OWASP: {finding.owasp_category or 'N/A'}")
        print(f"     Evidence: {finding.evidence[:60]}...")
        print()
    
    # Show findings by OWASP category
    print("6. Findings by OWASP Category:")
    findings_by_owasp = collector.get_findings_by_owasp_category()
    
    for owasp_cat, findings in findings_by_owasp.items():
        print(f"  {owasp_cat} ({collector.OWASP_CATEGORIES[owasp_cat]}):")
        for finding in findings:
            print(f"    - [{finding.severity.value}] {finding.category} at {finding.endpoint}")
    
    # Export summary
    print("\n7. Exporting findings summary...")
    summary = collector.export_findings_summary()
    
    # Save to file
    output_file = f"findings_summary_{scan_id[:8]}.json"
    with open(output_file, 'w') as f:
        json.dump(summary, f, indent=2, default=str)
    
    print(f"  Summary exported to: {output_file}")
    print(f"  Summary contains {len(summary['top_findings'])} top findings")
    print(f"  Risk distribution: {summary['summary']['risk_distribution']}")
    
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    main()