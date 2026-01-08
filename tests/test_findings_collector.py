"""
Test suite for enhanced FindingsCollector
Tests aggregation, deduplication, classification, and OWASP categorization
"""

import pytest
from datetime import datetime
from uuid import uuid4

from utils.findings import FindingsCollector, Finding
from core.config import Severity


class TestFindingsCollector:
    """Test cases for FindingsCollector functionality"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.scan_id = str(uuid4())
        self.collector = FindingsCollector(self.scan_id)
    
    def test_initialization(self):
        """Test FindingsCollector initialization"""
        assert self.collector.scan_id == self.scan_id
        assert len(self.collector.findings) == 0
        assert len(self.collector._deduplication_cache) == 0
        assert self.collector.OWASP_CATEGORIES is not None
        assert len(self.collector.OWASP_CATEGORIES) == 10
    
    def test_add_finding_with_auto_classification(self):
        """Test adding finding with automatic severity classification"""
        finding = self.collector.add_finding(
            category="BOLA_ANONYMOUS_ACCESS",
            severity=None,  # Should be auto-classified as CRITICAL
            endpoint="/api/users/123",
            method="GET",
            evidence="User 123 accessible without authentication",
            recommendation="Implement proper authentication checks"
        )
        
        assert finding.severity == Severity.CRITICAL
        assert finding.owasp_category == "API1"
        assert finding.scan_id == self.scan_id
        assert len(self.collector.findings) == 1
    
    def test_add_finding_with_explicit_severity(self):
        """Test adding finding with explicit severity"""
        finding = self.collector.add_finding(
            category="CUSTOM_FINDING",
            severity=Severity.HIGH,
            endpoint="/api/test",
            method="POST",
            evidence="Custom test evidence",
            recommendation="Custom recommendation"
        )
        
        assert finding.severity == Severity.HIGH
        assert finding.owasp_category is None  # No mapping for custom category
        assert len(self.collector.findings) == 1
    
    def test_automatic_deduplication(self):
        """Test automatic deduplication during finding addition"""
        # Add first finding
        finding1 = self.collector.add_finding(
            category="BOLA_ANONYMOUS_ACCESS",
            severity=None,
            endpoint="/api/users/123",
            method="GET",
            evidence="User 123 accessible without authentication",
            recommendation="Implement proper authentication checks"
        )
        
        # Add duplicate finding (same endpoint, method, category, evidence)
        finding2 = self.collector.add_finding(
            category="BOLA_ANONYMOUS_ACCESS",
            severity=None,
            endpoint="/api/users/123",
            method="GET",
            evidence="User 123 accessible without authentication",
            recommendation="Implement proper authentication checks"
        )
        
        # Should only have one finding due to deduplication
        assert len(self.collector.findings) == 1
        assert len(self.collector._deduplication_cache) == 1
    
    def test_add_multiple_findings(self):
        """Test adding multiple findings with deduplication"""
        findings = [
            Finding(
                id=str(uuid4()),
                scan_id="test",
                category="BOLA_ANONYMOUS_ACCESS",
                severity=None,  # Will be auto-classified
                endpoint="/api/users/1",
                method="GET",
                evidence="Evidence 1",
                recommendation="Recommendation 1",
                owasp_category=None,  # Will be auto-assigned
                status_code=200,
                response_size=100,
                response_time=0.5
            ),
            Finding(
                id=str(uuid4()),
                scan_id="test",
                category="AUTH_BYPASS",
                severity=None,
                endpoint="/api/admin",
                method="POST",
                evidence="Evidence 2",
                recommendation="Recommendation 2",
                owasp_category=None,
                status_code=200,
                response_size=200,
                response_time=0.3
            ),
            # Duplicate of first finding
            Finding(
                id=str(uuid4()),
                scan_id="test",
                category="BOLA_ANONYMOUS_ACCESS",
                severity=None,
                endpoint="/api/users/1",
                method="GET",
                evidence="Evidence 1",
                recommendation="Recommendation 1",
                owasp_category=None,
                status_code=200,
                response_size=100,
                response_time=0.5
            )
        ]
        
        added_count = self.collector.add_findings(findings)
        
        assert added_count == 2  # Only 2 unique findings added
        assert len(self.collector.findings) == 2
        
        # Check auto-classification worked
        for finding in self.collector.findings:
            assert finding.severity is not None
            assert finding.scan_id == self.scan_id
    
    def test_severity_classification_rules(self):
        """Test severity classification rules for different categories"""
        test_cases = [
            ("BOLA_ANONYMOUS_ACCESS", Severity.CRITICAL),
            ("AUTH_BYPASS", Severity.CRITICAL),
            ("WEAK_JWT_ALGORITHM", Severity.HIGH),
            ("MISSING_RATE_LIMITING", Severity.MEDIUM),
            ("INFORMATION_DISCLOSURE", Severity.LOW),
            ("ENDPOINT_DISCOVERED", Severity.INFO),
            ("UNKNOWN_CATEGORY", Severity.MEDIUM)  # Default
        ]
        
        for category, expected_severity in test_cases:
            finding = self.collector.add_finding(
                category=category,
                severity=None,
                endpoint=f"/api/test/{category.lower()}",
                method="GET",
                evidence=f"Evidence for {category}",
                recommendation=f"Recommendation for {category}"
            )
            assert finding.severity == expected_severity
    
    def test_owasp_category_mapping(self):
        """Test OWASP category mapping for different finding categories"""
        test_cases = [
            ("BOLA_ANONYMOUS_ACCESS", "API1"),
            ("AUTH_BYPASS", "API2"),
            ("SENSITIVE_DATA_EXPOSURE", "API3"),
            ("MISSING_RATE_LIMITING", "API4"),
            ("ADMIN_ACCESS_ANONYMOUS", "API5"),
            ("SSRF_INTERNAL_ACCESS", "API7"),
            ("CORS_MISCONFIGURATION", "API8"),
            ("FRAMEWORK_DETECTED", "API9"),
            ("UNKNOWN_CATEGORY", None)  # No mapping
        ]
        
        for category, expected_owasp in test_cases:
            finding = self.collector.add_finding(
                category=category,
                severity=None,
                endpoint=f"/api/test/{category.lower()}",
                method="GET",
                evidence=f"Evidence for {category}",
                recommendation=f"Recommendation for {category}"
            )
            assert finding.owasp_category == expected_owasp
    
    def test_get_findings_by_severity(self):
        """Test getting findings grouped by severity"""
        # Add findings with different severities
        self.collector.add_finding("BOLA_ANONYMOUS_ACCESS", None, "/api/1", "GET", "Evidence", "Rec")
        self.collector.add_finding("WEAK_JWT_ALGORITHM", None, "/api/2", "GET", "Evidence", "Rec")
        self.collector.add_finding("MISSING_RATE_LIMITING", None, "/api/3", "GET", "Evidence", "Rec")
        self.collector.add_finding("ENDPOINT_DISCOVERED", None, "/api/4", "GET", "Evidence", "Rec")
        
        findings_by_severity = self.collector.get_findings_by_severity()
        
        assert len(findings_by_severity[Severity.CRITICAL.value]) == 1
        assert len(findings_by_severity[Severity.HIGH.value]) == 1
        assert len(findings_by_severity[Severity.MEDIUM.value]) == 1
        assert len(findings_by_severity[Severity.LOW.value]) == 0
        assert len(findings_by_severity[Severity.INFO.value]) == 1
    
    def test_get_findings_by_owasp_category(self):
        """Test getting findings grouped by OWASP category"""
        # Add findings that map to different OWASP categories
        self.collector.add_finding("BOLA_ANONYMOUS_ACCESS", None, "/api/1", "GET", "Evidence", "Rec")
        self.collector.add_finding("AUTH_BYPASS", None, "/api/2", "GET", "Evidence", "Rec")
        self.collector.add_finding("BOLA_HORIZONTAL_ESCALATION", None, "/api/3", "GET", "Evidence", "Rec")
        
        findings_by_owasp = self.collector.get_findings_by_owasp_category()
        
        assert "API1" in findings_by_owasp
        assert "API2" in findings_by_owasp
        assert len(findings_by_owasp["API1"]) == 2  # Two BOLA findings
        assert len(findings_by_owasp["API2"]) == 1  # One auth finding
    
    def test_get_prioritized_findings(self):
        """Test getting prioritized findings"""
        # Add findings with different priorities
        self.collector.add_finding("ENDPOINT_DISCOVERED", None, "/api/1", "GET", "Evidence", "Rec")  # INFO
        self.collector.add_finding("BOLA_ANONYMOUS_ACCESS", None, "/api/2", "GET", "Evidence", "Rec")  # CRITICAL
        self.collector.add_finding("MISSING_RATE_LIMITING", None, "/api/3", "GET", "Evidence", "Rec")  # MEDIUM
        self.collector.add_finding("WEAK_JWT_ALGORITHM", None, "/api/4", "GET", "Evidence", "Rec")  # HIGH
        
        prioritized = self.collector.get_prioritized_findings()
        
        # Should be ordered by severity (CRITICAL, HIGH, MEDIUM, INFO)
        assert prioritized[0].severity == Severity.CRITICAL
        assert prioritized[1].severity == Severity.HIGH
        assert prioritized[2].severity == Severity.MEDIUM
        assert prioritized[3].severity == Severity.INFO
        
        # Test with limit
        limited = self.collector.get_prioritized_findings(limit=2)
        assert len(limited) == 2
        assert limited[0].severity == Severity.CRITICAL
    
    def test_owasp_coverage_analysis(self):
        """Test OWASP coverage analysis"""
        # Add findings for some OWASP categories
        self.collector.add_finding("BOLA_ANONYMOUS_ACCESS", None, "/api/1", "GET", "Evidence", "Rec")  # API1
        self.collector.add_finding("AUTH_BYPASS", None, "/api/2", "GET", "Evidence", "Rec")  # API2
        self.collector.add_finding("WEAK_JWT_ALGORITHM", None, "/api/3", "GET", "Evidence", "Rec")  # API2
        
        coverage = self.collector.get_owasp_coverage()
        
        assert coverage["total_categories"] == 10
        assert coverage["tested_categories"] == 2  # API1 and API2
        assert coverage["coverage_percentage"] == 20.0
        assert len(coverage["untested_categories"]) == 8
        
        # Check specific category details
        api1_coverage = coverage["categories"]["API1"]
        assert api1_coverage["tested"] is True
        assert api1_coverage["findings_count"] == 1
        assert api1_coverage["critical_findings"] == 1
        assert api1_coverage["risk_level"] == "CRITICAL"
        
        api2_coverage = coverage["categories"]["API2"]
        assert api2_coverage["tested"] is True
        assert api2_coverage["findings_count"] == 2
        assert api2_coverage["critical_findings"] == 1
        assert api2_coverage["high_findings"] == 1
    
    def test_get_statistics(self):
        """Test comprehensive statistics"""
        # Add various findings
        self.collector.add_finding("BOLA_ANONYMOUS_ACCESS", None, "/api/users/1", "GET", "Evidence", "Rec")
        self.collector.add_finding("AUTH_BYPASS", None, "/api/admin", "POST", "Evidence", "Rec")
        self.collector.add_finding("MISSING_RATE_LIMITING", None, "/api/users/2", "GET", "Evidence", "Rec")
        self.collector.add_finding("ENDPOINT_DISCOVERED", None, "/api/public", "GET", "Evidence", "Rec")
        
        stats = self.collector.get_statistics()
        
        assert stats["total_findings"] == 4
        assert stats["critical_findings"] == 2
        assert stats["high_findings"] == 0
        assert stats["medium_findings"] == 1
        assert stats["info_findings"] == 1
        assert stats["unique_endpoints"] == 4
        assert stats["unique_categories"] == 4
        assert stats["owasp_categories_tested"] == 4  # API1, API2, API4, API9
        assert stats["owasp_coverage_percentage"] == 40.0
        assert stats["most_critical_category"] == "API1"  # Has 1 critical finding
    
    def test_export_findings_summary(self):
        """Test findings summary export"""
        # Add some findings
        self.collector.add_finding("BOLA_ANONYMOUS_ACCESS", None, "/api/users/1", "GET", "Evidence", "Rec")
        self.collector.add_finding("AUTH_BYPASS", None, "/api/admin", "POST", "Evidence", "Rec")
        
        summary = self.collector.export_findings_summary()
        
        assert summary["scan_id"] == self.scan_id
        assert "timestamp" in summary
        assert summary["summary"]["total_findings"] == 2
        assert summary["summary"]["risk_distribution"]["critical"] == 2
        assert summary["summary"]["owasp_coverage"]["tested_categories"] == 2
        assert len(summary["top_findings"]) == 2
        assert "owasp_breakdown" in summary
    
    def test_filtering_functionality(self):
        """Test finding filtering by various criteria"""
        # Add findings with different attributes
        self.collector.add_finding("BOLA_ANONYMOUS_ACCESS", None, "/api/1", "GET", "Evidence", "Rec")
        self.collector.add_finding("AUTH_BYPASS", None, "/api/2", "POST", "Evidence", "Rec")
        self.collector.add_finding("MISSING_RATE_LIMITING", None, "/api/3", "GET", "Evidence", "Rec")
        
        # Filter by severity
        critical_findings = self.collector.get_findings(severity=Severity.CRITICAL)
        assert len(critical_findings) == 2
        
        # Filter by category
        bola_findings = self.collector.get_findings(category="BOLA_ANONYMOUS_ACCESS")
        assert len(bola_findings) == 1
        
        # Filter by OWASP category
        api1_findings = self.collector.get_findings(owasp_category="API1")
        assert len(api1_findings) == 1
        
        # Combined filtering
        critical_api2 = self.collector.get_findings(severity=Severity.CRITICAL, owasp_category="API2")
        assert len(critical_api2) == 1


if __name__ == "__main__":
    pytest.main([__file__])