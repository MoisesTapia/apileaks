"""
Test suite for Core Engine integration with enhanced FindingsCollector
Tests the integration between APILeakCore and FindingsCollector
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock
from datetime import datetime

from core.engine import APILeakCore, ScanResults
from core.config import APILeakConfig, TargetConfig, FuzzingConfig, OWASPConfig
from utils.findings import FindingsCollector, Finding
from core.config import Severity


class TestCoreEngineFindingsIntegration:
    """Test cases for Core Engine and FindingsCollector integration"""
    
    def setup_method(self):
        """Setup test fixtures"""
        # Create minimal config for testing
        self.config = APILeakConfig(
            target=TargetConfig(base_url="https://api.example.com"),
            fuzzing=FuzzingConfig(),
            owasp_testing=OWASPConfig(enabled_modules=["bola", "auth"])
        )
        self.core = APILeakCore(self.config)
    
    def test_core_engine_initialization_with_findings_collector(self):
        """Test that core engine initializes with findings collector"""
        assert self.core.findings_collector is not None
        assert isinstance(self.core.findings_collector, FindingsCollector)
        assert self.core.findings_collector.scan_id == self.core.scan_id
    
    def test_add_finding_through_core_engine(self):
        """Test adding findings through core engine interface"""
        finding = self.core.add_finding(
            category="BOLA_ANONYMOUS_ACCESS",
            severity=None,
            endpoint="/api/users/123",
            method="GET",
            evidence="User accessible without auth",
            recommendation="Add authentication"
        )
        
        assert finding.severity == Severity.CRITICAL
        assert finding.owasp_category == "API1"
        assert len(self.core.findings_collector.findings) == 1
    
    def test_get_findings_collector(self):
        """Test getting findings collector from core engine"""
        collector = self.core.get_findings_collector()
        assert collector is self.core.findings_collector
        
        # Add a finding and verify it's accessible
        collector.add_finding(
            category="AUTH_BYPASS",
            severity=None,
            endpoint="/api/admin",
            method="POST",
            evidence="Admin access without auth",
            recommendation="Fix authentication"
        )
        
        assert len(collector.findings) == 1
        assert collector.findings[0].severity == Severity.CRITICAL
    
    def test_scan_results_includes_findings_collector(self):
        """Test that scan results include the findings collector"""
        # Mock the async methods to avoid actual HTTP calls
        self.core._execute_discovery_phase = AsyncMock()
        self.core._execute_fuzzing_phase = AsyncMock(return_value={
            "endpoints_tested": 5,
            "findings": []
        })
        self.core._execute_owasp_phase = AsyncMock(return_value={
            "modules_executed": ["bola"],
            "findings": []
        })
        
        # Add some findings before running scan
        self.core.add_finding(
            category="BOLA_ANONYMOUS_ACCESS",
            severity=None,
            endpoint="/api/test",
            method="GET",
            evidence="Test evidence",
            recommendation="Test recommendation"
        )
        
        # Run scan
        async def run_test():
            results = await self.core.run_scan("https://api.example.com")
            return results
        
        results = asyncio.run(run_test())
        
        assert results.findings_collector is not None
        assert results.findings_collector is self.core.findings_collector
        assert len(results.findings_collector.findings) == 1
        assert results.statistics.findings_count == 1
        assert results.statistics.critical_findings == 1
    
    def test_scan_status_includes_findings_statistics(self):
        """Test that scan status includes findings statistics"""
        # Add some findings
        self.core.add_finding("BOLA_ANONYMOUS_ACCESS", None, "/api/1", "GET", "Evidence", "Rec")
        self.core.add_finding("AUTH_BYPASS", None, "/api/2", "POST", "Evidence", "Rec")
        self.core.add_finding("MISSING_RATE_LIMITING", None, "/api/3", "GET", "Evidence", "Rec")
        
        status = self.core.get_scan_status()
        
        assert "findings_statistics" in status
        stats = status["findings_statistics"]
        assert stats["total_findings"] == 3
        assert stats["critical_findings"] == 2
        assert stats["medium_findings"] == 1
        assert stats["owasp_categories_tested"] == 3
    
    @pytest.mark.asyncio
    async def test_aggregate_results_with_findings_collector(self):
        """Test that result aggregation works with findings collector"""
        # Setup mock scan results
        self.core.scan_results = ScanResults(
            scan_id=self.core.scan_id,
            timestamp=datetime.now(),
            target_url="https://api.example.com",
            configuration=self.config,
            statistics=Mock(),
            performance_metrics=Mock(),
            findings_collector=self.core.findings_collector
        )
        
        # Mock fuzzing and OWASP results with findings
        mock_fuzzing_findings = [
            Finding(
                id="1",
                scan_id=self.core.scan_id,
                category="ENDPOINT_DISCOVERED",
                severity=Severity.INFO,
                endpoint="/api/discovered",
                method="GET",
                evidence="Endpoint found via fuzzing",
                recommendation="Review endpoint security",
                owasp_category=None,
                status_code=200,
                response_size=100,
                response_time=0.1
            )
        ]
        
        mock_owasp_findings = [
            Finding(
                id="2",
                scan_id=self.core.scan_id,
                category="BOLA_ANONYMOUS_ACCESS",
                severity=Severity.CRITICAL,
                endpoint="/api/users/123",
                method="GET",
                evidence="BOLA vulnerability detected",
                recommendation="Implement authorization checks",
                owasp_category="API1",
                status_code=200,
                response_size=500,
                response_time=0.2
            )
        ]
        
        self.core.scan_results.fuzzing_results = {"findings": mock_fuzzing_findings}
        self.core.scan_results.owasp_results = {"findings": mock_owasp_findings}
        
        # Run aggregation
        await self.core._aggregate_results()
        
        # Verify findings were aggregated
        assert len(self.core.findings_collector.findings) == 2
        assert self.core.scan_results.statistics.findings_count == 2
        assert self.core.scan_results.statistics.critical_findings == 1
        assert self.core.scan_results.statistics.info_findings == 1
        
        # Verify OWASP coverage was calculated
        coverage = self.core.findings_collector.get_owasp_coverage()
        assert coverage["tested_categories"] == 2  # API1 and API9 tested
        assert coverage["coverage_percentage"] == 20.0  # 2 out of 10 categories
    
    def test_findings_collector_deduplication_in_core_engine(self):
        """Test that deduplication works when adding findings through core engine"""
        # Add same finding twice
        finding1 = self.core.add_finding(
            category="BOLA_ANONYMOUS_ACCESS",
            severity=None,
            endpoint="/api/users/123",
            method="GET",
            evidence="User accessible without auth",
            recommendation="Add authentication"
        )
        
        finding2 = self.core.add_finding(
            category="BOLA_ANONYMOUS_ACCESS",
            severity=None,
            endpoint="/api/users/123",
            method="GET",
            evidence="User accessible without auth",
            recommendation="Add authentication"
        )
        
        # Should only have one finding due to deduplication
        assert len(self.core.findings_collector.findings) == 1
        assert finding1.id == self.core.findings_collector.findings[0].id
    
    def test_findings_collector_owasp_prioritization(self):
        """Test OWASP prioritization through core engine"""
        # Add findings from different OWASP categories
        self.core.add_finding("ENDPOINT_DISCOVERED", None, "/api/1", "GET", "Evidence", "Rec")  # API9
        self.core.add_finding("BOLA_ANONYMOUS_ACCESS", None, "/api/2", "GET", "Evidence", "Rec")  # API1
        self.core.add_finding("SSRF_INTERNAL_ACCESS", None, "/api/3", "GET", "Evidence", "Rec")  # API7
        self.core.add_finding("AUTH_BYPASS", None, "/api/4", "GET", "Evidence", "Rec")  # API2
        
        # Get prioritized findings
        prioritized = self.core.findings_collector.get_prioritized_findings()
        
        # Should be ordered by severity first, then OWASP priority
        # All CRITICAL findings should come first, ordered by OWASP category (API1, API2, API7)
        # Then other severities
        critical_findings = [f for f in prioritized if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 3
        assert critical_findings[0].owasp_category == "API1"  # Highest OWASP priority
        assert critical_findings[1].owasp_category == "API2"
        assert critical_findings[2].owasp_category == "API7"
        
        # INFO finding should be last
        assert prioritized[-1].severity == Severity.INFO
        assert prioritized[-1].owasp_category == "API9"


if __name__ == "__main__":
    pytest.main([__file__])