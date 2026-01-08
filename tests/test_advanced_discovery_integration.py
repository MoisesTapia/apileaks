"""
Integration tests for Advanced Discovery modules
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock

from modules.advanced.subdomain_discovery import SubdomainDiscovery, SubdomainDiscoveryConfig
from modules.advanced.cors_analyzer import CORSAnalyzer, CORSAnalyzerConfig
from modules.advanced.security_headers_analyzer import SecurityHeadersAnalyzer, SecurityHeadersConfig
from modules.advanced.advanced_discovery_engine import AdvancedDiscoveryEngine, AdvancedDiscoveryConfig
from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig
from core.config import RateLimitConfig


class TestAdvancedDiscoveryIntegration:
    """Integration tests for Advanced Discovery functionality"""
    
    @pytest.fixture
    def http_client(self):
        """Create mock HTTP client for testing"""
        rate_limit_config = RateLimitConfig(requests_per_second=10, burst_size=20)
        rate_limiter = RateLimiter(rate_limit_config)
        retry_config = RetryConfig(max_attempts=2)
        return HTTPRequestEngine(rate_limiter, retry_config)
    
    @pytest.fixture
    def subdomain_config(self):
        """Create subdomain discovery configuration"""
        return SubdomainDiscoveryConfig(
            enabled=True,
            wordlist=["api", "www", "test"],
            timeout=5.0,
            max_concurrent=2,
            dns_resolution=False  # Disable DNS for testing
        )
    
    @pytest.fixture
    def cors_config(self):
        """Create CORS analyzer configuration"""
        return CORSAnalyzerConfig(
            enabled=True,
            test_origins=["https://example.com"],
            timeout=5.0,
            max_concurrent=2
        )
    
    @pytest.fixture
    def security_headers_config(self):
        """Create security headers configuration"""
        return SecurityHeadersConfig(
            enabled=True,
            timeout=5.0,
            max_concurrent=2
        )
    
    def test_subdomain_discovery_initialization(self, subdomain_config, http_client):
        """Test subdomain discovery initialization"""
        subdomain_discovery = SubdomainDiscovery(subdomain_config, http_client)
        
        assert subdomain_discovery.config == subdomain_config
        assert subdomain_discovery.http_client == http_client
        assert subdomain_discovery.discovered_subdomains == []
        assert subdomain_discovery.accessible_subdomains == []
    
    def test_cors_analyzer_initialization(self, cors_config, http_client):
        """Test CORS analyzer initialization"""
        cors_analyzer = CORSAnalyzer(cors_config, http_client)
        
        assert cors_analyzer.config == cors_config
        assert cors_analyzer.http_client == http_client
        assert cors_analyzer.analysis_results == {}
    
    def test_security_headers_analyzer_initialization(self, security_headers_config, http_client):
        """Test security headers analyzer initialization"""
        headers_analyzer = SecurityHeadersAnalyzer(security_headers_config, http_client)
        
        assert headers_analyzer.config == security_headers_config
        assert headers_analyzer.http_client == http_client
        assert headers_analyzer.analysis_results == {}
    
    def test_advanced_discovery_engine_initialization(self, http_client):
        """Test advanced discovery engine initialization"""
        from modules.advanced.subdomain_discovery import SubdomainDiscoveryConfig
        from modules.advanced.cors_analyzer import CORSAnalyzerConfig
        from modules.advanced.security_headers_analyzer import SecurityHeadersConfig
        
        subdomain_config = SubdomainDiscoveryConfig(enabled=True)
        cors_config = CORSAnalyzerConfig(enabled=True)
        headers_config = SecurityHeadersConfig(enabled=True)
        
        config = AdvancedDiscoveryConfig(
            subdomain_discovery=subdomain_config,
            cors_analysis=cors_config,
            security_headers=headers_config
        )
        
        engine = AdvancedDiscoveryEngine(config, http_client)
        
        assert engine.config == config
        assert engine.http_client == http_client
        assert engine.attack_surface is None
        assert engine.all_findings == []
    
    def test_subdomain_discovery_statistics(self, subdomain_config, http_client):
        """Test subdomain discovery statistics"""
        subdomain_discovery = SubdomainDiscovery(subdomain_config, http_client)
        
        stats = subdomain_discovery.get_statistics()
        
        assert isinstance(stats, dict)
        assert "total_tested" in stats
        assert "accessible_found" in stats
        assert "success_rate" in stats
        assert stats["total_tested"] == 0
        assert stats["accessible_found"] == 0
    
    def test_cors_analyzer_statistics(self, cors_config, http_client):
        """Test CORS analyzer statistics"""
        cors_analyzer = CORSAnalyzer(cors_config, http_client)
        
        stats = cors_analyzer.get_statistics()
        
        assert isinstance(stats, dict)
        assert "total_endpoints_analyzed" in stats
        assert "wildcard_origin_endpoints" in stats
        assert "high_risk_endpoints" in stats
        assert stats["total_endpoints_analyzed"] == 0
    
    def test_security_headers_analyzer_statistics(self, security_headers_config, http_client):
        """Test security headers analyzer statistics"""
        headers_analyzer = SecurityHeadersAnalyzer(security_headers_config, http_client)
        
        stats = headers_analyzer.get_statistics()
        
        assert isinstance(stats, dict)
        assert "total_endpoints_analyzed" in stats
        assert "average_security_score" in stats
        assert "endpoints_with_missing_headers" in stats
        assert stats["total_endpoints_analyzed"] == 0
    
    def test_findings_generation_structure(self, subdomain_config, http_client):
        """Test that findings are generated with correct structure"""
        subdomain_discovery = SubdomainDiscovery(subdomain_config, http_client)
        
        # Mock some accessible subdomains
        subdomain_discovery.accessible_subdomains = ["api.example.com", "dev.example.com"]
        
        findings = subdomain_discovery.generate_findings()
        
        assert isinstance(findings, list)
        assert len(findings) >= 1  # Should have at least discovery finding
        
        # Check finding structure
        for finding in findings:
            assert hasattr(finding, 'id')
            assert hasattr(finding, 'scan_id')
            assert hasattr(finding, 'category')
            assert hasattr(finding, 'severity')
            assert hasattr(finding, 'endpoint')
            assert hasattr(finding, 'method')
            assert hasattr(finding, 'evidence')
            assert hasattr(finding, 'recommendation')
    
    @pytest.mark.asyncio
    async def test_http_client_cleanup(self, http_client):
        """Test HTTP client cleanup"""
        # Ensure client can be closed without errors
        await http_client.close()
        
        # Should be able to close multiple times
        await http_client.close()


if __name__ == "__main__":
    pytest.main([__file__])