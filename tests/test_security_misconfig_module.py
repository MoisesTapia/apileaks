"""
Tests for Security Misconfiguration Testing Module (OWASP API8)
"""

import pytest
from unittest.mock import Mock, AsyncMock
from dataclasses import dataclass

from modules.owasp.security_misconfiguration import SecurityMisconfigModule
from modules.advanced.cors_analyzer import CORSAnalysis
from modules.advanced.security_headers_analyzer import SecurityHeadersAnalysis
from utils.http_client import HTTPRequestEngine
from core.config import SecurityMisconfigConfig, AuthContext, AuthType, Severity


@dataclass
class MockEndpoint:
    """Mock endpoint for testing"""
    url: str
    method: str = "GET"


class TestSecurityMisconfigModule:
    """Test cases for Security Misconfiguration Testing Module"""

    @pytest.fixture
    def misconfig_config(self):
        """Create Security Misconfiguration configuration for testing"""
        return SecurityMisconfigConfig(
            enabled=True,
            required_headers=[
                "Strict-Transport-Security",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Content-Security-Policy",
            ],
        )

    @pytest.fixture
    def auth_contexts(self):
        """Create auth contexts for testing"""
        return [
            AuthContext(
                name="user1",
                type=AuthType.BEARER,
                token="user1_token",
                privilege_level=1,
            )
        ]

    @pytest.fixture
    def mock_http_client(self):
        """Create mock HTTP client"""
        client = Mock(spec=HTTPRequestEngine)
        client.request = AsyncMock()
        return client

    @pytest.fixture
    def misconfig_module(self, misconfig_config, auth_contexts, mock_http_client):
        """Create Security Misconfiguration testing module"""
        return SecurityMisconfigModule(misconfig_config, mock_http_client, auth_contexts)

    def test_module_initialization(self, misconfig_module):
        """Test Security Misconfiguration module initialization"""
        assert misconfig_module.get_module_name() == "security_misconfig"
        assert misconfig_module.cors_analyzer is not None
        assert misconfig_module.security_headers_analyzer is not None

    @pytest.mark.asyncio
    async def test_permissive_cors_produces_finding(self, misconfig_module):
        """Permissive CORS analysis -> CORS_MISCONFIGURATION finding mapped to API8"""
        endpoint = "https://api.example.com/users"
        permissive = CORSAnalysis(
            wildcard_origin=True,
            credentials_allowed=False,
            dangerous_methods=["DELETE"],
            security_risk="HIGH",
            allowed_origins={"*"},
            allowed_methods={"GET", "DELETE"},
        )

        # Mock the composed analyzer's analyze_cors_policy method
        misconfig_module.cors_analyzer.analyze_cors_policy = AsyncMock(
            return_value={endpoint: permissive}
        )

        findings = await misconfig_module._test_cors([endpoint])

        assert len(findings) == 1
        assert findings[0].category == "CORS_MISCONFIGURATION"
        assert findings[0].owasp_category == "API8"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].endpoint == endpoint

    @pytest.mark.asyncio
    async def test_non_permissive_cors_produces_no_finding(self, misconfig_module):
        """A safe (LOW risk, no wildcard) CORS analysis -> no findings"""
        endpoint = "https://api.example.com/users"
        safe = CORSAnalysis(
            wildcard_origin=False,
            credentials_allowed=False,
            dangerous_methods=[],
            security_risk="LOW",
            allowed_origins={"https://trusted.example.com"},
            allowed_methods={"GET"},
        )

        misconfig_module.cors_analyzer.analyze_cors_policy = AsyncMock(
            return_value={endpoint: safe}
        )

        findings = await misconfig_module._test_cors([endpoint])

        assert findings == []

    @pytest.mark.asyncio
    async def test_credentials_with_wildcard_is_critical(self, misconfig_module):
        """Credentials allowed with wildcard origin -> CRITICAL severity finding"""
        endpoint = "https://api.example.com/account"
        critical = CORSAnalysis(
            wildcard_origin=True,
            credentials_allowed=True,
            dangerous_methods=[],
            security_risk="CRITICAL",
            allowed_origins={"*"},
            allowed_methods={"GET", "POST"},
        )

        misconfig_module.cors_analyzer.analyze_cors_policy = AsyncMock(
            return_value={endpoint: critical}
        )

        findings = await misconfig_module._test_cors([endpoint])

        assert len(findings) == 1
        assert findings[0].category == "CORS_MISCONFIGURATION"
        assert findings[0].owasp_category == "API8"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_missing_headers_produce_finding(self, misconfig_module):
        """Missing required headers -> MISSING_SECURITY_HEADERS finding (API8, MEDIUM)"""
        endpoint = "https://api.example.com/users"
        analysis = SecurityHeadersAnalysis(
            endpoint=endpoint,
            status_code=200,
            response_time=0.12,
            security_score=40,
            missing_headers=["Strict-Transport-Security", "Content-Security-Policy"],
        )

        misconfig_module.security_headers_analyzer.analyze_security_headers = AsyncMock(
            return_value={endpoint: analysis}
        )

        findings = await misconfig_module._test_security_headers([endpoint])

        assert len(findings) == 1
        assert findings[0].category == "MISSING_SECURITY_HEADERS"
        assert findings[0].owasp_category == "API8"
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].method == "GET"
        assert findings[0].status_code == 200
        assert "Strict-Transport-Security" in findings[0].evidence
        assert "Content-Security-Policy" in findings[0].evidence

    @pytest.mark.asyncio
    async def test_no_missing_headers_produce_no_finding(self, misconfig_module):
        """All required headers present -> no MISSING_SECURITY_HEADERS findings"""
        endpoint = "https://api.example.com/users"
        analysis = SecurityHeadersAnalysis(
            endpoint=endpoint,
            status_code=200,
            response_time=0.1,
            security_score=100,
            missing_headers=[],
        )

        misconfig_module.security_headers_analyzer.analyze_security_headers = AsyncMock(
            return_value={endpoint: analysis}
        )

        findings = await misconfig_module._test_security_headers([endpoint])

        assert findings == []

    @pytest.mark.asyncio
    async def test_execute_tests_empty_list_returns_empty(self, misconfig_module, mock_http_client):
        """execute_tests([]) returns [] and performs no HTTP requests (Requirement 3.6)"""
        # Spy on the composed analyzers to ensure they are not invoked either
        misconfig_module.cors_analyzer.analyze_cors_policy = AsyncMock(return_value={})
        misconfig_module.security_headers_analyzer.analyze_security_headers = AsyncMock(
            return_value={}
        )

        findings = await misconfig_module.execute_tests([])

        assert findings == []
        mock_http_client.request.assert_not_called()
        misconfig_module.cors_analyzer.analyze_cors_policy.assert_not_called()
        misconfig_module.security_headers_analyzer.analyze_security_headers.assert_not_called()

    @pytest.mark.asyncio
    async def test_execute_tests_combines_cors_and_header_findings(self, misconfig_module):
        """execute_tests aggregates CORS and missing-header findings (Requirement 3.5)"""
        endpoint = MockEndpoint("https://api.example.com/users")

        permissive = CORSAnalysis(
            wildcard_origin=True,
            security_risk="HIGH",
            allowed_origins={"*"},
            allowed_methods={"GET"},
        )
        header_analysis = SecurityHeadersAnalysis(
            endpoint=endpoint.url,
            status_code=200,
            response_time=0.1,
            security_score=30,
            missing_headers=["X-Frame-Options"],
        )

        misconfig_module.cors_analyzer.analyze_cors_policy = AsyncMock(
            return_value={endpoint.url: permissive}
        )
        misconfig_module.security_headers_analyzer.analyze_security_headers = AsyncMock(
            return_value={endpoint.url: header_analysis}
        )

        findings = await misconfig_module.execute_tests([endpoint])

        categories = sorted(f.category for f in findings)
        assert categories == ["CORS_MISCONFIGURATION", "MISSING_SECURITY_HEADERS"]
        assert all(f.owasp_category == "API8" for f in findings)


if __name__ == "__main__":
    pytest.main([__file__])
