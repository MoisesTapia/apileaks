"""
Tests for SSRF Testing Module (OWASP API7)
"""

import pytest
from unittest.mock import Mock, AsyncMock
from dataclasses import dataclass

from modules.owasp.ssrf_testing import SSRFTestingModule
from utils.http_client import HTTPRequestEngine, Response
from core.config import SSRFConfig, AuthContext, AuthType, Severity


@dataclass
class MockEndpoint:
    """Mock endpoint for testing"""
    url: str
    method: str = "GET"


def make_response(status_code=200, body="", url="https://api.example.com/fetch",
                  method="GET"):
    """Helper to build a Response with consistent text/content."""
    content = body.encode("utf-8")
    return Response(
        status_code=status_code,
        headers={"content-type": "text/plain"},
        content=content,
        text=body,
        url=url,
        elapsed=0.1,
        request_method=method,
    )


class TestSSRFTestingModule:
    """Test cases for the SSRF Testing Module"""

    @pytest.fixture
    def auth_contexts(self):
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
        client = Mock(spec=HTTPRequestEngine)
        client.request = AsyncMock()
        client.set_auth_context = Mock()
        return client

    def _module(self, config, mock_http_client, auth_contexts):
        return SSRFTestingModule(config, mock_http_client, auth_contexts)

    def test_module_initialization(self, mock_http_client, auth_contexts):
        """Module reports the correct name and stores auth contexts."""
        module = self._module(SSRFConfig(), mock_http_client, auth_contexts)
        assert module.get_module_name() == "ssrf"
        assert len(module.auth_contexts) == len(auth_contexts)

    @pytest.mark.asyncio
    async def test_internal_target_hit_produces_finding(self, mock_http_client,
                                                         auth_contexts):
        """Requirement 1.4: reaching an injected internal target emits
        SSRF_INTERNAL_ACCESS."""
        config = SSRFConfig(internal_targets=["169.254.169.254"], file_protocols=[])
        module = self._module(config, mock_http_client, auth_contexts)

        # Response body contains cloud-metadata signature and a 2xx status.
        mock_http_client.request.return_value = make_response(
            status_code=200,
            body="ami-id\ninstance-id\niam/security-credentials",
        )

        endpoints = [MockEndpoint("https://api.example.com/fetch")]
        findings = await module.execute_tests(endpoints)

        internal_findings = [f for f in findings
                             if f.category == "SSRF_INTERNAL_ACCESS"]
        assert len(internal_findings) >= 1
        finding = internal_findings[0]
        assert finding.owasp_category == "API7"
        assert finding.severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_file_protocol_hit_produces_finding(self, mock_http_client,
                                                       auth_contexts):
        """Requirement 1.5: an injected file-protocol value returning file
        system content emits FILE_PROTOCOL_ACCESS."""
        config = SSRFConfig(internal_targets=[], file_protocols=["file://"])
        module = self._module(config, mock_http_client, auth_contexts)

        # Response body contains /etc/passwd content signature.
        mock_http_client.request.return_value = make_response(
            status_code=200,
            body="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        )

        endpoints = [MockEndpoint("https://api.example.com/fetch")]
        findings = await module.execute_tests(endpoints)

        file_findings = [f for f in findings
                         if f.category == "FILE_PROTOCOL_ACCESS"]
        assert len(file_findings) >= 1
        finding = file_findings[0]
        assert finding.owasp_category == "API7"
        assert finding.severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_execute_tests_returns_list_of_findings(self, mock_http_client,
                                                           auth_contexts):
        """Requirement 1.6: execute_tests returns a list of findings."""
        config = SSRFConfig(internal_targets=["169.254.169.254"], file_protocols=[])
        module = self._module(config, mock_http_client, auth_contexts)

        mock_http_client.request.return_value = make_response(
            status_code=200, body="meta-data\nlocal-hostname",
        )

        endpoints = [MockEndpoint("https://api.example.com/fetch")]
        findings = await module.execute_tests(endpoints)

        assert isinstance(findings, list)
        assert all(hasattr(f, "category") for f in findings)
        assert all(hasattr(f, "severity") for f in findings)
        assert all(hasattr(f, "owasp_category") for f in findings)

    @pytest.mark.asyncio
    async def test_no_finding_when_no_signature_and_non_2xx(self, mock_http_client,
                                                            auth_contexts):
        """A benign 404 with no signatures produces no SSRF findings."""
        config = SSRFConfig(internal_targets=["169.254.169.254"],
                            file_protocols=["file://"])
        module = self._module(config, mock_http_client, auth_contexts)

        mock_http_client.request.return_value = make_response(
            status_code=404, body="Not Found",
        )

        endpoints = [MockEndpoint("https://api.example.com/fetch")]
        findings = await module.execute_tests(endpoints)

        assert findings == []

    @pytest.mark.asyncio
    async def test_empty_endpoint_list_returns_empty(self, mock_http_client,
                                                     auth_contexts):
        """Requirement 1.7: an empty endpoint list returns [] with no requests."""
        module = self._module(SSRFConfig(), mock_http_client, auth_contexts)

        findings = await module.execute_tests([])

        assert findings == []
        mock_http_client.request.assert_not_called()


if __name__ == "__main__":
    pytest.main([__file__])
