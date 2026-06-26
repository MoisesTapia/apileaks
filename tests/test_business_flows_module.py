"""
Tests for Business Flows Testing Module (OWASP API6)
"""

import pytest
from unittest.mock import Mock, AsyncMock
from dataclasses import dataclass

from modules.owasp.business_flows import BusinessFlowsTestingModule
from utils.http_client import HTTPRequestEngine, Response
from core.config import BusinessFlowConfig, AuthContext, AuthType, Severity


@dataclass
class MockEndpoint:
    """Mock endpoint for testing"""
    url: str
    method: str = "GET"


def make_response(status_code=200, body="", headers=None,
                  url="https://api.example.com/checkout", method="GET"):
    """Helper to build a Response with consistent text/content."""
    content = body.encode("utf-8")
    return Response(
        status_code=status_code,
        headers=headers if headers is not None else {"content-type": "application/json"},
        content=content,
        text=body,
        url=url,
        elapsed=0.1,
        request_method=method,
    )


class TestBusinessFlowsTestingModule:
    """Test cases for the Business Flows Testing Module"""

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
        return BusinessFlowsTestingModule(config, mock_http_client, auth_contexts)

    def test_module_name(self, mock_http_client, auth_contexts):
        """get_module_name() returns 'business_flow'."""
        module = self._module(BusinessFlowConfig(), mock_http_client, auth_contexts)
        assert module.get_module_name() == "business_flow"

    @pytest.mark.asyncio
    async def test_repetition_up_to_limit(self, mock_http_client, auth_contexts):
        """Requirement 2.3: repeated requests are issued up to repetition_limit
        against a sensitive-flow endpoint."""
        config = BusinessFlowConfig(
            sensitive_flow_patterns=["/checkout"],
            repetition_limit=5,
        )
        module = self._module(config, mock_http_client, auth_contexts)

        # Always-unthrottled 200 responses with no rate-limit headers.
        mock_http_client.request.return_value = make_response(status_code=200)

        endpoints = [MockEndpoint("https://api.example.com/checkout")]
        await module.execute_tests(endpoints)

        assert mock_http_client.request.call_count == 5

    @pytest.mark.asyncio
    async def test_finding_emitted_when_unthrottled(self, mock_http_client,
                                                    auth_contexts):
        """Requirement 2.4: unthrottled repeated requests emit a
        BUSINESS_FLOW_NO_LIMIT / API6 HIGH finding."""
        config = BusinessFlowConfig(
            sensitive_flow_patterns=["/checkout"],
            repetition_limit=10,
        )
        module = self._module(config, mock_http_client, auth_contexts)

        mock_http_client.request.return_value = make_response(status_code=200)

        endpoints = [MockEndpoint("https://api.example.com/checkout")]
        findings = await module.execute_tests(endpoints)

        flow_findings = [f for f in findings
                         if f.category == "BUSINESS_FLOW_NO_LIMIT"]
        assert len(flow_findings) == 1
        finding = flow_findings[0]
        assert finding.owasp_category == "API6"
        assert finding.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_no_finding_when_rate_limited_429(self, mock_http_client,
                                                    auth_contexts):
        """No finding is emitted when an HTTP 429 is observed."""
        config = BusinessFlowConfig(
            sensitive_flow_patterns=["/checkout"],
            repetition_limit=10,
        )
        module = self._module(config, mock_http_client, auth_contexts)

        mock_http_client.request.return_value = make_response(status_code=429,
                                                              body="Too Many Requests")

        endpoints = [MockEndpoint("https://api.example.com/checkout")]
        findings = await module.execute_tests(endpoints)

        assert findings == []

    @pytest.mark.asyncio
    async def test_no_finding_when_rate_limit_headers_present(self, mock_http_client,
                                                              auth_contexts):
        """No finding is emitted when anti-automation headers are present."""
        config = BusinessFlowConfig(
            sensitive_flow_patterns=["/checkout"],
            repetition_limit=10,
        )
        module = self._module(config, mock_http_client, auth_contexts)

        mock_http_client.request.return_value = make_response(
            status_code=200,
            headers={"content-type": "application/json", "X-RateLimit-Remaining": "0"},
        )

        endpoints = [MockEndpoint("https://api.example.com/checkout")]
        findings = await module.execute_tests(endpoints)

        assert findings == []

    @pytest.mark.asyncio
    async def test_non_sensitive_endpoint_skipped(self, mock_http_client,
                                                  auth_contexts):
        """Endpoints that do not match a sensitive-flow pattern are skipped."""
        config = BusinessFlowConfig(
            sensitive_flow_patterns=["/checkout"],
            repetition_limit=5,
        )
        module = self._module(config, mock_http_client, auth_contexts)

        mock_http_client.request.return_value = make_response(status_code=200)

        endpoints = [MockEndpoint("https://api.example.com/users")]
        findings = await module.execute_tests(endpoints)

        assert findings == []
        mock_http_client.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_execute_tests_returns_list(self, mock_http_client, auth_contexts):
        """Requirement 2.5: execute_tests returns a list of findings."""
        config = BusinessFlowConfig(
            sensitive_flow_patterns=["/checkout"],
            repetition_limit=3,
        )
        module = self._module(config, mock_http_client, auth_contexts)

        mock_http_client.request.return_value = make_response(status_code=200)

        endpoints = [MockEndpoint("https://api.example.com/checkout")]
        findings = await module.execute_tests(endpoints)

        assert isinstance(findings, list)
        assert all(hasattr(f, "category") for f in findings)
        assert all(hasattr(f, "owasp_category") for f in findings)

    @pytest.mark.asyncio
    async def test_empty_endpoint_list_returns_empty(self, mock_http_client,
                                                     auth_contexts):
        """Requirement 2.6: an empty endpoint list returns [] with no requests."""
        module = self._module(BusinessFlowConfig(), mock_http_client, auth_contexts)

        findings = await module.execute_tests([])

        assert findings == []
        mock_http_client.request.assert_not_called()


if __name__ == "__main__":
    pytest.main([__file__])
