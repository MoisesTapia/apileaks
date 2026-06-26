"""
Tests for Unsafe Consumption Testing Module (OWASP API10)
"""

import pytest
from unittest.mock import Mock, AsyncMock
from dataclasses import dataclass

from modules.owasp.unsafe_consumption import UnsafeConsumptionModule
from utils.http_client import HTTPRequestEngine, Response
from core.config import UnsafeConsumptionConfig, AuthContext, AuthType, Severity


@dataclass
class MockEndpoint:
    """Mock endpoint for testing"""
    url: str
    method: str = "GET"


def make_response(status_code=200, body="", headers=None,
                  url="https://api.example.com/proxy/fetch", method="GET"):
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


class TestUnsafeConsumptionModule:
    """Test cases for the Unsafe Consumption Testing Module"""

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
        return UnsafeConsumptionModule(config, mock_http_client, auth_contexts)

    def test_module_name(self, mock_http_client, auth_contexts):
        """get_module_name() returns 'unsafe_consumption'."""
        module = self._module(UnsafeConsumptionConfig(), mock_http_client, auth_contexts)
        assert module.get_module_name() == "unsafe_consumption"

    @pytest.mark.asyncio
    async def test_reflection_detection_emits_finding(self, mock_http_client,
                                                       auth_contexts):
        """Requirements 5.3, 5.4: an upstream-sourced endpoint that reflects a
        malformed payload verbatim emits an UNSAFE_UPSTREAM_DATA / API10 HIGH
        finding."""
        payload = "<script>"
        config = UnsafeConsumptionConfig(
            upstream_indicators=["proxy"],
            malformed_payloads=[payload],
        )
        module = self._module(config, mock_http_client, auth_contexts)

        # URL contains the 'proxy' upstream indicator, and the response reflects
        # the malformed payload verbatim in its body.
        mock_http_client.request.return_value = make_response(
            status_code=200,
            body=f"upstream response echoing {payload} unsanitized",
            url="https://api.example.com/proxy/fetch",
        )

        endpoints = [MockEndpoint("https://api.example.com/proxy/fetch")]
        findings = await module.execute_tests(endpoints)

        upstream_findings = [f for f in findings
                             if f.category == "UNSAFE_UPSTREAM_DATA"]
        assert len(upstream_findings) >= 1
        finding = upstream_findings[0]
        assert finding.owasp_category == "API10"
        assert finding.severity == Severity.HIGH
        assert finding.method == "GET"
        assert payload in finding.evidence

    @pytest.mark.asyncio
    async def test_execute_tests_returns_list(self, mock_http_client, auth_contexts):
        """Requirement 5.5: execute_tests returns a list of findings."""
        config = UnsafeConsumptionConfig(
            upstream_indicators=["proxy"],
            malformed_payloads=["<script>"],
        )
        module = self._module(config, mock_http_client, auth_contexts)

        mock_http_client.request.return_value = make_response(
            status_code=200,
            body="upstream response echoing <script> unsanitized",
        )

        endpoints = [MockEndpoint("https://api.example.com/proxy/fetch")]
        findings = await module.execute_tests(endpoints)

        assert isinstance(findings, list)
        assert all(hasattr(f, "category") for f in findings)
        assert all(hasattr(f, "severity") for f in findings)
        assert all(hasattr(f, "owasp_category") for f in findings)

    @pytest.mark.asyncio
    async def test_no_finding_when_payload_not_reflected(self, mock_http_client,
                                                         auth_contexts):
        """An upstream-sourced endpoint that does NOT reflect the payload emits
        no finding."""
        config = UnsafeConsumptionConfig(
            upstream_indicators=["proxy"],
            malformed_payloads=["<script>"],
        )
        module = self._module(config, mock_http_client, auth_contexts)

        # Upstream-sourced (url indicator) but payload is not reflected/sanitized.
        mock_http_client.request.return_value = make_response(
            status_code=200,
            body="upstream response without any reflected input",
            url="https://api.example.com/proxy/fetch",
        )

        endpoints = [MockEndpoint("https://api.example.com/proxy/fetch")]
        findings = await module.execute_tests(endpoints)

        assert findings == []

    @pytest.mark.asyncio
    async def test_no_finding_when_endpoint_not_upstream_sourced(self, mock_http_client,
                                                                auth_contexts):
        """An endpoint not identified as upstream-sourced emits no finding even
        if it would reflect the payload."""
        payload = "<script>"
        config = UnsafeConsumptionConfig(
            upstream_indicators=["proxy"],
            malformed_payloads=[payload],
        )
        module = self._module(config, mock_http_client, auth_contexts)

        # No upstream indicator in URL, body, or headers -> not upstream-sourced.
        mock_http_client.request.return_value = make_response(
            status_code=200,
            body=f"plain response reflecting {payload}",
            headers={"content-type": "application/json"},
            url="https://api.example.com/users",
        )

        endpoints = [MockEndpoint("https://api.example.com/users")]
        findings = await module.execute_tests(endpoints)

        assert findings == []

    @pytest.mark.asyncio
    async def test_empty_endpoint_list_returns_empty(self, mock_http_client,
                                                     auth_contexts):
        """Requirement 5.6: an empty endpoint list returns [] with no requests."""
        module = self._module(UnsafeConsumptionConfig(), mock_http_client, auth_contexts)

        findings = await module.execute_tests([])

        assert findings == []
        mock_http_client.request.assert_not_called()


if __name__ == "__main__":
    pytest.main([__file__])
