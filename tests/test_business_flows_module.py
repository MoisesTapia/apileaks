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

    @pytest.mark.asyncio
    async def test_retry_after_header_suppresses_finding(self, mock_http_client,
                                                         auth_contexts):
        """Retry-After header is recognised as an anti-automation control."""
        config = BusinessFlowConfig(
            sensitive_flow_patterns=["/checkout"],
            repetition_limit=5,
        )
        module = self._module(config, mock_http_client, auth_contexts)

        mock_http_client.request.return_value = make_response(
            status_code=200,
            headers={"content-type": "application/json", "Retry-After": "60"},
        )

        findings = await module.execute_tests(
            [MockEndpoint("https://api.example.com/checkout")]
        )
        assert findings == []

    @pytest.mark.asyncio
    async def test_new_sensitive_patterns_respected(self, mock_http_client,
                                                    auth_contexts):
        """New built-in patterns like /booking and /referral are matched."""
        config = BusinessFlowConfig(
            sensitive_flow_patterns=["/referral"],
            repetition_limit=3,
        )
        module = self._module(config, mock_http_client, auth_contexts)
        mock_http_client.request.return_value = make_response(status_code=200)

        findings = await module.execute_tests(
            [MockEndpoint("https://api.example.com/referral/create")]
        )
        assert mock_http_client.request.call_count == 3
        assert any(f.category == "BUSINESS_FLOW_NO_LIMIT" for f in findings)


class TestQuotaDecrementDetector:
    """Tests for Detector 2 — quota / resource decrement (BUSINESS_FLOW_QUOTA_NOT_ENFORCED)."""

    @pytest.fixture
    def auth_contexts(self):
        return [AuthContext(name="u1", type=AuthType.BEARER,
                            token="tok", privilege_level=1)]

    @pytest.fixture
    def mock_http_client(self):
        client = Mock(spec=HTTPRequestEngine)
        client.request = AsyncMock()
        client.set_auth_context = Mock()
        return client

    def _module(self, config, mock_http_client, auth_contexts):
        return BusinessFlowsTestingModule(config, mock_http_client, auth_contexts)

    @pytest.mark.asyncio
    async def test_quota_not_enforced_emits_finding(self, mock_http_client,
                                                    auth_contexts):
        """When the 'stock' field stays constant across N requests,
        BUSINESS_FLOW_QUOTA_NOT_ENFORCED / API6 / HIGH is emitted."""
        config = BusinessFlowConfig(
            sensitive_flow_patterns=["/purchase"],
            repetition_limit=3,
            check_quota_decrement=True,
            quota_fields=["stock"],
        )
        module = self._module(config, mock_http_client, auth_contexts)

        # stock = 100 on every response → quota never decremented
        mock_http_client.request.return_value = make_response(
            status_code=200,
            body='{"item": "console", "stock": 100}',
        )

        findings = await module.execute_tests(
            [MockEndpoint("https://api.example.com/purchase")]
        )

        quota_findings = [f for f in findings
                          if f.category == "BUSINESS_FLOW_QUOTA_NOT_ENFORCED"]
        assert len(quota_findings) == 1
        f = quota_findings[0]
        assert f.owasp_category == "API6"
        assert f.severity == Severity.HIGH
        assert "stock" in f.evidence

    @pytest.mark.asyncio
    async def test_no_quota_finding_when_value_decrements(self, mock_http_client,
                                                          auth_contexts):
        """When 'remaining' decreases between first and last response,
        no BUSINESS_FLOW_QUOTA_NOT_ENFORCED is emitted."""
        config = BusinessFlowConfig(
            sensitive_flow_patterns=["/purchase"],
            repetition_limit=3,
            check_quota_decrement=True,
            quota_fields=["remaining"],
        )
        module = self._module(config, mock_http_client, auth_contexts)

        # Responses: remaining=10, remaining=9, remaining=8 — decrement confirmed
        mock_http_client.request.side_effect = [
            make_response(status_code=200, body='{"remaining": 10}'),
            make_response(status_code=200, body='{"remaining": 9}'),
            make_response(status_code=200, body='{"remaining": 8}'),
        ]

        findings = await module.execute_tests(
            [MockEndpoint("https://api.example.com/purchase")]
        )
        assert not any(f.category == "BUSINESS_FLOW_QUOTA_NOT_ENFORCED"
                       for f in findings)

    @pytest.mark.asyncio
    async def test_quota_check_disabled_skips_detector(self, mock_http_client,
                                                       auth_contexts):
        """When check_quota_decrement=False, the detector is never triggered."""
        config = BusinessFlowConfig(
            sensitive_flow_patterns=["/purchase"],
            repetition_limit=3,
            check_quota_decrement=False,
            quota_fields=["stock"],
        )
        module = self._module(config, mock_http_client, auth_contexts)

        mock_http_client.request.return_value = make_response(
            status_code=200,
            body='{"stock": 100}',
        )

        findings = await module.execute_tests(
            [MockEndpoint("https://api.example.com/purchase")]
        )
        assert not any(f.category == "BUSINESS_FLOW_QUOTA_NOT_ENFORCED"
                       for f in findings)

    @pytest.mark.asyncio
    async def test_quota_nested_field_detected(self, mock_http_client, auth_contexts):
        """A quota field nested one level deep is still found and checked."""
        config = BusinessFlowConfig(
            sensitive_flow_patterns=["/reserve"],
            repetition_limit=2,
            check_quota_decrement=True,
            quota_fields=["seats"],
        )
        module = self._module(config, mock_http_client, auth_contexts)

        # 'seats' nested under 'availability' — same value both times
        mock_http_client.request.return_value = make_response(
            status_code=200,
            body='{"flight": "AA123", "availability": {"seats": 50}}',
        )

        findings = await module.execute_tests(
            [MockEndpoint("https://api.example.com/reserve")]
        )
        assert any(f.category == "BUSINESS_FLOW_QUOTA_NOT_ENFORCED"
                   for f in findings)

    @pytest.mark.asyncio
    async def test_quota_field_absent_in_response_no_finding(self, mock_http_client,
                                                              auth_contexts):
        """When the configured quota field is absent from the response body,
        no BUSINESS_FLOW_QUOTA_NOT_ENFORCED is emitted."""
        config = BusinessFlowConfig(
            sensitive_flow_patterns=["/purchase"],
            repetition_limit=3,
            check_quota_decrement=True,
            quota_fields=["stock"],
        )
        module = self._module(config, mock_http_client, auth_contexts)

        # Response has no 'stock' field
        mock_http_client.request.return_value = make_response(
            status_code=200,
            body='{"order_id": "abc-123", "status": "placed"}',
        )

        findings = await module.execute_tests(
            [MockEndpoint("https://api.example.com/purchase")]
        )
        assert not any(f.category == "BUSINESS_FLOW_QUOTA_NOT_ENFORCED"
                       for f in findings)


class TestMultiStepFlowDetector:
    """Tests for Detector 3 — multi-step flow bypass (BUSINESS_FLOW_MULTI_STEP_BYPASS)."""

    @pytest.fixture
    def auth_contexts(self):
        return [AuthContext(name="u1", type=AuthType.BEARER,
                            token="tok", privilege_level=1)]

    @pytest.fixture
    def mock_http_client(self):
        client = Mock(spec=HTTPRequestEngine)
        client.request = AsyncMock()
        client.set_auth_context = Mock()
        return client

    def _make_flow(self, name, steps):
        """Build a SimpleNamespace that looks like a MultiStepFlow."""
        from types import SimpleNamespace
        return SimpleNamespace(name=name, steps=steps)

    def _module(self, config, mock_http_client, auth_contexts):
        return BusinessFlowsTestingModule(config, mock_http_client, auth_contexts)

    @pytest.mark.asyncio
    async def test_multi_step_bypass_emits_finding(self, mock_http_client,
                                                   auth_contexts):
        """When a 2-step flow completes N times without controls,
        BUSINESS_FLOW_MULTI_STEP_BYPASS / API6 / HIGH is emitted."""
        flow = self._make_flow("scalping_flow", [
            {"method": "POST", "path": "https://api.example.com/cart/add"},
            {"method": "POST", "path": "https://api.example.com/checkout"},
        ])
        config = BusinessFlowConfig(
            sensitive_flow_patterns=[],
            repetition_limit=3,
            multi_step_flows=[flow],
        )
        module = self._module(config, mock_http_client, auth_contexts)

        mock_http_client.request.return_value = make_response(status_code=200)

        findings = await module.execute_tests([])

        step_findings = [f for f in findings
                         if f.category == "BUSINESS_FLOW_MULTI_STEP_BYPASS"]
        assert len(step_findings) == 1
        f = step_findings[0]
        assert f.owasp_category == "API6"
        assert f.severity == Severity.HIGH
        assert "scalping_flow" in f.evidence
        # 3 iterations × 2 steps = 6 requests
        assert mock_http_client.request.call_count == 6

    @pytest.mark.asyncio
    async def test_multi_step_no_finding_when_429_on_step(self, mock_http_client,
                                                           auth_contexts):
        """A 429 on any step stops the sequence and suppresses the finding."""
        flow = self._make_flow("checkout_flow", [
            {"method": "POST", "path": "https://api.example.com/cart/add"},
            {"method": "POST", "path": "https://api.example.com/checkout"},
        ])
        config = BusinessFlowConfig(
            sensitive_flow_patterns=[],
            repetition_limit=5,
            multi_step_flows=[flow],
        )
        module = self._module(config, mock_http_client, auth_contexts)

        # First step succeeds, second returns 429
        mock_http_client.request.side_effect = [
            make_response(status_code=200),
            make_response(status_code=429),
        ]

        findings = await module.execute_tests([])
        assert not any(f.category == "BUSINESS_FLOW_MULTI_STEP_BYPASS"
                       for f in findings)

    @pytest.mark.asyncio
    async def test_multi_step_no_finding_when_step_returns_4xx(self,
                                                                mock_http_client,
                                                                auth_contexts):
        """A 4xx (non-429) on any step means the iteration failed — if no iteration
        succeeds, no finding is emitted."""
        flow = self._make_flow("booking_flow", [
            {"method": "POST", "path": "https://api.example.com/reserve"},
            {"method": "POST", "path": "https://api.example.com/confirm"},
        ])
        config = BusinessFlowConfig(
            sensitive_flow_patterns=[],
            repetition_limit=3,
            multi_step_flows=[flow],
        )
        module = self._module(config, mock_http_client, auth_contexts)

        # Second step always 403 — no iteration ever completes
        mock_http_client.request.side_effect = [
            make_response(status_code=200),
            make_response(status_code=403),
        ] * 3

        findings = await module.execute_tests([])
        assert not any(f.category == "BUSINESS_FLOW_MULTI_STEP_BYPASS"
                       for f in findings)

    @pytest.mark.asyncio
    async def test_empty_steps_flow_is_skipped(self, mock_http_client, auth_contexts):
        """A flow with no steps is silently skipped — no requests, no findings."""
        flow = self._make_flow("empty_flow", [])
        config = BusinessFlowConfig(
            sensitive_flow_patterns=[],
            repetition_limit=3,
            multi_step_flows=[flow],
        )
        module = self._module(config, mock_http_client, auth_contexts)

        findings = await module.execute_tests([])

        assert findings == []
        mock_http_client.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_multi_step_safe_mode_skips_post_steps(self, mock_http_client,
                                                          auth_contexts):
        """In safe mode, state-changing steps are skipped — iterations never
        complete, so no BUSINESS_FLOW_MULTI_STEP_BYPASS is emitted."""
        flow = self._make_flow("purchase_flow", [
            {"method": "POST", "path": "https://api.example.com/cart/add"},
            {"method": "POST", "path": "https://api.example.com/checkout"},
        ])
        config = BusinessFlowConfig(
            sensitive_flow_patterns=[],
            repetition_limit=3,
            multi_step_flows=[flow],
        )
        config.safe_mode = True
        module = self._module(config, mock_http_client, auth_contexts)

        findings = await module.execute_tests([])

        assert not any(f.category == "BUSINESS_FLOW_MULTI_STEP_BYPASS"
                       for f in findings)
        mock_http_client.request.assert_not_called()


if __name__ == "__main__":
    pytest.main([__file__])
