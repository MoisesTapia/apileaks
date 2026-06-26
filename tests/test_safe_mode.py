"""
Tests for non-destructive Safe Mode behavior (Task 10.2).

Covers:
- State-changing probes (POST/PUT/PATCH/DELETE) are skipped when safe_mode is
  enabled, for the modules that honor it (SSRF, Business Flows, Unsafe
  Consumption), while non-state-changing (GET) probing still runs.
- The full set of test steps runs against state-changing endpoints when
  safe_mode is disabled.
- Metadata records safe_mode: in the JSON report scan_info, in the XML report
  scan_info, and threaded through configuration.

Validates: Requirements 10.1, 10.2, 10.3, 10.4
"""

import xml.etree.ElementTree as ET
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from unittest.mock import Mock, AsyncMock

from modules.owasp.ssrf_testing import SSRFTestingModule
from modules.owasp.business_flows import BusinessFlowsTestingModule
from modules.owasp.unsafe_consumption import UnsafeConsumptionModule
from utils.http_client import HTTPRequestEngine, Response
from utils.report_generator import ReportGenerator
from core.config import (
    SSRFConfig,
    BusinessFlowConfig,
    UnsafeConsumptionConfig,
    AuthContext,
    AuthType,
    Severity,
    ConfigurationManager,
)
from utils.findings import Finding


@dataclass
class MockEndpoint:
    """Mock endpoint for testing."""
    url: str
    method: str = "GET"


def make_response(status_code=200, body="", headers=None,
                  url="https://api.example.com/resource", method="GET"):
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


@pytest.fixture
def auth_contexts():
    return [
        AuthContext(
            name="user1",
            type=AuthType.BEARER,
            token="user1_token",
            privilege_level=1,
        )
    ]


@pytest.fixture
def mock_http_client():
    client = Mock(spec=HTTPRequestEngine)
    client.request = AsyncMock()
    client.set_auth_context = Mock()
    return client


class TestSSRFSafeMode:
    """Safe Mode behavior for the SSRF module (API7)."""

    @pytest.mark.asyncio
    async def test_state_changing_endpoint_skipped_when_safe_mode_enabled(
            self, mock_http_client, auth_contexts):
        """Requirement 10.2: a POST (state-changing) endpoint is skipped
        entirely in safe mode - no requests are issued and no findings emitted."""
        config = SSRFConfig(internal_targets=["169.254.169.254"], file_protocols=[])
        config.safe_mode = True
        module = SSRFTestingModule(config, mock_http_client, auth_contexts)
        assert module.safe_mode is True

        endpoints = [MockEndpoint("https://api.example.com/import", method="POST")]
        findings = await module.execute_tests(endpoints)

        assert findings == []
        mock_http_client.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_full_probing_runs_when_safe_mode_disabled(
            self, mock_http_client, auth_contexts):
        """Requirement 10.1: with safe mode disabled, the same POST endpoint is
        probed (state-changing steps run)."""
        config = SSRFConfig(internal_targets=["169.254.169.254"], file_protocols=[])
        config.safe_mode = False
        module = SSRFTestingModule(config, mock_http_client, auth_contexts)

        mock_http_client.request.return_value = make_response(
            status_code=200, body="ami-id\ninstance-id\niam/security-credentials",
        )

        endpoints = [MockEndpoint("https://api.example.com/import", method="POST")]
        findings = await module.execute_tests(endpoints)

        assert mock_http_client.request.call_count > 0
        # The POST probes were issued with the original (state-changing) method.
        assert all(call.args[0] == "POST" for call in mock_http_client.request.call_args_list)
        assert any(f.category == "SSRF_INTERNAL_ACCESS" for f in findings)

    @pytest.mark.asyncio
    async def test_safe_method_still_probed_when_safe_mode_enabled(
            self, mock_http_client, auth_contexts):
        """Requirement 10.3: non-state-changing (GET) endpoints are still probed
        in safe mode - safe mode does not disable benign testing."""
        config = SSRFConfig(internal_targets=["169.254.169.254"], file_protocols=[])
        config.safe_mode = True
        module = SSRFTestingModule(config, mock_http_client, auth_contexts)

        mock_http_client.request.return_value = make_response(
            status_code=200, body="meta-data\nlocal-hostname",
        )

        endpoints = [MockEndpoint("https://api.example.com/fetch", method="GET")]
        findings = await module.execute_tests(endpoints)

        assert mock_http_client.request.call_count > 0
        assert all(call.args[0] == "GET" for call in mock_http_client.request.call_args_list)
        assert any(f.category == "SSRF_INTERNAL_ACCESS" for f in findings)


class TestBusinessFlowsSafeMode:
    """Safe Mode behavior for the Business Flows module (API6)."""

    @pytest.mark.asyncio
    async def test_state_changing_flow_skipped_when_safe_mode_enabled(
            self, mock_http_client, auth_contexts):
        """Requirement 10.2: a POST sensitive-flow endpoint is skipped in safe
        mode - no requests issued, no findings emitted."""
        config = BusinessFlowConfig(
            sensitive_flow_patterns=["/checkout"],
            repetition_limit=5,
        )
        config.safe_mode = True
        module = BusinessFlowsTestingModule(config, mock_http_client, auth_contexts)
        assert module.safe_mode is True

        endpoints = [MockEndpoint("https://api.example.com/checkout", method="POST")]
        findings = await module.execute_tests(endpoints)

        assert findings == []
        mock_http_client.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_full_repetition_runs_when_safe_mode_disabled(
            self, mock_http_client, auth_contexts):
        """Requirement 10.1: with safe mode disabled, the POST sensitive flow is
        probed up to repetition_limit and a finding is emitted when unthrottled."""
        config = BusinessFlowConfig(
            sensitive_flow_patterns=["/checkout"],
            repetition_limit=5,
        )
        config.safe_mode = False
        module = BusinessFlowsTestingModule(config, mock_http_client, auth_contexts)

        mock_http_client.request.return_value = make_response(status_code=200)

        endpoints = [MockEndpoint("https://api.example.com/checkout", method="POST")]
        findings = await module.execute_tests(endpoints)

        assert mock_http_client.request.call_count == 5
        assert any(f.category == "BUSINESS_FLOW_NO_LIMIT" for f in findings)

    @pytest.mark.asyncio
    async def test_safe_method_flow_still_probed_when_safe_mode_enabled(
            self, mock_http_client, auth_contexts):
        """Requirement 10.3: a GET sensitive flow is still probed in safe mode."""
        config = BusinessFlowConfig(
            sensitive_flow_patterns=["/checkout"],
            repetition_limit=4,
        )
        config.safe_mode = True
        module = BusinessFlowsTestingModule(config, mock_http_client, auth_contexts)

        mock_http_client.request.return_value = make_response(status_code=200)

        endpoints = [MockEndpoint("https://api.example.com/checkout", method="GET")]
        await module.execute_tests(endpoints)

        assert mock_http_client.request.call_count == 4
        assert all(call.args[0] == "GET" for call in mock_http_client.request.call_args_list)


class TestUnsafeConsumptionSafeMode:
    """Safe Mode behavior for the Unsafe Consumption module (API10)."""

    @pytest.mark.asyncio
    async def test_state_changing_endpoint_skipped_when_safe_mode_enabled(
            self, mock_http_client, auth_contexts):
        """Requirement 10.2: a POST upstream endpoint is skipped in safe mode -
        no requests issued, no findings emitted."""
        payload = "<script>"
        config = UnsafeConsumptionConfig(
            upstream_indicators=["proxy"],
            malformed_payloads=[payload],
        )
        config.safe_mode = True
        module = UnsafeConsumptionModule(config, mock_http_client, auth_contexts)
        assert module.safe_mode is True

        endpoints = [MockEndpoint("https://api.example.com/proxy/fetch", method="POST")]
        findings = await module.execute_tests(endpoints)

        assert findings == []
        mock_http_client.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_full_probing_runs_when_safe_mode_disabled(
            self, mock_http_client, auth_contexts):
        """Requirement 10.1: with safe mode disabled, the POST upstream endpoint
        is probed (baseline + payloads) and reflection is detected."""
        payload = "<script>"
        config = UnsafeConsumptionConfig(
            upstream_indicators=["proxy"],
            malformed_payloads=[payload],
        )
        config.safe_mode = False
        module = UnsafeConsumptionModule(config, mock_http_client, auth_contexts)

        mock_http_client.request.return_value = make_response(
            status_code=200,
            body=f"upstream proxy response echoing {payload} unsanitized",
            url="https://api.example.com/proxy/fetch",
        )

        endpoints = [MockEndpoint("https://api.example.com/proxy/fetch", method="POST")]
        findings = await module.execute_tests(endpoints)

        assert mock_http_client.request.call_count > 0
        assert any(f.category == "UNSAFE_UPSTREAM_DATA" for f in findings)

    @pytest.mark.asyncio
    async def test_safe_method_endpoint_still_probed_when_safe_mode_enabled(
            self, mock_http_client, auth_contexts):
        """Requirement 10.3: a GET upstream endpoint is still probed in safe
        mode, using query injection only (no state-changing body probes)."""
        payload = "<script>"
        config = UnsafeConsumptionConfig(
            upstream_indicators=["proxy"],
            malformed_payloads=[payload],
        )
        config.safe_mode = True
        module = UnsafeConsumptionModule(config, mock_http_client, auth_contexts)

        mock_http_client.request.return_value = make_response(
            status_code=200,
            body=f"upstream proxy response echoing {payload} unsanitized",
            url="https://api.example.com/proxy/fetch",
        )

        endpoints = [MockEndpoint("https://api.example.com/proxy/fetch", method="GET")]
        findings = await module.execute_tests(endpoints)

        assert mock_http_client.request.call_count > 0
        # All probes use the safe GET method; no state-changing method is issued.
        assert all(call.args[0] == "GET" for call in mock_http_client.request.call_args_list)
        assert any(f.category == "UNSAFE_UPSTREAM_DATA" for f in findings)


# --- Metadata recording -----------------------------------------------------

def _make_results(safe_mode):
    """Build a minimal results object the report generators can consume,
    including a configuration namespace carrying safe_mode."""
    now = datetime.now()
    findings = [
        Finding(
            id=str(uuid4()),
            scan_id="scan-1",
            category="SSRF_INTERNAL_ACCESS",
            owasp_category="API7",
            severity=Severity.HIGH,
            endpoint="/api/fetch",
            method="GET",
            status_code=200,
            response_size=100,
            response_time=0.1,
            evidence="evidence",
            recommendation="fix it",
        )
    ]
    statistics = SimpleNamespace(
        findings_count=len(findings),
        critical_findings=0,
        high_findings=1,
        medium_findings=0,
        low_findings=0,
        info_findings=0,
        total_requests=10,
        endpoints_discovered=2,
    )
    performance_metrics = SimpleNamespace(
        duration=timedelta(seconds=5),
        requests_per_second=2.0,
        average_response_time=0.1,
        start_time=now,
        end_time=now + timedelta(seconds=5),
    )
    return SimpleNamespace(
        scan_id="scan-1",
        target_url="https://api.example.com",
        timestamp=now,
        statistics=statistics,
        performance_metrics=performance_metrics,
        findings=findings,
        discovered_endpoints=[],
        configuration=SimpleNamespace(safe_mode=safe_mode),
    )


class TestSafeModeMetadata:
    """Requirement 10.4: scan output / report metadata records safe_mode."""

    @pytest.mark.parametrize("safe_mode", [True, False])
    def test_json_report_records_safe_mode(self, safe_mode):
        results = _make_results(safe_mode)
        doc = json.loads(ReportGenerator().generate_json_report(results))
        assert doc["scan_info"]["safe_mode"] is safe_mode

    @pytest.mark.parametrize("safe_mode,expected", [(True, "true"), (False, "false")])
    def test_xml_report_records_safe_mode(self, safe_mode, expected):
        results = _make_results(safe_mode)
        xml = ReportGenerator().generate_xml_report(results)
        root = ET.fromstring(xml)
        # Element is namespaced; search by local tag name.
        safe_mode_texts = [el.text for el in root.iter()
                           if el.tag.endswith("safe_mode")]
        assert safe_mode_texts == [expected]

    def test_safe_mode_threaded_through_configuration_from_dict(self):
        """Requirement 10.4: safe_mode flows from config into APILeakConfig."""
        manager = ConfigurationManager()

        cfg_enabled = manager.load_config_from_dict({
            "target": {"base_url": "https://api.example.com"},
            "safe_mode": True,
        })
        assert cfg_enabled.safe_mode is True

        cfg_default = manager.load_config_from_dict({
            "target": {"base_url": "https://api.example.com"},
        })
        assert cfg_default.safe_mode is False


if __name__ == "__main__":
    pytest.main([__file__])
