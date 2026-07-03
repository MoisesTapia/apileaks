"""
End-to-end test exercising all ten OWASP detection modules (API1-API10).

This test stands up a mock vulnerable API (a programmable HTTP stub) that exposes
one or more vulnerable endpoints covering every OWASP API Security Top 10 2023
category, runs a "full" OWASP scan with all ten modules enabled through the real
engine (registration, execution, FindingsCollector classification, OWASP coverage),
and asserts that:

  * all ten OWASP modules register and execute without a "module not registered"
    warning (Requirements 6.1, 6.2);
  * each detection module produces at least its expected Finding_Category
    (Requirements 1.4, 2.4, 3.3, 4.3, 5.4);
  * OWASP coverage reports 10/10 categories, including API6-API10 produced by the
    new modules (Requirement 7.4);
  * findings flow into the JSON and SARIF reports, with the SARIF document
    containing one result per finding (Requirement 8.2).

The HTTP layer is the only thing mocked: a single ``VulnerableMockHTTPClient`` is
patched in for ``utils.http_client.HTTPRequestEngine`` so every module and reused
advanced analyzer (CORS analyzer, security-headers analyzer, version fuzzer) talks
to the same crafted "vulnerable" target. All real engine wiring, module logic,
classification, coverage math, and report generation run unmodified.

Validates: Requirements 1.4, 2.4, 3.3, 4.3, 5.4, 6.1, 6.2, 7.4, 8.2
"""

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from core.engine import APILeakCore
from core.config import (
    APILeakConfig,
    TargetConfig,
    FuzzingConfig,
    OWASPConfig,
    AuthConfig,
    AuthContext,
    AuthType,
    RateLimitConfig,
    ReportConfig,
    AdvancedDiscoveryConfig,
    ResourceTestingConfig,
    Severity,
)
from utils.http_client import Response
from utils.report_generator import ReportGenerator


# The full set of OWASP module-name keys the engine must register/execute.
EXPECTED_OWASP_MODULES = [
    "bola",
    "auth",
    "property",
    "function_auth",
    "resource",
    "ssrf",
    "business_flow",
    "security_misconfig",
    "inventory",
    "unsafe_consumption",
]


@dataclass
class MockEndpoint:
    """Endpoint stub matching the attributes the modules and report generator read.

    The OWASP modules only read ``url``/``method``; the report generator also reads
    ``status_code``/``response_size``/``response_time`` when serializing discovered
    endpoints, so those are provided with sensible defaults.
    """
    url: str
    method: str = "GET"
    status_code: int = 200
    response_size: int = 256
    response_time: float = 0.01


# Signature strings that make the mock target look maximally vulnerable to the
# signature-based detectors (SSRF internal access, file-protocol access, upstream
# consumption, deprecated/undocumented inventory). Carefully avoids tokens that
# the accessibility heuristics treat as "not accessible" (error/forbidden/etc.).
_VULN_SIGNATURES = (
    "ami-id instance-id instance-action iam/security-credentials meta-data "
    "computeMetadata metadata.google.internal access_token security-credentials "
    "local-hostname public-ipv4 "
    "root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin "
    "nobody:x: "
    "api version deprecated sunset legacy "
    "upstream proxy external aggregate"
)


class VulnerableMockHTTPClient:
    """A programmable stand-in for HTTPRequestEngine that serves a single, highly
    vulnerable response to every request.

    Accepts (and ignores) the real engine constructor arguments so it can be
    patched in for ``HTTPRequestEngine`` transparently. Reflects any injected
    query/body values back into the response body so reflection-based detectors
    (e.g. Unsafe Consumption) fire.
    """

    def __init__(self, *args, **kwargs):
        # Mirror the public attributes that modules read/assign.
        self.current_auth_context = None
        self.auth_contexts = {}
        self.request_count = 0

    # --- auth context plumbing used by the modules -------------------------
    def set_auth_context(self, auth):
        self.current_auth_context = auth

    def add_auth_context(self, name, auth):
        self.auth_contexts[name] = auth

    # --- the single behaviour that matters ---------------------------------
    async def request(self, method, url, **kwargs):
        self.request_count += 1

        # Represent a genuinely BOLA-vulnerable target: a clearly-invalid object
        # id (the negative-control sentinel "0") returns not-found, so the
        # endpoint is *discriminating*. Valid object ids return real data that is
        # accessible without proper authorization. This keeps the target
        # genuinely vulnerable under the hardened BOLA negative-control logic
        # (Requirements 3, 25) rather than answering success for every input
        # (which is correctly suppressed as non-discriminating).
        last_segment = url.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
        if last_segment == "0":
            not_found = json.dumps({"message": "object not found"})
            return Response(
                status_code=404,
                headers={"content-type": "application/json"},
                content=not_found.encode("utf-8"),
                text=not_found,
                url=url,
                elapsed=0.01,
                request_method=method.upper(),
            )

        # Reflect any injected param/body values verbatim so reflection-based
        # detection (Unsafe Consumption, API10) observes the malformed payload.
        reflected_parts = []
        params = kwargs.get("params") or {}
        if isinstance(params, dict):
            reflected_parts.extend(str(v) for v in params.values())
        body = kwargs.get("json") or {}
        if isinstance(body, dict):
            reflected_parts.extend(str(v) for v in body.values())
        reflected = " ".join(reflected_parts)

        payload = {
            "status": "ok",
            "message": "successful response with data for users and api consumers",
            "data": _VULN_SIGNATURES,
            "users": [{"user_id": 123, "email": "alice@example.com"}],
            "password": "secret123",
            "api_key": "REDACTED-TEST-KEY-not-a-real-secret",
            "note": "this api version is deprecated; data sourced from upstream proxy",
            "reflected": reflected,
        }
        text = json.dumps(payload)
        content = text.encode("utf-8")

        # Permissive CORS (wildcard + credentials) and intentionally NO security
        # headers, so the Security Misconfiguration module (API8) flags both a
        # CORS misconfiguration and missing security headers.
        headers = {
            "content-type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
        }

        return Response(
            status_code=200,
            headers=headers,
            content=content,
            text=text,
            url=url,
            elapsed=0.01,
            request_method=method.upper(),
        )


def _make_config():
    """Build an APILeakConfig with all ten modules enabled and advanced discovery
    disabled (no network). Resource-consumption limits are reduced to keep the
    burst/payload probes fast under the mock."""
    return APILeakConfig(
        target=TargetConfig(base_url="https://vuln.test"),
        fuzzing=FuzzingConfig(),
        owasp_testing=OWASPConfig(
            enabled_modules=list(EXPECTED_OWASP_MODULES),
            # Keep the resource module's burst/payload probing small and fast.
            resource_testing=ResourceTestingConfig(
                burst_size=5,
                large_payload_sizes=[2048],
                json_depth_limit=20,
            ),
        ),
        authentication=AuthConfig(
            contexts=[
                AuthContext(name="user1", type=AuthType.BEARER, token="user1-token",
                            privilege_level=1),
                AuthContext(name="user2", type=AuthType.BEARER, token="user2-token",
                            privilege_level=1),
            ]
        ),
        rate_limiting=RateLimitConfig(),
        reporting=ReportConfig(),
        advanced_discovery=AdvancedDiscoveryConfig(enabled=False),
    )


def _mock_target_endpoints():
    """One vulnerable endpoint per OWASP category against the mock target.

    A single host is used so the inventory/version probes fuzz it once; the paths
    cover the URL-pattern triggers the modules look for (object IDs for BOLA,
    a sensitive business flow for API6, an admin function for API5, an
    upstream/proxy path for API10, and a fetch-style endpoint for SSRF).
    """
    return [
        MockEndpoint("https://vuln.test/api/users/123", "GET"),       # API1/2/3/4
        MockEndpoint("https://vuln.test/api/orders/42", "GET"),
        MockEndpoint("https://vuln.test/checkout", "POST"),           # API6 flow
        MockEndpoint("https://vuln.test/admin/delete/5", "DELETE"),   # API5 admin
        MockEndpoint("https://vuln.test/api/proxy/aggregate", "GET"), # API10 upstream
        MockEndpoint("https://vuln.test/fetch", "GET"),               # API7 ssrf
    ]


def _build_report_results(core):
    """Project the engine's collected findings into the lightweight results shape
    ReportGenerator.save_reports expects."""
    findings = core.findings_collector.findings
    now = datetime.now()
    statistics = SimpleNamespace(
        findings_count=len(findings),
        critical_findings=sum(1 for f in findings if f.severity == Severity.CRITICAL),
        high_findings=sum(1 for f in findings if f.severity == Severity.HIGH),
        medium_findings=sum(1 for f in findings if f.severity == Severity.MEDIUM),
        low_findings=sum(1 for f in findings if f.severity == Severity.LOW),
        info_findings=sum(1 for f in findings if f.severity == Severity.INFO),
        total_requests=0,
        endpoints_discovered=len(core.discovered_endpoints),
    )
    performance_metrics = SimpleNamespace(
        duration=timedelta(seconds=1),
        requests_per_second=1.0,
        average_response_time=0.01,
        start_time=now,
        end_time=now + timedelta(seconds=1),
    )
    return SimpleNamespace(
        scan_id=core.scan_id,
        target_url=core.config.target.base_url,
        timestamp=now,
        statistics=statistics,
        performance_metrics=performance_metrics,
        findings=findings,
        findings_collector=core.findings_collector,
        discovered_endpoints=core.discovered_endpoints,
    )


async def _run_all_modules_owasp_phase(core):
    """Initialize and run the real OWASP phase with all ten modules enabled."""
    core.discovered_endpoints = _mock_target_endpoints()
    # Capture engine-level log calls so we can assert no "module not registered"
    # warning is emitted while still letting the modules run for real.
    core.logger = MagicMock()
    await core._execute_owasp_phase()


@pytest.fixture(scope="module")
def executed_core():
    """Run the all-modules OWASP phase against the mock vulnerable target once and
    return the engine so multiple assertions can share the (expensive) result."""
    config = _make_config()
    core = APILeakCore(config)
    with patch("utils.http_client.HTTPRequestEngine", VulnerableMockHTTPClient):
        asyncio.run(_run_all_modules_owasp_phase(core))
    return core


def test_all_ten_modules_register_and_execute_without_warnings(executed_core):
    """All ten modules register and the OWASP phase runs without a
    "module not registered" warning (Requirements 6.1, 6.2)."""
    core = executed_core

    # Every expected module is registered.
    for name in EXPECTED_OWASP_MODULES:
        assert name in core.owasp_modules, f"OWASP module '{name}' was not registered"
    assert set(core.owasp_modules.keys()) == set(EXPECTED_OWASP_MODULES)

    # No "module not registered" warning was emitted by the engine.
    not_registered = [
        call
        for call in core.logger.warning.call_args_list
        if call.args and call.args[0] == "OWASP module not registered"
    ]
    assert not_registered == [], (
        f"Unexpected 'module not registered' warning(s): {not_registered}"
    )


def test_each_new_module_produces_expected_category(executed_core):
    """Each of the five new modules emits at least its expected Finding_Category
    (Requirements 1.4, 2.4, 3.3, 4.3, 5.4)."""
    core = executed_core
    categories = {f.category for f in core.findings_collector.findings}
    owasp_cats = {f.owasp_category for f in core.findings_collector.findings}

    # API7 SSRF (Requirement 1.4): internal-access or file-protocol access.
    assert {"SSRF_INTERNAL_ACCESS", "FILE_PROTOCOL_ACCESS"} & categories, (
        "SSRF module did not produce an SSRF finding"
    )

    # API6 Business Flows (Requirement 2.4).
    assert "BUSINESS_FLOW_NO_LIMIT" in categories, (
        "Business Flows module did not produce a BUSINESS_FLOW_NO_LIMIT finding"
    )

    # API8 Security Misconfiguration (Requirement 3.3): CORS misconfiguration.
    assert "CORS_MISCONFIGURATION" in categories, (
        "Security Misconfiguration module did not produce a CORS_MISCONFIGURATION finding"
    )

    # API9 Inventory Management (Requirement 4.3): any API9-categorized finding.
    assert "API9" in owasp_cats, (
        "Inventory Management module did not produce an API9 finding"
    )

    # API10 Unsafe Consumption (Requirement 5.4).
    assert "UNSAFE_UPSTREAM_DATA" in categories, (
        "Unsafe Consumption module did not produce an UNSAFE_UPSTREAM_DATA finding"
    )


def test_owasp_coverage_reaches_ten_of_ten(executed_core):
    """The all-modules scan drives OWASP coverage to 10/10 categories, including
    API6-API10 produced by the new modules (Requirement 7.4)."""
    core = executed_core
    coverage = core.findings_collector.get_owasp_coverage()

    assert coverage["total_categories"] == 10
    # The new modules must contribute API6-API10 coverage (Requirement 7.4).
    for owasp in ("API6", "API7", "API8", "API9", "API10"):
        assert coverage["categories"][owasp]["tested"] is True, (
            f"{owasp} should be covered by the new modules"
        )
    assert coverage["tested_categories"] == 10, (
        "Expected 10/10 OWASP coverage, untested: "
        f"{coverage['untested_categories']}"
    )
    assert coverage["coverage_percentage"] == 100.0


def test_findings_flow_into_json_and_sarif_reports(executed_core, tmp_path):
    """Findings flow into JSON + SARIF reports, and the SARIF document contains
    one result per finding (Requirement 8.2)."""
    core = executed_core
    findings = core.findings_collector.findings
    assert findings, "Expected the all-modules scan to produce findings"

    results = _build_report_results(core)
    generator = ReportGenerator(template_dir=str(tmp_path / "templates"))
    generator.save_reports(
        results,
        str(tmp_path),
        scan_type="full",
        output_filename="e2e_report",
        formats=["json", "sarif"],
    )

    json_path = tmp_path / "e2e_report.json"
    sarif_path = tmp_path / "e2e_report.sarif"
    assert json_path.exists(), "JSON report was not written"
    assert sarif_path.exists(), "SARIF report was not written"

    # SARIF: one result per finding (Requirement 8.2).
    sarif_doc = json.loads(sarif_path.read_text())
    assert sarif_doc["version"] == "2.1.0"
    assert len(sarif_doc["runs"]) == 1
    expected_count = len(core.findings_collector.get_prioritized_findings())
    assert len(sarif_doc["runs"][0]["results"]) == expected_count

    # JSON report carries the findings through as well.
    json_doc = json.loads(json_path.read_text())
    assert json_doc, "JSON report is empty"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
