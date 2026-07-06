"""
Property-based and unit tests for the SSRF Testing Module.

Covers:
  - Property 1: No SSRF_BLIND findings without callback_url (Req 4.2)
  - Property 2: No state-changing requests in safe mode (Req 10.1–10.4)
  - Property 3: No duplicate (endpoint, category, logical_target) tuples (Req 12.5)
  - Property 4: No SSRF_PORT_SCAN without allow_port_scan flag (Req 7.2, 8.2)
  - Unit 1: _build_probe_set() count verification
  - Unit 2: apply_ssrf_options() correctness
  - Unit 3: _test_body_injection() gating
  - Unit 4: _test_port_scan() gating
  - Unit 5: Cloud metadata probes extra_headers correctness
  - Unit 6: Bypass probes emit SSRF_SCHEME_BYPASS, not SSRF_INTERNAL_ACCESS
  - Unit 7: Cloud metadata hits emit SSRF_CLOUD_METADATA, not SSRF_INTERNAL_ACCESS
"""

import asyncio
from dataclasses import dataclass
from unittest.mock import AsyncMock, Mock

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cli.module_options import apply_ssrf_options
from core.config import AuthContext, AuthType, SSRFConfig, Severity
from modules.owasp.ssrf_testing import (
    BYPASS_PROBES,
    CLOUD_METADATA_PROBES,
    SSRF_SCHEMES,
    InternalProbe,
    SchemeProbe,
    SSRFTestingModule,
)
from utils.findings import Finding
from utils.http_client import HTTPRequestEngine, Response


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def make_response(
    status_code=200,
    body="",
    url="https://api.example.com/test",
    method="GET",
):
    """Build a Response with consistent text/content fields."""
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


def make_module(config=None, side_effect_fn=None, return_value=None):
    """Create an SSRFTestingModule with a mocked HTTP client."""
    if config is None:
        config = SSRFConfig()
    client = Mock(spec=HTTPRequestEngine)
    client.set_auth_context = Mock()
    if side_effect_fn:
        client.request = AsyncMock(side_effect=side_effect_fn)
    else:
        client.request = AsyncMock(return_value=return_value or make_response(404, ""))
    auth = AuthContext(name="tester", type=AuthType.BEARER, token="tok", privilege_level=1)
    return SSRFTestingModule(config, client, [auth])


@dataclass
class EP:
    url: str
    method: str = "GET"


# ---------------------------------------------------------------------------
# Property-based tests
# ---------------------------------------------------------------------------

_PBT_SETTINGS = dict(max_examples=10, deadline=None, suppress_health_check=[HealthCheck.too_slow])


@settings(**_PBT_SETTINGS)
@given(
    url_suffix=st.text(
        min_size=1,
        max_size=50,
        alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd")),
    )
)
def test_no_blind_findings_without_callback_url(url_suffix):
    """**Validates: Requirements 4.2**

    Property 1 — No SSRF_BLIND findings when callback_url is None.
    Regardless of the URL suffix generated, if there is no callback_url
    configured the module must never emit SSRF_BLIND findings.
    """

    async def _run():
        config = SSRFConfig(
            callback_url=None,
            internal_targets=[],
            bypass_encodings=False,
            scan_ports=[],
        )
        module = make_module(config, return_value=make_response(200, "hello"))
        endpoint_url = f"https://api.example.com/{url_suffix}"
        findings = await module.execute_tests([EP(endpoint_url)])
        blind = [f for f in findings if f.category == "SSRF_BLIND"]
        assert blind == [], (
            f"Expected no SSRF_BLIND findings without callback_url, got: {blind}"
        )

    asyncio.run(_run())


@settings(**_PBT_SETTINGS)
@given(
    method=st.sampled_from(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]),
    url=st.just("https://api.example.com/test"),
)
def test_safe_mode_no_state_changing_requests(method, url):
    """**Validates: Requirements 10.1, 10.2, 10.3, 10.4**

    Property 2 — In safe mode the module must never issue POST, PUT, PATCH,
    or DELETE requests, regardless of the endpoint's original HTTP method.
    """
    _state_changing = {"POST", "PUT", "PATCH", "DELETE"}

    async def _run():
        config = SSRFConfig(
            safe_mode=True,
            body_injection=True,
            callback_url="http://oob.example.com",
            scan_ports=[80, 443],
        )
        module = make_module(config, return_value=make_response(200, "ok"))
        await module.execute_tests([EP(url, method)])

        for call in module.http_client.request.call_args_list:
            # Positional args: request(method, url, ...)
            issued_method = call.args[0] if call.args else call.kwargs.get("method", "")
            assert issued_method.upper() not in _state_changing, (
                f"safe_mode=True but the module issued state-changing method "
                f"'{issued_method}' (endpoint method was '{method}')"
            )

    asyncio.run(_run())


@settings(**_PBT_SETTINGS)
@given(
    endpoint_urls=st.lists(
        st.just("https://api.example.com/resource"),
        min_size=1,
        max_size=3,
    )
)
def test_no_duplicate_endpoint_category_logical_target_tuples(endpoint_urls):
    """**Validates: Requirements 12.5**

    Property 3 — The deduplication tracker must ensure no two distinct Finding
    objects share the same (endpoint, category, logical_target) tuple.

    The simpler assertion: the number of returned findings must never exceed
    the number of unique keys tracked in module._emitted.
    """

    async def _run():
        config = SSRFConfig(
            internal_targets=["127.0.0.1", "localhost"],
            bypass_encodings=True,
            scan_ports=[],
        )
        # Mix of signature-matching and non-matching responses.
        responses = [
            make_response(200, "local-hostname"),
            make_response(200, "hello"),
            make_response(404, "not found"),
        ]
        call_count = 0

        async def _side_effect(*args, **kwargs):
            nonlocal call_count
            resp = responses[call_count % len(responses)]
            call_count += 1
            return resp

        module = make_module(config, side_effect_fn=_side_effect)
        endpoints = [EP(u) for u in endpoint_urls]
        findings = await module.execute_tests(endpoints)

        assert len(findings) <= len(module._emitted), (
            f"len(findings)={len(findings)} exceeds len(_emitted)={len(module._emitted)}"
        )

    asyncio.run(_run())


@settings(**_PBT_SETTINGS)
@given(
    endpoint_urls=st.lists(
        st.just("https://api.example.com/test"),
        min_size=0,
        max_size=3,
    )
)
def test_no_port_scan_without_allow_port_scan_flag(endpoint_urls):
    """**Validates: Requirements 7.2, 8.2**

    Property 4 — The module must never emit SSRF_PORT_SCAN findings when
    allow_port_scan is False, regardless of the scan_ports list.
    """

    async def _run():
        config = SSRFConfig(allow_port_scan=False, scan_ports=[80, 443, 8080])
        module = make_module(config, return_value=make_response(200, "ok"))
        endpoints = [EP(u) for u in endpoint_urls]
        findings = await module.execute_tests(endpoints)
        port_scan_findings = [f for f in findings if f.category == "SSRF_PORT_SCAN"]
        assert port_scan_findings == [], (
            f"Expected no SSRF_PORT_SCAN findings with allow_port_scan=False, "
            f"got: {port_scan_findings}"
        )

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Unit 1 — _build_probe_set() count verification
# ---------------------------------------------------------------------------


class TestBuildProbeSet:
    def _module(self, config):
        client = Mock(spec=HTTPRequestEngine)
        client.set_auth_context = Mock()
        client.request = AsyncMock(return_value=make_response(404, ""))
        auth = AuthContext(name="t", type=AuthType.BEARER, token="x", privilege_level=1)
        return SSRFTestingModule(config, client, [auth])

    def test_bypass_enabled_no_extras(self):
        config = SSRFConfig(bypass_encodings=True, additional_internal_targets=[], additional_schemes=[])
        module = self._module(config)
        internal, schemes = module._build_probe_set()
        expected_internal = len(config.internal_targets) + len(CLOUD_METADATA_PROBES) + len(BYPASS_PROBES)
        assert len(internal) == expected_internal
        assert len(schemes) == len(SSRF_SCHEMES)

    def test_bypass_disabled_with_extras(self):
        config = SSRFConfig(
            bypass_encodings=False,
            additional_internal_targets=["10.0.0.1", "10.0.0.2"],
            additional_schemes=["tftp://", "redis://"],
        )
        module = self._module(config)
        internal, schemes = module._build_probe_set()
        expected_internal = len(config.internal_targets) + len(CLOUD_METADATA_PROBES) + 2
        assert len(internal) == expected_internal
        assert len(schemes) == len(SSRF_SCHEMES) + 2

    def test_bypass_enabled_with_extras(self):
        config = SSRFConfig(
            bypass_encodings=True,
            additional_internal_targets=["192.168.1.1"],
            additional_schemes=["redis://"],
        )
        module = self._module(config)
        internal, schemes = module._build_probe_set()
        expected_internal = (
            len(config.internal_targets) + len(CLOUD_METADATA_PROBES) + len(BYPASS_PROBES) + 1
        )
        assert len(internal) == expected_internal
        assert len(schemes) == len(SSRF_SCHEMES) + 1


# ---------------------------------------------------------------------------
# Unit 2 — apply_ssrf_options() correctness
# ---------------------------------------------------------------------------


class TestApplySsrfOptions:
    def _fresh_config(self):
        return SSRFConfig()

    def test_callback_url_is_set(self):
        cfg = self._fresh_config()
        apply_ssrf_options(cfg, {"ssrf_callback_url": "https://oob.example.com"})
        assert cfg.callback_url == "https://oob.example.com"

    def test_internal_targets_merged_no_duplicates(self):
        cfg = self._fresh_config()
        cfg.additional_internal_targets = ["10.0.0.1"]
        apply_ssrf_options(cfg, {"ssrf_internal_targets": ("10.0.0.1", "10.0.0.2")})
        # 10.0.0.1 already present, 10.0.0.2 is new — no duplicates
        assert cfg.additional_internal_targets == ["10.0.0.1", "10.0.0.2"]

    def test_schemes_set(self):
        cfg = self._fresh_config()
        apply_ssrf_options(cfg, {"ssrf_schemes": ("tftp://", "redis://")})
        assert cfg.additional_schemes == ["tftp://", "redis://"]

    def test_scan_ports_parsed_from_comma_string(self):
        cfg = self._fresh_config()
        apply_ssrf_options(cfg, {"ssrf_scan_ports": "22,80,443"})
        assert cfg.scan_ports == [22, 80, 443]

    def test_body_injection_flag_sets_field(self):
        cfg = self._fresh_config()
        apply_ssrf_options(cfg, {"ssrf_body_injection": True})
        assert cfg.body_injection is True

    def test_allow_aggressive_sets_allow_port_scan(self):
        cfg = self._fresh_config()
        apply_ssrf_options(cfg, {"allow_aggressive_ssrf": True})
        assert cfg.allow_port_scan is True

    def test_no_options_is_noop(self):
        cfg = self._fresh_config()
        original_callback = cfg.callback_url
        original_body = cfg.body_injection
        original_port_scan = cfg.allow_port_scan
        apply_ssrf_options(cfg, {})
        assert cfg.callback_url == original_callback
        assert cfg.body_injection == original_body
        assert cfg.allow_port_scan == original_port_scan

    def test_all_six_options_at_once(self):
        cfg = self._fresh_config()
        apply_ssrf_options(
            cfg,
            {
                "ssrf_callback_url": "https://oob.test",
                "ssrf_internal_targets": ("192.168.0.1",),
                "ssrf_schemes": ("redis://",),
                "ssrf_scan_ports": "8080,9090",
                "ssrf_body_injection": True,
                "allow_aggressive_ssrf": True,
            },
        )
        assert cfg.callback_url == "https://oob.test"
        assert "192.168.0.1" in cfg.additional_internal_targets
        assert cfg.additional_schemes == ["redis://"]
        assert cfg.scan_ports == [8080, 9090]
        assert cfg.body_injection is True
        assert cfg.allow_port_scan is True


# ---------------------------------------------------------------------------
# Unit 3 — _test_body_injection() issues no requests when gated
# ---------------------------------------------------------------------------


class TestBodyInjectionGating:
    @pytest.mark.asyncio
    async def test_no_requests_when_safe_mode_true(self):
        config = SSRFConfig(safe_mode=True, body_injection=True)
        module = make_module(config)
        internal_probes, scheme_probes = module._build_probe_set()
        findings = await module._test_body_injection(
            "https://api.example.com/create", "POST", internal_probes, scheme_probes
        )
        assert findings == []
        module.http_client.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_requests_when_body_injection_false(self):
        config = SSRFConfig(safe_mode=False, body_injection=False)
        module = make_module(config)
        internal_probes, scheme_probes = module._build_probe_set()
        findings = await module._test_body_injection(
            "https://api.example.com/create", "POST", internal_probes, scheme_probes
        )
        assert findings == []
        module.http_client.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_requests_when_method_is_get(self):
        config = SSRFConfig(safe_mode=False, body_injection=True)
        module = make_module(config)
        internal_probes, scheme_probes = module._build_probe_set()
        findings = await module._test_body_injection(
            "https://api.example.com/fetch", "GET", internal_probes, scheme_probes
        )
        assert findings == []
        module.http_client.request.assert_not_called()


# ---------------------------------------------------------------------------
# Unit 4 — _test_port_scan() emits no findings when gated
# ---------------------------------------------------------------------------


class TestPortScanGating:
    @pytest.mark.asyncio
    async def test_no_findings_when_allow_port_scan_false(self):
        config = SSRFConfig(allow_port_scan=False, scan_ports=[80, 443, 8080])
        module = make_module(config, return_value=make_response(200, "open port"))
        findings = await module._test_port_scan("https://api.example.com/fetch", "GET")
        assert findings == []

    @pytest.mark.asyncio
    async def test_no_findings_when_safe_mode_true(self):
        config = SSRFConfig(safe_mode=True, allow_port_scan=True, scan_ports=[80, 443])
        module = make_module(config, return_value=make_response(200, "open port"))
        findings = await module._test_port_scan("https://api.example.com/fetch", "GET")
        assert findings == []

    @pytest.mark.asyncio
    async def test_no_requests_when_allow_port_scan_false(self):
        config = SSRFConfig(allow_port_scan=False, scan_ports=[80, 443])
        module = make_module(config)
        await module._test_port_scan("https://api.example.com/fetch", "GET")
        module.http_client.request.assert_not_called()


# ---------------------------------------------------------------------------
# Unit 5 — Cloud metadata probes have correct extra_headers
# ---------------------------------------------------------------------------


class TestCloudMetadataProbeHeaders:
    def test_gcp_probe_has_metadata_flavor_header(self):
        gcp_probes = [p for p in CLOUD_METADATA_PROBES if p.logical_target == "metadata.google.internal"]
        assert len(gcp_probes) >= 1
        for probe in gcp_probes:
            assert probe.extra_headers.get("Metadata-Flavor") == "Google"

    def test_azure_probe_has_metadata_true_header(self):
        # Azure hits 169.254.169.254 with a /metadata/ path and requires Metadata: true
        azure_probes = [
            p
            for p in CLOUD_METADATA_PROBES
            if p.logical_target == "169.254.169.254" and "metadata/instance" in p.payload
        ]
        assert len(azure_probes) >= 1
        for probe in azure_probes:
            assert probe.extra_headers.get("Metadata") == "true"

    def test_aws_imdsv1_probe_has_no_special_headers(self):
        aws_probes = [
            p for p in CLOUD_METADATA_PROBES if "security-credentials" in p.payload
        ]
        assert len(aws_probes) >= 1
        for probe in aws_probes:
            # AWS IMDSv1 doesn't need extra headers
            assert "Metadata-Flavor" not in probe.extra_headers
            assert "Metadata" not in probe.extra_headers

    def test_all_cloud_probes_are_not_bypass(self):
        for probe in CLOUD_METADATA_PROBES:
            assert probe.is_bypass is False


# ---------------------------------------------------------------------------
# Unit 6 — Bypass probes emit SSRF_SCHEME_BYPASS, not SSRF_INTERNAL_ACCESS
# ---------------------------------------------------------------------------


class TestBypassProbeCategory:
    @pytest.mark.asyncio
    async def test_bypass_probe_matching_signature_emits_scheme_bypass(self):
        """A bypass-encoded probe (is_bypass=True) that matches an internal signature
        must emit SSRF_SCHEME_BYPASS, not SSRF_INTERNAL_ACCESS."""
        bypass_probe = InternalProbe(
            payload="http://2130706433/",
            logical_target="127.0.0.1",
            extra_headers={},
            is_bypass=True,
        )
        config = SSRFConfig(internal_targets=[], bypass_encodings=False)
        module = make_module(config, return_value=make_response(200, "local-hostname"))
        module._build_probe_set = lambda: ([bypass_probe], [])

        findings = await module.execute_tests([EP("https://api.example.com/fetch")])

        bypass_findings = [f for f in findings if f.category == "SSRF_SCHEME_BYPASS"]
        internal_findings = [f for f in findings if f.category == "SSRF_INTERNAL_ACCESS"]
        assert len(bypass_findings) >= 1, "Expected SSRF_SCHEME_BYPASS findings"
        assert len(internal_findings) == 0, "bypass probe must not emit SSRF_INTERNAL_ACCESS"
        for f in bypass_findings:
            assert f.severity == Severity.HIGH

    def test_all_bypass_probes_have_is_bypass_true(self):
        for probe in BYPASS_PROBES:
            assert probe.is_bypass is True, (
                f"BYPASS_PROBE {probe.payload} should have is_bypass=True"
            )


# ---------------------------------------------------------------------------
# Unit 7 — Cloud metadata hits emit SSRF_CLOUD_METADATA, not SSRF_INTERNAL_ACCESS
# ---------------------------------------------------------------------------


class TestCloudMetadataCategory:
    @pytest.mark.asyncio
    async def test_cloud_metadata_probe_with_signature_emits_cloud_metadata(self):
        cloud_probe = InternalProbe(
            payload="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            logical_target="169.254.169.254",
            extra_headers={},
            is_bypass=False,
        )
        config = SSRFConfig(internal_targets=[], bypass_encodings=False)
        module = make_module(
            config,
            return_value=make_response(200, "iam/security-credentials\naccess_token"),
        )
        module._build_probe_set = lambda: ([cloud_probe], [])

        findings = await module.execute_tests([EP("https://api.example.com/fetch")])

        cloud_findings = [f for f in findings if f.category == "SSRF_CLOUD_METADATA"]
        internal_findings = [f for f in findings if f.category == "SSRF_INTERNAL_ACCESS"]
        assert len(cloud_findings) >= 1, "Expected SSRF_CLOUD_METADATA findings"
        assert len(internal_findings) == 0, "cloud metadata probe must not emit SSRF_INTERNAL_ACCESS"
        for f in cloud_findings:
            assert f.severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_gcp_metadata_probe_emits_cloud_metadata(self):
        gcp_probe = InternalProbe(
            payload="http://metadata.google.internal/computeMetadata/v1/instance/",
            logical_target="metadata.google.internal",
            extra_headers={"Metadata-Flavor": "Google"},
            is_bypass=False,
        )
        config = SSRFConfig(internal_targets=[], bypass_encodings=False)
        module = make_module(
            config,
            return_value=make_response(200, "computeMetadata\naccess_token"),
        )
        module._build_probe_set = lambda: ([gcp_probe], [])

        findings = await module.execute_tests([EP("https://api.example.com/fetch")])

        cloud_findings = [f for f in findings if f.category == "SSRF_CLOUD_METADATA"]
        assert len(cloud_findings) >= 1
        for f in cloud_findings:
            assert f.severity == Severity.CRITICAL


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
