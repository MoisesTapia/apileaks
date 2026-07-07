"""
Tests for SSRF Testing Module (OWASP API7)
"""

import pytest
from unittest.mock import Mock, AsyncMock
from dataclasses import dataclass

from modules.owasp.ssrf_testing import SSRFTestingModule
from utils.findings import Finding
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
        """Requirement 6.6 / 2.4: reaching a cloud metadata endpoint (169.254.169.254)
        with a signature match emits SSRF_CLOUD_METADATA (CRITICAL), not
        SSRF_INTERNAL_ACCESS. Plain internal targets that are NOT cloud-metadata
        hosts still emit SSRF_INTERNAL_ACCESS."""
        # Use a non-cloud-metadata internal target so we get SSRF_INTERNAL_ACCESS.
        config = SSRFConfig(
            internal_targets=["192.168.1.1"],
            file_protocols=[],
            # Disable bypass and cloud metadata probes to keep the finding set simple.
            bypass_encodings=False,
        )
        # Patch _build_probe_set to skip CLOUD_METADATA_PROBES for isolation.
        from modules.owasp.ssrf_testing import InternalProbe, SchemeProbe
        plain_probe = InternalProbe(
            payload="http://192.168.1.1/",
            logical_target="192.168.1.1",
            extra_headers={},
            is_bypass=False,
        )
        module = self._module(config, mock_http_client, auth_contexts)
        # Inject a probe set with only the plain (non-cloud) internal probe.
        module._build_probe_set = lambda: ([plain_probe], [])

        mock_http_client.request.return_value = make_response(
            status_code=200,
            body="local-hostname\npublic-ipv4",
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
    async def test_cloud_metadata_hit_produces_cloud_metadata_finding(
        self, mock_http_client, auth_contexts
    ):
        """Requirement 6.6 / 2.4: a cloud metadata probe that matches a signature
        emits SSRF_CLOUD_METADATA (CRITICAL)."""
        from modules.owasp.ssrf_testing import InternalProbe
        cloud_probe = InternalProbe(
            payload="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            logical_target="169.254.169.254",
            extra_headers={},
            is_bypass=False,
        )
        config = SSRFConfig(internal_targets=[], file_protocols=[])
        module = self._module(config, mock_http_client, auth_contexts)
        module._build_probe_set = lambda: ([cloud_probe], [])

        mock_http_client.request.return_value = make_response(
            status_code=200,
            body="ami-id\ninstance-id\niam/security-credentials",
        )

        endpoints = [MockEndpoint("https://api.example.com/fetch")]
        findings = await module.execute_tests(endpoints)

        cloud_findings = [f for f in findings if f.category == "SSRF_CLOUD_METADATA"]
        assert len(cloud_findings) >= 1
        finding = cloud_findings[0]
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
    async def test_no_finding_when_no_signature_and_server_error(self, mock_http_client,
                                                                  auth_contexts):
        """A 500 server error with no content signatures produces no SSRF findings.

        The new scheme-probe logic emits SSRF_SCHEME_BYPASS only when
        status_code < 500. A 500 response is treated as an error and suppressed,
        ensuring noisy server-error responses don't flood reports.
        """
        from modules.owasp.ssrf_testing import InternalProbe, SchemeProbe
        # Use a non-cloud-metadata internal probe to avoid SSRF_CLOUD_METADATA.
        plain_probe = InternalProbe(
            payload="http://192.168.1.1/",
            logical_target="192.168.1.1",
            extra_headers={},
            is_bypass=False,
        )
        scheme_probe = SchemeProbe(payload="gopher://127.0.0.1/", scheme="gopher")
        config = SSRFConfig(internal_targets=[], file_protocols=[])
        module = self._module(config, mock_http_client, auth_contexts)
        module._build_probe_set = lambda: ([plain_probe], [scheme_probe])

        mock_http_client.request.return_value = make_response(
            status_code=500, body="Internal Server Error",
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


class TestDedupFinding:
    """Unit tests for SSRFTestingModule._dedup_finding() — design §8, Req 12.5."""

    @pytest.fixture
    def module(self):
        client = Mock(spec=HTTPRequestEngine)
        client.request = AsyncMock()
        client.set_auth_context = Mock()
        auth = AuthContext(
            name="user1",
            type=AuthType.BEARER,
            token="tok",
            privilege_level=1,
        )
        return SSRFTestingModule(SSRFConfig(), client, [auth])

    def _make_finding(self, endpoint="https://api.example.com/v1/fetch",
                      category="SSRF_INTERNAL_ACCESS",
                      payload="query=http://169.254.169.254/"):
        return Finding(
            id="test-finding-id",
            scan_id="test-scan-id",
            category=category,
            owasp_category="API7",
            severity=Severity.CRITICAL,
            endpoint=endpoint,
            method="GET",
            status_code=200,
            response_size=512,
            response_time=0.1,
            evidence="matched signature ami-id",
            recommendation="Allowlist outbound targets.",
            payload=payload,
        )

    def test_first_emission_returns_finding_unchanged(self, module):
        """First call for a unique key returns the finding as-is."""
        finding = self._make_finding()
        result = module._dedup_finding(finding, "169.254.169.254")
        assert result is finding

    def test_first_emission_adds_key_to_emitted(self, module):
        """After the first call the key is tracked in _emitted."""
        finding = self._make_finding()
        module._dedup_finding(finding, "169.254.169.254")
        key = (finding.endpoint, finding.category, "169.254.169.254")
        assert key in module._emitted

    def test_duplicate_returns_none(self, module):
        """Second call with the same key returns None."""
        finding1 = self._make_finding(payload="query=http://169.254.169.254/")
        finding2 = self._make_finding(payload="header=http://169.254.169.254/")
        module._dedup_finding(finding1, "169.254.169.254")
        result = module._dedup_finding(finding2, "169.254.169.254")
        assert result is None

    def test_duplicate_merges_payload_with_separator(self, module):
        """Duplicate payload is appended to the existing finding with ' | '."""
        finding1 = self._make_finding(payload="query=http://169.254.169.254/")
        finding2 = self._make_finding(payload="header=http://169.254.169.254/")
        module._dedup_finding(finding1, "169.254.169.254")
        module._dedup_finding(finding2, "169.254.169.254")
        assert finding1.payload == (
            "query=http://169.254.169.254/ | header=http://169.254.169.254/"
        )

    def test_third_duplicate_keeps_accumulating_payloads(self, module):
        """Each duplicate appends its payload to the accumulated string."""
        f1 = self._make_finding(payload="p1")
        f2 = self._make_finding(payload="p2")
        f3 = self._make_finding(payload="p3")
        module._dedup_finding(f1, "127.0.0.1")
        module._dedup_finding(f2, "127.0.0.1")
        module._dedup_finding(f3, "127.0.0.1")
        assert f1.payload == "p1 | p2 | p3"

    def test_different_logical_targets_are_independent(self, module):
        """Same endpoint+category but different logical_target are separate keys."""
        f1 = self._make_finding(category="SSRF_INTERNAL_ACCESS", payload="p1")
        f2 = self._make_finding(category="SSRF_INTERNAL_ACCESS", payload="p2")
        r1 = module._dedup_finding(f1, "127.0.0.1")
        r2 = module._dedup_finding(f2, "169.254.169.254")
        assert r1 is f1
        assert r2 is f2

    def test_different_categories_are_independent(self, module):
        """Same endpoint+logical_target but different categories are separate keys."""
        f1 = self._make_finding(category="SSRF_INTERNAL_ACCESS", payload="p1")
        f2 = self._make_finding(category="SSRF_SCHEME_BYPASS", payload="p2")
        r1 = module._dedup_finding(f1, "127.0.0.1")
        r2 = module._dedup_finding(f2, "127.0.0.1")
        assert r1 is f1
        assert r2 is f2

    def test_different_endpoints_are_independent(self, module):
        """Same category+logical_target on different endpoints are separate keys."""
        f1 = self._make_finding(endpoint="https://api.example.com/a", payload="p1")
        f2 = self._make_finding(endpoint="https://api.example.com/b", payload="p2")
        r1 = module._dedup_finding(f1, "127.0.0.1")
        r2 = module._dedup_finding(f2, "127.0.0.1")
        assert r1 is f1
        assert r2 is f2

    @pytest.mark.asyncio
    async def test_emitted_reset_between_execute_tests_calls(self, module):
        """_emitted is cleared at the start of each execute_tests call."""
        # Manually seed the tracker as if a previous scan ran.
        dummy_finding = self._make_finding()
        key = (dummy_finding.endpoint, dummy_finding.category, "127.0.0.1")
        module._emitted.add(key)
        module._emitted_findings[key] = dummy_finding

        # Calling execute_tests with an empty list should still reset state.
        await module.execute_tests([])
        assert len(module._emitted) == 0
        assert len(module._emitted_findings) == 0


if __name__ == "__main__":
    pytest.main([__file__])
