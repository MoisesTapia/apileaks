"""
Tests for the shared declarative Unauthorized_Endpoint_Assertion evaluation
(_evaluate_unauthorized_assertions) wired into the BOLA, Auth, and Property
modules (Requirement 55).

Covers the four required behaviors for every module:
  * access GRANTED to a matching endpoint -> finding in the module's in-scope
    OWASP category (Req 55.2)
  * access DENIED -> no finding (Req 55.3)
  * non-discriminating negative-control baseline -> no finding (Req 55.4)
  * no assertions supplied -> existing behavior, no requests issued (Req 55.5)

Plus threading (AuthContext.unauthorized_patterns default) and strict findings
classification for the three new categories.
"""

import re

import pytest
from unittest.mock import Mock, AsyncMock

from modules.owasp.bola_testing import BOLATestingModule
from modules.owasp.auth_testing import AuthenticationTestingModule
from modules.owasp.property_level_auth import PropertyLevelAuthModule
from utils.http_client import HTTPRequestEngine, Response
from utils.findings import FindingsCollector
from core.config import (
    AuthContext,
    AuthType,
    BOLAConfig,
    AuthTestingConfig,
    PropertyTestingConfig,
    Severity,
)


ENDPOINT = "https://api.example.com/admin/reports"
NONEXISTENT_MARKER = "apileaks-nonexistent"


def make_response(status_code, body="", url=ENDPOINT, method="GET"):
    """Build a Response with the given status and JSON body."""
    content = body.encode() if isinstance(body, str) else body
    return Response(
        status_code=status_code,
        headers={"content-type": "application/json"},
        content=content,
        text=body if isinstance(body, str) else body.decode(),
        url=url,
        elapsed=0.01,
        request_method=method,
    )


def make_http_client():
    client = Mock(spec=HTTPRequestEngine)
    client.request = AsyncMock()
    client.set_auth_context = Mock()
    client.current_auth_context = None
    return client


def make_context(name="user1", patterns=None, privilege_level=1):
    ctx = AuthContext(
        name=name,
        type=AuthType.BEARER,
        token=f"{name}_token",
        privilege_level=privilege_level,
    )
    if patterns is not None:
        ctx.unauthorized_patterns = [re.compile(p) for p in patterns]
    return ctx


def build_module(module_cls, http_client, contexts):
    """Construct the given OWASP module with a minimal valid config."""
    if module_cls is BOLATestingModule:
        config = BOLAConfig(enabled=True, id_patterns=["sequential"],
                            test_contexts=["user"])
    elif module_cls is AuthenticationTestingModule:
        config = AuthTestingConfig(
            enabled=True,
            jwt_testing=False,
            weak_secrets_wordlist="wordlists/jwt_secrets.txt",
            test_logout_invalidation=False,
        )
    elif module_cls is PropertyLevelAuthModule:
        config = PropertyTestingConfig(
            enabled=True,
            sensitive_fields=["password"],
            mass_assignment_fields=["is_admin"],
        )
    else:  # pragma: no cover - defensive
        raise ValueError(module_cls)
    return module_cls(config, http_client, contexts)


# (module class, expected finding category, expected OWASP category)
MODULE_MATRIX = [
    (BOLATestingModule, "BOLA_UNAUTHORIZED_ENDPOINT_ACCESS", "API1"),
    (AuthenticationTestingModule, "AUTH_UNAUTHORIZED_ENDPOINT_ACCESS", "API2"),
    (PropertyLevelAuthModule, "PROPERTY_UNAUTHORIZED_ENDPOINT_ACCESS", "API3"),
]


@pytest.mark.parametrize("module_cls,category,owasp", MODULE_MATRIX)
class TestUnauthorizedEndpointAssertions:
    """Shared evaluation behavior across the three hardened modules."""

    @pytest.mark.asyncio
    async def test_access_granted_emits_finding(self, module_cls, category, owasp):
        """A context granted access to a forbidden endpoint yields a finding
        in the module's in-scope OWASP category (Req 55.2)."""
        http_client = make_http_client()

        def side_effect(method, url, *args, **kwargs):
            if NONEXISTENT_MARKER in url:
                # Negative control: nonexistent resource is denied (discriminating).
                return make_response(404, '{"error": "not found"}', url=url)
            # Real endpoint surfaces distinct, real data -> access granted.
            return make_response(
                200, '{"id": 99, "email": "victim@example.com"}', url=url
            )

        http_client.request.side_effect = side_effect

        ctx = make_context(patterns=[r"/admin/"])
        module = build_module(module_cls, http_client, [ctx])

        findings = await module._evaluate_unauthorized_assertions(ENDPOINT, ctx)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.category == category
        assert finding.owasp_category == owasp
        assert finding.severity == Severity.HIGH
        assert finding.endpoint == ENDPOINT
        assert "/admin/" in finding.payload

    @pytest.mark.asyncio
    async def test_access_denied_emits_nothing(self, module_cls, category, owasp):
        """When access to the matching endpoint is denied, no finding is
        reported for the assertion (Req 55.3)."""
        http_client = make_http_client()

        def side_effect(method, url, *args, **kwargs):
            if NONEXISTENT_MARKER in url:
                return make_response(404, '{"error": "not found"}', url=url)
            # Real endpoint is forbidden for this context.
            return make_response(403, '{"error": "forbidden"}', url=url)

        http_client.request.side_effect = side_effect

        ctx = make_context(patterns=[r"/admin/"])
        module = build_module(module_cls, http_client, [ctx])

        findings = await module._evaluate_unauthorized_assertions(ENDPOINT, ctx)

        assert findings == []

    @pytest.mark.asyncio
    async def test_non_discriminating_baseline_emits_nothing(
        self, module_cls, category, owasp
    ):
        """A non-discriminating negative-control baseline (endpoint returns
        success even for an invalid resource) suppresses the finding (Req 55.4)."""
        http_client = make_http_client()

        # Every request (including the invalid-resource negative control) is a
        # success -> baseline is non-discriminating.
        http_client.request.side_effect = lambda method, url, *a, **k: make_response(
            200, '{"id": 1}', url=url
        )

        ctx = make_context(patterns=[r"/admin/"])
        module = build_module(module_cls, http_client, [ctx])

        findings = await module._evaluate_unauthorized_assertions(ENDPOINT, ctx)

        assert findings == []

    @pytest.mark.asyncio
    async def test_no_assertions_preserves_existing_behavior(
        self, module_cls, category, owasp
    ):
        """When no assertions are supplied, the evaluation issues no requests
        and reports nothing (Req 55.5)."""
        http_client = make_http_client()
        ctx = make_context(patterns=None)  # unauthorized_patterns stays None
        module = build_module(module_cls, http_client, [ctx])

        findings = await module._evaluate_unauthorized_assertions(ENDPOINT, ctx)

        assert findings == []
        http_client.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_pattern_not_matching_emits_nothing(
        self, module_cls, category, owasp
    ):
        """An assertion whose patterns do not match the endpoint issues no
        requests and reports nothing."""
        http_client = make_http_client()
        ctx = make_context(patterns=[r"/billing/"])  # does not match /admin/
        module = build_module(module_cls, http_client, [ctx])

        findings = await module._evaluate_unauthorized_assertions(ENDPOINT, ctx)

        assert findings == []
        http_client.request.assert_not_called()


class TestMultiContextCorroboration:
    """The multi-context comparison is applied when >= 2 contexts exist."""

    @pytest.mark.asyncio
    async def test_multi_context_granted_still_emits(self):
        """With two contexts, the target context being granted access still
        yields a finding; the corroboration only enriches the evidence."""
        http_client = make_http_client()

        def side_effect(method, url, *args, **kwargs):
            if NONEXISTENT_MARKER in url:
                return make_response(404, '{"error": "not found"}', url=url)
            return make_response(
                200, '{"id": 99, "email": "victim@example.com"}', url=url
            )

        http_client.request.side_effect = side_effect

        forbidden = make_context(name="user1", patterns=[r"/admin/"])
        other = make_context(name="user2")
        module = build_module(BOLATestingModule, http_client, [forbidden, other])

        findings = await module._evaluate_unauthorized_assertions(ENDPOINT, forbidden)

        assert len(findings) == 1
        assert findings[0].category == "BOLA_UNAUTHORIZED_ENDPOINT_ACCESS"
        assert "multi-context comparison" in findings[0].evidence


class TestRunUnauthorizedAssertions:
    """The endpoint x context driver short-circuits when nothing is declared."""

    @pytest.mark.asyncio
    async def test_short_circuits_without_patterns(self):
        http_client = make_http_client()
        module = build_module(
            BOLATestingModule, http_client, [make_context(patterns=None)]
        )

        findings = await module._run_unauthorized_assertions([ENDPOINT])

        assert findings == []
        http_client.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_evaluates_declared_endpoints(self):
        http_client = make_http_client()

        def side_effect(method, url, *args, **kwargs):
            if NONEXISTENT_MARKER in url:
                return make_response(404, '{"error": "not found"}', url=url)
            return make_response(200, '{"id": 7, "email": "x@y.z"}', url=url)

        http_client.request.side_effect = side_effect

        ctx = make_context(patterns=[r"/admin/"])
        module = build_module(AuthenticationTestingModule, http_client, [ctx])

        findings = await module._run_unauthorized_assertions([ENDPOINT])

        assert len(findings) == 1
        assert findings[0].category == "AUTH_UNAUTHORIZED_ENDPOINT_ACCESS"


class TestThreadingAndClassification:
    """Config threading and strict findings classification."""

    def test_auth_context_unauthorized_patterns_defaults_none(self):
        ctx = AuthContext(name="c", type=AuthType.BEARER, token="t")
        assert ctx.unauthorized_patterns is None

    @pytest.mark.parametrize(
        "category,owasp",
        [
            ("BOLA_UNAUTHORIZED_ENDPOINT_ACCESS", "API1"),
            ("AUTH_UNAUTHORIZED_ENDPOINT_ACCESS", "API2"),
            ("PROPERTY_UNAUTHORIZED_ENDPOINT_ACCESS", "API3"),
        ],
    )
    def test_categories_resolve_strictly(self, category, owasp):
        collector = FindingsCollector(scan_id="test-scan")
        assert collector._classify_severity(category) == Severity.HIGH
        assert collector._get_owasp_category(category) == owasp
        assert category in FindingsCollector.EMITTED_CATEGORIES
