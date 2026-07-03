"""
Example-based unit tests for declarative Unauthorized_Endpoint_Assertions
(Requirement 55) across the three hardened OWASP modules.

**Feature: owasp-auth-modules-hardening, Task 51.1**

An Auth_Context may declare endpoint patterns it should be forbidden from
reaching. ``_evaluate_unauthorized_assertions`` calibrates each access decision
against a Negative_Control_Baseline (Reqs 3/5) and reports a broken-access-control
finding only when access is genuinely granted. These worked examples pin the four
required outcomes for BOLA (API1), Auth (API2), and Property (API3):

* access GRANTED to a matching endpoint -> a finding in the module's in-scope
  OWASP category (Req 55.2);
* access DENIED -> no finding (Req 55.3);
* a non-discriminating baseline (endpoint returns success even for an invalid
  resource) -> no finding (Req 55.4);
* no assertions supplied -> existing behavior, no requests issued (Req 55.5).

A mocked ``HTTPRequestEngine`` stands in for the network.
"""

import re

import pytest
from unittest.mock import AsyncMock, Mock

from core.config import (
    AuthContext,
    AuthType,
    AuthTestingConfig,
    BOLAConfig,
    PropertyTestingConfig,
    Severity,
)
from modules.owasp.auth_testing import AuthenticationTestingModule
from modules.owasp.bola_testing import BOLATestingModule
from modules.owasp.property_level_auth import PropertyLevelAuthModule
from utils.http_client import HTTPRequestEngine, Response


ENDPOINT = "https://api.example.com/admin/reports"
NONEXISTENT_MARKER = "apileaks-nonexistent"


def _response(status_code, body="", url=ENDPOINT, method="GET"):
    return Response(
        status_code=status_code,
        headers={"content-type": "application/json"},
        content=body.encode(),
        text=body,
        url=url,
        elapsed=0.01,
        request_method=method,
    )


def _http_client():
    client = Mock(spec=HTTPRequestEngine)
    client.request = AsyncMock()
    client.set_auth_context = Mock()
    client.current_auth_context = None
    return client


def _context(name="user1", patterns=None, privilege_level=1):
    ctx = AuthContext(
        name=name, type=AuthType.BEARER, token=f"{name}-token",
        privilege_level=privilege_level,
    )
    if patterns is not None:
        ctx.unauthorized_patterns = [re.compile(p) for p in patterns]
    return ctx


def _build_module(module_cls, http_client, contexts):
    if module_cls is BOLATestingModule:
        config = BOLAConfig(enabled=True, id_patterns=["sequential"],
                            test_contexts=["user"])
    elif module_cls is AuthenticationTestingModule:
        config = AuthTestingConfig(
            enabled=True, jwt_testing=False,
            weak_secrets_wordlist="wordlists/jwt_secrets.txt",
            test_logout_invalidation=False,
        )
    else:
        config = PropertyTestingConfig(
            enabled=True, sensitive_fields=["password"],
            mass_assignment_fields=["is_admin"],
        )
    return module_cls(config, http_client, contexts)


# (module class, expected finding category, expected OWASP category)
MODULE_MATRIX = [
    (BOLATestingModule, "BOLA_UNAUTHORIZED_ENDPOINT_ACCESS", "API1"),
    (AuthenticationTestingModule, "AUTH_UNAUTHORIZED_ENDPOINT_ACCESS", "API2"),
    (PropertyLevelAuthModule, "PROPERTY_UNAUTHORIZED_ENDPOINT_ACCESS", "API3"),
]


@pytest.mark.parametrize("module_cls,category,owasp", MODULE_MATRIX)
class TestUnauthorizedAssertions:

    @pytest.mark.asyncio
    async def test_access_granted_emits_in_scope_finding(
        self, module_cls, category, owasp
    ):
        """Granted access to a forbidden endpoint -> in-scope finding (Req 55.2)."""
        client = _http_client()

        def side_effect(method, url, *a, **k):
            if NONEXISTENT_MARKER in url:  # negative control: invalid id -> denied
                return _response(404, '{"error": "not found"}', url=url)
            return _response(200, '{"id": 99, "email": "victim@example.com"}', url=url)

        client.request.side_effect = side_effect
        ctx = _context(patterns=[r"/admin/"])
        module = _build_module(module_cls, client, [ctx])

        findings = await module._evaluate_unauthorized_assertions(ENDPOINT, ctx)

        assert len(findings) == 1
        assert findings[0].category == category
        assert findings[0].owasp_category == owasp
        assert findings[0].severity == Severity.HIGH
        assert findings[0].endpoint == ENDPOINT

    @pytest.mark.asyncio
    async def test_access_denied_emits_nothing(self, module_cls, category, owasp):
        """Denied access to the matching endpoint -> no finding (Req 55.3)."""
        client = _http_client()

        def side_effect(method, url, *a, **k):
            if NONEXISTENT_MARKER in url:
                return _response(404, '{"error": "not found"}', url=url)
            return _response(403, '{"error": "forbidden"}', url=url)

        client.request.side_effect = side_effect
        ctx = _context(patterns=[r"/admin/"])
        module = _build_module(module_cls, client, [ctx])

        assert await module._evaluate_unauthorized_assertions(ENDPOINT, ctx) == []

    @pytest.mark.asyncio
    async def test_non_discriminating_baseline_suppresses(
        self, module_cls, category, owasp
    ):
        """A non-discriminating baseline suppresses the finding (Req 55.4)."""
        client = _http_client()
        # Every request (incl. the invalid-resource control) succeeds -> the
        # baseline cannot discriminate, so no accessibility claim is made.
        client.request.side_effect = lambda method, url, *a, **k: _response(
            200, '{"id": 1}', url=url
        )
        ctx = _context(patterns=[r"/admin/"])
        module = _build_module(module_cls, client, [ctx])

        assert await module._evaluate_unauthorized_assertions(ENDPOINT, ctx) == []

    @pytest.mark.asyncio
    async def test_no_assertions_preserve_existing_behavior(
        self, module_cls, category, owasp
    ):
        """No assertions supplied -> no requests issued, no finding (Req 55.5)."""
        client = _http_client()
        ctx = _context(patterns=None)  # unauthorized_patterns stays None
        module = _build_module(module_cls, client, [ctx])

        findings = await module._evaluate_unauthorized_assertions(ENDPOINT, ctx)

        assert findings == []
        client.request.assert_not_called()


if __name__ == "__main__":
    pytest.main([__file__])
