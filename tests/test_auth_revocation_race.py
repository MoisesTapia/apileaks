"""
Unit tests for the token-revocation race probe (Requirement 42) in the
Authentication Testing Module.

Covers ``_test_revocation_race``:
* aggressive-gate enforcement - no request and no finding when Safe_Mode is on
  or the Aggressive_Opt_In is absent (Reqs 42.1, 42.5, 46.1-46.3);
* bounded concurrency - the total requests issued never exceed
  ``config.revocation_race_requests`` (Reqs 42.2, 46.4);
* detection - an ``AUTH_TOKEN_REVOCATION_RACE`` (API2) finding when a protected
  request is accepted after logout under concurrency (Reqs 42.3, 42.4);
* no finding when the token is rejected after logout, or when the logout itself
  is not accepted.
"""

import asyncio
from unittest.mock import Mock, AsyncMock

from modules.owasp.auth_testing import AuthenticationTestingModule
from utils.http_client import HTTPRequestEngine, Response
from core.config import AuthTestingConfig, Severity


TOKEN = "revocation-race-token"
LOGOUT = "https://api.example.com/logout"
PROTECTED = "https://api.example.com/me"


def _resp(status_code, method, url, body="{}"):
    content = body.encode() if isinstance(body, str) else body
    text = body if isinstance(body, str) else body.decode(errors="ignore")
    return Response(status_code, {"content-type": "application/json"},
                    content, text, url, 0.01, str(method).upper())


def _make_module(*, safe_mode=False, allow_aggressive=True,
                 revocation_race_requests=8):
    config = AuthTestingConfig(
        safe_mode=safe_mode,
        allow_aggressive=allow_aggressive,
        revocation_race_requests=revocation_race_requests,
    )
    http_client = Mock(spec=HTTPRequestEngine)
    http_client.request = AsyncMock()
    http_client.set_auth_context = Mock()
    http_client.current_auth_context = None
    module = AuthenticationTestingModule(config, http_client, [])
    return module, http_client


def _route(logout_status=200, protected_status=200):
    """Return a request side-effect that answers by HTTP method."""
    async def _side_effect(method, url, **kwargs):
        if str(method).upper() == "POST":
            return _resp(logout_status, method, url)
        return _resp(protected_status, method, url)
    return _side_effect


# ---------------------------------------------------------------------------
# Gate enforcement
# ---------------------------------------------------------------------------

def test_skips_when_safe_mode_on():
    module, http_client = _make_module(safe_mode=True, allow_aggressive=True)
    http_client.request.side_effect = _route()

    findings = asyncio.run(module._test_revocation_race(TOKEN, LOGOUT, PROTECTED))

    assert findings == []
    http_client.request.assert_not_called()


def test_skips_when_opt_in_absent():
    module, http_client = _make_module(safe_mode=False, allow_aggressive=False)
    http_client.request.side_effect = _route()

    findings = asyncio.run(module._test_revocation_race(TOKEN, LOGOUT, PROTECTED))

    assert findings == []
    http_client.request.assert_not_called()


def test_skips_when_no_token():
    module, http_client = _make_module()
    http_client.request.side_effect = _route()

    findings = asyncio.run(module._test_revocation_race("", LOGOUT, PROTECTED))

    assert findings == []
    http_client.request.assert_not_called()


def test_skips_when_bound_too_small():
    # A budget of 1 leaves no room for a protected request after the logout.
    module, http_client = _make_module(revocation_race_requests=1)
    http_client.request.side_effect = _route()

    findings = asyncio.run(module._test_revocation_race(TOKEN, LOGOUT, PROTECTED))

    assert findings == []
    http_client.request.assert_not_called()


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def test_reports_finding_when_token_accepted_after_logout():
    module, http_client = _make_module(revocation_race_requests=6)
    http_client.request.side_effect = _route(logout_status=200, protected_status=200)

    findings = asyncio.run(module._test_revocation_race(TOKEN, LOGOUT, PROTECTED))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == "AUTH_TOKEN_REVOCATION_RACE"
    assert finding.owasp_category == "API2"
    assert finding.severity == Severity.HIGH
    assert finding.endpoint == PROTECTED
    # Evidence documents post-logout acceptance under concurrency.
    assert "revocation" in finding.evidence.lower()


def test_no_finding_when_token_rejected_after_logout():
    module, http_client = _make_module(revocation_race_requests=6)
    http_client.request.side_effect = _route(logout_status=200, protected_status=401)

    findings = asyncio.run(module._test_revocation_race(TOKEN, LOGOUT, PROTECTED))

    assert findings == []


def test_no_finding_when_logout_not_accepted():
    module, http_client = _make_module(revocation_race_requests=6)
    # Logout fails => post-revocation acceptance is not meaningful.
    http_client.request.side_effect = _route(logout_status=500, protected_status=200)

    findings = asyncio.run(module._test_revocation_race(TOKEN, LOGOUT, PROTECTED))

    assert findings == []


# ---------------------------------------------------------------------------
# Bounded concurrency
# ---------------------------------------------------------------------------

def test_total_requests_never_exceed_bound():
    for bound in (2, 3, 5, 8, 12):
        module, http_client = _make_module(revocation_race_requests=bound)
        http_client.request.side_effect = _route()

        asyncio.run(module._test_revocation_race(TOKEN, LOGOUT, PROTECTED))

        assert http_client.request.call_count <= bound
        # Exactly one logout (POST) and the remainder protected (GET) requests.
        methods = [c.args[0].upper() for c in http_client.request.call_args_list]
        assert methods.count("POST") == 1
        assert methods.count("GET") == bound - 1


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
