"""
Unit tests for insecure credential transport (Req 38) and MFA bypass (Req 39)
detection in the Authentication Testing Module.

Covers:
* ``_build_secret_in_url`` query-parameter substitution discipline (Req 38).
* ``_test_secret_in_url`` negative-control-calibrated detection, suppression of
  non-discriminating endpoints, and secret redaction (Reqs 38.1-38.4).
* ``_test_mfa_bypass`` negative-control-calibrated detection, skip-on-missing
  inputs, suppression of non-discriminating endpoints, and evidence redaction
  (Reqs 39.1-39.5).
"""

import asyncio
from unittest.mock import Mock, AsyncMock

import pytest

from modules.owasp.auth_testing import AuthenticationTestingModule
from utils.http_client import HTTPRequestEngine, Response
from core.config import AuthTestingConfig, AuthContext, AuthType, Severity


def _resp(status_code, body="", url="https://api.example.com/data"):
    """Build a Response with the module's positional field order."""
    content = body.encode() if isinstance(body, str) else body
    text = body if isinstance(body, str) else body.decode(errors="ignore")
    return Response(status_code, {"content-type": "application/json"},
                    content, text, url, 0.1, "GET")


def _make_module():
    config = AuthTestingConfig()
    http_client = Mock(spec=HTTPRequestEngine)
    http_client.request = AsyncMock()
    http_client.set_auth_context = Mock()
    http_client.current_auth_context = None
    module = AuthenticationTestingModule(config, http_client, [])
    return module, http_client


VALID_SECRET = "VALIDSECRETTOKEN1234567890"


# ---------------------------------------------------------------------------
# _build_secret_in_url
# ---------------------------------------------------------------------------

def test_build_secret_in_url_sets_param_and_preserves_others():
    module, _ = _make_module()
    url = module._build_secret_in_url(
        "https://api.example.com/v1/data?foo=bar&baz=qux", "access_token", "S3CR3T"
    )
    assert "access_token=S3CR3T" in url
    # Existing parameters preserved.
    assert "foo=bar" in url
    assert "baz=qux" in url
    # Path preserved.
    assert "/v1/data" in url


def test_build_secret_in_url_overwrites_existing_param():
    module, _ = _make_module()
    url = module._build_secret_in_url(
        "https://api.example.com/data?token=old", "token", "new"
    )
    assert "token=new" in url
    assert "token=old" not in url


# ---------------------------------------------------------------------------
# _test_secret_in_url
# ---------------------------------------------------------------------------

def test_secret_in_url_reports_when_accepted():
    """Valid URL secret grants access; invalid does not => AUTH_SECRET_IN_URL."""
    module, http_client = _make_module()
    module.SECRET_URL_PARAM_NAMES = ["access_token"]

    async def side_effect(method, url, **kwargs):
        if VALID_SECRET in url:
            return _resp(200, '{"id": 42, "email": "user@example.com"}', url)
        return _resp(401, '{"error": "unauthorized"}', url)

    http_client.request.side_effect = side_effect
    ctx = AuthContext(name="user", type=AuthType.BEARER, token=VALID_SECRET)

    findings = asyncio.run(module._test_secret_in_url("https://api.example.com/data", ctx))

    assert len(findings) == 1
    f = findings[0]
    assert f.category == "AUTH_SECRET_IN_URL"
    assert f.owasp_category == "API2"
    assert f.severity == Severity.HIGH
    assert "access_token" in f.evidence
    # Leakage surfaces named as evidence (Req 38.3).
    assert "Referer" in f.evidence
    # Secret value never echoed (Req 38.3).
    assert VALID_SECRET not in f.evidence
    assert "<redacted>" in f.evidence


def test_secret_in_url_suppressed_when_non_discriminating():
    """Endpoint returns success for an invalid secret => suppressed (Req 3.4)."""
    module, http_client = _make_module()
    module.SECRET_URL_PARAM_NAMES = ["access_token"]
    # Every request (including the invalid-secret baseline) returns success.
    http_client.request = AsyncMock(return_value=_resp(200, '{"id": 1}'))
    ctx = AuthContext(name="user", type=AuthType.BEARER, token=VALID_SECRET)

    findings = asyncio.run(module._test_secret_in_url("https://api.example.com/data", ctx))
    assert findings == []


def test_secret_in_url_no_finding_when_not_accepted():
    """URL secret rejected (same as invalid) => no finding."""
    module, http_client = _make_module()
    module.SECRET_URL_PARAM_NAMES = ["access_token"]
    http_client.request = AsyncMock(return_value=_resp(401, '{"error": "unauthorized"}'))
    ctx = AuthContext(name="user", type=AuthType.BEARER, token=VALID_SECRET)

    findings = asyncio.run(module._test_secret_in_url("https://api.example.com/data", ctx))
    assert findings == []


def test_secret_in_url_skipped_without_secret():
    """No secret in the auth context => nothing probed."""
    module, http_client = _make_module()
    ctx = AuthContext(name="empty", type=AuthType.BEARER, token="")

    findings = asyncio.run(module._test_secret_in_url("https://api.example.com/data", ctx))
    assert findings == []
    http_client.request.assert_not_called()


# ---------------------------------------------------------------------------
# _test_mfa_bypass
# ---------------------------------------------------------------------------

PROVISIONAL_TOKEN = "PROVISIONALtoken0987654321"


def test_mfa_bypass_reports_when_access_granted():
    """Provisional token grants access; invalid denied => AUTH_MFA_BYPASS."""
    module, http_client = _make_module()
    # Order: negative control (invalid token) then provisional probe.
    http_client.request.side_effect = [
        _resp(401, '{"error": "unauthorized"}'),
        _resp(200, '{"id": 7, "user_id": 7}'),
    ]

    findings = asyncio.run(
        module._test_mfa_bypass(PROVISIONAL_TOKEN, "https://api.example.com/protected")
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.category == "AUTH_MFA_BYPASS"
    assert f.owasp_category == "API2"
    assert f.severity == Severity.CRITICAL
    assert "https://api.example.com/protected" in f.evidence
    # Provisional token value never echoed (Req 38.3 reuse).
    assert PROVISIONAL_TOKEN not in f.evidence
    assert "<redacted>" in f.evidence


def test_mfa_bypass_skipped_without_inputs():
    """No multi-step flow inputs => skip and log (Req 39.5)."""
    module, http_client = _make_module()

    findings = asyncio.run(module._test_mfa_bypass("", "https://api.example.com/protected"))
    assert findings == []

    findings = asyncio.run(module._test_mfa_bypass(PROVISIONAL_TOKEN, ""))
    assert findings == []

    http_client.request.assert_not_called()


def test_mfa_bypass_suppressed_when_non_discriminating():
    """Endpoint returns success for an invalid token => suppressed (Req 39.4)."""
    module, http_client = _make_module()
    http_client.request = AsyncMock(return_value=_resp(200, '{"id": 1}'))

    findings = asyncio.run(
        module._test_mfa_bypass(PROVISIONAL_TOKEN, "https://api.example.com/protected")
    )
    assert findings == []


def test_mfa_bypass_no_finding_when_access_denied():
    """Provisional token denied (same as invalid) => no finding."""
    module, http_client = _make_module()
    http_client.request.side_effect = [
        _resp(401, '{"error": "unauthorized"}'),
        _resp(401, '{"error": "mfa required"}'),
    ]

    findings = asyncio.run(
        module._test_mfa_bypass(PROVISIONAL_TOKEN, "https://api.example.com/protected")
    )
    assert findings == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
