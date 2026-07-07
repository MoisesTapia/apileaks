"""
tests/test_auth_flow.py
Tests for ci-cd/scripts/auth_flow.py

Requirements: 12
"""

import logging
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# Import path — ci-cd/scripts has a hyphen so we inject the path manually.
# ---------------------------------------------------------------------------
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "ci-cd", "scripts"),
)

from auth_flow import AutoAuthFlow, AuthFlowConfig, AuthResult  # noqa: E402
from openapi_discoverer import DiscoveredEndpoint  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(
    login_url: str = "https://api.example.com/auth/login",
    username: str = "user@example.com",
    password: str = "s3cr3t",
    token_field: str = "access_token",
    refresh_token_field: str = None,
    mfa_totp_secret: str = None,
    mfa_field: str = "totp_code",
    concurrency: int = 10,
) -> AuthFlowConfig:
    return AuthFlowConfig(
        login_url=login_url,
        username=username,
        password=password,
        token_field=token_field,
        refresh_token_field=refresh_token_field,
        mfa_totp_secret=mfa_totp_secret,
        mfa_field=mfa_field,
        concurrency=concurrency,
    )


def _make_endpoint(
    path: str = "https://api.example.com/users",
    methods: list = None,
    is_authenticated: bool = True,
) -> DiscoveredEndpoint:
    return DiscoveredEndpoint(
        path=path,
        methods=methods or ["GET"],
        security_schemes=["BearerAuth"],
        is_authenticated=is_authenticated,
        parameters=[],
        id_parameters=[],
    )


def _mock_response(status_code: int, json_data: dict = None, text: str = "") -> MagicMock:
    """Build a mock httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.text = text if json_data is None else ""
    if json_data is not None:
        resp.json.return_value = json_data
        resp.text = str(json_data)
    else:
        resp.json.side_effect = Exception("Not JSON")
    return resp


# ---------------------------------------------------------------------------
# 1. test_login_200_valid_token
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_200_valid_token():
    """A 200 response with the expected token field returns a correct AuthResult."""
    config = _make_config()
    flow = AutoAuthFlow(config)

    mock_resp = _mock_response(200, {"access_token": "my.jwt.token"})
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await flow.login()

    assert result.access_token == "my.jwt.token"
    assert result.token_field == "access_token"
    assert result.refresh_token is None


# ---------------------------------------------------------------------------
# 2. test_login_200_missing_jwt_field
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_200_missing_jwt_field(caplog):
    """200 response with missing JWT field must call sys.exit(1)."""
    config = _make_config()
    flow = AutoAuthFlow(config)

    mock_resp = _mock_response(200, {"other_field": "x"})
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("httpx.AsyncClient", return_value=mock_client):
        with caplog.at_level(logging.ERROR):
            with pytest.raises(SystemExit) as exc_info:
                await flow.login()

    assert exc_info.value.code == 1
    # Error message must mention expected field and present fields
    combined_log = " ".join(r.message for r in caplog.records)
    assert "access_token" in combined_log
    assert "other_field" in combined_log


# ---------------------------------------------------------------------------
# 3. test_login_401
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_401(caplog):
    """401 response must call sys.exit(1) and log the status code."""
    config = _make_config()
    flow = AutoAuthFlow(config)

    mock_resp = _mock_response(401, text="Unauthorized")
    mock_resp.json.side_effect = Exception("no json")
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("httpx.AsyncClient", return_value=mock_client):
        with caplog.at_level(logging.ERROR):
            with pytest.raises(SystemExit) as exc_info:
                await flow.login()

    assert exc_info.value.code == 1
    combined_log = " ".join(r.message for r in caplog.records)
    assert "401" in combined_log


# ---------------------------------------------------------------------------
# 4. test_login_503
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_503(caplog):
    """503 response must call sys.exit(1) and log first 500 chars of body."""
    config = _make_config()
    flow = AutoAuthFlow(config)

    body_text = "Service Unavailable"
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 503
    mock_resp.text = body_text
    mock_resp.json.side_effect = Exception("no json")

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("httpx.AsyncClient", return_value=mock_client):
        with caplog.at_level(logging.ERROR):
            with pytest.raises(SystemExit) as exc_info:
                await flow.login()

    assert exc_info.value.code == 1
    combined_log = " ".join(r.message for r in caplog.records)
    assert "Service Unavailable" in combined_log


# ---------------------------------------------------------------------------
# 5. test_mask_credentials_returns_stars
# ---------------------------------------------------------------------------


def test_mask_credentials_returns_stars():
    """mask_credentials returns same-length string of '*'."""
    result = AutoAuthFlow.mask_credentials("secret123")
    assert result == "*********"
    assert len(result) == len("secret123")
    assert all(c == "*" for c in result)


# ---------------------------------------------------------------------------
# 6. test_mask_credentials_empty_string
# ---------------------------------------------------------------------------


def test_mask_credentials_empty_string():
    """mask_credentials('') returns ''."""
    assert AutoAuthFlow.mask_credentials("") == ""


# ---------------------------------------------------------------------------
# 7. Property 1: Credential masking (Hypothesis)
# **Validates: Requirements 12**
# ---------------------------------------------------------------------------


@given(st.text())
@settings(max_examples=10, suppress_health_check=[HealthCheck.too_slow])
def test_property_mask_credentials_same_length_all_stars(s: str):
    """For any string s, mask_credentials(s) has same length and all '*'."""
    result = AutoAuthFlow.mask_credentials(s)
    assert len(result) == len(s), f"Length mismatch: {len(result)} != {len(s)}"
    assert all(c == "*" for c in result), f"Non-star char in result: {result!r}"


# ---------------------------------------------------------------------------
# 8. test_no_credentials_in_logs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_credentials_in_logs(caplog):
    """After login, no log message should contain the plaintext username or password."""
    username = "admin@example.com"
    password = "SuperSecret99!"
    config = _make_config(username=username, password=password)
    flow = AutoAuthFlow(config)

    mock_resp = _mock_response(200, {"access_token": "tok.123"})
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("httpx.AsyncClient", return_value=mock_client):
        with caplog.at_level(logging.DEBUG):
            await flow.login()

    for record in caplog.records:
        assert username not in record.getMessage(), (
            f"Username found in log: {record.getMessage()!r}"
        )
        assert password not in record.getMessage(), (
            f"Password found in log: {record.getMessage()!r}"
        )


# ---------------------------------------------------------------------------
# 9. Property 2: Token in-memory only (no refresh token written to disk)
# **Validates: Requirements 12**
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_property_refresh_token_not_written_to_disk(tmp_path):
    """After login, the refresh token value must not appear in any file on disk."""
    refresh_token_value = "SUPER_SECRET_REFRESH_TOKEN_XYZ789"
    config = _make_config(
        refresh_token_field="refresh_token",
    )
    flow = AutoAuthFlow(config)

    mock_resp = _mock_response(200, {
        "access_token": "access.tok",
        "refresh_token": refresh_token_value,
    })
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)

    # Redirect any temp file writes to tmp_path
    import tempfile as _tempfile

    created_files = []

    original_ntf = _tempfile.NamedTemporaryFile

    def mock_ntf(*args, **kwargs):
        kwargs.setdefault("dir", str(tmp_path))
        f = original_ntf(*args, **kwargs)
        created_files.append(f.name)
        return f

    with patch("httpx.AsyncClient", return_value=mock_client):
        with patch("tempfile.NamedTemporaryFile", side_effect=mock_ntf):
            result = await flow.login()

    assert result.refresh_token == refresh_token_value

    # Check no created temp files contain the refresh token
    for file_path in created_files:
        try:
            with open(file_path, "r") as f:
                content = f.read()
            assert refresh_token_value not in content, (
                f"Refresh token found in temp file {file_path}"
            )
        except FileNotFoundError:
            pass  # file already cleaned up


# ---------------------------------------------------------------------------
# 10. test_refresh_3_attempts_then_relogin
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_3_attempts_then_relogin():
    """First 3 refresh calls return 401, then re-login returns 200 with new token."""
    config = _make_config(refresh_token_field="refresh_token")
    flow = AutoAuthFlow(config)

    old_auth = AuthResult(
        access_token="old.token",
        refresh_token="old_refresh",
        token_field="access_token",
        expires_in=None,
    )

    fail_resp = MagicMock(spec=httpx.Response)
    fail_resp.status_code = 401
    fail_resp.text = "Unauthorized"
    fail_resp.json.side_effect = Exception("no json")

    success_resp = _mock_response(200, {"access_token": "new.token"})

    call_count = {"n": 0}

    async def mock_post(url, json=None, **kwargs):
        call_count["n"] += 1
        # First 3 calls (refresh attempts) fail
        if call_count["n"] <= 3:
            return fail_resp
        # 4th call (re-login) succeeds
        return success_resp

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = mock_post

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await flow.refresh(old_auth)

    assert result.access_token == "new.token"


# ---------------------------------------------------------------------------
# 11. test_refresh_all_fail_exits_2
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_all_fail_exits_2():
    """All refresh attempts and re-login fail → sys.exit(2)."""
    config = _make_config(refresh_token_field="refresh_token")
    flow = AutoAuthFlow(config)

    old_auth = AuthResult(
        access_token="old.token",
        refresh_token="old_refresh",
        token_field="access_token",
        expires_in=None,
    )

    fail_resp = MagicMock(spec=httpx.Response)
    fail_resp.status_code = 500
    fail_resp.text = "Internal Server Error"
    fail_resp.json.side_effect = Exception("no json")

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=fail_resp)

    with patch("httpx.AsyncClient", return_value=mock_client):
        with pytest.raises(SystemExit) as exc_info:
            await flow.refresh(old_auth)

    assert exc_info.value.code == 2


# ---------------------------------------------------------------------------
# 12. test_totp_mfa_included_in_login
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_totp_mfa_included_in_login():
    """Login with mfa_totp_secret includes a totp_code field in the request body."""
    import pyotp

    secret = "BASE32SECRET3232"
    config = _make_config(mfa_totp_secret=secret)
    flow = AutoAuthFlow(config)

    captured_body = {}

    mock_resp = _mock_response(200, {"access_token": "tok.mfa"})
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    async def mock_post(url, json=None, **kwargs):
        captured_body.update(json or {})
        return mock_resp

    mock_client.post = mock_post

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await flow.login()

    assert "totp_code" in captured_body, "totp_code field missing from login body"
    # Validate that the code matches expected TOTP
    expected_code = pyotp.TOTP(secret).now()
    # TOTP codes are time-based and valid for ~30s, so also allow adjacent
    totp = pyotp.TOTP(secret)
    assert totp.verify(captured_body["totp_code"], valid_window=1), (
        f"TOTP code {captured_body['totp_code']!r} is not valid for secret"
    )
    assert result.access_token == "tok.mfa"


# ---------------------------------------------------------------------------
# 13. test_broken_auth_no_auth_header_gets_200_is_critical
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_broken_auth_no_auth_header_gets_200_is_critical():
    """Endpoint returns 200 without Authorization header → CRITICAL finding."""
    config = _make_config()
    flow = AutoAuthFlow(config)

    endpoint = _make_endpoint(path="https://api.example.com/users", is_authenticated=True)

    ok_resp = MagicMock(spec=httpx.Response)
    ok_resp.status_code = 200

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.request = AsyncMock(return_value=ok_resp)

    with patch("httpx.AsyncClient", return_value=mock_client):
        findings = await flow.test_broken_auth([endpoint])

    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    assert len(critical) >= 1, f"Expected CRITICAL finding, got: {findings}"
    assert critical[0]["endpoint"] == "https://api.example.com/users"


# ---------------------------------------------------------------------------
# 14. test_broken_auth_invalid_jwt_gets_200_is_high
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_broken_auth_invalid_jwt_gets_200_is_high():
    """Endpoint returns 200 with invalid JWT → HIGH finding."""
    config = _make_config()
    flow = AutoAuthFlow(config)

    endpoint = _make_endpoint(path="https://api.example.com/data", is_authenticated=True)

    # First call (no-auth): 401 — not vulnerable to missing auth
    # Second call (invalid JWT): 200 — vulnerable to invalid token
    call_count = {"n": 0}

    async def mock_request(method, url, **kwargs):
        call_count["n"] += 1
        resp = MagicMock(spec=httpx.Response)
        if call_count["n"] == 1:
            resp.status_code = 401  # no-auth check: properly secured
        else:
            resp.status_code = 200  # invalid JWT: vulnerable
        return resp

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.request = mock_request

    with patch("httpx.AsyncClient", return_value=mock_client):
        findings = await flow.test_broken_auth([endpoint])

    high = [f for f in findings if f["severity"] == "HIGH"]
    assert len(high) >= 1, f"Expected HIGH finding, got: {findings}"
    assert high[0]["endpoint"] == "https://api.example.com/data"


# ---------------------------------------------------------------------------
# 15. test_broken_auth_unreachable_endpoint_does_not_stop
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_broken_auth_unreachable_endpoint_does_not_stop():
    """ConnectError on one endpoint does not stop the pipeline; others are still tested."""
    config = _make_config()
    flow = AutoAuthFlow(config)

    unreachable = _make_endpoint(
        path="https://unreachable.example.com/fail", is_authenticated=True
    )
    reachable = _make_endpoint(
        path="https://api.example.com/ok", is_authenticated=True
    )

    ok_resp = MagicMock(spec=httpx.Response)
    ok_resp.status_code = 401  # properly secured

    async def mock_request(method, url, **kwargs):
        if "unreachable" in url:
            raise httpx.ConnectError("Connection refused")
        return ok_resp

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.request = mock_request

    # Should complete without raising any exception
    with patch("httpx.AsyncClient", return_value=mock_client):
        findings = await flow.test_broken_auth([unreachable, reachable])

    # No critical/high findings for the reachable endpoint (it returned 401)
    assert isinstance(findings, list)
    # Reachable endpoint was tested (no finding) — unreachable was skipped gracefully
    unreachable_findings = [f for f in findings if "unreachable" in f.get("endpoint", "")]
    assert unreachable_findings == [], "Unreachable endpoint should produce no findings"
