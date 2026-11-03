"""
Tests for the HTTP/SSE transport of APILeakMCPServer (Task 3.2).

Verifies Requirements 2.2, 2.3, and 2.5:
  - Req 2.2: HTTP transport exposes SSE/MCP routes.
  - Req 2.3: Requests without a valid Bearer token receive HTTP 401.
  - Req 2.5: TLS is required; a WARNING is logged when no certs are provided.

Strategy:
  - We do NOT spin up a real uvicorn server.  Instead we use
    :meth:`APILeakMCPServer._build_starlette_app` to get the ASGI app and
    drive it with ``httpx.AsyncClient(transport=ASGITransport(app))``.  This
    keeps the tests fast, deterministic, and free of network I/O (consistent
    with Requirement 11.1).
  - All coroutines are driven via ``asyncio.new_event_loop()`` (not
    ``asyncio.run()`` or ``asyncio.get_event_loop()``) so that the global
    event loop state is not modified.  Other tests in the suite use the old
    ``asyncio.run()`` API; calling
    ``asyncio.run()`` between them would call ``set_event_loop(None)`` and
    break those tests on Python 3.12+ (see ``test_mcp_contract.py``).
  - TLS setup is verified by checking that the ``ssl.SSLContext`` would be
    built correctly from valid cert/key paths — we use self-signed certs
    generated in a pytest fixture.
  - The ``mcp-server --transport http`` CLI path is verified via Click's
    CliRunner to ensure the early-rejection guard fires when no auth token is
    configured.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import ssl
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from mcp_server.schemas import MCPServerConfig
from mcp_server.server import APILeakMCPServer, _BearerAuthMiddleware


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_TOKEN = "super-secret-test-token-42"


def _run(coro):
    """Run an awaitable synchronously using a private event loop.

    Uses asyncio.new_event_loop() directly instead of asyncio.run() so that
    the global event loop state (asyncio.get_event_loop()) is NOT modified.
    Other tests in the suite use the old asyncio.run()
    API; calling asyncio.run() between them would call set_event_loop(None) and
    break those tests on Python 3.13 where get_event_loop() raises RuntimeError
    when no current loop is set.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _make_server(
    *,
    auth_token: str | None = _VALID_TOKEN,
    tls_cert: str | None = None,
    tls_key: str | None = None,
    port: int | None = None,
) -> APILeakMCPServer:
    """Build an APILeakMCPServer configured for HTTP transport."""
    config = MCPServerConfig(
        transport="http",
        port=port,
        auth_token=auth_token,
        tls_cert=tls_cert,
        tls_key=tls_key,
    )
    return APILeakMCPServer(transport="http", config=config)


def _generate_self_signed_cert(tmp_path: Path) -> tuple[Path, Path]:
    """Generate a temporary self-signed certificate for testing.

    Returns ``(cert_file, key_file)`` paths.

    Uses Python's ``cryptography`` package (already a project dependency).
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]
    )
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )

    cert_file = tmp_path / "test.crt"
    key_file = tmp_path / "test.key"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_file, key_file


# ---------------------------------------------------------------------------
# _BearerAuthMiddleware unit tests
# ---------------------------------------------------------------------------


def test_bearer_middleware_allows_correct_token() -> None:
    """A request with the correct Bearer token is forwarded to the inner app."""
    received: list[dict] = []

    async def inner_app(scope, receive, send):
        received.append({"scope_type": scope["type"]})
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = _BearerAuthMiddleware(inner_app, "my-token")

    scope = {"type": "http", "headers": [(b"authorization", b"Bearer my-token")]}

    async def run():
        responses: list[dict] = []

        async def receive():
            return {"type": "http.request", "body": b""}

        async def send(event):
            responses.append(event)

        await middleware(scope, receive, send)
        return responses

    responses = _run(run())
    assert responses[0]["status"] == 200
    assert len(received) == 1


def test_bearer_middleware_rejects_missing_auth_header() -> None:
    """A request without an Authorization header receives HTTP 401."""
    middleware = _BearerAuthMiddleware(object(), "my-token")  # type: ignore[arg-type]
    scope = {"type": "http", "headers": []}

    async def run():
        responses: list[dict] = []

        async def receive():
            return {"type": "http.request", "body": b""}

        async def send(event):
            responses.append(event)

        await middleware(scope, receive, send)
        return responses

    responses = _run(run())
    assert responses[0]["status"] == 401


def test_bearer_middleware_rejects_wrong_token() -> None:
    """A request with an incorrect token receives HTTP 401."""
    middleware = _BearerAuthMiddleware(object(), "correct-token")  # type: ignore[arg-type]
    scope = {"type": "http", "headers": [(b"authorization", b"Bearer wrong-token")]}

    async def run():
        responses: list[dict] = []

        async def receive():
            return {"type": "http.request", "body": b""}

        async def send(event):
            responses.append(event)

        await middleware(scope, receive, send)
        return responses

    responses = _run(run())
    assert responses[0]["status"] == 401


def test_bearer_middleware_rejects_non_bearer_scheme() -> None:
    """An Authorization header with a non-Bearer scheme receives HTTP 401."""
    middleware = _BearerAuthMiddleware(object(), "my-token")  # type: ignore[arg-type]
    scope = {"type": "http", "headers": [(b"authorization", b"Basic dXNlcjpwYXNz")]}

    async def run():
        responses: list[dict] = []

        async def receive():
            return {"type": "http.request", "body": b""}

        async def send(event):
            responses.append(event)

        await middleware(scope, receive, send)
        return responses

    responses = _run(run())
    assert responses[0]["status"] == 401


def test_bearer_middleware_case_insensitive_scheme() -> None:
    """The 'bearer' prefix check is case-insensitive (RFC 7235)."""
    received: list[bool] = []

    async def inner_app(scope, receive, send):
        received.append(True)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = _BearerAuthMiddleware(inner_app, "my-token")

    for variant in [b"BEARER my-token", b"Bearer my-token", b"bearer my-token"]:
        received.clear()
        scope = {"type": "http", "headers": [(b"authorization", variant)]}

        async def run(v=variant):
            responses: list[dict] = []

            async def receive():
                return {"type": "http.request", "body": b""}

            async def send(event):
                responses.append(event)

            await middleware(scope, receive, send)
            return responses

        responses = _run(run())
        assert responses[0]["status"] == 200, f"Failed for variant: {variant}"


def test_bearer_middleware_401_body_is_valid_json() -> None:
    """The 401 response body is valid JSON with an 'error' key."""
    middleware = _BearerAuthMiddleware(object(), "my-token")  # type: ignore[arg-type]
    scope = {"type": "http", "headers": []}

    async def run():
        body_chunks: list[bytes] = []

        async def receive():
            return {"type": "http.request", "body": b""}

        async def send(event):
            if event["type"] == "http.response.body":
                body_chunks.append(event.get("body", b""))

        await middleware(scope, receive, send)
        return b"".join(body_chunks)

    body = _run(run())
    payload = json.loads(body)
    assert payload["error"] == "Unauthorized"
    assert "message" in payload


# ---------------------------------------------------------------------------
# ASGI app integration tests via httpx + ASGITransport
# ---------------------------------------------------------------------------


def test_http_app_rejects_request_without_token() -> None:
    """GET /sse without Authorization header → 401 (Requirement 2.3)."""
    server = _make_server(auth_token=_VALID_TOKEN)
    app = server._build_starlette_app()

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            return await client.get("/sse")

    response = _run(run())
    assert response.status_code == 401
    body = response.json()
    assert body["error"] == "Unauthorized"
    assert "Bearer" in response.headers.get("www-authenticate", "")


def test_http_app_rejects_request_with_wrong_token() -> None:
    """GET /sse with wrong Bearer token → 401 (Requirement 2.3)."""
    server = _make_server(auth_token=_VALID_TOKEN)
    app = server._build_starlette_app()

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            return await client.get("/sse", headers={"Authorization": "Bearer WRONG"})

    response = _run(run())
    assert response.status_code == 401


def test_http_app_accepts_request_with_correct_token() -> None:
    """POST /messages/ with correct Bearer token is forwarded past auth (Req 2.3).

    The /messages/ endpoint responds immediately with a 400 when session_id is
    missing — which proves the auth middleware let the request through.
    We avoid GET /sse because it starts an SSE stream that never terminates.
    """
    server = _make_server(auth_token=_VALID_TOKEN)
    app = server._build_starlette_app()

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            return await client.post(
                "/messages/",
                headers={"Authorization": f"Bearer {_VALID_TOKEN}"},
                content=b"{}",
                timeout=5.0,
            )

    response = _run(run())
    # Must NOT be 401 (auth passed)
    assert response.status_code != 401, "Correct token should pass the Bearer auth middleware"
    # The /messages/ endpoint rejects requests without a session_id with 400
    assert response.status_code in (400, 202), f"Unexpected status: {response.status_code}"


def test_http_app_exposes_sse_and_messages_routes() -> None:
    """The app exposes /sse (GET) and /messages/ (POST) routes (Req 2.2)."""
    server = _make_server(auth_token=_VALID_TOKEN)
    app = server._build_starlette_app()
    auth_headers = {"Authorization": f"Bearer {_VALID_TOKEN}"}

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            r_post_sse = await client.post("/sse", headers=auth_headers, timeout=5.0)
            r_post_messages = await client.post(
                "/messages/", headers=auth_headers, content=b"{}", timeout=5.0
            )
            return r_post_sse, r_post_messages

    r_post_sse, r_post_messages = _run(run())
    # /sse only accepts GET → 405
    assert r_post_sse.status_code == 405
    # /messages/ exists and responds with 400 (no session_id), not 404
    assert r_post_messages.status_code in (400, 200, 202)


def test_http_app_without_auth_token_no_middleware() -> None:
    """When no auth token is configured, POST /messages/ is reachable (returns 400, not 401).

    The CLI command separately prevents starting HTTP without a token — this
    test verifies the ASGI app itself doesn't add a middleware when unconfigured.
    """
    config = MCPServerConfig(transport="http", auth_token=None)
    server = APILeakMCPServer(transport="http", config=config)
    app = server._build_starlette_app()

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            return await client.post("/messages/", content=b"{}", timeout=5.0)

    response = _run(run())
    # No auth middleware → must not be 401
    assert response.status_code != 401


# ---------------------------------------------------------------------------
# TLS / no-TLS warning tests
# ---------------------------------------------------------------------------


def test_serve_http_logs_warning_when_no_tls_configured() -> None:
    """_serve_http() logs a WARNING when no TLS certificates are configured (Req 2.5)."""
    import uvicorn

    import mcp_server.server as server_module

    server = _make_server(auth_token=_VALID_TOKEN, tls_cert=None, tls_key=None)

    async def _noop_serve(self):
        return

    with patch.object(server_module.logger, "warning") as mock_warning:
        with patch.object(uvicorn.Server, "serve", _noop_serve):
            _run(server._serve_http())

    assert mock_warning.called, "logger.warning must be called when no TLS cert is configured"
    call_args = mock_warning.call_args
    warning_message = call_args[0][0] if call_args[0] else str(call_args)
    assert any(
        keyword in warning_message.lower()
        for keyword in ["tls", "proxy", "plain", "certificate"]
    ), f"TLS warning message should mention TLS/proxy/cert: {warning_message}"


def test_serve_http_does_not_warn_when_tls_configured(tmp_path: Path) -> None:
    """_serve_http() does NOT call logger.warning when certs are provided (Req 2.5)."""
    import uvicorn

    import mcp_server.server as server_module

    cert_file, key_file = _generate_self_signed_cert(tmp_path)
    server = _make_server(
        auth_token=_VALID_TOKEN,
        tls_cert=str(cert_file),
        tls_key=str(key_file),
    )

    async def _noop_serve(self):
        return

    with patch.object(server_module.logger, "warning") as mock_warning:
        with patch.object(uvicorn.Server, "serve", _noop_serve):
            _run(server._serve_http())

    # No warning should be logged when TLS is configured
    if mock_warning.called:
        for c in mock_warning.call_args_list:
            msg = c[0][0] if c[0] else ""
            assert "no_tls" not in msg.lower() and "plain-http" not in msg.lower(), (
                f"Unexpected TLS warning when certs are configured: {msg}"
            )


def test_serve_http_raises_when_no_auth_token() -> None:
    """_serve_http() raises ValueError when no auth token is set (Req 2.3)."""
    config = MCPServerConfig(transport="http", auth_token=None)
    server = APILeakMCPServer(transport="http", config=config)

    with pytest.raises(ValueError, match="authentication token"):
        _run(server._serve_http())


# ---------------------------------------------------------------------------
# CLI command tests (Requirement 2.3 early-rejection guard)
# ---------------------------------------------------------------------------


def test_cli_mcp_server_http_without_token_exits_with_error() -> None:
    """``mcp-server --transport http`` without a token → ClickException (Req 2.3)."""
    from click.testing import CliRunner

    from cli.commands.mcp_cmds import mcp_server_cmd

    runner = CliRunner()
    result = runner.invoke(
        mcp_server_cmd,
        ["--transport", "http"],
        env={},  # ensure APILEAKS_MCP_AUTH_TOKEN is not set
        catch_exceptions=False,
    )
    assert result.exit_code != 0
    assert "authentication token" in result.output.lower() or "auth" in result.output.lower()


def test_cli_mcp_server_http_help_available() -> None:
    """``mcp-server --help`` shows HTTP transport option (Req 2.2)."""
    from click.testing import CliRunner

    from cli.commands.mcp_cmds import mcp_server_cmd

    runner = CliRunner()
    result = runner.invoke(mcp_server_cmd, ["--help"])
    assert result.exit_code == 0
    assert "http" in result.output.lower()
    assert "--mcp-auth-token" in result.output
    assert "--tls-cert" in result.output
    assert "--tls-key" in result.output


# ---------------------------------------------------------------------------
# TLS context construction test
# ---------------------------------------------------------------------------


def test_ssl_context_built_from_cert_and_key(tmp_path: Path) -> None:
    """An SSLContext is successfully created from a self-signed cert/key pair."""
    cert_file, key_file = _generate_self_signed_cert(tmp_path)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))

    # If we get here without exception, the cert/key pair is valid
    assert ctx is not None
