"""
Unit tests for transport and TLS options for discovery.

**Feature: owasp-complete-purple-teaming-cicd, Task 33.2**

These tests cover Requirement 29 (Transport and TLS Options for Discovery),
validating the wiring implemented in task 33.1:

- client certificate (mTLS) and custom CA bundle are threaded into the underlying
  httpx ``AsyncClient`` via ``client_kwargs`` (29.1, 29.2)
- the same-domain redirect default and the ``--allow-cross-domain-redirects``
  toggle drive ``_handle_redirect`` in the EndpointFuzzer (29.3)
- ``parse_resolve`` parses a ``host:ip`` pair and the resolve override mounts a
  DNS-override transport on the client (29.4)
- a SOCKS5 ``--proxy`` URL flows through ``client_kwargs['proxy']`` (29.5)
- unreadable ``--client-cert``/``--ca-bundle`` paths and a malformed ``--resolve``
  value are rejected at the CLI layer, naming the offending path/value, with NO
  discovery performed; ``parse_resolve`` raises a descriptive ``ValueError`` for
  the malformed value (29.6, 29.7)

No real network I/O is performed: ``httpx.AsyncClient`` is patched to capture the
kwargs it is constructed with, ``_handle_redirect`` is exercised against an
AsyncMock ``_test_endpoint``, and the CLI tests patch out the discovery entry
point so option validation is proven to run *before* any discovery.
"""

from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

import apileaks
from apileaks import cli
from core.config import (
    FuzzingConfig,
    EndpointFuzzingConfig,
    ParameterFuzzingConfig,
    HeaderFuzzingConfig,
    RateLimitConfig,
)
from modules.fuzzing.orchestrator import EndpointFuzzer, Endpoint
from utils.http_client import (
    HTTPRequestEngine,
    RateLimiter,
    RetryConfig,
    Response,
    parse_resolve,
    _ResolveOverrideTransport,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_engine(**kwargs) -> HTTPRequestEngine:
    """Construct an HTTPRequestEngine with a fast rate limiter for tests."""
    rate_limiter = RateLimiter(RateLimitConfig(requests_per_second=100, burst_size=10))
    retry_config = RetryConfig(max_attempts=1)
    return HTTPRequestEngine(rate_limiter, retry_config, **kwargs)


@contextmanager
def _capture_async_client_kwargs():
    """Patch ``httpx.AsyncClient`` and capture the kwargs it is built with.

    Yields a dict that is populated with the constructor kwargs once
    ``_ensure_client`` runs, without ever constructing a real client.
    """
    captured = {}

    def _fake_client(**kwargs):
        captured.update(kwargs)
        return MagicMock()

    with patch("utils.http_client.httpx.AsyncClient", side_effect=_fake_client):
        yield captured


def _make_fuzzer(allow_cross_domain_redirects: bool) -> EndpointFuzzer:
    """Build an EndpointFuzzer whose endpoints config carries the toggle."""
    config = FuzzingConfig(
        endpoints=EndpointFuzzingConfig(
            enabled=True,
            follow_redirects=True,
            allow_cross_domain_redirects=allow_cross_domain_redirects,
        ),
        parameters=ParameterFuzzingConfig(enabled=False),
        headers=HeaderFuzzingConfig(enabled=False),
        recursive=False,
        max_depth=0,
    )
    http_client = MagicMock(spec=HTTPRequestEngine)
    return EndpointFuzzer(http_client, config)


def _redirect_response(location: str) -> Response:
    """Build a 302 Response carrying a ``Location`` header."""
    return Response(
        status_code=302,
        headers={"Location": location},
        content=b"",
        text="",
        url="https://api.example.com/old",
        elapsed=0.01,
        request_method="GET",
    )


# ---------------------------------------------------------------------------
# 29.1 / 29.2 — client cert and CA bundle wired into client_kwargs
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_client_cert_path_wired_into_client_kwargs():
    """A client-cert path is applied as httpx ``cert`` on every request.

    **Validates: Requirements 29.1**
    """
    engine = _make_engine(cert="/certs/client.pem")
    with _capture_async_client_kwargs() as kwargs:
        await engine._ensure_client()

    assert kwargs["cert"] == "/certs/client.pem"


@pytest.mark.asyncio
async def test_client_cert_tuple_wired_into_client_kwargs():
    """A (cert, key) tuple is applied unchanged as httpx ``cert``.

    **Validates: Requirements 29.1**
    """
    engine = _make_engine(cert=("/certs/client.pem", "/certs/client.key"))
    with _capture_async_client_kwargs() as kwargs:
        await engine._ensure_client()

    assert kwargs["cert"] == ("/certs/client.pem", "/certs/client.key")


@pytest.mark.asyncio
async def test_no_client_cert_means_no_cert_kwarg():
    """Without a client cert, no ``cert`` kwarg is passed to the client.

    **Validates: Requirements 29.1**
    """
    engine = _make_engine()
    with _capture_async_client_kwargs() as kwargs:
        await engine._ensure_client()

    assert "cert" not in kwargs


@pytest.mark.asyncio
async def test_ca_bundle_overrides_verify_with_path():
    """A CA bundle path overrides the boolean ``verify`` with the path.

    **Validates: Requirements 29.2**
    """
    engine = _make_engine(ca_bundle="/certs/ca.pem")
    with _capture_async_client_kwargs() as kwargs:
        await engine._ensure_client()

    assert kwargs["verify"] == "/certs/ca.pem"


@pytest.mark.asyncio
async def test_ca_bundle_overrides_even_when_verify_ssl_false():
    """A supplied CA bundle takes precedence over a False boolean verify.

    The CA bundle overrides the boolean only when supplied; here it is supplied
    alongside ``verify_ssl=False`` and must win.

    **Validates: Requirements 29.2**
    """
    engine = _make_engine(verify_ssl=False, ca_bundle="/certs/ca.pem")
    with _capture_async_client_kwargs() as kwargs:
        await engine._ensure_client()

    assert kwargs["verify"] == "/certs/ca.pem"


@pytest.mark.asyncio
async def test_no_ca_bundle_keeps_boolean_verify():
    """Without a CA bundle, ``verify`` stays the boolean verify_ssl flag.

    **Validates: Requirements 29.2**
    """
    engine_true = _make_engine()
    with _capture_async_client_kwargs() as kwargs_true:
        await engine_true._ensure_client()
    assert kwargs_true["verify"] is True

    engine_false = _make_engine(verify_ssl=False)
    with _capture_async_client_kwargs() as kwargs_false:
        await engine_false._ensure_client()
    assert kwargs_false["verify"] is False


# ---------------------------------------------------------------------------
# 29.3 — same-domain redirect default and cross-domain toggle
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_same_domain_redirect_followed_by_default():
    """With the toggle absent, a same-domain redirect target is followed.

    **Validates: Requirements 29.3**
    """
    fuzzer = _make_fuzzer(allow_cross_domain_redirects=False)
    fuzzer._test_endpoint = AsyncMock(return_value=None)

    endpoint = Endpoint(
        url="https://api.example.com/old",
        method="GET",
        status_code=302,
        response_size=0,
        response_time=0.01,
    )
    response = _redirect_response("https://api.example.com/new")

    await fuzzer._handle_redirect(endpoint, response)

    fuzzer._test_endpoint.assert_awaited_once()
    followed_url = fuzzer._test_endpoint.await_args.args[1]
    assert followed_url == "https://api.example.com/new"


@pytest.mark.asyncio
async def test_cross_domain_redirect_not_followed_by_default():
    """With the toggle absent, a cross-domain redirect target is NOT followed.

    **Validates: Requirements 29.3**
    """
    fuzzer = _make_fuzzer(allow_cross_domain_redirects=False)
    fuzzer._test_endpoint = AsyncMock(return_value=None)

    endpoint = Endpoint(
        url="https://api.example.com/old",
        method="GET",
        status_code=302,
        response_size=0,
        response_time=0.01,
    )
    response = _redirect_response("https://evil.other.com/landing")

    await fuzzer._handle_redirect(endpoint, response)

    # The cross-domain target is recorded but never fetched.
    assert endpoint.redirect_location == "https://evil.other.com/landing"
    fuzzer._test_endpoint.assert_not_awaited()


@pytest.mark.asyncio
async def test_cross_domain_redirect_followed_when_toggle_enabled():
    """With the toggle enabled, a cross-domain redirect target is followed.

    **Validates: Requirements 29.3**
    """
    fuzzer = _make_fuzzer(allow_cross_domain_redirects=True)
    fuzzer._test_endpoint = AsyncMock(return_value=None)

    endpoint = Endpoint(
        url="https://api.example.com/old",
        method="GET",
        status_code=302,
        response_size=0,
        response_time=0.01,
    )
    response = _redirect_response("https://other.example.net/landing")

    await fuzzer._handle_redirect(endpoint, response)

    fuzzer._test_endpoint.assert_awaited_once()
    followed_url = fuzzer._test_endpoint.await_args.args[1]
    assert followed_url == "https://other.example.net/landing"


# ---------------------------------------------------------------------------
# 29.4 — --resolve DNS override
# ---------------------------------------------------------------------------

def test_parse_resolve_returns_host_ip_tuple():
    """``parse_resolve`` splits a ``host:ip`` value into ``(host, ip)``.

    **Validates: Requirements 29.4**
    """
    assert parse_resolve("api.example.com:127.0.0.1") == (
        "api.example.com",
        "127.0.0.1",
    )


@pytest.mark.asyncio
async def test_resolve_override_mounts_transport_on_client():
    """A resolve override mounts a DNS-override transport under all://<host>.

    **Validates: Requirements 29.4**
    """
    engine = _make_engine(resolve=("api.example.com", "127.0.0.1"))
    with _capture_async_client_kwargs() as kwargs:
        await engine._ensure_client()

    mounts = kwargs["mounts"]
    assert "all://api.example.com" in mounts
    transport = mounts["all://api.example.com"]
    assert isinstance(transport, _ResolveOverrideTransport)
    assert transport._resolve_host == "api.example.com"
    assert transport._resolve_ip == "127.0.0.1"


# ---------------------------------------------------------------------------
# 29.5 — SOCKS5 via --proxy
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_socks5_proxy_passed_through_client_kwargs():
    """A SOCKS5 proxy URL with auth flows through ``client_kwargs['proxy']``.

    **Validates: Requirements 29.5**
    """
    proxy = "socks5://user:pass@127.0.0.1:1080"
    engine = _make_engine(proxy=proxy)
    with _capture_async_client_kwargs() as kwargs:
        await engine._ensure_client()

    assert kwargs["proxy"] == proxy


# ---------------------------------------------------------------------------
# 29.6 / 29.7 — CLI rejection with no discovery; parse_resolve ValueError
# ---------------------------------------------------------------------------

def _invoke_dir(args):
    """Invoke the ``dir`` command patching out the discovery entry point."""
    runner = CliRunner()
    with patch.object(apileaks, "run_enhanced_apileak") as discovery:
        result = runner.invoke(
            cli,
            ["--no-banner", "dir", "--target", "https://api.example.com", *args],
        )
    return result, discovery


def test_unreadable_client_cert_rejected_no_discovery():
    """An unreadable --client-cert path is rejected, naming it, no discovery.

    **Validates: Requirements 29.6**
    """
    bad_path = "/nonexistent/path/client-cert.pem"
    result, discovery = _invoke_dir(["--client-cert", bad_path])

    assert result.exit_code != 0
    assert bad_path in result.output
    discovery.assert_not_called()


def test_unreadable_ca_bundle_rejected_no_discovery():
    """An unreadable --ca-bundle path is rejected, naming it, no discovery.

    **Validates: Requirements 29.6**
    """
    bad_path = "/nonexistent/path/ca-bundle.pem"
    result, discovery = _invoke_dir(["--ca-bundle", bad_path])

    assert result.exit_code != 0
    assert bad_path in result.output
    discovery.assert_not_called()


def test_malformed_resolve_rejected_no_discovery():
    """A malformed --resolve value is rejected, naming it, with no discovery.

    **Validates: Requirements 29.7**
    """
    bad_value = "not-a-host-ip-pair"
    result, discovery = _invoke_dir(["--resolve", bad_value])

    assert result.exit_code != 0
    assert bad_value in result.output
    discovery.assert_not_called()


def test_parse_resolve_raises_valueerror_naming_value():
    """``parse_resolve`` raises a descriptive ValueError naming the bad value.

    **Validates: Requirements 29.7**
    """
    bad_value = "not-a-host-ip-pair"
    with pytest.raises(ValueError) as excinfo:
        parse_resolve(bad_value)

    assert bad_value in str(excinfo.value)


if __name__ == "__main__":
    pytest.main([__file__])
