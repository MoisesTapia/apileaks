"""
Integration tests: the advanced auth / JWT probes route through the shared
HTTPRequestEngine and inherit the operator's rate-limit / proxy / TLS controls.

**Feature: owasp-auth-modules-hardening, Task 31.3**

These are example-based integration tests (1-3 examples) that complement the
property-based Safe-Mode / routing coverage elsewhere in the suite. They wire a
real :class:`~utils.http_client.HTTPRequestEngine` — the single shared engine the
rest of the tool uses — to the two advanced capabilities added by this feature
and prove Requirement 48.1 (advanced probes are exercised through the shared
engine and honor operator controls):

- the anti-automation *login burst* probe in
  :class:`~modules.owasp.auth_testing.AuthenticationTestingModule`
  (``_test_rate_limiting``); and
- the *jku/x5u key-source SSRF* probe in
  :class:`~utils.jwt_attack_engine.JWTAttackEngine` (``test_key_source_ssrf``).

For each we assert that:
- every issued request flows *through* the shared ``HTTPRequestEngine`` (the
  engine's ``request`` pipeline runs and its request-count metric advances);
- the operator-configured ``RateLimiter`` instance is the one consulted (its
  ``acquire`` runs once per issued request); and
- the operator's proxy + mTLS client cert + custom CA bundle materialize on the
  client that issues the advanced-probe traffic.

No real network I/O occurs: the engine's underlying ``httpx`` client is replaced
with an in-memory fake (mirroring ``tests/test_jwt_http_routing_integration.py``),
and the rate limiter is configured with a high rate so the token bucket never
sleeps during the test.
"""

import asyncio
import time
from unittest.mock import patch

import pytest

from core.config import AuthContext, AuthTestingConfig, AuthType, RateLimitConfig
from modules.owasp.auth_testing import AuthenticationTestingModule
from utils import http_client
from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig
from utils.jwt_attack_engine import JWTAttackEngine
from utils.jwt_utils import encode_jwt


# ---------------------------------------------------------------------------
# Shared fixtures / fakes
# ---------------------------------------------------------------------------

LOGIN_URL = "https://target.example/api/login"
JWT_TARGET_URL = "https://target.example/api/account"
ATTACKER_KEY_SOURCE = "http://attacker.example/.well-known/jwks.json"
OPERATOR_SECRET = "operator-recovered-signing-key-77"
BENIGN_USERNAME = "apileaks_benign_probe@example.test"


def _make_base_token() -> str:
    """A realistic HS256 base token the JWT engine forges attack variants from."""
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": "user-1",
        "user_id": 1,
        "role": "user",
        "iat": now,
        "exp": now + 3600,
    }
    return encode_jwt(header, payload, OPERATOR_SECRET)


BASE_TOKEN = _make_base_token()


class _FakeHttpxResponse:
    """Minimal stand-in for an ``httpx.Response`` consumed by the engine."""

    def __init__(self, status_code, url, headers=None, content=b'{"ok": true}'):
        self.status_code = status_code
        self.url = url
        self.headers = headers or {"Content-Type": "application/json"}
        self.content = content
        self.text = (
            content.decode() if isinstance(content, (bytes, bytearray)) else str(content)
        )


class _RecordingHttpxClient:
    """In-memory httpx client double that records every issued request.

    Injected as ``HTTPRequestEngine.client`` so advanced-probe traffic exercises
    the real engine pipeline (rate limiting, retries, metrics) but never touches
    the network. Each call captures the method, url, and headers so the tests can
    assert the traffic actually flowed through the shared engine.
    """

    def __init__(self, status_code=200):
        self._status_code = status_code
        self.calls = []  # list of (method, url, headers)

    async def request(self, method, url, **kwargs):
        self.calls.append((method, url, dict(kwargs.get("headers", {}) or {})))
        return _FakeHttpxResponse(self._status_code, url)


class _CapturingAsyncClient:
    """Fake ``httpx.AsyncClient`` capturing the kwargs it is constructed with.

    Used for the TLS/proxy test: patching ``httpx.AsyncClient`` with this class
    lets a real probe request drive ``_ensure_client`` so the operator's
    proxy/cert/verify settings materialize into the constructor kwargs, while
    still returning an awaitable response so the probe flow completes.
    """

    last_kwargs = None

    def __init__(self, **kwargs):
        type(self).last_kwargs = kwargs

    async def request(self, method, url, **kwargs):
        return _FakeHttpxResponse(200, url)


def _make_shared_engine(rate_limiter=None, injected_client=None, **kwargs):
    """Build a real HTTPRequestEngine, optionally injecting a fake transport."""
    rl = rate_limiter or RateLimiter(
        RateLimitConfig(requests_per_second=1000, burst_size=1000)
    )
    engine = HTTPRequestEngine(rl, RetryConfig(max_attempts=1), **kwargs)
    if injected_client is not None:
        engine._client_initialized = True
        engine.client = injected_client
    return engine


def _spy_rate_limiter():
    """A real rate limiter whose ``acquire`` records how often it is consulted."""
    rate_limiter = RateLimiter(
        RateLimitConfig(requests_per_second=1000, burst_size=1000)
    )
    acquire_calls = {"count": 0}
    orig_acquire = rate_limiter.acquire

    async def _spy_acquire():
        acquire_calls["count"] += 1
        return await orig_acquire()

    rate_limiter.acquire = _spy_acquire
    return rate_limiter, acquire_calls


def _make_auth_module(http_engine, attempts=3):
    """Build an auth module with the aggressive login-burst opt-in enabled."""
    config = AuthTestingConfig(
        enabled=True,
        jwt_testing=False,
        safe_mode=False,
        allow_aggressive=True,
        rate_limit_attempts=attempts,
        benign_username=BENIGN_USERNAME,
    )
    return AuthenticationTestingModule(config, http_engine, auth_contexts=[])


def _make_jwt_engine(http_engine, safe_mode=False):
    return JWTAttackEngine(
        target_url=JWT_TARGET_URL,
        original_token=BASE_TOKEN,
        http_engine=http_engine,
        signing_secret=OPERATOR_SECRET,
        safe_mode=safe_mode,
    )


# ===========================================================================
# 48.1 — the login burst probe routes through the shared engine + rate limiter
# ===========================================================================

def test_login_burst_routes_through_shared_engine_and_rate_limiter():
    """The anti-automation login burst is issued through the shared engine.

    Driving ``_test_rate_limiting`` with a real ``HTTPRequestEngine`` (fake
    transport) issues the bounded burst of login POSTs through the shared engine:
    every request lands on the transport at the login endpoint, the engine's own
    request-count metric advances, and the operator-configured rate limiter is
    consulted exactly once per issued request — proving the burst honors the
    operator's rate-limit control rather than using a private client.

    **Validates: Requirements 48.1**
    """
    attempts = 3
    rate_limiter, acquire_calls = _spy_rate_limiter()
    transport = _RecordingHttpxClient(status_code=200)
    http_engine = _make_shared_engine(
        rate_limiter=rate_limiter, injected_client=transport
    )
    # The shared engine carries the operator's rate limiter instance.
    assert http_engine.rate_limiter is rate_limiter

    module = _make_auth_module(http_engine, attempts=attempts)
    asyncio.run(module._test_rate_limiting(LOGIN_URL))

    # The bounded burst was issued through the shared engine (Req 37.2/48.1).
    assert transport.calls, "expected login burst requests to be issued"
    assert len(transport.calls) == attempts
    for method, url, _headers in transport.calls:
        assert method == "POST"
        assert url == LOGIN_URL

    # The shared engine's pipeline ran (metrics advanced) and the operator rate
    # limiter gated every issued request.
    assert http_engine.metrics.total_requests == len(transport.calls)
    assert acquire_calls["count"] == len(transport.calls)


# ===========================================================================
# 48.1 — the jku/x5u probe routes through the shared engine + rate limiter
# ===========================================================================

def test_jku_x5u_probe_routes_through_shared_engine_and_rate_limiter():
    """The jku/x5u key-source SSRF probe is issued through the shared engine.

    Driving ``test_key_source_ssrf`` with a real ``HTTPRequestEngine`` (fake
    transport) issues the baseline plus the jku and x5u attack requests through
    the shared engine: every request lands on the transport carrying a Bearer
    JWT, the engine's request-count metric advances, and the operator-configured
    rate limiter is consulted once per issued request.

    **Validates: Requirements 48.1**
    """
    rate_limiter, acquire_calls = _spy_rate_limiter()
    transport = _RecordingHttpxClient(status_code=200)
    http_engine = _make_shared_engine(
        rate_limiter=rate_limiter, injected_client=transport
    )
    jwt_engine = _make_jwt_engine(http_engine)

    asyncio.run(jwt_engine.test_key_source_ssrf(ATTACKER_KEY_SOURCE))

    # Baseline + jku + x5u requests all routed through the shared engine.
    assert len(transport.calls) >= 3
    for _method, url, headers in transport.calls:
        assert url == JWT_TARGET_URL
        assert headers.get("Authorization", "").startswith("Bearer ")

    # The shared engine's pipeline ran and the operator rate limiter gated each
    # issued request.
    assert http_engine.metrics.total_requests == len(transport.calls)
    assert acquire_calls["count"] == len(transport.calls)


# ===========================================================================
# 48.1 — advanced probes inherit the operator's proxy / TLS controls
# ===========================================================================

def test_jku_x5u_probe_inherits_operator_proxy_and_tls_controls():
    """Operator proxy + mTLS cert + custom CA bundle materialize for probe traffic.

    A real jku/x5u probe, issued through the shared engine configured with a
    proxy, client certificate, and CA bundle, drives ``_ensure_client`` so those
    controls appear on the constructed client — demonstrating that advanced-probe
    traffic inherits the operator's proxy/TLS settings because it uses the same
    shared engine.

    **Validates: Requirements 48.1**
    """
    proxy = "http://127.0.0.1:8080"
    client_cert = ("/certs/client.pem", "/certs/client.key")
    ca_bundle = "/certs/ca.pem"

    http_engine = _make_shared_engine(
        proxy=proxy,
        cert=client_cert,
        ca_bundle=ca_bundle,
    )
    jwt_engine = _make_jwt_engine(http_engine)

    _CapturingAsyncClient.last_kwargs = None
    with patch.object(http_client.httpx, "AsyncClient", _CapturingAsyncClient):
        asyncio.run(jwt_engine.test_key_source_ssrf(ATTACKER_KEY_SOURCE))

    kwargs = _CapturingAsyncClient.last_kwargs
    assert kwargs is not None, "the shared engine's client was never constructed"
    # Proxy control applied to advanced-probe traffic (48.1).
    assert kwargs["proxy"] == proxy
    # mTLS client certificate (TLS control) applied to advanced-probe traffic.
    assert kwargs["cert"] == client_cert
    # Custom CA bundle overrides verify (TLS control) for advanced-probe traffic.
    assert kwargs["verify"] == ca_bundle


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
