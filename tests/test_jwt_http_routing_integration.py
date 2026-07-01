"""
Integration tests: JWT attack HTTP routes through the shared HTTPRequestEngine
and inherits the operator's rate-limit / proxy / TLS controls.

**Feature: owasp-auth-modules-hardening, Task 13.2**

These are example-based integration tests (the property-based Safe-Mode coverage
lives in ``tests/test_safe_mode_no_state_change_properties.py``). They wire a
real :class:`~utils.http_client.HTTPRequestEngine` — the single shared engine the
rest of the tool uses — to a :class:`~utils.jwt_attack_engine.JWTAttackEngine` and
prove Requirement 17:

- 17.1: every JWT attack request is issued *through* the shared
  ``HTTPRequestEngine`` (the engine's ``request`` pipeline runs; the underlying
  transport records each call carrying the Bearer JWT).
- 17.3: the operator-configured Rate_Limiter instance is the one consulted — its
  ``acquire`` runs once per issued JWT request — because the same engine instance
  is used.
- 17.4: the operator's proxy and TLS controls (proxy URL, mTLS client cert, custom
  CA bundle) materialize on the client that issues the JWT traffic, because that
  traffic flows through the same engine instance.

No real network I/O occurs: the engine's underlying ``httpx`` client is replaced
with an in-memory fake (mirroring the fake-client conventions in
``tests/test_resilience_controls.py`` and ``tests/test_transport_tls_options.py``),
and the rate limiter is configured with a high rate so the token bucket never
sleeps during the test.
"""

import asyncio
import time
from unittest.mock import patch

import pytest

from core.config import RateLimitConfig
from utils import http_client
from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig
from utils.jwt_attack_engine import JWTAttackEngine
from utils.jwt_attack_models import AttackType
from utils.jwt_utils import encode_jwt


# ---------------------------------------------------------------------------
# Fixtures / fakes
# ---------------------------------------------------------------------------

TARGET_URL = "https://target.example/api/account"
OPERATOR_SECRET = "operator-recovered-signing-key-77"


def _make_base_token() -> str:
    """A realistic HS256 base token the engine forges attack variants from."""
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

    Injected as ``HTTPRequestEngine.client`` so JWT traffic exercises the real
    engine pipeline (rate limiting, retries, metrics) but never touches the
    network. Each call captures the method, url, and headers so the tests can
    assert the Bearer JWT actually flowed through the shared engine.
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
    lets a real JWT request drive ``_ensure_client`` so the operator's
    proxy/cert/verify settings materialize into the constructor kwargs, while
    still returning an awaitable response so the attack flow completes.
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


def _make_jwt_engine(http_engine, safe_mode=False):
    return JWTAttackEngine(
        target_url=TARGET_URL,
        original_token=BASE_TOKEN,
        http_engine=http_engine,
        signing_secret=OPERATOR_SECRET,
        safe_mode=safe_mode,
    )


# ===========================================================================
# 17.1 — JWT attack traffic routes through the shared HTTPRequestEngine
# ===========================================================================

def test_jwt_attack_requests_route_through_shared_http_engine():
    """Every JWT attack request is issued through the shared HTTPRequestEngine.

    Driving ``execute_attack`` with a real ``HTTPRequestEngine`` (fake transport)
    records at least the baseline request (original token) plus the attack
    request, each carrying an ``Authorization: Bearer <jwt>`` header, and the
    engine's own request-count metric advances — proving the traffic flowed
    through the shared engine's pipeline rather than a separate client.

    **Validates: Requirements 17.1**
    """
    transport = _RecordingHttpxClient(status_code=200)
    http_engine = _make_shared_engine(injected_client=transport)
    jwt_engine = _make_jwt_engine(http_engine)

    result = asyncio.run(jwt_engine.execute_attack(AttackType.PRIVILEGE_ESCALATION))

    assert result is not None
    # Baseline (original token) + at least one attack request were issued.
    assert len(transport.calls) >= 2
    # The shared engine's metrics advanced, i.e. its pipeline actually ran.
    assert http_engine.metrics.total_requests == len(transport.calls)

    # Every recorded request carried a Bearer JWT through the shared engine.
    bearer_tokens = []
    for _method, url, headers in transport.calls:
        assert url == TARGET_URL
        auth = headers.get("Authorization", "")
        assert auth.startswith("Bearer ")
        bearer_tokens.append(auth[len("Bearer "):])

    # The baseline used the original token; a forged attack token differed.
    assert BASE_TOKEN in bearer_tokens
    assert any(tok != BASE_TOKEN for tok in bearer_tokens)


# ===========================================================================
# 17.3 — the operator-configured rate limiter is applied to JWT traffic
# ===========================================================================

def test_jwt_traffic_uses_operator_rate_limiter():
    """The operator's Rate_Limiter is consulted once per issued JWT request.

    Because the JWT engine uses the same ``HTTPRequestEngine`` instance, the
    operator-configured rate limiter (not a private one) gates every JWT
    request: its ``acquire`` runs exactly once per request the transport sees.

    **Validates: Requirements 17.3**
    """
    rate_limiter = RateLimiter(
        RateLimitConfig(requests_per_second=1000, burst_size=1000)
    )
    acquire_calls = {"count": 0}
    orig_acquire = rate_limiter.acquire

    async def _spy_acquire():
        acquire_calls["count"] += 1
        return await orig_acquire()

    rate_limiter.acquire = _spy_acquire

    transport = _RecordingHttpxClient(status_code=200)
    http_engine = _make_shared_engine(
        rate_limiter=rate_limiter, injected_client=transport
    )
    # The shared engine carries the operator's rate limiter instance.
    assert http_engine.rate_limiter is rate_limiter

    jwt_engine = _make_jwt_engine(http_engine)
    asyncio.run(jwt_engine.execute_attack(AttackType.PRIVILEGE_ESCALATION))

    # Rate limiting was applied to every JWT request that reached the transport.
    assert transport.calls, "expected JWT requests to be issued"
    assert acquire_calls["count"] == len(transport.calls)


# ===========================================================================
# 17.4 — the operator's proxy / TLS controls apply to JWT traffic
# ===========================================================================

def test_jwt_traffic_inherits_operator_proxy_and_tls_controls():
    """Operator proxy + mTLS cert + custom CA bundle materialize for JWT traffic.

    A real JWT attack request, issued through the shared engine configured with a
    proxy, client certificate, and CA bundle, drives ``_ensure_client`` so those
    controls appear on the constructed client — demonstrating JWT traffic
    inherits the operator's proxy/TLS settings because it uses the same engine.

    **Validates: Requirements 17.4**
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
        asyncio.run(jwt_engine.execute_attack(AttackType.PRIVILEGE_ESCALATION))

    kwargs = _CapturingAsyncClient.last_kwargs
    assert kwargs is not None, "the shared engine's client was never constructed"
    # Proxy control (17.4) applied to JWT traffic.
    assert kwargs["proxy"] == proxy
    # mTLS client certificate (TLS control) applied to JWT traffic.
    assert kwargs["cert"] == client_cert
    # Custom CA bundle overrides verify (TLS control) for JWT traffic.
    assert kwargs["verify"] == ca_bundle


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
