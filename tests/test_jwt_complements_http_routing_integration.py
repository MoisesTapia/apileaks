"""
Integration tests: the new HTTP-issuing JWT-complement vectors (Psychic /
timestamp-tampering / claim-fuzzing) route through the shared HTTPRequestEngine,
honor Safe_Mode, and apply the operator-configured rate limit.

**Feature: owasp-auth-modules-hardening, Task 39.3**

These are example-based integration tests. They wire a real
:class:`~utils.http_client.HTTPRequestEngine` — the single shared engine the rest
of the tool uses — to a :class:`~utils.jwt_attack_engine.JWTAttackEngine` (with an
in-memory transport double replacing the underlying ``httpx`` client, mirroring
``tests/test_jwt_http_routing_integration.py``) so the three new vectors flow
through the engine pipeline without real network I/O. They prove:

- 63.4: CLAIM_FUZZING requests route through the shared HTTPRequestEngine and the
  operator-configured rate limiter's ``acquire`` runs once per issued request.
- 63.5: while Safe_Mode is enabled, CLAIM_FUZZING requests are restricted to
  Safe_Methods (a state-changing body is downgraded to GET).
- 64.5: while Safe_Mode is enabled, TIMESTAMP_TAMPERING requests are restricted to
  Safe_Methods.

The Psychic (blank-ECDSA / null-signature) vector is exercised as the additional
HTTP-issuing vector called out by the task: it too routes through the shared
engine and inherits the operator rate limiter.
"""

import asyncio
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from core.config import RateLimitConfig
from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig
from utils.jwt_attack_engine import JWTAttackEngine
from utils.jwt_attack_models import AttackType
from utils.jwt_utils import ES_CURVES, encode_jwt, encode_jwt_ecdsa
from utils.safe_mode import SAFE_METHODS


# ---------------------------------------------------------------------------
# Constants / base tokens
# ---------------------------------------------------------------------------

TARGET_URL = "https://target.example/api/account"
OPERATOR_SECRET = "operator-recovered-signing-key-77"


def _make_hs256_base_token() -> str:
    """A realistic HS256 base token for the timestamp/claim-fuzzing vectors."""
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": "user-1",
        "user_id": 1,
        "role": "user",
        "iat": now,
        "exp": now + 3600,
        "nbf": now - 10,
    }
    return encode_jwt(header, payload, OPERATOR_SECRET)


def _make_es256_base_token() -> str:
    """A validly ES256-signed base token so the Psychic vector produces a token."""
    private_key = ec.generate_private_key(ES_CURVES["ES256"]())
    header = {"alg": "ES256", "typ": "JWT"}
    now = int(time.time())
    payload = {"sub": "user-1", "role": "user", "iat": now, "exp": now + 3600}
    return encode_jwt_ecdsa(header, payload, private_key)


HS256_BASE_TOKEN = _make_hs256_base_token()
ES256_BASE_TOKEN = _make_es256_base_token()


# ---------------------------------------------------------------------------
# Fakes / fixtures
# ---------------------------------------------------------------------------

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
    """In-memory httpx client double recording every issued request.

    Injected as ``HTTPRequestEngine.client`` so JWT traffic exercises the real
    engine pipeline (rate limiting, retries, metrics) but never touches the
    network. Each call captures method, url, and headers so tests can assert the
    Bearer JWT and the effective HTTP method that flowed through the engine.
    """

    def __init__(self, status_code=200):
        self._status_code = status_code
        self.calls = []  # list of (method, url, headers)

    async def request(self, method, url, **kwargs):
        self.calls.append((method, url, dict(kwargs.get("headers", {}) or {})))
        return _FakeHttpxResponse(self._status_code, url)


def _make_shared_engine(rate_limiter=None, injected_client=None, **kwargs):
    """Build a real HTTPRequestEngine, injecting the fake transport."""
    rl = rate_limiter or RateLimiter(
        RateLimitConfig(requests_per_second=1000, burst_size=1000)
    )
    engine = HTTPRequestEngine(rl, RetryConfig(max_attempts=1), **kwargs)
    if injected_client is not None:
        engine._client_initialized = True
        engine.client = injected_client
    return engine


def _make_jwt_engine(http_engine, base_token=HS256_BASE_TOKEN, safe_mode=False,
                     post_data=None, fuzz_target=None, fuzz_values=None):
    return JWTAttackEngine(
        target_url=TARGET_URL,
        original_token=base_token,
        http_engine=http_engine,
        signing_secret=OPERATOR_SECRET,
        safe_mode=safe_mode,
        post_data=post_data,
        fuzz_target=fuzz_target,
        fuzz_values=fuzz_values,
    )


def _bearer_tokens(calls):
    tokens = []
    for _method, url, headers in calls:
        assert url == TARGET_URL
        auth = headers.get("Authorization", "")
        assert auth.startswith("Bearer ")
        tokens.append(auth[len("Bearer "):])
    return tokens


# ===========================================================================
# 63.4 — CLAIM_FUZZING routes through the shared engine + operator rate limit
# ===========================================================================

def test_claim_fuzzing_routes_through_engine_and_applies_operator_rate_limit():
    """CLAIM_FUZZING requests flow through the shared HTTPRequestEngine and the
    operator-configured rate limiter gates every issued request.

    A spy wraps the operator rate limiter's ``acquire``; because the JWT engine
    uses that same ``HTTPRequestEngine`` instance, ``acquire`` runs exactly once
    per request the transport records (baseline + one per fuzz value), and each
    request carries a Bearer JWT — proving the vector is routed, not issued via a
    private client.

    **Validates: Requirements 63.4**
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
    assert http_engine.rate_limiter is rate_limiter

    fuzz_values = ["admin", "../../etc/passwd", "0"]
    jwt_engine = _make_jwt_engine(
        http_engine, fuzz_target="role", fuzz_values=fuzz_values
    )

    result = asyncio.run(jwt_engine.execute_attack(AttackType.CLAIM_FUZZING))

    assert result is not None
    # Baseline (original token) + one request per fuzz value were issued.
    assert len(transport.calls) >= 2
    assert http_engine.metrics.total_requests == len(transport.calls)
    # Operator rate limiter consulted exactly once per issued request.
    assert acquire_calls["count"] == len(transport.calls)

    # Fuzz variants carried forged tokens distinct from the baseline token.
    bearer_tokens = _bearer_tokens(transport.calls)
    assert HS256_BASE_TOKEN in bearer_tokens
    assert any(tok != HS256_BASE_TOKEN for tok in bearer_tokens)


# ===========================================================================
# 63.5 — CLAIM_FUZZING is restricted to Safe_Methods under Safe_Mode
# ===========================================================================

def test_claim_fuzzing_restricted_to_safe_methods_in_safe_mode():
    """Under Safe_Mode, CLAIM_FUZZING requests are downgraded to a Safe_Method.

    A body (``post_data``) would otherwise select POST; with Safe_Mode enabled
    every request the shared engine issues is a Safe_Method (GET), so no
    state-changing method reaches the transport.

    **Validates: Requirements 63.5**
    """
    transport = _RecordingHttpxClient(status_code=200)
    http_engine = _make_shared_engine(injected_client=transport)

    jwt_engine = _make_jwt_engine(
        http_engine,
        safe_mode=True,
        post_data='{"role": "user"}',
        fuzz_target="role",
        fuzz_values=["admin", "root"],
    )

    asyncio.run(jwt_engine.execute_attack(AttackType.CLAIM_FUZZING))

    assert transport.calls, "expected CLAIM_FUZZING requests to be issued"
    methods = {method.upper() for method, _url, _headers in transport.calls}
    assert methods, "expected at least one issued method"
    # Every issued method is a Safe_Method (POST was downgraded to GET).
    assert methods <= SAFE_METHODS
    assert "POST" not in methods


# ===========================================================================
# 64.5 — TIMESTAMP_TAMPERING is restricted to Safe_Methods under Safe_Mode
# ===========================================================================

def test_timestamp_tampering_restricted_to_safe_methods_in_safe_mode():
    """Under Safe_Mode, TIMESTAMP_TAMPERING requests are restricted to Safe_Methods.

    With a body present (POST would normally be used), Safe_Mode downgrades every
    routed request to GET, so all requests the shared engine issues for the
    tampered-time variants are Safe_Methods.

    **Validates: Requirements 64.5**
    """
    transport = _RecordingHttpxClient(status_code=200)
    http_engine = _make_shared_engine(injected_client=transport)

    jwt_engine = _make_jwt_engine(
        http_engine,
        safe_mode=True,
        post_data='{"action": "noop"}',
    )

    result = asyncio.run(jwt_engine.execute_attack(AttackType.TIMESTAMP_TAMPERING))

    assert result is not None
    assert transport.calls, "expected TIMESTAMP_TAMPERING requests to be issued"
    assert http_engine.metrics.total_requests == len(transport.calls)
    methods = {method.upper() for method, _url, _headers in transport.calls}
    assert methods <= SAFE_METHODS
    assert "POST" not in methods


# ===========================================================================
# Psychic (blank-ECDSA / null-signature) vector routes through the engine
# ===========================================================================

def test_psychic_signature_routes_through_shared_engine_and_rate_limiter():
    """The Psychic (null-ECDSA) vector routes through the shared HTTPRequestEngine
    and inherits the operator-configured rate limiter.

    Built from a validly ES256-signed base token, the vector forges a
    null-signature variant; both the baseline and the forged request flow through
    the same engine instance (rate limiter consulted once per request) and carry a
    Bearer JWT, and the forged token differs from the base token.

    **Validates: Requirements 63.4, 64.5**
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

    jwt_engine = _make_jwt_engine(http_engine, base_token=ES256_BASE_TOKEN)

    result = asyncio.run(jwt_engine.execute_attack(AttackType.PSYCHIC_SIGNATURE))

    assert result is not None
    # Baseline (original ES256 token) + the psychic variant were issued.
    assert len(transport.calls) >= 2
    assert http_engine.metrics.total_requests == len(transport.calls)
    assert acquire_calls["count"] == len(transport.calls)

    bearer_tokens = _bearer_tokens(transport.calls)
    assert ES256_BASE_TOKEN in bearer_tokens
    # The forged psychic token preserves header+payload but differs in signature.
    assert any(tok != ES256_BASE_TOKEN for tok in bearer_tokens)


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
