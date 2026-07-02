"""
Integration test for URL-based Spec_Source ingestion routing (Requirement 51).

**Feature: owasp-auth-modules-hardening, Task 51.2**

Where task 51.1 pins the observable behaviors of ``load_schema`` against a hand
double, this integration test wires a *real*
:class:`~utils.http_client.HTTPRequestEngine` — the same object an operator
configures for discovery traffic — and proves that URL-based spec ingestion is
routed through it rather than through a separate ad-hoc HTTP path. Because the
fetch travels the engine's normal request pipeline, the operator-configured
controls are inherited automatically:

* the engine's :class:`RateLimiter` is engaged before the spec is fetched, so the
  operator rate limit applies to spec retrieval (Req 51.5);
* the operator-configured proxy routing and TLS settings (``proxy``,
  ``verify_ssl``, ``ca_bundle``) live on that same engine instance and are the
  ones used for the fetch (Req 51.5);
* URL ingestion still produces a parsed ``SpecSchema`` (Reqs 51.1, 57.1).

The engine's transport is replaced with a recording httpx-client double so the
full engine pipeline (rate limiting + request dispatch) executes without issuing
a real network request.

**Validates: Requirements 51.5, 57.1**
"""

import asyncio
import json

import httpx
import pytest

from core.config import RateLimitConfig
from utils.http_client import (
    HTTPRequestEngine,
    RateLimiter,
    RetryConfig,
)
from utils.spec_import import SpecSchema, load_schema


SPEC_URL = "https://api.example.com/openapi.json"

# Operator-configured HTTP controls the spec fetch must inherit.
OPERATOR_RPS = 3
OPERATOR_BURST = 1
OPERATOR_PROXY = "http://127.0.0.1:8080"
OPERATOR_CA_BUNDLE = "/etc/apileaks/corp-ca.pem"

OPENAPI_DOC = {
    "openapi": "3.0.3",
    "paths": {
        "/users/{id}": {
            "get": {
                "parameters": [
                    {"name": "id", "in": "path", "required": True,
                     "schema": {"type": "integer"}},
                ]
            },
        },
        "/orders": {"get": {}},
    },
    "components": {
        "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}
    },
}


class RecordingHttpxClient:
    """An ``httpx.AsyncClient`` stand-in that records dispatched requests.

    Installed on the engine so the engine's real request pipeline runs (rate
    limiting, header assembly, retry loop) without any socket being opened. Each
    call returns a canned ``httpx.Response`` carrying the spec body.
    """

    def __init__(self, body):
        text = body if isinstance(body, str) else json.dumps(body)
        self._text = text
        self.requests = []

    async def request(self, method, url, **kwargs):
        self.requests.append((method, str(url)))
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=self._text.encode(),
            request=httpx.Request(method, url),
        )


def _operator_engine():
    """Build the HTTPRequestEngine an operator would configure for a scan.

    Carries a concrete rate limit, an intercepting-proxy route, and TLS controls
    (verification disabled for the proxy's CA plus a custom CA bundle). This is
    the single engine that discovery traffic uses; the spec fetch must reuse it.
    """
    rate_limiter = RateLimiter(
        RateLimitConfig(
            requests_per_second=OPERATOR_RPS,
            burst_size=OPERATOR_BURST,
            adaptive=False,
        )
    )
    engine = HTTPRequestEngine(
        rate_limiter=rate_limiter,
        retry_config=RetryConfig(max_attempts=1),
        timeout=15.0,
        verify_ssl=False,          # operator routes through an intercepting proxy
        proxy=OPERATOR_PROXY,      # operator-configured proxy routing
        ca_bundle=OPERATOR_CA_BUNDLE,  # operator-configured TLS trust store
    )
    return engine


def _install_recording_transport(engine, body):
    """Swap the engine's httpx client for a recording double and count throttle
    acquisitions so we can prove the operator rate limit is engaged."""
    client = RecordingHttpxClient(body)
    engine.client = client
    engine._client_initialized = True

    acquire_calls = {"count": 0}
    real_acquire = engine.rate_limiter.acquire

    async def counting_acquire():
        acquire_calls["count"] += 1
        return await real_acquire()

    engine.rate_limiter.acquire = counting_acquire
    return client, acquire_calls


# ---------------------------------------------------------------------------
# 51.5 / 57.1 - URL ingestion routes through the shared, operator-configured
#               engine, engaging its rate limiter.
# ---------------------------------------------------------------------------

def test_url_ingestion_routes_through_shared_engine_and_rate_limiter():
    """URL spec ingestion dispatches through the operator engine's pipeline,
    engaging its rate limiter before the fetch.

    **Validates: Requirements 51.5, 57.1**
    """
    engine = _operator_engine()
    client, acquire_calls = _install_recording_transport(engine, OPENAPI_DOC)

    schema = asyncio.run(load_schema(SPEC_URL, http_engine=engine))

    # The fetch went out over the operator engine's transport, not a side path.
    assert client.requests == [("GET", SPEC_URL)]
    # The operator rate limiter was engaged for the spec fetch (Req 51.5).
    assert acquire_calls["count"] == 1
    # And the ingestion still yielded a parsed schema (Reqs 51.1, 57.1).
    assert isinstance(schema, SpecSchema)
    assert {"/users/{id}", "/orders"} <= {op.path for op in schema.operations}


def test_spec_fetch_inherits_operator_proxy_and_tls_settings():
    """The engine that served the spec fetch carries the operator's proxy and
    TLS controls, so spec retrieval inherits them (Req 51.5).

    **Validates: Requirements 51.5, 57.1**
    """
    engine = _operator_engine()
    _install_recording_transport(engine, OPENAPI_DOC)

    asyncio.run(load_schema(SPEC_URL, http_engine=engine))

    # The controls the operator configured are intact on the very engine that
    # performed the fetch: proxy routing, TLS verification, and CA trust store.
    assert engine.proxy == OPERATOR_PROXY
    assert engine.verify_ssl is False
    assert engine.ca_bundle == OPERATOR_CA_BUNDLE
    # And the rate limit is the operator's configured value, not a default.
    assert engine.rate_limiter.config.requests_per_second == OPERATOR_RPS


if __name__ == "__main__":
    pytest.main([__file__])
