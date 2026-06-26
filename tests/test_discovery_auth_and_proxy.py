"""
Regression tests for two discovery-path behaviors:

1. Authentication propagation — the HTTP client used for endpoint discovery
   (the ``dir`` command path) must apply the configured authentication context
   (e.g. a ``--jwt`` token) so protected endpoints are reached authenticated
   rather than anonymously. Previously only OWASP modules received the auth
   contexts and discovery requests went out unauthenticated (seeing 401/403).

2. Proxy integration — when a proxy is configured (Burp Suite, Caido, Hetty,
   ...), the discovery HTTP client must route traffic through it, and TLS
   verification must be disabled by default for proxied HTTPS (re-enabled via
   ``proxy_verify_ssl``).

Both tests initialize the discovery phase with endpoint discovery disabled so
the fuzzing orchestrator (and its HTTP client) is constructed without performing
any network I/O.
"""

import pytest

from core.engine import APILeakCore
from core.config import (
    APILeakConfig,
    TargetConfig,
    FuzzingConfig,
    EndpointFuzzingConfig,
    ParameterFuzzingConfig,
    HeaderFuzzingConfig,
    OWASPConfig,
    AuthConfig,
    AuthContext,
    AuthType,
    RateLimitConfig,
)


def _base_config(**overrides) -> APILeakConfig:
    """Build a minimal config with endpoint discovery disabled (no network)."""
    config = APILeakConfig(
        target=TargetConfig(base_url="https://api.example.com"),
        fuzzing=FuzzingConfig(
            endpoints=EndpointFuzzingConfig(enabled=False),
            parameters=ParameterFuzzingConfig(enabled=False),
            headers=HeaderFuzzingConfig(enabled=False),
            recursive=False,
            max_depth=0,
        ),
        owasp_testing=OWASPConfig(enabled_modules=[]),
        authentication=AuthConfig(),
        rate_limiting=RateLimitConfig(requests_per_second=5, burst_size=5),
    )
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


@pytest.mark.asyncio
async def test_discovery_http_client_applies_jwt_auth_context():
    """The discovery HTTP client must carry the configured JWT/bearer token.

    Regression: authenticated `dir` runs previously hit protected endpoints
    anonymously because the fuzzing HTTP client never received the auth context.
    """
    token = "header.payload.signature"
    config = _base_config(
        authentication=AuthConfig(
            contexts=[
                AuthContext(name="user", type=AuthType.BEARER, token=token)
            ]
        )
    )

    core = APILeakCore(config)
    await core._execute_discovery_phase(config.target.base_url)

    http_client = core.fuzzing_orchestrator.http_client

    # The active auth context is set, so request() will apply it.
    assert http_client.current_auth_context is not None
    assert http_client.current_auth_context.token == token
    assert "user" in http_client.auth_contexts

    # Verify the Authorization header is actually produced for a request.
    from utils.http_client import Request

    request = Request(method="GET", url=config.target.base_url)
    http_client._apply_authentication(request, http_client.current_auth_context)
    assert request.headers.get("Authorization") == f"Bearer {token}"


@pytest.mark.asyncio
async def test_discovery_http_client_without_auth_has_no_context():
    """With no auth contexts configured, discovery stays anonymous."""
    config = _base_config(authentication=AuthConfig(contexts=[]))

    core = APILeakCore(config)
    await core._execute_discovery_phase(config.target.base_url)

    http_client = core.fuzzing_orchestrator.http_client
    assert http_client.current_auth_context is None
    assert http_client.auth_contexts == {}


@pytest.mark.asyncio
async def test_discovery_http_client_routes_through_proxy():
    """A configured proxy is applied to the discovery HTTP client.

    TLS verification defaults to off for proxied traffic (intercepting proxies
    terminate TLS with their own CA).
    """
    config = _base_config(proxy="http://127.0.0.1:8080", proxy_verify_ssl=False)

    core = APILeakCore(config)
    await core._execute_discovery_phase(config.target.base_url)

    http_client = core.fuzzing_orchestrator.http_client
    assert http_client.proxy == "http://127.0.0.1:8080"
    assert http_client.verify_ssl is False


@pytest.mark.asyncio
async def test_discovery_proxy_verify_ssl_opt_in():
    """proxy_verify_ssl re-enables TLS verification while still proxying."""
    config = _base_config(proxy="http://127.0.0.1:8080", proxy_verify_ssl=True)

    core = APILeakCore(config)
    await core._execute_discovery_phase(config.target.base_url)

    http_client = core.fuzzing_orchestrator.http_client
    assert http_client.proxy == "http://127.0.0.1:8080"
    assert http_client.verify_ssl is True


@pytest.mark.asyncio
async def test_discovery_no_proxy_keeps_target_verify_ssl():
    """Without a proxy, the client uses the target's verify_ssl setting."""
    config = _base_config()  # no proxy; target.verify_ssl defaults to True

    core = APILeakCore(config)
    await core._execute_discovery_phase(config.target.base_url)

    http_client = core.fuzzing_orchestrator.http_client
    assert http_client.proxy is None
    assert http_client.verify_ssl is True


@pytest.mark.asyncio
async def test_discovery_http_client_builds_async_client_with_proxy():
    """The underlying httpx client is constructed with the proxy configured."""
    config = _base_config(proxy="http://127.0.0.1:8080")

    core = APILeakCore(config)
    await core._execute_discovery_phase(config.target.base_url)

    http_client = core.fuzzing_orchestrator.http_client
    # Initializing the async client must not raise when a proxy is set.
    await http_client._ensure_client()
    assert http_client.client is not None
    await http_client.close() if hasattr(http_client, "close") else None
