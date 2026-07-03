"""
Unit + integration tests for Actor_Profile consumption in the OWASP modules.

**Feature: owasp-auth-modules-hardening, Task 47.2**

Task 47.1 added the ``ActorProfile`` model, loader, ``AuthContext.actor_profile``
field, and the ``--actor-profile`` CLI option. Task 47.2 consumes those inputs:
when a module issues a request under an ``AuthContext`` that carries an
``actor_profile``, the profile's per-endpoint ``query``/``body`` values are
merged on top of the typed base (``build_typed_params``/``build_typed_payload``
output, or the module's existing values), with the **profile values taking
precedence** (Requirement 54.2). When no profile is supplied (Requirement 54.3)
or the profile omits the endpoint (Requirement 54.4), the existing behavior is
preserved without error.

The shared merge logic lives in :func:`utils.typed_payload.apply_actor_profile`
and is reused by ``bola_testing``, ``auth_testing``, and ``property_level_auth``.
"""

import json
from unittest.mock import AsyncMock, Mock

import pytest

from core.config import (
    ActorProfile,
    AuthContext,
    AuthType,
    PropertyTestingConfig,
)
from utils.http_client import Response
from utils.typed_payload import apply_actor_profile


# ---------------------------------------------------------------------------
# Shared helper: apply_actor_profile (the merge logic all three modules use)
# ---------------------------------------------------------------------------

def _ctx_with_profile(profile):
    return AuthContext(
        name="alice",
        type=AuthType.BEARER,
        token="tok",
        actor_profile=profile,
    )


def test_apply_profile_query_overlays_base_with_precedence():
    """Profile query values overlay the typed base; profile wins on conflicts.

    **Validates: Requirement 54.2**
    """
    profile = ActorProfile(
        context_name="alice",
        query={"/api/orders": {"tenant": "acme", "shared": "profile"}},
    )
    ctx = _ctx_with_profile(profile)

    query, body = apply_actor_profile(
        ctx, "/api/orders",
        query={"page": 1, "shared": "base"},
        body=None,
    )

    # Base value preserved, profile value added, and the shared key resolves to
    # the profile value (profile takes precedence).
    assert query == {"page": 1, "shared": "profile", "tenant": "acme"}
    # Body untouched because the profile declares no body for this endpoint.
    assert body is None


def test_apply_profile_body_overlays_base_with_precedence():
    """Profile body values overlay the typed base; profile wins on conflicts.

    **Validates: Requirement 54.2**
    """
    profile = ActorProfile(
        context_name="alice",
        body={"/api/orders": {"owner": "alice", "role": "member"}},
    )
    ctx = _ctx_with_profile(profile)

    query, body = apply_actor_profile(
        ctx, "/api/orders",
        query=None,
        body={"role": "base", "note": "keep"},
    )

    assert body == {"role": "member", "note": "keep", "owner": "alice"}
    assert query is None


def test_apply_profile_endpoint_absent_returns_base_unchanged():
    """An endpoint the profile omits falls back to the base unchanged.

    **Validates: Requirement 54.4**
    """
    profile = ActorProfile(
        context_name="alice",
        query={"/api/other": {"x": 1}},
        body={"/api/other": {"y": 2}},
    )
    ctx = _ctx_with_profile(profile)

    base_query = {"page": 1}
    base_body = {"field": "value"}
    query, body = apply_actor_profile(
        ctx, "/api/orders", query=base_query, body=base_body
    )

    assert query == base_query
    assert body == base_body


def test_apply_no_profile_returns_base_unchanged():
    """An AuthContext without a profile preserves the base exactly (incl. None).

    **Validates: Requirement 54.3**
    """
    ctx = AuthContext(name="bob", type=AuthType.BEARER, token="tok")

    query, body = apply_actor_profile(ctx, "/api/orders", query={"a": 1}, body=None)
    assert query == {"a": 1}
    assert body is None

    # A None base stays None so a caller not sending params/body keeps doing so.
    query, body = apply_actor_profile(ctx, "/api/orders")
    assert query is None
    assert body is None


def test_apply_none_base_with_profile_builds_fresh_dict():
    """When the base is None but the profile has values, a fresh dict is built.

    **Validates: Requirement 54.2**
    """
    profile = ActorProfile(
        context_name="alice",
        query={"/api/orders": {"tenant": "acme"}},
        body={"/api/orders": {"owner": "alice"}},
    )
    ctx = _ctx_with_profile(profile)

    query, body = apply_actor_profile(ctx, "/api/orders")
    assert query == {"tenant": "acme"}
    assert body == {"owner": "alice"}


def test_apply_does_not_mutate_inputs():
    """Neither the base dicts nor the profile dicts are mutated."""
    profile = ActorProfile(
        context_name="alice",
        query={"/api/orders": {"tenant": "acme"}},
        body={"/api/orders": {"owner": "alice"}},
    )
    ctx = _ctx_with_profile(profile)
    base_query = {"page": 1}
    base_body = {"field": "v"}

    apply_actor_profile(ctx, "/api/orders", query=base_query, body=base_body)

    assert base_query == {"page": 1}
    assert base_body == {"field": "v"}
    assert profile.query == {"/api/orders": {"tenant": "acme"}}
    assert profile.body == {"/api/orders": {"owner": "alice"}}


def test_apply_none_auth_context_is_safe():
    """A ``None`` auth context returns the base unchanged without error."""
    query, body = apply_actor_profile(None, "/api/orders", query={"a": 1}, body={"b": 2})
    assert query == {"a": 1}
    assert body == {"b": 2}


# ---------------------------------------------------------------------------
# Integration: property_level_auth consumes the profile when issuing requests
# ---------------------------------------------------------------------------

def _json_response(url, payload, method="GET"):
    text = json.dumps(payload)
    return Response(
        status_code=200,
        headers={"content-type": "application/json"},
        content=text.encode(),
        text=text,
        url=url,
        elapsed=0.1,
        request_method=method,
    )


def _make_property_module(auth_contexts):
    from modules.owasp.property_level_auth import PropertyLevelAuthModule

    config = PropertyTestingConfig(
        enabled=True,
        sensitive_fields=["password", "api_key", "secret"],
        mass_assignment_fields=["is_admin"],
    )
    client = Mock()
    client.set_auth_context = Mock()
    client.request = AsyncMock()
    module = PropertyLevelAuthModule(config, client, auth_contexts)
    return module, client


@pytest.mark.asyncio
async def test_property_sensitive_data_merges_profile_query():
    """A profile's per-endpoint query is passed through on the read request.

    **Validates: Requirements 54.2, 54.4**
    """
    endpoint_url = "https://api.example.com/orders"
    profile = ActorProfile(
        context_name="alice",
        query={endpoint_url: {"tenant": "acme"}},
    )
    ctx = AuthContext(
        name="alice", type=AuthType.BEARER, token="tok",
        privilege_level=1, actor_profile=profile,
    )
    module, client = _make_property_module([ctx])
    client.request = AsyncMock(return_value=_json_response(endpoint_url, {"id": 1}))

    endpoint = Mock()
    endpoint.url = endpoint_url
    endpoint.method = "GET"

    await module._test_sensitive_data_exposure([endpoint])

    # The request carried the profile's query values as params.
    assert client.request.await_count >= 1
    _, kwargs = client.request.await_args
    assert kwargs.get("params") == {"tenant": "acme"}


@pytest.mark.asyncio
async def test_property_sensitive_data_no_profile_sends_no_params():
    """Without a profile the read request carries no injected params.

    **Validates: Requirement 54.3**
    """
    endpoint_url = "https://api.example.com/orders"
    ctx = AuthContext(name="bob", type=AuthType.BEARER, token="tok", privilege_level=1)
    module, client = _make_property_module([ctx])
    client.request = AsyncMock(return_value=_json_response(endpoint_url, {"id": 1}))

    endpoint = Mock()
    endpoint.url = endpoint_url
    endpoint.method = "GET"

    await module._test_sensitive_data_exposure([endpoint])

    _, kwargs = client.request.await_args
    assert "params" not in kwargs


@pytest.mark.asyncio
async def test_property_mass_assignment_merges_profile_body():
    """A profile's per-endpoint body overlays the mass-assignment payload.

    The injected mass-assignment field (``is_admin``) is preserved while the
    profile adds its realistic per-actor body values on top.

    **Validates: Requirement 54.2**
    """
    endpoint_url = "https://api.example.com/orders"
    profile = ActorProfile(
        context_name="alice",
        body={endpoint_url: {"owner": "alice"}},
    )
    ctx = AuthContext(
        name="alice", type=AuthType.BEARER, token="tok",
        privilege_level=1, actor_profile=profile,
    )
    module, client = _make_property_module([ctx])

    # Baseline GET + write + re-read all return a benign JSON body.
    client.request = AsyncMock(return_value=_json_response(endpoint_url, {"id": 1, "owner": "bob"}))

    await module._test_endpoint_mass_assignment(endpoint_url, "POST", ctx)

    # Find the write (POST) call and confirm the profile body was merged in
    # alongside the injected mass-assignment field.
    write_calls = [
        c for c in client.request.await_args_list
        if c.args and c.args[0] == "POST"
    ]
    assert write_calls, "expected a POST write probe to be issued"
    sent_body = write_calls[0].kwargs.get("json")
    assert sent_body is not None
    assert sent_body.get("owner") == "alice"      # profile value merged
    # The injected mass-assignment field (whichever was probed) is preserved
    # alongside the merged profile value.
    injected = set(sent_body) & module.mass_assignment_fields
    assert injected, f"expected an injected mass-assignment field, got {sent_body}"
