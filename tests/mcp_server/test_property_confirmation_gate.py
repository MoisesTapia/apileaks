# Feature: ai-mcp-integration, Property 1: Confirmación Obligatoria para Operaciones Destructivas
"""
Property-based tests for DestructiveConfirmationGate (Task 6.2).

**Feature: ai-mcp-integration**

Property 1: Confirmación Obligatoria para Operaciones Destructivas
    Para cualquier MCPToolSpec con is_destructive=True, MCPToolRegistry.invoke
    SHALL rechazar la invocación con ConfirmationRequiredError si no se provee
    un ConfirmationToken válido, independientemente del valor de allow_destructive
    a nivel de proceso.

Three sub-properties are verified:

1. **Property 1a** — Destructive tool, safe mode (allow_destructive=False):
   Any destructive invocation without a token MUST be rejected with an
   MCPToolError whose error_code is "DESTRUCTIVE_NOT_ENABLED".  The handler
   is never entered.

2. **Property 1b** — Destructive tool, destructive mode (allow_destructive=True):
   Any destructive invocation without a ConfirmationToken MUST raise
   ConfirmationRequiredError.  The allow_destructive flag does NOT substitute
   for the per-invocation token.  The handler is never entered.

3. **Property 1c** — Non-destructive tool:
   A non-destructive invocation (is_destructive=False) MUST NOT raise
   ConfirmationRequiredError or MCPToolError(DESTRUCTIVE_NOT_ENABLED),
   regardless of whether a ConfirmationToken is supplied.

**Validates: Requirements 4.1, 4.2**
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime

import pytest
from hypothesis import given, settings, strategies as st

# Optional MCP SDK — skip the whole module if the library is absent.
mcp = pytest.importorskip("mcp")

from mcp_server.confirmation_gate import DestructiveConfirmationGate  # noqa: E402
from mcp_server.schemas import (  # noqa: E402
    ConfirmationRequiredError,
    ConfirmationToken,
    MCPToolError,
    MCPToolResult,
    MCPToolSpec,
)
from mcp_server.tool_registry import MCPToolRegistry  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


@dataclass
class _CallCounter:
    """Mutable counter to detect whether the handler was called."""

    count: int = 0


# A permissive schema that accepts any object — isolates confirmation logic
# from schema validation logic.
_PERMISSIVE_SCHEMA: dict = {"type": "object"}


def _make_spec(
    name: str,
    is_destructive: bool,
    counter: _CallCounter,
) -> MCPToolSpec:
    """Build a minimal MCPToolSpec whose handler increments *counter*."""

    async def _handler(params: dict) -> MCPToolResult:
        counter.count += 1
        return MCPToolResult(tool_name=name)

    return MCPToolSpec(
        name=name,
        description="Test tool for property 1 confirmation tests.",
        input_schema=_PERMISSIVE_SCHEMA,
        output_schema={"type": "object"},
        is_destructive=is_destructive,
        handler=_handler,
    )


def _make_registry(allow_destructive: bool, spec: MCPToolSpec) -> MCPToolRegistry:
    """Build a registry with the given gate setting and register *spec*."""
    gate = DestructiveConfirmationGate(allow_destructive=allow_destructive)
    registry = MCPToolRegistry(confirmation_gate=gate)
    registry.register(spec)
    return registry


def _invoke(
    registry: MCPToolRegistry,
    tool_name: str,
    params: dict,
    confirmation: ConfirmationToken | None = None,
) -> MCPToolResult:
    """Run the async ``invoke`` method synchronously."""
    return asyncio.run(registry.invoke(tool_name, params, confirmation=confirmation))


def _make_valid_token(tool_name: str) -> ConfirmationToken:
    """Build a ConfirmationToken that matches *tool_name*."""
    return ConfirmationToken(
        tool_name=tool_name,
        confirmed_by="test-operator",
        timestamp=datetime.utcnow(),
    )


def _make_wrong_token(tool_name: str) -> ConfirmationToken:
    """Build a ConfirmationToken for a *different* tool name (mismatch)."""
    return ConfirmationToken(
        tool_name=tool_name + ".other",
        confirmed_by="test-operator",
        timestamp=datetime.utcnow(),
    )


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Valid tool name strings (dotted identifiers like "apileak.scan").
tool_names = st.text(
    alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"), whitelist_characters="._-"),
    min_size=3,
    max_size=40,
).filter(lambda s: s.strip() and not s.startswith(".") and not s.endswith("."))

# Valid input params — any JSON object (permissive schema accepts all).
json_scalars = st.one_of(
    st.text(),
    st.integers(),
    st.booleans(),
    st.none(),
)

json_values = st.recursive(
    json_scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(st.text(min_size=1, max_size=8), children, max_size=3),
    ),
    max_leaves=6,
)

valid_params = st.dictionaries(
    st.text(min_size=1, max_size=12),
    json_values,
    max_size=4,
)


# ---------------------------------------------------------------------------
# Property 1a — Destructive tool, safe mode → DESTRUCTIVE_NOT_ENABLED
# ---------------------------------------------------------------------------


@given(tool_name=tool_names, params=valid_params)
@settings(max_examples=30)
def test_property1a_destructive_safe_mode_no_token_rejected(
    tool_name: str, params: dict
) -> None:
    """For ANY destructive tool in safe mode, invocation without a token
    MUST raise MCPToolError(DESTRUCTIVE_NOT_ENABLED).
    The handler MUST never be entered.

    **Validates: Requirements 4.1, 4.2**
    """
    counter = _CallCounter()
    spec = _make_spec(tool_name, is_destructive=True, counter=counter)
    registry = _make_registry(allow_destructive=False, spec=spec)

    with pytest.raises(MCPToolError) as exc_info:
        _invoke(registry, tool_name, params, confirmation=None)

    assert exc_info.value.error_code == "DESTRUCTIVE_NOT_ENABLED", (
        f"Expected error_code='DESTRUCTIVE_NOT_ENABLED', got {exc_info.value.error_code!r}"
    )
    assert counter.count == 0, (
        "Handler was entered despite safe mode and no token — Property 1a violated!"
    )


@given(tool_name=tool_names, params=valid_params)
@settings(max_examples=30)
def test_property1a_destructive_safe_mode_token_still_rejected(
    tool_name: str, params: dict
) -> None:
    """Even when a valid ConfirmationToken is provided, safe mode (Tier 1) blocks
    execution before the token can be checked (Tier 2).
    Error code must be 'DESTRUCTIVE_NOT_ENABLED', NOT 'CONFIRMATION_REQUIRED'.

    **Validates: Requirements 4.1, 4.2**
    """
    counter = _CallCounter()
    spec = _make_spec(tool_name, is_destructive=True, counter=counter)
    registry = _make_registry(allow_destructive=False, spec=spec)
    token = _make_valid_token(tool_name)

    with pytest.raises(MCPToolError) as exc_info:
        _invoke(registry, tool_name, params, confirmation=token)

    assert exc_info.value.error_code == "DESTRUCTIVE_NOT_ENABLED", (
        "A ConfirmationToken must not bypass the Tier 1 safe-mode check."
    )
    assert counter.count == 0


# ---------------------------------------------------------------------------
# Property 1b — Destructive tool, destructive mode, no/wrong token →
#               ConfirmationRequiredError
# ---------------------------------------------------------------------------


@given(tool_name=tool_names, params=valid_params)
@settings(max_examples=30)
def test_property1b_destructive_mode_no_token_raises_confirmation_required(
    tool_name: str, params: dict
) -> None:
    """For ANY destructive tool with allow_destructive=True, invocation without
    a ConfirmationToken MUST raise ConfirmationRequiredError.
    The handler MUST never be entered.

    **Validates: Requirements 4.1, 4.2**
    """
    counter = _CallCounter()
    spec = _make_spec(tool_name, is_destructive=True, counter=counter)
    registry = _make_registry(allow_destructive=True, spec=spec)

    with pytest.raises(ConfirmationRequiredError) as exc_info:
        _invoke(registry, tool_name, params, confirmation=None)

    assert exc_info.value.error_code == "CONFIRMATION_REQUIRED"
    assert counter.count == 0, (
        "Handler was entered without a ConfirmationToken in destructive mode — "
        "Property 1b violated!"
    )


@given(tool_name=tool_names, params=valid_params)
@settings(max_examples=30)
def test_property1b_destructive_mode_wrong_token_raises_confirmation_required(
    tool_name: str, params: dict
) -> None:
    """For ANY destructive tool with allow_destructive=True, a token whose
    tool_name does not match the invoked tool MUST raise ConfirmationRequiredError.
    The handler MUST never be entered.

    **Validates: Requirements 4.1, 4.2**
    """
    counter = _CallCounter()
    spec = _make_spec(tool_name, is_destructive=True, counter=counter)
    registry = _make_registry(allow_destructive=True, spec=spec)
    wrong_token = _make_wrong_token(tool_name)

    with pytest.raises(ConfirmationRequiredError):
        _invoke(registry, tool_name, params, confirmation=wrong_token)

    assert counter.count == 0, (
        "Handler was entered with a mismatched token — Property 1b violated!"
    )


@given(tool_name=tool_names, params=valid_params)
@settings(max_examples=25)
def test_property1b_valid_token_allows_execution(
    tool_name: str, params: dict
) -> None:
    """For ANY destructive tool with allow_destructive=True and a matching
    ConfirmationToken, the handler MUST be called exactly once.
    (Validates the positive path — the gate must not over-block.)

    **Validates: Requirements 4.1, 4.2**
    """
    counter = _CallCounter()
    spec = _make_spec(tool_name, is_destructive=True, counter=counter)
    registry = _make_registry(allow_destructive=True, spec=spec)
    token = _make_valid_token(tool_name)

    _invoke(registry, tool_name, params, confirmation=token)

    assert counter.count == 1, (
        "Handler was not called despite valid token in destructive mode — "
        "the gate is over-blocking!"
    )


# ---------------------------------------------------------------------------
# Property 1c — Non-destructive tool is never blocked by the confirmation gate
# ---------------------------------------------------------------------------


@given(tool_name=tool_names, params=valid_params, allow_destructive=st.booleans())
@settings(max_examples=30)
def test_property1c_non_destructive_tool_not_blocked(
    tool_name: str, params: dict, allow_destructive: bool
) -> None:
    """For ANY non-destructive tool, invocation (with or without a token)
    MUST NOT raise ConfirmationRequiredError or MCPToolError(DESTRUCTIVE_NOT_ENABLED).
    The handler MUST be called exactly once.

    **Validates: Requirements 4.1, 4.2**
    """
    counter = _CallCounter()
    spec = _make_spec(tool_name, is_destructive=False, counter=counter)
    registry = _make_registry(allow_destructive=allow_destructive, spec=spec)

    # Should not raise.
    result = _invoke(registry, tool_name, params, confirmation=None)

    assert result is not None
    assert counter.count == 1, (
        "Non-destructive handler was not called — the gate is incorrectly blocking "
        "non-destructive tools!"
    )


# ---------------------------------------------------------------------------
# Concrete regression examples
# ---------------------------------------------------------------------------


def test_example_destructive_safe_mode_no_token() -> None:
    """Concrete: destructive + safe mode + no token → DESTRUCTIVE_NOT_ENABLED."""
    counter = _CallCounter()
    spec = _make_spec("apileak.scan", is_destructive=True, counter=counter)
    registry = _make_registry(allow_destructive=False, spec=spec)

    with pytest.raises(MCPToolError) as exc_info:
        _invoke(registry, "apileak.scan", {})

    assert exc_info.value.error_code == "DESTRUCTIVE_NOT_ENABLED"
    assert counter.count == 0


def test_example_destructive_mode_no_token() -> None:
    """Concrete: destructive + allow_destructive=True + no token → ConfirmationRequiredError."""
    counter = _CallCounter()
    spec = _make_spec("apileak.scan", is_destructive=True, counter=counter)
    registry = _make_registry(allow_destructive=True, spec=spec)

    with pytest.raises(ConfirmationRequiredError) as exc_info:
        _invoke(registry, "apileak.scan", {})

    assert exc_info.value.error_code == "CONFIRMATION_REQUIRED"
    assert "apileak.scan" in exc_info.value.tool_name
    assert counter.count == 0


def test_example_destructive_mode_wrong_token() -> None:
    """Concrete: destructive + allow_destructive=True + wrong tool_name token → ConfirmationRequiredError."""
    counter = _CallCounter()
    spec = _make_spec("apileak.scan", is_destructive=True, counter=counter)
    registry = _make_registry(allow_destructive=True, spec=spec)
    wrong_token = ConfirmationToken(
        tool_name="apileak.OTHER_TOOL",
        confirmed_by="operator",
        timestamp=datetime.utcnow(),
    )

    with pytest.raises(ConfirmationRequiredError):
        _invoke(registry, "apileak.scan", {}, confirmation=wrong_token)

    assert counter.count == 0


def test_example_destructive_mode_valid_token_succeeds() -> None:
    """Concrete: destructive + allow_destructive=True + matching token → success."""
    counter = _CallCounter()
    spec = _make_spec("apileak.scan", is_destructive=True, counter=counter)
    registry = _make_registry(allow_destructive=True, spec=spec)
    token = _make_valid_token("apileak.scan")

    result = _invoke(registry, "apileak.scan", {}, confirmation=token)

    assert result.tool_name == "apileak.scan"
    assert counter.count == 1


def test_example_non_destructive_no_token_safe_mode() -> None:
    """Concrete: non-destructive + safe mode + no token → passes cleanly."""
    counter = _CallCounter()
    spec = _make_spec("apileak.jwt.attack_test", is_destructive=False, counter=counter)
    registry = _make_registry(allow_destructive=False, spec=spec)

    result = _invoke(registry, "apileak.jwt.attack_test", {"target_url": "https://api.example.com"})

    assert result is not None
    assert counter.count == 1


def test_example_confirmation_required_error_is_mcp_tool_error_subclass() -> None:
    """ConfirmationRequiredError must be a subclass of MCPToolError (Requirement 1.5)."""
    err = ConfirmationRequiredError("apileak.scan")
    assert isinstance(err, MCPToolError), (
        "ConfirmationRequiredError must subclass MCPToolError so the MCP "
        "transport always receives a structured error response."
    )
    assert err.error_code == "CONFIRMATION_REQUIRED"


def test_example_safe_mode_token_does_not_bypass_tier1() -> None:
    """A valid token CANNOT bypass the Tier 1 safe-mode block.  Tier 1 is
    evaluated before Tier 2 — the server must be restarted with
    --allow-destructive-mcp first."""
    counter = _CallCounter()
    spec = _make_spec("apileak.owasp.bola_testing", is_destructive=True, counter=counter)
    registry = _make_registry(allow_destructive=False, spec=spec)
    token = _make_valid_token("apileak.owasp.bola_testing")

    with pytest.raises(MCPToolError) as exc_info:
        _invoke(registry, "apileak.owasp.bola_testing", {}, confirmation=token)

    assert exc_info.value.error_code == "DESTRUCTIVE_NOT_ENABLED"
    assert counter.count == 0
