# Feature: ai-mcp-integration, Property 5: Validación de Esquema antes de Ejecución
"""
Property-based tests for MCPToolRegistry schema validation (Task 1.1).

**Feature: ai-mcp-integration**

Property 5: Validación de Esquema antes de Ejecución
    Para cualquier invocación de un MCP_Tool con parámetros que no satisfacen
    su input_schema, MCPToolRegistry.invoke SHALL rechazar la invocación ANTES
    de ejecutar cualquier lógica del handler subyacente.

Two complementary test groups verify this invariant:

1. **Property tests (Hypothesis)** — generate arbitrary invalid parameter
   payloads against a fixed schema and assert:
   a. Invocation is rejected (SchemaValidationError is raised).
   b. The handler counter remains zero — the handler was never entered.

2. **Concrete examples** — targeted cases (empty dict, wrong type, extra-only)
   that act as regression anchors.

The MCP SDK itself is an optional dependency; ``pytest.importorskip("mcp")``
ensures these tests are skipped gracefully when the SDK is not installed.

**Validates: Requirements 1.3**
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import pytest
from hypothesis import given, settings, strategies as st

# Optional MCP SDK — skip the whole module if the library is absent.
mcp = pytest.importorskip("mcp")

from mcp_server.schemas import (  # noqa: E402
    ConfirmationToken,
    MCPToolResult,
    MCPToolSpec,
    SchemaValidationError,
    ToolNotFoundError,
)
from mcp_server.tool_registry import MCPToolRegistry  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


@dataclass
class _CallCounter:
    """Mutable counter that lets us detect whether the handler was called."""

    count: int = 0


def _make_spec(
    schema: dict,
    counter: _CallCounter,
    name: str = "test.tool",
    is_destructive: bool = False,
) -> MCPToolSpec:
    """Build an MCPToolSpec whose handler increments *counter* and then returns."""

    async def _handler(params: dict) -> MCPToolResult:
        counter.count += 1
        return MCPToolResult(tool_name=name)

    return MCPToolSpec(
        name=name,
        description="Test tool for property tests.",
        input_schema=schema,
        output_schema={"type": "object"},
        is_destructive=is_destructive,
        handler=_handler,
    )


def _invoke(registry: MCPToolRegistry, tool_name: str, params: dict) -> None:
    """Run the async ``invoke`` method synchronously in tests."""
    asyncio.run(registry.invoke(tool_name, params, confirmation=None))


# ---------------------------------------------------------------------------
# Shared schema used across property tests
# ---------------------------------------------------------------------------

# A schema that requires exactly one field "target_url" of type string.
_STRICT_SCHEMA = {
    "type": "object",
    "properties": {
        "target_url": {"type": "string"},
    },
    "required": ["target_url"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Scalars that are NOT strings — useful for producing wrong-type values.
non_string_scalars = st.one_of(
    st.integers(),
    st.floats(allow_nan=False, allow_infinity=False),
    st.booleans(),
    st.none(),
    st.lists(st.text(), max_size=3),
)

# Valid JSON-serialisable values (scalars + flat dicts/lists).
json_scalars = st.one_of(
    st.text(),
    st.integers(),
    st.floats(allow_nan=False, allow_infinity=False),
    st.booleans(),
    st.none(),
)

json_values = st.recursive(
    json_scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(st.text(min_size=1, max_size=10), children, max_size=3),
    ),
    max_leaves=6,
)

# Params that omit "target_url" but may have other keys.
params_missing_required = st.dictionaries(
    st.text(min_size=1, max_size=20).filter(lambda k: k != "target_url"),
    json_values,
    max_size=3,
)

# Params with "target_url" present but of the wrong type.
params_wrong_type = st.fixed_dictionaries(
    {"target_url": non_string_scalars}
)

# Params that have both "target_url" (valid) and an extra key (violates
# additionalProperties: false).
params_extra_key = st.fixed_dictionaries(
    {
        "target_url": st.text(),
        "extra_field": json_values,
    }
)


# ---------------------------------------------------------------------------
# Property 5a — invalid params are rejected (SchemaValidationError is raised)
# ---------------------------------------------------------------------------


@given(params=params_missing_required)
@settings(max_examples=25)
def test_property5_missing_required_raises_schema_error(params: dict) -> None:
    """For any params that omit the required 'target_url', invoke MUST raise
    SchemaValidationError before calling the handler.

    **Validates: Requirements 1.3**
    """
    counter = _CallCounter()
    registry = MCPToolRegistry()
    registry.register(_make_spec(_STRICT_SCHEMA, counter))

    with pytest.raises(SchemaValidationError):
        _invoke(registry, "test.tool", params)

    # The handler must never have been entered.
    assert counter.count == 0, (
        "Handler was called despite invalid params — Property 5 violated!"
    )


@given(params=params_wrong_type)
@settings(max_examples=25)
def test_property5_wrong_type_raises_schema_error(params: dict) -> None:
    """For any params with 'target_url' of the wrong type, invoke MUST raise
    SchemaValidationError before calling the handler.

    **Validates: Requirements 1.3**
    """
    counter = _CallCounter()
    registry = MCPToolRegistry()
    registry.register(_make_spec(_STRICT_SCHEMA, counter))

    with pytest.raises(SchemaValidationError):
        _invoke(registry, "test.tool", params)

    assert counter.count == 0, (
        "Handler was called despite wrong-type params — Property 5 violated!"
    )


@given(params=params_extra_key)
@settings(max_examples=25)
def test_property5_extra_key_raises_schema_error(params: dict) -> None:
    """For any params with an extra key (additionalProperties: false), invoke
    MUST raise SchemaValidationError before calling the handler.

    **Validates: Requirements 1.3**
    """
    counter = _CallCounter()
    registry = MCPToolRegistry()
    registry.register(_make_spec(_STRICT_SCHEMA, counter))

    with pytest.raises(SchemaValidationError):
        _invoke(registry, "test.tool", params)

    assert counter.count == 0, (
        "Handler was called despite extra-key params — Property 5 violated!"
    )


# ---------------------------------------------------------------------------
# Property 5b — valid params DO reach the handler
# ---------------------------------------------------------------------------


@given(target_url=st.text(min_size=1))
@settings(max_examples=20)
def test_property5_valid_params_reach_handler(target_url: str) -> None:
    """For any valid 'target_url' string, the handler is called exactly once
    (schema validation passes and does not block valid invocations).

    **Validates: Requirements 1.3**
    """
    counter = _CallCounter()
    registry = MCPToolRegistry()
    registry.register(_make_spec(_STRICT_SCHEMA, counter))

    _invoke(registry, "test.tool", {"target_url": target_url})

    assert counter.count == 1, (
        "Handler was not called for valid params — schema gate is over-blocking!"
    )


# ---------------------------------------------------------------------------
# Concrete regression examples
# ---------------------------------------------------------------------------


def test_example_empty_dict_rejected() -> None:
    """Empty dict is missing required 'target_url' → SchemaValidationError."""
    counter = _CallCounter()
    registry = MCPToolRegistry()
    registry.register(_make_spec(_STRICT_SCHEMA, counter))

    with pytest.raises(SchemaValidationError):
        _invoke(registry, "test.tool", {})

    assert counter.count == 0


def test_example_wrong_type_int_rejected() -> None:
    """target_url=42 (integer instead of string) → SchemaValidationError."""
    counter = _CallCounter()
    registry = MCPToolRegistry()
    registry.register(_make_spec(_STRICT_SCHEMA, counter))

    with pytest.raises(SchemaValidationError):
        _invoke(registry, "test.tool", {"target_url": 42})

    assert counter.count == 0


def test_example_extra_field_rejected() -> None:
    """Extra field 'depth' violates additionalProperties:false → rejected."""
    counter = _CallCounter()
    registry = MCPToolRegistry()
    registry.register(_make_spec(_STRICT_SCHEMA, counter))

    with pytest.raises(SchemaValidationError):
        _invoke(registry, "test.tool", {"target_url": "https://example.com", "depth": 5})

    assert counter.count == 0


def test_example_valid_params_succeed() -> None:
    """Valid params with required string field → handler called once."""
    counter = _CallCounter()
    registry = MCPToolRegistry()
    registry.register(_make_spec(_STRICT_SCHEMA, counter))

    _invoke(registry, "test.tool", {"target_url": "https://api.example.com"})

    assert counter.count == 1


def test_example_unknown_tool_raises_tool_not_found() -> None:
    """Invoking an unregistered tool name → ToolNotFoundError."""
    registry = MCPToolRegistry()

    with pytest.raises(ToolNotFoundError):
        _invoke(registry, "apileak.nonexistent", {"target_url": "https://x.com"})


def test_example_none_type_rejected() -> None:
    """target_url=None violates the string type constraint."""
    counter = _CallCounter()
    registry = MCPToolRegistry()
    registry.register(_make_spec(_STRICT_SCHEMA, counter))

    with pytest.raises(SchemaValidationError):
        _invoke(registry, "test.tool", {"target_url": None})

    assert counter.count == 0


def test_schema_with_no_restrictions_passes_any_object() -> None:
    """A permissive schema (empty object schema) accepts any params object."""
    permissive_schema: dict = {"type": "object"}
    counter = _CallCounter()
    registry = MCPToolRegistry()
    registry.register(_make_spec(permissive_schema, counter))

    # Both empty and non-empty dicts should pass.
    _invoke(registry, "test.tool", {})
    _invoke(registry, "test.tool", {"anything": "goes", "depth": 3})

    assert counter.count == 2


def test_manifest_hash_changes_on_registration() -> None:
    """Registering a new tool changes the manifest hash (Requirement 4.7)."""
    registry = MCPToolRegistry()
    hash_before = registry.manifest_hash()

    counter = _CallCounter()
    registry.register(_make_spec(_STRICT_SCHEMA, counter, name="apileak.scan"))

    hash_after = registry.manifest_hash()
    assert hash_before != hash_after, "Manifest hash must change when a tool is added."
