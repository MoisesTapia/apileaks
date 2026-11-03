"""
Contract tests for all registered MCP tools (Task 2.5).

Verifies the "contract" of each MCP tool — the guarantee made to any
in-process client about its discovery, schema, and invocation behaviour —
without using a real MCP transport.  The MCPToolRegistry.invoke method IS
the "in-memory MCP client" described by Requirement 11.1.

Contract definition (per task spec):
  1. Tool is discoverable via list_tools() with name, description, and JSON Schema.
  2. Input schema has type=object, required=[...], additionalProperties=false.
  3. Valid invocations return MCPToolResult with tool_name, findings, metadata,
     untrusted_content.
  4. Missing required params raise SchemaValidationError before the handler runs.
  5. Unknown params raise SchemaValidationError (additionalProperties=false).
  6. Destructive tools raise ConfirmationRequiredError without ConfirmationToken.
  7. Non-destructive tools do NOT raise ConfirmationRequiredError for valid calls.
  8. manifest_hash() is deterministic and changes when the tool set changes.

All tests use noop handlers or direct spec inspection — no real network calls
are made anywhere in this file.

Validates: Requirement 11.1
"""

from __future__ import annotations

import asyncio
import dataclasses
from datetime import datetime

import pytest

from cli.owasp_descriptors import all_keys
from mcp_server.schemas import (
    ConfirmationRequiredError,
    ConfirmationToken,
    MCPServerConfig,
    MCPToolResult,
    MCPToolSpec,
    SchemaValidationError,
)
from mcp_server.server import APILeakMCPServer
from mcp_server.tool_registry import MCPToolRegistry


# ---------------------------------------------------------------------------
# Module-level server instance (shared, read-only across all tests)
# ---------------------------------------------------------------------------

_CONFIG = MCPServerConfig(transport="stdio")
_SERVER = APILeakMCPServer(transport="stdio", config=_CONFIG)
_ALL_SPECS: list[MCPToolSpec] = _SERVER.registry.list_tools()
_ALL_TOOL_NAMES: list[str] = [s.name for s in _ALL_SPECS]

# Derived partition of specs by destructiveness flag.
_DESTRUCTIVE_SPECS: list[MCPToolSpec] = [s for s in _ALL_SPECS if s.is_destructive]
_NON_DESTRUCTIVE_SPECS: list[MCPToolSpec] = [s for s in _ALL_SPECS if not s.is_destructive]

# Canonical set of expected tool names (derived, not hard-coded).
_EXPECTED_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "apileak.scan",
        "apileak.jwt.attack_test",
        "apileak.cloud_audit",
        "apileak.discovery.dir",
        "apileak.discovery.par",
    }
    | {f"apileak.owasp.{key}" for key in all_keys()}
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _noop_handler(params: dict) -> MCPToolResult:  # noqa: ARG001
    """Trivial async handler that returns an empty MCPToolResult immediately."""
    return MCPToolResult(tool_name="noop", findings=[], metadata={})


def _minimal_valid_params(spec: MCPToolSpec) -> dict:
    """Return the smallest parameter dict that satisfies ``spec.input_schema``.

    Iterates the ``required`` list and synthesises a value of the correct
    JSON Schema type for each field.  URL-looking fields ("target", "url",
    "base_url") receive an HTTPS example URL; all other string fields receive
    a plain ``"dummy_value"`` that satisfies a bare ``type: string`` constraint.
    """
    required_fields: list[str] = spec.input_schema.get("required", [])
    properties: dict = spec.input_schema.get("properties", {})
    params: dict = {}
    for field_name in required_fields:
        prop = properties.get(field_name, {})
        prop_type = prop.get("type", "string")
        if prop_type == "string":
            if field_name in ("target", "url", "base_url", "endpoint"):
                params[field_name] = "https://example.com/api"
            else:
                params[field_name] = "dummy_value"
        elif prop_type == "integer":
            params[field_name] = 1
        elif prop_type == "number":
            params[field_name] = 1.0
        elif prop_type == "boolean":
            params[field_name] = False
        elif prop_type == "array":
            params[field_name] = []
        else:
            # Fallback for object types or unrecognised schemas.
            params[field_name] = "dummy_value"
    return params


def _noop_registry(spec: MCPToolSpec) -> MCPToolRegistry:
    """Return a fresh registry containing a noop-handler copy of *spec*.

    Using ``dataclasses.replace`` keeps the original *spec* immutable —
    important because _ALL_SPECS is shared state at module level.
    The is_destructive flag is preserved as-is so gate tests stay accurate.

    For destructive specs the registry is configured with
    ``allow_destructive=True`` so that contract tests can reach Tier 2
    (per-invocation ConfirmationToken check) rather than being blocked by
    Tier 1 (process-level safe-mode block).  The Tier 1 block is tested
    separately in ``test_cloud_audit_tool.py::test_invoke_blocked_in_safe_mode``.
    """
    from mcp_server.confirmation_gate import DestructiveConfirmationGate

    gate = DestructiveConfirmationGate(allow_destructive=spec.is_destructive)
    registry = MCPToolRegistry(confirmation_gate=gate)
    noop_spec = dataclasses.replace(spec, handler=_noop_handler)
    registry.register(noop_spec)
    return registry


def _run(coro):
    """Run an awaitable synchronously using a private event loop.

    Uses asyncio.new_event_loop() directly instead of asyncio.run() so that
    the global event loop state (asyncio.get_event_loop()) is NOT modified.
    Other tests in the suite use the old asyncio.run()
    API; calling asyncio.run() between them would call set_event_loop(None) and
    break those tests on Python 3.12+ where get_event_loop() raises RuntimeError
    when no current loop is set.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Universal contract — runs for EVERY registered tool
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("spec", _ALL_SPECS, ids=lambda s: s.name)
class TestMCPToolContractUniversal:
    """Contract checks that every registered MCP tool must satisfy.

    These tests do not invoke handlers — they inspect spec metadata only
    (tests 1–5) or route through a noop-handler registry (tests 6–7) so that
    no real engine or network call is ever made.
    """

    # ------------------------------------------------------------------
    # Contract 1: discoverability — name, description, schemas
    # ------------------------------------------------------------------

    def test_name_matches_apileak_prefix(self, spec: MCPToolSpec):
        """Tool name must start with 'apileak.' (naming convention)."""
        assert spec.name.startswith("apileak."), (
            f"Tool name '{spec.name}' must start with 'apileak.'"
        )

    def test_name_has_at_least_two_segments(self, spec: MCPToolSpec):
        """Tool name must have at least two dot-separated segments (apileak.<sub>)."""
        parts = spec.name.split(".")
        assert len(parts) >= 2, (
            f"Tool name '{spec.name}' must have at least two dot-separated segments"
        )

    def test_description_is_nonempty_string(self, spec: MCPToolSpec):
        """Tool description must be a non-empty string."""
        assert isinstance(spec.description, str), (
            f"Tool '{spec.name}' description must be a str"
        )
        assert len(spec.description.strip()) > 0, (
            f"Tool '{spec.name}' must have a non-empty description"
        )

    def test_is_mcp_tool_spec_instance(self, spec: MCPToolSpec):
        """list_tools() entries must be MCPToolSpec instances."""
        assert isinstance(spec, MCPToolSpec)

    # ------------------------------------------------------------------
    # Contract 2: input_schema shape
    # ------------------------------------------------------------------

    def test_input_schema_type_is_object(self, spec: MCPToolSpec):
        """input_schema must declare type='object'."""
        assert spec.input_schema.get("type") == "object", (
            f"Tool '{spec.name}' input_schema must have type='object', "
            f"got: {spec.input_schema.get('type')!r}"
        )

    def test_input_schema_has_required_list(self, spec: MCPToolSpec):
        """input_schema must have a non-empty 'required' list."""
        required = spec.input_schema.get("required")
        assert isinstance(required, list), (
            f"Tool '{spec.name}' input_schema 'required' must be a list, got {type(required)}"
        )
        assert len(required) > 0, (
            f"Tool '{spec.name}' input_schema 'required' must not be empty"
        )

    def test_input_schema_required_fields_exist_in_properties(self, spec: MCPToolSpec):
        """Every field listed in 'required' must appear in 'properties'."""
        required = spec.input_schema.get("required", [])
        properties = spec.input_schema.get("properties", {})
        missing = [f for f in required if f not in properties]
        assert not missing, (
            f"Tool '{spec.name}': required fields {missing} are absent from properties"
        )

    def test_input_schema_additionalproperties_false(self, spec: MCPToolSpec):
        """input_schema must set additionalProperties=false to prevent unknown params."""
        assert spec.input_schema.get("additionalProperties") is False, (
            f"Tool '{spec.name}' input_schema must set additionalProperties=false"
        )

    # ------------------------------------------------------------------
    # Contract 3: output_schema present
    # ------------------------------------------------------------------

    def test_output_schema_is_nonempty_dict(self, spec: MCPToolSpec):
        """output_schema must be a non-empty dict."""
        assert isinstance(spec.output_schema, dict) and len(spec.output_schema) > 0, (
            f"Tool '{spec.name}' must have a non-empty output_schema"
        )

    # ------------------------------------------------------------------
    # Contract 4: missing required params → SchemaValidationError
    # ------------------------------------------------------------------

    def test_empty_params_raises_schema_validation_error(self, spec: MCPToolSpec):
        """Invoking with {} (all required params absent) must raise SchemaValidationError
        before the handler is called (Property 5 / Requirement 1.3)."""
        # Override is_destructive=False so confirmation gate doesn't interfere;
        # we want to isolate schema validation here.
        registry = MCPToolRegistry()
        safe_noop = dataclasses.replace(
            spec, handler=_noop_handler, is_destructive=False
        )
        registry.register(safe_noop)
        with pytest.raises(SchemaValidationError):
            _run(registry.invoke(spec.name, {}))

    # ------------------------------------------------------------------
    # Contract 5: unknown params → SchemaValidationError
    # ------------------------------------------------------------------

    def test_unknown_param_raises_schema_validation_error(self, spec: MCPToolSpec):
        """Adding an unrecognised parameter to a valid call must raise
        SchemaValidationError (additionalProperties=false enforcement)."""
        registry = MCPToolRegistry()
        safe_noop = dataclasses.replace(
            spec, handler=_noop_handler, is_destructive=False
        )
        registry.register(safe_noop)
        params = {**_minimal_valid_params(spec), "_unknown_injection_param_": "evil"}
        with pytest.raises(SchemaValidationError):
            _run(registry.invoke(spec.name, params))


# ---------------------------------------------------------------------------
# Destructive tool contract — currently: apileak.cloud_audit
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not _DESTRUCTIVE_SPECS,
    reason="No destructive tools are currently registered.",
)
@pytest.mark.parametrize("spec", _DESTRUCTIVE_SPECS, ids=lambda s: s.name)
class TestDestructiveToolContract:
    """Destructive tools MUST enforce the ConfirmationToken gate.

    Contract 6: a valid-params call without a token raises ConfirmationRequiredError.
    The noop handler is used so that passing the gate would actually succeed.
    """

    def test_no_token_raises_confirmation_required_error(self, spec: MCPToolSpec):
        """Schema-valid invocation without ConfirmationToken must raise
        ConfirmationRequiredError — no part of the operation may execute."""
        registry = _noop_registry(spec)
        params = _minimal_valid_params(spec)
        with pytest.raises(ConfirmationRequiredError) as exc_info:
            _run(registry.invoke(spec.name, params, confirmation=None))
        assert exc_info.value.tool_name == spec.name, (
            f"ConfirmationRequiredError.tool_name must be '{spec.name}', "
            f"got '{exc_info.value.tool_name}'"
        )

    def test_wrong_tool_name_in_token_raises_confirmation_error(self, spec: MCPToolSpec):
        """A ConfirmationToken for a *different* tool must also be rejected."""
        registry = _noop_registry(spec)
        params = _minimal_valid_params(spec)
        wrong_token = ConfirmationToken(
            tool_name="apileak.some_completely_different_tool",
            confirmed_by="test_operator",
            timestamp=datetime.utcnow(),
        )
        with pytest.raises(ConfirmationRequiredError):
            _run(registry.invoke(spec.name, params, confirmation=wrong_token))

    def test_correct_token_passes_gate_and_returns_result(self, spec: MCPToolSpec):
        """A ConfirmationToken with the correct tool_name must pass the gate
        and return an MCPToolResult (noop handler)."""
        registry = _noop_registry(spec)
        params = _minimal_valid_params(spec)
        token = ConfirmationToken(
            tool_name=spec.name,
            confirmed_by="test_operator",
            timestamp=datetime.utcnow(),
        )
        result = _run(registry.invoke(spec.name, params, confirmation=token))
        assert isinstance(result, MCPToolResult), (
            f"Tool '{spec.name}' with valid token must return MCPToolResult"
        )

    def test_confirmation_error_code_is_correct(self, spec: MCPToolSpec):
        """ConfirmationRequiredError must carry the CONFIRMATION_REQUIRED error code."""
        registry = _noop_registry(spec)
        params = _minimal_valid_params(spec)
        with pytest.raises(ConfirmationRequiredError) as exc_info:
            _run(registry.invoke(spec.name, params, confirmation=None))
        assert exc_info.value.error_code == "CONFIRMATION_REQUIRED"


# ---------------------------------------------------------------------------
# Non-destructive tool contract
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not _NON_DESTRUCTIVE_SPECS,
    reason="No non-destructive tools are currently registered.",
)
@pytest.mark.parametrize("spec", _NON_DESTRUCTIVE_SPECS, ids=lambda s: s.name)
class TestNonDestructiveToolContract:
    """Non-destructive tools must NOT impose a ConfirmationToken requirement.

    Contract 7: a valid-params call without a token must succeed (return
    MCPToolResult) without raising ConfirmationRequiredError.
    """

    def test_no_token_does_not_raise_confirmation_error(self, spec: MCPToolSpec):
        """Schema-valid invocation without ConfirmationToken must NOT raise
        ConfirmationRequiredError on a non-destructive tool."""
        registry = _noop_registry(spec)
        params = _minimal_valid_params(spec)
        # Must not raise ConfirmationRequiredError — any other exception (e.g.
        # MCPToolError from an actual handler) would indicate a different problem,
        # but confirmation gating must never block a non-destructive tool.
        result = _run(registry.invoke(spec.name, params, confirmation=None))
        assert isinstance(result, MCPToolResult), (
            f"Non-destructive tool '{spec.name}' must return MCPToolResult for valid params"
        )

    def test_is_destructive_flag_is_false(self, spec: MCPToolSpec):
        """The spec itself must declare is_destructive=False."""
        assert spec.is_destructive is False, (
            f"Tool '{spec.name}' is in the non-destructive partition but "
            f"has is_destructive=True"
        )


# ---------------------------------------------------------------------------
# list_tools() and manifest_hash() contract
# ---------------------------------------------------------------------------


class TestListToolsContract:
    """Verify the server's list_tools() and manifest_hash() contracts.

    These tests use _SERVER.registry directly (module-level singleton) for
    read-only assertions, and build isolated MCPToolRegistry instances for
    mutation-based checks (hash-change tests).
    """

    # ------------------------------------------------------------------
    # Tool name completeness
    # ------------------------------------------------------------------

    def test_all_expected_tool_names_present(self):
        """Every expected tool name must appear in the registry."""
        registered = set(_ALL_TOOL_NAMES)
        missing = _EXPECTED_TOOL_NAMES - registered
        assert not missing, (
            f"Expected tools are missing from the registry: {sorted(missing)}"
        )

    def test_no_unexpected_tool_names(self):
        """No tool name outside the expected set should appear."""
        registered = set(_ALL_TOOL_NAMES)
        unexpected = registered - _EXPECTED_TOOL_NAMES
        assert not unexpected, (
            f"Unexpected tools appeared in the registry: {sorted(unexpected)}"
        )

    def test_no_duplicate_tool_names(self):
        """list_tools() must not return the same name twice."""
        assert len(_ALL_TOOL_NAMES) == len(set(_ALL_TOOL_NAMES)), (
            f"Duplicate tool names detected: "
            f"{[n for n in _ALL_TOOL_NAMES if _ALL_TOOL_NAMES.count(n) > 1]}"
        )

    def test_list_tools_returns_mcp_tool_spec_instances(self):
        """Every entry returned by list_tools() must be an MCPToolSpec."""
        for spec in _ALL_SPECS:
            assert isinstance(spec, MCPToolSpec), (
                f"list_tools() must return MCPToolSpec instances; "
                f"got {type(spec).__name__} for '{spec}'"
            )

    def test_list_tools_sorted_alphabetically(self):
        """list_tools() must return tools sorted by name."""
        names = [s.name for s in _ALL_SPECS]
        assert names == sorted(names), (
            "list_tools() must return tools in alphabetical order"
        )

    def test_owasp_tool_count_matches_descriptors(self):
        """Exactly one apileak.owasp.<key> tool per OWASP descriptor."""
        owasp_tool_names = [n for n in _ALL_TOOL_NAMES if n.startswith("apileak.owasp.")]
        expected_keys = all_keys()
        assert len(owasp_tool_names) == len(expected_keys), (
            f"Expected {len(expected_keys)} OWASP tools, got {len(owasp_tool_names)}"
        )

    # ------------------------------------------------------------------
    # manifest_hash() contract (Contract 8)
    # ------------------------------------------------------------------

    def test_manifest_hash_returns_string(self):
        """manifest_hash() must return a string."""
        assert isinstance(_SERVER.registry.manifest_hash(), str)

    def test_manifest_hash_is_sha256_hex(self):
        """manifest_hash() must be a 64-character lowercase hex string (SHA-256)."""
        h = _SERVER.registry.manifest_hash()
        assert len(h) == 64, (
            f"manifest_hash() must be 64 hex chars; got {len(h)}: {h!r}"
        )
        assert all(c in "0123456789abcdef" for c in h), (
            f"manifest_hash() must be lowercase hex; got: {h!r}"
        )

    def test_manifest_hash_is_deterministic(self):
        """Calling manifest_hash() twice on the same registry must return the same value."""
        h1 = _SERVER.registry.manifest_hash()
        h2 = _SERVER.registry.manifest_hash()
        assert h1 == h2, "manifest_hash() must be deterministic across consecutive calls"

    def test_manifest_hash_changes_when_tool_added(self):
        """Registering an extra tool must change the manifest hash."""
        registry = MCPToolRegistry()
        for spec in _ALL_SPECS:
            registry.register(spec)
        hash_before = registry.manifest_hash()

        extra_spec = dataclasses.replace(
            _ALL_SPECS[0],
            name="apileak._test_extra_tool_xyz_",
            is_destructive=False,
            handler=_noop_handler,
        )
        registry.register(extra_spec)
        hash_after = registry.manifest_hash()

        assert hash_before != hash_after, (
            "manifest_hash() must change when a new tool is added to the registry"
        )

    def test_manifest_hash_changes_when_tool_removed(self):
        """A registry with one fewer tool must have a different manifest hash."""
        registry_full = MCPToolRegistry()
        registry_partial = MCPToolRegistry()

        for spec in _ALL_SPECS:
            registry_full.register(spec)

        for spec in _ALL_SPECS[:-1]:  # all tools except the last
            registry_partial.register(spec)

        assert registry_full.manifest_hash() != registry_partial.manifest_hash(), (
            "manifest_hash() must change when a tool is removed from the registry"
        )

    def test_two_registries_with_same_tools_have_equal_hashes(self):
        """Two independently-built registries with identical tool names must
        produce the same hash — the hash is deterministic across instances."""
        registry_a = MCPToolRegistry()
        registry_b = MCPToolRegistry()
        for spec in _ALL_SPECS:
            registry_a.register(spec)
            registry_b.register(spec)
        assert registry_a.manifest_hash() == registry_b.manifest_hash()

    def test_manifest_hash_stored_on_server_matches_registry(self):
        """The server's cached _tool_manifest_hash must match the live registry hash."""
        assert _SERVER._tool_manifest_hash == _SERVER.registry.manifest_hash(), (
            "Server's cached manifest hash must equal the registry's current hash"
        )
