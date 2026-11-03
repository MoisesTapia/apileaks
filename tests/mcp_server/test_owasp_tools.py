"""
Tests for the OWASP module MCP tools (Task 2.2).

Covers:
- All OWASP module keys appear in the registry after server init (Req 1.2)
- Each tool spec has the correct name format (apileak.owasp.<key>)
- Each tool spec is a valid MCPToolSpec instance
- Schema validation rejects missing required params (Req 1.3)
- Schema validation rejects unknown parameters
- Handler returns MCPToolResult with findings list and untrusted_content=True (Req 1.4)
- Tool count matches the OWASP_MODULE_DESCRIPTORS list
- Concurrent tool specs do not share handler closures

Validates: Requirements 1.2, 1.4

Uses in-process mocks for the scan engine so no real network calls are made
(Requirement 11.1 — in-memory invocation, no real MCP SDK transport required).
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cli.owasp_descriptors import OWASP_MODULE_DESCRIPTORS, all_keys
from mcp_server.owasp_tools import (
    _MODULE_EXTRA_PROPERTIES,
    _build_input_schema,
    build_owasp_tool_specs,
)
from mcp_server.schemas import (
    MCPServerConfig,
    MCPToolResult,
    MCPToolSpec,
    SchemaValidationError,
)
from mcp_server.server import APILeakMCPServer
from mcp_server.tool_registry import MCPToolRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_server() -> APILeakMCPServer:
    """Instantiate an APILeakMCPServer with the default tool set registered."""
    config = MCPServerConfig(transport="stdio")
    return APILeakMCPServer(transport="stdio", config=config)


def _make_registry_with_owasp() -> MCPToolRegistry:
    """Build a registry pre-populated with all OWASP tool specs.

    Uses ``allow_destructive=True`` so handler tests can invoke destructive
    tools (bola, function_auth) without hitting the Tier 1 process-level
    block.  Tests that specifically want to verify the Tier 1 block should
    create their own registry with ``allow_destructive=False``.
    """
    from mcp_server.confirmation_gate import DestructiveConfirmationGate

    gate = DestructiveConfirmationGate(allow_destructive=True)
    registry = MCPToolRegistry(confirmation_gate=gate)
    for spec in build_owasp_tool_specs():
        registry.register(spec)
    return registry


# ---------------------------------------------------------------------------
# build_owasp_tool_specs — tool count and naming
# ---------------------------------------------------------------------------


class TestBuildOwaspToolSpecs:
    """Verify the factory produces one tool per descriptor with correct naming."""

    def test_count_matches_descriptors(self):
        """One MCPToolSpec must be generated per OwaspModuleDescriptor."""
        specs = build_owasp_tool_specs()
        assert len(specs) == len(OWASP_MODULE_DESCRIPTORS)

    def test_all_keys_present(self):
        """Every OWASP module key must appear as a registered tool name."""
        specs = build_owasp_tool_specs()
        registered_names = {spec.name for spec in specs}
        for key in all_keys():
            expected = f"apileak.owasp.{key}"
            assert expected in registered_names, (
                f"Expected tool '{expected}' not found in registered tools: "
                f"{sorted(registered_names)}"
            )

    def test_name_format(self):
        """All tool names must follow 'apileak.owasp.<key>'."""
        for spec in build_owasp_tool_specs():
            assert spec.name.startswith("apileak.owasp."), (
                f"Tool name {spec.name!r} does not follow 'apileak.owasp.<key>' pattern"
            )

    def test_all_are_mcp_tool_spec_instances(self):
        for spec in build_owasp_tool_specs():
            assert isinstance(spec, MCPToolSpec), (
                f"{spec.name!r} is not a MCPToolSpec instance"
            )

    def test_no_duplicate_names(self):
        specs = build_owasp_tool_specs()
        names = [spec.name for spec in specs]
        assert len(names) == len(set(names)), (
            f"Duplicate tool names detected: {[n for n in names if names.count(n) > 1]}"
        )

    def test_all_have_callable_handler(self):
        for spec in build_owasp_tool_specs():
            assert callable(spec.handler), f"{spec.name!r} has no callable handler"

    def test_all_have_description(self):
        for spec in build_owasp_tool_specs():
            assert spec.description, f"{spec.name!r} description is empty"

    def test_destructive_flag_matches_cli_options(self):
        """Only tools whose CLI commands accept --allow-destructive* flags must
        be marked is_destructive=True (Task 6.1).

        Expected destructive modules (have --allow-destructive* or equivalent):
          - bola  (--allow-write-bola)
          - function_auth  (--allow-destructive-bfla)
        All others must remain non-destructive.
        """
        _EXPECTED_DESTRUCTIVE = frozenset({"bola", "function_auth"})
        for spec in build_owasp_tool_specs():
            key = spec.name.removeprefix("apileak.owasp.")
            expected = key in _EXPECTED_DESTRUCTIVE
            assert spec.is_destructive is expected, (
                f"{spec.name!r}: expected is_destructive={expected}, "
                f"got is_destructive={spec.is_destructive}"
            )

    def test_timeout_is_positive(self):
        for spec in build_owasp_tool_specs():
            assert spec.max_execution_seconds > 0, (
                f"{spec.name!r} has non-positive timeout"
            )

    def test_handlers_are_distinct_closures(self):
        """Each tool must have its own distinct handler (not the same function object)."""
        specs = build_owasp_tool_specs()
        handlers = [spec.handler for spec in specs]
        # All handler objects must be distinct so a bola invocation never runs
        # the ssrf handler, etc.
        assert len(handlers) == len(set(id(h) for h in handlers)), (
            "Multiple OWASP tools share the same handler object — likely a "
            "late-binding closure bug"
        )


# ---------------------------------------------------------------------------
# Server registration (Req 1.2)
# ---------------------------------------------------------------------------


class TestServerRegistration:
    """Verify all OWASP tools are registered when APILeakMCPServer starts."""

    def test_owasp_tools_present_in_server_registry(self):
        server = _make_server()
        registered_names = {spec.name for spec in server.registry.list_tools()}
        for key in all_keys():
            expected = f"apileak.owasp.{key}"
            assert expected in registered_names, (
                f"'{expected}' missing from server registry after init"
            )

    def test_scan_tool_still_present(self):
        """Registering OWASP tools must not displace apileak.scan."""
        server = _make_server()
        names = {spec.name for spec in server.registry.list_tools()}
        assert "apileak.scan" in names

    def test_total_tool_count_after_server_init(self):
        """Server should have scan + all OWASP tools registered."""
        server = _make_server()
        registered = server.registry.list_tools()
        # 1 scan tool + N OWASP module tools
        expected_minimum = 1 + len(OWASP_MODULE_DESCRIPTORS)
        assert len(registered) >= expected_minimum


# ---------------------------------------------------------------------------
# JSON Schema — input_schema structure (Req 1.3)
# ---------------------------------------------------------------------------


class TestOwaspInputSchemas:
    """Verify that every OWASP tool's input schema is well-formed."""

    def test_all_schemas_have_required_target(self):
        for spec in build_owasp_tool_specs():
            assert "target" in spec.input_schema.get("required", []), (
                f"{spec.name!r}: 'target' not in required list"
            )

    def test_all_schemas_additional_properties_false(self):
        """additionalProperties: false ensures unknown keys are rejected."""
        for spec in build_owasp_tool_specs():
            assert spec.input_schema.get("additionalProperties") is False, (
                f"{spec.name!r}: additionalProperties should be False"
            )

    def test_all_schemas_have_target_property(self):
        for spec in build_owasp_tool_specs():
            props = spec.input_schema.get("properties", {})
            assert "target" in props, f"{spec.name!r}: missing 'target' property"
            assert props["target"]["type"] == "string"

    def test_all_schemas_have_common_properties(self):
        """Each schema must contain the shared transversal properties."""
        common_keys = {"target", "auth_context", "safe_mode", "timeout", "proxy"}
        for spec in build_owasp_tool_specs():
            props = set(spec.input_schema.get("properties", {}).keys())
            missing = common_keys - props
            assert not missing, (
                f"{spec.name!r} is missing common properties: {missing}"
            )

    def test_module_specific_properties_present(self):
        """Each module with known extra properties must have them in its schema."""
        specs_by_key = {
            spec.name.split(".")[-1]: spec for spec in build_owasp_tool_specs()
        }
        for key, extra_props in _MODULE_EXTRA_PROPERTIES.items():
            spec = specs_by_key.get(key)
            assert spec is not None, f"No spec for module key {key!r}"
            schema_props = spec.input_schema.get("properties", {})
            for prop_name in extra_props:
                assert prop_name in schema_props, (
                    f"{spec.name!r}: expected module-specific property "
                    f"'{prop_name}' not found in input_schema"
                )

    def test_bola_schema_has_destructive_flag(self):
        specs = {s.name: s for s in build_owasp_tool_specs()}
        bola_spec = specs["apileak.owasp.bola"]
        assert "allow_write_bola" in bola_spec.input_schema["properties"]

    def test_function_auth_schema_has_destructive_flag(self):
        specs = {s.name: s for s in build_owasp_tool_specs()}
        bfla_spec = specs["apileak.owasp.function_auth"]
        assert "allow_destructive_bfla" in bfla_spec.input_schema["properties"]

    def test_ssrf_schema_has_callback_url(self):
        specs = {s.name: s for s in build_owasp_tool_specs()}
        ssrf_spec = specs["apileak.owasp.ssrf"]
        assert "ssrf_callback_url" in ssrf_spec.input_schema["properties"]

    def test_build_input_schema_returns_valid_json_schema_structure(self):
        """build_input_schema must return a dict with type/properties/required."""
        for descriptor in OWASP_MODULE_DESCRIPTORS:
            schema = _build_input_schema(descriptor)
            assert schema["type"] == "object"
            assert "properties" in schema
            assert "required" in schema
            assert "$schema" in schema


# ---------------------------------------------------------------------------
# Schema validation via registry (Req 1.3)
# ---------------------------------------------------------------------------


class TestOwaspSchemaValidationViaRegistry:
    """Registry must reject bad params before calling the handler."""

    def setup_method(self):
        self.registry = _make_registry_with_owasp()

    def _run(self, coro):
        return asyncio.run(coro)

    def test_missing_target_raises_schema_validation_error(self):
        with pytest.raises(SchemaValidationError):
            self._run(self.registry.invoke("apileak.owasp.bola", {}))

    def test_wrong_target_type_raises_schema_validation_error(self):
        with pytest.raises(SchemaValidationError):
            self._run(
                self.registry.invoke("apileak.owasp.ssrf", {"target": 12345})
            )

    def test_unknown_parameter_raises_schema_validation_error(self):
        """additionalProperties: false must catch unknown keys."""
        with pytest.raises(SchemaValidationError):
            self._run(
                self.registry.invoke(
                    "apileak.owasp.auth",
                    {"target": "https://api.example.com", "unknown_key": True},
                )
            )

    def test_valid_target_passes_schema_validation(self):
        """A params dict with only the required 'target' must pass schema validation.

        The handler itself will fail (no real engine), but we should NOT get a
        SchemaValidationError — that would mean schema validation wrongly
        rejected a valid payload.

        bola is now destructive (Task 6.1) so a ConfirmationToken is provided
        to bypass the gate and reach the handler level.
        """
        from mcp_server.schemas import ConfirmationToken
        from datetime import datetime

        # Patch the engine so the handler never actually tries to connect.
        with patch("mcp_server.owasp_tools.APILeakCore") as mock_core_cls:
            mock_core = MagicMock()
            mock_core.health_check = AsyncMock(return_value={})
            mock_core.run_scan = AsyncMock(return_value=None)
            mock_core.get_findings_collector.return_value.get_findings.return_value = []
            mock_core.get_findings_collector.return_value.get_statistics.return_value = {}
            mock_core_cls.return_value = mock_core

            token = ConfirmationToken(
                tool_name="apileak.owasp.bola",
                confirmed_by="test_operator",
                timestamp=datetime.utcnow(),
            )
            result = self._run(
                self.registry.invoke(
                    "apileak.owasp.bola",
                    {"target": "https://api.example.com"},
                    confirmation=token,
                )
            )
        # If we reach here without SchemaValidationError, validation passed.
        assert isinstance(result, MCPToolResult)


# ---------------------------------------------------------------------------
# Handler: MCPToolResult structure (Req 1.4)
# ---------------------------------------------------------------------------


class TestOwaspHandlerResult:
    """Verify handlers return MCPToolResult with correct structure."""

    def _run(self, coro):
        return asyncio.run(coro)

    def _patched_invoke(self, tool_name: str, params: dict, mock_findings=None):
        """Invoke ``tool_name`` with engine fully mocked, optionally injecting findings.

        For destructive tools (bola, function_auth) a matching ConfirmationToken
        is provided automatically so the gate does not block handler tests that
        are only interested in the output structure, not the gate behavior.
        """
        if mock_findings is None:
            mock_findings = []

        # Provide a confirmation token for destructive tools so the gate
        # passes and we reach the actual handler (the gate behavior is tested
        # separately in TestBuildOwaspToolSpecs and test_cloud_audit_tool.py).
        from mcp_server.schemas import ConfirmationToken
        from datetime import datetime

        registry = _make_registry_with_owasp()
        spec = registry._tools.get(tool_name)
        confirmation = (
            ConfirmationToken(tool_name=tool_name, confirmed_by="test_operator",
                              timestamp=datetime.utcnow())
            if (spec and spec.is_destructive)
            else None
        )

        with patch("mcp_server.owasp_tools.APILeakCore") as mock_core_cls:
            mock_core = MagicMock()
            mock_core.health_check = AsyncMock(return_value={})
            mock_core.run_scan = AsyncMock(return_value=None)
            mock_core.get_findings_collector.return_value.get_findings.return_value = (
                mock_findings
            )
            mock_core.get_findings_collector.return_value.get_statistics.return_value = {
                "total": len(mock_findings)
            }
            mock_core_cls.return_value = mock_core

            return self._run(
                registry.invoke(
                    tool_name,
                    {"target": "https://api.example.com"},
                    confirmation=confirmation,
                )
            )

    def test_result_is_mcp_tool_result(self):
        result = self._patched_invoke("apileak.owasp.bola", {})
        assert isinstance(result, MCPToolResult)

    def test_tool_name_in_result(self):
        result = self._patched_invoke("apileak.owasp.auth", {})
        assert result.tool_name == "apileak.owasp.auth"

    def test_findings_is_list(self):
        result = self._patched_invoke("apileak.owasp.ssrf", {})
        assert isinstance(result.findings, list)

    def test_untrusted_content_is_true(self):
        """All OWASP tools must mark findings as untrusted (Req 4.8 / OWASP MCP06)."""
        for spec in build_owasp_tool_specs():
            result = self._patched_invoke(spec.name, {})
            assert result.untrusted_content is True, (
                f"{spec.name!r}: untrusted_content should be True"
            )

    def test_metadata_contains_module_key(self):
        result = self._patched_invoke("apileak.owasp.property", {})
        assert result.metadata.get("module") == "property"

    def test_metadata_contains_owasp_category(self):
        result = self._patched_invoke("apileak.owasp.bola", {})
        # bola is API1
        assert result.metadata.get("owasp_category") == "API1"

    def test_metadata_contains_target(self):
        result = self._patched_invoke("apileak.owasp.resource", {})
        assert result.metadata.get("target") == "https://api.example.com"

    def test_findings_are_serialisable_dicts(self):
        """Findings must be plain dicts (JSON-serialisable), not dataclass objects."""
        # Create a minimal mock Finding with a to_dict-able structure.
        import dataclasses
        from enum import Enum

        class FakeSeverity(Enum):
            HIGH = "high"

        @dataclasses.dataclass
        class FakeFinding:
            id: str = "f-001"
            severity: FakeSeverity = FakeSeverity.HIGH
            title: str = "Test finding"

        result = self._patched_invoke(
            "apileak.owasp.security_misconfig",
            {},
            mock_findings=[FakeFinding()],
        )
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert isinstance(finding, dict), "Findings must be dicts, not dataclass objects"
        # Severity enum must be converted to its string value
        assert finding["severity"] == "high"

    def test_every_module_handler_produces_mcp_tool_result(self):
        """Smoke-test every module handler with a mocked engine."""
        for spec in build_owasp_tool_specs():
            result = self._patched_invoke(spec.name, {})
            assert isinstance(result, MCPToolResult), (
                f"{spec.name!r} handler did not return MCPToolResult"
            )

    def test_each_handler_uses_only_its_module(self):
        """Each handler must enable only its module in the engine config."""
        from mcp_server.schemas import ConfirmationToken
        from datetime import datetime

        for spec in build_owasp_tool_specs():
            module_key = spec.name.split(".")[-1]
            captured_configs = []

            def capture_config(cfg):
                captured_configs.append(cfg.owasp_testing.enabled_modules[:])
                mock_core = MagicMock()
                mock_core.health_check = AsyncMock(return_value={})
                mock_core.run_scan = AsyncMock(return_value=None)
                mock_core.get_findings_collector.return_value.get_findings.return_value = []
                mock_core.get_findings_collector.return_value.get_statistics.return_value = {}
                return mock_core

            confirmation = (
                ConfirmationToken(tool_name=spec.name, confirmed_by="test_operator",
                                  timestamp=datetime.utcnow())
                if spec.is_destructive
                else None
            )

            with patch("mcp_server.owasp_tools.APILeakCore", side_effect=capture_config):
                registry = _make_registry_with_owasp()
                asyncio.run(
                    registry.invoke(
                        spec.name,
                        {"target": "https://api.example.com"},
                        confirmation=confirmation,
                    )
                )

            assert captured_configs, f"{spec.name!r}: APILeakCore was never instantiated"
            assert captured_configs[0] == [module_key], (
                f"{spec.name!r}: enabled_modules should be [{module_key!r}], "
                f"got {captured_configs[0]}"
            )
