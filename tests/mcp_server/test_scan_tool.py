"""
Tests for the ``apileak.scan`` MCP tool (Task 2.1).

Covers:
- Tool spec construction (name, schema presence, is_destructive flag)
- JSON Schema validation: required field, enum constraints, type constraints
- Handler integration: MCPToolResult structure, untrusted_content flag
- Server registration: apileak.scan appears in the registry after init

Validates: Requirements 1.2, 1.4

Uses an in-process mock for the scan engine so no real network calls are made
(Requirement 11.1 — in-memory client, no real MCP SDK transport required).
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_server.scan_handler import (
    SCAN_INPUT_SCHEMA,
    SCAN_OUTPUT_SCHEMA,
    build_scan_tool_spec,
    _scan_handler,
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


def _make_registry_with_scan() -> MCPToolRegistry:
    registry = MCPToolRegistry()
    registry.register(build_scan_tool_spec())
    return registry


# ---------------------------------------------------------------------------
# Spec construction
# ---------------------------------------------------------------------------


class TestScanToolSpec:
    def test_name(self):
        spec = build_scan_tool_spec()
        assert spec.name == "apileak.scan"

    def test_not_destructive(self):
        """Scan tool is non-destructive by default (destructive gate in Task 6.1)."""
        spec = build_scan_tool_spec()
        assert spec.is_destructive is False

    def test_has_input_schema(self):
        spec = build_scan_tool_spec()
        assert isinstance(spec.input_schema, dict)
        assert spec.input_schema.get("type") == "object"

    def test_has_output_schema(self):
        spec = build_scan_tool_spec()
        assert isinstance(spec.output_schema, dict)

    def test_has_handler(self):
        spec = build_scan_tool_spec()
        assert callable(spec.handler)

    def test_timeout_is_ample(self):
        """Full scans can be long — default timeout should be at least 5 min."""
        spec = build_scan_tool_spec()
        assert spec.max_execution_seconds >= 300.0

    def test_is_mcp_tool_spec_instance(self):
        spec = build_scan_tool_spec()
        assert isinstance(spec, MCPToolSpec)


# ---------------------------------------------------------------------------
# JSON Schema
# ---------------------------------------------------------------------------


class TestScanInputSchema:
    def test_target_is_required(self):
        assert "target" in SCAN_INPUT_SCHEMA["required"]

    def test_target_is_string(self):
        assert SCAN_INPUT_SCHEMA["properties"]["target"]["type"] == "string"

    def test_additional_properties_false(self):
        """additionalProperties: false prevents unknown keys slipping through."""
        assert SCAN_INPUT_SCHEMA.get("additionalProperties") is False

    def test_modules_enum_contains_known_keys(self):
        modules_schema = SCAN_INPUT_SCHEMA["properties"]["modules"]
        enum = modules_schema["items"]["enum"]
        for known_key in ("bola", "auth", "ssrf", "property", "resource"):
            assert known_key in enum, f"{known_key!r} missing from modules enum"

    def test_fail_on_enum(self):
        enum = SCAN_INPUT_SCHEMA["properties"]["fail_on"]["enum"]
        assert set(enum) == {"critical", "high", "medium", "low"}

    def test_depth_minimum_zero(self):
        assert SCAN_INPUT_SCHEMA["properties"]["depth"]["minimum"] == 0

    def test_concurrency_minimum_one(self):
        assert SCAN_INPUT_SCHEMA["properties"]["concurrency"]["minimum"] == 1

    def test_timeout_exclusive_minimum(self):
        assert SCAN_INPUT_SCHEMA["properties"]["timeout"]["exclusiveMinimum"] == 0


# ---------------------------------------------------------------------------
# Registry: schema validation blocks bad invocations (Req 1.3 / Property 5)
# ---------------------------------------------------------------------------


class TestScanSchemaValidationViaRegistry:
    """Verify that the registry rejects bad params before calling the handler."""

    def setup_method(self):
        self.registry = _make_registry_with_scan()

    def test_missing_target_raises_schema_validation_error(self):
        with pytest.raises(SchemaValidationError):
            asyncio.run(
                self.registry.invoke("apileak.scan", {})
            )

    def test_invalid_module_key_raises_schema_validation_error(self):
        with pytest.raises(SchemaValidationError):
            asyncio.run(
                self.registry.invoke(
                    "apileak.scan",
                    {"target": "https://x.example.com", "modules": ["__not_a_real_key__"]},
                )
            )

    def test_wrong_type_for_depth_raises_schema_validation_error(self):
        with pytest.raises(SchemaValidationError):
            asyncio.run(
                self.registry.invoke(
                    "apileak.scan",
                    {"target": "https://x.example.com", "depth": "three"},
                )
            )

    def test_negative_depth_raises_schema_validation_error(self):
        with pytest.raises(SchemaValidationError):
            asyncio.run(
                self.registry.invoke(
                    "apileak.scan",
                    {"target": "https://x.example.com", "depth": -1},
                )
            )

    def test_additional_property_raises_schema_validation_error(self):
        with pytest.raises(SchemaValidationError):
            asyncio.run(
                self.registry.invoke(
                    "apileak.scan",
                    {"target": "https://x.example.com", "unknown_param": "oops"},
                )
            )

    def test_valid_minimal_params_pass_schema_validation(self):
        """Valid params must not be rejected by schema validation.

        We mock the scan engine so no real network call is made.  The handler
        must be entered (schema validation passes), and a valid MCPToolResult
        must be returned.
        """
        from unittest.mock import AsyncMock, MagicMock, patch

        mock_collector = MagicMock()
        mock_collector.get_findings.return_value = []
        mock_collector.get_statistics.return_value = {}

        mock_core = MagicMock()
        mock_core.health_check = AsyncMock(return_value={"status": "healthy"})
        mock_core.run_scan = AsyncMock(return_value=None)
        mock_core.get_findings_collector.return_value = mock_collector

        with patch("mcp_server.scan_handler.APILeakCore", return_value=mock_core):
            result = asyncio.run(
                self.registry.invoke(
                    "apileak.scan",
                    {"target": "https://valid-target.example.com"},
                )
            )
        assert isinstance(result, MCPToolResult)
        assert result.tool_name == "apileak.scan"


# ---------------------------------------------------------------------------
# Handler integration: MCPToolResult contract (Req 1.4)
# ---------------------------------------------------------------------------


class TestScanHandlerResult:
    """Verify MCPToolResult structure using a mocked core engine."""

    @pytest.mark.asyncio
    async def test_handler_returns_mcp_tool_result(self):
        """The handler must return an MCPToolResult (Req 1.4)."""
        fake_finding = MagicMock()
        fake_finding.id = "f-001"
        fake_finding.scan_id = "scan-001"
        fake_finding.category = "BOLA"
        fake_finding.owasp_category = "API1"
        fake_finding.endpoint = "https://target.example.com/api/users/1"
        fake_finding.method = "GET"
        fake_finding.status_code = 200
        fake_finding.response_size = 512
        fake_finding.response_time = 0.1
        fake_finding.evidence = "Accessed resource of another user"
        fake_finding.recommendation = "Implement BOLA controls"
        fake_finding.payload = None
        fake_finding.response_snippet = None
        fake_finding.evidence_chain = None
        fake_finding.confidence = "high"
        fake_finding.headers = {}
        fake_finding.timestamp = None
        fake_finding.detection_signal = None
        fake_finding.detection_signals = []
        fake_finding.reflection_location = None
        fake_finding.new_json_fields = None
        fake_finding.confirmation_status = None

        from core.config import Severity
        fake_finding.severity = Severity.HIGH

        # Mock FindingsCollector
        mock_collector = MagicMock()
        mock_collector.get_findings.return_value = [fake_finding]
        mock_collector.get_statistics.return_value = {"total": 1, "by_severity": {"high": 1}}

        # Mock APILeakCore
        mock_core = MagicMock()
        mock_core.health_check = AsyncMock(return_value={"status": "healthy"})
        mock_core.run_scan = AsyncMock(return_value=None)
        mock_core.get_findings_collector.return_value = mock_collector

        with patch("mcp_server.scan_handler.APILeakCore", return_value=mock_core):
            result = await _scan_handler({"target": "https://target.example.com"})

        assert isinstance(result, MCPToolResult)

    @pytest.mark.asyncio
    async def test_handler_result_tool_name(self):
        mock_collector = MagicMock()
        mock_collector.get_findings.return_value = []
        mock_collector.get_statistics.return_value = {}

        mock_core = MagicMock()
        mock_core.health_check = AsyncMock(return_value={"status": "healthy"})
        mock_core.run_scan = AsyncMock(return_value=None)
        mock_core.get_findings_collector.return_value = mock_collector

        with patch("mcp_server.scan_handler.APILeakCore", return_value=mock_core):
            result = await _scan_handler({"target": "https://target.example.com"})

        assert result.tool_name == "apileak.scan"

    @pytest.mark.asyncio
    async def test_handler_result_has_findings_list(self):
        mock_collector = MagicMock()
        mock_collector.get_findings.return_value = []
        mock_collector.get_statistics.return_value = {}

        mock_core = MagicMock()
        mock_core.health_check = AsyncMock(return_value={"status": "healthy"})
        mock_core.run_scan = AsyncMock(return_value=None)
        mock_core.get_findings_collector.return_value = mock_collector

        with patch("mcp_server.scan_handler.APILeakCore", return_value=mock_core):
            result = await _scan_handler({"target": "https://target.example.com"})

        assert isinstance(result.findings, list)

    @pytest.mark.asyncio
    async def test_handler_result_has_metadata(self):
        mock_collector = MagicMock()
        mock_collector.get_findings.return_value = []
        mock_collector.get_statistics.return_value = {"total": 0}

        mock_core = MagicMock()
        mock_core.health_check = AsyncMock(return_value={"status": "healthy"})
        mock_core.run_scan = AsyncMock(return_value=None)
        mock_core.get_findings_collector.return_value = mock_collector

        with patch("mcp_server.scan_handler.APILeakCore", return_value=mock_core):
            result = await _scan_handler(
                {"target": "https://target.example.com", "safe_mode": True}
            )

        assert "target" in result.metadata
        assert result.metadata["target"] == "https://target.example.com"
        assert "finding_count" in result.metadata

    @pytest.mark.asyncio
    async def test_handler_marks_untrusted_content(self):
        """Req 4.8 / OWASP MCP06: results with target data must be marked untrusted."""
        mock_collector = MagicMock()
        mock_collector.get_findings.return_value = []
        mock_collector.get_statistics.return_value = {}

        mock_core = MagicMock()
        mock_core.health_check = AsyncMock(return_value={"status": "healthy"})
        mock_core.run_scan = AsyncMock(return_value=None)
        mock_core.get_findings_collector.return_value = mock_collector

        with patch("mcp_server.scan_handler.APILeakCore", return_value=mock_core):
            result = await _scan_handler({"target": "https://target.example.com"})

        assert result.untrusted_content is True

    @pytest.mark.asyncio
    async def test_handler_propagates_module_selection(self):
        mock_collector = MagicMock()
        mock_collector.get_findings.return_value = []
        mock_collector.get_statistics.return_value = {}

        mock_core = MagicMock()
        mock_core.health_check = AsyncMock(return_value={"status": "healthy"})
        mock_core.run_scan = AsyncMock(return_value=None)
        mock_core.get_findings_collector.return_value = mock_collector

        selected = ["bola", "ssrf"]

        with patch("mcp_server.scan_handler.APILeakCore", return_value=mock_core) as MockCore:
            await _scan_handler(
                {"target": "https://target.example.com", "modules": selected}
            )
            # The config passed to APILeakCore should have only selected modules
            cfg_arg = MockCore.call_args[0][0]
            assert cfg_arg.owasp_testing.enabled_modules == selected


# ---------------------------------------------------------------------------
# Server registration (Req 1.2)
# ---------------------------------------------------------------------------


class TestServerRegistration:
    def test_server_registers_scan_tool(self):
        """apileak.scan must appear in the registry after server init (Req 1.2)."""
        config = MCPServerConfig(transport="stdio")
        server = APILeakMCPServer(transport="stdio", config=config)
        tool_names = [t.name for t in server.registry.list_tools()]
        assert "apileak.scan" in tool_names

    def test_manifest_hash_changes_when_tool_is_added(self):
        """Manifest hash must reflect the registered tool set (Req 4.7)."""
        empty_registry = MCPToolRegistry()
        empty_hash = empty_registry.manifest_hash()

        registry_with_scan = _make_registry_with_scan()
        scan_hash = registry_with_scan.manifest_hash()

        assert empty_hash != scan_hash
