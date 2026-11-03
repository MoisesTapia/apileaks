"""
Tests for the ``apileak.discovery.*`` MCP tools (Task 2.3).

Covers:
- Tool spec construction (names, schemas, is_destructive flags)
- JSON Schema validation: required fields, type constraints
- Handler integration: MCPToolResult structure and untrusted_content=True
- Server registration: both tools appear in the registry after server init

Validates: Requirements 1.2, 1.4

Uses in-process mocks for the scan engine so no real network calls are made
(Requirement 11.1 — in-memory invocation, no real MCP SDK required).
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_server.discovery_tools import (
    DIR_INPUT_SCHEMA,
    DIR_OUTPUT_SCHEMA,
    PAR_INPUT_SCHEMA,
    PAR_OUTPUT_SCHEMA,
    _dir_handler,
    _par_handler,
    build_discovery_tool_specs,
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


def _make_registry_with_discovery() -> MCPToolRegistry:
    registry = MCPToolRegistry()
    for spec in build_discovery_tool_specs():
        registry.register(spec)
    return registry


def _make_core_mock(*, findings=None, endpoints=None):
    """Return a mock that satisfies the APILeakCore interface used by handlers."""
    mock_core = MagicMock()
    mock_core.health_check = AsyncMock(return_value={"status": "healthy"})
    mock_core.run_scan = AsyncMock(return_value=None)

    # Findings collector
    mock_collector = MagicMock()
    mock_collector.get_findings = MagicMock(return_value=findings or [])
    mock_collector.get_statistics = MagicMock(return_value={"total": 0})
    mock_core.get_findings_collector = MagicMock(return_value=mock_collector)

    # Discovered endpoints
    mock_core.get_discovered_endpoints = MagicMock(return_value=endpoints or [])

    return mock_core


# ---------------------------------------------------------------------------
# build_discovery_tool_specs — spec construction
# ---------------------------------------------------------------------------


class TestBuildDiscoveryToolSpecs:
    def test_returns_two_tools(self):
        specs = build_discovery_tool_specs()
        assert len(specs) == 2

    def test_dir_tool_present(self):
        names = {s.name for s in build_discovery_tool_specs()}
        assert "apileak.discovery.dir" in names

    def test_par_tool_present(self):
        names = {s.name for s in build_discovery_tool_specs()}
        assert "apileak.discovery.par" in names

    def test_all_are_mcp_tool_spec_instances(self):
        for spec in build_discovery_tool_specs():
            assert isinstance(spec, MCPToolSpec)

    def test_dir_not_destructive(self):
        spec = next(s for s in build_discovery_tool_specs() if s.name == "apileak.discovery.dir")
        assert spec.is_destructive is False

    def test_par_not_destructive(self):
        spec = next(s for s in build_discovery_tool_specs() if s.name == "apileak.discovery.par")
        assert spec.is_destructive is False

    def test_dir_has_handler(self):
        spec = next(s for s in build_discovery_tool_specs() if s.name == "apileak.discovery.dir")
        assert callable(spec.handler)

    def test_par_has_handler(self):
        spec = next(s for s in build_discovery_tool_specs() if s.name == "apileak.discovery.par")
        assert callable(spec.handler)

    def test_timeouts_are_ample(self):
        for spec in build_discovery_tool_specs():
            assert spec.max_execution_seconds >= 60.0


# ---------------------------------------------------------------------------
# JSON Schema — apileak.discovery.dir
# ---------------------------------------------------------------------------


class TestDirInputSchema:
    def test_target_required(self):
        assert "target" in DIR_INPUT_SCHEMA["required"]

    def test_target_is_string(self):
        assert DIR_INPUT_SCHEMA["properties"]["target"]["type"] == "string"

    def test_depth_minimum_zero(self):
        assert DIR_INPUT_SCHEMA["properties"]["depth"]["minimum"] == 0

    def test_extensions_is_array(self):
        assert DIR_INPUT_SCHEMA["properties"]["extensions"]["type"] == "array"

    def test_detect_secrets_is_boolean(self):
        assert DIR_INPUT_SCHEMA["properties"]["detect_secrets"]["type"] == "boolean"

    def test_concurrency_minimum_one(self):
        assert DIR_INPUT_SCHEMA["properties"]["concurrency"]["minimum"] == 1

    def test_max_requests_minimum_one(self):
        assert DIR_INPUT_SCHEMA["properties"]["max_requests"]["minimum"] == 1

    def test_additional_properties_false(self):
        assert DIR_INPUT_SCHEMA.get("additionalProperties") is False

    def test_jwt_present(self):
        assert "jwt" in DIR_INPUT_SCHEMA["properties"]

    def test_proxy_present(self):
        assert "proxy" in DIR_INPUT_SCHEMA["properties"]


# ---------------------------------------------------------------------------
# JSON Schema — apileak.discovery.par
# ---------------------------------------------------------------------------


class TestParInputSchema:
    def test_target_required(self):
        assert "target" in PAR_INPUT_SCHEMA["required"]

    def test_target_is_string(self):
        assert PAR_INPUT_SCHEMA["properties"]["target"]["type"] == "string"

    def test_methods_is_array(self):
        assert PAR_INPUT_SCHEMA["properties"]["methods"]["type"] == "array"

    def test_methods_enum_contains_http_verbs(self):
        method_items = PAR_INPUT_SCHEMA["properties"]["methods"]["items"]
        enum_vals = method_items["enum"]
        for verb in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            assert verb in enum_vals

    def test_boundary_testing_is_boolean(self):
        assert PAR_INPUT_SCHEMA["properties"]["boundary_testing"]["type"] == "boolean"

    def test_depth_minimum_zero(self):
        assert PAR_INPUT_SCHEMA["properties"]["depth"]["minimum"] == 0

    def test_additional_properties_false(self):
        assert PAR_INPUT_SCHEMA.get("additionalProperties") is False


# ---------------------------------------------------------------------------
# Registry: schema validation (Req 1.3)
# ---------------------------------------------------------------------------


class TestDirSchemaValidationViaRegistry:
    def setup_method(self):
        self.registry = _make_registry_with_discovery()

    def test_missing_target_raises_schema_validation_error(self):
        with pytest.raises(SchemaValidationError):
            asyncio.run(
                self.registry.invoke("apileak.discovery.dir", {})
            )

    def test_wrong_type_for_depth_raises_schema_validation_error(self):
        with pytest.raises(SchemaValidationError):
            asyncio.run(
                self.registry.invoke(
                    "apileak.discovery.dir",
                    {"target": "https://api.example.com", "depth": "three"},
                )
            )

    def test_negative_depth_raises_schema_validation_error(self):
        with pytest.raises(SchemaValidationError):
            asyncio.run(
                self.registry.invoke(
                    "apileak.discovery.dir",
                    {"target": "https://api.example.com", "depth": -1},
                )
            )

    def test_additional_property_raises_schema_validation_error(self):
        with pytest.raises(SchemaValidationError):
            asyncio.run(
                self.registry.invoke(
                    "apileak.discovery.dir",
                    {"target": "https://api.example.com", "bogus_field": "oops"},
                )
            )


class TestParSchemaValidationViaRegistry:
    def setup_method(self):
        self.registry = _make_registry_with_discovery()

    def test_missing_target_raises_schema_validation_error(self):
        with pytest.raises(SchemaValidationError):
            asyncio.run(
                self.registry.invoke("apileak.discovery.par", {})
            )

    def test_invalid_method_value_raises_schema_validation_error(self):
        with pytest.raises(SchemaValidationError):
            asyncio.run(
                self.registry.invoke(
                    "apileak.discovery.par",
                    {
                        "target": "https://api.example.com/users",
                        "methods": ["INVALID"],
                    },
                )
            )

    def test_wrong_type_for_boundary_testing_raises_schema_validation_error(self):
        with pytest.raises(SchemaValidationError):
            asyncio.run(
                self.registry.invoke(
                    "apileak.discovery.par",
                    {
                        "target": "https://api.example.com/users",
                        "boundary_testing": "yes",  # should be bool
                    },
                )
            )


# ---------------------------------------------------------------------------
# Handler: MCPToolResult structure (Req 1.4)
# ---------------------------------------------------------------------------


_PATCH_APILEAK_CORE = "mcp_server.discovery_tools.APILeakCore"
_PATCH_CONFIG_MANAGER = "mcp_server.discovery_tools.ConfigurationManager"


class TestDirHandler:
    """Verify _dir_handler returns correct MCPToolResult using mocked engine."""

    @patch(_PATCH_APILEAK_CORE)
    @patch(_PATCH_CONFIG_MANAGER)
    def test_returns_mcp_tool_result(self, MockConfigManager, MockAPILeakCore):
        mock_cm = MagicMock()
        mock_cm.load_config_from_dict = MagicMock(return_value=MagicMock(
            owasp_testing=MagicMock(enabled_modules=[]),
            fuzzing=MagicMock(
                parameters=MagicMock(enabled=True),
                headers=MagicMock(enabled=True),
            ),
        ))
        mock_cm.validate_configuration = MagicMock(return_value=[])
        MockConfigManager.return_value = mock_cm

        mock_core = _make_core_mock()
        MockAPILeakCore.return_value = mock_core

        result = asyncio.run(
            _dir_handler({"target": "https://api.example.com"})
        )

        assert isinstance(result, MCPToolResult)

    @patch(_PATCH_APILEAK_CORE)
    @patch(_PATCH_CONFIG_MANAGER)
    def test_tool_name_is_correct(self, MockConfigManager, MockAPILeakCore):
        mock_cm = MagicMock()
        mock_cm.load_config_from_dict = MagicMock(return_value=MagicMock(
            owasp_testing=MagicMock(enabled_modules=[]),
            fuzzing=MagicMock(
                parameters=MagicMock(enabled=True),
                headers=MagicMock(enabled=True),
            ),
        ))
        mock_cm.validate_configuration = MagicMock(return_value=[])
        MockConfigManager.return_value = mock_cm

        mock_core = _make_core_mock()
        MockAPILeakCore.return_value = mock_core

        result = asyncio.run(
            _dir_handler({"target": "https://api.example.com"})
        )

        assert result.tool_name == "apileak.discovery.dir"

    @patch(_PATCH_APILEAK_CORE)
    @patch(_PATCH_CONFIG_MANAGER)
    def test_untrusted_content_true(self, MockConfigManager, MockAPILeakCore):
        """Discovery responses contain verbatim target data — must be marked untrusted (Req 4.8)."""
        mock_cm = MagicMock()
        mock_cm.load_config_from_dict = MagicMock(return_value=MagicMock(
            owasp_testing=MagicMock(enabled_modules=[]),
            fuzzing=MagicMock(
                parameters=MagicMock(enabled=True),
                headers=MagicMock(enabled=True),
            ),
        ))
        mock_cm.validate_configuration = MagicMock(return_value=[])
        MockConfigManager.return_value = mock_cm

        mock_core = _make_core_mock()
        MockAPILeakCore.return_value = mock_core

        result = asyncio.run(
            _dir_handler({"target": "https://api.example.com"})
        )

        assert result.untrusted_content is True

    @patch(_PATCH_APILEAK_CORE)
    @patch(_PATCH_CONFIG_MANAGER)
    def test_findings_is_list(self, MockConfigManager, MockAPILeakCore):
        mock_cm = MagicMock()
        mock_cm.load_config_from_dict = MagicMock(return_value=MagicMock(
            owasp_testing=MagicMock(enabled_modules=[]),
            fuzzing=MagicMock(
                parameters=MagicMock(enabled=True),
                headers=MagicMock(enabled=True),
            ),
        ))
        mock_cm.validate_configuration = MagicMock(return_value=[])
        MockConfigManager.return_value = mock_cm

        mock_core = _make_core_mock()
        MockAPILeakCore.return_value = mock_core

        result = asyncio.run(
            _dir_handler({"target": "https://api.example.com"})
        )

        assert isinstance(result.findings, list)

    @patch(_PATCH_APILEAK_CORE)
    @patch(_PATCH_CONFIG_MANAGER)
    def test_metadata_contains_target_and_endpoints_found(
        self, MockConfigManager, MockAPILeakCore
    ):
        mock_cm = MagicMock()
        mock_cm.load_config_from_dict = MagicMock(return_value=MagicMock(
            owasp_testing=MagicMock(enabled_modules=[]),
            fuzzing=MagicMock(
                parameters=MagicMock(enabled=True),
                headers=MagicMock(enabled=True),
            ),
        ))
        mock_cm.validate_configuration = MagicMock(return_value=[])
        MockConfigManager.return_value = mock_cm

        # Two mock endpoints
        ep1 = MagicMock()
        ep1.url = "https://api.example.com/users"
        ep1.status = MagicMock(value="valid")
        ep1.auth_required = False
        ep1.method = "GET"
        ep2 = MagicMock()
        ep2.url = "https://api.example.com/admin"
        ep2.status = MagicMock(value="valid")
        ep2.auth_required = True
        ep2.method = "GET"

        mock_core = _make_core_mock(endpoints=[ep1, ep2])
        MockAPILeakCore.return_value = mock_core

        target = "https://api.example.com"
        result = asyncio.run(
            _dir_handler({"target": target})
        )

        assert result.metadata["target"] == target
        assert result.metadata["endpoints_found"] == 2
        assert "discovered_urls" in result.metadata


class TestParHandler:
    """Verify _par_handler returns correct MCPToolResult using mocked engine."""

    @patch(_PATCH_APILEAK_CORE)
    @patch(_PATCH_CONFIG_MANAGER)
    def test_returns_mcp_tool_result(self, MockConfigManager, MockAPILeakCore):
        mock_cm = MagicMock()
        mock_cm.load_config_from_dict = MagicMock(return_value=MagicMock(
            owasp_testing=MagicMock(enabled_modules=[]),
            fuzzing=MagicMock(
                parameters=MagicMock(enabled=True, methods=["GET", "POST"], boundary_testing=True),
                headers=MagicMock(enabled=True),
            ),
        ))
        mock_cm.validate_configuration = MagicMock(return_value=[])
        MockConfigManager.return_value = mock_cm

        mock_core = _make_core_mock()
        MockAPILeakCore.return_value = mock_core

        result = asyncio.run(
            _par_handler({"target": "https://api.example.com/users/123"})
        )

        assert isinstance(result, MCPToolResult)

    @patch(_PATCH_APILEAK_CORE)
    @patch(_PATCH_CONFIG_MANAGER)
    def test_tool_name_is_correct(self, MockConfigManager, MockAPILeakCore):
        mock_cm = MagicMock()
        mock_cm.load_config_from_dict = MagicMock(return_value=MagicMock(
            owasp_testing=MagicMock(enabled_modules=[]),
            fuzzing=MagicMock(
                parameters=MagicMock(enabled=True, methods=["GET", "POST"], boundary_testing=True),
                headers=MagicMock(enabled=True),
            ),
        ))
        mock_cm.validate_configuration = MagicMock(return_value=[])
        MockConfigManager.return_value = mock_cm

        mock_core = _make_core_mock()
        MockAPILeakCore.return_value = mock_core

        result = asyncio.run(
            _par_handler({"target": "https://api.example.com/users/123"})
        )

        assert result.tool_name == "apileak.discovery.par"

    @patch(_PATCH_APILEAK_CORE)
    @patch(_PATCH_CONFIG_MANAGER)
    def test_untrusted_content_true(self, MockConfigManager, MockAPILeakCore):
        mock_cm = MagicMock()
        mock_cm.load_config_from_dict = MagicMock(return_value=MagicMock(
            owasp_testing=MagicMock(enabled_modules=[]),
            fuzzing=MagicMock(
                parameters=MagicMock(enabled=True, methods=["GET", "POST"], boundary_testing=True),
                headers=MagicMock(enabled=True),
            ),
        ))
        mock_cm.validate_configuration = MagicMock(return_value=[])
        MockConfigManager.return_value = mock_cm

        mock_core = _make_core_mock()
        MockAPILeakCore.return_value = mock_core

        result = asyncio.run(
            _par_handler({"target": "https://api.example.com/users/123"})
        )

        assert result.untrusted_content is True

    @patch(_PATCH_APILEAK_CORE)
    @patch(_PATCH_CONFIG_MANAGER)
    def test_metadata_contains_target(self, MockConfigManager, MockAPILeakCore):
        mock_cm = MagicMock()
        mock_cm.load_config_from_dict = MagicMock(return_value=MagicMock(
            owasp_testing=MagicMock(enabled_modules=[]),
            fuzzing=MagicMock(
                parameters=MagicMock(enabled=True, methods=["GET", "POST"], boundary_testing=True),
                headers=MagicMock(enabled=True),
            ),
        ))
        mock_cm.validate_configuration = MagicMock(return_value=[])
        MockConfigManager.return_value = mock_cm

        mock_core = _make_core_mock()
        MockAPILeakCore.return_value = mock_core

        target = "https://api.example.com/users/123"
        result = asyncio.run(
            _par_handler({"target": target})
        )

        assert result.metadata["target"] == target

    @patch(_PATCH_APILEAK_CORE)
    @patch(_PATCH_CONFIG_MANAGER)
    def test_findings_is_list(self, MockConfigManager, MockAPILeakCore):
        mock_cm = MagicMock()
        mock_cm.load_config_from_dict = MagicMock(return_value=MagicMock(
            owasp_testing=MagicMock(enabled_modules=[]),
            fuzzing=MagicMock(
                parameters=MagicMock(enabled=True, methods=["GET", "POST"], boundary_testing=True),
                headers=MagicMock(enabled=True),
            ),
        ))
        mock_cm.validate_configuration = MagicMock(return_value=[])
        MockConfigManager.return_value = mock_cm

        mock_core = _make_core_mock()
        MockAPILeakCore.return_value = mock_core

        result = asyncio.run(
            _par_handler({"target": "https://api.example.com/users/123"})
        )

        assert isinstance(result.findings, list)


# ---------------------------------------------------------------------------
# Server registration (Req 1.2)
# ---------------------------------------------------------------------------


class TestDiscoveryToolsServerRegistration:
    """Verify both discovery tools appear in the registry after server init."""

    def test_discovery_dir_in_registry(self):
        config = MCPServerConfig(transport="stdio")
        server = APILeakMCPServer(transport="stdio", config=config)
        tool_names = {spec.name for spec in server.registry.list_tools()}
        assert "apileak.discovery.dir" in tool_names

    def test_discovery_par_in_registry(self):
        config = MCPServerConfig(transport="stdio")
        server = APILeakMCPServer(transport="stdio", config=config)
        tool_names = {spec.name for spec in server.registry.list_tools()}
        assert "apileak.discovery.par" in tool_names

    def test_discovery_tool_count(self):
        """Both dir and par tools must be registered."""
        config = MCPServerConfig(transport="stdio")
        server = APILeakMCPServer(transport="stdio", config=config)
        discovery_tools = [
            spec for spec in server.registry.list_tools()
            if spec.name.startswith("apileak.discovery.")
        ]
        assert len(discovery_tools) >= 2
