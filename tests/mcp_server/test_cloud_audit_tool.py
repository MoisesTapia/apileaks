"""
Tests for the ``apileak.cloud_audit`` MCP tool (Task 2.4).

Covers:
- Tool spec construction: name, is_destructive flag, timeout, schema presence
- Tool appears in registry after APILeakMCPServer init (Req 1.2)
- JSON Schema validation: required field, enum constraints, unknown params
- Handler stub behaviour: raises MCPToolError(NOT_IMPLEMENTED) when
  CloudAuditOrchestrator is unavailable
- Handler delegation: invokes CloudAuditOrchestrator when available and
  returns a structured MCPToolResult (Req 1.4)
- untrusted_content flag is set on results (Req 4.8 / OWASP MCP06)
- Destructive confirmation is required (Req 4.1, 4.2)

Validates: Requirements 1.2, 1.4

Uses in-process mocks — no real network or cloud SDK calls are made
(Requirement 11.1 — in-memory client, no real MCP SDK transport required).
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_server.cloud_audit_tool import (
    CLOUD_AUDIT_INPUT_SCHEMA,
    CLOUD_AUDIT_OUTPUT_SCHEMA,
    build_cloud_audit_tool_spec,
)
from mcp_server.schemas import (
    ConfirmationToken,
    MCPServerConfig,
    MCPToolError,
    MCPToolResult,
    MCPToolSpec,
    SchemaValidationError,
)
from mcp_server.server import APILeakMCPServer
from mcp_server.tool_registry import MCPToolRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_registry_with_cloud_audit(allow_destructive: bool = True) -> MCPToolRegistry:
    """Create a registry pre-loaded with the cloud_audit tool.

    Args:
        allow_destructive: When True (default) the gate allows destructive ops
            so tests can reach Tier 2 (token check).  Pass False to test the
            Tier 1 process-level block (DESTRUCTIVE_NOT_ENABLED).
    """
    from mcp_server.confirmation_gate import DestructiveConfirmationGate

    gate = DestructiveConfirmationGate(allow_destructive=allow_destructive)
    registry = MCPToolRegistry(confirmation_gate=gate)
    registry.register(build_cloud_audit_tool_spec())
    return registry


def _make_confirmation() -> ConfirmationToken:
    return ConfirmationToken(
        tool_name="apileak.cloud_audit",
        confirmed_by="test_operator",
        timestamp=datetime.utcnow(),
    )


def _minimal_params() -> dict:
    """Minimal valid params satisfying the input schema."""
    return {"target": "my-api-gateway-id"}


# ---------------------------------------------------------------------------
# Spec construction
# ---------------------------------------------------------------------------


class TestCloudAuditToolSpec:
    def test_name(self):
        spec = build_cloud_audit_tool_spec()
        assert spec.name == "apileak.cloud_audit"

    def test_is_destructive(self):
        """Cloud audit is destructive — write ops on the management plane."""
        spec = build_cloud_audit_tool_spec()
        assert spec.is_destructive is True

    def test_has_input_schema(self):
        spec = build_cloud_audit_tool_spec()
        assert isinstance(spec.input_schema, dict)
        assert spec.input_schema.get("type") == "object"

    def test_has_output_schema(self):
        spec = build_cloud_audit_tool_spec()
        assert isinstance(spec.output_schema, dict)

    def test_has_handler(self):
        spec = build_cloud_audit_tool_spec()
        assert callable(spec.handler)

    def test_timeout_is_ample(self):
        """Cloud enumeration across regions can be slow — min 5 min."""
        spec = build_cloud_audit_tool_spec()
        assert spec.max_execution_seconds >= 300.0

    def test_description_mentions_dependency(self):
        """Description should warn about cloud-gateway-security-audit dep."""
        spec = build_cloud_audit_tool_spec()
        assert "cloud-gateway-security-audit" in spec.description

    def test_input_schema_requires_target(self):
        """'target' must be in the required list."""
        assert "target" in CLOUD_AUDIT_INPUT_SCHEMA["required"]

    def test_input_schema_provider_enum(self):
        """'provider' must be restricted to aws | azure | gcp."""
        provider_schema = CLOUD_AUDIT_INPUT_SCHEMA["properties"]["provider"]
        assert set(provider_schema["enum"]) == {"aws", "azure", "gcp"}

    def test_input_schema_no_additional_properties(self):
        """Schema must forbid unknown properties (Req 1.3)."""
        assert CLOUD_AUDIT_INPUT_SCHEMA.get("additionalProperties") is False

    def test_input_schema_allow_destructive_is_boolean(self):
        prop = CLOUD_AUDIT_INPUT_SCHEMA["properties"]["allow_destructive_cloud_audit"]
        assert prop["type"] == "boolean"
        assert prop.get("default") is False

    def test_azure_client_secret_not_in_schema(self):
        """azure_client_secret must NOT be an accepted MCP param (Req 7.3)."""
        assert "azure_client_secret" not in CLOUD_AUDIT_INPUT_SCHEMA["properties"]


# ---------------------------------------------------------------------------
# Server registration (Requirement 1.2)
# ---------------------------------------------------------------------------


class TestCloudAuditRegistration:
    def test_tool_registered_in_server(self):
        """apileak.cloud_audit must appear in the registry after server init."""
        config = MCPServerConfig(transport="stdio")
        server = APILeakMCPServer(transport="stdio", config=config)
        tool_names = [spec.name for spec in server.registry.list_tools()]
        assert "apileak.cloud_audit" in tool_names

    def test_tool_registered_in_standalone_registry(self):
        registry = _make_registry_with_cloud_audit()
        tool_names = [spec.name for spec in registry.list_tools()]
        assert "apileak.cloud_audit" in tool_names


# ---------------------------------------------------------------------------
# JSON Schema validation (Requirement 1.3 / Property 5)
# ---------------------------------------------------------------------------


class TestCloudAuditSchemaValidation:
    def test_valid_minimal_params_accepted(self):
        """Minimal valid params must pass schema validation."""
        registry = _make_registry_with_cloud_audit()
        # Should not raise SchemaValidationError
        spec = registry._tools["apileak.cloud_audit"]
        MCPToolRegistry._validate_params(spec, _minimal_params())

    def test_missing_target_raises_schema_error(self):
        registry = _make_registry_with_cloud_audit()
        spec = registry._tools["apileak.cloud_audit"]
        with pytest.raises(SchemaValidationError):
            MCPToolRegistry._validate_params(spec, {})

    def test_unknown_param_raises_schema_error(self):
        """additionalProperties=false should reject unknown keys."""
        registry = _make_registry_with_cloud_audit()
        spec = registry._tools["apileak.cloud_audit"]
        bad_params = {**_minimal_params(), "unknown_key": "value"}
        with pytest.raises(SchemaValidationError):
            MCPToolRegistry._validate_params(spec, bad_params)

    def test_invalid_provider_enum_raises_schema_error(self):
        registry = _make_registry_with_cloud_audit()
        spec = registry._tools["apileak.cloud_audit"]
        bad_params = {**_minimal_params(), "provider": "digitalocean"}
        with pytest.raises(SchemaValidationError):
            MCPToolRegistry._validate_params(spec, bad_params)

    def test_valid_provider_values_accepted(self):
        registry = _make_registry_with_cloud_audit()
        spec = registry._tools["apileak.cloud_audit"]
        for provider in ("aws", "azure", "gcp"):
            MCPToolRegistry._validate_params(spec, {**_minimal_params(), "provider": provider})

    def test_allow_destructive_wrong_type_raises(self):
        registry = _make_registry_with_cloud_audit()
        spec = registry._tools["apileak.cloud_audit"]
        bad_params = {**_minimal_params(), "allow_destructive_cloud_audit": "yes"}
        with pytest.raises(SchemaValidationError):
            MCPToolRegistry._validate_params(spec, bad_params)

    def test_empty_target_raises_schema_error(self):
        registry = _make_registry_with_cloud_audit()
        spec = registry._tools["apileak.cloud_audit"]
        with pytest.raises(SchemaValidationError):
            MCPToolRegistry._validate_params(spec, {"target": ""})


# ---------------------------------------------------------------------------
# Destructive confirmation gate (Requirements 4.1, 4.2)
# ---------------------------------------------------------------------------


class TestCloudAuditDestructiveGating:
    def test_invoke_without_confirmation_raises(self):
        """Destructive tool must raise ConfirmationRequiredError without token
        when server is in destructive mode (Tier 2 check)."""
        from mcp_server.schemas import ConfirmationRequiredError

        # Registry with allow_destructive=True so we reach Tier 2 (token check).
        registry = _make_registry_with_cloud_audit(allow_destructive=True)
        with pytest.raises(ConfirmationRequiredError):
            asyncio.run(
                registry.invoke("apileak.cloud_audit", _minimal_params(), confirmation=None)
            )

    def test_invoke_blocked_in_safe_mode(self):
        """Destructive tool must be blocked (MCPToolError) when server is in
        safe mode — even if the caller would supply a valid token (Tier 1 check)."""
        from mcp_server.schemas import MCPToolError

        # Registry with allow_destructive=False (safe mode, the default).
        registry = _make_registry_with_cloud_audit(allow_destructive=False)
        with pytest.raises(MCPToolError) as exc_info:
            asyncio.run(
                registry.invoke("apileak.cloud_audit", _minimal_params(), confirmation=None)
            )
        assert exc_info.value.error_code == "DESTRUCTIVE_NOT_ENABLED"

    def test_invoke_wrong_tool_confirmation_raises(self):
        """A ConfirmationToken for a different tool must be rejected."""
        from mcp_server.schemas import ConfirmationRequiredError

        # Registry with allow_destructive=True so we reach Tier 2 (token check).
        registry = _make_registry_with_cloud_audit(allow_destructive=True)
        wrong_token = ConfirmationToken(
            tool_name="apileak.scan",  # wrong tool
            confirmed_by="test_operator",
        )
        with pytest.raises(ConfirmationRequiredError):
            asyncio.run(
                registry.invoke(
                    "apileak.cloud_audit", _minimal_params(), confirmation=wrong_token
                )
            )


# ---------------------------------------------------------------------------
# Stub behaviour — NOT_IMPLEMENTED when orchestrator unavailable
# ---------------------------------------------------------------------------


class TestCloudAuditStubBehaviour:
    def test_handler_raises_not_implemented_when_import_fails(self):
        """When CloudAuditOrchestrator cannot be imported, the handler must
        raise MCPToolError with error_code='NOT_IMPLEMENTED'."""
        import builtins

        real_import = builtins.__import__

        def _blocking_import(name, *args, **kwargs):
            if name in ("core.cloud_audit", "core.config"):
                raise ImportError(f"Simulated missing dependency: {name}")
            return real_import(name, *args, **kwargs)

        spec = build_cloud_audit_tool_spec()

        with patch("builtins.__import__", side_effect=_blocking_import):
            with pytest.raises(MCPToolError) as exc_info:
                asyncio.run(spec.handler(_minimal_params()))

        assert exc_info.value.error_code == "NOT_IMPLEMENTED"
        assert "cloud-gateway-security-audit" in str(exc_info.value)

    def test_not_implemented_error_message_is_helpful(self):
        """NOT_IMPLEMENTED message must explain the dependency."""
        import builtins

        real_import = builtins.__import__

        def _blocking_import(name, *args, **kwargs):
            if name in ("core.cloud_audit", "core.config"):
                raise ImportError("Simulated")
            return real_import(name, *args, **kwargs)

        spec = build_cloud_audit_tool_spec()

        with patch("builtins.__import__", side_effect=_blocking_import):
            with pytest.raises(MCPToolError) as exc_info:
                asyncio.run(spec.handler(_minimal_params()))

        msg = str(exc_info.value)
        # Message should mention both the dependency spec and the install extra
        assert "cloud-gateway-security-audit" in msg
        assert "apileaks[cloud]" in msg


# ---------------------------------------------------------------------------
# Handler delegation — when orchestrator IS available (Requirement 1.4)
# ---------------------------------------------------------------------------


class TestCloudAuditHandlerDelegation:
    def _make_mock_summary(self, findings=None):
        """Build a mock AuditSummary returned by CloudAuditOrchestrator.run()."""
        summary = MagicMock()
        summary.findings = findings or []
        summary.auditors_succeeded = ["aws_us_east_1"]
        summary.auditors_failed = []
        summary.auditors_skipped_no_credentials = []
        return summary

    def test_handler_returns_mcp_tool_result(self):
        """When orchestrator is available, handler must return MCPToolResult."""
        mock_summary = self._make_mock_summary()
        mock_orchestrator = MagicMock()
        mock_orchestrator.run = AsyncMock(return_value=mock_summary)

        mock_config_cls = MagicMock(return_value=MagicMock())
        mock_orch_cls = MagicMock(return_value=mock_orchestrator)

        with (
            patch("mcp_server.cloud_audit_tool.CloudAuditOrchestrator", mock_orch_cls, create=True),
            patch("mcp_server.cloud_audit_tool.CloudAuditConfig", mock_config_cls, create=True),
            patch.dict(
                "sys.modules",
                {
                    "core.cloud_audit": MagicMock(CloudAuditOrchestrator=mock_orch_cls),
                    "core.config": MagicMock(CloudAuditConfig=mock_config_cls),
                },
            ),
        ):
            spec = build_cloud_audit_tool_spec()
            result = asyncio.run(
                spec.handler({**_minimal_params(), "provider": "aws"})
            )

        assert isinstance(result, MCPToolResult)

    def test_result_tool_name_is_correct(self):
        mock_summary = self._make_mock_summary()
        mock_orchestrator = MagicMock()
        mock_orchestrator.run = AsyncMock(return_value=mock_summary)
        mock_orch_cls = MagicMock(return_value=mock_orchestrator)
        mock_config_cls = MagicMock(return_value=MagicMock())

        with (
            patch.dict(
                "sys.modules",
                {
                    "core.cloud_audit": MagicMock(CloudAuditOrchestrator=mock_orch_cls),
                    "core.config": MagicMock(CloudAuditConfig=mock_config_cls),
                },
            ),
        ):
            spec = build_cloud_audit_tool_spec()
            result = asyncio.run(
                spec.handler(_minimal_params())
            )

        assert result.tool_name == "apileak.cloud_audit"

    def test_result_has_untrusted_content_flag(self):
        """Results must be flagged as untrusted_content=True (Req 4.8)."""
        mock_summary = self._make_mock_summary()
        mock_orchestrator = MagicMock()
        mock_orchestrator.run = AsyncMock(return_value=mock_summary)
        mock_orch_cls = MagicMock(return_value=mock_orchestrator)
        mock_config_cls = MagicMock(return_value=MagicMock())

        with (
            patch.dict(
                "sys.modules",
                {
                    "core.cloud_audit": MagicMock(CloudAuditOrchestrator=mock_orch_cls),
                    "core.config": MagicMock(CloudAuditConfig=mock_config_cls),
                },
            ),
        ):
            spec = build_cloud_audit_tool_spec()
            result = asyncio.run(
                spec.handler(_minimal_params())
            )

        assert result.untrusted_content is True

    def test_result_metadata_contains_finding_count(self):
        mock_finding = MagicMock()
        mock_summary = self._make_mock_summary(findings=[mock_finding])
        mock_orchestrator = MagicMock()
        mock_orchestrator.run = AsyncMock(return_value=mock_summary)
        mock_orch_cls = MagicMock(return_value=mock_orchestrator)
        mock_config_cls = MagicMock(return_value=MagicMock())

        with (
            patch.dict(
                "sys.modules",
                {
                    "core.cloud_audit": MagicMock(CloudAuditOrchestrator=mock_orch_cls),
                    "core.config": MagicMock(CloudAuditConfig=mock_config_cls),
                },
            ),
        ):
            spec = build_cloud_audit_tool_spec()
            result = asyncio.run(
                spec.handler(_minimal_params())
            )

        assert result.metadata["finding_count"] == 1
        assert result.metadata["untrusted_content"] is True

    def test_handler_wraps_orchestrator_exception(self):
        """Runtime failures in the orchestrator must be wrapped in MCPToolError."""
        mock_orchestrator = MagicMock()
        mock_orchestrator.run = AsyncMock(side_effect=RuntimeError("SDK connection failed"))
        mock_orch_cls = MagicMock(return_value=mock_orchestrator)
        mock_config_cls = MagicMock(return_value=MagicMock())

        with (
            patch.dict(
                "sys.modules",
                {
                    "core.cloud_audit": MagicMock(CloudAuditOrchestrator=mock_orch_cls),
                    "core.config": MagicMock(CloudAuditConfig=mock_config_cls),
                },
            ),
        ):
            spec = build_cloud_audit_tool_spec()
            with pytest.raises(MCPToolError) as exc_info:
                asyncio.run(
                    spec.handler(_minimal_params())
                )

        assert exc_info.value.error_code == "CLOUD_AUDIT_ERROR"
