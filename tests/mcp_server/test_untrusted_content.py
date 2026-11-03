"""
Tests for the ``untrusted_content: true`` metadata mark on MCP responses
containing raw target data (Task 6.8).

Verifies:
- Every scan/OWASP/JWT/discovery/cloud_audit handler sets
  ``MCPToolResult.untrusted_content = True`` when returning raw target data
  (Requirement 4.8 / OWASP MCP06).
- The ``untrusted_content`` flag propagates into the serialised JSON response
  produced by ``APILeakMCPServer._build_mcp_sdk_server()`` (server-level
  serialisation contract).
- ``MCPToolResult`` defaults to ``untrusted_content=False`` for tools that do
  not embed raw target data (regression guard).

All tests use in-process mocks — no real network calls, no MCP transport.

Validates: Requirements 4.8
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import mcp.types as mcp_types

from mcp_server.schemas import MCPServerConfig, MCPToolResult, MCPToolSpec
from mcp_server.server import APILeakMCPServer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_core_no_findings():
    """Return a MagicMock that mimics APILeakCore with zero findings."""
    mock_collector = MagicMock()
    mock_collector.get_findings.return_value = []
    mock_collector.get_statistics.return_value = {}

    mock_core = MagicMock()
    mock_core.health_check = AsyncMock(return_value={"status": "healthy"})
    mock_core.run_scan = AsyncMock(return_value=None)
    mock_core.get_findings_collector.return_value = mock_collector
    return mock_core


def _run(coro):
    """Run a coroutine synchronously on a fresh event loop."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _call_call_tool_via_sdk(sdk_server, tool_name: str, arguments: dict) -> dict:
    """Invoke a tool through the SDK server's registered call_tool handler.

    Returns the parsed JSON response dict.
    """
    handler = sdk_server.request_handlers.get(mcp_types.CallToolRequest)
    assert handler is not None, "call_tool handler must be registered on the SDK server"
    request = mcp_types.CallToolRequest(
        method="tools/call",
        params=mcp_types.CallToolRequestParams(name=tool_name, arguments=arguments),
    )
    result = asyncio.new_event_loop().run_until_complete(handler(request))
    content = result.root.content
    assert len(content) == 1
    return json.loads(content[0].text)


# ---------------------------------------------------------------------------
# MCPToolResult default (regression guard)
# ---------------------------------------------------------------------------


class TestMCPToolResultDefault:
    """``untrusted_content`` defaults to False for tools that return no raw data."""

    def test_default_is_false(self):
        result = MCPToolResult(tool_name="apileak.test", findings=[], metadata={})
        assert result.untrusted_content is False

    def test_explicit_false(self):
        result = MCPToolResult(
            tool_name="apileak.test",
            findings=[],
            metadata={},
            untrusted_content=False,
        )
        assert result.untrusted_content is False

    def test_explicit_true(self):
        result = MCPToolResult(
            tool_name="apileak.test",
            findings=[],
            metadata={},
            untrusted_content=True,
        )
        assert result.untrusted_content is True


# ---------------------------------------------------------------------------
# Scan handler
# ---------------------------------------------------------------------------


class TestScanHandlerUntrustedContent:
    """``apileak.scan`` handler must set ``untrusted_content=True``."""

    @pytest.mark.asyncio
    async def test_scan_handler_sets_untrusted_content(self):
        from mcp_server.scan_handler import _scan_handler

        mock_core = _make_mock_core_no_findings()
        with patch("mcp_server.scan_handler.APILeakCore", return_value=mock_core):
            result = await _scan_handler({"target": "https://example.com/api"})

        assert isinstance(result, MCPToolResult)
        assert result.untrusted_content is True, (
            "scan handler must mark results untrusted_content=True "
            "(Requirement 4.8 / OWASP MCP06)"
        )

    @pytest.mark.asyncio
    async def test_scan_handler_untrusted_content_even_with_findings(self):
        from mcp_server.scan_handler import _scan_handler

        mock_finding = MagicMock()
        mock_finding.id = "f-001"
        mock_finding.scan_id = "scan-001"
        mock_finding.category = "BOLA"
        mock_finding.severity = MagicMock(value="high")
        mock_finding.timestamp = MagicMock(isoformat=lambda: "2024-01-01T00:00:00")

        mock_collector = MagicMock()
        mock_collector.get_findings.return_value = [mock_finding]
        mock_collector.get_statistics.return_value = {"total": 1}

        mock_core = MagicMock()
        mock_core.health_check = AsyncMock(return_value={"status": "healthy"})
        mock_core.run_scan = AsyncMock(return_value=None)
        mock_core.get_findings_collector.return_value = mock_collector

        with patch("mcp_server.scan_handler.APILeakCore", return_value=mock_core):
            result = await _scan_handler({"target": "https://example.com/api"})

        assert result.untrusted_content is True


# ---------------------------------------------------------------------------
# OWASP handlers
# ---------------------------------------------------------------------------


class TestOwaspHandlersUntrustedContent:
    """All ``apileak.owasp.*`` handlers must set ``untrusted_content=True``."""

    @pytest.mark.asyncio
    async def test_first_owasp_module_sets_untrusted_content(self):
        """Spot-check at least one OWASP module handler."""
        from cli.owasp_descriptors import iter_descriptors
        from mcp_server.owasp_tools import _make_owasp_handler

        # Pick the first available descriptor — independent of module ordering.
        descriptors = list(iter_descriptors())
        assert descriptors, "No OWASP descriptors found"
        descriptor = descriptors[0]

        handler = _make_owasp_handler(descriptor)

        mock_core = _make_mock_core_no_findings()
        with patch("mcp_server.owasp_tools.APILeakCore", return_value=mock_core):
            result = await handler({"target": "https://example.com/api"})

        assert isinstance(result, MCPToolResult)
        assert result.untrusted_content is True, (
            f"OWASP handler for '{descriptor.key}' must set untrusted_content=True"
        )

    def test_all_owasp_tool_specs_have_untrusted_content_true_by_inspection(self):
        """Verify every OWASP handler returns untrusted_content=True by running them all.

        Uses a shared mock to avoid repeated boilerplate.
        This parametric style covers every registered OWASP module.
        """
        from cli.owasp_descriptors import iter_descriptors
        from mcp_server.owasp_tools import _make_owasp_handler

        mock_core = _make_mock_core_no_findings()
        for descriptor in iter_descriptors():
            handler = _make_owasp_handler(descriptor)
            with patch("mcp_server.owasp_tools.APILeakCore", return_value=mock_core):
                result = _run(handler({"target": "https://example.com/api"}))
            assert result.untrusted_content is True, (
                f"OWASP handler for '{descriptor.key}' must set untrusted_content=True "
                "(Requirement 4.8)"
            )


# ---------------------------------------------------------------------------
# JWT handler
# ---------------------------------------------------------------------------


class TestJWTHandlerUntrustedContent:
    """``apileak.jwt.attack_test`` handler must set ``untrusted_content=True``."""

    @pytest.mark.asyncio
    async def test_jwt_handler_sets_untrusted_content(self):
        import base64

        from mcp_server.jwt_tools import _jwt_attack_test_handler

        def b64url(data):
            return (
                base64.urlsafe_b64encode(json.dumps(data).encode())
                .rstrip(b"=")
                .decode()
            )

        header = b64url({"alg": "HS256", "typ": "JWT"})
        payload = b64url({"sub": "test", "iat": 1700000000})
        fake_jwt = f"{header}.{payload}.fakesig"

        # Build a mock session and attack summary matching what the handler expects.
        mock_session = MagicMock()
        mock_session.session_id = "mock-session"
        mock_session.total_attacks = 5
        mock_session.successful_attacks = 0
        mock_session.success_rate = 0.0
        mock_session.duration = 0.1

        mock_summary = MagicMock()
        mock_summary.session = mock_session

        mock_engine = MagicMock()
        mock_engine.execute_all = AsyncMock(return_value=mock_summary)
        mock_engine.to_findings = MagicMock(return_value=[])

        mock_http_engine = MagicMock()
        mock_http_engine.close = AsyncMock(return_value=None)

        with (
            patch(
                "mcp_server.jwt_tools.JWTAttackEngine",
                return_value=mock_engine,
            ),
            patch(
                "mcp_server.jwt_tools.HTTPRequestEngine",
                return_value=mock_http_engine,
            ),
        ):
            result = await _jwt_attack_test_handler(
                {
                    "token": fake_jwt,
                    "url": "https://example.com/api",
                }
            )

        assert isinstance(result, MCPToolResult)
        assert result.untrusted_content is True, (
            "JWT attack test handler must set untrusted_content=True "
            "(Requirement 4.8 / OWASP MCP06)"
        )


# ---------------------------------------------------------------------------
# Discovery handlers
# ---------------------------------------------------------------------------


class TestDiscoveryHandlersUntrustedContent:
    """``apileak.discovery.*`` handlers must set ``untrusted_content=True``."""

    @pytest.mark.asyncio
    async def test_dir_handler_sets_untrusted_content(self):
        from mcp_server.discovery_tools import _dir_handler

        mock_core = _make_mock_core_no_findings()
        # _dir_handler also calls get_discovered_endpoints
        mock_core.get_discovered_endpoints = MagicMock(return_value=[])

        with patch("mcp_server.discovery_tools.APILeakCore", return_value=mock_core):
            result = await _dir_handler({"target": "https://example.com/api"})

        assert isinstance(result, MCPToolResult)
        assert result.untrusted_content is True, (
            "discovery.dir handler must set untrusted_content=True "
            "(Requirement 4.8 / OWASP MCP06)"
        )

    @pytest.mark.asyncio
    async def test_par_handler_sets_untrusted_content(self):
        from mcp_server.discovery_tools import _par_handler

        mock_core = _make_mock_core_no_findings()

        with patch("mcp_server.discovery_tools.APILeakCore", return_value=mock_core):
            result = await _par_handler({"target": "https://example.com/api"})

        assert isinstance(result, MCPToolResult)
        assert result.untrusted_content is True, (
            "discovery.par handler must set untrusted_content=True "
            "(Requirement 4.8 / OWASP MCP06)"
        )


# ---------------------------------------------------------------------------
# Cloud audit handler
# ---------------------------------------------------------------------------


class TestCloudAuditHandlerUntrustedContent:
    """``apileak.cloud_audit`` handler must set ``untrusted_content=True``."""

    @pytest.mark.asyncio
    async def test_cloud_audit_handler_sets_untrusted_content(self):
        from mcp_server.cloud_audit_tool import _cloud_audit_handler

        mock_summary = MagicMock()
        mock_summary.findings = []
        mock_summary.auditors_succeeded = []
        mock_summary.auditors_failed = []
        mock_summary.auditors_skipped_no_credentials = []

        mock_orchestrator = MagicMock()
        mock_orchestrator.run = AsyncMock(return_value=mock_summary)

        mock_config_instance = MagicMock()
        mock_config_instance.allow_destructive = False

        # The handler uses local imports (`from core.cloud_audit import …`),
        # so we patch the attributes on those source modules directly.
        with (
            patch(
                "core.cloud_audit.CloudAuditOrchestrator",
                return_value=mock_orchestrator,
            ),
            patch(
                "core.config.CloudAuditConfig",
                return_value=mock_config_instance,
            ),
        ):
            result = await _cloud_audit_handler(
                {"target": "https://example.com", "provider": "aws"}
            )

        assert isinstance(result, MCPToolResult)
        assert result.untrusted_content is True, (
            "cloud_audit handler must set untrusted_content=True "
            "(Requirement 4.8 / OWASP MCP06)"
        )


# ---------------------------------------------------------------------------
# Server serialisation: untrusted_content in JSON response
# ---------------------------------------------------------------------------


class TestServerSerialisationUntrustedContent:
    """``untrusted_content`` must appear in the JSON output produced by the server."""

    def _build_sdk_server_with_stub(self, untrusted: bool):
        """Build an SDK server that has a single stub tool returning *untrusted*."""
        from mcp_server.tool_registry import MCPToolRegistry

        async def stub_handler(params):  # noqa: ARG001
            return MCPToolResult(
                tool_name="apileak.stub",
                findings=[],
                metadata={"stub": True},
                untrusted_content=untrusted,
            )

        stub_spec = MCPToolSpec(
            name="apileak.stub",
            description="Stub tool for serialisation tests.",
            input_schema={
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False,
            },
            output_schema={"type": "object"},
            is_destructive=False,
            handler=stub_handler,
        )

        config = MCPServerConfig(transport="stdio")
        server = APILeakMCPServer(transport="stdio", config=config)
        # Replace registry with one containing only the stub spec.
        server.registry = MCPToolRegistry()
        server.registry.register(stub_spec)
        return server._build_mcp_sdk_server()

    def test_untrusted_true_propagates_to_json_response(self):
        sdk_server = self._build_sdk_server_with_stub(untrusted=True)
        response = _call_call_tool_via_sdk(sdk_server, "apileak.stub", {})
        assert "untrusted_content" in response, (
            "untrusted_content key must appear in the serialised MCP response"
        )
        assert response["untrusted_content"] is True, (
            "untrusted_content must be True when the handler sets it to True"
        )

    def test_untrusted_false_propagates_to_json_response(self):
        sdk_server = self._build_sdk_server_with_stub(untrusted=False)
        response = _call_call_tool_via_sdk(sdk_server, "apileak.stub", {})
        assert "untrusted_content" in response, (
            "untrusted_content key must appear in the serialised MCP response "
            "even when False"
        )
        assert response["untrusted_content"] is False

    def test_scan_tool_response_includes_untrusted_content_true(self):
        """End-to-end: scan tool response through the full SDK server path."""
        config = MCPServerConfig(transport="stdio")
        server = APILeakMCPServer(transport="stdio", config=config)
        sdk_server = server._build_mcp_sdk_server()

        mock_core = _make_mock_core_no_findings()
        with patch("mcp_server.scan_handler.APILeakCore", return_value=mock_core):
            response = _call_call_tool_via_sdk(
                sdk_server,
                "apileak.scan",
                {"target": "https://example.com/api"},
            )

        # Either the tool succeeded (contains untrusted_content) or returned an error.
        # On success, untrusted_content must be True.
        if "error_code" not in response:
            assert response.get("untrusted_content") is True, (
                "apileak.scan response must include untrusted_content=true "
                "(Requirement 4.8)"
            )
