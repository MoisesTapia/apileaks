"""
Checkpoint 4 — End-to-end verification of stdio server startup and tool invocation.

Verifies that:
1. ``APILeakMCPServer`` in stdio mode announces its full list of tools to the
   MCP client via ``list_tools``.
2. ``apileak.jwt.attack_test`` can be invoked through the complete SDK server
   path (``_build_mcp_sdk_server`` → ``call_tool`` handler → registry →
   ``_jwt_attack_test_handler``) and returns a well-formed structured result.

Strategy:
- All tests run **in-process** using ``_build_mcp_sdk_server()`` — no subprocess,
  no real network I/O.
- The ``JWTAttackEngine`` is patched to avoid real HTTP calls while still
  exercising every layer between the MCP client interface and the tool handler.
- Expected tool names are derived directly from the registry so the test stays
  accurate as new tools are added.

This file is the artifact for Task 4 of the ai-mcp-integration spec.
"""

from __future__ import annotations

import asyncio
import base64
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import mcp.types as mcp_types

from mcp_server.schemas import MCPServerConfig
from mcp_server.server import APILeakMCPServer


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

EXPECTED_ALWAYS_PRESENT_TOOLS = {
    "apileak.scan",
    "apileak.jwt.attack_test",
    "apileak.cloud_audit",
}


def _make_valid_jwt() -> str:
    """Return a syntactically-valid JWT for use in test parameters.

    The signature is deliberately fake; the attack engine is mocked so it
    never validates the token cryptographically.
    """

    def b64url(data: dict) -> str:
        return (
            base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()
        )

    header = b64url({"alg": "HS256", "typ": "JWT"})
    payload = b64url({"sub": "checkpoint-test", "iat": 1700000000})
    return f"{header}.{payload}.fakesig"


@pytest.fixture(scope="module")
def server() -> APILeakMCPServer:
    """Module-scoped server instance in stdio mode — built once, reused across tests."""
    config = MCPServerConfig(transport="stdio")
    return APILeakMCPServer(transport="stdio", config=config)


@pytest.fixture(scope="module")
def sdk_server(server: APILeakMCPServer):
    """Module-scoped SDK server built from the server fixture."""
    return server._build_mcp_sdk_server()


# ---------------------------------------------------------------------------
# Helper — call the list_tools handler synchronously
# ---------------------------------------------------------------------------


def _call_list_tools(sdk_server) -> list[mcp_types.Tool]:
    handler = sdk_server.request_handlers.get(mcp_types.ListToolsRequest)
    assert handler is not None, "list_tools handler must be registered on the SDK server"
    request = mcp_types.ListToolsRequest(method="tools/list", params=None)
    result = asyncio.new_event_loop().run_until_complete(handler(request))
    return result.root.tools


def _call_call_tool(sdk_server, tool_name: str, arguments: dict) -> dict:
    """Invoke a tool through the SDK call_tool handler and parse the JSON response.

    Returns a dict.  When the MCP SDK's own schema validation fires (before our
    handler), the response is a JSON-encoded string rather than a JSON object.
    In that case we wrap it in a synthetic ``{"error_code": "SCHEMA_VALIDATION_ERROR",
    "message": <text>}`` dict so callers can use a uniform interface.
    """
    handler = sdk_server.request_handlers.get(mcp_types.CallToolRequest)
    assert handler is not None, "call_tool handler must be registered"
    request = mcp_types.CallToolRequest(
        method="tools/call",
        params=mcp_types.CallToolRequestParams(name=tool_name, arguments=arguments),
    )
    result = asyncio.new_event_loop().run_until_complete(handler(request))
    content = result.root.content
    assert len(content) == 1, f"Expected exactly one content block, got {len(content)}"

    raw = content[0].text
    # Empty or whitespace-only text means the SDK returned nothing useful.
    if not raw or not raw.strip():
        return {"error_code": "SCHEMA_VALIDATION_ERROR", "message": "(empty response)"}

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        # The MCP SDK returned a plain-text validation error (not JSON).
        return {"error_code": "SCHEMA_VALIDATION_ERROR", "message": raw}

    # If the SDK returned a JSON string (its own validation message), wrap it.
    if isinstance(parsed, str):
        return {"error_code": "SCHEMA_VALIDATION_ERROR", "message": parsed}
    return parsed


# ---------------------------------------------------------------------------
# 1. list_tools — full tool roster verification
# ---------------------------------------------------------------------------


class TestListToolsEndToEnd:
    """Checkpoint: list_tools surfaces the full registered tool set."""

    def test_list_tools_returns_nonempty_list(self, sdk_server):
        """list_tools must return at least one tool."""
        tools = _call_list_tools(sdk_server)
        assert len(tools) > 0

    def test_scan_tool_present(self, sdk_server):
        """apileak.scan must be announced."""
        names = {t.name for t in _call_list_tools(sdk_server)}
        assert "apileak.scan" in names

    def test_jwt_attack_test_present(self, sdk_server):
        """apileak.jwt.attack_test must be announced."""
        names = {t.name for t in _call_list_tools(sdk_server)}
        assert "apileak.jwt.attack_test" in names

    def test_cloud_audit_present(self, sdk_server):
        """apileak.cloud_audit must be announced."""
        names = {t.name for t in _call_list_tools(sdk_server)}
        assert "apileak.cloud_audit" in names

    def test_owasp_tools_present(self, sdk_server, server):
        """At least one apileak.owasp.* tool must be announced."""
        names = {t.name for t in _call_list_tools(sdk_server)}
        owasp_names = {n for n in names if n.startswith("apileak.owasp.")}
        assert len(owasp_names) > 0, "No apileak.owasp.* tools found in list_tools"

    def test_discovery_tools_present(self, sdk_server):
        """At least one apileak.discovery.* tool must be announced."""
        names = {t.name for t in _call_list_tools(sdk_server)}
        discovery_names = {n for n in names if n.startswith("apileak.discovery.")}
        assert len(discovery_names) > 0, "No apileak.discovery.* tools found in list_tools"

    def test_all_tools_have_name_description_input_schema(self, sdk_server):
        """Every announced tool must have a non-empty name, description, and inputSchema."""
        for tool in _call_list_tools(sdk_server):
            assert tool.name, f"Tool has empty name"
            assert tool.description, f"Tool '{tool.name}' has empty description"
            assert isinstance(tool.inputSchema, dict), (
                f"Tool '{tool.name}' inputSchema must be a dict"
            )

    def test_all_tools_input_schema_type_object(self, sdk_server):
        """Every announced tool's inputSchema must declare type=object."""
        for tool in _call_list_tools(sdk_server):
            assert tool.inputSchema.get("type") == "object", (
                f"Tool '{tool.name}' inputSchema.type must be 'object'"
            )

    def test_registry_and_sdk_server_announce_same_tools(self, server, sdk_server):
        """The SDK server must not hide or add tools relative to the registry."""
        registry_names = {spec.name for spec in server.registry.list_tools()}
        sdk_names = {t.name for t in _call_list_tools(sdk_server)}
        assert sdk_names == registry_names, (
            f"SDK server / registry mismatch: "
            f"extra in SDK={sdk_names - registry_names}, "
            f"missing from SDK={registry_names - sdk_names}"
        )

    def test_no_duplicate_tool_names(self, sdk_server):
        """list_tools must not announce any tool name more than once."""
        names = [t.name for t in _call_list_tools(sdk_server)]
        assert len(names) == len(set(names)), f"Duplicate tool names: {names}"


# ---------------------------------------------------------------------------
# 2. apileak.jwt.attack_test — end-to-end invocation with mock data
# ---------------------------------------------------------------------------


class TestJwtAttackTestEndToEnd:
    """Checkpoint: full call path for apileak.jwt.attack_test returns structured output."""

    def _mock_attack_summary(self):
        """Build a minimal mock AttackSummary that satisfies the handler's contract."""
        summary = MagicMock()
        session = MagicMock()
        session.session_id = "ckpt-session-001"
        session.total_attacks = 10
        session.successful_attacks = 0
        session.success_rate = 0.0
        session.duration = 0.42
        summary.session = session
        return summary

    @patch("mcp_server.jwt_tools.JWTAttackEngine")
    @patch("mcp_server.jwt_tools.HTTPRequestEngine")
    @patch("mcp_server.jwt_tools.RateLimiter")
    @patch("mcp_server.jwt_tools.RetryConfig")
    def test_invocation_returns_tool_name(
        self, _MockRetry, _MockRateLimiter, MockHTTP, MockEngine, sdk_server
    ):
        """call_tool must surface tool_name='apileak.jwt.attack_test' in the result."""
        mock_http = AsyncMock()
        MockHTTP.return_value = mock_http

        mock_engine = MagicMock()
        mock_engine.execute_all = AsyncMock(return_value=self._mock_attack_summary())
        mock_engine.to_findings = MagicMock(return_value=[])
        MockEngine.return_value = mock_engine

        payload = _call_call_tool(
            sdk_server,
            "apileak.jwt.attack_test",
            {"token": _make_valid_jwt(), "url": "https://api.example.com/protected"},
        )

        assert payload.get("tool_name") == "apileak.jwt.attack_test"

    @patch("mcp_server.jwt_tools.JWTAttackEngine")
    @patch("mcp_server.jwt_tools.HTTPRequestEngine")
    @patch("mcp_server.jwt_tools.RateLimiter")
    @patch("mcp_server.jwt_tools.RetryConfig")
    def test_invocation_returns_finding_count(
        self, _MockRetry, _MockRateLimiter, MockHTTP, MockEngine, sdk_server
    ):
        """call_tool result must include a numeric finding_count field."""
        mock_http = AsyncMock()
        MockHTTP.return_value = mock_http

        mock_engine = MagicMock()
        mock_engine.execute_all = AsyncMock(return_value=self._mock_attack_summary())
        mock_engine.to_findings = MagicMock(return_value=[])
        MockEngine.return_value = mock_engine

        payload = _call_call_tool(
            sdk_server,
            "apileak.jwt.attack_test",
            {"token": _make_valid_jwt(), "url": "https://api.example.com/protected"},
        )

        assert "finding_count" in payload
        assert isinstance(payload["finding_count"], int)

    @patch("mcp_server.jwt_tools.JWTAttackEngine")
    @patch("mcp_server.jwt_tools.HTTPRequestEngine")
    @patch("mcp_server.jwt_tools.RateLimiter")
    @patch("mcp_server.jwt_tools.RetryConfig")
    def test_invocation_marks_untrusted_content(
        self, _MockRetry, _MockRateLimiter, MockHTTP, MockEngine, sdk_server
    ):
        """Results that include target data must be flagged untrusted_content=True (Req 4.8)."""
        mock_http = AsyncMock()
        MockHTTP.return_value = mock_http

        mock_engine = MagicMock()
        mock_engine.execute_all = AsyncMock(return_value=self._mock_attack_summary())
        mock_engine.to_findings = MagicMock(return_value=[])
        MockEngine.return_value = mock_engine

        payload = _call_call_tool(
            sdk_server,
            "apileak.jwt.attack_test",
            {"token": _make_valid_jwt(), "url": "https://api.example.com/protected"},
        )

        assert payload.get("untrusted_content") is True

    @patch("mcp_server.jwt_tools.JWTAttackEngine")
    @patch("mcp_server.jwt_tools.HTTPRequestEngine")
    @patch("mcp_server.jwt_tools.RateLimiter")
    @patch("mcp_server.jwt_tools.RetryConfig")
    def test_invocation_includes_metadata(
        self, _MockRetry, _MockRateLimiter, MockHTTP, MockEngine, sdk_server
    ):
        """call_tool result must carry a metadata dict (session stats, target)."""
        mock_http = AsyncMock()
        MockHTTP.return_value = mock_http

        mock_engine = MagicMock()
        mock_engine.execute_all = AsyncMock(return_value=self._mock_attack_summary())
        mock_engine.to_findings = MagicMock(return_value=[])
        MockEngine.return_value = mock_engine

        target = "https://api.example.com/protected"
        payload = _call_call_tool(
            sdk_server,
            "apileak.jwt.attack_test",
            {"token": _make_valid_jwt(), "url": target},
        )

        assert isinstance(payload.get("metadata"), dict)
        assert payload["metadata"].get("target") == target

    def test_invocation_with_missing_token_returns_error(self, sdk_server):
        """Omitting the required 'token' field must return a schema validation error."""
        payload = _call_call_tool(
            sdk_server,
            "apileak.jwt.attack_test",
            {"url": "https://api.example.com/protected"},
        )

        assert "error_code" in payload
        assert payload["error_code"] in {
            "SCHEMA_VALIDATION_ERROR",
            "CONFIRMATION_REQUIRED",
        }

    def test_invocation_with_missing_url_returns_error(self, sdk_server):
        """Omitting the required 'url' field must return a schema validation error."""
        payload = _call_call_tool(
            sdk_server,
            "apileak.jwt.attack_test",
            {"token": _make_valid_jwt()},
        )

        assert "error_code" in payload
        assert payload["error_code"] in {
            "SCHEMA_VALIDATION_ERROR",
            "CONFIRMATION_REQUIRED",
        }

    def test_unknown_tool_returns_structured_error(self, sdk_server):
        """Calling a tool that does not exist must return a TOOL_NOT_FOUND error, not a crash."""
        payload = _call_call_tool(sdk_server, "apileak.nonexistent.tool", {})

        assert payload.get("error_code") == "TOOL_NOT_FOUND"
        assert "message" in payload


# ---------------------------------------------------------------------------
# 3. Server-level wiring (manifest hash stored on the server object)
# ---------------------------------------------------------------------------


class TestServerStartupWiring:
    """Checkpoint: basic server object attributes are populated after construction."""

    def test_registry_is_populated(self, server):
        """The server registry must contain tools after construction."""
        assert len(server.registry.list_tools()) > 0

    def test_tool_manifest_hash_is_stored(self, server):
        """After construction, _tool_manifest_hash must be a non-empty SHA-256 hex string."""
        manifest_hash = getattr(server, "_tool_manifest_hash", None)
        assert manifest_hash is not None, "_tool_manifest_hash not set on server"
        assert len(manifest_hash) == 64, "SHA-256 hex digest must be 64 characters"
        assert all(c in "0123456789abcdef" for c in manifest_hash), (
            "_tool_manifest_hash must be a lowercase hex string"
        )

    def test_manifest_hash_matches_registry(self, server):
        """The stored manifest hash must equal the registry's computed manifest hash."""
        assert server._tool_manifest_hash == server.registry.manifest_hash()

    def test_transport_attribute(self, server):
        """server.transport must equal 'stdio'."""
        assert server.transport == "stdio"
