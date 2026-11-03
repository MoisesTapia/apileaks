"""
Tests for the stdio transport of APILeakMCPServer (Task 3.1).

Verifies Requirement 2.1: when started with ``transport="stdio"``, the server
communicates exclusively over stdin/stdout using the MCP protocol and correctly
responds to ``list_tools`` requests.

Strategy:
- We do NOT spin up a subprocess.  Instead we test the _build_mcp_sdk_server()
  helper directly in-process.  This lets us drive the SDK Server's handlers
  without a real transport, keeping the test fast and deterministic
  (consistent with the project's in-process MCP client testing strategy from
  Requirement 11.1).
- We also verify the CLI ``mcp-server`` command is correctly wired up by
  importing it and checking its Click metadata.

Validates: Requirement 2.1
"""

from __future__ import annotations

import asyncio
import json

import pytest

from mcp_server.schemas import MCPServerConfig
from mcp_server.server import APILeakMCPServer


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def server() -> APILeakMCPServer:
    """A server instance configured for stdio transport."""
    config = MCPServerConfig(transport="stdio")
    return APILeakMCPServer(transport="stdio", config=config)


# ---------------------------------------------------------------------------
# Tests for _build_mcp_sdk_server() / list_tools handler
# ---------------------------------------------------------------------------


def test_build_mcp_sdk_server_returns_sdk_server(server: APILeakMCPServer) -> None:
    """_build_mcp_sdk_server() returns an MCP SDK Server instance."""
    from mcp.server import Server as MCPSDKServer

    sdk_server = server._build_mcp_sdk_server()
    assert isinstance(sdk_server, MCPSDKServer)


def test_list_tools_returns_all_registered_tools(server: APILeakMCPServer) -> None:
    """The list_tools handler exposes every tool from the registry."""
    sdk_server = server._build_mcp_sdk_server()
    expected_names = {spec.name for spec in server.registry.list_tools()}

    # The list_tools handler is registered under request_handlers; we call the
    # underlying decorated function directly.
    import mcp.types as mcp_types

    handler = sdk_server.request_handlers.get(mcp_types.ListToolsRequest)
    assert handler is not None, "list_tools handler must be registered on the SDK server"

    # Build a minimal ListToolsRequest to satisfy the handler signature.
    request = mcp_types.ListToolsRequest(method="tools/list", params=None)
    server_result = asyncio.run(handler(request))

    returned_names = {tool.name for tool in server_result.root.tools}
    assert returned_names == expected_names, (
        f"list_tools mismatch: registry has {expected_names - returned_names} extra tools "
        f"not surfaced to the MCP client."
    )


def test_list_tools_each_has_name_description_and_input_schema(
    server: APILeakMCPServer,
) -> None:
    """Every MCP tool descriptor has name, description, and inputSchema populated."""
    sdk_server = server._build_mcp_sdk_server()
    import mcp.types as mcp_types

    request = mcp_types.ListToolsRequest(method="tools/list", params=None)
    handler = sdk_server.request_handlers[mcp_types.ListToolsRequest]
    server_result = asyncio.run(handler(request))

    for tool in server_result.root.tools:
        assert tool.name, f"Tool must have a non-empty name"
        assert tool.description, f"Tool '{tool.name}' must have a description"
        assert isinstance(tool.inputSchema, dict), (
            f"Tool '{tool.name}' inputSchema must be a dict"
        )


def test_call_tool_unknown_tool_returns_error_payload(server: APILeakMCPServer) -> None:
    """Calling an unknown tool returns a structured JSON error block (not a crash)."""
    sdk_server = server._build_mcp_sdk_server()
    import mcp.types as mcp_types

    handler = sdk_server.request_handlers.get(mcp_types.CallToolRequest)
    assert handler is not None, "call_tool handler must be registered on the SDK server"

    request = mcp_types.CallToolRequest(
        method="tools/call",
        params=mcp_types.CallToolRequestParams(name="apileak.nonexistent", arguments={}),
    )
    result = asyncio.run(handler(request))
    content = result.root.content
    assert len(content) == 1
    payload = json.loads(content[0].text)
    assert payload["error_code"] == "TOOL_NOT_FOUND"


def test_call_tool_schema_validation_error_returns_error_payload(
    server: APILeakMCPServer,
) -> None:
    """Invoking a tool with invalid params returns an error (validation surfaced)."""
    sdk_server = server._build_mcp_sdk_server()
    import mcp.types as mcp_types

    # Pick the first registered tool and pass no arguments (required fields missing).
    first_spec = server.registry.list_tools()[0]
    handler = sdk_server.request_handlers[mcp_types.CallToolRequest]
    request = mcp_types.CallToolRequest(
        method="tools/call",
        params=mcp_types.CallToolRequestParams(name=first_spec.name, arguments={}),
    )
    result = asyncio.run(handler(request))
    content = result.root.content
    assert len(content) == 1, "Expected exactly one content block in the error response"
    text = content[0].text

    # The SDK may return a plain-text validation error (when validate_input=True fires
    # before our handler) OR our handler wraps it as JSON — both are acceptable.
    # What matters is that an error is surfaced, not a successful result.
    assert text, "Error response must contain a non-empty text block"
    # If the response IS JSON, check that it contains a recognised error code.
    try:
        payload = json.loads(text)
        assert payload["error_code"] in {
            "SCHEMA_VALIDATION_ERROR",
            "CONFIRMATION_REQUIRED",
            "TOOL_NOT_FOUND",
        }, f"Unexpected JSON error_code: {payload['error_code']}"
    except json.JSONDecodeError:
        # Plain-text error from SDK-level validation is also acceptable.
        assert "error" in text.lower() or "required" in text.lower() or "invalid" in text.lower(), (
            f"Plain-text error response does not look like a validation message: {text!r}"
        )


# ---------------------------------------------------------------------------
# CLI command registration test
# ---------------------------------------------------------------------------


def test_mcp_server_command_registered_in_cli() -> None:
    """The ``mcp-server`` Click command is registered on the root ``cli`` group."""
    from click.testing import CliRunner

    # Import the root CLI group from the entry-point module.
    import importlib.util
    import sys
    from pathlib import Path

    workspace = Path(__file__).resolve().parents[2]  # project root
    spec = importlib.util.spec_from_file_location("apileaks_main", workspace / "apileaks.py")
    apileaks_module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(apileaks_module)  # type: ignore[union-attr]

    runner = CliRunner()
    result = runner.invoke(apileaks_module.cli, ["mcp-server", "--help"])
    assert result.exit_code == 0, f"mcp-server --help failed:\n{result.output}"
    assert "--transport" in result.output


def test_mcp_server_command_transport_option_defaults_to_stdio() -> None:
    """``mcp-server`` defaults to stdio transport."""
    from cli.commands.mcp_cmds import mcp_server_cmd
    from click.testing import CliRunner

    runner = CliRunner()
    # Only check --help, not actual execution (which would block on stdin).
    result = runner.invoke(mcp_server_cmd, ["--help"])
    assert result.exit_code == 0
    assert "stdio" in result.output
