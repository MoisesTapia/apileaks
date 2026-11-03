"""
mcp_server — APILeak MCP Server package.

Exposes the core capabilities of APILeak (scan, OWASP modules, JWT attack
testing, discovery, cloud-audit) as MCP tools invocable by AI agents.

Install the optional extra to activate:
    pip install apileaks[mcp]

All public symbols are re-exported from this namespace for convenience.
"""

from mcp_server.schemas import (
    ConfirmationRequiredError,
    ConfirmationToken,
    MCPServerConfig,
    MCPToolError,
    MCPToolResult,
    MCPToolSpec,
)
from mcp_server.tool_registry import MCPToolRegistry

__all__ = [
    "ConfirmationToken",
    "ConfirmationRequiredError",
    "MCPServerConfig",
    "MCPToolError",
    "MCPToolResult",
    "MCPToolSpec",
    "MCPToolRegistry",
]
