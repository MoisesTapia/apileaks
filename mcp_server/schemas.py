"""
mcp_server.schemas — Core data models and exceptions for the APILeak MCP Server.

Defines the canonical types shared across tool_registry, server, and
confirmation_gate:

- :class:`MCPToolSpec` — specification for a single MCP tool.
- :class:`MCPToolResult` — structured result returned by an invoked tool.
- :class:`MCPServerConfig` — startup configuration for :class:`APILeakMCPServer`.
- :class:`ConfirmationToken` — proof of explicit human confirmation for a
  destructive operation.
- :class:`MCPToolError` — structured error returned to the MCP client
  (Requirement 1.5).
- :class:`ConfirmationRequiredError` — subclass raised when a destructive tool
  is invoked without a valid :class:`ConfirmationToken` (Requirements 4.1, 4.2).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class MCPToolError(Exception):
    """Structured error returned to the MCP client (Requirement 1.5).

    Carries a machine-readable ``error_code`` alongside the human-readable
    message so clients can branch on the error type without string-parsing.
    Internal tracebacks are *never* forwarded to the client.
    """

    def __init__(self, message: str, error_code: str = "TOOL_ERROR") -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message

    def __repr__(self) -> str:  # pragma: no cover
        return f"{type(self).__name__}(error_code={self.error_code!r}, message={self.message!r})"


class SchemaValidationError(MCPToolError):
    """Input parameters do not satisfy the tool's JSON Schema (Requirement 1.3).

    Raised by :meth:`MCPToolRegistry.invoke` *before* calling the handler,
    so the handler is guaranteed never to execute with invalid parameters
    (Property 5).
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, error_code="SCHEMA_VALIDATION_ERROR")


class ConfirmationRequiredError(MCPToolError):
    """A destructive tool was invoked without a valid :class:`ConfirmationToken`.

    Raised by :class:`DestructiveConfirmationGate` before any part of the
    underlying operation is executed (Requirements 4.1, 4.2).
    """

    def __init__(self, tool_name: str) -> None:
        super().__init__(
            f"Tool '{tool_name}' requires explicit human confirmation before "
            "execution.  Provide a ConfirmationToken with the invocation.",
            error_code="CONFIRMATION_REQUIRED",
        )
        self.tool_name = tool_name


class ToolNotFoundError(MCPToolError):
    """The requested tool name is not registered in the registry."""

    def __init__(self, tool_name: str) -> None:
        super().__init__(
            f"No tool named '{tool_name}' is registered.",
            error_code="TOOL_NOT_FOUND",
        )
        self.tool_name = tool_name


# ---------------------------------------------------------------------------
# Core data models
# ---------------------------------------------------------------------------


@dataclass
class MCPToolResult:
    """Structured result returned after a successful tool invocation.

    Requirement 1.4 mandates that the output is structured (not raw text) and
    uses the same :class:`~utils.findings.Finding` format as the rest of
    APILeak when the tool produces security findings.
    """

    tool_name: str
    findings: list[Any] = field(default_factory=list)
    """Security findings in the standard APILeak Finding format."""

    metadata: dict[str, Any] = field(default_factory=dict)
    """Arbitrary key/value context produced by the tool (phase info, stats, …)."""

    raw_output: str | None = None
    """Optional human-readable summary for display in the AI client."""

    untrusted_content: bool = False
    """
    When True, the result includes data obtained verbatim from the scan target
    (response bodies, headers, etc.) and the MCP client SHOULD apply its own
    defences against prompt-injection on that data (Requirement 4.8 / OWASP MCP06).
    """


@dataclass
class MCPToolSpec:
    """Specification of a single MCP tool exposed by :class:`APILeakMCPServer`.

    Each spec maps 1-to-1 to an existing APILeak CLI command / OWASP module.
    The ``input_schema`` and ``output_schema`` are plain JSON Schema dicts
    (draft-07 compatible) used both for MCP protocol advertisement and for
    runtime parameter validation before the handler is called.
    """

    name: str
    """Dotted tool identifier, e.g. ``apileak.owasp.bola_testing``."""

    description: str
    """Human-readable explanation of what the tool does (shown to AI clients)."""

    input_schema: dict[str, Any]
    """JSON Schema for the tool's input parameters (Requirement 1.3)."""

    output_schema: dict[str, Any]
    """JSON Schema for the tool's output (informational; not validated at runtime)."""

    is_destructive: bool
    """
    If True, the tool performs state-changing operations and MUST be guarded by
    :class:`DestructiveConfirmationGate` (Requirements 4.1, 4.2).
    """

    handler: Callable[..., Awaitable[MCPToolResult]]
    """Async callable that implements the tool logic."""

    max_execution_seconds: float = 300.0
    """
    Maximum wall-clock time allowed for a single invocation of this tool.
    The server cancels the handler and returns a structured timeout error if
    this limit is exceeded (Requirement 15.1 / OWASP MCP05).
    """


@dataclass
class MCPServerConfig:
    """Runtime configuration for :class:`APILeakMCPServer`."""

    transport: str
    """Transport type: ``"stdio"`` or ``"http"``."""

    port: int | None = None
    """TCP port for HTTP transport (ignored for stdio)."""

    auth_token: str | None = None
    """Bearer token required by HTTP clients (Requirement 2.3)."""

    allow_destructive: bool = False
    """
    Process-level opt-in for destructive tool execution.  Even when True,
    individual invocations still require a :class:`ConfirmationToken`
    (Requirement 4.1).
    """

    tls_cert: str | None = None
    """Path to the TLS certificate file (Requirement 2.5)."""

    tls_key: str | None = None
    """Path to the TLS private-key file (Requirement 2.5)."""

    rate_limit_per_minute: int = 60
    """Maximum tool invocations per client per minute (Requirement 15.2)."""

    allowed_tools: list[str] | None = None
    """
    Optional allowlist of tool names that may be invoked. When None all
    registered tools are accessible (OWASP MCP02).
    """

    audit_log_path: str | None = None
    """
    Path for the append-only JSON-Lines audit log.  Defaults to
    ``apileaks-mcp-audit.jsonl`` in the current working directory if not set.
    """


@dataclass
class ConfirmationToken:
    """Proof of explicit human confirmation for a single destructive invocation.

    Created by the *human operator* or confirmation UI and supplied alongside
    the tool invocation parameters.  The server verifies the token is present
    and matches the tool being invoked (Requirements 4.1, 4.2).
    """

    tool_name: str
    """The exact name of the tool this token authorises."""

    confirmed_by: str
    """Identifier of the human/operator who granted confirmation."""

    timestamp: datetime = field(default_factory=datetime.utcnow)
    """UTC timestamp when the confirmation was granted."""
