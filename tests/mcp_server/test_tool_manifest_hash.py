"""
Tests for tool manifest SHA-256 hashing — Task 6.7.

Verifies Requirements 4.7 and 12.4:

- 4.7  WHEN the MCP_Server starts, the system SHALL compute and log a SHA-256
       hash of the registered tools manifest so any alteration of the tool
       registry is detectable (OWASP MCP03).
- 12.4 WHEN the server starts, the system SHALL record the SHA-256 hash of the
       active tools manifest in the audit log so log entries can be correlated
       with the exact version of the tool registry that was active.

The tests cover:

1. ``manifest_hash()`` returns a valid 64-character lowercase hex string.
2. Adding a new tool changes the hash (sensitivity to additions).
3. Removing a tool changes the hash (sensitivity to removals).
4. Renaming a tool changes the hash (sensitivity to renames).
5. Changing a tool's ``input_schema`` changes the hash (schema sensitivity).
6. Changing a tool's ``description`` changes the hash (description sensitivity).
7. The hash is deterministic — identical registries always produce the same value.
8. The hash is present in the ``mcp_server_starting`` INFO log entry produced
   by ``APILeakMCPServer.__init__``.
9. The startup log entry is emitted at INFO level (not DEBUG).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any
from unittest.mock import patch

import pytest

pytest.importorskip("mcp")

from mcp_server.schemas import MCPServerConfig, MCPToolResult, MCPToolSpec  # noqa: E402
from mcp_server.tool_registry import MCPToolRegistry  # noqa: E402
import mcp_server.server as server_module  # noqa: E402
from mcp_server.server import APILeakMCPServer  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _noop_handler(params: dict[str, Any]) -> MCPToolResult:  # pragma: no cover
    return MCPToolResult(tool_name="noop", findings=[])


def _make_spec(
    name: str = "tool.alpha",
    description: str = "A test tool",
    input_schema: dict[str, Any] | None = None,
) -> MCPToolSpec:
    return MCPToolSpec(
        name=name,
        description=description,
        input_schema=input_schema or {"type": "object", "properties": {}},
        output_schema={},
        is_destructive=False,
        handler=_noop_handler,
    )


def _startup_log_kwargs(recorded: list[tuple]) -> dict | None:
    """Extract kwargs from the ``mcp_server_starting`` INFO log call."""
    for args, kwargs in recorded:
        if args and args[0] == "mcp_server_starting":
            return kwargs
    return None


def _make_server_and_capture() -> tuple[APILeakMCPServer, list[tuple]]:
    config = MCPServerConfig(transport="stdio", allow_destructive=False)
    recorded: list[tuple] = []

    with patch.object(server_module.logger, "info", side_effect=lambda *a, **kw: recorded.append((a, kw))):
        server = APILeakMCPServer(transport="stdio", config=config)

    return server, recorded


# ---------------------------------------------------------------------------
# 1. manifest_hash() returns a valid 64-char hex string
# ---------------------------------------------------------------------------


def test_manifest_hash_is_64_char_hex() -> None:
    """manifest_hash() must return a lowercase 64-character hex string (SHA-256)."""
    registry = MCPToolRegistry()
    registry.register(_make_spec("tool.alpha"))

    digest = registry.manifest_hash()

    assert isinstance(digest, str), "manifest_hash() must return a str"
    assert len(digest) == 64, f"SHA-256 hex digest must be 64 chars, got {len(digest)}"
    assert all(c in "0123456789abcdef" for c in digest), (
        "manifest_hash() must be a lowercase hex string"
    )


def test_manifest_hash_empty_registry_is_valid_hex() -> None:
    """An empty registry still produces a valid 64-char hex digest."""
    registry = MCPToolRegistry()
    digest = registry.manifest_hash()
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


# ---------------------------------------------------------------------------
# 2–4. Hash sensitivity to structural changes (add / remove / rename)
# ---------------------------------------------------------------------------


def test_manifest_hash_changes_when_tool_added() -> None:
    """Registering a new tool MUST produce a different hash (Requirement 4.7)."""
    registry = MCPToolRegistry()
    registry.register(_make_spec("tool.alpha"))
    hash_before = registry.manifest_hash()

    registry.register(_make_spec("tool.beta"))
    hash_after = registry.manifest_hash()

    assert hash_before != hash_after, (
        "Adding a tool must change the manifest hash so the addition is detectable"
    )


def test_manifest_hash_changes_when_tool_removed() -> None:
    """Removing a tool MUST produce a different hash."""
    registry = MCPToolRegistry()
    registry.register(_make_spec("tool.alpha"))
    registry.register(_make_spec("tool.beta"))
    hash_before = registry.manifest_hash()

    del registry._tools["tool.beta"]
    hash_after = registry.manifest_hash()

    assert hash_before != hash_after, (
        "Removing a tool must change the manifest hash so the removal is detectable"
    )


def test_manifest_hash_changes_when_tool_renamed() -> None:
    """Renaming a tool (register under a new name) MUST change the hash."""
    registry = MCPToolRegistry()
    registry.register(_make_spec("tool.original"))
    hash_before = registry.manifest_hash()

    del registry._tools["tool.original"]
    registry.register(_make_spec("tool.renamed"))
    hash_after = registry.manifest_hash()

    assert hash_before != hash_after, (
        "Renaming a tool must change the manifest hash so the rename is detectable"
    )


# ---------------------------------------------------------------------------
# 5. Hash sensitivity to input_schema changes
# ---------------------------------------------------------------------------


def test_manifest_hash_changes_when_input_schema_changes() -> None:
    """Modifying a tool's input_schema MUST change the hash (Requirement 4.7)."""
    schema_v1 = {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}
    schema_v2 = {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "depth": {"type": "integer"},
        },
        "required": ["url"],
    }

    registry = MCPToolRegistry()
    registry.register(_make_spec("tool.scanner", input_schema=schema_v1))
    hash_v1 = registry.manifest_hash()

    # Replace with a modified schema
    registry._tools["tool.scanner"] = _make_spec("tool.scanner", input_schema=schema_v2)
    hash_v2 = registry.manifest_hash()

    assert hash_v1 != hash_v2, (
        "Changing a tool's input_schema must change the manifest hash "
        "so schema tampering is detectable (Requirement 4.7)"
    )


# ---------------------------------------------------------------------------
# 6. Hash sensitivity to description changes
# ---------------------------------------------------------------------------


def test_manifest_hash_changes_when_description_changes() -> None:
    """Modifying a tool's description MUST change the hash."""
    registry = MCPToolRegistry()
    registry.register(_make_spec("tool.alpha", description="Original description"))
    hash_before = registry.manifest_hash()

    registry._tools["tool.alpha"] = _make_spec("tool.alpha", description="Tampered description")
    hash_after = registry.manifest_hash()

    assert hash_before != hash_after, (
        "Changing a tool's description must change the manifest hash "
        "so description tampering is detectable"
    )


# ---------------------------------------------------------------------------
# 7. Determinism — same registry always produces the same hash
# ---------------------------------------------------------------------------


def test_manifest_hash_is_deterministic() -> None:
    """Identical tool registries must always produce the same hash."""
    schema = {"type": "object", "properties": {"target": {"type": "string"}}}

    def _build_registry() -> MCPToolRegistry:
        r = MCPToolRegistry()
        r.register(_make_spec("tool.alpha", description="Alpha", input_schema=schema))
        r.register(_make_spec("tool.beta", description="Beta"))
        return r

    hash_a = _build_registry().manifest_hash()
    hash_b = _build_registry().manifest_hash()

    assert hash_a == hash_b, (
        "manifest_hash() must be deterministic: same tools → same hash"
    )


def test_manifest_hash_order_independent() -> None:
    """Registration order must not affect the hash (sorted internally)."""
    registry_ab = MCPToolRegistry()
    registry_ab.register(_make_spec("tool.alpha"))
    registry_ab.register(_make_spec("tool.beta"))

    registry_ba = MCPToolRegistry()
    registry_ba.register(_make_spec("tool.beta"))
    registry_ba.register(_make_spec("tool.alpha"))

    assert registry_ab.manifest_hash() == registry_ba.manifest_hash(), (
        "Registration order must not affect manifest_hash() — "
        "tools are sorted by name before hashing"
    )


# ---------------------------------------------------------------------------
# 8. Hash present in the mcp_server_starting INFO log entry
# ---------------------------------------------------------------------------


def test_startup_log_contains_tool_manifest_hash() -> None:
    """Req 4.7 / 12.4 — tool_manifest_hash must be present in the startup log."""
    _, recorded = _make_server_and_capture()
    startup = _startup_log_kwargs(recorded)

    assert startup is not None, (
        "Expected a 'mcp_server_starting' INFO log entry during __init__"
    )
    assert "tool_manifest_hash" in startup, (
        "Startup log entry must contain 'tool_manifest_hash' (Requirement 4.7 / 12.4)"
    )
    digest = startup["tool_manifest_hash"]
    assert isinstance(digest, str) and len(digest) == 64, (
        f"tool_manifest_hash must be a 64-char hex string, got: {digest!r}"
    )


def test_startup_log_hash_matches_registry_hash() -> None:
    """The logged hash must equal the registry's own manifest_hash() at startup."""
    server, recorded = _make_server_and_capture()
    startup = _startup_log_kwargs(recorded)

    assert startup is not None
    logged_hash = startup.get("tool_manifest_hash")
    computed_hash = server.registry.manifest_hash()

    assert logged_hash == computed_hash, (
        "The hash logged at startup must match registry.manifest_hash() "
        "(Requirement 12.4 — log must reflect the active tool registry version)"
    )


def test_startup_hash_stored_on_server_instance() -> None:
    """The hash must be stored as ``_tool_manifest_hash`` on the server instance."""
    server, _ = _make_server_and_capture()

    assert server._tool_manifest_hash is not None, (
        "APILeakMCPServer must store the manifest hash in _tool_manifest_hash"
    )
    assert server._tool_manifest_hash == server.registry.manifest_hash(), (
        "_tool_manifest_hash must equal the registry's current hash"
    )


# ---------------------------------------------------------------------------
# 9. Startup log is emitted at INFO level (not DEBUG)
# ---------------------------------------------------------------------------


def test_startup_manifest_hash_logged_at_info_level() -> None:
    """Req 4.7 — the startup entry containing tool_manifest_hash must be at INFO."""
    config = MCPServerConfig(transport="stdio", allow_destructive=False)
    info_events: list[str] = []
    debug_events: list[str] = []

    with (
        patch.object(
            server_module.logger, "info",
            side_effect=lambda *a, **kw: info_events.append(a[0] if a else ""),
        ),
        patch.object(
            server_module.logger, "debug",
            side_effect=lambda *a, **kw: debug_events.append(a[0] if a else ""),
        ),
    ):
        APILeakMCPServer(transport="stdio", config=config)

    assert "mcp_server_starting" in info_events, (
        "mcp_server_starting (which carries tool_manifest_hash) must be logged "
        "at INFO level so operators see it with standard log filters (Req 4.7)"
    )
    assert "mcp_server_starting" not in debug_events, (
        "mcp_server_starting must NOT be relegated to DEBUG"
    )
