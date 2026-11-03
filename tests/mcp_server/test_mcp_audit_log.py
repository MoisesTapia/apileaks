"""
Tests for MCPAuditLogger and audit-log behavior in MCPToolRegistry (Task 6A.4).

Verifies Requirement 12.5: every tool invocation — successful or failed —
produces exactly one audit log entry containing all required fields.

Test coverage
-------------
1. Successful invocation → one entry, outcome="success", error_code=null,
   finding_count matches result.
2. Handler raises exception → one entry, outcome="error", error_code set.
3. Schema-validation failure → one entry, outcome="error".
4. ``record_startup`` writes a server_start sentinel with all expected fields.

Strategy
--------
- No network calls; handlers are in-process coroutines.
- The audit log is written to a ``tmp_path`` temp file (pytest fixture).
- The MCP SDK is an optional dependency; the whole module is skipped when it
  is absent.

**Validates: Requirements 12.5**
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

# Skip the whole module when the optional MCP SDK is not installed.
pytest.importorskip("mcp")

from mcp_server.audit_log import MCPAuditLogger  # noqa: E402
from mcp_server.schemas import (  # noqa: E402
    MCPToolError,
    MCPToolResult,
    MCPToolSpec,
    SchemaValidationError,
)
from mcp_server.tool_registry import MCPToolRegistry  # noqa: E402


# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

_REQUIRED_ENTRY_FIELDS = frozenset(
    {
        "tool_name",
        "caller_identity",
        "param_hash",
        "timestamp_start",
        "timestamp_end",
        "outcome",
        "error_code",
        "finding_count",
        "confirmation_token_id",
        "tool_manifest_hash",
    }
)

_SIMPLE_SCHEMA: dict = {
    "type": "object",
    "properties": {"target_url": {"type": "string"}},
    "required": ["target_url"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    """Execute an async coroutine synchronously (mirrors project test style)."""
    return asyncio.run(coro)


def _read_entries(log_path: Path) -> list[dict]:
    """Return all JSON lines from *log_path* as parsed dicts."""
    text = log_path.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line.strip()]
    return [json.loads(line) for line in lines]


def _make_success_spec(name: str = "test.audit.success") -> MCPToolSpec:
    """Return a non-destructive tool spec whose handler returns two findings."""

    async def _handler(params: dict) -> MCPToolResult:
        return MCPToolResult(
            tool_name=name,
            findings=["finding_a", "finding_b"],
            metadata={"scanned": True},
        )

    return MCPToolSpec(
        name=name,
        description="Audit-log test — success path.",
        input_schema=_SIMPLE_SCHEMA,
        output_schema={"type": "object"},
        is_destructive=False,
        handler=_handler,
    )


def _make_error_spec(name: str = "test.audit.error") -> MCPToolSpec:
    """Return a spec whose handler always raises a plain Exception."""

    async def _handler(params: dict) -> MCPToolResult:
        raise RuntimeError("deliberate handler failure")

    return MCPToolSpec(
        name=name,
        description="Audit-log test — error path.",
        input_schema=_SIMPLE_SCHEMA,
        output_schema={"type": "object"},
        is_destructive=False,
        handler=_handler,
    )


# ---------------------------------------------------------------------------
# Test 1 — successful invocation produces exactly one entry with all fields
# ---------------------------------------------------------------------------


def test_successful_invocation_produces_one_audit_entry(tmp_path: Path) -> None:
    """Req 12.5 — a successful invoke writes exactly one complete audit entry.

    Asserts:
    - Exactly one line written to the log.
    - All required fields are present.
    - outcome == "success".
    - error_code is null.
    - finding_count matches the number of findings returned by the handler.
    """
    log_file = tmp_path / "audit.jsonl"
    audit_logger = MCPAuditLogger(log_file)

    spec = _make_success_spec()
    registry = MCPToolRegistry(audit_logger=audit_logger)
    registry.register(spec)

    _run(
        registry.invoke(
            spec.name,
            {"target_url": "https://example.com"},
            caller_identity="test-caller",
        )
    )

    entries = _read_entries(log_file)
    assert len(entries) == 1, (
        f"Expected exactly 1 audit entry, got {len(entries)}: {entries}"
    )

    entry = entries[0]

    missing = _REQUIRED_ENTRY_FIELDS - entry.keys()
    assert not missing, f"Audit entry missing required fields: {missing}"

    assert entry["tool_name"] == spec.name
    assert entry["caller_identity"] == "test-caller"
    assert entry["outcome"] == "success"
    assert entry["error_code"] is None
    assert entry["finding_count"] == 2  # handler returns 2 findings
    assert entry["confirmation_token_id"] is None
    assert entry["param_hash"]  # non-empty hash string
    assert entry["tool_manifest_hash"]
    assert entry["timestamp_start"]
    assert entry["timestamp_end"]


# ---------------------------------------------------------------------------
# Test 2 — handler exception produces exactly one entry with error fields set
# ---------------------------------------------------------------------------


def test_handler_exception_produces_one_audit_entry(tmp_path: Path) -> None:
    """Req 12.5 — an errored invoke writes exactly one complete audit entry.

    Asserts:
    - Exactly one line written to the log.
    - All required fields are present.
    - outcome == "error".
    - error_code is not null.
    - MCPToolError is raised to the caller.
    """
    log_file = tmp_path / "audit.jsonl"
    audit_logger = MCPAuditLogger(log_file)

    spec = _make_error_spec()
    registry = MCPToolRegistry(audit_logger=audit_logger)
    registry.register(spec)

    with pytest.raises(MCPToolError):
        _run(
            registry.invoke(
                spec.name,
                {"target_url": "https://example.com"},
                caller_identity="test-caller",
            )
        )

    entries = _read_entries(log_file)
    assert len(entries) == 1, (
        f"Expected exactly 1 audit entry, got {len(entries)}: {entries}"
    )

    entry = entries[0]

    missing = _REQUIRED_ENTRY_FIELDS - entry.keys()
    assert not missing, f"Audit entry missing required fields: {missing}"

    assert entry["tool_name"] == spec.name
    assert entry["outcome"] == "error"
    assert entry["error_code"] is not None, (
        "error_code must be set (non-null) for an errored invocation"
    )
    assert entry["finding_count"] == 0


# ---------------------------------------------------------------------------
# Test 3 — schema-validation failure produces exactly one entry
# ---------------------------------------------------------------------------


def test_schema_validation_failure_produces_one_audit_entry(tmp_path: Path) -> None:
    """Req 12.5 — a schema-validation failure writes exactly one complete audit entry.

    Asserts:
    - Exactly one line written (the handler was never called).
    - outcome == "error".
    - error_code is not null.
    """
    log_file = tmp_path / "audit.jsonl"
    audit_logger = MCPAuditLogger(log_file)

    spec = _make_success_spec(name="test.audit.schema_fail")
    registry = MCPToolRegistry(audit_logger=audit_logger)
    registry.register(spec)

    # Pass params that violate the schema (missing required "target_url").
    with pytest.raises(SchemaValidationError):
        _run(
            registry.invoke(
                spec.name,
                {},  # missing required field
                caller_identity="test-caller",
            )
        )

    entries = _read_entries(log_file)
    assert len(entries) == 1, (
        f"Expected exactly 1 audit entry for a schema-validation failure, "
        f"got {len(entries)}: {entries}"
    )

    entry = entries[0]

    missing = _REQUIRED_ENTRY_FIELDS - entry.keys()
    assert not missing, f"Audit entry missing required fields: {missing}"

    assert entry["outcome"] == "error"
    assert entry["error_code"] is not None


# ---------------------------------------------------------------------------
# Test 4 — record_startup writes a server_start sentinel with all fields
# ---------------------------------------------------------------------------


def test_record_startup_writes_server_start_entry(tmp_path: Path) -> None:
    """Req 12.5 — record_startup writes a server_start entry with all expected fields.

    Asserts:
    - Exactly one line written.
    - tool_name == "server_start".
    - tool_manifest_hash matches the hash passed in.
    - timestamp and pid fields are present.
    """
    log_file = tmp_path / "startup-audit.jsonl"
    audit_logger = MCPAuditLogger(log_file)

    fake_hash = "abc123def456" * 4  # 48 chars — looks like a partial hex digest

    audit_logger.record_startup(fake_hash)

    entries = _read_entries(log_file)
    assert len(entries) == 1, (
        f"Expected exactly 1 server_start entry, got {len(entries)}: {entries}"
    )

    entry = entries[0]

    assert entry.get("tool_name") == "server_start", (
        f"Expected tool_name='server_start', got {entry.get('tool_name')!r}"
    )
    assert entry.get("tool_manifest_hash") == fake_hash, (
        f"Expected tool_manifest_hash={fake_hash!r}, got {entry.get('tool_manifest_hash')!r}"
    )
    assert "timestamp" in entry, "server_start entry must contain a 'timestamp' field"
    assert "pid" in entry, "server_start entry must contain a 'pid' field"
    assert entry["pid"] == os.getpid()
