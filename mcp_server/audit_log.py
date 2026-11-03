"""
mcp_server.audit_log — MCPAuditLogger: append-only JSON Lines audit trail.

Implements the MCP invocation audit log required by OWASP MCP08.  Every tool
invocation (successful, failed, or cancelled) is recorded as exactly one JSON
Line in an append-only log file so the full invocation history is always
preserved and attributable.

Design principles
-----------------
* **Append-only**: the log file is always opened in ``'a'`` mode; existing
  entries are never overwritten or truncated (Requirements 12.1, 12.2).
* **No raw parameter values**: raw tool parameters are *never* written to the
  log.  Only a SHA-256 digest of the redacted, serialized parameters is stored
  so secrets cannot be accidentally leaked through the audit trail
  (Requirement 12.3).
* **Synchronous writes**: :meth:`MCPAuditLogger.record` is a plain synchronous
  call.  This ensures the entry is durable before control returns to the
  caller, regardless of whether the server's async event loop is still running.

Utility
-------
:func:`compute_param_hash` is the canonical helper for computing the
``param_hash`` field.  It serialises the parameter dict, runs the result
through the shared ``BOLATestingModule.redact_secrets`` redactor so that any
credential-shaped values are masked, and then returns the SHA-256 hex digest of
the redacted string.  Callers that build an :class:`MCPAuditEntry` should
always use this function rather than hashing raw parameters directly.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Secret redaction helper
# ---------------------------------------------------------------------------

def _redact(text: str) -> str:
    """Apply ``BOLATestingModule.redact_secrets`` to *text*.

    Imports and instantiates ``BOLATestingModule`` via ``__new__`` (no HTTP
    client or config required) to reuse the shared redaction logic — the same
    pattern used by ``jwt_attack_engine``, ``auth_testing``, and
    ``modules/cloud/normalizer.py``.

    Falls back to returning *text* unchanged if the import or call fails so
    that an unexpected import error never blocks audit logging.
    """
    try:
        from modules.owasp.bola_testing import BOLATestingModule  # type: ignore[import]

        redactor: Any = BOLATestingModule.__new__(BOLATestingModule)
        return redactor.redact_secrets(text)
    except Exception:
        # Redaction must never break audit logging; log the failure and fall
        # through so the hash is still written (without redaction).
        logger.warning(
            "mcp_audit_redaction_unavailable",
            detail="BOLATestingModule.redact_secrets could not be imported; "
                   "param_hash computed on un-redacted serialisation.",
        )
        return text


# ---------------------------------------------------------------------------
# Public utility: compute param_hash
# ---------------------------------------------------------------------------

def compute_param_hash(params: dict[str, Any]) -> str:
    """Return the SHA-256 hex digest of the redacted, serialised *params*.

    Steps:

    1. Serialise *params* to a compact, deterministic JSON string (keys sorted,
       no extra whitespace).
    2. Run the serialised string through :func:`_redact` so credential-shaped
       values are masked before hashing.
    3. Return the SHA-256 hex digest of the UTF-8 encoded redacted string.

    This is the canonical way to produce the ``param_hash`` field for an
    :class:`MCPAuditEntry` (Requirement 12.3).

    Args:
        params: The raw tool invocation parameters.

    Returns:
        40-character lowercase hex string (SHA-256 digest).
    """
    serialised = json.dumps(params, sort_keys=True, separators=(",", ":"))
    redacted = _redact(serialised)
    return hashlib.sha256(redacted.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class MCPAuditEntry:
    """One invocation record written to the audit log (Requirements 12.1–12.3).

    Fields
    ------
    tool_name
        Registered name of the tool that was invoked (e.g. ``apileak.scan``).
    caller_identity
        Opaque identity of the caller: a token hash for HTTP clients, or
        ``"stdio:<pid>"`` for stdio transport.
    param_hash
        SHA-256 hex digest of the tool parameters *after* secret redaction.
        Use :func:`compute_param_hash` to produce this value.  Raw parameter
        values are NEVER stored in the audit log (Requirement 12.3).
    timestamp_start
        UTC wall-clock time when the tool invocation began.
    timestamp_end
        UTC wall-clock time when the tool invocation finished (success, error,
        or cancellation).
    outcome
        Invocation outcome: one of ``"success"``, ``"error"``, or
        ``"cancelled"``.
    error_code
        Machine-readable error code (e.g. ``"CONFIRMATION_REQUIRED"``) or
        ``None`` for successful invocations.
    finding_count
        Number of :class:`~utils.findings.Finding` objects produced.
    confirmation_token_id
        Opaque identifier of the :class:`~mcp_server.schemas.ConfirmationToken`
        that authorised a destructive invocation, or ``None`` for non-destructive
        tools.
    tool_manifest_hash
        SHA-256 hex digest of the active tool manifest at the time of
        invocation.  Produced by
        :meth:`~mcp_server.tool_registry.MCPToolRegistry.manifest_hash`
        (Requirement 12.4).
    """

    tool_name: str
    caller_identity: str
    param_hash: str
    timestamp_start: datetime
    timestamp_end: datetime
    outcome: str  # "success" | "error" | "cancelled"
    error_code: str | None
    finding_count: int
    confirmation_token_id: str | None
    tool_manifest_hash: str


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------

_STARTUP_TOOL_NAME = "server_start"


class MCPAuditLogger:
    """Append-only JSON Lines audit logger for MCP tool invocations.

    Each :meth:`record` call atomically appends exactly one JSON Line to the
    log file.  The file is opened in ``'a'`` (append) mode on every write so
    the OS guarantees that no previously written bytes are touched.

    Usage::

        logger = MCPAuditLogger(Path("apileaks-mcp-audit.jsonl"))
        logger.record_startup(registry.manifest_hash())
        # … later, after an invocation …
        logger.record(entry)

    Args:
        log_path: Destination file.  Parent directories must already exist;
            the file itself is created on first write if it does not exist.
    """

    def __init__(self, log_path: Path) -> None:
        self._log_path = Path(log_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(self, entry: MCPAuditEntry) -> None:
        """Write *entry* as a JSON Line to the audit log (synchronous, append-only).

        The entry is serialised to a single line of JSON and immediately
        flushed + synced to the underlying file so the record is durable even
        if the process crashes shortly after (Requirements 12.1, 12.2).

        Args:
            entry: The invocation record to append.  ``param_hash`` must
                already have been computed via :func:`compute_param_hash`;
                raw parameter values must never be passed through this method.
        """
        line = self._serialise_entry(entry)
        self._append_line(line)
        logger.debug(
            "mcp_audit_recorded",
            tool_name=entry.tool_name,
            outcome=entry.outcome,
            log_path=str(self._log_path),
        )

    def record_startup(self, tool_manifest_hash: str) -> None:
        """Write a ``server_start`` sentinel entry to the audit log.

        The startup entry documents which tool manifest was active when the
        server launched, enabling detection of manifest tampering across
        server restarts (Requirement 12.4).

        Args:
            tool_manifest_hash: SHA-256 hex digest produced by
                :meth:`~mcp_server.tool_registry.MCPToolRegistry.manifest_hash`.
        """
        now = datetime.now(tz=UTC)
        record: dict[str, Any] = {
            "tool_name": _STARTUP_TOOL_NAME,
            "event": "server_start",
            "tool_manifest_hash": tool_manifest_hash,
            "timestamp": now.isoformat(),
            "pid": os.getpid(),
        }
        line = json.dumps(record, separators=(",", ":"))
        self._append_line(line)
        logger.info(
            "mcp_audit_startup_recorded",
            tool_manifest_hash=tool_manifest_hash,
            log_path=str(self._log_path),
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _serialise_entry(entry: MCPAuditEntry) -> str:
        """Convert *entry* to a compact JSON string (no trailing newline)."""
        record: dict[str, Any] = {
            "tool_name": entry.tool_name,
            "caller_identity": entry.caller_identity,
            "param_hash": entry.param_hash,
            "timestamp_start": entry.timestamp_start.isoformat(),
            "timestamp_end": entry.timestamp_end.isoformat(),
            "outcome": entry.outcome,
            "error_code": entry.error_code,
            "finding_count": entry.finding_count,
            "confirmation_token_id": entry.confirmation_token_id,
            "tool_manifest_hash": entry.tool_manifest_hash,
        }
        return json.dumps(record, separators=(",", ":"))

    def _append_line(self, line: str) -> None:
        """Open the log file in append mode, write *line* + newline, flush and sync.

        Opening in ``'a'`` mode on each call ensures no existing content is
        ever overwritten, even if the file is rotated externally (Requirements
        12.1, 12.2).  ``os.fsync`` is called so the entry survives a process
        crash immediately after this method returns.

        Raises:
            OSError: If the file cannot be opened or written (e.g. permissions
                error, disk full).  The caller should handle this and decide
                whether to propagate or degrade gracefully.
        """
        with self._log_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
