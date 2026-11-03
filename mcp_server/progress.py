"""
mcp_server.progress — Incremental progress streaming for long-running MCP tools.

Implements Task 5.1: ``ToolProgressStream`` and its wiring to the scan phase
loop in ``core/engine.py``.

The class provides a transport-agnostic abstraction:

* When a *streaming callback* is injected (``callback`` parameter), every
  call to :meth:`ToolProgressStream.emit` immediately forwards the update to
  that callback.  HTTP/SSE and stdio transports inject their specific send
  function here (Requirements 3.1, 3.2).

* When ``supports_streaming=False`` (or no callback is supplied) the
  transport does not support incremental updates.  ``emit`` is a no-op on the
  wire; it **accumulates** all updates in :attr:`updates` so the full list
  can be serialised into the final result once the tool finishes
  (Requirement 3.3).

Design:
    ``ToolProgressStream`` is intentionally transport-free.  Transport-level
    coupling (SSE, stdio, …) lives in the callback — a plain async callable
    ``async (ProgressUpdate) -> None``.  Injecting a mock callable is
    sufficient to test this class in isolation without any MCP SDK present.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ProgressUpdate:
    """A single incremental progress event emitted during a tool's execution.

    Requirements 3.1, 3.2: each update carries the current phase name,
    the accumulated findings count, and an optional progress percentage.
    """

    phase: str
    """Human-readable name of the scan phase that just completed or started."""

    findings_count: int
    """Number of findings accumulated *so far* across all completed phases."""

    percent_complete: float | None
    """
    Estimated completion percentage in the range [0.0, 100.0], or ``None``
    when an estimate cannot be provided (e.g. when the total phase count is
    not yet known).
    """

    extra: dict[str, Any] = field(default_factory=dict)
    """Optional extra metadata (e.g. phase description, endpoints found)."""


# Type alias for the transport callback
ProgressCallback = Callable[[ProgressUpdate], Awaitable[None]]


# ---------------------------------------------------------------------------
# ToolProgressStream
# ---------------------------------------------------------------------------


class ToolProgressStream:
    """Transport-agnostic progress stream for long-running MCP tools.

    Args:
        callback:
            An async callable ``async (ProgressUpdate) -> None`` that the
            transport uses to push the update to the connected MCP client.
            When *None* the stream operates in **accumulation-only** mode
            (useful when no transport callback is available at construction
            time or when the transport does not support streaming).
        supports_streaming:
            Controls whether :meth:`emit` actively forwards updates via
            ``callback``.  Setting this to ``False`` forces accumulation-only
            mode even if a callback is provided — the updates are buffered so
            the caller can attach them to the final result (Requirement 3.3).

    Attributes:
        updates: All :class:`ProgressUpdate` objects emitted so far, in order.
    """

    def __init__(
        self,
        callback: ProgressCallback | None = None,
        *,
        supports_streaming: bool = True,
    ) -> None:
        self._callback = callback
        self._supports_streaming = supports_streaming
        self._updates: list[ProgressUpdate] = []

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @property
    def supports_streaming(self) -> bool:
        """True if the underlying transport supports incremental streaming."""
        return self._supports_streaming

    @property
    def updates(self) -> list[ProgressUpdate]:
        """All updates emitted so far (accumulation buffer, read-only view)."""
        return list(self._updates)

    def as_final_result_summary(self) -> dict[str, Any]:
        """Serialise all accumulated updates into a compact dict.

        Intended for use by :class:`~mcp_server.tool_registry.MCPToolRegistry`
        when the transport does not support streaming (Requirement 3.3): the
        full phase list is attached to the final :class:`MCPToolResult` metadata
        under the key ``"progress_summary"`` so the client receives all
        progress information in the single terminal response.

        Returns:
            A dict with two keys:

            * ``update_count`` — total number of updates emitted.
            * ``phases`` — list of dicts, one per :class:`ProgressUpdate`, each
              containing ``phase``, ``findings_count``, ``percent_complete``,
              and ``extra``.
        """
        return {
            "update_count": len(self._updates),
            "phases": [
                {
                    "phase": u.phase,
                    "findings_count": u.findings_count,
                    "percent_complete": u.percent_complete,
                    "extra": u.extra,
                }
                for u in self._updates
            ],
        }

    async def emit(
        self,
        phase: str,
        findings_count: int,
        percent_complete: float | None,
        *,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Emit a progress update.

        Always records the update in :attr:`updates`.  Only forwards to the
        callback when :attr:`supports_streaming` is True *and* a callback was
        provided.

        Args:
            phase: Name of the scan phase (e.g. ``"discovery"``,
                ``"owasp_testing"``).
            findings_count: Accumulated finding count at the time of emission.
            percent_complete: Estimated completion percentage, or ``None``.
            extra: Optional extra context to attach to the update.

        Requirements:
            3.1 — emit is called as each scan phase completes.
            3.2 — each update carries phase name, findings count, and percentage.
            3.3 — when streaming is not supported, emit is a no-op on the wire
                  (but still accumulates internally so the final result can be
                  built from :attr:`updates`).
        """
        update = ProgressUpdate(
            phase=phase,
            findings_count=findings_count,
            percent_complete=percent_complete,
            extra=extra or {},
        )
        self._updates.append(update)

        if self._supports_streaming and self._callback is not None:
            try:
                result = self._callback(update)
                # Support both sync callables that return None and real coroutines
                if asyncio.isfuture(result) or asyncio.iscoroutine(result):
                    await result
            except Exception:  # noqa: BLE001  — transport errors must not abort the scan
                pass  # Silently discard transport errors; the scan continues.
