"""
mcp_server.confirmation_gate — DestructiveConfirmationGate.

Implements the two-tier human-confirmation check that guards every MCP tool
marked as destructive (Requirements 4.1, 4.2 / Property 1).

**Tier 1 — Process-level opt-in (``allow_destructive`` flag)**

The server must have been started explicitly with ``--allow-destructive-mcp``
(i.e. ``MCPServerConfig.allow_destructive=True``).  When the server is running
in safe mode (``allow_destructive=False``), *every* destructive tool is
unconditionally rejected regardless of any ``ConfirmationToken`` the caller
provides.  This prevents a misconfigured client from accidentally enabling
destructive operations just by supplying a token.

**Tier 2 — Per-invocation ConfirmationToken**

Even when the server is running in destructive mode (Tier 1 passes), each
individual tool invocation *still* requires a valid :class:`ConfirmationToken`
whose ``tool_name`` matches the tool being invoked.  This ensures that a human
operator explicitly acknowledges each destructive action individually —
bulk/automated confirmation is not possible (Requirement 4.1, 4.2).

Design note
-----------
The :attr:`allow_destructive` flag is independent of the per-invocation
confirmation: setting ``allow_destructive=True`` only unblocks the *category*
of destructive tools; it does *not* provide the per-invocation confirmation.
Callers must supply both the process-level flag at server startup AND a
``ConfirmationToken`` on every destructive invocation.
"""

from __future__ import annotations

from mcp_server.schemas import (
    ConfirmationRequiredError,
    ConfirmationToken,
    MCPToolError,
    MCPToolSpec,
)


class DestructiveConfirmationGate:
    """Two-tier guard that enforces human confirmation for destructive tools.

    Usage::

        gate = DestructiveConfirmationGate(allow_destructive=True)
        gate.check(spec, confirmation_token)   # raises on failure

    Args:
        allow_destructive: Process-level flag.  When ``False`` (default),
            *all* destructive tools are blocked unconditionally regardless of
            any ``ConfirmationToken``.  When ``True``, destructive tools are
            permitted but still require a valid per-invocation token.
    """

    def __init__(self, allow_destructive: bool = False) -> None:
        self.allow_destructive = allow_destructive

    def check(
        self, tool_spec: MCPToolSpec, confirmation: ConfirmationToken | None
    ) -> None:
        """Enforce the two-tier destructive guard for *tool_spec*.

        If *tool_spec* is not destructive this method returns immediately
        without side effects.

        For destructive tools the following checks are applied **in order**:

        1. **Tier 1 — process-level opt-in**: raises :class:`MCPToolError`
           with ``error_code="DESTRUCTIVE_NOT_ENABLED"`` when
           ``allow_destructive=False``.  No ``ConfirmationToken`` can bypass
           this check — the operator must restart the server with
           ``--allow-destructive-mcp``.

        2. **Tier 2 — per-invocation token**: raises
           :class:`ConfirmationRequiredError` when *confirmation* is ``None``
           or its ``tool_name`` does not match the tool being invoked.  This
           check applies even when ``allow_destructive=True`` — the
           process-level flag does *not* supply the per-invocation confirmation
           (Requirements 4.1, 4.2 / Property 1).

        Args:
            tool_spec: The spec of the tool about to be executed.
            confirmation: Per-invocation token provided by the caller,
                or ``None`` if absent.

        Raises:
            MCPToolError: (``DESTRUCTIVE_NOT_ENABLED``) When the server was
                not started in destructive mode (Tier 1 failure).
            ConfirmationRequiredError: When the tool is destructive and the
                per-invocation token is missing or mismatched (Tier 2 failure).
        """
        if not tool_spec.is_destructive:
            return

        # Tier 1: process-level opt-in.
        if not self.allow_destructive:
            raise MCPToolError(
                f"Tool '{tool_spec.name}' is a destructive operation.  "
                "The server was started in safe mode (no destructive operations "
                "are permitted).  Restart the server with '--allow-destructive-mcp' "
                "to enable destructive tools, then provide an explicit "
                "ConfirmationToken on each invocation.",
                error_code="DESTRUCTIVE_NOT_ENABLED",
            )

        # Tier 2: per-invocation ConfirmationToken — required even in destructive
        # mode.  The process-level flag does not substitute for per-invocation
        # human confirmation (Requirements 4.1, 4.2).
        if confirmation is None or confirmation.tool_name != tool_spec.name:
            raise ConfirmationRequiredError(tool_spec.name)
