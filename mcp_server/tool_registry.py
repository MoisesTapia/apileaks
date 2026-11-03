"""
mcp_server.tool_registry — MCPToolRegistry: registration and dispatch hub.

The registry is the single choke-point through which every MCP tool invocation
passes.  It guarantees:

1. **Schema validation before execution** (Property 5 / Requirement 1.3):
   ``invoke`` validates the caller's parameters against the tool's
   ``input_schema`` *before* calling the handler.  If validation fails the
   handler is never entered.

2. **Destructive confirmation gating** (Requirement 4.1, 4.2):
   Tools with ``is_destructive=True`` require a valid :class:`ConfirmationToken`.

3. **Per-client rate limiting** (Requirement 15.2):
   When a :class:`~mcp_server.rate_limiter.MCPRateLimiter` is attached to the
   registry, ``invoke`` checks the caller's ``client_id`` before dispatching
   the handler.  Over-quota clients receive a structured
   ``RATE_LIMIT_EXCEEDED`` error and the handler is *never* called.

4. **Execution timeout** (Requirement 15.1 / OWASP MCP05):
   Each invocation is wrapped in an ``asyncio.wait_for`` using the tool's
   ``max_execution_seconds``.

5. **Structured error wrapping** (Requirement 1.5):
   Any uncaught exception from a handler is wrapped in an :class:`MCPToolError`
   so the MCP transport layer always receives a structured response, never a raw
   Python traceback.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import jsonschema
import jsonschema.exceptions

from core.logging import get_logger
from mcp_server.audit_log import MCPAuditEntry, MCPAuditLogger, compute_param_hash
from mcp_server.confirmation_gate import DestructiveConfirmationGate
from mcp_server.input_sanitizer import flag_prompt_injection_attempt
from mcp_server.rate_limiter import MCPRateLimiter
from mcp_server.schemas import (
    ConfirmationToken,
    MCPToolError,
    MCPToolResult,
    MCPToolSpec,
    SchemaValidationError,
    ToolNotFoundError,
)

if TYPE_CHECKING:
    from mcp_server.progress import ToolProgressStream

logger = get_logger(__name__)


class MCPToolRegistry:
    """Central registry and dispatcher for MCP tools.

    Usage::

        registry = MCPToolRegistry()
        registry.register(spec)
        result = await registry.invoke("apileak.scan", params, confirmation=None)

    Args:
        confirmation_gate: Optional :class:`~mcp_server.confirmation_gate.DestructiveConfirmationGate`
            to use for destructive tool invocations.  When not provided a
            default gate is created with ``allow_destructive=False`` (safe
            mode).  Pass the gate from :class:`~mcp_server.server.APILeakMCPServer`
            so that the process-level ``--allow-destructive-mcp`` flag is
            respected (Requirements 4.1, 4.2).
    """

    def __init__(
        self,
        confirmation_gate: DestructiveConfirmationGate | None = None,
        rate_limiter: MCPRateLimiter | None = None,
        audit_logger: MCPAuditLogger | None = None,
    ) -> None:
        self._tools: dict[str, MCPToolSpec] = {}
        # Use the supplied gate or fall back to a default safe-mode gate.
        self._confirmation_gate: DestructiveConfirmationGate = (
            confirmation_gate
            if confirmation_gate is not None
            else DestructiveConfirmationGate(allow_destructive=False)
        )
        # Optional rate limiter; None means no rate limiting is enforced.
        self._rate_limiter: MCPRateLimiter | None = rate_limiter
        # Optional audit logger (Requirement 12.1); None means no audit logging.
        # Inject via constructor so tests can supply a mock without touching the
        # filesystem.
        self._audit_logger: MCPAuditLogger | None = audit_logger

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, spec: MCPToolSpec) -> None:
        """Register *spec* under its :attr:`~MCPToolSpec.name`.

        Overwrites any previously registered tool with the same name (useful
        for re-registration during tests).
        """
        if not isinstance(spec, MCPToolSpec):
            raise TypeError(f"Expected MCPToolSpec, got {type(spec).__name__}")
        self._tools[spec.name] = spec
        logger.debug("mcp_tool_registered", tool_name=spec.name, is_destructive=spec.is_destructive)

    # ------------------------------------------------------------------
    # Listing
    # ------------------------------------------------------------------

    def list_tools(self) -> list[MCPToolSpec]:
        """Return a snapshot of all registered tool specs (alphabetical order)."""
        return sorted(self._tools.values(), key=lambda s: s.name)

    def manifest_hash(self) -> str:
        """Return a SHA-256 hex digest of the current tool manifest.

        The digest covers, for each registered tool (sorted by name):

        * ``name`` — detects additions, removals, and renames.
        * ``description`` — detects changes to tool descriptions that could
          alter how an AI agent interprets the tool's purpose.
        * ``input_schema`` — detects schema changes (field additions, type
          changes, etc.) that alter what parameters the tool accepts.

        Any modification to these fields produces a different hash, making
        silent tampering detectable (Requirement 4.7 / OWASP MCP03,
        Requirement 12.4).
        """
        tools_snapshot = [
            {
                "name": spec.name,
                "description": spec.description,
                "input_schema": spec.input_schema,
            }
            for spec in sorted(self._tools.values(), key=lambda s: s.name)
        ]
        manifest = json.dumps(tools_snapshot, sort_keys=True)
        return hashlib.sha256(manifest.encode()).hexdigest()

    # ------------------------------------------------------------------
    # Invocation
    # ------------------------------------------------------------------

    async def invoke(
        self,
        tool_name: str,
        params: dict[str, Any],
        confirmation: ConfirmationToken | None = None,
        *,
        progress_stream: ToolProgressStream | None = None,
        client_id: str = "__default__",
        caller_identity: str = "unknown",
    ) -> MCPToolResult:
        """Validate, guard, and dispatch a tool invocation.

        Steps (in order):

        1. Look up the tool — raises :class:`ToolNotFoundError` if absent.
        2. **Rate-limit check** (Requirement 15.2): if a
           :class:`~mcp_server.rate_limiter.MCPRateLimiter` is attached and the
           ``client_id`` has exceeded its quota, raises
           :class:`~mcp_server.schemas.MCPToolError` with code
           ``"RATE_LIMIT_EXCEEDED"`` *without* calling the handler.
        3. **Validate** ``params`` against ``input_schema`` — raises
           :class:`SchemaValidationError` if invalid, *without* calling the
           handler (Property 5).
        4. Check destructive confirmation — raises
           :class:`ConfirmationRequiredError` if the tool is destructive and no
           valid token was provided.
        5. Dispatch to the handler, enforcing ``max_execution_seconds``.
        6. Wrap any unhandled exception in :class:`MCPToolError`.
        7. **Progress degradation** (Requirement 3.3): when a
           ``progress_stream`` is provided and its transport does not support
           native streaming (``supports_streaming=False``), the accumulated
           phase updates are attached to the result's ``metadata`` under the
           key ``"progress_summary"``.  When the transport *does* support
           streaming, progress was already delivered incrementally and no
           post-processing is needed.
        8. **Audit log** (Requirement 12.1): regardless of the outcome a single
           :class:`~mcp_server.audit_log.MCPAuditEntry` is written via
           :meth:`~mcp_server.audit_log.MCPAuditLogger.record` in a
           ``finally`` block so no invocation — successful, failed, or
           cancelled — is ever missing from the audit trail.

        Args:
            tool_name: The registered name of the tool to invoke.
            params: Input parameters to pass to the handler.
            confirmation: Optional confirmation token for destructive tools.
            progress_stream: Optional :class:`~mcp_server.progress.ToolProgressStream`
                attached to this invocation.  When provided and the stream's
                ``supports_streaming`` property is ``False``, the accumulated
                progress updates are serialised and attached to the returned
                :class:`MCPToolResult` metadata (Requirement 3.3).
            client_id: Opaque identifier for the calling client used by the
                rate limiter (Requirement 15.2).  Defaults to
                ``"__default__"``.  HTTP transport should pass the client IP;
                stdio transport can leave the default.
            caller_identity: Opaque identity of the caller recorded in the
                audit log (Requirement 12.1).  HTTP transport should pass a
                hash of the bearer token; stdio transport should use
                ``"stdio:<pid>"``.

        Returns:
            :class:`MCPToolResult` produced by the handler.  If
            ``progress_stream`` is provided with ``supports_streaming=False``,
            the result's ``metadata["progress_summary"]`` will contain the
            full phase-level progress summary.

        Raises:
            ToolNotFoundError: ``tool_name`` is not registered.
            MCPToolError(RATE_LIMIT_EXCEEDED): Client has exceeded its quota.
            SchemaValidationError: ``params`` do not satisfy ``input_schema``.
            ConfirmationRequiredError: Destructive tool invoked without token.
            MCPToolError: Any other error from the handler.
        """
        # Capture start time before anything else so the audit window is accurate.
        timestamp_start = datetime.now(tz=UTC)

        # Compute the param_hash once up front from the raw params.  This is
        # done outside the try block so the hash is always available in finally
        # even if the invocation never reaches the handler.
        param_hash = compute_param_hash(params)

        # Track outcome/error_code for the audit entry.
        outcome: str = "error"
        audit_error_code: str | None = None
        result: MCPToolResult | None = None

        try:
            # 1. Look up the tool spec.
            spec = self._tools.get(tool_name)
            if spec is None:
                raise ToolNotFoundError(tool_name)

            # 2. Rate-limit check — BEFORE schema validation or handler execution
            #    so that over-quota clients never cause any processing cost.
            if self._rate_limiter is not None:
                await self._rate_limiter.check_and_record(client_id)

            # 3. Validate input parameters BEFORE calling the handler.
            #    This is the core invariant tested by Property 5.
            self._validate_params(spec, params)

            # 3b. Prompt-injection detection (Requirement 4.4 / OWASP MCP06).
            #     If any parameter value looks like an instruction directed at an AI
            #     agent, log a WARNING but continue — params are passed as opaque data
            #     to the Python handler and are NEVER executed as instructions by the
            #     server.  This step is explicitly non-blocking.
            flag_prompt_injection_attempt(params)

            # 4. Destructive confirmation gate — delegates to the two-tier
            #    DestructiveConfirmationGate (process-level opt-in + per-invocation
            #    ConfirmationToken).  The gate raises before the handler is called
            #    so no part of the operation is executed without confirmation.
            self._confirmation_gate.check(spec, confirmation)

            # 5. Dispatch to handler with timeout.
            logger.debug("mcp_tool_invoking", tool_name=tool_name)
            try:
                result = await asyncio.wait_for(
                    spec.handler(params),
                    timeout=spec.max_execution_seconds,
                )
            except TimeoutError as exc:
                raise MCPToolError(
                    f"Tool '{tool_name}' exceeded its maximum execution time of "
                    f"{spec.max_execution_seconds}s.",
                    error_code="EXECUTION_TIMEOUT",
                ) from exc
            except MCPToolError:
                # Already structured — re-raise as-is.
                raise
            except Exception as exc:
                # 6. Wrap unexpected exceptions so no raw traceback reaches the client.
                logger.error(
                    "mcp_tool_handler_error",
                    tool_name=tool_name,
                    exc_type=type(exc).__name__,
                    exc_message=str(exc),
                )
                raise MCPToolError(
                    f"Tool '{tool_name}' encountered an internal error.",
                    error_code="INTERNAL_ERROR",
                ) from exc

            # 7. Progress degradation (Requirement 3.3).
            #    When the transport cannot stream incrementally, every accumulated
            #    phase update is serialised and attached to the final result so the
            #    client still receives all phase-level progress data.
            if progress_stream is not None and not progress_stream.supports_streaming:
                result.metadata["progress_summary"] = progress_stream.as_final_result_summary()
                logger.debug(
                    "mcp_tool_progress_degraded",
                    tool_name=tool_name,
                    update_count=len(progress_stream.updates),
                )

            logger.debug("mcp_tool_completed", tool_name=tool_name)
            outcome = "success"
            return result

        except MCPToolError as exc:
            # Capture the structured error code for the audit entry, then
            # re-raise so callers receive the original exception unchanged.
            audit_error_code = exc.error_code
            raise
        except Exception as exc:
            # Unexpected exception that escaped all internal handling.
            audit_error_code = type(exc).__name__
            raise
        finally:
            # 8. Audit log — guaranteed to run exactly once per invoke call,
            #    regardless of outcome (Requirement 12.1).
            timestamp_end = datetime.now(tz=UTC)
            if self._audit_logger is not None:
                entry = MCPAuditEntry(
                    tool_name=tool_name,
                    caller_identity=caller_identity,
                    param_hash=param_hash,
                    timestamp_start=timestamp_start,
                    timestamp_end=timestamp_end,
                    outcome=outcome,
                    error_code=audit_error_code,
                    finding_count=len(result.findings) if result is not None else 0,
                    confirmation_token_id=self._token_id(confirmation),
                    tool_manifest_hash=self.manifest_hash(),
                )
                try:
                    self._audit_logger.record(entry)
                except Exception as audit_exc:  # noqa: BLE001
                    # Audit failures must NEVER suppress the original invocation
                    # result or exception — log and continue.
                    logger.error(
                        "mcp_audit_write_failed",
                        tool_name=tool_name,
                        exc_type=type(audit_exc).__name__,
                        exc_message=str(audit_exc),
                    )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _token_id(confirmation: ConfirmationToken | None) -> str | None:
        """Return a deterministic opaque identifier for *confirmation*, or ``None``.

        Since :class:`~mcp_server.schemas.ConfirmationToken` has no explicit ID
        field, we derive one by SHA-256-hashing the concatenation of its three
        constituent fields.  Only the first 16 hex characters (64-bit prefix)
        are stored — sufficient for log correlation without leaking the full
        token data.
        """
        if confirmation is None:
            return None
        raw = (
            f"{confirmation.tool_name}:"
            f"{confirmation.confirmed_by}:"
            f"{confirmation.timestamp.isoformat()}"
        )
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @staticmethod
    def _validate_params(spec: MCPToolSpec, params: dict[str, Any]) -> None:
        """Validate *params* against *spec.input_schema*.

        Raises :class:`SchemaValidationError` on the first violation found.
        The handler is *not* called if this method raises.
        """
        try:
            jsonschema.validate(instance=params, schema=spec.input_schema)
        except jsonschema.exceptions.ValidationError as exc:
            raise SchemaValidationError(
                f"Parameter validation failed for tool '{spec.name}': {exc.message}"
            ) from exc
        except jsonschema.exceptions.SchemaError as exc:
            # The spec's own schema is malformed — surface as a tool error.
            raise MCPToolError(
                f"Tool '{spec.name}' has an invalid input_schema: {exc.message}",
                error_code="INVALID_SCHEMA",
            ) from exc
