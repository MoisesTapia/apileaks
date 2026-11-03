"""
Session isolation tests for concurrent MCP tool invocations (Task 3.4).

Verifies Requirements 14.1, 14.2, 14.3 — OWASP MCP10:

  14.1  Simultaneous invocations from two distinct clients must not share
        Findings, scan state, progress variables, or ConfirmationTokens.

  14.2  Once an invocation finishes (success or error), the execution state
        associated with it must be released before the slot is available for
        a new invocation.

  14.3  At least one concurrency test launches two simultaneous tool
        invocations and verifies the Findings from each are exclusive to
        their own session.

Strategy
--------
All tests run in-process without a real network transport.  The
``MCPToolRegistry`` is used directly as the "in-memory MCP client" — this
follows the same pattern established in test_mcp_contract.py and reflects
the principle stated in Requirement 11.1 that the registry's ``invoke``
method *is* the in-process contract boundary.

``asyncio.gather`` is used to run two coroutines in the same event loop
concurrently, which faithfully exercises any shared-state bugs that would
manifest in an asyncio-based HTTP server handling two simultaneous requests.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import pytest

# Optional MCP SDK — skip the whole module if the library is absent.
mcp = pytest.importorskip("mcp")

from mcp_server.confirmation_gate import DestructiveConfirmationGate  # noqa: E402
from mcp_server.schemas import (  # noqa: E402
    ConfirmationRequiredError,
    ConfirmationToken,
    MCPServerConfig,
    MCPToolError,
    MCPToolResult,
    MCPToolSpec,
    SchemaValidationError,
)
from mcp_server.server import APILeakMCPServer  # noqa: E402
from mcp_server.tool_registry import MCPToolRegistry  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass
class _MockFinding:
    """Minimal stand-in for a real APILeak Finding sufficient for isolation tests."""

    finding_id: str
    source_tool: str


def _run(coro) -> Any:
    """Run a coroutine on a dedicated event loop without touching the global one."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _make_tool_spec(
    name: str,
    *,
    finding_id: str,
    delay_seconds: float = 0.0,
    is_destructive: bool = False,
) -> MCPToolSpec:
    """Build a deterministic MCPToolSpec whose handler returns a single Finding.

    The handler sleeps for *delay_seconds* before returning, allowing two
    coroutines that call ``asyncio.gather`` to overlap meaningfully and expose
    any shared-state bugs.

    Args:
        name: Registered tool name (must start with ``apileak.``).
        finding_id: Unique identifier embedded in the returned Finding; used
            to verify that results from one tool never appear in another's output.
        delay_seconds: How long the handler sleeps before returning.  When two
            tools are invoked concurrently with different delays, the second
            tool's result is available before the first's, ensuring the test
            exercises true concurrency rather than sequential execution.
        is_destructive: Whether the tool should require a ConfirmationToken.
    """

    async def _handler(params: dict) -> MCPToolResult:  # noqa: ARG001
        if delay_seconds > 0:
            await asyncio.sleep(delay_seconds)
        finding = _MockFinding(finding_id=finding_id, source_tool=name)
        return MCPToolResult(
            tool_name=name,
            findings=[finding],
            metadata={"source_finding_id": finding_id},
        )

    return MCPToolSpec(
        name=name,
        description=f"Test tool — always returns finding '{finding_id}'.",
        input_schema={
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
            "additionalProperties": False,
        },
        output_schema={"type": "object"},
        is_destructive=is_destructive,
        handler=_handler,
    )


_VALID_PARAMS = {"target": "https://example.com"}


# ---------------------------------------------------------------------------
# Test 1 — Concurrent invocations produce separate, non-overlapping Finding sets
#           (Requirement 14.3)
# ---------------------------------------------------------------------------


def test_concurrent_invocations_produce_separate_findings() -> None:
    """Two simultaneous tool invocations must return completely separate Findings.

    Uses asyncio.gather() to run both invocations in the same event loop so
    that they genuinely overlap (tool_a sleeps briefly, allowing tool_b to
    run concurrently).  The test verifies:

    - result_a contains exactly the Finding produced by tool_a (id="finding_A")
    - result_b contains exactly the Finding produced by tool_b (id="finding_B")
    - Neither result contains the other tool's Finding

    **Validates: Requirements 14.1, 14.3**
    """
    registry = MCPToolRegistry()
    registry.register(
        _make_tool_spec("apileak.test.tool_a", finding_id="finding_A", delay_seconds=0.01)
    )
    registry.register(
        _make_tool_spec("apileak.test.tool_b", finding_id="finding_B", delay_seconds=0.0)
    )

    async def run_concurrent():
        return await asyncio.gather(
            registry.invoke("apileak.test.tool_a", _VALID_PARAMS, confirmation=None),
            registry.invoke("apileak.test.tool_b", _VALID_PARAMS, confirmation=None),
        )

    result_a, result_b = _run(run_concurrent())

    # Each result must have exactly one finding.
    assert len(result_a.findings) == 1, (
        f"tool_a must return exactly 1 finding; got {len(result_a.findings)}"
    )
    assert len(result_b.findings) == 1, (
        f"tool_b must return exactly 1 finding; got {len(result_b.findings)}"
    )

    # The findings must belong to the correct tool's result.
    assert result_a.findings[0].finding_id == "finding_A", (
        f"result_a must contain finding_A; got {result_a.findings[0].finding_id!r}"
    )
    assert result_b.findings[0].finding_id == "finding_B", (
        f"result_b must contain finding_B; got {result_b.findings[0].finding_id!r}"
    )

    # Confirm cross-contamination did not occur.
    a_ids = {f.finding_id for f in result_a.findings}
    b_ids = {f.finding_id for f in result_b.findings}
    assert a_ids.isdisjoint(b_ids), (
        f"Finding sets must be disjoint; overlap = {a_ids & b_ids}"
    )


# ---------------------------------------------------------------------------
# Test 2 — Scan state / metadata from invocation A not present in result of B
#           (Requirement 14.1)
# ---------------------------------------------------------------------------


def test_invocation_state_not_shared_between_sessions() -> None:
    """Metadata and raw_output produced by invocation A must not appear in B.

    Verifies that the MCPToolRegistry does not accumulate per-invocation state
    that bleeds across calls.  Both invocations run concurrently; Tool A embeds
    a large unique payload in its metadata; Tool B's result must be completely
    free of that payload.

    **Validates: Requirements 14.1, 14.2**
    """
    sentinel_a = "UNIQUE_SESSION_TOKEN_FOR_TOOL_A_XYZ_12345"
    sentinel_b = "UNIQUE_SESSION_TOKEN_FOR_TOOL_B_ABC_67890"

    async def _handler_a(params: dict) -> MCPToolResult:  # noqa: ARG001
        await asyncio.sleep(0.01)
        return MCPToolResult(
            tool_name="apileak.test.stateful_a",
            findings=[_MockFinding(finding_id=sentinel_a, source_tool="stateful_a")],
            metadata={"session_secret": sentinel_a, "findings_list": [sentinel_a]},
            raw_output=f"Result from A: {sentinel_a}",
        )

    async def _handler_b(params: dict) -> MCPToolResult:  # noqa: ARG001
        return MCPToolResult(
            tool_name="apileak.test.stateful_b",
            findings=[_MockFinding(finding_id=sentinel_b, source_tool="stateful_b")],
            metadata={"session_secret": sentinel_b, "findings_list": [sentinel_b]},
            raw_output=f"Result from B: {sentinel_b}",
        )

    spec_a = MCPToolSpec(
        name="apileak.test.stateful_a",
        description="Stateful test tool A.",
        input_schema={
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
            "additionalProperties": False,
        },
        output_schema={"type": "object"},
        is_destructive=False,
        handler=_handler_a,
    )
    spec_b = MCPToolSpec(
        name="apileak.test.stateful_b",
        description="Stateful test tool B.",
        input_schema={
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
            "additionalProperties": False,
        },
        output_schema={"type": "object"},
        is_destructive=False,
        handler=_handler_b,
    )

    registry = MCPToolRegistry()
    registry.register(spec_a)
    registry.register(spec_b)

    async def run_concurrent():
        return await asyncio.gather(
            registry.invoke("apileak.test.stateful_a", _VALID_PARAMS, confirmation=None),
            registry.invoke("apileak.test.stateful_b", _VALID_PARAMS, confirmation=None),
        )

    result_a, result_b = _run(run_concurrent())

    # result_b must contain no trace of A's sentinel value.
    assert sentinel_a not in str(result_b.metadata), (
        f"result_b metadata must not contain sentinel_a ({sentinel_a!r}); "
        f"got metadata: {result_b.metadata}"
    )
    assert result_b.raw_output is None or sentinel_a not in result_b.raw_output, (
        f"result_b raw_output must not contain sentinel_a; got: {result_b.raw_output!r}"
    )
    b_finding_ids = {f.finding_id for f in result_b.findings}
    assert sentinel_a not in b_finding_ids, (
        f"result_b findings must not contain sentinel_a; got IDs: {b_finding_ids}"
    )

    # result_a must contain no trace of B's sentinel value.
    assert sentinel_b not in str(result_a.metadata), (
        f"result_a metadata must not contain sentinel_b ({sentinel_b!r}); "
        f"got metadata: {result_a.metadata}"
    )
    a_finding_ids = {f.finding_id for f in result_a.findings}
    assert sentinel_b not in a_finding_ids, (
        f"result_a findings must not contain sentinel_b; got IDs: {a_finding_ids}"
    )


# ---------------------------------------------------------------------------
# Test 3 — Registry accumulates no per-invocation state across calls
#           (Requirement 14.2)
# ---------------------------------------------------------------------------


def test_registry_does_not_accumulate_per_invocation_state() -> None:
    """The MCPToolRegistry must not retain execution state after each invocation.

    Verifies that:
    1. The number of registered tools does not change after invocations.
    2. A subsequent invocation after a completed one returns a fresh, independent
       result — the previous invocation's findings do not appear.

    This reflects Requirement 14.2: execution state is released after each
    invocation completes so the slot is clean for new invocations.

    **Validates: Requirements 14.2**
    """
    registry = MCPToolRegistry()
    registry.register(
        _make_tool_spec("apileak.test.stateless", finding_id="inv_finding")
    )

    tools_before = len(registry.list_tools())

    async def run_sequential():
        result1 = await registry.invoke("apileak.test.stateless", _VALID_PARAMS, confirmation=None)
        result2 = await registry.invoke("apileak.test.stateless", _VALID_PARAMS, confirmation=None)
        return result1, result2

    result1, result2 = _run(run_sequential())

    # Registry tool count must be unchanged after invocations.
    tools_after = len(registry.list_tools())
    assert tools_before == tools_after, (
        f"Registry tool count changed after invocations: {tools_before} → {tools_after}. "
        "Per-invocation state must not be retained in the registry."
    )

    # Each invocation must return exactly its own finding (no accumulation).
    assert len(result1.findings) == 1, (
        f"First invocation returned {len(result1.findings)} findings; expected 1"
    )
    assert len(result2.findings) == 1, (
        f"Second invocation returned {len(result2.findings)} findings; expected 1. "
        "Findings from the first invocation must not leak into the second."
    )

    # Findings from both calls are independent objects (not the same reference).
    assert result1.findings is not result2.findings, (
        "Each invocation must return an independent findings list; "
        "shared reference detected."
    )


def test_active_tasks_set_does_not_retain_completed_tasks_after_shutdown() -> None:
    """Completed tasks in _active_tasks do not interfere with a subsequent shutdown.

    The server's _active_tasks set is used to cancel in-flight work during
    shutdown.  This test verifies that tasks which complete naturally before
    shutdown are handled gracefully (not double-cancelled) and do not prevent
    the shutdown event from being set.

    This is a proxy for Requirement 14.2: the server's accounting of active
    work does not accumulate stale completed entries that could incorrectly
    represent lingering state from a previous invocation.

    **Validates: Requirements 14.2**
    """
    config = MCPServerConfig(transport="stdio")
    server = APILeakMCPServer(transport="stdio", config=config)

    async def run():
        loop = asyncio.get_event_loop()

        # Simulate two tool invocations tracked as tasks — one completes before
        # shutdown, one is still running when shutdown arrives.
        async def fast_task():
            return "done"

        async def slow_task():
            await asyncio.sleep(9999)

        t_fast = loop.create_task(fast_task())
        t_slow = loop.create_task(slow_task())

        server._active_tasks.add(t_fast)
        server._active_tasks.add(t_slow)

        # Allow fast_task to complete naturally.
        await t_fast

        # Now trigger shutdown.
        await server.shutdown()

        # The shutdown event must be set.
        assert server._shutdown_event.is_set(), "_shutdown_event must be set after shutdown()"

        # The slow task must have been cancelled (it was still in-flight).
        assert t_slow.cancelled(), "Slow in-flight task must be cancelled on shutdown"

        # The fast task completed before shutdown — it must not raise when checked.
        assert t_fast.done() and not t_fast.cancelled(), (
            "Fast completed task must still be done (not re-cancelled) after shutdown"
        )

    _run(run())


# ---------------------------------------------------------------------------
# Test 4 — ConfirmationTokens are not shared between invocations
#           (Requirement 14.1, Property 1)
# ---------------------------------------------------------------------------


def test_confirmation_token_for_tool_a_does_not_authorise_tool_b() -> None:
    """A ConfirmationToken issued for tool A must not satisfy the gate for tool B.

    DestructiveConfirmationGate checks the token's ``tool_name`` field against
    the spec being invoked.  This test confirms that the gate is stateless and
    per-invocation — possessing a valid token for any *other* tool does not
    grant access to a destructive tool.

    **Validates: Requirements 14.1, 4.1, 4.2**
    """
    gate = DestructiveConfirmationGate(allow_destructive=True)

    spec_a = MCPToolSpec(
        name="apileak.test.destructive_a",
        description="Destructive test tool A.",
        input_schema={"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        output_schema={"type": "object"},
        is_destructive=True,
        handler=lambda p: None,  # type: ignore[arg-type]
    )
    spec_b = MCPToolSpec(
        name="apileak.test.destructive_b",
        description="Destructive test tool B.",
        input_schema={"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        output_schema={"type": "object"},
        is_destructive=True,
        handler=lambda p: None,  # type: ignore[arg-type]
    )

    # A token issued for tool A.
    token_for_a = ConfirmationToken(
        tool_name="apileak.test.destructive_a",
        confirmed_by="human_operator",
        timestamp=datetime.utcnow(),
    )

    # The token must authorise tool A ...
    gate.check(spec_a, token_for_a)  # must not raise

    # ... but must NOT authorise tool B.
    with pytest.raises(ConfirmationRequiredError) as exc_info:
        gate.check(spec_b, token_for_a)

    assert exc_info.value.tool_name == "apileak.test.destructive_b", (
        "ConfirmationRequiredError must name the tool that was blocked, not the token's tool"
    )


def test_confirmation_gate_is_stateless_across_concurrent_checks() -> None:
    """The gate produces consistent per-invocation decisions when called concurrently.

    Two concurrent invocations of a destructive tool each receive their own
    ConfirmationToken.  The test verifies via asyncio.gather that:
    - The invocation that provides the correct token succeeds.
    - The invocation that provides no token raises ConfirmationRequiredError.
    - The two outcomes are independent and do not cross-contaminate.

    **Validates: Requirements 14.1, 4.1**
    """
    from mcp_server.confirmation_gate import DestructiveConfirmationGate

    call_log: list[str] = []

    async def _handler_destructive(params: dict) -> MCPToolResult:  # noqa: ARG001
        call_log.append("handler_called")
        return MCPToolResult(
            tool_name="apileak.test.gated",
            findings=[_MockFinding(finding_id="gated_finding", source_tool="gated")],
        )

    spec = MCPToolSpec(
        name="apileak.test.gated",
        description="Destructive tool for gate concurrency test.",
        input_schema={
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
            "additionalProperties": False,
        },
        output_schema={"type": "object"},
        is_destructive=True,
        handler=_handler_destructive,
    )

    # allow_destructive=True so we reach Tier 2 (token check) rather than
    # being blocked by Tier 1 (process-level safe-mode).  This tests that
    # the gate correctly distinguishes between a valid and a missing token
    # in concurrent calls.
    gate = DestructiveConfirmationGate(allow_destructive=True)
    registry = MCPToolRegistry(confirmation_gate=gate)
    registry.register(spec)

    valid_token = ConfirmationToken(
        tool_name="apileak.test.gated",
        confirmed_by="concurrent_test_operator",
        timestamp=datetime.utcnow(),
    )

    async def invoke_with_token():
        return await registry.invoke("apileak.test.gated", _VALID_PARAMS, confirmation=valid_token)

    async def invoke_without_token():
        return await registry.invoke("apileak.test.gated", _VALID_PARAMS, confirmation=None)

    async def run_concurrent():
        # gather returns exceptions rather than raising when return_exceptions=True
        results = await asyncio.gather(
            invoke_with_token(),
            invoke_without_token(),
            return_exceptions=True,
        )
        return results

    outcomes = _run(run_concurrent())

    # Invocation with a valid token must succeed.
    result_authorised = outcomes[0]
    assert isinstance(result_authorised, MCPToolResult), (
        f"Authorised invocation must return MCPToolResult; got {type(result_authorised)}"
    )
    assert len(result_authorised.findings) == 1

    # Invocation without a token must be refused.
    result_refused = outcomes[1]
    assert isinstance(result_refused, ConfirmationRequiredError), (
        f"Unauthorised invocation must raise ConfirmationRequiredError; "
        f"got {type(result_refused)}"
    )

    # The handler must have been called exactly once (only the authorised invocation).
    assert call_log == ["handler_called"], (
        f"Handler must be called exactly once (by the authorised invocation); "
        f"call_log = {call_log}"
    )


def test_confirmation_token_from_one_session_not_reused_in_next() -> None:
    """A ConfirmationToken must not persist between sequential invocations.

    The registry passes the ``confirmation`` argument directly to each
    invocation without caching it.  This test verifies that providing a token
    in call 1 does not grant access to call 2 (which provides no token).

    **Validates: Requirements 14.1, 14.2, 4.1**
    """
    from mcp_server.confirmation_gate import DestructiveConfirmationGate

    # allow_destructive=True so we reach Tier 2 (token check).
    gate = DestructiveConfirmationGate(allow_destructive=True)
    registry = MCPToolRegistry(confirmation_gate=gate)
    registry.register(
        _make_tool_spec("apileak.test.destructive_seq", finding_id="seq_finding", is_destructive=True)
    )

    valid_token = ConfirmationToken(
        tool_name="apileak.test.destructive_seq",
        confirmed_by="operator",
        timestamp=datetime.utcnow(),
    )

    async def run():
        # First call: with a valid token → must succeed.
        result = await registry.invoke(
            "apileak.test.destructive_seq", _VALID_PARAMS, confirmation=valid_token
        )
        assert isinstance(result, MCPToolResult)

        # Second call: no token provided → must be refused, regardless of first call.
        with pytest.raises(ConfirmationRequiredError):
            await registry.invoke(
                "apileak.test.destructive_seq", _VALID_PARAMS, confirmation=None
            )

    _run(run())
