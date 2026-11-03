"""
SafeModeGuard / DestructiveConfirmationGate isolation tests for concurrent
MCP tool invocations (Task 6.5).

Verifies Requirement 4.5:
    WHILE the MCP server is active, THE System SHALL prevent any MCP_Tool
    from modifying the SafeModeGuard configuration of another MCP_Tool in
    concurrent execution.

Design note — why this requirement is already satisfied
-------------------------------------------------------
``DestructiveConfirmationGate`` is effectively **immutable** after construction:

* ``allow_destructive`` is set once in ``__init__`` and never reassigned.
* ``check()`` is a **pure reader** — it reads ``self.allow_destructive`` and
  evaluates the arguments passed in (``tool_spec``, ``confirmation``).  No
  field is ever written during ``check()``.
* ``MCPToolRegistry.invoke()`` passes per-invocation data (params, confirmation
  token, tool spec) as local variables or arguments — it stores nothing on
  ``self`` that could leak across concurrent calls.

Therefore, two concurrent invocations that share the same gate instance
cannot mutate each other's state: there *is* no mutable per-invocation state
on the shared objects.  These tests document and enforce that guarantee.

Strategy
--------
All tests run in-process using ``asyncio.gather`` on a dedicated event loop
(same pattern as ``test_session_isolation.py``).  No real network transport is
needed — the registry's ``invoke`` method is the relevant in-process boundary.

**Validates: Requirement 4.5**
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import pytest

# Optional MCP SDK — skip the whole module if the library is absent.
mcp = pytest.importorskip("mcp")

from mcp_server.confirmation_gate import DestructiveConfirmationGate  # noqa: E402
from mcp_server.schemas import (  # noqa: E402
    ConfirmationRequiredError,
    ConfirmationToken,
    MCPToolError,
    MCPToolResult,
    MCPToolSpec,
)
from mcp_server.tool_registry import MCPToolRegistry  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass
class _CallRecord:
    """Tracks invocation counts and any attempt to mutate allow_destructive."""

    called: int = 0
    mutation_attempted: bool = False


def _run(coro) -> Any:
    """Execute *coro* on a dedicated event loop (no global loop side-effects)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _make_spec(
    name: str,
    *,
    is_destructive: bool,
    record: _CallRecord,
    delay: float = 0.0,
) -> MCPToolSpec:
    """Build a minimal ``MCPToolSpec`` whose handler records each call.

    The handler deliberately tries to inspect and optionally sleep so that
    concurrent invocations actually overlap in the event loop.
    """

    async def _handler(params: dict) -> MCPToolResult:  # noqa: ARG001
        if delay:
            await asyncio.sleep(delay)
        record.called += 1
        return MCPToolResult(
            tool_name=name,
            metadata={"invocation_count": record.called},
        )

    return MCPToolSpec(
        name=name,
        description=f"Isolation test tool — is_destructive={is_destructive}.",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        is_destructive=is_destructive,
        handler=_handler,
    )


def _valid_token(tool_name: str) -> ConfirmationToken:
    return ConfirmationToken(
        tool_name=tool_name,
        confirmed_by="test-operator",
        timestamp=datetime.utcnow(),
    )


_PARAMS: dict = {}


# ---------------------------------------------------------------------------
# Test 1 — Gate allow_destructive is fixed at construction; concurrent calls
#           cannot change it (Requirement 4.5)
# ---------------------------------------------------------------------------


def test_allow_destructive_flag_immutable_across_concurrent_invocations() -> None:
    """``allow_destructive`` on the shared gate must remain False throughout two
    concurrent invocations — one destructive (should be blocked), one
    non-destructive (should pass).

    Verifies that the non-destructive tool completing successfully does not
    somehow flip the gate's state and grant access to the destructive tool.

    **Validates: Requirement 4.5**
    """
    record_safe = _CallRecord()
    record_destructive = _CallRecord()

    safe_spec = _make_spec(
        "apileak.isolation.non_destructive",
        is_destructive=False,
        record=record_safe,
        delay=0.01,  # overlaps with the destructive invocation
    )
    destructive_spec = _make_spec(
        "apileak.isolation.destructive",
        is_destructive=True,
        record=record_destructive,
        delay=0.0,
    )

    # Shared gate in safe mode — destructive tools are unconditionally blocked.
    gate = DestructiveConfirmationGate(allow_destructive=False)
    registry = MCPToolRegistry(confirmation_gate=gate)
    registry.register(safe_spec)
    registry.register(destructive_spec)

    async def run():
        results = await asyncio.gather(
            registry.invoke("apileak.isolation.non_destructive", _PARAMS),
            registry.invoke("apileak.isolation.destructive", _PARAMS),
            return_exceptions=True,
        )
        return results

    result_safe, result_destructive = _run(run())

    # Non-destructive invocation must succeed.
    assert isinstance(result_safe, MCPToolResult), (
        f"Non-destructive tool must return MCPToolResult; got {type(result_safe)}"
    )
    assert record_safe.called == 1, "Non-destructive handler must be called once."

    # Destructive invocation must be blocked — safe mode was NOT modified.
    assert isinstance(result_destructive, MCPToolError), (
        f"Destructive tool in safe mode must raise MCPToolError; got {type(result_destructive)}"
    )
    assert result_destructive.error_code == "DESTRUCTIVE_NOT_ENABLED", (
        f"Error code must be DESTRUCTIVE_NOT_ENABLED; got {result_destructive.error_code!r}"
    )
    assert record_destructive.called == 0, (
        "Destructive handler must never be called in safe mode — "
        "SafeModeGuard state was unexpectedly mutated by the concurrent invocation!"
    )

    # The gate must still be in safe mode after both invocations complete.
    assert gate.allow_destructive is False, (
        "gate.allow_destructive must still be False after concurrent invocations — "
        "concurrent execution must not modify SafeModeGuard configuration!"
    )


# ---------------------------------------------------------------------------
# Test 2 — Two destructive tools with their own tokens: each is evaluated
#           independently, neither contaminates the other (Requirement 4.5)
# ---------------------------------------------------------------------------


def test_two_destructive_tools_independent_token_evaluation() -> None:
    """Two concurrent destructive invocations each supply their own token.
    Each must be evaluated against its own spec, with no cross-contamination.

    - Tool A receives the correct token → succeeds.
    - Tool B receives no token → blocked with ConfirmationRequiredError.

    If the gate were stateful (e.g. caching a token from one call and
    applying it to another), tool B might incorrectly succeed.

    **Validates: Requirement 4.5**
    """
    record_a = _CallRecord()
    record_b = _CallRecord()

    spec_a = _make_spec(
        "apileak.isolation.destructive_a",
        is_destructive=True,
        record=record_a,
        delay=0.01,
    )
    spec_b = _make_spec(
        "apileak.isolation.destructive_b",
        is_destructive=True,
        record=record_b,
        delay=0.0,
    )

    gate = DestructiveConfirmationGate(allow_destructive=True)
    registry = MCPToolRegistry(confirmation_gate=gate)
    registry.register(spec_a)
    registry.register(spec_b)

    token_for_a = _valid_token("apileak.isolation.destructive_a")

    async def run():
        return await asyncio.gather(
            registry.invoke(
                "apileak.isolation.destructive_a", _PARAMS, confirmation=token_for_a
            ),
            registry.invoke(
                "apileak.isolation.destructive_b", _PARAMS, confirmation=None
            ),
            return_exceptions=True,
        )

    result_a, result_b = _run(run())

    # Tool A (valid token) must succeed.
    assert isinstance(result_a, MCPToolResult), (
        f"Tool A with valid token must succeed; got {type(result_a)}"
    )
    assert record_a.called == 1, "Tool A handler must be called exactly once."

    # Tool B (no token) must be blocked — token from A must not leak to B.
    assert isinstance(result_b, ConfirmationRequiredError), (
        f"Tool B without a token must raise ConfirmationRequiredError; got {type(result_b)}"
    )
    assert result_b.tool_name == "apileak.isolation.destructive_b", (
        f"Error must name tool B; got {result_b.tool_name!r}"
    )
    assert record_b.called == 0, (
        "Tool B handler must never be called — confirmation token from Tool A "
        "must not contaminate Tool B's invocation!"
    )


# ---------------------------------------------------------------------------
# Test 3 — Many concurrent invocations: all see the same fixed gate state
#           (Requirement 4.5)
# ---------------------------------------------------------------------------


def test_many_concurrent_invocations_see_consistent_gate_state() -> None:
    """N concurrent non-destructive invocations all see allow_destructive=False
    as an immutable read — no race condition can produce a different outcome for
    any single invocation.

    All N invocations must complete successfully and each must call its handler
    exactly once.

    **Validates: Requirement 4.5**
    """
    N = 10
    records = [_CallRecord() for _ in range(N)]
    specs = [
        _make_spec(
            f"apileak.isolation.concurrent_{i}",
            is_destructive=False,
            record=records[i],
            delay=0.005,
        )
        for i in range(N)
    ]

    gate = DestructiveConfirmationGate(allow_destructive=False)
    registry = MCPToolRegistry(confirmation_gate=gate)
    for spec in specs:
        registry.register(spec)

    async def run():
        return await asyncio.gather(
            *[
                registry.invoke(f"apileak.isolation.concurrent_{i}", _PARAMS)
                for i in range(N)
            ],
            return_exceptions=True,
        )

    results = _run(run())

    for i, result in enumerate(results):
        assert isinstance(result, MCPToolResult), (
            f"Invocation {i} must return MCPToolResult; got {type(result)} — "
            "concurrent invocations must not interfere with each other's gate check."
        )
        assert records[i].called == 1, (
            f"Handler {i} must be called exactly once; called {records[i].called} times."
        )

    # Gate state must be unchanged after all concurrent invocations.
    assert gate.allow_destructive is False, (
        "Concurrent invocations must not modify gate.allow_destructive!"
    )


# ---------------------------------------------------------------------------
# Test 4 — Interleaved destructive (blocked) and non-destructive (pass)
#           do not affect each other's outcome (Requirement 4.5)
# ---------------------------------------------------------------------------


def test_interleaved_destructive_and_safe_invocations_isolated() -> None:
    """Rapid interleaving of blocked destructive and passing non-destructive
    invocations must produce the correct outcome for each without any bleed.

    Uses ``asyncio.gather`` with return_exceptions=True so both outcomes are
    captured without the test aborting on the expected error.

    **Validates: Requirement 4.5**
    """
    record_nd = _CallRecord()  # non-destructive
    record_d = _CallRecord()   # destructive

    nd_spec = _make_spec(
        "apileak.isolation.interleaved_nd",
        is_destructive=False,
        record=record_nd,
        delay=0.005,
    )
    d_spec = _make_spec(
        "apileak.isolation.interleaved_d",
        is_destructive=True,
        record=record_d,
        delay=0.0,
    )

    gate = DestructiveConfirmationGate(allow_destructive=False)
    registry = MCPToolRegistry(confirmation_gate=gate)
    registry.register(nd_spec)
    registry.register(d_spec)

    async def run():
        # Interleave: start non-destructive (slow), immediately followed by
        # destructive (fast) — the destructive one resolves first, then
        # the non-destructive one finishes.
        return await asyncio.gather(
            registry.invoke("apileak.isolation.interleaved_nd", _PARAMS),
            registry.invoke("apileak.isolation.interleaved_d", _PARAMS),
            registry.invoke("apileak.isolation.interleaved_nd", _PARAMS),
            registry.invoke("apileak.isolation.interleaved_d", _PARAMS),
            return_exceptions=True,
        )

    r_nd1, r_d1, r_nd2, r_d2 = _run(run())

    # Both non-destructive invocations must succeed.
    for idx, result in enumerate([r_nd1, r_nd2], start=1):
        assert isinstance(result, MCPToolResult), (
            f"Non-destructive invocation {idx} must return MCPToolResult; "
            f"got {type(result)}"
        )

    # Both destructive invocations must be blocked.
    for idx, result in enumerate([r_d1, r_d2], start=1):
        assert isinstance(result, MCPToolError), (
            f"Destructive invocation {idx} must be blocked; got {type(result)}"
        )
        assert result.error_code == "DESTRUCTIVE_NOT_ENABLED", (
            f"Destructive invocation {idx} must report DESTRUCTIVE_NOT_ENABLED; "
            f"got {result.error_code!r}"
        )

    # Invocation counts reflect actual handler calls.
    assert record_nd.called == 2, (
        f"Non-destructive handler must be called twice; got {record_nd.called}"
    )
    assert record_d.called == 0, (
        "Destructive handler must never be called in safe mode — "
        f"but was called {record_d.called} time(s)."
    )

    # Gate is unchanged.
    assert gate.allow_destructive is False


# ---------------------------------------------------------------------------
# Test 5 — Gate.check() is a pure reader: no mutation of self during check
#           (documents the statelessness guarantee — Requirement 4.5)
# ---------------------------------------------------------------------------


def test_gate_check_does_not_mutate_allow_destructive() -> None:
    """``DestructiveConfirmationGate.check()`` must not write to ``self`` for
    any combination of inputs.  This is the key structural guarantee behind
    Requirement 4.5.

    Verified by calling ``check()`` many times with varying inputs and
    asserting ``allow_destructive`` is unchanged after every call.

    **Validates: Requirement 4.5**
    """

    async def _noop_handler(params: dict) -> MCPToolResult:
        return MCPToolResult(tool_name="noop")

    destructive_spec = MCPToolSpec(
        name="apileak.isolation.gate_purity_d",
        description="Gate purity test — destructive.",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        is_destructive=True,
        handler=_noop_handler,
    )
    non_destructive_spec = MCPToolSpec(
        name="apileak.isolation.gate_purity_nd",
        description="Gate purity test — non-destructive.",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        is_destructive=False,
        handler=_noop_handler,
    )

    for allow_destructive_initial in (True, False):
        gate = DestructiveConfirmationGate(allow_destructive=allow_destructive_initial)
        initial_state = gate.allow_destructive

        # Call check() in ways that raise and ways that pass.
        calls: list[tuple] = [
            (non_destructive_spec, None),
            (non_destructive_spec, _valid_token("apileak.isolation.gate_purity_nd")),
            (destructive_spec, None),  # raises — but must not mutate
            (destructive_spec, _valid_token("apileak.isolation.gate_purity_d")),
        ]

        for spec, token in calls:
            try:
                gate.check(spec, token)
            except MCPToolError:
                pass  # expected for certain combinations — we only care about mutation

            assert gate.allow_destructive is initial_state, (
                f"gate.allow_destructive changed from {initial_state!r} to "
                f"{gate.allow_destructive!r} after check(spec={spec.name!r}, "
                f"token={token!r}).  check() must be a pure reader!"
            )


# ---------------------------------------------------------------------------
# Test 6 — Separate registry instances with different gates do not share state
#           (Requirement 4.5 — process-level isolation)
# ---------------------------------------------------------------------------


def test_separate_registry_instances_have_independent_gate_state() -> None:
    """Two ``MCPToolRegistry`` instances with different ``allow_destructive``
    settings must produce independent outcomes for concurrent invocations of
    the same logical tool.

    This models two hypothetical server processes (or test fixtures) running
    concurrently — their SafeModeGuard configs must remain isolated.

    **Validates: Requirement 4.5**
    """
    record_safe = _CallRecord()
    record_destructive = _CallRecord()

    # Same logical tool, different registry instances.
    TOOL_NAME = "apileak.isolation.shared_name"

    safe_registry = MCPToolRegistry(
        confirmation_gate=DestructiveConfirmationGate(allow_destructive=False)
    )
    safe_registry.register(
        _make_spec(TOOL_NAME, is_destructive=True, record=record_safe)
    )

    destructive_registry = MCPToolRegistry(
        confirmation_gate=DestructiveConfirmationGate(allow_destructive=True)
    )
    destructive_registry.register(
        _make_spec(TOOL_NAME, is_destructive=True, record=record_destructive)
    )

    token = _valid_token(TOOL_NAME)

    async def run():
        return await asyncio.gather(
            safe_registry.invoke(TOOL_NAME, _PARAMS, confirmation=token),
            destructive_registry.invoke(TOOL_NAME, _PARAMS, confirmation=token),
            return_exceptions=True,
        )

    result_safe_reg, result_destructive_reg = _run(run())

    # The safe registry must block even with a token.
    assert isinstance(result_safe_reg, MCPToolError), (
        f"Safe registry must block destructive tool; got {type(result_safe_reg)}"
    )
    assert result_safe_reg.error_code == "DESTRUCTIVE_NOT_ENABLED"
    assert record_safe.called == 0

    # The destructive registry must allow with a valid token.
    assert isinstance(result_destructive_reg, MCPToolResult), (
        f"Destructive registry with valid token must succeed; got {type(result_destructive_reg)}"
    )
    assert record_destructive.called == 1
