"""
Tests for Task 5.2 — progress degradation to complete result when the
transport does not support streaming.

Verifies Requirement 3.3:
    WHEN the transport in use does not support native streaming, THE System
    SHALL degrade to returning the complete final result without failing the
    invocation.

Coverage:
1. ``as_final_result_summary()`` correctly serialises all accumulated updates.
2. With ``supports_streaming=False``, ``MCPToolRegistry.invoke`` attaches the
   progress summary to ``result.metadata["progress_summary"]``.
3. With ``supports_streaming=True``, ``result.metadata`` does NOT contain a
   ``progress_summary`` key (progress was already streamed live).
4. With no ``progress_stream`` at all, the invocation still succeeds and
   ``metadata`` has no ``progress_summary``.
5. Degraded invocation succeeds even when zero updates were emitted (empty
   progress stream still returns a valid result).
6. Degraded invocation succeeds even when multiple updates have been emitted
   (all phases included in the summary).
7. ``as_final_result_summary()`` always returns an identical snapshot — calling
   it twice on the same stream gives the same result.

The MCP SDK is an optional dependency.  ``pytest.importorskip("mcp")`` at
module level ensures the tests are skipped gracefully when the SDK is absent.

All tests are fully self-contained — no real network calls, no real scan engine.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

# Skip the whole module if the optional MCP SDK is not installed (Req 11.3).
mcp = pytest.importorskip("mcp")

from mcp_server.progress import ProgressUpdate, ToolProgressStream  # noqa: E402
from mcp_server.schemas import MCPToolResult, MCPToolSpec  # noqa: E402
from mcp_server.tool_registry import MCPToolRegistry  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PERMISSIVE_SCHEMA: dict[str, Any] = {"type": "object"}


def _make_spec(
    name: str = "test.tool",
    *,
    stream: ToolProgressStream | None = None,
    extra_findings: int = 0,
) -> MCPToolSpec:
    """Build a simple MCPToolSpec whose handler optionally emits progress.

    If *stream* is provided the handler will emit two progress updates before
    returning so that the stream has accumulated data regardless of whether
    streaming is active.
    """

    async def _handler(params: dict[str, Any]) -> MCPToolResult:
        if stream is not None:
            await stream.emit("phase_one", 0, 50.0)
            await stream.emit("phase_two", extra_findings, 100.0, extra={"note": "done"})
        return MCPToolResult(
            tool_name=name,
            findings=[object() for _ in range(extra_findings)],
        )

    return MCPToolSpec(
        name=name,
        description="Test tool for progress degradation tests.",
        input_schema=_PERMISSIVE_SCHEMA,
        output_schema={"type": "object"},
        is_destructive=False,
        handler=_handler,
    )


def _run(coro: Any) -> Any:
    """Thin helper to run a coroutine synchronously in a test."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# 1. as_final_result_summary() serialisation
# ---------------------------------------------------------------------------


class TestAsFinalResultSummary:
    def test_empty_stream_returns_zero_updates(self) -> None:
        stream = ToolProgressStream(supports_streaming=False)
        summary = stream.as_final_result_summary()

        assert summary["update_count"] == 0
        assert summary["phases"] == []

    def test_summary_contains_all_emitted_phases(self) -> None:
        async def _go() -> dict:
            stream = ToolProgressStream(supports_streaming=False)
            await stream.emit("discovery", 0, 25.0)
            await stream.emit("owasp_testing", 7, 75.0)
            await stream.emit("results", 7, 100.0)
            return stream.as_final_result_summary()

        summary = _run(_go())

        assert summary["update_count"] == 3
        phases = summary["phases"]
        assert len(phases) == 3
        assert [p["phase"] for p in phases] == ["discovery", "owasp_testing", "results"]

    def test_summary_phase_has_all_required_fields(self) -> None:
        async def _go() -> dict:
            stream = ToolProgressStream(supports_streaming=False)
            await stream.emit("discovery", 5, 33.3, extra={"endpoints": 12})
            return stream.as_final_result_summary()

        summary = _run(_go())
        phase = summary["phases"][0]

        assert phase["phase"] == "discovery"
        assert phase["findings_count"] == 5
        assert phase["percent_complete"] == 33.3
        assert phase["extra"] == {"endpoints": 12}

    def test_summary_none_percent_is_preserved(self) -> None:
        async def _go() -> dict:
            stream = ToolProgressStream(supports_streaming=False)
            await stream.emit("fuzzing", 0, None)
            return stream.as_final_result_summary()

        summary = _run(_go())
        assert summary["phases"][0]["percent_complete"] is None

    def test_summary_is_stable_across_two_calls(self) -> None:
        """Calling as_final_result_summary() twice returns identical results."""

        async def _go():
            stream = ToolProgressStream(supports_streaming=False)
            await stream.emit("phase_a", 1, 50.0)
            return stream.as_final_result_summary(), stream.as_final_result_summary()

        first, second = _run(_go())
        assert first == second

    def test_summary_works_on_streaming_true_stream(self) -> None:
        """as_final_result_summary() is available regardless of supports_streaming."""

        async def _go() -> dict:
            async def _noop(u: ProgressUpdate) -> None:
                pass

            stream = ToolProgressStream(callback=_noop, supports_streaming=True)
            await stream.emit("p1", 0, 50.0)
            return stream.as_final_result_summary()

        summary = _run(_go())
        # The update was forwarded live but is also in the accumulation buffer.
        assert summary["update_count"] == 1


# ---------------------------------------------------------------------------
# 2. invoke() attaches progress_summary when supports_streaming=False
# ---------------------------------------------------------------------------


class TestInvokeDegradationNonStreaming:
    def test_result_metadata_contains_progress_summary(self) -> None:
        async def _go() -> MCPToolResult:
            stream = ToolProgressStream(supports_streaming=False)
            registry = MCPToolRegistry()
            registry.register(_make_spec(stream=stream))
            return await registry.invoke("test.tool", {}, progress_stream=stream)

        result = _run(_go())

        assert "progress_summary" in result.metadata

    def test_progress_summary_update_count_matches_emitted(self) -> None:
        async def _go() -> MCPToolResult:
            stream = ToolProgressStream(supports_streaming=False)
            registry = MCPToolRegistry()
            registry.register(_make_spec(stream=stream))
            return await registry.invoke("test.tool", {}, progress_stream=stream)

        result = _run(_go())
        # _make_spec handler emits exactly 2 updates.
        assert result.metadata["progress_summary"]["update_count"] == 2

    def test_progress_summary_phases_list_has_correct_length(self) -> None:
        async def _go() -> MCPToolResult:
            stream = ToolProgressStream(supports_streaming=False)
            registry = MCPToolRegistry()
            registry.register(_make_spec(stream=stream))
            return await registry.invoke("test.tool", {}, progress_stream=stream)

        result = _run(_go())
        phases = result.metadata["progress_summary"]["phases"]
        assert len(phases) == 2
        assert phases[0]["phase"] == "phase_one"
        assert phases[1]["phase"] == "phase_two"

    def test_invocation_succeeds_no_exception_raised(self) -> None:
        async def _go() -> MCPToolResult:
            stream = ToolProgressStream(supports_streaming=False)
            registry = MCPToolRegistry()
            registry.register(_make_spec(stream=stream))
            return await registry.invoke("test.tool", {}, progress_stream=stream)

        # Should not raise anything.
        result = _run(_go())
        assert result.tool_name == "test.tool"

    def test_empty_stream_summary_still_attached(self) -> None:
        """Even a stream with zero emits gets a progress_summary (empty list)."""

        async def _handler(params: dict) -> MCPToolResult:
            return MCPToolResult(tool_name="test.tool")

        async def _go() -> MCPToolResult:
            stream = ToolProgressStream(supports_streaming=False)
            spec = MCPToolSpec(
                name="test.tool",
                description="no-op",
                input_schema=_PERMISSIVE_SCHEMA,
                output_schema={"type": "object"},
                is_destructive=False,
                handler=_handler,
            )
            registry = MCPToolRegistry()
            registry.register(spec)
            return await registry.invoke("test.tool", {}, progress_stream=stream)

        result = _run(_go())
        summary = result.metadata["progress_summary"]
        assert summary["update_count"] == 0
        assert summary["phases"] == []

    def test_existing_metadata_preserved_alongside_summary(self) -> None:
        """MCPToolResult metadata set by the handler is not overwritten."""

        async def _handler(params: dict) -> MCPToolResult:
            return MCPToolResult(
                tool_name="test.tool",
                metadata={"custom_key": "custom_value"},
            )

        async def _go() -> MCPToolResult:
            stream = ToolProgressStream(supports_streaming=False)
            spec = MCPToolSpec(
                name="test.tool",
                description="no-op",
                input_schema=_PERMISSIVE_SCHEMA,
                output_schema={"type": "object"},
                is_destructive=False,
                handler=_handler,
            )
            registry = MCPToolRegistry()
            registry.register(spec)
            return await registry.invoke("test.tool", {}, progress_stream=stream)

        result = _run(_go())
        # Original handler metadata must still be present.
        assert result.metadata["custom_key"] == "custom_value"
        # Progress summary is added alongside it.
        assert "progress_summary" in result.metadata


# ---------------------------------------------------------------------------
# 3. invoke() does NOT attach progress_summary when supports_streaming=True
# ---------------------------------------------------------------------------


class TestInvokeNoSummaryWhenStreaming:
    def test_no_progress_summary_when_streaming_active(self) -> None:
        async def _go() -> MCPToolResult:
            received: list[ProgressUpdate] = []

            async def _cb(u: ProgressUpdate) -> None:
                received.append(u)

            stream = ToolProgressStream(callback=_cb, supports_streaming=True)
            registry = MCPToolRegistry()
            registry.register(_make_spec(stream=stream))
            return await registry.invoke("test.tool", {}, progress_stream=stream)

        result = _run(_go())
        assert "progress_summary" not in result.metadata

    def test_streaming_callbacks_were_fired_live(self) -> None:
        """When streaming=True, the callback receives updates during execution."""

        async def _go() -> list[ProgressUpdate]:
            fired: list[ProgressUpdate] = []

            async def _cb(u: ProgressUpdate) -> None:
                fired.append(u)

            stream = ToolProgressStream(callback=_cb, supports_streaming=True)
            registry = MCPToolRegistry()
            registry.register(_make_spec(stream=stream))
            await registry.invoke("test.tool", {}, progress_stream=stream)
            return fired

        fired = _run(_go())
        assert len(fired) == 2
        assert fired[0].phase == "phase_one"
        assert fired[1].phase == "phase_two"


# ---------------------------------------------------------------------------
# 4. invoke() with no progress_stream — unchanged behaviour
# ---------------------------------------------------------------------------


class TestInvokeNoProgressStream:
    def test_invocation_succeeds_without_stream(self) -> None:
        async def _go() -> MCPToolResult:
            registry = MCPToolRegistry()
            registry.register(_make_spec())
            # No progress_stream argument — existing API must still work.
            return await registry.invoke("test.tool", {})

        result = _run(_go())
        assert result.tool_name == "test.tool"

    def test_no_progress_summary_in_metadata_without_stream(self) -> None:
        async def _go() -> MCPToolResult:
            registry = MCPToolRegistry()
            registry.register(_make_spec())
            return await registry.invoke("test.tool", {})

        result = _run(_go())
        assert "progress_summary" not in result.metadata

    def test_explicit_none_stream_does_not_attach_summary(self) -> None:
        async def _go() -> MCPToolResult:
            registry = MCPToolRegistry()
            registry.register(_make_spec())
            return await registry.invoke("test.tool", {}, progress_stream=None)

        result = _run(_go())
        assert "progress_summary" not in result.metadata
