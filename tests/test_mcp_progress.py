"""
Tests for ``mcp_server.progress.ToolProgressStream`` (Task 5.1).

Covers:
1. ``emit`` forwards the update to the injected callback with the correct fields.
2. When ``supports_streaming=False`` the callback is NOT called but updates are
   accumulated internally.
3. When no callback is provided, ``emit`` accumulates updates silently.
4. Progress events are actually emitted when ``APILeakCore.run_scan`` is called
   with a ``progress_stream`` wired in (engine phases mocked so no network calls).
5. Callback transport errors do not abort the emit (resilience).

Validates: Requirements 3.1, 3.2, 3.3
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from mcp_server.progress import ProgressUpdate, ToolProgressStream


# ---------------------------------------------------------------------------
# 1. Callback receives correct fields
# ---------------------------------------------------------------------------


class TestEmitWithCallback:
    def test_callback_called_with_correct_phase(self):
        received: list[ProgressUpdate] = []

        async def _run():
            async def cb(update: ProgressUpdate) -> None:
                received.append(update)

            stream = ToolProgressStream(callback=cb, supports_streaming=True)
            await stream.emit("discovery", 5, 20.0)

        asyncio.run(_run())

        assert len(received) == 1
        assert received[0].phase == "discovery"

    def test_callback_receives_findings_count(self):
        received: list[ProgressUpdate] = []

        async def _run():
            async def cb(update: ProgressUpdate) -> None:
                received.append(update)

            stream = ToolProgressStream(callback=cb, supports_streaming=True)
            await stream.emit("owasp_testing", 42, 60.0)

        asyncio.run(_run())
        assert received[0].findings_count == 42

    def test_callback_receives_percent_complete(self):
        received: list[ProgressUpdate] = []

        async def _run():
            async def cb(update: ProgressUpdate) -> None:
                received.append(update)

            stream = ToolProgressStream(callback=cb, supports_streaming=True)
            await stream.emit("traditional_fuzzing", 3, 50.0)

        asyncio.run(_run())
        assert received[0].percent_complete == 50.0

    def test_callback_receives_none_percent(self):
        received: list[ProgressUpdate] = []

        async def _run():
            async def cb(update: ProgressUpdate) -> None:
                received.append(update)

            stream = ToolProgressStream(callback=cb, supports_streaming=True)
            await stream.emit("discovery", 0, None)

        asyncio.run(_run())
        assert received[0].percent_complete is None

    def test_multiple_emits_all_forwarded(self):
        received: list[ProgressUpdate] = []

        async def _run():
            async def cb(update: ProgressUpdate) -> None:
                received.append(update)

            stream = ToolProgressStream(callback=cb, supports_streaming=True)
            await stream.emit("discovery", 0, 14.3)
            await stream.emit("owasp_testing", 7, 71.4)
            await stream.emit("results_aggregation", 7, 100.0)

        asyncio.run(_run())

        assert len(received) == 3
        assert [u.phase for u in received] == [
            "discovery", "owasp_testing", "results_aggregation"
        ]

    def test_update_accumulated_alongside_callback(self):
        """Updates are stored even when a callback is present."""

        async def _run():
            async def cb(update: ProgressUpdate) -> None:
                pass

            stream = ToolProgressStream(callback=cb, supports_streaming=True)
            await stream.emit("waf_detection", 1, 30.0)
            assert len(stream.updates) == 1
            assert stream.updates[0].phase == "waf_detection"

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# 2. Non-streaming mode — callback silent, updates accumulated
# ---------------------------------------------------------------------------


class TestNoStreamingMode:
    def test_callback_not_called_when_streaming_disabled(self):
        called: list[ProgressUpdate] = []

        async def _run():
            async def cb(update: ProgressUpdate) -> None:
                called.append(update)

            stream = ToolProgressStream(callback=cb, supports_streaming=False)
            await stream.emit("discovery", 5, 25.0)

        asyncio.run(_run())

        # Callback must NOT have been called (Requirement 3.3)
        assert called == []

    def test_updates_accumulated_when_streaming_disabled(self):
        async def _run():
            async def cb(update: ProgressUpdate) -> None:
                pass

            stream = ToolProgressStream(callback=cb, supports_streaming=False)
            await stream.emit("discovery", 0, 33.3)
            await stream.emit("owasp_testing", 4, 66.7)
            await stream.emit("results_aggregation", 4, 100.0)

            # All three updates must be in the buffer
            assert len(stream.updates) == 3
            assert stream.updates[1].findings_count == 4

        asyncio.run(_run())

    def test_supports_streaming_property_reflects_constructor(self):
        s_on = ToolProgressStream(supports_streaming=True)
        s_off = ToolProgressStream(supports_streaming=False)

        assert s_on.supports_streaming is True
        assert s_off.supports_streaming is False


# ---------------------------------------------------------------------------
# 3. No callback — silent accumulation
# ---------------------------------------------------------------------------


class TestNoCallback:
    def test_emit_without_callback_accumulates(self):
        async def _run():
            stream = ToolProgressStream()  # no callback
            await stream.emit("discovery", 0, 50.0)
            assert len(stream.updates) == 1
            assert stream.updates[0].phase == "discovery"

        asyncio.run(_run())

    def test_updates_property_returns_copy(self):
        async def _run():
            stream = ToolProgressStream()
            await stream.emit("discovery", 0, 10.0)

            copy1 = stream.updates
            copy1.clear()  # mutating the returned list must not affect the internal buffer
            assert len(stream.updates) == 1

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# 4. Callback transport errors do not abort emit
# ---------------------------------------------------------------------------


class TestCallbackResilience:
    def test_exception_in_callback_does_not_propagate(self):
        async def _run():
            async def bad_cb(update: ProgressUpdate) -> None:
                raise RuntimeError("transport broken")

            stream = ToolProgressStream(callback=bad_cb, supports_streaming=True)
            # Must not raise
            await stream.emit("discovery", 0, 25.0)
            # Update still accumulated despite callback failure
            assert len(stream.updates) == 1

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# 5. Engine integration — progress events emitted during a scan
# ---------------------------------------------------------------------------


def _make_minimal_config():
    """Return a minimal APILeakConfig with all phases disabled."""
    from core import ConfigurationManager

    config_dict = {
        "target": {"base_url": "http://test.example.com"},
        "fuzzing": {
            "endpoints": {"enabled": False},
            "parameters": {"enabled": False},
            "headers": {"enabled": False},
        },
        "owasp_testing": {"enabled_modules": []},
        "advanced_discovery": {
            "framework_detection": {"enabled": False},
            "version_fuzzing": {"enabled": False},
            "waf_detection": {"enabled": False},
            "cors_analysis": False,
            "security_headers": False,
            "subdomain_discovery": False,
        },
        "reporting": {"formats": []},
    }

    mgr = ConfigurationManager()
    return mgr.load_config_from_dict(config_dict)


class TestEngineIntegration:
    """Verify that run_scan with a progress_stream emits phase progress.

    The engine's internal modules are mocked out so no network calls happen.
    We only care that the orchestrator calls _emit_phase_progress on the engine
    and that the engine forwards those calls to the stream.
    """

    def test_run_scan_emits_progress_for_each_phase(self):
        """At least one ProgressUpdate is emitted when a scan completes."""
        from core.engine import APILeakCore

        received: list[ProgressUpdate] = []

        async def _run():
            async def cb(update: ProgressUpdate) -> None:
                received.append(update)

            stream = ToolProgressStream(callback=cb, supports_streaming=True)
            cfg = _make_minimal_config()
            core = APILeakCore(cfg)

            # Mock the internal discovery so no real HTTP is needed
            with patch.object(core, "_execute_discovery_phase", new=AsyncMock()):
                with patch.object(core, "_execute_owasp_phase", new=AsyncMock()):
                    with patch.object(core, "_aggregate_results", new=AsyncMock()):
                        with patch.object(core, "health_check", new=AsyncMock()):
                            with patch.object(core, "_build_fuzzing_results", return_value=None):
                                await core.run_scan(
                                    "http://test.example.com",
                                    progress_stream=stream,
                                )

        asyncio.run(_run())

        # At least one update should have been emitted (results_aggregation is always enabled)
        assert len(received) >= 1, (
            "Expected at least one progress update from the scan; got none. "
            "Check that execute_orchestration calls _emit_phase_progress."
        )

    def test_run_scan_without_progress_stream_does_not_error(self):
        """Passing no progress_stream (default None) must not raise."""
        from core.engine import APILeakCore

        async def _run():
            cfg = _make_minimal_config()
            core = APILeakCore(cfg)
            with patch.object(core, "_execute_discovery_phase", new=AsyncMock()):
                with patch.object(core, "_execute_owasp_phase", new=AsyncMock()):
                    with patch.object(core, "_aggregate_results", new=AsyncMock()):
                        with patch.object(core, "health_check", new=AsyncMock()):
                            with patch.object(core, "_build_fuzzing_results", return_value=None):
                                # No progress_stream argument — should not raise
                                await core.run_scan("http://test.example.com")

        asyncio.run(_run())

    def test_progress_updates_contain_required_fields(self):
        """Each emitted ProgressUpdate has phase, findings_count, and percent_complete."""
        from core.engine import APILeakCore

        received: list[ProgressUpdate] = []

        async def _run():
            async def cb(update: ProgressUpdate) -> None:
                received.append(update)

            stream = ToolProgressStream(callback=cb, supports_streaming=True)
            cfg = _make_minimal_config()
            core = APILeakCore(cfg)

            with patch.object(core, "_execute_discovery_phase", new=AsyncMock()):
                with patch.object(core, "_execute_owasp_phase", new=AsyncMock()):
                    with patch.object(core, "_aggregate_results", new=AsyncMock()):
                        with patch.object(core, "health_check", new=AsyncMock()):
                            with patch.object(core, "_build_fuzzing_results", return_value=None):
                                await core.run_scan(
                                    "http://test.example.com",
                                    progress_stream=stream,
                                )

        asyncio.run(_run())

        for update in received:
            # Requirement 3.2: every update must carry phase name, findings count, percent
            assert isinstance(update.phase, str) and update.phase, (
                f"Update phase must be a non-empty string: {update!r}"
            )
            assert isinstance(update.findings_count, int) and update.findings_count >= 0, (
                f"findings_count must be a non-negative int: {update!r}"
            )
            # percent_complete may be None when indeterminate, otherwise must be in [0, 100]
            if update.percent_complete is not None:
                assert 0.0 <= update.percent_complete <= 100.0, (
                    f"percent_complete out of range: {update!r}"
                )
