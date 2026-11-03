"""
Tests for graceful shutdown of APILeakMCPServer (Task 3.3).

Verifies Requirement 2.4: when the MCP server receives a termination signal
it finalises in an orderly fashion any in-progress scan tasks and releases
resources (HTTP connections, uvicorn server).

Strategy:
- All tests run in-process without spinning up a real network server.
- Signal-based tests use asyncio's loop.add_signal_handler and os.kill to
  deliver the signal in-process; the SIGTERM test is skipped on Windows where
  that signal is not properly supported.
- The uvicorn shutdown test patches a minimal stub instead of starting a real
  HTTP server, keeping the test fast and side-effect-free.
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_server.schemas import MCPServerConfig
from mcp_server.server import APILeakMCPServer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_server(transport: str = "stdio") -> APILeakMCPServer:
    config = MCPServerConfig(transport=transport, auth_token="tok" if transport == "http" else None)
    return APILeakMCPServer(transport=transport, config=config)


def _run(coro):
    """Run a coroutine on a fresh event loop without touching the global one."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# 1. shutdown() sets the shutdown event/flag
# ---------------------------------------------------------------------------


def test_shutdown_sets_shutdown_event() -> None:
    """Calling shutdown() must set the internal _shutdown_event (Req 2.4)."""
    server = _make_server()

    async def run():
        assert not server._shutdown_event.is_set(), "event should start unset"
        await server.shutdown()
        assert server._shutdown_event.is_set(), "event must be set after shutdown()"

    _run(run())


def test_shutdown_is_idempotent() -> None:
    """Calling shutdown() multiple times must not raise (Req 2.4)."""
    server = _make_server()

    async def run():
        await server.shutdown()
        await server.shutdown()  # second call — must not raise or deadlock
        assert server._shutdown_event.is_set()

    _run(run())


def test_shutdown_logs_requested_message() -> None:
    """shutdown() must log 'mcp_server_shutdown_requested' (Req 2.4)."""
    import mcp_server.server as server_module

    server = _make_server()

    with patch.object(server_module.logger, "info") as mock_info:
        _run(server.shutdown())

    log_events = [call[0][0] for call in mock_info.call_args_list]
    assert any("shutdown_requested" in evt for evt in log_events), (
        f"Expected 'mcp_server_shutdown_requested' log entry, got: {log_events}"
    )


# ---------------------------------------------------------------------------
# 2. Active tasks are cancelled on shutdown
# ---------------------------------------------------------------------------


def test_shutdown_cancels_active_tasks() -> None:
    """Any asyncio.Task in _active_tasks must be cancelled on shutdown (Req 2.4)."""
    server = _make_server()

    async def long_running():
        await asyncio.sleep(9999)

    async def run():
        loop = asyncio.get_event_loop()
        task = loop.create_task(long_running())
        server._active_tasks.add(task)

        await server.shutdown()

        assert task.cancelled(), "Task must be cancelled after shutdown()"

    _run(run())


def test_shutdown_clears_completed_tasks_gracefully() -> None:
    """Tasks already done before shutdown() are not re-cancelled (no error)."""
    server = _make_server()

    async def already_done():
        return 42

    async def run():
        loop = asyncio.get_event_loop()
        task = loop.create_task(already_done())
        await task  # let it complete first
        server._active_tasks.add(task)

        # Must not raise even though the task is already done
        await server.shutdown()
        assert server._shutdown_event.is_set()

    _run(run())


# ---------------------------------------------------------------------------
# 3. SIGTERM triggers shutdown on Unix (skipped on Windows)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="SIGTERM not reliably supported on Windows")
def test_sigterm_triggers_shutdown() -> None:
    """Delivering SIGTERM to the process must invoke shutdown() on POSIX (Req 2.4)."""
    server = _make_server()

    async def run():
        loop = asyncio.get_running_loop()

        # Install signal handlers the same way serve() would.
        server._install_signal_handlers()

        # Deliver SIGTERM to ourselves.
        os.kill(os.getpid(), signal.SIGTERM)

        # Give the event loop one cycle to process the signal.
        await asyncio.sleep(0)
        # Another cycle in case the task was just scheduled.
        await asyncio.sleep(0)

        assert server._shutdown_event.is_set(), (
            "SIGTERM must trigger shutdown and set _shutdown_event"
        )

    _run(run())


# ---------------------------------------------------------------------------
# 4. uvicorn should_exit is set on HTTP shutdown
# ---------------------------------------------------------------------------


def test_http_shutdown_sets_uvicorn_should_exit() -> None:
    """shutdown() must set uv_server.should_exit=True for HTTP transport (Req 2.4)."""
    server = _make_server(transport="http")

    # Inject a stub uvicorn server with a should_exit attribute.
    stub_uv_server = MagicMock()
    stub_uv_server.should_exit = False
    server._uv_server = stub_uv_server

    _run(server.shutdown())

    assert stub_uv_server.should_exit is True, (
        "shutdown() must set uvicorn Server.should_exit=True so uvicorn stops"
    )


def test_http_shutdown_without_uv_server_does_not_raise() -> None:
    """shutdown() must not raise when _uv_server is None (server not yet started)."""
    server = _make_server(transport="http")
    assert server._uv_server is None

    _run(server.shutdown())  # must not raise

    assert server._shutdown_event.is_set()


def test_uv_server_stored_during_serve_http() -> None:
    """_serve_http() must store the uvicorn Server on self._uv_server (Req 2.4)."""
    import uvicorn

    import mcp_server.server as server_module

    server = _make_server(transport="http")
    captured: list[Any] = []

    async def _noop_serve(self):
        # By the time serve() is called, _uv_server must already be set.
        captured.append(server._uv_server)

    from typing import Any

    with patch.object(uvicorn.Server, "serve", _noop_serve):
        _run(server._serve_http())

    assert len(captured) == 1, "serve() should have been called once"
    assert captured[0] is not None, "_uv_server must be set before uvicorn.Server.serve() runs"
    assert isinstance(captured[0], uvicorn.Server)
