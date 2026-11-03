"""
Tests for MCPRateLimiter and its integration with MCPToolRegistry.

Verifies Requirements 15.2 and 15.3:

- Req 15.2: When a client exceeds the configured invocations/min rate limit,
  return a structured MCP rate-limit error WITHOUT executing the tool.
- Req 15.3: Conservative defaults (timeout: 300s per tool, rate limit:
  60 invocations/min) are applied and logged at startup.

Test strategy
-------------
- Pure unit tests for MCPRateLimiter (no server needed).
- Integration test for MCPToolRegistry with an attached MCPRateLimiter to
  verify the handler is NOT called when rate-limited.
- Startup-log test to verify both rate_limit_per_minute and
  default_max_execution_seconds appear in the 'mcp_server_starting' log entry.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

pytest.importorskip("mcp")  # skip if optional MCP SDK is absent

from mcp_server.rate_limiter import MCPRateLimiter  # noqa: E402
from mcp_server.schemas import (  # noqa: E402
    MCPServerConfig,
    MCPToolError,
    MCPToolResult,
    MCPToolSpec,
)
from mcp_server.tool_registry import MCPToolRegistry  # noqa: E402
import mcp_server.server as server_module  # noqa: E402
from mcp_server.server import APILeakMCPServer  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_noop_spec(name: str = "test.noop") -> MCPToolSpec:
    """Build a minimal non-destructive tool spec with a no-op handler.

    The spec has a ``_test_calls`` attribute added so tests can verify
    how many times the handler was actually invoked.
    """
    calls: list[dict] = []

    async def _handler(params: dict) -> MCPToolResult:
        calls.append(params)
        return MCPToolResult(tool_name=name)

    spec = MCPToolSpec(
        name=name,
        description="No-op tool for rate-limit tests.",
        input_schema={"type": "object", "properties": {}},
        output_schema={"type": "object"},
        is_destructive=False,
        handler=_handler,
    )
    # Attach the calls list so tests can verify invocation count.
    spec._test_calls = calls  # type: ignore[attr-defined]
    return spec


def _run(coro):
    """Run a coroutine in a fresh event loop — avoids stale-loop issues."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Unit tests — MCPRateLimiter
# ---------------------------------------------------------------------------


class TestMCPRateLimiterDefaults:
    """Verify conservative defaults (Requirement 15.3)."""

    def test_default_rate_limit_is_60(self) -> None:
        limiter = MCPRateLimiter()
        assert limiter.rate_limit_per_minute == 60

    def test_custom_rate_limit_stored(self) -> None:
        limiter = MCPRateLimiter(rate_limit_per_minute=10)
        assert limiter.rate_limit_per_minute == 10

    def test_invalid_rate_limit_raises(self) -> None:
        with pytest.raises(ValueError, match="positive integer"):
            MCPRateLimiter(rate_limit_per_minute=0)

        with pytest.raises(ValueError, match="positive integer"):
            MCPRateLimiter(rate_limit_per_minute=-5)


class TestMCPRateLimiterAllowsUnderLimit:
    """Calls within the limit should succeed."""

    def test_single_call_allowed(self) -> None:
        limiter = MCPRateLimiter(rate_limit_per_minute=5)
        _run(limiter.check_and_record("client-1"))
        assert limiter.current_count("client-1") == 1

    def test_calls_up_to_limit_are_allowed(self) -> None:
        async def _go():
            limiter = MCPRateLimiter(rate_limit_per_minute=5)
            for _ in range(5):
                await limiter.check_and_record("client-A")
            assert limiter.current_count("client-A") == 5

        _run(_go())

    def test_different_clients_have_independent_limits(self) -> None:
        async def _go():
            limiter = MCPRateLimiter(rate_limit_per_minute=2)
            await limiter.check_and_record("alpha")
            await limiter.check_and_record("alpha")
            # beta is independent — should still be allowed
            await limiter.check_and_record("beta")
            assert limiter.current_count("beta") == 1

        _run(_go())


class TestMCPRateLimiterExceedsLimit:
    """Calls that exceed the limit must raise MCPToolError with the right code."""

    def test_exceeding_limit_raises_mcp_tool_error(self) -> None:
        async def _go():
            limiter = MCPRateLimiter(rate_limit_per_minute=3)
            for _ in range(3):
                await limiter.check_and_record("greedy")
            with pytest.raises(MCPToolError) as exc_info:
                await limiter.check_and_record("greedy")
            assert exc_info.value.error_code == "RATE_LIMIT_EXCEEDED"

        _run(_go())

    def test_rate_limit_error_message_contains_client_id(self) -> None:
        async def _go():
            limiter = MCPRateLimiter(rate_limit_per_minute=1)
            await limiter.check_and_record("192.0.2.42")
            with pytest.raises(MCPToolError) as exc_info:
                await limiter.check_and_record("192.0.2.42")
            assert "192.0.2.42" in exc_info.value.message

        _run(_go())

    def test_rate_limit_error_is_mcp_tool_error_subclass(self) -> None:
        """RATE_LIMIT_EXCEEDED must be an MCPToolError (Req 1.5 / 15.2)."""
        async def _go():
            limiter = MCPRateLimiter(rate_limit_per_minute=1)
            await limiter.check_and_record("x")
            with pytest.raises(MCPToolError):
                await limiter.check_and_record("x")

        _run(_go())

    def test_reset_clears_bucket(self) -> None:
        async def _go():
            limiter = MCPRateLimiter(rate_limit_per_minute=2)
            await limiter.check_and_record("r")
            await limiter.check_and_record("r")
            limiter.reset("r")
            # After reset, calls should be allowed again
            await limiter.check_and_record("r")
            assert limiter.current_count("r") == 1

        _run(_go())

    def test_reset_all_clears_all_buckets(self) -> None:
        async def _go():
            limiter = MCPRateLimiter(rate_limit_per_minute=1)
            await limiter.check_and_record("a")
            await limiter.check_and_record("b")
            limiter.reset()
            assert limiter.current_count("a") == 0
            assert limiter.current_count("b") == 0

        _run(_go())


# ---------------------------------------------------------------------------
# Integration tests — MCPToolRegistry + MCPRateLimiter
# ---------------------------------------------------------------------------


class TestRegistryEnforcesRateLimit:
    """The registry must refuse to call the handler when rate-limited (Req 15.2)."""

    def test_handler_not_called_when_rate_limited(self) -> None:
        """The handler must NOT execute when the client is over quota."""
        async def _go():
            limiter = MCPRateLimiter(rate_limit_per_minute=2)
            registry = MCPToolRegistry(rate_limiter=limiter)
            spec = _make_noop_spec()
            registry.register(spec)

            # First two calls succeed
            await registry.invoke("test.noop", {}, client_id="ip-1")
            await registry.invoke("test.noop", {}, client_id="ip-1")
            assert len(spec._test_calls) == 2  # type: ignore[attr-defined]

            # Third call exceeds the limit — handler must NOT be called
            with pytest.raises(MCPToolError) as exc_info:
                await registry.invoke("test.noop", {}, client_id="ip-1")

            assert exc_info.value.error_code == "RATE_LIMIT_EXCEEDED"
            # Handler was NOT called on the third invocation
            assert len(spec._test_calls) == 2  # type: ignore[attr-defined]

        _run(_go())

    def test_rate_limit_error_is_structured(self) -> None:
        """The raised error must have the structured MCPToolError interface."""
        async def _go():
            limiter = MCPRateLimiter(rate_limit_per_minute=1)
            registry = MCPToolRegistry(rate_limiter=limiter)
            spec = _make_noop_spec()
            registry.register(spec)

            await registry.invoke("test.noop", {}, client_id="x")

            with pytest.raises(MCPToolError) as exc_info:
                await registry.invoke("test.noop", {}, client_id="x")

            err = exc_info.value
            assert err.error_code == "RATE_LIMIT_EXCEEDED"
            assert err.message  # non-empty human-readable message

        _run(_go())

    def test_different_clients_not_affected_by_each_other(self) -> None:
        """Rate limit for client-A must not bleed into client-B."""
        async def _go():
            limiter = MCPRateLimiter(rate_limit_per_minute=1)
            registry = MCPToolRegistry(rate_limiter=limiter)
            spec = _make_noop_spec()
            registry.register(spec)

            # Exhaust quota for client-A
            await registry.invoke("test.noop", {}, client_id="A")

            # client-B should still succeed
            await registry.invoke("test.noop", {}, client_id="B")
            assert len(spec._test_calls) == 2  # type: ignore[attr-defined]

        _run(_go())

    def test_no_rate_limiter_means_no_limit(self) -> None:
        """When no rate limiter is attached, any number of calls should succeed."""
        async def _go():
            registry = MCPToolRegistry()  # no rate_limiter
            spec = _make_noop_spec()
            registry.register(spec)

            for _ in range(10):
                await registry.invoke("test.noop", {}, client_id="z")

            assert len(spec._test_calls) == 10  # type: ignore[attr-defined]

        _run(_go())


# ---------------------------------------------------------------------------
# Startup log tests — Requirement 15.3
# ---------------------------------------------------------------------------


def _make_server_and_capture_logs() -> tuple[APILeakMCPServer, list[tuple]]:
    """Instantiate APILeakMCPServer with patched logger; return server + calls."""
    config = MCPServerConfig(transport="stdio")
    recorded: list[tuple] = []

    def _capture(*args, **kwargs):
        recorded.append((args, kwargs))

    with patch.object(server_module.logger, "info", side_effect=_capture):
        server = APILeakMCPServer(transport="stdio", config=config)

    return server, recorded


def _find_startup_kwargs(recorded: list[tuple]) -> dict | None:
    for args, kwargs in recorded:
        if args and args[0] == "mcp_server_starting":
            return kwargs
    return None


class TestStartupLogIncludesRateLimitAndTimeout:
    """Req 15.3: active rate-limit and default timeout must appear in the startup log."""

    def test_startup_log_includes_rate_limit_per_minute(self) -> None:
        _, recorded = _make_server_and_capture_logs()
        startup = _find_startup_kwargs(recorded)
        assert startup is not None, "Expected 'mcp_server_starting' log at INFO level"
        assert "rate_limit_per_minute" in startup, (
            f"rate_limit_per_minute missing from startup log. Keys: {list(startup)}"
        )
        assert startup["rate_limit_per_minute"] == 60

    def test_startup_log_includes_default_max_execution_seconds(self) -> None:
        _, recorded = _make_server_and_capture_logs()
        startup = _find_startup_kwargs(recorded)
        assert startup is not None, "Expected 'mcp_server_starting' log at INFO level"
        assert "default_max_execution_seconds" in startup, (
            f"default_max_execution_seconds missing from startup log. Keys: {list(startup)}"
        )
        assert startup["default_max_execution_seconds"] == 300.0

    def test_startup_log_rate_limit_reflects_config(self) -> None:
        """Non-default rate_limit_per_minute must be reflected in the log."""
        config = MCPServerConfig(transport="stdio", rate_limit_per_minute=120)
        recorded: list[tuple] = []

        with patch.object(server_module.logger, "info", side_effect=lambda *a, **kw: recorded.append((a, kw))):
            APILeakMCPServer(transport="stdio", config=config)

        startup = _find_startup_kwargs(recorded)
        assert startup is not None
        assert startup["rate_limit_per_minute"] == 120

    def test_mcp_server_config_default_rate_limit_is_60(self) -> None:
        """MCPServerConfig default must be 60 req/min (Req 15.3)."""
        config = MCPServerConfig(transport="stdio")
        assert config.rate_limit_per_minute == 60

    def test_mcp_tool_spec_default_max_execution_seconds_is_300(self) -> None:
        """MCPToolSpec default must be 300s (Req 15.3)."""
        import dataclasses
        defaults = {f.name: f.default for f in dataclasses.fields(MCPToolSpec)}
        assert defaults["max_execution_seconds"] == 300.0
