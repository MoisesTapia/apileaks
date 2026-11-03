"""
Tests for startup security-mode logging — Task 6.3.

Verifies Requirement 4.3: when APILeakMCPServer is instantiated, the startup
log MUST include a ``security_mode`` field (either ``"safe_default"`` or
``"destructive_enabled"``) and the ``allow_destructive`` boolean so that an
operator can confirm the active security posture at a glance.

Strategy
--------
- MCP is an optional dependency; the whole module is skipped when it is
  absent so CI never fails on a bare install.
- No network, no file I/O, no real transport — only ``__init__`` is exercised.
- The module-level ``logger`` in ``mcp_server.server`` is patched with
  ``unittest.mock.patch.object`` *before* instantiation so we intercept the
  ``logger.info(...)`` call made inside ``_log_startup_info``.
"""

from __future__ import annotations

from unittest.mock import call, patch

import pytest

# Skip the whole module when the optional MCP SDK is not installed.
pytest.importorskip("mcp")

from mcp_server.schemas import MCPServerConfig  # noqa: E402  (after importorskip)
import mcp_server.server as server_module  # noqa: E402
from mcp_server.server import APILeakMCPServer  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_server(allow_destructive: bool) -> tuple[APILeakMCPServer, list[tuple]]:
    """Instantiate *APILeakMCPServer* with a patched logger.

    Returns the server instance together with the list of positional +
    keyword arguments for every ``logger.info`` call that fired during
    ``__init__``.
    """
    config = MCPServerConfig(
        transport="stdio",
        allow_destructive=allow_destructive,
    )
    recorded: list[tuple] = []  # [(args, kwargs), ...]

    def _capture_info(*args, **kwargs):
        recorded.append((args, kwargs))

    with patch.object(server_module.logger, "info", side_effect=_capture_info):
        server = APILeakMCPServer(transport="stdio", config=config)

    return server, recorded


def _find_startup_log(
    recorded: list[tuple],
) -> dict | None:
    """Return the kwargs of the ``mcp_server_starting`` log entry, or *None*."""
    for args, kwargs in recorded:
        if args and args[0] == "mcp_server_starting":
            return kwargs
    return None


# ---------------------------------------------------------------------------
# Test: safe mode (allow_destructive=False, the default)
# ---------------------------------------------------------------------------


def test_startup_log_safe_mode() -> None:
    """Req 4.3 — safe mode: security_mode must be 'safe_default' at startup."""
    _, recorded = _make_server(allow_destructive=False)

    startup = _find_startup_log(recorded)
    assert startup is not None, (
        "Expected a 'mcp_server_starting' INFO log entry during __init__, "
        f"but none was found. Calls: {recorded}"
    )

    assert startup.get("security_mode") == "safe_default", (
        f"Expected security_mode='safe_default', got: {startup.get('security_mode')!r}"
    )
    assert startup.get("allow_destructive") is False, (
        f"Expected allow_destructive=False, got: {startup.get('allow_destructive')!r}"
    )


# ---------------------------------------------------------------------------
# Test: destructive mode (allow_destructive=True, explicitly enabled)
# ---------------------------------------------------------------------------


def test_startup_log_destructive_mode() -> None:
    """Req 4.3 — destructive mode: security_mode must be 'destructive_enabled' at startup."""
    _, recorded = _make_server(allow_destructive=True)

    startup = _find_startup_log(recorded)
    assert startup is not None, (
        "Expected a 'mcp_server_starting' INFO log entry during __init__, "
        f"but none was found. Calls: {recorded}"
    )

    assert startup.get("security_mode") == "destructive_enabled", (
        f"Expected security_mode='destructive_enabled', got: {startup.get('security_mode')!r}"
    )
    assert startup.get("allow_destructive") is True, (
        f"Expected allow_destructive=True, got: {startup.get('allow_destructive')!r}"
    )


# ---------------------------------------------------------------------------
# Test: log is emitted at INFO level (not DEBUG or WARNING)
# ---------------------------------------------------------------------------


def test_startup_log_is_info_level() -> None:
    """Req 4.3 — the security-mode entry must be visible at INFO level (not only DEBUG)."""
    config = MCPServerConfig(transport="stdio", allow_destructive=False)
    info_called = []
    debug_called = []

    with (
        patch.object(server_module.logger, "info", side_effect=lambda *a, **kw: info_called.append(a[0])),
        patch.object(server_module.logger, "debug", side_effect=lambda *a, **kw: debug_called.append(a[0])),
    ):
        APILeakMCPServer(transport="stdio", config=config)

    assert "mcp_server_starting" in info_called, (
        "mcp_server_starting must be logged at INFO level so operators see it "
        "with standard log filters (Req 4.3)"
    )
    # Sanity check: it should NOT be only in debug calls
    assert "mcp_server_starting" not in debug_called, (
        "mcp_server_starting must not be relegated to DEBUG — "
        "it would be invisible to operators using the default INFO filter"
    )
