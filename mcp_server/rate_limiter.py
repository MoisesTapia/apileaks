"""
mcp_server.rate_limiter — Per-client invocation rate limiting (Requirement 15.2).

:class:`MCPRateLimiter` tracks the number of tool invocations per *client
identifier* in a rolling 60-second window.  When a client exceeds the
configured ``rate_limit_per_minute`` the limiter raises
:class:`~mcp_server.schemas.MCPToolError` with ``error_code="RATE_LIMIT_EXCEEDED"``
*before* any tool handler is called, so the underlying operation is never
executed for over-quota clients.

Key design decisions
---------------------

* **Sliding window** — timestamps of the last N calls are stored in a deque.
  On every check, timestamps older than ``window_seconds`` are evicted.  This
  gives a smooth limit rather than the "burst at the boundary" behaviour of a
  fixed-bucket approach.
* **Thread safety** — each client bucket is protected by its own
  :class:`asyncio.Lock` so concurrent invocations from the same client are
  serialised correctly.
* **Single-client transports** — for stdio transport there is only one
  implicit client (the MCP SDK process).  Pass ``client_id="__stdio__"`` (or
  any fixed string) to preserve the contract without hitting rate-limit issues
  in practice (the default 60 req/min is generous for a single interactive
  agent).
* **No external dependencies** — the implementation uses only the standard
  library (``collections.deque``, ``time.monotonic``, ``asyncio``).
"""

from __future__ import annotations

import asyncio
import time
from collections import deque

from core.logging import get_logger
from mcp_server.schemas import MCPToolError

logger = get_logger(__name__)

_WINDOW_SECONDS: float = 60.0


class MCPRateLimiter:
    """Sliding-window rate limiter for MCP tool invocations (Requirement 15.2).

    One instance is typically shared by :class:`~mcp_server.tool_registry.MCPToolRegistry`
    for the lifetime of the server.

    Args:
        rate_limit_per_minute: Maximum invocations allowed per client per
            minute.  Must be a positive integer.  Defaults to ``60``.
        window_seconds: Duration of the sliding window in seconds.  The
            default of ``60.0`` implements a "per minute" rate limit.

    Example::

        limiter = MCPRateLimiter(rate_limit_per_minute=60)
        # Raises MCPToolError(error_code="RATE_LIMIT_EXCEEDED") on the 61st call
        # from the same client_id within any 60-second rolling window.
        await limiter.check_and_record("192.0.2.1")
    """

    def __init__(
        self,
        rate_limit_per_minute: int = 60,
        window_seconds: float = _WINDOW_SECONDS,
    ) -> None:
        if rate_limit_per_minute <= 0:
            raise ValueError(
                f"rate_limit_per_minute must be a positive integer, got {rate_limit_per_minute!r}"
            )
        self._limit = rate_limit_per_minute
        self._window = window_seconds
        # client_id → deque of monotonic timestamps within the window
        self._buckets: dict[str, deque[float]] = {}
        # per-client lock to avoid race conditions on concurrent invocations
        self._locks: dict[str, asyncio.Lock] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def rate_limit_per_minute(self) -> int:
        """The configured maximum invocations per client per minute."""
        return self._limit

    async def check_and_record(self, client_id: str) -> None:
        """Check whether *client_id* is within quota and record the call.

        This is the single method the registry calls before dispatching a
        tool.  It atomically:

        1. Prunes timestamps older than the rolling window.
        2. Raises :class:`~mcp_server.schemas.MCPToolError` (code
           ``"RATE_LIMIT_EXCEEDED"``) if the remaining count is already at or
           above the limit.
        3. Otherwise, appends the current timestamp and returns normally.

        Args:
            client_id: An opaque string identifying the caller.  Typically the
                client's IP address for HTTP transport, or ``"__stdio__"`` for
                stdio transport.

        Raises:
            MCPToolError: When the client has exceeded the configured rate limit
                within the current rolling window.
        """
        lock = self._get_lock(client_id)
        async with lock:
            now = time.monotonic()
            bucket = self._get_bucket(client_id)

            # Evict timestamps that have fallen outside the rolling window.
            cutoff = now - self._window
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= self._limit:
                logger.warning(
                    "mcp_rate_limit_exceeded",
                    client_id=client_id,
                    window_seconds=self._window,
                    limit=self._limit,
                    current_count=len(bucket),
                )
                raise MCPToolError(
                    f"Rate limit exceeded: client '{client_id}' has made "
                    f"{len(bucket)} invocations in the last {int(self._window)}s "
                    f"(limit: {self._limit} per {int(self._window)}s).  "
                    "Please wait before retrying.",
                    error_code="RATE_LIMIT_EXCEEDED",
                )

            # Record this invocation.
            bucket.append(now)

    def current_count(self, client_id: str) -> int:
        """Return the number of *valid* (within-window) calls recorded for *client_id*.

        Intended for testing and monitoring.  Does **not** record a new call.

        Args:
            client_id: The client identifier to query.

        Returns:
            Number of calls within the current rolling window.
        """
        now = time.monotonic()
        cutoff = now - self._window
        bucket = self._buckets.get(client_id, deque())
        return sum(1 for ts in bucket if ts > cutoff)

    def reset(self, client_id: str | None = None) -> None:
        """Clear recorded timestamps.

        Args:
            client_id: If given, clear only the bucket for that client.
                If *None*, clear all buckets.

        Primarily useful in tests.
        """
        if client_id is not None:
            self._buckets.pop(client_id, None)
            self._locks.pop(client_id, None)
        else:
            self._buckets.clear()
            self._locks.clear()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_bucket(self, client_id: str) -> deque[float]:
        if client_id not in self._buckets:
            self._buckets[client_id] = deque()
        return self._buckets[client_id]

    def _get_lock(self, client_id: str) -> asyncio.Lock:
        if client_id not in self._locks:
            self._locks[client_id] = asyncio.Lock()
        return self._locks[client_id]
