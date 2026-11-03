"""
utils.ai.retry — Shared exponential back-off retry helper for LLM providers.

Retries exclusively on :class:`~utils.ai.provider_base.LLMRateLimitError`
(HTTP 429 / provider rate-limit).  All other exceptions — including
:class:`~utils.ai.provider_base.LLMProviderUnavailableError` (timeout,
connection failure) and :class:`~utils.ai.provider_base.LLMResponseParseError`
— propagate immediately without retrying (Requirements 10.1, 10.3).

Usage
-----
Wrap each single-attempt coroutine with :func:`retry_with_backoff`.  The
coroutine receives no arguments and should already capture everything it needs
(provider client, prompt, timeout, etc.) via closure::

    async def _attempt() -> str:
        try:
            return await asyncio.wait_for(_call(), timeout=timeout)
        except TimeoutError as exc:
            raise LLMProviderUnavailableError(...) from exc

    return await retry_with_backoff(
        _attempt,
        max_retries=config.max_retries,
    )

The :class:`~utils.ai.provider_base.LLMRateLimitError` is raised by concrete
providers when the underlying SDK signals a rate-limit; it is caught here and
the attempt is scheduled for retry after an exponentially growing delay.
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import Awaitable, Callable
from typing import TypeVar

from utils.ai.provider_base import LLMProviderUnavailableError, LLMRateLimitError

logger = logging.getLogger(__name__)

T = TypeVar("T")


async def retry_with_backoff(
    coro_fn: Callable[[], Awaitable[T]],
    *,
    max_retries: int,
    initial_delay: float = 1.0,
    max_delay: float = 60.0,
    jitter: bool = True,
) -> T:
    """Execute *coro_fn* retrying on rate-limit errors with exponential back-off.

    Only :class:`~utils.ai.provider_base.LLMRateLimitError` triggers a retry;
    every other exception propagates immediately to the caller without any
    delay or retry attempt.

    Back-off schedule (before jitter)::

        attempt 0 → fail → wait initial_delay
        attempt 1 → fail → wait min(initial_delay * 2, max_delay)
        attempt 2 → fail → wait min(initial_delay * 4, max_delay)
        ...
        attempt max_retries → fail → raise LLMProviderUnavailableError

    Args:
        coro_fn: Zero-argument async callable to execute.  Called once on the
            first attempt and then once per retry.
        max_retries: Maximum number of *additional* attempts after the first.
            ``0`` means one attempt total with no retries.
        initial_delay: Seconds to wait before the first retry.
        max_delay: Upper bound (in seconds) on the back-off delay after
            applying the exponential factor.  Jitter is applied before
            capping at this value.
        jitter: When ``True`` (default), multiply each computed delay by a
            uniform random factor in ``[0.5, 1.5]`` before capping at
            *max_delay*.  This spreads retry traffic across a time window to
            avoid thundering-herd effects when multiple callers hit the same
            rate limit simultaneously.

    Returns:
        The value returned by *coro_fn* on a successful attempt.

    Raises:
        LLMProviderUnavailableError: When all *max_retries* retry attempts are
            exhausted due to continued rate-limit errors (Requirement 10.3).
        Any exception other than :class:`~utils.ai.provider_base.LLMRateLimitError`:
            Propagated immediately to the caller without retrying.
    """
    last_exc: LLMRateLimitError | None = None
    delay = initial_delay

    for attempt in range(max_retries + 1):  # attempt 0 = first try (not a retry)
        try:
            return await coro_fn()
        except LLMRateLimitError as exc:
            last_exc = exc
            if attempt >= max_retries:
                break  # exhausted — fall through to the final raise below
            actual_delay = min(delay, max_delay)
            if jitter:
                actual_delay = min(actual_delay * random.uniform(0.5, 1.5), max_delay)
            logger.warning(
                "LLM rate limit on attempt %d/%d; retrying in %.2fs — %s",
                attempt + 1,
                max_retries + 1,
                actual_delay,
                exc,
            )
            await asyncio.sleep(actual_delay)
            delay = min(delay * 2, max_delay)  # exponential growth, capped

    raise LLMProviderUnavailableError(
        f"LLM rate limit was hit and all {max_retries} "
        f"{'retry' if max_retries == 1 else 'retries'} were exhausted. "
        f"Last error: {last_exc}"
    ) from last_exc
