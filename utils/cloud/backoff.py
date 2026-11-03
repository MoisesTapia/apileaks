"""
Exponential backoff utility for cloud provider API calls.

Provides :func:`with_exponential_backoff`, an async helper that retries a
callable (sync or async) when it raises a specified exception class, using
exponential back-off with optional jitter.  After *max_retries* retries the
final exception is re-raised so callers can decide how to handle exhaustion.

Typical usage inside an async auditor method::

    from modules.cloud.base import ProviderThrottledError
    from utils.cloud.backoff import with_exponential_backoff

    result = await with_exponential_backoff(
        some_sdk_call, arg1, arg2,
        retry_on=ProviderThrottledError,
        max_retries=3,
    )
"""

from __future__ import annotations

import asyncio
import inspect
import random
from collections.abc import Callable
from typing import Any


async def with_exponential_backoff(
    fn: Callable[..., Any],
    *args: Any,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    jitter: bool = True,
    retry_on: type[Exception] | tuple[type[Exception], ...] = Exception,
    **kwargs: Any,
) -> Any:
    """
    Retry *fn* with exponential back-off when *retry_on* is raised.

    Parameters
    ----------
    fn:
        Callable to invoke.  May be a plain sync function *or* a coroutine
        function; both are handled transparently.
    *args:
        Positional arguments forwarded to *fn*.
    max_retries:
        Maximum number of *additional* attempts after the first failure.
        Total attempts = max_retries + 1.
    base_delay:
        Initial sleep duration in seconds before the first retry.
    max_delay:
        Upper bound on the sleep duration regardless of the computed value.
    jitter:
        When True the delay is scaled by a random factor in [0.5, 1.0] to
        spread concurrent callers.
    retry_on:
        Exception class or tuple of classes to catch and retry.  Any other
        exception propagates immediately without retrying.
    **kwargs:
        Keyword arguments forwarded to *fn*.

    Returns
    -------
    Any
        The return value of *fn* on success.

    Raises
    ------
    retry_on
        Re-raises the most recent *retry_on* exception after *max_retries*
        retries are exhausted.
    Any other exception
        Propagated immediately without retrying.
    """
    last_exc: BaseException | None = None

    for attempt in range(max_retries + 1):
        try:
            if inspect.iscoroutinefunction(fn):
                return await fn(*args, **kwargs)
            return fn(*args, **kwargs)
        except retry_on as exc:  # type: ignore[misc]
            last_exc = exc
            if attempt >= max_retries:
                # Retries exhausted — raise to caller
                break
            delay = min(base_delay * (2.0 ** attempt), max_delay)
            if jitter:
                delay *= 0.5 + random.random() * 0.5
            await asyncio.sleep(delay)

    # Should always be set after the loop body executes at least once
    assert last_exc is not None, "with_exponential_backoff: no attempts were made"
    raise last_exc
