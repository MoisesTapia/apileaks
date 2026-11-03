"""
utils.ai.anthropic_provider — Anthropic (Claude) LLM provider implementation.

Requires the ``apileaks[ai]`` optional extra::

    pip install apileaks[ai]

Credentials are resolved exclusively from the environment variable
``ANTHROPIC_API_KEY`` — never from YAML or any plaintext config file
(Requirement 7.3).

Rate-limit errors (HTTP 429) are retried with exponential back-off via
:func:`utils.ai.retry.retry_with_backoff`.  Timeouts abort the current
attempt immediately and are never retried (Requirements 10.1, 10.3).
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import TYPE_CHECKING

from utils.ai.provider_base import (
    AIConfig,
    LLMProvider,
    LLMProviderUnavailableError,
    LLMRateLimitError,
    LLMResponseParseError,
)
from utils.ai.retry import retry_with_backoff

if TYPE_CHECKING:
    pass

# ---------------------------------------------------------------------------
# Optional SDK import — guarded so the base package stays importable without
# the [ai] extra installed.
# ---------------------------------------------------------------------------

try:
    import anthropic as _anthropic_sdk
    from anthropic import (
        APIConnectionError as _AnthropicConnectionError,
    )
    from anthropic import (
        APITimeoutError as _AnthropicTimeoutError,
    )
    from anthropic import AsyncAnthropic
    from anthropic import (
        AuthenticationError as _AnthropicAuthError,
    )
    from anthropic import (
        RateLimitError as _AnthropicRateLimitError,
    )

    _SDK_AVAILABLE = True
except ImportError:
    _SDK_AVAILABLE = False
    _anthropic_sdk = None  # type: ignore[assignment]
    AsyncAnthropic = None  # type: ignore[assignment,misc]
    _AnthropicConnectionError = None  # type: ignore[assignment,misc]
    _AnthropicTimeoutError = None  # type: ignore[assignment,misc]
    _AnthropicAuthError = None  # type: ignore[assignment,misc]
    _AnthropicRateLimitError = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

# Default model used when AIConfig.model is not set.
_DEFAULT_MODEL = "claude-3-5-sonnet-20241022"

# Environment variable that carries the Anthropic API key.
_API_KEY_ENV_VAR = "ANTHROPIC_API_KEY"


def _require_sdk() -> None:
    """Raise a clear ImportError if the Anthropic SDK is not installed."""
    if not _SDK_AVAILABLE:
        raise ImportError(
            "The 'anthropic' package is required for AnthropicProvider. "
            "Install the AI optional extra with:  pip install apileaks[ai]"
        )


def _resolve_api_key() -> str:
    """Resolve the Anthropic API key from the environment.

    Returns the key string if found.

    Raises:
        LLMProviderUnavailableError: If ``ANTHROPIC_API_KEY`` is not set.
    """
    key = os.environ.get(_API_KEY_ENV_VAR)
    if not key:
        raise LLMProviderUnavailableError(
            f"Anthropic API key not found. "
            f"Set the {_API_KEY_ENV_VAR!r} environment variable. "
            "Never put credentials in the APILeak YAML config (Requirement 7.3)."
        )
    return key


class AnthropicProvider(LLMProvider):
    """LLM provider that calls the Anthropic Claude API.

    The underlying SDK client is constructed lazily on the first call to
    :meth:`complete` so that import-time failures (SDK not installed) only
    occur when the provider is actually used.

    Rate-limit errors (HTTP 429) are retried up to ``config.max_retries``
    times using exponential back-off with jitter (Requirement 10.3).
    Timeouts abort the current attempt and propagate immediately as
    :class:`~utils.ai.provider_base.LLMProviderUnavailableError` — they are
    never retried (Requirement 10.1).

    Args:
        config: AI layer configuration.  ``config.model`` overrides the
            default model; ``config.timeout_seconds`` is used as the
            per-request deadline; ``config.max_retries`` controls how many
            times a rate-limited request is retried.
    """

    def __init__(self, config: AIConfig) -> None:
        _require_sdk()
        self._config = config
        self._model = config.model or _DEFAULT_MODEL
        self._client: AsyncAnthropic | None = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_client(self) -> AsyncAnthropic:
        """Return (and cache) the async Anthropic client."""
        if self._client is None:
            api_key = _resolve_api_key()
            self._client = AsyncAnthropic(api_key=api_key)
        return self._client

    # ------------------------------------------------------------------
    # LLMProvider interface
    # ------------------------------------------------------------------

    @property
    def provider_name(self) -> str:
        return "anthropic"

    async def complete(
        self,
        prompt: str,
        *,
        max_tokens: int,
        timeout: float,
    ) -> str:
        """Send *prompt* to the Anthropic Messages API and return the text.

        Each attempt is bounded by *timeout* via :func:`asyncio.wait_for`.
        Rate-limit errors (HTTP 429) are caught and retried with exponential
        back-off up to ``config.max_retries`` times.  All other errors
        propagate immediately (Requirement 10.1, 10.3).

        Args:
            prompt: Full prompt string.  **Callers must redact secrets before
                calling this method** (Requirement 5.5).
            max_tokens: Maximum tokens in the completion.
            timeout: Per-attempt deadline in seconds.
                :class:`~utils.ai.provider_base.LLMProviderUnavailableError`
                is raised immediately on expiry without retrying
                (Requirement 10.1).

        Returns:
            The text content of the first content block in the response.

        Raises:
            LLMProviderUnavailableError: On timeout, connection failure,
                authentication error, or exhausted rate-limit retries.
            LLMResponseParseError: If the response cannot be interpreted as
                expected (empty content, unexpected structure).
        """
        client = self._get_client()

        async def _attempt() -> str:
            async def _call() -> str:
                try:
                    response = await client.messages.create(
                        model=self._model,
                        max_tokens=max_tokens,
                        messages=[{"role": "user", "content": prompt}],
                    )
                except _AnthropicRateLimitError as exc:  # type: ignore[misc]
                    # Raise the retryable sentinel so retry_with_backoff handles it.
                    raise LLMRateLimitError(
                        f"Anthropic rate limit (HTTP 429): {exc}"
                    ) from exc
                except _AnthropicTimeoutError as exc:  # type: ignore[misc]
                    raise LLMProviderUnavailableError(
                        f"Anthropic request timed out after {timeout}s: {exc}"
                    ) from exc
                except _AnthropicConnectionError as exc:  # type: ignore[misc]
                    raise LLMProviderUnavailableError(
                        f"Anthropic connection error: {exc}"
                    ) from exc
                except _AnthropicAuthError as exc:  # type: ignore[misc]
                    raise LLMProviderUnavailableError(
                        f"Anthropic authentication error — check {_API_KEY_ENV_VAR}: {exc}"
                    ) from exc
                except _anthropic_sdk.APIError as exc:  # type: ignore[union-attr]
                    raise LLMProviderUnavailableError(
                        f"Anthropic API error ({type(exc).__name__}): {exc}"
                    ) from exc

                # Parse the response content.
                try:
                    content_blocks = response.content
                    if not content_blocks:
                        raise LLMResponseParseError(
                            "Anthropic returned an empty content list."
                        )
                    first_block = content_blocks[0]
                    # TextBlock has a .text attribute; other block types (tool_use,
                    # etc.) are not expected in plain completion calls.
                    if not hasattr(first_block, "text"):
                        raise LLMResponseParseError(
                            f"Unexpected Anthropic response block type: "
                            f"{type(first_block).__name__!r}. Expected TextBlock."
                        )
                    return first_block.text
                except LLMResponseParseError:
                    raise
                except Exception as exc:
                    raise LLMResponseParseError(
                        f"Failed to parse Anthropic response: {exc}"
                    ) from exc

            # Enforce the per-attempt timeout.  TimeoutError is NOT retried.
            try:
                return await asyncio.wait_for(_call(), timeout=timeout)
            except TimeoutError as exc:
                raise LLMProviderUnavailableError(
                    f"Anthropic request exceeded timeout of {timeout}s."
                ) from exc

        return await retry_with_backoff(
            _attempt,
            max_retries=self._config.max_retries,
        )

    def __repr__(self) -> str:
        return f"AnthropicProvider(model={self._model!r})"
