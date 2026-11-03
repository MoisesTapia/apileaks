"""
utils.ai.openai_provider — OpenAI GPT LLM provider implementation.

Requires the ``apileaks[ai]`` optional extra::

    pip install apileaks[ai]

Credentials are resolved exclusively from the environment variable
``OPENAI_API_KEY`` — never from YAML or any plaintext config file
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
    import openai as _openai_sdk
    from openai import (
        APIConnectionError as _OpenAIConnectionError,
    )
    from openai import (
        APITimeoutError as _OpenAITimeoutError,
    )
    from openai import AsyncOpenAI
    from openai import (
        AuthenticationError as _OpenAIAuthError,
    )
    from openai import (
        RateLimitError as _OpenAIRateLimitError,
    )

    _SDK_AVAILABLE = True
except ImportError:
    _SDK_AVAILABLE = False
    _openai_sdk = None  # type: ignore[assignment]
    AsyncOpenAI = None  # type: ignore[assignment,misc]
    _OpenAIConnectionError = None  # type: ignore[assignment,misc]
    _OpenAITimeoutError = None  # type: ignore[assignment,misc]
    _OpenAIAuthError = None  # type: ignore[assignment,misc]
    _OpenAIRateLimitError = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

# Default model used when AIConfig.model is not set.
_DEFAULT_MODEL = "gpt-4o"

# Environment variable that carries the OpenAI API key.
_API_KEY_ENV_VAR = "OPENAI_API_KEY"


def _require_sdk() -> None:
    """Raise a clear ImportError if the OpenAI SDK is not installed."""
    if not _SDK_AVAILABLE:
        raise ImportError(
            "The 'openai' package is required for OpenAIProvider. "
            "Install the AI optional extra with:  pip install apileaks[ai]"
        )


def _resolve_api_key() -> str:
    """Resolve the OpenAI API key from the environment.

    Returns the key string if found.

    Raises:
        LLMProviderUnavailableError: If ``OPENAI_API_KEY`` is not set.
    """
    key = os.environ.get(_API_KEY_ENV_VAR)
    if not key:
        raise LLMProviderUnavailableError(
            f"OpenAI API key not found. "
            f"Set the {_API_KEY_ENV_VAR!r} environment variable. "
            "Never put credentials in the APILeak YAML config (Requirement 7.3)."
        )
    return key


class OpenAIProvider(LLMProvider):
    """LLM provider that calls the OpenAI Chat Completions API.

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
        self._client: AsyncOpenAI | None = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_client(self) -> AsyncOpenAI:
        """Return (and cache) the async OpenAI client."""
        if self._client is None:
            api_key = _resolve_api_key()
            # Pass timeout=None here; we enforce the deadline ourselves via
            # asyncio.wait_for so that error messages are consistent across
            # providers.
            self._client = AsyncOpenAI(api_key=api_key)
        return self._client

    # ------------------------------------------------------------------
    # LLMProvider interface
    # ------------------------------------------------------------------

    @property
    def provider_name(self) -> str:
        return "openai"

    async def complete(
        self,
        prompt: str,
        *,
        max_tokens: int,
        timeout: float,
    ) -> str:
        """Send *prompt* to the OpenAI Chat Completions API and return the text.

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
            The text content of the first choice's message.

        Raises:
            LLMProviderUnavailableError: On timeout, connection failure,
                authentication error, or exhausted rate-limit retries.
            LLMResponseParseError: If the response cannot be interpreted as
                expected (empty choices, null content).
        """
        client = self._get_client()

        async def _attempt() -> str:
            async def _call() -> str:
                try:
                    response = await client.chat.completions.create(
                        model=self._model,
                        messages=[{"role": "user", "content": prompt}],
                        max_tokens=max_tokens,
                    )
                except _OpenAIRateLimitError as exc:  # type: ignore[misc]
                    # Raise the retryable sentinel so retry_with_backoff handles it.
                    raise LLMRateLimitError(
                        f"OpenAI rate limit (HTTP 429): {exc}"
                    ) from exc
                except _OpenAITimeoutError as exc:  # type: ignore[misc]
                    raise LLMProviderUnavailableError(
                        f"OpenAI request timed out after {timeout}s: {exc}"
                    ) from exc
                except _OpenAIConnectionError as exc:  # type: ignore[misc]
                    raise LLMProviderUnavailableError(
                        f"OpenAI connection error: {exc}"
                    ) from exc
                except _OpenAIAuthError as exc:  # type: ignore[misc]
                    raise LLMProviderUnavailableError(
                        f"OpenAI authentication error — check {_API_KEY_ENV_VAR}: {exc}"
                    ) from exc
                except _openai_sdk.APIError as exc:  # type: ignore[union-attr]
                    raise LLMProviderUnavailableError(
                        f"OpenAI API error ({type(exc).__name__}): {exc}"
                    ) from exc

                # Parse the response.
                try:
                    choices = response.choices
                    if not choices:
                        raise LLMResponseParseError(
                            "OpenAI returned a response with no choices."
                        )
                    message_content = choices[0].message.content
                    if message_content is None:
                        raise LLMResponseParseError(
                            "OpenAI returned a choice with null message content."
                        )
                    return message_content
                except LLMResponseParseError:
                    raise
                except Exception as exc:
                    raise LLMResponseParseError(
                        f"Failed to parse OpenAI response: {exc}"
                    ) from exc

            # Enforce the per-attempt timeout.  TimeoutError is NOT retried.
            try:
                return await asyncio.wait_for(_call(), timeout=timeout)
            except TimeoutError as exc:
                raise LLMProviderUnavailableError(
                    f"OpenAI request exceeded timeout of {timeout}s."
                ) from exc

        return await retry_with_backoff(
            _attempt,
            max_retries=self._config.max_retries,
        )

    def __repr__(self) -> str:
        return f"OpenAIProvider(model={self._model!r})"
