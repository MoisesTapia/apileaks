"""
utils.ai.provider_base — Abstract LLM provider interface and factory.

Defines:

- :class:`AIConfig` — configuration dataclass for the AI assistance layer.
- :class:`LLMProvider` — abstract base class all concrete providers implement.
- :func:`build_llm_provider` — factory that returns the configured provider, or
  ``None`` silently when no provider is configured (Requirement 7.2).
- :class:`LLMProviderUnavailableError` — raised when a configured provider
  cannot be reached (timeout, auth failure, etc.).
- :class:`LLMResponseParseError` — raised when a provider response cannot be
  parsed as expected.

Concrete provider implementations (``AnthropicProvider``, ``OpenAIProvider``,
``BedrockProvider``) live in sibling modules and depend on optional SDK extras
(``apileaks[ai]``).  Nothing in this module imports those SDKs, so the base
layer is always available even without the ``[ai]`` extra installed.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class LLMProviderUnavailableError(Exception):
    """The configured LLM provider did not respond or is not reachable.

    Callers of AI-assisted functions (triage, dedup) MUST catch this and
    degrade gracefully — the underlying scan MUST NOT fail (Requirement 10.1).
    """


class LLMResponseParseError(Exception):
    """The LLM provider returned a response that could not be parsed.

    Callers MUST catch this and continue the scan without the AI section
    (Requirement 10.2).
    """


class LLMRateLimitError(LLMProviderUnavailableError):
    """Rate-limit (HTTP 429) response from the LLM provider.

    This is a specialisation of :class:`LLMProviderUnavailableError` that the
    retry layer recognises as eligible for exponential back-off retry
    (Requirement 10.3).  Non-rate-limit failures — timeouts, auth errors,
    parse errors — propagate immediately without retrying.

    Raised by concrete providers when the underlying SDK signals a rate-limit;
    handled transparently by :func:`utils.ai.retry.retry_with_backoff`.
    """


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class AIConfig:
    """Configuration for the AI assistance layer.

    Attributes:
        provider: LLM provider to use. One of ``"anthropic"``, ``"openai"``,
            ``"bedrock"``, or ``None`` to disable AI assistance.
        model: Model identifier to pass to the provider (e.g.
            ``"claude-3-5-sonnet-20241022"``). When ``None`` the provider uses
            its own default.
        timeout_seconds: Per-request timeout in seconds (Requirement 10.1).
        max_retries: Maximum retry attempts on rate-limit errors before
            giving up on an AI function (Requirement 10.3).
    """

    provider: str | None = None  # "anthropic" | "openai" | "bedrock" | None
    model: str | None = None
    timeout_seconds: float = 30.0
    max_retries: int = 3


# ---------------------------------------------------------------------------
# Abstract base class
# ---------------------------------------------------------------------------


class LLMProvider(ABC):
    """Abstract base class for all LLM provider implementations.

    Concrete subclasses implement :meth:`complete` against a specific vendor
    API (Anthropic, OpenAI, Amazon Bedrock).  All provider-specific SDK
    imports live in the concrete subclass files so this module stays importable
    without any ``[ai]`` extras installed.
    """

    @abstractmethod
    async def complete(
        self,
        prompt: str,
        *,
        max_tokens: int,
        timeout: float,
    ) -> str:
        """Send *prompt* to the provider and return the completion text.

        Args:
            prompt: The full prompt string to send.  Callers are responsible
                for redacting secrets **before** calling this method
                (Requirement 5.5).
            max_tokens: Maximum number of tokens in the completion.
            timeout: Per-request timeout in seconds.  Implementations MUST
                honour this and raise :class:`LLMProviderUnavailableError` on
                expiry (Requirement 10.1).

        Returns:
            The completion string from the provider.

        Raises:
            LLMProviderUnavailableError: If the provider cannot be reached or
                the request times out.
            LLMResponseParseError: If the provider returns a response that
                cannot be interpreted as expected.
        """

    # ------------------------------------------------------------------
    # Optional extension points — concrete providers may override these
    # ------------------------------------------------------------------

    @property
    def provider_name(self) -> str:
        """Human-readable provider name, e.g. ``"anthropic"``."""
        return type(self).__name__

    def __repr__(self) -> str:  # pragma: no cover
        return f"{type(self).__name__}()"


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_llm_provider(config: AIConfig) -> LLMProvider | None:
    """Instantiate and return the :class:`LLMProvider` specified in *config*.

    Returns ``None`` **without raising** when no provider is configured
    (``config.provider is None``).  AI-assisted functions MUST handle a
    ``None`` return by degrading gracefully — they MUST NOT raise an
    unhandled exception or fail the parent scan (Requirement 7.2).

    Provider SDK modules (``anthropic``, ``openai``, ``boto3``) are imported
    lazily inside this function so the base package remains importable without
    the ``[ai]`` optional extras.

    Args:
        config: AI layer configuration.

    Returns:
        A configured :class:`LLMProvider` instance, or ``None`` if
        ``config.provider`` is ``None``.

    Raises:
        ValueError: If ``config.provider`` is a non-``None`` string that is
            not one of the supported values (``"anthropic"``, ``"openai"``,
            ``"bedrock"``).
        ImportError: If the required SDK for the configured provider is not
            installed (e.g. ``apileaks[ai]`` extra is missing).
    """
    if config.provider is None:
        logger.debug("No LLM provider configured — AI assistance disabled.")
        return None

    provider_key = config.provider.lower()

    if provider_key == "anthropic":
        from utils.ai.anthropic_provider import AnthropicProvider  # noqa: PLC0415

        return AnthropicProvider(config)

    if provider_key == "openai":
        from utils.ai.openai_provider import OpenAIProvider  # noqa: PLC0415

        return OpenAIProvider(config)

    if provider_key == "bedrock":
        from utils.ai.bedrock_provider import BedrockProvider  # noqa: PLC0415

        return BedrockProvider(config)

    supported = ("anthropic", "openai", "bedrock")
    raise ValueError(
        f"Unknown LLM provider {config.provider!r}. "
        f"Supported values: {', '.join(supported)}"
    )
