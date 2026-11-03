"""
utils.ai — Optional AI assistance layer for APILeak.

Provides a multi-provider LLM abstraction used by the finding triage
assistant and semantic deduplicator.

Install the optional extra to activate:
    pip install apileaks[ai]          # Anthropic + OpenAI providers
    pip install apileaks[aws]         # Amazon Bedrock provider (requires boto3)
    pip install apileaks[ai,aws]      # all providers

All public symbols are re-exported from this namespace for convenience.
The concrete provider classes (AnthropicProvider, OpenAIProvider,
BedrockProvider) are imported lazily through build_llm_provider — you
generally do not need to import them directly.

Rate-limit retry behaviour (Requirement 10.3) is implemented in
:mod:`utils.ai.retry` and integrated into each concrete provider.
"""

from utils.ai.provider_base import (
    AIConfig,
    LLMProvider,
    LLMProviderUnavailableError,
    LLMRateLimitError,
    LLMResponseParseError,
    build_llm_provider,
)
from utils.ai.retry import retry_with_backoff
from utils.ai.semantic_dedup import FindingGroup, SemanticDeduplicator
from utils.ai.triage_assistant import FindingTriageAssistant, TriageReport

__all__ = [
    "AIConfig",
    "LLMProvider",
    "LLMProviderUnavailableError",
    "LLMRateLimitError",
    "LLMResponseParseError",
    "build_llm_provider",
    "retry_with_backoff",
    "FindingTriageAssistant",
    "TriageReport",
    "SemanticDeduplicator",
    "FindingGroup",
    # Concrete providers — available after the respective SDK extras are installed.
    "AnthropicProvider",
    "OpenAIProvider",
    "BedrockProvider",
]


def __getattr__(name: str) -> object:
    """Lazy-load concrete provider classes to avoid hard import failures when
    the optional SDK extras are not installed."""
    if name == "AnthropicProvider":
        from utils.ai.anthropic_provider import AnthropicProvider

        return AnthropicProvider
    if name == "OpenAIProvider":
        from utils.ai.openai_provider import OpenAIProvider

        return OpenAIProvider
    if name == "BedrockProvider":
        from utils.ai.bedrock_provider import BedrockProvider

        return BedrockProvider
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
