"""
Tests for utils.ai.provider_base — LLMProvider ABC and build_llm_provider factory.

Covers:
- AIConfig dataclass defaults and field types.
- LLMProvider is abstract and cannot be instantiated directly.
- build_llm_provider returns None silently when config.provider is None (Req 7.2).
- build_llm_provider raises ValueError for unknown provider names.
- build_llm_provider delegates to the correct concrete provider module for
  each supported name ("anthropic", "openai", "bedrock").
- LLMProviderUnavailableError and LLMResponseParseError exist and are importable.
- utils.ai package re-exports all public symbols.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

# Pre-import core.logging directly (not via core/__init__) to break a
# pre-existing circular import in the project:
#   utils/__init__ → utils.findings → core.config → core/__init__
#   → core.engine → utils.findings (already initializing → ImportError)
# Importing core.logging first registers `core` in sys.modules without
# running core/__init__, so the cycle is never triggered.
import core.logging  # noqa: F401

from utils.ai.provider_base import (
    AIConfig,
    LLMProvider,
    LLMProviderUnavailableError,
    LLMResponseParseError,
    build_llm_provider,
)


# ---------------------------------------------------------------------------
# AIConfig dataclass
# ---------------------------------------------------------------------------


class TestAIConfig:
    def test_default_provider_is_none(self):
        config = AIConfig()
        assert config.provider is None

    def test_default_model_is_none(self):
        config = AIConfig()
        assert config.model is None

    def test_default_timeout(self):
        config = AIConfig()
        assert config.timeout_seconds == 30.0

    def test_default_max_retries(self):
        config = AIConfig()
        assert config.max_retries == 3

    def test_custom_values(self):
        config = AIConfig(
            provider="anthropic",
            model="claude-3-5-sonnet-20241022",
            timeout_seconds=60.0,
            max_retries=5,
        )
        assert config.provider == "anthropic"
        assert config.model == "claude-3-5-sonnet-20241022"
        assert config.timeout_seconds == 60.0
        assert config.max_retries == 5


# ---------------------------------------------------------------------------
# LLMProvider ABC
# ---------------------------------------------------------------------------


class TestLLMProviderABC:
    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError):
            LLMProvider()  # type: ignore[abstract]

    def test_concrete_subclass_must_implement_complete(self):
        """A subclass missing 'complete' should also be uninstantiable."""

        class Incomplete(LLMProvider):
            pass  # does not implement complete

        with pytest.raises(TypeError):
            Incomplete()  # type: ignore[abstract]

    def test_concrete_subclass_is_instantiable(self):
        class Minimal(LLMProvider):
            async def complete(self, prompt: str, *, max_tokens: int, timeout: float) -> str:
                return "ok"

        instance = Minimal()
        assert isinstance(instance, LLMProvider)

    def test_provider_name_default(self):
        class MyProvider(LLMProvider):
            async def complete(self, prompt: str, *, max_tokens: int, timeout: float) -> str:
                return ""

        assert MyProvider().provider_name == "MyProvider"


# ---------------------------------------------------------------------------
# build_llm_provider — None / disabled path
# ---------------------------------------------------------------------------


class TestBuildLLMProviderNone:
    def test_returns_none_when_provider_is_none(self):
        """Requirement 7.2: no exception, silent None."""
        config = AIConfig(provider=None)
        result = build_llm_provider(config)
        assert result is None

    def test_returns_none_for_default_config(self):
        result = build_llm_provider(AIConfig())
        assert result is None

    def test_does_not_raise_for_none_provider(self):
        """Should never raise — callers depend on this for graceful degradation."""
        try:
            build_llm_provider(AIConfig(provider=None))
        except Exception as exc:  # noqa: BLE001
            pytest.fail(f"build_llm_provider raised unexpectedly: {exc}")


# ---------------------------------------------------------------------------
# build_llm_provider — unknown provider raises ValueError
# ---------------------------------------------------------------------------


class TestBuildLLMProviderUnknown:
    @pytest.mark.parametrize("bad_provider", ["gpt4all", "cohere", "ollama", "", "NONE"])
    def test_raises_value_error_for_unknown_provider(self, bad_provider: str):
        config = AIConfig(provider=bad_provider)
        with pytest.raises(ValueError, match="Unknown LLM provider"):
            build_llm_provider(config)

    def test_error_message_lists_supported_providers(self):
        config = AIConfig(provider="unsupported")
        with pytest.raises(ValueError) as exc_info:
            build_llm_provider(config)
        msg = str(exc_info.value)
        assert "anthropic" in msg
        assert "openai" in msg
        assert "bedrock" in msg


# ---------------------------------------------------------------------------
# build_llm_provider — delegation to concrete providers (lazy imports)
# ---------------------------------------------------------------------------


class _FakeProvider(LLMProvider):
    """Stand-in for a real concrete provider in factory delegation tests."""

    def __init__(self, config: AIConfig) -> None:
        self.config = config

    async def complete(self, prompt: str, *, max_tokens: int, timeout: float) -> str:
        return "fake"


class TestBuildLLMProviderDelegation:
    """Verify that build_llm_provider imports and instantiates the correct
    concrete provider module for each supported provider name, without
    requiring the real SDKs to be installed."""

    def _patch_and_call(self, module_path: str, class_name: str, provider: str) -> LLMProvider:
        """Patch a concrete provider class with _FakeProvider and call factory."""
        with patch(module_path, _FakeProvider):
            config = AIConfig(provider=provider)
            return build_llm_provider(config)  # type: ignore[return-value]

    def test_anthropic_provider_instantiated(self):
        with patch.dict(
            "sys.modules",
            {
                "utils.ai.anthropic_provider": MagicMock(AnthropicProvider=_FakeProvider),
            },
        ):
            result = build_llm_provider(AIConfig(provider="anthropic"))
        assert isinstance(result, _FakeProvider)

    def test_openai_provider_instantiated(self):
        with patch.dict(
            "sys.modules",
            {
                "utils.ai.openai_provider": MagicMock(OpenAIProvider=_FakeProvider),
            },
        ):
            result = build_llm_provider(AIConfig(provider="openai"))
        assert isinstance(result, _FakeProvider)

    def test_bedrock_provider_instantiated(self):
        with patch.dict(
            "sys.modules",
            {
                "utils.ai.bedrock_provider": MagicMock(BedrockProvider=_FakeProvider),
            },
        ):
            result = build_llm_provider(AIConfig(provider="bedrock"))
        assert isinstance(result, _FakeProvider)

    def test_provider_name_case_insensitive(self):
        """Provider name matching is case-insensitive."""
        with patch.dict(
            "sys.modules",
            {
                "utils.ai.anthropic_provider": MagicMock(AnthropicProvider=_FakeProvider),
            },
        ):
            result = build_llm_provider(AIConfig(provider="ANTHROPIC"))
        assert isinstance(result, _FakeProvider)

    def test_config_forwarded_to_provider(self):
        config = AIConfig(provider="openai", model="gpt-4o", timeout_seconds=45.0)
        with patch.dict(
            "sys.modules",
            {
                "utils.ai.openai_provider": MagicMock(OpenAIProvider=_FakeProvider),
            },
        ):
            result = build_llm_provider(config)
        assert isinstance(result, _FakeProvider)
        assert result.config is config  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class TestExceptions:
    def test_unavailable_is_exception(self):
        exc = LLMProviderUnavailableError("timeout")
        assert isinstance(exc, Exception)
        assert "timeout" in str(exc)

    def test_parse_error_is_exception(self):
        exc = LLMResponseParseError("bad json")
        assert isinstance(exc, Exception)
        assert "bad json" in str(exc)

    def test_exceptions_are_distinct(self):
        assert LLMProviderUnavailableError is not LLMResponseParseError
        assert not issubclass(LLMProviderUnavailableError, LLMResponseParseError)
        assert not issubclass(LLMResponseParseError, LLMProviderUnavailableError)


# ---------------------------------------------------------------------------
# Package-level re-exports (utils.ai __init__)
# ---------------------------------------------------------------------------


class TestPackageReexports:
    def test_ai_init_exports_all_symbols(self):
        import utils.ai as ai_pkg

        for name in ("AIConfig", "LLMProvider", "LLMProviderUnavailableError",
                     "LLMResponseParseError", "build_llm_provider"):
            assert hasattr(ai_pkg, name), f"utils.ai is missing export: {name}"

    def test_ai_init_aiconfig_is_same_class(self):
        import utils.ai as ai_pkg

        assert ai_pkg.AIConfig is AIConfig

    def test_ai_init_llm_provider_is_same_class(self):
        import utils.ai as ai_pkg

        assert ai_pkg.LLMProvider is LLMProvider
