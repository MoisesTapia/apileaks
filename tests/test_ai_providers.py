"""
tests/test_ai_providers.py — Comprehensive mock-based tests for the three
concrete LLM providers: AnthropicProvider, OpenAIProvider, BedrockProvider.

All tests use mocks — NO real API calls are made (Requirement 11.2).
Tests that require a specific SDK use ``pytest.importorskip`` to skip
gracefully when the extra is not installed (Requirement 11.3).

Coverage (per provider):
- Happy path: complete() returns the text from a mocked response
- Missing credentials: LLMProviderUnavailableError when env var / creds absent
- SDK not installed: ImportError with a clear message mentioning pip install
- Auth error: SDK auth error → LLMProviderUnavailableError
- Connection error: network/connection error → LLMProviderUnavailableError
- Empty response: empty content/choices → LLMResponseParseError
- Malformed response: unexpected structure → LLMResponseParseError
- Config forwarded: config.model is used when set; default model when not
- provider_name: returns the expected string
- __repr__: contains the active model name

Rate-limit / backoff / timeout behaviour is already covered in
test_ai_retry.py and is intentionally NOT duplicated here.
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Break the circular import that exists at project level before anything else
# imports from utils/ — mirrors the pattern in test_ai_provider_base.py.
import core.logging  # noqa: F401

from utils.ai.provider_base import (
    AIConfig,
    LLMProviderUnavailableError,
    LLMResponseParseError,
)


# ---------------------------------------------------------------------------
# Helpers shared across provider test classes
# ---------------------------------------------------------------------------


def _make_config(**kwargs) -> AIConfig:
    """Return an AIConfig with sensible defaults for unit tests."""
    defaults = dict(timeout_seconds=5.0, max_retries=0)
    defaults.update(kwargs)
    return AIConfig(**defaults)


# ===========================================================================
# AnthropicProvider
# ===========================================================================


class TestAnthropicProvider:
    """Tests for utils.ai.anthropic_provider.AnthropicProvider.

    Each test calls pytest.importorskip("anthropic") so the test is
    silently skipped when the SDK extra is not installed (Requirement 11.3).
    """

    # ------------------------------------------------------------------
    # Internal factory — bypasses __init__ (which calls _require_sdk) via
    # object.__new__, mirroring the pattern used in test_ai_retry.py.
    # ------------------------------------------------------------------

    def _make_provider(self, model: str | None = None, max_retries: int = 0):
        pytest.importorskip("anthropic")
        from utils.ai.anthropic_provider import AnthropicProvider

        config = _make_config(provider="anthropic", model=model, max_retries=max_retries)
        provider = object.__new__(AnthropicProvider)
        provider._config = config
        provider._model = model or "claude-3-5-sonnet-20241022"
        provider._client = None
        return provider

    def _make_mock_client(self, text: str = "hello"):
        block = MagicMock()
        block.text = text
        resp = MagicMock()
        resp.content = [block]
        mock_client = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=resp)
        return mock_client

    # ------------------------------------------------------------------
    # Happy path
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_complete_returns_text(self):
        provider = self._make_provider()
        provider._client = self._make_mock_client("anthropic result")

        result = await provider.complete("prompt", max_tokens=100, timeout=5.0)

        assert result == "anthropic result"

    @pytest.mark.asyncio
    async def test_complete_calls_api_with_prompt_and_max_tokens(self):
        provider = self._make_provider()
        provider._client = self._make_mock_client("ok")

        await provider.complete("my prompt", max_tokens=256, timeout=5.0)

        provider._client.messages.create.assert_awaited_once()
        call_kwargs = provider._client.messages.create.call_args.kwargs
        assert call_kwargs.get("max_tokens") == 256
        messages = call_kwargs.get("messages", [])
        assert any("my prompt" in str(m) for m in messages)

    # ------------------------------------------------------------------
    # Config forwarding
    # ------------------------------------------------------------------

    def test_model_from_config_when_set(self):
        provider = self._make_provider(model="claude-3-opus-20240229")
        assert provider._model == "claude-3-opus-20240229"

    def test_default_model_when_config_model_is_none(self):
        provider = self._make_provider(model=None)
        assert provider._model == "claude-3-5-sonnet-20241022"

    @pytest.mark.asyncio
    async def test_model_sent_to_api(self):
        provider = self._make_provider(model="claude-3-haiku-20240307")
        provider._client = self._make_mock_client("ok")

        await provider.complete("hi", max_tokens=10, timeout=5.0)

        call_kwargs = provider._client.messages.create.call_args.kwargs
        assert call_kwargs.get("model") == "claude-3-haiku-20240307"

    # ------------------------------------------------------------------
    # Missing credentials
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_missing_api_key_raises_unavailable(self):
        """ANTHROPIC_API_KEY absent → LLMProviderUnavailableError before any call."""
        provider = self._make_provider()
        # _client is None so _get_client() → _resolve_api_key() will fire.

        env_without_key = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
        with patch.dict(os.environ, env_without_key, clear=True):
            with pytest.raises(LLMProviderUnavailableError, match="ANTHROPIC_API_KEY"):
                await provider.complete("hi", max_tokens=10, timeout=5.0)

    # ------------------------------------------------------------------
    # SDK not installed
    # ------------------------------------------------------------------

    def test_sdk_not_installed_raises_import_error(self):
        """When the SDK is absent, instantiation raises ImportError with pip hint."""
        pytest.importorskip("anthropic")
        from utils.ai.anthropic_provider import AnthropicProvider

        config = _make_config(provider="anthropic")
        with patch("utils.ai.anthropic_provider._SDK_AVAILABLE", False):
            with pytest.raises(ImportError, match="pip install apileaks"):
                AnthropicProvider(config)

    # ------------------------------------------------------------------
    # Auth error
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_auth_error_raises_unavailable(self):
        pytest.importorskip("anthropic")
        from anthropic import AuthenticationError as AnthropicAuthError

        provider = self._make_provider()

        async def fake_create(**kwargs):
            raise AnthropicAuthError(
                message="invalid api key",
                response=MagicMock(status_code=401, headers={}),
                body=None,
            )

        mock_client = MagicMock()
        mock_client.messages.create = fake_create
        provider._client = mock_client

        with pytest.raises(LLMProviderUnavailableError, match="authentication"):
            await provider.complete("hi", max_tokens=10, timeout=5.0)

    # ------------------------------------------------------------------
    # Connection error
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_connection_error_raises_unavailable(self):
        pytest.importorskip("anthropic")
        from anthropic import APIConnectionError as AnthropicConnectionError

        provider = self._make_provider()

        async def fake_create(**kwargs):
            raise AnthropicConnectionError(request=MagicMock())

        mock_client = MagicMock()
        mock_client.messages.create = fake_create
        provider._client = mock_client

        with pytest.raises(LLMProviderUnavailableError, match="connection"):
            await provider.complete("hi", max_tokens=10, timeout=5.0)

    # ------------------------------------------------------------------
    # Empty response
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_empty_content_list_raises_parse_error(self):
        provider = self._make_provider()

        resp = MagicMock()
        resp.content = []
        mock_client = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=resp)
        provider._client = mock_client

        with pytest.raises(LLMResponseParseError, match="empty"):
            await provider.complete("hi", max_tokens=10, timeout=5.0)

    # ------------------------------------------------------------------
    # Malformed response
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_non_text_block_raises_parse_error(self):
        """First block has no .text attribute (e.g. a tool_use block)."""
        provider = self._make_provider()

        non_text_block = MagicMock(spec=[])  # no attributes at all
        resp = MagicMock()
        resp.content = [non_text_block]
        mock_client = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=resp)
        provider._client = mock_client

        with pytest.raises(LLMResponseParseError):
            await provider.complete("hi", max_tokens=10, timeout=5.0)

    # ------------------------------------------------------------------
    # provider_name and __repr__
    # ------------------------------------------------------------------

    def test_provider_name(self):
        provider = self._make_provider()
        assert provider.provider_name == "anthropic"

    def test_repr_contains_model(self):
        provider = self._make_provider(model="claude-3-5-sonnet-20241022")
        assert "claude-3-5-sonnet-20241022" in repr(provider)


# ===========================================================================
# OpenAIProvider
# ===========================================================================


class TestOpenAIProvider:
    """Tests for utils.ai.openai_provider.OpenAIProvider."""

    def _make_provider(self, model: str | None = None, max_retries: int = 0):
        pytest.importorskip("openai")
        from utils.ai.openai_provider import OpenAIProvider

        config = _make_config(provider="openai", model=model, max_retries=max_retries)
        provider = object.__new__(OpenAIProvider)
        provider._config = config
        provider._model = model or "gpt-4o"
        provider._client = None
        return provider

    def _make_mock_client(self, text: str = "openai result"):
        msg = MagicMock()
        msg.content = text
        choice = MagicMock()
        choice.message = msg
        resp = MagicMock()
        resp.choices = [choice]
        mock_client = MagicMock()
        mock_client.chat.completions.create = AsyncMock(return_value=resp)
        return mock_client

    # ------------------------------------------------------------------
    # Happy path
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_complete_returns_text(self):
        provider = self._make_provider()
        provider._client = self._make_mock_client("openai result")

        result = await provider.complete("prompt", max_tokens=100, timeout=5.0)

        assert result == "openai result"

    @pytest.mark.asyncio
    async def test_complete_calls_api_with_prompt_and_max_tokens(self):
        provider = self._make_provider()
        provider._client = self._make_mock_client("ok")

        await provider.complete("my openai prompt", max_tokens=512, timeout=5.0)

        provider._client.chat.completions.create.assert_awaited_once()
        call_kwargs = provider._client.chat.completions.create.call_args.kwargs
        assert call_kwargs.get("max_tokens") == 512
        messages = call_kwargs.get("messages", [])
        assert any("my openai prompt" in str(m) for m in messages)

    # ------------------------------------------------------------------
    # Config forwarding
    # ------------------------------------------------------------------

    def test_model_from_config_when_set(self):
        provider = self._make_provider(model="gpt-4-turbo")
        assert provider._model == "gpt-4-turbo"

    def test_default_model_when_config_model_is_none(self):
        provider = self._make_provider(model=None)
        assert provider._model == "gpt-4o"

    @pytest.mark.asyncio
    async def test_model_sent_to_api(self):
        provider = self._make_provider(model="gpt-3.5-turbo")
        provider._client = self._make_mock_client("ok")

        await provider.complete("hi", max_tokens=10, timeout=5.0)

        call_kwargs = provider._client.chat.completions.create.call_args.kwargs
        assert call_kwargs.get("model") == "gpt-3.5-turbo"

    # ------------------------------------------------------------------
    # Missing credentials
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_missing_api_key_raises_unavailable(self):
        """OPENAI_API_KEY absent → LLMProviderUnavailableError before any call."""
        provider = self._make_provider()

        env_without_key = {k: v for k, v in os.environ.items() if k != "OPENAI_API_KEY"}
        with patch.dict(os.environ, env_without_key, clear=True):
            with pytest.raises(LLMProviderUnavailableError, match="OPENAI_API_KEY"):
                await provider.complete("hi", max_tokens=10, timeout=5.0)

    # ------------------------------------------------------------------
    # SDK not installed
    # ------------------------------------------------------------------

    def test_sdk_not_installed_raises_import_error(self):
        pytest.importorskip("openai")
        from utils.ai.openai_provider import OpenAIProvider

        config = _make_config(provider="openai")
        with patch("utils.ai.openai_provider._SDK_AVAILABLE", False):
            with pytest.raises(ImportError, match="pip install apileaks"):
                OpenAIProvider(config)

    # ------------------------------------------------------------------
    # Auth error
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_auth_error_raises_unavailable(self):
        pytest.importorskip("openai")
        from openai import AuthenticationError as OpenAIAuthError

        provider = self._make_provider()

        async def fake_create(**kwargs):
            raise OpenAIAuthError(
                message="Incorrect API key",
                response=MagicMock(
                    status_code=401,
                    headers={},
                    json=MagicMock(return_value={"error": {"message": "Incorrect API key"}}),
                    text="Incorrect API key",
                    request=MagicMock(),
                ),
                body={"error": {"message": "Incorrect API key"}},
            )

        mock_client = MagicMock()
        mock_client.chat.completions.create = fake_create
        provider._client = mock_client

        with pytest.raises(LLMProviderUnavailableError, match="authentication"):
            await provider.complete("hi", max_tokens=10, timeout=5.0)

    # ------------------------------------------------------------------
    # Connection error
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_connection_error_raises_unavailable(self):
        pytest.importorskip("openai")
        from openai import APIConnectionError as OpenAIConnectionError

        provider = self._make_provider()

        async def fake_create(**kwargs):
            raise OpenAIConnectionError(request=MagicMock())

        mock_client = MagicMock()
        mock_client.chat.completions.create = fake_create
        provider._client = mock_client

        with pytest.raises(LLMProviderUnavailableError, match="connection"):
            await provider.complete("hi", max_tokens=10, timeout=5.0)

    # ------------------------------------------------------------------
    # Empty response
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_empty_choices_raises_parse_error(self):
        provider = self._make_provider()

        resp = MagicMock()
        resp.choices = []
        mock_client = MagicMock()
        mock_client.chat.completions.create = AsyncMock(return_value=resp)
        provider._client = mock_client

        with pytest.raises(LLMResponseParseError, match="choices"):
            await provider.complete("hi", max_tokens=10, timeout=5.0)

    # ------------------------------------------------------------------
    # Malformed response
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_null_message_content_raises_parse_error(self):
        """Choice with message.content = None → LLMResponseParseError."""
        provider = self._make_provider()

        msg = MagicMock()
        msg.content = None
        choice = MagicMock()
        choice.message = msg
        resp = MagicMock()
        resp.choices = [choice]
        mock_client = MagicMock()
        mock_client.chat.completions.create = AsyncMock(return_value=resp)
        provider._client = mock_client

        with pytest.raises(LLMResponseParseError, match="null"):
            await provider.complete("hi", max_tokens=10, timeout=5.0)

    # ------------------------------------------------------------------
    # provider_name and __repr__
    # ------------------------------------------------------------------

    def test_provider_name(self):
        provider = self._make_provider()
        assert provider.provider_name == "openai"

    def test_repr_contains_model(self):
        provider = self._make_provider(model="gpt-4o")
        assert "gpt-4o" in repr(provider)


# ===========================================================================
# BedrockProvider
# ===========================================================================


class TestBedrockProvider:
    """Tests for utils.ai.bedrock_provider.BedrockProvider.

    boto3 calls are synchronous and dispatched via run_in_executor.  We mock
    the boto3 client's ``converse`` method synchronously; the provider wraps
    it in a thread-pool call transparently.
    """

    def _make_provider(self, model: str | None = None, max_retries: int = 0):
        pytest.importorskip("boto3")
        from utils.ai.bedrock_provider import BedrockProvider

        config = _make_config(provider="bedrock", model=model, max_retries=max_retries)
        provider = object.__new__(BedrockProvider)
        provider._config = config
        provider._model = model or "anthropic.claude-3-5-sonnet-20241022-v2:0"
        provider._client = MagicMock()  # pre-populate so _get_client() is bypassed
        return provider

    def _bedrock_response(self, text: str = "bedrock result") -> dict:
        return {"output": {"message": {"content": [{"text": text}]}}}

    def _client_error(self, code: str):
        import botocore.exceptions

        return botocore.exceptions.ClientError(
            {"Error": {"Code": code, "Message": "synthetic error"}},
            "Converse",
        )

    # ------------------------------------------------------------------
    # Happy path
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_complete_returns_text(self):
        provider = self._make_provider()
        provider._client.converse.return_value = self._bedrock_response("bedrock result")

        result = await provider.complete("prompt", max_tokens=100, timeout=5.0)

        assert result == "bedrock result"

    @pytest.mark.asyncio
    async def test_complete_calls_converse_with_prompt(self):
        provider = self._make_provider()
        provider._client.converse.return_value = self._bedrock_response("ok")

        await provider.complete("my bedrock prompt", max_tokens=256, timeout=5.0)

        provider._client.converse.assert_called_once()
        call_kwargs = provider._client.converse.call_args.kwargs
        messages = call_kwargs.get("messages", [])
        assert any("my bedrock prompt" in str(m) for m in messages)

    @pytest.mark.asyncio
    async def test_complete_passes_max_tokens(self):
        provider = self._make_provider()
        provider._client.converse.return_value = self._bedrock_response("ok")

        await provider.complete("hi", max_tokens=512, timeout=5.0)

        call_kwargs = provider._client.converse.call_args.kwargs
        inference_config = call_kwargs.get("inferenceConfig", {})
        assert inference_config.get("maxTokens") == 512

    # ------------------------------------------------------------------
    # Config forwarding
    # ------------------------------------------------------------------

    def test_model_from_config_when_set(self):
        provider = self._make_provider(model="amazon.titan-text-express-v1")
        assert provider._model == "amazon.titan-text-express-v1"

    def test_default_model_when_config_model_is_none(self):
        provider = self._make_provider(model=None)
        assert provider._model == "anthropic.claude-3-5-sonnet-20241022-v2:0"

    @pytest.mark.asyncio
    async def test_model_id_sent_to_api(self):
        provider = self._make_provider(model="amazon.titan-text-express-v1")
        provider._client.converse.return_value = self._bedrock_response("ok")

        await provider.complete("hi", max_tokens=10, timeout=5.0)

        call_kwargs = provider._client.converse.call_args.kwargs
        assert call_kwargs.get("modelId") == "amazon.titan-text-express-v1"

    # ------------------------------------------------------------------
    # Missing / invalid credentials (NoCredentialsError → BotoCoreError)
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_no_credentials_raises_unavailable(self):
        """botocore.NoCredentialsError (a BotoCoreError) → LLMProviderUnavailableError."""
        pytest.importorskip("boto3")
        import botocore.exceptions

        provider = self._make_provider()
        provider._client.converse.side_effect = botocore.exceptions.NoCredentialsError()

        with pytest.raises(LLMProviderUnavailableError):
            await provider.complete("hi", max_tokens=10, timeout=5.0)

    # ------------------------------------------------------------------
    # SDK not installed
    # ------------------------------------------------------------------

    def test_sdk_not_installed_raises_import_error(self):
        pytest.importorskip("boto3")
        from utils.ai.bedrock_provider import BedrockProvider

        config = _make_config(provider="bedrock")
        with patch("utils.ai.bedrock_provider._SDK_AVAILABLE", False):
            with pytest.raises(ImportError, match="pip install apileaks"):
                BedrockProvider(config)

    # ------------------------------------------------------------------
    # Auth / permission error (non-throttle ClientError)
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_access_denied_raises_unavailable(self):
        provider = self._make_provider()
        provider._client.converse.side_effect = self._client_error("AccessDeniedException")

        with pytest.raises(LLMProviderUnavailableError):
            await provider.complete("hi", max_tokens=10, timeout=5.0)

    # ------------------------------------------------------------------
    # Connection / endpoint error
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_endpoint_resolution_error_raises_unavailable(self):
        pytest.importorskip("boto3")
        import botocore.exceptions

        provider = self._make_provider()
        provider._client.converse.side_effect = botocore.exceptions.EndpointResolutionError(
            msg="bedrock-runtime.us-east-1.amazonaws.com could not be resolved"
        )

        with pytest.raises(LLMProviderUnavailableError, match="endpoint"):
            await provider.complete("hi", max_tokens=10, timeout=5.0)

    @pytest.mark.asyncio
    async def test_generic_boto_error_raises_unavailable(self):
        pytest.importorskip("boto3")
        import botocore.exceptions

        provider = self._make_provider()
        provider._client.converse.side_effect = botocore.exceptions.BotoCoreError()

        with pytest.raises(LLMProviderUnavailableError):
            await provider.complete("hi", max_tokens=10, timeout=5.0)

    @pytest.mark.asyncio
    async def test_unexpected_exception_raises_unavailable(self):
        """Non-botocore exceptions (e.g. OSError) are also wrapped."""
        provider = self._make_provider()
        provider._client.converse.side_effect = OSError("network gone")

        with pytest.raises(LLMProviderUnavailableError, match="Unexpected"):
            await provider.complete("hi", max_tokens=10, timeout=5.0)

    # ------------------------------------------------------------------
    # Empty response
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_empty_content_blocks_raises_parse_error(self):
        provider = self._make_provider()
        provider._client.converse.return_value = {
            "output": {"message": {"content": []}}
        }

        with pytest.raises(LLMResponseParseError, match="content blocks"):
            await provider.complete("hi", max_tokens=10, timeout=5.0)

    # ------------------------------------------------------------------
    # Malformed response
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_block_without_text_key_raises_parse_error(self):
        """First content block has no 'text' key."""
        provider = self._make_provider()
        provider._client.converse.return_value = {
            "output": {"message": {"content": [{"image": "..."}]}}
        }

        with pytest.raises(LLMResponseParseError, match="text"):
            await provider.complete("hi", max_tokens=10, timeout=5.0)

    @pytest.mark.asyncio
    async def test_missing_output_key_raises_parse_error(self):
        """Response missing 'output' → falls through to empty content → parse error."""
        provider = self._make_provider()
        provider._client.converse.return_value = {}

        with pytest.raises(LLMResponseParseError):
            await provider.complete("hi", max_tokens=10, timeout=5.0)

    # ------------------------------------------------------------------
    # _invoke_sync unit tests (synchronous helper tested directly)
    # ------------------------------------------------------------------

    def test_invoke_sync_happy_path(self):
        pytest.importorskip("boto3")

        provider = self._make_provider()
        mock_client = MagicMock()
        mock_client.converse.return_value = self._bedrock_response("sync result")

        result = provider._invoke_sync(mock_client, provider._model, "prompt", 100)

        assert result == "sync result"

    def test_invoke_sync_unknown_client_error_raises_unavailable(self):
        pytest.importorskip("boto3")

        provider = self._make_provider()
        mock_client = MagicMock()
        mock_client.converse.side_effect = self._client_error("ModelNotFound")

        with pytest.raises(LLMProviderUnavailableError, match="ModelNotFound"):
            provider._invoke_sync(mock_client, provider._model, "prompt", 100)

    # ------------------------------------------------------------------
    # _get_client — region resolution
    # ------------------------------------------------------------------

    def test_get_client_uses_aws_default_region(self):
        """AWS_DEFAULT_REGION is forwarded to the boto3 client constructor."""
        pytest.importorskip("boto3")
        from utils.ai.bedrock_provider import BedrockProvider

        config = _make_config(provider="bedrock")
        provider = object.__new__(BedrockProvider)
        provider._config = config
        provider._model = "anthropic.claude-3-5-sonnet-20241022-v2:0"
        provider._client = None  # force _get_client() to build a new client

        with (
            patch.dict(os.environ, {"AWS_DEFAULT_REGION": "eu-west-1"}),
            patch("utils.ai.bedrock_provider._boto3") as mock_boto3,
        ):
            mock_boto3.client.return_value = MagicMock()
            provider._get_client()

        mock_boto3.client.assert_called_once_with(
            "bedrock-runtime", region_name="eu-west-1"
        )

    def test_get_client_falls_back_to_aws_region_env(self):
        """Falls back to AWS_REGION when AWS_DEFAULT_REGION is absent."""
        pytest.importorskip("boto3")
        from utils.ai.bedrock_provider import BedrockProvider

        config = _make_config(provider="bedrock")
        provider = object.__new__(BedrockProvider)
        provider._config = config
        provider._model = "anthropic.claude-3-5-sonnet-20241022-v2:0"
        provider._client = None

        env = {k: v for k, v in os.environ.items() if k != "AWS_DEFAULT_REGION"}
        env["AWS_REGION"] = "ap-southeast-1"

        with (
            patch.dict(os.environ, env, clear=True),
            patch("utils.ai.bedrock_provider._boto3") as mock_boto3,
        ):
            mock_boto3.client.return_value = MagicMock()
            provider._get_client()

        mock_boto3.client.assert_called_once_with(
            "bedrock-runtime", region_name="ap-southeast-1"
        )

    def test_get_client_cached_after_first_call(self):
        """_get_client() returns the same object on subsequent calls."""
        provider = self._make_provider()
        existing_client = provider._client

        returned = provider._get_client()

        assert returned is existing_client

    # ------------------------------------------------------------------
    # provider_name and __repr__
    # ------------------------------------------------------------------

    def test_provider_name(self):
        provider = self._make_provider()
        assert provider.provider_name == "bedrock"

    def test_repr_contains_model(self):
        provider = self._make_provider(model="anthropic.claude-3-5-sonnet-20241022-v2:0")
        assert "anthropic.claude-3-5-sonnet-20241022-v2:0" in repr(provider)
