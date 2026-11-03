"""
Tests for utils.ai.retry — retry_with_backoff helper — and for the
rate-limit / timeout behaviour added to each concrete LLM provider.

All tests use mocks; no real API calls are made (Requirement 11.2).

Coverage:
- retry_with_backoff retries on LLMRateLimitError up to max_retries (Req 10.3)
- retry_with_backoff does NOT retry on LLMProviderUnavailableError (Req 10.1)
- retry_with_backoff does NOT retry on LLMResponseParseError
- retry_with_backoff raises LLMProviderUnavailableError after exhausting retries
- Exponential back-off delay doubles each attempt, capped at max_delay
- Jitter can be disabled (jitter=False) for deterministic testing
- Immediate success path returns value without sleeping
- AnthropicProvider: RateLimitError → LLMRateLimitError → retry (Req 10.3)
- AnthropicProvider: timeout → LLMProviderUnavailableError, no retry (Req 10.1)
- OpenAIProvider: RateLimitError → LLMRateLimitError → retry (Req 10.3)
- OpenAIProvider: timeout → LLMProviderUnavailableError, no retry (Req 10.1)
- BedrockProvider: ThrottlingException → LLMRateLimitError → retry (Req 10.3)
- BedrockProvider: TooManyRequestsException → LLMRateLimitError → retry (Req 10.3)
- BedrockProvider: timeout → LLMProviderUnavailableError, no retry (Req 10.1)
- LLMRateLimitError is a subclass of LLMProviderUnavailableError
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import core.logging  # noqa: F401 — break circular import (see test_ai_provider_base.py)

from utils.ai.provider_base import (
    AIConfig,
    LLMProviderUnavailableError,
    LLMRateLimitError,
    LLMResponseParseError,
)
from utils.ai.retry import retry_with_backoff


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_attempt_seq(*outcomes):
    """Return an async callable that yields each *outcome* in sequence.

    Each outcome is either:
    - An exception type/instance  → raised on that call.
    - A non-exception value       → returned on that call.
    """
    call_count = 0

    async def _attempt():
        nonlocal call_count
        result = outcomes[min(call_count, len(outcomes) - 1)]
        call_count += 1
        if isinstance(result, BaseException):
            raise result
        if isinstance(result, type) and issubclass(result, BaseException):
            raise result("synthetic")
        return result

    return _attempt


# ---------------------------------------------------------------------------
# LLMRateLimitError hierarchy
# ---------------------------------------------------------------------------


class TestLLMRateLimitError:
    def test_is_subclass_of_unavailable(self):
        assert issubclass(LLMRateLimitError, LLMProviderUnavailableError)

    def test_is_exception(self):
        exc = LLMRateLimitError("too many requests")
        assert isinstance(exc, Exception)
        assert "too many" in str(exc)

    def test_not_subclass_of_parse_error(self):
        assert not issubclass(LLMRateLimitError, LLMResponseParseError)


# ---------------------------------------------------------------------------
# retry_with_backoff — core behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestRetryWithBackoff:
    async def test_success_on_first_attempt(self):
        """No retries needed when the first call succeeds."""
        fn = _make_attempt_seq("hello")
        result = await retry_with_backoff(fn, max_retries=3, jitter=False)
        assert result == "hello"

    async def test_succeeds_after_one_rate_limit(self):
        """Retries once on LLMRateLimitError, then succeeds."""
        fn = _make_attempt_seq(LLMRateLimitError("429"), "ok")
        with patch("utils.ai.retry.asyncio.sleep", new=AsyncMock()) as mock_sleep:
            result = await retry_with_backoff(fn, max_retries=3, jitter=False)
        assert result == "ok"
        mock_sleep.assert_awaited_once()

    async def test_succeeds_after_multiple_rate_limits(self):
        """Retries on every attempt until success."""
        fn = _make_attempt_seq(
            LLMRateLimitError("429"),
            LLMRateLimitError("429"),
            "done",
        )
        with patch("utils.ai.retry.asyncio.sleep", new=AsyncMock()):
            result = await retry_with_backoff(fn, max_retries=3, jitter=False)
        assert result == "done"

    async def test_raises_after_exhausting_retries(self):
        """Raises LLMProviderUnavailableError once max_retries are exhausted."""
        fn = _make_attempt_seq(
            LLMRateLimitError("1"),
            LLMRateLimitError("2"),
            LLMRateLimitError("3"),
            LLMRateLimitError("4"),
        )
        with patch("utils.ai.retry.asyncio.sleep", new=AsyncMock()):
            with pytest.raises(LLMProviderUnavailableError, match="exhausted"):
                await retry_with_backoff(fn, max_retries=3, jitter=False)

    async def test_zero_retries_no_sleep(self):
        """max_retries=0 means one attempt total; no sleep on failure."""
        fn = _make_attempt_seq(LLMRateLimitError("429"))
        with patch("utils.ai.retry.asyncio.sleep", new=AsyncMock()) as mock_sleep:
            with pytest.raises(LLMProviderUnavailableError):
                await retry_with_backoff(fn, max_retries=0, jitter=False)
        mock_sleep.assert_not_awaited()

    async def test_does_not_retry_on_unavailable_error(self):
        """Non-rate-limit LLMProviderUnavailableError propagates immediately."""
        fn = _make_attempt_seq(LLMProviderUnavailableError("timeout"))
        with patch("utils.ai.retry.asyncio.sleep", new=AsyncMock()) as mock_sleep:
            with pytest.raises(LLMProviderUnavailableError, match="timeout"):
                await retry_with_backoff(fn, max_retries=5, jitter=False)
        mock_sleep.assert_not_awaited()

    async def test_does_not_retry_on_parse_error(self):
        """LLMResponseParseError propagates immediately, no retry."""
        fn = _make_attempt_seq(LLMResponseParseError("bad json"))
        with patch("utils.ai.retry.asyncio.sleep", new=AsyncMock()) as mock_sleep:
            with pytest.raises(LLMResponseParseError):
                await retry_with_backoff(fn, max_retries=5, jitter=False)
        mock_sleep.assert_not_awaited()

    async def test_does_not_retry_on_arbitrary_exception(self):
        """Any other exception propagates immediately."""
        fn = _make_attempt_seq(ValueError("unexpected"))
        with patch("utils.ai.retry.asyncio.sleep", new=AsyncMock()) as mock_sleep:
            with pytest.raises(ValueError, match="unexpected"):
                await retry_with_backoff(fn, max_retries=5, jitter=False)
        mock_sleep.assert_not_awaited()

    async def test_exponential_backoff_delay_doubles(self):
        """Sleep delay doubles each retry attempt, capped at max_delay."""
        sleep_calls: list[float] = []

        async def fake_sleep(delay: float) -> None:
            sleep_calls.append(delay)

        fn = _make_attempt_seq(
            LLMRateLimitError("1"),
            LLMRateLimitError("2"),
            LLMRateLimitError("3"),
            "ok",
        )
        with patch("utils.ai.retry.asyncio.sleep", side_effect=fake_sleep):
            result = await retry_with_backoff(
                fn, max_retries=5, initial_delay=1.0, max_delay=60.0, jitter=False
            )
        assert result == "ok"
        # Delays should be 1.0, 2.0, 4.0 (doubling each time)
        assert sleep_calls == [1.0, 2.0, 4.0]

    async def test_delay_capped_at_max_delay(self):
        """Delay does not exceed max_delay."""
        sleep_calls: list[float] = []

        async def fake_sleep(delay: float) -> None:
            sleep_calls.append(delay)

        fn = _make_attempt_seq(
            LLMRateLimitError("1"),
            LLMRateLimitError("2"),
            LLMRateLimitError("3"),
            "ok",
        )
        with patch("utils.ai.retry.asyncio.sleep", side_effect=fake_sleep):
            await retry_with_backoff(
                fn, max_retries=5, initial_delay=10.0, max_delay=15.0, jitter=False
            )
        # 10 → 15 (capped) → 15 (capped)
        assert sleep_calls[0] == 10.0
        assert all(d <= 15.0 for d in sleep_calls)

    async def test_jitter_produces_non_deterministic_delay(self):
        """With jitter=True the sleep value is different from the base delay."""
        sleep_calls: list[float] = []

        async def fake_sleep(delay: float) -> None:
            sleep_calls.append(delay)

        # Recreate fn each iteration — call_count is captured in its closure.
        for _ in range(10):
            fn = _make_attempt_seq(LLMRateLimitError("1"), "ok")
            sleep_calls.clear()
            with patch("utils.ai.retry.asyncio.sleep", side_effect=fake_sleep):
                await retry_with_backoff(
                    fn, max_retries=3, initial_delay=2.0, max_delay=60.0, jitter=True
                )
            # Jitter multiplier is [0.5, 1.5], so delay is in [1.0, 3.0]
            assert len(sleep_calls) == 1
            assert 1.0 <= sleep_calls[0] <= 3.0

    async def test_exhaust_message_mentions_retries(self):
        """Error message after exhaustion mentions the number of retries."""
        fn = _make_attempt_seq(*(LLMRateLimitError("x") for _ in range(5)))
        with patch("utils.ai.retry.asyncio.sleep", new=AsyncMock()):
            with pytest.raises(LLMProviderUnavailableError) as exc_info:
                await retry_with_backoff(fn, max_retries=4, jitter=False)
        assert "4" in str(exc_info.value) or "retry" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# AnthropicProvider — rate-limit and timeout behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestAnthropicProviderRetry:
    """Test that AnthropicProvider converts SDK errors to the right types."""

    def _make_provider(self, max_retries: int = 2) -> "object":
        from utils.ai.anthropic_provider import AnthropicProvider

        config = AIConfig(
            provider="anthropic",
            model="claude-3-5-sonnet-20241022",
            timeout_seconds=5.0,
            max_retries=max_retries,
        )
        provider = object.__new__(AnthropicProvider)
        provider._config = config
        provider._model = "claude-3-5-sonnet-20241022"
        provider._client = None
        return provider

    async def test_rate_limit_retried_and_succeeds(self):
        """RateLimitError causes a retry; success on second attempt."""
        pytest.importorskip("anthropic")
        from anthropic import RateLimitError as AnthropicRateLimitError

        from utils.ai.anthropic_provider import AnthropicProvider

        provider = self._make_provider(max_retries=2)

        # Build a fake client whose messages.create raises RateLimitError once.
        call_count = 0

        async def fake_create(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Minimal AnthropicRateLimitError — needs a request arg.
                mock_request = MagicMock()
                mock_request.method = "POST"
                mock_request.url = "https://api.anthropic.com/v1/messages"
                raise AnthropicRateLimitError(
                    message="rate limited",
                    response=MagicMock(status_code=429, headers={}),
                    body=None,
                )
            # Second call succeeds.
            block = MagicMock()
            block.text = "hello"
            resp = MagicMock()
            resp.content = [block]
            return resp

        mock_client = MagicMock()
        mock_client.messages.create = fake_create
        provider._client = mock_client

        with patch("utils.ai.retry.asyncio.sleep", new=AsyncMock()):
            result = await provider.complete("hi", max_tokens=100, timeout=5.0)

        assert result == "hello"
        assert call_count == 2

    async def test_timeout_raises_unavailable_not_retried(self):
        """asyncio.TimeoutError → LLMProviderUnavailableError, no retry."""
        pytest.importorskip("anthropic")

        from utils.ai.anthropic_provider import AnthropicProvider

        provider = self._make_provider(max_retries=3)

        # This coroutine never returns — asyncio.wait_for will cancel it.
        # We do NOT patch asyncio.sleep here because doing so would also make
        # the sleep inside this coroutine return immediately, defeating the test.
        async def fake_create(**kwargs):
            # Block indefinitely until cancelled by wait_for.
            await asyncio.Event().wait()

        mock_client = MagicMock()
        mock_client.messages.create = fake_create
        provider._client = mock_client

        # retry_with_backoff.asyncio.sleep must NOT be called — patch it to
        # verify while keeping the provider's wait_for able to fire.
        with patch("utils.ai.retry.asyncio.sleep", new=AsyncMock()) as mock_sleep:
            with pytest.raises(LLMProviderUnavailableError, match="timeout"):
                await provider.complete("hi", max_tokens=100, timeout=0.01)

        # Timeout is NOT retried — sleep should never be called.
        mock_sleep.assert_not_awaited()

    async def test_rate_limit_exhausted_raises_unavailable(self):
        """When retries run out, LLMProviderUnavailableError is raised."""
        pytest.importorskip("anthropic")
        from anthropic import RateLimitError as AnthropicRateLimitError

        from utils.ai.anthropic_provider import AnthropicProvider

        provider = self._make_provider(max_retries=2)

        async def always_rate_limit(**kwargs):
            mock_request = MagicMock()
            raise AnthropicRateLimitError(
                message="rate limited",
                response=MagicMock(status_code=429, headers={}),
                body=None,
            )

        mock_client = MagicMock()
        mock_client.messages.create = always_rate_limit
        provider._client = mock_client

        with patch("utils.ai.retry.asyncio.sleep", new=AsyncMock()):
            with pytest.raises(LLMProviderUnavailableError, match="exhausted"):
                await provider.complete("hi", max_tokens=100, timeout=5.0)


# ---------------------------------------------------------------------------
# OpenAIProvider — rate-limit and timeout behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestOpenAIProviderRetry:
    def _make_provider(self, max_retries: int = 2) -> "object":
        from utils.ai.openai_provider import OpenAIProvider

        config = AIConfig(
            provider="openai",
            model="gpt-4o",
            timeout_seconds=5.0,
            max_retries=max_retries,
        )
        provider = object.__new__(OpenAIProvider)
        provider._config = config
        provider._model = "gpt-4o"
        provider._client = None
        return provider

    async def test_rate_limit_retried_and_succeeds(self):
        """RateLimitError causes a retry; success on second attempt."""
        pytest.importorskip("openai")
        from openai import RateLimitError as OpenAIRateLimitError

        call_count = 0

        async def fake_create(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise OpenAIRateLimitError(
                    message="rate limited",
                    response=MagicMock(
                        status_code=429,
                        headers={},
                        json=MagicMock(return_value={"error": {"message": "rate limited"}}),
                        text="rate limited",
                        request=MagicMock(),
                    ),
                    body={"error": {"message": "rate limited"}},
                )
            # Second call succeeds.
            msg = MagicMock()
            msg.content = "world"
            choice = MagicMock()
            choice.message = msg
            resp = MagicMock()
            resp.choices = [choice]
            return resp

        provider = self._make_provider(max_retries=2)
        mock_client = MagicMock()
        mock_client.chat.completions.create = fake_create
        provider._client = mock_client

        with patch("utils.ai.retry.asyncio.sleep", new=AsyncMock()):
            result = await provider.complete("hi", max_tokens=100, timeout=5.0)

        assert result == "world"
        assert call_count == 2

    async def test_timeout_raises_unavailable_not_retried(self):
        """asyncio.TimeoutError → LLMProviderUnavailableError, no retry."""
        pytest.importorskip("openai")

        provider = self._make_provider(max_retries=3)

        # Block indefinitely so asyncio.wait_for fires its timeout.
        async def fake_create(**kwargs):
            await asyncio.Event().wait()

        mock_client = MagicMock()
        mock_client.chat.completions.create = fake_create
        provider._client = mock_client

        with patch("utils.ai.retry.asyncio.sleep", new=AsyncMock()) as mock_sleep:
            with pytest.raises(LLMProviderUnavailableError, match="timeout"):
                await provider.complete("hi", max_tokens=100, timeout=0.01)

        assert mock_sleep.await_count == 0


# ---------------------------------------------------------------------------
# BedrockProvider — rate-limit and timeout behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestBedrockProviderRetry:
    def _make_provider(self, max_retries: int = 2) -> "object":
        pytest.importorskip("boto3")
        from utils.ai.bedrock_provider import BedrockProvider

        config = AIConfig(
            provider="bedrock",
            model="anthropic.claude-3-5-sonnet-20241022-v2:0",
            timeout_seconds=5.0,
            max_retries=max_retries,
        )
        provider = object.__new__(BedrockProvider)
        provider._config = config
        provider._model = "anthropic.claude-3-5-sonnet-20241022-v2:0"
        # Pre-populate with a MagicMock so _get_client() never touches real boto3.
        provider._client = MagicMock()
        return provider

    def _make_boto_rate_limit(self, code: str):
        """Build a botocore ClientError that looks like a rate-limit."""
        import botocore.exceptions

        error_response = {"Error": {"Code": code, "Message": "Too many requests"}}
        return botocore.exceptions.ClientError(error_response, "Converse")

    async def test_throttling_exception_retried(self):
        """ThrottlingException from Bedrock → LLMRateLimitError → retry."""
        pytest.importorskip("boto3")

        provider = self._make_provider(max_retries=2)
        call_count = 0
        throttle_exc = self._make_boto_rate_limit("ThrottlingException")

        def fake_converse(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise throttle_exc
            # Second call returns a valid Bedrock response shape.
            return {
                "output": {
                    "message": {
                        "content": [{"text": "bedrock ok"}]
                    }
                }
            }

        provider._client.converse.side_effect = fake_converse

        with patch("utils.ai.retry.asyncio.sleep", new=AsyncMock()):
            result = await provider.complete("hi", max_tokens=100, timeout=5.0)

        assert result == "bedrock ok"
        assert call_count == 2

    async def test_too_many_requests_retried(self):
        """TooManyRequestsException from Bedrock → LLMRateLimitError → retry."""
        pytest.importorskip("boto3")

        provider = self._make_provider(max_retries=2)
        call_count = 0

        def fake_converse(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise self._make_boto_rate_limit("TooManyRequestsException")
            return {
                "output": {
                    "message": {
                        "content": [{"text": "bedrock ok"}]
                    }
                }
            }

        provider._client.converse.side_effect = fake_converse

        with patch("utils.ai.retry.asyncio.sleep", new=AsyncMock()):
            result = await provider.complete("hi", max_tokens=100, timeout=5.0)

        assert result == "bedrock ok"
        assert call_count == 2

    async def test_non_throttle_client_error_not_retried(self):
        """A non-rate-limit ClientError (e.g. ValidationException) propagates immediately."""
        pytest.importorskip("boto3")
        import botocore.exceptions

        provider = self._make_provider(max_retries=3)
        call_count = 0

        def fake_converse(**kwargs):
            nonlocal call_count
            call_count += 1
            error_response = {
                "Error": {"Code": "ValidationException", "Message": "bad input"}
            }
            raise botocore.exceptions.ClientError(error_response, "Converse")

        provider._client.converse.side_effect = fake_converse

        with patch("utils.ai.retry.asyncio.sleep", new=AsyncMock()) as mock_sleep:
            with pytest.raises(LLMProviderUnavailableError):
                await provider.complete("hi", max_tokens=100, timeout=5.0)

        assert call_count == 1  # not retried
        mock_sleep.assert_not_awaited()

    async def test_timeout_not_retried(self):
        """asyncio.TimeoutError → LLMProviderUnavailableError, no retry."""
        pytest.importorskip("boto3")

        provider = self._make_provider(max_retries=3)

        # Make the converse call block indefinitely via an asyncio Event so
        # asyncio.wait_for can cancel it cleanly.
        async def blocking_converse_in_executor():
            await asyncio.Event().wait()

        original_run_executor = None

        async def mock_run_in_executor(executor, fn, *args):
            # Replace the synchronous call with an async blocking one.
            await asyncio.Event().wait()

        # Patch run_in_executor at the event loop level for this test.
        loop = asyncio.get_event_loop()
        with (
            patch.object(loop, "run_in_executor", side_effect=mock_run_in_executor),
            patch("utils.ai.retry.asyncio.sleep", new=AsyncMock()) as mock_sleep,
        ):
            with pytest.raises(LLMProviderUnavailableError, match="timeout"):
                await provider.complete("hi", max_tokens=100, timeout=0.01)

        mock_sleep.assert_not_awaited()

    async def test_invoke_sync_raises_rate_limit_error_on_throttle(self):
        """_invoke_sync converts ThrottlingException directly to LLMRateLimitError."""
        pytest.importorskip("boto3")
        from utils.ai.bedrock_provider import BedrockProvider

        provider = self._make_provider()
        mock_client = MagicMock()
        mock_client.converse.side_effect = self._make_boto_rate_limit("ThrottlingException")

        with pytest.raises(LLMRateLimitError, match="ThrottlingException"):
            provider._invoke_sync(mock_client, "model", "prompt", 100)
