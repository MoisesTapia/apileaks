"""
utils.ai.bedrock_provider — Amazon Bedrock LLM provider implementation.

Requires ``boto3`` which ships with the ``apileaks[aws]`` optional extra::

    pip install apileaks[aws]

No API keys are hardcoded or read from config files.  Credentials are
resolved exclusively via the standard AWS credential chain: environment
variables (``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY`` /
``AWS_SESSION_TOKEN``), ``~/.aws/credentials`` profiles, EC2/ECS instance
profiles, or IAM roles — exactly how the rest of APILeak's AWS integrations
work (Requirement 7.3).

The provider uses the ``bedrock-runtime`` *converse* API which provides a
uniform interface across all Bedrock-hosted model families.

Rate-limit errors (``ThrottlingException`` / ``TooManyRequestsException``)
are retried with exponential back-off via
:func:`utils.ai.retry.retry_with_backoff`.  Timeouts abort the current
attempt immediately and are never retried (Requirements 10.1, 10.3).
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import TYPE_CHECKING, Any

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
# the [aws] extra installed.
# ---------------------------------------------------------------------------

try:
    import boto3 as _boto3
    import botocore.exceptions as _botocore_exc

    _SDK_AVAILABLE = True
except ImportError:
    _SDK_AVAILABLE = False
    _boto3 = None  # type: ignore[assignment]
    _botocore_exc = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

# Default model used when AIConfig.model is not set.
# Anthropic Claude 3.5 Sonnet v2 on Bedrock.
_DEFAULT_MODEL = "anthropic.claude-3-5-sonnet-20241022-v2:0"

# Environment variable optionally used to override the AWS region for the
# Bedrock runtime endpoint.  Falls back to boto3's own region resolution.
_REGION_ENV_VAR = "AWS_DEFAULT_REGION"

# Bedrock ClientError codes that indicate a rate-limit / throttle condition.
# These are the two codes Bedrock uses for transient over-capacity responses.
_RATE_LIMIT_CODES: frozenset[str] = frozenset(
    {"ThrottlingException", "TooManyRequestsException"}
)


def _require_sdk() -> None:
    """Raise a clear ImportError if boto3 is not installed."""
    if not _SDK_AVAILABLE:
        raise ImportError(
            "The 'boto3' package is required for BedrockProvider. "
            "Install the AWS optional extra with:  pip install apileaks[aws]"
        )


class BedrockProvider(LLMProvider):
    """LLM provider that calls Amazon Bedrock via the *converse* API.

    The ``bedrock-runtime`` boto3 client is constructed lazily on the first
    call to :meth:`complete`.  Credentials flow through the standard AWS
    credential chain — no key material is ever stored in this object.

    Because boto3 is a synchronous library, API calls are dispatched to a
    thread-pool executor so that the async caller is never blocked.
    Per-attempt timeouts are enforced with :func:`asyncio.wait_for`.

    Rate-limit errors (``ThrottlingException`` / ``TooManyRequestsException``)
    are retried up to ``config.max_retries`` times using exponential back-off
    with jitter (Requirement 10.3).  Timeouts abort the current attempt and
    propagate immediately — they are never retried (Requirement 10.1).

    Args:
        config: AI layer configuration.  ``config.model`` overrides the
            default model; ``config.timeout_seconds`` is used as the
            per-request deadline; ``config.max_retries`` controls how many
            times a throttled request is retried.
    """

    def __init__(self, config: AIConfig) -> None:
        _require_sdk()
        self._config = config
        self._model = config.model or _DEFAULT_MODEL
        self._client: Any | None = None  # boto3 bedrock-runtime client

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_client(self) -> Any:
        """Return (and cache) the boto3 bedrock-runtime client.

        Region is resolved in the following order:
        1. ``AWS_DEFAULT_REGION`` environment variable (APILeak convention).
        2. ``AWS_REGION`` environment variable (Lambda / ECS convention).
        3. boto3's own resolution chain (``~/.aws/config``, instance metadata).
        """
        if self._client is None:
            region = (
                os.environ.get(_REGION_ENV_VAR)
                or os.environ.get("AWS_REGION")
                or None  # let boto3 resolve from config / instance metadata
            )
            kwargs: dict[str, Any] = {}
            if region:
                kwargs["region_name"] = region
            self._client = _boto3.client("bedrock-runtime", **kwargs)  # type: ignore[union-attr]
        return self._client

    def _invoke_sync(self, client: Any, model_id: str, prompt: str, max_tokens: int) -> str:
        """Execute the synchronous boto3 *converse* call.

        This method is intended to be run in a thread-pool executor so the
        async event loop is not blocked.

        Rate-limit errors (``ThrottlingException`` /
        ``TooManyRequestsException``) are raised as
        :class:`~utils.ai.provider_base.LLMRateLimitError` so they are
        eligible for retry by the caller (Requirement 10.3).  All other
        :class:`botocore.exceptions.ClientError` codes are raised as
        :class:`~utils.ai.provider_base.LLMProviderUnavailableError`.

        Args:
            client: Initialised boto3 ``bedrock-runtime`` client.
            model_id: Bedrock model identifier.
            prompt: Prompt text.
            max_tokens: Maximum tokens in the completion.

        Returns:
            The text of the first content block in the response.

        Raises:
            LLMRateLimitError: On throttling / too-many-requests from Bedrock.
            LLMProviderUnavailableError: On other AWS / network errors.
            LLMResponseParseError: If the response structure is unexpected.
        """
        try:
            response = client.converse(
                modelId=model_id,
                messages=[
                    {
                        "role": "user",
                        "content": [{"text": prompt}],
                    }
                ],
                inferenceConfig={"maxTokens": max_tokens},
            )
        except _botocore_exc.ClientError as exc:  # type: ignore[union-attr]
            error_code = exc.response.get("Error", {}).get("Code", "Unknown")
            if error_code in _RATE_LIMIT_CODES:
                raise LLMRateLimitError(
                    f"Bedrock rate limit [{error_code}]: {exc}"
                ) from exc
            raise LLMProviderUnavailableError(
                f"Bedrock API error [{error_code}]: {exc}"
            ) from exc
        except _botocore_exc.EndpointResolutionError as exc:  # type: ignore[union-attr]
            raise LLMProviderUnavailableError(
                f"Bedrock endpoint resolution error: {exc}"
            ) from exc
        except _botocore_exc.BotoCoreError as exc:  # type: ignore[union-attr]
            raise LLMProviderUnavailableError(
                f"Bedrock/boto3 error ({type(exc).__name__}): {exc}"
            ) from exc
        except Exception as exc:
            # Catch connection-level errors not wrapped by botocore.
            raise LLMProviderUnavailableError(
                f"Unexpected error calling Bedrock: {exc}"
            ) from exc

        # Parse the converse response structure.
        # Expected shape: {"output": {"message": {"content": [{"text": "..."}]}}}
        try:
            output = response.get("output", {})
            message = output.get("message", {})
            content_blocks = message.get("content", [])
            if not content_blocks:
                raise LLMResponseParseError(
                    "Bedrock converse response contained no content blocks."
                )
            first_block = content_blocks[0]
            text = first_block.get("text")
            if text is None:
                raise LLMResponseParseError(
                    f"Bedrock converse response first block has no 'text' key. "
                    f"Block keys: {list(first_block.keys())}"
                )
            return text
        except LLMResponseParseError:
            raise
        except Exception as exc:
            raise LLMResponseParseError(
                f"Failed to parse Bedrock converse response: {exc}. "
                f"Raw response keys: {list(response.keys()) if isinstance(response, dict) else type(response).__name__}"
            ) from exc

    # ------------------------------------------------------------------
    # LLMProvider interface
    # ------------------------------------------------------------------

    @property
    def provider_name(self) -> str:
        return "bedrock"

    async def complete(
        self,
        prompt: str,
        *,
        max_tokens: int,
        timeout: float,
    ) -> str:
        """Send *prompt* to Amazon Bedrock and return the completion text.

        The synchronous boto3 call is dispatched to a thread-pool executor
        so the event loop remains unblocked.  Each attempt is bounded by
        *timeout* via :func:`asyncio.wait_for`.  Throttling errors
        (``ThrottlingException`` / ``TooManyRequestsException``) are retried
        with exponential back-off up to ``config.max_retries`` times.
        Timeouts propagate immediately without retrying (Requirements 10.1,
        10.3).

        Args:
            prompt: Full prompt string.  **Callers must redact secrets before
                calling this method** (Requirement 5.5).
            max_tokens: Maximum tokens in the completion.
            timeout: Per-attempt deadline in seconds.
                :class:`~utils.ai.provider_base.LLMProviderUnavailableError`
                is raised immediately on expiry without retrying
                (Requirement 10.1).

        Returns:
            The text content of the first response block.

        Raises:
            LLMProviderUnavailableError: On timeout, connection failure,
                AWS API error, or exhausted rate-limit retries.
            LLMResponseParseError: If the response cannot be interpreted as
                expected.
        """
        client = self._get_client()
        model_id = self._model

        async def _attempt() -> str:
            loop = asyncio.get_event_loop()

            async def _call() -> str:
                # Run the synchronous boto3 call in a thread-pool executor so it
                # doesn't block the event loop.
                return await loop.run_in_executor(
                    None,
                    self._invoke_sync,
                    client,
                    model_id,
                    prompt,
                    max_tokens,
                )

            # Enforce the per-attempt timeout.  TimeoutError is NOT retried.
            try:
                return await asyncio.wait_for(_call(), timeout=timeout)
            except TimeoutError as exc:
                raise LLMProviderUnavailableError(
                    f"Bedrock request exceeded timeout of {timeout}s."
                ) from exc

        return await retry_with_backoff(
            _attempt,
            max_retries=self._config.max_retries,
        )

    def __repr__(self) -> str:
        return f"BedrockProvider(model={self._model!r})"
