"""
Unit tests for per-request resilience controls (--timeout / --retries, retry,
429 backoff, and rate-limit / concurrency composition).

**Feature: owasp-complete-purple-teaming-cicd, Task 32.2**

These tests cover Requirement 28 (Per-Request Resilience Controls):

- 28.1: ``--timeout`` reaches the client config (threaded into
  ``config_dict['target']['timeout']`` for BOTH ``dir`` and ``full``).
- 28.2: ``--retries`` reaches ``RetryConfig`` -- it is threaded into
  ``config_dict['fuzzing']['retries']`` for BOTH ``dir`` and ``full`` and
  ``core.engine._get_retry_settings`` sources ``RetryConfig.max_attempts`` as
  ``retries + 1``.
- 28.3: a timeout abandons the request and retries up to the Retry_Limit -- the
  ``HTTPRequestEngine`` (with a ``RetryConfig`` whose ``max_attempts`` derives
  from the configured retries) retries up to the configured number of attempts.
- 28.4 / 28.5: a 429 response invokes ``RateLimiter.handle_rate_limit_response``
  (applying backoff) while still honoring the token-bucket Rate_Limit and the
  ``_semaphore`` Concurrency_Limit.
- 28.6: an invalid ``--timeout`` (non-positive) is rejected with a descriptive
  error naming the value and performs no discovery.
- 28.7: an invalid ``--retries`` (negative or non-integer) is rejected with a
  descriptive error naming the value and performs no discovery.

No real HTTP requests are made: the discovery entry point is patched for the
CLI validation tests, the configuration loader is short-circuited so option
threading is exercised in isolation, and the engine/orchestrator tests drive the
real retry + rate-limit + concurrency machinery against an in-memory fake
``httpx`` client (mirroring the fake-client conventions in
``tests/test_extension_fuzzing_wiring.py``).
"""

import asyncio
import os
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import pytest
from click.testing import CliRunner

import apileaks
from apileaks import cli
from core.engine import _get_retry_settings
from core.config import (
    FuzzingConfig,
    EndpointFuzzingConfig,
    ParameterFuzzingConfig,
    HeaderFuzzingConfig,
    RateLimitConfig,
)
from modules.fuzzing.orchestrator import EndpointFuzzer
from utils import http_client
from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig


# ===========================================================================
# Shared helpers / fakes
# ===========================================================================

class _ShortCircuit(Exception):
    """Sentinel raised to stop the command after config_dict is captured."""


def _invoke_capturing_config(command, args):
    """Invoke ``dir`` or ``full`` and capture the threaded ``config_dict``.

    ConfigurationManager.load_config_from_dict is the first consumer of the
    fully threaded config, so capturing its argument lets us inspect the
    resilience controls written into the config dict without running a real
    scan. A sentinel is raised afterwards; Click surfaces it as a non-zero exit.
    """
    captured = {}

    def _capture(self, config_dict):
        captured["config_dict"] = config_dict
        raise _ShortCircuit()

    runner = CliRunner()
    with patch.object(
        apileaks.ConfigurationManager, "load_config_from_dict", _capture
    ):
        runner.invoke(
            cli,
            ["--no-banner", command, "--target", "https://api.example.com", *args],
        )
    return captured.get("config_dict")


class _FakeHttpxResponse:
    """Minimal stand-in for an ``httpx.Response`` consumed by the engine."""

    def __init__(self, status_code, url, headers=None, content=b'{"ok": true}'):
        self.status_code = status_code
        self.url = url
        self.headers = headers or {}
        self.content = content
        self.text = (
            content.decode() if isinstance(content, (bytes, bytearray)) else str(content)
        )


class _SequenceHttpxClient:
    """Fake httpx client returning a preset sequence of status codes.

    A ``None`` entry raises ``httpx.TimeoutException`` to simulate a request
    that does not complete within the Request_Timeout. The final entry repeats
    for any calls beyond the sequence length.
    """

    def __init__(self, statuses):
        self._statuses = list(statuses)
        self.calls = []

    @property
    def call_count(self):
        return len(self.calls)

    async def request(self, method, url, **kwargs):
        idx = len(self.calls)
        self.calls.append((method, url))
        status = self._statuses[idx] if idx < len(self._statuses) else self._statuses[-1]
        if status is None:
            raise httpx.TimeoutException("simulated timeout")
        return _FakeHttpxResponse(status, url)


class _PerUrl429ThenOkClient:
    """Fake httpx client that answers 429 on the first hit of each URL, 200 after.

    Tracks peak simultaneous in-flight requests (incrementing on entry,
    decrementing on exit, yielding in between so sibling coroutines overlap) so
    tests can assert the Concurrency_Limit is honored even while 429 backoff is
    applied.
    """

    def __init__(self):
        self.calls = []
        self._seen = {}
        self.in_flight = 0
        self.peak_in_flight = 0

    async def request(self, method, url, **kwargs):
        self.in_flight += 1
        self.peak_in_flight = max(self.peak_in_flight, self.in_flight)
        self.calls.append((method, url))
        try:
            await asyncio.sleep(0)  # let concurrent siblings overlap
            seen = self._seen.get(url, 0)
            self._seen[url] = seen + 1
            status = 429 if seen == 0 else 200
            return _FakeHttpxResponse(status, url)
        finally:
            self.in_flight -= 1


async def _noop_sleep(*args, **kwargs):
    """Async no-op replacing asyncio.sleep so retry/backoff waits are instant."""
    return None


def _make_engine(fake_httpx, retries=2, rate_limiter=None):
    """Build a real HTTPRequestEngine with an injected fake httpx client.

    The RetryConfig.max_attempts derives from the Retry_Limit exactly as
    ``core.engine._get_retry_settings`` computes it (``retries + 1``).
    """
    rl = rate_limiter or RateLimiter(RateLimitConfig())
    engine = HTTPRequestEngine(
        rl,
        RetryConfig(
            max_attempts=retries + 1,
            backoff_factor=2.0,
            retry_on_status=[429, 502, 503, 504],
        ),
    )
    # Bypass real client creation; inject the fake transport.
    engine._client_initialized = True
    engine.client = fake_httpx
    return engine


def _make_fuzzing_config(max_requests=None, concurrency=50):
    """Single-method, non-recursive FuzzingConfig for orchestrator tests."""
    return FuzzingConfig(
        endpoints=EndpointFuzzingConfig(
            enabled=True,
            wordlist="unused.txt",
            methods=["GET"],
            follow_redirects=False,
            extensions=[],
        ),
        parameters=ParameterFuzzingConfig(enabled=False),
        headers=HeaderFuzzingConfig(enabled=False),
        recursive=False,
        max_depth=0,
        max_requests=max_requests,
        concurrency=concurrency,
    )


def _write_wordlist(words):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    f.write("\n".join(words) + "\n")
    f.close()
    return f.name


# ===========================================================================
# 28.1 --timeout reaches the client config (dir + full)
# ===========================================================================

@pytest.mark.parametrize("command", ["dir", "full"])
def test_timeout_threaded_into_target_config(command):
    """``--timeout`` is threaded into ``config_dict['target']['timeout']``.

    ``TargetConfig(**target_data)`` then carries it onto
    ``apileak_config.target.timeout``, which the engine consumes as its read
    timeout, so the supplied value reaches the client config for BOTH commands.

    **Validates: Requirements 28.1**
    """
    config_dict = _invoke_capturing_config(command, ["--timeout=7.5"])

    assert config_dict is not None
    assert config_dict["target"]["timeout"] == 7.5


@pytest.mark.parametrize("command", ["dir", "full"])
def test_timeout_absent_leaves_default(command):
    """Without ``--timeout`` no override is written and the default stands.

    **Validates: Requirements 28.1**
    """
    config_dict = _invoke_capturing_config(command, [])

    assert config_dict is not None
    # The default target timeout (10) is left untouched (not overwritten to None).
    assert config_dict["target"]["timeout"] == 10


# ===========================================================================
# 28.2 --retries reaches RetryConfig (dir + full)
# ===========================================================================

@pytest.mark.parametrize("command", ["dir", "full"])
def test_retries_threaded_into_fuzzing_config(command):
    """``--retries`` is threaded into ``config_dict['fuzzing']['retries']``.

    **Validates: Requirements 28.2**
    """
    config_dict = _invoke_capturing_config(command, ["--retries=5"])

    assert config_dict is not None
    assert config_dict["fuzzing"]["retries"] == 5


def test_get_retry_settings_returns_retries_plus_one():
    """``_get_retry_settings`` sources ``RetryConfig.max_attempts`` as retries+1.

    This is the exact computation the engine uses to build the RetryConfig from
    the configured Retry_Limit, so a configured ``--retries N`` reaches
    ``RetryConfig`` as ``max_attempts = N + 1``.

    **Validates: Requirements 28.2**
    """
    for retries in (0, 1, 2, 5):
        config = SimpleNamespace(fuzzing=FuzzingConfig(retries=retries))
        assert _get_retry_settings(config) == retries + 1


def test_get_retry_settings_default_is_three_attempts():
    """With the default Retry_Limit (2), RetryConfig.max_attempts is 3.

    **Validates: Requirements 28.2**
    """
    config = SimpleNamespace(fuzzing=FuzzingConfig())
    assert _get_retry_settings(config) == 3


def test_engine_retryconfig_built_from_configured_retries():
    """A configured Retry_Limit propagates into the engine's RetryConfig.

    Building the engine the way ``core.engine`` does -- ``max_attempts`` from
    ``_get_retry_settings`` -- yields a client whose RetryConfig reflects the
    user-supplied ``--retries`` value.

    **Validates: Requirements 28.2**
    """
    config = SimpleNamespace(fuzzing=FuzzingConfig(retries=4))
    engine = _make_engine(_SequenceHttpxClient([200]), retries=4)

    assert engine.retry_config.max_attempts == _get_retry_settings(config) == 5


# ===========================================================================
# 28.3 a timeout triggers a retry up to the Retry_Limit
# ===========================================================================

def test_timeout_retried_then_succeeds(monkeypatch):
    """A timed-out request is abandoned and retried, succeeding within the limit.

    With retries=2 (max_attempts=3) the transport times out twice and then
    answers 200; the engine returns the successful response after exactly 3
    attempts, proving timeouts are retried up to the configured limit.

    **Validates: Requirements 28.3**
    """
    monkeypatch.setattr(http_client.asyncio, "sleep", _noop_sleep)
    fake = _SequenceHttpxClient([None, None, 200])
    engine = _make_engine(fake, retries=2)

    response = asyncio.run(engine.request("GET", "https://api.example.com/x"))

    assert fake.call_count == 3              # initial attempt + 2 retries
    assert response.status_code == 200       # retry recovered the request


def test_timeout_retries_capped_at_limit(monkeypatch):
    """A persistently timing-out request retries no more than the Retry_Limit.

    With retries=2 the transport always times out: the engine attempts exactly
    max_attempts (3) times -- the initial attempt plus 2 retries -- then gives
    up with a connection-error response (status_code 0), never exceeding the
    configured limit.

    **Validates: Requirements 28.3**
    """
    monkeypatch.setattr(http_client.asyncio, "sleep", _noop_sleep)
    fake = _SequenceHttpxClient([None])  # always times out
    engine = _make_engine(fake, retries=2)

    response = asyncio.run(engine.request("GET", "https://api.example.com/x"))

    assert fake.call_count == 3              # exactly retries + 1 attempts
    assert response.status_code == 0         # abandoned after the limit


def test_retry_limit_zero_makes_single_attempt(monkeypatch):
    """``--retries 0`` permits the initial attempt only (no retries).

    **Validates: Requirements 28.2, 28.3**
    """
    monkeypatch.setattr(http_client.asyncio, "sleep", _noop_sleep)
    fake = _SequenceHttpxClient([None])
    engine = _make_engine(fake, retries=0)

    response = asyncio.run(engine.request("GET", "https://api.example.com/x"))

    assert fake.call_count == 1
    assert response.status_code == 0


# ===========================================================================
# 28.4 / 28.5 a 429 invokes RateLimiter backoff while honoring rate limit +
#              concurrency
# ===========================================================================

def test_429_invokes_rate_limiter_backoff(monkeypatch):
    """A 429 response invokes ``handle_rate_limit_response`` and applies backoff.

    The request is then retried (429 -> 200). The rate limiter is consulted on
    every attempt (Rate_Limit honored) and a backoff window is armed.

    **Validates: Requirements 28.4, 28.5**
    """
    monkeypatch.setattr(http_client.asyncio, "sleep", _noop_sleep)

    rate_limiter = RateLimiter(RateLimitConfig())

    backoff_calls = {"count": 0}
    acquire_calls = {"count": 0}
    orig_backoff = rate_limiter.handle_rate_limit_response
    orig_acquire = rate_limiter.acquire

    async def _spy_backoff(response):
        backoff_calls["count"] += 1
        return await orig_backoff(response)

    async def _spy_acquire():
        acquire_calls["count"] += 1
        return await orig_acquire()

    rate_limiter.handle_rate_limit_response = _spy_backoff
    rate_limiter.acquire = _spy_acquire

    fake = _SequenceHttpxClient([429, 200])
    engine = _make_engine(fake, retries=2, rate_limiter=rate_limiter)

    response = asyncio.run(engine.request("GET", "https://api.example.com/x"))

    # 28.4: the 429 triggered a single backoff invocation and a recovery retry.
    assert backoff_calls["count"] == 1
    assert response.status_code == 200
    # 28.4: a backoff window was armed (the successful retry then clears the
    # consecutive-limit counter, but the backoff timestamp remains).
    assert rate_limiter.backoff_until > 0
    # 28.5: the token-bucket Rate_Limit was honored on every attempt.
    assert acquire_calls["count"] == fake.call_count == 2


def test_429_backoff_honors_concurrency_limit(monkeypatch):
    """429 backoff composes with the ``_semaphore`` Concurrency_Limit.

    Driving the real EndpointFuzzer against a real HTTPRequestEngine whose
    transport answers 429 (then 200 on retry) for every path, the in-flight
    Discovery_Requests never exceed the configured Concurrency_Limit even though
    far more candidates are dispatched in one batch, and the rate limiter still
    records the 429 backoff.

    **Validates: Requirements 28.4, 28.5**
    """
    monkeypatch.setattr(http_client.asyncio, "sleep", _noop_sleep)

    concurrency = 3
    words = [f"w{i}" for i in range(8)]  # > concurrency, dispatched at depth 0

    rate_limiter = RateLimiter(RateLimitConfig())
    backoff_calls = {"count": 0}
    orig_backoff = rate_limiter.handle_rate_limit_response

    async def _spy_backoff(response):
        backoff_calls["count"] += 1
        return await orig_backoff(response)

    rate_limiter.handle_rate_limit_response = _spy_backoff

    fake = _PerUrl429ThenOkClient()
    engine = _make_engine(fake, retries=2, rate_limiter=rate_limiter)
    fuzzer = EndpointFuzzer(engine, _make_fuzzing_config(concurrency=concurrency))

    wordlist_path = _write_wordlist(words)
    try:
        asyncio.run(fuzzer.discover_endpoints("https://api.example.com", wordlist_path))
    finally:
        os.unlink(wordlist_path)

    # 28.5: in-flight Discovery_Requests stayed within the Concurrency_Limit.
    assert fuzzer.concurrency == concurrency
    assert fake.peak_in_flight <= concurrency
    # Non-vacuous: more candidates than the limit really were dispatched.
    assert len(fake.calls) > concurrency
    # 28.4: the 429 responses invoked the rate limiter's backoff handling.
    assert backoff_calls["count"] >= 1
    assert rate_limiter.backoff_until > 0


# ===========================================================================
# 28.6 invalid --timeout rejected, no discovery
# ===========================================================================

_INVALID_TIMEOUT_CASES = [
    ("dir", "0"),
    ("full", "0"),
    ("dir", "-1"),
    ("full", "-1"),
]


@pytest.mark.parametrize("command, value", _INVALID_TIMEOUT_CASES)
def test_invalid_timeout_rejected_and_no_discovery(command, value):
    """A non-positive ``--timeout`` fails, names the value, and runs no discovery.

    The Click callback rejects the value during option parsing, so the discovery
    entry point is never reached.

    **Validates: Requirements 28.6**
    """
    runner = CliRunner()
    with patch.object(apileaks, "run_enhanced_apileak") as discovery:
        result = runner.invoke(
            cli,
            [
                "--no-banner",
                command,
                "--target",
                "https://api.example.com",
                f"--timeout={value}",
            ],
        )

    assert result.exit_code != 0
    assert value in result.output      # the offending value is named
    assert "--timeout" in result.output
    discovery.assert_not_called()      # no discovery was performed


# ===========================================================================
# 28.7 invalid --retries rejected, no discovery
# ===========================================================================

_INVALID_RETRIES_CASES = [
    ("dir", "-1"),
    ("full", "-1"),
    ("dir", "abc"),
    ("full", "abc"),
]


@pytest.mark.parametrize("command, value", _INVALID_RETRIES_CASES)
def test_invalid_retries_rejected_and_no_discovery(command, value):
    """A negative or non-integer ``--retries`` fails, names the value, runs no scan.

    Click's ``type=int`` rejects non-integers and the callback rejects values
    ``< 0``; either way the value is rejected during option parsing before any
    discovery runs.

    **Validates: Requirements 28.7**
    """
    runner = CliRunner()
    with patch.object(apileaks, "run_enhanced_apileak") as discovery:
        result = runner.invoke(
            cli,
            [
                "--no-banner",
                command,
                "--target",
                "https://api.example.com",
                f"--retries={value}",
            ],
        )

    assert result.exit_code != 0
    assert value in result.output      # the offending value is named
    assert "--retries" in result.output
    discovery.assert_not_called()      # no discovery was performed
