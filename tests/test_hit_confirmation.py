"""
Unit tests for Hit_Confirmation behavior on discovered endpoints.

**Feature: owasp-complete-purple-teaming-cicd, Task 40.4**

These tests cover Requirement 35 (Hit_Confirmation: re-request interesting
candidates to reduce false positives) across the config default, the consistent
/ inconsistent recording decision, the budget / concurrency / rate-limited-client
composition, and the CLI option validation:

- 35.1 / 35.6: Hit_Confirmation is opt-in and disabled by default. With it off,
  each candidate is recorded with a single Discovery_Request (the existing
  single-request behavior is preserved).
- 35.3: when enabled and the confirmation responses are consistent with the
  first response (same Status_Code_Class and body sizes within tolerance), the
  candidate IS recorded as a Discovery_Result.
- 35.4: when enabled and the confirmation responses are inconsistent (different
  status class or a large body-size difference), the candidate is NOT recorded.
- 35.5: confirmation requests count toward the Request_Budget, stay within the
  Concurrency_Limit, and flow through the same (rate-limited)
  HTTPRequestEngine.request path as every other Discovery_Request.
- 35.7: ``--confirm-hits 0`` and a non-integer value are rejected during option
  parsing, naming the offending value, and no discovery is performed.

No real HTTP requests are made: discovery drives an in-memory fake
HTTPRequestEngine that records every request and answers each candidate path
according to a programmable response plan, matching the existing fake-client
conventions used by the budget/concurrency/method-enumeration tests in this
suite.
"""

import asyncio
import os
import tempfile
from unittest.mock import patch
from urllib.parse import urljoin, urlparse

import pytest
from click.testing import CliRunner

import apileaks
from apileaks import cli
from modules.fuzzing.orchestrator import EndpointFuzzer, Endpoint
from core.config import (
    FuzzingConfig,
    EndpointFuzzingConfig,
    ParameterFuzzingConfig,
    HeaderFuzzingConfig,
    HitConfirmationConfig,
)
from utils.http_client import Response


BASE_URL = "http://example.com"

# Catch-all detection probes target uuid4().hex-based paths (33 chars); genuine
# wordlist segments below are short, so a length threshold reliably distinguishes
# a catch-all probe path from a real candidate path.
_PROBE_SEGMENT_MIN_LEN = 20

# A consistent 2xx body answered for genuine candidate paths by default.
_OK_BODY = b'{"ok": true}'


class ConfirmationFakeClient:
    """
    In-memory fake HTTPRequestEngine for Hit_Confirmation tests.

    Records every (method, url) call in order and tracks live/peak in-flight
    concurrency. Long, uuid-like catch-all probe paths always answer 404 so
    Catch_All_Response detection stays off. Every other (genuine) candidate path
    is answered by ``response_plan(method, url, attempt)`` where ``attempt`` is
    the zero-based number of prior requests already made to that URL -- letting a
    test return a different response for the first request vs. the confirmation
    re-requests.
    """

    def __init__(self, response_plan=None):
        # response_plan(method, url, attempt) -> (status_code, content_bytes).
        # Defaults to a stable 200/_OK_BODY for every genuine candidate path.
        self.response_plan = response_plan or (lambda m, u, a: (200, _OK_BODY))
        self.calls = []          # list of (method, url) in call order
        self._url_counts = {}    # per-url request count (attempt index source)
        self.in_flight = 0
        self.peak_in_flight = 0

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def requests_for(self, url):
        """Return the list of (method, url) calls made to ``url``."""
        return [c for c in self.calls if c[1] == url]

    async def request(self, method: str, url: str, **kwargs) -> Response:
        self.in_flight += 1
        self.peak_in_flight = max(self.peak_in_flight, self.in_flight)
        self.calls.append((method, url))
        attempt = self._url_counts.get(url, 0)
        self._url_counts[url] = attempt + 1
        try:
            # Yield so concurrently dispatched requests overlap and the in-flight
            # count can build up toward (but never past) the Concurrency_Limit.
            await asyncio.sleep(0)

            path = urlparse(url).path
            segments = [s for s in path.split("/") if s]
            last_segment = segments[-1] if segments else ""
            if len(last_segment) >= _PROBE_SEGMENT_MIN_LEN:
                status_code, content = 404, b""
            else:
                status_code, content = self.response_plan(method, url, attempt)

            return Response(
                status_code=status_code,
                headers={"Content-Type": "application/json"},
                content=content,
                text=content.decode("utf-8", "replace"),
                url=url,
                elapsed=0.01,
                request_method=method,
            )
        finally:
            self.in_flight -= 1


def _make_config(
    words_methods=("GET",),
    hit_confirmation: HitConfirmationConfig = None,
    concurrency: int = 50,
    max_requests=None,
) -> FuzzingConfig:
    """Build a non-recursive FuzzingConfig for a focused Hit_Confirmation test."""
    return FuzzingConfig(
        endpoints=EndpointFuzzingConfig(
            enabled=True,
            wordlist="unused.txt",
            methods=list(words_methods),  # single method => one request per path
            follow_redirects=False,
        ),
        parameters=ParameterFuzzingConfig(enabled=False),
        headers=HeaderFuzzingConfig(enabled=False),
        recursive=False,             # keep the candidate space to depth-0 only
        max_depth=0,
        max_requests=max_requests,
        concurrency=concurrency,
        hit_confirmation=hit_confirmation or HitConfirmationConfig(),
    )


def _write_wordlist(words):
    """Write words to a temp wordlist file and return its path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    f.write("\n".join(words) + "\n")
    f.close()
    return f.name


async def _run_discovery(words, config: FuzzingConfig, response_plan=None):
    """Run a depth-0 discovery pass; return (fake_client, fuzzer, discovered)."""
    fake_client = ConfirmationFakeClient(response_plan=response_plan)
    fuzzer = EndpointFuzzer(fake_client, config)
    wordlist_path = _write_wordlist(words)
    try:
        discovered = await fuzzer.discover_endpoints(BASE_URL, wordlist_path)
    finally:
        os.unlink(wordlist_path)
    return fake_client, fuzzer, discovered


# ---------------------------------------------------------------------------
# 35.1 / 35.6: opt-in, disabled by default => single request per candidate
# ---------------------------------------------------------------------------

def test_default_off_records_candidate_with_single_request():
    """With Hit_Confirmation disabled (default), a candidate is recorded after a
    single Discovery_Request -- the existing single-request behavior.

    **Validates: Requirements 35.1, 35.6**
    """
    # Default config => hit_confirmation disabled.
    config = _make_config()
    assert config.hit_confirmation.enabled is False

    fake_client, fuzzer, discovered = asyncio.run(
        _run_discovery(["admin"], config)
    )

    url = urljoin(BASE_URL + "/", "admin")
    # Exactly one request was issued for the candidate (no confirmation re-requests).
    assert fake_client.requests_for(url) == [("GET", url)]
    # The candidate is recorded as a Discovery_Result.
    assert url in fuzzer.discovered_endpoints
    assert any(isinstance(e, Endpoint) and e.url == url for e in discovered)


# ---------------------------------------------------------------------------
# 35.3: consistent confirmations => candidate IS recorded
# ---------------------------------------------------------------------------

def test_consistent_confirmations_record_candidate():
    """When enabled and the confirmation responses are consistent with the first
    response, the candidate IS recorded as a Discovery_Result.

    **Validates: Requirement 35.3 (and 35.1/35.2 composition)**
    """
    config = _make_config(
        hit_confirmation=HitConfirmationConfig(enabled=True, count=2)
    )

    # Every request to the genuine path answers the same 200/_OK_BODY, so the
    # first response plus the two confirmations are mutually consistent.
    fake_client, fuzzer, discovered = asyncio.run(
        _run_discovery(["admin"], config)
    )

    url = urljoin(BASE_URL + "/", "admin")
    # First request + 2 confirmation re-requests = 3 requests to the candidate.
    assert fake_client.requests_for(url) == [("GET", url)] * 3
    # Consistent => recorded.
    assert url in fuzzer.discovered_endpoints
    assert any(e.url == url for e in discovered)


# ---------------------------------------------------------------------------
# 35.4: inconsistent confirmations => candidate is NOT recorded
# ---------------------------------------------------------------------------

def _plan_status_class_mismatch(method, url, attempt):
    """First response 200, confirmations 500 (different Status_Code_Class)."""
    return (200, _OK_BODY) if attempt == 0 else (500, _OK_BODY)


def _plan_body_size_mismatch(method, url, attempt):
    """First response a small body, confirmations a much larger body (>5%)."""
    return (200, b"x") if attempt == 0 else (200, b"x" * 10_000)


@pytest.mark.parametrize(
    "plan, label",
    [
        (_plan_status_class_mismatch, "different status class"),
        (_plan_body_size_mismatch, "large body-size difference"),
    ],
)
def test_inconsistent_confirmations_do_not_record(plan, label):
    """When enabled and the confirmation responses are inconsistent (different
    status class or a large body-size difference), the candidate is NOT recorded.

    **Validates: Requirement 35.4**
    """
    config = _make_config(
        hit_confirmation=HitConfirmationConfig(enabled=True, count=2)
    )

    fake_client, fuzzer, discovered = asyncio.run(
        _run_discovery(["admin"], config, response_plan=plan)
    )

    url = urljoin(BASE_URL + "/", "admin")
    # Confirmation re-requests were still issued (first + 2 confirmations)...
    assert len(fake_client.requests_for(url)) == 3, label
    # ...but the inconsistent set means the candidate is dropped, never stored.
    assert url not in fuzzer.discovered_endpoints, label
    assert all(e.url != url for e in discovered), label


# ---------------------------------------------------------------------------
# 35.5: confirmation requests count toward budget, stay within concurrency,
#       and flow through the rate-limited client.request path
# ---------------------------------------------------------------------------

def test_confirmation_requests_counted_bounded_and_routed_through_client():
    """Confirmation re-requests count toward the Request_Budget, never exceed the
    Concurrency_Limit, and every one flows through HTTPRequestEngine.request.

    **Validates: Requirement 35.5**
    """
    words = ["alpha", "beta", "gamma", "delta"]
    concurrency = 2
    count = 2
    # A finite budget large enough that nothing is truncated, so requests_issued
    # accounts for every request (catch-all probes + first requests + confirmations).
    config = _make_config(
        hit_confirmation=HitConfirmationConfig(enabled=True, count=count),
        concurrency=concurrency,
        max_requests=10_000,
    )

    fake_client, fuzzer, discovered = asyncio.run(_run_discovery(words, config))

    # Every interesting candidate was confirmed: first request + ``count``
    # confirmation re-requests = count + 1 requests per candidate URL.
    for word in words:
        url = urljoin(BASE_URL + "/", word)
        assert len(fake_client.requests_for(url)) == count + 1, url

    # The internal budget counter accounts for every request that flowed through
    # the client, including the confirmation re-requests (so requests_issued is
    # strictly larger than the one-per-candidate count would be).
    assert fuzzer.requests_issued == fake_client.call_count
    assert fuzzer.requests_issued >= len(words) * (count + 1)

    # The Concurrency_Limit was never exceeded across the whole run.
    assert fake_client.peak_in_flight <= concurrency, (
        f"peak in-flight {fake_client.peak_in_flight} exceeds Concurrency_Limit "
        f"{concurrency}"
    )

    # Consistent responses => every candidate was recorded.
    assert len(discovered) == len(words)


# ---------------------------------------------------------------------------
# 35.7: --confirm-hits validation rejects invalid values, runs no discovery
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", ["0", "abc"])
def test_confirm_hits_invalid_value_rejected_and_no_discovery(value):
    """``--confirm-hits 0`` and a non-integer value are rejected during option
    parsing, naming the offending value, and no discovery is performed.

    ``0`` fails the lower-bound callback (must be >= 1); a non-integer fails
    Click's ``type=int`` conversion. Both happen before the discovery entry point
    is reached.

    **Validates: Requirement 35.7**
    """
    runner = CliRunner()

    with patch.object(apileaks, "run_enhanced_apileak") as discovery:
        result = runner.invoke(
            cli,
            [
                "--no-banner",
                "dir",
                "--target",
                "https://api.example.com",
                f"--confirm-hits={value}",
            ],
        )

    # Non-zero exit, and the offending value is named in the error output.
    assert result.exit_code != 0
    assert value in result.output
    assert "--confirm-hits" in result.output
    # No discovery was performed.
    discovery.assert_not_called()
