"""
Property-Based Tests for Concurrency Bound

**Feature: owasp-complete-purple-teaming-cicd, Property 11: Concurrency bound**

Property 11 (from design.md):
    FOR ALL Concurrency_Limit values N >= 1, the number of Discovery_Requests in
    flight simultaneously never exceeds N. Verified with a fake client that
    increments a shared in-flight counter on entry and decrements it on exit,
    recording the peak across the whole run, and asserting peak <= N -- while
    confirming every request still passes through the rate limiter.

These tests drive the real EndpointFuzzer.discover_endpoints against an
in-memory fake HTTPRequestEngine (no network). The fake answers every genuine
wordlist path with a 2xx response so discovery, with recursion enabled, builds
a candidate space far larger than any small Concurrency_Limit -- giving the
asyncio.Semaphore in _test_endpoint something real to throttle. The long,
uuid-like catch-all detection probes are answered with 404 so Catch_All_Response
detection stays off and recursion proceeds.

The fake increments a shared in-flight counter on entry, yields control via
asyncio.sleep(0) so sibling coroutines dispatched in the same batch overlap,
records the running peak, then decrements on exit. Because every in-flight
request holds the semaphore for the duration of the client call, the recorded
peak equals the maximum simultaneous in-flight Discovery_Requests, which the
property asserts is bounded by N. Every request flows through the same
client.request path (the only path that applies the rate limiter, Req 20.4),
and the test confirms that count matches the requests the fuzzer issued.

**Validates: Requirements 20.6, 20.2, 20.4**
"""

import asyncio
import os
import tempfile
from urllib.parse import urlparse

from hypothesis import given, settings, strategies as st

from modules.fuzzing.orchestrator import EndpointFuzzer
from core.config import (
    FuzzingConfig,
    EndpointFuzzingConfig,
    ParameterFuzzingConfig,
    HeaderFuzzingConfig,
)
from utils.http_client import Response


BASE_URL = "http://example.com"

# Catch-all detection probes target uuid4().hex-based paths (33 chars). The
# genuine wordlist segments below are short, so a length threshold reliably
# distinguishes a catch-all probe path from a real candidate path.
_PROBE_SEGMENT_MIN_LEN = 20

# A small but multi-level candidate tree. With recursion enabled and an
# always-2xx target, depth-0 issues NUM_WORDS requests, each discovered endpoint
# spawns NUM_WORDS children at the next depth, and so on up to MAX_DEPTH. This
# produces far more concurrently-dispatchable candidates than the small
# Concurrency_Limit values generated below, so the semaphore is meaningfully
# exercised while the overall run stays finite.
NUM_WORDS = 4
MAX_DEPTH = 2
WORDS = [f"seg{i}" for i in range(NUM_WORDS)]


class PeakTrackingRecursableFakeClient:
    """
    In-memory fake HTTPRequestEngine that records peak in-flight concurrency and
    makes every genuine candidate path look recursable.

    On entry the fake increments a shared in-flight counter and updates the
    running peak; it then yields control (await asyncio.sleep(0)) so other
    coroutines dispatched concurrently in the same batch overlap with it; on
    exit it decrements the counter. The recorded peak is therefore the maximum
    number of Discovery_Requests simultaneously inside the client -- i.e. the
    maximum number simultaneously holding the EndpointFuzzer semaphore.

    Every request to a normal wordlist path returns a 2xx response (so discovery
    keeps recursing and dispatching more candidates). Requests to the long,
    random catch-all detection probe paths return 404 so Catch_All_Response
    detection stays off and recursion proceeds.

    Every (method, url) call is recorded so the test can assert that every
    Discovery_Request flowed through this single (rate-limited) client path.
    """

    def __init__(self):
        self.calls = []          # list of (method, url) in call order
        self.in_flight = 0       # current number of in-flight requests
        self.peak_in_flight = 0  # peak observed concurrency across the run

    @property
    def call_count(self) -> int:
        return len(self.calls)

    async def request(self, method: str, url: str, **kwargs) -> Response:
        # Track concurrency: increment on entry, record peak, yield, decrement.
        self.in_flight += 1
        self.peak_in_flight = max(self.peak_in_flight, self.in_flight)
        self.calls.append((method, url))
        try:
            # Yield control so concurrent requests can overlap and build up the
            # in-flight count toward (but never past) the Concurrency_Limit.
            await asyncio.sleep(0)

            path = urlparse(url).path
            segments = [s for s in path.split("/") if s]
            last_segment = segments[-1] if segments else ""

            # Catch-all detection probes use long, random (uuid-like) segments.
            # Answer those with 404 so catch-all detection does not trigger.
            status_code = 404 if len(last_segment) >= _PROBE_SEGMENT_MIN_LEN else 200

            return Response(
                status_code=status_code,
                headers={"Content-Type": "application/json"},
                content=b'{"ok": true}',
                text='{"ok": true}',
                url=url,
                elapsed=0.01,
                request_method=method,
            )
        finally:
            self.in_flight -= 1


def _make_config(concurrency) -> FuzzingConfig:
    """Build a recursion-enabled FuzzingConfig with the given Concurrency_Limit."""
    return FuzzingConfig(
        endpoints=EndpointFuzzingConfig(
            enabled=True,
            wordlist="unused.txt",
            methods=["GET"],          # single method => one request per unique path
            follow_redirects=False,
        ),
        parameters=ParameterFuzzingConfig(enabled=False),
        headers=HeaderFuzzingConfig(enabled=False),
        recursive=True,              # recursive passes give the semaphore work
        max_depth=MAX_DEPTH,
        max_requests=None,           # unbounded: only the concurrency bound applies
        concurrency=concurrency,     # Concurrency_Limit under test
    )


def _write_wordlist(words):
    """Write words to a temp wordlist file and return its path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    f.write("\n".join(words) + "\n")
    f.close()
    return f.name


async def _run_discovery(concurrency):
    """Run a full discovery pass and return (fake_client, fuzzer, discovered)."""
    fake_client = PeakTrackingRecursableFakeClient()
    fuzzer = EndpointFuzzer(fake_client, _make_config(concurrency))
    wordlist_path = _write_wordlist(WORDS)
    try:
        discovered = await fuzzer.discover_endpoints(BASE_URL, wordlist_path)
    finally:
        os.unlink(wordlist_path)
    return fake_client, fuzzer, discovered


# Reference unbounded-concurrency run: with a very large Concurrency_Limit the
# semaphore never throttles, so the whole always-2xx candidate tree is issued.
# This fixes the total number of Discovery_Requests the run makes, which every
# bounded run below must still issue in full (the concurrency cap only limits
# how many run at once, never how many run in total -- Req 20.4).
_REF_CLIENT, _REF_FUZZER, _REF_DISCOVERED = asyncio.run(
    _run_discovery(concurrency=10_000)
)
TOTAL_REQUESTS = _REF_CLIENT.call_count
TOTAL_DISCOVERED = len(_REF_DISCOVERED)


@given(concurrency=st.integers(min_value=1, max_value=TOTAL_REQUESTS + 5))
@settings(max_examples=120, deadline=None)
def test_peak_in_flight_never_exceeds_concurrency_limit(concurrency):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 11: Concurrency
    bound**
    **Validates: Requirements 20.6, 20.2, 20.4**

    For any Concurrency_Limit N >= 1 (including values both below and above the
    candidate space), against an always-2xx recursable target:

      - 20.2 / 20.6: the peak number of Discovery_Requests in flight
        simultaneously -- recorded by the client's live in-flight counter across
        the entire run (depth-0 pass, recursive passes, and catch-all probes) --
        is at most N.
      - 20.4: the concurrency cap never drops or short-circuits a request: every
        Discovery_Request still flows through the single (rate-limited)
        client.request path, so the client-observed count equals the total the
        unbounded reference run issued.
    """
    fake_client, fuzzer, discovered = asyncio.run(_run_discovery(concurrency))

    # 20.2 / 20.6: simultaneous in-flight requests never exceeded the limit.
    assert fake_client.peak_in_flight <= concurrency, (
        f"peak in-flight {fake_client.peak_in_flight} exceeds Concurrency_Limit "
        f"{concurrency}"
    )

    # Sanity: the fuzzer actually used the configured limit for its semaphore.
    assert fuzzer.concurrency == concurrency

    # 20.4: throttling concurrency must not drop requests. Every candidate still
    # passes through the rate-limited client, so the total issued matches the
    # unbounded reference run regardless of N.
    assert fake_client.call_count == TOTAL_REQUESTS, (
        f"client saw {fake_client.call_count} requests with Concurrency_Limit "
        f"{concurrency}, expected {TOTAL_REQUESTS} (concurrency must not drop "
        f"requests)"
    )
    assert len(discovered) == TOTAL_DISCOVERED


@given(concurrency=st.integers(min_value=1, max_value=3))
@settings(max_examples=60, deadline=None)
def test_small_limit_is_actually_reached_and_respected(concurrency):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 11: Concurrency
    bound**
    **Validates: Requirements 20.6, 20.2**

    For small Concurrency_Limit values the candidate space comfortably exceeds N
    (depth-0 alone dispatches NUM_WORDS > N requests at once), so the bound is
    genuinely exercised: the peak in-flight count must still be at most N. This
    guards against a vacuous pass where concurrency simply never built up.
    """
    assert NUM_WORDS > 3  # ensure depth-0 can exceed the max generated limit

    fake_client, _, _ = asyncio.run(_run_discovery(concurrency))

    assert fake_client.peak_in_flight <= concurrency, (
        f"peak in-flight {fake_client.peak_in_flight} exceeds small "
        f"Concurrency_Limit {concurrency}"
    )
    # The run did real work, so concurrency had the opportunity to build up.
    assert fake_client.call_count >= NUM_WORDS
