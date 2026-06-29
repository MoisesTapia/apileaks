"""
Property-Based Tests for Request Budget Bound

**Feature: owasp-complete-purple-teaming-cicd, Property 10: Request budget bound**

Property 10 (from design.md):
    FOR ALL Request_Budget values N >= 1, the total number of Discovery_Requests
    issued by Endpoint_Discovery during a run (initial pass, recursive passes,
    and catch-all probes combined) is at most N, and discovery still returns the
    endpoints discovered before truncation. Verified with a request-counting
    fake client against a target/wordlist large enough to exceed N, asserting
    requests_issued <= N and that a partial result set is returned with
    budget_reached set.

These tests drive the real EndpointFuzzer.discover_endpoints against an
in-memory, request-counting fake HTTPRequestEngine (no network). The fake
answers every genuine wordlist path with a 2xx response, so -- with recursion
enabled -- discovery would descend through a far larger candidate space than
any finite budget allows. The long, uuid-like catch-all detection probes are
answered with 404 so Catch_All_Response detection stays off and recursion (and
therefore the combined initial + recursive + probe request count) is exercised
against the budget bound under test.

**Validates: Requirements 18.8, 18.2, 18.3, 18.4**
"""

import asyncio
import os
import tempfile
from urllib.parse import urlparse

from hypothesis import given, settings, strategies as st

from modules.fuzzing.orchestrator import EndpointFuzzer, Endpoint
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
# keeps the unbounded run finite (so we can compute a reference) while still
# producing far more candidates than the budgets we generate.
NUM_WORDS = 3
MAX_DEPTH = 2
WORDS = [f"seg{i}" for i in range(NUM_WORDS)]


class CountingRecursableFakeClient:
    """
    In-memory fake HTTPRequestEngine that counts every request and makes every
    genuine candidate path look recursable.

    Every request to a normal wordlist path returns a 2xx response (so
    Endpoint_Discovery would keep recursing and issuing requests well past any
    finite budget). Requests to the long, random catch-all detection probe paths
    return 404 so Catch_All_Response detection stays off and recursion proceeds.

    Every (method, url) call is recorded so the test can assert how many
    Discovery_Requests actually flowed through the client.
    """

    def __init__(self):
        self.calls = []  # list of (method, url) in call order

    @property
    def call_count(self) -> int:
        return len(self.calls)

    async def request(self, method: str, url: str, **kwargs) -> Response:
        self.calls.append((method, url))
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


def _make_config(max_requests) -> FuzzingConfig:
    """Build a recursion-enabled FuzzingConfig with the given Request_Budget."""
    return FuzzingConfig(
        endpoints=EndpointFuzzingConfig(
            enabled=True,
            wordlist="unused.txt",
            methods=["GET"],          # single method => one request per unique path
            follow_redirects=False,
        ),
        parameters=ParameterFuzzingConfig(enabled=False),
        headers=HeaderFuzzingConfig(enabled=False),
        recursive=True,              # recursive passes contribute to the count
        max_depth=MAX_DEPTH,
        max_requests=max_requests,   # Request_Budget (None => unbounded)
        concurrency=50,
    )


def _write_wordlist(words):
    """Write words to a temp wordlist file and return its path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    f.write("\n".join(words) + "\n")
    f.close()
    return f.name


async def _run_discovery(max_requests):
    """Run a full discovery pass and return (fake_client, fuzzer, discovered)."""
    fake_client = CountingRecursableFakeClient()
    fuzzer = EndpointFuzzer(fake_client, _make_config(max_requests))
    wordlist_path = _write_wordlist(WORDS)
    try:
        discovered = await fuzzer.discover_endpoints(BASE_URL, wordlist_path)
    finally:
        os.unlink(wordlist_path)
    return fake_client, fuzzer, discovered


# Reference unbounded run: with no budget, discovery issues a fixed, finite
# number of requests and discovers a fixed set of endpoints. Any budget N below
# this total must therefore truncate, set budget_reached, and return a strictly
# smaller (partial) result set.
_UNBOUNDED_CLIENT, _UNBOUNDED_FUZZER, _UNBOUNDED_DISCOVERED = asyncio.run(
    _run_discovery(max_requests=None)
)
UNBOUNDED_REQUESTS = _UNBOUNDED_CLIENT.call_count
UNBOUNDED_DISCOVERED = len(_UNBOUNDED_DISCOVERED)


@given(max_requests=st.integers(min_value=1, max_value=UNBOUNDED_REQUESTS - 1))
@settings(max_examples=150, deadline=None)
def test_total_requests_never_exceed_budget(max_requests):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 10: Request budget
    bound**
    **Validates: Requirements 18.8, 18.2, 18.3, 18.4**

    For any Request_Budget N >= 1 (bounded above by the unbounded run's total so
    the wordlist/recursion candidate space always exceeds N):

      - 18.2 / 18.8: the total Discovery_Requests issued -- the depth-0 wordlist
        pass, every recursive pass, and the catch-all probes combined -- is at
        most N, both as counted internally (requests_issued) and as observed at
        the client (call_count).
      - 18.3: discovery stops once the budget is reached, so budget_reached is
        set.
      - 18.4: discovery still returns the endpoints found before truncation -- a
        partial result set, strictly smaller than the unbounded run.
    """
    fake_client, fuzzer, discovered = asyncio.run(_run_discovery(max_requests))

    # 18.2 / 18.8: the combined request count never exceeds the budget.
    assert fuzzer.requests_issued <= max_requests, (
        f"requests_issued {fuzzer.requests_issued} exceeds budget {max_requests}"
    )
    # 18.2 / 20.4: every issued request flowed through the client, and the
    # client-observed count is likewise bounded by the budget.
    assert fake_client.call_count == fuzzer.requests_issued
    assert fake_client.call_count <= max_requests, (
        f"client issued {fake_client.call_count} requests, exceeds budget "
        f"{max_requests}"
    )

    # 18.3: the candidate space exceeds the budget, so discovery truncates and
    # marks the budget reached.
    assert fuzzer.budget_reached is True, (
        f"budget_reached not set for budget {max_requests} despite candidate "
        f"space of {UNBOUNDED_REQUESTS} requests"
    )

    # 18.4: a partial result set is returned -- only real Endpoints, never more
    # than the requests actually issued, and strictly fewer than the unbounded
    # run would have discovered.
    assert all(isinstance(e, Endpoint) for e in discovered)
    assert len(discovered) <= fuzzer.requests_issued
    assert len(discovered) < UNBOUNDED_DISCOVERED, (
        f"discovered {len(discovered)} endpoints is not a partial subset of the "
        f"unbounded {UNBOUNDED_DISCOVERED}"
    )
