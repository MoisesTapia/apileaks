"""
Property-Based Tests for Recursion Depth Bound

**Feature: owasp-complete-purple-teaming-cicd, Property 9: Recursion depth bound**

Property 9 (from design.md):
    FOR ALL non-negative depth values N (including 0) and any base target, the
    deepest recursion level at which Endpoint_Discovery issues a
    Discovery_Request is at most N; when N == 0 or recursion is disabled, no
    recursive Discovery_Request is issued (only the depth-0 wordlist pass runs).
    Verified by driving discovery against a fake target that always returns a
    recursable (2xx) response -- so recursion would continue without a bound --
    and asserting the maximum observed request depth is <= N.

These tests drive the real EndpointFuzzer.discover_endpoints against an
in-memory fake HTTPRequestEngine (no network). The fake answers every genuine
wordlist path with a 2xx response, so recursion would descend indefinitely if
it were not bounded by the configured Recursion_Depth / Recursion_Toggle.

The fake deliberately answers the random catch-all detection probes (long,
uuid-like path segments) with a 404 so Catch_All_Response detection stays off
and recursion proceeds purely according to the depth bound under test.

**Validates: Requirements 17.10, 17.2, 17.3, 17.5**
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

# Catch-all detection probes target uuid4().hex-based paths (33 chars). Genuine
# wordlist segments generated below are short, so a length threshold reliably
# distinguishes a catch-all probe path from a real candidate path.
_PROBE_SEGMENT_MIN_LEN = 20


class AlwaysRecursableFakeClient:
    """
    In-memory fake HTTPRequestEngine that makes every genuine candidate path
    look recursable.

    Every request to a normal wordlist path returns a 2xx response (so
    Endpoint_Discovery would keep recursing without a bound). Requests to the
    long, random catch-all detection probe paths return 404 so that
    Catch_All_Response detection stays off and the depth bound -- not catch-all
    exclusion -- is what limits recursion.

    Every (method, url) call is recorded so the test can reconstruct the depth
    at which each Discovery_Request was issued.
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
        if len(last_segment) >= _PROBE_SEGMENT_MIN_LEN:
            status_code = 404
        else:
            status_code = 200

        return Response(
            status_code=status_code,
            headers={"Content-Type": "application/json"},
            content=b'{"ok": true}',
            text='{"ok": true}',
            url=url,
            elapsed=0.01,
            request_method=method,
        )


def _make_config(recursive: bool, max_depth: int) -> FuzzingConfig:
    """Build a FuzzingConfig that exercises only endpoint discovery."""
    return FuzzingConfig(
        endpoints=EndpointFuzzingConfig(
            enabled=True,
            wordlist="unused.txt",
            methods=["GET"],          # single method => one request per unique path
            follow_redirects=False,
        ),
        parameters=ParameterFuzzingConfig(enabled=False),
        headers=HeaderFuzzingConfig(enabled=False),
        recursive=recursive,
        max_depth=max_depth,
        max_requests=None,            # unbounded: only the depth bound limits us
        concurrency=50,
    )


def _write_wordlist(words):
    """Write words to a temp wordlist file and return its path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    f.write("\n".join(words) + "\n")
    f.close()
    return f.name


def _request_depth(url: str) -> int:
    """Recursion depth at which a Discovery_Request for ``url`` was issued.

    The depth-0 wordlist pass appends one path segment to the base URL; each
    recursive level appends one further segment. So depth == (segment count) - 1.
    """
    path = urlparse(url).path
    segments = [s for s in path.split("/") if s]
    return len(segments) - 1


async def _run_discovery(recursive: bool, max_depth: int, words):
    """Run a full discovery pass and return (fake_client, discovered)."""
    fake_client = AlwaysRecursableFakeClient()
    fuzzer = EndpointFuzzer(fake_client, _make_config(recursive, max_depth))
    wordlist_path = _write_wordlist(words)
    try:
        discovered = await fuzzer.discover_endpoints(BASE_URL, wordlist_path)
    finally:
        os.unlink(wordlist_path)
    return fake_client, discovered


@given(
    max_depth=st.integers(min_value=0, max_value=3),
    recursive=st.booleans(),
    num_words=st.integers(min_value=1, max_value=2),
)
@settings(max_examples=40, deadline=None)
def test_recursion_never_exceeds_configured_depth(max_depth, recursive, num_words):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 9: Recursion depth
    bound**
    **Validates: Requirements 17.10, 17.2, 17.3, 17.5**

    Against an always-recursable (2xx) fake target, the deepest level at which
    a Discovery_Request is issued is at most the effective Recursion_Depth:
      - N when recursion is enabled and N > 0 (17.2, 17.10), and
      - 0 when N == 0 (17.3) or recursion is disabled (17.5),
    in which case no recursive Discovery_Request is issued (only the depth-0
    wordlist pass runs).
    """
    # Short, url-safe segments that are clearly distinct from the long random
    # catch-all probe paths.
    words = [f"seg{i}" for i in range(num_words)]

    fake_client, _ = asyncio.run(_run_discovery(recursive, max_depth, words))

    # Recursive descent only happens when the toggle is on AND depth > 0.
    recursion_active = recursive and max_depth > 0
    expected_max_depth = max_depth if recursion_active else 0

    # Depth of every issued Discovery_Request (catch-all probes are depth 0).
    observed_depths = [_request_depth(url) for _, url in fake_client.calls]

    # The depth-0 wordlist pass must always run, so there is something to bound.
    assert any(d == 0 for d in observed_depths), (
        "expected at least the depth-0 wordlist pass to issue requests"
    )

    # 17.10 / 17.2: no Discovery_Request is issued deeper than the bound.
    assert max(observed_depths) <= expected_max_depth, (
        f"observed max depth {max(observed_depths)} exceeds bound "
        f"{expected_max_depth} (recursive={recursive}, max_depth={max_depth})"
    )

    # 17.3 / 17.5: when recursion is disabled or N == 0, no recursive request
    # (depth >= 1) is ever issued.
    if not recursion_active:
        recursive_calls = [
            url for _, url in fake_client.calls if _request_depth(url) >= 1
        ]
        assert recursive_calls == [], (
            f"expected no recursive Discovery_Request, but saw {recursive_calls} "
            f"(recursive={recursive}, max_depth={max_depth})"
        )


@given(num_words=st.integers(min_value=1, max_value=2))
@settings(max_examples=20, deadline=None)
def test_depth_zero_issues_no_recursive_request(num_words):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 9: Recursion depth
    bound**
    **Validates: Requirements 17.3, 17.10**

    With recursion enabled but a Recursion_Depth of 0, only the initial depth-0
    wordlist pass runs and no recursive Discovery_Request (depth >= 1) is issued,
    even though the target would otherwise be infinitely recursable.
    """
    words = [f"seg{i}" for i in range(num_words)]

    fake_client, _ = asyncio.run(_run_discovery(recursive=True, max_depth=0, words=words))

    recursive_calls = [url for _, url in fake_client.calls if _request_depth(url) >= 1]
    assert recursive_calls == [], (
        f"depth 0 must issue no recursive Discovery_Request, saw {recursive_calls}"
    )


@given(max_depth=st.integers(min_value=1, max_value=3))
@settings(max_examples=20, deadline=None)
def test_disabled_recursion_ignores_depth(max_depth):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 9: Recursion depth
    bound**
    **Validates: Requirements 17.5, 17.10**

    With --no-recursive (recursion disabled), Endpoint_Discovery performs only
    the depth-0 wordlist pass and issues no recursive Discovery_Request
    irrespective of the Recursion_Depth value.
    """
    words = ["seg0", "seg1"]

    fake_client, _ = asyncio.run(
        _run_discovery(recursive=False, max_depth=max_depth, words=words)
    )

    recursive_calls = [url for _, url in fake_client.calls if _request_depth(url) >= 1]
    assert recursive_calls == [], (
        f"disabled recursion must issue no recursive Discovery_Request, "
        f"saw {recursive_calls} (max_depth={max_depth})"
    )
