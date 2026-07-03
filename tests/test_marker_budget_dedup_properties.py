"""
Property-Based Tests for marker-mode budget and deduplication bounds.

# Feature: owasp-complete-purple-teaming-cicd, Property 30: Marker candidates
# obey the budget and deduplication bounds

Property 30 (from design.md):
    FOR ALL Request_Budget values N >= 1 run against a marker target whose
    product/zip candidate space exceeds N, marker-mode Endpoint_Discovery issues
    at most N Discovery_Requests in total (catch-all detection probes and every
    other Discovery_Request count toward the same budget), tests each canonical
    URL exactly once (one ``tested_urls`` entry and one Discovery_Request per
    URL after ``normalize_url``), returns a partial ``Discovery_Result`` set of
    the records found before truncation, and sets ``budget_reached``.

These tests drive the real ``EndpointFuzzer.discover_endpoints`` marker branch
(``_fuzz_wordlist`` at depth 0) against an in-memory, request-counting fake
``HTTPRequestEngine`` (no network). Marker mode activates because the raw target
carries at least one Fuzz_Keyword occurrence and ``marker_wordlists`` is
configured. The candidate space (cartesian product for CLUSTERBOMB, index-wise
zip for PITCHFORK) is sized to exceed every generated budget so truncation and
``budget_reached`` are genuinely exercised.

The fake client answers the long, uuid-like catch-all detection probe paths with
404 (so Catch_All_Response detection stays off) and every marker candidate with
200, and records every ``(method, url)`` so the tests can assert both the budget
bound and the per-canonical-URL deduplication bound at the client.

**Validates: Requirements 47.6, 42.3, 42.4, 43.4, 45.1, 45.2, 45.3**
"""

import asyncio
import os
import tempfile
from collections import Counter
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
from utils.url_normalize import normalize_url


# A raw target carrying exactly two literal FUZZ markers in the path. Both
# markers fall in short path segments, so a substituted candidate's final path
# segment is a short value (see below) and never collides with the long,
# uuid-like catch-all probe segments.
MARKER_TARGET = "http://example.com/FUZZ/section/FUZZ"

# Catch-all detection probes target uuid4().hex-based paths (>= 32 hex chars),
# so a length threshold reliably distinguishes a catch-all probe path from a
# marker candidate path (whose values are short "aNN"/"bNN" tokens below).
_PROBE_SEGMENT_MIN_LEN = 20

# Per-marker Marker_Wordlists. Each value is distinct within its list and short,
# so every substituted candidate URL is already canonical (lower-case, no
# trailing slash) and pairwise-distinct after normalize_url. Sizes are chosen so
# BOTH combination modes exceed every generated budget:
#   - CLUSTERBOMB: 50 x 50 = 2500 candidates
#   - PITCHFORK:   min(50, 50) = 50 candidates
_WL_SIZE = 50
_WORDLIST_A = [f"a{i:02d}" for i in range(_WL_SIZE)]
_WORDLIST_B = [f"b{i:02d}" for i in range(_WL_SIZE)]

# The smallest candidate space across the tested modes (PITCHFORK == 50). Every
# generated budget stays strictly below this so the candidate space always
# exceeds N and truncation is guaranteed.
_MIN_CANDIDATE_SPACE = _WL_SIZE

# Catch-all detection issues up to CATCH_ALL_PROBES requests that also consume
# the budget. Keeping the minimum budget above that count guarantees at least
# one marker candidate is issued (so the result set is genuinely partial and
# non-empty) while the maximum stays below the candidate space.
_MIN_BUDGET = EndpointFuzzer.CATCH_ALL_PROBES + 1  # 4
_MAX_BUDGET = _MIN_CANDIDATE_SPACE - 10            # 40


def _is_probe_url(url: str) -> bool:
    """True when ``url`` is a catch-all detection probe (long uuid-like segment)."""
    path = urlparse(url).path
    segments = [s for s in path.split("/") if s]
    last_segment = segments[-1] if segments else ""
    return len(last_segment) >= _PROBE_SEGMENT_MIN_LEN


class CountingMarkerFakeClient:
    """In-memory fake HTTPRequestEngine that counts every Discovery_Request.

    Catch-all detection probes (long, uuid-like paths) are answered 404 so
    Catch_All_Response detection stays off; every marker candidate is answered
    200 so it is recorded as a Discovery_Result. Each ``(method, url)`` call is
    stored in order so the tests can assert the budget bound and the
    per-canonical-URL deduplication bound as observed at the client.
    """

    def __init__(self):
        self.calls = []  # list of (method, url) in call order

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def marker_calls(self):
        """Return the URLs of the non-probe (marker candidate) requests, in order."""
        return [url for _, url in self.calls if not _is_probe_url(url)]

    async def request(self, method: str, url: str, **kwargs) -> Response:
        self.calls.append((method, url))
        await asyncio.sleep(0)
        status_code = 404 if _is_probe_url(url) else 200
        return Response(
            status_code=status_code,
            headers={"Content-Type": "application/json"},
            content=b'{"ok": true}',
            text='{"ok": true}',
            url=url,
            elapsed=0.01,
            request_method=method,
        )


def _make_config(max_requests, fuzz_mode) -> FuzzingConfig:
    """Build a marker-mode FuzzingConfig with the given budget and Fuzz_Mode."""
    return FuzzingConfig(
        endpoints=EndpointFuzzingConfig(
            enabled=True,
            wordlist="unused.txt",
            methods=["GET"],          # single method => one request per unique URL
            follow_redirects=False,
            fuzz_keyword="FUZZ",
            fuzz_mode=fuzz_mode,
            marker_wordlists=[list(_WORDLIST_A), list(_WORDLIST_B)],
        ),
        parameters=ParameterFuzzingConfig(enabled=False),
        headers=HeaderFuzzingConfig(enabled=False),
        recursive=False,             # marker mode is a flat depth-0 sweep
        max_depth=0,
        max_requests=max_requests,   # Request_Budget (None => unbounded)
        concurrency=50,
    )


def _write_wordlist(words):
    """Write a non-empty wordlist file (its content is ignored in marker mode)."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    f.write("\n".join(words) + "\n")
    f.close()
    return f.name


async def _run_discovery(max_requests, fuzz_mode):
    """Run a marker-mode discovery pass; return (fake_client, fuzzer, discovered)."""
    fake_client = CountingMarkerFakeClient()
    fuzzer = EndpointFuzzer(fake_client, _make_config(max_requests, fuzz_mode))
    # A non-empty wordlist file is required for discover_endpoints to proceed;
    # its content is unused because the marker branch generates candidates from
    # the Fuzz_Markers, not the wordlist.
    wordlist_path = _write_wordlist(["placeholder"])
    try:
        discovered = await fuzzer.discover_endpoints(MARKER_TARGET, wordlist_path)
    finally:
        os.unlink(wordlist_path)
    return fake_client, fuzzer, discovered


@given(
    max_requests=st.integers(min_value=_MIN_BUDGET, max_value=_MAX_BUDGET),
    fuzz_mode=st.sampled_from(["clusterbomb", "pitchfork"]),
)
@settings(max_examples=150, deadline=None)
def test_marker_candidates_obey_budget_and_dedup_bounds(max_requests, fuzz_mode):
    """
    # Feature: owasp-complete-purple-teaming-cicd, Property 30: Marker candidates
    # obey the budget and deduplication bounds
    **Validates: Requirements 47.6, 42.3, 42.4, 45.1, 45.2, 45.3, 43.4**

    For any Request_Budget N in ``[CATCH_ALL_PROBES + 1, candidate_space - 10]``
    against a two-marker target whose candidate space (CLUSTERBOMB product or
    PITCHFORK zip) exceeds N:

      - 47.6 / 42.3 / 42.4 / 43.4: the total Discovery_Requests issued -- the
        catch-all probes plus the drained marker candidates -- is at most N, both
        as counted internally (``requests_issued``) and as observed at the client;
        lazy generation is cut off once the budget is hit, so discovery stops
        rather than materializing the whole product/zip.
      - 45.1 / 45.2: each canonical URL is tested exactly once -- every issued
        marker request is already canonical and no canonical URL is requested
        more than once (one ``tested_urls`` entry and one Discovery_Request per
        canonical URL).
      - 45.3: a partial Discovery_Result set is returned (the records found
        before truncation) and ``budget_reached`` is set.
    """
    fake_client, fuzzer, discovered = asyncio.run(
        _run_discovery(max_requests, fuzz_mode)
    )

    # --- Budget bound (47.6, 42.3/42.4/43.4) -------------------------------
    # Catch-all probes and every marker Discovery_Request share the one budget,
    # so the combined count never exceeds N (asserted <=, not ==, because the
    # probes also consume budget).
    assert fuzzer.requests_issued <= max_requests, (
        f"requests_issued {fuzzer.requests_issued} exceeds budget {max_requests}"
    )
    # Every issued request flowed through the client exactly once, so the
    # client-observed count matches and is likewise bounded by the budget.
    assert fake_client.call_count == fuzzer.requests_issued
    assert fake_client.call_count <= max_requests

    marker_calls = fake_client.marker_calls()

    # --- Deduplication bound (45.1, 45.2) ----------------------------------
    # Every issued marker URL is already canonical (normalize_url is a fixed
    # point on it), so no canonical collapse was skipped before dispatch.
    assert all(normalize_url(u) == u for u in marker_calls)
    # No canonical URL is requested more than once: one Discovery_Request per
    # canonical URL.
    canonical_counts = Counter(normalize_url(u) for u in marker_calls)
    assert all(count == 1 for count in canonical_counts.values()), (
        f"a canonical URL was requested more than once: {canonical_counts}"
    )
    # tested_urls holds canonical, pairwise-distinct entries (a set), and every
    # issued marker request corresponds to one of them: one tested_urls entry
    # per canonical URL.
    assert all(normalize_url(u) == u for u in fuzzer.tested_urls)
    assert set(marker_calls) <= fuzzer.tested_urls

    # --- Partial result set + budget_reached (45.3) ------------------------
    # At least one marker candidate is issued (N > CATCH_ALL_PROBES) and every
    # issued marker candidate answered 200, so a non-empty, partial set of real
    # Endpoints is returned -- never more than the requests issued, and strictly
    # fewer than the full candidate space.
    assert all(isinstance(e, Endpoint) for e in discovered)
    assert len(discovered) >= 1
    assert len(discovered) <= fuzzer.requests_issued
    assert len(discovered) < _MIN_CANDIDATE_SPACE, (
        f"discovered {len(discovered)} is not a partial subset of the candidate "
        f"space (>= {_MIN_CANDIDATE_SPACE})"
    )

    # The candidate space exceeds the budget, so discovery truncates and marks
    # the budget reached.
    assert fuzzer.budget_reached is True, (
        f"budget_reached not set for budget {max_requests} (mode={fuzz_mode})"
    )


# A single-marker target used to exercise the deduplication collapse directly:
# a Marker_Wordlist with repeated values produces duplicate candidate URLs that
# must collapse to one tested_urls entry and one Discovery_Request per canonical
# URL (Requirements 45.1, 45.2).
_SINGLE_MARKER_TARGET = "http://example.com/api/FUZZ"


@given(
    values=st.lists(
        st.sampled_from([f"w{i}" for i in range(6)]),
        min_size=1,
        max_size=30,
    )
)
@settings(max_examples=150, deadline=None)
def test_marker_dedup_collapses_duplicate_candidates(values):
    """
    # Feature: owasp-complete-purple-teaming-cicd, Property 30: Marker candidates
    # obey the budget and deduplication bounds
    **Validates: Requirements 47.6, 45.1, 45.2**

    FOR ALL single-marker Marker_Wordlists that may contain repeated values, the
    duplicate candidate URLs they generate collapse to exactly one tested-and-
    requested entry per canonical URL:

      - 45.1 / 45.2: ``tested_urls`` and the marker Discovery_Requests both equal
        the set of DISTINCT canonical candidate URLs -- one entry and one request
        per canonical URL, never one per (possibly duplicated) generated value.

    Run unbounded (no Request_Budget) so the collapse -- not truncation -- is what
    bounds the request count.
    """
    async def _run():
        client = CountingMarkerFakeClient()
        config = FuzzingConfig(
            endpoints=EndpointFuzzingConfig(
                enabled=True,
                wordlist="unused.txt",
                methods=["GET"],
                follow_redirects=False,
                fuzz_keyword="FUZZ",
                fuzz_mode="clusterbomb",
                marker_wordlists=[list(values)],
            ),
            parameters=ParameterFuzzingConfig(enabled=False),
            headers=HeaderFuzzingConfig(enabled=False),
            recursive=False,
            max_depth=0,
            max_requests=None,       # unbounded: collapse is the only bound
            concurrency=50,
        )
        fuzzer = EndpointFuzzer(client, config)
        wordlist_path = _write_wordlist(["placeholder"])
        try:
            discovered = await fuzzer.discover_endpoints(
                _SINGLE_MARKER_TARGET, wordlist_path
            )
        finally:
            os.unlink(wordlist_path)
        return client, fuzzer, discovered

    client, fuzzer, discovered = asyncio.run(_run())

    # Independently derive the DISTINCT canonical candidate URLs from the raw
    # Marker_Wordlist (one marker => one value substituted per candidate).
    expected_canonical = {
        normalize_url(_SINGLE_MARKER_TARGET.replace("FUZZ", v)) for v in values
    }

    marker_calls = client.marker_calls()

    # Deduplication collapse: one tested_urls entry per canonical URL, and one
    # Discovery_Request per canonical URL -- regardless of how many duplicate
    # values were supplied.
    assert fuzzer.tested_urls == expected_canonical
    assert set(marker_calls) == expected_canonical
    assert len(marker_calls) == len(expected_canonical)
    assert Counter(normalize_url(u) for u in marker_calls) == Counter(expected_canonical)

    # Every distinct canonical candidate answered 200, so all are stored once.
    assert set(fuzzer.discovered_endpoints.keys()) == expected_canonical
    assert len(discovered) == len(expected_canonical)
