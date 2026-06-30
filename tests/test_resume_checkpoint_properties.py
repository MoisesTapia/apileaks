"""
Property-Based Tests for Discovery Resume (Checkpoint) — no-duplication and
no-recompute.

**Feature: owasp-complete-purple-teaming-cicd, Property 21: Resume no-duplication**
**Feature: owasp-complete-purple-teaming-cicd, Property 22: Resume no-recompute**

Property 21 (from design.md):
    FOR ALL interrupted-then-resumed runs, the union of the Discovery_Result
    records from the original partial run and the resumed run contains no two
    records sharing the same (url, method) pair, where url is compared in
    canonical (normalized) form.

    **Validates: Requirements 37.7, 37.4**

Property 22 (from design.md):
    FOR ALL interrupted-then-resumed runs, no candidate recorded as already
    tested in the Discovery_Checkpoint is requested again during the resumed run.
    Verified with a request-counting fake client: every (url, method) in the
    checkpoint's tested set issues zero Discovery_Requests after resume.

    **Validates: Requirements 37.8, 37.3**

These tests drive the real EndpointFuzzer (seed_from_checkpoint +
discover_endpoints / _write_checkpoint) against an in-memory, request-counting
fake HTTPRequestEngine (no network), mirroring the established property tests in
test_request_budget_bound_properties.py / test_recursion_depth_bound_properties.py
and the RecordingFakeClient pattern from test_discovery_checkpoint_resume.py.

The fake answers the long, uuid-like catch-all detection probes with a 404 so
Catch_All_Response detection stays off and genuine (short) wordlist candidates
are discovered with a 2xx; recursion is disabled so candidates are exactly the
base-url + word combinations under test.
"""

import asyncio
import os
import string
import tempfile
from urllib.parse import urljoin

from hypothesis import given, settings, strategies as st

from modules.fuzzing.orchestrator import EndpointFuzzer
from core.config import (
    FuzzingConfig,
    EndpointFuzzingConfig,
    ParameterFuzzingConfig,
    HeaderFuzzingConfig,
)
from utils.discovery_checkpoint import DiscoveryCheckpoint
from utils.discovery_session import DiscoveryResult
from utils.http_client import Response
from utils.url_normalize import normalize_url


BASE_URL = "http://example.com"

# Catch-all detection probes target uuid4().hex-based paths (>= 32 chars). The
# generated wordlist segments below are short, so a length threshold reliably
# distinguishes a catch-all probe path from a real candidate path.
_PROBE_SEGMENT_MIN_LEN = 20


class CountingFakeClient:
    """In-memory fake HTTPRequestEngine recording every request as (method, url).

    Genuine (short) wordlist paths answer with a 2xx so they are discovered;
    the long, random catch-all detection probe paths answer with 404 so
    Catch_All_Response detection stays off and does not perturb storage.
    """

    def __init__(self):
        self.calls = []  # list of (method, url) in call order

    @property
    def call_count(self) -> int:
        return len(self.calls)

    async def request(self, method: str, url: str, **kwargs) -> Response:
        self.calls.append((method, url))
        await asyncio.sleep(0)

        path = url.split("?", 1)[0]
        last_segment = [s for s in path.split("/") if s]
        tail = last_segment[-1] if last_segment else ""
        status_code = 404 if len(tail) >= _PROBE_SEGMENT_MIN_LEN else 200

        return Response(
            status_code=status_code,
            headers={"Content-Type": "application/json"},
            content=b'{"ok": true}',
            text='{"ok": true}',
            url=url,
            elapsed=0.01,
            request_method=method,
        )


def _make_config(method: str) -> FuzzingConfig:
    """Build a discovery-only, non-recursive, unbounded FuzzingConfig."""
    return FuzzingConfig(
        endpoints=EndpointFuzzingConfig(
            enabled=True,
            wordlist="unused.txt",
            methods=[method],
            follow_redirects=False,
        ),
        parameters=ParameterFuzzingConfig(enabled=False),
        headers=HeaderFuzzingConfig(enabled=False),
        recursive=False,        # candidates are exactly base_url + word
        max_depth=0,
        max_requests=None,      # unbounded: resume seeding is the only skip
        concurrency=50,
    )


def _write_wordlist(words):
    """Write words to a temp wordlist file and return its path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    f.write("\n".join(words) + "\n")
    f.close()
    return f.name


def _candidate_url(word: str) -> str:
    """The canonical URL a wordlist ``word`` resolves to under discovery.

    Mirrors EndpointFuzzer: discover_endpoints appends a trailing slash to the
    base URL, then ``_fuzz_wordlist`` normalizes ``urljoin(base_url, word)``.
    """
    return normalize_url(urljoin(BASE_URL + "/", word))


# Short, url-safe path segments, clearly distinct from the long random
# catch-all probe paths. Unique words => distinct canonical candidate URLs.
_word = st.text(alphabet=string.ascii_lowercase + string.digits, min_size=1, max_size=8)
_words = st.lists(_word, min_size=1, max_size=6, unique=True)
_methods = st.sampled_from(["GET", "POST", "PUT"])


@given(words=_words, method=_methods, data=st.data())
@settings(max_examples=150, deadline=None)
def test_resume_no_recompute(words, method, data):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 22: Resume
    no-recompute**
    **Validates: Requirements 37.8, 37.3**

    For any candidate set and any subset recorded as already tested in the
    Discovery_Checkpoint, after seeding the fuzzer from that checkpoint and
    running discovery over the full candidate set, NO Discovery_Request is issued
    for any (url, method) recorded as tested in the checkpoint — the
    request-counting fake confirms zero requests for every checkpointed
    candidate (37.3), so a resumed run never recomputes already-tested work
    (37.8).
    """
    # Pick the subset of candidates the checkpoint records as already tested.
    tested_words = data.draw(st.sets(st.sampled_from(words)))
    tested_urls = {_candidate_url(w) for w in tested_words}

    checkpoint = DiscoveryCheckpoint(
        target=BASE_URL + "/",
        timestamp="2025-01-01T00:00:00+00:00",
        tool_version="test",
        tested=[(url, method) for url in sorted(tested_urls)],
        results=[
            DiscoveryResult(url=url, method=method, status_code=200,
                            endpoint_status="valid")
            for url in sorted(tested_urls)
        ],
    )

    fake_client = CountingFakeClient()
    fuzzer = EndpointFuzzer(fake_client, _make_config(method))
    fuzzer.seed_from_checkpoint(checkpoint)

    wordlist_path = _write_wordlist(words)
    try:
        asyncio.run(fuzzer.discover_endpoints(BASE_URL, wordlist_path))
    finally:
        os.unlink(wordlist_path)

    # 37.3 / 37.8: every (url, method) recorded as tested issues zero
    # Discovery_Requests after resume. Catch-all probe paths use long uuid
    # segments and never collide with a checkpointed candidate URL.
    issued_urls = {url for _, url in fake_client.calls}
    assert tested_urls.isdisjoint(issued_urls), (
        "resumed run re-issued a Discovery_Request for a checkpointed candidate: "
        f"{tested_urls & issued_urls}"
    )
    # The non-checkpointed candidates are still discoverable, so resume continues
    # work rather than skipping everything.
    untested_urls = {_candidate_url(w) for w in words} - tested_urls
    assert untested_urls <= issued_urls


@given(words=_words, method=_methods, data=st.data())
@settings(max_examples=150, deadline=None)
def test_resume_no_duplication(words, method, data):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 21: Resume
    no-duplication**
    **Validates: Requirements 37.7, 37.4**

    Run a partial discovery over a subset of candidates with checkpointing on,
    persist the Discovery_Checkpoint, then run a fresh fuzzer seeded from that
    checkpoint over the FULL candidate set. The union of the partial-run results
    and the resumed-run discovered_endpoints contains no two records sharing the
    same canonical (url, method) pair (37.7), and the resumed run merges the
    newly discovered records with the checkpointed ones (37.4).
    """
    # The partial run covers a (possibly empty) subset; the resumed run covers
    # the full candidate set.
    partial_words = sorted(data.draw(st.sets(st.sampled_from(words))))

    # --- Phase 1: partial run that writes a checkpoint --------------------
    checkpoint_fd, checkpoint_path = tempfile.mkstemp(suffix=".json")
    os.close(checkpoint_fd)
    os.unlink(checkpoint_path)  # let the fuzzer create it via atomic write

    partial_client = CountingFakeClient()
    partial_fuzzer = EndpointFuzzer(
        partial_client, _make_config(method), checkpoint_path=checkpoint_path
    )
    partial_wordlist = _write_wordlist(partial_words or ["__none__placeholder__"])
    try:
        if partial_words:
            partial_discovered = asyncio.run(
                partial_fuzzer.discover_endpoints(BASE_URL, partial_wordlist)
            )
        else:
            # No partial candidates: still produce a (possibly empty) checkpoint
            # so resume has an artifact to load.
            partial_discovered = []
            partial_fuzzer._checkpoint_target = BASE_URL + "/"
            partial_fuzzer._write_checkpoint()
    finally:
        os.unlink(partial_wordlist)

    # --- Phase 2: fresh fuzzer resumed from the checkpoint ---------------
    checkpoint = DiscoveryCheckpoint.load(checkpoint_path)
    os.unlink(checkpoint_path)

    resumed_client = CountingFakeClient()
    resumed_fuzzer = EndpointFuzzer(resumed_client, _make_config(method))
    resumed_fuzzer.seed_from_checkpoint(checkpoint)

    full_wordlist = _write_wordlist(words)
    try:
        resumed_discovered = asyncio.run(
            resumed_fuzzer.discover_endpoints(BASE_URL, full_wordlist)
        )
    finally:
        os.unlink(full_wordlist)

    partial_pairs = {(e.url, e.method) for e in partial_discovered}
    resumed_pairs_list = [(e.url, e.method) for e in resumed_discovered]
    resumed_pairs = set(resumed_pairs_list)

    # 37.7: the resumed (merged) result set itself contains no duplicate
    # (url, method) pair — guaranteed by the normalized-url keying of
    # discovered_endpoints.
    assert len(resumed_pairs_list) == len(resumed_pairs), (
        "resumed discovered_endpoints contains duplicate (url, method) pairs"
    )

    # 37.4: the resumed run merged the newly discovered records WITH the
    # checkpointed (partial-run) records, so every partial record survives.
    assert partial_pairs <= resumed_pairs, (
        "resumed run dropped a checkpointed record instead of merging it: "
        f"{partial_pairs - resumed_pairs}"
    )

    # 37.7 (union form): the union of the partial-run and resumed-run results
    # contains no two records sharing the same canonical (url, method) pair.
    # Since partial ⊆ resumed, the union equals resumed_pairs; verify that each
    # canonical url maps to exactly one method, so no two distinct records share
    # a canonical (url, method).
    union = partial_pairs | resumed_pairs
    union_urls = [url for url, _ in union]
    assert len(union_urls) == len(set(union_urls)), (
        "union of partial and resumed results has a canonical url under "
        "conflicting methods (duplication)"
    )
