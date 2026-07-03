"""
Integration tests for marker-candidate interoperability with the shared
discovery pipeline.

**Feature: owasp-complete-purple-teaming-cicd, Task 49.4**

These tests drive the real ``EndpointFuzzer.discover_endpoints`` marker branch
(``_fuzz_wordlist`` at depth 0) against deterministic, in-memory fake
``HTTPRequestEngine`` clients (no network) and assert that marker-generated
candidates flow through EXACTLY the same discovery controls as ordinary
wordlist candidates (Requirement 45):

- 45.4: every marker Discovery_Request passes through the rate-limited /
  User-Agent client. The real ``HTTPRequestEngine`` is driven against an
  in-memory fake ``httpx`` transport (mirroring tests/test_resilience_controls.py)
  with a spy ``RateLimiter`` and a custom ``UserAgentRotator``; the test asserts
  the rate limiter is acquired once per marker request and the configured
  User-Agent is applied to every outgoing marker request.
- 45.5: the Path_Scope / Storage_Status_Selection (matchers/filters/status) and
  the display Status_Code_Filter narrow the marker ``Discovery_Result`` records
  exactly as they narrow ordinary candidates (mirroring
  tests/test_discovery_scope.py).
- 45.6: ``--confirm-hits`` routes marker candidates through
  ``_confirm_candidate`` -- an interesting marker candidate is re-requested
  ``count`` times and recorded only when the confirmations are consistent
  (mirroring tests/test_hit_confirmation.py).
- 45.7: marker mode is a flat depth-0 sweep -- marker results are NOT recursed
  into unless a marker result independently satisfies Requirement 34 recursion
  eligibility (VALID/AUTH_REQUIRED, not Catch_All_Response, and admitted by any
  Recursion_Scope), in which case recursion descends into it subject to
  Recursion_Depth, Request_Budget, and the Recursion_Scope (mirroring
  tests/test_recursion_scope.py).

The fake clients answer the long, uuid-like catch-all detection probe paths with
404 (so Catch_All_Response detection stays off) and answer genuine candidate
paths per a deterministic status plan, recording every ``(method, url)`` so the
assertions can be made at the client.

**Validates: Requirements 45.4, 45.5, 45.6, 45.7**
"""

import asyncio
import os
import tempfile
from urllib.parse import urlparse

import pytest

from modules.fuzzing.orchestrator import EndpointFuzzer, Endpoint, EndpointStatus
from core.config import (
    FuzzingConfig,
    EndpointFuzzingConfig,
    ParameterFuzzingConfig,
    HeaderFuzzingConfig,
    HitConfirmationConfig,
    RateLimitConfig,
)
from utils.discovery_scope import (
    RecursionScope,
    parse_path_scope,
    parse_storage_status_selection,
)
from utils.discovery_session import (
    DiscoveryResult,
    apply_status_filter,
    parse_status_filter,
)
from utils.http_client import (
    HTTPRequestEngine,
    RateLimiter,
    RetryConfig,
    UserAgentRotator,
    Response,
)
from utils.url_normalize import normalize_url


BASE_HOST = "http://example.com"

# Catch-all detection probes target uuid4().hex-based paths (>= 32 hex chars);
# the genuine marker/candidate segments below are short, so a length threshold
# on the final path segment reliably distinguishes a probe path from a real
# candidate path.
_PROBE_SEGMENT_MIN_LEN = 20


def _last_segment(url: str) -> str:
    path = urlparse(url).path
    segments = [s for s in path.split("/") if s]
    return segments[-1] if segments else ""


def _is_probe_url(url: str) -> bool:
    """True when ``url`` is a catch-all detection probe (long uuid-like segment)."""
    return len(_last_segment(url)) >= _PROBE_SEGMENT_MIN_LEN


def _path_of(url: str) -> str:
    return urlparse(url).path


def _write_wordlist(words):
    """Write a non-empty wordlist file; return its path (caller unlinks)."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    f.write("\n".join(words) + "\n")
    f.close()
    return f.name


# ===========================================================================
# Shared in-memory fake HTTPRequestEngine (request(method, url) interface)
# ===========================================================================

class MarkerFakeClient:
    """In-memory fake HTTPRequestEngine for marker-pipeline integration tests.

    Records every ``(method, url)`` call in order and tracks live/peak in-flight
    concurrency. Long, uuid-like catch-all probe paths always answer 404 so
    Catch_All_Response detection stays off. Genuine candidate paths are answered
    by:

      * ``response_plan(method, url, attempt)`` -> (status_code, content_bytes)
        when supplied (``attempt`` is the zero-based count of prior requests to
        that URL, so a test can differ the first response from confirmation
        re-requests), OR
      * the ``path_status`` mapping keyed by the full URL path, falling back to
        ``default_status`` for any path not present.
    """

    def __init__(self, path_status=None, default_status=200, response_plan=None):
        self.path_status = path_status or {}
        self.default_status = default_status
        self.response_plan = response_plan
        self.calls = []            # list of (method, url) in call order
        self._url_counts = {}      # per-url request count (attempt index source)
        self.in_flight = 0
        self.peak_in_flight = 0

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def genuine_calls(self):
        """Return the (method, url) calls that are NOT catch-all probes."""
        return [(m, u) for m, u in self.calls if not _is_probe_url(u)]

    def genuine_urls(self):
        return [u for _, u in self.genuine_calls()]

    def requests_for(self, url):
        return [c for c in self.calls if c[1] == url]

    async def request(self, method: str, url: str, **kwargs) -> Response:
        self.in_flight += 1
        self.peak_in_flight = max(self.peak_in_flight, self.in_flight)
        self.calls.append((method, url))
        attempt = self._url_counts.get(url, 0)
        self._url_counts[url] = attempt + 1
        try:
            await asyncio.sleep(0)  # let concurrent siblings overlap
            if _is_probe_url(url):
                status, content = 404, b""
            elif self.response_plan is not None:
                status, content = self.response_plan(method, url, attempt)
            else:
                status = self.path_status.get(_path_of(url), self.default_status)
                content = b'{"ok": true}'
            return Response(
                status_code=status,
                headers={"Content-Type": "application/json"},
                content=content,
                text=content.decode("utf-8", "replace"),
                url=url,
                elapsed=0.01,
                request_method=method,
            )
        finally:
            self.in_flight -= 1


def _make_marker_config(
    marker_wordlists,
    *,
    fuzz_mode="clusterbomb",
    methods=("GET",),
    recursive=False,
    max_depth=0,
    max_requests=None,
    concurrency=50,
    path_scope=None,
    storage_status=None,
    recursion_scope=None,
    hit_confirmation=None,
) -> FuzzingConfig:
    """Build a marker-mode FuzzingConfig wired with the given controls."""
    return FuzzingConfig(
        endpoints=EndpointFuzzingConfig(
            enabled=True,
            wordlist="unused.txt",
            methods=list(methods),
            follow_redirects=False,
            extensions=[],
            fuzz_keyword="FUZZ",
            fuzz_mode=fuzz_mode,
            marker_wordlists=[list(wl) for wl in marker_wordlists],
        ),
        parameters=ParameterFuzzingConfig(enabled=False),
        headers=HeaderFuzzingConfig(enabled=False),
        recursive=recursive,
        max_depth=max_depth,
        max_requests=max_requests,
        concurrency=concurrency,
        path_scope=path_scope,
        storage_status=storage_status,
        recursion_scope=recursion_scope,
        hit_confirmation=hit_confirmation or HitConfirmationConfig(),
    )


async def _run_marker_discovery(client, config, target, recursion_words=("placeholder",)):
    """Drive discover_endpoints on ``target``; return (client, fuzzer, discovered).

    ``recursion_words`` seeds the on-disk wordlist. In marker mode the depth-0
    candidates come from the Fuzz_Markers, not the wordlist, but the wordlist is
    what a recursive (depth > 0) pass appends under an eligible marker result --
    so tests that exercise recursion supply meaningful sub-path words here.
    """
    fuzzer = EndpointFuzzer(client, config)
    wordlist_path = _write_wordlist(list(recursion_words))
    try:
        discovered = await fuzzer.discover_endpoints(target, wordlist_path)
    finally:
        os.unlink(wordlist_path)
    return client, fuzzer, discovered


# ===========================================================================
# 45.4: every marker request passes through the rate-limited / User-Agent client
# ===========================================================================

class _FakeHttpxResponse:
    """Minimal stand-in for an ``httpx.Response`` consumed by HTTPRequestEngine."""

    def __init__(self, status_code, url, content=b'{"ok": true}'):
        self.status_code = status_code
        self.url = url
        self.headers = {}
        self.content = content
        self.text = content.decode() if isinstance(content, (bytes, bytearray)) else str(content)


class _RecordingHttpxClient:
    """Fake httpx transport recording the headers of every request it receives.

    Catch-all probe paths answer 404; genuine candidate paths answer 200. Every
    call captures ``(method, url, headers)`` so the test can assert the
    User-Agent header the engine applied to each outgoing marker request.
    """

    def __init__(self):
        self.calls = []  # list of (method, url, headers)

    async def request(self, method, url, **kwargs):
        headers = dict(kwargs.get("headers") or {})
        self.calls.append((method, url, headers))
        status = 404 if _is_probe_url(url) else 200
        return _FakeHttpxResponse(status, url)


class _SpyRateLimiter(RateLimiter):
    """RateLimiter that counts how many times ``acquire`` is invoked."""

    def __init__(self, config):
        super().__init__(config)
        self.acquire_calls = 0

    async def acquire(self) -> None:
        self.acquire_calls += 1
        await super().acquire()


def _make_real_engine(fake_httpx, rate_limiter, user_agent_rotator) -> HTTPRequestEngine:
    """Build a real HTTPRequestEngine wrapping an injected fake httpx transport."""
    engine = HTTPRequestEngine(
        rate_limiter,
        RetryConfig(max_attempts=1, backoff_factor=2.0, retry_on_status=[429, 502, 503, 504]),
        user_agent_rotator=user_agent_rotator,
    )
    # Bypass real client creation; inject the fake transport.
    engine._client_initialized = True
    engine.client = fake_httpx
    return engine


def test_marker_requests_flow_through_rate_limited_user_agent_client():
    """Every marker Discovery_Request is rate-limited and carries the User-Agent.

    Driving the real ``HTTPRequestEngine`` (with a spy RateLimiter and a custom
    UserAgentRotator) against a fake httpx transport, every marker candidate
    request:
      - acquires a rate-limit token exactly once (the token bucket / Rate_Limit
        gates each Discovery_Request), and
      - is issued with the configured User-Agent header applied by the engine.

    **Validates: Requirements 45.4**
    """
    target = f"{BASE_HOST}/api/FUZZ"
    values = ["users", "orders", "admin"]
    custom_ua = "APILeak-Test-UA/9.9"

    fake_httpx = _RecordingHttpxClient()
    # A generous token bucket so acquire never sleeps -- we assert the acquire
    # COUNT (rate limiter consulted per request), not throttling timing.
    rate_limiter = _SpyRateLimiter(
        RateLimitConfig(requests_per_second=100000, burst_size=100000)
    )
    ua_rotator = UserAgentRotator(mode="custom", custom_user_agent=custom_ua)
    engine = _make_real_engine(fake_httpx, rate_limiter, ua_rotator)

    config = _make_marker_config([values])
    _, fuzzer, discovered = asyncio.run(
        _run_marker_discovery(engine, config, target)
    )

    expected_marker_urls = {
        normalize_url(target.replace("FUZZ", v)) for v in values
    }
    marker_calls = [
        (m, u, h) for (m, u, h) in fake_httpx.calls if not _is_probe_url(u)
    ]
    marker_urls = {u for _, u, _ in marker_calls}

    # Every marker candidate was issued through the shared client.
    assert marker_urls == expected_marker_urls
    # All three genuine candidates were recorded as Discovery_Results.
    assert {e.url for e in discovered} == expected_marker_urls

    # Rate limiting: the rate limiter was acquired once per request that flowed
    # through the engine (catch-all probes + marker candidates).
    assert rate_limiter.acquire_calls == len(fake_httpx.calls)
    assert rate_limiter.acquire_calls >= len(expected_marker_urls)

    # User-Agent: every outgoing marker request carried the configured UA.
    for _, url, headers in marker_calls:
        assert headers.get("User-Agent") == custom_ua, url


# ===========================================================================
# 45.5: matchers/filters/status-filter narrow marker Discovery_Result records
# ===========================================================================

_SCOPE_TARGET = f"{BASE_HOST}/api/FUZZ"
_SCOPE_VALUES = ["ok", "srv", "secret"]
_SCOPE_STATUS = {
    "/api/ok": 200,      # kept: 2xx, not path-excluded
    "/api/srv": 500,     # dropped by Storage_Status_Selection (include 2xx)
    "/api/secret": 200,  # dropped by Path_Scope (exclude "secret"), despite 2xx
}


def test_storage_status_selection_narrows_marker_records():
    """A marker record excluded by Storage_Status_Selection is never stored.

    With ``--include-status 2xx`` the 500 marker candidate ("/api/srv") is dropped
    at storage time -- absent from ``discovered_endpoints`` -- while the 2xx
    marker candidates are stored. The 5xx request WAS still issued (proving the
    marker candidate flowed through the pipeline and was filtered at storage, not
    avoided at request time).

    **Validates: Requirements 45.5**
    """
    storage_status = parse_storage_status_selection("2xx", None)
    client = MarkerFakeClient(path_status=_SCOPE_STATUS)
    config = _make_marker_config([_SCOPE_VALUES], storage_status=storage_status)
    _, fuzzer, discovered = asyncio.run(
        _run_marker_discovery(client, config, _SCOPE_TARGET)
    )

    ok_url = normalize_url(f"{BASE_HOST}/api/ok")
    srv_url = normalize_url(f"{BASE_HOST}/api/srv")
    stored = set(fuzzer.discovered_endpoints.keys())

    assert ok_url in stored
    assert srv_url not in stored
    assert all(e.status_code != 500 for e in discovered)
    # The 5xx marker candidate was requested (filtered at storage, not skipped).
    assert ("GET", srv_url) in client.calls


def test_path_scope_narrows_marker_records():
    """A marker candidate excluded by Path_Scope is never requested nor stored.

    With ``--exclude-path secret`` the "/api/secret" marker candidate (which would
    answer 200) is dropped before dispatch: no request is issued for it and it
    never enters ``discovered_endpoints``.

    **Validates: Requirements 45.5**
    """
    path_scope = parse_path_scope([], ["secret"])
    client = MarkerFakeClient(path_status=_SCOPE_STATUS)
    config = _make_marker_config([_SCOPE_VALUES], path_scope=path_scope)
    _, fuzzer, discovered = asyncio.run(
        _run_marker_discovery(client, config, _SCOPE_TARGET)
    )

    ok_url = normalize_url(f"{BASE_HOST}/api/ok")
    secret_url = normalize_url(f"{BASE_HOST}/api/secret")
    stored = set(fuzzer.discovered_endpoints.keys())

    assert ok_url in stored
    assert secret_url not in stored
    # Excluded by Path_Scope => no Discovery_Request was ever issued for it.
    assert not any(u == secret_url for _, u in client.calls)


def test_display_status_filter_narrows_marker_records():
    """The display Status_Code_Filter narrows the stored marker records.

    All marker candidates are stored (no storage scope), then the display-only
    Status_Code_Filter (Requirement 13, ``apply_status_filter``) narrows the
    projected records to a chosen Status_Code_Class -- exactly as it narrows
    ordinary candidates.

    **Validates: Requirements 45.5**
    """
    client = MarkerFakeClient(path_status=_SCOPE_STATUS)
    config = _make_marker_config([_SCOPE_VALUES])
    _, fuzzer, _ = asyncio.run(
        _run_marker_discovery(client, config, _SCOPE_TARGET)
    )

    records = [
        DiscoveryResult.from_endpoint(e)
        for e in fuzzer.discovered_endpoints.values()
    ]
    # All three marker candidates were stored (no storage scope).
    stored_paths = {_path_of(r.url) for r in records}
    assert stored_paths == {"/api/ok", "/api/srv", "/api/secret"}

    # A 2xx display filter narrows to just the 2xx marker records.
    only_2xx = apply_status_filter(records, parse_status_filter("2xx"))
    assert {_path_of(r.url) for r in only_2xx} == {"/api/ok", "/api/secret"}
    assert all(r.status_code // 100 == 2 for r in only_2xx)

    # A 5xx display filter narrows to just the 5xx marker record.
    only_5xx = apply_status_filter(records, parse_status_filter("5xx"))
    assert {_path_of(r.url) for r in only_5xx} == {"/api/srv"}


# ===========================================================================
# 45.6: --confirm-hits routes marker candidates through _confirm_candidate
# ===========================================================================

def test_confirm_hits_routes_marker_candidates_through_confirm_candidate():
    """An interesting marker candidate is re-requested via ``_confirm_candidate``.

    With Hit_Confirmation enabled (count=2) and consistent responses, each marker
    candidate is re-requested ``count`` additional times through
    ``_confirm_candidate`` (first request + 2 confirmations = 3 requests) and,
    because the responses are consistent, recorded as a Discovery_Result.

    **Validates: Requirements 45.6**
    """
    target = f"{BASE_HOST}/api/FUZZ"
    values = ["alpha", "beta"]
    count = 2

    client = MarkerFakeClient(default_status=200)
    config = _make_marker_config(
        [values],
        hit_confirmation=HitConfirmationConfig(enabled=True, count=count),
    )
    fuzzer = EndpointFuzzer(client, config)

    # Spy on _confirm_candidate to prove marker candidates are routed through it.
    confirmed_urls = []
    original_confirm = fuzzer._confirm_candidate

    async def _spy_confirm(method, url, first_response):
        confirmed_urls.append(url)
        return await original_confirm(method, url, first_response)

    fuzzer._confirm_candidate = _spy_confirm

    wordlist_path = _write_wordlist(["placeholder"])
    try:
        discovered = asyncio.run(fuzzer.discover_endpoints(target, wordlist_path))
    finally:
        os.unlink(wordlist_path)

    expected_urls = {normalize_url(target.replace("FUZZ", v)) for v in values}

    # Every marker candidate was routed through _confirm_candidate exactly once.
    assert set(confirmed_urls) == expected_urls
    # First request + `count` confirmation re-requests per marker candidate.
    for url in expected_urls:
        assert len(client.requests_for(url)) == count + 1, url
    # Consistent confirmations => every marker candidate recorded.
    assert {e.url for e in discovered} == expected_urls


def test_confirm_hits_drops_inconsistent_marker_candidate():
    """An inconsistent marker candidate is NOT recorded under Hit_Confirmation.

    When the confirmation responses disagree with the first response (different
    Status_Code_Class), the marker candidate is dropped and never stored -- while
    the confirmation re-requests were still issued through the shared client.

    **Validates: Requirements 45.6**
    """
    target = f"{BASE_HOST}/api/FUZZ"
    values = ["flaky"]
    count = 2
    flaky_url = normalize_url(f"{BASE_HOST}/api/flaky")

    def _plan(method, url, attempt):
        # First response 200, confirmations 500 (different Status_Code_Class).
        return (200, b'{"ok": true}') if attempt == 0 else (500, b'{"ok": true}')

    client = MarkerFakeClient(response_plan=_plan)
    config = _make_marker_config(
        [values],
        hit_confirmation=HitConfirmationConfig(enabled=True, count=count),
    )
    _, fuzzer, discovered = asyncio.run(
        _run_marker_discovery(client, config, target)
    )

    # Confirmation re-requests were issued (first + count)...
    assert len(client.requests_for(flaky_url)) == count + 1
    # ...but the inconsistent set means the marker candidate is not recorded.
    assert flaky_url not in fuzzer.discovered_endpoints
    assert all(e.url != flaky_url for e in discovered)


# ===========================================================================
# 45.7: flat depth-0 sweep, except a marker result eligible per Requirement 34
# ===========================================================================

_REC_TARGET = f"{BASE_HOST}/svc/FUZZ"
_REC_VALUES = ["live", "dead"]
# "/svc/live" is VALID (2xx) and recursion-eligible; "/svc/dead" is a 404 that
# is never stored and therefore never recursed into. Sub-paths appended during
# recursion default to 404 (not eligible) so recursion terminates at depth 1.
_REC_STATUS = {"/svc/live": 200, "/svc/dead": 404}
_REC_SUBWORDS = ["sub1", "sub2"]


def test_marker_mode_is_flat_when_recursion_disabled():
    """With recursion off, marker mode is a flat depth-0 sweep (no descent).

    Only the two marker candidates are requested; no sub-path is appended under
    the VALID marker result.

    **Validates: Requirements 45.7**
    """
    client = MarkerFakeClient(path_status=_REC_STATUS, default_status=404)
    config = _make_marker_config(
        [_REC_VALUES], recursive=False, max_depth=0
    )
    _, fuzzer, discovered = asyncio.run(
        _run_marker_discovery(client, config, _REC_TARGET, recursion_words=_REC_SUBWORDS)
    )

    genuine_paths = {_path_of(u) for u in client.genuine_urls()}
    # Exactly the two flat marker candidates -- no recursion descent.
    assert genuine_paths == {"/svc/live", "/svc/dead"}
    assert not any(p.startswith("/svc/live/") for p in genuine_paths)


def test_eligible_marker_result_is_recursed_into():
    """A marker result satisfying Requirement 34 eligibility IS recursed into.

    With recursion enabled (max_depth=1) and default eligibility, the VALID
    "/svc/live" marker result is recursed into -- its sub-paths are appended and
    requested -- while the 404 "/svc/dead" marker result (never stored) is not.
    The Fuzz_Keyword is NOT re-applied at depth > 0: recursion uses the legacy
    base-path append, so no recursive request carries the keyword.

    **Validates: Requirements 45.7**
    """
    client = MarkerFakeClient(path_status=_REC_STATUS, default_status=404)
    config = _make_marker_config(
        [_REC_VALUES], recursive=True, max_depth=1
    )
    _, fuzzer, discovered = asyncio.run(
        _run_marker_discovery(client, config, _REC_TARGET, recursion_words=_REC_SUBWORDS)
    )

    genuine_paths = {_path_of(u) for u in client.genuine_urls()}

    # The flat marker candidates were issued...
    assert "/svc/live" in genuine_paths
    assert "/svc/dead" in genuine_paths
    # ...and recursion descended into the VALID marker result only.
    assert "/svc/live/sub1" in genuine_paths
    assert "/svc/live/sub2" in genuine_paths
    # The 404 marker result was never stored, so it was never recursed into.
    assert not any(p.startswith("/svc/dead/") for p in genuine_paths)
    # Depth bound (max_depth=1): no depth-2 descent below the sub-paths.
    assert not any(p.startswith("/svc/live/sub1/") for p in genuine_paths)
    # The keyword is never re-applied at depth > 0.
    assert not any("fuzz" in u.lower() for u in client.genuine_urls())


def test_recursion_scope_narrows_marker_result_recursion():
    """Recursion into a marker result is subject to the Recursion_Scope.

    Even with recursion enabled, a Recursion_Scope that the VALID marker result
    does not satisfy (here: restrict recursion to 3xx results) suppresses descent
    into it -- no sub-paths are requested.

    **Validates: Requirements 45.7**
    """
    scope = RecursionScope(status_classes=frozenset({"3xx"}))
    client = MarkerFakeClient(path_status=_REC_STATUS, default_status=404)
    config = _make_marker_config(
        [_REC_VALUES], recursive=True, max_depth=1, recursion_scope=scope
    )
    _, fuzzer, discovered = asyncio.run(
        _run_marker_discovery(client, config, _REC_TARGET, recursion_words=_REC_SUBWORDS)
    )

    genuine_paths = {_path_of(u) for u in client.genuine_urls()}
    # The 2xx marker result is not admitted by a 3xx-only Recursion_Scope.
    assert genuine_paths == {"/svc/live", "/svc/dead"}
    assert not any(p.startswith("/svc/live/") for p in genuine_paths)


def test_marker_recursion_is_subject_to_request_budget():
    """Recursion into an eligible marker result stops at the Request_Budget.

    With recursion enabled and a small Request_Budget, the combined catch-all
    probes + marker candidates + recursive sub-path requests never exceed the
    budget, and ``budget_reached`` is set once the budget is hit.

    **Validates: Requirements 45.7**
    """
    # Many sub-words so the recursive pass would exceed the budget if unbounded.
    subwords = [f"s{i:02d}" for i in range(40)]
    budget = EndpointFuzzer.CATCH_ALL_PROBES + 4  # room for probes + a few requests
    client = MarkerFakeClient(path_status=_REC_STATUS, default_status=200)
    config = _make_marker_config(
        [_REC_VALUES], recursive=True, max_depth=2, max_requests=budget
    )
    _, fuzzer, discovered = asyncio.run(
        _run_marker_discovery(client, config, _REC_TARGET, recursion_words=subwords)
    )

    assert fuzzer.requests_issued <= budget
    assert client.call_count <= budget
    assert fuzzer.budget_reached is True
