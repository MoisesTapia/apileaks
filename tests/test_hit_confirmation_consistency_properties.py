"""
Property-Based Tests for Hit-confirmation consistency

**Feature: owasp-complete-purple-teaming-cicd, Property 19: Hit-confirmation
consistency**

Property 19 (from design.md):
    FOR ALL candidate interesting results, WHILE ``Hit_Confirmation`` is enabled,
    any candidate recorded as a ``Discovery_Result`` produced consistent responses
    across all confirmation ``Discovery_Requests`` -- the same ``Status_Code_Class``
    and a comparable response body size for every confirmation request
    (``responses_consistent([first, *confirmations]) == True``). A candidate with
    inconsistent confirmation responses is never recorded.

These tests drive the real ``EndpointFuzzer.discover_endpoints`` against an
in-memory fake ``HTTPRequestEngine`` (no network), reusing the fake-client
conventions of ``tests/test_hit_confirmation.py``. Each genuine candidate path is
answered with a generated, attempt-indexed sequence of responses (a first
response plus ``count`` confirmation responses); status codes are drawn across
and within ``Status_Code_Class`` boundaries and body sizes are drawn so that both
consistent and inconsistent confirmation sets are exercised. The long, uuid-like
catch-all detection probe paths answer 404 so ``Catch_All_Response`` detection
stays off.

The fake records every response it actually returns per URL, so the test can
reconstruct the exact ``[first, *confirmations]`` sequence the fuzzer saw and
assert the recording decision matches ``responses_consistent`` over that
sequence: every recorded candidate is consistent, and every inconsistent
candidate is absent from ``discovered_endpoints``.

**Validates: Requirements 35.8, 35.3, 35.4**
"""

import asyncio
import os
import tempfile
from urllib.parse import urljoin, urlparse

from hypothesis import given, settings, strategies as st

from modules.fuzzing.orchestrator import EndpointFuzzer
from core.config import (
    FuzzingConfig,
    EndpointFuzzingConfig,
    ParameterFuzzingConfig,
    HeaderFuzzingConfig,
    HitConfirmationConfig,
)
from utils.http_client import Response


BASE_URL = "http://example.com"

# Catch-all detection probes target uuid4().hex-based paths (33 chars); the
# genuine candidate segments below ("w0", "w1", ...) are short, so a length
# threshold reliably distinguishes a catch-all probe path from a real candidate.
_PROBE_SEGMENT_MIN_LEN = 20

# Status codes used for the FIRST response of a candidate. Every value is an
# "interesting" result (anything other than a true 404 NOT_FOUND), so the
# Hit_Confirmation branch in _test_endpoint always fires and the candidate's
# recording decision is governed purely by confirmation consistency.
_INTERESTING_STATUS = [200, 201, 204, 301, 302, 401, 403, 405, 500, 503]

# Status codes used for confirmation responses. Includes 404 and spans every
# Status_Code_Class so confirmations can agree with or diverge from the first
# response's class, exercising both consistent and inconsistent sets.
_ANY_STATUS = [200, 201, 204, 301, 302, 401, 403, 404, 405, 500, 503]

# Body sizes spanning identical, within-5%-tolerance, and well-beyond-tolerance
# differences so both "comparable" and "incomparable" body-size sets occur.
_BODY_SIZES = [0, 1, 10, 50, 100, 105, 1000, 1050, 5000]


class RecordingConfirmationFakeClient:
    """
    In-memory fake HTTPRequestEngine that answers each genuine candidate path
    from a per-URL, attempt-indexed plan and records every response it returns.

    Long, uuid-like catch-all probe paths always answer 404 (empty body) so
    Catch_All_Response detection stays off. Every genuine candidate URL is
    answered from ``plan_by_url[url][attempt]`` where ``attempt`` is the
    zero-based count of prior requests to that URL -- letting the first request
    and each confirmation re-request return a distinct (status, body size). The
    actual returned responses are stored per URL so the test can reconstruct the
    exact sequence the fuzzer observed.
    """

    def __init__(self, plan_by_url):
        # plan_by_url: {url: [(status_code, body_size), ...]} for genuine paths.
        self.plan_by_url = plan_by_url
        self.calls = []                 # (method, url) in call order
        self._url_counts = {}           # per-url request count (attempt source)
        self._responses_by_url = {}     # url -> list of returned Response objects

    def responses_for(self, url):
        """Return the list of Response objects actually returned for ``url``."""
        return list(self._responses_by_url.get(url, []))

    async def request(self, method: str, url: str, **kwargs) -> Response:
        self.calls.append((method, url))
        attempt = self._url_counts.get(url, 0)
        self._url_counts[url] = attempt + 1

        # Yield so concurrently dispatched requests overlap.
        await asyncio.sleep(0)

        path = urlparse(url).path
        segments = [s for s in path.split("/") if s]
        last_segment = segments[-1] if segments else ""

        if len(last_segment) >= _PROBE_SEGMENT_MIN_LEN:
            # Catch-all detection probe: answer 404 with an empty body.
            status_code, size = 404, 0
        else:
            plan = self.plan_by_url[url]
            # Clamp defensively; the fuzzer never issues more than len(plan)
            # requests to an interesting candidate (first + count confirmations).
            status_code, size = plan[min(attempt, len(plan) - 1)]

        content = b"x" * size
        response = Response(
            status_code=status_code,
            headers={"Content-Type": "application/json"},
            content=content,
            text=content.decode("utf-8", "replace"),
            url=url,
            elapsed=0.01,
            request_method=method,
        )
        self._responses_by_url.setdefault(url, []).append(response)
        return response


def _make_config(count: int) -> FuzzingConfig:
    """Build a depth-0 FuzzingConfig with Hit_Confirmation enabled.

    Unbounded budget and a large Concurrency_Limit so nothing is trimmed and
    every candidate receives its full first + ``count`` confirmation requests.
    """
    return FuzzingConfig(
        endpoints=EndpointFuzzingConfig(
            enabled=True,
            wordlist="unused.txt",
            methods=["GET"],          # single method => one chain per candidate
            follow_redirects=False,   # 3xx must not spawn extra redirect requests
        ),
        parameters=ParameterFuzzingConfig(enabled=False),
        headers=HeaderFuzzingConfig(enabled=False),
        recursive=False,             # depth-0 candidate space only
        max_depth=0,
        max_requests=None,           # unbounded: no budget trimming
        concurrency=50,
        hit_confirmation=HitConfirmationConfig(enabled=True, count=count),
    )


def _write_wordlist(words):
    """Write words to a temp wordlist file and return its path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    f.write("\n".join(words) + "\n")
    f.close()
    return f.name


async def _run_discovery(words, plan_by_url, count):
    """Run a depth-0 discovery pass; return (fake_client, fuzzer, discovered)."""
    fake_client = RecordingConfirmationFakeClient(plan_by_url)
    fuzzer = EndpointFuzzer(fake_client, _make_config(count))
    wordlist_path = _write_wordlist(words)
    try:
        discovered = await fuzzer.discover_endpoints(BASE_URL, wordlist_path)
    finally:
        os.unlink(wordlist_path)
    return fake_client, fuzzer, discovered


@st.composite
def _confirmation_scenarios(draw):
    """Generate (count, words, plan_by_url) for a Hit_Confirmation run.

    ``count`` confirmation requests apply to every candidate (a single value, as
    the config carries one count). Each candidate's plan is a sequence of
    ``count + 1`` (status_code, body_size) pairs: the first drawn from the
    interesting (non-404) statuses so confirmation always fires, the rest drawn
    across every Status_Code_Class (including 404). Body sizes are drawn to span
    identical, within-tolerance, and beyond-tolerance differences, so both
    consistent and inconsistent confirmation sets are produced.
    """
    count = draw(st.integers(min_value=1, max_value=4))
    num_candidates = draw(st.integers(min_value=1, max_value=4))

    words = [f"w{i}" for i in range(num_candidates)]
    plan_by_url = {}
    for word in words:
        first_status = draw(st.sampled_from(_INTERESTING_STATUS))
        rest_status = draw(
            st.lists(st.sampled_from(_ANY_STATUS), min_size=count, max_size=count)
        )
        sizes = draw(
            st.lists(
                st.sampled_from(_BODY_SIZES), min_size=count + 1, max_size=count + 1
            )
        )
        statuses = [first_status, *rest_status]
        plan = list(zip(statuses, sizes))
        url = urljoin(BASE_URL + "/", word)
        plan_by_url[url] = plan

    return count, words, plan_by_url


@given(scenario=_confirmation_scenarios())
@settings(max_examples=200, deadline=None)
def test_recorded_candidates_have_consistent_confirmations(scenario):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 19: Hit-confirmation
    consistency**
    **Validates: Requirements 35.8, 35.3, 35.4**

    For any candidate interesting result, while Hit_Confirmation is enabled:

      - 35.8 / 35.3: every candidate recorded as a Discovery_Result produced a
        consistent confirmation set -- ``responses_consistent([first,
        *confirmations]) == True`` over the exact sequence the fuzzer observed.
      - 35.4: every candidate whose confirmation set is inconsistent is NOT
        recorded (absent from ``discovered_endpoints``).

    Because the first response is always interesting (never a true 404), the
    only reason to drop a candidate is confirmation inconsistency, so the
    recording decision equals ``responses_consistent`` over the observed
    sequence in both directions.
    """
    count, words, plan_by_url = scenario

    fake_client, fuzzer, discovered = asyncio.run(
        _run_discovery(words, plan_by_url, count)
    )

    discovered_urls = {e.url for e in discovered}

    for word in words:
        url = urljoin(BASE_URL + "/", word)

        # The fuzzer issued exactly first + count confirmations for every
        # interesting candidate, so the recorded sequence has count + 1 entries.
        observed = fake_client.responses_for(url)
        assert len(observed) == count + 1, (
            f"{url}: expected {count + 1} requests (first + {count} "
            f"confirmations), saw {len(observed)}"
        )

        consistent = EndpointFuzzer.responses_consistent(observed)
        recorded = url in fuzzer.discovered_endpoints

        # 35.8 / 35.3: a recorded candidate must have a consistent set.
        if recorded:
            assert consistent, (
                f"{url} was recorded but its confirmation set is inconsistent: "
                f"{[(r.status_code, len(r.content)) for r in observed]}"
            )

        # 35.4: an inconsistent candidate is never recorded.
        if not consistent:
            assert not recorded, (
                f"{url} has an inconsistent confirmation set but was recorded: "
                f"{[(r.status_code, len(r.content)) for r in observed]}"
            )

        # Storage state and returned list agree (no half-recorded candidate).
        assert recorded == (url in discovered_urls)
        # With an always-interesting first response the recording decision is
        # exactly the consistency decision (no other drop reason applies).
        assert recorded == consistent
