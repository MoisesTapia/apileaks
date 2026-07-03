"""Property-based tests for parameter-fuzzing Hit_Confirmation semantics.

# Feature: parameter-fuzzing, Property 5: Hit confirmation inclusion/exclusion semantics

Property 5 (from design.md / tasks.md task 8.2):
    FOR ALL candidate findings and any confirmation count N >= 1, when
    Hit_Confirmation is enabled the fuzzer SHALL issue N additional retest
    requests and SHALL include the candidate **if and only if** all N retests
    reproduce the candidate's Response_Difference signals; when Hit_Confirmation
    is disabled the fuzzer SHALL report the candidate without issuing any
    retest.

The test exercises confirmation *end-to-end through the fuzzer*: it runs
``ParameterFuzzer.fuzz_parameters`` against the offline stub ``HTTPRequestEngine``
from task 1.1 (:mod:`tests.support.http_stub`) so ``_confirm_and_annotate`` /
``_confirm_candidate`` actually re-issue requests through the shared
``_test_query_parameter`` path (each retest incrementing ``requests_made``),
and the reported vs excluded findings are the real outcome of confirmation.

All tests run fully offline: the stub returns scripted responses with no real
network access.

Input model
    A single query candidate is fuzzed against a GET endpoint (boundary testing
    disabled), so every run issues exactly one paramless baseline request
    followed by one param-carrying *initial fuzz* request and then, when
    confirmation is enabled, the confirmation retests. The initial fuzz always
    produces a clean single-signal Response_Difference (``status_code``: the
    baseline responds 200, the fuzz responds 301 with a byte-identical body so
    no other signal fires). Each confirmation retest is independently scripted
    to either reproduce that difference (respond 301) or not (respond 200, i.e.
    identical to baseline, so no signal fires).

Detection signal
    Using only a status-code difference keeps the expected signal set a clean
    ``{"status_code"}`` -- confirmation reproduces the candidate iff a retest
    reproduces exactly that signal, which is what ``_confirm_candidate`` checks.

Oracles
    * Inclusion (R5.1, R5.2): when every one of the N retests reproduces the
      difference, the candidate is reported with ``confirmation_status ==
      "confirmed"`` and exactly N retest requests are issued.
    * Exclusion (R5.3): when at least one retest fails to reproduce, the
      candidate is excluded from the reported findings, recorded in
      ``excluded_findings`` with ``confirmation_status ==
      "excluded_failed_retest"``, and the number of retests issued is between 1
      and N (the implementation stops at the first non-reproducing retest, so
      the count never exceeds N).
    * Disabled (R5.6): with confirmation disabled, the candidate is reported
      with no retest request issued at all.

**Validates: Requirements 5.1, 5.2, 5.3, 5.6**
"""

from __future__ import annotations

import asyncio

from hypothesis import given, settings, strategies as st

from core.config import FuzzingConfig
from modules.fuzzing.orchestrator import Endpoint, ParameterFuzzer
from tests.support.http_stub import (
    HTTPRequestEngineStub,
    RecordedRequest,
    ScriptedResponse,
)


TARGET = "https://api.example.test/resource"

# Baseline vs difference status codes. 301 differs from the 200 baseline (a
# clean ``status_code`` signal) while staying < 500 so it is not treated as a
# transport/server failure; a retest that responds 200 is byte-identical to the
# baseline and therefore reproduces no signal.
_BASELINE_STATUS = 200
_DIFF_STATUS = 301
_BODY = "identical-body"


def _make_fuzzer(stub: HTTPRequestEngineStub, confirm_hits) -> ParameterFuzzer:
    """Build a ParameterFuzzer over ``stub`` fuzzing a single query candidate.

    Boundary testing is disabled so the only requests a GET run issues are the
    baseline, the initial fuzz, and the confirmation retests (keeping the retest
    count exact). ``_load_wordlist`` is overridden to a single candidate so the
    run fuzzes exactly one parameter. ``confirm_hits`` sets the Hit_Confirmation
    count (None/0 => disabled).
    """
    config = FuzzingConfig()
    config.parameters.boundary_testing = False
    config.parameters.confirm_hits = confirm_hits

    fuzzer = ParameterFuzzer(stub, config)

    async def _fixed_wordlist(_path: str):
        return ["candidate"]

    fuzzer._load_wordlist = _fixed_wordlist  # type: ignore[method-assign]
    return fuzzer


def _endpoint() -> Endpoint:
    """A synthetic VALID (200) GET endpoint -> query injection point."""
    return Endpoint(
        url=TARGET,
        method="GET",
        status_code=200,
        response_size=0,
        response_time=0.0,
    )


def _baseline_response() -> ScriptedResponse:
    return ScriptedResponse(status_code=_BASELINE_STATUS, body=_BODY)


def _difference_response() -> ScriptedResponse:
    # Same body as baseline, only the status differs -> single "status_code"
    # signal, no size/content-type/reflection noise.
    return ScriptedResponse(status_code=_DIFF_STATUS, body=_BODY)


def _param_findings(findings):
    return [f for f in findings if f.category == "PARAMETER_FOUND"]


def _retests_issued(stub: HTTPRequestEngineStub) -> int:
    """Number of confirmation retests = param-carrying requests minus the initial fuzz."""
    param_requests = [r for r in stub.requests if r.params]
    return len(param_requests) - 1


# ---------------------------------------------------------------------------
# Inclusion: enabled + all N retests reproduce -> included, exactly N retests
# ---------------------------------------------------------------------------
@given(n=st.integers(min_value=1, max_value=5))
@settings(max_examples=100, deadline=None)
def test_all_retests_reproduce_includes_candidate_with_exactly_n_retests(n):
    """All N retests reproduce -> candidate included after exactly N retests.

    # Feature: parameter-fuzzing, Property 5: Hit confirmation inclusion/exclusion semantics
    **Validates: Requirements 5.1, 5.2**
    """
    def responder(recorded: RecordedRequest) -> ScriptedResponse:
        if not recorded.params:
            return _baseline_response()
        # Initial fuzz AND every confirmation retest reproduce the difference.
        return _difference_response()

    stub = HTTPRequestEngineStub(responder=responder)
    fuzzer = _make_fuzzer(stub, confirm_hits=n)

    findings = asyncio.run(fuzzer.fuzz_parameters([_endpoint()]))

    param_findings = _param_findings(findings)
    assert len(param_findings) == 1, (
        f"expected the candidate to be included, got {len(param_findings)} findings"
    )
    assert param_findings[0].confirmation_status == "confirmed"
    assert fuzzer.excluded_findings == []

    # Exactly N additional retest requests were issued (R5.1), on top of the
    # single baseline + single initial-fuzz request.
    assert _retests_issued(stub) == n
    assert fuzzer.requests_made == n + 2


# ---------------------------------------------------------------------------
# Exclusion: enabled + at least one retest fails -> excluded, retests bounded
# ---------------------------------------------------------------------------
@st.composite
def _exclusion_cases(draw):
    """(N, fail_index): N retests where the retest at ``fail_index`` fails."""
    n = draw(st.integers(min_value=1, max_value=5))
    fail_index = draw(st.integers(min_value=0, max_value=n - 1))
    return n, fail_index


@given(case=_exclusion_cases())
@settings(max_examples=100, deadline=None)
def test_any_retest_failing_excludes_candidate(case):
    """A single non-reproducing retest excludes the candidate (R5.3).

    The confirmation retest at ``fail_index`` responds identically to the
    baseline (no signal), so it fails to reproduce the difference. The candidate
    must be excluded regardless of which retest fails.

    # Feature: parameter-fuzzing, Property 5: Hit confirmation inclusion/exclusion semantics
    **Validates: Requirements 5.3**
    """
    n, fail_index = case

    def responder(recorded: RecordedRequest) -> ScriptedResponse:
        if not recorded.params:
            return _baseline_response()
        # param-carrying requests in order: #1 = initial fuzz, #2.. = retests.
        param_seen = sum(1 for r in stub.requests if r.params)  # includes current
        retest_number = param_seen - 1  # 0 for the initial fuzz, 1..N for retests
        if retest_number == 0:
            return _difference_response()  # initial fuzz always differs
        # Confirmation retest: reproduce unless this is the designated failure.
        if retest_number - 1 == fail_index:
            return _baseline_response()  # identical to baseline -> no signal
        return _difference_response()

    stub = HTTPRequestEngineStub(responder=responder)
    fuzzer = _make_fuzzer(stub, confirm_hits=n)

    findings = asyncio.run(fuzzer.fuzz_parameters([_endpoint()]))

    # Excluded from reported findings (R5.3) ...
    assert _param_findings(findings) == []
    # ... and observable as an excluded finding with the recorded status.
    assert len(fuzzer.excluded_findings) == 1
    assert fuzzer.excluded_findings[0].confirmation_status == "excluded_failed_retest"

    # At least one retest was issued and the count never exceeds N (the run
    # stops once a retest fails to reproduce).
    retests = _retests_issued(stub)
    assert 1 <= retests <= n


# ---------------------------------------------------------------------------
# Disabled: no retest issued, candidate reported (R5.6)
# ---------------------------------------------------------------------------
@given(confirm_hits=st.sampled_from([None, 0]))
@settings(max_examples=100, deadline=None)
def test_confirmation_disabled_reports_candidate_without_retest(confirm_hits):
    """Disabled confirmation reports the candidate and issues no retest (R5.6).

    # Feature: parameter-fuzzing, Property 5: Hit confirmation inclusion/exclusion semantics
    **Validates: Requirements 5.6**
    """
    def responder(recorded: RecordedRequest) -> ScriptedResponse:
        if not recorded.params:
            return _baseline_response()
        return _difference_response()

    stub = HTTPRequestEngineStub(responder=responder)
    fuzzer = _make_fuzzer(stub, confirm_hits=confirm_hits)

    findings = asyncio.run(fuzzer.fuzz_parameters([_endpoint()]))

    param_findings = _param_findings(findings)
    assert len(param_findings) == 1, "candidate should be reported with confirmation disabled"
    # No confirmation was applied.
    assert param_findings[0].confirmation_status is None
    assert fuzzer.excluded_findings == []

    # No retest request issued: only the baseline + the single initial fuzz.
    assert _retests_issued(stub) == 0
    assert fuzzer.requests_made == 2


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
