"""Property-based tests for the parameter-fuzzing Request_Budget bound.

# Feature: parameter-fuzzing, Property 6: Request budget bounds total requests

Property 6 (from design.md / tasks.md task 9.2):
    FOR ALL configured request budgets B >= 1 and any wordlist, the total number
    of HTTP requests the run issues (baseline requests, parameter fuzzing
    requests, boundary requests, and confirmation retests all counted) SHALL
    never exceed B; when the run stops because the budget is reached it SHALL
    record the budget stop reason and retain all findings gathered before the
    stop.

The tests drive the real ``ParameterFuzzer.fuzz_parameters`` against the offline
stub ``HTTPRequestEngine`` from task 1.1 (:mod:`tests.support.http_stub`) so the
budget guard (``_budget_exhausted``) is exercised on the genuine baseline / fuzz
/ boundary / confirmation request paths. Every request flows through the stub,
so the stub's recorded call count and the fuzzer's internal ``requests_made``
counter are cross-checked against the budget.

All tests run fully offline: the stub returns scripted responses with no real
network access.

Input model
    A single GET endpoint is fuzzed (so only the query injection point runs) with
    a generated wordlist. The baseline responds 200 and every parameter-carrying
    request responds 301 with a byte-identical body -- a clean single
    ``status_code`` Response_Difference so every tested candidate becomes a
    finding. Boundary testing and Hit_Confirmation are toggled by Hypothesis to
    exercise every request-issuing path against the budget.

**Validates: Requirements 5.4, 11.1, 11.2, 11.3**
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

# Baseline vs difference status codes: 301 differs from the 200 baseline (a
# clean ``status_code`` signal) while staying < 500 so it is not treated as a
# transport/server failure. Both share a byte-identical body so no size /
# content-type / reflection signal fires.
_BASELINE_STATUS = 200
_DIFF_STATUS = 301
_BODY = "identical-body"


def _endpoint() -> Endpoint:
    """A synthetic VALID (200) GET endpoint -> query injection point only."""
    return Endpoint(
        url=TARGET,
        method="GET",
        status_code=200,
        response_size=0,
        response_time=0.0,
    )


def _responder(stub: HTTPRequestEngineStub):
    """Baseline (no params) responds 200; every param-carrying request differs."""
    def responder(recorded: RecordedRequest) -> ScriptedResponse:
        if not recorded.params:
            return ScriptedResponse(status_code=_BASELINE_STATUS, body=_BODY)
        return ScriptedResponse(status_code=_DIFF_STATUS, body=_BODY)

    return responder


def _make_fuzzer(stub: HTTPRequestEngineStub, wordlist, *, max_requests,
                 boundary_testing, confirm_hits) -> ParameterFuzzer:
    """Build a ParameterFuzzer over ``stub`` fuzzing the given query wordlist."""
    config = FuzzingConfig()
    config.parameters.boundary_testing = boundary_testing
    config.parameters.confirm_hits = confirm_hits
    config.parameters.max_requests = max_requests

    fuzzer = ParameterFuzzer(stub, config)

    async def _fixed_wordlist(_path: str):
        return list(wordlist)

    fuzzer._load_wordlist = _fixed_wordlist  # type: ignore[method-assign]
    return fuzzer


def _param_findings(findings):
    return [f for f in findings if f.category == "PARAMETER_FOUND"]


# Distinct candidate parameter names so the wordlist size is exactly len(wordlist).
_wordlists = st.lists(
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=8),
    min_size=1,
    max_size=20,
    unique=True,
)


# ---------------------------------------------------------------------------
# The budget is an upper bound on total issued requests, in every config.
# ---------------------------------------------------------------------------
@given(
    wordlist=_wordlists,
    budget=st.integers(min_value=1, max_value=60),
    boundary_testing=st.booleans(),
    confirm_hits=st.sampled_from([None, 1, 2, 3]),
)
@settings(max_examples=200, deadline=None)
def test_total_requests_never_exceed_budget(wordlist, budget, boundary_testing,
                                             confirm_hits):
    """Total issued requests never exceed the configured budget B.

    # Feature: parameter-fuzzing, Property 6: Request budget bounds total requests
    **Validates: Requirements 5.4, 11.1, 11.2**

    Regardless of wordlist size and of whether boundary testing and
    Hit_Confirmation are enabled -- i.e. counting baseline, fuzz, boundary, and
    confirmation retest requests together -- the run issues at most B requests,
    both as counted internally (``requests_made``) and as observed at the stub
    (``call_count``).
    """
    stub = HTTPRequestEngineStub()
    stub.set_responder(_responder(stub))
    fuzzer = _make_fuzzer(
        stub, wordlist,
        max_requests=budget,
        boundary_testing=boundary_testing,
        confirm_hits=confirm_hits,
    )

    findings = asyncio.run(fuzzer.fuzz_parameters([_endpoint()]))

    # 11.1 / 11.2 / 5.4: the combined request count never exceeds the budget.
    assert fuzzer.requests_made <= budget, (
        f"requests_made {fuzzer.requests_made} exceeds budget {budget}"
    )
    # Every issued request flowed through the stub, and the stub-observed count
    # is likewise bounded by the budget.
    assert stub.call_count == fuzzer.requests_made
    assert stub.call_count <= budget

    # Findings are only ever a subset of the fuzz requests actually issued.
    assert len(_param_findings(findings)) <= fuzzer.requests_made


# ---------------------------------------------------------------------------
# When the budget stops the run, the stop reason is recorded and partial
# findings gathered before the stop are retained.
# ---------------------------------------------------------------------------
@st.composite
def _truncating_cases(draw):
    """(wordlist, budget) where the budget forces truncation.

    With boundary testing and confirmation disabled a GET run issues exactly one
    baseline request plus one fuzz request per candidate, so an unbounded run
    would issue ``len(wordlist) + 1`` requests. Choosing ``budget <=
    len(wordlist)`` guarantees the budget is reached before the wordlist is
    exhausted.
    """
    wordlist = draw(_wordlists)
    budget = draw(st.integers(min_value=1, max_value=len(wordlist)))
    return wordlist, budget


@given(case=_truncating_cases())
@settings(max_examples=200, deadline=None)
def test_budget_stop_records_reason_and_retains_partial_findings(case):
    """Budget-triggered stop records a reason and keeps partial findings.

    # Feature: parameter-fuzzing, Property 6: Request budget bounds total requests
    **Validates: Requirements 11.2, 11.3**

    Boundary testing and confirmation are disabled so counting is exact: the run
    issues one baseline request then one finding-producing fuzz request per
    candidate until the budget B is reached. Because B <= len(wordlist) < the
    unbounded total (len(wordlist) + 1), the budget always truncates the run.
    """
    wordlist, budget = case

    stub = HTTPRequestEngineStub()
    stub.set_responder(_responder(stub))
    fuzzer = _make_fuzzer(
        stub, wordlist,
        max_requests=budget,
        boundary_testing=False,
        confirm_hits=None,
    )

    findings = asyncio.run(fuzzer.fuzz_parameters([_endpoint()]))

    # 11.1 / 11.2: the budget is an exact upper bound and, since the candidate
    # space exceeds it, the run consumes exactly B requests.
    assert fuzzer.requests_made == budget
    assert stub.call_count == budget

    # 11.3: the run stopped because of the budget, so the stop reason is recorded.
    assert fuzzer.budget_stop_reason is not None, (
        f"budget_stop_reason not recorded for budget {budget} against a "
        f"candidate space of {len(wordlist) + 1} requests"
    )

    # 11.3: findings gathered before the stop are retained. Every fuzz request
    # (requests_made minus the single baseline) produced a difference, so the
    # partial result set is exactly the fuzz requests issued before truncation.
    param_findings = _param_findings(findings)
    assert len(param_findings) == budget - 1


# ---------------------------------------------------------------------------
# An unbounded run (no budget) records no stop reason.
# ---------------------------------------------------------------------------
@given(wordlist=_wordlists)
@settings(max_examples=100, deadline=None)
def test_unbounded_run_records_no_stop_reason(wordlist):
    """With no budget the run is unbounded and records no stop reason.

    # Feature: parameter-fuzzing, Property 6: Request budget bounds total requests
    **Validates: Requirements 11.2, 11.3**
    """
    stub = HTTPRequestEngineStub()
    stub.set_responder(_responder(stub))
    fuzzer = _make_fuzzer(
        stub, wordlist,
        max_requests=None,
        boundary_testing=False,
        confirm_hits=None,
    )

    findings = asyncio.run(fuzzer.fuzz_parameters([_endpoint()]))

    # Unbounded: one baseline + one fuzz request per candidate, no stop reason.
    assert fuzzer.budget_stop_reason is None
    assert fuzzer.requests_made == len(wordlist) + 1
    assert len(_param_findings(findings)) == len(wordlist)


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
