"""Example tests for confirmation-retest transport-failure exclusion.

# Feature: parameter-fuzzing, Task 8.3 (example test for confirmation transport failure)

Task 8.3 (from tasks.md) targets the transport-failure branch of
Hit_Confirmation: when confirmation is enabled and a re-test request fails to
complete due to a transport error or timeout, the ``ParameterFuzzer`` must treat
that re-test as a non-reproduction, exclude the candidate from the reported
findings, and record that the candidate was excluded due to a failed
confirmation request.

Requirement 5.5:
    WHILE Hit_Confirmation is enabled, IF a confirmation re-test request fails to
    complete due to a transport error or timeout, THEN THE Parameter_Fuzzer SHALL
    treat that re-test as a non-reproduction and exclude the candidate from the
    reported findings, and SHALL record an indication that the candidate was
    excluded due to a failed confirmation request.

The fuzzer runs end-to-end through the offline stub ``HTTPRequestEngine`` from
task 1.1 (:mod:`tests.support.http_stub`), so ``fuzz_parameters`` constructs a
real candidate ``Finding`` and then drives the confirmation retest. The stub's
responder is scripted so that:

* the baseline request (no query params) returns a static plain-text body;
* the initial fuzz request reflects the run-unique sentinel back into the body,
  producing a ``Response_Difference`` -> a candidate finding is created;
* the subsequent confirmation re-test raises a transport error/timeout, which
  the shared ``_test_*`` request helpers swallow and surface as ``None`` ->
  non-reproduction.

These are example-based tests (not Hypothesis): each pins a concrete transport
failure (a connection error and a timeout) and asserts the candidate is excluded
from the reported findings while being recorded in ``excluded_findings`` with
``confirmation_status == "excluded_failed_retest"``. All tests run fully offline
with no real network access.

_Requirements: 5.5_
"""

from __future__ import annotations

import asyncio

import httpx

from core.config import FuzzingConfig
from modules.fuzzing.orchestrator import Endpoint, ParameterFuzzer
from tests.support.http_stub import (
    HTTPRequestEngineStub,
    RecordedRequest,
    ScriptedResponse,
)


TARGET = "https://api.example.test/resource"
KNOWN = "search"


def _make_fuzzer(stub: HTTPRequestEngineStub, candidates) -> ParameterFuzzer:
    """Build a ParameterFuzzer over ``stub`` with confirmation enabled.

    Boundary testing is disabled so the only findings a run can produce are the
    ``PARAMETER_FOUND`` records, and ``confirm_hits`` is enabled so every
    candidate is retested via Hit_Confirmation. ``_load_wordlist`` is overridden
    to return exactly ``candidates`` so the run fuzzes a single controlled
    parameter regardless of any on-disk wordlist.
    """
    config = FuzzingConfig()
    config.parameters.boundary_testing = False
    # Enable Hit_Confirmation with a single retest so one failed re-test is
    # enough to trigger the transport-failure exclusion branch (R5.5).
    config.parameters.confirm_hits = 1

    fuzzer = ParameterFuzzer(stub, config)

    async def _fixed_wordlist(_path: str):
        return list(candidates)

    fuzzer._load_wordlist = _fixed_wordlist  # type: ignore[method-assign]
    return fuzzer


def _endpoint(method: str = "GET") -> Endpoint:
    """Construct a synthetic VALID (200) endpoint for parameter fuzzing."""
    return Endpoint(
        url=TARGET,
        method=method,
        status_code=200,
        response_size=0,
        response_time=0.0,
    )


def _param_findings(findings):
    """Return only the PARAMETER_FOUND findings from a run."""
    return [f for f in findings if f.category == "PARAMETER_FOUND"]


def _run_with_retest_error(error: Exception):
    """Run a query fuzz where the confirmation re-test raises ``error``.

    Returns ``(findings, fuzzer)``. The responder scripts a static plain-text
    baseline, reflects the sentinel on the first (initial) fuzz request so a
    candidate finding is created, and raises ``error`` on the second
    sentinel-carrying request (the confirmation re-test), simulating a transport
    error/timeout.
    """
    # Number of query (sentinel-carrying) requests seen so far. Request #1 is
    # the initial fuzz probe; request #2 is the Hit_Confirmation re-test.
    state = {"sentinel_calls": 0}

    def responder(recorded: RecordedRequest) -> ScriptedResponse:
        if not recorded.params:
            # Baseline request: static plain-text body, no sentinel.
            return ScriptedResponse(
                status_code=200,
                body="static baseline content",
                content_type="text/plain",
            )
        state["sentinel_calls"] += 1
        if state["sentinel_calls"] == 1:
            # Initial fuzz request: reflect the sentinel -> Response_Difference.
            value = next(iter(recorded.params.values()))
            return ScriptedResponse(
                status_code=200,
                body=f"you searched for: {value}",
                content_type="text/plain",
            )
        # Confirmation re-test: fail to complete due to a transport error.
        raise error

    stub = HTTPRequestEngineStub(responder=responder)
    fuzzer = _make_fuzzer(stub, [KNOWN])

    findings = asyncio.run(fuzzer.fuzz_parameters([_endpoint("GET")]))
    return findings, fuzzer


def _assert_excluded(findings, fuzzer):
    """Assert the candidate is excluded from findings and recorded (R5.5)."""
    # (1) The candidate is NOT among the reported findings.
    assert _param_findings(findings) == [], (
        "candidate whose confirmation re-test failed must be excluded from "
        f"reported findings, got {findings!r}"
    )

    # (2) The candidate is recorded in excluded_findings with the failed-retest
    #     confirmation status, so the exclusion is observable (R5.5).
    assert len(fuzzer.excluded_findings) == 1, (
        f"expected exactly one excluded finding, got {fuzzer.excluded_findings!r}"
    )
    excluded = fuzzer.excluded_findings[0]
    assert excluded.confirmation_status == "excluded_failed_retest"
    assert excluded.category == "PARAMETER_FOUND"
    assert KNOWN in excluded.evidence


def test_confirmation_connection_error_excludes_candidate():
    """A re-test connection error excludes the candidate and records it (R5.5)."""
    findings, fuzzer = _run_with_retest_error(
        httpx.ConnectError("simulated transport failure during confirmation")
    )
    _assert_excluded(findings, fuzzer)


def test_confirmation_timeout_excludes_candidate():
    """A re-test timeout excludes the candidate and records it (R5.5)."""
    findings, fuzzer = _run_with_retest_error(
        httpx.TimeoutException("simulated timeout during confirmation")
    )
    _assert_excluded(findings, fuzzer)


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
