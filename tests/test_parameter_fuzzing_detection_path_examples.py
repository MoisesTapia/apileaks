"""End-to-end example tests for the executable detection paths.

# Feature: parameter-fuzzing, Task 5.9 (example tests for executable detection paths)

Unlike the earlier unit tests for tasks 5.4/5.6 that drove the detector helpers
(``_detect_reflection`` / ``_detect_new_json_fields``) in isolation, task 5.9
exercises each detection path *end-to-end through the fuzzer*: it runs
``ParameterFuzzer.fuzz_parameters`` against the offline stub ``HTTPRequestEngine``
from task 1.1 (:mod:`tests.support.http_stub`) so the ``Finding`` objects are
actually constructed and their detection-signal fields
(``detection_signal``/``detection_signals``/``reflection_location``/
``new_json_fields``) are populated via task 5.8's ``_evaluate_difference`` and
``_primary_signal``.

Covered acceptance criteria:

* **R13.4** — the reflection path end-to-end reports a reflected parameter as a
  finding with ``detection_signal == "reflection"`` and a recorded location.
* **R13.5** — the new-JSON-field path end-to-end reports the parameter as a
  finding with ``detection_signal == "new_json_field"`` and the added key.
* **R13.2** — a stub target that accepts exactly one known parameter yields
  exactly one ``PARAMETER_FOUND`` finding carrying the recorded detection signal
  that triggered it.

All tests run fully offline: the stub returns scripted responses with no real
network access.

_Requirements: 13.2, 13.4, 13.5_
"""

from __future__ import annotations

import asyncio

from core.config import FuzzingConfig
from modules.fuzzing.orchestrator import Endpoint, ParameterFuzzer
from tests.support.http_stub import (
    HTTPRequestEngineStub,
    RecordedRequest,
    ScriptedResponse,
)


TARGET = "https://api.example.test/resource"


def _make_fuzzer(stub: HTTPRequestEngineStub, candidates) -> ParameterFuzzer:
    """Build a ParameterFuzzer over ``stub`` with a controlled candidate set.

    Boundary testing is disabled so the only findings a run can produce are the
    ``PARAMETER_FOUND`` records driven by ``_evaluate_difference`` (keeping the
    "exactly one finding" oracle for R13.2 precise), and ``_load_wordlist`` is
    overridden to return exactly ``candidates`` so the test controls which
    parameter names are fuzzed regardless of any on-disk wordlist.
    """
    config = FuzzingConfig()
    config.parameters.boundary_testing = False

    fuzzer = ParameterFuzzer(stub, config)

    async def _fixed_wordlist(_path: str):
        return list(candidates)

    # Both query and body fuzzing route through the same _load_wordlist.
    fuzzer._load_wordlist = _fixed_wordlist  # type: ignore[method-assign]
    return fuzzer


def _endpoint(method: str) -> Endpoint:
    """Construct a synthetic VALID (200) endpoint for parameter fuzzing.

    ``fuzz_parameters`` only fuzzes endpoints classified VALID or
    AUTH_REQUIRED; a 200 status yields VALID.
    """
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


# ---------------------------------------------------------------------------
# R13.4 — reflection path end-to-end
# ---------------------------------------------------------------------------
def test_reflection_path_reports_reflected_parameter():
    """A reflected sentinel is reported as a reflection finding (R13.4).

    The stub echoes whatever value the fuzzer injects back into the (plain-text)
    response body, so the run-unique sentinel appears verbatim in the test body
    and is absent from the static baseline body -> reflection at ``body``.
    """
    KNOWN = "search"

    def responder(recorded: RecordedRequest) -> ScriptedResponse:
        if not recorded.params:
            # Baseline request (no injected query parameter): static body with
            # no sentinel, plain text so JSON-field detection is skipped.
            return ScriptedResponse(
                status_code=200,
                body="static baseline content",
                content_type="text/plain",
            )
        # Query test: reflect the injected sentinel value back into the body.
        value = next(iter(recorded.params.values()))
        return ScriptedResponse(
            status_code=200,
            body=f"you searched for: {value}",
            content_type="text/plain",
        )

    stub = HTTPRequestEngineStub(responder=responder)
    fuzzer = _make_fuzzer(stub, [KNOWN])

    # GET endpoint -> query injection point.
    findings = asyncio.run(fuzzer.fuzz_parameters([_endpoint("GET")]))

    param_findings = _param_findings(findings)
    assert len(param_findings) == 1, (
        f"expected exactly one PARAMETER_FOUND finding, got {len(param_findings)}"
    )
    finding = param_findings[0]

    assert KNOWN in finding.evidence
    assert finding.detection_signal == "reflection"
    assert finding.reflection_location == "body"
    assert "reflection:body" in finding.detection_signals


# ---------------------------------------------------------------------------
# R13.5 — new-JSON-field path end-to-end
# ---------------------------------------------------------------------------
def test_new_json_field_path_reports_parameter():
    """A parameter that introduces a new top-level JSON field is reported (R13.5).

    The stub returns a baseline JSON body for the baseline request and for the
    form/XML injection points, but adds a new top-level key only for the JSON
    body injection, so exactly the JSON path produces a new-JSON-field finding.
    """
    KNOWN = "debug"
    ADDED_KEY = "injected_field"

    def responder(recorded: RecordedRequest) -> ScriptedResponse:
        content_type = (recorded.content_type or "").lower()
        if "application/json" in content_type and recorded.json:
            # JSON body injection -> response gains a new top-level key vs
            # baseline, and carries no sentinel so reflection does not fire.
            return ScriptedResponse(
                status_code=200,
                body={"ok": True, ADDED_KEY: "present"},
            )
        # Baseline request and the form/XML injections return the baseline body
        # byte-identically, so only the JSON path differs.
        return ScriptedResponse(status_code=200, body={"ok": True})

    stub = HTTPRequestEngineStub(responder=responder)
    fuzzer = _make_fuzzer(stub, [KNOWN])

    # POST endpoint -> body injection points (JSON, form, XML).
    findings = asyncio.run(fuzzer.fuzz_parameters([_endpoint("POST")]))

    param_findings = _param_findings(findings)
    assert len(param_findings) == 1, (
        f"expected exactly one PARAMETER_FOUND finding, got {len(param_findings)}"
    )
    finding = param_findings[0]

    assert KNOWN in finding.evidence
    assert finding.detection_signal == "new_json_field"
    assert finding.new_json_fields == [ADDED_KEY]
    assert "new_json_field" in finding.detection_signals


# ---------------------------------------------------------------------------
# R13.2 — accepted-parameter finding carries the recorded detection signal
# ---------------------------------------------------------------------------
def test_accepted_parameter_yields_exactly_one_finding_with_signal():
    """One accepted known parameter -> exactly one finding with its signal (R13.2).

    The stub accepts a single known query parameter by echoing its injected
    sentinel into the response body (a reflection), while the baseline request
    returns a static body. With boundary testing disabled and a single-candidate
    wordlist, the run produces exactly one PARAMETER_FOUND finding, and that
    finding records the detection signal that triggered it.
    """
    KNOWN = "callback"

    def responder(recorded: RecordedRequest) -> ScriptedResponse:
        if not recorded.params:
            return ScriptedResponse(
                status_code=200,
                body="baseline body",
                content_type="text/plain",
            )
        value = next(iter(recorded.params.values()))
        return ScriptedResponse(
            status_code=200,
            body=f"accepted: {value}",
            content_type="text/plain",
        )

    stub = HTTPRequestEngineStub(responder=responder)
    fuzzer = _make_fuzzer(stub, [KNOWN])

    findings = asyncio.run(fuzzer.fuzz_parameters([_endpoint("GET")]))

    param_findings = _param_findings(findings)
    assert len(param_findings) == 1, (
        f"expected exactly one PARAMETER_FOUND finding, got {len(param_findings)}"
    )
    finding = param_findings[0]

    # Exactly one candidate was tested.
    assert fuzzer.parameters_tested == 1

    # The finding is for the accepted parameter and carries the recorded signal
    # that triggered it (a non-empty detection_signal that also appears in the
    # full detection_signals list).
    assert KNOWN in finding.evidence
    assert finding.detection_signal is not None
    assert finding.detection_signal == "reflection"
    assert finding.detection_signals
    assert "reflection:body" in finding.detection_signals


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
