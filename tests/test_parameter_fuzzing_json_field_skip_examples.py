"""Example tests for the new-JSON-field detector's non-JSON skip path.

# Feature: parameter-fuzzing, Task 5.7 (example test for non-JSON skip path)

Task 5.7 (from tasks.md) targets the graceful-skip contract of
``ParameterFuzzer._detect_new_json_fields``:

    Feed non-JSON bodies on either side; assert no exception is raised (the
    detector returns ``None`` gracefully) and that remaining candidates
    continue processing.

Requirement 4.3:
    IF the test response or the Baseline_Response cannot be parsed as JSON,
    THEN THE Parameter_Fuzzer SHALL skip new-JSON-field detection for that
    candidate Parameter without raising an error and SHALL continue processing
    remaining candidate Parameters.

The fuzzer is constructed against the offline stub ``HTTPRequestEngine`` from
task 1.1 (:mod:`tests.support.http_stub`) so the tests run fully offline with no
real network access. ``_detect_new_json_fields`` issues no requests itself; the
stub simply keeps fuzzer construction identical to the rest of the suite, and
``ScriptedResponse.to_response`` builds the real ``Response`` objects fed to the
detector.

These are example-based tests (not Hypothesis): each case pins a concrete
non-JSON body shape (plain text, HTML, empty string) opposite a valid JSON body
and asserts the detector returns ``None`` without raising.

_Requirements: 4.3_
"""

from __future__ import annotations

from core.config import FuzzingConfig
from modules.fuzzing.orchestrator import ParameterFuzzer
from tests.support.http_stub import HTTPRequestEngineStub, ScriptedResponse


def _make_fuzzer() -> ParameterFuzzer:
    """Construct a ParameterFuzzer wired to the offline stub engine."""
    stub = HTTPRequestEngineStub()
    return ParameterFuzzer(stub, FuzzingConfig())


def _response(body, *, content_type=None):
    """Build a real ``Response`` carrying ``body`` verbatim.

    ``content_type=None`` keeps the stub from injecting a ``Content-Type``
    header; the detector only inspects ``Response.text`` so the header set is
    irrelevant here.
    """
    return ScriptedResponse(
        status_code=200,
        body=body,
        headers={},
        content_type=content_type,
    ).to_response(url="https://target.test/api", method="GET")


# Representative non-JSON body shapes the detector must skip gracefully.
_NON_JSON_BODIES = [
    "not json",                       # plain text
    "<html><body>hi</body></html>",   # HTML
    "",                               # empty string
    "key: value\nother: thing",       # YAML-ish / plain text
    "12,34,not,json",                 # CSV-ish
]

# A valid JSON object body used opposite the non-JSON bodies.
_VALID_JSON_BODY = '{"id": 1, "name": "widget"}'


def test_non_json_baseline_json_test_returns_none():
    """Non-JSON baseline + JSON test -> ``None``, no exception (R4.3)."""
    fuzzer = _make_fuzzer()
    for body in _NON_JSON_BODIES:
        baseline = _response(body)
        test = _response(_VALID_JSON_BODY)
        # Must not raise, must skip gracefully.
        assert fuzzer._detect_new_json_fields(baseline, test) is None, (
            f"expected None for non-JSON baseline body {body!r}"
        )


def test_json_baseline_non_json_test_returns_none():
    """JSON baseline + non-JSON test -> ``None``, no exception (R4.3)."""
    fuzzer = _make_fuzzer()
    for body in _NON_JSON_BODIES:
        baseline = _response(_VALID_JSON_BODY)
        test = _response(body)
        assert fuzzer._detect_new_json_fields(baseline, test) is None, (
            f"expected None for non-JSON test body {body!r}"
        )


def test_non_json_both_sides_returns_none():
    """Non-JSON on both sides -> ``None``, no exception (R4.3)."""
    fuzzer = _make_fuzzer()
    for baseline_body in _NON_JSON_BODIES:
        for test_body in _NON_JSON_BODIES:
            baseline = _response(baseline_body)
            test = _response(test_body)
            assert fuzzer._detect_new_json_fields(baseline, test) is None, (
                f"expected None for baseline={baseline_body!r} test={test_body!r}"
            )


def test_remaining_candidates_continue_after_non_json_skip():
    """A non-JSON pair skips gracefully without aborting the candidate loop (R4.3).

    Iterating a small list that mixes a non-JSON pair (skipped -> ``None``) with
    a valid JSON pair (detects the new key) demonstrates that the skip does not
    abort processing: the later valid pair is still evaluated and its new
    top-level key is reported.
    """
    fuzzer = _make_fuzzer()

    candidates = [
        # (label, baseline_body, test_body, expected result)
        ("non_json_pair", "not json at all", "still not json", None),
        (
            "valid_json_new_key",
            '{"id": 1}',
            '{"id": 1, "debug": true}',
            ["debug"],
        ),
        ("non_json_baseline", "<html/>", '{"a": 1}', None),
        (
            "valid_json_no_new_key",
            '{"id": 1, "name": "x"}',
            '{"id": 2, "name": "y"}',
            [],
        ),
    ]

    results = []
    for label, baseline_body, test_body, _expected in candidates:
        baseline = _response(baseline_body)
        test = _response(test_body)
        # No candidate should raise; the loop must reach every entry.
        results.append((label, fuzzer._detect_new_json_fields(baseline, test)))

    # Every candidate was processed (loop not aborted by the non-JSON skips).
    assert len(results) == len(candidates)

    result_by_label = dict(results)
    assert result_by_label["non_json_pair"] is None
    assert result_by_label["non_json_baseline"] is None
    # The valid JSON pair after a skipped non-JSON pair is still evaluated.
    assert result_by_label["valid_json_new_key"] == ["debug"]
    # A valid pair with no new top-level key returns [] (distinct from None).
    assert result_by_label["valid_json_no_new_key"] == []


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
