"""Property-based tests for the parameter-fuzzing new-JSON-field detector.

# Feature: parameter-fuzzing, Property 4: New-JSON-field detection correctness

Property 4 (from design.md / tasks.md task 5.6):
    FOR ALL baseline/test response pairs that are both parseable as JSON, the
    candidate SHALL be classified as a finding **if and only if** the parsed
    test JSON contains at least one top-level field key absent from the parsed
    baseline JSON, and the finding SHALL record ``new_json_fields`` equal to
    exactly those absent keys (sorted).

The test drives ``ParameterFuzzer._detect_new_json_fields`` directly. The fuzzer
is constructed against the offline stub ``HTTPRequestEngine`` from task 1.1
(:mod:`tests.support.http_stub`) so the test runs fully offline with no real
network access -- although ``_detect_new_json_fields`` itself issues no
requests, wiring the stub keeps the fuzzer construction identical to the rest of
the suite.

Scope note (task 5.6)
    At this stage the new-JSON-field signal is not yet wired into ``Finding``
    construction (that happens in task 5.8's ``_evaluate_difference``). Property
    4's substance at this stage is therefore the *iff* correctness of
    ``_detect_new_json_fields``: a non-empty list is returned **iff** the test
    JSON has >= 1 top-level key absent from the baseline JSON, and that list
    equals exactly those keys (sorted). The returned list is what populates a
    finding's ``new_json_fields`` field downstream.

Input model
    Each example is a pair of JSON objects (``dict``s) for the baseline and test
    responses, mirroring the real detection input where both bodies parse as
    JSON. Keys are short identifiers drawn from a shared alphabet so the
    generated pairs naturally exercise overlapping, disjoint, subset, and
    superset key relationships. Bodies are serialised to JSON and returned as
    real ``Response`` objects via the stub's ``ScriptedResponse``.

Oracle
    The detector's contract, computed independently of the implementation:

        expected := sorted(set(test_keys) - set(baseline_keys))

    A finding is reported (the list is non-empty) **iff** that set difference is
    non-empty, i.e. iff the test JSON has >= 1 top-level key absent from the
    baseline JSON.

**Validates: Requirements 4.1, 4.2**
"""

from __future__ import annotations

import json

from hypothesis import given, settings, strategies as st

from core.config import FuzzingConfig
from modules.fuzzing.orchestrator import ParameterFuzzer
from tests.support.http_stub import HTTPRequestEngineStub, ScriptedResponse


def _make_fuzzer() -> ParameterFuzzer:
    """Construct a ParameterFuzzer wired to the offline stub engine."""
    stub = HTTPRequestEngineStub()
    return ParameterFuzzer(stub, FuzzingConfig())


def _json_response(payload) -> "object":
    """Build a real ``Response`` whose body is ``payload`` serialised as JSON."""
    return ScriptedResponse(
        status_code=200,
        body=json.dumps(payload),
        headers=None,
        content_type="application/json",
    ).to_response(url="https://target.test/api", method="GET")


# Top-level JSON keys: short identifiers drawn from a small shared alphabet so
# baseline/test key sets frequently overlap, enabling disjoint, subset, and
# superset relationships to be explored.
_json_key = st.from_regex(r"[a-e][a-e0-9_]{0,4}", fullmatch=True)

# JSON scalar values -- the value never affects top-level key detection, so a
# simple, JSON-serialisable set of scalars keeps generation cheap.
_json_value = st.one_of(
    st.integers(min_value=-1000, max_value=1000),
    st.text(max_size=8),
    st.booleans(),
    st.none(),
)

# A JSON object (dict) with 0-8 top-level keys.
_json_object = st.dictionaries(keys=_json_key, values=_json_value, max_size=8)


@given(baseline=_json_object, test=_json_object)
@settings(max_examples=50, deadline=None)
def test_new_json_fields_equal_absent_top_level_keys(baseline, test):
    """New-JSON-field list equals exactly the test-only top-level keys.

    A finding (non-empty list) is returned iff the test JSON has >= 1 top-level
    key absent from the baseline JSON, and the list equals exactly those keys
    (sorted).

    # Feature: parameter-fuzzing, Property 4: New-JSON-field detection correctness
    **Validates: Requirements 4.1, 4.2**
    """
    fuzzer = _make_fuzzer()

    baseline_response = _json_response(baseline)
    test_response = _json_response(test)

    result = fuzzer._detect_new_json_fields(baseline_response, test_response)

    expected = sorted(set(test.keys()) - set(baseline.keys()))

    # Both bodies parse as JSON, so the detector must never skip (never None).
    assert result is not None, "detector skipped a pair of valid JSON bodies"

    # new_json_fields equals exactly the test-only top-level keys, sorted (R4.2).
    assert result == expected, (
        f"expected {expected!r} but got {result!r}\n"
        f"  baseline keys={sorted(baseline.keys())}\n"
        f"  test keys={sorted(test.keys())}"
    )

    # Finding iff there is at least one absent-in-baseline key (R4.1).
    finding_reported = bool(result)
    has_new_key = bool(set(test.keys()) - set(baseline.keys()))
    assert finding_reported == has_new_key


@given(shared=_json_object, extra=_json_object)
@settings(max_examples=50, deadline=None)
def test_superset_test_reports_exactly_the_added_keys(shared, extra):
    """When test is baseline plus extra keys, the added keys are reported.

    Constructs test as baseline (``shared``) merged with ``extra`` so the set of
    genuinely new keys is exactly ``extra`` minus ``shared``.

    # Feature: parameter-fuzzing, Property 4: New-JSON-field detection correctness
    **Validates: Requirements 4.1, 4.2**
    """
    fuzzer = _make_fuzzer()

    test = dict(shared)
    test.update(extra)

    result = fuzzer._detect_new_json_fields(
        _json_response(shared), _json_response(test)
    )

    expected = sorted(set(extra.keys()) - set(shared.keys()))
    assert result == expected


def test_identical_json_objects_report_no_new_fields():
    """Identical JSON bodies yield an empty new-field list, not None."""
    fuzzer = _make_fuzzer()
    payload = {"a": 1, "b": "two", "c": True}
    result = fuzzer._detect_new_json_fields(
        _json_response(payload), _json_response(dict(payload))
    )
    assert result == []


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
