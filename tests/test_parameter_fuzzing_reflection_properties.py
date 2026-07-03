"""Property-based tests for the parameter-fuzzing reflection detector.

# Feature: parameter-fuzzing, Property 3: Reflection detection correctness

Property 3 (from design.md / tasks.md task 5.4):
    FOR ALL baseline/test response pairs and any candidate sentinel, the
    candidate SHALL be classified as a Reflection finding **if and only if** the
    sentinel appears verbatim in the test response body or headers AND does not
    appear in the corresponding baseline location; and every such finding SHALL
    record the detection signal was Reflection together with the location
    (``body`` or ``header``) where the sentinel was found.

The test drives ``ParameterFuzzer._detect_reflection`` directly. The fuzzer is
constructed against the offline stub ``HTTPRequestEngine`` from task 1.1
(:mod:`tests.support.http_stub`) so the test runs fully offline with no real
network access -- although ``_detect_reflection`` itself issues no requests,
wiring the stub keeps the fuzzer construction identical to the rest of the
suite.

Scope note (task 5.4)
    At this stage the reflection signal is not yet wired into ``Finding``
    construction (that happens in task 5.8's ``_evaluate_difference``). Property
    3's substance at this stage is therefore the *iff* correctness of
    ``_detect_reflection`` and the returned location string (``'body'`` /
    ``'header'`` / ``None``), which is exactly what these tests assert.

Input model
    Each example independently controls whether the sentinel is placed into
    the test body, the baseline body, the test headers, and the baseline
    headers, surrounded by arbitrary noise text that is guaranteed (via
    ``assume``) not to accidentally contain the sentinel. The sentinel mirrors
    a real run-unique sentinel: 16-24 alphanumeric characters.

Oracle
    The detector's contract, computed independently of the implementation:

    * ``body_reflected``   := sentinel in test body   and sentinel NOT in baseline body
    * ``header_reflected`` := sentinel in test headers and sentinel NOT in baseline headers
    * expected := ``'body'`` if ``body_reflected`` else
                  ``'header'`` if ``header_reflected`` else ``None``

    (Body is checked before headers, so a sentinel that is new in *both*
    locations is reported as ``'body'``.)

**Validates: Requirements 3.2, 3.3, 3.4, 3.5**
"""

from __future__ import annotations

from hypothesis import assume, given, settings, strategies as st

from core.config import FuzzingConfig
from modules.fuzzing.orchestrator import ParameterFuzzer
from tests.support.http_stub import HTTPRequestEngineStub, ScriptedResponse


def _make_fuzzer() -> ParameterFuzzer:
    """Construct a ParameterFuzzer wired to the offline stub engine."""
    stub = HTTPRequestEngineStub()
    return ParameterFuzzer(stub, FuzzingConfig())


def _response(*, body: str, headers: dict) -> "object":
    """Build a real ``Response`` with an explicit body and header set.

    ``content_type=None`` keeps the stub from injecting a ``Content-Type``
    header so the header set under test is exactly what the generator chose.
    """
    return ScriptedResponse(
        status_code=200,
        body=body,
        headers=headers,
        content_type=None,
    ).to_response(url="https://target.test/api", method="GET")


# Run-unique sentinel shape: 16-24 alphanumeric chars (>= the R3.1 floor of 16;
# the real generator draws SENTINEL_LEN = 20).
_sentinel = st.from_regex(r"[A-Za-z0-9]{16,24}", fullmatch=True)

# Arbitrary noise text. Longish printable text exercises substring matching
# without (post-``assume``) colliding with the sentinel.
_noise = st.text(max_size=48)


@st.composite
def _reflection_cases(draw):
    """Generate a (sentinel, baseline, test, expected) reflection scenario.

    The sentinel is independently placed (or not) into four locations -- test
    body, baseline body, test headers, baseline headers -- wrapped in noise
    that is asserted not to contain the sentinel, so placement flags fully
    determine presence. The oracle is computed from those flags per the
    detector contract.
    """
    sentinel = draw(_sentinel)

    def clean_noise() -> str:
        n = draw(_noise)
        assume(sentinel not in n)
        return n

    in_test_body = draw(st.booleans())
    in_baseline_body = draw(st.booleans())
    in_test_header = draw(st.booleans())
    in_baseline_header = draw(st.booleans())

    def make_body(place: bool) -> str:
        pre, post = clean_noise(), clean_noise()
        return f"{pre}{sentinel if place else ''}{post}"

    def make_headers(place: bool) -> dict:
        # A fixed header name (never contains the sentinel) with a noise value
        # that optionally embeds the sentinel; plus a benign second header.
        pre, post = clean_noise(), clean_noise()
        # Header values cannot contain newlines/carriage returns in the
        # serialized "name: value" form without ambiguity; strip them so the
        # placement flag alone governs sentinel presence.
        value = f"{pre}{sentinel if place else ''}{post}".replace("\n", " ").replace("\r", " ")
        return {"X-Reflect": value, "X-Static": "constant"}

    baseline = _response(
        body=make_body(in_baseline_body),
        headers=make_headers(in_baseline_header),
    )
    test = _response(
        body=make_body(in_test_body),
        headers=make_headers(in_test_header),
    )

    body_reflected = in_test_body and not in_baseline_body
    header_reflected = in_test_header and not in_baseline_header
    if body_reflected:
        expected = "body"
    elif header_reflected:
        expected = "header"
    else:
        expected = None

    return sentinel, baseline, test, expected


@given(case=_reflection_cases())
@settings(max_examples=50, deadline=None)
def test_reflection_detected_iff_sentinel_new_in_test_location(case):
    """Reflection flagged iff sentinel is new in test body/headers, with location.

    # Feature: parameter-fuzzing, Property 3: Reflection detection correctness
    **Validates: Requirements 3.2, 3.3, 3.4, 3.5**
    """
    sentinel, baseline, test, expected = case
    fuzzer = _make_fuzzer()

    result = fuzzer._detect_reflection(sentinel, baseline, test)

    assert result == expected, (
        f"expected {expected!r} but got {result!r}\n"
        f"  sentinel={sentinel!r}\n"
        f"  baseline.text={baseline.text!r}\n  test.text={test.text!r}\n"
        f"  baseline.headers={baseline.headers!r}\n  test.headers={test.headers!r}"
    )

    # When flagged (R3.5), the location is exactly one of the two reflection
    # sites and the sentinel is genuinely present there and absent from the
    # matching baseline location.
    if result == "body":
        assert sentinel in test.text
        assert sentinel not in baseline.text
    elif result == "header":
        assert sentinel in fuzzer._serialize_headers(test.headers)
        assert sentinel not in fuzzer._serialize_headers(baseline.headers)
    else:
        assert result is None
        # Not flagged: it is NOT the case that the sentinel is new in the body,
        # NOR that it is new in the headers (R3.3 baseline-present exclusion).
        body_new = sentinel in test.text and sentinel not in baseline.text
        header_new = sentinel in fuzzer._serialize_headers(
            test.headers
        ) and sentinel not in fuzzer._serialize_headers(baseline.headers)
        assert not body_new and not header_new


@given(
    sentinel=_sentinel,
    baseline_body=_noise,
    test_body=_noise,
)
@settings(max_examples=50, deadline=None)
def test_baseline_present_sentinel_is_never_a_reflection(sentinel, baseline_body, test_body):
    """A sentinel present in the baseline body is never reported (R3.3).

    # Feature: parameter-fuzzing, Property 3: Reflection detection correctness
    **Validates: Requirements 3.3**
    """
    assume(sentinel not in baseline_body)
    assume(sentinel not in test_body)
    fuzzer = _make_fuzzer()

    # Sentinel appears in BOTH baseline and test bodies -> pre-existing, so it
    # must not be flagged as a body reflection.
    baseline = _response(body=f"{baseline_body}{sentinel}", headers={})
    test = _response(body=f"{test_body}{sentinel}", headers={})

    assert fuzzer._detect_reflection(sentinel, baseline, test) is None


def test_empty_sentinel_returns_none():
    """A degenerate empty sentinel is never treated as reflected."""
    fuzzer = _make_fuzzer()
    baseline = _response(body="anything", headers={"X": "y"})
    test = _response(body="anything else", headers={"X": "y"})
    assert fuzzer._detect_reflection("", baseline, test) is None


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
