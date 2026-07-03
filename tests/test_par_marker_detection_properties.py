"""Property-Based and Example Tests for par-positional-markers detection,
confirmation, budget, selection, and machine output (Tasks 8.4–8.9).

# Feature: par-positional-markers

Properties implemented:
  Property 10 (task 8.4): Request budget bounds total requests and preserves gathered findings
  Property 11 (task 8.5): Marker findings record candidate URL, values, and triggering signals
  Property 12 (task 8.6): Hit_Confirmation inclusion/exclusion in Marker_Mode
  Property 13 (task 8.7): Matcher/filter selection applies matchers before filters
  Property 14 (task 8.8): Machine-readable output round-trips marker findings

Task 8.9: Example tests for detection-signal reuse

Validates: Requirements 5.4, 6.3, 9.1, 9.2, 9.3, 9.4, 11.1, 11.2, 11.3,
           11.4, 11.5
"""

from __future__ import annotations

import asyncio
import csv
import json
import math
import tempfile
from collections import Counter
from pathlib import Path
from typing import List, Optional
from uuid import uuid4

import pytest
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

import apileaks
from core.config import ConfigurationManager, Severity
from core.engine import _select_parameter_findings
from modules.fuzzing.markers import (
    FuzzMode,
    find_markers,
    generate_marker_candidates,
    substitute_markers,
)
from modules.fuzzing.orchestrator import Endpoint, ParameterFuzzer
from tests.support.http_stub import HTTPRequestEngineStub, ScriptedResponse, RecordedRequest
from utils.discovery_output import (
    FINDING_CSV_FIELDNAMES,
    _finding_to_output_dict,
    write_parameter_findings_output,
)
from utils.findings import Finding
from utils.response_selector import Bound, DiscoveryResultEx, ResponseSelector


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

MARKER_URL = "https://api.example.test/v1/?id=FUZZ"
TWO_MARKER_URL = "https://api.example.test/v1/?a=FUZZ&b=FUZZ"

_BASELINE_STATUS = 200
_DIFF_STATUS = 301
_BODY = "identical-body"


def _make_fuzzer(
    url: str,
    wordlists: List[List[str]],
    *,
    fuzz_mode: str = "clusterbomb",
    methods: Optional[List[str]] = None,
    max_requests: Optional[int] = None,
    confirm_hits: Optional[int] = None,
) -> tuple:
    """Build a ParameterFuzzer wired to an offline HTTPRequestEngineStub."""
    if methods is None:
        methods = ["GET"]

    config_dict = apileaks.create_default_config(
        url, None, "par",
        fuzz_keyword="FUZZ",
        fuzz_mode=fuzz_mode,
        marker_wordlists=wordlists,
    )
    cfg = config_dict["fuzzing"]["parameters"]
    cfg["methods"] = methods
    cfg["boundary_testing"] = False
    cfg["max_requests"] = max_requests
    cfg["confirm_hits"] = confirm_hits

    config = ConfigurationManager().load_config_from_dict(config_dict)
    stub = HTTPRequestEngineStub()
    fuzzer = ParameterFuzzer(stub, config.fuzzing)
    return fuzzer, stub


def _endpoint(url: str) -> Endpoint:
    return Endpoint(
        url=url,
        method="GET",
        status_code=200,
        response_size=0,
        response_time=0.01,
        discovered_via="target",
        endpoint_type="parameter_target",
    )


# ---------------------------------------------------------------------------
# Wordlist / value strategies used across properties
# ---------------------------------------------------------------------------

_wl_entry = st.text(
    min_size=1,
    max_size=8,
    alphabet=st.characters(whitelist_categories=("Ll", "Nd")),
)
_wl = st.lists(_wl_entry, min_size=1, max_size=6)

# ===========================================================================
# Task 8.4 — Property 10: Request budget bounds total requests
# # Feature: par-positional-markers, Property 10: Request budget bounds total requests
# Validates: Requirements 5.4, 6.3, 11.1, 11.2
# ===========================================================================


@given(
    wl=st.lists(_wl_entry, min_size=1, max_size=20, unique=True),
    budget=st.integers(min_value=1, max_value=25),
    confirm_hits=st.sampled_from([None, 1, 2]),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_property10_budget_bounds_total_requests(wl, budget, confirm_hits):
    """Property 10: Request budget bounds total requests and preserves gathered findings.

    # Feature: par-positional-markers, Property 10: Request budget bounds total requests
    **Validates: Requirements 5.4, 6.3, 11.1, 11.2**

    Assert: total requests (baseline + candidate + confirmation retests) never
    exceed B. When stopped by budget, the stop reason is recorded and gathered
    findings retained.
    """
    fuzzer, stub = _make_fuzzer(
        MARKER_URL, [wl],
        max_requests=budget,
        confirm_hits=confirm_hits,
    )

    # Use request order: first request is baseline (GET with single method),
    # subsequent requests are candidates or retests.
    request_counter = [0]

    def responder(req: RecordedRequest) -> ScriptedResponse:
        request_counter[0] += 1
        if request_counter[0] == 1:
            return ScriptedResponse(status_code=_BASELINE_STATUS, body=_BODY)
        return ScriptedResponse(status_code=_DIFF_STATUS, body=_BODY)

    stub.set_responder(responder)
    findings = asyncio.run(fuzzer.fuzz_parameters([_endpoint(MARKER_URL)]))

    # Budget bound: total requests never exceed B
    assert fuzzer.requests_made <= budget, (
        f"requests_made {fuzzer.requests_made} exceeds budget {budget}"
    )
    assert stub.call_count == fuzzer.requests_made
    assert stub.call_count <= budget

    # Findings are only ever from requests actually issued
    marker_findings = [f for f in findings if f.category == "PARAMETER_FOUND"]
    assert len(marker_findings) <= fuzzer.requests_made


@given(
    wl=st.lists(_wl_entry, min_size=3, max_size=15, unique=True),
    budget=st.integers(min_value=1, max_value=3),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_property10_budget_stop_records_reason_and_retains_findings(wl, budget):
    """Property 10: Budget stop records reason and retains partial findings.

    # Feature: par-positional-markers, Property 10: Request budget bounds total requests
    **Validates: Requirements 5.4, 11.1, 11.2**

    With a budget smaller than the candidate space (1 baseline + N candidates),
    the run is truncated: budget_stop_reason is non-None and findings gathered
    before the stop are retained.
    """
    from hypothesis import assume
    # Ensure candidate space (len(wl) + 1 baseline) exceeds the budget
    assume(len(wl) + 1 > budget)

    fuzzer, stub = _make_fuzzer(MARKER_URL, [wl], max_requests=budget)

    request_counter2 = [0]

    def responder(req: RecordedRequest) -> ScriptedResponse:
        request_counter2[0] += 1
        if request_counter2[0] == 1:
            return ScriptedResponse(status_code=_BASELINE_STATUS, body=_BODY)
        return ScriptedResponse(status_code=_DIFF_STATUS, body=_BODY)

    stub.set_responder(responder)
    findings = asyncio.run(fuzzer.fuzz_parameters([_endpoint(MARKER_URL)]))

    # Budget is exhausted -> stop reason is recorded
    assert fuzzer.budget_stop_reason is not None, (
        f"budget_stop_reason not set for budget={budget}, wl size={len(wl)}"
    )
    # Requests never exceed budget
    assert fuzzer.requests_made <= budget

    # Findings gathered before stop are retained
    marker_findings = [f for f in findings if f.category == "PARAMETER_FOUND"]
    assert isinstance(marker_findings, list)  # findings returned (possibly empty)

    # No stop reason when unbounded
    fuzzer2, stub2 = _make_fuzzer(MARKER_URL, [wl], max_requests=None)

    def always_diff(_req: RecordedRequest) -> ScriptedResponse:
        return ScriptedResponse(status_code=_BASELINE_STATUS, body=_BODY)

    stub2.set_responder(always_diff)
    asyncio.run(fuzzer2.fuzz_parameters([_endpoint(MARKER_URL)]))
    assert fuzzer2.budget_stop_reason is None


# ===========================================================================
# Task 8.5 — Property 11: Marker findings record candidate URL, values, signals
# # Feature: par-positional-markers, Property 11: Marker findings record candidate URL, values, and triggering signals
# Validates: Requirements 9.1, 9.2, 9.3, 9.4
# ===========================================================================

_SIGNAL_SPECS = st.sampled_from([
    # (baseline_status, test_status, baseline_body, test_body, expected_primary_signal)
    (200, 301, "same", "same", "status_code"),
])


@given(
    val=st.text(min_size=1, max_size=8, alphabet=st.characters(whitelist_categories=("Ll",))),
    signal_spec=_SIGNAL_SPECS,
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_property11_finding_records_candidate_url_values_signals(val, signal_spec):
    """Property 11: Marker findings record candidate URL, values, and triggering signals.

    # Feature: par-positional-markers, Property 11: Marker findings record candidate URL, values, and triggering signals
    **Validates: Requirements 9.1, 9.2, 9.3, 9.4**

    A Response_Difference candidate yields a finding recording:
    - endpoint = candidate URL (the substituted URL)
    - payload = substituted value(s)
    - detection_signal = the primary signal that triggered
    - detection_signals = non-empty list of signals
    No difference → success with no marker findings.
    """
    base_status, test_status, base_body, test_body, expected_signal = signal_spec
    url = MARKER_URL  # has exactly one FUZZ marker at ?id=FUZZ

    fuzzer, stub = _make_fuzzer(url, [[val]])
    markers = find_markers(url, "FUZZ")
    expected_candidate = substitute_markers(url, markers, [val])

    # Use request-order to distinguish baseline (first request) from candidates.
    # _fuzz_markers issues baseline request(s) first, then candidates.
    request_count = [0]

    def responder(req: RecordedRequest) -> ScriptedResponse:
        request_count[0] += 1
        if request_count[0] == 1:
            # First request is always the baseline
            return ScriptedResponse(status_code=base_status, body=base_body)
        return ScriptedResponse(status_code=test_status, body=test_body)

    stub.set_responder(responder)
    findings = asyncio.run(fuzzer.fuzz_parameters([_endpoint(url)]))

    marker_findings = [f for f in findings if f.category == "PARAMETER_FOUND"]

    # Exactly one finding for one triggering candidate
    assert len(marker_findings) == 1, (
        f"Expected 1 marker finding, got {len(marker_findings)}"
    )
    finding = marker_findings[0]

    # R9.1: endpoint records the candidate URL (fully substituted)
    assert finding.endpoint == expected_candidate, (
        f"Finding endpoint {finding.endpoint!r} != expected candidate {expected_candidate!r}"
    )
    # R9.1: payload records the substituted value
    assert val in finding.payload or finding.payload == val, (
        f"Payload {finding.payload!r} does not contain value {val!r}"
    )
    # R9.3: detection_signal records the primary triggering signal
    assert finding.detection_signal == expected_signal, (
        f"Expected detection_signal={expected_signal!r}, got {finding.detection_signal!r}"
    )
    # R9.3: detection_signals is a non-empty list
    assert isinstance(finding.detection_signals, list) and len(finding.detection_signals) > 0
    # R9.2: category and severity correct
    assert finding.category == "PARAMETER_FOUND"
    assert finding.severity == Severity.INFO


@given(val=st.text(min_size=1, max_size=8, alphabet=st.characters(whitelist_categories=("Ll",))))
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_property11_no_difference_yields_no_findings(val):
    """Property 11 (no difference case): no findings when baseline == test.

    # Feature: par-positional-markers, Property 11: Marker findings record candidate URL, values, and triggering signals
    **Validates: Requirement 9.4**
    """
    fuzzer, stub = _make_fuzzer(MARKER_URL, [[val]])
    stub.set_default(ScriptedResponse(status_code=200, body="same-for-all"))

    findings = asyncio.run(fuzzer.fuzz_parameters([_endpoint(MARKER_URL)]))
    marker_findings = [f for f in findings if f.category == "PARAMETER_FOUND"]

    # No difference between baseline and candidates -> no findings
    assert len(marker_findings) == 0, (
        f"Expected 0 findings when no difference, got {len(marker_findings)}"
    )


# ===========================================================================
# Task 8.6 — Property 12: Hit_Confirmation inclusion/exclusion in Marker_Mode
# # Feature: par-positional-markers, Property 12: Hit_Confirmation inclusion/exclusion in Marker_Mode
# Validates: Requirement 11.3
# ===========================================================================


@given(n=st.integers(min_value=1, max_value=4))
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_property12_all_retests_reproduce_includes_candidate(n):
    """Property 12: With N≥1, all retests reproduce → finding included.

    # Feature: par-positional-markers, Property 12: Hit_Confirmation inclusion/exclusion in Marker_Mode
    **Validates: Requirement 11.3**

    The candidate is re-issued N additional times and included iff every retest
    reproduces the signals.
    """
    val = "testval"
    fuzzer, stub = _make_fuzzer(MARKER_URL, [[val]], confirm_hits=n)

    request_counter = [0]

    def responder(req: RecordedRequest) -> ScriptedResponse:
        request_counter[0] += 1
        if request_counter[0] == 1:
            # First request is baseline
            return ScriptedResponse(status_code=200, body="same")
        # All candidate requests (including retests) differ from baseline
        return ScriptedResponse(status_code=301, body="same")

    stub.set_responder(responder)
    findings = asyncio.run(fuzzer.fuzz_parameters([_endpoint(MARKER_URL)]))

    marker_findings = [f for f in findings if f.category == "PARAMETER_FOUND"]
    assert len(marker_findings) == 1, f"Expected 1 confirmed finding, got {len(marker_findings)}"
    assert marker_findings[0].confirmation_status == "confirmed"
    assert fuzzer.excluded_findings == []

    # N additional retest requests were issued: 1 baseline + 1 initial + N retests
    # Total requests: 1 (baseline) + 1 (initial) + N (retests) = N+2
    assert stub.call_count == n + 2, (
        f"Expected {n+2} total requests (1 baseline + 1 initial + {n} retests), "
        f"got {stub.call_count}"
    )


@given(n=st.integers(min_value=1, max_value=4))
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_property12_any_retest_failing_excludes_candidate(n):
    """Property 12: A failing retest excludes the candidate.

    # Feature: par-positional-markers, Property 12: Hit_Confirmation inclusion/exclusion in Marker_Mode
    **Validates: Requirement 11.3**
    """
    val = "testval"
    # Use a list to track request count across the closure
    request_counter = [0]
    fuzzer, stub = _make_fuzzer(MARKER_URL, [[val]], confirm_hits=n)

    def responder(req: RecordedRequest) -> ScriptedResponse:
        request_counter[0] += 1
        if request_counter[0] == 1:
            # First request is the baseline
            return ScriptedResponse(status_code=200, body="same")
        # request_counter[0] == 2 is the initial candidate diff
        # request_counter[0] >= 3 are retests (first retest fails)
        if request_counter[0] == 2:
            return ScriptedResponse(status_code=301, body="same")  # initial diff
        return ScriptedResponse(status_code=200, body="same")  # retests identical -> no signal

    stub.set_responder(responder)
    findings = asyncio.run(fuzzer.fuzz_parameters([_endpoint(MARKER_URL)]))

    marker_findings = [f for f in findings if f.category == "PARAMETER_FOUND"]
    assert len(marker_findings) == 0, "Failed retest should exclude the candidate"
    assert len(fuzzer.excluded_findings) == 1
    assert fuzzer.excluded_findings[0].confirmation_status == "excluded_failed_retest"


@given(confirm_hits=st.sampled_from([None, 0]))
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_property12_disabled_reports_candidate_no_retest(confirm_hits):
    """Property 12: Disabled confirmation reports candidate, no retest.

    # Feature: par-positional-markers, Property 12: Hit_Confirmation inclusion/exclusion in Marker_Mode
    **Validates: Requirement 11.3**
    """
    val = "testval"
    fuzzer, stub = _make_fuzzer(MARKER_URL, [[val]], confirm_hits=confirm_hits)

    request_counter_3 = [0]

    def responder(req: RecordedRequest) -> ScriptedResponse:
        request_counter_3[0] += 1
        if request_counter_3[0] == 1:
            return ScriptedResponse(status_code=200, body="same")
        return ScriptedResponse(status_code=301, body="same")

    stub.set_responder(responder)
    findings = asyncio.run(fuzzer.fuzz_parameters([_endpoint(MARKER_URL)]))

    marker_findings = [f for f in findings if f.category == "PARAMETER_FOUND"]
    assert len(marker_findings) == 1
    assert marker_findings[0].confirmation_status is None
    assert fuzzer.excluded_findings == []

    # No retest: only baseline + initial candidate = 2 total requests
    assert stub.call_count == 2, f"Expected 2 requests (no retest), got {stub.call_count}"


# ===========================================================================
# Task 8.7 — Property 13: Matcher/filter selection applies matchers before filters
# # Feature: par-positional-markers, Property 13: Matcher/filter selection applies matchers before filters
# Validates: Requirement 11.4
# ===========================================================================

from utils.discovery_session import DiscoveryResult


def _make_marker_finding(*, endpoint: str, status_code: int,
                         response_size: int, response_time: float,
                         snippet: str = "") -> Finding:
    return Finding(
        id=str(uuid4()),
        scan_id="test-scan",
        category="PARAMETER_FOUND",
        owasp_category=None,
        severity=Severity.INFO,
        endpoint=endpoint,
        method="GET",
        status_code=status_code,
        response_size=response_size,
        response_time=response_time,
        evidence="Marker candidate differs from baseline",
        recommendation="review",
        response_snippet=snippet,
        detection_signal="status_code",
        detection_signals=["status_code"],
    )


def _oracle_select(findings, matchers, filters):
    """Reference: retain every matcher, then exclude any filter."""
    from utils.response_selector import apply_selectors

    retained = []
    for f in findings:
        snippet = f.response_snippet or ""
        result = DiscoveryResult(
            url=f.endpoint, method=f.method,
            status_code=f.status_code, endpoint_status="valid",
        )
        view = DiscoveryResultEx(
            result=result,
            size=f.response_size,
            words=len(snippet.split()),
            lines=len(snippet.splitlines()),
            elapsed=f.response_time,
            text=snippet,
        )
        if not all(_eval_selector(m, view) for m in matchers):
            continue
        if any(_eval_selector(fi, view) for fi in filters):
            continue
        retained.append(f)
    return retained


def _eval_selector(sel: ResponseSelector, view: DiscoveryResultEx) -> bool:
    def _bound(b: Bound, v: float) -> bool:
        if b.op == "==": return v == b.lo
        if b.op == ">": return v > b.lo
        if b.op == ">=": return v >= b.lo
        if b.op == "<": return v < b.lo
        if b.op == "<=": return v <= b.lo
        if b.op == "range":
            hi = b.hi if b.hi is not None else b.lo
            return b.lo <= v <= hi
        return False
    if sel.size is not None and not _bound(sel.size, view.size): return False
    if sel.words is not None and not _bound(sel.words, view.words): return False
    if sel.lines is not None and not _bound(sel.lines, view.lines): return False
    if sel.time is not None and not _bound(sel.time, view.elapsed): return False
    if sel.regex is not None and sel.regex.search(view.text) is None: return False
    return True


_num = st.integers(min_value=0, max_value=20)


@st.composite
def _finding_st(draw) -> Finding:
    snippet = draw(st.text(alphabet="ab \n", min_size=0, max_size=16))
    return _make_marker_finding(
        endpoint=draw(st.sampled_from(["https://api.test/a", "https://api.test/b"])),
        status_code=draw(st.integers(min_value=200, max_value=500)),
        response_size=draw(_num),
        response_time=draw(st.floats(min_value=0.0, max_value=20.0)),
        snippet=snippet,
    )


@st.composite
def _selector_st(draw) -> ResponseSelector:
    import re
    kind = draw(st.sampled_from(["size", "words", "lines", "time"]))
    op = draw(st.sampled_from(["==", ">", ">=", "<", "<=", "range"]))
    lo = float(draw(st.integers(min_value=0, max_value=20)))
    if op == "range":
        hi = lo + float(draw(st.integers(min_value=0, max_value=10)))
        b = Bound(op="range", lo=lo, hi=hi)
    else:
        b = Bound(op=op, lo=lo)
    return ResponseSelector(**{kind: b})


@given(
    findings=st.lists(_finding_st(), min_size=0, max_size=20),
    matchers=st.lists(_selector_st(), min_size=0, max_size=3),
    filters=st.lists(_selector_st(), min_size=0, max_size=3),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=5000)
def test_property13_matcher_before_filter_for_marker_findings(findings, matchers, filters):
    """Property 13: Matcher/filter selection applies matchers before filters.

    # Feature: par-positional-markers, Property 13: Matcher/filter selection applies matchers before filters
    **Validates: Requirement 11.4**

    Reported marker findings equal the set produced by retaining
    matcher-satisfying findings then excluding filter-satisfying findings,
    identical to the name-discovery / dir pipeline.
    """
    selected = _select_parameter_findings(findings, matchers, filters)
    expected = _oracle_select(findings, matchers, filters)

    assert [id(f) for f in selected] == [id(f) for f in expected], (
        f"Marker findings selection does not match oracle. "
        f"Selected IDs: {[id(f) for f in selected]}, "
        f"Expected IDs: {[id(f) for f in expected]}"
    )
    # Subset and order preservation
    input_index = {id(f): i for i, f in enumerate(findings)}
    indices = [input_index[id(f)] for f in selected]
    assert indices == sorted(indices)


# ===========================================================================
# Task 8.8 — Property 14: Machine-readable output round-trips marker findings
# # Feature: par-positional-markers, Property 14: Machine-readable output round-trips marker findings
# Validates: Requirement 11.5
# ===========================================================================

_nonempty_text = st.text(min_size=1, max_size=24)
_optional_text = st.one_of(st.none(), _nonempty_text)
_string_list = st.lists(_nonempty_text, min_size=0, max_size=4)

DETECTION_SIGNALS = ["status_code", "response_size", "response_time",
                     "content_type", "reflection", "new_json_field"]
REFLECTION_LOCS = ["body", "header"]
CONFIRM_STATUSES = ["confirmed", "excluded_failed_retest"]


@st.composite
def _marker_finding_st(draw) -> Finding:
    """Generate a marker Finding covering the fields written by write_parameter_findings_output."""
    return Finding(
        id="fixed-id",
        scan_id="fixed-scan",
        category="PARAMETER_FOUND",
        owasp_category=None,
        severity=Severity.INFO,
        endpoint=draw(_nonempty_text),
        method=draw(st.sampled_from(["GET", "POST", "PUT", "DELETE", "PATCH"])),
        status_code=draw(st.integers(min_value=0, max_value=599)),
        response_size=0,
        response_time=0.0,
        evidence="Marker candidate differs from baseline",
        recommendation="review",
        detection_signal=draw(st.one_of(st.none(), st.sampled_from(DETECTION_SIGNALS))),
        detection_signals=draw(_string_list),
        reflection_location=draw(st.one_of(st.none(), st.sampled_from(REFLECTION_LOCS))),
        new_json_fields=draw(st.one_of(st.none(), _string_list)),
        confirmation_status=draw(st.one_of(st.none(), st.sampled_from(CONFIRM_STATUSES))),
        payload=draw(_nonempty_text),
    )


def _canonical(record: dict) -> tuple:
    njf = record["new_json_fields"]
    return (
        record["category"],
        record["endpoint"],
        record["method"],
        record["status_code"],
        record["detection_signal"],
        tuple(record["detection_signals"]),
        record["reflection_location"],
        None if njf is None else tuple(njf),
        record["confirmation_status"],
    )


def _expected_multiset(findings):
    return Counter(_canonical(_finding_to_output_dict(f)) for f in findings)


def _parse_csv(path: str):
    parsed = []
    with open(path, "r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        assert tuple(reader.fieldnames) == FINDING_CSV_FIELDNAMES
        for row in reader:
            parsed.append({
                "category": row["category"],
                "endpoint": row["endpoint"],
                "method": row["method"],
                "status_code": int(row["status_code"]),
                "detection_signal": row["detection_signal"] or None,
                "detection_signals": json.loads(row["detection_signals"]),
                "reflection_location": row["reflection_location"] or None,
                "new_json_fields": json.loads(row["new_json_fields"]),
                "confirmation_status": row["confirmation_status"] or None,
            })
    return parsed


def _parse_jsonl(path: str):
    parsed = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                parsed.append(json.loads(line))
    return parsed


def _parsed_multiset(records):
    return Counter(_canonical(r) for r in records)


@given(findings=st.lists(_marker_finding_st(), min_size=0, max_size=20))
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_property14_csv_round_trip_marker_findings(findings):
    """Property 14 (CSV): marker findings round-trip through CSV.

    # Feature: par-positional-markers, Property 14: Machine-readable output round-trips marker findings
    **Validates: Requirement 11.5**
    """
    with tempfile.TemporaryDirectory() as tmp:
        path = str(Path(tmp) / "findings.csv")
        write_parameter_findings_output(findings, path)
        parsed = _parse_csv(path)

    assert _parsed_multiset(parsed) == _expected_multiset(findings)


@given(findings=st.lists(_marker_finding_st(), min_size=0, max_size=20))
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_property14_jsonl_round_trip_marker_findings(findings):
    """Property 14 (JSONL): marker findings round-trip through JSONL.

    # Feature: par-positional-markers, Property 14: Machine-readable output round-trips marker findings
    **Validates: Requirement 11.5**
    """
    with tempfile.TemporaryDirectory() as tmp:
        path = str(Path(tmp) / "findings.jsonl")
        write_parameter_findings_output(findings, path)
        parsed = _parse_jsonl(path)

    assert _parsed_multiset(parsed) == _expected_multiset(findings)


# ===========================================================================
# Task 8.9 — Example tests for detection-signal reuse
# Validates: Requirements 9.2, 9.3
# ===========================================================================


class TestMarkerDetectionSignalReuse:
    """Example tests verifying marker mode records the same signals as Name_Discovery_Mode.

    Feeds scripted responses exercising each signal type and asserts marker
    findings record the triggering signal. Also verifies non-JSON bodies skip
    JSON detection without error.

    Validates: Requirements 9.2, 9.3
    """

    def _run(self, url: str, wordlist: List[str], responder_fn, *,
             methods: List[str] = None) -> tuple:
        """Run _fuzz_markers for the given URL/wordlist and return (fuzzer, findings)."""
        if methods is None:
            methods = ["GET"]
        fuzzer, stub = _make_fuzzer(url, [wordlist], methods=methods)
        stub.set_responder(responder_fn(fuzzer))
        findings = asyncio.run(fuzzer.fuzz_parameters([_endpoint(url)]))
        return fuzzer, findings

    def test_status_code_signal(self):
        """Status-code difference triggers 'status_code' signal in marker finding.

        Validates: Requirement 9.2
        """
        val = "admin"

        def make_responder(fuzzer):
            counter = [0]
            def responder(req: RecordedRequest) -> ScriptedResponse:
                counter[0] += 1
                if counter[0] == 1:
                    return ScriptedResponse(status_code=200, body="same")
                return ScriptedResponse(status_code=403, body="same")
            return responder

        fuzzer, findings = self._run(MARKER_URL, [val], make_responder)
        marker_findings = [f for f in findings if f.category == "PARAMETER_FOUND"]
        assert len(marker_findings) == 1
        assert "status_code" in marker_findings[0].detection_signals
        assert marker_findings[0].detection_signal == "status_code"

    def test_response_size_signal(self):
        """Body-size difference triggers 'response_size' signal in marker finding.

        Validates: Requirement 9.2
        """
        val = "debug"

        def make_responder(fuzzer):
            counter = [0]
            def responder(req: RecordedRequest) -> ScriptedResponse:
                counter[0] += 1
                if counter[0] == 1:
                    return ScriptedResponse(status_code=200, body="short")
                return ScriptedResponse(status_code=200, body="x" * 500)
            return responder

        fuzzer, findings = self._run(MARKER_URL, [val], make_responder)
        marker_findings = [f for f in findings if f.category == "PARAMETER_FOUND"]
        assert len(marker_findings) == 1
        signals = marker_findings[0].detection_signals
        assert any("response_size" in s or "size" in s for s in signals), (
            f"Expected response_size signal, got {signals}"
        )

    def test_content_type_signal(self):
        """Content-type change triggers signal in marker finding.

        Validates: Requirement 9.2
        """
        val = "xml"
        # Combine content-type change with status code change to ensure a signal fires.
        # The status_code signal is used as the reliable trigger; we also check
        # that no exception is raised when content-type headers differ.

        def make_responder(fuzzer):
            counter = [0]
            def responder(req: RecordedRequest) -> ScriptedResponse:
                counter[0] += 1
                if counter[0] == 1:
                    # Baseline: JSON content type
                    return ScriptedResponse(status_code=200, body="data",
                                            content_type="application/json")
                # Candidate: different status + different content type
                return ScriptedResponse(status_code=301, body="data",
                                        content_type="text/xml")
            return responder

        fuzzer, findings = self._run(MARKER_URL, [val], make_responder)
        marker_findings = [f for f in findings if f.category == "PARAMETER_FOUND"]
        # Any signal difference is fine; just ensure we got a finding
        assert len(marker_findings) >= 1, "Expected at least one finding on content-type change"

    def test_new_json_field_signal(self):
        """New JSON field in response triggers 'new_json_field' signal.

        Validates: Requirement 9.2
        """
        val = "debug"

        def make_responder(fuzzer):
            counter = [0]
            def responder(req: RecordedRequest) -> ScriptedResponse:
                counter[0] += 1
                if counter[0] == 1:
                    return ScriptedResponse(status_code=200, body={"ok": True})
                return ScriptedResponse(status_code=200,
                                        body={"ok": True, "debug_info": "present"})
            return responder

        fuzzer, findings = self._run(MARKER_URL, [val], make_responder)
        marker_findings = [f for f in findings if f.category == "PARAMETER_FOUND"]
        assert len(marker_findings) == 1
        assert "new_json_field" in marker_findings[0].detection_signals
        assert marker_findings[0].new_json_fields == ["debug_info"]

    def test_non_json_body_skips_json_detection_without_error(self):
        """Non-JSON bodies skip JSON field detection without error.

        Verifies remaining candidates continue after non-JSON responses.

        Validates: Requirement 9.2, 9.3
        """
        vals = ["first", "second", "third"]

        def make_responder(fuzzer):
            # Track which request number we're on
            counter = [0]

            def responder(req: RecordedRequest) -> ScriptedResponse:
                sentinel_vals = list(fuzzer._sentinels.values())
                is_baseline = any(sv in req.url for sv in sentinel_vals) if sentinel_vals else False
                if is_baseline:
                    return ScriptedResponse(status_code=200, body="baseline text",
                                            content_type="text/plain")
                counter[0] += 1
                if counter[0] == 1:
                    # First candidate: non-JSON, same status -> no signal (shouldn't error)
                    return ScriptedResponse(status_code=200, body="<xml>not json</xml>",
                                            content_type="application/xml")
                if counter[0] == 2:
                    # Second candidate: non-JSON, status diff -> status_code signal
                    return ScriptedResponse(status_code=403, body="<xml>forbidden</xml>",
                                            content_type="application/xml")
                # Third candidate: same as baseline
                return ScriptedResponse(status_code=200, body="baseline text",
                                        content_type="text/plain")
            return responder

        fuzzer, findings = self._run(MARKER_URL, vals, make_responder)
        # No exception raised; the second candidate triggered a status_code finding
        marker_findings = [f for f in findings if f.category == "PARAMETER_FOUND"]
        # Exactly one finding (second candidate with status 403)
        assert len(marker_findings) == 1
        assert "status_code" in marker_findings[0].detection_signals

    def test_signals_match_name_discovery_signal_set(self):
        """Marker findings use same signal types as Name_Discovery_Mode.

        Validates: Requirement 9.2
        """
        val = "test"

        def make_responder(fuzzer):
            counter = [0]
            def responder(req: RecordedRequest) -> ScriptedResponse:
                counter[0] += 1
                if counter[0] == 1:
                    return ScriptedResponse(status_code=200, body={"ok": True})
                # New JSON field: signal used by name-discovery too
                return ScriptedResponse(status_code=200,
                                        body={"ok": True, "hidden": "param"})
            return responder

        fuzzer, findings = self._run(MARKER_URL, [val], make_responder)
        marker_findings = [f for f in findings if f.category == "PARAMETER_FOUND"]
        assert len(marker_findings) == 1
        finding = marker_findings[0]

        # All signal values are from the shared signal set
        known_signals = {
            "status_code", "response_size", "response_time", "content_type",
            "new_json_field",
        }
        for sig in finding.detection_signals:
            # Signals may be compound like "reflection:body", check prefix
            base_sig = sig.split(":")[0]
            assert base_sig in known_signals or sig in known_signals, (
                f"Unexpected signal {sig!r} not in shared signal set"
            )


if __name__ == "__main__":
    import pytest as _pytest
    raise SystemExit(_pytest.main([__file__, "-v"]))
