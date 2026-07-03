"""
Property-Based Tests for `par` Matcher/Filter Selection

**Feature: parameter-fuzzing, Property 11: Matcher/filter selection applies
matchers before filters**

Property 11 (from design.md):
    *For any* set of parameter findings and *any* configured matchers and
    filters, the reported findings SHALL equal the set produced by first
    retaining only findings that satisfy every matcher and then excluding every
    finding that satisfies any filter, identical to the ``dir`` selection
    pipeline.

These tests exercise ``core.engine._select_parameter_findings`` -- the helper
that routes ``par`` findings through the SAME
``utils.response_selector.apply_selectors`` matcher-before-filter pipeline that
``dir`` uses (Requirements 12.1, 12.2, 12.3). The retained set is compared
against an independently-computed "retain-every-matcher THEN exclude-any-filter"
oracle re-derived from the acceptance criteria, so the assertion is a real
cross-check rather than a tautology against the code under test.

The selection helper is pure -- it issues no requests -- so these tests run
fully offline with no real network access, consistent with the shared stub
``HTTPRequestEngine`` harness (task 1.1) used across the parameter-fuzzing
suite.
"""

import re
from uuid import uuid4

from hypothesis import given, settings, strategies as st
from hypothesis.strategies import composite

from core.config import Severity
from core.engine import _select_parameter_findings
from utils.discovery_session import DiscoveryResult
from utils.findings import Finding
from utils.response_selector import (
    Bound,
    DiscoveryResultEx,
    ResponseSelector,
)


# ---------------------------------------------------------------------------
# Independent selection oracle
#
# Re-derived from Requirement 12.1/12.2/12.3: retain findings satisfying EVERY
# matcher, THEN exclude findings satisfying ANY filter (matchers before
# filters). The Finding->view mapping mirrors _select_parameter_findings so the
# oracle selects over the same attribute projection, but the retain/exclude
# logic and the predicate evaluation are re-implemented here so the assertion
# is a genuine cross-check.
# ---------------------------------------------------------------------------

def _finding_to_view(finding: Finding) -> DiscoveryResultEx:
    """Adapt a Finding into the selectable view, mirroring the engine helper."""
    snippet = finding.response_snippet or ""
    result = DiscoveryResult(
        url=finding.endpoint,
        method=finding.method,
        status_code=finding.status_code,
        endpoint_status="valid",
    )
    return DiscoveryResultEx(
        result=result,
        size=finding.response_size,
        words=len(snippet.split()),
        lines=len(snippet.splitlines()),
        elapsed=finding.response_time,
        text=snippet,
    )


def _oracle_bound(bound: Bound, value: float) -> bool:
    """Independently mirror Bound.test semantics."""
    if bound.op == "==":
        return value == bound.lo
    if bound.op == ">":
        return value > bound.lo
    if bound.op == ">=":
        return value >= bound.lo
    if bound.op == "<":
        return value < bound.lo
    if bound.op == "<=":
        return value <= bound.lo
    if bound.op == "range":
        hi = bound.hi if bound.hi is not None else bound.lo
        return bound.lo <= value <= hi
    raise AssertionError(f"unexpected bound op {bound.op!r}")


def _oracle_selector(selector: ResponseSelector, view: DiscoveryResultEx) -> bool:
    """Independently evaluate whether a view satisfies a selector."""
    if selector.size is not None and not _oracle_bound(selector.size, view.size):
        return False
    if selector.words is not None and not _oracle_bound(selector.words, view.words):
        return False
    if selector.lines is not None and not _oracle_bound(selector.lines, view.lines):
        return False
    if selector.time is not None and not _oracle_bound(selector.time, view.elapsed):
        return False
    if selector.regex is not None and selector.regex.search(view.text) is None:
        return False
    return True


def _oracle_select(findings, matchers, filters):
    """Retain every-matcher THEN exclude any-filter (Requirements 12.1-12.3)."""
    retained = []
    for finding in findings:
        view = _finding_to_view(finding)
        # 12.1: keep only findings satisfying EVERY matcher.
        if not all(_oracle_selector(m, view) for m in matchers):
            continue
        # 12.2/12.3: THEN drop findings satisfying ANY filter (after matchers).
        if any(_oracle_selector(f, view) for f in filters):
            continue
        retained.append(finding)
    return retained


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]

# Small alphabet so regex predicates and word/line counts land in a meaningful
# range, exercising both the hit and miss branches of every predicate.
_TEXT_ALPHABET = "ab \n"
_REGEX_PATTERNS = ["a", "b", "ab", "a+", "^a", "b$", "[ab]", "a.b", "aa"]

# Numeric values overlap with the bound values (0-20) so matchers/filters retain
# and drop findings in roughly balanced proportions.
_NUM = st.integers(min_value=0, max_value=20)


@composite
def finding_strategy(draw) -> Finding:
    """Generate one parameter Finding with broad selectable-attribute coverage.

    Only the fields the selection pipeline projects (response_size,
    response_time, response_snippet, status_code, endpoint, method) are varied
    meaningfully; the remaining required fields are populated with valid,
    representative values.
    """
    snippet = draw(st.text(alphabet=_TEXT_ALPHABET, min_size=0, max_size=16))
    return Finding(
        id=str(uuid4()),
        scan_id="test-scan",
        category="PARAMETER_DISCOVERED",
        owasp_category=None,
        severity=Severity.INFO,
        endpoint=draw(st.sampled_from(["https://api.test/a", "https://api.test/b"])),
        method=draw(st.sampled_from(HTTP_METHODS)),
        status_code=draw(
            st.one_of(
                st.integers(min_value=200, max_value=299),
                st.integers(min_value=300, max_value=599),
            )
        ),
        response_size=draw(_NUM),
        response_time=draw(st.floats(min_value=0.0, max_value=20.0)),
        evidence="generated finding",
        recommendation="review parameter",
        response_snippet=snippet,
    )


@composite
def bound_strategy(draw) -> Bound:
    """Generate a numeric Bound spanning ==, >, >=, <, <=, and range."""
    op = draw(st.sampled_from(["==", ">", ">=", "<", "<=", "range"]))
    lo = float(draw(st.integers(min_value=0, max_value=20)))
    if op == "range":
        hi = lo + float(draw(st.integers(min_value=0, max_value=10)))
        return Bound(op="range", lo=lo, hi=hi)
    return Bound(op=op, lo=lo)


@composite
def selector_strategy(draw) -> ResponseSelector:
    """Generate a single ResponseSelector over one selectable attribute.

    Covers numeric Bounds on size/words/lines/time and a response-body regex
    predicate -- the matcher/filter grammar the ``par`` selection projects onto
    parameter findings.
    """
    kind = draw(st.sampled_from(["size", "words", "lines", "time", "regex"]))
    if kind == "regex":
        return ResponseSelector(regex=re.compile(draw(st.sampled_from(_REGEX_PATTERNS))))
    return ResponseSelector(**{kind: draw(bound_strategy())})


# ---------------------------------------------------------------------------
# Property 11
# ---------------------------------------------------------------------------

@given(
    findings=st.lists(finding_strategy(), min_size=0, max_size=25),
    matchers=st.lists(selector_strategy(), min_size=0, max_size=4),
    filters=st.lists(selector_strategy(), min_size=0, max_size=4),
)
@settings(max_examples=200, deadline=5000)
def test_matcher_before_filter_selection(findings, matchers, filters):
    """
    **Feature: parameter-fuzzing, Property 11: Matcher/filter selection applies
    matchers before filters**
    **Validates: Requirements 12.1, 12.2, 12.3**

    FOR ALL generated parameter finding sets, matcher sets, and filter sets:
      - _select_parameter_findings retains exactly the findings that satisfy
        EVERY matcher (12.1) and are excluded by NO filter (12.2), with matchers
        applied before filters (12.3), as computed by an independent oracle; and
      - the reported findings are a subset of the input preserving relative
        order (the shared ``dir`` selection pipeline is order-preserving).
    """
    selected = _select_parameter_findings(findings, matchers, filters)
    expected = _oracle_select(findings, matchers, filters)

    # Selection equals the retain-matchers-then-exclude-filters oracle, by
    # object identity so equal-valued findings are not conflated.
    assert [id(f) for f in selected] == [id(f) for f in expected]

    # Retained findings are a subset of the input preserving relative order.
    input_index = {id(f): i for i, f in enumerate(findings)}
    indices = [input_index[id(f)] for f in selected]
    assert indices == sorted(indices)
    assert all(f in findings for f in selected)


def test_matchers_applied_before_filters_ordering():
    """
    **Feature: parameter-fuzzing, Property 11: Matcher/filter selection applies
    matchers before filters**
    **Validates: Requirements 12.1, 12.2, 12.3**

    A finding that satisfies a matcher but ALSO satisfies a filter MUST be
    excluded: matchers are applied first (retain), then filters remove any that
    match (12.3). This pins the ordering requirement directly.
    """
    def make(size):
        return Finding(
            id=str(uuid4()),
            scan_id="test-scan",
            category="PARAMETER_DISCOVERED",
            owasp_category=None,
            severity=Severity.INFO,
            endpoint="https://api.test/x",
            method="GET",
            status_code=200,
            response_size=size,
            response_time=0.01,
            evidence="e",
            recommendation="r",
            response_snippet="",
        )

    small = make(5)      # matcher keeps it, filter also matches -> excluded
    large = make(50)     # matcher keeps it, filter does not match -> retained

    # Matcher: size >= 1 (keeps both). Filter: size < 10 (drops `small`).
    matchers = [ResponseSelector(size=Bound(op=">=", lo=1.0))]
    filters = [ResponseSelector(size=Bound(op="<", lo=10.0))]

    selected = _select_parameter_findings([small, large], matchers, filters)

    # `small` satisfies the matcher yet also satisfies the filter -> excluded.
    assert [id(f) for f in selected] == [id(large)]


def test_no_selectors_returns_findings_unchanged():
    """
    **Feature: parameter-fuzzing, Property 11: Matcher/filter selection
    (identity case)**
    **Validates: Requirements 12.1, 12.2, 12.3**

    With no matchers and no filters the reported findings are the input list
    unchanged (order-preserving no-op), so runs without selectors and other
    commands are unaffected.
    """
    findings = [
        Finding(
            id=str(uuid4()),
            scan_id="test-scan",
            category="PARAMETER_DISCOVERED",
            owasp_category=None,
            severity=Severity.INFO,
            endpoint=f"https://api.test/{i}",
            method="GET",
            status_code=200,
            response_size=i,
            response_time=float(i),
            evidence="e",
            recommendation="r",
            response_snippet="ab " * i,
        )
        for i in range(5)
    ]
    assert _select_parameter_findings(findings, [], []) == findings
