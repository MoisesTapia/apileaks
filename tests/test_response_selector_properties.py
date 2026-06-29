"""
Property-Based Tests for Response Matcher/Filter Selection

**Feature: owasp-complete-purple-teaming-cicd, Property 12: Response
matcher/filter idempotence and conjunctive selection**

Property 12 (from design.md):
    FOR ALL sets of discovery records S, any matcher set M, any filter set F,
    and any status filter Q, apply_selectors(S, M, F, Q) retains exactly the
    records that satisfy Q AND every matcher in M AND no filter in F; and
    applying the same selection twice retains the same set as applying it once:
    apply_selectors(apply_selectors(S, M, F, Q), M, F, Q) ==
    apply_selectors(S, M, F, Q). Selection is a pure, order-independent
    set-narrowing operation.

These tests use Hypothesis to generate sets of DiscoveryResultEx records
spanning varied status codes, sizes, words, lines, elapsed times, and body
text; matcher and filter sets covering response-body regex predicates and
numeric Bounds across equality (==), inclusive range, >, >=, <, <=; and an
optional status filter (class token or explicit codes). The retained set is
compared against an independently-computed conjunction oracle (Requirement
22.7), and idempotence is asserted (Requirement 22.10).
"""

import re

from hypothesis import given, settings, strategies as st
from hypothesis.strategies import composite

from utils.discovery_session import (
    DiscoveryResult,
    StatusFilter,
    status_code_class,
)
from utils.response_selector import (
    Bound,
    DiscoveryResultEx,
    ResponseSelector,
    apply_selectors,
)


# ---------------------------------------------------------------------------
# Independent conjunction oracle
#
# Re-implemented here from the acceptance criteria so the assertion is a real
# cross-check rather than a tautology against the code under test.
# ---------------------------------------------------------------------------

def _oracle_status(status_filter, result):
    """Mirror apply_status_filter semantics for a single record."""
    if status_filter is None:
        return True
    if status_filter.status_class is not None:
        return status_code_class(result.status_code) == status_filter.status_class
    codes = status_filter.codes or frozenset()
    return result.status_code in codes


def _oracle_bound(bound, value):
    """Mirror Bound.test semantics independently."""
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


def _oracle_selector(selector, ex):
    """Independently evaluate whether a record satisfies a selector."""
    if selector.status is not None and not _oracle_status(
        selector.status, ex.result
    ):
        return False
    if selector.size is not None and not _oracle_bound(selector.size, ex.size):
        return False
    if selector.words is not None and not _oracle_bound(selector.words, ex.words):
        return False
    if selector.lines is not None and not _oracle_bound(selector.lines, ex.lines):
        return False
    if selector.time is not None and not _oracle_bound(selector.time, ex.elapsed):
        return False
    if selector.regex is not None and selector.regex.search(ex.text) is None:
        return False
    return True


def _oracle_apply(records, matchers, filters, status_filter):
    """Independently compute the conjunctive retained set (Requirement 22.7)."""
    retained = []
    for record in records:
        if not _oracle_status(status_filter, record.result):
            continue
        if not all(_oracle_selector(m, record) for m in matchers):
            continue
        if any(_oracle_selector(f, record) for f in filters):
            continue
        retained.append(record)
    return retained


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]
ENDPOINT_STATUSES = ["valid", "auth_required", "redirect", "not_found", "unknown"]

# Small alphabet so regex predicates actually match a meaningful fraction of
# generated bodies, exercising both branches of the regex predicate.
_TEXT_ALPHABET = "ab \n"

# Simple, always-valid regex patterns spanning literal, alternation, anchors,
# repetition and a class -- broad enough to hit and miss the bounded bodies.
_REGEX_PATTERNS = ["a", "b", "ab", "a+", "^a", "b$", "[ab]", "a.b", "aa"]

# Numeric values for records are kept small and overlapping with bound values so
# matchers/filters retain and drop records in roughly balanced proportions.
_NUM = st.integers(min_value=0, max_value=20)


@composite
def discovery_result_ex_strategy(draw):
    """Generate one DiscoveryResultEx with broad attribute coverage.

    Status codes span the 2xx-5xx classes plus out-of-class values (1xx and
    >599) so both the class-token and explicit-code status filters are
    exercised, including records that belong to no class.
    """
    status_code = draw(
        st.one_of(
            st.integers(min_value=200, max_value=599),
            st.integers(min_value=100, max_value=199),
            st.integers(min_value=600, max_value=799),
        )
    )
    result = DiscoveryResult(
        url=draw(st.text(min_size=0, max_size=30)),
        method=draw(st.sampled_from(HTTP_METHODS)),
        status_code=status_code,
        endpoint_status=draw(st.sampled_from(ENDPOINT_STATUSES)),
    )
    return DiscoveryResultEx(
        result=result,
        size=draw(_NUM),
        words=draw(_NUM),
        lines=draw(_NUM),
        elapsed=draw(st.floats(min_value=0.0, max_value=20.0)),
        text=draw(st.text(alphabet=_TEXT_ALPHABET, min_size=0, max_size=12)),
    )


@composite
def bound_strategy(draw):
    """Generate a numeric Bound spanning ==, >, >=, <, <=, and range."""
    op = draw(st.sampled_from(["==", ">", ">=", "<", "<=", "range"]))
    lo = float(draw(st.integers(min_value=0, max_value=20)))
    if op == "range":
        hi = lo + float(draw(st.integers(min_value=0, max_value=10)))
        return Bound(op="range", lo=lo, hi=hi)
    return Bound(op=op, lo=lo)


@composite
def status_filter_strategy(draw):
    """Generate a StatusFilter: either a class token or explicit codes."""
    if draw(st.booleans()):
        return StatusFilter(status_class=draw(st.sampled_from(["2xx", "3xx", "4xx", "5xx"])))
    codes = draw(
        st.frozensets(
            st.integers(min_value=100, max_value=599), min_size=1, max_size=5
        )
    )
    return StatusFilter(codes=codes)


@composite
def selector_strategy(draw):
    """Generate a single ResponseSelector over one response attribute.

    Covers numeric Bounds on size/words/lines/time, a response-body regex
    predicate, and a status predicate -- the full matcher/filter grammar.
    """
    kind = draw(
        st.sampled_from(["size", "words", "lines", "time", "regex", "status"])
    )
    if kind == "regex":
        return ResponseSelector(regex=re.compile(draw(st.sampled_from(_REGEX_PATTERNS))))
    if kind == "status":
        return ResponseSelector(status=draw(status_filter_strategy()))
    return ResponseSelector(**{kind: draw(bound_strategy())})


@given(
    records=st.lists(discovery_result_ex_strategy(), min_size=0, max_size=30),
    matchers=st.lists(selector_strategy(), min_size=0, max_size=4),
    filters=st.lists(selector_strategy(), min_size=0, max_size=4),
    status_filter=st.one_of(st.none(), status_filter_strategy()),
)
@settings(max_examples=300, deadline=5000)
def test_conjunctive_selection_and_idempotence(records, matchers, filters, status_filter):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 12: Response
    matcher/filter idempotence and conjunctive selection**
    **Validates: Requirements 22.10, 22.2, 22.3, 22.4, 22.7**

    FOR ALL generated record sets S, matcher sets M, filter sets F, and status
    filters Q:
      - apply_selectors(S, M, F, Q) retains exactly the records that satisfy Q
        AND every matcher in M AND no filter in F (conjunction, Requirement
        22.7), as computed by an independent oracle; and
      - applying the selection twice retains the same set as applying it once
        (idempotence, Requirement 22.10).
    """
    once = apply_selectors(records, matchers, filters, status_filter)

    # Conjunction (22.7): retained set equals the independently-computed
    # status AND every-matcher AND no-filter conjunction, order preserved.
    expected = _oracle_apply(records, matchers, filters, status_filter)
    assert once == expected

    # Retained set is a subset of the input preserving relative order.
    assert all(r in records for r in once)
    input_index = {id(r): i for i, r in enumerate(records)}
    indices = [input_index[id(r)] for r in once]
    assert indices == sorted(indices)

    # Idempotence (22.10): a second application is a no-op.
    twice = apply_selectors(once, matchers, filters, status_filter)
    assert twice == once


def test_no_selectors_retains_every_record():
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 12: Response
    matcher/filter idempotence (identity case)**
    **Validates: Requirements 22.7, 22.10**

    With no matchers, no filters, and no status filter every record is retained
    in its original order.
    """
    records = [
        DiscoveryResultEx(
            result=DiscoveryResult(
                url=f"https://example.test/{i}",
                method="GET",
                status_code=200 + i,
                endpoint_status="valid",
            ),
            size=i,
            words=i,
            lines=i,
            elapsed=float(i),
            text="ab" * i,
        )
        for i in range(5)
    ]
    assert apply_selectors(records, [], [], None) == records


def test_empty_record_set_yields_empty_result():
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 12: Response
    matcher/filter idempotence (empty input)**
    **Validates: Requirements 22.7, 22.10**

    Selecting over an empty record set yields an empty result regardless of the
    matchers, filters, or status filter applied.
    """
    matchers = [ResponseSelector(size=Bound(op=">", lo=10.0))]
    filters = [ResponseSelector(words=Bound(op="<", lo=5.0))]
    status_filter = StatusFilter(status_class="2xx")
    assert apply_selectors([], matchers, filters, status_filter) == []
