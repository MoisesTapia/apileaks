"""
Property-Based Tests for the CI/CD Baseline Comparator

**Feature: owasp-complete-purple-teaming-cicd**

Validates two correctness properties of ``utils.baseline.BaselineComparator``
from design.md:

Property 2 (Baseline idempotence, Requirement 11.6):
    FOR ALL finding sets ``R``, ``BaselineComparator.classify(R,
    baseline=keys(R))`` produces an empty New_Finding list. Comparing a result
    set against a baseline derived from that same set yields zero new findings.

Property 3 (Baseline partition completeness, Requirements 11.1, 11.2, 11.3):
    FOR ALL finding sets ``R`` and baselines ``B``, the returned
    ``(new, known)`` lists partition ``R``: every finding is in exactly one
    list and ``len(new) + len(known) == len(R)``.

These tests use Hypothesis to generate arbitrary Finding sets and baselines,
mirroring the established style in
``tests/test_property_level_auth_properties.py`` and
``tests/test_severity_gate_properties.py``.
"""

from uuid import uuid4

import pytest
from hypothesis import given, settings, strategies as st
from hypothesis.strategies import composite

from core.config import Severity
from utils.findings import Finding
from utils.baseline import BaselineComparator, FindingKey


# Constrained input spaces so generated keys collide often enough to exercise
# both the "new" and "known" branches of classify().
CATEGORIES = [
    "BOLA_ANONYMOUS_ACCESS",
    "AUTH_BYPASS",
    "MASS_ASSIGNMENT",
    "CORS_MISCONFIGURATION",
    "MISSING_RATE_LIMITING",
    "ENDPOINT_DISCOVERED",
]
ENDPOINTS = ["/users", "/users/{id}", "/admin", "/orders", "/login", "/héllo/世界"]
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]


@composite
def finding_strategy(draw):
    """Generate a valid :class:`~utils.findings.Finding`.

    Category, endpoint, and method are drawn from small constrained pools so
    that distinct findings frequently share a :class:`FindingKey`, which lets
    the property tests exercise both new and known classifications. All other
    fields are filled with plausible values.
    """
    category = draw(st.sampled_from(CATEGORIES))
    endpoint = draw(st.sampled_from(ENDPOINTS))
    method = draw(st.sampled_from(METHODS))
    severity = draw(st.sampled_from(list(Severity)))

    return Finding(
        id=str(uuid4()),
        scan_id="scan-test",
        category=category,
        owasp_category=None,
        severity=severity,
        endpoint=endpoint,
        method=method,
        status_code=draw(st.integers(min_value=100, max_value=599)),
        response_size=draw(st.integers(min_value=0, max_value=100000)),
        response_time=draw(st.floats(min_value=0.0, max_value=30.0,
                                     allow_nan=False, allow_infinity=False)),
        evidence=draw(st.text(min_size=0, max_size=50)),
        recommendation=draw(st.text(min_size=0, max_size=50)),
    )


@composite
def findings_list_strategy(draw):
    """Generate a list of Findings, including the empty list."""
    return draw(st.lists(finding_strategy(), min_size=0, max_size=15))


@composite
def baseline_strategy(draw):
    """Generate an arbitrary baseline of :class:`FindingKey` values.

    Keys are drawn from the same constrained pools as findings so the baseline
    overlaps the generated finding sets with reasonable frequency.
    """
    return draw(
        st.sets(
            st.builds(
                FindingKey,
                category=st.sampled_from(CATEGORIES),
                endpoint=st.sampled_from(ENDPOINTS),
                method=st.sampled_from(METHODS),
            ),
            min_size=0,
            max_size=10,
        )
    )


@given(findings=findings_list_strategy())
@settings(max_examples=300, deadline=5000)
def test_baseline_idempotence_yields_no_new_findings(findings):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 2: Baseline
    idempotence**
    **Validates: Requirements 11.6**

    FOR ALL finding sets R, classifying R against a baseline derived from R's
    own keys produces an empty New_Finding list, and every finding is reported
    as known.
    """
    comparator = BaselineComparator()
    baseline = {comparator.key(f) for f in findings}

    new_findings, known_findings = comparator.classify(findings, baseline)

    # No finding can be new when the baseline is derived from the set itself.
    assert new_findings == []
    # Every finding is therefore classified as known.
    assert len(known_findings) == len(findings)


@given(findings=findings_list_strategy(), baseline=baseline_strategy())
@settings(max_examples=300, deadline=5000)
def test_classify_partitions_findings_completely(findings, baseline):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 3: Baseline
    partition completeness**
    **Validates: Requirements 11.1, 11.2, 11.3**

    FOR ALL finding sets R and baselines B, the returned (new, known) lists
    partition R: their lengths sum to len(R), every input finding appears in
    exactly one list, and no finding is invented or dropped.
    """
    comparator = BaselineComparator()

    new_findings, known_findings = comparator.classify(findings, baseline)

    # Lengths sum to the input size (completeness).
    assert len(new_findings) + len(known_findings) == len(findings)

    # The two lists are disjoint by object identity (exactly-one membership).
    new_ids = [id(f) for f in new_findings]
    known_ids = [id(f) for f in known_findings]
    assert set(new_ids).isdisjoint(known_ids)

    # The union reproduces exactly the input findings (nothing added/dropped).
    combined_ids = sorted(new_ids + known_ids)
    assert combined_ids == sorted(id(f) for f in findings)

    # Classification matches baseline membership for each finding.
    for finding in new_findings:
        assert comparator.key(finding) not in baseline
    for finding in known_findings:
        assert comparator.key(finding) in baseline


# ---------------------------------------------------------------------------
# Representative example-based cases pinning the documented behaviour.
# ---------------------------------------------------------------------------


def _make_finding(category, endpoint, method):
    return Finding(
        id=str(uuid4()),
        scan_id="scan-test",
        category=category,
        owasp_category=None,
        severity=Severity.HIGH,
        endpoint=endpoint,
        method=method,
        status_code=200,
        response_size=0,
        response_time=0.0,
        evidence="",
        recommendation="",
    )


def test_empty_baseline_makes_all_findings_new():
    """
    **Validates: Requirements 11.1, 11.3**

    With an empty baseline every finding is a New_Finding.
    """
    comparator = BaselineComparator()
    findings = [
        _make_finding("AUTH_BYPASS", "/login", "POST"),
        _make_finding("MASS_ASSIGNMENT", "/users", "PUT"),
    ]

    new_findings, known_findings = comparator.classify(findings, set())

    assert len(new_findings) == 2
    assert known_findings == []


def test_self_baseline_makes_all_findings_known():
    """
    **Validates: Requirement 11.6**

    Classifying findings against their own keys yields zero new findings.
    """
    comparator = BaselineComparator()
    findings = [
        _make_finding("AUTH_BYPASS", "/login", "POST"),
        _make_finding("CORS_MISCONFIGURATION", "/admin", "GET"),
    ]
    baseline = {comparator.key(f) for f in findings}

    new_findings, known_findings = comparator.classify(findings, baseline)

    assert new_findings == []
    assert len(known_findings) == 2


def test_partial_baseline_splits_new_and_known():
    """
    **Validates: Requirements 11.2, 11.3**

    Only findings whose (category, endpoint, method) key is in the baseline are
    known; the rest are new.
    """
    comparator = BaselineComparator()
    known = _make_finding("AUTH_BYPASS", "/login", "POST")
    introduced = _make_finding("MASS_ASSIGNMENT", "/users", "PUT")

    baseline = {comparator.key(known)}
    new_findings, known_findings = comparator.classify([known, introduced], baseline)

    assert known_findings == [known]
    assert new_findings == [introduced]
