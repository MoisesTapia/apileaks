"""
Property-Based Tests for Status-Class Partition and Filter Completeness

**Feature: owasp-complete-purple-teaming-cicd, Property 8: Status-class
partition and filter completeness**

Property 8 (from design.md):
    FOR ALL lists of DiscoveryResult records, group_by_status_class places every
    record whose status code has a leading digit of 2, 3, 4, or 5 into exactly
    one group -- the group whose leading digit equals the record's -- and places
    every record whose leading digit is not 2/3/4/5 (e.g. 1xx) into no group;
    the sum of the four group sizes equals the count of retained records.
    Furthermore, for any class filter the retained records are exactly those
    whose leading digit matches the class, and for any explicit-code filter the
    retained records are exactly those whose status code equals a value in the
    filter set.

These tests use Hypothesis to generate arbitrary lists of DiscoveryResult
records spanning status codes across the full range (including 1xx and beyond),
then assert the partition and filter completeness properties.

**Validates: Requirements 13.1, 13.2, 13.3, 13.7, 13.8**
"""

from collections import Counter

from hypothesis import given, settings, strategies as st
from hypothesis.strategies import composite

from utils.discovery_session import (
    STATUS_CLASSES,
    DiscoveryResult,
    StatusFilter,
    apply_status_filter,
    group_by_status_class,
    parse_status_filter,
)


HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]

ENDPOINT_STATUSES = [
    "valid",
    "auth_required",
    "redirect",
    "not_found",
    "server_error",
    "unknown",
]


@composite
def discovery_result_strategy(draw):
    """Generate a single DiscoveryResult with broad status-code coverage.

    Status codes intentionally span the full range from 0 to 799, so the
    generated lists include 1xx codes and codes beyond 5xx (which must land in
    no status-class group), alongside the canonical 2xx-5xx codes.
    """
    url = draw(st.text(min_size=0, max_size=80))
    method = draw(st.sampled_from(HTTP_METHODS))
    # Span 1xx-5xx and beyond: include sub-100, 1xx, and >599 codes.
    status_code = draw(st.integers(min_value=0, max_value=799))
    endpoint_status = draw(st.sampled_from(ENDPOINT_STATUSES))

    return DiscoveryResult(
        url=url,
        method=method,
        status_code=status_code,
        endpoint_status=endpoint_status,
    )


@given(records=st.lists(discovery_result_strategy(), min_size=0, max_size=60))
@settings(max_examples=200, deadline=5000)
def test_group_by_status_class_partitions_retained_records(records):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 8: Status-class
    partition and filter completeness**
    **Validates: Requirements 13.1, 13.2, 13.3**

    group_by_status_class always exposes the four classes in ascending order;
    every 2/3/4/5-leading-digit record lands in exactly one group (the matching
    one), non-2/3/4/5 codes land in no group, and group sizes sum to the count
    of retained records.
    """
    grouped = group_by_status_class(records)

    # The four keys are always present, in fixed ascending order (13.1).
    assert tuple(grouped.keys()) == STATUS_CLASSES
    assert STATUS_CLASSES == ("2xx", "3xx", "4xx", "5xx")

    retained = [r for r in records if r.status_code // 100 in (2, 3, 4, 5)]
    dropped = [r for r in records if r.status_code // 100 not in (2, 3, 4, 5)]

    # Each retained record lands in exactly its matching ascending group (13.2),
    # and only there. We verify membership counts via multisets to handle
    # duplicate records correctly.
    for status_class, group in grouped.items():
        lead = int(status_class[0])
        expected = [r for r in retained if r.status_code // 100 == lead]
        assert Counter(group) == Counter(expected)

    # Records whose leading digit is not 2/3/4/5 land in no group (13.3).
    all_grouped = [r for group in grouped.values() for r in group]
    for record in dropped:
        assert record not in all_grouped

    # Group sizes sum to the count of retained records (no record duplicated or
    # lost across groups).
    total_grouped = sum(len(group) for group in grouped.values())
    assert total_grouped == len(retained)

    # The union of the groups is exactly the retained multiset.
    assert Counter(all_grouped) == Counter(retained)


@given(
    records=st.lists(discovery_result_strategy(), min_size=0, max_size=60),
    status_class=st.sampled_from(STATUS_CLASSES),
)
@settings(max_examples=200, deadline=5000)
def test_class_filter_retains_exactly_matching_leading_digit(records, status_class):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 8: Status-class
    partition and filter completeness**
    **Validates: Requirements 13.7**

    A class filter (parsed via parse_status_filter) retains exactly the records
    whose status-code leading digit matches the class, in original order.
    """
    status_filter = parse_status_filter(status_class)
    assert isinstance(status_filter, StatusFilter)
    assert status_filter.status_class == status_class

    retained = apply_status_filter(records, status_filter)

    lead = int(status_class[0])
    expected = [r for r in records if r.status_code // 100 == lead]

    # Exact subset, preserving original relative order.
    assert retained == expected


@composite
def code_filter_strategy(draw):
    """Generate a set of explicit status codes within the valid 100-599 range.

    parse_status_filter validates explicit codes to the inclusive 100-599 range,
    so we draw codes from that range to exercise the explicit-code filter path.
    """
    codes = draw(
        st.lists(st.integers(min_value=100, max_value=599), min_size=1, max_size=8)
    )
    return sorted(set(codes))


@given(
    records=st.lists(discovery_result_strategy(), min_size=0, max_size=60),
    codes=code_filter_strategy(),
)
@settings(max_examples=200, deadline=5000)
def test_explicit_code_filter_retains_exactly_codes_in_set(records, codes):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 8: Status-class
    partition and filter completeness**
    **Validates: Requirements 13.8**

    An explicit-code filter (parsed via parse_status_filter from a comma-joined
    code list) retains exactly the records whose status code is in the set, in
    original order.
    """
    raw = ",".join(str(code) for code in codes)
    status_filter = parse_status_filter(raw)
    assert isinstance(status_filter, StatusFilter)
    assert status_filter.status_class is None
    assert status_filter.codes == frozenset(codes)

    retained = apply_status_filter(records, status_filter)

    code_set = set(codes)
    expected = [r for r in records if r.status_code in code_set]

    # Exact subset, preserving original relative order.
    assert retained == expected
