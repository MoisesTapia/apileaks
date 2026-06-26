"""
Property-Based Tests for Discovery Session Round-Trip Preservation

**Feature: owasp-complete-purple-teaming-cicd, Property 7: Discovery session
round-trip preservation**

Property 7 (from design.md):
    FOR ALL sets of DiscoveryResult records S (including the empty set),
    DiscoverySession.load(path) after DiscoverySession(...).save(path) yields a
    set of DiscoveryResult records equal to S -- same count and same per-record
    fields (url, method, status_code, endpoint_status), with no record added or
    omitted.

These tests use Hypothesis to generate arbitrary lists of DiscoveryResult
records (including the empty list) spanning status codes 1xx-5xx and beyond,
varied HTTP methods, and unicode URLs, then assert that saving the session to a
file and loading it back reproduces exactly the same records.
"""

import tempfile
from collections import Counter
from pathlib import Path

from hypothesis import given, settings, strategies as st
from hypothesis.strategies import composite

from utils.discovery_session import DiscoveryResult, DiscoverySession


# Varied HTTP methods, including a couple of less common ones.
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]

# EndpointStatus string values projected into DiscoveryResult.endpoint_status.
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
    """Generate a single DiscoveryResult with broad field coverage.

    Status codes intentionally span 1xx-5xx and beyond (including values below
    100 and above 599) so the round-trip is exercised outside the canonical HTTP
    range. URLs draw from the full unicode space to confirm non-ASCII text is
    preserved across the JSON save/load boundary.
    """
    url = draw(st.text(min_size=0, max_size=120))
    method = draw(st.sampled_from(HTTP_METHODS))
    # 1xx-5xx and beyond: deliberately include sub-100 and >599 codes.
    status_code = draw(st.integers(min_value=0, max_value=799))
    endpoint_status = draw(st.sampled_from(ENDPOINT_STATUSES))

    return DiscoveryResult(
        url=url,
        method=method,
        status_code=status_code,
        endpoint_status=endpoint_status,
    )


@given(results=st.lists(discovery_result_strategy(), min_size=0, max_size=50))
@settings(max_examples=200, deadline=5000)
def test_discovery_session_round_trip_preservation(results):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 7: Discovery session
    round-trip preservation**
    **Validates: Requirements 14.8, 14.1**

    FOR ALL generated lists of DiscoveryResult records (including the empty
    list), saving a DiscoverySession to a JSON file and loading it back yields a
    set of records equal to the original -- same count and same per-record
    fields -- with no record added or omitted.
    """
    session = DiscoverySession(
        target="https://example.test",
        timestamp="2024-01-01T00:00:00Z",
        tool_version="test",
        results=list(results),
    )

    # Use a fresh temporary directory per generated example (a function-scoped
    # fixture is not reset between Hypothesis inputs).
    with tempfile.TemporaryDirectory() as tmp_dir:
        path = str(Path(tmp_dir) / "session.json")
        session.save(path)
        loaded = DiscoverySession.load(path)

    # Count is preserved exactly (no record added or omitted).
    assert len(loaded.results) == len(results)

    # Multiset equality: same per-record fields with the same multiplicities.
    # DiscoveryResult is a frozen dataclass, so it is hashable and compares by
    # its four fields (url, method, status_code, endpoint_status).
    assert Counter(loaded.results) == Counter(results)


def test_empty_discovery_session_round_trip(tmp_path):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 7: Discovery session
    round-trip preservation (empty set)**
    **Validates: Requirements 14.8, 14.1**

    Saving an empty DiscoverySession and loading it back yields zero records.
    """
    session = DiscoverySession(
        target="https://example.test",
        timestamp="2024-01-01T00:00:00Z",
        tool_version="test",
        results=[],
    )

    path = str(tmp_path / "empty_session.json")
    session.save(path)
    loaded = DiscoverySession.load(path)

    assert loaded.results == []


def test_unicode_url_round_trip(tmp_path):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 7: Discovery session
    round-trip preservation (unicode URLs)**
    **Validates: Requirements 14.8, 14.1**

    A record with a unicode URL and a status code outside the 1xx-5xx range is
    preserved exactly across save/load.
    """
    record = DiscoveryResult(
        url="https://例え.test/路径/✓?q=ñ",
        method="POST",
        status_code=799,
        endpoint_status="unknown",
    )
    session = DiscoverySession(
        target="https://例え.test",
        timestamp="2024-01-01T00:00:00Z",
        tool_version="test",
        results=[record],
    )

    path = str(tmp_path / "unicode_session.json")
    session.save(path)
    loaded = DiscoverySession.load(path)

    assert loaded.results == [record]
