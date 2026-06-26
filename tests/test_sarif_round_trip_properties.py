"""
Property-Based Tests for SARIF Round-Trip Count Preservation

**Feature: owasp-complete-purple-teaming-cicd, Property 1: SARIF round-trip
count preservation**

Property 1 (from design.md):
    FOR ALL scan result sets R, parse(SARIFFormatter.format(R)).result_count
    == len(R.findings) -- including the empty set (zero findings -> zero
    results).

These tests use Hypothesis to generate arbitrary sets of Finding objects and
assert that the number of SARIF results produced (both as a dict and after a
full JSON serialize/parse round-trip) always equals the number of findings fed
in, never adding, dropping, or merging entries.
"""

import json

import pytest
from hypothesis import given, settings, strategies as st
from hypothesis.strategies import composite

from core.config import Severity
from utils.findings import Finding
from utils.sarif_formatter import SARIFFormatter


# Real finding categories drawn from the FindingsCollector severity/OWASP maps.
CATEGORIES = [
    "SSRF_INTERNAL_ACCESS",
    "FILE_PROTOCOL_ACCESS",
    "BUSINESS_FLOW_NO_LIMIT",
    "CORS_MISCONFIGURATION",
    "MISSING_SECURITY_HEADERS",
    "DEPRECATED_API_VERSION",
    "UNDOCUMENTED_API_VERSION",
    "UNSAFE_UPSTREAM_DATA",
]

OWASP_CATEGORIES = [f"API{i}" for i in range(1, 11)]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

VALID_LEVELS = {"error", "warning", "note"}


@composite
def finding_strategy(draw):
    """Generate a syntactically valid Finding the SARIFFormatter can consume."""
    return Finding(
        id="",
        scan_id="",
        category=draw(st.sampled_from(CATEGORIES)),
        owasp_category=draw(st.one_of(st.none(), st.sampled_from(OWASP_CATEGORIES))),
        severity=draw(st.sampled_from(list(Severity))),
        endpoint=draw(st.text(min_size=1, max_size=80)),
        method=draw(st.sampled_from(HTTP_METHODS)),
        status_code=draw(st.integers(min_value=100, max_value=599)),
        response_size=draw(st.integers(min_value=0, max_value=10_000_000)),
        response_time=draw(
            st.floats(min_value=0.0, max_value=600.0, allow_nan=False, allow_infinity=False)
        ),
        evidence=draw(st.text(min_size=0, max_size=200)),
        recommendation=draw(st.text(min_size=0, max_size=200)),
    )


@given(findings=st.lists(finding_strategy(), min_size=0, max_size=50))
@settings(max_examples=200, deadline=5000)
def test_round_trip_count_preservation(findings):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 1: SARIF round-trip
    count preservation**
    **Validates: Requirements 8.6, 8.2, 8.5**

    FOR ALL generated finding sets, formatting to SARIF (as a dict and through a
    full JSON serialize/parse round-trip) yields exactly one result per finding,
    including the zero-finding case.
    """
    formatter = SARIFFormatter()

    # Direct dict form.
    doc = formatter.format(findings)
    results = doc["runs"][0]["results"]
    assert len(results) == len(findings)

    # Full JSON round-trip.
    parsed = json.loads(formatter.to_json(findings))
    parsed_results = parsed["runs"][0]["results"]
    assert len(parsed_results) == len(findings)


def test_empty_findings_zero_results():
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 1: SARIF round-trip
    count preservation (empty set)**
    **Validates: Requirements 8.5, 8.6**

    Formatting an empty finding set yields a valid SARIF 2.1.0 document with zero
    results, both as a dict and through a JSON round-trip.
    """
    formatter = SARIFFormatter()

    doc = formatter.format([])
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []

    parsed = json.loads(formatter.to_json([]))
    assert parsed["version"] == "2.1.0"
    assert parsed["runs"][0]["results"] == []


@given(findings=st.lists(finding_strategy(), min_size=1, max_size=30))
@settings(max_examples=100, deadline=5000)
def test_each_result_has_required_fields(findings):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 1: SARIF result
    well-formedness**
    **Validates: Requirements 8.2, 8.5, 8.6**

    FOR ALL generated finding sets, every emitted SARIF result carries the
    required location URI and properties, and a valid severity level.
    """
    formatter = SARIFFormatter()
    results = formatter.format(findings)["runs"][0]["results"]

    assert len(results) == len(findings)

    for result, finding in zip(results, findings):
        # Location URI is derived from the finding endpoint.
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == finding.endpoint

        # Properties carry method + owasp category.
        assert result["properties"]["method"] == finding.method
        assert result["properties"]["owaspCategory"] == finding.owasp_category

        # A ruleId is always present (owasp category or falling back to category).
        assert result["ruleId"]

        # Level is one of the valid SARIF result levels.
        assert result["level"] in VALID_LEVELS
