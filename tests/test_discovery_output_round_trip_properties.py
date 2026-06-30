"""
Property-Based Tests for Machine-Readable Output Round-Trip Count

**Feature: owasp-complete-purple-teaming-cicd, Property 16: Machine-readable
output round-trip count**

Property 16 (from design.md):
    FOR ALL sets of DiscoveryResult records S (including the empty set) and for
    BOTH supported machine-readable output formats (``.csv`` and ``.jsonl``),
    parsing the Discovery_Output_File produced by
    write_discovery_output(records, path) yields exactly len(S) records -- the
    parsed record count equals the input record count, with no record added or
    omitted (count preservation, including zero).

These tests use Hypothesis to generate arbitrary lists of DiscoveryResult
records (including the empty list) spanning status codes 1xx-5xx and beyond,
varied HTTP methods, and unicode URLs. The records the output module appends
after the grouped 2xx-5xx records are exactly those with status codes outside
the 2xx-5xx range (e.g. 1xx/6xx/7xx), so the generator deliberately produces
those codes as well. For each generated list we write both a ``.csv`` and a
``.jsonl`` output file, parse the file back with the appropriate parser, and
assert that the parsed record count equals the number of input records.

The CSV writer in ``utils/discovery_output.py`` uses ``csv.QUOTE_MINIMAL`` with
``newline=""``, so embedded newlines/commas in a URL are quoted and round-trip
correctly under the ``csv`` module -- we count parsed CSV rows (not raw physical
lines). For JSONL, ``json.dumps`` escapes newlines within the JSON string so
each record stays on exactly one physical line -- we count non-empty lines.
"""

import csv
import json
import tempfile
from pathlib import Path

from hypothesis import given, settings, strategies as st
from hypothesis.strategies import composite

from utils.discovery_output import write_discovery_output
from utils.discovery_session import DiscoveryResult


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
    100 and above 599) so the output round-trip is exercised for records that
    fall into a 2xx-5xx group as well as records that are appended afterwards
    (1xx/6xx/7xx). URLs draw from the full unicode space -- including empty
    strings and text containing commas and newlines -- to confirm the parsed
    record count is correct even when a field contains the CSV delimiter or a
    line break.
    """
    url = draw(st.text(min_size=0, max_size=120))
    method = draw(st.sampled_from(HTTP_METHODS))
    # 1xx-5xx and beyond: deliberately include sub-100 and >599 codes so the
    # appended (unclassified) records are exercised.
    status_code = draw(st.integers(min_value=0, max_value=799))
    endpoint_status = draw(st.sampled_from(ENDPOINT_STATUSES))

    return DiscoveryResult(
        url=url,
        method=method,
        status_code=status_code,
        endpoint_status=endpoint_status,
    )


def _count_csv_records(path: str) -> int:
    """Return the number of data rows (excluding the header) in a CSV file.

    Uses :class:`csv.DictReader` so quoted fields containing embedded newlines
    or commas are parsed as a single row -- never counted as extra rows.
    """
    with open(path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return sum(1 for _ in reader)


def _count_jsonl_records(path: str) -> int:
    """Return the number of JSON objects in a JSON Lines file.

    Counts non-empty lines and confirms each parses as JSON via
    :func:`json.loads`.
    """
    count = 0
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            json.loads(line)  # confirm each record is valid JSON
            count += 1
    return count


@given(records=st.lists(discovery_result_strategy(), min_size=0, max_size=50))
@settings(max_examples=200, deadline=5000)
def test_csv_output_round_trip_count(records):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 16: Machine-readable
    output round-trip count (CSV)**
    **Validates: Requirements 31.6**

    FOR ALL generated lists of DiscoveryResult records (including the empty
    list), writing a ``.csv`` Discovery_Output_File and parsing it back yields a
    data-row count equal to the number of input records -- no record added or
    omitted.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        path = str(Path(tmp_dir) / "discovery_output.csv")
        write_discovery_output(records, path)
        parsed_count = _count_csv_records(path)

    assert parsed_count == len(records)


@given(records=st.lists(discovery_result_strategy(), min_size=0, max_size=50))
@settings(max_examples=200, deadline=5000)
def test_jsonl_output_round_trip_count(records):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 16: Machine-readable
    output round-trip count (JSONL)**
    **Validates: Requirements 31.6**

    FOR ALL generated lists of DiscoveryResult records (including the empty
    list), writing a ``.jsonl`` Discovery_Output_File and parsing it back yields
    a line count equal to the number of input records -- no record added or
    omitted.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        path = str(Path(tmp_dir) / "discovery_output.jsonl")
        write_discovery_output(records, path)
        parsed_count = _count_jsonl_records(path)

    assert parsed_count == len(records)


def test_empty_csv_output_round_trip(tmp_path):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 16: Machine-readable
    output round-trip count (empty set, CSV)**
    **Validates: Requirements 31.6**

    Writing an empty record list to a ``.csv`` file and parsing it back yields
    zero data rows.
    """
    path = str(tmp_path / "empty_output.csv")
    write_discovery_output([], path)

    assert _count_csv_records(path) == 0


def test_empty_jsonl_output_round_trip(tmp_path):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 16: Machine-readable
    output round-trip count (empty set, JSONL)**
    **Validates: Requirements 31.6**

    Writing an empty record list to a ``.jsonl`` file and parsing it back yields
    zero records.
    """
    path = str(tmp_path / "empty_output.jsonl")
    write_discovery_output([], path)

    assert _count_jsonl_records(path) == 0


def test_unicode_url_csv_output_round_trip(tmp_path):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 16: Machine-readable
    output round-trip count (unicode URLs, CSV)**
    **Validates: Requirements 31.6**

    Records with unicode URLs (including one with an embedded comma and one with
    an embedded newline) and a status code outside the 2xx-5xx range round-trip
    to the correct parsed row count in CSV.
    """
    records = [
        DiscoveryResult(
            url="https://例え.test/路径/✓?q=ñ",
            method="POST",
            status_code=799,
            endpoint_status="unknown",
        ),
        DiscoveryResult(
            url="https://例え.test/a,b,c",  # embedded CSV delimiter
            method="GET",
            status_code=200,
            endpoint_status="valid",
        ),
        DiscoveryResult(
            url="https://例え.test/line1\nline2",  # embedded newline
            method="GET",
            status_code=101,  # 1xx: appended after grouped records
            endpoint_status="unknown",
        ),
    ]

    path = str(tmp_path / "unicode_output.csv")
    write_discovery_output(records, path)

    assert _count_csv_records(path) == len(records)


def test_unicode_url_jsonl_output_round_trip(tmp_path):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 16: Machine-readable
    output round-trip count (unicode URLs, JSONL)**
    **Validates: Requirements 31.6**

    Records with unicode URLs (including one with an embedded newline) and a
    status code outside the 2xx-5xx range round-trip to the correct parsed line
    count in JSONL.
    """
    records = [
        DiscoveryResult(
            url="https://例え.test/路径/✓?q=ñ",
            method="POST",
            status_code=799,
            endpoint_status="unknown",
        ),
        DiscoveryResult(
            url="https://例え.test/line1\nline2",  # embedded newline
            method="GET",
            status_code=101,  # 1xx: appended after grouped records
            endpoint_status="unknown",
        ),
    ]

    path = str(tmp_path / "unicode_output.jsonl")
    write_discovery_output(records, path)

    assert _count_jsonl_records(path) == len(records)
