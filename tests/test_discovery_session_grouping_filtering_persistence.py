"""
Unit tests for discovery-session grouping, filtering, and persistence edge cases.

**Feature: owasp-complete-purple-teaming-cicd, Task 15.5**

These example-based tests complement the property-based round-trip tests by
pinning down specific behaviours and error conditions:

- group ordering is exactly ``2xx, 3xx, 4xx, 5xx`` (Requirement 13.4) and a
  non-matching filter still yields four empty groups (Requirement 13.9)
- ``parse_status_filter`` accepts a class token and explicit codes/ranges and
  rejects out-of-range values, naming the offending value (Requirements 13.5,
  13.6)
- ``save`` writes every record (Requirement 14.1); an unwritable path returns a
  descriptive error leaving no partial file (Requirement 14.2); a missing path
  raises a not-found error (Requirement 14.9); corrupt/wrong-structure JSON
  raises an invalid-file error and loads zero records (Requirement 14.10)
"""

import json
import os
from unittest import mock

import pytest

from utils.discovery_session import (
    STATUS_CLASSES,
    DiscoveryResult,
    DiscoverySession,
    DiscoverySessionNotFoundError,
    DiscoverySessionWriteError,
    InvalidSessionFileError,
    apply_status_filter,
    group_by_status_class,
    parse_status_filter,
)


def _record(status_code: int, url: str = "https://api.example.com/x") -> DiscoveryResult:
    """Build a DiscoveryResult with the given status code."""
    return DiscoveryResult(
        url=url,
        method="GET",
        status_code=status_code,
        endpoint_status="valid",
    )


# ---------------------------------------------------------------------------
# Grouping (Requirements 13.4, 13.9)
# ---------------------------------------------------------------------------


def test_group_ordering_is_exactly_2xx_3xx_4xx_5xx():
    """Grouping always exposes the four classes in fixed ascending order (13.4)."""
    records = [_record(404), _record(200), _record(503), _record(301)]

    grouped = group_by_status_class(records)

    assert list(grouped.keys()) == ["2xx", "3xx", "4xx", "5xx"]
    assert list(grouped.keys()) == list(STATUS_CLASSES)
    # Records land in the class matching their leading digit.
    assert [r.status_code for r in grouped["2xx"]] == [200]
    assert [r.status_code for r in grouped["3xx"]] == [301]
    assert [r.status_code for r in grouped["4xx"]] == [404]
    assert [r.status_code for r in grouped["5xx"]] == [503]


def test_non_matching_filter_yields_four_empty_groups():
    """A filter matching no records still yields four empty groups (13.9)."""
    records = [_record(200), _record(201), _record(204)]

    # Filter for 5xx, which matches none of the 2xx records.
    status_filter = parse_status_filter("5xx")
    filtered = apply_status_filter(records, status_filter)
    assert filtered == []

    grouped = group_by_status_class(filtered)
    assert list(grouped.keys()) == ["2xx", "3xx", "4xx", "5xx"]
    assert all(grouped[status_class] == [] for status_class in STATUS_CLASSES)


# ---------------------------------------------------------------------------
# parse_status_filter (Requirements 13.5, 13.6)
# ---------------------------------------------------------------------------


def test_parse_status_filter_accepts_class_token():
    """A class token is parsed as a class filter (13.5)."""
    status_filter = parse_status_filter("4xx")

    assert status_filter is not None
    assert status_filter.status_class == "4xx"
    assert status_filter.codes is None


def test_parse_status_filter_class_token_is_case_insensitive():
    """Class tokens are accepted regardless of case (13.5)."""
    status_filter = parse_status_filter("5XX")

    assert status_filter is not None
    assert status_filter.status_class == "5xx"


def test_parse_status_filter_accepts_explicit_codes():
    """Explicit comma-separated codes are parsed as an explicit filter (13.5)."""
    status_filter = parse_status_filter("200,404")

    assert status_filter is not None
    assert status_filter.status_class is None
    assert status_filter.codes == frozenset({200, 404})


def test_parse_status_filter_accepts_explicit_range():
    """An explicit inclusive range is expanded into its codes (13.5)."""
    status_filter = parse_status_filter("200-300")

    assert status_filter is not None
    assert status_filter.status_class is None
    assert status_filter.codes == frozenset(range(200, 301))


@pytest.mark.parametrize("offending", [99, 600, 1000])
def test_parse_status_filter_rejects_out_of_range_value(offending):
    """Out-of-range codes raise ValueError naming the offending value (13.6)."""
    with pytest.raises(ValueError) as exc_info:
        parse_status_filter(str(offending))

    assert str(offending) in str(exc_info.value)


def test_parse_status_filter_empty_returns_none():
    """An empty/whitespace filter means no filtering."""
    assert parse_status_filter("") is None
    assert parse_status_filter("   ") is None


# ---------------------------------------------------------------------------
# save (Requirements 14.1, 14.2)
# ---------------------------------------------------------------------------


def test_save_writes_every_record(tmp_path):
    """save serializes every record; round-trip count is preserved (14.1)."""
    records = [_record(200, "https://api.example.com/a"),
               _record(301, "https://api.example.com/b"),
               _record(404, "https://api.example.com/c"),
               _record(500, "https://api.example.com/d")]
    session = DiscoverySession(
        target="https://api.example.com",
        timestamp="2024-01-01T00:00:00Z",
        tool_version="1.2.3",
        results=records,
    )
    path = str(tmp_path / "session.json")

    session.save(path)

    with open(path, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    assert len(document["results"]) == len(records)

    reloaded = DiscoverySession.load(path)
    assert len(reloaded.results) == len(records)
    assert reloaded.results == records


def test_save_unwritable_path_returns_error_and_leaves_no_partial_file(tmp_path):
    """An unwritable path raises a descriptive write error and leaves no temp file (14.2)."""
    session = DiscoverySession(
        target="https://api.example.com",
        timestamp="2024-01-01T00:00:00Z",
        tool_version="1.2.3",
        results=[_record(200)],
    )
    path = str(tmp_path / "session.json")
    tmp_file = f"{path}.tmp"

    # Simulate the final atomic move failing after the temp file is written.
    with mock.patch(
        "utils.discovery_session.os.replace",
        side_effect=OSError("permission denied"),
    ):
        with pytest.raises(DiscoverySessionWriteError) as exc_info:
            session.save(path)

    message = str(exc_info.value)
    assert path in message
    assert "permission denied" in message
    # No partial session file and no leftover temp file.
    assert not os.path.exists(path)
    assert not os.path.exists(tmp_file)


# ---------------------------------------------------------------------------
# load error handling (Requirements 14.9, 14.10)
# ---------------------------------------------------------------------------


def test_load_missing_path_raises_not_found(tmp_path):
    """Loading a non-existent path raises the not-found error (14.9)."""
    missing = str(tmp_path / "does_not_exist.json")

    with pytest.raises(DiscoverySessionNotFoundError) as exc_info:
        DiscoverySession.load(missing)

    assert missing in str(exc_info.value)


def test_load_corrupt_json_raises_invalid_file(tmp_path):
    """Unparseable JSON raises the invalid-file error with zero records loaded (14.10)."""
    path = tmp_path / "corrupt.json"
    path.write_text("{ this is not valid json", encoding="utf-8")

    with pytest.raises(InvalidSessionFileError):
        DiscoverySession.load(str(path))


def test_load_wrong_structure_json_raises_invalid_file(tmp_path):
    """Valid JSON with the wrong structure raises the invalid-file error (14.10)."""
    path = tmp_path / "wrong_structure.json"
    # Valid JSON object but missing the required 'results' array.
    path.write_text(json.dumps({"target": "x", "timestamp": "y"}), encoding="utf-8")

    with pytest.raises(InvalidSessionFileError):
        DiscoverySession.load(str(path))


def test_load_results_not_a_list_raises_invalid_file(tmp_path):
    """A 'results' value that is not an array raises the invalid-file error (14.10)."""
    path = tmp_path / "results_not_list.json"
    path.write_text(json.dumps({"results": "nope"}), encoding="utf-8")

    with pytest.raises(InvalidSessionFileError):
        DiscoverySession.load(str(path))


def test_load_malformed_record_raises_invalid_file(tmp_path):
    """A malformed record inside 'results' raises the invalid-file error (14.10)."""
    path = tmp_path / "bad_record.json"
    # status_code as a string rather than an integer.
    path.write_text(
        json.dumps({"results": [{"url": "u", "method": "GET",
                                 "status_code": "200", "endpoint_status": "valid"}]}),
        encoding="utf-8",
    )

    with pytest.raises(InvalidSessionFileError):
        DiscoverySession.load(str(path))
