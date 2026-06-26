"""
Unit tests for the human-readable discovery export.

**Feature: owasp-complete-purple-teaming-cicd, Task 16.2**

These example-based tests pin down the export behaviour:

- ``.md`` and ``.txt`` exports are written, present every record grouped by
  status class, and order the groups ascending ``2xx, 3xx, 4xx, 5xx``
  (Requirements 14.3, 14.5)
- requesting an unsupported format (``.csv``, ``.json``, ``.html`` or no
  extension) raises a descriptive error and writes no file (Requirement 14.4)
"""

import os

import pytest

from utils.discovery_export import (
    SUPPORTED_EXTENSIONS,
    UnsupportedExportFormatError,
    write_discovery_export,
)
from utils.discovery_session import DiscoveryResult


def _record(status_code: int, url: str) -> DiscoveryResult:
    """Build a DiscoveryResult with the given status code and URL."""
    return DiscoveryResult(
        url=url,
        method="GET",
        status_code=status_code,
        endpoint_status="valid",
    )


def _mixed_records():
    """Return records spanning all four status classes, in shuffled class order."""
    return [
        _record(404, "https://api.example.com/missing"),
        _record(200, "https://api.example.com/ok"),
        _record(503, "https://api.example.com/down"),
        _record(301, "https://api.example.com/moved"),
    ]


# ---------------------------------------------------------------------------
# Supported formats are written, grouped, and ordered ascending (14.3, 14.5)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("extension", [".md", ".txt"])
def test_export_writes_file_for_supported_formats(tmp_path, extension):
    """A .md/.txt export is written to disk (14.3)."""
    path = str(tmp_path / f"discovery{extension}")

    write_discovery_export(_mixed_records(), path)

    assert os.path.exists(path)
    content = open(path, "r", encoding="utf-8").read()
    assert content.strip() != ""


@pytest.mark.parametrize("extension", [".md", ".txt"])
def test_export_contains_every_record(tmp_path, extension):
    """Every record's URL appears in the export (14.3)."""
    records = _mixed_records()
    path = str(tmp_path / f"discovery{extension}")

    write_discovery_export(records, path)

    content = open(path, "r", encoding="utf-8").read()
    for record in records:
        assert record.url in content
        assert str(record.status_code) in content


@pytest.mark.parametrize("extension", [".md", ".txt"])
def test_export_groups_in_ascending_status_class_order(tmp_path, extension):
    """Groups appear in ascending class order: 2xx before 3xx before 4xx before 5xx (14.5)."""
    path = str(tmp_path / f"discovery{extension}")

    write_discovery_export(_mixed_records(), path)

    content = open(path, "r", encoding="utf-8").read()
    index_2xx = content.index("2xx")
    index_3xx = content.index("3xx")
    index_4xx = content.index("4xx")
    index_5xx = content.index("5xx")
    assert index_2xx < index_3xx < index_4xx < index_5xx


@pytest.mark.parametrize("extension", [".md", ".txt"])
def test_export_records_appear_under_their_class(tmp_path, extension):
    """Each record's URL appears after its class heading and before the next (14.5)."""
    path = str(tmp_path / f"discovery{extension}")

    write_discovery_export(_mixed_records(), path)

    content = open(path, "r", encoding="utf-8").read()
    # The 2xx record must come before the 3xx heading; the 5xx record after 5xx.
    assert content.index("https://api.example.com/ok") < content.index("3xx")
    assert content.index("https://api.example.com/down") > content.index("5xx")


@pytest.mark.parametrize("extension", [".md", ".txt"])
def test_export_empty_records_still_written(tmp_path, extension):
    """An empty record set still produces a file with all four class headings (14.5)."""
    path = str(tmp_path / f"empty{extension}")

    write_discovery_export([], path)

    assert os.path.exists(path)
    content = open(path, "r", encoding="utf-8").read()
    for status_class in ("2xx", "3xx", "4xx", "5xx"):
        assert status_class in content


def test_supported_extensions_are_md_and_txt():
    """The module advertises exactly the .md and .txt formats (14.3)."""
    assert set(SUPPORTED_EXTENSIONS) == {".md", ".txt"}


# ---------------------------------------------------------------------------
# Unsupported formats raise a descriptive error and write nothing (14.4)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("extension", [".csv", ".json", ".html", ".pdf", ""])
def test_unsupported_format_raises_and_writes_no_file(tmp_path, extension):
    """An unsupported format raises a descriptive error and creates no file (14.4)."""
    path = str(tmp_path / f"discovery{extension}")

    with pytest.raises(UnsupportedExportFormatError) as exc_info:
        write_discovery_export(_mixed_records(), path)

    message = str(exc_info.value)
    # Descriptive: names the supported formats so the user knows what to use.
    assert ".md" in message
    assert ".txt" in message
    # Nothing was written for the rejected format.
    assert not os.path.exists(path)


def test_unsupported_format_does_not_create_any_file_in_dir(tmp_path):
    """A rejected export leaves the destination directory empty (14.4)."""
    path = str(tmp_path / "discovery.csv")

    with pytest.raises(UnsupportedExportFormatError):
        write_discovery_export(_mixed_records(), path)

    assert os.listdir(str(tmp_path)) == []
