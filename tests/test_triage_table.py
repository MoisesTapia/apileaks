"""
Unit tests for the triage table renderer.

**Feature: owasp-complete-purple-teaming-cicd, Task 17.2**

These example-based tests pin down the rendering behaviour of
:func:`utils.triage_table.render_triage_table`:

- exactly four columns in the order URL, Method, Status, EndpointStatus
  (Requirement 15.3)
- rows grouped ascending by status class ``2xx, 3xx, 4xx, 5xx``
  (Requirement 15.4)
- a status filter restricts the displayed rows (Requirement 15.5)
- the table is built from in-memory / reloaded ``DiscoveryResult`` records and
  never from a ``Discovery_Export_File`` (Requirements 15.1, 15.2, 15.6)
- an empty record set yields the header row and zero data rows
  (Requirement 15.7)
"""

from utils.discovery_session import (
    DiscoveryResult,
    DiscoverySession,
    StatusFilter,
    parse_status_filter,
)
from utils.triage_table import COLUMN_HEADERS, render_triage_table


def _record(status_code: int, url: str, method: str = "GET") -> DiscoveryResult:
    """Build a DiscoveryResult with the given status code, URL and method."""
    return DiscoveryResult(
        url=url,
        method=method,
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


def _column_cells(table, header):
    """Return the ordered list of cell values for the column with ``header``."""
    for column in table.columns:
        if column.header == header:
            return list(column._cells)
    raise AssertionError(f"column {header!r} not found")


def _url_rows_in_order(table):
    """Return the URL column cells in row order."""
    return _column_cells(table, "URL")


# ---------------------------------------------------------------------------
# Exactly four columns in order (15.3)
# ---------------------------------------------------------------------------


def test_table_has_exactly_four_columns_in_order():
    """The table exposes exactly four columns: URL, Method, Status, EndpointStatus (15.3)."""
    table = render_triage_table(_mixed_records())

    headers = [column.header for column in table.columns]
    assert headers == ["URL", "Method", "Status", "EndpointStatus"]
    assert len(table.columns) == 4
    # The module constant pins the same order used to build the table.
    assert tuple(headers) == COLUMN_HEADERS


def test_table_columns_carry_expected_cell_values():
    """Each column holds the matching DiscoveryResult field (15.3)."""
    record = _record(200, "https://api.example.com/ok", method="POST")

    table = render_triage_table([record])

    assert _column_cells(table, "URL") == ["https://api.example.com/ok"]
    assert _column_cells(table, "Method") == ["POST"]
    assert _column_cells(table, "Status") == ["200"]
    assert _column_cells(table, "EndpointStatus") == ["valid"]


# ---------------------------------------------------------------------------
# Rows grouped ascending by status class (15.4)
# ---------------------------------------------------------------------------


def test_rows_grouped_ascending_by_status_class():
    """Rows are ordered by ascending status class 2xx -> 3xx -> 4xx -> 5xx (15.4)."""
    table = render_triage_table(_mixed_records())

    urls = _url_rows_in_order(table)
    assert urls == [
        "https://api.example.com/ok",       # 200 (2xx)
        "https://api.example.com/moved",    # 301 (3xx)
        "https://api.example.com/missing",  # 404 (4xx)
        "https://api.example.com/down",     # 503 (5xx)
    ]


def test_rows_preserve_relative_order_within_a_class():
    """Records sharing a class keep their input order within the group (15.4)."""
    records = [
        _record(204, "https://api.example.com/b"),
        _record(200, "https://api.example.com/a"),
        _record(404, "https://api.example.com/missing"),
    ]

    table = render_triage_table(records)

    urls = _url_rows_in_order(table)
    assert urls == [
        "https://api.example.com/b",        # 204, first 2xx in input
        "https://api.example.com/a",        # 200, second 2xx in input
        "https://api.example.com/missing",  # 404 (4xx)
    ]


def test_non_2xx_5xx_records_are_excluded():
    """A record whose leading digit is not 2-5 (e.g. 1xx) is not displayed (15.4)."""
    records = [
        _record(100, "https://api.example.com/continue"),
        _record(200, "https://api.example.com/ok"),
    ]

    table = render_triage_table(records)

    assert _url_rows_in_order(table) == ["https://api.example.com/ok"]
    assert table.row_count == 1


# ---------------------------------------------------------------------------
# A status filter restricts the displayed rows (15.5)
# ---------------------------------------------------------------------------


def test_class_filter_restricts_displayed_rows():
    """A class filter (e.g. 4xx) shows only matching records (15.5)."""
    table = render_triage_table(_mixed_records(), status_filter=parse_status_filter("4xx"))

    assert _url_rows_in_order(table) == ["https://api.example.com/missing"]
    assert table.row_count == 1


def test_explicit_code_filter_restricts_displayed_rows():
    """An explicit-code filter shows only the exact matching codes (15.5)."""
    records = _mixed_records()

    table = render_triage_table(records, status_filter=parse_status_filter("200,503"))

    urls = _url_rows_in_order(table)
    # Ascending class order is preserved: 200 (2xx) before 503 (5xx).
    assert urls == ["https://api.example.com/ok", "https://api.example.com/down"]
    assert table.row_count == 2


def test_none_filter_shows_every_record():
    """A None filter displays every (in-range) record (15.5)."""
    table = render_triage_table(_mixed_records(), status_filter=None)

    assert table.row_count == 4


def test_filter_excluding_all_yields_zero_data_rows():
    """A filter matching nothing yields a table with zero data rows (15.5, 15.7)."""
    table = render_triage_table(
        _mixed_records(), status_filter=StatusFilter(codes=frozenset({418}))
    )

    assert table.row_count == 0
    assert len(table.columns) == 4


# ---------------------------------------------------------------------------
# Built from in-memory / reloaded records, never from an export (15.1, 15.2, 15.6)
# ---------------------------------------------------------------------------


def test_rendered_from_in_memory_records():
    """The renderer is driven purely by in-memory DiscoveryResult records (15.1, 15.2)."""
    records = _mixed_records()

    table = render_triage_table(records)

    # Every in-memory record's URL is present as a data row.
    displayed = set(_url_rows_in_order(table))
    assert displayed == {record.url for record in records}


def test_rendered_from_reloaded_session_records(tmp_path):
    """Records reloaded from a session file render identically (15.6).

    The session JSON file is the source of truth on reload; the table is built
    from the reconstructed in-memory records, never from any export artifact.
    """
    records = _mixed_records()
    session = DiscoverySession(
        target="https://api.example.com",
        timestamp="2024-01-01T00:00:00Z",
        tool_version="0.2.0",
        results=records,
    )
    path = str(tmp_path / "session.json")
    session.save(path)

    reloaded = DiscoverySession.load(path)
    table_from_memory = render_triage_table(records)
    table_from_reload = render_triage_table(reloaded.results)

    assert _url_rows_in_order(table_from_reload) == _url_rows_in_order(table_from_memory)
    assert [c.header for c in table_from_reload.columns] == list(COLUMN_HEADERS)


def test_renderer_signature_takes_records_not_a_file_path():
    """render_triage_table accepts records, not an export-file path (15.2, 15.6).

    Passing a list of in-memory records produces a populated table, confirming
    the input contract is the record set rather than a Discovery_Export_File.
    """
    import inspect

    params = list(inspect.signature(render_triage_table).parameters)
    assert params[0] == "records"
    # No parameter implies reading a file/export path.
    assert not any("path" in name or "file" in name or "export" in name for name in params)


# ---------------------------------------------------------------------------
# Empty record set -> header row, zero data rows (15.7)
# ---------------------------------------------------------------------------


def test_empty_records_yields_header_and_zero_data_rows():
    """An empty record set yields the four-column header and zero data rows (15.7)."""
    table = render_triage_table([])

    assert [column.header for column in table.columns] == list(COLUMN_HEADERS)
    assert len(table.columns) == 4
    assert table.row_count == 0
