"""
Unit tests for machine-readable discovery output and discovery statistics.

**Feature: owasp-complete-purple-teaming-cicd, Task 35.4**

These example-based tests pin down the machine-readable
``Discovery_Output_File`` behaviour and the discovery summary statistics line:

- ``write_discovery_output`` writes ``.csv`` and ``.jsonl`` and orders records
  consistently with the triage table: ascending status class
  (``2xx, 3xx, 4xx, 5xx``) with unclassified (``1xx``/``6xx+``) records appended
  last in stable order (Requirements 31.1, 31.2)
- an unsupported output format raises :class:`UnsupportedOutputFormatError`,
  names the offending format, and writes no file (Requirement 31.4)
- an :class:`OSError` during the write is wrapped in
  :class:`DiscoveryOutputError` naming the destination path (Requirement 31.5)
- the ``dir`` command routes ``--output-file``/``--output-format`` through the
  triage path when sourced from a reloaded session (no HTTP), writing the
  machine-readable file and surfacing format errors as CLI errors
  (Requirements 31.1, 31.4, 31.5)
- the discovery summary emits the :class:`FuzzingStats` line alongside the
  budget/catch-all flags, and stays silent when stats are unavailable
  (Requirement 31.3)

No real HTTP requests are made: the CLI tests source records from a reloaded
``DiscoverySession`` JSON file, and the summary tests drive
``_echo_discovery_control_status`` with a small ``_FakeCore`` stub.
"""

import csv
import json
import os
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from apileaks import cli, _echo_discovery_control_status
from modules.fuzzing.orchestrator import FuzzingStats
from utils.discovery_output import (
    DiscoveryOutputError,
    UnsupportedOutputFormatError,
    write_discovery_output,
)
from utils.discovery_session import DiscoveryResult, DiscoverySession


def _record(status_code: int, url: str) -> DiscoveryResult:
    """Build a DiscoveryResult with the given status code and URL."""
    return DiscoveryResult(
        url=url,
        method="GET",
        status_code=status_code,
        endpoint_status="valid",
    )


def _out_of_order_records():
    """Records deliberately shuffled across classes, plus an unclassified 1xx.

    Order on input: 500, 200, 404, 301, 101. The expected output ordering is
    ascending status class (200, 301, 404, 500) followed by the unclassified
    101 record last.
    """
    return [
        _record(500, "https://api.example.com/down"),
        _record(200, "https://api.example.com/ok"),
        _record(404, "https://api.example.com/missing"),
        _record(301, "https://api.example.com/moved"),
        _record(101, "https://api.example.com/switching"),  # 1xx -> unclassified
    ]


# Expected URL order after _order_records: ascending class, unclassified last.
_EXPECTED_URL_ORDER = [
    "https://api.example.com/ok",         # 2xx
    "https://api.example.com/moved",      # 3xx
    "https://api.example.com/missing",    # 4xx
    "https://api.example.com/down",       # 5xx
    "https://api.example.com/switching",  # 1xx (unclassified, appended last)
]


# ---------------------------------------------------------------------------
# Machine output writing + ordering (Requirements 31.1, 31.2)
# ---------------------------------------------------------------------------


def test_csv_output_written_and_ordered_by_status_class(tmp_path):
    """A .csv output is written with the four columns and class-ascending rows.

    The header is exactly ``url, method, status_code, endpoint_status`` and the
    data rows appear grouped ascending by status class (2xx, 3xx, 4xx, 5xx) with
    the unclassified 1xx record appended last.

    **Validates: Requirements 31.1, 31.2**
    """
    path = str(tmp_path / "discovery.csv")

    write_discovery_output(_out_of_order_records(), path)

    assert os.path.exists(path)
    with open(path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        # Header columns are exactly these four, in this order.
        assert reader.fieldnames == ["url", "method", "status_code", "endpoint_status"]
        rows = list(reader)

    assert [row["url"] for row in rows] == _EXPECTED_URL_ORDER


def test_jsonl_output_written_and_ordered_by_status_class(tmp_path):
    """A .jsonl output is written with one object per line in class order.

    Each line is a JSON object carrying the four DiscoveryResult keys, and the
    objects appear grouped ascending by status class with the unclassified 1xx
    record last.

    **Validates: Requirements 31.1, 31.2**
    """
    path = str(tmp_path / "discovery.jsonl")

    write_discovery_output(_out_of_order_records(), path)

    assert os.path.exists(path)
    with open(path, "r", encoding="utf-8") as handle:
        objects = [json.loads(line) for line in handle if line.strip()]

    assert [obj["url"] for obj in objects] == _EXPECTED_URL_ORDER
    for obj in objects:
        assert set(obj.keys()) == {"url", "method", "status_code", "endpoint_status"}


# ---------------------------------------------------------------------------
# Unsupported format raises and writes nothing (Requirement 31.4)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("filename", ["out.txt", "out.xml", "out"])
def test_unsupported_format_raises_and_writes_no_file(tmp_path, filename):
    """An unsupported output format raises, names the format, and writes no file.

    **Validates: Requirements 31.4**
    """
    path = str(tmp_path / filename)

    with pytest.raises(UnsupportedOutputFormatError) as exc_info:
        write_discovery_output(_out_of_order_records(), path)

    message = str(exc_info.value)
    # The message names the supported formats so the user knows the valid set.
    assert ".csv" in message
    assert ".jsonl" in message
    # Nothing was written for the rejected format.
    assert not os.path.exists(path)


# ---------------------------------------------------------------------------
# Write failure is wrapped naming the path (Requirement 31.5)
# ---------------------------------------------------------------------------


def test_write_failure_wrapped_in_discovery_output_error(tmp_path):
    """An OSError during the write is wrapped in DiscoveryOutputError naming path.

    **Validates: Requirements 31.5**
    """
    path = str(tmp_path / "discovery.csv")

    with patch("builtins.open", side_effect=OSError("disk full")):
        with pytest.raises(DiscoveryOutputError) as exc_info:
            write_discovery_output(_out_of_order_records(), path)

    message = str(exc_info.value)
    # The descriptive message names the destination path.
    assert path in message


# ---------------------------------------------------------------------------
# CLI wiring without real HTTP (Requirements 31.1, 31.4, 31.5)
# ---------------------------------------------------------------------------


def _seed_session(path: str) -> DiscoverySession:
    """Save a DiscoverySession with a few records to ``path`` (reload source)."""
    records = [
        _record(200, "https://api.example.com/ok"),
        _record(301, "https://api.example.com/moved"),
        _record(404, "https://api.example.com/missing"),
    ]
    session = DiscoverySession(
        target="https://api.example.com",
        timestamp="2025-01-15T10:30:00Z",
        tool_version="0.2.0",
        results=records,
    )
    session.save(path)
    return session


def test_cli_output_file_csv_written_from_loaded_session(tmp_path):
    """``dir --load-session --output-file out.csv`` writes the CSV without HTTP.

    The reloaded session is the sole source of records, so no discovery runs;
    the triage path writes the machine-readable CSV with one row per record.

    **Validates: Requirements 31.1**
    """
    runner = CliRunner()
    session_path = str(tmp_path / "session.json")
    out_path = str(tmp_path / "out.csv")
    _seed_session(session_path)

    with patch("apileaks._discover_endpoints_for_triage") as never_discover:
        result = runner.invoke(
            cli,
            [
                "--no-banner",
                "dir",
                "--target", "https://api.example.com",
                "--load-session", session_path,
                "--output-file", out_path,
            ],
            catch_exceptions=False,
        )
        never_discover.assert_not_called()

    assert result.exit_code == 0, result.output
    assert os.path.exists(out_path)
    with open(out_path, "r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 3


def test_cli_output_format_jsonl_defaults_to_reports_dir(tmp_path):
    """``dir --output-format jsonl`` writes the default reports/discovery_output.jsonl.

    Run inside an isolated filesystem so the default ``reports/`` directory is
    created in a temporary cwd and cleaned up afterwards.

    **Validates: Requirements 31.1**
    """
    runner = CliRunner()

    with runner.isolated_filesystem():
        session_path = "session.json"
        _seed_session(session_path)

        with patch("apileaks._discover_endpoints_for_triage") as never_discover:
            result = runner.invoke(
                cli,
                [
                    "--no-banner",
                    "dir",
                    "--target", "https://api.example.com",
                    "--load-session", session_path,
                    "--output-format", "jsonl",
                ],
                catch_exceptions=False,
            )
            never_discover.assert_not_called()

        assert result.exit_code == 0, result.output
        default_path = os.path.join("reports", "discovery_output.jsonl")
        assert os.path.exists(default_path)
        with open(default_path, "r", encoding="utf-8") as handle:
            lines = [line for line in handle if line.strip()]
        assert len(lines) == 3


def test_cli_unsupported_output_format_errors_and_writes_nothing(tmp_path):
    """``dir --output-file out.xml`` exits non-zero and writes no file.

    Exercises the CLI's DiscoveryOutputError handler for an unsupported format.

    **Validates: Requirements 31.4, 31.5**
    """
    runner = CliRunner()
    session_path = str(tmp_path / "session.json")
    out_path = str(tmp_path / "out.xml")
    _seed_session(session_path)

    with patch("apileaks._discover_endpoints_for_triage") as never_discover:
        result = runner.invoke(
            cli,
            [
                "--no-banner",
                "dir",
                "--target", "https://api.example.com",
                "--load-session", session_path,
                "--output-file", out_path,
            ],
            catch_exceptions=False,
        )
        never_discover.assert_not_called()

    assert result.exit_code != 0
    # The error output names the unsupported format/extension.
    assert ".xml" in result.output or "xml" in result.output
    assert not os.path.exists(out_path)


# ---------------------------------------------------------------------------
# Summary statistics line (Requirement 31.3)
# ---------------------------------------------------------------------------

_BUDGET_MSG = "Request budget reached"
_CATCH_ALL_MSG = "Catch-all response detected"


class _FakeCore:
    """Core stub exposing discovery status and (optionally) fuzzing stats.

    ``get_secret_findings`` is intentionally omitted; ``_echo_secret_findings``
    guards its absence via ``getattr`` so the summary stays clean.
    """

    def __init__(self, status, stats=None, include_stats=True):
        self._status = status
        self._stats = stats
        if include_stats:
            self.get_fuzzing_stats = self._get_fuzzing_stats

    def get_discovery_status(self):
        return self._status

    def _get_fuzzing_stats(self):
        return self._stats


def _known_stats() -> FuzzingStats:
    """FuzzingStats with known values: 4/20 successful -> 20.0% success rate."""
    return FuzzingStats(
        endpoints_tested=12,
        endpoints_discovered=4,
        total_requests=20,
        successful_requests=4,
        recursive_depth_reached=2,
    )


def test_summary_includes_fuzzing_stats_alongside_flags(capsys):
    """The summary prints the FuzzingStats values next to the budget/catch-all flags.

    **Validates: Requirements 31.3**
    """
    core = _FakeCore(
        {"budget_reached": True, "catch_all_detected": True},
        stats=_known_stats(),
    )

    _echo_discovery_control_status(core)
    out = capsys.readouterr().out

    # The budget and catch-all warnings appear alongside the stats line.
    assert _BUDGET_MSG in out
    assert _CATCH_ALL_MSG in out
    # The FuzzingStats values are all present.
    assert "12" in out          # endpoints tested
    assert "4" in out           # endpoints discovered
    assert "20" in out          # total requests
    assert "20.0%" in out       # success rate (4/20 -> 20.0%)
    assert "depth 2" in out     # recursion depth reached


def test_summary_stats_present_without_flags(capsys):
    """With no flags set, the stats line still prints (no budget/catch-all noise).

    **Validates: Requirements 31.3**
    """
    core = _FakeCore(
        {"budget_reached": False, "catch_all_detected": False},
        stats=_known_stats(),
    )

    _echo_discovery_control_status(core)
    out = capsys.readouterr().out

    assert _BUDGET_MSG not in out
    assert _CATCH_ALL_MSG not in out
    assert "20.0%" in out
    assert "depth 2" in out


def test_summary_silent_when_stats_unavailable(capsys):
    """A core without get_fuzzing_stats prints no stats line (guards the fake core).

    **Validates: Requirements 31.3**
    """
    core = _FakeCore(
        {"budget_reached": False, "catch_all_detected": False},
        include_stats=False,
    )
    # Confirm the stub really lacks the accessor.
    assert not hasattr(core, "get_fuzzing_stats")

    _echo_discovery_control_status(core)
    out = capsys.readouterr().out

    assert "Discovery stats" not in out
    assert "success rate" not in out


def test_summary_silent_when_stats_is_none(capsys):
    """When get_fuzzing_stats returns None (no discovery ran), no stats line prints.

    **Validates: Requirements 31.3**
    """
    core = _FakeCore(
        {"budget_reached": False, "catch_all_detected": False},
        stats=None,
    )

    _echo_discovery_control_status(core)
    out = capsys.readouterr().out

    assert "Discovery stats" not in out
