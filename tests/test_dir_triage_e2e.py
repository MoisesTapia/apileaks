"""
End-to-end validation of the ``dir`` discovery-triage workflow.

**Feature: owasp-complete-purple-teaming-cicd, Task 19.1**

These tests drive the real ``dir`` Click command through ``CliRunner`` with all
network I/O and stdin mocked, exercising ``--save-session``, ``--load-session``,
``--export``, a status filter, and ``--interactive`` together. They confirm the
four end-to-end behaviours required by Task 19.1:

- session round-trip: saving then reloading yields an equal record set
  (Requirement 14.8)
- export grouping: the human-readable export groups records by status class in
  ascending order (Requirement 14.5 / 13.1)
- table rendering: the triage table is rendered to the console (Requirement 15.1)
- CI non-blocking: ``--interactive`` combined with ``--ci-mode`` never prompts and
  never blocks, launching no follow-up scan even with empty stdin (Requirement 16.3)

No real HTTP requests are made: discovery is mocked to return in-memory
``Endpoint`` objects, and the targeted follow-up scan is mocked so a valid
interactive selection is observable without performing a real scan.
"""

import json
import os
from unittest.mock import patch

from click.testing import CliRunner

from apileaks import cli
from modules.fuzzing.orchestrator import Endpoint
from utils.discovery_session import DiscoveryResult, DiscoverySession


def _endpoint(status_code: int, path: str, method: str = "GET") -> Endpoint:
    """Build a discovered Endpoint with the given status code and path."""
    return Endpoint(
        url=f"https://api.example.com{path}",
        method=method,
        status_code=status_code,
        response_size=128,
        response_time=0.01,
    )


def _mock_endpoints():
    """Endpoints spanning all four status classes plus a 1xx (excluded) record."""
    return [
        _endpoint(404, "/missing"),
        _endpoint(200, "/ok"),
        _endpoint(503, "/down"),
        _endpoint(301, "/moved"),
        _endpoint(101, "/switching"),  # 1xx -> excluded from all groups
    ]


async def _fake_discover(_apileak_config, _discovery_progress=None):
    """Async stand-in for endpoint discovery returning fixed in-memory endpoints.

    Mirrors the ``_discover_endpoints_for_triage`` contract, returning the
    ``(endpoints, soft_404_baseline)`` tuple; the baseline is ``None`` since the
    mocked run derives no soft-404 signature.
    """
    return _mock_endpoints(), None


def test_dir_triage_save_export_filter_table_and_ci_non_blocking(tmp_path):
    """Discovery-path run: save session, export grouped, render table, CI no-prompt.

    Exercises --save-session, --export/--export-file, a 2xx status filter,
    --interactive and --ci-mode in a single mocked invocation. Confirms the
    triage table renders, the export is grouped ascending by status class, the
    session file captures every discovered record, and that interactive mode in
    CI never blocks (empty stdin) and launches no follow-up scan.
    """
    runner = CliRunner()
    session_path = tmp_path / "session.json"
    export_path = tmp_path / "export.md"

    with patch("apileaks._discover_endpoints_for_triage", _fake_discover), patch(
        "apileaks._run_targeted_follow_up_scan"
    ) as follow_up:
        result = runner.invoke(
            cli,
            [
                "dir",
                "--target", "https://api.example.com",
                "--save-session", str(session_path),
                "--export-file", str(export_path),
                "--status-code", "2xx",
                "--interactive",
                "--ci-mode",
            ],
            input="",  # no stdin: CI mode must not block waiting for input
            catch_exceptions=False,
        )

    assert result.exit_code == 0, result.output

    # CI mode disabled the interactive prompt -> no follow-up scan launched (16.3).
    follow_up.assert_not_called()

    # Session file written with every discovered record, none omitted (14.1).
    assert session_path.exists()
    saved = json.loads(session_path.read_text())
    saved_codes = sorted(r["status_code"] for r in saved["results"])
    assert saved_codes == [101, 200, 301, 404, 503]

    # Export written and grouped by status class in ascending order (14.5 / 13.1).
    assert export_path.exists()
    export_text = export_path.read_text()
    pos_2xx = export_text.find("2xx")
    pos_3xx = export_text.find("3xx")
    pos_4xx = export_text.find("4xx")
    pos_5xx = export_text.find("5xx")
    assert -1 < pos_2xx < pos_3xx < pos_4xx < pos_5xx

    # Triage table rendered to the console (15.1): header columns appear.
    for column in ("URL", "Method", "Status"):
        assert column in result.output


def test_dir_triage_load_session_round_trip(tmp_path):
    """Reload path: --load-session reproduces exactly the saved record set (14.8).

    First save a session via the discovery path, then reload it with a separate
    invocation and confirm the reloaded record set equals the saved one.
    """
    runner = CliRunner()
    session_path = tmp_path / "session.json"

    # Phase 1: save a session from mocked discovery.
    with patch("apileaks._discover_endpoints_for_triage", _fake_discover):
        save_result = runner.invoke(
            cli,
            [
                "dir",
                "--target", "https://api.example.com",
                "--save-session", str(session_path),
            ],
            catch_exceptions=False,
        )
    assert save_result.exit_code == 0, save_result.output
    assert session_path.exists()

    expected = set(DiscoveryResult.from_endpoint(e) for e in _mock_endpoints())

    # Phase 2: reload the session (no discovery) and confirm an equal record set.
    with patch("apileaks._discover_endpoints_for_triage") as never_discover:
        load_result = runner.invoke(
            cli,
            [
                "dir",
                "--target", "https://api.example.com",
                "--load-session", str(session_path),
            ],
            catch_exceptions=False,
        )
        # Reload must source records from the session file only, never discover.
        never_discover.assert_not_called()

    assert load_result.exit_code == 0, load_result.output

    reloaded = set(DiscoverySession.load(str(session_path)).results)
    assert reloaded == expected


def test_dir_triage_interactive_selection_launches_one_follow_up(tmp_path):
    """Non-CI interactive run with simulated stdin launches one follow-up scan.

    Reloads a saved session and provides stdin selecting the first endpoint;
    the targeted follow-up scan is mocked and must be invoked exactly once
    (Requirements 16.1, 16.2).
    """
    runner = CliRunner()
    session_path = tmp_path / "session.json"

    # Seed a session file directly (source of truth for reload).
    records = [DiscoveryResult.from_endpoint(e) for e in _mock_endpoints()]
    DiscoverySession(
        target="https://api.example.com",
        timestamp="2025-01-15T10:30:00Z",
        tool_version="0.2.0",
        results=records,
    ).save(str(session_path))

    with patch("apileaks._run_targeted_follow_up_scan") as follow_up:
        result = runner.invoke(
            cli,
            [
                "dir",
                "--target", "https://api.example.com",
                "--load-session", str(session_path),
                "--interactive",
            ],
            input="1\n",  # select the first displayed endpoint
            catch_exceptions=False,
        )

    assert result.exit_code == 0, result.output
    follow_up.assert_called_once()
