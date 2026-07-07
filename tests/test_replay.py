"""
Unit and integration tests for the ``replay`` command and ``utils/replay.py``.

Covers:
- :func:`utils.replay.load_report` — happy path, missing file, bad JSON
- :func:`utils.replay._extract_requests_from_report` — endpoint + finding extraction
- :func:`utils.replay.filter_requests` — all filter combinations
- :func:`utils.replay.print_request_list` — smoke test (no crash)
- CLI: ``apileaks replay --list`` surfaces items from a report
- CLI: ``apileaks replay`` with ``--index`` out of range
- CLI: ``apileaks replay`` errors when report is empty

No real HTTP requests are issued.
"""

import json
import os
import tempfile

import pytest
from click.testing import CliRunner

from apileaks import cli
from utils.replay import (
    _extract_requests_from_report,
    filter_requests,
    load_report,
    print_request_list,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_report(*, endpoints=None, findings=None):
    """Build a minimal report dict."""
    return {
        "report_metadata": {"format": "JSON", "version": "1.0"},
        "scan_info": {"target": "https://api.example.com"},
        "discovered_endpoints": endpoints or [],
        "findings": findings or [],
    }


def _write_report(data: dict) -> str:
    """Write a report dict to a temp file and return the path."""
    fh = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    )
    json.dump(data, fh)
    fh.close()
    return fh.name


# ---------------------------------------------------------------------------
# load_report
# ---------------------------------------------------------------------------

def test_load_report_happy_path(tmp_path):
    """A valid JSON report file is loaded into a dict."""
    report = _make_report(endpoints=[{"url": "https://api.example.com/users", "method": "GET", "status_code": 200}])
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))

    loaded = load_report(str(path))

    assert loaded["scan_info"]["target"] == "https://api.example.com"
    assert len(loaded["discovered_endpoints"]) == 1


def test_load_report_missing_file():
    """A missing file causes SystemExit with a descriptive message."""
    with pytest.raises(SystemExit) as exc_info:
        load_report("/nonexistent/path/report.json")
    assert "not found" in str(exc_info.value).lower()


def test_load_report_bad_json(tmp_path):
    """A non-JSON file causes SystemExit with a descriptive message."""
    path = tmp_path / "bad.json"
    path.write_text("this is not json {{{}}}}")

    with pytest.raises(SystemExit) as exc_info:
        load_report(str(path))
    assert "json" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# _extract_requests_from_report
# ---------------------------------------------------------------------------

def test_extract_endpoints_from_report():
    """Discovered endpoints are extracted with method and URL."""
    report = _make_report(endpoints=[
        {"url": "https://api.example.com/users", "method": "GET", "status_code": 200},
        {"url": "https://api.example.com/admin", "method": "POST", "status_code": 403},
    ])

    requests = _extract_requests_from_report(report)

    assert len(requests) == 2
    urls = {r["url"] for r in requests}
    assert "https://api.example.com/users" in urls
    assert "https://api.example.com/admin" in urls
    assert all(r["source"] == "endpoint" for r in requests)
    assert all(r["method"] in ("GET", "POST") for r in requests)


def test_extract_findings_from_report():
    """Security findings are extracted with method, URL, and optional body."""
    payload = {"username": "admin", "password": "x"}
    report = _make_report(findings=[
        {
            "id": "f1",
            "endpoint": "https://api.example.com/login",
            "method": "POST",
            "status_code": 200,
            "severity": "HIGH",
            "category": "AUTH_BYPASS",
            "evidence": "test",
            "recommendation": "fix",
            "payload": payload,
            "metadata": {"headers": {"X-Custom": "yes"}},
        }
    ])

    requests = _extract_requests_from_report(report)

    assert len(requests) == 1
    req = requests[0]
    assert req["source"] == "finding"
    assert req["method"] == "POST"
    assert req["url"] == "https://api.example.com/login"
    assert req["json_body"] == payload
    assert req["headers"].get("X-Custom") == "yes"


def test_extract_finding_with_json_string_payload():
    """A JSON-string payload in a finding is parsed into a dict."""
    report = _make_report(findings=[
        {
            "endpoint": "https://api.example.com/data",
            "method": "PUT",
            "status_code": 200,
            "severity": "MEDIUM",
            "category": "MASS_ASSIGNMENT",
            "evidence": "",
            "recommendation": "",
            "payload": '{"is_admin": true}',
        }
    ])

    requests = _extract_requests_from_report(report)

    assert requests[0]["json_body"] == {"is_admin": True}


def test_extract_skips_entries_without_url():
    """Entries missing a URL are silently skipped."""
    report = _make_report(
        endpoints=[{"method": "GET", "status_code": 200}],   # no URL
        findings=[{"method": "POST", "status_code": 201}],   # no endpoint
    )

    requests = _extract_requests_from_report(report)

    assert len(requests) == 0


def test_extract_mixed_report():
    """Both endpoints and findings are extracted from the same report."""
    report = _make_report(
        endpoints=[{"url": "https://api.example.com/health", "method": "GET", "status_code": 200}],
        findings=[
            {
                "endpoint": "https://api.example.com/secret",
                "method": "GET",
                "status_code": 200,
                "severity": "INFO",
                "category": "ENDPOINT_DISCOVERED",
                "evidence": "",
                "recommendation": "",
            }
        ],
    )

    requests = _extract_requests_from_report(report)

    assert len(requests) == 2
    sources = {r["source"] for r in requests}
    assert sources == {"endpoint", "finding"}


# ---------------------------------------------------------------------------
# filter_requests
# ---------------------------------------------------------------------------

def _sample_requests():
    return [
        {"url": "https://api.example.com/users", "method": "GET", "source": "endpoint"},
        {"url": "https://api.example.com/admin", "method": "POST", "source": "finding"},
        {"url": "https://api.example.com/login", "method": "POST", "source": "endpoint"},
        {"url": "https://api.example.com/health", "method": "GET", "source": "endpoint"},
    ]


def test_filter_by_url():
    reqs = filter_requests(_sample_requests(), url_filter="admin")
    assert len(reqs) == 1
    assert reqs[0]["url"] == "https://api.example.com/admin"


def test_filter_by_method():
    reqs = filter_requests(_sample_requests(), method_filter="POST")
    assert len(reqs) == 2
    assert all(r["method"] == "POST" for r in reqs)


def test_filter_by_source_finding():
    reqs = filter_requests(_sample_requests(), source_filter="finding")
    assert len(reqs) == 1
    assert reqs[0]["source"] == "finding"


def test_filter_by_index():
    reqs = filter_requests(_sample_requests(), index=2)
    assert len(reqs) == 1
    assert reqs[0]["url"] == "https://api.example.com/login"


def test_filter_by_index_out_of_range():
    reqs = filter_requests(_sample_requests(), index=99)
    assert reqs == []


def test_filter_combined_url_and_method():
    reqs = filter_requests(
        _sample_requests(), url_filter="login", method_filter="POST"
    )
    assert len(reqs) == 1
    assert reqs[0]["url"] == "https://api.example.com/login"


def test_filter_no_match():
    reqs = filter_requests(_sample_requests(), url_filter="/nonexistent")
    assert reqs == []


def test_filter_none_returns_all():
    reqs = filter_requests(_sample_requests())
    assert len(reqs) == 4


# ---------------------------------------------------------------------------
# print_request_list — smoke test
# ---------------------------------------------------------------------------

def test_print_request_list_empty(capsys):
    """Empty list prints a message and does not crash."""
    print_request_list([])
    captured = capsys.readouterr()
    assert "no replayable" in captured.out.lower()


def test_print_request_list_items(capsys):
    """A non-empty list prints each item with index and URL."""
    reqs = [
        {
            "url": "https://api.example.com/users",
            "method": "GET",
            "source": "endpoint",
            "label": "[endpoint] GET https://api.example.com/users  [200]",
        }
    ]
    print_request_list(reqs)
    captured = capsys.readouterr()
    assert "users" in captured.out
    assert "GET" in captured.out


# ---------------------------------------------------------------------------
# CLI: apileaks replay --list
# ---------------------------------------------------------------------------

def test_cli_replay_list(tmp_path):
    """``apileaks replay --list`` prints a table and exits 0."""
    report = _make_report(endpoints=[
        {"url": "https://api.example.com/users", "method": "GET", "status_code": 200},
    ])
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))

    runner = CliRunner()
    result = runner.invoke(cli, ["--no-banner", "replay", str(path), "--list"])

    assert result.exit_code == 0, result.output
    assert "users" in result.output
    assert "GET" in result.output


def test_cli_replay_list_empty_report(tmp_path):
    """``apileaks replay --list`` on an empty report exits non-zero."""
    report = _make_report()
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))

    runner = CliRunner()
    result = runner.invoke(cli, ["--no-banner", "replay", str(path), "--list"])

    assert result.exit_code != 0


def test_cli_replay_list_with_url_filter(tmp_path):
    """``apileaks replay --list --url admin`` filters results."""
    report = _make_report(endpoints=[
        {"url": "https://api.example.com/users", "method": "GET", "status_code": 200},
        {"url": "https://api.example.com/admin", "method": "GET", "status_code": 403},
    ])
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))

    runner = CliRunner()
    result = runner.invoke(
        cli, ["--no-banner", "replay", str(path), "--list", "--url", "admin"]
    )

    assert result.exit_code == 0, result.output
    assert "admin" in result.output
    # 'users' should not appear (filtered out)
    assert "users" not in result.output


def test_cli_replay_index_out_of_range(tmp_path):
    """``apileaks replay --index 99`` on a small report exits non-zero."""
    report = _make_report(endpoints=[
        {"url": "https://api.example.com/users", "method": "GET", "status_code": 200},
    ])
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))

    runner = CliRunner()
    result = runner.invoke(cli, ["--no-banner", "replay", str(path), "--index", "99"])

    assert result.exit_code != 0


def test_cli_replay_multiple_findings_list(tmp_path):
    """Reports with findings surface them correctly in --list mode."""
    report = _make_report(
        findings=[
            {
                "endpoint": "https://api.example.com/login",
                "method": "POST",
                "status_code": 200,
                "severity": "HIGH",
                "category": "AUTH_BYPASS",
                "evidence": "",
                "recommendation": "",
            },
            {
                "endpoint": "https://api.example.com/admin",
                "method": "GET",
                "status_code": 403,
                "severity": "MEDIUM",
                "category": "FUNCTION_LEVEL_BYPASS",
                "evidence": "",
                "recommendation": "",
            },
        ]
    )
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))

    runner = CliRunner()
    result = runner.invoke(cli, ["--no-banner", "replay", str(path), "--list"])

    assert result.exit_code == 0, result.output
    assert "login" in result.output
    assert "admin" in result.output
    # Source column should mention "finding"
    assert "finding" in result.output
