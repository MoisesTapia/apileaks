"""CI/CD severity-gate, SARIF, and baseline CLI tests (task 9).

These tests exercise the CI/CD surface of the restructured orchestrator
(``scan``) built in tasks 5-7 (``apileaks.py``): the ``--ci-mode`` severity
gate, the ``--fail-on`` threshold (default ``high``), the ``--sarif`` report,
and the ``--baseline`` readability guard. They anchor Requirement 5 acceptance
criteria and Property 7 (pre-request failure atomicity) for the baseline path.

* R5.1 / R5.5: ``--ci-mode`` exits 0 when no gating finding meets/exceeds the
  ``--fail-on`` threshold and exits nonzero when at least one does. The gate is
  evaluated on the ordered scale informational < low < medium < high < critical.
* R5.6: without an explicit ``--fail-on`` the CI threshold defaults to ``high``
  (asserted both structurally on the option and behaviorally through the gate).
* R5.2: ``--sarif`` writes a valid SARIF 2.1.0 report containing zero results
  when there are no findings.
* R5.7 / Property 7: an existing but unreadable/malformed ``--baseline`` file
  exits nonzero naming the file, runs no scan and therefore no Severity_Gate; a
  *missing* baseline path is allowed (treated as an empty baseline).

The engine boundary is controlled two ways depending on what is under test:

* For gate exit codes, a fake ``APILeakCore`` returns a results object whose
  ``statistics`` carry the exact severity counts the gate consumes, and the
  report generator is stubbed so no files are written. This isolates the gate's
  exit-code decision from a real scan.
* For the SARIF assertion, the fake core returns a zero-finding results object
  and the REAL ``ReportGenerator`` runs inside an isolated filesystem so the
  actual ``.sarif`` artifact can be read back and validated.

Configuration validation is stubbed (as in ``tests/test_owasp_group_cli.py``)
so behavior is isolated from unrelated filesystem checks (e.g. wordlists).
"""

import glob
import json
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import click
import pytest
from click.testing import CliRunner

import apileaks
from apileaks import cli, scan
from core.config import Severity
from utils.findings import Finding


TARGET = "http://example.com"


# --------------------------------------------------------------------------- #
# Environment isolation: the orchestrator honors APILEAK_* Environment_Overrides
# (setting-resolution precedence), so clear them for deterministic CLI behavior.
# --------------------------------------------------------------------------- #

@pytest.fixture(autouse=True)
def _clear_apileak_env(monkeypatch):
    for var in ("APILEAK_TARGET", "APILEAK_MODULES", "APILEAK_TIMEOUT",
                "APILEAK_USER_AGENT", "APILEAK_MAX_DEPTH", "APILEAK_VERIFY_SSL"):
        monkeypatch.delenv(var, raising=False)


# --------------------------------------------------------------------------- #
# Fake engine helpers.
# --------------------------------------------------------------------------- #

def _make_finding(severity):
    """Build a minimal Finding at the given severity."""
    return Finding(
        id=str(uuid4()),
        scan_id="scan-ci",
        category="TEST_FINDING",
        owasp_category="API1",
        severity=severity,
        endpoint="/e",
        method="GET",
        status_code=200,
        response_size=1,
        response_time=0.1,
        evidence="evidence",
        recommendation="remediation",
    )


def _make_results(findings):
    """Build a results object exposing exactly what ``run_enhanced_apileak`` reads.

    The CI severity gate (with no baseline) derives its counts from
    ``statistics.{critical,high,medium,low}_findings``, so those carry the gate
    input. ``findings_collector`` is ``None`` so the fallback statistics path is
    taken. ``findings`` is the same list, which the SARIF report renders.
    """
    now = datetime.now()
    statistics = SimpleNamespace(
        findings_count=len(findings),
        critical_findings=sum(1 for f in findings if f.severity == Severity.CRITICAL),
        high_findings=sum(1 for f in findings if f.severity == Severity.HIGH),
        medium_findings=sum(1 for f in findings if f.severity == Severity.MEDIUM),
        low_findings=sum(1 for f in findings if f.severity == Severity.LOW),
        info_findings=sum(1 for f in findings if f.severity == Severity.INFO),
        total_requests=1,
        endpoints_discovered=0,
    )
    performance_metrics = SimpleNamespace(
        duration=timedelta(seconds=1),
        requests_per_second=1.0,
        average_response_time=0.1,
        start_time=now,
        end_time=now,
    )
    return SimpleNamespace(
        scan_id="scan-ci",
        target_url=TARGET,
        timestamp=now,
        statistics=statistics,
        performance_metrics=performance_metrics,
        findings=findings,
        discovered_endpoints=[],
        findings_collector=None,
    )


def _fake_core_class(results):
    """Return a fake ``APILeakCore`` class whose ``run_scan`` yields ``results``."""

    class _FakeCore:
        def __init__(self, config):
            self.config = config

        async def health_check(self):
            return {"status": "healthy"}

        async def run_scan(self, target_url, scope_endpoints=None):
            return results

        def get_discovery_status(self):
            return {}

        def get_fuzzing_stats(self):
            return None

        def get_secret_findings(self):
            return []

        def get_discovered_endpoints(self):
            return []

    return _FakeCore


def _run_ci_gate(findings, extra_args):
    """Invoke ``scan --ci-mode`` with a fake engine and stubbed report writer.

    Returns the ``CliRunner`` result. The report generator is stubbed so no
    files are written; the gate's exit code is driven solely by the severity
    counts in the fake results.
    """
    results = _make_results(findings)
    runner = CliRunner()
    with runner.isolated_filesystem():
        with patch.object(apileaks, "APILeakCore", _fake_core_class(results)), patch.object(
            apileaks.ConfigurationManager, "validate_configuration", return_value=[]
        ), patch("utils.report_generator.ReportGenerator") as report_gen:
            report_gen.return_value.save_reports.return_value = []
            result = runner.invoke(
                cli,
                ["--no-banner", "scan", "--target", TARGET, "--ci-mode", *extra_args],
            )
    return result


# --------------------------------------------------------------------------- #
# R5.1 / R5.5: gate exits 0 below threshold, nonzero at/above.
# --------------------------------------------------------------------------- #

def test_ci_mode_exits_zero_when_below_threshold():
    """Only medium/low findings under ``--fail-on high`` -> exit 0 (R5.1, R5.5).

    The highest severity present (medium) is below the ``high`` threshold, so
    the gate passes.

    **Validates: Requirements 5.1, 5.5**
    """
    result = _run_ci_gate(
        [_make_finding(Severity.MEDIUM), _make_finding(Severity.LOW)],
        ["--fail-on", "high"],
    )

    assert result.exit_code == 0, result.output


def test_ci_mode_exits_one_when_at_threshold():
    """A ``high`` finding at the ``--fail-on high`` threshold -> exit 1 (R5.1).

    A high finding (no critical present) meets the threshold, so the gate fails
    with exit code 1.

    **Validates: Requirements 5.1, 5.5**
    """
    result = _run_ci_gate([_make_finding(Severity.HIGH)], ["--fail-on", "high"])

    assert result.exit_code == 1, result.output


def test_ci_mode_exits_nonzero_when_above_threshold():
    """A ``high`` finding above a ``--fail-on medium`` threshold -> nonzero (R5.5).

    The highest severity present (high) exceeds the ``medium`` threshold, so the
    gate fails.

    **Validates: Requirements 5.1, 5.5**
    """
    result = _run_ci_gate([_make_finding(Severity.HIGH)], ["--fail-on", "medium"])

    assert result.exit_code != 0, result.output


def test_ci_mode_no_findings_exits_zero():
    """No findings -> the gate passes with exit 0 regardless of threshold (R5.1).

    **Validates: Requirements 5.1**
    """
    result = _run_ci_gate([], ["--fail-on", "high"])

    assert result.exit_code == 0, result.output


# --------------------------------------------------------------------------- #
# R5.6: default --fail-on is `high`.
# --------------------------------------------------------------------------- #

def test_fail_on_default_is_high_structurally():
    """The ``scan`` command's ``--fail-on`` option defaults to ``high`` (R5.6).

    **Validates: Requirements 5.6**
    """
    fail_on = next(p for p in scan.params if p.name == "fail_on")
    assert fail_on.default == "high"


def test_ci_mode_without_fail_on_uses_high_default_high_finding_fails():
    """``--ci-mode`` with no ``--fail-on`` gates a high finding (default high).

    A high finding trips the gate when the threshold is the ``high`` default,
    so the run exits nonzero (R5.6).

    **Validates: Requirements 5.6**
    """
    result = _run_ci_gate([_make_finding(Severity.HIGH)], [])

    assert result.exit_code == 1, result.output


def test_ci_mode_without_fail_on_uses_high_default_medium_finding_passes():
    """``--ci-mode`` with no ``--fail-on`` passes a medium finding (default high).

    A medium finding is below the ``high`` default threshold, so the gate passes
    with exit 0 — demonstrating the default is ``high`` and not, say, ``medium``
    or ``critical`` (R5.6).

    **Validates: Requirements 5.6**
    """
    result = _run_ci_gate([_make_finding(Severity.MEDIUM)], [])

    assert result.exit_code == 0, result.output


# --------------------------------------------------------------------------- #
# R5.2: --sarif with zero findings writes a valid empty report.
# --------------------------------------------------------------------------- #

def test_sarif_zero_findings_writes_valid_empty_report():
    """``--sarif`` with no findings writes a valid empty SARIF 2.1.0 report (R5.2).

    The REAL report generator runs inside an isolated filesystem so the produced
    ``.sarif`` artifact is read back and validated: it is well-formed SARIF
    2.1.0 with a single run whose results array is empty.

    **Validates: Requirements 5.2**
    """
    results = _make_results([])
    runner = CliRunner()
    with runner.isolated_filesystem():
        with patch.object(apileaks, "APILeakCore", _fake_core_class(results)), patch.object(
            apileaks.ConfigurationManager, "validate_configuration", return_value=[]
        ):
            result = runner.invoke(
                cli, ["--no-banner", "scan", "--target", TARGET, "--sarif"]
            )

        assert result.exit_code == 0, result.output

        sarif_files = glob.glob("**/*.sarif", recursive=True)
        assert sarif_files, f"no .sarif report was written; output:\n{result.output}"

        doc = json.loads(open(sarif_files[0], encoding="utf-8").read())

    # Valid SARIF 2.1.0 document with exactly one run and zero results.
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert len(doc["runs"]) == 1
    assert doc["runs"][0]["results"] == []


# --------------------------------------------------------------------------- #
# R5.7 / Property 7: malformed --baseline aborts nonzero with no gate.
# --------------------------------------------------------------------------- #

def test_malformed_baseline_exits_nonzero_naming_file_with_no_scan():
    """A malformed ``--baseline`` file aborts nonzero, naming it, no scan (R5.7).

    An existing but unparseable baseline cannot establish prior knowledge, so
    the run aborts before any request is issued: no engine call is made (hence
    no Severity_Gate runs against a partial baseline) and the error names the
    offending file.

    **Validates: Requirements 5.7**
    """
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("bad_baseline.json", "w", encoding="utf-8") as handle:
            handle.write("{ this is not valid json ]")

        with patch.object(apileaks, "run_enhanced_apileak") as mock_run, patch.object(
            apileaks, "APILeakCore"
        ) as mock_core:
            result = runner.invoke(
                cli,
                ["--no-banner", "scan", "--target", TARGET, "--ci-mode",
                 "--baseline", "bad_baseline.json"],
            )

    # Nonzero exit, the baseline file is named, and NO scan/gate ran.
    assert result.exit_code != 0
    assert "bad_baseline.json" in result.stderr
    mock_run.assert_not_called()
    mock_core.assert_not_called()


def test_unreadable_baseline_directory_exits_nonzero_with_no_scan():
    """A ``--baseline`` path that is a directory (unreadable as a file) aborts (R5.7).

    **Validates: Requirements 5.7**
    """
    runner = CliRunner()
    with runner.isolated_filesystem():
        import os

        os.mkdir("baseline_dir")

        with patch.object(apileaks, "run_enhanced_apileak") as mock_run, patch.object(
            apileaks, "APILeakCore"
        ) as mock_core:
            result = runner.invoke(
                cli,
                ["--no-banner", "scan", "--target", TARGET, "--ci-mode",
                 "--baseline", "baseline_dir"],
            )

    assert result.exit_code != 0
    assert "baseline_dir" in result.stderr
    mock_run.assert_not_called()
    mock_core.assert_not_called()


def test_missing_baseline_path_is_allowed_and_runs_the_scan():
    """A *missing* baseline path is not an error: the scan runs (empty baseline).

    R5.7 targets unreadable/malformed files; a nonexistent path is documented to
    treat every finding as new, so it must NOT abort the run.

    **Validates: Requirements 5.7**
    """
    result = _run_ci_gate([], ["--baseline", "does_not_exist.json"])

    # The gate ran (zero findings -> exit 0), i.e. the missing baseline was
    # tolerated rather than treated as an error.
    assert result.exit_code == 0, result.output


def test_valid_empty_baseline_runs_the_scan():
    """A well-formed baseline file is accepted and the scan runs (R5.7 negative).

    **Validates: Requirements 5.7**
    """
    results = _make_results([])
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("good_baseline.json", "w", encoding="utf-8") as handle:
            handle.write('{"findings": []}')

        with patch.object(apileaks, "APILeakCore", _fake_core_class(results)), patch.object(
            apileaks.ConfigurationManager, "validate_configuration", return_value=[]
        ), patch("utils.report_generator.ReportGenerator") as report_gen:
            report_gen.return_value.save_reports.return_value = []
            result = runner.invoke(
                cli,
                ["--no-banner", "scan", "--target", TARGET, "--ci-mode",
                 "--baseline", "good_baseline.json"],
            )

    assert result.exit_code == 0, result.output
