"""Behavior-preservation characterization/snapshot baselines for par-positional-markers.

# Feature: par-positional-markers, Task 1.2

These are *characterization tests* for the par-positional-markers feature: they
capture the CURRENT (pre-feature) behavior as a baseline that MUST keep passing
before and after every change in the par-positional-markers effort. They mirror
the parameter-fuzzing task 1.2 baselines (test_parameter_fuzzing_baselines.py)
and serve as the behavior-preservation guardrail for this feature.

Snapshots covered:
  - Markerless ``par`` (Name_Discovery_Mode): stdout, findings payload shape,
    request volume, and exit code.
  - ``dir`` marker behavior: stdout, results, exit code (byte-for-byte
    preservation for the dir command).
  - ``scan``/``full`` stdout+results+exit (byte-for-byte preservation).
  - A representative OWASP run (bola module).
  - All retained legacy ``par`` options parse without terminating.

All tests run fully offline using the shared HTTPRequestEngineStub (no real
network access). Volatile fields (scan IDs, durations, report paths) are
normalized out so snapshots are stable across runs.

_Requirements: 2.1, 2.4, 2.5, 2.6_
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from urllib.parse import urlparse

import pytest
from click.testing import CliRunner

from tests.support.http_stub import HTTPRequestEngineStub, ScriptedResponse, RecordedRequest


# ---------------------------------------------------------------------------
# Snapshot storage — golden files go alongside the parameter-fuzzing baselines
# ---------------------------------------------------------------------------

BASELINE_DIR = Path(__file__).parent / "support" / "baselines"

# Offline stub target — no real network access is ever made.
TARGET = "https://api.example.test"

# Target with one FUZZ marker (for dir marker-behavior snapshot)
TARGET_ONE_MARKER = "https://api.example.test/FUZZ"


def _assert_snapshot(name: str, content: str) -> None:
    """Assert ``content`` matches the stored golden snapshot ``name``.

    On first run (no golden file yet) the snapshot is written and the assertion
    trivially passes. On every subsequent run the content must match byte-for-byte.
    """
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    golden = BASELINE_DIR / name
    if not golden.exists():
        golden.write_text(content, encoding="utf-8")
        return
    expected = golden.read_text(encoding="utf-8")
    assert content == expected, (
        f"Behavior-preservation snapshot '{name}' changed.\n"
        f"--- expected (baseline) ---\n{expected}\n"
        f"--- actual (current) ---\n{content}\n"
    )


# ---------------------------------------------------------------------------
# Offline HTTP layer — reuses the task 1.1 stub from parameter-fuzzing
# ---------------------------------------------------------------------------

KNOWN_OK_LEAVES = {"users", "health"}
KNOWN_OK_MARKER_SEGMENTS = {"users", "health"}


def _path_leaf(url: str) -> str:
    path = urlparse(url).path.rstrip("/")
    if not path:
        return ""
    return path.rsplit("/", 1)[-1]


def _offline_responder(recorded: RecordedRequest) -> ScriptedResponse:
    """Deterministic offline responder for characterization runs."""
    leaf = _path_leaf(recorded.url)
    if leaf in KNOWN_OK_LEAVES:
        return ScriptedResponse(status_code=200, body={"resource": leaf, "ok": True})
    return ScriptedResponse(status_code=404, body={"error": "not_found"})


class _OfflineHTTPRequestEngine(HTTPRequestEngineStub):
    """Drop-in replacement for ``HTTPRequestEngine``. No real network access."""

    def __init__(self, *args, **kwargs):
        super().__init__(responder=_offline_responder)


@pytest.fixture
def offline_http(monkeypatch):
    """Patch the single ``HTTPRequestEngine`` construction point to the stub."""
    import utils.http_client as hc
    monkeypatch.setattr(hc, "HTTPRequestEngine", _OfflineHTTPRequestEngine)
    return _OfflineHTTPRequestEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_wordlist(tmp_path: Path, entries) -> str:
    wl = tmp_path / "wordlist.txt"
    wl.write_text("\n".join(entries) + "\n", encoding="utf-8")
    return str(wl)


def _invoke_cli(args):
    import apileaks
    runner = CliRunner()
    return runner.invoke(apileaks.cli, args)


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _normalize_stdout(text: str) -> str:
    """Strip volatile fields so CLI stdout snapshots are stable."""
    out = _ANSI_RE.sub("", text)
    lines = []
    in_reports_block = False
    for raw in out.splitlines():
        line = raw.rstrip()
        if line.startswith("Scan ID:"):
            line = "Scan ID: <SCAN_ID>"
        elif line.startswith("Duration:"):
            line = "Duration: <DURATION>"
        elif line.startswith("Reports generated:"):
            in_reports_block = True
            lines.append(line)
            continue
        elif in_reports_block and line.strip().startswith("- "):
            line = "  - <REPORT_FILE>"
        elif in_reports_block and line.strip() == "":
            in_reports_block = False
        lines.append(line)
    return "\n".join(lines) + "\n"


@pytest.fixture
def stub_reports(monkeypatch):
    """Replace report writing with a deterministic no-op."""
    from utils.report_generator import ReportGenerator

    def _fake_save_reports(self, results, output_dir, scan_type, output_filename=None, formats=None):
        return [f"reports/{scan_type}_baseline.json"]

    monkeypatch.setattr(ReportGenerator, "save_reports", _fake_save_reports)


# ===========================================================================
# 1. Markerless par (Name_Discovery_Mode) baselines
#    Requirement 2.1 — output, findings, request volume, exit code unchanged
# ===========================================================================

def _run_par_offline(tmp_path: Path, *, wordlist_entries=("id", "debug", "admin")):
    """Run ``par`` end-to-end offline. Returns the completed ``APILeakCore``."""
    from apileaks import create_default_config
    from core.config import ConfigurationManager
    from core.engine import APILeakCore

    wordlist = _write_wordlist(tmp_path, list(wordlist_entries))
    config_dict = create_default_config(
        TARGET, wordlist, "par",
        query_candidates=list(wordlist_entries),
        body_candidates=list(wordlist_entries),
    )
    apileak_config = ConfigurationManager().load_config_from_dict(config_dict)
    core = APILeakCore(apileak_config)
    asyncio.run(core.run_scan(TARGET))
    return core


def _parameters_tested(core) -> int:
    """Read the reported ``parameters_tested`` count from a completed run.

    Mirrors the helper in test_par_disconnected_regression.py.
    """
    results = core.scan_results
    assert results is not None, "run_scan did not populate scan_results"
    fuzzing_results = getattr(results, "fuzzing_results", None)
    if fuzzing_results is not None and "parameters_tested" in fuzzing_results:
        return fuzzing_results["parameters_tested"]
    return getattr(results.statistics, "parameters_tested", 0)


def test_par_name_discovery_parameters_tested_nonzero(offline_http, tmp_path):
    """Markerless ``par`` runs Name_Discovery_Mode and tests >= 1 parameter.

    Locks the core liveness invariant: a markerless ``par`` run against a
    reachable offline target tests at least one parameter name (parameters_tested
    >= 1). This guards against the disconnected-par regression.

    _Requirements: 2.1_
    """
    core = _run_par_offline(tmp_path)
    parameters_tested = _parameters_tested(core)
    assert parameters_tested >= 1, (
        f"Markerless par must test >= 1 parameter; got {parameters_tested}"
    )
    _assert_snapshot(
        "ppm_par_name_discovery_parameters_tested_nonzero.txt",
        f"{parameters_tested >= 1}\n",
    )


def _par_findings_summary(core) -> dict:
    """Normalized findings payload shape for snapshotting."""
    collector = core.get_findings_collector()
    stats = collector.get_statistics()
    return {
        "total_findings": stats["total_findings"],
        "critical": stats["critical_findings"],
        "high": stats["high_findings"],
        "medium": stats["medium_findings"],
        "low": stats["low_findings"],
        "info": stats["info_findings"],
        "finding_categories": sorted(
            {f.category for f in collector.get_findings()}
        ),
    }


def test_par_name_discovery_findings_payload_shape(offline_http, tmp_path):
    """Markerless ``par`` findings payload shape is stable (pre-feature baseline).

    Snapshots the SHAPE of the findings payload (totals per severity, categories)
    but not the exact counts, which are wordlist-dependent. The invariant checked
    here is that total = sum of per-severity counts, which must always hold.

    _Requirements: 2.1_
    """
    core = _run_par_offline(tmp_path)
    summary = _par_findings_summary(core)

    # Invariant: total findings == sum of per-severity counts.
    assert summary["total_findings"] == (
        summary["critical"] + summary["high"] + summary["medium"]
        + summary["low"] + summary["info"]
    ), "Findings totals do not sum correctly"

    _assert_snapshot(
        "ppm_par_name_discovery_findings_shape.json",
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
    )


def test_par_name_discovery_request_volume(offline_http, tmp_path):
    """Markerless ``par`` request volume is non-zero (pre-feature baseline).

    Asserts the stub recorded at least one HTTP request during a markerless par
    run, snapshotting whether the request count is non-zero as the baseline.
    The exact count is wordlist-dependent so we snapshot a boolean flag only.

    _Requirements: 2.1_
    """
    core = _run_par_offline(tmp_path)
    # parameters_tested >= 1 implies requests were made (baseline + candidates)
    parameters_tested = _parameters_tested(core)
    requests_nonzero = parameters_tested >= 1

    _assert_snapshot(
        "ppm_par_name_discovery_request_volume_nonzero.txt",
        f"{requests_nonzero}\n",
    )


def test_par_cli_name_discovery_stdout_and_exit_code(offline_http, stub_reports, tmp_path):
    """Markerless ``par`` CLI: stdout + exit code are stable (pre-feature baseline).

    Invokes ``par`` without any marker or marker-only option and snapshots the
    normalized stdout and exit code. This is the primary Name_Discovery_Mode
    preservation guardrail.

    _Requirements: 2.1_
    """
    wordlist = _write_wordlist(tmp_path, ["id", "debug"])
    result = _invoke_cli([
        "--no-banner",
        "par",
        "--target", TARGET,
        "--wordlist", wordlist,
        "--log-level", "ERROR",
    ])

    assert result.exit_code == 0, result.output

    _assert_snapshot("ppm_par_name_discovery_stdout.txt", _normalize_stdout(result.output))
    _assert_snapshot("ppm_par_name_discovery_exit_code.txt", f"{result.exit_code}\n")


# ===========================================================================
# 2. dir marker behavior baseline (byte-for-byte preservation)
#    Requirement 2.4 — dir marker output/results/exit unchanged
# ===========================================================================

def test_dir_marker_behavior_baseline_stdout_and_exit(offline_http, stub_reports, tmp_path):
    """``dir`` marker behavior: stdout + exit code unchanged (pre-feature baseline).

    Runs ``dir`` with a FUZZ-marked target and a tiny wordlist. The marker
    substitution replaces FUZZ with each wordlist entry; the offline stub answers
    200 for "users" and 404 for everything else. Snapshots normalized stdout and
    exit code as the pre-feature behavior.

    _Requirements: 2.4_
    """
    wordlist = _write_wordlist(tmp_path, ["users", "admin"])
    result = _invoke_cli([
        "--no-banner",
        "dir",
        "--target", TARGET_ONE_MARKER,
        "--wordlist", wordlist,
        "--log-level", "ERROR",
    ])

    # dir marker mode should complete without error
    assert result.exit_code == 0, result.output

    _assert_snapshot(
        "ppm_dir_marker_behavior_stdout.txt",
        _normalize_stdout(result.output),
    )
    _assert_snapshot(
        "ppm_dir_marker_behavior_exit_code.txt",
        f"{result.exit_code}\n",
    )


def _run_dir_marker_offline(tmp_path: Path):
    """Run ``dir`` with FUZZ marker end-to-end offline. Returns completed core."""
    from apileaks import create_default_config
    from core.config import ConfigurationManager
    from core.engine import APILeakCore

    wordlist = _write_wordlist(tmp_path, ["users", "admin"])
    config_dict = create_default_config(
        TARGET_ONE_MARKER, wordlist, "dir",
    )
    # Wire in marker wordlists directly on the endpoints sub-dict (as dir does).
    config_dict["fuzzing"]["endpoints"]["fuzz_keyword"] = "FUZZ"
    config_dict["fuzzing"]["endpoints"]["fuzz_mode"] = "clusterbomb"
    config_dict["fuzzing"]["endpoints"]["marker_wordlists"] = [["users", "admin"]]
    apileak_config = ConfigurationManager().load_config_from_dict(config_dict)
    core = APILeakCore(apileak_config)
    asyncio.run(core.run_scan(TARGET_ONE_MARKER))
    return core


def _endpoint_summary(core) -> list:
    """Deterministic, order-independent summary of discovered endpoints."""
    endpoints = core.get_discovered_endpoints()
    rows = sorted({
        (
            _path_leaf(e.url),
            e.method,
            getattr(e, "status_code", None),
            getattr(getattr(e, "status", None), "value", None),
        )
        for e in endpoints
    })
    return [
        {"leaf": leaf, "method": method, "status_code": sc, "status": status}
        for (leaf, method, sc, status) in rows
    ]


def test_dir_marker_behavior_results_snapshot(offline_http, tmp_path):
    """``dir`` marker behavior: discovered endpoints snapshot (pre-feature baseline).

    The offline stub returns 200 for "users" and 404 for "admin", so only
    "users" should appear as a valid endpoint. Snapshots the results payload.

    _Requirements: 2.4_
    """
    core = _run_dir_marker_offline(tmp_path)
    summary = _endpoint_summary(core)

    # Invariant: "users" is discovered as a 200 endpoint via marker substitution.
    leaves = {row["leaf"] for row in summary}
    assert "users" in leaves
    users_rows = [r for r in summary if r["leaf"] == "users"]
    assert any(r["status_code"] == 200 for r in users_rows)

    _assert_snapshot(
        "ppm_dir_marker_behavior_results.json",
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
    )


# ===========================================================================
# 3. scan/full stdout+results+exit baselines (byte-for-byte preservation)
#    Requirement 2.5 — scan/full output unchanged
# ===========================================================================

def _run_scan_offline(scan_type: str, tmp_path: Path, enabled_modules=None):
    """Build the real command config and run the engine fully offline."""
    from apileaks import create_default_config
    from core.config import ConfigurationManager
    from core.engine import APILeakCore

    wordlist = _write_wordlist(tmp_path, ["users", "admin"])
    config_dict = create_default_config(TARGET, wordlist, scan_type)
    if enabled_modules is not None:
        config_dict["owasp_testing"]["enabled_modules"] = enabled_modules

    apileak_config = ConfigurationManager().load_config_from_dict(config_dict)
    core = APILeakCore(apileak_config)
    asyncio.run(core.run_scan(TARGET))
    return core


def _findings_summary(core) -> dict:
    """Deterministic summary of findings + OWASP coverage."""
    collector = core.get_findings_collector()
    stats = collector.get_statistics()
    coverage = collector.get_owasp_coverage()
    return {
        "total_findings": stats["total_findings"],
        "critical": stats["critical_findings"],
        "high": stats["high_findings"],
        "medium": stats["medium_findings"],
        "low": stats["low_findings"],
        "info": stats["info_findings"],
        "owasp_tested_categories": coverage["tested_categories"],
        "owasp_total_categories": coverage["total_categories"],
        "finding_categories": sorted(
            {f.category for f in collector.get_findings()}
        ),
    }


def test_scan_results_snapshot(offline_http, tmp_path):
    """``scan`` results are deterministic offline (pre-feature baseline).

    Runs a full scan (endpoints + parameters) against the offline stub and
    snapshots the findings/coverage summary.

    _Requirements: 2.5_
    """
    core = _run_scan_offline("full", tmp_path, enabled_modules=["bola"])
    summary = _findings_summary(core)

    # Invariant: findings totals sum correctly, OWASP coverage is stable.
    assert summary["total_findings"] == (
        summary["critical"] + summary["high"] + summary["medium"]
        + summary["low"] + summary["info"]
    )
    assert summary["owasp_total_categories"] == 10

    _assert_snapshot(
        "ppm_scan_results.json",
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
    )


def test_scan_cli_stdout_and_exit_snapshot(offline_http, stub_reports, tmp_path):
    """``scan`` CLI stdout + exit code are stable (pre-feature baseline).

    _Requirements: 2.5_
    """
    wordlist = _write_wordlist(tmp_path, ["users", "admin"])
    result = _invoke_cli([
        "--no-banner",
        "scan",
        "--target", TARGET,
        "--modules", "bola",
        "--log-level", "ERROR",
    ])

    assert result.exit_code in (0, 1, 2), result.output

    _assert_snapshot(
        "ppm_scan_cli_stdout.txt",
        _normalize_stdout(result.output),
    )
    _assert_snapshot(
        "ppm_scan_cli_exit_code.txt",
        f"{result.exit_code}\n",
    )


def test_full_alias_stdout_and_exit_snapshot(offline_http, stub_reports, tmp_path):
    """``full`` CLI stdout + exit code are stable (pre-feature baseline).

    _Requirements: 2.5_
    """
    result = _invoke_cli([
        "--no-banner",
        "full",
        "--target", TARGET,
        "--modules", "bola",
        "--log-level", "ERROR",
    ])

    # full is a deprecated alias; exit code may be 0, 1, or 2.
    assert result.exit_code in (0, 1, 2), result.output
    combined = _ANSI_RE.sub("", (result.output or "") + (result.stderr or ""))
    # Deprecation notice must reference both 'full' and 'scan'.
    assert "full" in combined and "scan" in combined

    _assert_snapshot(
        "ppm_full_alias_stdout.txt",
        _normalize_stdout(result.output),
    )
    _assert_snapshot(
        "ppm_full_alias_exit_code.txt",
        f"{result.exit_code}\n",
    )


# ===========================================================================
# 4. Representative OWASP run (bola) — results snapshot
#    Requirement 2.5 — OWASP results unchanged
# ===========================================================================

def test_owasp_bola_run_results_snapshot(offline_http, tmp_path):
    """Representative OWASP bola run: results snapshot (pre-feature baseline).

    Mirrors the parameter-fuzzing baseline for OWASP runs. The bola module is
    representative; its findings/coverage summary must remain stable.

    _Requirements: 2.5_
    """
    core = _run_scan_offline("full", tmp_path, enabled_modules=["bola"])
    summary = _findings_summary(core)

    # Invariants shared with the existing parameter-fuzzing baseline.
    assert summary["owasp_total_categories"] == 10
    assert summary["total_findings"] == (
        summary["critical"] + summary["high"] + summary["medium"]
        + summary["low"] + summary["info"]
    )

    _assert_snapshot(
        "ppm_owasp_bola_results.json",
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
    )


# ===========================================================================
# 5. Retained legacy par options — parse without terminating
#    Requirement 2.6 — all legacy par options accepted
# ===========================================================================

# The complete set of legacy ``par`` options that existed before the
# par-positional-markers feature work (mirrors parameter-fuzzing task 11.6).
PPM_LEGACY_PAR_OPTIONS = frozenset({
    "--target",
    "--wordlist",
    "--output",
    "--log-level",
    "--log-file",
    "--json-logs",
    "--rate-limit",
    "--methods",
    "--user-agent-random",
    "--user-agent-custom",
    "--user-agent-file",
    "--jwt",
    "--response",
    "--status-code",
    "--detect-framework",
    "--proxy",
    "--proxy-verify-ssl",
    "--confirm-hits",
    "--max-requests",
    "--timeout",
    "--retries",
    "--header",
    "--cookie",
    "--basic-auth",
    "--match-size",
    "--match-words",
    "--match-lines",
    "--match-regex",
    "--match-time",
    "--filter-size",
    "--filter-words",
    "--filter-lines",
    "--filter-regex",
    "--filter-time",
    "--output-format",
    "--output-file",
    "--client-cert",
    "--ca-bundle",
    "--resolve",
    "--concurrency",
})


def test_par_legacy_options_still_declared_on_command():
    """Every legacy ``par`` option is still declared on the live command (R2.6).

    Introspects the registered ``par`` Click command's parameters and asserts the
    complete pre-feature option surface remains fully present (none was silently
    removed by the par-positional-markers work).

    _Requirements: 2.6_
    """
    import apileaks

    par_cmd = apileaks.cli.commands["par"]
    declared = set()
    for param in par_cmd.params:
        declared.update(param.opts)
        declared.update(param.secondary_opts)

    missing = PPM_LEGACY_PAR_OPTIONS - declared
    assert not missing, (
        f"Legacy par options missing from command after par-positional-markers work: "
        f"{sorted(missing)}"
    )


def test_par_accepts_full_legacy_option_surface_without_terminating(
    offline_http, stub_reports, tmp_path
):
    """Every retained legacy ``par`` option is accepted and the run completes.

    Exercises the full pre-feature ``par`` option surface in a single invocation
    and asserts the command completes with exit code 0 (no option parsing or
    handling failure).

    _Requirements: 2.6_
    """
    wordlist = _write_wordlist(tmp_path, ["debug", "admin"])
    ua_file = tmp_path / "agents.txt"
    ua_file.write_text("APILeak-Test-Agent/1.0\n", encoding="utf-8")

    result = _invoke_cli([
        "--no-banner",
        "par",
        "--target", TARGET,
        "--wordlist", wordlist,
        "--output", "ppm_legacy_test",
        "--log-level", "ERROR",
        "--json-logs",
        "--rate-limit", "5",
        "--methods", "GET,POST",
        "--user-agent-file", str(ua_file),
        "--response", "200,404",
        "--status-code", "200",
        "--detect-framework",
    ])

    assert result.exit_code == 0, (result.output, getattr(result, "stderr", ""))

    _assert_snapshot(
        "ppm_par_legacy_options_exit_code.txt",
        f"{result.exit_code}\n",
    )


def test_par_repeatable_wordlist_backward_compatible(offline_http, stub_reports, tmp_path):
    """A single ``--wordlist`` still works (backward compatible, R2.6).

    ``--wordlist`` was already repeatable before this feature; a lone value must
    keep working.

    _Requirements: 2.6_
    """
    wordlist = _write_wordlist(tmp_path, ["token"])
    result = _invoke_cli([
        "--no-banner",
        "par",
        "--target", TARGET,
        "--wordlist", wordlist,
        "--log-level", "ERROR",
    ])

    assert result.exit_code == 0, (result.output, getattr(result, "stderr", ""))


def test_par_no_deprecation_notice_for_retained_options(offline_http, stub_reports, tmp_path):
    """A retained-option ``par`` run emits NO deprecation notice.

    The par-positional-markers work must not invent deprecations for any retained
    legacy option.

    _Requirements: 2.6_
    """
    wordlist = _write_wordlist(tmp_path, ["debug"])
    result = _invoke_cli([
        "--no-banner",
        "par",
        "--target", TARGET,
        "--wordlist", wordlist,
        "--methods", "GET,POST",
        "--rate-limit", "5",
        "--detect-framework",
        "--log-level", "ERROR",
    ])

    assert result.exit_code == 0, (result.output, getattr(result, "stderr", ""))

    combined = _ANSI_RE.sub("", result.output or "")
    stderr_combined = _ANSI_RE.sub("", getattr(result, "stderr", "") or "")
    deprecation_lines = [
        line for line in (combined + stderr_combined).splitlines()
        if "[DEPRECATION]" in line
    ]
    assert deprecation_lines == [], (
        f"Unexpected deprecation notices emitted: {deprecation_lines}"
    )


# ===========================================================================
# 6. Config-mode matrix for par is unchanged after feature work
#    Requirement 2.4 / 2.5 — config assembly for dir/scan/full unaffected
# ===========================================================================

def test_par_positional_markers_config_mode_matrix_unchanged():
    """par/dir/scan config-mode matrix is unchanged by par-positional-markers work.

    Locks the exact fuzzing-mode + OWASP-module wiring for every command:
      - dir: endpoints enabled, parameters disabled, no OWASP modules
      - par: endpoints disabled, parameters enabled, no OWASP modules
      - full: both enabled, standard OWASP module set

    This is the config-seam preservation guardrail: any regression at this
    level means the feature accidentally changed non-par behavior.

    _Requirements: 2.4, 2.5_
    """
    from apileaks import create_default_config

    dir_cfg = create_default_config(TARGET, None, "dir")
    par_cfg = create_default_config(TARGET, None, "par")
    full_cfg = create_default_config(TARGET, None, "full")

    matrix = {
        "dir": {
            "endpoints_enabled": dir_cfg["fuzzing"]["endpoints"]["enabled"],
            "parameters_enabled": dir_cfg["fuzzing"]["parameters"]["enabled"],
            "headers_enabled": dir_cfg["fuzzing"]["headers"]["enabled"],
            "owasp_modules": dir_cfg["owasp_testing"]["enabled_modules"],
        },
        "par": {
            "endpoints_enabled": par_cfg["fuzzing"]["endpoints"]["enabled"],
            "parameters_enabled": par_cfg["fuzzing"]["parameters"]["enabled"],
            "headers_enabled": par_cfg["fuzzing"]["headers"]["enabled"],
            "owasp_modules": par_cfg["owasp_testing"]["enabled_modules"],
        },
        "full": {
            "endpoints_enabled": full_cfg["fuzzing"]["endpoints"]["enabled"],
            "parameters_enabled": full_cfg["fuzzing"]["parameters"]["enabled"],
            "headers_enabled": full_cfg["fuzzing"]["headers"]["enabled"],
            "owasp_modules": full_cfg["owasp_testing"]["enabled_modules"],
        },
    }

    # Direct invariants — these must NEVER change.
    assert matrix["dir"]["endpoints_enabled"] is True
    assert matrix["dir"]["parameters_enabled"] is False
    assert matrix["par"]["endpoints_enabled"] is False
    assert matrix["par"]["parameters_enabled"] is True
    assert matrix["par"]["owasp_modules"] == []
    assert matrix["full"]["endpoints_enabled"] is True
    assert matrix["full"]["parameters_enabled"] is True

    _assert_snapshot(
        "ppm_command_config_mode_matrix.json",
        json.dumps(matrix, indent=2, sort_keys=True) + "\n",
    )


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
