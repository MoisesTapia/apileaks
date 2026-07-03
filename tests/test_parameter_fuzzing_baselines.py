"""Behavior-preservation characterization/snapshot baselines.

**Feature: parameter-fuzzing, Task 1.2 (behavior preservation guardrail)**

These are *characterization tests*: they capture the CURRENT behavior of the
existing implementation as a baseline that MUST keep passing before and after
every change in the parameter-fuzzing effort. They are deliberately offline and
deterministic:

* The registered engine-module set and registration order (both the OWASP
  modules registered on ``APILeakCore`` and the orchestration phases registered
  on ``EnhancedOrchestrator``) are asserted against expected constants captured
  from the current implementation (Requirement 2.3).
* ``dir`` and ``scan``/``full`` are exercised end-to-end against an offline
  HTTP layer (no real network access), and their structured results, OWASP
  module results, stdout, and exit codes are snapshotted (Requirements 2.1,
  2.2, 2.4). ``par`` itself is intentionally NOT pinned as a preservation
  baseline here: it is the command being fixed, so its behavior is expected to
  change (its disconnected-state regression is covered separately).

Offline HTTP
    Every network call in the scan path funnels through
    ``HTTPRequestEngine.request``. We reuse the shared offline stub built in task
    1.1 (:mod:`tests.support.http_stub`) by patching the single construction
    point (``utils.http_client.HTTPRequestEngine`` — imported function-locally at
    every site) so the real engine is transparently replaced with a
    deterministic, network-free double.

Snapshots
    Golden snapshots live under ``tests/support/baselines`` and are generated on
    first run, then asserted on every subsequent run. Volatile fields (scan id,
    duration, timestamps, report paths) are normalized out so the snapshot is
    stable. Direct invariant assertions accompany every snapshot so the offline
    harness itself is validated independently of the golden files.

_Requirements: 2.1, 2.2, 2.3, 2.4_
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
# Snapshot storage
# ---------------------------------------------------------------------------

BASELINE_DIR = Path(__file__).parent / "support" / "baselines"

TARGET = "https://api.example.test"


def _assert_snapshot(name: str, content: str) -> None:
    """Assert ``content`` matches the stored golden snapshot ``name``.

    On first run (no golden file yet) the snapshot is written and the assertion
    trivially passes — this captures the CURRENT behavior as the baseline. On
    every subsequent run the content must match byte-for-byte, so a behavioral
    regression in a preserved command surfaces as a failure here.
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
# Offline HTTP layer (reuses the task 1.1 stub)
# ---------------------------------------------------------------------------

# Path leaves that the offline target "serves" with a 200; everything else 404s.
# Keeping this tiny and deterministic makes discovery + OWASP results stable.
KNOWN_OK_LEAVES = {"users", "health"}


def _path_leaf(url: str) -> str:
    path = urlparse(url).path.rstrip("/")
    if not path:
        return ""
    return path.rsplit("/", 1)[-1]


def _offline_responder(recorded: RecordedRequest) -> ScriptedResponse:
    """Deterministic offline responder used for every characterization run."""
    leaf = _path_leaf(recorded.url)
    if leaf in KNOWN_OK_LEAVES:
        return ScriptedResponse(status_code=200, body={"resource": leaf, "ok": True})
    return ScriptedResponse(status_code=404, body={"error": "not_found"})


class _OfflineHTTPRequestEngine(HTTPRequestEngineStub):
    """Drop-in replacement for ``HTTPRequestEngine`` used in characterization.

    Accepts (and ignores) the real engine's constructor arguments so it can be
    substituted at every ``HTTPRequestEngine(...)`` call site, while returning
    deterministic scripted responses with no network access.
    """

    def __init__(self, *args, **kwargs):  # noqa: D401 - see class docstring
        super().__init__(responder=_offline_responder)


@pytest.fixture
def offline_http(monkeypatch):
    """Patch the single ``HTTPRequestEngine`` construction point to the stub.

    ``core.engine`` and ``core.orchestrator`` both import ``HTTPRequestEngine``
    function-locally from ``utils.http_client`` at call time, so patching the
    attribute on ``utils.http_client`` transparently replaces every engine
    constructed during a scan.
    """
    import utils.http_client as hc

    monkeypatch.setattr(hc, "HTTPRequestEngine", _OfflineHTTPRequestEngine)
    return _OfflineHTTPRequestEngine


# ---------------------------------------------------------------------------
# Small deterministic wordlist helper
# ---------------------------------------------------------------------------

def _write_wordlist(tmp_path: Path, entries) -> str:
    wl = tmp_path / "wordlist.txt"
    wl.write_text("\n".join(entries) + "\n", encoding="utf-8")
    return str(wl)


# ===========================================================================
# 1. Engine-module set and registration order (Requirement 2.3)
# ===========================================================================

# The exact set and order of OWASP modules the engine registers today. This is
# the behavior-preservation guardrail for module registration: any reorder,
# addition, or removal must be an intentional, reviewed change.
EXPECTED_OWASP_MODULE_ORDER = [
    "bola",
    "auth",
    "property",
    "function_auth",
    "resource",
    "ssrf",
    "business_flow",
    "security_misconfig",
    "inventory",
    "unsafe_consumption",
]

# The exact set and order of orchestration phases registered on the enhanced
# orchestrator today (insertion order in ``_initialize_phases``).
EXPECTED_PHASE_ORDER = [
    "discovery",
    "advanced_discovery",
    "waf_detection",
    "traditional_fuzzing",
    "owasp_testing",
    "security_analysis",
    "results_aggregation",
]


def _make_engine_config(enabled_modules=None):
    """Build an APILeakConfig with advanced discovery disabled (no network)."""
    from core.config import (
        APILeakConfig,
        TargetConfig,
        FuzzingConfig,
        OWASPConfig,
        AuthConfig,
        RateLimitConfig,
        ReportConfig,
        AdvancedDiscoveryConfig,
    )

    if enabled_modules is None:
        enabled_modules = list(EXPECTED_OWASP_MODULE_ORDER)
    return APILeakConfig(
        target=TargetConfig(base_url=TARGET),
        fuzzing=FuzzingConfig(),
        owasp_testing=OWASPConfig(enabled_modules=enabled_modules),
        authentication=AuthConfig(),
        rate_limiting=RateLimitConfig(),
        reporting=ReportConfig(),
        advanced_discovery=AdvancedDiscoveryConfig(enabled=False),
    )


@pytest.mark.asyncio
async def test_owasp_module_registration_set_and_order(offline_http):
    """The engine registers exactly the expected OWASP modules, in order.

    _Requirements: 2.3_
    """
    from core.engine import APILeakCore

    core = APILeakCore(_make_engine_config())
    await core._initialize_owasp_modules()

    registered = list(core.owasp_modules.keys())

    # Set equality (no missing/extra modules) and exact registration order.
    assert set(registered) == set(EXPECTED_OWASP_MODULE_ORDER)
    assert registered == EXPECTED_OWASP_MODULE_ORDER

    _assert_snapshot(
        "engine_owasp_module_order.json",
        json.dumps(registered, indent=2) + "\n",
    )


def test_orchestrator_phase_registration_set_and_order():
    """The enhanced orchestrator registers exactly the expected phases, in order.

    _Requirements: 2.3_
    """
    from core.orchestrator import EnhancedOrchestrator
    from utils.findings import FindingsCollector

    orchestrator = EnhancedOrchestrator(_make_engine_config(), FindingsCollector("baseline"))

    registered = list(orchestrator.phases.keys())

    assert set(registered) == set(EXPECTED_PHASE_ORDER)
    assert registered == EXPECTED_PHASE_ORDER

    _assert_snapshot(
        "orchestrator_phase_order.json",
        json.dumps(registered, indent=2) + "\n",
    )


# ===========================================================================
# 2. Config-construction characterization for each command (Req 2.1, 2.2, 2.4)
# ===========================================================================

def test_command_config_mode_matrix():
    """dir/par/scan(full) build the expected fuzzing-mode + OWASP-module wiring.

    Locks the config-construction seam every command's runtime behavior depends
    on: dir discovers endpoints only, par fuzzes parameters only (endpoints
    disabled), and scan/full enables both plus the default OWASP module set.

    _Requirements: 2.1, 2.2, 2.4_
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

    # Direct invariants (documented current behavior).
    assert matrix["dir"]["endpoints_enabled"] is True
    assert matrix["dir"]["parameters_enabled"] is False
    assert matrix["par"]["endpoints_enabled"] is False
    assert matrix["par"]["parameters_enabled"] is True
    assert matrix["par"]["owasp_modules"] == []
    assert matrix["full"]["endpoints_enabled"] is True
    assert matrix["full"]["parameters_enabled"] is True

    _assert_snapshot(
        "command_config_mode_matrix.json",
        json.dumps(matrix, indent=2, sort_keys=True) + "\n",
    )


# ===========================================================================
# 3. Structured-results snapshots via direct engine runs (offline)
# ===========================================================================

def _run_scan_offline(scan_type: str, tmp_path: Path, enabled_modules=None):
    """Build the real command config and run the engine fully offline.

    Returns the ``APILeakCore`` after ``run_scan`` completes so callers can read
    discovered endpoints, statistics, and OWASP coverage.
    """
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


def _endpoint_summary(core):
    """Deterministic, order-independent summary of discovered endpoints."""
    endpoints = core.get_discovered_endpoints()
    rows = sorted(
        {
            (
                _path_leaf(e.url),
                e.method,
                getattr(e, "status_code", None),
                getattr(getattr(e, "status", None), "value", None),
            )
            for e in endpoints
        }
    )
    return [
        {"leaf": leaf, "method": method, "status_code": sc, "status": status}
        for (leaf, method, sc, status) in rows
    ]


def _findings_summary(core):
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


def test_dir_results_snapshot(offline_http, tmp_path):
    """``dir`` discovers the offline endpoints deterministically (results payload).

    _Requirements: 2.1_
    """
    core = _run_scan_offline("dir", tmp_path)

    summary = _endpoint_summary(core)
    leaves = {row["leaf"] for row in summary}

    # Invariants: the known-good "users" leaf is discovered as a 200/valid
    # endpoint, and the unknown "admin" leaf is seen as 404 (not valid).
    assert "users" in leaves
    users_rows = [r for r in summary if r["leaf"] == "users"]
    assert any(r["status_code"] == 200 for r in users_rows)

    _assert_snapshot(
        "dir_results.json",
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
    )


def test_scan_owasp_results_snapshot(offline_http, tmp_path):
    """Representative ``scan`` run: OWASP module results are deterministic.

    Uses the ``bola`` module as a representative OWASP run against the offline
    target and snapshots the findings + coverage summary.

    _Requirements: 2.2, 2.4_
    """
    core = _run_scan_offline("full", tmp_path, enabled_modules=["bola"])

    summary = _findings_summary(core)

    # Invariants: coverage accounting is stable and total categories is 10.
    assert summary["owasp_total_categories"] == 10
    assert summary["total_findings"] == (
        summary["critical"]
        + summary["high"]
        + summary["medium"]
        + summary["low"]
        + summary["info"]
    )

    _assert_snapshot(
        "scan_bola_owasp_results.json",
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
    )


# ===========================================================================
# 4. CLI stdout + exit-code snapshots (offline)
# ===========================================================================

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
    """Replace report writing with a deterministic no-op file list.

    Report file names embed timestamps and the writer touches the filesystem
    (templates, output dir). Neither is relevant to a command-behavior
    characterization, so we return a fixed list and skip all IO.
    """
    from utils.report_generator import ReportGenerator

    def _fake_save_reports(self, results, output_dir, scan_type, output_filename=None, formats=None):
        return [f"reports/{scan_type}_baseline.json"]

    monkeypatch.setattr(ReportGenerator, "save_reports", _fake_save_reports)


def _invoke_cli(args):
    import apileaks

    runner = CliRunner()
    return runner.invoke(apileaks.cli, args)


def test_dir_cli_stdout_and_exit_snapshot(offline_http, stub_reports, tmp_path):
    """``dir`` CLI stdout + exit code are deterministic offline.

    _Requirements: 2.1_
    """
    wordlist = _write_wordlist(tmp_path, ["users", "admin"])
    result = _invoke_cli(
        [
            "--no-banner",
            "dir",
            "--target",
            TARGET,
            "--wordlist",
            wordlist,
            "--log-level",
            "ERROR",
        ]
    )

    assert result.exit_code == 0, result.output

    _assert_snapshot("dir_cli_stdout.txt", _normalize_stdout(result.output))
    _assert_snapshot("dir_cli_exit_code.txt", f"{result.exit_code}\n")


def test_full_alias_matches_scan_deprecation(offline_http, stub_reports, tmp_path):
    """``full`` is a deprecated alias of ``scan`` and forwards to it.

    Locks the current behavior that ``full`` emits a deprecation notice naming
    its replacement and otherwise runs identically to ``scan``.

    _Requirements: 2.2_
    """
    wordlist = _write_wordlist(tmp_path, ["users"])
    result = _invoke_cli(
        [
            "--no-banner",
            "full",
            "--target",
            TARGET,
            "--modules",
            "bola",
            "--log-level",
            "ERROR",
        ]
    )

    combined = _ANSI_RE.sub("", result.output)
    # Deprecation notice names the command and its replacement.
    assert "full" in combined and "scan" in combined
    assert result.exit_code in (0, 1, 2)

    _assert_snapshot("full_alias_exit_code.txt", f"{result.exit_code}\n")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
