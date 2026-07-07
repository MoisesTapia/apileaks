"""
tests/test_security_gate.py
Tests for ci-cd/scripts/security_gate.py

Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7
"""

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st

# ---------------------------------------------------------------------------
# Import path — ci-cd/scripts has a hyphen so we inject the path manually.
# ---------------------------------------------------------------------------
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "ci-cd", "scripts"),
)

from security_gate import GateResult, SecurityGate  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RESULT_FILENAME = "security-gate-result.json"


def make_gate(env_overrides=None):
    """Create a SecurityGate with optional env variable overrides."""
    defaults = {
        "APILEAK_CRITICAL_THRESHOLD": "0",
        "APILEAK_HIGH_THRESHOLD": "5",
        "APILEAK_MEDIUM_THRESHOLD": "20",
        "APILEAK_GATE_FAIL_ON_WARN": "false",
        "APILEAK_PIPELINE_ID": "test-pipeline-1",
    }
    if env_overrides:
        defaults.update(env_overrides)
    original = {}
    for k, v in defaults.items():
        original[k] = os.environ.get(k)
        os.environ[k] = v
    gate = SecurityGate()
    # Restore
    for k, orig in original.items():
        if orig is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = orig
    return gate


def write_findings_json(tmp_path, filename, data):
    """Write a JSON report file into tmp_path/reports/."""
    reports = tmp_path / "reports"
    reports.mkdir(exist_ok=True)
    (reports / filename).write_text(json.dumps(data), encoding="utf-8")


# ---------------------------------------------------------------------------
# 1. Empty findings directory → pass, result file still written
# ---------------------------------------------------------------------------


def test_empty_reports_dir_produces_pass(tmp_path):
    """No findings → status pass, exit_code 0, result file written."""
    gate = make_gate()
    result = gate.evaluate(str(tmp_path))
    gate.write_result(result, str(tmp_path))

    assert result.status == "pass"
    assert result.exit_code == 0
    assert result.counts["total"] == 0
    assert (tmp_path / RESULT_FILENAME).exists()


def test_nonexistent_findings_dir_produces_pass(tmp_path):
    """Non-existent findings dir → status pass, no crash."""
    gate = make_gate()
    missing = str(tmp_path / "no_such_dir")
    result = gate.evaluate(missing)
    gate.write_result(result, str(tmp_path))

    assert result.status == "pass"
    assert result.exit_code == 0
    assert (tmp_path / RESULT_FILENAME).exists()


# ---------------------------------------------------------------------------
# 2. Corrupt / unreadable files — skipped, not a crash
# ---------------------------------------------------------------------------


def test_corrupt_json_file_is_skipped(tmp_path):
    """Bad JSON in a report file is skipped; evaluate() does not raise."""
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "bad.json").write_text("NOT VALID JSON {{{}}", encoding="utf-8")
    gate = make_gate()
    result = gate.evaluate(str(tmp_path))
    gate.write_result(result, str(tmp_path))

    assert result.status == "pass"
    assert result.counts["total"] == 0


# ---------------------------------------------------------------------------
# 3. findings[] array format
# ---------------------------------------------------------------------------


def test_findings_array_format_counts_correctly(tmp_path):
    """findings[] array format is read and counted per severity."""
    data = {
        "findings": [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
            {"severity": "LOW"},
            {"severity": "INFO"},
        ]
    }
    write_findings_json(tmp_path, "scan.json", data)
    gate = make_gate()
    result = gate.evaluate(str(tmp_path))

    assert result.counts["critical"] == 1
    assert result.counts["high"] == 2
    assert result.counts["medium"] == 1
    assert result.counts["low"] == 1
    assert result.counts["info"] == 1
    assert result.counts["total"] == 6


# ---------------------------------------------------------------------------
# 4. statistics dict format
# ---------------------------------------------------------------------------


def test_statistics_dict_format_counts_correctly(tmp_path):
    """statistics dict format is read and counted per severity."""
    data = {
        "statistics": {
            "critical_findings": 0,
            "high_findings": 3,
            "medium_findings": 10,
            "low_findings": 5,
            "info_findings": 2,
            "findings_count": 20,
        }
    }
    write_findings_json(tmp_path, "scan.json", data)
    gate = make_gate()
    result = gate.evaluate(str(tmp_path))

    assert result.counts["critical"] == 0
    assert result.counts["high"] == 3
    assert result.counts["medium"] == 10
    assert result.counts["low"] == 5
    assert result.counts["info"] == 2


# ---------------------------------------------------------------------------
# 5. Aggregation across multiple files
# ---------------------------------------------------------------------------


def test_aggregation_across_multiple_files(tmp_path):
    """Counts from multiple JSON files are summed together."""
    write_findings_json(tmp_path, "scan1.json", {
        "findings": [{"severity": "HIGH"}, {"severity": "HIGH"}]
    })
    write_findings_json(tmp_path, "scan2.json", {
        "statistics": {
            "critical_findings": 0,
            "high_findings": 4,
            "medium_findings": 0,
            "low_findings": 0,
            "info_findings": 0,
        }
    })
    gate = make_gate()
    result = gate.evaluate(str(tmp_path))

    # 2 HIGH from findings[] + 4 HIGH from statistics = 6 HIGH
    assert result.counts["high"] == 6


# ---------------------------------------------------------------------------
# 6. Boundary tests — CRITICAL threshold
# ---------------------------------------------------------------------------


def test_critical_at_threshold_is_pass(tmp_path):
    """critical == threshold (0) → pass."""
    write_findings_json(tmp_path, "s.json", {"findings": []})
    gate = make_gate({"APILEAK_CRITICAL_THRESHOLD": "0"})
    result = gate.evaluate(str(tmp_path))
    assert result.status == "pass"
    assert result.exit_code == 0


def test_critical_above_threshold_is_fail(tmp_path):
    """critical == threshold + 1 → fail, exit_code 2."""
    write_findings_json(tmp_path, "s.json", {
        "findings": [{"severity": "CRITICAL"}]
    })
    gate = make_gate({"APILEAK_CRITICAL_THRESHOLD": "0"})
    result = gate.evaluate(str(tmp_path))
    assert result.status == "fail"
    assert result.exit_code == 2
    assert "critical" in result.exceeded_thresholds


def test_critical_zero_findings_is_pass(tmp_path):
    """0 critical findings → always pass regardless of threshold."""
    gate = make_gate({"APILEAK_CRITICAL_THRESHOLD": "5"})
    result = gate.evaluate(str(tmp_path))
    assert result.status == "pass"


# ---------------------------------------------------------------------------
# 7. Boundary tests — HIGH threshold
# ---------------------------------------------------------------------------


def test_high_at_threshold_is_pass(tmp_path):
    """high == threshold (5) → pass (equal is NOT exceeded)."""
    write_findings_json(tmp_path, "s.json", {
        "statistics": {
            "critical_findings": 0, "high_findings": 5,
            "medium_findings": 0, "low_findings": 0, "info_findings": 0,
        }
    })
    gate = make_gate({"APILEAK_HIGH_THRESHOLD": "5"})
    result = gate.evaluate(str(tmp_path))
    assert result.status == "pass"
    assert result.exit_code == 0


def test_high_above_threshold_is_warn(tmp_path):
    """high == threshold + 1 → warn, exit_code 1."""
    write_findings_json(tmp_path, "s.json", {
        "statistics": {
            "critical_findings": 0, "high_findings": 6,
            "medium_findings": 0, "low_findings": 0, "info_findings": 0,
        }
    })
    gate = make_gate({"APILEAK_HIGH_THRESHOLD": "5"})
    result = gate.evaluate(str(tmp_path))
    assert result.status == "warn"
    assert result.exit_code == 1
    assert "high" in result.exceeded_thresholds


def test_high_zero_findings_is_pass(tmp_path):
    """0 high findings → always pass."""
    gate = make_gate({"APILEAK_HIGH_THRESHOLD": "0"})
    result = gate.evaluate(str(tmp_path))
    assert result.status == "pass"


# ---------------------------------------------------------------------------
# 8. Boundary tests — MEDIUM threshold
# ---------------------------------------------------------------------------


def test_medium_at_threshold_is_pass(tmp_path):
    """medium == threshold (20) → pass."""
    write_findings_json(tmp_path, "s.json", {
        "statistics": {
            "critical_findings": 0, "high_findings": 0,
            "medium_findings": 20, "low_findings": 0, "info_findings": 0,
        }
    })
    gate = make_gate({"APILEAK_MEDIUM_THRESHOLD": "20"})
    result = gate.evaluate(str(tmp_path))
    assert result.status == "pass"
    assert result.exit_code == 0


def test_medium_above_threshold_is_warn(tmp_path):
    """medium == threshold + 1 → warn, exit_code 1."""
    write_findings_json(tmp_path, "s.json", {
        "statistics": {
            "critical_findings": 0, "high_findings": 0,
            "medium_findings": 21, "low_findings": 0, "info_findings": 0,
        }
    })
    gate = make_gate({"APILEAK_MEDIUM_THRESHOLD": "20"})
    result = gate.evaluate(str(tmp_path))
    assert result.status == "warn"
    assert result.exit_code == 1
    assert "medium" in result.exceeded_thresholds


def test_medium_zero_findings_is_pass(tmp_path):
    """0 medium findings → always pass."""
    gate = make_gate({"APILEAK_MEDIUM_THRESHOLD": "0"})
    result = gate.evaluate(str(tmp_path))
    assert result.status == "pass"


# ---------------------------------------------------------------------------
# 9. CRITICAL takes priority over HIGH / MEDIUM
# ---------------------------------------------------------------------------


def test_critical_takes_priority_over_high(tmp_path):
    """When both critical and high exceed thresholds, status is 'fail' not 'warn'."""
    write_findings_json(tmp_path, "s.json", {
        "statistics": {
            "critical_findings": 1, "high_findings": 10,
            "medium_findings": 30, "low_findings": 0, "info_findings": 0,
        }
    })
    gate = make_gate()
    result = gate.evaluate(str(tmp_path))
    assert result.status == "fail"
    assert result.exit_code == 2
    assert "critical" in result.exceeded_thresholds
    # high and medium should NOT be in exceeded_thresholds (critical takes priority)
    assert "high" not in result.exceeded_thresholds


# ---------------------------------------------------------------------------
# 10. APILEAK_GATE_FAIL_ON_WARN escalation
# ---------------------------------------------------------------------------


def test_fail_on_warn_true_escalates_warn_to_exit_2(tmp_path):
    """APILEAK_GATE_FAIL_ON_WARN=true → warn exit_code becomes 2."""
    write_findings_json(tmp_path, "s.json", {
        "statistics": {
            "critical_findings": 0, "high_findings": 6,
            "medium_findings": 0, "low_findings": 0, "info_findings": 0,
        }
    })
    gate = make_gate({
        "APILEAK_HIGH_THRESHOLD": "5",
        "APILEAK_GATE_FAIL_ON_WARN": "true",
    })
    result = gate.evaluate(str(tmp_path))
    assert result.status == "warn"
    assert result.exit_code == 2


def test_fail_on_warn_one_escalates_warn_to_exit_2(tmp_path):
    """APILEAK_GATE_FAIL_ON_WARN=1 → warn exit_code becomes 2."""
    write_findings_json(tmp_path, "s.json", {
        "statistics": {
            "critical_findings": 0, "high_findings": 6,
            "medium_findings": 0, "low_findings": 0, "info_findings": 0,
        }
    })
    gate = make_gate({
        "APILEAK_HIGH_THRESHOLD": "5",
        "APILEAK_GATE_FAIL_ON_WARN": "1",
    })
    result = gate.evaluate(str(tmp_path))
    assert result.status == "warn"
    assert result.exit_code == 2


def test_fail_on_warn_false_does_not_escalate(tmp_path):
    """APILEAK_GATE_FAIL_ON_WARN=false → warn exit_code stays 1."""
    write_findings_json(tmp_path, "s.json", {
        "statistics": {
            "critical_findings": 0, "high_findings": 6,
            "medium_findings": 0, "low_findings": 0, "info_findings": 0,
        }
    })
    gate = make_gate({
        "APILEAK_HIGH_THRESHOLD": "5",
        "APILEAK_GATE_FAIL_ON_WARN": "false",
    })
    result = gate.evaluate(str(tmp_path))
    assert result.exit_code == 1


def test_fail_on_warn_does_not_affect_pass(tmp_path):
    """APILEAK_GATE_FAIL_ON_WARN=true on a pass result → still exit 0."""
    gate = make_gate({"APILEAK_GATE_FAIL_ON_WARN": "true"})
    result = gate.evaluate(str(tmp_path))
    assert result.status == "pass"
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# 11. write_result always produces correct JSON schema
# ---------------------------------------------------------------------------


def test_write_result_produces_correct_schema(tmp_path):
    """write_result() writes all required fields with correct types."""
    gate = make_gate()
    result = GateResult(
        status="warn",
        counts={"critical": 0, "high": 6, "medium": 0, "low": 0, "info": 0, "total": 6},
        thresholds={"critical": 0, "high": 5, "medium": 20},
        exceeded_thresholds=["high"],
        pipeline_id="pipe-42",
        exit_code=1,
    )
    gate.write_result(result, str(tmp_path))

    out_file = tmp_path / RESULT_FILENAME
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))

    assert data["status"] == "warn"
    assert data["counts"]["high"] == 6
    assert data["thresholds"]["high"] == 5
    assert data["exceeded_thresholds"] == ["high"]
    assert data["pipeline_id"] == "pipe-42"


# ---------------------------------------------------------------------------
# 12. Result file is ALWAYS written — even on empty / missing dir
# ---------------------------------------------------------------------------


def test_result_written_when_reports_dir_missing(tmp_path):
    """security-gate-result.json is written even when findings dir doesn't exist."""
    gate = make_gate()
    result = gate.evaluate(str(tmp_path / "ghost"))
    gate.write_result(result, str(tmp_path))
    assert (tmp_path / RESULT_FILENAME).exists()


def test_result_written_when_reports_dir_empty(tmp_path):
    """security-gate-result.json is written even when reports/ is empty."""
    (tmp_path / "reports").mkdir()
    gate = make_gate()
    result = gate.evaluate(str(tmp_path))
    gate.write_result(result, str(tmp_path))
    assert (tmp_path / RESULT_FILENAME).exists()


def test_result_written_when_all_files_corrupt(tmp_path):
    """Result file is written even when every report file is corrupt JSON."""
    reports = tmp_path / "reports"
    reports.mkdir()
    for i in range(3):
        (reports / f"bad{i}.json").write_text("{{invalid}}", encoding="utf-8")
    gate = make_gate()
    result = gate.evaluate(str(tmp_path))
    gate.write_result(result, str(tmp_path))
    assert (tmp_path / RESULT_FILENAME).exists()
    assert result.status == "pass"


# ---------------------------------------------------------------------------
# 13. Property 4 (Hypothesis) — evaluate() ALWAYS writes result file
#     Validates: Requirements 10.7
# ---------------------------------------------------------------------------


def _make_gate_with_counts_env(critical_t=0, high_t=5, medium_t=20):
    """Helper: make a gate with specific thresholds without mutating os.environ."""
    env_backup = {}
    overrides = {
        "APILEAK_CRITICAL_THRESHOLD": str(critical_t),
        "APILEAK_HIGH_THRESHOLD": str(high_t),
        "APILEAK_MEDIUM_THRESHOLD": str(medium_t),
        "APILEAK_GATE_FAIL_ON_WARN": "false",
        "APILEAK_PIPELINE_ID": "",
    }
    for k, v in overrides.items():
        env_backup[k] = os.environ.get(k)
        os.environ[k] = v
    gate = SecurityGate()
    for k, orig in env_backup.items():
        if orig is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = orig
    return gate


@given(
    counts=st.lists(st.integers(min_value=0, max_value=50), min_size=0, max_size=5),
)
@settings(max_examples=100, deadline=5000)
def test_property4_result_always_written(counts):
    """
    **Property 4: Gate result always written**
    **Validates: Requirements 10.7**

    FOR ANY state of the findings directory (empty, with errors, with findings),
    write_result() writes security-gate-result.json before returning.
    """
    tmp = Path(tempfile.mkdtemp())
    try:
        gate = _make_gate_with_counts_env()

        # Build a varying number of findings files based on the drawn list
        reports = tmp / "reports"
        reports.mkdir(exist_ok=True)
        for idx, count in enumerate(counts):
            findings = [{"severity": "HIGH"}] * count
            (reports / f"scan{idx}.json").write_text(
                json.dumps({"findings": findings}), encoding="utf-8"
            )

        out_dir = tmp / "out"
        out_dir.mkdir(exist_ok=True)

        result = gate.evaluate(str(tmp))
        gate.write_result(result, str(out_dir))

        assert (out_dir / RESULT_FILENAME).exists(), (
            "security-gate-result.json must always be written"
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# 14. Property 5 (Hypothesis) — threshold strict comparison
#     Validates: Requirements 10.2, 10.3, 10.4
# ---------------------------------------------------------------------------


@given(
    critical=st.integers(min_value=0, max_value=50),
    high=st.integers(min_value=0, max_value=50),
    medium=st.integers(min_value=0, max_value=50),
    c_thresh=st.integers(min_value=0, max_value=49),
    h_thresh=st.integers(min_value=0, max_value=49),
    m_thresh=st.integers(min_value=0, max_value=49),
)
@settings(max_examples=100, deadline=5000)
def test_property5_threshold_strict_comparison(
    critical, high, medium,
    c_thresh, h_thresh, m_thresh,
):
    """
    **Property 5: Threshold strict comparison**
    **Validates: Requirements 10.2, 10.3, 10.4**

    count == threshold  → status is "pass" (equal is NOT exceeded).
    count > threshold   → status is "warn" or "fail".
    """
    tmp = Path(tempfile.mkdtemp())
    try:
        gate = _make_gate_with_counts_env(
            critical_t=c_thresh,
            high_t=h_thresh,
            medium_t=m_thresh,
        )

        # Write a scan file with exactly the drawn counts
        data = {
            "statistics": {
                "critical_findings": critical,
                "high_findings": high,
                "medium_findings": medium,
                "low_findings": 0,
                "info_findings": 0,
            }
        }
        reports = tmp / "reports"
        reports.mkdir(exist_ok=True)
        (reports / "scan.json").write_text(json.dumps(data), encoding="utf-8")

        result = gate.evaluate(str(tmp))

        any_exceeded = (
            critical > c_thresh
            or (high > h_thresh and critical <= c_thresh)
            or (medium > m_thresh and critical <= c_thresh and high <= h_thresh)
        )

        if not any_exceeded:
            assert result.status == "pass", (
                f"Expected pass but got {result.status!r} for "
                f"critical={critical}/{c_thresh}, high={high}/{h_thresh}, medium={medium}/{m_thresh}"
            )
            assert result.exit_code == 0
        else:
            assert result.status in ("warn", "fail"), (
                f"Expected warn/fail but got {result.status!r}"
            )
            assert result.exit_code in (1, 2)

        # Equal-to-threshold means NOT exceeded
        if critical == c_thresh and high <= h_thresh and medium <= m_thresh:
            assert result.status == "pass", (
                f"critical == c_thresh should be pass, got {result.status!r}"
            )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
