#!/usr/bin/env python3
"""
security_gate.py — Unified Security Gate for APILeaks CI/CD pipelines.

Reads all reports/*.json files from a findings directory, aggregates severity
counts across all files, applies configurable thresholds, and writes
security-gate-result.json unconditionally before exiting (Req 10.7).

Exit codes:
    0 — pass  (all thresholds OK)
    1 — warn  (HIGH or MEDIUM exceeded)
    2 — fail  (CRITICAL exceeded, or APILEAK_GATE_FAIL_ON_WARN=true|1 on warn)

Env vars:
    APILEAK_CRITICAL_THRESHOLD  (default: 0)
    APILEAK_HIGH_THRESHOLD      (default: 5)
    APILEAK_MEDIUM_THRESHOLD    (default: 20)
    APILEAK_GATE_FAIL_ON_WARN   (default: false) — escalate warn exit code to 2
    APILEAK_FINDINGS_DIR        (default: "reports")
    APILEAK_OUTPUT_DIR          (default: CWD)
    APILEAK_PIPELINE_ID         (default: "")
"""

import json
import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class GateResult:
    """Result produced by the SecurityGate after evaluating findings."""

    status: str                        # "pass" | "warn" | "fail"
    counts: Dict[str, int]             # {critical, high, medium, low, info, total}
    thresholds: Dict[str, int]         # configured thresholds {critical, high, medium}
    exceeded_thresholds: List[str]     # severities that exceeded threshold
    pipeline_id: str
    exit_code: int                     # 0=pass, 1=warn, 2=fail


class SecurityGate:
    """
    Unified security gate that:
    - Reads ALL reports/*.json files from a findings directory
    - Aggregates severity counts across ALL files
    - Applies decision logic against configured thresholds
    - Writes security-gate-result.json UNCONDITIONALLY (Req 10.7)
    """

    # Map from JSON field names (both formats) to canonical severity keys
    _FINDINGS_SEVERITY_FIELD = "severity"

    # Map statistics dict keys → canonical severity
    _STATS_KEY_MAP: Dict[str, str] = {
        "critical_findings": "critical",
        "high_findings": "high",
        "medium_findings": "medium",
        "low_findings": "low",
        "info_findings": "info",
    }

    def __init__(self) -> None:
        self.critical_threshold = int(os.environ.get("APILEAK_CRITICAL_THRESHOLD", "0"))
        self.high_threshold = int(os.environ.get("APILEAK_HIGH_THRESHOLD", "5"))
        self.medium_threshold = int(os.environ.get("APILEAK_MEDIUM_THRESHOLD", "20"))
        self.pipeline_id = os.environ.get("APILEAK_PIPELINE_ID", "")
        raw_fail_on_warn = os.environ.get("APILEAK_GATE_FAIL_ON_WARN", "false").strip().lower()
        self.fail_on_warn: bool = raw_fail_on_warn in ("true", "1")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _read_counts_from_file(self, path: Path) -> Dict[str, int]:
        """
        Parse one JSON report file and return a counts dict.

        Supports two formats:
        1. findings[] array — list of dicts each with a ``severity`` field.
        2. statistics dict — keys like ``critical_findings``, ``high_findings``, …

        On any parse / key error: logs a warning and returns empty counts.
        """
        counts: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            logger.warning("Skipping %s — JSON parse error: %s", path, exc)
            return counts
        except OSError as exc:
            logger.warning("Skipping %s — I/O error: %s", path, exc)
            return counts

        if not isinstance(data, dict):
            logger.warning("Skipping %s — top-level is not a JSON object", path)
            return counts

        # --- Format 1: findings[] array -----------------------------------
        findings = data.get("findings")
        if isinstance(findings, list):
            for item in findings:
                if not isinstance(item, dict):
                    continue
                sev = str(item.get(self._FINDINGS_SEVERITY_FIELD, "")).lower()
                if sev in counts:
                    counts[sev] += 1
            return counts

        # --- Format 2: statistics dict ------------------------------------
        stats = data.get("statistics")
        if isinstance(stats, dict):
            for stat_key, canonical in self._STATS_KEY_MAP.items():
                val = stats.get(stat_key, 0)
                if isinstance(val, int):
                    counts[canonical] += val
            return counts

        # Neither format found — log and return zeros
        logger.warning(
            "Skipping %s — no 'findings' array or 'statistics' dict found", path
        )
        return counts

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, findings_dir: str) -> GateResult:
        """
        Read all reports/*.json from *findings_dir*, aggregate counts, and
        return a GateResult with the appropriate status and exit code.

        This method MUST be called inside a try/finally that writes the result
        file.  See the __main__ block and the property-based test contract.
        """
        totals: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }

        reports_path = Path(findings_dir) / "reports"
        if reports_path.is_dir():
            json_files = sorted(reports_path.glob("*.json"))
            if not json_files:
                logger.info("No JSON reports found in %s", reports_path)
            for json_file in json_files:
                file_counts = self._read_counts_from_file(json_file)
                for sev in totals:
                    totals[sev] += file_counts.get(sev, 0)
        else:
            logger.info(
                "Reports directory does not exist: %s — treating as zero findings",
                reports_path,
            )

        total_count = sum(totals.values())
        totals_with_total = {**totals, "total": total_count}

        thresholds = {
            "critical": self.critical_threshold,
            "high": self.high_threshold,
            "medium": self.medium_threshold,
        }

        exceeded: List[str] = []
        status = "pass"
        exit_code = 0

        # Decision logic — checked in priority order
        if totals["critical"] > self.critical_threshold:
            exceeded.append("critical")
            status = "fail"
            exit_code = 2
            logger.info(
                "CRITICAL findings (%d) exceed threshold (%d)",
                totals["critical"], self.critical_threshold,
            )
        elif totals["high"] > self.high_threshold:
            exceeded.append("high")
            status = "warn"
            exit_code = 1
            logger.info(
                "HIGH findings (%d) exceed threshold (%d)",
                totals["high"], self.high_threshold,
            )
        elif totals["medium"] > self.medium_threshold:
            exceeded.append("medium")
            status = "warn"
            exit_code = 1
            logger.info(
                "MEDIUM findings (%d) exceed threshold (%d)",
                totals["medium"], self.medium_threshold,
            )
        else:
            logger.info(
                "All findings within thresholds — critical=%d high=%d medium=%d",
                totals["critical"], totals["high"], totals["medium"],
            )

        # Req 10.6 — escalate warn → fail when APILEAK_GATE_FAIL_ON_WARN is set
        if status == "warn" and self.fail_on_warn:
            exit_code = 2

        return GateResult(
            status=status,
            counts=totals_with_total,
            thresholds=thresholds,
            exceeded_thresholds=exceeded,
            pipeline_id=self.pipeline_id,
            exit_code=exit_code,
        )

    def write_result(self, result: GateResult, output_path: str) -> None:
        """
        Write *result* as JSON to *output_path* / ``security-gate-result.json``.

        Creates the output directory if necessary.  The pipeline_id is included
        but the exit_code is intentionally omitted from the JSON schema (it is
        communicated via the process exit code instead).
        """
        out = Path(output_path) / "security-gate-result.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "status": result.status,
            "counts": result.counts,
            "thresholds": result.thresholds,
            "exceeded_thresholds": result.exceeded_thresholds,
            "pipeline_id": result.pipeline_id,
        }
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        logger.info("security-gate-result.json written to %s", out)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    findings_dir = os.environ.get("APILEAK_FINDINGS_DIR", "reports")
    output_dir = os.environ.get("APILEAK_OUTPUT_DIR", os.getcwd())

    gate = SecurityGate()

    # Build a zero-count "unknown" result so write_result always has something
    # to write even if evaluate() raises an unexpected exception (Req 10.7).
    fallback_result = GateResult(
        status="fail",
        counts={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
        thresholds={
            "critical": gate.critical_threshold,
            "high": gate.high_threshold,
            "medium": gate.medium_threshold,
        },
        exceeded_thresholds=[],
        pipeline_id=gate.pipeline_id,
        exit_code=2,
    )

    result = fallback_result
    try:
        result = gate.evaluate(findings_dir)
    except Exception as exc:  # noqa: BLE001
        logger.error("Unexpected error during evaluation: %s", exc)
        # result stays as fallback_result
    finally:
        # Req 10.7 — ALWAYS write the result file before exiting
        gate.write_result(result, output_dir)

    sys.exit(result.exit_code)
