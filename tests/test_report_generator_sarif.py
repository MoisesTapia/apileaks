"""
Test suite for SARIF integration in ReportGenerator.

Covers:
- generate_sarif_report produces a valid SARIF 2.1.0 doc with one result per finding
- save_reports honors an explicit formats list (json + sarif only)
- save_reports preserves backward-compatible behavior when formats is None
  (xml, json, html, txt; no sarif)

Validates: Requirements 8.1
"""

import json
from datetime import datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from core.config import Severity
from utils.findings import Finding
from utils.report_generator import ReportGenerator


def make_finding(
    category="SSRF_INTERNAL_ACCESS",
    owasp_category="API7",
    severity=Severity.HIGH,
    endpoint="/api/fetch",
    method="POST",
):
    return Finding(
        id=str(uuid4()),
        scan_id="scan-1",
        category=category,
        owasp_category=owasp_category,
        severity=severity,
        endpoint=endpoint,
        method=method,
        status_code=200,
        response_size=100,
        response_time=0.1,
        evidence="evidence text",
        recommendation="remediation text",
    )


def make_results(findings):
    """Build a minimal results object with the attributes save_reports needs."""
    now = datetime.now()
    statistics = SimpleNamespace(
        findings_count=len(findings),
        critical_findings=sum(1 for f in findings if f.severity == Severity.CRITICAL),
        high_findings=sum(1 for f in findings if f.severity == Severity.HIGH),
        medium_findings=sum(1 for f in findings if f.severity == Severity.MEDIUM),
        low_findings=sum(1 for f in findings if f.severity == Severity.LOW),
        info_findings=sum(1 for f in findings if f.severity == Severity.INFO),
        total_requests=10,
        endpoints_discovered=2,
    )
    performance_metrics = SimpleNamespace(
        duration=timedelta(seconds=5),
        requests_per_second=2.0,
        average_response_time=0.1,
        start_time=now,
        end_time=now + timedelta(seconds=5),
    )
    return SimpleNamespace(
        scan_id="scan-1",
        target_url="https://api.example.com",
        timestamp=now,
        statistics=statistics,
        performance_metrics=performance_metrics,
        findings=findings,
        discovered_endpoints=[],
    )


class TestGenerateSarifReport:
    def test_returns_valid_sarif_with_one_result_per_finding(self):
        results = make_results([make_finding(), make_finding(owasp_category="API1")])
        gen = ReportGenerator()

        out = gen.generate_sarif_report(results)
        doc = json.loads(out)

        assert doc["version"] == "2.1.0"
        assert len(doc["runs"]) == 1
        assert len(doc["runs"][0]["results"]) == 2

    def test_zero_findings_produces_valid_document(self):
        results = make_results([])
        gen = ReportGenerator()

        doc = json.loads(gen.generate_sarif_report(results))

        assert doc["version"] == "2.1.0"
        assert doc["runs"][0]["results"] == []

    def test_findings_collector_takes_precedence(self):
        """When findings_collector is present, its prioritized findings are used."""
        findings = [make_finding(), make_finding(owasp_category="API1")]
        collector = SimpleNamespace(
            get_prioritized_findings=lambda: findings
        )
        results = SimpleNamespace(findings_collector=collector, findings=None)
        gen = ReportGenerator()

        doc = json.loads(gen.generate_sarif_report(results))
        assert len(doc["runs"][0]["results"]) == 2


class TestSaveReportsFormats:
    def test_explicit_formats_only_generates_requested(self, tmp_path):
        results = make_results([make_finding()])
        gen = ReportGenerator(template_dir=str(tmp_path / "templates"))

        gen.save_reports(
            results,
            str(tmp_path),
            scan_type="full",
            output_filename="report",
            formats=["json", "sarif"],
        )

        assert (tmp_path / "report.sarif").exists()
        assert (tmp_path / "report.json").exists()
        assert not (tmp_path / "report.html").exists()
        assert not (tmp_path / "report.xml").exists()
        assert not (tmp_path / "report.txt").exists()

        # The SARIF file is a valid SARIF doc.
        doc = json.loads((tmp_path / "report.sarif").read_text())
        assert doc["version"] == "2.1.0"
        assert len(doc["runs"][0]["results"]) == 1

    def test_default_formats_backward_compatible(self, tmp_path):
        results = make_results([make_finding()])
        gen = ReportGenerator(template_dir=str(tmp_path / "templates"))

        gen.save_reports(
            results,
            str(tmp_path),
            scan_type="full",
            output_filename="report",
        )

        assert (tmp_path / "report.xml").exists()
        assert (tmp_path / "report.json").exists()
        assert (tmp_path / "report.html").exists()
        assert (tmp_path / "report.txt").exists()
        assert not (tmp_path / "report.sarif").exists()
