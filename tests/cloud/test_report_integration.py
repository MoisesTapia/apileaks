"""
Integration tests — cloud-audit findings through the ReportGenerator pipeline.

Covers Req 1.5 and 7.4:
  1.5: Cloud-audit findings are routed through ReportGenerator, the same
       pipeline used by every other APILeak scan.
  7.4: When the engine runs cloud-audit alongside a normal OWASP scan, both
       sets of findings are combined in a single consolidated report.

No real cloud credentials or network access are required — all SDK calls and
the CloudAuditOrchestrator are mocked.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.config import CloudAuditConfig, Severity
from utils.findings import Finding, FindingsCollector
from utils.report_generator import ReportGenerator


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------


def _make_cloud_finding(category: str = "CLOUD_GATEWAY_MISCONFIGURATION") -> Finding:
    """Return a minimal cloud-audit Finding with owasp_category=API8."""
    return Finding(
        id="test-id",
        scan_id="test-scan",
        category=category,
        owasp_category="API8",
        severity=Severity.MEDIUM,
        endpoint="arn:aws:apigateway:us-east-1::/restapis/abc123",
        method="N/A",
        status_code=0,
        response_size=0,
        response_time=0.0,
        evidence="Missing WAF association on stage prod",
        recommendation="Associate a WAFv2 WebACL with the API stage.",
    )


def _make_owasp_finding(category: str = "CORS_MISCONFIGURATION") -> Finding:
    """Return a minimal OWASP Finding (non-cloud)."""
    return Finding(
        id="owasp-id",
        scan_id="test-scan",
        category=category,
        owasp_category="API8",
        severity=Severity.HIGH,
        endpoint="https://api.example.com/v1/users",
        method="GET",
        status_code=200,
        response_size=512,
        response_time=0.05,
        evidence="Access-Control-Allow-Origin: *",
        recommendation="Restrict CORS origin to known domains.",
    )


def _build_minimal_scan_results(findings: list[Finding], scan_id: str = "test-scan") -> SimpleNamespace:
    """Build the minimal results namespace that ReportGenerator.save_reports expects."""
    collector = FindingsCollector(scan_id)
    collector.add_findings(findings)

    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev[f.severity.value] = sev.get(f.severity.value, 0) + 1

    now = datetime.now()
    return SimpleNamespace(
        scan_id=scan_id,
        target_url="https://api.example.com",
        timestamp=now,
        statistics=SimpleNamespace(
            findings_count=len(findings),
            critical_findings=sev["CRITICAL"],
            high_findings=sev["HIGH"],
            medium_findings=sev["MEDIUM"],
            low_findings=sev["LOW"],
            info_findings=sev["INFO"],
            total_requests=5,
            endpoints_discovered=3,
        ),
        performance_metrics=SimpleNamespace(
            duration=timedelta(seconds=1),
            requests_per_second=5.0,
            average_response_time=0.02,
            start_time=now,
            end_time=now + timedelta(seconds=1),
        ),
        findings_collector=collector,
        findings=findings,
        discovered_endpoints=[],
    )


# ---------------------------------------------------------------------------
# Req 1.5: cloud_audit_cmd routes through ReportGenerator
# ---------------------------------------------------------------------------


class TestCloudAuditCmdUsesReportGenerator:
    """
    cloud_audit_cmd must call ReportGenerator.save_reports rather than
    writing a bare ad-hoc JSON file (Req 1.5).
    """

    def test_save_cloud_audit_reports_calls_report_generator(self, tmp_path):
        """
        _save_cloud_audit_reports builds a results namespace and calls
        ReportGenerator.save_reports — not json.dump directly.
        """
        from cli.commands.cloud_audit_cmds import _save_cloud_audit_reports

        findings = [_make_cloud_finding()]
        start = datetime.now()
        end = start + timedelta(seconds=2)

        with patch("cli.commands.cloud_audit_cmds.ReportGenerator") as MockRG:
            instance = MockRG.return_value
            instance.save_reports.return_value = [{"path": str(tmp_path / "report.json")}]

            result = _save_cloud_audit_reports(
                findings=findings,
                providers=["aws"],
                output_dir=str(tmp_path),
                start_time=start,
                end_time=end,
            )

        MockRG.assert_called_once()
        instance.save_reports.assert_called_once()
        call_args = instance.save_reports.call_args
        # scan_type is passed as a keyword argument
        assert call_args.kwargs.get("scan_type") == "cloud_audit"

    def test_save_cloud_audit_reports_populates_findings_collector(self, tmp_path):
        """
        The results namespace passed to save_reports must carry a populated
        FindingsCollector so OWASP coverage stats are correct.
        """
        from cli.commands.cloud_audit_cmds import _save_cloud_audit_reports

        cloud_finding = _make_cloud_finding()
        start = datetime.now()
        end = start + timedelta(seconds=1)

        captured_results = []

        def capture_save(results, *args, **kwargs):
            captured_results.append(results)
            return []

        with patch("cli.commands.cloud_audit_cmds.ReportGenerator") as MockRG:
            MockRG.return_value.save_reports.side_effect = capture_save
            _save_cloud_audit_reports(
                findings=[cloud_finding],
                providers=["aws"],
                output_dir=str(tmp_path),
                start_time=start,
                end_time=end,
            )

        assert len(captured_results) == 1
        results = captured_results[0]
        assert results.findings_collector is not None
        collector_findings = results.findings_collector.findings
        assert len(collector_findings) == 1
        assert collector_findings[0].owasp_category == "API8"

    def test_save_cloud_audit_reports_statistics_match_findings(self, tmp_path):
        """
        statistics.findings_count and per-severity counts must match the
        actual findings passed in.
        """
        from cli.commands.cloud_audit_cmds import _save_cloud_audit_reports

        high_finding = Finding(
            id="h1",
            scan_id="s1",
            category="CLOUD_GATEWAY_MISCONFIGURATION",
            owasp_category="API8",
            severity=Severity.HIGH,
            endpoint="arn:aws:apigateway:us-east-1::/restapis/xyz",
            method="N/A",
            status_code=0,
            response_size=0,
            response_time=0.0,
            evidence="Open resource policy",
            recommendation="Restrict resource policy.",
        )
        medium_finding = _make_cloud_finding()

        start = datetime.now()
        end = start + timedelta(seconds=1)
        captured: list[SimpleNamespace] = []

        def capture_save(results, *a, **kw):
            captured.append(results)
            return []

        with patch("cli.commands.cloud_audit_cmds.ReportGenerator") as MockRG:
            MockRG.return_value.save_reports.side_effect = capture_save
            _save_cloud_audit_reports(
                findings=[high_finding, medium_finding],
                providers=["aws"],
                output_dir=str(tmp_path),
                start_time=start,
                end_time=end,
            )

        stats = captured[0].statistics
        assert stats.findings_count == 2
        assert stats.high_findings == 1
        assert stats.medium_findings == 1
        assert stats.critical_findings == 0

    def test_target_url_includes_provider_names(self, tmp_path):
        """
        target_url in the results namespace should embed the provider names
        so the report clearly labels what was audited.
        """
        from cli.commands.cloud_audit_cmds import _save_cloud_audit_reports

        start = datetime.now()
        end = start + timedelta(seconds=1)
        captured: list[SimpleNamespace] = []

        def capture_save(results, *a, **kw):
            captured.append(results)
            return []

        with patch("cli.commands.cloud_audit_cmds.ReportGenerator") as MockRG:
            MockRG.return_value.save_reports.side_effect = capture_save
            _save_cloud_audit_reports(
                findings=[],
                providers=["aws", "gcp"],
                output_dir=str(tmp_path),
                start_time=start,
                end_time=end,
            )

        assert "aws" in captured[0].target_url
        assert "gcp" in captured[0].target_url


# ---------------------------------------------------------------------------
# Req 1.5: merge_cloud_findings helper
# ---------------------------------------------------------------------------


class TestMergeCloudFindings:
    """merge_cloud_findings adds cloud findings to an existing collector."""

    def test_merge_adds_findings_to_collector(self):
        from cli.commands.cloud_audit_cmds import merge_cloud_findings

        collector = FindingsCollector("scan-abc")
        owasp_finding = _make_owasp_finding()
        collector.add_findings([owasp_finding])

        cloud_finding = _make_cloud_finding()
        added = merge_cloud_findings([cloud_finding], collector)

        assert added == 1
        assert len(collector.findings) == 2

    def test_merge_returns_zero_for_empty_list(self):
        from cli.commands.cloud_audit_cmds import merge_cloud_findings

        collector = FindingsCollector("scan-xyz")
        added = merge_cloud_findings([], collector)
        assert added == 0

    def test_merge_deduplicates_cloud_findings(self):
        """Identical cloud findings are not added twice."""
        from cli.commands.cloud_audit_cmds import merge_cloud_findings

        collector = FindingsCollector("scan-dedup")
        finding = _make_cloud_finding()
        # same finding twice
        merge_cloud_findings([finding], collector)
        added_second = merge_cloud_findings([finding], collector)

        assert added_second == 0
        assert len(collector.findings) == 1


# ---------------------------------------------------------------------------
# Req 7.4: APILeakCore.run_cloud_audit merges into existing collector
# ---------------------------------------------------------------------------


class TestAPILeakCoreRunCloudAudit:
    """
    APILeakCore.run_cloud_audit() should:
      - invoke CloudAuditOrchestrator.run()
      - add the normalised findings to self.findings_collector
      - return the list of findings
    This enables a consolidated report after both run_scan() and run_cloud_audit().
    """

    def _make_core(self):
        """Build a minimal APILeakCore with a real FindingsCollector."""
        from unittest.mock import MagicMock

        from core.engine import APILeakCore

        config = MagicMock()
        config.target.base_url = "https://api.example.com"
        config.owasp_testing.enabled_modules = []
        with patch("core.engine.ConfigurationManager"):
            core = APILeakCore.__new__(APILeakCore)
        core.scan_id = "engine-test-scan"
        core.config = config
        core.findings_collector = FindingsCollector("engine-test-scan")
        core.fuzzing_modules = {}
        core.owasp_modules = {}
        core.discovered_endpoints = []
        core.scan_results = None
        core.is_running = False
        from core.logging import get_logger
        core.logger = get_logger("test-engine")
        return core

    def test_run_cloud_audit_adds_findings_to_collector(self):
        """Findings returned by the orchestrator land in findings_collector."""
        from core.engine import APILeakCore

        core = self._make_core()
        cloud_finding = _make_cloud_finding()

        # Pre-populate with one OWASP finding
        owasp_finding = _make_owasp_finding()
        core.findings_collector.add_findings([owasp_finding])

        mock_orch = MagicMock()
        mock_orch.run = AsyncMock(return_value=[cloud_finding])

        config = CloudAuditConfig(providers=["aws"])

        with patch(
            "modules.cloud.orchestrator.CloudAuditOrchestrator",
            return_value=mock_orch,
        ):
            returned = asyncio.run(core.run_cloud_audit(config))

        assert len(returned) == 1
        # Both OWASP and cloud findings are now in the collector
        assert len(core.findings_collector.findings) == 2

    def test_run_cloud_audit_returns_findings_list(self):
        """run_cloud_audit returns the list of findings added."""
        from core.engine import APILeakCore

        core = self._make_core()
        f1 = _make_cloud_finding("CLOUD_GATEWAY_MISCONFIGURATION")
        f2 = _make_cloud_finding("AWS_APIGW_NO_WAF")
        # Give them unique endpoints to avoid deduplication
        f2.endpoint = "arn:aws:apigateway:eu-west-1::/restapis/xyz"

        mock_orch = MagicMock()
        mock_orch.run = AsyncMock(return_value=[f1, f2])

        config = CloudAuditConfig(providers=["aws"])
        with patch(
            "modules.cloud.orchestrator.CloudAuditOrchestrator",
            return_value=mock_orch,
        ):
            returned = asyncio.run(core.run_cloud_audit(config))

        assert len(returned) == 2

    def test_run_cloud_audit_passes_scan_id_to_orchestrator(self):
        """The engine's scan_id should be threaded into orchestrator.run()."""
        from core.engine import APILeakCore

        core = self._make_core()
        core.scan_id = "fixed-scan-id-001"

        mock_orch = MagicMock()
        mock_orch.run = AsyncMock(return_value=[])

        config = CloudAuditConfig(providers=["aws"])
        with patch(
            "modules.cloud.orchestrator.CloudAuditOrchestrator",
            return_value=mock_orch,
        ):
            asyncio.run(core.run_cloud_audit(config))

        mock_orch.run.assert_awaited_once_with(scan_id="fixed-scan-id-001")

    def test_consolidated_report_contains_both_finding_sets(self, tmp_path):
        """
        After run_scan + run_cloud_audit, ReportGenerator.save_reports called
        with scan_results should include both OWASP and cloud findings (Req 7.4).
        """
        from core.engine import APILeakCore

        core = self._make_core()

        # Simulate OWASP scan findings already in the collector
        owasp_f = _make_owasp_finding()
        core.findings_collector.add_findings([owasp_f])

        # Cloud audit adds more findings
        cloud_f = _make_cloud_finding()
        mock_orch = MagicMock()
        mock_orch.run = AsyncMock(return_value=[cloud_f])

        config = CloudAuditConfig(providers=["aws"])
        with patch(
            "modules.cloud.orchestrator.CloudAuditOrchestrator",
            return_value=mock_orch,
        ):
            asyncio.run(core.run_cloud_audit(config))

        # Build a results namespace as runner.py does and verify both findings
        # are visible to ReportGenerator
        all_findings = core.findings_collector.findings
        assert len(all_findings) == 2

        categories = {f.owasp_category for f in all_findings}
        assert "API8" in categories  # both cloud and this OWASP finding map to API8

        # Verify ReportGenerator can serialize both without error
        results = _build_minimal_scan_results(all_findings, scan_id=core.scan_id)
        generator = ReportGenerator(template_dir=str(tmp_path / "tpl"))
        json_report = generator.generate_json_report(results)
        import json as _json

        doc = _json.loads(json_report)
        assert doc["statistics"]["findings"]["total"] == 2
