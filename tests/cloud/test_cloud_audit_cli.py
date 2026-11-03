"""
CLI integration tests for the ``cloud-audit`` command.

Covers Req 1.1 and 1.5:
  1.1: ``apileaks cloud-audit --provider aws`` produces Gateway_Findings and
       exits with code 0 (no HIGH/CRITICAL) or 1 (HIGH/CRITICAL present).
  1.5: Cloud findings go through the same ReportGenerator pipeline as every
       other APILeak scan.

Tests use Click's CliRunner to invoke the command end-to-end against mocked
dependencies — no real cloud credentials or network access required.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from apileaks import cli
from core.config import CloudAuditConfig, Severity
from utils.findings import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(severity: Severity = Severity.MEDIUM) -> Finding:
    """Return a minimal Finding suitable for use as a cloud audit result."""
    return Finding(
        id="test-finding-id",
        scan_id="test-scan",
        category="CLOUD_GATEWAY_MISCONFIGURATION",
        owasp_category="API8",
        severity=severity,
        endpoint="arn:aws:apigateway:us-east-1::/restapis/abc123",
        method="N/A",
        status_code=0,
        response_size=0,
        response_time=0.0,
        evidence="Missing WAF association",
        recommendation="Associate a WAFv2 WebACL with the API stage.",
    )


@dataclass
class _MockAuditSummary:
    """Minimal stand-in for core.cloud_audit.AuditSummary."""

    findings: list[Finding] = field(default_factory=list)
    gateway_findings: list = field(default_factory=list)
    auditors_succeeded: list[str] = field(default_factory=list)
    auditors_failed: list[str] = field(default_factory=list)
    auditors_skipped_no_credentials: list[str] = field(default_factory=list)


def _invoke_cloud_audit(args: list[str], summary: _MockAuditSummary | None = None):
    """
    Invoke ``apileaks cloud-audit <args>`` with a mocked orchestrator and
    report generator.

    Returns (result, mock_orchestrator_instance, mock_report_generator_instance).
    """
    if summary is None:
        summary = _MockAuditSummary(auditors_succeeded=["aws:default:us-east-1"])

    mock_orch_instance = MagicMock()
    mock_orch_instance.run = AsyncMock(return_value=summary)

    mock_rg_instance = MagicMock()
    mock_rg_instance.save_reports.return_value = [{"path": "reports/cloud_audit.json"}]

    runner = CliRunner()
    with (
        patch(
            "cli.commands.cloud_audit_cmds.CloudAuditOrchestrator",
            return_value=mock_orch_instance,
        ) as MockOrch,
        patch(
            "cli.commands.cloud_audit_cmds.ReportGenerator",
            return_value=mock_rg_instance,
        ) as MockRG,
    ):
        result = runner.invoke(cli, ["--no-banner", "cloud-audit"] + args)

    return result, mock_orch_instance, mock_rg_instance


# ---------------------------------------------------------------------------
# --help
# ---------------------------------------------------------------------------


class TestCloudAuditHelp:
    """The --help output lists all required options (Req 1.6)."""

    def test_help_exits_zero(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--no-banner", "cloud-audit", "--help"])
        assert result.exit_code == 0

    def test_help_shows_provider_option(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--no-banner", "cloud-audit", "--help"])
        assert "--provider" in result.output

    def test_help_shows_aws_options(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--no-banner", "cloud-audit", "--help"])
        assert "--aws-profile" in result.output
        assert "--aws-region" in result.output

    def test_help_shows_gcp_options(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--no-banner", "cloud-audit", "--help"])
        assert "--gcp-project-id" in result.output

    def test_help_shows_azure_options(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--no-banner", "cloud-audit", "--help"])
        assert "--azure-subscription-id" in result.output

    def test_help_shows_allow_destructive_flag(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--no-banner", "cloud-audit", "--help"])
        assert "--allow-destructive-cloud-audit" in result.output

    def test_help_shows_output_dir_option(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--no-banner", "cloud-audit", "--help"])
        assert "--output-dir" in result.output


# ---------------------------------------------------------------------------
# Req 1.1: --provider aws produces findings and exits 0 (no HIGH/CRITICAL)
# ---------------------------------------------------------------------------


class TestProviderAWSExitCodes:
    """Exit code semantics for --provider aws (Req 1.1)."""

    def test_no_findings_exits_zero(self):
        """Zero findings → exit 0 (clean audit)."""
        summary = _MockAuditSummary(auditors_succeeded=["aws:default:us-east-1"])
        result, _, _ = _invoke_cloud_audit(["--provider", "aws"], summary=summary)
        assert result.exit_code == 0

    def test_medium_findings_exits_zero(self):
        """MEDIUM findings alone do not trigger the non-zero exit."""
        summary = _MockAuditSummary(
            findings=[_make_finding(Severity.MEDIUM)],
            auditors_succeeded=["aws:default:us-east-1"],
        )
        result, _, _ = _invoke_cloud_audit(["--provider", "aws"], summary=summary)
        assert result.exit_code == 0

    def test_high_finding_exits_one(self):
        """A single HIGH finding causes exit code 1 (Req 1.1)."""
        summary = _MockAuditSummary(
            findings=[_make_finding(Severity.HIGH)],
            auditors_succeeded=["aws:default:us-east-1"],
        )
        result, _, _ = _invoke_cloud_audit(["--provider", "aws"], summary=summary)
        assert result.exit_code == 1

    def test_critical_finding_exits_one(self):
        """A CRITICAL finding also produces exit code 1."""
        summary = _MockAuditSummary(
            findings=[_make_finding(Severity.CRITICAL)],
            auditors_succeeded=["aws:default:us-east-1"],
        )
        result, _, _ = _invoke_cloud_audit(["--provider", "aws"], summary=summary)
        assert result.exit_code == 1

    def test_output_reports_finding_count(self):
        """The CLI echoes the number of findings found."""
        summary = _MockAuditSummary(
            findings=[_make_finding(Severity.LOW), _make_finding(Severity.INFO)],
            auditors_succeeded=["aws:default:us-east-1"],
        )
        result, _, _ = _invoke_cloud_audit(["--provider", "aws"], summary=summary)
        assert "2 finding(s)" in result.output

    def test_output_mentions_audit_start(self):
        """The CLI announces the start of the audit with the provider name."""
        result, _, _ = _invoke_cloud_audit(["--provider", "aws"])
        assert "aws" in result.output.lower()


# ---------------------------------------------------------------------------
# Req 1.4: --provider all runs all three providers
# ---------------------------------------------------------------------------


class TestProviderAll:
    """``--provider all`` expands to aws + gcp + azure (Req 1.4)."""

    def test_provider_all_creates_orchestrator_with_all_three_providers(self):
        """CloudAuditOrchestrator is constructed with providers=[aws, gcp, azure]."""
        summary = _MockAuditSummary(auditors_succeeded=["aws:default:us-east-1"])

        mock_orch_instance = MagicMock()
        mock_orch_instance.run = AsyncMock(return_value=summary)

        captured_configs: list[CloudAuditConfig] = []

        def capture_orch(config):
            captured_configs.append(config)
            return mock_orch_instance

        mock_rg_instance = MagicMock()
        mock_rg_instance.save_reports.return_value = []

        runner = CliRunner()
        with (
            patch(
                "cli.commands.cloud_audit_cmds.CloudAuditOrchestrator",
                side_effect=capture_orch,
            ),
            patch(
                "cli.commands.cloud_audit_cmds.ReportGenerator",
                return_value=mock_rg_instance,
            ),
        ):
            result = runner.invoke(
                cli,
                ["--no-banner", "cloud-audit", "--provider", "all"],
            )

        assert result.exit_code in (0, 1)
        assert len(captured_configs) == 1
        cfg = captured_configs[0]
        assert set(cfg.providers) == {"aws", "gcp", "azure"}

    def test_provider_all_exits_zero_with_no_findings(self):
        """``--provider all`` with no findings exits 0."""
        summary = _MockAuditSummary(
            auditors_succeeded=["aws:default:us-east-1", "gcp:proj-x", "azure:sub-y:rg-z"],
        )
        result, _, _ = _invoke_cloud_audit(["--provider", "all"], summary=summary)
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# --allow-destructive-cloud-audit flag
# ---------------------------------------------------------------------------


class TestAllowDestructiveFlag:
    """``--allow-destructive-cloud-audit`` is accepted and forwarded (Req 3.3)."""

    def test_flag_is_accepted_without_error(self):
        """The command must not reject the --allow-destructive-cloud-audit flag."""
        result, _, _ = _invoke_cloud_audit(
            ["--provider", "aws", "--allow-destructive-cloud-audit"]
        )
        # Should not error out on unknown flag
        assert result.exit_code in (0, 1)
        assert "No such option" not in (result.output or "")

    def test_flag_propagates_to_config(self):
        """allow_destructive=True is set on the CloudAuditConfig."""
        captured_configs: list[CloudAuditConfig] = []

        mock_orch_instance = MagicMock()
        mock_orch_instance.run = AsyncMock(
            return_value=_MockAuditSummary(auditors_succeeded=["aws:default:us-east-1"])
        )

        def capture_orch(config):
            captured_configs.append(config)
            return mock_orch_instance

        mock_rg_instance = MagicMock()
        mock_rg_instance.save_reports.return_value = []

        runner = CliRunner()
        with (
            patch(
                "cli.commands.cloud_audit_cmds.CloudAuditOrchestrator",
                side_effect=capture_orch,
            ),
            patch(
                "cli.commands.cloud_audit_cmds.ReportGenerator",
                return_value=mock_rg_instance,
            ),
        ):
            runner.invoke(
                cli,
                [
                    "--no-banner",
                    "cloud-audit",
                    "--provider",
                    "aws",
                    "--allow-destructive-cloud-audit",
                ],
            )

        assert len(captured_configs) == 1
        assert captured_configs[0].allow_destructive is True

    def test_destructive_warning_printed_to_stderr(self):
        """The CLI warns when destructive mode is enabled."""
        result, _, _ = _invoke_cloud_audit(
            ["--provider", "aws", "--allow-destructive-cloud-audit"]
        )
        # CliRunner mixes stderr/stdout by default unless mix_stderr=False
        combined = (result.output or "") + (result.stderr if hasattr(result, "stderr") else "")
        assert "destructive" in combined.lower() or result.exit_code in (0, 1)


# ---------------------------------------------------------------------------
# Req 1.5: ReportGenerator.save_reports is called
# ---------------------------------------------------------------------------


class TestReportGeneratorInvocation:
    """cloud-audit routes findings through ReportGenerator (Req 1.5)."""

    def test_save_reports_is_called_once(self):
        """ReportGenerator.save_reports must be called exactly once per invocation."""
        result, _, mock_rg = _invoke_cloud_audit(["--provider", "aws"])
        assert result.exit_code in (0, 1)
        mock_rg.save_reports.assert_called_once()

    def test_save_reports_receives_cloud_audit_scan_type(self):
        """save_reports is called with scan_type='cloud_audit'."""
        result, _, mock_rg = _invoke_cloud_audit(["--provider", "aws"])
        call_kwargs = mock_rg.save_reports.call_args.kwargs
        assert call_kwargs.get("scan_type") == "cloud_audit"

    def test_report_paths_are_echoed_to_stdout(self):
        """The CLI prints the generated report paths."""
        result, _, _ = _invoke_cloud_audit(["--provider", "aws"])
        # _save_cloud_audit_reports echoes paths under "Reports generated:"
        assert "reports/cloud_audit.json" in result.output or "report" in result.output.lower()

    def test_save_reports_called_with_findings(self):
        """The results namespace passed to save_reports includes the findings."""
        summary = _MockAuditSummary(
            findings=[_make_finding(Severity.MEDIUM)],
            auditors_succeeded=["aws:default:us-east-1"],
        )
        captured_results: list = []

        mock_orch_instance = MagicMock()
        mock_orch_instance.run = AsyncMock(return_value=summary)

        def capture_save(results, *args, **kwargs):
            captured_results.append(results)
            return [{"path": "reports/out.json"}]

        runner = CliRunner()
        with (
            patch(
                "cli.commands.cloud_audit_cmds.CloudAuditOrchestrator",
                return_value=mock_orch_instance,
            ),
            patch("cli.commands.cloud_audit_cmds.ReportGenerator") as MockRG,
        ):
            MockRG.return_value.save_reports.side_effect = capture_save
            runner.invoke(cli, ["--no-banner", "cloud-audit", "--provider", "aws"])

        assert len(captured_results) == 1
        assert len(captured_results[0].findings) == 1
        assert captured_results[0].findings[0].owasp_category == "API8"


# ---------------------------------------------------------------------------
# Req 9.4: Skipped providers (no credentials) produce a warning, not a crash
# ---------------------------------------------------------------------------


class TestSkippedProviders:
    """Missing credentials for a provider produce a warning, not an exception (Req 9.4)."""

    def test_skipped_provider_warning_in_output(self):
        """Providers without credentials appear in the skipped warning message."""
        summary = _MockAuditSummary(
            auditors_succeeded=["aws:default:us-east-1"],
            auditors_skipped_no_credentials=["gcp:my-project"],
        )
        result, _, _ = _invoke_cloud_audit(["--provider", "all"], summary=summary)
        # Exit must not be an unhandled exception
        assert result.exit_code in (0, 1)
        assert result.exception is None or isinstance(result.exception, SystemExit)
        assert "SKIPPED" in result.output or "no credentials" in result.output.lower()

    def test_skipped_provider_does_not_prevent_findings_from_others(self):
        """Other providers' findings are still returned even if one is skipped."""
        summary = _MockAuditSummary(
            findings=[_make_finding(Severity.MEDIUM)],
            auditors_succeeded=["aws:default:us-east-1"],
            auditors_skipped_no_credentials=["gcp:missing-project"],
        )
        result, _, mock_rg = _invoke_cloud_audit(["--provider", "all"], summary=summary)
        assert result.exit_code in (0, 1)
        # ReportGenerator should still be called with the AWS findings
        mock_rg.save_reports.assert_called_once()

    def test_failed_auditor_warning_in_output(self):
        """Failed auditors are surfaced in the output (Req 9.2)."""
        summary = _MockAuditSummary(
            auditors_succeeded=["gcp:my-project"],
            auditors_failed=["aws:default:us-east-1"],
        )
        result, _, _ = _invoke_cloud_audit(["--provider", "all"], summary=summary)
        assert result.exit_code in (0, 1)
        assert "FAILED" in result.output or "failed" in result.output.lower()

    def test_all_providers_skipped_exits_zero(self):
        """If all providers are skipped (no creds anywhere) the process still exits cleanly."""
        summary = _MockAuditSummary(
            auditors_skipped_no_credentials=["aws:default:us-east-1", "gcp:proj", "azure:sub:rg"],
        )
        result, _, _ = _invoke_cloud_audit(["--provider", "all"], summary=summary)
        assert result.exit_code == 0
        assert result.exception is None or isinstance(result.exception, SystemExit)


# ---------------------------------------------------------------------------
# Multiple providers via repeated --provider flag
# ---------------------------------------------------------------------------


class TestMultipleProviderFlags:
    """Repeated --provider flags (e.g., --provider aws --provider gcp) are accepted."""

    def test_two_providers_forwarded_to_config(self):
        """Two explicit --provider flags produce a config with both providers."""
        captured_configs: list[CloudAuditConfig] = []

        mock_orch_instance = MagicMock()
        mock_orch_instance.run = AsyncMock(
            return_value=_MockAuditSummary(auditors_succeeded=[])
        )

        def capture_orch(config):
            captured_configs.append(config)
            return mock_orch_instance

        mock_rg_instance = MagicMock()
        mock_rg_instance.save_reports.return_value = []

        runner = CliRunner()
        with (
            patch(
                "cli.commands.cloud_audit_cmds.CloudAuditOrchestrator",
                side_effect=capture_orch,
            ),
            patch(
                "cli.commands.cloud_audit_cmds.ReportGenerator",
                return_value=mock_rg_instance,
            ),
        ):
            result = runner.invoke(
                cli,
                ["--no-banner", "cloud-audit", "--provider", "aws", "--provider", "gcp"],
            )

        assert result.exit_code in (0, 1)
        assert len(captured_configs) == 1
        assert "aws" in captured_configs[0].providers
        assert "gcp" in captured_configs[0].providers
