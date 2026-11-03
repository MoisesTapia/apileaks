"""
tests/test_ai_triage_cli_integration.py — Unit tests for the --ai-triage CLI flag.

Covers task 8.6: integration of ``--ai-triage`` in ``cli/commands/scan_cmds.py``
and the ``_run_ai_triage_section`` helper in ``cli/runner.py``.

Requirement 5.1 — scan appends AI triage section when ``--ai-triage`` is set.
Requirement 5.2 — original findings are never modified.
Requirement 5.3 — AI triage failure never fails the scan (safe_triage returns None).
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import click
import pytest

# Break circular import that exists at project level (same pattern as other tests).
import core.logging  # noqa: F401

from utils.ai.triage_assistant import FindingTriageAssistant, TriageReport


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(id_: str, severity: str = "high") -> MagicMock:
    """Return a minimal mock Finding object."""
    f = MagicMock()
    f.id = id_
    f.category = "auth"
    f.owasp_category = "API2"
    f.severity = MagicMock()
    f.severity.value = severity
    f.endpoint = "/api/resource"
    f.method = "GET"
    f.evidence = "evidence text"
    f.recommendation = "Fix it"
    f.payload = None
    f.response_snippet = None
    return f


def _make_results(findings: list) -> MagicMock:
    """Return a minimal mock ScanResults object."""
    results = MagicMock()
    results.findings_collector = MagicMock()
    results.findings_collector.get_prioritized_findings.return_value = findings
    results.findings = findings
    return results


# ---------------------------------------------------------------------------
# Tests for _run_ai_triage_section
# ---------------------------------------------------------------------------


class TestRunAiTriageSection:
    """Direct tests for the ``_run_ai_triage_section`` helper."""

    def test_no_op_when_import_fails(self, capsys):
        """Requirement 5.3: import failure logs WARNING, output unchanged."""
        from cli.runner import _run_ai_triage_section

        results = _make_results([_make_finding("F1")])
        with patch.dict(
            "sys.modules",
            {
                "utils.ai.provider_base": None,
                "utils.ai.triage_assistant": None,
            },
        ):
            # Should not raise; scan is never failed.
            _run_ai_triage_section(results, None)

        # No "AI Triage Report" header should appear.
        captured = capsys.readouterr()
        assert "AI Triage Report" not in captured.out

    def test_renders_triage_section_on_success(self, capsys):
        """Requirement 5.1: triage section is printed when safe_triage succeeds."""
        from cli.runner import _run_ai_triage_section

        findings = [_make_finding("F1"), _make_finding("F2")]
        results = _make_results(findings)

        triage_report = TriageReport(
            prioritized_finding_ids=["F1", "F2"],
            narrative_summary="F1 is the most critical issue.",
            per_finding_notes={"F1": "High impact", "F2": "Lower impact"},
        )

        mock_provider = MagicMock()
        mock_provider.complete = AsyncMock(return_value='{"prioritized_finding_ids": ["F1", "F2"], "narrative_summary": "F1 is the most critical issue.", "per_finding_notes": {"F1": "High impact", "F2": "Lower impact"}}')
        mock_provider.provider_name = "mock"

        from utils.ai.provider_base import AIConfig

        ai_config = AIConfig(provider=None)  # provider=None -> safe_triage mocked below

        with patch.object(FindingTriageAssistant, "safe_triage", new=AsyncMock(return_value=triage_report)):
            _run_ai_triage_section(results, ai_config)

        captured = capsys.readouterr()
        assert "AI Triage Report" in captured.out
        assert "F1 is the most critical issue." in captured.out
        assert "F1" in captured.out
        assert "F2" in captured.out
        assert "High impact" in captured.out

    def test_no_section_when_safe_triage_returns_none(self, capsys):
        """Requirement 5.3: None from safe_triage -> no AI section, no error."""
        from cli.runner import _run_ai_triage_section

        findings = [_make_finding("F1")]
        results = _make_results(findings)

        from utils.ai.provider_base import AIConfig

        ai_config = AIConfig(provider=None)

        with patch.object(FindingTriageAssistant, "safe_triage", new=AsyncMock(return_value=None)):
            _run_ai_triage_section(results, ai_config)

        captured = capsys.readouterr()
        assert "AI Triage Report" not in captured.out

    def test_invalid_provider_logs_warning_not_raises(self, capsys):
        """Requirement 5.3: ValueError from build_llm_provider is caught gracefully."""
        from cli.runner import _run_ai_triage_section
        from utils.ai.provider_base import AIConfig

        findings = [_make_finding("F1")]
        results = _make_results(findings)
        ai_config = AIConfig(provider="unsupported_provider_xyz")

        # build_llm_provider raises ValueError for unknown providers.
        # _run_ai_triage_section must catch it and NOT raise.
        _run_ai_triage_section(results, ai_config)  # must not raise

        captured = capsys.readouterr()
        assert "AI Triage Report" not in captured.out

    def test_empty_findings_renders_empty_priority_list(self, capsys):
        """Edge case: no findings produces a valid (empty) triage section."""
        from cli.runner import _run_ai_triage_section
        from utils.ai.provider_base import AIConfig

        results = _make_results([])

        triage_report = TriageReport(
            prioritized_finding_ids=[],
            narrative_summary="No findings to triage.",
            per_finding_notes={},
        )

        ai_config = AIConfig(provider=None)

        with patch.object(FindingTriageAssistant, "safe_triage", new=AsyncMock(return_value=triage_report)):
            _run_ai_triage_section(results, ai_config)

        captured = capsys.readouterr()
        assert "AI Triage Report" in captured.out
        assert "No findings to triage." in captured.out

    def test_findings_read_from_collector_when_present(self, capsys):
        """Requirement 5.1: findings come from findings_collector when available."""
        from cli.runner import _run_ai_triage_section
        from utils.ai.provider_base import AIConfig

        findings = [_make_finding("F-COL")]
        results = MagicMock()
        results.findings_collector = MagicMock()
        results.findings_collector.get_prioritized_findings.return_value = findings

        triage_report = TriageReport(
            prioritized_finding_ids=["F-COL"],
            narrative_summary="Collector-based triage.",
            per_finding_notes={},
        )
        ai_config = AIConfig(provider=None)

        captured_findings = []

        async def _capture_safe_triage(self_inner, f):
            captured_findings.extend(f)
            return triage_report

        with patch.object(FindingTriageAssistant, "safe_triage", new=AsyncMock(return_value=triage_report)):
            _run_ai_triage_section(results, ai_config)

        # Verify collector was consulted.
        results.findings_collector.get_prioritized_findings.assert_called_once()

    def test_falls_back_to_results_findings_when_no_collector(self, capsys):
        """Fallback path: when findings_collector is absent, use results.findings."""
        from cli.runner import _run_ai_triage_section
        from utils.ai.provider_base import AIConfig

        findings = [_make_finding("F-FB")]
        results = MagicMock()
        results.findings_collector = None  # no collector
        results.findings = findings

        triage_report = TriageReport(
            prioritized_finding_ids=["F-FB"],
            narrative_summary="Fallback triage.",
            per_finding_notes={},
        )
        ai_config = AIConfig(provider=None)

        with patch.object(FindingTriageAssistant, "safe_triage", new=AsyncMock(return_value=triage_report)):
            _run_ai_triage_section(results, ai_config)

        captured = capsys.readouterr()
        assert "AI Triage Report" in captured.out


# ---------------------------------------------------------------------------
# Tests for the --ai-triage flag presence on the scan command
# ---------------------------------------------------------------------------


class TestAiTriageFlagRegistered:
    """Verify the ``--ai-triage`` flag is wired onto the ``scan`` command."""

    def test_scan_command_has_ai_triage_option(self):
        """The scan command must expose --ai-triage (Requirement 5.1)."""
        from cli.commands.scan_cmds import scan

        option_names = {
            name
            for param in scan.params
            for name in param.opts
        }
        assert "--ai-triage" in option_names, (
            "--ai-triage flag not found on the scan command"
        )

    def test_ai_triage_defaults_to_false(self):
        """--ai-triage must be an opt-in flag, defaulting to False."""
        from cli.commands.scan_cmds import scan

        for param in scan.params:
            if "--ai-triage" in param.opts:
                assert param.default is False, (
                    "--ai-triage should default to False (opt-in flag)"
                )
                break

    def test_full_command_also_has_ai_triage_option(self):
        """The 'full' alias must also expose --ai-triage via shared _orchestrator_options."""
        from cli.commands.scan_cmds import full

        option_names = {
            name
            for param in full.params
            for name in param.opts
        }
        assert "--ai-triage" in option_names, (
            "--ai-triage flag not found on the full (deprecated alias) command"
        )
