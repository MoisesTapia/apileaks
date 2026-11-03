"""
tests/test_ai_dedup_cli_integration.py — Unit tests for the --ai-dedup CLI flag.

Covers task 9.2: integration of ``--ai-dedup`` in ``cli/commands/scan_cmds.py``
and the ``_run_ai_dedup_section`` helper in ``cli/runner.py``.

Requirement 6.1 — scan groups findings when ``--ai-dedup`` is set.
Requirement 6.2 — both the consolidated group summary AND full individual Finding
                  detail are present in the rendered output (no information loss).
Requirement 6.3 — when no LLM provider is configured the deterministic fallback
                  is used; the section always appears without error.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Avoid circular imports at collection time.
import core.logging  # noqa: F401

from utils.ai.semantic_dedup import FindingGroup, SemanticDeduplicator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    id_: str,
    severity: str = "high",
    category: str = "auth",
    owasp_category: str = "API2",
    endpoint: str = "/api/resource",
    method: str = "GET",
    evidence: str = "evidence text",
    recommendation: str = "Fix it",
) -> MagicMock:
    """Return a minimal mock Finding object."""
    f = MagicMock()
    f.id = id_
    f.category = category
    f.owasp_category = owasp_category
    f.severity = MagicMock()
    f.severity.value = severity
    f.endpoint = endpoint
    f.method = method
    f.evidence = evidence
    f.recommendation = recommendation
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
# Tests for _run_ai_dedup_section
# ---------------------------------------------------------------------------


class TestRunAiDedupSection:
    """Direct unit-tests for the ``_run_ai_dedup_section`` helper."""

    def test_no_op_when_import_fails(self, capsys):
        """Requirement 6.3: import failure logs WARNING, output unchanged."""
        from cli.runner import _run_ai_dedup_section

        results = _make_results([_make_finding("F1")])
        with patch.dict(
            "sys.modules",
            {
                "utils.ai.provider_base": None,
                "utils.ai.semantic_dedup": None,
            },
        ):
            _run_ai_dedup_section(results, None)

        captured = capsys.readouterr()
        assert "Dedup" not in captured.out

    def test_renders_consolidated_group_with_member_details(self, capsys):
        """Requirement 6.2: consolidated group summary AND individual details shown."""
        from cli.runner import _run_ai_dedup_section
        from utils.ai.provider_base import AIConfig

        f1 = _make_finding("F1", severity="high", endpoint="/api/users", method="GET")
        f2 = _make_finding("F2", severity="medium", endpoint="/api/items", method="POST")
        results = _make_results([f1, f2])

        groups = [
            FindingGroup(
                group_id="aaaa-bbbb-cccc-dddd",
                root_cause_summary="Broken auth in multiple endpoints",
                member_finding_ids=["F1", "F2"],
            )
        ]

        ai_config = AIConfig(provider=None)

        with patch.object(
            SemanticDeduplicator, "safe_deduplicate", new=AsyncMock(return_value=groups)
        ):
            _run_ai_dedup_section(results, ai_config)

        captured = capsys.readouterr()
        # Group summary
        assert "Broken auth in multiple endpoints" in captured.out
        # Individual member detail — Requirement 6.2
        assert "F1" in captured.out
        assert "F2" in captured.out
        assert "/api/users" in captured.out
        assert "/api/items" in captured.out
        # Section header
        assert "Deduplication" in captured.out

    def test_singleton_findings_rendered(self, capsys):
        """Requirement 6.2: ungrouped (singleton) findings are still rendered."""
        from cli.runner import _run_ai_dedup_section
        from utils.ai.provider_base import AIConfig

        f1 = _make_finding("F-SOLO", severity="critical", endpoint="/secret")
        results = _make_results([f1])

        groups = [
            FindingGroup(
                group_id="solo-solo",
                root_cause_summary="auth (API2)",
                member_finding_ids=["F-SOLO"],
            )
        ]

        ai_config = AIConfig(provider=None)

        with patch.object(
            SemanticDeduplicator, "safe_deduplicate", new=AsyncMock(return_value=groups)
        ):
            _run_ai_dedup_section(results, ai_config)

        captured = capsys.readouterr()
        assert "F-SOLO" in captured.out
        assert "/secret" in captured.out

    def test_no_section_when_safe_deduplicate_returns_none(self, capsys):
        """Requirement 6.3: None from safe_deduplicate -> no dedup section, no error."""
        from cli.runner import _run_ai_dedup_section
        from utils.ai.provider_base import AIConfig

        results = _make_results([_make_finding("F1")])
        ai_config = AIConfig(provider=None)

        with patch.object(
            SemanticDeduplicator, "safe_deduplicate", new=AsyncMock(return_value=None)
        ):
            _run_ai_dedup_section(results, ai_config)

        captured = capsys.readouterr()
        assert "Deduplication" not in captured.out

    def test_no_findings_produces_empty_section(self, capsys):
        """Edge case: zero findings renders the section with 0-finding summary."""
        from cli.runner import _run_ai_dedup_section
        from utils.ai.provider_base import AIConfig

        results = _make_results([])
        ai_config = AIConfig(provider=None)

        _run_ai_dedup_section(results, ai_config)

        captured = capsys.readouterr()
        assert "Deduplication" in captured.out
        # No crash, section is shown with the note about nothing to deduplicate.
        assert "No findings" in captured.out

    def test_invalid_provider_degrades_gracefully(self, capsys):
        """Requirement 6.3: ValueError from build_llm_provider is caught."""
        from cli.runner import _run_ai_dedup_section
        from utils.ai.provider_base import AIConfig

        results = _make_results([_make_finding("F1")])
        ai_config = AIConfig(provider="unsupported_xyz")

        # Must not raise — deterministic fallback or warning is acceptable.
        _run_ai_dedup_section(results, ai_config)

    def test_findings_read_from_collector_when_present(self):
        """Findings come from findings_collector when available."""
        from cli.runner import _run_ai_dedup_section
        from utils.ai.provider_base import AIConfig

        findings = [_make_finding("F-COL")]
        results = _make_results(findings)
        ai_config = AIConfig(provider=None)

        groups = [
            FindingGroup(
                group_id="g1",
                root_cause_summary="root",
                member_finding_ids=["F-COL"],
            )
        ]

        with patch.object(
            SemanticDeduplicator, "safe_deduplicate", new=AsyncMock(return_value=groups)
        ):
            _run_ai_dedup_section(results, ai_config)

        results.findings_collector.get_prioritized_findings.assert_called_once()

    def test_falls_back_to_results_findings_when_no_collector(self, capsys):
        """Fallback: when findings_collector is None, use results.findings."""
        from cli.runner import _run_ai_dedup_section
        from utils.ai.provider_base import AIConfig

        findings = [_make_finding("F-FB")]
        results = MagicMock()
        results.findings_collector = None
        results.findings = findings
        ai_config = AIConfig(provider=None)

        groups = [
            FindingGroup(
                group_id="g-fb",
                root_cause_summary="fallback root",
                member_finding_ids=["F-FB"],
            )
        ]

        with patch.object(
            SemanticDeduplicator, "safe_deduplicate", new=AsyncMock(return_value=groups)
        ):
            _run_ai_dedup_section(results, ai_config)

        captured = capsys.readouterr()
        assert "F-FB" in captured.out

    def test_multiple_groups_all_rendered(self, capsys):
        """Requirement 6.1: all groups are rendered when multiple are returned."""
        from cli.runner import _run_ai_dedup_section
        from utils.ai.provider_base import AIConfig

        f1 = _make_finding("F1")
        f2 = _make_finding("F2")
        f3 = _make_finding("F3", endpoint="/ssrf-endpoint")
        results = _make_results([f1, f2, f3])
        ai_config = AIConfig(provider=None)

        groups = [
            FindingGroup(
                group_id="g1",
                root_cause_summary="Auth issue",
                member_finding_ids=["F1", "F2"],
            ),
            FindingGroup(
                group_id="g2",
                root_cause_summary="SSRF issue",
                member_finding_ids=["F3"],
            ),
        ]

        with patch.object(
            SemanticDeduplicator, "safe_deduplicate", new=AsyncMock(return_value=groups)
        ):
            _run_ai_dedup_section(results, ai_config)

        captured = capsys.readouterr()
        # Consolidated group summary must appear
        assert "Auth issue" in captured.out
        # All finding IDs must appear (no information loss, Requirement 6.2)
        assert "F1" in captured.out
        assert "F2" in captured.out
        # Singleton finding must appear (rendered with its individual detail)
        assert "F3" in captured.out
        assert "/ssrf-endpoint" in captured.out


# ---------------------------------------------------------------------------
# Tests for the --ai-dedup flag presence on the scan command
# ---------------------------------------------------------------------------


class TestAiDedupFlagRegistered:
    """Verify the ``--ai-dedup`` flag is wired onto the ``scan`` command."""

    def test_scan_command_has_ai_dedup_option(self):
        """The scan command must expose --ai-dedup (Requirement 6.1)."""
        from cli.commands.scan_cmds import scan

        option_names = {name for param in scan.params for name in param.opts}
        assert "--ai-dedup" in option_names, "--ai-dedup flag not found on the scan command"

    def test_ai_dedup_defaults_to_false(self):
        """--ai-dedup must be an opt-in flag, defaulting to False."""
        from cli.commands.scan_cmds import scan

        for param in scan.params:
            if "--ai-dedup" in param.opts:
                assert param.default is False, "--ai-dedup should default to False"
                break

    def test_full_command_also_has_ai_dedup_option(self):
        """The 'full' alias must also expose --ai-dedup via shared _orchestrator_options."""
        from cli.commands.scan_cmds import full

        option_names = {name for param in full.params for name in param.opts}
        assert "--ai-dedup" in option_names, "--ai-dedup flag not found on the full command"

    def test_ai_triage_and_ai_dedup_are_independent_flags(self):
        """--ai-triage and --ai-dedup are independent; both must be present."""
        from cli.commands.scan_cmds import scan

        option_names = {name for param in scan.params for name in param.opts}
        assert "--ai-triage" in option_names
        assert "--ai-dedup" in option_names
