"""
tests/test_semantic_dedup.py — Unit tests for SemanticDeduplicator.

Coverage:
- deduplicate() with empty list returns []
- deduplicate() with LLM: happy path groups correctly (Req 6.1, 6.2)
- deduplicate() with LLM: every finding appears in exactly one group (Req 6.2)
- deduplicate() with LLM: low-confidence groups (1 member) are rejected (Req 6.3)
- deduplicate() with LLM: original Finding objects are never modified (Req 5.2)
- deduplicate() with LLM: LLM-fabricated IDs are silently dropped
- deduplicate() with LLM: singletons appear as single-member FindingGroups (Req 6.2)
- deduplicate() with LLM: markdown-fenced JSON response is handled
- deduplicate() with LLM: invalid JSON response falls back to deterministic
- deduplicate() with LLM: LLMProviderUnavailableError falls back to deterministic
- deduplicate() without provider: deterministic grouping by (owasp_category, category)
- deduplicate() without provider: findings with None owasp_category are singletons (Req 6.3)
- deduplicate() without provider: unique (owasp_category, category) pairs are singletons
- safe_deduplicate(): returns groups on success
- safe_deduplicate(): returns None and logs on unexpected error

All tests use mocks — NO real API calls are made (Requirement 11.2).
"""

from __future__ import annotations

import copy
import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Ensure core.logging is available before importing utils.
import core.logging  # noqa: F401

from core.config import Severity
from utils.ai.provider_base import LLMProviderUnavailableError, LLMResponseParseError
from utils.ai.semantic_dedup import FindingGroup, SemanticDeduplicator
from utils.findings import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    *,
    id: str = "finding-001",
    category: str = "BOLA_OBJECT_ACCESS",
    owasp_category: str | None = "API1",
    severity: Severity = Severity.HIGH,
    endpoint: str = "/api/v1/users/123",
    method: str = "GET",
    evidence: str = "Unauthorized object access detected",
    recommendation: str = "Implement proper object-level authorization.",
    payload: str | None = None,
) -> Finding:
    """Return a minimal Finding for testing."""
    return Finding(
        id=id,
        scan_id="scan-test-001",
        category=category,
        owasp_category=owasp_category,
        severity=severity,
        endpoint=endpoint,
        method=method,
        status_code=200,
        response_size=1024,
        response_time=0.1,
        evidence=evidence,
        recommendation=recommendation,
        payload=payload,
        timestamp=datetime(2024, 1, 1, 12, 0, 0),
    )


def _make_provider(response_text: str = "") -> MagicMock:
    """Return a mock LLMProvider whose ``complete`` coroutine returns *response_text*."""
    provider = MagicMock()
    provider.provider_name = "mock-provider"
    provider.complete = AsyncMock(return_value=response_text)
    return provider


def _valid_dedup_json(groups: list[dict]) -> str:
    """Build a valid deduplication JSON response."""
    return json.dumps({"groups": groups})


# ---------------------------------------------------------------------------
# Tests: FindingGroup dataclass
# ---------------------------------------------------------------------------


class TestFindingGroup:
    def test_fields_accessible(self) -> None:
        fg = FindingGroup(
            group_id="g-001",
            root_cause_summary="BOLA vulnerability",
            member_finding_ids=["f-001", "f-002"],
        )
        assert fg.group_id == "g-001"
        assert fg.root_cause_summary == "BOLA vulnerability"
        assert fg.member_finding_ids == ["f-001", "f-002"]

    def test_singleton_group_has_one_member(self) -> None:
        fg = FindingGroup(
            group_id="g-002",
            root_cause_summary="Unique finding",
            member_finding_ids=["f-001"],
        )
        assert len(fg.member_finding_ids) == 1


# ---------------------------------------------------------------------------
# Tests: empty input
# ---------------------------------------------------------------------------


class TestDeduplicateEmpty:
    @pytest.mark.asyncio
    async def test_empty_list_returns_empty(self) -> None:
        dedup = SemanticDeduplicator(provider=None)
        result = await dedup.deduplicate([])
        assert result == []

    @pytest.mark.asyncio
    async def test_empty_list_with_provider_returns_empty(self) -> None:
        provider = _make_provider("")
        dedup = SemanticDeduplicator(provider=provider)
        result = await dedup.deduplicate([])
        assert result == []
        # No LLM call should be made for empty input.
        provider.complete.assert_not_called()


# ---------------------------------------------------------------------------
# Tests: LLM-assisted strategy
# ---------------------------------------------------------------------------


class TestDeduplicateLLM:
    @pytest.mark.asyncio
    async def test_happy_path_groups_two_findings(self) -> None:
        """Two findings with the same root cause are grouped by LLM."""
        f1 = _make_finding(id="f-001", category="BOLA_OBJECT_ACCESS")
        f2 = _make_finding(id="f-002", category="BOLA_OBJECT_ACCESS")

        response = _valid_dedup_json([
            {"root_cause_summary": "BOLA on /users endpoint", "member_finding_ids": ["f-001", "f-002"]},
        ])
        provider = _make_provider(response)
        dedup = SemanticDeduplicator(provider=provider)

        groups = await dedup.deduplicate([f1, f2])

        assert len(groups) == 1
        assert set(groups[0].member_finding_ids) == {"f-001", "f-002"}
        assert groups[0].root_cause_summary == "BOLA on /users endpoint"

    @pytest.mark.asyncio
    async def test_every_finding_appears_in_exactly_one_group(self) -> None:
        """Requirement 6.2: no information loss — every finding is in a group."""
        findings = [_make_finding(id=f"f-{i:03d}") for i in range(5)]

        # LLM groups f-000 and f-001; the rest are ungrouped.
        response = _valid_dedup_json([
            {"root_cause_summary": "Shared BOLA", "member_finding_ids": ["f-000", "f-001"]},
        ])
        provider = _make_provider(response)
        dedup = SemanticDeduplicator(provider=provider)

        groups = await dedup.deduplicate(findings)

        all_ids_in_groups = [fid for g in groups for fid in g.member_finding_ids]
        assert sorted(all_ids_in_groups) == sorted(f.id for f in findings)

        # No ID appears in more than one group.
        assert len(all_ids_in_groups) == len(set(all_ids_in_groups))

    @pytest.mark.asyncio
    async def test_single_member_group_rejected_becomes_singleton(self) -> None:
        """Requirement 6.3: groups with only 1 member from LLM are discarded."""
        f1 = _make_finding(id="f-001")
        f2 = _make_finding(id="f-002")

        # LLM returns a "group" with only 1 member — this should be rejected.
        response = _valid_dedup_json([
            {"root_cause_summary": "Only one finding", "member_finding_ids": ["f-001"]},
        ])
        provider = _make_provider(response)
        dedup = SemanticDeduplicator(provider=provider)

        groups = await dedup.deduplicate([f1, f2])

        # Both should be singletons.
        assert len(groups) == 2
        for g in groups:
            assert len(g.member_finding_ids) == 1

    @pytest.mark.asyncio
    async def test_original_findings_not_modified(self) -> None:
        """Requirement 5.2: original Finding objects are never mutated."""
        f1 = _make_finding(id="f-001", evidence="original evidence")
        original_evidence = f1.evidence

        response = _valid_dedup_json([
            {"root_cause_summary": "BOLA group", "member_finding_ids": ["f-001"]},
        ])
        provider = _make_provider(response)
        dedup = SemanticDeduplicator(provider=provider)

        await dedup.deduplicate([f1])

        assert f1.evidence == original_evidence

    @pytest.mark.asyncio
    async def test_fabricated_ids_are_dropped(self) -> None:
        """LLM cannot introduce IDs that do not exist in the input."""
        f1 = _make_finding(id="f-001")
        f2 = _make_finding(id="f-002")

        # LLM includes a fabricated ID "f-999" that doesn't exist.
        response = _valid_dedup_json([
            {"root_cause_summary": "With fake ID", "member_finding_ids": ["f-001", "f-999"]},
        ])
        provider = _make_provider(response)
        dedup = SemanticDeduplicator(provider=provider)

        groups = await dedup.deduplicate([f1, f2])

        # "f-999" is unknown so the group has only 1 valid member → rejected.
        # Both real findings become singletons.
        all_ids = [fid for g in groups for fid in g.member_finding_ids]
        assert "f-999" not in all_ids
        assert set(all_ids) == {"f-001", "f-002"}

    @pytest.mark.asyncio
    async def test_markdown_fenced_json_parsed_correctly(self) -> None:
        """Code-fence markers around JSON are stripped before parsing."""
        f1 = _make_finding(id="f-001")
        f2 = _make_finding(id="f-002")

        inner = _valid_dedup_json([
            {"root_cause_summary": "BOLA group", "member_finding_ids": ["f-001", "f-002"]},
        ])
        fenced = f"```json\n{inner}\n```"

        provider = _make_provider(fenced)
        dedup = SemanticDeduplicator(provider=provider)

        groups = await dedup.deduplicate([f1, f2])

        assert len(groups) == 1
        assert set(groups[0].member_finding_ids) == {"f-001", "f-002"}

    @pytest.mark.asyncio
    async def test_invalid_json_falls_back_to_deterministic(self) -> None:
        """LLMResponseParseError triggers deterministic fallback, not a crash."""
        f1 = _make_finding(id="f-001", category="BOLA", owasp_category="API1")
        f2 = _make_finding(id="f-002", category="BOLA", owasp_category="API1")

        provider = _make_provider("this is not json at all")
        dedup = SemanticDeduplicator(provider=provider)

        groups = await dedup.deduplicate([f1, f2])

        # Deterministic fallback groups by (owasp_category, category) match.
        all_ids = [fid for g in groups for fid in g.member_finding_ids]
        assert set(all_ids) == {"f-001", "f-002"}

    @pytest.mark.asyncio
    async def test_provider_unavailable_falls_back_to_deterministic(self) -> None:
        """LLMProviderUnavailableError triggers deterministic fallback."""
        f1 = _make_finding(id="f-001", category="SSRF", owasp_category="API7")
        f2 = _make_finding(id="f-002", category="SSRF", owasp_category="API7")

        provider = MagicMock()
        provider.provider_name = "mock-provider"
        provider.complete = AsyncMock(
            side_effect=LLMProviderUnavailableError("Connection refused")
        )
        dedup = SemanticDeduplicator(provider=provider)

        groups = await dedup.deduplicate([f1, f2])

        # Deterministic fallback should group them (same owasp + category).
        assert len(groups) == 1
        assert set(groups[0].member_finding_ids) == {"f-001", "f-002"}

    @pytest.mark.asyncio
    async def test_llm_called_with_redacted_data(self) -> None:
        """Secrets in evidence must be redacted before the LLM call (Req 5.5)."""
        f1 = _make_finding(id="f-001", evidence="token=supersecret123")

        response = _valid_dedup_json([])
        provider = _make_provider(response)
        dedup = SemanticDeduplicator(provider=provider)

        with patch("utils.ai.semantic_dedup._redact", wraps=lambda t: "[REDACTED]") as mock_redact:
            await dedup.deduplicate([f1])

        # _redact was called, meaning redaction happened before the prompt was sent.
        mock_redact.assert_called()
        # The prompt passed to the LLM must not contain the raw secret.
        call_args = provider.complete.call_args
        prompt_sent = call_args[0][0]
        assert "supersecret123" not in prompt_sent


# ---------------------------------------------------------------------------
# Tests: deterministic fallback strategy
# ---------------------------------------------------------------------------


class TestDeduplicateDeterministic:
    @pytest.mark.asyncio
    async def test_groups_by_owasp_and_category(self) -> None:
        """Findings with identical (owasp_category, category) are grouped."""
        f1 = _make_finding(id="f-001", category="BOLA", owasp_category="API1")
        f2 = _make_finding(id="f-002", category="BOLA", owasp_category="API1")
        f3 = _make_finding(id="f-003", category="SSRF", owasp_category="API7")

        dedup = SemanticDeduplicator(provider=None)
        groups = await dedup.deduplicate([f1, f2, f3])

        # f1 and f2 should be in one group; f3 is a singleton.
        assert len(groups) == 2

        bola_group = next(g for g in groups if len(g.member_finding_ids) == 2)
        assert set(bola_group.member_finding_ids) == {"f-001", "f-002"}

        singleton = next(g for g in groups if len(g.member_finding_ids) == 1)
        assert singleton.member_finding_ids == ["f-003"]

    @pytest.mark.asyncio
    async def test_none_owasp_category_yields_singleton(self) -> None:
        """Requirement 6.3: findings with None owasp_category stay as singletons."""
        f1 = _make_finding(id="f-001", category="CUSTOM_CHECK", owasp_category=None)
        f2 = _make_finding(id="f-002", category="CUSTOM_CHECK", owasp_category=None)

        dedup = SemanticDeduplicator(provider=None)
        groups = await dedup.deduplicate([f1, f2])

        # Neither finding has an owasp_category — both should be singletons.
        assert len(groups) == 2
        for g in groups:
            assert len(g.member_finding_ids) == 1

    @pytest.mark.asyncio
    async def test_unique_category_pair_is_singleton(self) -> None:
        """A finding with a unique (owasp, category) pair stays as a singleton."""
        f1 = _make_finding(id="f-001", category="BOLA", owasp_category="API1")
        f2 = _make_finding(id="f-002", category="SSRF", owasp_category="API7")
        f3 = _make_finding(id="f-003", category="MASS_ASSIGN", owasp_category="API6")

        dedup = SemanticDeduplicator(provider=None)
        groups = await dedup.deduplicate([f1, f2, f3])

        assert len(groups) == 3
        for g in groups:
            assert len(g.member_finding_ids) == 1

    @pytest.mark.asyncio
    async def test_all_ids_present_no_loss(self) -> None:
        """Requirement 6.2: all findings are present in the output."""
        findings = [
            _make_finding(id=f"f-{i:03d}", category=f"CAT_{i % 2}", owasp_category=f"API{i % 3 + 1}")
            for i in range(6)
        ]

        dedup = SemanticDeduplicator(provider=None)
        groups = await dedup.deduplicate(findings)

        all_ids = [fid for g in groups for fid in g.member_finding_ids]
        assert sorted(all_ids) == sorted(f.id for f in findings)

    @pytest.mark.asyncio
    async def test_different_category_same_owasp_not_grouped(self) -> None:
        """Different vulnerability categories under the same OWASP category are NOT grouped."""
        f1 = _make_finding(id="f-001", category="BOLA", owasp_category="API1")
        f2 = _make_finding(id="f-002", category="BOLA_WRITE", owasp_category="API1")

        dedup = SemanticDeduplicator(provider=None)
        groups = await dedup.deduplicate([f1, f2])

        # Both categories differ → two singletons (Requirement 6.3: prefer no grouping).
        assert len(groups) == 2
        for g in groups:
            assert len(g.member_finding_ids) == 1

    @pytest.mark.asyncio
    async def test_original_findings_not_modified_deterministic(self) -> None:
        """Requirement 5.2: original findings are not mutated by deterministic path."""
        f1 = _make_finding(id="f-001", evidence="original evidence", owasp_category="API1")
        f2 = _make_finding(id="f-002", evidence="another evidence", owasp_category="API1")

        snapshot_f1 = copy.deepcopy(f1)
        snapshot_f2 = copy.deepcopy(f2)

        dedup = SemanticDeduplicator(provider=None)
        await dedup.deduplicate([f1, f2])

        assert f1.evidence == snapshot_f1.evidence
        assert f2.evidence == snapshot_f2.evidence
        assert f1.category == snapshot_f1.category
        assert f2.category == snapshot_f2.category


# ---------------------------------------------------------------------------
# Tests: safe_deduplicate wrapper
# ---------------------------------------------------------------------------


class TestSafeDeduplicate:
    @pytest.mark.asyncio
    async def test_returns_groups_on_success(self) -> None:
        f1 = _make_finding(id="f-001")
        dedup = SemanticDeduplicator(provider=None)
        result = await dedup.safe_deduplicate([f1])
        assert result is not None
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_returns_none_on_unexpected_error(self) -> None:
        """If deduplicate raises unexpectedly, safe_deduplicate returns None."""
        f1 = _make_finding(id="f-001")
        dedup = SemanticDeduplicator(provider=None)

        with patch.object(dedup, "deduplicate", side_effect=RuntimeError("boom")):
            result = await dedup.safe_deduplicate([f1])

        assert result is None

    @pytest.mark.asyncio
    async def test_empty_input_returns_empty_list(self) -> None:
        dedup = SemanticDeduplicator(provider=None)
        result = await dedup.safe_deduplicate([])
        assert result == []


# ---------------------------------------------------------------------------
# Tests: group_id uniqueness
# ---------------------------------------------------------------------------


class TestGroupIdUniqueness:
    @pytest.mark.asyncio
    async def test_all_group_ids_are_unique(self) -> None:
        """Every returned FindingGroup must have a unique group_id."""
        findings = [_make_finding(id=f"f-{i:03d}", owasp_category=f"API{i + 1}") for i in range(5)]
        dedup = SemanticDeduplicator(provider=None)
        groups = await dedup.deduplicate(findings)
        group_ids = [g.group_id for g in groups]
        assert len(group_ids) == len(set(group_ids))
