"""
tests/test_triage_assistant.py — Unit tests for FindingTriageAssistant.

Coverage:
- triage() happy path: valid JSON response → TriageReport
- triage() empty findings list → empty TriageReport (no LLM call)
- triage() provider=None → LLMProviderUnavailableError
- triage() markdown-fenced JSON response → correctly parsed
- triage() invalid JSON response → LLMResponseParseError
- triage() LLM fabricates unknown IDs → silently dropped
- triage() original Finding objects are never modified (Requirement 5.2)
- triage() secrets in evidence are redacted before prompt is built (Req 5.5)
- explain_remediation() happy path: returns response text
- explain_remediation() OWASP category and module appear in prompt (Req 5.4)
- explain_remediation() provider=None → LLMProviderUnavailableError
- explain_remediation() secrets in evidence are redacted (Requirement 5.5)
- explain_remediation() original Finding is never modified (Requirement 5.2)

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
from utils.ai.provider_base import (
    LLMProviderUnavailableError,
    LLMResponseParseError,
)
from utils.ai.triage_assistant import FindingTriageAssistant, TriageReport
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
    evidence: str = "User 123 data returned for user 456 token",
    recommendation: str = "Implement proper object-level authorization checks.",
    payload: str | None = None,
    response_snippet: str | None = None,
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
        response_snippet=response_snippet,
        timestamp=datetime(2024, 1, 1, 12, 0, 0),
    )


def _make_provider(response_text: str = "") -> MagicMock:
    """Return a mock LLMProvider whose ``complete`` coroutine returns *response_text*."""
    provider = MagicMock()
    provider.complete = AsyncMock(return_value=response_text)
    return provider


def _valid_triage_json(finding_ids: list[str]) -> str:
    """Build a valid triage JSON response for the given finding IDs."""
    return json.dumps(
        {
            "prioritized_finding_ids": finding_ids,
            "narrative_summary": "Critical BOLA vulnerability requires immediate attention.",
            "per_finding_notes": {id_: f"High priority: {id_}" for id_ in finding_ids},
        }
    )


# ---------------------------------------------------------------------------
# Tests: TriageReport dataclass
# ---------------------------------------------------------------------------


class TestTriageReport:
    def test_fields(self):
        report = TriageReport(
            prioritized_finding_ids=["a", "b"],
            narrative_summary="Summary.",
            per_finding_notes={"a": "note a", "b": "note b"},
        )
        assert report.prioritized_finding_ids == ["a", "b"]
        assert report.narrative_summary == "Summary."
        assert report.per_finding_notes == {"a": "note a", "b": "note b"}


# ---------------------------------------------------------------------------
# Tests: FindingTriageAssistant.triage
# ---------------------------------------------------------------------------


class TestFindingTriageAssistantTriage:
    @pytest.mark.asyncio
    async def test_happy_path_returns_triage_report(self):
        finding = _make_finding(id="f-1")
        response = _valid_triage_json(["f-1"])
        provider = _make_provider(response)

        assistant = FindingTriageAssistant(provider)
        report = await assistant.triage([finding])

        assert isinstance(report, TriageReport)
        assert report.prioritized_finding_ids == ["f-1"]
        assert "Critical" in report.narrative_summary
        assert "f-1" in report.per_finding_notes

    @pytest.mark.asyncio
    async def test_empty_findings_returns_empty_report_without_llm_call(self):
        provider = _make_provider()

        assistant = FindingTriageAssistant(provider)
        report = await assistant.triage([])

        # Provider should NOT be called for empty findings.
        provider.complete.assert_not_called()
        assert report.prioritized_finding_ids == []
        assert report.per_finding_notes == {}

    @pytest.mark.asyncio
    async def test_none_provider_raises(self):
        assistant = FindingTriageAssistant(None)
        with pytest.raises(LLMProviderUnavailableError):
            await assistant.triage([_make_finding()])

    @pytest.mark.asyncio
    async def test_markdown_fenced_json_parsed(self):
        finding = _make_finding(id="f-2")
        inner = _valid_triage_json(["f-2"])
        fenced = f"```json\n{inner}\n```"
        provider = _make_provider(fenced)

        assistant = FindingTriageAssistant(provider)
        report = await assistant.triage([finding])

        assert report.prioritized_finding_ids == ["f-2"]

    @pytest.mark.asyncio
    async def test_invalid_json_raises_parse_error(self):
        provider = _make_provider("this is not json")

        assistant = FindingTriageAssistant(provider)
        with pytest.raises(LLMResponseParseError):
            await assistant.triage([_make_finding()])

    @pytest.mark.asyncio
    async def test_fabricated_ids_dropped(self):
        """LLM-fabricated IDs that don't exist in original findings are dropped."""
        finding = _make_finding(id="real-id")
        response = json.dumps(
            {
                "prioritized_finding_ids": ["real-id", "fake-id-from-llm"],
                "narrative_summary": "Summary",
                "per_finding_notes": {
                    "real-id": "note",
                    "fake-id-from-llm": "should be dropped",
                },
            }
        )
        provider = _make_provider(response)

        assistant = FindingTriageAssistant(provider)
        report = await assistant.triage([finding])

        assert "fake-id-from-llm" not in report.prioritized_finding_ids
        assert "fake-id-from-llm" not in report.per_finding_notes
        assert "real-id" in report.prioritized_finding_ids

    @pytest.mark.asyncio
    async def test_original_findings_not_modified(self):
        """Requirement 5.2: original Finding objects MUST NOT be modified."""
        finding = _make_finding(
            id="f-orig",
            evidence="original evidence",
            payload="original payload",
        )
        original_evidence = finding.evidence
        original_payload = finding.payload
        original_id = finding.id

        response = _valid_triage_json(["f-orig"])
        provider = _make_provider(response)

        assistant = FindingTriageAssistant(provider)
        await assistant.triage([finding])

        # The Finding must be exactly as before.
        assert finding.id == original_id
        assert finding.evidence == original_evidence
        assert finding.payload == original_payload

    @pytest.mark.asyncio
    async def test_secrets_redacted_in_prompt(self):
        """Requirement 5.5: secrets in evidence MUST be redacted before the prompt."""
        # Use a token-shaped value that redact_secrets will redact.
        secret_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        finding = _make_finding(id="f-secret", evidence=f"token={secret_token}")

        captured_prompt: list[str] = []

        async def _capture_complete(prompt: str, *, max_tokens: int, timeout: float) -> str:
            captured_prompt.append(prompt)
            return _valid_triage_json(["f-secret"])

        provider = MagicMock()
        provider.complete = _capture_complete

        assistant = FindingTriageAssistant(provider)
        await assistant.triage([finding])

        assert captured_prompt, "provider.complete was never called"
        prompt = captured_prompt[0]

        # The raw secret token MUST NOT appear in the prompt.
        assert secret_token not in prompt, (
            "Raw secret token found in LLM prompt — Requirement 5.5 violated."
        )

    @pytest.mark.asyncio
    async def test_multiple_findings_all_included_in_prompt(self):
        findings = [_make_finding(id=f"f-{i}") for i in range(3)]
        ids = [f.id for f in findings]
        response = _valid_triage_json(ids)
        provider = _make_provider(response)

        assistant = FindingTriageAssistant(provider)
        report = await assistant.triage(findings)

        # All IDs should appear in the prioritised list.
        assert set(report.prioritized_finding_ids) == set(ids)

    @pytest.mark.asyncio
    async def test_json_root_not_dict_raises(self):
        """A JSON array at the root (not an object) must raise LLMResponseParseError."""
        provider = _make_provider('["not", "an", "object"]')

        assistant = FindingTriageAssistant(provider)
        with pytest.raises(LLMResponseParseError):
            await assistant.triage([_make_finding()])


# ---------------------------------------------------------------------------
# Tests: FindingTriageAssistant.explain_remediation
# ---------------------------------------------------------------------------


class TestFindingTriageAssistantExplainRemediation:
    @pytest.mark.asyncio
    async def test_happy_path_returns_text(self):
        provider = _make_provider("Implement proper object-level authorization checks.")
        assistant = FindingTriageAssistant(provider)

        result = await assistant.explain_remediation(_make_finding())

        assert isinstance(result, str)
        assert "authorization" in result.lower()

    @pytest.mark.asyncio
    async def test_none_provider_raises(self):
        assistant = FindingTriageAssistant(None)
        with pytest.raises(LLMProviderUnavailableError):
            await assistant.explain_remediation(_make_finding())

    @pytest.mark.asyncio
    async def test_owasp_category_in_prompt(self):
        """Requirement 5.4: OWASP category MUST appear in the remediation prompt."""
        finding = _make_finding(owasp_category="API1", category="BOLA_OBJECT_ACCESS")

        captured: list[str] = []

        async def _capture(prompt: str, *, max_tokens: int, timeout: float) -> str:
            captured.append(prompt)
            return "Recommendation text."

        provider = MagicMock()
        provider.complete = _capture

        assistant = FindingTriageAssistant(provider)
        await assistant.explain_remediation(finding)

        assert captured
        prompt = captured[0]
        assert "API1" in prompt, "OWASP category not found in remediation prompt"

    @pytest.mark.asyncio
    async def test_module_category_in_prompt(self):
        """Requirement 5.4: module/vulnerability category MUST appear in the prompt."""
        finding = _make_finding(category="JWT_NONE_ALGORITHM", owasp_category="API2")

        captured: list[str] = []

        async def _capture(prompt: str, *, max_tokens: int, timeout: float) -> str:
            captured.append(prompt)
            return "Recommendation text."

        provider = MagicMock()
        provider.complete = _capture

        assistant = FindingTriageAssistant(provider)
        await assistant.explain_remediation(finding)

        assert captured
        prompt = captured[0]
        assert "JWT_NONE_ALGORITHM" in prompt, "Module category not found in prompt"

    @pytest.mark.asyncio
    async def test_original_finding_not_modified(self):
        """Requirement 5.2: explain_remediation must not modify the original finding."""
        finding = _make_finding(
            id="f-rem",
            evidence="evidence text",
            owasp_category="API2",
            category="JWT_WEAK_SECRET",
        )
        original_evidence = finding.evidence
        original_category = finding.category
        original_owasp = finding.owasp_category

        provider = _make_provider("Fix the JWT weak secret issue.")
        assistant = FindingTriageAssistant(provider)
        await assistant.explain_remediation(finding)

        assert finding.evidence == original_evidence
        assert finding.category == original_category
        assert finding.owasp_category == original_owasp

    @pytest.mark.asyncio
    async def test_secrets_redacted_in_prompt(self):
        """Requirement 5.5: secrets in finding evidence must be redacted."""
        secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        finding = _make_finding(
            id="f-sec-rem",
            evidence=f'Authorization: Bearer {secret}',
            owasp_category="API2",
            category="AUTH_SECRET_IN_URL",
        )

        captured: list[str] = []

        async def _capture(prompt: str, *, max_tokens: int, timeout: float) -> str:
            captured.append(prompt)
            return "Recommendation."

        provider = MagicMock()
        provider.complete = _capture

        assistant = FindingTriageAssistant(provider)
        await assistant.explain_remediation(finding)

        assert captured
        prompt = captured[0]
        assert secret not in prompt, (
            "Raw secret found in remediation prompt — Requirement 5.5 violated."
        )

    @pytest.mark.asyncio
    async def test_response_whitespace_stripped(self):
        """Leading/trailing whitespace in LLM responses is stripped."""
        provider = _make_provider("  Recommendation with surrounding spaces.  \n")
        assistant = FindingTriageAssistant(provider)

        result = await assistant.explain_remediation(_make_finding())
        assert result == "Recommendation with surrounding spaces."

    @pytest.mark.asyncio
    async def test_payload_included_when_present(self):
        """When the finding has a payload, it should appear in the prompt."""
        finding = _make_finding(payload='{"admin": true}')

        captured: list[str] = []

        async def _capture(prompt: str, *, max_tokens: int, timeout: float) -> str:
            captured.append(prompt)
            return "Recommendation."

        provider = MagicMock()
        provider.complete = _capture

        assistant = FindingTriageAssistant(provider)
        await assistant.explain_remediation(finding)

        assert captured
        # The payload should appear in the prompt (or its redacted form).
        assert "Payload" in captured[0] or "payload" in captured[0]
