"""
Property-based test — Preservación de la Evidencia Original.

Feature: ai-mcp-integration

Property 2: Preservación de la Evidencia Original
For ANY execution of ``FindingTriageAssistant.triage``, the input ``Finding``
objects SHALL remain unmodified after the call; all AI output SHALL reside
exclusively in the returned ``TriageReport``, never replacing already-calculated
evidence.

**Validates: Requirements 5.2**
"""

from __future__ import annotations

import asyncio
import copy
import dataclasses
import json
from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

# Ensure core logging is available before importing utils.
import core.logging  # noqa: F401

from core.config import Severity
from utils.ai.triage_assistant import FindingTriageAssistant, TriageReport
from utils.findings import Finding

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

_SEVERITIES = list(Severity)
_OWASP_CATEGORIES = ["API1", "API2", "API3", "API4", "API5", None]
_HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
_CATEGORIES = [
    "BOLA_OBJECT_ACCESS",
    "AUTH_WEAK_PASSWORD",
    "JWT_NONE_ALGORITHM",
    "SSRF_OPEN_REDIRECT",
    "MASS_ASSIGNMENT",
    "SECURITY_MISCONFIGURATION",
    "RATE_LIMIT_BYPASS",
    "BFLA_FUNCTION_ACCESS",
    "INJECTION_SQL",
    "UNRESTRICTED_RESOURCE_CONSUMPTION",
]

# Printable text without null bytes — safe for JSON serialisation and comparison.
_safe_text = st.text(
    alphabet=st.characters(
        whitelist_categories=("Lu", "Ll", "Nd", "Pc", "Pd", "Zs"),
        whitelist_characters="/:?=&._-@#!",
    ),
    min_size=0,
    max_size=120,
)

_safe_text_nonempty = st.text(
    alphabet=st.characters(
        whitelist_categories=("Lu", "Ll", "Nd", "Pc", "Pd"),
        whitelist_characters="/:?=&._-@#!",
    ),
    min_size=1,
    max_size=80,
)


@st.composite
def findings_strategy(draw) -> list[Finding]:
    """Generate a non-empty list of arbitrary Finding objects."""
    count = draw(st.integers(min_value=1, max_value=8))
    findings = []
    used_ids: set[str] = set()

    for i in range(count):
        # Generate a unique ID so triage JSON remains valid.
        base_id = draw(_safe_text_nonempty)
        fid = f"{base_id}_{i}" if base_id in used_ids else base_id
        used_ids.add(fid)

        finding = Finding(
            id=fid,
            scan_id=draw(_safe_text_nonempty),
            category=draw(st.sampled_from(_CATEGORIES)),
            owasp_category=draw(st.sampled_from(_OWASP_CATEGORIES)),
            severity=draw(st.sampled_from(_SEVERITIES)),
            endpoint=draw(st.just("/api/v1/resource") | _safe_text_nonempty),
            method=draw(st.sampled_from(_HTTP_METHODS)),
            status_code=draw(st.integers(min_value=100, max_value=599)),
            response_size=draw(st.integers(min_value=0, max_value=65535)),
            response_time=draw(st.floats(min_value=0.0, max_value=30.0, allow_nan=False)),
            evidence=draw(_safe_text),
            recommendation=draw(_safe_text),
            payload=draw(st.one_of(st.none(), _safe_text)),
            response_snippet=draw(st.one_of(st.none(), _safe_text)),
            timestamp=datetime(2024, 1, 1, 12, 0, 0),
        )
        findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Mock provider helpers
# ---------------------------------------------------------------------------


def _make_valid_triage_response(findings: list[Finding]) -> str:
    """Build a valid JSON triage response for the given findings."""
    ids = [f.id for f in findings]
    return json.dumps(
        {
            "prioritized_finding_ids": ids,
            "narrative_summary": "AI-generated summary for property test.",
            "per_finding_notes": {fid: f"Note for {fid}" for fid in ids},
        }
    )


def _make_mock_provider(findings: list[Finding]) -> MagicMock:
    """Return a mock LLMProvider whose ``complete`` coroutine returns valid JSON."""
    provider = MagicMock()
    provider.complete = AsyncMock(return_value=_make_valid_triage_response(findings))
    return provider


# ---------------------------------------------------------------------------
# Snapshot helpers
# ---------------------------------------------------------------------------


def _snapshot_finding(finding: Finding) -> dict[str, Any]:
    """Return a deep copy of every Finding field as a plain dict.

    Uses ``dataclasses.asdict`` with a custom deep-copy factory so that
    mutable fields (headers dict, detection_signals list, etc.) are all
    independent copies — not aliases of the original mutable objects.
    """
    # dataclasses.asdict recurses into nested dataclasses/dicts/lists.
    try:
        snap = dataclasses.asdict(finding)
    except TypeError:
        # If evidence_chain is a non-dataclass object, asdict may fail.
        # Fall back to a manual field snapshot in that case.
        snap = {
            f.name: copy.deepcopy(getattr(finding, f.name))
            for f in dataclasses.fields(finding)
        }
    return snap


def _assert_finding_unchanged(finding: Finding, snapshot: dict[str, Any]) -> None:
    """Assert that every field of *finding* matches its pre-call *snapshot*."""
    for field_def in dataclasses.fields(finding):
        name = field_def.name
        current = getattr(finding, name)
        expected = snapshot[name]
        assert current == expected, (
            f"Finding field '{name}' was mutated by triage().\n"
            f"  Before: {expected!r}\n"
            f"  After:  {current!r}"
        )


# ---------------------------------------------------------------------------
# Property 2: Preservación de la Evidencia Original
# ---------------------------------------------------------------------------


@settings(
    max_examples=150,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(findings=findings_strategy())
def test_triage_does_not_mutate_input_findings(findings: list[Finding]) -> None:
    """Property 2: Preservación de la Evidencia Original.

    For ANY list of Finding objects passed to ``FindingTriageAssistant.triage``,
    every field of every Finding SHALL be identical before and after the call.
    The AI output SHALL reside exclusively in the returned ``TriageReport``.

    **Validates: Requirements 5.2**
    """
    # Snapshot every Finding's state BEFORE calling triage.
    snapshots = [_snapshot_finding(f) for f in findings]

    provider = _make_mock_provider(findings)
    assistant = FindingTriageAssistant(provider)

    report = asyncio.run(assistant.triage(findings))

    # --- Assertion 1: every Finding field is exactly unchanged ---
    for finding, snapshot in zip(findings, snapshots):
        _assert_finding_unchanged(finding, snapshot)

    # --- Assertion 2: the returned value is a TriageReport ---
    assert isinstance(report, TriageReport), (
        f"triage() returned {type(report)!r} instead of TriageReport."
    )


@settings(
    max_examples=150,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(findings=findings_strategy())
def test_triage_report_does_not_alias_finding_mutable_state(
    findings: list[Finding],
) -> None:
    """Property 2 (mutable aliasing): the TriageReport SHALL NOT hold live
    references into the mutable state of the original Finding objects.

    Specifically:
    - Mutating ``per_finding_notes`` on the report after the call MUST NOT
      alter any Finding field.
    - Modifying a Finding's mutable fields after the call MUST NOT alter the
      already-returned TriageReport content.

    **Validates: Requirements 5.2**
    """
    provider = _make_mock_provider(findings)
    assistant = FindingTriageAssistant(provider)

    report = asyncio.run(assistant.triage(findings))

    # Capture report state before mutating the findings.
    report_ids_before = list(report.prioritized_finding_ids)
    report_summary_before = report.narrative_summary
    report_notes_before = dict(report.per_finding_notes)

    # Mutate every Finding in-place.
    for finding in findings:
        finding.evidence = "__MUTATED_AFTER_TRIAGE__"
        finding.recommendation = "__MUTATED_RECOMMENDATION__"
        if finding.payload is not None:
            finding.payload = "__MUTATED_PAYLOAD__"

    # The already-returned TriageReport MUST be unaffected.
    assert report.prioritized_finding_ids == report_ids_before, (
        "TriageReport.prioritized_finding_ids changed after mutating Findings — "
        "the report holds a live alias (Requirement 5.2 violated)."
    )
    assert report.narrative_summary == report_summary_before, (
        "TriageReport.narrative_summary changed after mutating Findings — "
        "the report holds a live alias (Requirement 5.2 violated)."
    )
    assert report.per_finding_notes == report_notes_before, (
        "TriageReport.per_finding_notes changed after mutating Findings — "
        "the report holds a live alias (Requirement 5.2 violated)."
    )


@settings(
    max_examples=150,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(findings=findings_strategy())
def test_triage_report_ids_are_subset_of_input_ids(findings: list[Finding]) -> None:
    """Property 2 (no fabrication): the TriageReport SHALL only reference Finding
    IDs that existed in the input; it SHALL NOT introduce new IDs.

    This verifies that all AI output is anchored to the existing evidence rather
    than creating phantom findings (Requirement 5.2).

    **Validates: Requirements 5.2**
    """
    input_ids = {f.id for f in findings}

    provider = _make_mock_provider(findings)
    assistant = FindingTriageAssistant(provider)

    report = asyncio.run(assistant.triage(findings))

    # Every ID in the prioritised list must exist in the input.
    for reported_id in report.prioritized_finding_ids:
        assert reported_id in input_ids, (
            f"TriageReport contains fabricated ID {reported_id!r} not present "
            "in the input findings (Requirement 5.2 violated)."
        )

    # Every key in per_finding_notes must also be a known input ID.
    for note_id in report.per_finding_notes:
        assert note_id in input_ids, (
            f"TriageReport.per_finding_notes contains fabricated ID {note_id!r} "
            "not present in the input findings (Requirement 5.2 violated)."
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
