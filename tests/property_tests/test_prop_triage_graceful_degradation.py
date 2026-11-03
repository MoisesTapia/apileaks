"""
Property-based test — Degradación Elegante sin Proveedor de IA.

Feature: ai-mcp-integration

Property 4: Degradación Elegante sin Proveedor de IA
For ANY execution of ``--ai-triage``/``--ai-dedup`` without a configured
LLMProvider OR with the provider unavailable, the scan SHALL complete
successfully without the AI section, without throwing an unhandled exception.

Three degradation cases are verified:

4a — ``provider=None``:
    ``safe_triage()`` and ``safe_explain_remediation()`` SHALL return ``None``
    (never raise) when no provider is configured (Requirement 7.2).

4b — Provider raises ``LLMProviderUnavailableError``:
    Both safe wrappers SHALL catch the error and return ``None``
    (Requirements 5.3, 10.1).

4c — Provider raises ``LLMResponseParseError``:
    Both safe wrappers SHALL catch the error and return ``None``
    (Requirement 10.2).

For all three cases:
    - The original Finding objects SHALL remain unmodified.
    - No exception SHALL propagate to the caller.

Note on empty findings: ``triage()`` short-circuits for an empty list and
returns a valid empty ``TriageReport`` before calling the provider.  Tests 4b
and 4c therefore use ``nonempty_findings_strategy`` so the provider is always
invoked and the degradation path is exercised.  Test 4a (provider=None) uses
the general ``findings_strategy`` because the ``None``-provider check fires
before the empty-list check.

**Validates: Requirements 5.3, 7.2, 10.1, 10.2**
"""

from __future__ import annotations

import asyncio
import copy
import dataclasses
from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

# Ensure core logging is available before importing utils.
import core.logging  # noqa: F401

from core.config import Severity
from utils.ai.provider_base import LLMProviderUnavailableError, LLMResponseParseError
from utils.ai.triage_assistant import FindingTriageAssistant, TriageReport
from utils.findings import Finding

# ---------------------------------------------------------------------------
# Strategies — reused from existing property test conventions
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


def _build_finding_list(draw, count: int) -> list[Finding]:
    """Shared helper that builds *count* arbitrary Finding objects."""
    findings = []
    used_ids: set[str] = set()

    for i in range(count):
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


@st.composite
def findings_strategy(draw) -> list[Finding]:
    """Generate an arbitrary list (0 or more) of Finding objects."""
    count = draw(st.integers(min_value=0, max_value=8))
    return _build_finding_list(draw, count)


@st.composite
def nonempty_findings_strategy(draw) -> list[Finding]:
    """Generate a non-empty list of Finding objects (at least 1).

    Used for tests 4b and 4c where the provider must actually be invoked
    (``triage()`` short-circuits for an empty list before calling the provider).
    """
    count = draw(st.integers(min_value=1, max_value=8))
    return _build_finding_list(draw, count)


@st.composite
def single_finding_strategy(draw) -> Finding:
    """Generate a single arbitrary Finding object."""
    return _build_finding_list(draw, 1)[0]


# ---------------------------------------------------------------------------
# Snapshot helpers — identical to those in test_prop_triage_evidence_preservation
# ---------------------------------------------------------------------------


def _snapshot_finding(finding: Finding) -> dict[str, Any]:
    """Return a deep-copy snapshot of every field of *finding* as a plain dict."""
    try:
        return dataclasses.asdict(finding)
    except TypeError:
        return {
            f.name: copy.deepcopy(getattr(finding, f.name))
            for f in dataclasses.fields(finding)
        }


def _assert_finding_unchanged(finding: Finding, snapshot: dict[str, Any]) -> None:
    """Assert that every field of *finding* matches its pre-call *snapshot*."""
    for field_def in dataclasses.fields(finding):
        name = field_def.name
        current = getattr(finding, name)
        expected = snapshot[name]
        assert current == expected, (
            f"Finding field '{name}' was mutated during degradation.\n"
            f"  Before: {expected!r}\n"
            f"  After:  {current!r}"
        )


# ---------------------------------------------------------------------------
# Mock provider helpers
# ---------------------------------------------------------------------------


def _make_unavailable_provider() -> MagicMock:
    """Provider whose ``complete`` coroutine raises LLMProviderUnavailableError."""
    provider = MagicMock()
    provider.provider_name = "mock-unavailable"
    provider.complete = AsyncMock(
        side_effect=LLMProviderUnavailableError("Provider unreachable (test stub)")
    )
    return provider


def _make_parse_error_provider() -> MagicMock:
    """Provider whose ``complete`` coroutine raises LLMResponseParseError."""
    provider = MagicMock()
    provider.provider_name = "mock-parse-error"
    provider.complete = AsyncMock(
        side_effect=LLMResponseParseError("Unparseable response (test stub)")
    )
    return provider


# ---------------------------------------------------------------------------
# Property 4a — safe_triage: provider=None → returns None (Requirement 7.2)
# ---------------------------------------------------------------------------


@settings(
    max_examples=100,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(findings=findings_strategy())
def test_safe_triage_returns_none_when_no_provider(findings: list[Finding]) -> None:
    """Property 4a: safe_triage() with provider=None SHALL return None, not raise.

    Verifies that when no LLM provider is configured, the scan can continue
    without an AI section and without an unhandled exception.  The provider=None
    check fires before the empty-list short-circuit, so this test covers all
    list sizes including empty.

    **Validates: Requirements 5.3, 7.2**
    """
    snapshots = [_snapshot_finding(f) for f in findings]
    assistant = FindingTriageAssistant(provider=None)

    result = asyncio.run(assistant.safe_triage(findings))

    # Core property: must return None, not raise.
    assert result is None, (
        f"safe_triage(provider=None) returned {result!r}; expected None "
        "(Requirement 7.2 violated — AI layer must degrade gracefully)."
    )

    # Original findings must be unmodified.
    for finding, snapshot in zip(findings, snapshots):
        _assert_finding_unchanged(finding, snapshot)


# ---------------------------------------------------------------------------
# Property 4b — safe_triage: provider raises LLMProviderUnavailableError → None
# ---------------------------------------------------------------------------


@settings(
    max_examples=100,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(findings=nonempty_findings_strategy())
def test_safe_triage_returns_none_on_provider_unavailable(findings: list[Finding]) -> None:
    """Property 4b: safe_triage() SHALL return None when the provider is unreachable.

    Uses non-empty findings so the provider is actually called and its error
    triggers the degradation path.  Verifies that a runtime availability
    failure is caught and the scan completes without an unhandled exception.

    **Validates: Requirements 5.3, 10.1**
    """
    snapshots = [_snapshot_finding(f) for f in findings]
    assistant = FindingTriageAssistant(provider=_make_unavailable_provider())

    result = asyncio.run(assistant.safe_triage(findings))

    assert result is None, (
        f"safe_triage() returned {result!r} when provider raised "
        "LLMProviderUnavailableError; expected None "
        "(Requirements 5.3, 10.1 violated)."
    )

    for finding, snapshot in zip(findings, snapshots):
        _assert_finding_unchanged(finding, snapshot)


# ---------------------------------------------------------------------------
# Property 4c — safe_triage: provider raises LLMResponseParseError → None
# ---------------------------------------------------------------------------


@settings(
    max_examples=100,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(findings=nonempty_findings_strategy())
def test_safe_triage_returns_none_on_parse_error(findings: list[Finding]) -> None:
    """Property 4c: safe_triage() SHALL return None when the LLM returns an
    unparseable response.

    Uses non-empty findings so the provider is actually called and its parse
    error triggers the degradation path.

    **Validates: Requirement 10.2**
    """
    snapshots = [_snapshot_finding(f) for f in findings]
    assistant = FindingTriageAssistant(provider=_make_parse_error_provider())

    result = asyncio.run(assistant.safe_triage(findings))

    assert result is None, (
        f"safe_triage() returned {result!r} when provider raised "
        "LLMResponseParseError; expected None "
        "(Requirement 10.2 violated)."
    )

    for finding, snapshot in zip(findings, snapshots):
        _assert_finding_unchanged(finding, snapshot)


# ---------------------------------------------------------------------------
# Property 4a — safe_explain_remediation: provider=None → None (Req 7.2)
# ---------------------------------------------------------------------------


@settings(
    max_examples=100,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(finding=single_finding_strategy())
def test_safe_explain_remediation_returns_none_when_no_provider(finding: Finding) -> None:
    """Property 4a (remediation): safe_explain_remediation() with provider=None
    SHALL return None, not raise.

    **Validates: Requirements 5.3, 7.2**
    """
    snapshot = _snapshot_finding(finding)
    assistant = FindingTriageAssistant(provider=None)

    result = asyncio.run(assistant.safe_explain_remediation(finding))

    assert result is None, (
        f"safe_explain_remediation(provider=None) returned {result!r}; expected None "
        "(Requirement 7.2 violated)."
    )

    _assert_finding_unchanged(finding, snapshot)


# ---------------------------------------------------------------------------
# Property 4b — safe_explain_remediation: LLMProviderUnavailableError → None
# ---------------------------------------------------------------------------


@settings(
    max_examples=100,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(finding=single_finding_strategy())
def test_safe_explain_remediation_returns_none_on_provider_unavailable(
    finding: Finding,
) -> None:
    """Property 4b (remediation): safe_explain_remediation() SHALL return None
    when the provider raises LLMProviderUnavailableError.

    **Validates: Requirements 5.3, 10.1**
    """
    snapshot = _snapshot_finding(finding)
    assistant = FindingTriageAssistant(provider=_make_unavailable_provider())

    result = asyncio.run(assistant.safe_explain_remediation(finding))

    assert result is None, (
        f"safe_explain_remediation() returned {result!r} when provider raised "
        "LLMProviderUnavailableError; expected None "
        "(Requirements 5.3, 10.1 violated)."
    )

    _assert_finding_unchanged(finding, snapshot)


# ---------------------------------------------------------------------------
# Property 4c — safe_explain_remediation: LLMResponseParseError → None
# ---------------------------------------------------------------------------


@settings(
    max_examples=100,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(finding=single_finding_strategy())
def test_safe_explain_remediation_returns_none_on_parse_error(finding: Finding) -> None:
    """Property 4c (remediation): safe_explain_remediation() SHALL return None
    when the provider raises LLMResponseParseError.

    **Validates: Requirement 10.2**
    """
    snapshot = _snapshot_finding(finding)
    assistant = FindingTriageAssistant(provider=_make_parse_error_provider())

    result = asyncio.run(assistant.safe_explain_remediation(finding))

    assert result is None, (
        f"safe_explain_remediation() returned {result!r} when provider raised "
        "LLMResponseParseError; expected None "
        "(Requirement 10.2 violated)."
    )

    _assert_finding_unchanged(finding, snapshot)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
