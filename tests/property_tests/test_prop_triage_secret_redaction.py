"""
tests/property_tests/test_prop_triage_secret_redaction.py

Property-based test — Redacción de Secretos antes de Enviar a un LLM.

Feature: ai-mcp-integration

Property 3: Redacción de Secretos antes de Enviar a un LLM
    Para cualquier Finding cuya evidencia contenga un secreto/credencial/token,
    el prompt enviado a cualquier LLMProvider SHALL contener esa evidencia
    redactada, nunca en texto plano.

Two sub-properties are verified:

3a — ``triage()`` path:
    For ANY Finding whose evidence contains a credential pattern, the prompt
    passed to ``provider.complete`` during ``triage()`` SHALL NOT contain the
    raw secret value verbatim.

3b — ``explain_remediation()`` path:
    For ANY Finding whose evidence contains a credential pattern, the prompt
    passed to ``provider.complete`` during ``explain_remediation()`` SHALL NOT
    contain the raw secret value verbatim.

Secret patterns covered:
    - Bearer token in Authorization header: ``Authorization: Bearer <token>``
    - Key=value credential field:           ``token=<value>``
    - Stripe-style API key prefix:          ``api_key=sk_<20+alphanum>``
    - AWS Access Key prefix:                ``access_key=AKIA<16chars>``

**Validates: Requirements 5.5**
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any
from unittest.mock import MagicMock

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from hypothesis.strategies import composite

# Ensure core logging is available before importing utils.
import core.logging  # noqa: F401

from core.config import Severity
from utils.ai.triage_assistant import FindingTriageAssistant
from utils.findings import Finding


# ---------------------------------------------------------------------------
# Constants and base alphabet
# ---------------------------------------------------------------------------

_SEVERITIES = list(Severity)
_OWASP_CATEGORIES = ["API1", "API2", "API3", "API4", "API5", None]
_HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]
_CATEGORIES = [
    "BOLA_OBJECT_ACCESS",
    "AUTH_WEAK_PASSWORD",
    "JWT_NONE_ALGORITHM",
    "SSRF_OPEN_REDIRECT",
    "MASS_ASSIGNMENT",
    "SECURITY_MISCONFIGURATION",
    "RATE_LIMIT_BYPASS",
    "BFLA_FUNCTION_ACCESS",
]

# Alphanumeric characters only — no spaces or shell-special chars so the
# generated value won't be split by the regex stop-chars in redact_secrets.
_alphanum_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


# ---------------------------------------------------------------------------
# Secret-pattern strategies
# ---------------------------------------------------------------------------
# Each composite strategy returns a (evidence_text, raw_secret) pair where:
#   evidence_text — the full string that will be stored in Finding.evidence
#   raw_secret    — the specific value that MUST NOT appear verbatim in the
#                   prompt after redaction
#
# All patterns are reliably caught by ``BOLATestingModule.redact_secrets``.


@composite
def bearer_token_evidence(draw: Any) -> tuple[str, str]:
    """Pattern A — Bearer Authorization header.

    ``Authorization: Bearer <token>``

    The keyword ``authorization`` triggers rule 2 of redact_secrets; the
    token value is replaced with ``<redacted>``.
    """
    raw_secret = draw(
        st.text(alphabet=_alphanum_chars, min_size=24, max_size=48)
    )
    evidence = f"Authorization: Bearer {raw_secret}"
    return evidence, raw_secret


@composite
def token_kv_evidence(draw: Any) -> tuple[str, str]:
    """Pattern B — ``token=<value>`` key=value credential.

    The keyword ``token`` triggers rule 2 of redact_secrets; the value is
    replaced with ``<redacted>``.
    """
    raw_secret = draw(
        st.text(alphabet=_alphanum_chars, min_size=24, max_size=48)
    )
    evidence = f"token={raw_secret}"
    return evidence, raw_secret


@composite
def sk_key_evidence(draw: Any) -> tuple[str, str]:
    """Pattern C — Stripe-style ``api_key=sk_<20+alphanum>`` credential.

    Two redaction rules apply:
    - Rule 2: keyword ``api_key`` redacts the whole ``api_key=sk_...`` value.
    - Rule 3: credential prefix ``sk_`` makes the bare token self-sufficient.

    The raw ``sk_<suffix>`` value must not appear in the prompt.
    """
    suffix = draw(
        st.text(
            alphabet=_alphanum_chars,
            min_size=20,
            max_size=40,
        )
    )
    raw_secret = f"sk_{suffix}"
    evidence = f"api_key={raw_secret}"
    return evidence, raw_secret


@composite
def aws_key_evidence(draw: Any) -> tuple[str, str]:
    """Pattern D — AWS-style access key ``access_key=AKIA<16chars>``.

    Two redaction rules apply:
    - Rule 2: keyword ``access_key`` redacts the whole value.
    - Rule 3: credential prefix ``AKIA`` makes the bare token self-sufficient.

    The raw ``AKIA<suffix>`` value must not appear in the prompt.
    """
    suffix = draw(
        st.text(
            alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            min_size=16,
            max_size=16,
        )
    )
    raw_secret = f"AKIA{suffix}"
    evidence = f"access_key={raw_secret}"
    return evidence, raw_secret


# Union strategy — picks one of the four secret patterns on each example.
secret_evidence_strategy = st.one_of(
    bearer_token_evidence(),
    token_kv_evidence(),
    sk_key_evidence(),
    aws_key_evidence(),
)


# ---------------------------------------------------------------------------
# Finding / mock-provider helpers
# ---------------------------------------------------------------------------


def _make_finding_with_secret(
    evidence: str,
    finding_id: str = "finding-secret-001",
) -> Finding:
    """Return a minimal Finding whose ``evidence`` field contains a secret."""
    return Finding(
        id=finding_id,
        scan_id="scan-prop-secret-001",
        category="AUTH_SECRET_IN_URL",
        owasp_category="API2",
        severity=Severity.HIGH,
        endpoint="/api/v1/resource",
        method="GET",
        status_code=200,
        response_size=512,
        response_time=0.05,
        evidence=evidence,
        recommendation="Rotate all exposed credentials immediately.",
        payload=None,
        response_snippet=None,
        timestamp=datetime(2024, 1, 1, 12, 0, 0),
    )


def _valid_triage_json(finding_id: str) -> str:
    """Build a valid triage JSON response for a single finding ID."""
    return json.dumps(
        {
            "prioritized_finding_ids": [finding_id],
            "narrative_summary": "Secret exposure requires immediate credential rotation.",
            "per_finding_notes": {finding_id: "Critical: exposed credential detected."},
        }
    )


def _make_capturing_provider(
    captured_prompts: list[str],
    triage_response: str,
) -> MagicMock:
    """Return a mock LLMProvider that stores every prompt it receives.

    Uses a plain async def (not AsyncMock) so that Hypothesis does not
    interfere with coroutine state across examples.
    """
    provider = MagicMock()

    async def _capture(prompt: str, *, max_tokens: int, timeout: float) -> str:
        captured_prompts.append(prompt)
        return triage_response

    provider.complete = _capture
    return provider


# ---------------------------------------------------------------------------
# Property 3a — triage() path
# ---------------------------------------------------------------------------


@settings(
    max_examples=150,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(secret_pair=secret_evidence_strategy)
def test_triage_does_not_send_raw_secret_to_llm(
    secret_pair: tuple[str, str],
) -> None:
    """Property 3a: triage() path — secret redaction before LLM call.

    For ANY Finding whose evidence contains a known credential pattern, the
    prompt sent to ``provider.complete`` during ``triage()`` SHALL NOT contain
    the raw secret value verbatim.

    **Validates: Requirements 5.5**
    """
    evidence_text, raw_secret = secret_pair
    finding_id = "finding-prop3a"
    finding = _make_finding_with_secret(evidence_text, finding_id=finding_id)

    captured_prompts: list[str] = []
    triage_response = _valid_triage_json(finding_id)
    provider = _make_capturing_provider(captured_prompts, triage_response)

    assistant = FindingTriageAssistant(provider)
    asyncio.run(assistant.triage([finding]))

    assert captured_prompts, (
        "provider.complete was never called — triage() did not invoke the LLM "
        "for a non-empty findings list."
    )
    prompt = captured_prompts[0]

    assert raw_secret not in prompt, (
        f"Raw secret value found verbatim in the triage prompt — "
        f"Requirement 5.5 violated.\n"
        f"  evidence  : {evidence_text!r}\n"
        f"  raw_secret: {raw_secret!r}\n"
        f"  prompt excerpt (first 400 chars): {prompt[:400]!r}"
    )


# ---------------------------------------------------------------------------
# Property 3b — explain_remediation() path
# ---------------------------------------------------------------------------


@settings(
    max_examples=150,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(secret_pair=secret_evidence_strategy)
def test_explain_remediation_does_not_send_raw_secret_to_llm(
    secret_pair: tuple[str, str],
) -> None:
    """Property 3b: explain_remediation() path — secret redaction before LLM call.

    For ANY Finding whose evidence contains a known credential pattern, the
    prompt sent to ``provider.complete`` during ``explain_remediation()`` SHALL
    NOT contain the raw secret value verbatim.

    **Validates: Requirements 5.5**
    """
    evidence_text, raw_secret = secret_pair
    finding = _make_finding_with_secret(evidence_text)

    captured_prompts: list[str] = []
    provider = _make_capturing_provider(
        captured_prompts,
        triage_response="Immediately rotate the exposed credential and audit access logs.",
    )

    assistant = FindingTriageAssistant(provider)
    asyncio.run(assistant.explain_remediation(finding))

    assert captured_prompts, (
        "provider.complete was never called — explain_remediation() did not "
        "invoke the LLM."
    )
    prompt = captured_prompts[0]

    assert raw_secret not in prompt, (
        f"Raw secret value found verbatim in the remediation prompt — "
        f"Requirement 5.5 violated.\n"
        f"  evidence  : {evidence_text!r}\n"
        f"  raw_secret: {raw_secret!r}\n"
        f"  prompt excerpt (first 400 chars): {prompt[:400]!r}"
    )


# ---------------------------------------------------------------------------
# Concrete regression examples (fast sanity checks)
# ---------------------------------------------------------------------------


def test_example_bearer_token_not_in_triage_prompt() -> None:
    """Concrete: a JWT-shaped Bearer token is not included in the triage prompt."""
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjMifQ"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    evidence = f"Authorization: Bearer {jwt}"
    finding = _make_finding_with_secret(evidence, finding_id="jwt-example")

    captured: list[str] = []
    provider = _make_capturing_provider(captured, _valid_triage_json("jwt-example"))
    assistant = FindingTriageAssistant(provider)
    asyncio.run(assistant.triage([finding]))

    assert captured, "provider.complete was never called"
    assert jwt not in captured[0], (
        "JWT token leaked into triage prompt — Requirement 5.5 violated."
    )


def test_example_bearer_token_not_in_remediation_prompt() -> None:
    """Concrete: a Bearer token is not included in the remediation prompt."""
    secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
    evidence = f"Authorization: Bearer {secret}"
    finding = _make_finding_with_secret(evidence)

    captured: list[str] = []
    provider = _make_capturing_provider(captured, "Rotate the exposed API key.")
    assistant = FindingTriageAssistant(provider)
    asyncio.run(assistant.explain_remediation(finding))

    assert captured, "provider.complete was never called"
    assert secret not in captured[0], (
        "Bearer API key leaked into remediation prompt — Requirement 5.5 violated."
    )


def test_example_token_kv_not_in_triage_prompt() -> None:
    """Concrete: a raw token in key=value form is not included in the triage prompt."""
    raw_token = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd"
    evidence = f"token={raw_token}"
    finding = _make_finding_with_secret(evidence, finding_id="kv-example")

    captured: list[str] = []
    provider = _make_capturing_provider(captured, _valid_triage_json("kv-example"))
    assistant = FindingTriageAssistant(provider)
    asyncio.run(assistant.triage([finding]))

    assert captured, "provider.complete was never called"
    assert raw_token not in captured[0], (
        "Raw token value leaked into triage prompt — Requirement 5.5 violated."
    )


def test_example_aws_key_not_in_remediation_prompt() -> None:
    """Concrete: an AWS Access Key is not included in the remediation prompt."""
    raw_key = "AKIAIOSFODNN7EXAMPLE"
    evidence = f"access_key={raw_key}"
    finding = _make_finding_with_secret(evidence)

    captured: list[str] = []
    provider = _make_capturing_provider(captured, "Revoke the exposed IAM key immediately.")
    assistant = FindingTriageAssistant(provider)
    asyncio.run(assistant.explain_remediation(finding))

    assert captured, "provider.complete was never called"
    assert raw_key not in captured[0], (
        "AWS Access Key leaked into remediation prompt — Requirement 5.5 violated."
    )


def test_example_sk_key_not_in_triage_prompt() -> None:
    """Concrete: a Stripe-style sk_ key embedded in api_key field is redacted."""
    raw_key = "sk_EXAMPLE_abcdefghijklmnopqrstuvwxyz0123456789"
    evidence = f"api_key={raw_key}"
    finding = _make_finding_with_secret(evidence, finding_id="sk-example")

    captured: list[str] = []
    provider = _make_capturing_provider(captured, _valid_triage_json("sk-example"))
    assistant = FindingTriageAssistant(provider)
    asyncio.run(assistant.triage([finding]))

    assert captured, "provider.complete was never called"
    assert raw_key not in captured[0], (
        "Stripe-style API key leaked into triage prompt — Requirement 5.5 violated."
    )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
