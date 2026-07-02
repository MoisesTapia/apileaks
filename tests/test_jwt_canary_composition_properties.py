# Feature: owasp-auth-modules-hardening, Property 39: A canary value never causes success without analyzer confirmation
"""
Property-Based Tests for canary composition in JWT attack success detection.

**Feature: owasp-auth-modules-hardening, Property 39: A canary value never
causes success without analyzer confirmation**

Property 39 (from design.md / Requirements 67.3, 67.4, 69.7):
    For all attack responses and all canary configurations (absent,
    present-and-matching, present-but-not-matching),
    ``JWTAttackEngine._attack_succeeded`` reports success if and only if the
    analyzer assessment is vulnerable; the canary only appends corroborating
    evidence when the analyzer already reports success.

This test drives the real ``_attack_succeeded`` method with a
``VulnerabilityAssessment`` carrying an arbitrary ``is_vulnerable`` flag and a
base evidence list, an engine constructed with an arbitrary canary
configuration, and an arbitrary response body. It asserts:

  1. The return value equals ``assessment.is_vulnerable`` for every canary
     configuration (success iff analyzer vulnerable — Req 67.4).
  2. When the analyzer is NOT vulnerable, no corroborating evidence is appended
     regardless of canary presence.
  3. When the analyzer IS vulnerable AND the canary is set AND its substring
     appears in the response body, exactly one corroborating evidence line is
     appended, idempotently across repeated calls (Req 67.3).
  4. When the analyzer IS vulnerable but the canary is absent or not present in
     the body, no evidence is appended.

Requirements covered: 67.3, 67.4, 69.7.

**Validates: Requirements 67.3, 67.4, 69.7**
"""

from hypothesis import given, settings, strategies as st

from utils.jwt_attack_engine import JWTAttackEngine
from utils.jwt_attack_models import (
    VulnerabilityAssessment,
    VulnerabilitySeverity,
)
from utils.jwt_utils import encode_jwt


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TARGET_URL = "https://target.example/api/account"

# A valid base token so the engine constructs successfully.
BASE_TOKEN = encode_jwt(
    {"alg": "HS256", "typ": "JWT"}, {"sub": "1234", "role": "user"}, "secret")


# ---------------------------------------------------------------------------
# Test double
# ---------------------------------------------------------------------------


class _StubHTTPEngine:
    """Minimal HTTP engine stub; _attack_succeeded performs no HTTP."""

    async def request(self, method, url, **kwargs):  # pragma: no cover
        raise AssertionError("_attack_succeeded must not perform HTTP requests")


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Canary tokens: short, non-empty strings so they can be embedded in bodies.
canary_tokens = st.text(
    alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
    min_size=3,
    max_size=16,
)

# Base evidence lists carried by the assessment before _attack_succeeded runs.
base_evidence = st.lists(st.text(min_size=0, max_size=24), max_size=4)

# Arbitrary surrounding text (may or may not contain the canary).
filler_text = st.text(max_size=40)


@st.composite
def scenarios(draw):
    """Draw (is_vulnerable, canary_value, response_body, canary_in_body).

    Covers all three canary configurations:
      * absent           -> canary_value is None
      * present-matching -> canary_value set AND its substring in response_body
      * present-mismatch -> canary_value set AND NOT in response_body
    """
    is_vulnerable = draw(st.booleans())
    config = draw(st.sampled_from(["absent", "matching", "mismatch"]))

    prefix = draw(filler_text)
    suffix = draw(filler_text)

    if config == "absent":
        canary_value = None
        response_body = prefix + suffix
    elif config == "matching":
        canary_value = draw(canary_tokens)
        response_body = prefix + canary_value + suffix
    else:  # mismatch
        canary_value = draw(canary_tokens)
        # Ensure the canary substring is NOT present in the body.
        body = prefix + suffix
        while canary_value in body:
            body += "."
        response_body = body

    canary_in_body = bool(canary_value) and canary_value in response_body
    return is_vulnerable, canary_value, response_body, canary_in_body


def _make_assessment(is_vulnerable, evidence):
    return VulnerabilityAssessment(
        is_vulnerable=is_vulnerable,
        vulnerability_type="Test Vulnerability",
        severity=VulnerabilitySeverity.HIGH,
        evidence=list(evidence),
        confidence_score=0.9,
        remediation_advice="Fix the JWT validation.",
    )


# ---------------------------------------------------------------------------
# Property 39
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(scenario=scenarios(), evidence=base_evidence)
def test_canary_never_promotes_without_analyzer_confirmation(scenario, evidence):
    """Success iff analyzer vulnerable; canary only corroborates a success.

    **Validates: Requirements 67.3, 67.4, 69.7**
    """
    is_vulnerable, canary_value, response_body, canary_in_body = scenario

    engine = JWTAttackEngine(
        TARGET_URL, BASE_TOKEN, _StubHTTPEngine(), canary_value=canary_value)

    assessment = _make_assessment(is_vulnerable, evidence)
    # Snapshot the evidence length before the call (the method mutates in place).
    evidence_len_before = len(assessment.evidence)

    result = engine._attack_succeeded(assessment, response_body)

    # 1. Return value equals the analyzer verdict for ALL canary configs.
    assert result == is_vulnerable

    evidence_len_after = len(assessment.evidence)

    if not is_vulnerable:
        # 2. No corroboration when the analyzer did not report success — even
        #    when the canary is present in the body.
        assert evidence_len_after == evidence_len_before
    else:
        if canary_value and canary_in_body:
            # 3. Exactly one corroborating evidence line appended on success.
            assert evidence_len_after == evidence_len_before + 1
            # Idempotent: a second call does not append again.
            engine._attack_succeeded(assessment, response_body)
            assert len(assessment.evidence) == evidence_len_before + 1
        else:
            # 4. Canary absent or not in body -> no evidence appended.
            assert evidence_len_after == evidence_len_before
