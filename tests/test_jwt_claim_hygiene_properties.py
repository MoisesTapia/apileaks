# Feature: owasp-auth-modules-hardening, Property 36: Claim-hygiene reports a missing-claim finding iff the claim is absent
"""
Property-Based Tests for the static JWT claim-hygiene analyzer.

**Feature: owasp-auth-modules-hardening, Property 36: Claim-hygiene reports a
missing-claim finding iff the claim is absent**

Property 36 (from design.md):
    For all decoded JWT payloads, ``assess_claim_hygiene`` reports the
    missing-claim finding for a Registered_Claim in {``exp``, ``iss``, ``aud``,
    ``jti``} IF AND ONLY IF that claim is absent, each finding names exactly the
    absent claim, and the assessment issues no HTTP request.

These tests drive the real ``assess_claim_hygiene`` helper in
``utils.jwt_utils``. Arbitrary payloads are generated with Hypothesis, randomly
including/excluding each security claim and mixing in arbitrary unrelated
claims/keys that must not affect the result. The analyzer is a pure, static,
network-free inspection, so any attempt to open a socket during assessment
fails the test.

Requirements covered: 61.1, 61.2, 61.3, 61.4, 61.5, 61.6, 62.3, 62.4, 69.4.

**Validates: Requirements 61.1, 61.2, 61.3, 61.4, 61.5, 61.6, 62.3, 62.4, 69.4**
"""

from unittest import mock

from hypothesis import given, settings, strategies as st

from utils.jwt_utils import (
    assess_claim_hygiene,
    SECURITY_CLAIMS,
    CLAIM_MISSING_CATEGORY,
    ClaimFinding,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# JSON-serializable scalar values used for arbitrary claim values.
json_scalars = st.one_of(
    st.text(max_size=30),
    st.integers(min_value=-(10 ** 12), max_value=10 ** 12),
    st.booleans(),
    st.none(),
)

# Arbitrary "other" claims/keys that are NOT security claims. These must never
# influence the missing-claim findings.
other_claims = st.dictionaries(
    st.text(min_size=1, max_size=20).filter(lambda k: k not in SECURITY_CLAIMS),
    json_scalars,
    max_size=6,
)


@st.composite
def payloads(draw):
    """Generate an arbitrary decoded JWT payload.

    Each security claim (exp/iss/aud/jti) is independently included or excluded,
    and arbitrary unrelated claims are mixed in.
    """
    payload = dict(draw(other_claims))
    for claim in SECURITY_CLAIMS:
        if draw(st.booleans()):
            payload[claim] = draw(json_scalars)
    return payload


# ---------------------------------------------------------------------------
# Property 36: missing-claim finding iff the claim is absent
# ---------------------------------------------------------------------------


@settings(max_examples=200)
@given(payload=payloads())
def test_claim_hygiene_missing_iff_absent(payload):
    """A missing-claim finding is reported iff the security claim is absent.

    **Validates: Requirements 61.1, 61.2, 61.3, 61.4, 61.5, 61.6, 62.3, 62.4, 69.4**
    """
    # The assessment must be network-free: opening a socket during the call is
    # a failure (Reqs 61.1, 62.4).
    with mock.patch(
        "socket.socket",
        side_effect=AssertionError("assess_claim_hygiene must not open a socket"),
    ):
        findings = assess_claim_hygiene(payload)

    # Result must be a list of ClaimFinding objects.
    assert isinstance(findings, list)
    assert all(isinstance(f, ClaimFinding) for f in findings)

    # Index findings by the claim they name for the IFF checks below.
    findings_by_claim = {}
    for f in findings:
        # Each finding names exactly one absent security claim with the
        # matching missing-claim category (Reqs 61.2-61.6).
        assert f.claim in SECURITY_CLAIMS
        assert f.category == CLAIM_MISSING_CATEGORY[f.claim]
        # A finding names exactly one claim -> no duplicate findings per claim.
        assert f.claim not in findings_by_claim
        findings_by_claim[f.claim] = f

    # The IFF property: for every security claim, a finding is present exactly
    # when the claim is absent from the payload.
    for claim in SECURITY_CLAIMS:
        absent = claim not in payload
        reported = claim in findings_by_claim
        assert reported == absent, (
            f"claim {claim!r}: reported={reported} but absent={absent}"
        )

    # No findings for present claims (equivalently, only absent claims appear).
    for claim in findings_by_claim:
        assert claim not in payload
