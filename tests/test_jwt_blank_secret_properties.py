# Feature: owasp-auth-modules-hardening, Property 34: Blank-secret acceptance is reported iff the signature verifies under the empty key
"""
Property-Based Tests for blank-secret acceptance detection.

**Feature: owasp-auth-modules-hardening, Property 34: Blank-secret acceptance is
reported iff the signature verifies under the empty key**

Property 34 (from design.md / Requirements 58.1, 58.2, 69.2):
    For all JWT tokens and all signing keys used to produce them (including the
    empty string ``""``), the blank-secret detector reports a
    ``JWT_BLANK_SECRET_ACCEPTED`` local match if and only if
    ``verify_hmac_secret(token, "")`` is ``True``, and never on any other basis.

The "local match" (blank-secret detector) is
``utils.jwt_attack_engine._resolve_finding_category`` returning
``JWT_BLANK_SECRET_ACCEPTED``. This test drives that real function with
WEAK_SECRET ``AttackResult``s carrying tokens signed with arbitrary keys
(including ``""``) and with tokens produced by the engine's own
``_generate_weak_secret`` (which prepends the empty-key candidate). It asserts
the biconditional against the Requirement 16 verification path
``verify_hmac_secret(token, "")`` and that a WEAK_SECRET result is otherwise
reported as ``JWT_WEAK_SECRET``. A non-WEAK_SECRET attack type is checked to
never yield the blank category.

Requirements covered: 58.1, 58.2, 69.2.

**Validates: Requirements 58.1, 58.2, 69.2**
"""

from hypothesis import given, settings, strategies as st

from utils.jwt_attack_engine import (
    JWTAttackEngine,
    JWT_BLANK_SECRET_CATEGORY,
    _resolve_finding_category,
)
from utils.jwt_attack_models import (
    AttackResult,
    AttackType,
    RequestDetails,
    ResponseDetails,
    VulnerabilityAssessment,
    VulnerabilitySeverity,
)
from utils.jwt_utils import encode_jwt, verify_hmac_secret


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TARGET_URL = "https://target.example/api/account"

# JWT_BLANK_SECRET_CATEGORY is defined to equal this literal (Req 58.2).
assert JWT_BLANK_SECRET_CATEGORY == "JWT_BLANK_SECRET_ACCEPTED"


# ---------------------------------------------------------------------------
# Test double
# ---------------------------------------------------------------------------


class _StubHTTPEngine:
    """Minimal HTTP engine stub; token generation performs no HTTP."""

    async def request(self, method, url, **kwargs):  # pragma: no cover
        raise AssertionError("token generation must not perform HTTP requests")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_weak_secret_result(token, attack_type=AttackType.WEAK_SECRET):
    """Build a minimal AttackResult carrying ``token`` for the given vector."""
    assessment = VulnerabilityAssessment(
        is_vulnerable=True,
        vulnerability_type="Test Vulnerability",
        severity=VulnerabilitySeverity.HIGH,
        evidence=["Authentication bypass: 401 -> 200"],
        confidence_score=0.9,
        remediation_advice="Fix the JWT validation.",
    )
    return AttackResult(
        attack_type=attack_type,
        attack_variant="standard",
        jwt_token=token,
        request_details=RequestDetails(
            url=TARGET_URL, method="GET", headers={"Authorization": "Bearer x"}),
        response_details=ResponseDetails(
            status_code=200, headers={}, body="{}", response_time=0.02,
            content_length=2),
        vulnerability_assessment=assessment,
    )


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# HMAC algorithms a token might declare.
hmac_algs = st.sampled_from(["HS256", "HS384", "HS512"])

# Signing keys, including the empty string "" so blank-secret tokens are
# generated, plus varied non-empty keys.
signing_keys = st.one_of(
    st.just(""),
    st.text(min_size=1, max_size=24),
)

# Payload claim values.
identity_values = st.one_of(
    st.text(min_size=0, max_size=24),
    st.integers(min_value=0, max_value=10 ** 9),
)


@st.composite
def signed_tokens(draw):
    """Generate a JWT signed with an arbitrary key (including "")."""
    alg = draw(hmac_algs)
    secret = draw(signing_keys)
    payload = {
        "sub": draw(identity_values),
        "role": draw(st.sampled_from(["user", "admin", "guest", "editor"])),
    }
    header = {"alg": alg, "typ": "JWT"}
    return encode_jwt(header, payload, secret)


# ---------------------------------------------------------------------------
# Property 34
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(token=signed_tokens())
def test_blank_secret_reported_iff_verifies_under_empty_key(token):
    """WEAK_SECRET result -> blank category iff verify_hmac_secret(token, "").

    **Validates: Requirements 58.1, 58.2, 69.2**
    """
    result = _make_weak_secret_result(token)
    category = _resolve_finding_category(result)

    verifies_blank = verify_hmac_secret(token, "")

    if verifies_blank:
        assert category == "JWT_BLANK_SECRET_ACCEPTED"
    else:
        # Reported on no other basis: a WEAK_SECRET result that does NOT verify
        # under the empty key is the generic weak-secret category.
        assert category == "JWT_WEAK_SECRET"

    # Biconditional restated: the blank category is emitted exactly when the
    # signature verifies under the empty key.
    assert (category == "JWT_BLANK_SECRET_ACCEPTED") == verifies_blank


@settings(max_examples=100)
@given(
    alg=hmac_algs,
    sub=identity_values,
    role=st.sampled_from(["user", "admin", "guest", "editor"]),
)
def test_engine_generated_weak_secret_tokens_report_blank_iff_empty_key(alg, sub, role):
    """Tokens from the engine's _generate_weak_secret honor the biconditional.

    ``_generate_weak_secret`` prepends the empty-key candidate, so the first
    token verifies under "" (blank-secret reported) while wordlist tokens signed
    with non-empty secrets do not.

    **Validates: Requirements 58.1, 58.2, 69.2**
    """
    base_token = encode_jwt({"alg": alg, "typ": "JWT"}, {"sub": sub, "role": role}, "secret")
    engine = JWTAttackEngine(TARGET_URL, base_token, _StubHTTPEngine())

    tokens = engine.generate_token(AttackType.WEAK_SECRET)
    assert tokens, "WEAK_SECRET generation must yield at least one token"

    saw_blank = False
    for token in tokens:
        result = _make_weak_secret_result(token)
        category = _resolve_finding_category(result)
        verifies_blank = verify_hmac_secret(token, "")
        assert (category == "JWT_BLANK_SECRET_ACCEPTED") == verifies_blank
        if verifies_blank:
            saw_blank = True

    # The prepended empty-key candidate guarantees at least one blank-secret hit.
    assert saw_blank


@settings(max_examples=100)
@given(token=signed_tokens())
def test_non_weak_secret_attack_never_reports_blank_category(token):
    """A non-WEAK_SECRET attack type never yields the blank category.

    Even when the token verifies under the empty key, the blank-secret match is
    only reported for the WEAK_SECRET vector — never on any other basis.

    **Validates: Requirements 58.1, 58.2, 69.2**
    """
    result = _make_weak_secret_result(token, attack_type=AttackType.ALG_NONE)
    category = _resolve_finding_category(result)
    assert category != "JWT_BLANK_SECRET_ACCEPTED"
    assert category == "JWT_NONE_ALGORITHM"
