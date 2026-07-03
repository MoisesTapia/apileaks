# Feature: owasp-auth-modules-hardening, Property 25: kid / jku / x5u construction modifies only the targeted header
"""
Property-Based Tests for JWT header-construction integrity.

**Feature: owasp-auth-modules-hardening, Property 25: kid / jku / x5u
construction modifies only the targeted header**

Property 25 (from design.md / Requirements 44.1, 45.1, 48.4):
    For all original tokens and injection payloads, ``KID_INJECTION`` generation
    and ``jku``/``x5u`` construction modify ONLY the targeted header field and
    preserve every other header field and the entire payload unchanged.

These tests drive the real ``JWTAttackEngine._generate_kid_injection`` and
``JWTAttackEngine._generate_jwks_spoof`` in ``utils.jwt_attack_engine``. A valid
base JWT is built with Hypothesis-generated header/payload structures using the
module's own ``encode_jwt`` helper, so the property is exercised across varied
claim sets and header fields. Token generation is fully offline; the
constructor's ``http_engine`` is satisfied with a stub whose ``request`` raises
if ever invoked, so no network or behavioural mocking is involved.

Requirements covered: 44.1, 45.1, 48.4.

**Validates: Requirements 44.1, 45.1, 48.4**
"""

from hypothesis import given, settings, strategies as st

from utils.jwt_attack_engine import JWTAttackEngine
from utils.jwt_utils import decode_jwt, encode_jwt


# ---------------------------------------------------------------------------
# Test double
# ---------------------------------------------------------------------------


class _StubHTTPEngine:
    """HTTP engine stub.

    Header construction performs no HTTP, so ``request`` should never be invoked
    during these tests. If it ever is, fail loudly rather than silently pass.
    """

    async def request(self, method, url, **kwargs):  # pragma: no cover
        raise AssertionError("token generation must not perform HTTP requests")


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Secret used to sign the generated base token (any valid HMAC secret works;
# signing does not affect the decoded header/payload the property inspects).
BASE_SECRET = "header-construction-base-secret"
SIGNING_SECRET = "operator-recovered-signing-key-42"

# Header fields the engine itself constructs/targets; excluded from the random
# extra header fields so generated base tokens don't collide with the targeted
# ``kid``/``jku``/``x5u`` fields or the reserved ``alg``/``typ`` fields.
_RESERVED_HEADER_KEYS = frozenset({"alg", "typ", "kid", "jku", "x5u"})

VALID_ALGS = st.sampled_from(["HS256", "HS384", "HS512"])

identity_values = st.one_of(
    st.text(min_size=1, max_size=24),
    st.integers(min_value=0, max_value=10 ** 9),
)

role_values = st.sampled_from(["user", "guest", "member", "editor", "viewer", "staff"])

timestamps = st.integers(min_value=1_000_000_000, max_value=2_000_000_000)

claim_values = st.one_of(
    st.text(max_size=16),
    st.integers(min_value=-1000, max_value=1000),
    st.booleans(),
)


@st.composite
def base_payloads(draw):
    """Generate a varied JWT payload (different claim sets)."""
    payload = {}
    if draw(st.booleans()):
        payload["sub"] = str(draw(identity_values))
    if draw(st.booleans()):
        payload["user_id"] = draw(identity_values)
    if draw(st.booleans()):
        payload["username"] = draw(st.text(min_size=1, max_size=16))
    if draw(st.booleans()):
        payload["role"] = draw(role_values)
    if draw(st.booleans()):
        payload["iat"] = draw(timestamps)
    if draw(st.booleans()):
        payload["exp"] = draw(timestamps)
    extra = draw(st.dictionaries(
        st.text(min_size=1, max_size=10).filter(
            lambda k: k not in ("sub", "user_id", "username", "role", "iat", "exp")),
        claim_values,
        max_size=3,
    ))
    payload.update(extra)
    return payload


@st.composite
def base_headers(draw):
    """Generate a varied JWT header with optional extra (non-reserved) fields."""
    header = {"alg": draw(VALID_ALGS), "typ": "JWT"}
    extra = draw(st.dictionaries(
        st.text(min_size=1, max_size=10).filter(lambda k: k not in _RESERVED_HEADER_KEYS),
        claim_values,
        max_size=3,
    ))
    header.update(extra)
    return header


@st.composite
def base_tokens(draw):
    """Build a valid HMAC-signed base JWT from a generated header/payload."""
    header = draw(base_headers())
    payload = draw(base_payloads())
    return encode_jwt(header, payload, BASE_SECRET)


def _make_engine(base_token):
    return JWTAttackEngine(
        target_url="https://target.example/api",
        original_token=base_token,
        http_engine=_StubHTTPEngine(),
        signing_secret=SIGNING_SECRET,
    )


# ---------------------------------------------------------------------------
# Property 25a: KID_INJECTION modifies only the ``kid`` header
# ---------------------------------------------------------------------------


# Feature: owasp-auth-modules-hardening, Property 25: kid / jku / x5u construction modifies only the targeted header
@settings(max_examples=150)
@given(base_token=base_tokens())
def test_kid_injection_modifies_only_kid_header_and_preserves_payload(base_token):
    """``_generate_kid_injection`` injects a ``kid`` and changes nothing else.

    For any valid base token, every generated KID token decodes to a header
    equal to the base header except for the (present/injected) ``kid`` field,
    and its payload equals the base payload verbatim.

    **Validates: Requirements 44.1, 48.4**
    """
    engine = _make_engine(base_token)
    base = decode_jwt(base_token)
    base_header_without_kid = {k: v for k, v in base["header"].items() if k != "kid"}

    tokens = engine._generate_kid_injection()
    assert tokens, "expected KID_INJECTION to produce tokens"

    for token in tokens:
        decoded = decode_jwt(token)

        # The entire payload is preserved unchanged.
        assert decoded["payload"] == base["payload"]

        # A ``kid`` header was actually injected.
        assert "kid" in decoded["header"]

        # Every header field other than ``kid`` is preserved exactly.
        header_without_kid = {k: v for k, v in decoded["header"].items() if k != "kid"}
        assert header_without_kid == base_header_without_kid


# ---------------------------------------------------------------------------
# Property 25b: jku / x5u construction modifies only the targeted header
# ---------------------------------------------------------------------------


# Feature: owasp-auth-modules-hardening, Property 25: kid / jku / x5u construction modifies only the targeted header
@settings(max_examples=150)
@given(base_token=base_tokens())
def test_jwks_spoof_modifies_only_targeted_jku_or_x5u_header(base_token):
    """``_generate_jwks_spoof`` sets exactly one of ``jku``/``x5u`` per token.

    For any valid base token, every generated JWKS-spoof token decodes to a
    header that differs from the base header in exactly one field — either
    ``jku`` or ``x5u`` — with every other header field preserved and the payload
    preserved verbatim.

    **Validates: Requirements 45.1, 48.4**
    """
    engine = _make_engine(base_token)
    base = decode_jwt(base_token)
    base_header = base["header"]

    tokens = engine._generate_jwks_spoof()
    assert tokens, "expected JWKS_SPOOF to produce tokens"

    for token in tokens:
        decoded = decode_jwt(token)

        # The entire payload is preserved unchanged.
        assert decoded["payload"] == base["payload"]

        # Exactly one header field differs from the base header, and it is one
        # of the targeted jku/x5u fields.
        all_keys = set(base_header) | set(decoded["header"])
        diff_keys = {k for k in all_keys if base_header.get(k) != decoded["header"].get(k)}
        assert len(diff_keys) == 1, f"expected exactly one changed header field, got {diff_keys}"
        (changed_field,) = diff_keys
        assert changed_field in ("jku", "x5u")

        # The targeted field was actually added/set to a spoof URL value.
        assert isinstance(decoded["header"][changed_field], str)
        assert decoded["header"][changed_field]

        # Every other header field is preserved exactly.
        for key, value in base_header.items():
            if key == changed_field:
                continue
            assert decoded["header"].get(key) == value
