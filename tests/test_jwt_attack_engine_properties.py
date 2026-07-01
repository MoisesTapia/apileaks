# Feature: owasp-auth-modules-hardening, Property 9: Every AttackType has an executable generation path
"""
Property-Based Tests for JWT attack-vector executability.

**Feature: owasp-auth-modules-hardening, Property 9: Every AttackType has an
executable generation path**

Property 9 (from design.md / Requirements 15.3, 15.4):
    For all nine ``AttackType`` members, ``JWTAttackEngine.generate_token``
    returns a non-empty list containing at least one non-empty token string,
    and every member is covered by an executable generation path (the dispatch
    table in ``generate_token``). No vector is silently unimplemented.

These tests drive the real ``JWTAttackEngine.generate_token`` in
``utils.jwt_attack_engine``. A valid base JWT is built with Hypothesis-generated
header/payload structures using the module's own ``encode_jwt`` helper, so the
property is exercised across varied identity/role/expiration claims and header
algorithms. Token generation is fully offline; the constructor's ``http_engine``
is satisfied with a lightweight stub exposing an async ``request`` (never called
during generation), so no network or real mocking of behavior is involved.

Requirements covered: 15.3, 15.4.

**Validates: Requirements 15.3, 15.4**
"""

import pytest
from hypothesis import given, settings, strategies as st

from utils.jwt_attack_engine import JWTAttackEngine
from utils.jwt_attack_models import AttackType
from utils.jwt_utils import encode_jwt


# ---------------------------------------------------------------------------
# Test double
# ---------------------------------------------------------------------------


class _StubHTTPEngine:
    """Minimal HTTP engine stub.

    ``generate_token`` performs no HTTP, so ``request`` should never be invoked
    during these tests. If it ever is, fail loudly rather than silently pass.
    """

    async def request(self, method, url, **kwargs):  # pragma: no cover
        raise AssertionError(
            "generate_token must not perform HTTP requests")


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Secret used to sign the generated base token (any valid HMAC secret works).
BASE_SECRET = "attack-engine-base-secret"

# Header algorithms a real base token might declare.
VALID_ALGS = st.sampled_from(["HS256", "HS384", "HS512"])

# Subject / user identity claim values (strings and ints both appear in the wild).
identity_values = st.one_of(
    st.text(min_size=1, max_size=24),
    st.integers(min_value=0, max_value=10 ** 9),
)

# Role claim values.
role_values = st.sampled_from(["user", "guest", "member", "editor", "viewer", "staff"])

# Unix-epoch-ish timestamps for iat/exp.
timestamps = st.integers(min_value=1_000_000_000, max_value=2_000_000_000)


@st.composite
def base_payloads(draw):
    """Generate a realistic JWT payload varying identity/role/expiration claims.

    Every field is optional so the generator explores payloads that do and do
    not carry ``sub``/``user_id``/``username``/``role``/``exp``/``iat`` — the
    claims the identity/expiration vectors add or remove.
    """
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
    # A couple of arbitrary extra claims to broaden the input space.
    extra = draw(st.dictionaries(
        st.text(min_size=1, max_size=10).filter(
            lambda k: k not in ("sub", "user_id", "username", "role", "iat", "exp")),
        st.one_of(st.text(max_size=16), st.integers(min_value=-1000, max_value=1000),
                  st.booleans()),
        max_size=3,
    ))
    payload.update(extra)
    return payload


@st.composite
def base_tokens(draw):
    """Build a valid HMAC-signed base JWT from a generated header/payload."""
    alg = draw(VALID_ALGS)
    payload = draw(base_payloads())
    header = {"alg": alg, "typ": "JWT"}
    return encode_jwt(header, payload, BASE_SECRET)


def _make_engine(base_token, signing_secret=None):
    return JWTAttackEngine(
        target_url="https://target.example/api",
        original_token=base_token,
        http_engine=_StubHTTPEngine(),
        signing_secret=signing_secret,
    )


# ---------------------------------------------------------------------------
# Property 9 (core): every AttackType yields at least one non-empty token
# ---------------------------------------------------------------------------


@settings(max_examples=200)
@given(base_token=base_tokens())
def test_every_attack_type_generates_a_nonempty_token(base_token):
    """For all nine ``AttackType`` members, ``generate_token`` returns a
    non-empty list with at least one non-empty token string.

    Driven across varied base tokens (identity/role/expiration claims and
    header algorithms) so the executable-path guarantee holds for any valid
    base token, not just a fixed one.

    **Validates: Requirements 15.3, 15.4**
    """
    engine = _make_engine(base_token)

    members = list(AttackType)
    # Guard the "nine members" assumption the property is written against.
    assert len(members) == 9

    for attack_type in members:
        tokens = engine.generate_token(attack_type)

        # Executable path exists and produced output for this vector.
        assert isinstance(tokens, list)
        assert len(tokens) >= 1, f"{attack_type} produced no tokens"

        # At least one non-empty token string.
        assert any(isinstance(t, str) and t for t in tokens), (
            f"{attack_type} produced no non-empty token")

        # generate_token already filters falsy tokens, so none should be empty.
        assert all(isinstance(t, str) and t for t in tokens), (
            f"{attack_type} produced an empty token")


# ---------------------------------------------------------------------------
# Property 9 (dispatch coverage): the dispatch table covers every member
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(base_token=base_tokens())
def test_generate_all_tokens_covers_every_attack_type(base_token):
    """``generate_all_tokens`` returns an entry for every ``AttackType`` and each
    entry is a non-empty list of non-empty tokens.

    This pins the "single generation path per vector" guarantee: no member maps
    to a missing/empty generator.

    **Validates: Requirements 15.3, 15.4**
    """
    engine = _make_engine(base_token)

    all_tokens = engine.generate_all_tokens()

    # Exactly the nine members are present as keys.
    assert set(all_tokens.keys()) == set(AttackType)

    for attack_type, tokens in all_tokens.items():
        assert tokens, f"{attack_type} has no executable generation path"
        assert all(isinstance(t, str) and t for t in tokens), (
            f"{attack_type} produced an empty token")


# ---------------------------------------------------------------------------
# Property 9 (signing-secret invariance): path stays executable with/without key
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(base_token=base_tokens(), signing_secret=st.text(min_size=1, max_size=32))
def test_executable_path_holds_with_signing_secret(base_token, signing_secret):
    """Every vector remains executable whether or not an operator signing secret
    is supplied (signature-requiring vectors use the key; key-less vectors do
    not), so the executability guarantee is independent of key availability.

    **Validates: Requirements 15.3, 15.4**
    """
    engine = _make_engine(base_token, signing_secret=signing_secret)

    for attack_type in AttackType:
        tokens = engine.generate_token(attack_type)
        assert tokens, f"{attack_type} produced no tokens with a signing secret"
        assert any(isinstance(t, str) and t for t in tokens)


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
