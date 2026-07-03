# Feature: owasp-auth-modules-hardening, Property 9: Every AttackType has an executable generation path
"""
Property-Based Tests for JWT attack-vector executability.

**Feature: owasp-auth-modules-hardening, Property 9: Every AttackType has an
executable generation path**

Property 9 (from design.md / Requirements 15.3, 15.4):
    For every ``AttackType`` member, ``JWTAttackEngine.generate_token``
    returns a non-empty list containing at least one non-empty token string
    when the vector is exercised under an engine that satisfies its documented
    precondition, and every member is covered by an executable generation path
    (the dispatch table in ``generate_token``). No vector is silently
    unimplemented. Most vectors are executable from any HMAC base token; the
    ECDSA-only PSYCHIC_SIGNATURE vector requires an ES* base token (Req 59.2)
    and CLAIM_FUZZING requires an operator-supplied fuzz target/values (Req 63.1).

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
from cryptography.hazmat.primitives.asymmetric import ec

from utils.jwt_attack_engine import JWTAttackEngine
from utils.jwt_attack_models import AttackType
from utils.jwt_utils import ES_CURVES, encode_jwt, encode_jwt_ecdsa, generate_rsa_keypair


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


# A single fixed EC private key reused across examples: PSYCHIC_SIGNATURE is an
# ECDSA-only vector (CVE-2022-21449), so its executable path requires an ES*
# base token. Generating one key once keeps the property fast without narrowing
# the input space (the payload still varies per example).
_EC_PRIVATE_KEY = ec.generate_private_key(ES_CURVES["ES256"]())


@st.composite
def es_base_tokens(draw):
    """Build a valid ES256-signed base JWT (for the ECDSA-only psychic vector)."""
    payload = draw(base_payloads())
    header = {"alg": "ES256", "typ": "JWT"}
    return encode_jwt_ecdsa(header, payload, _EC_PRIVATE_KEY)


# Vectors with a documented precondition beyond "any HMAC base token":
#   * PSYCHIC_SIGNATURE needs an ECDSA base token (Property 35 / Req 59.2).
#   * CLAIM_FUZZING needs an operator-supplied fuzz target + values (Req 63.1).
#   * ALGORITHM_CONFUSION needs operator-supplied public-key material used as
#     the HMAC key (RS256->HS256 substitution).
# Every other vector is executable from a plain HMAC base token with no extra
# configuration. The Property 9 executability guarantee therefore holds when
# each vector is exercised under an engine that satisfies its precondition.
ECDSA_ONLY = {AttackType.PSYCHIC_SIGNATURE}
REQUIRES_FUZZ = {AttackType.CLAIM_FUZZING}
REQUIRES_PUBLIC_KEY = {AttackType.ALGORITHM_CONFUSION}
FUZZ_TARGET = "role"
FUZZ_VALUES = ("admin", "root", "superuser")

# A fixed RSA public key reused across examples as the confusion HMAC key.
_CONFUSION_PUBLIC_PEM = generate_rsa_keypair(2048)[1]


def _make_engine(base_token, signing_secret=None, fuzz_target=None,
                 fuzz_values=None, public_key_material=None):
    return JWTAttackEngine(
        target_url="https://target.example/api",
        original_token=base_token,
        http_engine=_StubHTTPEngine(),
        signing_secret=signing_secret,
        fuzz_target=fuzz_target,
        fuzz_values=fuzz_values,
        public_key_material=public_key_material,
    )


def _engine_for(attack_type, hmac_token, es_token, *, signing_secret=None):
    """Build an engine configured to satisfy ``attack_type``'s precondition.

    ECDSA-only vectors get an ES* base token; fuzzing vectors get a configured
    fuzz target/values; algorithm-confusion gets public-key material; every
    other vector uses the plain HMAC base token.
    """
    if attack_type in ECDSA_ONLY:
        return _make_engine(es_token, signing_secret=signing_secret)
    if attack_type in REQUIRES_FUZZ:
        return _make_engine(hmac_token, signing_secret=signing_secret,
                            fuzz_target=FUZZ_TARGET, fuzz_values=list(FUZZ_VALUES))
    if attack_type in REQUIRES_PUBLIC_KEY:
        return _make_engine(hmac_token, signing_secret=signing_secret,
                            public_key_material=_CONFUSION_PUBLIC_PEM)
    return _make_engine(hmac_token, signing_secret=signing_secret)


def _fully_capable_engine(es_token, signing_secret=None):
    """An engine whose base token + config satisfy EVERY vector at once.

    An ES256 base token supports the ECDSA-only psychic vector, configuring a
    fuzz target/values supports CLAIM_FUZZING, and public-key material supports
    ALGORITHM_CONFUSION; every other vector is executable from an ES256 base
    token too, so ``generate_all_tokens`` yields a non-empty list for every
    member.
    """
    return _make_engine(es_token, signing_secret=signing_secret,
                        fuzz_target=FUZZ_TARGET, fuzz_values=list(FUZZ_VALUES),
                        public_key_material=_CONFUSION_PUBLIC_PEM)


# ---------------------------------------------------------------------------
# Property 9 (core): every AttackType yields at least one non-empty token
# ---------------------------------------------------------------------------


@settings(max_examples=200)
@given(hmac_token=base_tokens(), es_token=es_base_tokens())
def test_every_attack_type_generates_a_nonempty_token(hmac_token, es_token):
    """For every ``AttackType`` member, ``generate_token`` returns a non-empty
    list with at least one non-empty token string, when the vector is exercised
    under an engine that satisfies its documented precondition.

    Most vectors are executable from any HMAC base token; the ECDSA-only psychic
    vector uses an ES* base token and CLAIM_FUZZING uses a configured fuzz
    target/values (see ``_engine_for``). Driven across varied payloads so the
    executable-path guarantee holds for any valid base token, not a fixed one.

    **Validates: Requirements 15.3, 15.4**
    """
    members = list(AttackType)
    # Guard against a vector being added without an executable generation path:
    # the dispatch table must cover exactly the enum members.
    assert set(_fully_capable_engine(es_token).generate_all_tokens().keys()) == set(members)

    for attack_type in members:
        engine = _engine_for(attack_type, hmac_token, es_token)
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
@given(es_token=es_base_tokens())
def test_generate_all_tokens_covers_every_attack_type(es_token):
    """``generate_all_tokens`` returns an entry for every ``AttackType`` and each
    entry is a non-empty list of non-empty tokens.

    This pins the "single generation path per vector" guarantee: no member maps
    to a missing/empty generator. It uses a fully-capable engine (ES256 base
    token + configured fuzz target/values) so every vector's precondition is
    satisfied in a single ``generate_all_tokens`` call.

    **Validates: Requirements 15.3, 15.4**
    """
    engine = _fully_capable_engine(es_token)

    all_tokens = engine.generate_all_tokens()

    # Every enum member is present as a key.
    assert set(all_tokens.keys()) == set(AttackType)

    for attack_type, tokens in all_tokens.items():
        assert tokens, f"{attack_type} has no executable generation path"
        assert all(isinstance(t, str) and t for t in tokens), (
            f"{attack_type} produced an empty token")


# ---------------------------------------------------------------------------
# Property 9 (signing-secret invariance): path stays executable with/without key
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(hmac_token=base_tokens(), es_token=es_base_tokens(),
       signing_secret=st.text(min_size=1, max_size=32))
def test_executable_path_holds_with_signing_secret(hmac_token, es_token, signing_secret):
    """Every vector remains executable whether or not an operator signing secret
    is supplied (signature-requiring vectors use the key; key-less vectors do
    not), so the executability guarantee is independent of key availability.

    Each vector is exercised under an engine that satisfies its precondition
    (ES* base token for the ECDSA-only psychic vector, configured fuzz
    target/values for CLAIM_FUZZING), with the signing secret threaded through.

    **Validates: Requirements 15.3, 15.4**
    """
    for attack_type in AttackType:
        engine = _engine_for(attack_type, hmac_token, es_token,
                             signing_secret=signing_secret)
        tokens = engine.generate_token(attack_type)
        assert tokens, f"{attack_type} produced no tokens with a signing secret"
        assert any(isinstance(t, str) and t for t in tokens)


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
