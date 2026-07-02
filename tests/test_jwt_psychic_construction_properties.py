# Feature: owasp-auth-modules-hardening, Property 35: ECDSA and Psychic Signature construction modifies only the signature segment
"""
Property-Based Tests for ECDSA / Psychic Signature construction segment-isolation.

**Feature: owasp-auth-modules-hardening, Property 35: ECDSA and Psychic Signature
construction modifies only the signature segment**

Property 35 (from design.md / Requirements 59.1, 59.2, 69.3):
    For all ES256/ES384/ES512 base tokens,
    ``JWTAttackEngine._generate_psychic_signature`` preserves the header segment
    (``parts[0]``) and payload segment (``parts[1]``) byte-for-byte and replaces
    ONLY the signature segment (``parts[2]``) with the base64url of
    ``ES_SIG_BYTES[alg]`` zero bytes — the JOSE null ``(r == 0, s == 0)``
    encoding (CVE-2022-21449). Symmetrically, ECDSA re-signing
    (``encode_jwt_ecdsa``) over the same header/payload changes only the
    signature segment relative to the source header/payload.

These tests drive the real ``JWTAttackEngine._generate_psychic_signature`` in
``utils.jwt_attack_engine``. Valid ES* base tokens are built with
Hypothesis-generated header/payload structures using the module's own
``encode_jwt_ecdsa`` helper, so the property is exercised across varied
identity/role/expiration claims, extra header fields, and all three ECDSA
algorithms. Construction is fully offline; the constructor's ``http_engine`` is
satisfied with a lightweight stub exposing an async ``request`` (never called),
so no network or behavioural mocking is involved.

Requirements covered: 59.1, 59.2, 69.3.

**Validates: Requirements 59.1, 59.2**
"""

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from hypothesis import given, settings, strategies as st

from utils.jwt_attack_engine import JWTAttackEngine
from utils.jwt_utils import (
    ES_CURVES,
    ES_SIG_BYTES,
    encode_jwt_ecdsa,
    psychic_signature_segment,
)


# ---------------------------------------------------------------------------
# Test double
# ---------------------------------------------------------------------------


class _StubHTTPEngine:
    """Minimal HTTP engine stub.

    Psychic-signature construction performs no HTTP, so ``request`` must never be
    invoked during these tests. If it ever is, fail loudly rather than silently
    pass.
    """

    async def request(self, method, url, **kwargs):  # pragma: no cover
        raise AssertionError(
            "_generate_psychic_signature must not perform HTTP requests")


# ---------------------------------------------------------------------------
# Fixed EC private keys per algorithm
# ---------------------------------------------------------------------------

# Generate one EC private key per ECDSA algorithm ONCE and reuse it for every
# Hypothesis example. Fresh key generation per example would dominate runtime
# without broadening the input space (the property is about segment isolation,
# not the specific key material).
ES_ALGS = ("ES256", "ES384", "ES512")
_EC_PRIVATE_KEYS = {alg: ec.generate_private_key(ES_CURVES[alg]()) for alg in ES_ALGS}


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

identity_values = st.one_of(
    st.text(min_size=1, max_size=24),
    st.integers(min_value=0, max_value=10 ** 9),
)

role_values = st.sampled_from(
    ["user", "guest", "member", "editor", "viewer", "staff", "admin"])

timestamps = st.integers(min_value=1_000_000_000, max_value=2_000_000_000)


@st.composite
def base_payloads(draw):
    """Generate a realistic JWT payload varying identity/role/expiration claims."""
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
        st.one_of(st.text(max_size=16), st.integers(min_value=-1000, max_value=1000),
                  st.booleans()),
        max_size=3,
    ))
    payload.update(extra)
    return payload


@st.composite
def es_headers(draw, alg):
    """Generate an ES* header carrying the given alg plus optional extra fields."""
    header = {"alg": alg, "typ": "JWT"}
    if draw(st.booleans()):
        header["kid"] = draw(st.text(min_size=1, max_size=16))
    # Occasionally add an arbitrary extra header field to broaden the space.
    extra = draw(st.dictionaries(
        st.text(min_size=1, max_size=8).filter(
            lambda k: k not in ("alg", "typ", "kid")),
        st.one_of(st.text(max_size=12), st.integers(min_value=0, max_value=1000)),
        max_size=2,
    ))
    header.update(extra)
    return header


@st.composite
def es_base_tokens(draw):
    """Build a valid ECDSA-signed base JWT (ES256/ES384/ES512).

    Returns ``(alg, token)`` so tests can assert against the expected null-
    signature segment for that algorithm.
    """
    alg = draw(st.sampled_from(ES_ALGS))
    header = draw(es_headers(alg))
    payload = draw(base_payloads())
    token = encode_jwt_ecdsa(header, payload, _EC_PRIVATE_KEYS[alg])
    return alg, token


def _make_engine(base_token):
    return JWTAttackEngine(
        target_url="https://target.example/api",
        original_token=base_token,
        http_engine=_StubHTTPEngine(),
    )


# ---------------------------------------------------------------------------
# Property 35 (core): psychic construction changes only the signature segment
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(alg_token=es_base_tokens())
def test_psychic_signature_modifies_only_signature_segment(alg_token):
    """For any ES* base token, ``_generate_psychic_signature`` preserves the
    header and payload segments byte-for-byte and replaces ONLY the signature
    segment with the base64url of ``ES_SIG_BYTES[alg]`` zero bytes.

    **Validates: Requirements 59.1, 59.2**
    """
    alg, base_token = alg_token
    engine = _make_engine(base_token)

    base_parts = base_token.split(".")
    assert len(base_parts) == 3

    tokens = engine._generate_psychic_signature()

    # An ES* base token yields exactly one psychic token.
    assert isinstance(tokens, list)
    assert len(tokens) == 1
    psychic_parts = tokens[0].split(".")
    assert len(psychic_parts) == 3

    # Header segment preserved byte-for-byte.
    assert psychic_parts[0] == base_parts[0]
    # Payload segment preserved byte-for-byte.
    assert psychic_parts[1] == base_parts[1]

    # Signature segment replaced with the JOSE null (r == 0, s == 0) encoding.
    expected_sig = psychic_signature_segment(alg)
    assert psychic_parts[2] == expected_sig
    # And that segment is exactly base64url of ES_SIG_BYTES[alg] zero bytes.
    from utils.jwt_utils import base64url_encode
    assert psychic_parts[2] == base64url_encode(b"\x00" * ES_SIG_BYTES[alg])

    # The signature segment is the ONLY thing that changed relative to the base.
    assert psychic_parts[2] != base_parts[2]


# ---------------------------------------------------------------------------
# Property 35 (symmetric): ECDSA re-signing changes only the signature segment
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(alg_token=es_base_tokens())
def test_ecdsa_resigning_changes_only_signature_segment(alg_token):
    """Re-signing the same header/payload with ``encode_jwt_ecdsa`` produces a
    token whose header and payload segments match the source byte-for-byte,
    changing only the signature segment.

    **Validates: Requirements 59.1, 59.2**
    """
    alg, base_token = alg_token
    base_parts = base_token.split(".")
    assert len(base_parts) == 3

    # Re-sign the exact same header/payload the base token carries.
    from utils.jwt_utils import base64url_decode
    import json

    header = json.loads(base64url_decode(base_parts[0]).decode("utf-8"))
    payload = json.loads(base64url_decode(base_parts[1]).decode("utf-8"))

    resigned = encode_jwt_ecdsa(header, payload, _EC_PRIVATE_KEYS[alg])
    resigned_parts = resigned.split(".")
    assert len(resigned_parts) == 3

    # Header and payload segments are identical to the source.
    assert resigned_parts[0] == base_parts[0]
    assert resigned_parts[1] == base_parts[1]

    # The signature segment is the correct fixed width for the algorithm.
    assert len(base64url_decode(resigned_parts[2])) == ES_SIG_BYTES[alg]


# ---------------------------------------------------------------------------
# Property 35 (guard): non-ECDSA base tokens produce no psychic token
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(alg=st.sampled_from(["HS256", "HS384", "HS512"]), payload=base_payloads())
def test_non_ecdsa_base_token_yields_no_psychic_token(alg, payload):
    """A non-ECDSA base token has no valid null ``(r, s)`` encoding, so
    ``_generate_psychic_signature`` returns an empty list and modifies nothing.

    **Validates: Requirements 59.1, 59.2**
    """
    from utils.jwt_utils import encode_jwt

    base_token = encode_jwt({"alg": alg, "typ": "JWT"}, payload, "base-secret")
    engine = _make_engine(base_token)

    assert engine._generate_psychic_signature() == []


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
