# Feature: owasp-auth-modules-hardening, Property 4: Brute-secret recovers a secret iff its signature verifies
"""
Property-Based Tests for JWT brute-secret signature verification.

**Feature: owasp-auth-modules-hardening, Property 4: Brute-secret recovers a
secret iff its signature verifies**

Property 4 (from design.md / Requirement 16):
    ``verify_hmac_secret(token, candidate)`` reports a recovered secret
    (returns ``True``) IF AND ONLY IF the HMAC computed over the ORIGINAL raw
    ``header.payload`` segments (using the algorithm declared in the token
    header) equals the token's ORIGINAL signature segment.

These tests drive the real ``verify_hmac_secret`` helper in
``utils.jwt_utils``. Tokens are constructed using the module's own
``encode_jwt`` encoder (HS256) and the module's ``base64url_encode`` helper
combined with the standard-library HMAC primitives for HS384/HS512 (which the
module's ``verify_hmac_secret`` supports). No network or mocking is involved.

Requirements covered: 16.1, 16.3, 24.4.
"""

import hashlib
import hmac
import json

import pytest
from hypothesis import given, settings, strategies as st

from utils.jwt_utils import (
    base64url_decode,
    base64url_encode,
    encode_jwt,
    verify_hmac_secret,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# HMAC algorithms supported by verify_hmac_secret and their digest functions.
_DIGESTMODS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def _sign_token(header, payload, secret, alg):
    """Construct an HMAC-signed JWT for ``alg`` using the module's encoder.

    HS256 tokens are produced by the module's ``encode_jwt`` (its native
    encoder). HS384/HS512 tokens are produced with the module's
    ``base64url_encode`` plus the matching HMAC digest, mirroring exactly how a
    real HS384/HS512 token's ``header.payload`` segments are signed. In all
    cases the signature is the HMAC over the raw ``header.payload`` string.
    """
    header = dict(header)
    header["alg"] = alg
    header.setdefault("typ", "JWT")

    if alg == "HS256":
        return encode_jwt(header, dict(payload), secret)

    header_encoded = base64url_encode(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    )
    payload_encoded = base64url_encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )
    signing_input = f"{header_encoded}.{payload_encoded}"
    signature = hmac.new(
        secret.encode("utf-8"), signing_input.encode("utf-8"), _DIGESTMODS[alg]
    ).digest()
    return f"{signing_input}.{base64url_encode(signature)}"


def _independent_signature_matches(token, candidate):
    """Reference oracle for Property 4, computed independently of the SUT.

    Recomputes the HMAC over the token's ORIGINAL raw ``header.payload``
    segments with ``candidate`` and compares to the ORIGINAL signature segment.
    Returns True iff they match. Non-HMAC / unsupported algorithms and
    malformed tokens are treated as "not recovered".
    """
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        header = json.loads(base64url_decode(parts[0]).decode("utf-8"))
    except Exception:
        return False
    digestmod = _DIGESTMODS.get(str(header.get("alg", "")).upper())
    if digestmod is None:
        return False
    signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
    computed = base64url_encode(
        hmac.new(candidate.encode("utf-8"), signing_input, digestmod).digest()
    )
    return hmac.compare_digest(computed, parts[2])


# Secrets are non-empty printable text. Kept short so collisions are effectively
# impossible while the input space still exercises varied byte content.
secrets = st.text(min_size=1, max_size=32)
algorithms = st.sampled_from(["HS256", "HS384", "HS512"])

# Small JSON-serializable header/payload structures.
json_scalars = st.one_of(
    st.integers(min_value=-(10 ** 6), max_value=10 ** 6),
    st.text(max_size=20),
    st.booleans(),
)
payloads = st.dictionaries(st.text(min_size=1, max_size=12), json_scalars, max_size=5)


# ---------------------------------------------------------------------------
# Property 4 (core): recovered IFF the candidate's signature matches
# ---------------------------------------------------------------------------


@settings(max_examples=200)
@given(
    true_secret=secrets,
    candidate=secrets,
    alg=algorithms,
    payload=payloads,
)
def test_recovered_iff_signature_verifies(true_secret, candidate, alg, payload):
    """``verify_hmac_secret`` recovers a secret IFF the candidate's HMAC over
    the original ``header.payload`` equals the original signature.

    The right-hand side of the "iff" is computed by an independent reference
    oracle (not the implementation under test), so this genuinely pins the
    biconditional rather than restating the code.

    **Validates: Requirements 16.1, 16.3, 24.4**
    """
    token = _sign_token({}, payload, true_secret, alg)

    recovered = verify_hmac_secret(token, candidate)
    expected = _independent_signature_matches(token, candidate)

    assert recovered is expected


# ---------------------------------------------------------------------------
# Property 4 (forward direction): the true secret is always recovered
# ---------------------------------------------------------------------------


@settings(max_examples=200)
@given(
    true_secret=secrets,
    alg=algorithms,
    payload=payloads,
)
def test_true_secret_is_always_recovered(true_secret, alg, payload):
    """Signing with ``true_secret`` and verifying with the SAME secret always
    reports recovered (the signature verifies).

    **Validates: Requirements 16.1, 16.3, 24.4**
    """
    token = _sign_token({}, payload, true_secret, alg)
    assert verify_hmac_secret(token, true_secret) is True


# ---------------------------------------------------------------------------
# Property 4 (reverse direction): a wrong secret is never reported recovered
# ---------------------------------------------------------------------------


@settings(max_examples=200)
@given(
    true_secret=secrets,
    candidate=secrets,
    alg=algorithms,
    payload=payloads,
)
def test_wrong_secret_is_not_recovered(true_secret, candidate, alg, payload):
    """A candidate that differs from the signing secret does not verify (an
    HMAC collision across two distinct short secrets is cryptographically
    infeasible), so it is never reported recovered.

    **Validates: Requirements 16.1, 16.3, 24.4**
    """
    if candidate == true_secret:
        return  # only exercise genuinely-different candidates here

    token = _sign_token({}, payload, true_secret, alg)
    assert verify_hmac_secret(token, candidate) is False


# ---------------------------------------------------------------------------
# Property 4 (guard): malformed tokens and non-HMAC algorithms report False
# ---------------------------------------------------------------------------


@settings(max_examples=200)
@given(
    blob=st.text(max_size=40).filter(lambda s: s.count(".") != 2),
    candidate=secrets,
)
def test_malformed_token_is_not_recovered(blob, candidate):
    """Tokens that are not three dot-separated segments never report recovered.

    **Validates: Requirements 16.1, 16.3**
    """
    assert verify_hmac_secret(blob, candidate) is False


@settings(max_examples=200)
@given(
    secret=secrets,
    payload=payloads,
    alg=st.sampled_from(["none", "RS256", "RS384", "ES256", "PS256", "HS999"]),
)
def test_non_hmac_algorithms_are_not_recovered(secret, payload, alg):
    """A token declaring a non-HMAC (or unsupported) algorithm cannot be
    recovered as an HMAC secret, regardless of candidate.

    The signature bytes are irrelevant here; the header ``alg`` alone must
    cause ``verify_hmac_secret`` to decline.

    **Validates: Requirements 16.1, 16.3**
    """
    header = {"alg": alg, "typ": "JWT"}
    header_encoded = base64url_encode(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    )
    payload_encoded = base64url_encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )
    token = f"{header_encoded}.{payload_encoded}.{base64url_encode(b'sig')}"

    assert verify_hmac_secret(token, secret) is False


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
