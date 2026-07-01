# Feature: owasp-auth-modules-hardening, Property 3: JWT decode → encode → decode round-trip
"""
Property-Based Tests for the JWT decode/encode round-trip.

**Feature: owasp-auth-modules-hardening, Property 3: JWT decode → encode →
decode round-trip**

Property 3 (from design.md):
    For all valid header/payload structures, ``decode_jwt`` → ``encode_jwt`` →
    ``decode_jwt`` yields an equivalent header and payload.

These tests drive the real ``encode_jwt`` / ``decode_jwt`` helpers in
``utils.jwt_utils``. A header and payload are generated with Hypothesis, signed
into a token with a fixed secret, then run through decode → encode → decode.
The header and payload produced by the two decode passes must be equal.

Requirements covered: 24.3.

**Validates: Requirements 24.3**
"""

from hypothesis import given, settings, strategies as st

from utils.jwt_utils import decode_jwt, encode_jwt


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# A fixed secret used to sign every generated token.
SECRET = "round-trip-secret"

# Valid HMAC algorithms understood by encode_jwt/verify paths.
VALID_ALGS = st.sampled_from(["HS256", "HS384", "HS512"])

# JSON-serializable scalar values whose Python identity survives a JSON
# round-trip exactly (text, bounded ints, bools, None). Floats are intentionally
# excluded because values such as NaN/Infinity are not representable in strict
# JSON and would not compare equal after a round-trip.
json_scalars = st.one_of(
    st.text(max_size=40),
    st.integers(min_value=-(10 ** 12), max_value=10 ** 12),
    st.booleans(),
    st.none(),
)

# JSON-serializable values: scalars, flat lists of scalars, and flat string-keyed
# objects of scalars. This exercises nested structures while keeping every value
# stable across a JSON round-trip.
json_values = st.recursive(
    json_scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(st.text(min_size=1, max_size=20), children, max_size=5),
    ),
    max_leaves=10,
)

# Payloads are arbitrary string-keyed JSON objects.
payloads = st.dictionaries(st.text(min_size=1, max_size=20), json_values, max_size=6)

# Headers are string-keyed JSON objects that always carry a valid ``alg``.
extra_header_fields = st.dictionaries(
    st.text(min_size=1, max_size=20).filter(lambda k: k not in ("alg", "typ")),
    json_values,
    max_size=4,
)


@st.composite
def headers(draw):
    header = draw(extra_header_fields)
    header["alg"] = draw(VALID_ALGS)
    header["typ"] = "JWT"
    return header


# ---------------------------------------------------------------------------
# Property 3: decode → encode → decode round-trip
# ---------------------------------------------------------------------------


@settings(max_examples=200)
@given(header=headers(), payload=payloads)
def test_jwt_decode_encode_decode_roundtrip(header, payload):
    """decode → encode → decode yields an equivalent header and payload.

    **Validates: Requirements 24.3**
    """
    # Produce an initial valid token from the generated header/payload.
    token = encode_jwt(dict(header), dict(payload), secret=SECRET)

    # First decode establishes the reference header/payload.
    first = decode_jwt(token)

    # Re-encode the decoded header/payload, then decode again.
    reencoded = encode_jwt(dict(first["header"]), dict(first["payload"]), secret=SECRET)
    second = decode_jwt(reencoded)

    # The header and payload must be equivalent across the round-trip.
    assert first["header"] == second["header"]
    assert first["payload"] == second["payload"]

    # Re-encoding identical structures with the same secret is deterministic,
    # so the full tokens (including signature) must also match.
    assert token == reencoded
