# Feature: owasp-auth-modules-hardening, Property 37: Timestamp tampering preserves every component except the targeted time claim and the recomputed signature
"""
Property-Based Tests for the JWT TIMESTAMP_TAMPERING vector.

**Feature: owasp-auth-modules-hardening, Property 37: Timestamp tampering
preserves every component except the targeted time claim and the recomputed
signature**

Property 37 (from design.md / Requirements 64.1, 64.2, 69.5):
    For all validly-signed base tokens and all tamper variants
    (``exp`` -> past, ``exp`` -> far-future, ``nbf`` -> future,
    ``iat`` -> future), ``JWTAttackEngine._generate_timestamp_tamper`` produces
    one validly-signed token per variant that:

      (a) differs from the base payload in EXACTLY the one targeted time claim
          (every other payload claim and the whole header are preserved),
      (b) covers exactly the four expected variants, and
      (c) carries a signature that verifies under the engine's signing key over
          the tampered payload.

The test drives the real ``JWTAttackEngine`` in ``utils.jwt_attack_engine``.
A valid HMAC-signed base token is built with Hypothesis-generated
header/payload structures using the module's own ``encode_jwt`` helper, and the
engine is constructed with the matching ``signing_secret`` so the recomputed
signature verifies. Token generation is fully offline; the constructor's
``http_engine`` is satisfied with a lightweight stub whose ``request`` is never
called during generation.

Requirements covered: 64.1, 64.2, 69.5.

**Validates: Requirements 64.1, 64.2, 69.5**
"""

import time

from hypothesis import given, settings, strategies as st

from utils.jwt_attack_engine import JWTAttackEngine
from utils.jwt_utils import decode_jwt, encode_jwt, verify_hmac_secret


# ---------------------------------------------------------------------------
# Test double
# ---------------------------------------------------------------------------


class _StubHTTPEngine:
    """Minimal HTTP engine stub.

    ``_generate_timestamp_tamper`` performs no HTTP, so ``request`` should never
    be invoked during these tests. If it ever is, fail loudly.
    """

    async def request(self, method, url, **kwargs):  # pragma: no cover
        raise AssertionError(
            "timestamp tamper generation must not perform HTTP requests")


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Header algorithm for the base token. The engine re-signs tampered tokens with
# ``encode_jwt``, which HMACs with SHA-256; ``verify_hmac_secret`` selects its
# digest from the header ``alg``. The two agree on ``HS256``, so the base token
# declares ``HS256`` for the signature-verification leg of the property to hold.
VALID_ALGS = st.just("HS256")

# Non-empty signing secrets (the engine signs the tampered payload with this).
signing_secrets = st.text(min_size=1, max_size=32)

# Identity claim values (strings and ints both appear in the wild).
identity_values = st.one_of(
    st.text(min_size=1, max_size=24),
    st.integers(min_value=0, max_value=10 ** 9),
)

role_values = st.sampled_from(["user", "guest", "member", "editor", "viewer"])

# Base timestamps deliberately constrained to the DISTANT PAST relative to the
# current wall clock so they can never coincide with the runtime-computed tamper
# values (now-3600, now+3600, now+~10y). This keeps "the targeted claim actually
# differs" true even when the base payload already carries exp/nbf/iat.
base_timestamps = st.integers(min_value=1_000_000_000, max_value=1_500_000_000)

# Reserved time-claim keys handled specially by the vector.
_TIME_CLAIMS = ("exp", "nbf", "iat")


@st.composite
def base_payloads(draw):
    """Generate a realistic JWT payload varying identity/role/time claims.

    Every field is optional so the generator explores payloads that do and do
    not already carry ``exp``/``nbf``/``iat`` — the claims the vector tampers
    with — plus arbitrary extra claims to broaden the input space.
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
        payload["iat"] = draw(base_timestamps)
    if draw(st.booleans()):
        payload["exp"] = draw(base_timestamps)
    if draw(st.booleans()):
        payload["nbf"] = draw(base_timestamps)
    # Arbitrary extra claims (never colliding with the reserved names above).
    extra = draw(st.dictionaries(
        st.text(min_size=1, max_size=10).filter(
            lambda k: k not in ("sub", "user_id", "username", "role",
                                 "iat", "exp", "nbf")),
        st.one_of(st.text(max_size=16),
                  st.integers(min_value=-1000, max_value=1000),
                  st.booleans()),
        max_size=3,
    ))
    payload.update(extra)
    return payload


@st.composite
def base_specs(draw):
    """Yield ``(base_token, base_header, base_payload, signing_secret)``.

    The base token is a valid HMAC-signed JWT; the engine is later constructed
    with the same ``signing_secret`` so its recomputed signatures verify.
    """
    alg = draw(VALID_ALGS)
    secret = draw(signing_secrets)
    payload = draw(base_payloads())
    header = {"alg": alg, "typ": "JWT"}
    token = encode_jwt(header, payload, secret)
    # Decode back so we compare against the canonical round-tripped structures.
    decoded = decode_jwt(token)
    return token, decoded["header"], decoded["payload"], secret


def _make_engine(base_token, signing_secret):
    return JWTAttackEngine(
        target_url="https://target.example/api",
        original_token=base_token,
        http_engine=_StubHTTPEngine(),
        signing_secret=signing_secret,
    )


def _sole_changed_or_added_key(base_payload, produced_payload):
    """Return the single key that was added or whose value changed.

    Asserts that produced_payload equals base_payload except for exactly one
    key (added or value-changed) and that NO base key was removed. Returns that
    single key.
    """
    # No base claim may be dropped.
    assert set(base_payload).issubset(set(produced_payload)), (
        "a base payload claim was removed by timestamp tampering")

    changed = [
        k for k in produced_payload
        if k not in base_payload or produced_payload[k] != base_payload[k]
    ]
    assert len(changed) == 1, (
        f"expected exactly one changed/added claim, got {changed}")
    return changed[0]


# ---------------------------------------------------------------------------
# Property 37: exactly-one-claim tampering, full preservation, valid signature
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(spec=base_specs())
def test_timestamp_tamper_preserves_all_but_targeted_claim(spec):
    """For all validly-signed base tokens, ``_generate_timestamp_tamper``
    produces exactly the four expected variants, each modifying only its one
    targeted time claim, preserving the header and every other payload claim,
    and carrying a signature that verifies under the signing key.

    **Validates: Requirements 64.1, 64.2, 69.5**
    """
    base_token, base_header, base_payload, signing_secret = spec
    engine = _make_engine(base_token, signing_secret)

    # Bracket the vector's internal ``time.time()`` so we can classify the
    # produced tamper values without depending on an exact clock reading.
    now_lo = int(time.time())
    tokens = engine._generate_timestamp_tamper()
    now_hi = int(time.time())

    # (b) Exactly the four expected variants are produced.
    assert len(tokens) == 4, f"expected 4 tamper tokens, got {len(tokens)}"

    far = 60 * 60 * 24 * 3650  # ~10 years, matching the production constant.
    observed_variants = set()

    for token in tokens:
        decoded = decode_jwt(token)
        produced_header = decoded["header"]
        produced_payload = decoded["payload"]

        # (a) Header preserved byte-for-structure and only one payload claim
        # differs from the base payload.
        assert produced_header == base_header, "header was not preserved"
        claim = _sole_changed_or_added_key(base_payload, produced_payload)
        assert claim in _TIME_CLAIMS, (
            f"tampered claim {claim!r} is not a time claim")

        value = produced_payload[claim]
        assert isinstance(value, int)

        # Classify the variant from the (claim, value) pair.
        if claim == "exp" and now_lo - 3600 <= value <= now_hi - 3600:
            variant = "exp_past"
        elif claim == "exp" and now_lo + far <= value <= now_hi + far:
            variant = "exp_far_future"
        elif claim == "nbf" and now_lo + 3600 <= value <= now_hi + 3600:
            variant = "nbf_future"
        elif claim == "iat" and now_lo + 3600 <= value <= now_hi + 3600:
            variant = "iat_future"
        else:
            raise AssertionError(
                f"unexpected tamper variant: claim={claim!r} value={value}")
        observed_variants.add(variant)

        # (c) The recomputed signature verifies under the engine's signing key
        # over the tampered payload.
        assert verify_hmac_secret(token, signing_secret), (
            f"signature did not verify for variant {variant}")

    assert observed_variants == {
        "exp_past", "exp_far_future", "nbf_future", "iat_future"
    }, f"variant coverage mismatch: {observed_variants}"
