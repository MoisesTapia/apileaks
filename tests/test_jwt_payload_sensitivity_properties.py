# Feature: owasp-auth-modules-hardening, Property 24: Sensitive JWT-payload flagging requires corroboration
"""
Property-Based Tests for corroboration-gated JWT-payload sensitivity flagging.

**Feature: owasp-auth-modules-hardening, Property 24: Sensitive JWT-payload
flagging requires corroboration**

Property 24 (from design.md / Requirements 43.1, 43.2, 43.4, 48.3):
    *For all* JWT payload claims, ``JWTAttackEngine.inspect_payload_sensitivity``
    flags a claim as sensitive **if and only if** a credential/PII pattern match
    is corroborated by additional evidence — a sensitive field name, a known
    credential prefix (e.g. ``sk_``), or a high-entropy check. A bare pattern
    match with no corroboration is NEVER flagged, and every flagged claim's raw
    value is redacted (never echoed verbatim) in the resulting finding.

These tests drive the real ``JWTAttackEngine.inspect_payload_sensitivity`` in
``utils.jwt_attack_engine``, which reuses the Req-12 corroboration discipline
from ``PropertyLevelAuthModule._contains_sensitive_data``. Tokens are built with
the module's own ``encode_jwt`` helper across Hypothesis-generated payloads that
mix:

* corroborated claims — self-sufficient value patterns (email/SSN/credit-card/
  ``sk_`` keys), known credential prefixes (``pk_``/``AKIA``/``ghp_``/``xoxb-``),
  credential-shape values in a sensitive-named field, and high-entropy blobs; and
* non-corroborated claims — long credential-shape strings with LOW entropy sitting
  in a NON-sensitive field (a bare pattern match with no corroboration).

The engine's constructor requires an ``http_engine``; sensitivity inspection is
fully offline, so a lightweight stub whose ``request`` is never called satisfies
it without mocking behavior.

Requirements covered: 43.1, 43.2, 43.4, 48.3.

**Validates: Requirements 43.1, 43.2, 43.4, 48.3**
"""

import string
import time

from hypothesis import given, settings, strategies as st

from core.config import Severity
from utils.jwt_attack_engine import JWTAttackEngine
from utils.jwt_utils import encode_jwt


# ---------------------------------------------------------------------------
# Test double
# ---------------------------------------------------------------------------


class _UnusedHTTPEngine:
    """HTTP engine stub; payload-sensitivity inspection performs no HTTP.

    If ``request`` is ever invoked during these tests, fail loudly rather than
    silently pass.
    """

    async def request(self, method, url, **kwargs):  # pragma: no cover
        raise AssertionError(
            "inspect_payload_sensitivity must not perform HTTP requests")


# ---------------------------------------------------------------------------
# Fixtures / constants
# ---------------------------------------------------------------------------

TARGET_URL = "https://target.example/api/account"
SIGNING_SECRET = "operator-recovered-signing-key-42"
HEADER = {"alg": "HS256", "typ": "JWT"}


def _make_base_token():
    now = int(time.time())
    payload = {"sub": "user-123", "role": "user", "iat": now, "exp": now + 3600}
    return encode_jwt(HEADER, payload, SIGNING_SECRET)


BASE_TOKEN = _make_base_token()


def _make_engine():
    return JWTAttackEngine(
        target_url=TARGET_URL,
        original_token=BASE_TOKEN,
        http_engine=_UnusedHTTPEngine(),
        signing_secret=SIGNING_SECRET,
    )


# Field-name bases that DO NOT match any sensitive field pattern
# (``PropertyLevelAuthModule.SENSITIVE_FIELD_PATTERNS``). Appending "_<idx>"
# keeps them non-sensitive.
NON_SENSITIVE_BASES = ["data", "blob", "value", "content", "chunk", "segment",
                       "note", "meta"]

# Field-name bases that DO match a sensitive field pattern. Appending "_<idx>"
# preserves the sensitive substring, so they stay sensitive.
SENSITIVE_BASES = ["password", "api_key", "secret", "auth_token",
                   "credit_card", "session_key"]

_LOWER = string.ascii_lowercase
_ALNUM = string.ascii_letters + string.digits


# ---------------------------------------------------------------------------
# Value strategies
# ---------------------------------------------------------------------------

# Category A — self-sufficient value patterns (flagged regardless of field name).

@st.composite
def _email_values(draw):
    local = draw(st.text(alphabet=_LOWER, min_size=1, max_size=8))
    domain = draw(st.text(alphabet=_LOWER, min_size=1, max_size=8))
    return f"{local}@{domain}.com"


@st.composite
def _ssn_values(draw):
    d = st.text(alphabet=string.digits, min_size=1, max_size=1)
    part3 = "".join(draw(st.lists(d, min_size=3, max_size=3)))
    part2 = "".join(draw(st.lists(d, min_size=2, max_size=2)))
    part4 = "".join(draw(st.lists(d, min_size=4, max_size=4)))
    return f"{part3}-{part2}-{part4}"


@st.composite
def _credit_card_values(draw):
    d = st.text(alphabet=string.digits, min_size=1, max_size=1)
    return "".join(draw(st.lists(d, min_size=16, max_size=16)))


@st.composite
def _sk_key_values(draw):
    tail = draw(st.text(alphabet=_ALNUM, min_size=20, max_size=32))
    return f"sk_{tail}"


SELF_SUFFICIENT_VALUES = st.one_of(
    _email_values(), _ssn_values(), _credit_card_values(), _sk_key_values(),
)


# Category B — known credential prefixes (self-sufficient via prefix check).

@st.composite
def _prefixed_values(draw):
    prefix = draw(st.sampled_from(["pk_", "AKIA", "ghp_", "xoxb-"]))
    tail = draw(st.text(alphabet=_ALNUM, min_size=8, max_size=24))
    return f"{prefix}{tail}"


# Category C — credential-SHAPE value (32+ chars) with NO self-sufficient match
# and low/arbitrary entropy; only corroborated by a SENSITIVE field name.

@st.composite
def _shape_values(draw):
    return draw(st.text(alphabet=_LOWER, min_size=32, max_size=48))


# Category D — high-entropy credential-shape blob. Built from DISTINCT
# alphanumeric characters (>= 32), so Shannon entropy is >= log2(32) = 5 bits/char,
# well above the 3.5 threshold. No self-sufficient match, no credential prefix
# (distinct chars cannot repeat, so 'AKIA' is impossible; no '_'/'-' present).
@st.composite
def _high_entropy_values(draw):
    chars = draw(st.lists(st.sampled_from(_ALNUM), min_size=32, max_size=50,
                          unique=True))
    return "".join(chars)


# Non-corroborated — long credential-shape string (>= 32 letters) with LOW
# entropy (<= log2(4) = 2 bits/char) in a NON-sensitive field. A bare pattern
# match with no corroboration: NEVER flagged.
@st.composite
def _non_corroborated_values(draw):
    alphabet_size = draw(st.integers(min_value=2, max_value=4))
    alphabet = draw(st.lists(st.sampled_from(_LOWER), min_size=alphabet_size,
                             max_size=alphabet_size, unique=True))
    length = draw(st.integers(min_value=32, max_value=64))
    body = draw(st.lists(st.sampled_from(alphabet), min_size=length,
                         max_size=length))
    return "".join(body)


# ---------------------------------------------------------------------------
# Claim strategies: (is_flagged, base_field_pool, value)
# ---------------------------------------------------------------------------


@st.composite
def _corroborated_claim(draw):
    """A claim that MUST be flagged, with its corroboration source varied."""
    kind = draw(st.sampled_from(
        ["self_sufficient", "prefix", "shape_in_sensitive_field",
         "high_entropy"]))
    if kind == "self_sufficient":
        return (True, NON_SENSITIVE_BASES, draw(SELF_SUFFICIENT_VALUES))
    if kind == "prefix":
        return (True, NON_SENSITIVE_BASES, draw(_prefixed_values()))
    if kind == "shape_in_sensitive_field":
        # Corroborated by the sensitive field NAME, not the value alone.
        return (True, SENSITIVE_BASES, draw(_shape_values()))
    # high_entropy: corroborated by the entropy check, in a non-sensitive field.
    return (True, NON_SENSITIVE_BASES, draw(_high_entropy_values()))


@st.composite
def _non_corroborated_claim(draw):
    """A claim that MUST NOT be flagged (bare pattern match, no corroboration)."""
    return (False, NON_SENSITIVE_BASES, draw(_non_corroborated_values()))


@st.composite
def _sensitivity_scenarios(draw):
    """Build a payload mixing corroborated and non-corroborated claims.

    Returns ``(payload, expected_flagged_fields, raw_values_by_field)`` where
    ``expected_flagged_fields`` is exactly the set of fields the engine must
    flag, and ``raw_values_by_field`` maps every flagged field to its raw secret
    (for the redaction assertion).
    """
    corroborated = draw(st.lists(_corroborated_claim(), min_size=1, max_size=4))
    non_corroborated = draw(
        st.lists(_non_corroborated_claim(), min_size=1, max_size=4))

    payload = {}
    expected_flagged = set()
    raw_values = {}
    idx = 0

    for is_flagged, base_pool, value in corroborated + non_corroborated:
        base = base_pool[idx % len(base_pool)]
        field = f"{base}_{idx}"
        payload[field] = value
        if is_flagged:
            expected_flagged.add(field)
            raw_values[field] = value
        idx += 1

    return payload, expected_flagged, raw_values


# ---------------------------------------------------------------------------
# Property 24
# ---------------------------------------------------------------------------


# Feature: owasp-auth-modules-hardening, Property 24: Sensitive JWT-payload flagging requires corroboration
@settings(max_examples=150)
@given(_sensitivity_scenarios())
def test_payload_sensitivity_flagging_requires_corroboration(scenario):
    """A claim is flagged iff a pattern match is corroborated; values redacted.

    **Validates: Requirements 43.1, 43.2, 43.4, 48.3**
    """
    payload, expected_flagged, raw_values = scenario
    engine = _make_engine()
    token = encode_jwt(HEADER, payload, SIGNING_SECRET)

    findings = engine.inspect_payload_sensitivity(token, scan_id="scan-prop24")

    # The finding's ``payload`` field is exactly "Field: <name>".
    prefix = "Field: "
    flagged_fields = set()
    for finding in findings:
        assert finding.payload.startswith(prefix)
        flagged_fields.add(finding.payload[len(prefix):])

    # iff: exactly the corroborated claims are flagged; bare pattern matches
    # (non-corroborated) are never flagged.
    assert flagged_fields == expected_flagged

    for finding in findings:
        # Every finding is a MEDIUM-severity API2 sensitive-payload finding.
        assert finding.category == "JWT_SENSITIVE_DATA_IN_PAYLOAD"
        assert finding.owasp_category == "API2"
        assert finding.severity == Severity.MEDIUM
        assert finding.scan_id == "scan-prop24"

        # Redaction (Req 43.4): the raw secret never appears verbatim.
        field = finding.payload[len(prefix):]
        raw = raw_values[field]
        assert raw not in finding.evidence
