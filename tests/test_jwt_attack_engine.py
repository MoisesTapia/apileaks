"""
Unit tests for the consolidated JWT Attack Engine (``utils.jwt_attack_engine``).

These are example-based unit tests (the property-based coverage lives in
``tests/test_jwt_attack_engine_properties.py``). They exercise the concrete,
observable behaviour of the engine's five responsibilities:

1. Per-``AttackType`` token generation (Req 24.1, 15.1-15.4):
   - signature-requiring vectors are HMAC-signed with the operator-supplied
     ``signing_secret`` (and NOT the literal "secret");
   - ``ALG_NONE`` produces ``alg=none`` unsigned tokens;
   - ``WEAK_SECRET`` re-signs the token with each wordlist candidate.
2. Vector -> Finding_Category mapping via ``_ATTACK_TYPE_TO_CATEGORY`` /
   ``jwt_assessment_to_finding`` with ``owasp_category='API2'`` (Req 18.4, 18.3).
3. Severity reconciliation via ``_SEVERITY_MAP`` (Req 18.1).
4. The 'no findings' result emitted by ``to_findings`` (Req 18.2).
5. Analyzer-based success with baseline-comparison evidence + confidence score
   driven through ``execute_attack`` / ``execute_all`` (Req 19.1, 19.3).

The engine is driven with a lightweight async HTTP stub exposing
``async request(method, url, **kwargs)`` returning a response object with
``status_code``/``headers``/``content``/``text``/``elapsed`` — the exact surface
the engine adapts — so no real network or behavioural mocking is involved.
"""

import time

import pytest

from core.config import Severity
from utils.findings import Finding, FindingsCollector
from utils.jwt_attack_engine import (
    JWTAttackEngine,
    jwt_assessment_to_finding,
    _SEVERITY_MAP,
    _ATTACK_TYPE_TO_CATEGORY,
    JWT_OWASP_CATEGORY,
    JWT_NO_FINDINGS_CATEGORY,
)
from utils.jwt_attack_models import (
    AttackConfiguration,
    AttackResult,
    AttackSession,
    AttackSummary,
    AttackType,
    BaselineResponse,
    RequestDetails,
    ResponseDetails,
    VulnerabilityAssessment,
    VulnerabilitySeverity,
)
from utils.jwt_utils import decode_jwt, encode_jwt, verify_hmac_secret


# ---------------------------------------------------------------------------
# Constants / fixtures
# ---------------------------------------------------------------------------

TARGET_URL = "https://target.example/api/account"

# The real secret the server would use. Deliberately NOT the literal "secret"
# so we can prove signature-requiring vectors sign with the operator key
# (Req 15.1) rather than the historic hardcoded fallback.
SIGNING_SECRET = "operator-recovered-signing-key-42"

# The base token the server originally issued (signed with SIGNING_SECRET).
BASE_SECRET = SIGNING_SECRET


def _make_base_token():
    """Build a realistic HS256 base token carrying identity/role/exp claims."""
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": "user-123",
        "user_id": 123,
        "username": "alice",
        "role": "user",
        "iat": now,
        "exp": now + 3600,
    }
    return encode_jwt(header, payload, BASE_SECRET)


BASE_TOKEN = _make_base_token()

# Signature-requiring vectors that MUST be HMAC-signed with the operator key
# for EVERY generated token. KID_INJECTION is handled separately because Req 44.1
# adds a predictable/empty-key path whose tokens are signed with the forced key.
SIGNED_VECTORS = [
    AttackType.JWKS_SPOOF,
    AttackType.INLINE_JWKS,
    AttackType.PRIVILEGE_ESCALATION,
    AttackType.USER_IMPERSONATION,
    AttackType.EXPIRATION_BYPASS,
]


# ---------------------------------------------------------------------------
# Async HTTP stub
# ---------------------------------------------------------------------------


class _StubResponse:
    """Minimal response object mirroring ``utils.http_client.Response``."""

    def __init__(self, status_code, body="", headers=None, elapsed=0.01):
        self.status_code = status_code
        self.text = body
        self.content = body.encode("utf-8")
        self.headers = headers or {"Content-Type": "application/json"}
        self.elapsed = elapsed


class _StubHTTPEngine:
    """Async HTTP engine double.

    Distinguishes the baseline request (issued with the *original* token) from
    attack requests by inspecting the ``Authorization`` header, then returns the
    configured baseline vs attack responses. Records every call for assertions.
    """

    def __init__(self, original_token, baseline_response, attack_response):
        self._original_token = original_token
        self._baseline_response = baseline_response
        self._attack_response = attack_response
        self.calls = []

    async def request(self, method, url, **kwargs):
        headers = kwargs.get("headers", {}) or {}
        auth = headers.get("Authorization", "")
        self.calls.append((method, url, auth))
        if auth == f"Bearer {self._original_token}":
            return self._baseline_response
        return self._attack_response


class _UnusedHTTPEngine:
    """HTTP stub for tests that never issue requests (generation/mapping)."""

    async def request(self, method, url, **kwargs):  # pragma: no cover
        raise AssertionError("no HTTP request expected in this test")


def _make_engine(http_engine=None, signing_secret=SIGNING_SECRET,
                 weak_secrets=None, safe_mode=False):
    return JWTAttackEngine(
        target_url=TARGET_URL,
        original_token=BASE_TOKEN,
        http_engine=http_engine or _UnusedHTTPEngine(),
        signing_secret=signing_secret,
        safe_mode=safe_mode,
        weak_secrets=weak_secrets,
    )


# ===========================================================================
# 1. Per-AttackType token generation (Req 24.1, 15.1-15.4)
# ===========================================================================


def test_every_attack_type_generates_nonempty_tokens():
    """Each always-on vector yields at least one non-empty token (Req 24.1).

    The three conditional vectors are excluded from the always-on guarantee
    because they legitimately produce no tokens for this engine configuration
    (asserted separately below):

    * ``PSYCHIC_SIGNATURE`` applies only when the base token uses an ECDSA
      algorithm (Req 59.2); the HS256 base token here yields no token.
    * ``CLAIM_FUZZING`` requires an operator-supplied ``fuzz_target`` +
      ``fuzz_values`` (Req 63.1); with neither configured it yields no token.
    * ``ALGORITHM_CONFUSION`` requires operator-supplied ``public_key_material``
      to use as the HMAC key; with none configured it yields no token.
    """
    engine = _make_engine()
    conditional = {
        AttackType.PSYCHIC_SIGNATURE,
        AttackType.CLAIM_FUZZING,
        AttackType.ALGORITHM_CONFUSION,
    }
    for attack_type in AttackType:
        if attack_type in conditional:
            continue
        tokens = engine.generate_token(attack_type)
        assert isinstance(tokens, list)
        assert tokens, f"{attack_type} produced no tokens"
        assert all(isinstance(t, str) and t for t in tokens), (
            f"{attack_type} produced an empty token")


def test_conditional_vectors_yield_no_tokens_without_their_preconditions():
    """PSYCHIC_SIGNATURE (non-ECDSA base), CLAIM_FUZZING (no config), and
    ALGORITHM_CONFUSION (no public key) all yield []."""
    engine = _make_engine()
    # HS256 base token => no ECDSA psychic-signature token (Req 59.2).
    assert engine.generate_token(AttackType.PSYCHIC_SIGNATURE) == []
    # No public key material configured => no algorithm-confusion token.
    assert engine.generate_token(AttackType.ALGORITHM_CONFUSION) == []
    # No fuzz_target / fuzz_values configured => no claim-fuzzing token (Req 63.1).
    assert engine.generate_token(AttackType.CLAIM_FUZZING) == []


def test_signed_vectors_use_operator_signing_secret_not_literal_secret():
    """Signature-requiring vectors verify under the operator key, not "secret".

    Proves KID/JWKS/INLINE_JWKS/privilege/impersonation/expiration tokens are
    HMAC-signed with the operator-supplied ``signing_secret`` (Req 15.1) rather
    than the historic hardcoded "secret" fallback.
    """
    engine = _make_engine()
    assert SIGNING_SECRET != "secret"  # guard the test's own premise

    for attack_type in SIGNED_VECTORS:
        tokens = engine.generate_token(attack_type)
        assert tokens, f"{attack_type} produced no tokens"
        for token in tokens:
            assert verify_hmac_secret(token, SIGNING_SECRET), (
                f"{attack_type} token not signed with the operator secret")
            assert not verify_hmac_secret(token, "secret"), (
                f"{attack_type} token was signed with the literal 'secret'")


def test_signed_vectors_fall_back_to_secret_only_without_signing_key():
    """Without an operator key the engine falls back to "secret" (Req 15.1)."""
    engine = _make_engine(signing_secret=None)
    tokens = engine.generate_token(AttackType.PRIVILEGE_ESCALATION)
    assert tokens
    for token in tokens:
        assert verify_hmac_secret(token, "secret")
        assert not verify_hmac_secret(token, SIGNING_SECRET)


def test_kid_injection_signs_standard_probes_with_operator_key_and_forces_predictable_key():
    """KID_INJECTION covers SQLi/traversal/file-inclusion + a predictable-key path.

    Standard injection probes are HMAC-signed with the operator-supplied key
    (Req 15.1/15.2), never the literal "secret"; and at least one predictable/
    empty-key probe (e.g. ``/dev/null`` forcing an empty signing key) is signed
    with that forced key so acceptance confirms the injection (Req 44.1/44.2).
    """
    engine = _make_engine()
    tokens = engine.generate_token(AttackType.KID_INJECTION)
    assert tokens

    # No KID token is signed with the historic hardcoded literal "secret".
    for token in tokens:
        assert not verify_hmac_secret(token, "secret"), (
            "a KID token was signed with the literal 'secret'")

    # Standard injection probes are signed with the operator key (Req 15.1/15.2).
    operator_signed = [t for t in tokens if verify_hmac_secret(t, SIGNING_SECRET)]
    assert operator_signed, "expected KID probes signed with the operator key"

    # The predictable/empty-key path signs with the forced empty key (Req 44.1).
    empty_key_signed = [t for t in tokens if verify_hmac_secret(t, "")]
    assert empty_key_signed, "expected a KID probe signed with the forced empty key"


def test_kid_injection_modifies_only_kid_header_and_preserves_payload():
    """KID token generation changes only the ``kid`` header (Req 44.1 / 48.4)."""
    engine = _make_engine()
    base = decode_jwt(BASE_TOKEN)
    base_header_without_kid = {k: v for k, v in base["header"].items() if k != "kid"}

    for token in engine.generate_token(AttackType.KID_INJECTION):
        decoded = decode_jwt(token)
        # Payload preserved verbatim.
        assert decoded["payload"] == base["payload"]
        # Every header field except ``kid`` is preserved.
        header_without_kid = {k: v for k, v in decoded["header"].items() if k != "kid"}
        assert header_without_kid == base_header_without_kid
        # A ``kid`` header was actually injected.
        assert "kid" in decoded["header"]


def test_alg_none_produces_unsigned_none_algorithm_tokens():
    """ALG_NONE sets ``alg=none`` and drops the signature (Req 15.4)."""
    engine = _make_engine()
    tokens = engine.generate_token(AttackType.ALG_NONE)
    assert tokens

    # The trailing-dot variant is a well-formed 3-part token with empty sig.
    dotted = [t for t in tokens if t.endswith(".")]
    assert dotted, "expected an alg=none token with an empty signature segment"
    decoded = decode_jwt(dotted[0])
    assert decoded["header"].get("alg") == "none"
    assert decoded["signature"] == ""

    # A no-signature variant (header.payload without a signature) is also produced.
    assert any(t.count(".") == 1 for t in tokens)


def test_null_signature_keeps_header_payload_with_empty_signatures():
    """NULL_SIGNATURE keeps the original header/payload with null signatures."""
    engine = _make_engine()
    tokens = engine.generate_token(AttackType.NULL_SIGNATURE)
    assert tokens
    base = decode_jwt(BASE_TOKEN)
    for token in tokens:
        parts = token.split(".")
        assert len(parts) == 3
        # header + payload preserved from the original token
        assert parts[0] == base["raw_header"]
        assert parts[1] == base["raw_payload"]


def test_weak_secret_resigns_with_each_wordlist_candidate():
    """WEAK_SECRET re-signs the token with each weak-secret candidate (Req 15.3).

    The empty string ``""`` is prepended as the first candidate (Req 58.1), so a
    validly-HMAC-signed blank-secret token is produced ahead of the wordlist
    tokens. Each produced token must verify under its corresponding candidate
    (including ``""``), demonstrating a server accepting one has a guessable
    (or empty) secret.
    """
    wordlist = ["secret", "password", "admin", "changeme"]
    engine = _make_engine(weak_secrets=wordlist)
    tokens = engine.generate_token(AttackType.WEAK_SECRET)

    # The blank-secret candidate is prepended, so there is one token per wordlist
    # entry PLUS the leading blank-secret token.
    expected_candidates = [""] + wordlist
    assert len(tokens) == len(expected_candidates)
    for candidate, token in zip(expected_candidates, tokens):
        # Header must declare HS256 (weak-secret forgery targets HMAC).
        assert decode_jwt(token)["header"]["alg"] == "HS256"
        assert verify_hmac_secret(token, candidate), (
            f"weak-secret token not signed with candidate '{candidate}'")

    # The leading token is the blank-secret token: it verifies under "" only.
    assert verify_hmac_secret(tokens[0], "")


# ===========================================================================
# 2. Vector -> Finding_Category mapping (Req 18.4, 18.3)
# ===========================================================================


EXPECTED_CATEGORY_BY_TYPE = {
    AttackType.ALG_NONE: "JWT_NONE_ALGORITHM",
    AttackType.NULL_SIGNATURE: "JWT_NULL_SIGNATURE",
    AttackType.WEAK_SECRET: "JWT_WEAK_SECRET",
    AttackType.KID_INJECTION: "JWT_KID_INJECTION",
    AttackType.JWKS_SPOOF: "JWT_JWKS_SPOOF",
    AttackType.INLINE_JWKS: "JWT_INLINE_JWKS",
    AttackType.PRIVILEGE_ESCALATION: "JWT_PRIVILEGE_ESCALATION",
    AttackType.USER_IMPERSONATION: "JWT_USER_IMPERSONATION",
    AttackType.EXPIRATION_BYPASS: "JWT_EXPIRATION_BYPASS",
}


def test_attack_type_to_category_map_is_exhaustive_and_correct():
    """Every AttackType maps to its expected Finding_Category (Req 18.4)."""
    assert set(_ATTACK_TYPE_TO_CATEGORY.keys()) == set(AttackType)
    for attack_type, expected in EXPECTED_CATEGORY_BY_TYPE.items():
        assert _ATTACK_TYPE_TO_CATEGORY[attack_type] == expected


def _make_attack_result(attack_type, severity=VulnerabilitySeverity.HIGH,
                        confidence=0.9, baseline_comparison=None):
    """Build a minimal vulnerable AttackResult for mapping/severity tests."""
    assessment = VulnerabilityAssessment(
        is_vulnerable=True,
        vulnerability_type="Test Vulnerability",
        severity=severity,
        evidence=["Authentication bypass: 401 -> 200"],
        confidence_score=confidence,
        remediation_advice="Fix the JWT validation.",
    )
    return AttackResult(
        attack_type=attack_type,
        attack_variant="standard",
        jwt_token="header.payload.signature",
        request_details=RequestDetails(
            url=TARGET_URL, method="GET", headers={"Authorization": "Bearer x"}),
        response_details=ResponseDetails(
            status_code=200, headers={}, body="{}", response_time=0.02,
            content_length=2),
        vulnerability_assessment=assessment,
        baseline_comparison=baseline_comparison,
    )


def test_jwt_assessment_to_finding_maps_category_and_owasp_api2():
    """Each AttackType finding carries its category + owasp_category=API2 (18.4/18.3)."""
    for attack_type, expected_category in EXPECTED_CATEGORY_BY_TYPE.items():
        result = _make_attack_result(attack_type)
        finding = jwt_assessment_to_finding(result, scan_id="scan-1")
        assert isinstance(finding, Finding)
        assert finding.category == expected_category
        assert finding.owasp_category == JWT_OWASP_CATEGORY == "API2"
        assert finding.scan_id == "scan-1"
        assert finding.endpoint == TARGET_URL


def test_mapped_categories_are_accepted_by_findings_collector():
    """Findings produced for every vector resolve cleanly in FindingsCollector.

    FindingsCollector enforces strict classification for emitted categories, so
    a clean add proves each JWT category resolves to a Severity + in-scope OWASP
    category (Req 18.3).
    """
    collector = FindingsCollector(scan_id="scan-collector")
    findings = [jwt_assessment_to_finding(_make_attack_result(t), scan_id="")
                for t in AttackType]
    added = collector.add_findings(findings)
    assert added == len(list(AttackType))
    for finding in collector.findings:
        assert finding.owasp_category == "API2"


# ===========================================================================
# 3. Severity reconciliation (Req 18.1)
# ===========================================================================


def test_severity_map_reconciles_every_vulnerability_severity():
    """Each JWT VulnerabilitySeverity maps to the correct core Severity (18.1)."""
    expected = {
        VulnerabilitySeverity.CRITICAL: Severity.CRITICAL,
        VulnerabilitySeverity.HIGH: Severity.HIGH,
        VulnerabilitySeverity.MEDIUM: Severity.MEDIUM,
        VulnerabilitySeverity.LOW: Severity.LOW,
        VulnerabilitySeverity.INFO: Severity.INFO,
    }
    assert set(_SEVERITY_MAP.keys()) == set(VulnerabilitySeverity)
    for jwt_sev, core_sev in expected.items():
        assert _SEVERITY_MAP[jwt_sev] == core_sev


def test_finding_severity_follows_assessment_severity():
    """The reconciled severity flows through to the emitted Finding (18.1)."""
    for jwt_sev, core_sev in _SEVERITY_MAP.items():
        result = _make_attack_result(AttackType.ALG_NONE, severity=jwt_sev)
        finding = jwt_assessment_to_finding(result, scan_id="s")
        assert finding.severity == core_sev


# ===========================================================================
# 4. No-findings result (Req 18.2)
# ===========================================================================


def _empty_summary():
    config = AttackConfiguration(target_url=TARGET_URL, original_jwt=BASE_TOKEN)
    session = AttackSession(session_id="sess-1", configuration=config)
    return AttackSummary(session=session)


def test_to_findings_emits_single_no_findings_info_result_when_clean():
    """A clean summary yields exactly one INFO 'no findings' result (Req 18.2)."""
    engine = _make_engine()
    findings = engine.to_findings(_empty_summary(), scan_id="scan-clean")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == JWT_NO_FINDINGS_CATEGORY == "JWT_SCAN_COMPLETED_NO_FINDINGS"
    assert finding.severity == Severity.INFO
    assert finding.owasp_category == "API2"
    assert finding.scan_id == "scan-clean"


def test_no_findings_result_is_accepted_by_findings_collector():
    """The 'no findings' result classifies cleanly in FindingsCollector (18.2/18.3)."""
    engine = _make_engine()
    findings = engine.to_findings(_empty_summary(), scan_id="")
    collector = FindingsCollector(scan_id="scan-clean")
    added = collector.add_findings(findings)
    assert added == 1
    assert collector.findings[0].category == JWT_NO_FINDINGS_CATEGORY
    assert collector.findings[0].severity == Severity.INFO


# ===========================================================================
# 5. Analyzer-based success with baseline evidence + confidence (Req 19.1, 19.3)
# ===========================================================================


ADMIN_BODY = '{"role":"admin","is_admin":true,"user":{"id":1}}'


@pytest.mark.asyncio
async def test_execute_attack_flags_bypass_with_baseline_and_confidence():
    """A 401 baseline turning into a 200 attack response is flagged vulnerable.

    Uses the analyzer's baseline comparison + confidence scoring (Req 19.1) and
    the result carries the baseline comparison + a confidence score (Req 19.3).
    """
    baseline = _StubResponse(401, body='{"error":"unauthorized"}')
    attack = _StubResponse(200, body=ADMIN_BODY)
    http = _StubHTTPEngine(BASE_TOKEN, baseline, attack)
    engine = _make_engine(http_engine=http)

    result = await engine.execute_attack(AttackType.PRIVILEGE_ESCALATION)

    assert result is not None
    assert result.vulnerability_assessment.is_vulnerable is True
    assert result.vulnerability_assessment.confidence_score > 0.0
    # Baseline comparison evidence is captured on the result (Req 19.3).
    assert result.baseline_comparison
    assert result.baseline_comparison["baseline_status"] == 401
    assert result.baseline_comparison["attack_status"] == 200
    # The baseline request (original token) was issued before the attack request.
    assert http.calls[0][2] == f"Bearer {BASE_TOKEN}"


@pytest.mark.asyncio
async def test_reported_finding_includes_baseline_evidence_and_confidence():
    """Reported findings embed baseline-comparison evidence + confidence (19.3)."""
    baseline = _StubResponse(403, body='{"error":"forbidden"}')
    attack = _StubResponse(200, body=ADMIN_BODY)
    http = _StubHTTPEngine(BASE_TOKEN, baseline, attack)
    engine = _make_engine(http_engine=http)

    summary = await engine.execute_all()
    assert summary.vulnerabilities_found, "expected at least one vulnerability"

    findings = engine.to_findings(summary, scan_id="scan-evidence")
    assert findings
    for finding in findings:
        assert finding.owasp_category == "API2"
        assert "Baseline comparison:" in finding.evidence
        assert "Confidence score:" in finding.evidence

    # Findings flow into the unified collector without classification errors.
    collector = FindingsCollector(scan_id="scan-evidence")
    added = collector.add_findings(findings)
    assert added == len(findings)


@pytest.mark.asyncio
async def test_execute_all_no_bypass_yields_no_vulnerabilities():
    """When attack responses match an authorized baseline, nothing is flagged.

    Confirms success is evidence/baseline driven rather than keyword driven:
    an identical 200 baseline and 200 attack response (even containing 'admin')
    does not by itself produce a confirmed vulnerability, so ``to_findings``
    emits the 'no findings' result (Req 19.1, 19.2, 18.2).
    """
    baseline = _StubResponse(200, body=ADMIN_BODY)
    attack = _StubResponse(200, body=ADMIN_BODY)
    http = _StubHTTPEngine(BASE_TOKEN, baseline, attack)
    engine = _make_engine(http_engine=http)

    summary = await engine.execute_all()

    assert summary.vulnerabilities_found == []
    findings = engine.to_findings(summary, scan_id="scan-none")
    assert len(findings) == 1
    assert findings[0].category == JWT_NO_FINDINGS_CATEGORY


# ===========================================================================
# 6. Sensitive-data-in-payload inspection (Req 43)
# ===========================================================================


def _token_with_payload(payload):
    """Sign a token carrying ``payload`` with the operator secret."""
    return encode_jwt({"alg": "HS256", "typ": "JWT"}, payload, BASE_SECRET)


def test_inspect_payload_flags_corroborated_claims_and_redacts_values():
    """Corroborated credential/PII claims → JWT_SENSITIVE_DATA_IN_PAYLOAD (Req 43.1-43.4)."""
    high_entropy_secret = "aB3xY9zQ7wE2rT5yU8iO1pA4sD6fG0hJ"  # 32-char high-entropy
    api_key = "sk_" + "FAKEKEY_not_a_real_secret"             # sk_ prefix (self-sufficient)
    email = "alice.victim@example.com"                        # PII pattern
    payload = {
        "sub": "user-123",
        "password": high_entropy_secret,   # credential-shape + sensitive field name
        "api_key": api_key,                 # known credential prefix
        "email": email,                     # PII
        "role": "user",                     # not sensitive
    }
    engine = _make_engine()
    findings = engine.inspect_payload_sensitivity(_token_with_payload(payload),
                                                  scan_id="scan-jwt-pii")

    flagged_fields = {f.payload for f in findings}
    assert "Field: password" in flagged_fields
    assert "Field: api_key" in flagged_fields
    assert "Field: email" in flagged_fields
    # Non-sensitive claims are never flagged.
    assert "Field: sub" not in flagged_fields
    assert "Field: role" not in flagged_fields

    for finding in findings:
        assert finding.category == "JWT_SENSITIVE_DATA_IN_PAYLOAD"
        assert finding.owasp_category == "API2"
        assert finding.scan_id == "scan-jwt-pii"
        # The field name and sensitivity type are included (Req 43.3).
        assert "sensitivity type:" in finding.evidence
        # The raw secret/PII value is NEVER echoed (Req 43.4).
        assert high_entropy_secret not in finding.evidence
        assert api_key not in finding.evidence
        assert email not in finding.evidence

    # The findings classify cleanly in the unified collector (Req 43.3).
    collector = FindingsCollector(scan_id="scan-jwt-pii")
    assert collector.add_findings(findings) == len(findings)


def test_inspect_payload_does_not_flag_bare_pattern_without_corroboration():
    """A bare credential-shaped string with no corroboration is not flagged (Req 43.2)."""
    payload = {
        "sub": "user-123",
        # 40 chars, all identical -> matches [A-Za-z0-9]{32,} shape but LOW
        # entropy and a NON-sensitive field name => necessary but not sufficient.
        "data": "a" * 40,
        "note": "just-a-plain-value",
    }
    engine = _make_engine()
    findings = engine.inspect_payload_sensitivity(_token_with_payload(payload))
    assert findings == []


def test_inspect_payload_ignores_non_string_and_undecodable_tokens():
    """Non-string claims are skipped and a malformed token yields no findings (Req 43.2)."""
    payload = {"user_id": 123, "is_admin": True, "count": 42}
    engine = _make_engine()
    assert engine.inspect_payload_sensitivity(_token_with_payload(payload)) == []

    # An undecodable token is treated as "no sensitive claims", never raising.
    assert engine.inspect_payload_sensitivity("not-a-jwt") == []


# ===========================================================================
# 7. kid injection success confirmation (Req 44.2)
# ===========================================================================


@pytest.mark.asyncio
async def test_confirm_kid_injection_reuses_analyzer_assessment():
    """_confirm_kid_injection confirms only when the analyzer flags vulnerable (Req 44.2)."""
    engine = _make_engine()

    vulnerable = _make_attack_result(AttackType.KID_INJECTION,
                                     severity=VulnerabilitySeverity.HIGH)
    assert await engine._confirm_kid_injection(vulnerable) is True

    not_vulnerable = _make_attack_result(AttackType.KID_INJECTION)
    not_vulnerable.vulnerability_assessment.is_vulnerable = False
    assert await engine._confirm_kid_injection(not_vulnerable) is False

    # No result (no request produced a response) is never confirmed.
    assert await engine._confirm_kid_injection(None) is False


@pytest.mark.asyncio
async def test_confirmed_kid_injection_maps_to_jwt_kid_injection_finding():
    """A confirmed KID_INJECTION result maps to JWT_KID_INJECTION / API2 (Req 44.3)."""
    baseline = _StubResponse(401, body='{"error":"unauthorized"}')
    attack = _StubResponse(200, body=ADMIN_BODY)
    http = _StubHTTPEngine(BASE_TOKEN, baseline, attack)
    engine = _make_engine(http_engine=http)

    result = await engine.execute_attack(AttackType.KID_INJECTION)
    assert await engine._confirm_kid_injection(result) is True

    finding = jwt_assessment_to_finding(result, scan_id="scan-kid")
    assert finding.category == "JWT_KID_INJECTION"
    assert finding.owasp_category == "API2"
    assert "Baseline comparison:" in finding.evidence


# ===========================================================================
# 8. jku / x5u key-source SSRF + allowlist assessment (Req 45.1, 45.2, 45.3, 45.5)
# ===========================================================================


ATTACKER_KEY_SOURCE_URL = "http://attacker.evil.example/.well-known/jwks.json"


def test_build_jku_x5u_token_modifies_only_targeted_header_and_signs_with_attacker_key():
    """Only the jku/x5u header is set; payload/other header fields preserved (Req 45.1)."""
    engine = _make_engine()
    base = decode_jwt(BASE_TOKEN)

    for header_field, other_field in (("jku", "x5u"), ("x5u", "jku")):
        token = engine._build_jku_x5u_token(header_field, ATTACKER_KEY_SOURCE_URL)
        decoded = decode_jwt(token)

        # Targeted header points at the attacker-controlled key source.
        assert decoded["header"][header_field] == ATTACKER_KEY_SOURCE_URL
        # The sibling key-source header was NOT introduced.
        assert other_field not in decoded["header"]
        # Payload is preserved verbatim (Req 45.1 / 48.4).
        assert decoded["payload"] == base["payload"]
        # Every base header field is preserved unchanged.
        for key, value in base["header"].items():
            assert decoded["header"][key] == value
        # The token is NOT signed with the server's real operator key — it is
        # signed with attacker-hosted key material, so acceptance is unambiguous.
        assert not verify_hmac_secret(token, SIGNING_SECRET)


def test_build_jku_x5u_token_rejects_unknown_header_field():
    """Only 'jku' and 'x5u' are valid targeted header fields (Req 45.1)."""
    engine = _make_engine()
    with pytest.raises(ValueError):
        engine._build_jku_x5u_token("kid", ATTACKER_KEY_SOURCE_URL)


@pytest.mark.asyncio
async def test_key_source_ssrf_confirmed_by_attacker_signed_token_acceptance():
    """Acceptance of the attacker-signed token confirms SSRF (Req 45.2, 45.5).

    A 401 baseline turning into a 200 for the attacker-signed token is flagged
    by the single success detector; the finding is JWT_JKU_SSRF / API2 and
    carries the key-source allowlist assessment (domain NOT allowlisted).
    """
    baseline = _StubResponse(401, body='{"error":"unauthorized"}')
    attack = _StubResponse(200, body=ADMIN_BODY)
    http = _StubHTTPEngine(BASE_TOKEN, baseline, attack)
    engine = _make_engine(http_engine=http)

    findings = await engine.test_key_source_ssrf(ATTACKER_KEY_SOURCE_URL,
                                                 scan_id="scan-jku")

    # Both the jku and x5u probes are accepted -> one finding each.
    assert len(findings) == 2
    for finding in findings:
        assert finding.category == "JWT_JKU_SSRF"
        assert finding.owasp_category == "API2"
        assert finding.severity == Severity.HIGH
        assert finding.scan_id == "scan-jku"
        # Confirmation basis is spoofed-key acceptance (Req 45.2).
        assert "accepted a token signed with attacker-hosted keys" in finding.evidence
        # Allowlist assessment is included and reports NOT constrained (Req 45.5).
        assert "Key-source allowlist assessment" in finding.evidence
        assert "NOT constrained by an allowlist" in finding.evidence
        # The attacker key source is named in the evidence.
        assert ATTACKER_KEY_SOURCE_URL in finding.evidence

    # The baseline (original token) was issued before any attack request.
    assert http.calls[0][2] == f"Bearer {BASE_TOKEN}"

    # Findings classify cleanly in the unified collector (Req 45.2).
    collector = FindingsCollector(scan_id="scan-jku")
    assert collector.add_findings(findings) == len(findings)


@pytest.mark.asyncio
async def test_key_source_ssrf_confirmed_by_observed_outbound_request():
    """An observed outbound request to the attacker URL confirms SSRF (Req 45.3, 45.5).

    Even when the attacker-signed token is NOT accepted (baseline 200 == attack
    200, nothing flagged by the analyzer), an out-of-band observer reporting an
    outbound request to the attacker key source confirms the finding.
    """
    # Identical authorized baseline/attack responses => the analyzer does NOT
    # flag acceptance, so confirmation must come solely from the observer.
    baseline = _StubResponse(200, body='{"ok":true}')
    attack = _StubResponse(200, body='{"ok":true}')
    http = _StubHTTPEngine(BASE_TOKEN, baseline, attack)
    engine = _make_engine(http_engine=http)

    observed_urls = []

    def observer(url):
        observed_urls.append(url)
        return True

    findings = await engine.test_key_source_ssrf(
        ATTACKER_KEY_SOURCE_URL, key_source_observer=observer, scan_id="scan-oob")

    assert len(findings) == 2
    assert observed_urls == [ATTACKER_KEY_SOURCE_URL, ATTACKER_KEY_SOURCE_URL]
    for finding in findings:
        assert finding.category == "JWT_JKU_SSRF"
        assert finding.owasp_category == "API2"
        # Confirmation basis is the observed outbound request (Req 45.3).
        assert "outbound request to the attacker-controlled key source" in finding.evidence
        # Allowlist assessment: honored via observation => NOT constrained (Req 45.5).
        assert "NOT constrained by an allowlist" in finding.evidence


@pytest.mark.asyncio
async def test_key_source_ssrf_supports_awaitable_observer():
    """The out-of-band observer may be an async callable (Req 45.3)."""
    baseline = _StubResponse(200, body='{"ok":true}')
    attack = _StubResponse(200, body='{"ok":true}')
    http = _StubHTTPEngine(BASE_TOKEN, baseline, attack)
    engine = _make_engine(http_engine=http)

    async def async_observer(url):
        return True

    findings = await engine.test_key_source_ssrf(
        ATTACKER_KEY_SOURCE_URL, key_source_observer=async_observer)

    assert len(findings) == 2
    assert all(f.category == "JWT_JKU_SSRF" for f in findings)


@pytest.mark.asyncio
async def test_key_source_ssrf_not_confirmed_without_acceptance_or_observation():
    """No acceptance and no observed outbound request => no finding (Req 45.2, 45.3).

    Neither mere submission of the token nor a benign key-source fetch confirms
    the vulnerability, so the probe reports nothing.
    """
    baseline = _StubResponse(200, body='{"ok":true}')
    attack = _StubResponse(200, body='{"ok":true}')
    http = _StubHTTPEngine(BASE_TOKEN, baseline, attack)
    engine = _make_engine(http_engine=http)

    # No observer => no observed outbound request; identical responses => no
    # analyzer-confirmed acceptance.
    findings = await engine.test_key_source_ssrf(ATTACKER_KEY_SOURCE_URL)
    assert findings == []


def test_assess_key_source_allowlist_reports_none_when_probe_not_honored():
    """A single negative probe cannot prove an allowlist => allowlisted is None (Req 45.5)."""
    engine = _make_engine()
    assessment = engine._assess_key_source_allowlist(
        "jku", ATTACKER_KEY_SOURCE_URL, accepted=False, outbound_observed=False)

    assert assessment["allowlisted"] is None
    assert assessment["domain"] == "attacker.evil.example"
    assert "appears constrained by an allowlist" in assessment["evidence"]


def test_assess_key_source_allowlist_reports_false_when_honored():
    """When the attacker key source is honored the domain is NOT allowlisted (Req 45.5)."""
    engine = _make_engine()

    accepted = engine._assess_key_source_allowlist(
        "x5u", ATTACKER_KEY_SOURCE_URL, accepted=True, outbound_observed=False)
    assert accepted["allowlisted"] is False
    assert "NOT constrained by an allowlist" in accepted["evidence"]
    assert "attacker-signed token accepted" in accepted["evidence"]

    observed = engine._assess_key_source_allowlist(
        "jku", ATTACKER_KEY_SOURCE_URL, accepted=False, outbound_observed=True)
    assert observed["allowlisted"] is False
    assert "outbound request observed" in observed["evidence"]


if __name__ == "__main__":
    pytest.main([__file__, "-q"])