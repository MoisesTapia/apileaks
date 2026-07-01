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

# Signature-requiring vectors: these MUST be HMAC-signed with the operator key.
SIGNED_VECTORS = [
    AttackType.KID_INJECTION,
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
    """Each of the nine vectors yields at least one non-empty token (Req 24.1)."""
    engine = _make_engine()
    for attack_type in AttackType:
        tokens = engine.generate_token(attack_type)
        assert isinstance(tokens, list)
        assert tokens, f"{attack_type} produced no tokens"
        assert all(isinstance(t, str) and t for t in tokens), (
            f"{attack_type} produced an empty token")


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

    Each produced token must verify under its corresponding wordlist entry,
    demonstrating a server accepting one has a guessable secret.
    """
    wordlist = ["secret", "password", "admin", "changeme"]
    engine = _make_engine(weak_secrets=wordlist)
    tokens = engine.generate_token(AttackType.WEAK_SECRET)

    assert len(tokens) == len(wordlist)
    for candidate, token in zip(wordlist, tokens):
        # Header must declare HS256 (weak-secret forgery targets HMAC).
        assert decode_jwt(token)["header"]["alg"] == "HS256"
        assert verify_hmac_secret(token, candidate), (
            f"weak-secret token not signed with candidate '{candidate}'")


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


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
