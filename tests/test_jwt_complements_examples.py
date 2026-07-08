# Feature: owasp-auth-modules-hardening, Task 39.1: Example-based tests for the mandated JWT-complement coverage
"""
Example-based (deterministic) tests for the JWT Subsystem Complements.

These focused unit tests cover the mandated JWT-complement capabilities of
Requirement 69.1 with concrete, deterministic examples (the biconditional and
preservation invariants are additionally covered by the dedicated property
tests). Coverage here:

* ECDSA sign/verify round-trip and Psychic_Signature rejection (Req 59.1).
* Numeric token-lifetime threshold behaviour, reported iff lifetime exceeds the
  threshold, with the computed lifetime and threshold in the finding detail
  (Reqs 62.1, 62.2).
* ``verify_token`` validity/algorithm reporting and the descriptive key-source
  error (Reqs 65.1, 65.2, 65.4).
* ``generate_rsa_keypair`` / ``generate_ec_keypair`` and
  ``reconstruct_public_key_from_jwks`` (Reqs 66.1, 66.2).
* ``parse_raw_request`` JWT location within a raw HTTP request (Req 67.1).
* Blank-secret finding evidence (Req 58.4 complement of 69.1).
* Algorithm-confusion accepted-representation evidence via
  ``_public_key_variants`` (Req 60.1/60.3 complement of 69.1).

Requirements covered: 69.1, 59.1, 62.1, 62.2, 65.1, 65.2, 66.1, 66.2, 67.1.
"""

import datetime as _dt

import pytest

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from utils.jwt_utils import (
    encode_jwt,
    encode_jwt_ecdsa,
    verify_ecdsa_signature,
    psychic_signature_segment,
    ES_CURVES,
    assess_lifetime,
    verify_token,
    VerifyResult,
    generate_rsa_keypair,
    generate_ec_keypair,
    reconstruct_public_key_from_jwks,
    base64url_encode,
    parse_raw_request,
    _public_key_variants,
)
from utils.jwt_attack_engine import (
    JWT_BLANK_SECRET_CATEGORY,
    _resolve_finding_category,
    _category_specific_evidence,
    jwt_assessment_to_finding,
)
from utils.jwt_attack_models import (
    AttackResult,
    AttackType,
    RequestDetails,
    ResponseDetails,
    VulnerabilityAssessment,
    VulnerabilitySeverity,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

ES_ALGS = ["ES256", "ES384", "ES512"]


def _load_ec_private(private_pem: str):
    return serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)


def _load_public(public_pem: str):
    return serialization.load_pem_public_key(public_pem.encode("utf-8"))


def _b64_uint(value: int) -> str:
    """base64url of the big-endian minimal bytes of a non-negative integer."""
    length = (value.bit_length() + 7) // 8 or 1
    return base64url_encode(value.to_bytes(length, "big"))


# ===========================================================================
# ECDSA sign/verify round-trip and Psychic_Signature rejection (Req 59.1)
# ===========================================================================

class TestEcdsaRoundTrip:
    @pytest.mark.parametrize("alg", ES_ALGS)
    def test_sign_then_verify_round_trip(self, alg):
        """A token signed with the EC private key verifies with its public key."""
        private_pem, public_pem = generate_ec_keypair(alg)
        private_key = _load_ec_private(private_pem)
        public_key = _load_public(public_pem)

        header = {"alg": alg, "typ": "JWT"}
        payload = {"sub": "alice", "role": "admin"}
        token = encode_jwt_ecdsa(header, payload, private_key)

        assert verify_ecdsa_signature(token, public_key) is True

    @pytest.mark.parametrize("alg", ES_ALGS)
    def test_verify_fails_for_wrong_key(self, alg):
        """A token does not verify against an unrelated EC public key."""
        priv_pem, _ = generate_ec_keypair(alg)
        _, other_pub_pem = generate_ec_keypair(alg)
        token = encode_jwt_ecdsa(
            {"alg": alg, "typ": "JWT"}, {"sub": "bob"}, _load_ec_private(priv_pem)
        )
        assert verify_ecdsa_signature(token, _load_public(other_pub_pem)) is False

    def test_verify_fails_for_tampered_payload(self):
        """Tampering the payload segment breaks verification."""
        priv_pem, pub_pem = generate_ec_keypair("ES256")
        token = encode_jwt_ecdsa(
            {"alg": "ES256", "typ": "JWT"}, {"sub": "alice", "role": "user"},
            _load_ec_private(priv_pem),
        )
        header_b64, _payload_b64, sig_b64 = token.split(".")
        forged_payload = base64url_encode(b'{"sub":"alice","role":"admin"}')
        forged = f"{header_b64}.{forged_payload}.{sig_b64}"
        assert verify_ecdsa_signature(forged, _load_public(pub_pem)) is False

    @pytest.mark.parametrize("alg", ES_ALGS)
    def test_psychic_signature_is_rejected(self, alg):
        """A null (r == s == 0) Psychic_Signature never verifies (CVE-2022-21449)."""
        priv_pem, pub_pem = generate_ec_keypair(alg)
        token = encode_jwt_ecdsa(
            {"alg": alg, "typ": "JWT"}, {"sub": "alice"}, _load_ec_private(priv_pem)
        )
        header_b64, payload_b64, _ = token.split(".")
        psychic = f"{header_b64}.{payload_b64}.{psychic_signature_segment(alg)}"
        assert verify_ecdsa_signature(psychic, _load_public(pub_pem)) is False


# ===========================================================================
# Numeric token-lifetime threshold, reported iff exceeded (Reqs 62.1, 62.2)
# ===========================================================================

class TestLifetimeThreshold:
    def _lifetime_findings(self, findings):
        return [f for f in findings if f.category == "JWT_EXCESSIVE_TOKEN_LIFETIME"]

    def test_lifetime_over_threshold_reports_finding_with_detail(self):
        """lifetime > threshold -> JWT_EXCESSIVE_TOKEN_LIFETIME with computed detail."""
        payload = {"iat": 1000, "exp": 1000 + 7200, "jti": "id-1"}
        findings = assess_lifetime(payload, threshold_seconds=3600)
        lifetime_findings = self._lifetime_findings(findings)

        assert len(lifetime_findings) == 1
        detail = lifetime_findings[0].detail
        assert detail["lifetime"] == 7200
        assert detail["threshold"] == 3600
        assert lifetime_findings[0].claim == "exp"

    def test_lifetime_below_threshold_reports_no_lifetime_finding(self):
        """lifetime < threshold -> no lifetime finding."""
        payload = {"iat": 1000, "exp": 1000 + 60, "jti": "id-1"}
        findings = assess_lifetime(payload, threshold_seconds=3600)
        assert self._lifetime_findings(findings) == []

    def test_lifetime_equal_to_threshold_is_not_reported(self):
        """lifetime == threshold is NOT excessive (strict greater-than, Req 62.2)."""
        payload = {"iat": 1000, "exp": 1000 + 3600, "jti": "id-1"}
        findings = assess_lifetime(payload, threshold_seconds=3600)
        assert self._lifetime_findings(findings) == []

    def test_missing_exp_or_iat_yields_no_lifetime_finding(self):
        """Without both exp and iat the lifetime cannot be computed (Req 62.1)."""
        assert self._lifetime_findings(
            assess_lifetime({"exp": 5000, "jti": "id"}, 10)) == []
        assert self._lifetime_findings(
            assess_lifetime({"iat": 1000, "jti": "id"}, 10)) == []

    def test_missing_jti_reports_replay_finding(self):
        """Absent jti -> JWT_MISSING_JTI_CLAIM (Req 62.3)."""
        payload = {"iat": 1000, "exp": 1000 + 60}
        findings = assess_lifetime(payload, threshold_seconds=3600)
        jti = [f for f in findings if f.category == "JWT_MISSING_JTI_CLAIM"]
        assert len(jti) == 1
        assert jti[0].claim == "jti"


# ===========================================================================
# verify_token validity/algorithm reporting + key-source error (Req 65)
# ===========================================================================

class TestVerifyToken:
    def test_hmac_valid_reports_algorithm_and_source(self):
        """A correct HS256 secret -> valid, algorithm HS256, key_source 'secret'."""
        token = encode_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "a"}, "s3cr3t")
        result = verify_token(token, secret="s3cr3t")
        assert isinstance(result, VerifyResult)
        assert result.valid is True
        assert result.algorithm == "HS256"
        assert result.key_source == "secret"

    def test_hmac_wrong_secret_reports_invalid(self):
        """A wrong secret -> valid False but still reports the header algorithm."""
        token = encode_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "a"}, "right")
        result = verify_token(token, secret="wrong")
        assert result.valid is False
        assert result.algorithm == "HS256"
        assert result.key_source == "secret"

    def test_hmac_without_secret_raises_naming_secret(self):
        """An HS token with no secret is rejected with a descriptive error (Req 65.4)."""
        token = encode_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "a"}, "x")
        with pytest.raises(ValueError, match="secret"):
            verify_token(token)

    def test_ecdsa_valid_with_pem_reports_source_pem(self):
        """An ES256 token verifies against a supplied PEM public key (Req 65.1/65.2)."""
        priv_pem, pub_pem = generate_ec_keypair("ES256")
        token = encode_jwt_ecdsa(
            {"alg": "ES256", "typ": "JWT"}, {"sub": "a"}, _load_ec_private(priv_pem)
        )
        result = verify_token(token, pem=pub_pem)
        assert result.valid is True
        assert result.algorithm == "ES256"
        assert result.key_source == "pem"

    def test_asymmetric_without_key_source_raises(self):
        """An ES token with no key source is rejected with a descriptive error."""
        priv_pem, _ = generate_ec_keypair("ES256")
        token = encode_jwt_ecdsa(
            {"alg": "ES256", "typ": "JWT"}, {"sub": "a"}, _load_ec_private(priv_pem)
        )
        with pytest.raises(ValueError):
            verify_token(token)

    def test_unparseable_pem_raises_naming_source(self):
        """Unparseable PEM material is rejected with an error naming the source."""
        priv_pem, _ = generate_ec_keypair("ES256")
        token = encode_jwt_ecdsa(
            {"alg": "ES256", "typ": "JWT"}, {"sub": "a"}, _load_ec_private(priv_pem)
        )
        with pytest.raises(ValueError, match="PEM"):
            verify_token(token, pem="-----NOT A KEY-----")

    def test_unreadable_key_file_raises_naming_file(self):
        """A missing key file is rejected with an error naming the file (Req 65.4)."""
        priv_pem, _ = generate_ec_keypair("ES256")
        token = encode_jwt_ecdsa(
            {"alg": "ES256", "typ": "JWT"}, {"sub": "a"}, _load_ec_private(priv_pem)
        )
        missing = "/nonexistent/path/does-not-exist.pem"
        with pytest.raises(ValueError, match="does-not-exist.pem"):
            verify_token(token, key_file=missing)


# ===========================================================================
# Key generation and JWKS reconstruction (Reqs 66.1, 66.2)
# ===========================================================================

class TestKeyGenerationAndJwksReconstruction:
    def test_generate_rsa_keypair_emits_loadable_rsa_material(self):
        private_pem, public_pem = generate_rsa_keypair(2048)
        assert "BEGIN PRIVATE KEY" in private_pem
        assert "BEGIN PUBLIC KEY" in public_pem
        private_key = serialization.load_pem_private_key(
            private_pem.encode("utf-8"), password=None)
        public_key = _load_public(public_pem)
        assert isinstance(private_key, rsa.RSAPrivateKey)
        assert isinstance(public_key, RSAPublicKey)

    @pytest.mark.parametrize("alg", ES_ALGS)
    def test_generate_ec_keypair_emits_loadable_ec_material(self, alg):
        private_pem, public_pem = generate_ec_keypair(alg)
        private_key = _load_ec_private(private_pem)
        public_key = _load_public(public_pem)
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)
        # The curve matches the requested algorithm.
        assert isinstance(public_key.curve, ES_CURVES[alg])

    def test_generate_ec_keypair_rejects_unsupported_curve(self):
        with pytest.raises(ValueError):
            generate_ec_keypair("ES999")

    def test_reconstruct_rsa_public_key_from_jwk(self):
        """An RSA JWK (n, e) reconstructs to the same public key."""
        _, public_pem = generate_rsa_keypair(2048)
        original = _load_public(public_pem)
        numbers = original.public_numbers()
        jwk = {"kty": "RSA", "n": _b64_uint(numbers.n), "e": _b64_uint(numbers.e)}

        reconstructed_pem = reconstruct_public_key_from_jwks(jwk)
        reconstructed = _load_public(reconstructed_pem)
        assert reconstructed.public_numbers() == numbers

    def test_reconstruct_ec_public_key_from_jwk(self):
        """An EC JWK (crv, x, y) reconstructs to the same public key."""
        _, public_pem = generate_ec_keypair("ES256")
        original = _load_public(public_pem)
        numbers = original.public_numbers()
        jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64_uint(numbers.x),
            "y": _b64_uint(numbers.y),
        }
        reconstructed_pem = reconstruct_public_key_from_jwks(jwk)
        reconstructed = _load_public(reconstructed_pem)
        assert reconstructed.public_numbers().x == numbers.x
        assert reconstructed.public_numbers().y == numbers.y

    def test_reconstruct_missing_params_raises(self):
        """A JWK lacking the parameters to reconstruct a key is rejected (Req 66.5)."""
        with pytest.raises(ValueError):
            reconstruct_public_key_from_jwks({"kty": "RSA", "e": "AQAB"})
        with pytest.raises(ValueError):
            reconstruct_public_key_from_jwks({"kty": "EC", "crv": "P-256", "x": "abc"})


# ===========================================================================
# parse_raw_request JWT location within a raw HTTP request (Req 67.1)
# ===========================================================================

class TestParseRawRequest:
    def _token(self):
        return encode_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "a"}, "secret")

    def test_locates_bearer_token_and_populates_request(self, tmp_path):
        token = self._token()
        raw = (
            "GET /api/account HTTP/1.1\r\n"
            "Host: api.example.com\r\n"
            f"Authorization: Bearer {token}\r\n"
            "\r\n"
        )
        path = tmp_path / "req.txt"
        path.write_text(raw)

        parsed = parse_raw_request(str(path))
        assert parsed.token == token
        assert parsed.method == "GET"
        assert parsed.url == "http://api.example.com/api/account"
        assert parsed.headers["Host"] == "api.example.com"

    def test_locates_token_in_cookie(self, tmp_path):
        token = self._token()
        raw = (
            "GET /profile HTTP/1.1\r\n"
            "Host: api.example.com\r\n"
            f"Cookie: session={token}; theme=dark\r\n"
            "\r\n"
        )
        path = tmp_path / "cookie.txt"
        path.write_text(raw)

        parsed = parse_raw_request(str(path))
        assert parsed.token == token
        assert parsed.cookies["session"] == token
        assert parsed.cookies["theme"] == "dark"

    def test_locates_token_in_body(self, tmp_path):
        token = self._token()
        raw = (
            "POST /login HTTP/1.1\r\n"
            "Host: api.example.com\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            f'{{"jwt":"{token}"}}'
        )
        path = tmp_path / "body.txt"
        path.write_text(raw)

        parsed = parse_raw_request(str(path))
        assert parsed.token == token
        assert parsed.method == "POST"
        assert parsed.body is not None and token in parsed.body

    def test_no_locatable_token_raises_naming_file(self, tmp_path):
        raw = (
            "GET /api HTTP/1.1\r\n"
            "Host: api.example.com\r\n"
            "\r\n"
        )
        path = tmp_path / "notoken.txt"
        path.write_text(raw)
        with pytest.raises(ValueError, match="notoken.txt"):
            parse_raw_request(str(path))

    def test_unreadable_file_raises_naming_file(self):
        missing = "/nonexistent/path/raw-request-missing.txt"
        with pytest.raises(ValueError, match="raw-request-missing.txt"):
            parse_raw_request(missing)


# ===========================================================================
# Blank-secret finding evidence (complement of Req 69.1 / Req 58.4)
# ===========================================================================

def _weak_secret_result(token, attack_type=AttackType.WEAK_SECRET):
    assessment = VulnerabilityAssessment(
        is_vulnerable=True,
        vulnerability_type="Weak/blank secret",
        severity=VulnerabilitySeverity.CRITICAL,
        evidence=["Authentication bypass: 401 -> 200"],
        confidence_score=0.95,
        remediation_advice="Use a strong signing secret.",
    )
    return AttackResult(
        attack_type=attack_type,
        attack_variant="standard",
        jwt_token=token,
        request_details=RequestDetails(
            url="https://target.example/api", method="GET",
            headers={"Authorization": "Bearer x"}),
        response_details=ResponseDetails(
            status_code=200, headers={}, body="{}", response_time=0.01,
            content_length=2),
        vulnerability_assessment=assessment,
        baseline_comparison={
            "baseline_status": 401, "attack_status": 200,
            "status_code_diff": 1, "content_length_diff": 0,
            "response_time_diff": 0.0,
        },
    )


class TestBlankSecretEvidence:
    def test_blank_secret_category_and_evidence_names_algorithm(self):
        """A token verifying under the empty key -> blank category + evidence."""
        token = encode_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "a"}, "")
        result = _weak_secret_result(token)

        category = _resolve_finding_category(result)
        assert category == JWT_BLANK_SECRET_CATEGORY == "JWT_BLANK_SECRET_ACCEPTED"

        evidence = _category_specific_evidence(result, category)
        assert len(evidence) == 1
        assert "Blank-secret acceptance" in evidence[0]
        assert "HS256" in evidence[0]

    def test_finding_evidence_includes_blank_secret_line(self):
        """The generated Finding carries the blank-secret evidence and category."""
        token = encode_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "a"}, "")
        finding = jwt_assessment_to_finding(_weak_secret_result(token), scan_id="scan-1")

        assert finding.category == "JWT_BLANK_SECRET_ACCEPTED"
        assert finding.owasp_category == "API2"
        assert "Blank-secret acceptance" in finding.evidence
        assert "HS256" in finding.evidence

    def test_non_blank_weak_secret_reports_generic_category(self):
        """A token that does NOT verify under the empty key stays JWT_WEAK_SECRET."""
        token = encode_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "a"}, "strong-secret")
        result = _weak_secret_result(token)
        category = _resolve_finding_category(result)
        assert category == "JWT_WEAK_SECRET"
        evidence = _category_specific_evidence(result, category)
        assert evidence and "Weak-secret acceptance" in evidence[0]


# ===========================================================================
# Algorithm-confusion accepted-representation evidence (complement of Req 69.1)
# ===========================================================================

def _rsa_public_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def _self_signed_cert_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "apileaks-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.utcnow() - _dt.timedelta(days=1))
        .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


class TestAlgConfusionRepresentations:
    def test_public_key_yields_three_named_representations(self):
        """A bare public key yields PEM(+nl), PEM(-nl), DER, and ssh_serialized representations."""
        variants = dict(_public_key_variants(_rsa_public_pem()))
        assert set(variants) == {"pem_with_newline", "pem_without_newline", "der", "ssh_serialized"}
        assert variants["pem_with_newline"].endswith(b"\n")
        assert not variants["pem_without_newline"].endswith(b"\n")
        assert (
            variants["pem_with_newline"]
            == variants["pem_without_newline"] + b"\n"
        )

    def test_certificate_yields_four_representations_including_x5c(self):
        """Certificate material additionally derives the x5c_cert_der representation."""
        variants = dict(_public_key_variants(_self_signed_cert_pem()))
        assert set(variants) >= {
            "pem_with_newline", "pem_without_newline", "der", "x5c_cert_der",
        }
        # Every representation carries non-empty distinct key bytes usable as an
        # HMAC key in the algorithm-confusion probe (Req 60.1/60.2).
        assert all(isinstance(b, (bytes, bytearray)) and b for b in variants.values())

    def test_unparseable_material_yields_no_representations(self):
        """Unparseable material yields an empty list rather than raising."""
        assert _public_key_variants("not a key at all") == []
