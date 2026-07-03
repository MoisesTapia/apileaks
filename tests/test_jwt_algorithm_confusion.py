"""
Unit tests for the JWT algorithm/key-confusion (Substitution) attack vector.

Covers the ``AttackType.ALGORITHM_CONFUSION`` vector newly exposed both in the
:class:`~utils.jwt_attack_engine.JWTAttackEngine` and as the manual
``jwt test-alg-confusion`` CLI subcommand. The attack forges a token that a
server validates with the SAME asymmetric public key it uses for RS*/ES*
verification, but treated as an HS256 HMAC secret (the classic RS256->HS256
key-confusion bypass).

Three layers are exercised:

1. Engine token generation: one HS256-forged token per public-key
   representation, each verifiable under that representation as the HMAC key,
   with the payload preserved and the header ``alg`` switched to ``HS256``.
2. Finding-category mapping: the vector resolves to the ``JWT_ALGORITHM_CONFUSION``
   Finding_Category (CRITICAL / API2).
3. The manual ``jwt test-alg-confusion`` CLI subcommand: it is registered,
   requires ``--public-key``, and prints forged tokens for manual testing.

Mirrors the engine/model conventions in ``tests/test_jwt_attack_engine.py`` and
the CliRunner conventions in ``tests/test_jwt_cli_subcommands.py``.
"""

import time

import pytest
from click.testing import CliRunner

from apileaks import cli
from utils.jwt_attack_engine import (
    JWTAttackEngine,
    jwt_assessment_to_finding,
    _ATTACK_TYPE_TO_CATEGORY,
)
from utils.jwt_attack_models import (
    AttackType,
    AttackResult,
    RequestDetails,
    ResponseDetails,
    VulnerabilitySeverity,
    VulnerabilityAssessment,
)
from utils.jwt_utils import (
    base64url_encode,
    decode_jwt,
    encode_jwt,
    generate_rsa_keypair,
    verify_hmac_secret,
    _public_key_variants,
)

import json


TARGET_URL = "https://target.example/api/account"

# A fresh RSA keypair standing in for the target's signing key. The PUBLIC PEM
# is what an attacker would harvest and feed back as the HMAC secret.
PRIVATE_PEM, PUBLIC_PEM = generate_rsa_keypair(2048)


def _make_rs256_token():
    """Build a realistic RS256 base token (the signature bytes are irrelevant
    to the confusion generator, which re-signs header.payload as HS256)."""
    header = {"alg": "RS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": "user-123",
        "username": "alice",
        "role": "user",
        "iat": now,
        "exp": now + 3600,
    }
    header_b64 = base64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = base64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig_b64 = base64url_encode(b"\x00" * 32)  # placeholder RS256 signature
    return f"{header_b64}.{payload_b64}.{sig_b64}", header, payload


BASE_TOKEN, BASE_HEADER, BASE_PAYLOAD = _make_rs256_token()


class _UnusedHTTPEngine:
    """HTTP stub for tests that never issue requests (generation/mapping)."""

    async def request(self, method, url, **kwargs):  # pragma: no cover
        raise AssertionError("no HTTP request expected in this test")


def _make_engine(public_key_material=PUBLIC_PEM):
    return JWTAttackEngine(
        target_url=TARGET_URL,
        original_token=BASE_TOKEN,
        http_engine=_UnusedHTTPEngine(),
        public_key_material=public_key_material,
    )


# ===========================================================================
# 1. Engine token generation
# ===========================================================================


def test_confusion_generates_one_token_per_public_key_representation():
    """One forged token is produced per derivable public-key representation."""
    engine = _make_engine()
    tokens = engine.generate_token(AttackType.ALGORITHM_CONFUSION)

    variants = _public_key_variants(PUBLIC_PEM)
    assert variants, "expected at least one public-key representation"
    assert len(tokens) == len(variants)
    assert len(tokens) >= 2  # PEM with and without trailing newline at minimum
    assert all(isinstance(t, str) and t.count(".") == 2 for t in tokens)


def test_confusion_tokens_are_hs256_and_preserve_payload():
    """Each forged token switches alg to HS256 and preserves the payload."""
    engine = _make_engine()
    tokens = engine.generate_token(AttackType.ALGORITHM_CONFUSION)

    for token in tokens:
        decoded = decode_jwt(token)
        assert decoded["header"]["alg"] == "HS256"
        # The entire payload is preserved verbatim from the base token.
        assert decoded["payload"] == BASE_PAYLOAD


def test_confusion_token_verifies_under_public_key_as_hmac_secret():
    """At least one forged token verifies with the PUBLIC PEM as the HMAC key.

    This is the crux of the attack: the token's HS256 signature validates when
    the server uses its public key material as the HMAC secret.
    """
    engine = _make_engine()
    tokens = engine.generate_token(AttackType.ALGORITHM_CONFUSION)

    # The PEM-with-newline representation equals ``PUBLIC_PEM`` encoded to bytes,
    # so verify_hmac_secret(token, PUBLIC_PEM) must be True for that token.
    assert any(verify_hmac_secret(token, PUBLIC_PEM) for token in tokens)


def test_confusion_signature_matches_a_public_key_representation():
    """Every forged token's signature is an HMAC over header.payload keyed by
    one of the public-key representation byte-forms."""
    import hmac
    import hashlib

    engine = _make_engine()
    tokens = engine.generate_token(AttackType.ALGORITHM_CONFUSION)
    variant_bytes = [kb for _name, kb in _public_key_variants(PUBLIC_PEM)]

    for token in tokens:
        header_b64, payload_b64, sig_b64 = token.split(".")
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        expected = {
            base64url_encode(hmac.new(kb, signing_input, hashlib.sha256).digest())
            for kb in variant_bytes
        }
        assert sig_b64 in expected


def test_confusion_without_public_key_yields_no_tokens():
    """Without public key material the vector produces no tokens (safe no-op)."""
    engine = _make_engine(public_key_material=None)
    assert engine.generate_token(AttackType.ALGORITHM_CONFUSION) == []


def test_confusion_with_unparseable_public_key_yields_no_tokens():
    """Unparseable key material derives no representation, so no tokens."""
    engine = _make_engine(public_key_material="not-a-real-key")
    assert engine.generate_token(AttackType.ALGORITHM_CONFUSION) == []


# ===========================================================================
# 2. Finding-category mapping
# ===========================================================================


def test_confusion_maps_to_jwt_algorithm_confusion_category():
    """The vector resolves to the JWT_ALGORITHM_CONFUSION Finding_Category."""
    assert (
        _ATTACK_TYPE_TO_CATEGORY[AttackType.ALGORITHM_CONFUSION]
        == "JWT_ALGORITHM_CONFUSION"
    )


def test_confusion_assessment_maps_to_api2_finding():
    """A vulnerable confusion AttackResult maps to an API2 CRITICAL finding."""
    engine = _make_engine()
    forged = engine.generate_token(AttackType.ALGORITHM_CONFUSION)[0]

    result = AttackResult(
        attack_type=AttackType.ALGORITHM_CONFUSION,
        attack_variant="standard",
        jwt_token=forged,
        request_details=RequestDetails(
            url=TARGET_URL, method="GET",
            headers={"Authorization": f"Bearer {forged}"}),
        response_details=ResponseDetails(
            status_code=200, headers={}, body="{}", response_time=0.01,
            content_length=2),
        vulnerability_assessment=VulnerabilityAssessment(
            is_vulnerable=True,
            vulnerability_type="JWT algorithm confusion",
            severity=VulnerabilitySeverity.CRITICAL,
            confidence_score=0.9),
    )

    finding = jwt_assessment_to_finding(result, scan_id="scan-1")
    assert finding.category == "JWT_ALGORITHM_CONFUSION"
    assert finding.owasp_category == "API2"


# ===========================================================================
# 3. Manual CLI subcommand: jwt test-alg-confusion
# ===========================================================================


def test_cli_subcommand_is_registered():
    """``jwt test-alg-confusion`` is a registered subcommand of the jwt group."""
    jwt_group = cli.commands["jwt"]
    assert "test-alg-confusion" in jwt_group.commands


def test_cli_requires_public_key_option():
    """Omitting --public-key is a usage error (the key is required)."""
    runner = CliRunner()
    result = runner.invoke(cli, ["jwt", "test-alg-confusion", BASE_TOKEN])
    assert result.exit_code != 0
    assert "public-key" in result.output.lower()


def test_cli_generates_confusion_tokens_for_manual_testing(tmp_path):
    """With a public key and no --url, the CLI prints forged tokens and each
    token verifies as HS256 under the supplied public key."""
    key_file = tmp_path / "server_pub.pem"
    key_file.write_text(PUBLIC_PEM)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["jwt", "test-alg-confusion", BASE_TOKEN, "--public-key", str(key_file)],
    )
    assert result.exit_code == 0, result.output
    assert "Algorithm/Key Confusion" in result.output

    # Extract printed 3-part tokens and confirm at least one is a valid forgery.
    printed = [
        line.split(". ", 1)[1].strip()
        for line in result.output.splitlines()
        if ". eyJ" in line
    ]
    assert printed, result.output
    assert any(verify_hmac_secret(tok, PUBLIC_PEM) for tok in printed)


def test_cli_accepts_inline_pem_material():
    """The --public-key option accepts inline PEM material (not just a path)."""
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["jwt", "test-alg-confusion", BASE_TOKEN, "--public-key", PUBLIC_PEM],
    )
    assert result.exit_code == 0, result.output
    assert "Generated" in result.output
