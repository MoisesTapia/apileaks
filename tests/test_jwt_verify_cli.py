"""
Unit tests for the ``jwt verify`` CLI subcommand.

**Feature: owasp-auth-modules-hardening, Task 38.1**

``jwt verify TOKEN [--secret | --key-file | --pem | --jwks]`` performs a
network-free Token_Verification via :func:`utils.jwt_utils.verify_token`,
printing signature validity and the header algorithm. A JWKS source is read
locally and converted with ``reconstruct_public_key_from_jwks`` inside
``verify_token``; an unreadable/unparseable key source produces a descriptive
error that names the offending source and issues no HTTP request.

Covers Requirements:
  - 65.1 report whether the signature is valid against the supplied material
  - 65.2 report the algorithm named in the token header
  - 65.3 no HTTP request is issued
  - 65.4 descriptive error naming the offending key source on read/parse failure

Mirrors the CliRunner conventions in ``tests/test_jwt_cli_subcommands.py``.
"""

import base64
import json

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from apileaks import cli
from utils.jwt_utils import (
    base64url_encode,
    encode_jwt,
    generate_rsa_keypair,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

HS_SECRET = "s3cr3t-signing-key"
HS_TOKEN = encode_jwt(
    {"alg": "HS256", "typ": "JWT"},
    {"sub": "user-123", "role": "user"},
    HS_SECRET,
)


def _invoke(*args):
    return CliRunner().invoke(cli, ["--no-banner", "jwt", "verify", *args])


def _sign_rs256(private_pem: str, header: dict, payload: dict) -> str:
    """Sign an RS256 token with the supplied PKCS#8 PEM private key."""
    private_key = serialization.load_pem_private_key(
        private_pem.encode("utf-8"), password=None
    )
    segments = [
        base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8")),
        base64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
    ]
    signing_input = ".".join(segments).encode("utf-8")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    segments.append(base64url_encode(signature))
    return ".".join(segments)


def _public_pem_to_jwks(public_pem: str) -> dict:
    """Build a minimal RSA JWK ({"keys":[...]}) from a public PEM."""
    public_key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    numbers = public_key.public_numbers()

    def _b64uint(value: int) -> str:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

    return {
        "keys": [
            {"kty": "RSA", "n": _b64uint(numbers.n), "e": _b64uint(numbers.e)}
        ]
    }


@pytest.fixture(scope="module")
def rsa_keypair():
    return generate_rsa_keypair(bits=2048)


@pytest.fixture(scope="module")
def rs256_token(rsa_keypair):
    private_pem, _ = rsa_keypair
    return _sign_rs256(private_pem, {"alg": "RS256", "typ": "JWT"},
                       {"sub": "user-123", "role": "admin"})


# ===========================================================================
# HMAC (--secret) path — Reqs 65.1, 65.2
# ===========================================================================


def test_verify_hmac_valid_secret_reports_valid_and_algorithm():
    """A correct secret yields VALID and reports the header algorithm.

    **Validates: Requirements 65.1, 65.2**
    """
    result = _invoke(HS_TOKEN, "--secret", HS_SECRET)

    assert result.exit_code == 0, result.output
    assert "VALID" in result.output
    assert "INVALID" not in result.output
    assert "HS256" in result.output


def test_verify_hmac_wrong_secret_reports_invalid_with_nonzero_exit():
    """A wrong secret yields INVALID and a non-zero exit code.

    **Validates: Requirements 65.1, 65.2**
    """
    result = _invoke(HS_TOKEN, "--secret", "totally-wrong")

    assert result.exit_code == 1
    assert "INVALID" in result.output
    assert "HS256" in result.output


# ===========================================================================
# Asymmetric (--pem / --key-file / --jwks) paths — Reqs 65.1, 65.2
# ===========================================================================


def test_verify_rs256_with_inline_pem(rsa_keypair, rs256_token):
    """RS256 verification against inline PEM public key reports VALID + alg.

    **Validates: Requirements 65.1, 65.2**
    """
    _, public_pem = rsa_keypair
    result = _invoke(rs256_token, "--pem", public_pem)

    assert result.exit_code == 0, result.output
    assert "VALID" in result.output and "INVALID" not in result.output
    assert "RS256" in result.output


def test_verify_rs256_with_key_file(tmp_path, rsa_keypair, rs256_token):
    """RS256 verification against a PEM key file reports VALID.

    **Validates: Requirements 65.1, 65.2**
    """
    _, public_pem = rsa_keypair
    key_file = tmp_path / "public.pem"
    key_file.write_text(public_pem)

    result = _invoke(rs256_token, "--key-file", str(key_file))

    assert result.exit_code == 0, result.output
    assert "VALID" in result.output and "INVALID" not in result.output
    assert "RS256" in result.output


def test_verify_rs256_with_jwks_file(tmp_path, rsa_keypair, rs256_token):
    """A local JWKS file is reconstructed and used to verify (no network).

    **Validates: Requirements 65.1, 65.2, 65.3**
    """
    _, public_pem = rsa_keypair
    jwks_file = tmp_path / "jwks.json"
    jwks_file.write_text(json.dumps(_public_pem_to_jwks(public_pem)))

    result = _invoke(rs256_token, "--jwks", str(jwks_file))

    assert result.exit_code == 0, result.output
    assert "VALID" in result.output and "INVALID" not in result.output
    assert "RS256" in result.output


# ===========================================================================
# Descriptive error naming the offending key source — Req 65.4
# ===========================================================================


def test_verify_missing_jwks_file_names_the_source(rs256_token):
    """An unreadable JWKS file yields a descriptive error naming the file.

    **Validates: Requirements 65.4**
    """
    result = _invoke(rs256_token, "--jwks", "/nonexistent/does-not-exist.json")

    assert result.exit_code == 1
    assert "does-not-exist.json" in result.output
    assert "JWKS" in result.output


def test_verify_unparseable_jwks_file_names_the_source(tmp_path, rs256_token):
    """A malformed JWKS file yields a descriptive parse error naming the file.

    **Validates: Requirements 65.4**
    """
    jwks_file = tmp_path / "broken.json"
    jwks_file.write_text("{ this is not json ")

    result = _invoke(rs256_token, "--jwks", str(jwks_file))

    assert result.exit_code == 1
    assert "broken.json" in result.output


def test_verify_unparseable_pem_reports_error(rs256_token):
    """Unparseable PEM material yields a descriptive error naming PEM.

    **Validates: Requirements 65.4**
    """
    result = _invoke(rs256_token, "--pem", "-----BEGIN PUBLIC KEY-----\nnope\n")

    assert result.exit_code == 1
    assert "PEM" in result.output


def test_verify_hmac_without_secret_reports_error():
    """An HS* token with no --secret is rejected with a descriptive error.

    **Validates: Requirements 65.4**
    """
    result = _invoke(HS_TOKEN)

    assert result.exit_code == 1
    assert "secret" in result.output.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
