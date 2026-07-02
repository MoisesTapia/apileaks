"""
Unit tests for the ``jwt genkey`` and ``jwt jwks-to-key`` CLI subcommands.

**Feature: owasp-auth-modules-hardening, Task 38.2**

``jwt genkey --type {rsa,ec}`` generates a fresh test keypair via
:func:`utils.jwt_utils.generate_rsa_keypair` / ``generate_ec_keypair`` and emits
the generated public and private key material. ``jwt jwks-to-key --jwks FILE``
reads a local JWKS entry and prints the reconstructed public-key PEM via
:func:`utils.jwt_utils.reconstruct_public_key_from_jwks`. Both operate without
any HTTP request for local input and reject unparseable/insufficient input with
a descriptive error.

Covers Requirements:
  - 66.1 generate an RSA or EC keypair and emit public + private material
  - 66.2 reconstruct a public key from a JWKS entry (RSA n/e or EC x/y)
  - 66.4 operate without any HTTP request for local input
  - 66.5 descriptive error for unparseable/parameter-missing JWKS input

Mirrors the CliRunner conventions in ``tests/test_jwt_verify_cli.py``.
"""

import base64
import json

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization

from apileaks import cli
from utils.jwt_utils import (
    generate_rsa_keypair,
    generate_ec_keypair,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _invoke(*args):
    return CliRunner().invoke(cli, ["--no-banner", "jwt", *args])


def _b64uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _rsa_jwk(public_pem: str) -> dict:
    """Build a minimal RSA JWK entry from a public PEM."""
    public_key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    numbers = public_key.public_numbers()
    return {"kty": "RSA", "n": _b64uint(numbers.n), "e": _b64uint(numbers.e)}


_EC_CRV = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}


def _ec_jwk(public_pem: str) -> dict:
    """Build a minimal EC JWK entry from a public PEM."""
    public_key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    numbers = public_key.public_numbers()
    return {
        "kty": "EC",
        "crv": _EC_CRV[numbers.curve.name],
        "x": _b64uint(numbers.x),
        "y": _b64uint(numbers.y),
    }


def _normalize_pem(pem: str) -> str:
    """Load a public PEM and re-serialize to a canonical SPKI PEM for comparison."""
    key = serialization.load_pem_public_key(pem.encode("utf-8"))
    return key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


@pytest.fixture(scope="module")
def rsa_keypair():
    return generate_rsa_keypair(bits=2048)


@pytest.fixture(scope="module")
def ec_keypair():
    return generate_ec_keypair(curve="ES256")


# ===========================================================================
# jwt genkey — Reqs 66.1, 66.4
# ===========================================================================


def test_genkey_rsa_emits_private_and_public_pem():
    """``genkey --type rsa`` emits usable private and public PEM material.

    **Validates: Requirements 66.1, 66.4**
    """
    result = _invoke("genkey", "--type", "rsa")

    assert result.exit_code == 0, result.output
    assert "BEGIN PRIVATE KEY" in result.output
    assert "BEGIN PUBLIC KEY" in result.output
    # The emitted material must load as real keys.
    private_marker = "-----BEGIN PRIVATE KEY-----"
    public_marker = "-----BEGIN PUBLIC KEY-----"
    assert private_marker in result.output and public_marker in result.output


def test_genkey_rsa_material_loads_as_valid_keys():
    """The emitted RSA PEM blocks parse back into valid key objects.

    **Validates: Requirements 66.1**
    """
    result = _invoke("genkey", "--type", "rsa", "--bits", "2048")
    assert result.exit_code == 0, result.output

    priv = _extract_pem(result.output, "PRIVATE KEY")
    pub = _extract_pem(result.output, "PUBLIC KEY")
    # Neither call should raise.
    serialization.load_pem_private_key(priv.encode("utf-8"), password=None)
    serialization.load_pem_public_key(pub.encode("utf-8"))


def test_genkey_ec_emits_private_and_public_pem():
    """``genkey --type ec`` emits usable EC private and public PEM material.

    **Validates: Requirements 66.1, 66.4**
    """
    result = _invoke("genkey", "--type", "ec", "--curve", "ES256")

    assert result.exit_code == 0, result.output
    priv = _extract_pem(result.output, "PRIVATE KEY")
    pub = _extract_pem(result.output, "PUBLIC KEY")
    serialization.load_pem_private_key(priv.encode("utf-8"), password=None)
    serialization.load_pem_public_key(pub.encode("utf-8"))


def test_genkey_rejects_invalid_type():
    """An unsupported --type value is rejected by Click with a non-zero exit.

    **Validates: Requirements 66.1**
    """
    result = _invoke("genkey", "--type", "dsa")
    assert result.exit_code != 0


# ===========================================================================
# jwt jwks-to-key — Reqs 66.2, 66.4
# ===========================================================================


def test_jwks_to_key_reconstructs_rsa_public_key(tmp_path, rsa_keypair):
    """A local RSA JWKS entry round-trips to the original public key PEM.

    **Validates: Requirements 66.2, 66.4**
    """
    _, public_pem = rsa_keypair
    jwks_file = tmp_path / "jwks.json"
    jwks_file.write_text(json.dumps({"keys": [_rsa_jwk(public_pem)]}))

    result = _invoke("jwks-to-key", "--jwks", str(jwks_file))

    assert result.exit_code == 0, result.output
    reconstructed = _extract_pem(result.output, "PUBLIC KEY")
    assert _normalize_pem(reconstructed) == _normalize_pem(public_pem)


def test_jwks_to_key_accepts_single_jwk_entry(tmp_path, rsa_keypair):
    """A bare single JWK entry (no {"keys": [...]}) is accepted.

    **Validates: Requirements 66.2**
    """
    _, public_pem = rsa_keypair
    jwks_file = tmp_path / "single.json"
    jwks_file.write_text(json.dumps(_rsa_jwk(public_pem)))

    result = _invoke("jwks-to-key", "--jwks", str(jwks_file))

    assert result.exit_code == 0, result.output
    reconstructed = _extract_pem(result.output, "PUBLIC KEY")
    assert _normalize_pem(reconstructed) == _normalize_pem(public_pem)


def test_jwks_to_key_reconstructs_ec_public_key(tmp_path, ec_keypair):
    """A local EC JWKS entry round-trips to the original public key PEM.

    **Validates: Requirements 66.2, 66.4**
    """
    _, public_pem = ec_keypair
    jwks_file = tmp_path / "ec.json"
    jwks_file.write_text(json.dumps({"keys": [_ec_jwk(public_pem)]}))

    result = _invoke("jwks-to-key", "--jwks", str(jwks_file))

    assert result.exit_code == 0, result.output
    reconstructed = _extract_pem(result.output, "PUBLIC KEY")
    assert _normalize_pem(reconstructed) == _normalize_pem(public_pem)


# ===========================================================================
# Descriptive errors for bad input — Req 66.5
# ===========================================================================


def test_jwks_to_key_missing_file_names_the_source():
    """An unreadable JWKS file yields a descriptive error naming the file.

    **Validates: Requirements 66.5**
    """
    result = _invoke("jwks-to-key", "--jwks", "/nonexistent/missing-jwks.json")

    assert result.exit_code == 1
    assert "missing-jwks.json" in result.output
    assert "JWKS" in result.output


def test_jwks_to_key_unparseable_file_names_the_source(tmp_path):
    """A malformed JWKS file yields a descriptive parse error naming the file.

    **Validates: Requirements 66.5**
    """
    jwks_file = tmp_path / "broken.json"
    jwks_file.write_text("{ not valid json ")

    result = _invoke("jwks-to-key", "--jwks", str(jwks_file))

    assert result.exit_code == 1
    assert "broken.json" in result.output


def test_jwks_to_key_missing_parameters_reports_error(tmp_path):
    """An RSA JWK lacking 'n'/'e' yields a descriptive reconstruction error.

    **Validates: Requirements 66.5**
    """
    jwks_file = tmp_path / "insufficient.json"
    jwks_file.write_text(json.dumps({"keys": [{"kty": "RSA"}]}))

    result = _invoke("jwks-to-key", "--jwks", str(jwks_file))

    assert result.exit_code == 1
    assert "Error reconstructing public key" in result.output


def test_jwks_to_key_empty_keys_reports_error(tmp_path):
    """A JWKS with an empty key list is rejected with a descriptive error.

    **Validates: Requirements 66.5**
    """
    jwks_file = tmp_path / "empty.json"
    jwks_file.write_text(json.dumps({"keys": []}))

    result = _invoke("jwks-to-key", "--jwks", str(jwks_file))

    assert result.exit_code == 1
    assert "no key entries" in result.output


# ---------------------------------------------------------------------------
# Local helper
# ---------------------------------------------------------------------------


def _extract_pem(output: str, marker: str) -> str:
    """Extract the ``-----BEGIN {marker}-----`` ... ``END`` block from output."""
    begin = f"-----BEGIN {marker}-----"
    end = f"-----END {marker}-----"
    start = output.index(begin)
    stop = output.index(end) + len(end)
    return output[start:stop] + "\n"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
