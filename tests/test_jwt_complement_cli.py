"""
CLI subcommand unit tests for the new ``jwt`` complement subcommands and options.

**Feature: owasp-auth-modules-hardening, Task 39.2**

This file consolidates end-to-end ``CliRunner`` coverage for the JWT-complement
CLI surface added by Task 38, exercising the real command wiring (option
parsing, key-source handling, and the up-front error-before-request ordering)
without any network I/O:

* ``jwt verify`` — network-free Token_Verification reporting signature validity
  and the header algorithm; an unreadable/unparseable key source is rejected
  with a descriptive error naming the offending source (Reqs 65.1, 65.2, 65.4).
* ``jwt genkey`` — emits both generated public and private key material for an
  RSA or EC keypair, locally (Req 66.1).
* ``jwt jwks-to-key`` — reconstructs a public-key PEM from a local JWKS entry and
  rejects unparseable/insufficient input with a descriptive error (Reqs 66.2,
  66.5).
* ``jwt attack-test`` new options — ``--vector-file`` (read before any request;
  an unreadable file aborts naming it, Req 63.6), ``--raw-request`` (parsed
  before any request; an unparseable/token-less file aborts naming it, Req 67.2),
  and ``--canary`` (threaded to the engine). When no new option is supplied the
  single-token path is preserved unchanged (Req 67.5).

The ``attack-test`` cases patch ``apileaks.JWTAttackEngine`` with a spy and
``utils.http_client.HTTPRequestEngine`` with a fake so the "before any request"
guarantee is asserted structurally: the error-before-request cases construct
neither the engine nor an HTTP client. Mirrors the CliRunner/patching
conventions in ``tests/test_jwt_cli_subcommands.py`` and
``tests/test_jwt_attack_test_new_options.py``.
"""

import base64
import json

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization

import apileaks
from apileaks import cli
from utils.jwt_attack_models import (
    AttackConfiguration,
    AttackSession,
    AttackSummary,
)
from utils.jwt_utils import encode_jwt, generate_rsa_keypair


# ---------------------------------------------------------------------------
# Constants / helpers
# ---------------------------------------------------------------------------

URL = "https://api.example.com/protected"

# A generic valid HS256 token used to drive verify / attack-test paths.
HS256_SECRET = "some-strong-signing-key"
HS256_TOKEN = encode_jwt(
    {"alg": "HS256", "typ": "JWT"},
    {"sub": "user-123", "role": "user"},
    HS256_SECRET,
)


def _b64uint(value: int) -> str:
    """Base64url-encode an unsigned integer without padding (JWK n/e style)."""
    length = (value.bit_length() + 7) // 8 or 1
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


def _rsa_jwk_from_pem(public_pem: str) -> dict:
    """Build a minimal RSA JWK entry ({"kty","n","e"}) from a public PEM."""
    public_key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    numbers = public_key.public_numbers()
    return {"kty": "RSA", "n": _b64uint(numbers.n), "e": _b64uint(numbers.e)}


def _invoke(*args, **kwargs):
    return CliRunner().invoke(cli, ["--no-banner", "jwt", *args], **kwargs)


# ---------------------------------------------------------------------------
# Spy engine + fake HTTP engine for the attack-test option cases
# ---------------------------------------------------------------------------


class _SpyEngine:
    """Records construction so tests can prove the option-threading behavior.

    ``execute_all`` returns an empty (no-findings) summary so no network is
    needed; ``generate_token`` returns real-looking token strings for the
    display path.
    """

    instances = []

    def __init__(self, target_url, original_token, http_engine=None,
                 signing_secret=None, public_key_material=None, safe_mode=False,
                 custom_headers=None, post_data=None, weak_secrets=None,
                 fuzz_target=None, fuzz_values=None, canary_value=None):
        self.target_url = target_url
        self.original_token = original_token
        self.http_engine = http_engine
        self.custom_headers = custom_headers or {}
        self.post_data = post_data
        self.fuzz_target = fuzz_target
        self.fuzz_values = list(fuzz_values) if fuzz_values else []
        self.canary_value = canary_value
        self.execute_all_called = False
        _SpyEngine.instances.append(self)

    def generate_token(self, attack_type):
        return ["header.payload.sig"]

    async def execute_attack(self, attack_type):
        return None

    async def execute_all(self):
        self.execute_all_called = True
        config = AttackConfiguration(
            target_url=self.target_url, original_jwt=self.original_token)
        session = AttackSession(session_id="spy-session", configuration=config)
        return AttackSummary(session=session)


class _FakeHTTPEngine:
    """Fake shared HTTP engine: any real request is an error; only close awaited."""

    built = 0

    def __init__(self, *args, **kwargs):
        _FakeHTTPEngine.built += 1
        self.closed = False

    async def request(self, *args, **kwargs):  # pragma: no cover - must not run
        raise AssertionError("no real HTTP request expected in CLI unit tests")

    async def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def _reset_doubles():
    _SpyEngine.instances.clear()
    _FakeHTTPEngine.built = 0
    yield
    _SpyEngine.instances.clear()
    _FakeHTTPEngine.built = 0


@pytest.fixture
def spy_engine(monkeypatch):
    """Patch the engine + shared HTTP engine used by ``jwt attack-test``."""
    monkeypatch.setattr(apileaks, "JWTAttackEngine", _SpyEngine)
    import utils.http_client as http_client_mod
    monkeypatch.setattr(http_client_mod, "HTTPRequestEngine", _FakeHTTPEngine)
    return _SpyEngine


# ===========================================================================
# jwt verify — validity + algorithm reporting and key-source error (Req 65)
# ===========================================================================


def test_verify_reports_valid_and_algorithm_for_correct_secret():
    """``jwt verify`` reports a VALID signature and the header algorithm.

    Network-free HS256 verification against the correct shared secret exits 0.

    **Validates: Requirements 65.1, 65.2**
    """
    result = _invoke("verify", HS256_TOKEN, "--secret", HS256_SECRET)

    assert result.exit_code == 0, result.output
    assert "✅ VALID" in result.output
    assert "Algorithm: HS256" in result.output


def test_verify_reports_invalid_for_wrong_secret():
    """A wrong secret yields an INVALID (reported, not errored) result, exit 1.

    **Validates: Requirements 65.1, 65.2**
    """
    result = _invoke("verify", HS256_TOKEN, "--secret", "the-wrong-secret")

    assert result.exit_code == 1, result.output
    assert "INVALID" in result.output
    assert "Algorithm: HS256" in result.output


def test_verify_unreadable_key_source_names_the_source():
    """An unreadable JWKS key source is rejected with an error naming the file.

    The key source is read up-front (network-free); a missing file produces a
    descriptive error that names the offending source and exits non-zero.

    **Validates: Requirements 65.4**
    """
    missing = "/nonexistent/dir/keys.json"

    result = _invoke("verify", HS256_TOKEN, "--jwks", missing)

    assert result.exit_code == 1
    assert missing in result.output


# ===========================================================================
# jwt genkey — emits generated public + private material (Req 66.1)
# ===========================================================================


@pytest.mark.parametrize("key_args", [["--type", "rsa"], ["--type", "ec"]])
def test_genkey_emits_public_and_private_material(key_args):
    """``jwt genkey`` emits both the private and public key material locally.

    **Validates: Requirements 66.1**
    """
    result = _invoke("genkey", *key_args)

    assert result.exit_code == 0, result.output
    assert "Private Key" in result.output
    assert "Public Key" in result.output
    assert "BEGIN PRIVATE KEY" in result.output
    assert "BEGIN PUBLIC KEY" in result.output


# ===========================================================================
# jwt jwks-to-key — reconstruct PEM / reject bad input (Reqs 66.2, 66.5)
# ===========================================================================


def test_jwks_to_key_reconstructs_public_key(tmp_path):
    """A local RSA JWKS entry reconstructs a public-key PEM (no network).

    **Validates: Requirements 66.2**
    """
    _, public_pem = generate_rsa_keypair()
    jwks_file = tmp_path / "jwks.json"
    jwks_file.write_text(json.dumps({"keys": [_rsa_jwk_from_pem(public_pem)]}))

    result = _invoke("jwks-to-key", "--jwks", str(jwks_file))

    assert result.exit_code == 0, result.output
    assert "BEGIN PUBLIC KEY" in result.output


def test_jwks_to_key_unparseable_input_names_the_source(tmp_path):
    """Malformed JWKS JSON is rejected with a descriptive error naming the file.

    **Validates: Requirements 66.5**
    """
    jwks_file = tmp_path / "broken.json"
    jwks_file.write_text("{ this is not valid json ")

    result = _invoke("jwks-to-key", "--jwks", str(jwks_file))

    assert result.exit_code == 1
    assert str(jwks_file) in result.output


def test_jwks_to_key_insufficient_parameters_reports_error(tmp_path):
    """An RSA JWK lacking the required ``n``/``e`` parameters is rejected.

    **Validates: Requirements 66.5**
    """
    jwks_file = tmp_path / "insufficient.json"
    jwks_file.write_text(json.dumps({"keys": [{"kty": "RSA"}]}))

    result = _invoke("jwks-to-key", "--jwks", str(jwks_file))

    assert result.exit_code == 1
    assert "Error" in result.output


# ===========================================================================
# jwt attack-test — --vector-file error-before-request (Req 63.6)
# ===========================================================================


def test_unreadable_vector_file_aborts_before_any_request(spy_engine):
    """An unreadable Vector_File aborts BEFORE any request, naming the file.

    Neither the attack engine nor a shared HTTP engine is constructed, so the
    failure is provably before any request is issued.

    **Validates: Requirements 63.6**
    """
    missing = "/nonexistent/dir/vectors.txt"

    result = _invoke("attack-test", HS256_TOKEN, "--url", URL,
                     "--fuzz-target", "role", "--vector-file", missing)

    assert result.exit_code == 1
    assert missing in result.output
    assert _SpyEngine.instances == []
    assert _FakeHTTPEngine.built == 0


# ===========================================================================
# jwt attack-test — --raw-request error-before-request (Req 67.2)
# ===========================================================================


def test_unparseable_raw_request_aborts_before_any_request(spy_engine, tmp_path):
    """A raw request with no locatable JWT aborts BEFORE any request, naming it.

    **Validates: Requirements 67.2**
    """
    raw = tmp_path / "request.txt"
    raw.write_text(
        "GET /profile HTTP/1.1\r\n"
        "Host: api.example.com\r\n"
        "Accept: application/json\r\n\r\n"
    )

    result = _invoke("attack-test", "--raw-request", str(raw))

    assert result.exit_code == 1
    assert str(raw) in result.output
    assert _SpyEngine.instances == []
    assert _FakeHTTPEngine.built == 0


def test_unreadable_raw_request_aborts_before_any_request(spy_engine):
    """An unreadable raw request file aborts BEFORE any request, naming it.

    **Validates: Requirements 67.2**
    """
    missing = "/nonexistent/dir/request.txt"

    result = _invoke("attack-test", "--raw-request", missing)

    assert result.exit_code == 1
    assert missing in result.output
    assert _SpyEngine.instances == []
    assert _FakeHTTPEngine.built == 0


# ===========================================================================
# jwt attack-test — single-token path preserved / --canary threaded (Req 67.5)
# ===========================================================================


def test_single_token_path_preserved_when_no_new_option(spy_engine):
    """With only TOKEN + --url (no new option) the single-token path is intact.

    The engine is constructed with no fuzz target/values and no canary, and the
    attack run proceeds through ``execute_all`` exactly as before.

    **Validates: Requirements 67.5**
    """
    result = _invoke("attack-test", HS256_TOKEN, "--url", URL)

    assert result.exit_code == 0, result.output
    assert len(_SpyEngine.instances) == 1
    engine = _SpyEngine.instances[0]
    assert engine.target_url == URL
    assert engine.original_token == HS256_TOKEN
    assert engine.fuzz_target is None
    assert engine.fuzz_values == []
    assert engine.canary_value is None
    assert engine.execute_all_called is True


def test_canary_is_threaded_to_the_engine(spy_engine):
    """``--canary`` reaches the engine's ``canary_value`` (corroborating only).

    **Validates: Requirements 67.5**
    """
    result = _invoke("attack-test", HS256_TOKEN, "--url", URL,
                     "--canary", "SECRET-FLAG")

    assert result.exit_code == 0, result.output
    assert len(_SpyEngine.instances) == 1
    assert _SpyEngine.instances[0].canary_value == "SECRET-FLAG"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
