"""
Unit tests for the ``jwt`` CLI subcommands and the JWT consolidation structure.

**Feature: owasp-auth-modules-hardening, Task 11.3**

Task 11.1 rewired every ``jwt test-*``/``attack-test`` subcommand so attack-token
generation and execution route through the single-source-of-truth
:class:`~utils.jwt_attack_engine.JWTAttackEngine` and the shared
``HTTPRequestEngine`` (no inline attack logic; success decided by the engine's
response analyzer, not ``admin``/``dashboard`` keywords). ``jwt brute-secret``
recovers a secret iff ``verify_hmac_secret`` is True and reports the recovered
secret + matching algorithm. Task 11.2 removed
``utils/jwt_attack_token_generator.py`` (and the former orchestrator), folding all
logic into the engine.

These tests lock that behaviour in via Click's ``CliRunner``:

1. Each affected ``jwt`` subcommand routes generation/execution through
   ``JWTAttackEngine`` (Req 14.2). A spy engine patched over
   ``apileaks.JWTAttackEngine`` records construction and the vectors requested;
   no real network I/O occurs (attack-test's ``HTTPRequestEngine`` is faked).
2. The consolidation structure (Req 14.1): the token-generator file is gone, the
   module is not importable, and ``utils.jwt_attack_engine`` is the single source
   of truth with no lingering ``JWTAttackTokenGenerator``.
3. The 'no findings' result is emitted (Req 18.2): when the engine reports no
   vulnerabilities, ``attack-test`` reports "No vulnerabilities detected" and
   exits successfully.
4. ``brute-secret`` recovers a known weak secret via ``verify_hmac_secret`` and
   reports the matching algorithm (Req 14.1 consolidation / 16.4), forging the
   exploitation tokens through the engine with the recovered secret.

Mirrors the CliRunner/patching conventions in
``tests/test_dir_headers_auth_cli.py`` and the engine model usage in
``tests/test_jwt_attack_engine.py``.
"""

import importlib
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

import apileaks
from apileaks import cli
from utils.jwt_attack_models import (
    AttackConfiguration,
    AttackSession,
    AttackSummary,
    AttackType,
)
from utils.jwt_utils import decode_jwt, encode_jwt, verify_hmac_secret


# ---------------------------------------------------------------------------
# Fixtures / constants
# ---------------------------------------------------------------------------

URL = "https://api.example.com/protected"

# A generic valid HS256 token used to drive the test-* / attack-test vectors.
BASE_TOKEN = encode_jwt(
    {"alg": "HS256", "typ": "JWT"},
    {"sub": "user-123", "role": "user"},
    "some-strong-signing-key",
)

# A token deliberately signed with a *weak* secret so brute-secret recovers it
# via signature verification (Req 16.x).
WEAK_SECRET = "secret"
WEAK_TOKEN = encode_jwt(
    {"alg": "HS256", "typ": "JWT"},
    {"sub": "user-123", "role": "user"},
    WEAK_SECRET,
)

# The nine engine-routed test-* vectors and their expected AttackType.
TEST_VECTOR_COMMANDS = {
    "test-alg-none": AttackType.ALG_NONE,
    "test-null-signature": AttackType.NULL_SIGNATURE,
    "test-kid-injection": AttackType.KID_INJECTION,
    "test-jwks-spoof": AttackType.JWKS_SPOOF,
    "test-inline-jwks": AttackType.INLINE_JWKS,
}


class _SpyEngine:
    """Spy standing in for :class:`JWTAttackEngine`.

    Records construction (target_url/token/signing_secret) and every vector
    requested through ``generate_token`` / ``execute_attack`` / ``execute_all``
    so tests can prove a subcommand routed through the engine. ``generate_token``
    returns real token strings so the CLI display path works; ``execute_all``
    returns an empty (no-findings) :class:`AttackSummary` by default so no real
    network is needed.
    """

    instances = []

    def __init__(self, target_url, original_token, http_engine=None,
                 signing_secret=None, public_key_material=None, safe_mode=False,
                 custom_headers=None, post_data=None, method=None,
                 weak_secrets=None,
                 fuzz_target=None, fuzz_values=None, canary_value=None):
        self.target_url = target_url
        self.original_token = original_token
        self.http_engine = http_engine
        self.signing_secret = signing_secret
        self.custom_headers = custom_headers or {}
        self.post_data = post_data
        self.fuzz_target = fuzz_target
        self.fuzz_values = list(fuzz_values) if fuzz_values else []
        self.canary_value = canary_value
        self.generate_calls = []
        self.execute_attack_calls = []
        self.execute_all_called = False
        _SpyEngine.instances.append(self)

    def generate_token(self, attack_type):
        self.generate_calls.append(attack_type)
        return ["header.payload.sig1", "header.payload.sig2"]

    async def execute_attack(self, attack_type):
        self.execute_attack_calls.append(attack_type)
        return None

    async def execute_all(self):
        self.execute_all_called = True
        config = AttackConfiguration(
            target_url=self.target_url, original_jwt=self.original_token)
        session = AttackSession(session_id="spy-session", configuration=config)
        # Empty summary => no vulnerabilities found (Req 18.2 path).
        return AttackSummary(session=session)


class _FakeHTTPEngine:
    """Fake shared HTTP engine so attack-test constructs no real client.

    ``execute_all`` is handled by :class:`_SpyEngine`, so ``request`` must never
    be called; only ``close`` is awaited by the subcommand.
    """

    def __init__(self, *args, **kwargs):
        self.closed = False

    async def request(self, *args, **kwargs):  # pragma: no cover
        raise AssertionError("no real HTTP request expected in CLI unit tests")

    async def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def _reset_spy():
    _SpyEngine.instances.clear()
    yield
    _SpyEngine.instances.clear()


@pytest.fixture
def spy_engine(monkeypatch):
    """Patch ``apileaks.JWTAttackEngine`` with the spy for the duration of a test."""
    monkeypatch.setattr(apileaks, "JWTAttackEngine", _SpyEngine)
    return _SpyEngine


def _invoke(*args, **kwargs):
    return CliRunner().invoke(cli, ["--no-banner", "jwt", *args], **kwargs)


# ===========================================================================
# 1. Each affected subcommand routes through JWTAttackEngine (Req 14.2)
# ===========================================================================


@pytest.mark.parametrize("subcommand,expected_type", list(TEST_VECTOR_COMMANDS.items()))
def test_test_vector_subcommand_routes_through_engine(spy_engine, subcommand,
                                                      expected_type):
    """Each ``jwt test-*`` vector generates its tokens via ``JWTAttackEngine``.

    Invoked without ``--url`` (no live endpoint needed): the subcommand builds a
    :class:`JWTAttackEngine` and asks it for exactly its own vector's tokens
    rather than reimplementing generation inline.

    **Validates: Requirements 14.2**
    """
    result = _invoke(subcommand, BASE_TOKEN)

    assert result.exit_code == 0, result.output
    # The engine was constructed and used for this vector (single source of truth).
    assert len(spy_engine.instances) >= 1
    engine = spy_engine.instances[0]
    assert expected_type in engine.generate_calls
    # No inline generation: the vector requested matches the subcommand.
    assert engine.generate_calls == [expected_type]


def test_attack_test_routes_execution_through_engine(spy_engine, monkeypatch):
    """``jwt attack-test`` drives every vector through ``engine.execute_all``.

    The shared ``HTTPRequestEngine`` is faked so no real network call is made;
    the spy proves the subcommand delegates execution to the engine rather than
    running attack logic inline.

    **Validates: Requirements 14.2**
    """
    import utils.http_client as http_client_mod
    monkeypatch.setattr(http_client_mod, "HTTPRequestEngine", _FakeHTTPEngine)

    result = _invoke("attack-test", BASE_TOKEN, "--url", URL)

    assert result.exit_code == 0, result.output
    assert len(spy_engine.instances) == 1
    engine = spy_engine.instances[0]
    assert engine.execute_all_called is True
    # The engine received the target URL the operator supplied.
    assert engine.target_url == URL


def test_test_vector_without_url_makes_no_http_engine(spy_engine, monkeypatch):
    """A test-* vector without ``--url`` never constructs a shared HTTP engine.

    Guards that generation-only invocations perform no network setup: if the CLI
    tried to build an ``HTTPRequestEngine`` the fake would flag it, but the
    generation path must not reach it at all.

    **Validates: Requirements 14.2, 17.1**
    """
    built = {"count": 0}

    class _TrackingHTTPEngine(_FakeHTTPEngine):
        def __init__(self, *args, **kwargs):
            built["count"] += 1
            super().__init__(*args, **kwargs)

    import utils.http_client as http_client_mod
    monkeypatch.setattr(http_client_mod, "HTTPRequestEngine", _TrackingHTTPEngine)

    result = _invoke("test-alg-none", BASE_TOKEN)

    assert result.exit_code == 0, result.output
    assert built["count"] == 0
    assert spy_engine.instances[0].generate_calls == [AttackType.ALG_NONE]


# ---------------------------------------------------------------------------
# decode / encode remain functional utility subcommands (no engine needed)
# ---------------------------------------------------------------------------


def test_decode_subcommand_outputs_header_and_payload():
    """``jwt decode`` decodes a token and prints its header/payload JSON.

    **Validates: Requirements 14.2**
    """
    result = _invoke("decode", BASE_TOKEN)

    assert result.exit_code == 0, result.output
    assert '"role": "user"' in result.output
    assert '"sub": "user-123"' in result.output


def test_encode_subcommand_emits_a_verifiable_token():
    """``jwt encode`` produces a token that decodes to the supplied payload.

    **Validates: Requirements 14.2**
    """
    payload = {"sub": "admin", "role": "admin"}
    result = _invoke("encode", json.dumps(payload), "--secret", "k")

    assert result.exit_code == 0, result.output
    # The generated token is the last non-empty line before the trailing banner.
    tokens = [line.strip() for line in result.output.splitlines()
              if line.count(".") == 2 and " " not in line.strip()]
    assert tokens, result.output
    decoded = decode_jwt(tokens[-1])
    assert decoded["payload"] == payload
    assert verify_hmac_secret(tokens[-1], "k")


# ===========================================================================
# 2. Consolidation structure — single source of truth (Req 14.1)
# ===========================================================================

_UTILS_DIR = Path(apileaks.__file__).resolve().parent / "utils"


def test_token_generator_file_removed():
    """``utils/jwt_attack_token_generator.py`` no longer exists (Req 14.1)."""
    assert not (_UTILS_DIR / "jwt_attack_token_generator.py").exists()


def test_token_generator_module_not_importable():
    """The removed generator module cannot be imported (Req 14.1)."""
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("utils.jwt_attack_token_generator")


def test_engine_is_the_single_source_of_truth():
    """``utils.jwt_attack_engine`` provides the one generation implementation.

    Confirms ``JWTAttackEngine`` owns per-vector ``generate_token`` and that no
    lingering ``JWTAttackTokenGenerator`` remains importable (Req 14.1).
    """
    engine_mod = importlib.import_module("utils.jwt_attack_engine")
    assert hasattr(engine_mod, "JWTAttackEngine")
    assert hasattr(engine_mod.JWTAttackEngine, "generate_token")
    assert not hasattr(engine_mod, "JWTAttackTokenGenerator")
    # The CLI binds to the same single engine class.
    assert apileaks.JWTAttackEngine is engine_mod.JWTAttackEngine


# ===========================================================================
# 3. No-findings result emitted (Req 18.2)
# ===========================================================================


def test_attack_test_reports_no_vulnerabilities_when_engine_finds_none(spy_engine,
                                                                       monkeypatch):
    """A clean engine summary yields a 'no vulnerabilities' message + exit 0.

    **Validates: Requirements 18.2**
    """
    import utils.http_client as http_client_mod
    monkeypatch.setattr(http_client_mod, "HTTPRequestEngine", _FakeHTTPEngine)

    result = _invoke("attack-test", BASE_TOKEN, "--url", URL)

    assert result.exit_code == 0, result.output
    assert "No vulnerabilities detected" in result.output
    assert "Attack testing completed successfully" in result.output


# ===========================================================================
# 4. brute-secret recovers a weak secret + reports the matching algorithm
# ===========================================================================


def _write_wordlist(tmp_path, secrets):
    path = tmp_path / "secrets.txt"
    path.write_text("\n".join(secrets) + "\n")
    return str(path)


def test_brute_secret_recovers_weak_secret_and_reports_algorithm(tmp_path):
    """``brute-secret`` recovers a weak HMAC secret and reports its algorithm.

    Drives the real recovery path (``verify_hmac_secret`` over the original
    ``header.payload`` segments) with a wordlist containing the true secret; the
    forged exploitation tokens are generated by the real engine (no ``--url`` =>
    no network).

    **Validates: Requirements 14.1, 18.2**
    """
    wordlist = _write_wordlist(tmp_path, ["wrong1", "nope", WEAK_SECRET, "another"])

    result = _invoke("brute-secret", WEAK_TOKEN, "-w", wordlist)

    assert result.exit_code == 0, result.output
    assert "HMAC SECRET RECOVERED" in result.output
    assert f"Recovered Secret: '{WEAK_SECRET}'" in result.output
    # The matching algorithm (the token header alg) is reported (Req 16.4).
    assert "Matching Algorithm: HS256" in result.output


def test_brute_secret_forges_through_engine_with_recovered_secret(spy_engine,
                                                                  tmp_path):
    """The recovered secret becomes the engine's signing key for forging.

    Proves the consolidation: after recovery, ``brute-secret`` forges the
    exploitation vectors through ``JWTAttackEngine`` seeded with the recovered
    secret rather than any inline generator.

    **Validates: Requirements 14.1, 14.2**
    """
    wordlist = _write_wordlist(tmp_path, [WEAK_SECRET])

    result = _invoke("brute-secret", WEAK_TOKEN, "-w", wordlist)

    assert result.exit_code == 0, result.output
    assert spy_engine.instances, "expected the engine to be used for forging"
    forging_engine = spy_engine.instances[-1]
    assert forging_engine.signing_secret == WEAK_SECRET
    # The forge vectors are generated through the single engine.
    assert AttackType.PRIVILEGE_ESCALATION in forging_engine.generate_calls
    assert AttackType.WEAK_SECRET in forging_engine.generate_calls


def test_brute_secret_reports_not_found_for_strong_secret(tmp_path):
    """A wordlist missing the true secret yields a 'not found' result, exit 0.

    Confirms recovery is signature-driven: no candidate verifies, so nothing is
    (falsely) reported as recovered.

    **Validates: Requirements 14.1**
    """
    wordlist = _write_wordlist(tmp_path, ["wrong1", "wrong2", "wrong3"])

    result = _invoke("brute-secret", WEAK_TOKEN, "-w", wordlist)

    assert result.exit_code == 0, result.output
    assert "Secret not found" in result.output
    assert "HMAC SECRET RECOVERED" not in result.output


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
