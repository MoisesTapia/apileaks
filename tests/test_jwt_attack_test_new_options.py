"""
Unit tests for the new ``jwt attack-test`` options.

**Feature: owasp-auth-modules-hardening, Task 38.3**

Task 38.3 adds four opt-in options to the existing ``jwt attack-test``
subcommand and threads them through the single-source-of-truth
:class:`~utils.jwt_attack_engine.JWTAttackEngine`:

* ``--fuzz-target`` + ``--vector-file``  — drive the CLAIM_FUZZING vector; the
  Vector_File is read via :func:`utils.jwt_utils.read_vector_file` and an
  unreadable file aborts BEFORE any request naming the file (Reqs 63.1, 63.6).
* ``--raw-request``  — supplies the JWT and request context, parsed via
  :func:`utils.jwt_utils.parse_raw_request`; an unparseable / token-less file
  aborts BEFORE any request naming the file (Reqs 67.1, 67.2).
* ``--canary``  — threaded to the engine ``canary_value`` (Req 67.3).

The blank-secret candidate, ``PSYCHIC_SIGNATURE``, ``TIMESTAMP_TAMPERING`` and
``CLAIM_FUZZING`` vectors run through ``execute_all`` (they are members of
``AttackType``), so wiring the options into the engine is sufficient.

When no new option is supplied the single-token path is preserved unchanged
(Req 67.5): the engine receives ``fuzz_target=None``, ``fuzz_values=[]`` and
``canary_value=None``.

Requirements: 58.1, 59.5, 63.1, 63.6, 64.1, 67.1, 67.2, 67.5

Mirrors the CliRunner / spy-engine conventions in
``tests/test_jwt_cli_subcommands.py``.
"""

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
from utils.jwt_utils import encode_jwt


URL = "https://api.example.com/protected"

BASE_TOKEN = encode_jwt(
    {"alg": "HS256", "typ": "JWT"},
    {"sub": "user-123", "role": "user"},
    "some-strong-signing-key",
)


class _SpyEngine:
    """Records construction kwargs and proves execute_all is driven once."""

    instances = []

    def __init__(self, target_url, original_token, http_engine=None,
                 signing_secret=None, public_key_material=None, safe_mode=False,
                 custom_headers=None, post_data=None, weak_secrets=None,
                 fuzz_target=None, fuzz_values=None, canary_value=None):
        self.target_url = target_url
        self.original_token = original_token
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
    """Fake shared HTTP engine — proves NO real HTTP request is made."""

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
    monkeypatch.setattr(apileaks, "JWTAttackEngine", _SpyEngine)
    import utils.http_client as http_client_mod
    monkeypatch.setattr(http_client_mod, "HTTPRequestEngine", _FakeHTTPEngine)
    return _SpyEngine


def _invoke(*args, **kwargs):
    return CliRunner().invoke(cli, ["--no-banner", "jwt", "attack-test", *args],
                              **kwargs)


# ===========================================================================
# --vector-file / --fuzz-target (Reqs 63.1, 63.6)
# ===========================================================================


def test_vector_file_and_fuzz_target_thread_values_to_engine(spy_engine, tmp_path):
    """``--fuzz-target`` + ``--vector-file`` read the file and thread the values.

    The Vector_File values reach the engine's ``fuzz_values`` and the target
    name reaches ``fuzz_target`` so the CLAIM_FUZZING vector (a member of
    ``AttackType`` executed by ``execute_all``) can substitute the named claim.

    **Validates: Requirements 63.1**
    """
    vf = tmp_path / "vectors.txt"
    vf.write_text("admin\nroot\n\nsuperuser\n")

    result = _invoke(BASE_TOKEN, "--url", URL,
                     "--fuzz-target", "role", "--vector-file", str(vf))

    assert result.exit_code == 0, result.output
    engine = spy_engine.instances[0]
    assert engine.fuzz_target == "role"
    # Blank lines are skipped by read_vector_file.
    assert engine.fuzz_values == ["admin", "root", "superuser"]
    assert engine.execute_all_called is True


def test_unreadable_vector_file_aborts_before_any_request(spy_engine):
    """An unreadable Vector_File aborts BEFORE any request, naming the file.

    No engine is constructed and the fake HTTP engine (which would raise on a
    request) is never reached.

    **Validates: Requirements 63.6**
    """
    missing = "/nonexistent/dir/vectors.txt"

    result = _invoke(BASE_TOKEN, "--url", URL,
                     "--fuzz-target", "role", "--vector-file", missing)

    assert result.exit_code == 1
    assert missing in result.output
    assert spy_engine.instances == []


def test_vector_file_without_fuzz_target_is_rejected(spy_engine, tmp_path):
    """``--vector-file`` without ``--fuzz-target`` is rejected up-front."""
    vf = tmp_path / "vectors.txt"
    vf.write_text("admin\n")

    result = _invoke(BASE_TOKEN, "--url", URL, "--vector-file", str(vf))

    assert result.exit_code == 1
    assert "--fuzz-target" in result.output
    assert spy_engine.instances == []


# ===========================================================================
# --raw-request (Reqs 67.1, 67.2)
# ===========================================================================


def test_raw_request_supplies_token_and_context(spy_engine, tmp_path):
    """``--raw-request`` populates the token, URL, headers and body (Req 67.1).

    The JWT is located in the ``Authorization: Bearer`` header, the URL is built
    from the Host header + request target, other headers seed the request
    context, and the body becomes the POST data.

    **Validates: Requirements 67.1**
    """
    raw = tmp_path / "request.txt"
    raw.write_text(
        "POST /api/data HTTP/1.1\r\n"
        "Host: api.example.com\r\n"
        f"Authorization: Bearer {BASE_TOKEN}\r\n"
        "X-Trace: abc123\r\n"
        "\r\n"
        "{\"q\": 1}"
    )

    result = _invoke("--raw-request", str(raw))

    assert result.exit_code == 0, result.output
    engine = spy_engine.instances[0]
    assert engine.original_token == BASE_TOKEN
    assert engine.target_url == "http://api.example.com/api/data"
    assert engine.custom_headers.get("X-Trace") == "abc123"
    assert engine.post_data == "{\"q\": 1}"
    assert engine.execute_all_called is True


def test_raw_request_tokenless_aborts_before_any_request(spy_engine, tmp_path):
    """A raw request with no locatable JWT aborts BEFORE any request (Req 67.2).

    **Validates: Requirements 67.2**
    """
    raw = tmp_path / "request.txt"
    raw.write_text(
        "GET /api/data HTTP/1.1\r\n"
        "Host: api.example.com\r\n"
        "\r\n"
    )

    result = _invoke("--raw-request", str(raw))

    assert result.exit_code == 1
    assert str(raw) in result.output
    assert spy_engine.instances == []


def test_raw_request_unreadable_aborts_before_any_request(spy_engine):
    """An unreadable raw request file aborts BEFORE any request, naming it.

    **Validates: Requirements 67.2**
    """
    missing = "/nonexistent/dir/request.txt"

    result = _invoke("--raw-request", missing)

    assert result.exit_code == 1
    assert missing in result.output
    assert spy_engine.instances == []


def test_explicit_header_overrides_raw_request_header(spy_engine, tmp_path):
    """An explicit ``-H`` overrides the same-named header from the raw request."""
    raw = tmp_path / "request.txt"
    raw.write_text(
        "GET /api/data HTTP/1.1\r\n"
        "Host: api.example.com\r\n"
        f"Authorization: Bearer {BASE_TOKEN}\r\n"
        "X-Trace: from-file\r\n"
        "\r\n"
    )

    result = _invoke("--raw-request", str(raw), "-H", "X-Trace: from-cli")

    assert result.exit_code == 0, result.output
    engine = spy_engine.instances[0]
    assert engine.custom_headers.get("X-Trace") == "from-cli"


# ===========================================================================
# --canary (Req 67.3)
# ===========================================================================


def test_canary_threaded_to_engine(spy_engine):
    """``--canary`` reaches the engine's ``canary_value`` (Req 67.3).

    **Validates: Requirements 67.3**
    """
    result = _invoke(BASE_TOKEN, "--url", URL, "--canary", "SECRET-FLAG")

    assert result.exit_code == 0, result.output
    engine = spy_engine.instances[0]
    assert engine.canary_value == "SECRET-FLAG"


# ===========================================================================
# Preserve existing single-token behavior when no new option supplied (67.5)
# ===========================================================================


def test_single_token_path_preserved_without_new_options(spy_engine):
    """With no new option, the engine gets no fuzz target/values and no canary.

    The blank-secret / PSYCHIC_SIGNATURE / TIMESTAMP_TAMPERING / CLAIM_FUZZING
    vectors still run via ``execute_all`` (they are ``AttackType`` members), but
    fuzzing produces no tokens without a target/values and behavior is exactly
    the pre-existing single-token path.

    **Validates: Requirements 58.1, 59.5, 64.1, 67.5**
    """
    result = _invoke(BASE_TOKEN, "--url", URL)

    assert result.exit_code == 0, result.output
    engine = spy_engine.instances[0]
    assert engine.original_token == BASE_TOKEN
    assert engine.target_url == URL
    assert engine.fuzz_target is None
    assert engine.fuzz_values == []
    assert engine.canary_value is None
    assert engine.execute_all_called is True


def test_missing_token_and_raw_request_is_rejected(spy_engine):
    """With neither TOKEN nor ``--raw-request`` the command errors out."""
    result = _invoke("--url", URL)

    assert result.exit_code == 1
    assert spy_engine.instances == []
