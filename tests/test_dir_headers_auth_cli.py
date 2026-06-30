"""
Unit tests for header / cookie / basic-auth threading in the ``dir`` command.

**Feature: owasp-complete-purple-teaming-cicd, Task 28.3**

These tests lock in how the ``dir`` command threads the discovery header options
(``-H``/``--header``, ``--cookie``, ``--basic-auth``) into the configuration the
engine consumes, and how those options are carried into a Targeted_Follow_Up_Scan
and (deliberately) NOT applied when a prior session is reloaded. They mirror the
patterns in ``tests/test_rate_limit_user_agent_cli.py`` and
``tests/test_discovery_controls_cli.py`` (config-dict capture via a patched
loader, ``run_enhanced_apileak`` patched to prove validation runs before any
discovery) and ``tests/test_discovery_auth_and_proxy.py`` (building the discovery
HTTP client with endpoint discovery disabled so the engine wiring is exercised
without any network I/O).

Covered behaviour:

- ``-H``/``--header`` values reach ``custom_headers`` and become engine-level
  default headers applied to every Discovery_Request (Requirement 24.2).
- ``--cookie`` reaches ``custom_headers['Cookie']`` and becomes a default header
  applied to every Discovery_Request (Requirement 24.3).
- ``--basic-auth`` maps onto the anonymous auth context and produces an HTTP
  Basic ``Authorization`` header (Requirement 24.4).
- ``--basic-auth`` together with ``--jwt`` errors with no discovery (24.5), and a
  colon-less ``--basic-auth`` value errors with no discovery (24.6).
- the Targeted_Follow_Up_Scan rebuilds the same header/cookie/basic-auth config
  from the params the triage path passes (Requirement 24.7).
- a reloaded session (``--load-session``) performs no discovery and threads no
  header options into any discovery config (Requirement 24.8).
"""

import base64
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

import apileaks
from apileaks import cli, _run_targeted_follow_up_scan
from core.engine import APILeakCore
from utils.discovery_session import DiscoveryResult, DiscoverySession
from utils.http_client import Request


TARGET = "https://api.example.com"


class _ShortCircuit(Exception):
    """Sentinel raised to stop a command once ``config_dict`` is captured."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _invoke_dir_capturing_config(args, *, input=None):
    """Invoke ``dir`` and capture the ``config_dict`` handed to the loader.

    ``ConfigurationManager.load_config_from_dict`` is the first consumer of the
    fully threaded config, so capturing its argument lets us inspect the header /
    cookie / basic-auth threading without performing a real scan.
    """
    captured = {}

    def _capture(self, config_dict):
        captured["config_dict"] = config_dict
        raise _ShortCircuit()

    runner = CliRunner()
    with patch.object(
        apileaks.ConfigurationManager, "load_config_from_dict", _capture
    ):
        runner.invoke(
            cli,
            ["--no-banner", "dir", "--target", TARGET, *args],
            input=input,
        )
    return captured.get("config_dict")


async def _build_discovery_http_client(args):
    """Build the discovery HTTP client the ``dir`` command would construct.

    Captures the threaded ``config_dict``, disables endpoint/parameter discovery
    so the engine builds the HTTP client without any network I/O, loads the real
    config, and runs the discovery phase — exactly mirroring
    ``tests/test_discovery_auth_and_proxy.py``. The returned client exposes the
    engine-level ``default_headers`` (applied to every Discovery_Request) and the
    active auth context.
    """
    config_dict = _invoke_dir_capturing_config(args)
    assert config_dict is not None

    # No network: the engine still constructs the discovery HTTP client.
    config_dict["fuzzing"]["endpoints"]["enabled"] = False
    config_dict["fuzzing"]["parameters"]["enabled"] = False

    config = apileaks.ConfigurationManager().load_config_from_dict(config_dict)
    core = APILeakCore(config)
    await core._execute_discovery_phase(config.target.base_url)
    return core.fuzzing_orchestrator.http_client


# ---------------------------------------------------------------------------
# --header / -H threading (Requirement 24.2)
# ---------------------------------------------------------------------------

def test_header_option_reaches_custom_headers():
    """``-H "Name: Value"`` lands in the fuzzing header config's custom_headers.

    **Validates: Requirements 24.2**
    """
    config_dict = _invoke_dir_capturing_config(["-H", "X-Token: abc123"])

    custom_headers = config_dict["fuzzing"]["headers"]["custom_headers"]
    assert custom_headers["X-Token"] == "abc123"


def test_multiple_header_options_reach_custom_headers():
    """Repeated ``--header`` values are all threaded into custom_headers.

    **Validates: Requirements 24.2**
    """
    config_dict = _invoke_dir_capturing_config(
        ["--header", "X-Token: abc123", "-H", "X-Env: staging"]
    )

    custom_headers = config_dict["fuzzing"]["headers"]["custom_headers"]
    assert custom_headers["X-Token"] == "abc123"
    assert custom_headers["X-Env"] == "staging"


@pytest.mark.asyncio
async def test_header_options_applied_to_every_request():
    """Supplied headers become engine default headers (applied to every request).

    The engine forwards ``custom_headers`` (minus the rotator-managed
    User-Agent) as ``default_headers``, which ``HTTPRequestEngine.request``
    applies to every Discovery_Request it issues.

    **Validates: Requirements 24.2**
    """
    http_client = await _build_discovery_http_client(
        ["-H", "X-Token: abc123", "-H", "X-Env: staging"]
    )

    assert http_client.default_headers.get("X-Token") == "abc123"
    assert http_client.default_headers.get("X-Env") == "staging"
    # The User-Agent stays managed by the rotator, not a forced default header.
    assert "User-Agent" not in http_client.default_headers

    # Prove the default headers actually reach a per-request header set the same
    # way HTTPRequestEngine.request applies them (setdefault, never overriding).
    request = Request(method="GET", url=f"{TARGET}/anything")
    for name, value in http_client.default_headers.items():
        request.headers.setdefault(name, value)
    assert request.headers["X-Token"] == "abc123"
    assert request.headers["X-Env"] == "staging"


# ---------------------------------------------------------------------------
# --cookie threading (Requirement 24.3)
# ---------------------------------------------------------------------------

def test_cookie_option_reaches_custom_headers_cookie_key():
    """``--cookie`` is carried under ``custom_headers['Cookie']``.

    **Validates: Requirements 24.3**
    """
    config_dict = _invoke_dir_capturing_config(["--cookie", "sid=42; theme=dark"])

    custom_headers = config_dict["fuzzing"]["headers"]["custom_headers"]
    assert custom_headers["Cookie"] == "sid=42; theme=dark"


@pytest.mark.asyncio
async def test_cookie_applied_to_every_request():
    """The cookie string becomes a default ``Cookie`` header on every request.

    **Validates: Requirements 24.3**
    """
    http_client = await _build_discovery_http_client(
        ["--cookie", "sid=42; theme=dark"]
    )

    assert http_client.default_headers.get("Cookie") == "sid=42; theme=dark"

    request = Request(method="GET", url=f"{TARGET}/anything")
    for name, value in http_client.default_headers.items():
        request.headers.setdefault(name, value)
    assert request.headers["Cookie"] == "sid=42; theme=dark"


# ---------------------------------------------------------------------------
# --basic-auth threading (Requirement 24.4)
# ---------------------------------------------------------------------------

def test_basic_auth_maps_onto_anonymous_auth_context():
    """``--basic-auth user:pass`` configures the anonymous context as Basic.

    **Validates: Requirements 24.4**
    """
    config_dict = _invoke_dir_capturing_config(["--basic-auth", "alice:s3cret"])

    context = config_dict["authentication"]["contexts"][0]
    assert context["type"] == "basic"
    assert context["username"] == "alice"
    assert context["password"] == "s3cret"


@pytest.mark.asyncio
async def test_basic_auth_produces_basic_authorization_header():
    """The discovery client emits ``Authorization: Basic <base64>`` per request.

    **Validates: Requirements 24.4**
    """
    http_client = await _build_discovery_http_client(["--basic-auth", "alice:s3cret"])

    # The basic context (no bearer token) is the active discovery auth context.
    assert http_client.current_auth_context is not None

    request = Request(method="GET", url=f"{TARGET}/anything")
    http_client._apply_authentication(request, http_client.current_auth_context)

    expected = base64.b64encode(b"alice:s3cret").decode()
    assert request.headers["Authorization"] == f"Basic {expected}"


@pytest.mark.asyncio
async def test_basic_auth_preserves_password_containing_colon():
    """A password containing a colon is preserved (split on the first colon).

    **Validates: Requirements 24.4**
    """
    http_client = await _build_discovery_http_client(
        ["--basic-auth", "alice:pa:ss:word"]
    )

    request = Request(method="GET", url=f"{TARGET}/anything")
    http_client._apply_authentication(request, http_client.current_auth_context)

    expected = base64.b64encode(b"alice:pa:ss:word").decode()
    assert request.headers["Authorization"] == f"Basic {expected}"


# ---------------------------------------------------------------------------
# Validation: --basic-auth + --jwt conflict / malformed value (24.5, 24.6)
# ---------------------------------------------------------------------------

def test_basic_auth_and_jwt_conflict_errors_with_no_discovery():
    """``--basic-auth`` + ``--jwt`` is rejected and performs no discovery.

    **Validates: Requirements 24.5**
    """
    runner = CliRunner()
    with patch.object(apileaks, "run_enhanced_apileak") as discovery, patch.object(
        apileaks, "_discover_endpoints_for_triage"
    ) as triage_discovery:
        result = runner.invoke(
            cli,
            [
                "--no-banner",
                "dir",
                "--target",
                TARGET,
                "--basic-auth",
                "alice:s3cret",
                "--jwt",
                "header.payload.signature",
            ],
        )

    assert result.exit_code != 0
    # The error names the conflicting authentication options.
    assert "--basic-auth" in result.output
    assert "--jwt" in result.output
    # No Endpoint_Discovery occurred on either the standard or triage path.
    discovery.assert_not_called()
    triage_discovery.assert_not_called()


def test_basic_auth_without_colon_errors_with_no_discovery():
    """A colon-less ``--basic-auth`` value is rejected and performs no discovery.

    **Validates: Requirements 24.6**
    """
    bad_value = "alicenocolon"
    runner = CliRunner()
    with patch.object(apileaks, "run_enhanced_apileak") as discovery, patch.object(
        apileaks, "_discover_endpoints_for_triage"
    ) as triage_discovery:
        result = runner.invoke(
            cli,
            [
                "--no-banner",
                "dir",
                "--target",
                TARGET,
                "--basic-auth",
                bad_value,
            ],
        )

    assert result.exit_code != 0
    # The error identifies the malformed value.
    assert bad_value in result.output
    discovery.assert_not_called()
    triage_discovery.assert_not_called()


# ---------------------------------------------------------------------------
# Targeted follow-up scan inherits the discovery header options (24.7)
# ---------------------------------------------------------------------------

def _selected_result():
    """A single triage selection used to drive the follow-up scan."""
    return DiscoveryResult(
        url=f"{TARGET}/users/1",
        method="GET",
        status_code=200,
        endpoint_status="valid",
    )


def _run_follow_up_capturing_config(**overrides):
    """Call ``_run_targeted_follow_up_scan`` and capture its built config_dict.

    Patches the config loader to capture the config and raise a sentinel before
    any real scan, mirroring how the triage path threads its options.
    """
    captured = {}

    def _capture(self, config_dict):
        captured["config_dict"] = config_dict
        raise _ShortCircuit()

    params = dict(
        rate_limit=None,
        user_agent_random=False,
        user_agent_custom=None,
        user_agent_file=None,
        jwt=None,
        response=None,
        output=None,
        detect_framework=False,
        fuzz_versions=False,
        header=(),
        cookie=None,
        basic_auth=None,
        logger=MagicMock(),
    )
    params.update(overrides)

    with patch.object(
        apileaks.ConfigurationManager, "load_config_from_dict", _capture
    ):
        with pytest.raises(_ShortCircuit):
            _run_targeted_follow_up_scan(_selected_result(), **params)
    return captured["config_dict"]


def test_follow_up_inherits_header_and_cookie():
    """The follow-up rebuilds the header/cookie custom_headers from its params.

    **Validates: Requirements 24.7, 24.2, 24.3**
    """
    config_dict = _run_follow_up_capturing_config(
        header=("X-Token: abc123", "X-Env: staging"), cookie="sid=42"
    )

    custom_headers = config_dict["fuzzing"]["headers"]["custom_headers"]
    assert custom_headers["X-Token"] == "abc123"
    assert custom_headers["X-Env"] == "staging"
    assert custom_headers["Cookie"] == "sid=42"


def test_follow_up_inherits_basic_auth():
    """The follow-up rebuilds the Basic auth context from its params.

    **Validates: Requirements 24.7, 24.4**
    """
    config_dict = _run_follow_up_capturing_config(basic_auth="bob:pw")

    context = config_dict["authentication"]["contexts"][0]
    assert context["type"] == "basic"
    assert context["username"] == "bob"
    assert context["password"] == "pw"
    # The follow-up stays scoped to the selected endpoint's method.
    assert config_dict["fuzzing"]["endpoints"]["methods"] == ["GET"]


# ---------------------------------------------------------------------------
# Reloaded session performs no discovery and applies no header options (24.8)
# ---------------------------------------------------------------------------

def _write_session(path):
    """Persist a minimal discovery session file to ``path``."""
    session = DiscoverySession(
        target=TARGET,
        timestamp=datetime.now(timezone.utc).isoformat(),
        tool_version="test",
        results=[
            DiscoveryResult(
                url=f"{TARGET}/users",
                method="GET",
                status_code=200,
                endpoint_status="valid",
            )
        ],
    )
    session.save(str(path))
    return str(path)


def test_reloaded_session_performs_no_discovery_and_no_header_options(tmp_path):
    """``--load-session`` runs no discovery, so no header option is applied.

    The session file is the sole source of truth; the reload path skips discovery
    entirely and never threads the supplied header/cookie/basic-auth into any
    discovery config.

    **Validates: Requirements 24.8**
    """
    session_path = _write_session(tmp_path / "session.json")

    runner = CliRunner()
    with patch.object(
        apileaks, "_discover_endpoints_for_triage"
    ) as triage_discovery, patch.object(
        apileaks, "run_enhanced_apileak"
    ) as discovery, patch.object(
        apileaks.ConfigurationManager, "load_config_from_dict"
    ) as load_config:
        result = runner.invoke(
            cli,
            [
                "--no-banner",
                "dir",
                "--target",
                TARGET,
                "--load-session",
                session_path,
                "-H",
                "X-Token: abc123",
                "--cookie",
                "sid=42",
                "--basic-auth",
                "alice:s3cret",
            ],
        )

    assert result.exit_code == 0, result.output
    # No Discovery_Request was issued on any path.
    triage_discovery.assert_not_called()
    discovery.assert_not_called()
    # No discovery config was built, so no Discovery_Header_Option was applied.
    load_config.assert_not_called()
