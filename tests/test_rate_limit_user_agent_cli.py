"""
CliRunner regression tests for rate-limit and User-Agent threading in ``dir``.

**Feature: owasp-complete-purple-teaming-cicd, Task 25.2**

These tests lock in how the ``dir`` command (and the triage follow-up scan it
launches) threads the ``--rate-limit`` option and the three mutually-exclusive
User-Agent options into the configuration dict that ``ConfigurationManager``
consumes. They mirror the patterns in ``tests/test_discovery_controls_cli.py``:
no real HTTP is performed, the config loader is short-circuited so option
parsing/threading is exercised in isolation, and the shared discovery entry
point is patched to prove validation happens before any discovery.

Covered behaviour:

- ``--rate-limit N`` sets ``config_dict['rate_limiting']['requests_per_second']``
  to ``N`` in both the standard ``dir`` path and the triage discovery path
  (Requirement 21.1).
- each User-Agent option threads the correct config keys: ``random_user_agent``
  for ``--user-agent-random`` (21.6), the custom ``User-Agent`` header for
  ``--user-agent-custom`` (21.4), and ``user_agent_list`` + ``user_agent_rotation``
  for ``--user-agent-file`` (21.5).
- specifying two User-Agent options is rejected with no discovery (21.3), and an
  invalid ``--user-agent-file`` path errors before discovery (21.8).
- ``_run_targeted_follow_up_scan`` rebuilds the same rate-limit override and
  User-Agent config from the parameters the triage path passes, so the follow-up
  inherits the originating settings (21.7).
"""

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

import apileaks
from apileaks import cli, _run_targeted_follow_up_scan
from utils.discovery_session import DiscoveryResult


TARGET = "https://api.example.com"


class _ShortCircuit(Exception):
    """Sentinel raised to stop a command once ``config_dict`` is captured."""


# ---------------------------------------------------------------------------
# Helpers: capture the threaded config_dict without running a real scan
# ---------------------------------------------------------------------------

def _invoke_dir_capturing_config(args, *, input=None):
    """Invoke ``dir`` and capture the ``config_dict`` handed to the loader.

    ``ConfigurationManager.load_config_from_dict`` is the first consumer of the
    fully threaded config in both the standard ``dir`` path and the triage
    discovery path, so capturing its argument lets us inspect the rate-limit and
    User-Agent threading without performing a real scan. We raise a sentinel
    afterwards to stop the command. The standard path lets it propagate; the
    triage path catches it as a generic CLI error — either way ``config_dict``
    has already been captured.
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


# ---------------------------------------------------------------------------
# Rate-limit threading (Requirement 21.1)
# ---------------------------------------------------------------------------

def test_rate_limit_threaded_in_standard_dir_path():
    """``dir --rate-limit N`` sets requests_per_second in the standard path.

    **Validates: Requirements 21.1**
    """
    config_dict = _invoke_dir_capturing_config(["--rate-limit", "7"])

    assert config_dict is not None
    assert config_dict["rate_limiting"]["requests_per_second"] == 7


def test_rate_limit_threaded_in_triage_discovery_path():
    """``dir --rate-limit N --interactive`` threads N through the triage path.

    The triage discovery path (``_run_dir_triage``) builds the discovery config
    exactly like the standard path before running discovery, so the supplied
    rate limit must reach ``config_dict['rate_limiting']``.

    **Validates: Requirements 21.1**
    """
    # --interactive (with no stdin) opts into triage but the config is captured
    # before discovery/prompting occurs.
    config_dict = _invoke_dir_capturing_config(
        ["--rate-limit", "13", "--interactive"], input=""
    )

    assert config_dict is not None
    assert config_dict["rate_limiting"]["requests_per_second"] == 13


# ---------------------------------------------------------------------------
# User-Agent option threading (Requirements 21.4, 21.5, 21.6)
# ---------------------------------------------------------------------------

def test_user_agent_random_sets_random_flag():
    """``--user-agent-random`` sets ``random_user_agent`` True, no custom UA/list.

    **Validates: Requirements 21.6**
    """
    config_dict = _invoke_dir_capturing_config(["--user-agent-random"])

    headers = config_dict["fuzzing"]["headers"]
    assert headers["random_user_agent"] is True
    assert headers["user_agent_list"] is None
    assert headers["user_agent_rotation"] is False


def test_user_agent_custom_sets_custom_header():
    """``--user-agent-custom`` threads the single UA string into custom headers.

    **Validates: Requirements 21.4**
    """
    custom_ua = "MyScanner/9.9 (+https://example.com)"
    config_dict = _invoke_dir_capturing_config(["--user-agent-custom", custom_ua])

    headers = config_dict["fuzzing"]["headers"]
    assert headers["custom_headers"]["User-Agent"] == custom_ua
    # The custom path must not enable random selection or rotation.
    assert headers["random_user_agent"] is False
    assert headers["user_agent_rotation"] is False
    assert headers["user_agent_list"] is None


def test_user_agent_file_sets_rotation_list(tmp_path):
    """``--user-agent-file`` loads UAs (skipping blanks/comments) and rotates.

    The loaded list populates ``user_agent_list``, enables
    ``user_agent_rotation``, and the first UA becomes the default header.

    **Validates: Requirements 21.5**
    """
    ua_file = tmp_path / "agents.txt"
    ua_file.write_text(
        "# a comment line\n"
        "Mozilla/5.0 (Agent-One)\n"
        "\n"
        "   \n"
        "Mozilla/5.0 (Agent-Two)\n"
        "# trailing comment\n"
    )

    config_dict = _invoke_dir_capturing_config(
        ["--user-agent-file", str(ua_file)]
    )

    headers = config_dict["fuzzing"]["headers"]
    assert headers["user_agent_list"] == [
        "Mozilla/5.0 (Agent-One)",
        "Mozilla/5.0 (Agent-Two)",
    ]
    assert headers["user_agent_rotation"] is True
    # First loaded UA is used as the default header (Requirement 21.5).
    assert headers["custom_headers"]["User-Agent"] == "Mozilla/5.0 (Agent-One)"
    assert headers["random_user_agent"] is False


# ---------------------------------------------------------------------------
# User-Agent option validation (Requirements 21.3, 21.8)
# ---------------------------------------------------------------------------

def test_two_user_agent_options_rejected_no_discovery():
    """Two User-Agent options are rejected with an error and no discovery.

    **Validates: Requirements 21.3**
    """
    runner = CliRunner()
    with patch.object(apileaks, "run_enhanced_apileak") as discovery:
        result = runner.invoke(
            cli,
            [
                "--no-banner",
                "dir",
                "--target",
                TARGET,
                "--user-agent-random",
                "--user-agent-custom",
                "CustomUA/1.0",
            ],
        )

    assert result.exit_code != 0
    assert "Only one user agent option" in result.output
    discovery.assert_not_called()


def test_invalid_user_agent_file_errors_before_discovery():
    """A non-existent ``--user-agent-file`` path errors before any discovery.

    **Validates: Requirements 21.8**
    """
    missing_path = "/nonexistent/path/to/user-agents.txt"
    runner = CliRunner()
    with patch.object(apileaks, "run_enhanced_apileak") as discovery:
        result = runner.invoke(
            cli,
            [
                "--no-banner",
                "dir",
                "--target",
                TARGET,
                "--user-agent-file",
                missing_path,
            ],
        )

    assert result.exit_code != 0
    # The offending path is named in the error output (Requirement 21.8).
    assert missing_path in result.output
    discovery.assert_not_called()


# ---------------------------------------------------------------------------
# Targeted follow-up scan inherits originating settings (Requirement 21.7)
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
    any real scan, exactly mirroring how the triage path threads its options.
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
        logger=MagicMock(),
    )
    params.update(overrides)

    with patch.object(
        apileaks.ConfigurationManager, "load_config_from_dict", _capture
    ):
        with pytest.raises(_ShortCircuit):
            _run_targeted_follow_up_scan(_selected_result(), **params)
    return captured["config_dict"]


def test_follow_up_inherits_rate_limit():
    """The follow-up rebuilds the same rate-limit override from its params.

    **Validates: Requirements 21.7**
    """
    config_dict = _run_follow_up_capturing_config(rate_limit=21)

    assert config_dict["rate_limiting"]["requests_per_second"] == 21


def test_follow_up_inherits_custom_user_agent():
    """The follow-up rebuilds the custom User-Agent header from its params.

    **Validates: Requirements 21.7, 21.4**
    """
    custom_ua = "FollowUpScanner/2.0"
    config_dict = _run_follow_up_capturing_config(user_agent_custom=custom_ua)

    assert config_dict["fuzzing"]["headers"]["custom_headers"]["User-Agent"] == custom_ua


def test_follow_up_inherits_random_user_agent():
    """The follow-up rebuilds the random-UA flag from its params.

    **Validates: Requirements 21.7, 21.6**
    """
    config_dict = _run_follow_up_capturing_config(user_agent_random=True)

    assert config_dict["fuzzing"]["headers"]["random_user_agent"] is True


def test_follow_up_inherits_user_agent_file_rotation(tmp_path):
    """The follow-up rebuilds the rotation list/flag from a UA file param.

    **Validates: Requirements 21.7, 21.5**
    """
    ua_file = tmp_path / "agents.txt"
    ua_file.write_text("Agent-A\n# comment\nAgent-B\n")

    config_dict = _run_follow_up_capturing_config(user_agent_file=str(ua_file))

    headers = config_dict["fuzzing"]["headers"]
    assert headers["user_agent_list"] == ["Agent-A", "Agent-B"]
    assert headers["user_agent_rotation"] is True
    assert headers["custom_headers"]["User-Agent"] == "Agent-A"


def test_follow_up_combines_rate_limit_and_user_agent():
    """The follow-up threads both rate-limit and User-Agent together (21.7).

    **Validates: Requirements 21.7**
    """
    config_dict = _run_follow_up_capturing_config(
        rate_limit=5, user_agent_custom="ComboUA/1.0"
    )

    assert config_dict["rate_limiting"]["requests_per_second"] == 5
    assert (
        config_dict["fuzzing"]["headers"]["custom_headers"]["User-Agent"]
        == "ComboUA/1.0"
    )
    # Method is scoped to the selected endpoint's method (follow-up contract).
    assert config_dict["fuzzing"]["endpoints"]["methods"] == ["GET"]
