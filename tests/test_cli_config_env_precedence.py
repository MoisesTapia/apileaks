"""Config-file and environment-override precedence CLI tests (task 9).

These tests exercise the setting-resolution precedence enforced by the
restructured orchestrator (``scan``) built in tasks 5-7 (``apileaks.py``):

    command-line option  >  Environment_Override  >  config file  >  default

(Requirements 10.1-10.5, Property 8). The four supported Environment_Overrides
are ``APILEAK_TARGET``, ``APILEAK_MODULES``, ``APILEAK_TIMEOUT``, and
``APILEAK_USER_AGENT`` (R10.3). The ordering is established through the pairwise
levels that define it:

* a command-line option overrides the matching Environment_Override (CLI > env);
* an Environment_Override is applied when the option is absent (env > default);
* a ``--config`` file supplies settings, and a command-line option overrides the
  file (CLI > config); the file value is used over the built-in default
  (config > default);
* the built-in default applies when nothing else is supplied.

``run_enhanced_apileak`` is the first consumer of the fully resolved config, so
patching it captures the resolved ``APILeakConfig`` without running a real scan
(mirroring ``tests/test_multi_auth_context_cli.py``). Configuration validation
is stubbed so behavior is isolated from unrelated filesystem checks.

Malformed ``--config`` handling (R10.5) is asserted directly: an unreadable or
unparseable config file aborts nonzero, names the file, and starts no scan.
"""

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

import apileaks
from apileaks import cli
from cli.owasp_descriptors import all_keys


CLI_TARGET = "http://cli-target.example"
ENV_TARGET = "http://env-target.example"
CONFIG_TARGET = "http://config-target.example"

DEFAULT_USER_AGENT = "APILeak/0.2.1"
DEFAULT_TIMEOUT = 10


# --------------------------------------------------------------------------- #
# Environment isolation: clear APILEAK_* so each test controls the env exactly.
# --------------------------------------------------------------------------- #

@pytest.fixture(autouse=True)
def _clear_apileak_env(monkeypatch):
    for var in ("APILEAK_TARGET", "APILEAK_MODULES", "APILEAK_TIMEOUT",
                "APILEAK_USER_AGENT", "APILEAK_MAX_DEPTH", "APILEAK_VERIFY_SSL"):
        monkeypatch.delenv(var, raising=False)


# --------------------------------------------------------------------------- #
# Capture helper.
# --------------------------------------------------------------------------- #

def _invoke_capturing_config(args, env=None):
    """Invoke ``cli`` with ``args`` and env vars, capturing the resolved config.

    Returns ``(result, config, mock_run)``. ``env`` values are set through the
    process environment (monkeypatch) so the orchestrator's env-override logic
    observes them; the autouse fixture clears them again between tests.
    """
    captured = {}

    def _capture(config, *rest, **kwargs):
        captured["config"] = config

        async def _noop():
            return None

        return _noop()

    runner = CliRunner(mix_stderr=False)
    with patch.object(
        apileaks.ConfigurationManager, "validate_configuration", return_value=[]
    ), patch.object(
        apileaks, "run_enhanced_apileak", MagicMock(side_effect=_capture)
    ) as mock_run:
        result = runner.invoke(cli, ["--no-banner", *args])
    return result, captured.get("config"), mock_run


def _invoke_with_env(monkeypatch, args, env):
    """Set ``env`` vars via monkeypatch, then invoke and capture the config."""
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return _invoke_capturing_config(args)


# A minimal but valid config file. ``validate_configuration`` is stubbed, so the
# referenced wordlists need not exist; only the parsed values matter.
_CONFIG_TEMPLATE = """\
target:
  base_url: "{base_url}"
  default_method: "GET"
  timeout: {timeout}
  verify_ssl: true

owasp_testing:
  enabled_modules:
    - "bola"
    - "auth"
"""


def _write_config(base_url=CONFIG_TARGET, timeout=33):
    return _CONFIG_TEMPLATE.format(base_url=base_url, timeout=timeout)


# --------------------------------------------------------------------------- #
# APILEAK_TARGET precedence (R10.2, R10.3, R10.4).
# --------------------------------------------------------------------------- #

def test_target_cli_overrides_env(monkeypatch):
    """A ``--target`` option overrides ``APILEAK_TARGET`` (CLI > env).

    **Validates: Requirements 10.4**
    """
    result, config, _ = _invoke_with_env(
        monkeypatch,
        ["scan", "--target", CLI_TARGET],
        {"APILEAK_TARGET": ENV_TARGET},
    )

    assert result.exit_code == 0, result.output
    assert config.target.base_url == CLI_TARGET


def test_target_env_used_when_option_absent(monkeypatch):
    """``APILEAK_TARGET`` supplies the target when ``--target`` is absent (env).

    **Validates: Requirements 10.2, 10.3, 10.4**
    """
    result, config, _ = _invoke_with_env(
        monkeypatch, ["scan"], {"APILEAK_TARGET": ENV_TARGET}
    )

    assert result.exit_code == 0, result.output
    assert config.target.base_url == ENV_TARGET


def test_target_absent_everywhere_aborts(monkeypatch):
    """No target from option, env, or config aborts nonzero (default path).

    **Validates: Requirements 10.4**
    """
    result, _, mock_run = _invoke_capturing_config(["scan"])

    assert result.exit_code != 0
    mock_run.assert_not_called()


# --------------------------------------------------------------------------- #
# APILEAK_TIMEOUT precedence (R10.3, R10.4).
# --------------------------------------------------------------------------- #

def test_timeout_cli_overrides_env(monkeypatch):
    """A ``--timeout`` option overrides ``APILEAK_TIMEOUT`` (CLI > env).

    **Validates: Requirements 10.4**
    """
    result, config, _ = _invoke_with_env(
        monkeypatch,
        ["scan", "--target", CLI_TARGET, "--timeout", "20"],
        {"APILEAK_TIMEOUT": "45"},
    )

    assert result.exit_code == 0, result.output
    assert config.target.timeout == 20


def test_timeout_env_used_when_option_absent(monkeypatch):
    """``APILEAK_TIMEOUT`` is applied when ``--timeout`` is absent (env > default).

    **Validates: Requirements 10.3, 10.4**
    """
    result, config, _ = _invoke_with_env(
        monkeypatch,
        ["scan", "--target", CLI_TARGET],
        {"APILEAK_TIMEOUT": "45"},
    )

    assert result.exit_code == 0, result.output
    assert config.target.timeout == 45


def test_timeout_default_when_option_and_env_absent():
    """The built-in ``timeout`` default applies with no option/env (default).

    **Validates: Requirements 10.4**
    """
    result, config, _ = _invoke_capturing_config(["scan", "--target", CLI_TARGET])

    assert result.exit_code == 0, result.output
    assert config.target.timeout == DEFAULT_TIMEOUT


# --------------------------------------------------------------------------- #
# APILEAK_MODULES precedence (R10.3, R10.4).
# --------------------------------------------------------------------------- #

def test_modules_cli_overrides_env(monkeypatch):
    """``--modules`` overrides ``APILEAK_MODULES`` (CLI > env).

    **Validates: Requirements 10.4**
    """
    result, config, _ = _invoke_with_env(
        monkeypatch,
        ["scan", "--target", CLI_TARGET, "--modules", "ssrf"],
        {"APILEAK_MODULES": "bola,auth"},
    )

    assert result.exit_code == 0, result.output
    assert config.owasp_testing.enabled_modules == ["ssrf"]


def test_modules_env_used_when_option_absent(monkeypatch):
    """``APILEAK_MODULES`` selects modules when ``--modules`` is absent (env).

    **Validates: Requirements 10.3, 10.4**
    """
    result, config, _ = _invoke_with_env(
        monkeypatch,
        ["scan", "--target", CLI_TARGET],
        {"APILEAK_MODULES": "bola,auth"},
    )

    assert result.exit_code == 0, result.output
    assert config.owasp_testing.enabled_modules == ["bola", "auth"]


def test_modules_default_is_all_keys_when_option_and_env_absent():
    """With no ``--modules`` and no env, all registered modules run (default).

    **Validates: Requirements 10.4**
    """
    result, config, _ = _invoke_capturing_config(["scan", "--target", CLI_TARGET])

    assert result.exit_code == 0, result.output
    assert config.owasp_testing.enabled_modules == all_keys()


# --------------------------------------------------------------------------- #
# APILEAK_USER_AGENT precedence (R10.3, R10.4).
# --------------------------------------------------------------------------- #

def _resolved_user_agent(config):
    return config.fuzzing.headers.custom_headers["User-Agent"]


def test_user_agent_cli_overrides_env(monkeypatch):
    """``--user-agent-custom`` overrides ``APILEAK_USER_AGENT`` (CLI > env).

    **Validates: Requirements 10.4**
    """
    result, config, _ = _invoke_with_env(
        monkeypatch,
        ["scan", "--target", CLI_TARGET, "--user-agent-custom", "CLI-Agent/1"],
        {"APILEAK_USER_AGENT": "Env-Agent/2"},
    )

    assert result.exit_code == 0, result.output
    assert _resolved_user_agent(config) == "CLI-Agent/1"


def test_user_agent_env_used_when_option_absent(monkeypatch):
    """``APILEAK_USER_AGENT`` applies when no UA option is set (env > default).

    **Validates: Requirements 10.3, 10.4**
    """
    result, config, _ = _invoke_with_env(
        monkeypatch,
        ["scan", "--target", CLI_TARGET],
        {"APILEAK_USER_AGENT": "Env-Agent/2"},
    )

    assert result.exit_code == 0, result.output
    assert _resolved_user_agent(config) == "Env-Agent/2"


def test_user_agent_default_when_option_and_env_absent():
    """The built-in User-Agent default applies with no option/env (default).

    **Validates: Requirements 10.4**
    """
    result, config, _ = _invoke_capturing_config(["scan", "--target", CLI_TARGET])

    assert result.exit_code == 0, result.output
    assert _resolved_user_agent(config) == DEFAULT_USER_AGENT


# --------------------------------------------------------------------------- #
# Config file: file value used over default, CLI option overrides file.
# --------------------------------------------------------------------------- #

def test_config_file_supplies_target_and_timeout_over_default():
    """A ``--config`` file supplies target/timeout over the defaults (config).

    **Validates: Requirements 10.1, 10.4**
    """
    runner = CliRunner(mix_stderr=False)
    with runner.isolated_filesystem():
        with open("cfg.yaml", "w", encoding="utf-8") as handle:
            handle.write(_write_config(base_url=CONFIG_TARGET, timeout=33))

        captured = {}

        def _capture(config, *rest, **kwargs):
            captured["config"] = config

            async def _noop():
                return None

            return _noop()

        with patch.object(
            apileaks.ConfigurationManager, "validate_configuration", return_value=[]
        ), patch.object(apileaks, "run_enhanced_apileak", MagicMock(side_effect=_capture)):
            result = runner.invoke(cli, ["--no-banner", "scan", "--config", "cfg.yaml"])

    assert result.exit_code == 0, result.output
    config = captured["config"]
    assert config.target.base_url == CONFIG_TARGET
    assert config.target.timeout == 33


def test_cli_option_overrides_config_file():
    """A ``--target``/``--timeout`` option overrides the config file (CLI > config).

    **Validates: Requirements 10.4**
    """
    runner = CliRunner(mix_stderr=False)
    with runner.isolated_filesystem():
        with open("cfg.yaml", "w", encoding="utf-8") as handle:
            handle.write(_write_config(base_url=CONFIG_TARGET, timeout=33))

        captured = {}

        def _capture(config, *rest, **kwargs):
            captured["config"] = config

            async def _noop():
                return None

            return _noop()

        with patch.object(
            apileaks.ConfigurationManager, "validate_configuration", return_value=[]
        ), patch.object(apileaks, "run_enhanced_apileak", MagicMock(side_effect=_capture)):
            result = runner.invoke(
                cli,
                ["--no-banner", "scan", "--config", "cfg.yaml",
                 "--target", CLI_TARGET, "--timeout", "20"],
            )

    assert result.exit_code == 0, result.output
    config = captured["config"]
    assert config.target.base_url == CLI_TARGET
    assert config.target.timeout == 20


# --------------------------------------------------------------------------- #
# R10.5: malformed --config aborts nonzero naming the file.
# --------------------------------------------------------------------------- #

def test_malformed_config_exits_nonzero_naming_file():
    """A malformed ``--config`` file aborts nonzero, names the file, no scan (R10.5).

    **Validates: Requirements 10.5**
    """
    runner = CliRunner(mix_stderr=False)
    with runner.isolated_filesystem():
        with open("broken.yaml", "w", encoding="utf-8") as handle:
            handle.write("::: not valid yaml :::\n\t- broken: [")

        with patch.object(apileaks, "run_enhanced_apileak") as mock_run:
            result = runner.invoke(
                cli, ["--no-banner", "scan", "--config", "broken.yaml"]
            )

    assert result.exit_code != 0
    # The error names the offending config file.
    combined = result.output + (result.stderr or "")
    assert "broken.yaml" in combined
    mock_run.assert_not_called()


def test_nonexistent_config_exits_nonzero_naming_file():
    """A nonexistent ``--config`` path aborts nonzero and names it (R10.5).

    Click's ``Path(exists=True)`` rejects a missing file before any scan runs.

    **Validates: Requirements 10.5**
    """
    runner = CliRunner(mix_stderr=False)
    with patch.object(apileaks, "run_enhanced_apileak") as mock_run:
        result = runner.invoke(
            cli, ["--no-banner", "scan", "--config", "definitely-missing.yaml"]
        )

    assert result.exit_code != 0
    combined = result.output + (result.stderr or "")
    assert "definitely-missing.yaml" in combined
    mock_run.assert_not_called()
