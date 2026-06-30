"""
CliRunner unit tests for discovery recursion-control options.

**Feature: owasp-complete-purple-teaming-cicd, Task 20.4**

These tests cover the CLI surface for the discovery recursion / budget /
concurrency controls:

- option validation rejects out-of-range values, naming the offending value,
  and performs no discovery (Requirements 17.9, 18.7, 20.5)
- ``resolve_max_depth`` precedence: explicit ``--depth`` > ``APILEAK_MAX_DEPTH``
  env var > default 3 (Requirements 17.6, 17.7, 17.8), and ``--depth 0`` forces
  ``recursive=False`` in the threaded ``config_dict['fuzzing']``
- the discovery summary reports ``budget_reached`` (Requirement 18.5) and
  ``catch_all_detected`` (Requirement 19.5) only when set

No real HTTP requests are made: the discovery entry point is patched out and the
configuration loader is short-circuited so option parsing/threading is exercised
in isolation.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

import apileaks
from apileaks import cli, resolve_max_depth, _echo_discovery_control_status
from core.engine import APILeakCore


# ---------------------------------------------------------------------------
# Option validation (Requirements 17.9, 18.7, 20.5)
# ---------------------------------------------------------------------------

# Each row: (command, option flag, invalid value) where the value must be
# rejected before any discovery runs.
_INVALID_OPTION_CASES = [
    ("dir", "--depth", "-1"),
    ("full", "--depth", "-1"),
    ("dir", "--max-requests", "0"),
    ("full", "--max-requests", "0"),
    ("dir", "--concurrency", "0"),
    ("full", "--concurrency", "0"),
]


@pytest.mark.parametrize("command, flag, value", _INVALID_OPTION_CASES)
def test_invalid_control_value_rejected_and_no_discovery(command, flag, value):
    """Out-of-range control values fail, name the value, and run no discovery.

    --depth -1, --max-requests 0 and --concurrency 0 are rejected during option
    parsing (Click callbacks), so the discovery entry point is never reached.

    **Validates: Requirements 17.9, 18.7, 20.5**
    """
    runner = CliRunner()

    # Patch the single discovery entry point shared by dir/full so we can prove
    # validation fails *before* any discovery is performed.
    with patch.object(apileaks, "run_enhanced_apileak") as discovery:
        result = runner.invoke(
            cli,
            [
                "--no-banner",
                command,
                "--target",
                "https://api.example.com",
                # "=" form so a negative value is not parsed as a new option.
                f"{flag}={value}",
            ],
        )

    # Non-zero exit and the offending value is named in the error output.
    assert result.exit_code != 0
    assert value in result.output
    assert flag in result.output
    # No discovery was performed.
    discovery.assert_not_called()


# ---------------------------------------------------------------------------
# resolve_max_depth precedence (Requirements 17.6, 17.7, 17.8)
# ---------------------------------------------------------------------------

def test_resolve_max_depth_cli_wins_over_env(monkeypatch):
    """An explicit --depth value overrides APILEAK_MAX_DEPTH.

    **Validates: Requirements 17.6**
    """
    monkeypatch.setenv("APILEAK_MAX_DEPTH", "9")
    assert resolve_max_depth(5) == 5


def test_resolve_max_depth_cli_zero_wins_over_env(monkeypatch):
    """An explicit --depth 0 is honoured over the env var (0 is not "unset").

    **Validates: Requirements 17.6**
    """
    monkeypatch.setenv("APILEAK_MAX_DEPTH", "9")
    assert resolve_max_depth(0) == 0


def test_resolve_max_depth_env_wins_over_default(monkeypatch):
    """With no CLI value, APILEAK_MAX_DEPTH overrides the built-in default.

    **Validates: Requirements 17.7**
    """
    monkeypatch.setenv("APILEAK_MAX_DEPTH", "7")
    assert resolve_max_depth(None) == 7


def test_resolve_max_depth_default_is_three(monkeypatch):
    """With neither CLI value nor env var, the default depth is 3.

    **Validates: Requirements 17.8**
    """
    monkeypatch.delenv("APILEAK_MAX_DEPTH", raising=False)
    assert resolve_max_depth(None) == 3


class _ShortCircuit(Exception):
    """Sentinel raised to stop the command after config_dict is captured."""


def _invoke_dir_capturing_config(args):
    """Invoke the ``dir`` command and capture the threaded ``config_dict``.

    ConfigurationManager.load_config_from_dict is the first consumer of the fully
    threaded config, so capturing its argument lets us inspect the discovery
    controls that the CLI wrote into ``config_dict['fuzzing']`` without running a
    real scan. We raise a sentinel afterwards; the command body catches it and
    exits cleanly.
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
            ["--no-banner", "dir", "--target", "https://api.example.com", *args],
        )
    return captured.get("config_dict")


def test_depth_zero_sets_recursive_false_in_config(monkeypatch):
    """--depth 0 threads recursive=False and max_depth=0 into the fuzzing config.

    **Validates: Requirements 17.6, 17.8**
    """
    # Env var must not leak into the explicit depth-0 resolution.
    monkeypatch.setenv("APILEAK_MAX_DEPTH", "9")
    config_dict = _invoke_dir_capturing_config(["--depth=0"])

    assert config_dict is not None
    assert config_dict["fuzzing"]["max_depth"] == 0
    assert config_dict["fuzzing"]["recursive"] is False


def test_positive_depth_threads_max_depth_and_keeps_recursive(monkeypatch):
    """A positive --depth threads max_depth and does not force recursive off.

    **Validates: Requirements 17.6**
    """
    monkeypatch.delenv("APILEAK_MAX_DEPTH", raising=False)
    config_dict = _invoke_dir_capturing_config(["--depth=2"])

    assert config_dict is not None
    assert config_dict["fuzzing"]["max_depth"] == 2
    # depth 2 != 0, so recursive is not forced to False by the depth-0 rule.
    assert config_dict["fuzzing"]["recursive"] is not False


# ---------------------------------------------------------------------------
# Extension_Set threading (Requirement 23.1)
# ---------------------------------------------------------------------------

def _invoke_full_capturing_config(args):
    """Invoke the ``full`` command and capture the threaded ``config_dict``.

    Mirrors ``_invoke_dir_capturing_config`` for the ``full`` command, which also
    threads the Extension_Set into ``config_dict['fuzzing']['endpoints']`` before
    handing the dict to ConfigurationManager.load_config_from_dict.
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
            ["--no-banner", "full", "--target", "https://api.example.com", *args],
        )
    return captured.get("config_dict")


def test_dir_extensions_comma_separated_threaded_and_normalized():
    """``dir -x`` accepts a comma-separated value, normalized into the config.

    **Validates: Requirements 23.1**
    """
    config_dict = _invoke_dir_capturing_config(["-x", "json,php"])

    assert config_dict is not None
    assert config_dict["fuzzing"]["endpoints"]["extensions"] == [".json", ".php"]


def test_dir_extensions_repeatable_and_deduplicated():
    """Repeated ``-x`` flags are flattened, normalized and de-duplicated.

    **Validates: Requirements 23.1**
    """
    config_dict = _invoke_dir_capturing_config(["-x", ".json", "-x", "json,php"])

    assert config_dict is not None
    assert config_dict["fuzzing"]["endpoints"]["extensions"] == [".json", ".php"]


def test_dir_extensions_absent_defaults_to_empty():
    """Without ``-x`` the threaded Extension_Set is empty (no expansion).

    **Validates: Requirements 23.1**
    """
    config_dict = _invoke_dir_capturing_config([])

    assert config_dict is not None
    assert config_dict["fuzzing"]["endpoints"]["extensions"] == []


def test_full_extensions_comma_separated_threaded_and_normalized():
    """``full -x`` threads a normalized Extension_Set into the fuzzing config.

    **Validates: Requirements 23.1**
    """
    config_dict = _invoke_full_capturing_config(["--extensions", "json,.php"])

    assert config_dict is not None
    assert config_dict["fuzzing"]["endpoints"]["extensions"] == [".json", ".php"]


# ---------------------------------------------------------------------------
# Discovery summary flags (Requirements 18.5, 19.5)
# ---------------------------------------------------------------------------

class _FakeCore:
    """Minimal core stub exposing get_discovery_status for summary tests."""

    def __init__(self, status):
        self._status = status

    def get_discovery_status(self):
        return self._status


_BUDGET_MSG = "Request budget reached"
_CATCH_ALL_MSG = "Catch-all response detected"


def test_summary_reports_both_flags(capsys):
    """When both flags are set, both warning lines are emitted.

    **Validates: Requirements 18.5, 19.5**
    """
    _echo_discovery_control_status(
        _FakeCore({"budget_reached": True, "catch_all_detected": True})
    )
    out = capsys.readouterr().out
    assert _BUDGET_MSG in out
    assert _CATCH_ALL_MSG in out


def test_summary_reports_budget_only(capsys):
    """budget_reached alone emits only the budget warning.

    **Validates: Requirements 18.5**
    """
    _echo_discovery_control_status(
        _FakeCore({"budget_reached": True, "catch_all_detected": False})
    )
    out = capsys.readouterr().out
    assert _BUDGET_MSG in out
    assert _CATCH_ALL_MSG not in out


def test_summary_reports_catch_all_only(capsys):
    """catch_all_detected alone emits only the catch-all warning.

    **Validates: Requirements 19.5**
    """
    _echo_discovery_control_status(
        _FakeCore({"budget_reached": False, "catch_all_detected": True})
    )
    out = capsys.readouterr().out
    assert _CATCH_ALL_MSG in out
    assert _BUDGET_MSG not in out


def test_summary_silent_when_no_flags_set(capsys):
    """With neither flag set, the summary stays silent.

    **Validates: Requirements 18.5, 19.5**
    """
    _echo_discovery_control_status(
        _FakeCore({"budget_reached": False, "catch_all_detected": False})
    )
    out = capsys.readouterr().out
    assert _BUDGET_MSG not in out
    assert _CATCH_ALL_MSG not in out


def test_get_discovery_status_reads_fuzzer_flags():
    """APILeakCore.get_discovery_status surfaces the fuzzer's control flags.

    **Validates: Requirements 18.5, 19.5**
    """
    fuzzer = SimpleNamespace(budget_reached=True, catch_all_detected=True)
    orchestrator = SimpleNamespace(endpoint_fuzzer=fuzzer)
    fake_self = SimpleNamespace(fuzzing_orchestrator=orchestrator)

    status = APILeakCore.get_discovery_status(fake_self)

    assert status == {
        "budget_reached": True,
        "catch_all_detected": True,
        "graphql_introspection_endpoint": None,
    }


def test_get_discovery_status_defaults_false_without_fuzzer():
    """get_discovery_status defaults both flags to False when no fuzzer exists.

    **Validates: Requirements 18.5, 19.5**
    """
    fake_self = SimpleNamespace()  # no fuzzing_orchestrator attribute

    status = APILeakCore.get_discovery_status(fake_self)

    assert status == {
        "budget_reached": False,
        "catch_all_detected": False,
        "graphql_introspection_endpoint": None,
    }
