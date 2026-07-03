"""Structural and routing tests for the ``owasp`` command group (task 6.1).

These tests exercise the dynamically generated ``owasp`` command group built in
task 6 (``apileaks.py``): one first-class subcommand per
``OWASP_MODULE_DESCRIPTORS`` entry, each stacking the shared Transversal_Options,
its own Module_Specific_Options (when it owns any), and routing through
``_build_and_run(selected_keys=[key], ...)``.

They anchor two correctness properties and several acceptance criteria:

* Property 2 (structural): the group exposes exactly one subcommand per
  descriptor, named character-for-character by the engine key (R1.2).
* Property 4 (help surface): each subcommand ``--help`` exits 0 and shows its own
  specific options plus every transversal option, and omits every OTHER
  module's specific options (R2.4, R11.3); a foreign specific option is rejected
  before any request (R2.7).
* R1.4: ``apileaks owasp`` with no subcommand lists all ten modules with key,
  OWASP category, and summary.
* R1.6: an unknown subcommand exits nonzero.
* R1.3: ``owasp bola --target URL`` runs only the ``bola`` module.
* R8.5: ``owasp dir`` / ``owasp par`` are not registered under ``owasp``.
* R7.4 / R7.5: ``owasp auth --help`` references the JWT_Module_Tests and the
  ``jwt`` group.

Expected option names are derived from the option decorators / descriptor
metadata (Click introspection) rather than hardcoded, so the assertions track
the single source of truth and do not drift. The engine boundary
(``run_enhanced_apileak``) is patched so no real scan runs, mirroring the
capture pattern in ``tests/test_multi_auth_context_cli.py``.
"""

from unittest.mock import patch

import click
from click.testing import CliRunner

import apileaks
from apileaks import cli
from cli.owasp_descriptors import OWASP_MODULE_DESCRIPTORS
from cli.shared_options import transversal_options


TARGET = "http://example.com"


# --------------------------------------------------------------------------- #
# Helpers: derive expected option flags from the decorators / descriptors.
# --------------------------------------------------------------------------- #

def _flags_of(command):
    """Return the set of every long/short flag on a Click command's options."""
    flags = set()
    for param in command.params:
        if isinstance(param, click.Option):
            flags.update(param.opts)
            flags.update(param.secondary_opts)
    return flags


def _decorator_flags(decorator):
    """Return the option flags a Click aggregate decorator declares.

    Applies the decorator to a throwaway command and reads its params, so the
    expected flag set is derived from the single source of truth rather than a
    hardcoded list.
    """
    @click.command()
    @decorator
    def _probe(**kwargs):  # pragma: no cover - never executed
        pass

    return _flags_of(_probe)


TRANSVERSAL_FLAGS = _decorator_flags(transversal_options)


def _specific_flags(desc):
    """Return the module-specific option flags owned by a descriptor."""
    if desc.specific_options is None:
        return set()
    return _decorator_flags(desc.specific_options)


# Map each descriptor key -> its specific-option flags (for foreign-option checks).
SPECIFIC_FLAGS_BY_KEY = {
    desc.key: _specific_flags(desc) for desc in OWASP_MODULE_DESCRIPTORS
}


def _owasp_group():
    """Return the ``owasp`` group object from the top-level ``cli``."""
    group = cli.commands["owasp"]
    assert isinstance(group, click.Group)
    return group


# --------------------------------------------------------------------------- #
# Property 2: structural — one subcommand per descriptor, named by key (R1.2)
# --------------------------------------------------------------------------- #

def test_owasp_group_exposes_exactly_one_subcommand_per_descriptor():
    """The group's subcommand names equal the descriptor keys exactly (R1.2).

    **Validates: Requirements 1.2**
    """
    group = _owasp_group()
    expected_keys = [desc.key for desc in OWASP_MODULE_DESCRIPTORS]

    # Exactly one subcommand per descriptor, no more and no fewer.
    assert set(group.commands) == set(expected_keys)
    assert len(group.commands) == len(expected_keys)


def test_each_subcommand_name_matches_descriptor_key_character_for_character():
    """Each subcommand's invocation name is byte-identical to its key (R1.2).

    **Validates: Requirements 1.2**
    """
    group = _owasp_group()
    for desc in OWASP_MODULE_DESCRIPTORS:
        assert desc.key in group.commands
        assert group.commands[desc.key].name == desc.key


# --------------------------------------------------------------------------- #
# Property 4: help surface — own + transversal shown, foreign omitted (R2.4, R11.3)
# --------------------------------------------------------------------------- #

def test_every_subcommand_help_exits_zero_shows_own_and_transversal_omits_foreign():
    """Each subcommand --help exits 0, shows own + transversal, omits foreign.

    **Validates: Requirements 2.4, 11.3**
    """
    runner = CliRunner()
    group = _owasp_group()

    for desc in OWASP_MODULE_DESCRIPTORS:
        result = runner.invoke(cli, ["--no-banner", "owasp", desc.key, "--help"])
        assert result.exit_code == 0, f"{desc.key} --help: {result.output}"
        output = result.output

        own_flags = SPECIFIC_FLAGS_BY_KEY[desc.key]
        foreign_flags = set()
        for other_key, flags in SPECIFIC_FLAGS_BY_KEY.items():
            if other_key != desc.key:
                foreign_flags |= flags
        # A foreign flag that also happens to be one of this module's own flags
        # (never the case today, but guard anyway) must not be treated as foreign.
        foreign_flags -= own_flags

        # Own specific options appear.
        for flag in own_flags:
            assert flag in output, f"{desc.key} --help missing own option {flag}"

        # Every transversal option appears (Shared_Option_Mechanism).
        for flag in TRANSVERSAL_FLAGS:
            assert flag in output, f"{desc.key} --help missing transversal {flag}"

        # No other module's specific options appear.
        for flag in foreign_flags:
            assert flag not in output, (
                f"{desc.key} --help leaked foreign option {flag}"
            )


def test_bola_help_shows_bola_options_and_omits_auth_and_mfa_options():
    """``owasp bola --help`` shows --bola-* and omits --auth-*/--mfa-* (R2.4).

    **Validates: Requirements 2.4, 11.3**
    """
    runner = CliRunner()
    result = runner.invoke(cli, ["--no-banner", "owasp", "bola", "--help"])

    assert result.exit_code == 0, result.output
    output = result.output

    # BOLA's own options are shown.
    assert "--bola-composite" in output
    assert "--bola-id-leakage" in output
    assert "--allow-write-bola" in output

    # Auth/MFA specific options are omitted.
    assert "--auth-rate-limit-attempts" not in output
    assert "--auth-benign-username" not in output
    assert "--mfa-provisional-token" not in output
    assert "--mfa-protected-endpoint" not in output


def test_auth_help_shows_auth_options_and_omits_bola_options():
    """``owasp auth --help`` shows auth options and omits --bola-* (R2.4).

    **Validates: Requirements 2.4, 11.3**
    """
    runner = CliRunner()
    result = runner.invoke(cli, ["--no-banner", "owasp", "auth", "--help"])

    assert result.exit_code == 0, result.output
    output = result.output

    # Auth's own options are shown.
    assert "--allow-aggressive-auth" in output
    assert "--mfa-provisional-token" in output
    assert "--public-key" in output

    # BOLA specific options are omitted.
    assert "--bola-composite" not in output
    assert "--bola-id-leakage" not in output
    assert "--allow-write-bola" not in output


# --------------------------------------------------------------------------- #
# R1.4: `apileaks owasp` with no subcommand lists all ten modules.
# --------------------------------------------------------------------------- #

def test_owasp_no_subcommand_lists_all_modules_with_category_and_summary():
    """``owasp`` (no subcommand) exits 0 and lists every module line (R1.4).

    Each descriptor's key, OWASP category, and summary appear together on the
    line for that module.

    **Validates: Requirements 1.4**
    """
    runner = CliRunner()
    result = runner.invoke(cli, ["--no-banner", "owasp"])

    assert result.exit_code == 0, result.output
    output = result.output

    # All ten modules are listed.
    assert len(OWASP_MODULE_DESCRIPTORS) == 10
    lines = output.splitlines()

    for desc in OWASP_MODULE_DESCRIPTORS:
        # Find the single line that carries this module's key + category + summary.
        matching = [
            line
            for line in lines
            if desc.key in line
            and desc.owasp_category in line
            and desc.summary in line
        ]
        assert matching, (
            f"listing missing a line for {desc.key} with its category/summary; "
            f"output was:\n{output}"
        )


# --------------------------------------------------------------------------- #
# R1.6: unknown subcommand exits nonzero.
# --------------------------------------------------------------------------- #

def test_unknown_subcommand_exits_nonzero():
    """Invoking an unregistered subcommand name errors nonzero (R1.6).

    **Validates: Requirements 1.6**
    """
    runner = CliRunner()
    result = runner.invoke(cli, ["--no-banner", "owasp", "definitely-not-a-module"])

    assert result.exit_code != 0


# --------------------------------------------------------------------------- #
# R1.3: routing — `owasp bola` runs only the bola module.
# --------------------------------------------------------------------------- #

def _invoke_owasp_capturing_config(subcommand_args):
    """Invoke an ``owasp`` subcommand, capturing the config handed to the engine.

    ``run_enhanced_apileak`` is the first consumer of the fully built config, so
    replacing it captures ``owasp_testing.enabled_modules`` without running a
    real scan. Configuration validation is stubbed so the routing behavior is
    isolated from unrelated filesystem checks. Returns ``(result, config)``.
    """
    captured = {}

    def _capture(config, *rest, **kwargs):
        captured["config"] = config

        async def _noop():
            return None

        return _noop()

    runner = CliRunner()
    with patch.object(
        apileaks.ConfigurationManager, "validate_configuration", return_value=[]
    ), patch.object(apileaks, "run_enhanced_apileak", _capture) as mock_run:
        result = runner.invoke(cli, ["--no-banner", "owasp", *subcommand_args])
    return result, captured.get("config"), mock_run


def test_owasp_bola_runs_only_bola_module():
    """``owasp bola --target URL`` enables exactly the ``bola`` module (R1.3).

    **Validates: Requirements 1.3**
    """
    result, config, _ = _invoke_owasp_capturing_config(
        ["bola", "--target", TARGET]
    )

    assert result.exit_code == 0, result.output
    assert config is not None
    assert config.owasp_testing.enabled_modules == ["bola"]


def test_owasp_bola_runs_no_other_module():
    """No OWASP module other than ``bola`` is enabled for the run (R1.3).

    **Validates: Requirements 1.3**
    """
    result, config, _ = _invoke_owasp_capturing_config(
        ["bola", "--target", TARGET]
    )

    assert result.exit_code == 0, result.output
    assert config is not None
    other_keys = {
        desc.key for desc in OWASP_MODULE_DESCRIPTORS if desc.key != "bola"
    }
    assert other_keys.isdisjoint(set(config.owasp_testing.enabled_modules))


# --------------------------------------------------------------------------- #
# Property 4 / R2.7: a foreign specific option is rejected before any request.
# --------------------------------------------------------------------------- #

def test_foreign_specific_option_rejected_before_any_request():
    """``owasp auth --bola-composite`` errors (exit 2) with no engine call.

    Click rejects the unrecognized option at parse time, so no request is issued
    (Property 4 / R2.7).

    **Validates: Requirements 2.7**
    """
    runner = CliRunner()
    with patch.object(apileaks, "run_enhanced_apileak") as mock_run:
        result = runner.invoke(
            cli,
            ["--no-banner", "owasp", "auth", "--target", TARGET, "--bola-composite"],
        )

    assert result.exit_code == 2
    assert "No such option" in result.output
    mock_run.assert_not_called()


# --------------------------------------------------------------------------- #
# R8.5: dir / par are not registered under owasp.
# --------------------------------------------------------------------------- #

def test_discovery_commands_not_registered_under_owasp():
    """``owasp dir`` and ``owasp par`` error nonzero (not registered) (R8.5).

    **Validates: Requirements 8.5**
    """
    runner = CliRunner()

    dir_result = runner.invoke(cli, ["--no-banner", "owasp", "dir"])
    assert dir_result.exit_code != 0
    assert "dir" not in _owasp_group().commands

    par_result = runner.invoke(cli, ["--no-banner", "owasp", "par"])
    assert par_result.exit_code != 0
    assert "par" not in _owasp_group().commands


# --------------------------------------------------------------------------- #
# R7.4 / R7.5: auth help references JWT_Module_Tests and the jwt group.
# --------------------------------------------------------------------------- #

def test_auth_help_references_jwt_module_tests_and_jwt_group():
    """``owasp auth --help`` names JWT_Module_Tests and the ``jwt`` group.

    **Validates: Requirements 7.4, 7.5**
    """
    runner = CliRunner()
    result = runner.invoke(cli, ["--no-banner", "owasp", "auth", "--help"])

    assert result.exit_code == 0, result.output
    output = result.output

    # R7.4: automated JWT detection is performed by the JWT_Module_Tests.
    assert "JWT_Module_Tests" in output
    # R7.5: manual JWT attacks live in the ``jwt`` command group.
    assert "jwt" in output
