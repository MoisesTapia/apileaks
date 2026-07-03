"""Command-tree preservation tests for the CLI restructure (task 8).

These tests lock in the two families the restructure must leave intact:

* The Discovery_Command_Family (``dir`` / ``par``) stays at the **top level** and
  is **never** registered under the ``owasp`` group (R8.1, R8.3, R8.4, R8.5).
* The manual JWT toolkit (``jwt`` group) keeps exactly its thirteen named
  subcommands and its help identifies it as a manual toolkit (R7.1, R7.3).
* The ``owasp auth`` subcommand help distinguishes the automated
  JWT_Module_Tests from the manual ``jwt`` group (R7.2 distinction, R7.4, R7.5).

They complement the structural/routing assertions in
``tests/test_owasp_group_cli.py`` (which already covers the ``owasp`` group
surface) and the behavioral assertions in
``tests/test_jwt_cli_subcommands.py`` (which covers per-subcommand behavior).
Here the focus is the *shape of the command tree*: which command lives where.

Expected command names are derived from Click introspection of the live ``cli``
tree so the assertions track the single source of truth rather than drifting.
No engine is invoked (help/introspection only), so no scan runs.
"""

import click
from click.testing import CliRunner

from apileaks import cli


# The exact thirteen JWT_CLI_Group subcommands (R7.1). Order-independent set.
EXPECTED_JWT_SUBCOMMANDS = {
    "decode",
    "encode",
    "verify",
    "genkey",
    "jwks-to-key",
    "test-alg-none",
    "test-null-signature",
    "test-alg-confusion",
    "brute-secret",
    "test-kid-injection",
    "test-jwks-spoof",
    "test-inline-jwks",
    "attack-test",
}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _owasp_group():
    """Return the ``owasp`` group object from the top-level ``cli``."""
    group = cli.commands["owasp"]
    assert isinstance(group, click.Group)
    return group


def _jwt_group():
    """Return the ``jwt`` group object from the top-level ``cli``."""
    group = cli.commands["jwt"]
    assert isinstance(group, click.Group)
    return group


# --------------------------------------------------------------------------- #
# R8.1 / R8.3 / R8.4: dir & par are top-level and never under owasp.
# --------------------------------------------------------------------------- #

def test_dir_and_par_are_top_level_commands():
    """``dir`` and ``par`` are registered directly on the top-level ``cli`` (R8.1).

    **Validates: Requirements 8.1**
    """
    assert "dir" in cli.commands
    assert "par" in cli.commands
    assert isinstance(cli.commands["dir"], click.Command)
    assert isinstance(cli.commands["par"], click.Command)


def test_dir_and_par_never_registered_under_owasp():
    """The ``owasp`` group contains neither ``dir`` nor ``par`` (R8.3).

    **Validates: Requirements 8.3**
    """
    owasp_group = _owasp_group()
    assert "dir" not in owasp_group.commands
    assert "par" not in owasp_group.commands


def test_top_level_help_lists_dir_and_par_and_not_under_owasp():
    """Top-level ``--help`` lists ``dir``/``par`` as top-level commands (R8.4).

    The top-level listing shows ``dir`` and ``par``; the ``owasp`` group listing
    does not, confirming the discovery family is not nested under ``owasp``.

    **Validates: Requirements 8.4**
    """
    runner = CliRunner()

    top_help = runner.invoke(cli, ["--no-banner", "--help"])
    assert top_help.exit_code == 0, top_help.output
    top_commands = _listed_command_names(top_help.output)
    assert "dir" in top_commands
    assert "par" in top_commands
    assert "owasp" in top_commands

    owasp_help = runner.invoke(cli, ["--no-banner", "owasp", "--help"])
    assert owasp_help.exit_code == 0, owasp_help.output
    owasp_commands = _listed_command_names(owasp_help.output)
    assert "dir" not in owasp_commands
    assert "par" not in owasp_commands


def _listed_command_names(help_output):
    """Return the set of command names listed in a Click ``--help`` output.

    Command-listing rows begin with the command name followed by two or more
    spaces; option rows begin with ``-`` and are skipped.
    """
    names = set()
    for line in help_output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("-"):
            continue
        parts = stripped.split()
        if parts:
            names.add(parts[0])
    return names


# --------------------------------------------------------------------------- #
# R8.5: `owasp dir` / `owasp par` error nonzero (not registered under owasp).
# --------------------------------------------------------------------------- #

def test_owasp_dir_and_owasp_par_error_nonzero():
    """``apileaks owasp dir`` and ``apileaks owasp par`` exit nonzero (R8.5).

    Because the discovery family is never added to the ``owasp`` group, Click
    reports ``No such command`` and no discovery action runs.

    **Validates: Requirements 8.5**
    """
    runner = CliRunner()

    dir_result = runner.invoke(cli, ["--no-banner", "owasp", "dir"])
    assert dir_result.exit_code != 0

    par_result = runner.invoke(cli, ["--no-banner", "owasp", "par"])
    assert par_result.exit_code != 0


# --------------------------------------------------------------------------- #
# R7.1: the jwt group has exactly the thirteen named subcommands.
# --------------------------------------------------------------------------- #

def test_jwt_group_has_exactly_the_twelve_named_subcommands():
    """The ``jwt`` group exposes exactly the thirteen named subcommands (R7.1).

    No subcommand is added to or removed from the set.

    **Validates: Requirements 7.1**
    """
    jwt_group = _jwt_group()
    assert set(jwt_group.commands) == EXPECTED_JWT_SUBCOMMANDS
    assert len(jwt_group.commands) == 13


def test_jwt_subcommand_names_match_character_for_character():
    """Each ``jwt`` subcommand's invocation name is byte-identical (R7.1).

    **Validates: Requirements 7.1**
    """
    jwt_group = _jwt_group()
    for name in EXPECTED_JWT_SUBCOMMANDS:
        assert name in jwt_group.commands
        assert jwt_group.commands[name].name == name


# --------------------------------------------------------------------------- #
# R7.3: jwt group help identifies it as a manual toolkit.
# --------------------------------------------------------------------------- #

def test_jwt_group_help_identifies_it_as_a_manual_toolkit():
    """``jwt --help`` describes the group as a manual JWT attack/utility toolkit.

    **Validates: Requirements 7.3**
    """
    runner = CliRunner()
    result = runner.invoke(cli, ["--no-banner", "jwt", "--help"])

    assert result.exit_code == 0, result.output
    output = result.output.lower()
    assert "manual" in output
    assert "toolkit" in output


# --------------------------------------------------------------------------- #
# R7.4 / R7.5: owasp auth help references JWT_Module_Tests and the jwt group.
# --------------------------------------------------------------------------- #

def test_owasp_auth_help_references_jwt_module_tests_and_jwt_group():
    """``owasp auth --help`` names JWT_Module_Tests and the ``jwt`` group.

    This is the distinction requirement: the auth subcommand help tells the
    operator that automated JWT detection is done by the JWT_Module_Tests during
    an orchestrated run (R7.4), and that manual JWT attacks live in the ``jwt``
    command group (R7.5).

    **Validates: Requirements 7.4, 7.5**
    """
    runner = CliRunner()
    result = runner.invoke(cli, ["--no-banner", "owasp", "auth", "--help"])

    assert result.exit_code == 0, result.output
    output = result.output

    # R7.4: automated JWT detection during an orchestrated run.
    assert "JWT_Module_Tests" in output
    # R7.5: manual JWT attacks live in the ``jwt`` command group.
    assert "jwt" in output
