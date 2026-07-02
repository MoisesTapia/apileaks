"""Pre-request failure atomicity tests — Property 7 (task 9).

These tests extend the CLI test suite to assert **Property 7 (pre-request
failure atomicity)** across every command that accepts Transversal_Options
(the ``owasp`` Module_Subcommands and the ``scan`` orchestrator, built in tasks
5-7 in ``apileaks.py``):

    Every validation error results in a nonzero exit with NO OWASP module
    executed and NO HTTP request issued.

The validation paths exercised are:

* missing target — a subcommand/orchestrator invoked with no ``--target``, no
  ``APILEAK_TARGET`` env, and no ``--config`` (R1.5);
* unknown module key — ``scan --modules <unregistered>`` (R4.7, R9.4);
* foreign module-specific option — a ``--bola-*`` option on ``owasp auth`` (or
  vice versa), rejected by Click before dispatch (R2.7);
* conflicting User-Agent options — more than one of
  ``--user-agent-random`` / ``--user-agent-custom`` / ``--user-agent-file``
  (R3.6);
* invalid transversal value — e.g. ``--timeout 0`` failing its validation
  callback (R3.7).

Atomicity is asserted by patching BOTH the engine entry point
(``run_enhanced_apileak``) and the engine class (``APILeakCore``) and requiring
that NEITHER is invoked: ``run_enhanced_apileak`` is the single code path that
constructs an ``APILeakCore`` and issues HTTP requests, so proving it is never
called (and the core is never constructed) proves no module executed and no
request was issued.

**Validates: Requirements 1.5, 2.7, 3.6, 3.7, 4.7, 9.4** (Property 7)
"""

from unittest.mock import patch

import pytest
from click.testing import CliRunner

import apileaks
from apileaks import cli


TARGET = "http://example.com"


# --------------------------------------------------------------------------- #
# Environment isolation: the missing-target path must not be satisfied by an
# ambient APILEAK_TARGET, and module resolution must not read APILEAK_MODULES.
# --------------------------------------------------------------------------- #

@pytest.fixture(autouse=True)
def _clear_apileak_env(monkeypatch):
    for var in ("APILEAK_TARGET", "APILEAK_MODULES", "APILEAK_TIMEOUT",
                "APILEAK_USER_AGENT", "APILEAK_MAX_DEPTH", "APILEAK_VERIFY_SSL"):
        monkeypatch.delenv(var, raising=False)


def _invoke_asserting_atomicity(args):
    """Invoke ``cli`` with ``args`` while blocking the engine, asserting atomicity.

    Patches both the engine entry point and the engine class so that any attempt
    to run a module or issue a request would be observable. Returns
    ``(result, mock_run, mock_core)`` for the caller to assert on exit code and
    error text; the "no module executed / no request issued" invariant is
    checked here.
    """
    runner = CliRunner()
    with patch.object(apileaks, "run_enhanced_apileak") as mock_run, patch.object(
        apileaks, "APILeakCore"
    ) as mock_core:
        result = runner.invoke(cli, ["--no-banner", *args])

    # No OWASP module executed and no HTTP request issued (Property 7).
    mock_run.assert_not_called()
    mock_core.assert_not_called()
    return result, mock_run, mock_core


# Commands that accept Transversal_Options; the UA-conflict and invalid-value
# paths must behave identically on each (R3.6, R3.7 "consistently on every
# command"). ``scan`` needs a target to reach the transversal validation, so it
# is supplied where relevant.
_TRANSVERSAL_COMMANDS = [
    ("owasp bola", ["owasp", "bola"]),
    ("owasp auth", ["owasp", "auth"]),
    ("owasp ssrf", ["owasp", "ssrf"]),
    ("scan", ["scan"]),
]


# --------------------------------------------------------------------------- #
# Path 1: missing target (R1.5).
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("label,base", _TRANSVERSAL_COMMANDS)
def test_missing_target_aborts_before_any_request(label, base):
    """A command with no target/env/config aborts nonzero, no module runs (R1.5).

    **Validates: Requirements 1.5**
    """
    result, _, _ = _invoke_asserting_atomicity(base)

    assert result.exit_code != 0, f"{label}: {result.output}"
    # The error indicates a target is required.
    combined = result.output + (result.stderr or "")
    assert "target" in combined.lower()


# --------------------------------------------------------------------------- #
# Path 2: unknown module key (R4.7, R9.4).
# --------------------------------------------------------------------------- #

def test_unknown_module_key_aborts_before_any_run():
    """``scan --modules <unregistered>`` aborts nonzero naming the key (R4.7, R9.4).

    **Validates: Requirements 4.7, 9.4**
    """
    result, _, _ = _invoke_asserting_atomicity(
        ["scan", "--target", TARGET, "--modules", "bola,definitely-not-a-module"]
    )

    assert result.exit_code != 0
    assert "definitely-not-a-module" in (result.stderr or result.output)


def test_unknown_subcommand_name_aborts_before_any_run():
    """An unregistered ``owasp`` subcommand name errors nonzero, no run (R1.6/9.4).

    **Validates: Requirements 4.7, 9.4**
    """
    result, _, _ = _invoke_asserting_atomicity(
        ["owasp", "not-a-real-module", "--target", TARGET]
    )

    assert result.exit_code != 0


# --------------------------------------------------------------------------- #
# Path 3: foreign module-specific option (R2.7).
# --------------------------------------------------------------------------- #

def test_bola_option_on_auth_aborts_before_any_request():
    """A ``--bola-*`` option on ``owasp auth`` is rejected pre-request (R2.7).

    **Validates: Requirements 2.7**
    """
    result, _, _ = _invoke_asserting_atomicity(
        ["owasp", "auth", "--target", TARGET, "--bola-composite"]
    )

    assert result.exit_code == 2
    assert "No such option" in result.output


def test_auth_option_on_bola_aborts_before_any_request():
    """An ``--mfa-*`` option on ``owasp bola`` is rejected pre-request (R2.7).

    **Validates: Requirements 2.7**
    """
    result, _, _ = _invoke_asserting_atomicity(
        ["owasp", "bola", "--target", TARGET, "--mfa-protected-endpoint", "/x"]
    )

    assert result.exit_code == 2
    assert "No such option" in result.output


# --------------------------------------------------------------------------- #
# Path 4: conflicting User-Agent options (R3.6).
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("label,base", _TRANSVERSAL_COMMANDS)
def test_conflicting_user_agent_options_abort_before_any_request(label, base):
    """Two mutually exclusive ``--user-agent-*`` options abort pre-request (R3.6).

    Behavior is identical on every command that accepts the Transversal_Options.

    **Validates: Requirements 3.6**
    """
    result, _, _ = _invoke_asserting_atomicity(
        [*base, "--target", TARGET,
         "--user-agent-random", "--user-agent-custom", "Custom/1"]
    )

    assert result.exit_code != 0, f"{label}: {result.output}"
    combined = result.output + (result.stderr or "")
    assert "user agent" in combined.lower() or "user-agent" in combined.lower()


# --------------------------------------------------------------------------- #
# Path 5: invalid transversal value (R3.7).
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("label,base", _TRANSVERSAL_COMMANDS)
def test_invalid_timeout_value_aborts_before_any_request(label, base):
    """``--timeout 0`` fails its validation callback pre-request on any command (R3.7).

    **Validates: Requirements 3.7**
    """
    result, _, _ = _invoke_asserting_atomicity(
        [*base, "--target", TARGET, "--timeout", "0"]
    )

    assert result.exit_code == 2, f"{label}: {result.output}"
    assert "--timeout" in result.output


@pytest.mark.parametrize("label,base", _TRANSVERSAL_COMMANDS)
def test_negative_retries_value_aborts_before_any_request(label, base):
    """``--retries -1`` fails its validation callback pre-request on any command (R3.7).

    **Validates: Requirements 3.7**
    """
    result, _, _ = _invoke_asserting_atomicity(
        [*base, "--target", TARGET, "--retries", "-1"]
    )

    assert result.exit_code == 2, f"{label}: {result.output}"
    assert "--retries" in result.output
