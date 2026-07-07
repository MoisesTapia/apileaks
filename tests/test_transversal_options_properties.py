"""Transversal-option uniformity tests for the CLI restructure (Property 3).

These tests pin the structural invariants of the Shared_Option_Mechanism created
in task 3 (``apileaks/cli/shared_options.py``): the single ``TRANSVERSAL_OPTIONS``
list and the ``transversal_options`` decorator that stamps that list onto every
command accepting transversal options.

They are Click-introspection tests. A probe command is decorated with
``@transversal_options`` and its ``command.params`` are compared field-by-field
against the option decorators declared in ``TRANSVERSAL_OPTIONS``. Because the
decorator applies the one authoritative list, matching the probe against that
list proves the transversal-option uniformity invariant (Property 3) holds for
any command built with the decorator.

Cross-checks performed here:

* Every transversal option appears on the probe command with identical name,
  flags, type, default, and validation callback to its declaration
  (Property 3 / Requirements 3.1, 3.3, 3.4).
* Each transversal option is declared exactly once in ``TRANSVERSAL_OPTIONS`` -
  no duplicate parameter names and no duplicate option flags (Property 3 "there
  exists exactly one declaration of o").
* The ``--fail-on`` option defaults to ``high`` (Requirement 5.6 / design D5).

**Validates: Requirements 3.1, 3.3, 3.4, 5.6**
"""

import click
import pytest

from cli.shared_options import (
    TRANSVERSAL_OPTIONS,
    transversal_options,
)


# The authoritative transversal parameter names, in declaration order. This
# literal anchors the test against accidental additions/removals/reordering in
# ``TRANSVERSAL_OPTIONS`` (Click derives ``recursive`` from ``--recursive/--no-recursive``).
EXPECTED_PARAM_NAMES = [
    "target",
    "target_file",
    "max_hosts",
    "output",
    "log_level",
    "log_file",
    "json_logs",
    "rate_limit",
    "timeout",
    "retries",
    "concurrency",
    "safe_mode",
    "jwt",
    "auth_context",
    "proxy",
    "proxy_verify_ssl",
    "ci_mode",
    "fail_on",
    "sarif",
    "baseline",
    "user_agent_random",
    "user_agent_custom",
    "user_agent_file",
    "depth",
    "recursive",
    "max_requests",
    "extensions",
    "recursion_status",
    "recursion_type",
]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _declared_option(decorator) -> click.Option:
    """Materialize the ``click.Option`` a ``click.option`` decorator declares.

    Each entry in ``TRANSVERSAL_OPTIONS`` is a ``click.option(...)`` decorator.
    Applying it to a throwaway function appends the concrete ``Option`` to that
    function's ``__click_params__``, which is exactly the object Click would
    attach to a real command. This lets us read the declared name/type/default/
    callback without depending on any command.
    """
    def _sink():
        pass

    decorator(_sink)
    params = getattr(_sink, "__click_params__", [])
    assert len(params) == 1, "each TRANSVERSAL_OPTIONS entry declares one option"
    return params[0]


def _type_signature(param_type: click.ParamType):
    """Return a hashable, comparable signature for a Click parameter type.

    Distinct ``Choice(...)`` instances are not equal by identity, so compare by
    class name plus the choice tuple (and the type's canonical ``name``) instead.
    """
    return (
        type(param_type).__name__,
        param_type.name,
        tuple(getattr(param_type, "choices", ()) or ()),
    )


# The concrete options declared by TRANSVERSAL_OPTIONS, keyed by parameter name.
DECLARED_OPTIONS = {opt.name: opt for opt in map(_declared_option, TRANSVERSAL_OPTIONS)}


@click.command()
@transversal_options
def _probe(**kwargs):  # pragma: no cover - body never executed
    """Probe command carrying only the transversal options for introspection."""


# The options Click actually attached to a command built with the decorator.
PROBE_OPTIONS = {
    p.name: p for p in _probe.params if isinstance(p, click.Option)
}


# --------------------------------------------------------------------------- #
# Declaration-set shape (exactly-once / no drift)
# --------------------------------------------------------------------------- #

def test_transversal_options_declared_exactly_once_by_name():
    """No transversal option parameter name is declared twice.

    "There exists exactly one declaration of ``o``" (Property 3): the count of
    declarations equals the count of distinct parameter names.
    """
    names = [opt.name for opt in map(_declared_option, TRANSVERSAL_OPTIONS)]
    assert len(names) == len(set(names)), (
        f"duplicate transversal parameter name(s): "
        f"{sorted(n for n in set(names) if names.count(n) > 1)}"
    )


def test_transversal_options_declared_exactly_once_by_flag():
    """No option flag (e.g. ``--timeout``, ``-t``) is declared on two options.

    Guards against a second declaration of the same user-facing flag under a
    different parameter name.
    """
    flags = []
    for opt in map(_declared_option, TRANSVERSAL_OPTIONS):
        flags.extend(opt.opts)
        flags.extend(opt.secondary_opts)
    assert len(flags) == len(set(flags)), (
        f"duplicate option flag(s): "
        f"{sorted(f for f in set(flags) if flags.count(f) > 1)}"
    )


def test_transversal_option_names_match_expected_declaration_order():
    """``TRANSVERSAL_OPTIONS`` declares exactly the expected names, in order."""
    declared = [opt.name for opt in map(_declared_option, TRANSVERSAL_OPTIONS)]
    assert declared == EXPECTED_PARAM_NAMES


# --------------------------------------------------------------------------- #
# Property 3: probe command mirrors the declared transversal options
# --------------------------------------------------------------------------- #

def test_probe_command_has_exactly_the_declared_transversal_options():
    """The probe's option set is exactly the declared transversal option set."""
    assert set(PROBE_OPTIONS) == set(DECLARED_OPTIONS)
    # And nothing but transversal options was attached.
    assert len(PROBE_OPTIONS) == len(EXPECTED_PARAM_NAMES)


@pytest.mark.parametrize("name", EXPECTED_PARAM_NAMES)
def test_probe_option_matches_declaration(name):
    """Each probe option matches its declaration field-by-field (Property 3).

    Compares name, primary/secondary flags, type, default, validation callback,
    and the flag/multiple shape between the option Click attached to a command
    via ``@transversal_options`` and the option declared once in
    ``TRANSVERSAL_OPTIONS``.
    """
    probe = PROBE_OPTIONS[name]
    declared = DECLARED_OPTIONS[name]

    assert probe.name == declared.name
    assert probe.opts == declared.opts
    assert probe.secondary_opts == declared.secondary_opts
    assert _type_signature(probe.type) == _type_signature(declared.type)
    assert probe.default == declared.default
    # Validation callbacks are shared module-level functions, so identity holds
    # (Requirement 3.3 - byte-identical validation behavior everywhere).
    assert probe.callback is declared.callback
    assert probe.is_flag == declared.is_flag
    assert probe.multiple == declared.multiple


# --------------------------------------------------------------------------- #
# --fail-on default (Requirement 5.6 / design D5)
# --------------------------------------------------------------------------- #

def test_fail_on_default_is_high():
    """``--fail-on`` defaults to ``high`` (changed from legacy ``critical``)."""
    fail_on = PROBE_OPTIONS["fail_on"]
    assert fail_on.default == "high"
    # It is still a Choice over the four severities.
    assert _type_signature(fail_on.type) == (
        "Choice",
        fail_on.type.name,
        ("critical", "high", "medium", "low"),
    )


def test_validation_callbacks_wired_on_expected_options():
    """Validated numeric options carry their dedicated callbacks (Req 3.3)."""
    expected_callbacks = {
        "timeout": "_validate_timeout",
        "retries": "_validate_retries",
        "concurrency": "_validate_concurrency",
        "depth": "_validate_depth",
        "max_requests": "_validate_max_requests",
    }
    for name, callback_name in expected_callbacks.items():
        callback = PROBE_OPTIONS[name].callback
        assert callback is not None, f"{name} has no validation callback"
        assert callback.__name__ == callback_name
