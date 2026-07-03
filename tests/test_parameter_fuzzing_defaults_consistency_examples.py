"""Defaults and consistency example tests for the ``par`` command (task 11.11).

**Feature: parameter-fuzzing, Task 11.11**

These example tests assert that the ``par`` command reaches parity with ``dir``
for the transversal options extracted into the shared decorator stacks
(tasks 11.1-11.6), without issuing any HTTP request. They inspect the real Click
command definitions (``apileaks.par`` / ``apileaks.dir``) and the real config
factory (``apileaks.create_default_config`` +
``core.config.ConfigurationManager``) directly, so the run is fully offline and
deterministic.

Three consistency guarantees are covered:

1. Omitted resilience/concurrency options resolve to the SAME defaults as
   ``dir`` -- ``--timeout`` -> 10s, ``--retries`` -> 2, ``--concurrency`` -> 50,
   and ``--max-requests`` -> unbounded (``None``) .......... R8.6, R11.5
2. The default parameter wordlist path is ``wordlists/parameters.txt`` when no
   ``--wordlist`` is supplied ............................... R10.4
3. ``par`` and ``dir`` share the extracted decorator stacks and reuse the exact
   same validator callbacks (same function objects), with identical option
   names, defaults, types, and repeatability ............... R7.4, R8.4, R9.4, R12.7

**Validates: Requirements 8.6, 10.4, 11.5, 7.4, 8.4, 9.4, 12.7**
"""

from __future__ import annotations

import pytest

import apileaks
from core.config import ConfigurationManager


TARGET = "https://api.example.test/resource"


# --------------------------------------------------------------------------- #
# Helpers: introspect the real Click command parameter definitions.
# --------------------------------------------------------------------------- #

def _params_by_name(command):
    """Return {param.name: click.Parameter} for a Click command."""
    return {p.name: p for p in command.params}


DIR_PARAMS = _params_by_name(apileaks.dir)
PAR_PARAMS = _params_by_name(apileaks.par)


# Option ``name`` (dest) -> the validator callback it MUST reuse from ``dir``.
# These are the shared resilience/concurrency/TLS validators extracted in
# tasks 11.1-11.6 and reused verbatim by ``par`` (tasks 11.2).
SHARED_VALIDATOR_CALLBACKS = {
    "timeout": apileaks._validate_timeout,
    "retries": apileaks._validate_retries,
    "concurrency": apileaks._validate_concurrency,
    "max_requests": apileaks._validate_max_requests,
    "client_cert": apileaks._validate_client_cert,
    "ca_bundle": apileaks._validate_ca_bundle,
    "resolve": apileaks._validate_resolve,
}

# Option names contributed by each shared decorator stack. ``par`` must expose
# every one of these with attributes identical to ``dir``.
REQUEST_CONTEXT_OPTIONS = ["basic_auth", "cookie", "header"]
RESILIENCE_OPTIONS = ["retries", "timeout"]
CONCURRENCY_OPTIONS = ["concurrency", "max_requests"]
TLS_OPTIONS = ["resolve", "ca_bundle", "client_cert"]
MATCHER_FILTER_OPTIONS = [
    "match_size", "match_words", "match_lines", "match_regex", "match_time",
    "filter_size", "filter_words", "filter_lines", "filter_regex", "filter_time",
]
MACHINE_OUTPUT_OPTIONS = ["output_format", "output_file"]

ALL_SHARED_OPTIONS = (
    REQUEST_CONTEXT_OPTIONS
    + RESILIENCE_OPTIONS
    + CONCURRENCY_OPTIONS
    + TLS_OPTIONS
    + MATCHER_FILTER_OPTIONS
    + MACHINE_OUTPUT_OPTIONS
)


def _choice_values(param):
    """Return the sorted choices for a click.Choice-typed param, else None."""
    ptype = getattr(param, "type", None)
    choices = getattr(ptype, "choices", None)
    return sorted(choices) if choices is not None else None


# --------------------------------------------------------------------------- #
# (a) Omitted resilience/concurrency options resolve to the same defaults as dir
#     -- R8.6, R11.5
# --------------------------------------------------------------------------- #

def _resolved_config(scan_type):
    """Build a default config for ``scan_type`` (options omitted) and load it."""
    config_dict = apileaks.create_default_config(TARGET, None, scan_type)
    return ConfigurationManager().load_config_from_dict(config_dict)


def test_omitted_transport_options_click_defaults_match_dir():
    """The Click-level defaults for the shared numeric options match dir (R8.6, R11.5).

    Because ``par`` and ``dir`` draw these options from the same extracted
    decorator stacks, their declared defaults are identical (all ``None``, so the
    resolved value falls back to the config default).
    """
    for name in ("timeout", "retries", "concurrency", "max_requests"):
        assert PAR_PARAMS[name].default == DIR_PARAMS[name].default, (
            f"--{name} Click default differs: par={PAR_PARAMS[name].default!r} "
            f"dir={DIR_PARAMS[name].default!r}"
        )
        # The shared decorators declare these with no Click-level default, so the
        # config-layer default is authoritative.
        assert PAR_PARAMS[name].default is None


def test_omitted_resilience_concurrency_resolve_to_dir_defaults():
    """Omitting resilience/concurrency options yields the same resolved defaults as dir.

    **Validates: Requirements 8.6, 11.5**
    """
    par_cfg = _resolved_config("par")
    dir_cfg = _resolved_config("dir")

    # R8.6: par's resolved defaults equal dir's for every omitted option.
    assert par_cfg.target.timeout == dir_cfg.target.timeout
    assert par_cfg.fuzzing.retries == dir_cfg.fuzzing.retries
    assert par_cfg.fuzzing.concurrency == dir_cfg.fuzzing.concurrency
    assert par_cfg.fuzzing.max_requests == dir_cfg.fuzzing.max_requests

    # And the concrete default values are the documented ones.
    assert par_cfg.target.timeout == 10           # --timeout default (seconds)
    assert par_cfg.fuzzing.retries == 2           # --retries default
    assert par_cfg.fuzzing.concurrency == 50      # --concurrency default

    # R11.5: no request budget configured => unbounded.
    assert par_cfg.fuzzing.max_requests is None
    assert dir_cfg.fuzzing.max_requests is None


# --------------------------------------------------------------------------- #
# (b) Default wordlist path is wordlists/parameters.txt when omitted -- R10.4
# --------------------------------------------------------------------------- #

def test_default_parameter_wordlist_constant():
    """The default parameter wordlist path constant is wordlists/parameters.txt (R10.4)."""
    assert apileaks.DEFAULT_PARAMETER_WORDLIST == "wordlists/parameters.txt"


def test_par_wordlist_option_is_repeatable_with_no_default():
    """``par --wordlist`` is repeatable and has no hard-coded path default (R10.4).

    The default path is applied inside ``_resolve_par_candidates`` (below), not as
    a Click default, so the option itself defaults to an empty tuple.
    """
    wl = PAR_PARAMS["wordlist"]
    assert wl.multiple is True
    # No hard-coded path default: a repeatable option with no explicit default
    # yields an empty tuple of values (Click may model the unset default as
    # ``None``, ``()``, or an UNSET sentinel). The default path is applied later
    # by ``_resolve_par_candidates``. The key guarantee is that it is NOT a
    # concrete wordlist path baked into the option.
    assert not isinstance(wl.default, str), (
        f"--wordlist must not hard-code a path default, got {wl.default!r}"
    )


def test_resolve_par_candidates_defaults_to_parameters_txt():
    """Omitting ``--wordlist`` reads candidates from wordlists/parameters.txt (R10.4).

    **Validates: Requirements 10.4**

    ``_resolve_par_candidates(())`` (no sources) must resolve exactly to the
    normalized, de-duplicated entries of the default ``wordlists/parameters.txt``
    file -- the same result as passing that path explicitly.
    """
    from_default = apileaks._resolve_par_candidates(())
    from_explicit = apileaks._resolve_par_candidates(
        [apileaks.DEFAULT_PARAMETER_WORDLIST]
    )

    assert from_default == from_explicit
    # The default wordlist ships with entries, so the resolved set is non-empty.
    assert from_default, "default parameter wordlist resolved to an empty set"


def test_par_config_default_parameter_wordlist_path():
    """When no wordlist is threaded, the config's parameter wordlists default correctly.

    ``par`` leaves the file path at its default and overrides candidates via
    ``query_candidates``/``body_candidates``; when neither is supplied the
    file-based default is ``wordlists/parameters.txt`` (R10.4).
    """
    cfg = _resolved_config("par")
    assert cfg.fuzzing.parameters.query_wordlist == "wordlists/parameters.txt"
    assert cfg.fuzzing.parameters.body_wordlist == "wordlists/parameters.txt"


# --------------------------------------------------------------------------- #
# (c) par and dir share the extracted decorators and validator callbacks
#     -- R7.4, R8.4, R9.4, R12.7
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", list(SHARED_VALIDATOR_CALLBACKS))
def test_par_reuses_dir_validator_callbacks(name):
    """``par`` reuses the exact same validator callback function as ``dir``.

    **Validates: Requirements 7.4, 8.4, 9.4**
    """
    expected = SHARED_VALIDATOR_CALLBACKS[name]
    par_cb = PAR_PARAMS[name].callback
    dir_cb = DIR_PARAMS[name].callback

    # Same function object on both commands, and it is the extracted validator.
    assert par_cb is expected, f"--{name} callback is not the shared validator"
    assert par_cb is dir_cb, f"--{name} callback differs between par and dir"


@pytest.mark.parametrize("name", ALL_SHARED_OPTIONS)
def test_par_shares_dir_shared_option_definitions(name):
    """Every shared-decorator option on ``par`` matches ``dir``'s definition.

    **Validates: Requirements 7.4, 8.4, 9.4, 12.7**

    The shared decorators (request-context, resilience, concurrency, TLS,
    matcher/filter, machine-output) are applied to both commands, so each option
    must exist on ``par`` with the same dest name, default, callback, type
    choices, and repeatability as on ``dir``.
    """
    assert name in PAR_PARAMS, f"par is missing shared option {name!r}"
    assert name in DIR_PARAMS, f"dir is missing shared option {name!r}"

    par_opt = PAR_PARAMS[name]
    dir_opt = DIR_PARAMS[name]

    # Same option flags (e.g. --match-size, -H/--header).
    assert set(par_opt.opts) == set(dir_opt.opts), (
        f"{name} flags differ: par={par_opt.opts} dir={dir_opt.opts}"
    )
    # Same default value.
    assert par_opt.default == dir_opt.default, (
        f"{name} default differs: par={par_opt.default!r} dir={dir_opt.default!r}"
    )
    # Same repeatability.
    assert par_opt.multiple == dir_opt.multiple, (
        f"{name} multiple differs: par={par_opt.multiple} dir={dir_opt.multiple}"
    )
    # Same validator callback (same function object, or both None).
    assert par_opt.callback is dir_opt.callback, (
        f"{name} callback differs between par and dir"
    )
    # Same Choice values where applicable (e.g. --output-format csv/jsonl).
    assert _choice_values(par_opt) == _choice_values(dir_opt), (
        f"{name} choices differ: par={_choice_values(par_opt)} "
        f"dir={_choice_values(dir_opt)}"
    )


def test_par_exposes_every_shared_decorator_option():
    """``par`` exposes the full set of options from every shared decorator stack.

    **Validates: Requirements 7.4, 8.4, 9.4, 12.7**
    """
    missing = [name for name in ALL_SHARED_OPTIONS if name not in PAR_PARAMS]
    assert not missing, f"par is missing shared options: {missing}"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
