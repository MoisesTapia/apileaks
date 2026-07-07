"""Module-specific option unit tests for the CLI restructure (task 4.1).

These tests pin the regression snapshot for the per-module Click decorators and
appliers created in task 4 (``apileaks/cli/module_options.py``):

* ``bola_options`` / ``auth_options`` register EXACTLY the option names, types,
  and defaults copied verbatim from the legacy ``full`` command (Requirements
  2.5, 2.6, 12.1, 12.2). This is a structural snapshot against option drift.
* ``apply_bola_options`` / ``apply_auth_options`` mutate a fresh
  ``BOLAConfig`` / ``AuthTestingConfig`` to the same values the legacy ``full``
  handler produced for representative inputs — including the destructive-methods
  comma-parse and the "skip when absent" defaults (Requirements 2.5, 2.6).

The tests use Click introspection (``__click_params__``) to read what each
decorator declares without depending on any command, mirroring the approach used
by ``test_transversal_options_properties.py``.

**Validates: Requirements 2.5, 2.6, 12.1, 12.2**
"""

import click
import pytest

from cli.module_options import (
    AUTH_OPTIONS,
    BOLA_OPTIONS,
    apply_auth_options,
    apply_bola_options,
    auth_options,
    bola_options,
)
from core.config import AuthTestingConfig, BOLAConfig


# --------------------------------------------------------------------------- #
# Expected option snapshots (copied from the legacy ``full`` definitions).
# Each tuple: (param_name, primary_flag, is_flag, multiple, default).
# --------------------------------------------------------------------------- #

EXPECTED_BOLA_OPTIONS = [
    ("allow_write_bola", "--allow-write-bola", True, False, False),
    ("bola_destructive_methods", "--bola-destructive-methods", False, False, None),
    ("bola_composite", "--bola-composite", True, False, False),
    ("bola_id_leakage", "--bola-id-leakage", True, False, False),
    ("bola_verb_tampering", "--bola-verb-tampering", True, False, False),
    ("bola_parameter_pollution", "--bola-parameter-pollution", True, False, False),
    ("bola_dry_run", "--bola-dry-run", True, False, False),
]

EXPECTED_AUTH_OPTIONS = [
    ("public_key", "--public-key", False, False, None),
    ("jwks_url", "--jwks-url", False, False, None),
    ("signing_secret", "--signing-secret", False, False, None),
    ("allow_aggressive_auth", "--allow-aggressive-auth", True, False, False),
    ("auth_rate_limit_attempts", "--auth-rate-limit-attempts", False, False, None),
    ("auth_revocation_race_requests", "--auth-revocation-race-requests", False, False, None),
    ("auth_benign_username", "--auth-benign-username", False, False, None),
    ("mfa_provisional_token", "--mfa-provisional-token", False, False, None),
    ("mfa_protected_endpoint", "--mfa-protected-endpoint", False, False, None),
    ("oauth_authorize_url", "--oauth-authorize-url", False, False, None),
    ("oauth_attacker_redirect", "--oauth-attacker-redirect", False, False, None),
    ("oauth_foreign_aud_token", "--oauth-foreign-aud-token", False, False, None),
    # Repeatable options: Click reports default () for multiple flags.
    ("reset_token_sample", "--reset-token-sample", False, True, ()),
    ("reset_token_known_input", "--reset-token-known-input", False, True, ()),
    # Advanced / Expert attack options (Level 2, 3 & Expert).
    ("otp_endpoint", "--otp-endpoint", False, False, None),
    ("otp_digits", "--otp-digits", False, False, None),
    ("otp_field", "--otp-field", False, False, None),
    ("otp_session_field", "--otp-session-field", False, False, None),
    ("otp_session_token", "--otp-session-token", False, False, None),
    ("otp_race_concurrency", "--otp-race-concurrency", False, False, None),
    ("users_wordlist", "--users-wordlist", False, False, None),
    ("spray_password", "--spray-password", False, False, None),
    ("spray_batch_size", "--spray-batch-size", False, False, None),
    ("login_username_field", "--login-username-field", False, False, None),
    ("login_password_field", "--login-password-field", False, False, None),
    ("ip_rotation_burst", "--ip-rotation-burst", False, False, None),
    ("extra_ip_headers", "--extra-ip-headers", False, True, ()),
    ("timing_samples", "--timing-samples", False, False, None),
    ("timing_threshold", "--timing-threshold", False, False, None),
]

# Options that Click parses as integers (``type=int``).
INT_TYPED_AUTH_PARAMS = {
    "auth_rate_limit_attempts",
    "auth_revocation_race_requests",
}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _materialize(decorator_list):
    """Return the concrete ``click.Option`` objects a decorator list declares.

    Each entry is a ``click.option(...)`` decorator; applying it to a throwaway
    function appends the concrete ``Option`` to ``__click_params__``.
    """
    options = []
    for decorator in decorator_list:
        def _sink():
            pass

        decorator(_sink)
        params = getattr(_sink, "__click_params__", [])
        assert len(params) == 1, "each option decorator declares exactly one option"
        options.append(params[0])
    return options


def _effective_default(opt):
    """Return an option's effective runtime default.

    Options declared without an explicit ``default=`` (verbatim from ``full``,
    e.g. the JWT crypto trio and the repeatable reset-token options) surface an
    UNSET sentinel on ``Option.default``. Click resolves that to ``()`` for a
    ``multiple`` option and ``None`` otherwise, which is the value the handler
    actually receives — so we compare against that resolved value.
    """
    default = opt.default
    if default is None or type(default).__name__ == "Sentinel":
        return () if opt.multiple else None
    return default


def _options_via_decorator(decorator):
    """Return the ``click.Option`` objects the aggregate decorator attaches."""

    @click.command()
    @decorator
    def _probe(**kwargs):  # pragma: no cover - never executed
        pass

    return [p for p in _probe.params if isinstance(p, click.Option)]


BOLA_DECLARED = {opt.name: opt for opt in _materialize(BOLA_OPTIONS)}
AUTH_DECLARED = {opt.name: opt for opt in _materialize(AUTH_OPTIONS)}
BOLA_ON_COMMAND = {opt.name: opt for opt in _options_via_decorator(bola_options)}
AUTH_ON_COMMAND = {opt.name: opt for opt in _options_via_decorator(auth_options)}


# --------------------------------------------------------------------------- #
# BOLA option registration snapshot (Requirements 2.6, 12.2)
# --------------------------------------------------------------------------- #

def test_bola_options_register_exactly_expected_names():
    """``bola_options`` attaches exactly the seven expected BOLA options."""
    expected = {name for name, *_ in EXPECTED_BOLA_OPTIONS}
    assert set(BOLA_ON_COMMAND) == expected
    assert len(BOLA_ON_COMMAND) == len(EXPECTED_BOLA_OPTIONS)


@pytest.mark.parametrize("name,flag,is_flag,multiple,default", EXPECTED_BOLA_OPTIONS)
def test_bola_option_matches_snapshot(name, flag, is_flag, multiple, default):
    """Each BOLA option preserves its legacy name/flag/type/default (Req 2.6)."""
    opt = BOLA_ON_COMMAND[name]
    assert opt.name == name
    assert flag in opt.opts
    assert opt.is_flag == is_flag
    assert opt.multiple == multiple
    assert opt.default == default

# --------------------------------------------------------------------------- #
# Auth option registration snapshot (Requirements 2.6, 12.2)
# --------------------------------------------------------------------------- #

def test_auth_options_register_exactly_expected_names():
    """``auth_options`` attaches exactly the expected Auth + JWT crypto options."""
    expected = {name for name, *_ in EXPECTED_AUTH_OPTIONS}
    assert set(AUTH_ON_COMMAND) == expected
    assert len(AUTH_ON_COMMAND) == len(EXPECTED_AUTH_OPTIONS)


def test_auth_options_include_jwt_crypto_trio():
    """The JWT_Module_Tests crypto trio rides the Auth subcommand (Req 2.3)."""
    for name in ("public_key", "jwks_url", "signing_secret"):
        assert name in AUTH_ON_COMMAND


@pytest.mark.parametrize("name,flag,is_flag,multiple,default", EXPECTED_AUTH_OPTIONS)
def test_auth_option_matches_snapshot(name, flag, is_flag, multiple, default):
    """Each Auth option preserves its legacy name/flag/type/default (Req 2.6)."""
    opt = AUTH_ON_COMMAND[name]
    assert opt.name == name
    assert flag in opt.opts
    assert opt.is_flag == is_flag
    assert opt.multiple == multiple
    assert _effective_default(opt) == default


@pytest.mark.parametrize("name", sorted(INT_TYPED_AUTH_PARAMS))
def test_auth_int_typed_options(name):
    """Integer-typed auth options declare ``type=int`` (validation parity)."""
    opt = AUTH_ON_COMMAND[name]
    assert opt.type is click.INT


def test_bola_and_auth_option_names_are_disjoint():
    """BOLA and Auth options share no parameter name (ownership isolation)."""
    assert set(BOLA_ON_COMMAND).isdisjoint(set(AUTH_ON_COMMAND))


# --------------------------------------------------------------------------- #
# apply_bola_options behavior (Requirements 2.5, 2.6)
# --------------------------------------------------------------------------- #

def _all_bola_opts(**overrides):
    """Return a full BOLA opts dict (all keys present, as Click would pass)."""
    opts = {
        "allow_write_bola": False,
        "bola_destructive_methods": None,
        "bola_composite": False,
        "bola_id_leakage": False,
        "bola_verb_tampering": False,
        "bola_parameter_pollution": False,
        "bola_dry_run": False,
    }
    opts.update(overrides)
    return opts


def test_apply_bola_defaults_preserve_config_defaults():
    """With no flags supplied, BOLAConfig keeps its safe read-only defaults."""
    cfg = BOLAConfig()
    apply_bola_options(cfg, _all_bola_opts())

    assert cfg.allow_destructive is False
    assert cfg.enable_composite is False
    assert cfg.enable_id_leakage is False
    assert cfg.verb_tampering is False
    assert cfg.parameter_pollution is False
    assert cfg.dry_run is False
    # destructive_methods untouched -> BOLAConfig default {PATCH, PUT}.
    assert cfg.destructive_methods == {"PATCH", "PUT"}


def test_apply_bola_all_flags_enabled():
    """Every boolean flag is threaded onto the config when supplied."""
    cfg = BOLAConfig()
    apply_bola_options(cfg, _all_bola_opts(
        allow_write_bola=True,
        bola_composite=True,
        bola_id_leakage=True,
        bola_verb_tampering=True,
        bola_parameter_pollution=True,
        bola_dry_run=True,
    ))

    assert cfg.allow_destructive is True
    assert cfg.enable_composite is True
    assert cfg.enable_id_leakage is True
    assert cfg.verb_tampering is True
    assert cfg.parameter_pollution is True
    assert cfg.dry_run is True


def test_apply_bola_destructive_methods_parsed_and_uppercased():
    """``--bola-destructive-methods`` is comma-split, trimmed, and uppercased."""
    cfg = BOLAConfig()
    apply_bola_options(cfg, _all_bola_opts(
        allow_write_bola=True,
        bola_destructive_methods=" patch , put , delete ",
    ))
    assert cfg.destructive_methods == {"PATCH", "PUT", "DELETE"}


def test_apply_bola_destructive_methods_absent_keeps_default():
    """An empty/None methods string leaves the BOLAConfig default in place."""
    cfg = BOLAConfig()
    apply_bola_options(cfg, _all_bola_opts(bola_destructive_methods=""))
    assert cfg.destructive_methods == {"PATCH", "PUT"}


# --------------------------------------------------------------------------- #
# apply_auth_options behavior (Requirements 2.5, 2.6)
# --------------------------------------------------------------------------- #

def _all_auth_opts(**overrides):
    """Return a full Auth opts dict (all keys present, as Click would pass)."""
    opts = {
        "public_key": None,
        "jwks_url": None,
        "signing_secret": None,
        "allow_aggressive_auth": False,
        "auth_rate_limit_attempts": None,
        "auth_revocation_race_requests": None,
        "auth_benign_username": None,
        "mfa_provisional_token": None,
        "mfa_protected_endpoint": None,
        "oauth_authorize_url": None,
        "oauth_attacker_redirect": None,
        "oauth_foreign_aud_token": None,
        "reset_token_sample": (),
        "reset_token_known_input": (),
    }
    opts.update(overrides)
    return opts


def test_apply_auth_defaults_preserve_config_defaults():
    """With no flags supplied, AuthTestingConfig keeps its safe defaults."""
    cfg = AuthTestingConfig()
    apply_auth_options(cfg, _all_auth_opts())

    assert cfg.public_key_material is None
    assert cfg.jwks_url is None
    assert cfg.signing_secret is None
    assert cfg.allow_aggressive is False
    assert cfg.rate_limit_attempts == 10
    assert cfg.revocation_race_requests == 8
    assert cfg.benign_username is None
    assert cfg.mfa_flow_inputs is None
    assert cfg.oauth_flow_inputs is None
    assert cfg.reset_token_samples is None
    assert cfg.reset_token_known_inputs is None


def test_apply_auth_jwt_crypto_trio_threaded():
    """The JWT crypto trio overrides the config when supplied (Req 2.3)."""
    cfg = AuthTestingConfig()
    apply_auth_options(cfg, _all_auth_opts(
        public_key="-----BEGIN PUBLIC KEY-----",
        jwks_url="https://issuer.example/.well-known/jwks.json",
        signing_secret="s3cr3t",
    ))
    assert cfg.public_key_material == "-----BEGIN PUBLIC KEY-----"
    assert cfg.jwks_url == "https://issuer.example/.well-known/jwks.json"
    assert cfg.signing_secret == "s3cr3t"


def test_apply_auth_aggressive_and_numeric_inputs():
    """Aggressive gate + numeric probe counts are threaded when supplied."""
    cfg = AuthTestingConfig()
    apply_auth_options(cfg, _all_auth_opts(
        allow_aggressive_auth=True,
        auth_rate_limit_attempts=25,
        auth_revocation_race_requests=16,
        auth_benign_username="tester",
    ))
    assert cfg.allow_aggressive is True
    assert cfg.rate_limit_attempts == 25
    assert cfg.revocation_race_requests == 16
    assert cfg.benign_username == "tester"


def test_apply_auth_numeric_zero_is_threaded():
    """A supplied numeric value of 0 is threaded (only None is skipped)."""
    cfg = AuthTestingConfig()
    apply_auth_options(cfg, _all_auth_opts(auth_rate_limit_attempts=0))
    assert cfg.rate_limit_attempts == 0


def test_apply_auth_mfa_flow_inputs_assembled():
    """MFA inputs are collected into ``mfa_flow_inputs`` only when supplied."""
    cfg = AuthTestingConfig()
    apply_auth_options(cfg, _all_auth_opts(
        mfa_provisional_token="prov-token",
        mfa_protected_endpoint="https://api.example/secure",
    ))
    assert cfg.mfa_flow_inputs == {
        "provisional_token": "prov-token",
        "protected_endpoint": "https://api.example/secure",
    }


def test_apply_auth_mfa_partial_input():
    """A single MFA input still produces a partial dict (matches legacy)."""
    cfg = AuthTestingConfig()
    apply_auth_options(cfg, _all_auth_opts(mfa_provisional_token="only-token"))
    assert cfg.mfa_flow_inputs == {"provisional_token": "only-token"}


def test_apply_auth_oauth_flow_inputs_assembled():
    """OAuth inputs are collected into ``oauth_flow_inputs`` only when supplied."""
    cfg = AuthTestingConfig()
    apply_auth_options(cfg, _all_auth_opts(
        oauth_authorize_url="https://auth.example/authorize",
        oauth_attacker_redirect="https://evil.example/cb",
        oauth_foreign_aud_token="foreign.jwt.token",
    ))
    assert cfg.oauth_flow_inputs == {
        "authorize_url": "https://auth.example/authorize",
        "attacker_redirect": "https://evil.example/cb",
        "foreign_aud_token": "foreign.jwt.token",
    }


def test_apply_auth_reset_token_lists():
    """Repeatable reset-token options become plain lists when supplied."""
    cfg = AuthTestingConfig()
    apply_auth_options(cfg, _all_auth_opts(
        reset_token_sample=("tok-a", "tok-b"),
        reset_token_known_input=("alice@example.com",),
    ))
    assert cfg.reset_token_samples == ["tok-a", "tok-b"]
    assert cfg.reset_token_known_inputs == ["alice@example.com"]


def test_apply_auth_empty_repeatables_skipped():
    """Empty repeatable tuples leave the config defaults (None) untouched."""
    cfg = AuthTestingConfig()
    apply_auth_options(cfg, _all_auth_opts(
        reset_token_sample=(),
        reset_token_known_input=(),
    ))
    assert cfg.reset_token_samples is None
    assert cfg.reset_token_known_inputs is None
