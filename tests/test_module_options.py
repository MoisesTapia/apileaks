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


# ===========================================================================
# New module options — Function Auth / Business Flow / Property / Resource /
# Security Misconfig / Inventory / Unsafe Consumption / SSRF
# ===========================================================================

import click
import pytest

from cli.module_options import (
    FUNCTION_AUTH_OPTIONS,
    BUSINESS_FLOW_OPTIONS,
    PROPERTY_OPTIONS,
    RESOURCE_OPTIONS,
    SECURITY_MISCONFIG_OPTIONS,
    INVENTORY_OPTIONS,
    UNSAFE_CONSUMPTION_OPTIONS,
    SSRF_OPTIONS,
    function_auth_options,
    business_flow_options,
    property_options,
    resource_options,
    security_misconfig_options,
    inventory_options,
    unsafe_consumption_options,
    ssrf_options,
    apply_function_auth_options,
    apply_business_flow_options,
    apply_property_options,
    apply_resource_options,
    apply_security_misconfig_options,
    apply_inventory_options,
    apply_unsafe_consumption_options,
    apply_ssrf_options,
)
from core.config import (
    FunctionAuthConfig,
    BusinessFlowConfig,
    PropertyTestingConfig,
    ResourceTestingConfig,
    SecurityMisconfigConfig,
    InventoryConfig,
    UnsafeConsumptionConfig,
    SSRFConfig,
)


# ---------------------------------------------------------------------------
# Shared introspection helper (mirrors the pattern above)
# ---------------------------------------------------------------------------

def _opts_on_command(decorator):
    """Return {name: Option} for every option the aggregate decorator attaches."""
    @click.command()
    @decorator
    def _probe(**kwargs):  # pragma: no cover
        pass
    return {p.name: p for p in _probe.params if isinstance(p, click.Option)}


def _eff_default(opt):
    """Resolved default: () for multiple, None otherwise when unset."""
    d = opt.default
    if d is None or type(d).__name__ == "Sentinel":
        return () if opt.multiple else None
    return d


# ---------------------------------------------------------------------------
# Option snapshots — (name, primary_flag, is_flag, multiple, default)
# ---------------------------------------------------------------------------

EXPECTED_FUNCTION_AUTH = [
    ("bfla_admin_endpoints",   "--bfla-admin-endpoints",   False, True,  ()),
    ("bfla_dangerous_methods", "--bfla-dangerous-methods", False, False, None),
    ("bfla_role_fields",       "--bfla-role-fields",       False, True,  ()),
    ("bfla_role_values",       "--bfla-role-values",       False, True,  ()),
    ("bfla_api_versions",      "--bfla-api-versions",      False, False, None),
    ("bfla_output_file",       "--bfla-output-file",       False, False, None),
    ("allow_destructive_bfla", "--allow-destructive-bfla", True,  False, False),
]

EXPECTED_BUSINESS_FLOW = [
    ("flow_patterns",     "--flow-patterns",     False, True,  ()),
    ("flow_repetitions",  "--flow-repetitions",  False, False, None),
    ("flow_check_quota",  "--flow-check-quota",  True,  False, True),
    ("flow_quota_fields", "--flow-quota-fields", False, True,  ()),
    ("flow_delay_ms",     "--flow-delay-ms",     False, False, None),
]

EXPECTED_PROPERTY = [
    ("property_sensitive_fields",       "--property-sensitive-fields",       False, True, ()),
    ("property_mass_assignment_fields", "--property-mass-assignment-fields", False, True, ()),
]

EXPECTED_RESOURCE = [
    ("resource_burst_size",    "--resource-burst-size",    False, False, None),
    ("resource_payload_sizes", "--resource-payload-sizes", False, False, None),
    ("resource_json_depth",    "--resource-json-depth",    False, False, None),
]

EXPECTED_SECURITY_MISCONFIG = [
    ("misconfig_required_headers", "--misconfig-required-headers", False, True, ()),
]

EXPECTED_INVENTORY = [
    ("inventory_detect_deprecated", "--inventory-detect-deprecated", True, False, True),
]

EXPECTED_UNSAFE_CONSUMPTION = [
    ("unsafe_upstream_indicators", "--unsafe-upstream-indicators", False, True,  ()),
    ("unsafe_payloads",            "--unsafe-payloads",            False, True,  ()),
    ("unsafe_check_redirects",     "--unsafe-check-redirects",     True,  False, True),
    ("unsafe_redirect_url",        "--unsafe-redirect-url",        False, False, None),
    ("unsafe_check_cleartext",     "--unsafe-check-cleartext",     True,  False, True),
]

EXPECTED_SSRF = [
    ("openapi",                "--openapi",                False, True,  ()),
    ("postman",                "--postman",                False, True,  ()),
    ("ssrf_callback_url",      "--ssrf-callback-url",      False, False, None),
    ("ssrf_internal_targets",  "--ssrf-internal-targets",  False, True,  ()),
    ("ssrf_schemes",           "--ssrf-schemes",           False, True,  ()),
    ("ssrf_scan_ports",        "--ssrf-scan-ports",        False, False, None),
    ("ssrf_body_injection",    "--ssrf-body-injection",    True,  False, False),
    ("ssrf_body_methods",      "--ssrf-body-methods",      False, False, None),
    ("ssrf_body_field",        "--ssrf-body-field",        False, True,  ()),
    ("burp_xml",               "--burp-xml",               False, False, None),
    ("har",                    "--har",                    False, False, None),
    ("allow_aggressive_ssrf",  "--allow-aggressive-ssrf",  True,  False, False),
    ("ssrf_require_signature", "--ssrf-require-signature", True,  False, False),
    ("ssrf_match_status",      "--ssrf-match-status",      False, False, None),
]


# ---------------------------------------------------------------------------
# Materialised command option dicts (one per module)
# ---------------------------------------------------------------------------

FA_OPTS  = _opts_on_command(function_auth_options)
BF_OPTS  = _opts_on_command(business_flow_options)
PR_OPTS  = _opts_on_command(property_options)
RE_OPTS  = _opts_on_command(resource_options)
SM_OPTS  = _opts_on_command(security_misconfig_options)
INV_OPTS = _opts_on_command(inventory_options)
UC_OPTS  = _opts_on_command(unsafe_consumption_options)
SS_OPTS  = _opts_on_command(ssrf_options)


# ---------------------------------------------------------------------------
# Registration count + name-set snapshot
# ---------------------------------------------------------------------------

def test_function_auth_options_register_exactly_expected_names():
    assert {n for n, *_ in EXPECTED_FUNCTION_AUTH} == set(FA_OPTS)
    assert len(FA_OPTS) == len(EXPECTED_FUNCTION_AUTH)


def test_business_flow_options_register_exactly_expected_names():
    assert {n for n, *_ in EXPECTED_BUSINESS_FLOW} == set(BF_OPTS)
    assert len(BF_OPTS) == len(EXPECTED_BUSINESS_FLOW)


def test_property_options_register_exactly_expected_names():
    assert {n for n, *_ in EXPECTED_PROPERTY} == set(PR_OPTS)
    assert len(PR_OPTS) == len(EXPECTED_PROPERTY)


def test_resource_options_register_exactly_expected_names():
    assert {n for n, *_ in EXPECTED_RESOURCE} == set(RE_OPTS)
    assert len(RE_OPTS) == len(EXPECTED_RESOURCE)


def test_security_misconfig_options_register_exactly_expected_names():
    assert {n for n, *_ in EXPECTED_SECURITY_MISCONFIG} == set(SM_OPTS)
    assert len(SM_OPTS) == len(EXPECTED_SECURITY_MISCONFIG)


def test_inventory_options_register_exactly_expected_names():
    assert {n for n, *_ in EXPECTED_INVENTORY} == set(INV_OPTS)
    assert len(INV_OPTS) == len(EXPECTED_INVENTORY)


def test_unsafe_consumption_options_register_exactly_expected_names():
    assert {n for n, *_ in EXPECTED_UNSAFE_CONSUMPTION} == set(UC_OPTS)
    assert len(UC_OPTS) == len(EXPECTED_UNSAFE_CONSUMPTION)


def test_ssrf_options_register_exactly_expected_names():
    assert {n for n, *_ in EXPECTED_SSRF} == set(SS_OPTS)
    assert len(SS_OPTS) == len(EXPECTED_SSRF)


# ---------------------------------------------------------------------------
# Per-option snapshot (flag / is_flag / multiple / default)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,flag,is_flag,multiple,default", EXPECTED_FUNCTION_AUTH)
def test_function_auth_option_snapshot(name, flag, is_flag, multiple, default):
    opt = FA_OPTS[name]
    assert flag in opt.opts
    assert opt.is_flag == is_flag
    assert opt.multiple == multiple
    assert _eff_default(opt) == default


@pytest.mark.parametrize("name,flag,is_flag,multiple,default", EXPECTED_BUSINESS_FLOW)
def test_business_flow_option_snapshot(name, flag, is_flag, multiple, default):
    opt = BF_OPTS[name]
    assert flag in opt.opts
    assert opt.is_flag == is_flag
    assert opt.multiple == multiple
    assert _eff_default(opt) == default


@pytest.mark.parametrize("name,flag,is_flag,multiple,default", EXPECTED_PROPERTY)
def test_property_option_snapshot(name, flag, is_flag, multiple, default):
    opt = PR_OPTS[name]
    assert flag in opt.opts
    assert opt.is_flag == is_flag
    assert opt.multiple == multiple
    assert _eff_default(opt) == default


@pytest.mark.parametrize("name,flag,is_flag,multiple,default", EXPECTED_RESOURCE)
def test_resource_option_snapshot(name, flag, is_flag, multiple, default):
    opt = RE_OPTS[name]
    assert flag in opt.opts
    assert opt.is_flag == is_flag
    assert opt.multiple == multiple
    assert _eff_default(opt) == default


@pytest.mark.parametrize("name,flag,is_flag,multiple,default", EXPECTED_SECURITY_MISCONFIG)
def test_security_misconfig_option_snapshot(name, flag, is_flag, multiple, default):
    opt = SM_OPTS[name]
    assert flag in opt.opts
    assert opt.is_flag == is_flag
    assert opt.multiple == multiple
    assert _eff_default(opt) == default


@pytest.mark.parametrize("name,flag,is_flag,multiple,default", EXPECTED_INVENTORY)
def test_inventory_option_snapshot(name, flag, is_flag, multiple, default):
    opt = INV_OPTS[name]
    assert flag in opt.opts
    assert opt.is_flag == is_flag
    assert opt.multiple == multiple
    assert _eff_default(opt) == default


@pytest.mark.parametrize("name,flag,is_flag,multiple,default", EXPECTED_UNSAFE_CONSUMPTION)
def test_unsafe_consumption_option_snapshot(name, flag, is_flag, multiple, default):
    opt = UC_OPTS[name]
    assert flag in opt.opts
    assert opt.is_flag == is_flag
    assert opt.multiple == multiple
    assert _eff_default(opt) == default


@pytest.mark.parametrize("name,flag,is_flag,multiple,default", EXPECTED_SSRF)
def test_ssrf_option_snapshot(name, flag, is_flag, multiple, default):
    opt = SS_OPTS[name]
    assert flag in opt.opts
    assert opt.is_flag == is_flag
    assert opt.multiple == multiple
    assert _eff_default(opt) == default


# ---------------------------------------------------------------------------
# All new modules are disjoint from each other and from bola/auth
# ---------------------------------------------------------------------------

def test_all_new_module_options_are_pairwise_disjoint():
    """No two modules share a parameter name (ownership isolation)."""
    all_groups = {
        "function_auth": set(FA_OPTS),
        "business_flow": set(BF_OPTS),
        "property":      set(PR_OPTS),
        "resource":      set(RE_OPTS),
        "sec_misconfig": set(SM_OPTS),
        "inventory":     set(INV_OPTS),
        "unsafe":        set(UC_OPTS),
        "ssrf":          set(SS_OPTS),
    }
    names = list(all_groups)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            overlap = all_groups[a] & all_groups[b]
            assert not overlap, f"{a} and {b} share: {overlap}"


# ---------------------------------------------------------------------------
# apply_* behaviour — defaults preserve config defaults
# ---------------------------------------------------------------------------

def test_apply_function_auth_defaults_preserve_config():
    cfg = FunctionAuthConfig()
    original_admins = list(cfg.admin_endpoints)
    original_methods = list(cfg.dangerous_methods)
    apply_function_auth_options(cfg, {
        "bfla_admin_endpoints": (),
        "bfla_dangerous_methods": None,
        "bfla_role_fields": (),
        "bfla_role_values": (),
        "bfla_api_versions": None,
        "bfla_output_file": None,
        "allow_destructive_bfla": False,
    })
    assert cfg.admin_endpoints == original_admins
    assert cfg.dangerous_methods == original_methods
    assert cfg.allow_destructive is False
    assert cfg.bfla_output_file is None


def test_apply_function_auth_endpoints_replaced():
    cfg = FunctionAuthConfig()
    apply_function_auth_options(cfg, {
        "bfla_admin_endpoints": ("/backstage", "/ops"),
        "bfla_dangerous_methods": None,
        "bfla_role_fields": (), "bfla_role_values": (),
        "bfla_api_versions": None, "bfla_output_file": None,
        "allow_destructive_bfla": False,
    })
    assert cfg.admin_endpoints == ["/backstage", "/ops"]


def test_apply_function_auth_dangerous_methods_comma_parsed():
    cfg = FunctionAuthConfig()
    apply_function_auth_options(cfg, {
        "bfla_admin_endpoints": (),
        "bfla_dangerous_methods": "DELETE, put ,PATCH",
        "bfla_role_fields": (), "bfla_role_values": (),
        "bfla_api_versions": None, "bfla_output_file": None,
        "allow_destructive_bfla": False,
    })
    assert cfg.dangerous_methods == ["DELETE", "PUT", "PATCH"]


def test_apply_function_auth_destructive_flag():
    cfg = FunctionAuthConfig()
    apply_function_auth_options(cfg, {
        "bfla_admin_endpoints": (), "bfla_dangerous_methods": None,
        "bfla_role_fields": (), "bfla_role_values": (),
        "bfla_api_versions": None, "bfla_output_file": "/tmp/out.json",
        "allow_destructive_bfla": True,
    })
    assert cfg.allow_destructive is True
    assert cfg.bfla_output_file == "/tmp/out.json"


def test_apply_function_auth_api_versions_comma_parsed():
    cfg = FunctionAuthConfig()
    apply_function_auth_options(cfg, {
        "bfla_admin_endpoints": (), "bfla_dangerous_methods": None,
        "bfla_role_fields": (), "bfla_role_values": (),
        "bfla_api_versions": "v1,v2,v3",
        "bfla_output_file": None, "allow_destructive_bfla": False,
    })
    assert cfg.api_versions == ["v1", "v2", "v3"]


def test_apply_business_flow_defaults_preserve_config():
    cfg = BusinessFlowConfig()
    original_patterns = list(cfg.sensitive_flow_patterns)
    apply_business_flow_options(cfg, {
        "flow_patterns": (), "flow_repetitions": None,
        "flow_check_quota": True, "flow_quota_fields": (),
        "flow_delay_ms": None,
    })
    assert cfg.sensitive_flow_patterns == original_patterns
    assert cfg.repetition_limit == 50
    assert cfg.check_quota_decrement is True
    assert cfg.inter_request_delay_ms == 0


def test_apply_business_flow_patterns_replaced():
    cfg = BusinessFlowConfig()
    apply_business_flow_options(cfg, {
        "flow_patterns": ("/buy", "/bid"),
        "flow_repetitions": None, "flow_check_quota": True,
        "flow_quota_fields": (), "flow_delay_ms": None,
    })
    assert cfg.sensitive_flow_patterns == ["/buy", "/bid"]


def test_apply_business_flow_repetitions_and_delay():
    cfg = BusinessFlowConfig()
    apply_business_flow_options(cfg, {
        "flow_patterns": (), "flow_repetitions": 200,
        "flow_check_quota": False, "flow_quota_fields": (),
        "flow_delay_ms": 1100,
    })
    assert cfg.repetition_limit == 200
    assert cfg.check_quota_decrement is False
    assert cfg.inter_request_delay_ms == 1100


def test_apply_business_flow_quota_fields_replaced():
    cfg = BusinessFlowConfig()
    apply_business_flow_options(cfg, {
        "flow_patterns": (), "flow_repetitions": None,
        "flow_check_quota": True,
        "flow_quota_fields": ("ticketsLeft", "creditsRemaining"),
        "flow_delay_ms": None,
    })
    assert cfg.quota_fields == ["ticketsLeft", "creditsRemaining"]


def test_apply_property_defaults_preserve_config():
    cfg = PropertyTestingConfig()
    original_sensitive = list(cfg.sensitive_fields)
    original_mass = list(cfg.mass_assignment_fields)
    apply_property_options(cfg, {
        "property_sensitive_fields": (),
        "property_mass_assignment_fields": (),
    })
    assert cfg.sensitive_fields == original_sensitive
    assert cfg.mass_assignment_fields == original_mass


def test_apply_property_fields_replaced():
    cfg = PropertyTestingConfig()
    apply_property_options(cfg, {
        "property_sensitive_fields": ("iban", "cvv"),
        "property_mass_assignment_fields": ("balance",),
    })
    assert cfg.sensitive_fields == ["iban", "cvv"]
    assert cfg.mass_assignment_fields == ["balance"]


def test_apply_resource_defaults_preserve_config():
    cfg = ResourceTestingConfig()
    apply_resource_options(cfg, {
        "resource_burst_size": None,
        "resource_payload_sizes": None,
        "resource_json_depth": None,
    })
    assert cfg.burst_size == 100
    assert cfg.json_depth_limit == 1000


def test_apply_resource_burst_size():
    cfg = ResourceTestingConfig()
    apply_resource_options(cfg, {
        "resource_burst_size": 250,
        "resource_payload_sizes": None,
        "resource_json_depth": None,
    })
    assert cfg.burst_size == 250


def test_apply_resource_payload_sizes_comma_parsed():
    cfg = ResourceTestingConfig()
    apply_resource_options(cfg, {
        "resource_burst_size": None,
        "resource_payload_sizes": "524288,5242880",
        "resource_json_depth": None,
    })
    assert cfg.large_payload_sizes == [524288, 5242880]


def test_apply_resource_json_depth():
    cfg = ResourceTestingConfig()
    apply_resource_options(cfg, {
        "resource_burst_size": None,
        "resource_payload_sizes": None,
        "resource_json_depth": 2000,
    })
    assert cfg.json_depth_limit == 2000


def test_apply_security_misconfig_defaults_preserve_config():
    cfg = SecurityMisconfigConfig()
    original = list(cfg.required_headers)
    apply_security_misconfig_options(cfg, {"misconfig_required_headers": ()})
    assert cfg.required_headers == original


def test_apply_security_misconfig_headers_replaced():
    cfg = SecurityMisconfigConfig()
    apply_security_misconfig_options(cfg, {
        "misconfig_required_headers": ("Strict-Transport-Security", "Permissions-Policy"),
    })
    assert cfg.required_headers == ["Strict-Transport-Security", "Permissions-Policy"]


def test_apply_inventory_defaults_preserve_config():
    cfg = InventoryConfig()
    apply_inventory_options(cfg, {"inventory_detect_deprecated": True})
    assert cfg.detect_deprecated is True


def test_apply_inventory_deprecated_disabled():
    cfg = InventoryConfig()
    apply_inventory_options(cfg, {"inventory_detect_deprecated": False})
    assert cfg.detect_deprecated is False


def test_apply_unsafe_consumption_defaults_preserve_config():
    cfg = UnsafeConsumptionConfig()
    original_indicators = list(cfg.upstream_indicators)
    original_payloads = list(cfg.malformed_payloads)
    apply_unsafe_consumption_options(cfg, {
        "unsafe_upstream_indicators": (),
        "unsafe_payloads": (),
        "unsafe_check_redirects": True,
        "unsafe_redirect_url": None,
        "unsafe_check_cleartext": True,
    })
    assert cfg.upstream_indicators == original_indicators
    assert cfg.malformed_payloads == original_payloads
    assert cfg.check_redirects is True
    assert cfg.check_cleartext_upstream is True


def test_apply_unsafe_consumption_indicators_replaced():
    cfg = UnsafeConsumptionConfig()
    apply_unsafe_consumption_options(cfg, {
        "unsafe_upstream_indicators": ("fetch", "webhook"),
        "unsafe_payloads": (),
        "unsafe_check_redirects": True,
        "unsafe_redirect_url": None,
        "unsafe_check_cleartext": True,
    })
    assert cfg.upstream_indicators == ["fetch", "webhook"]


def test_apply_unsafe_consumption_redirect_url_and_toggles():
    cfg = UnsafeConsumptionConfig()
    apply_unsafe_consumption_options(cfg, {
        "unsafe_upstream_indicators": (),
        "unsafe_payloads": (),
        "unsafe_check_redirects": False,
        "unsafe_redirect_url": "https://xyz.interact.sh",
        "unsafe_check_cleartext": False,
    })
    assert cfg.check_redirects is False
    assert cfg.redirect_test_url == "https://xyz.interact.sh"
    assert cfg.check_cleartext_upstream is False


def test_apply_ssrf_callback_url():
    cfg = SSRFConfig()
    apply_ssrf_options(cfg, {
        "ssrf_callback_url": "https://xyz.interact.sh",
        "ssrf_internal_targets": (),
        "ssrf_schemes": (),
        "ssrf_scan_ports": None,
        "ssrf_body_injection": False,
        "ssrf_body_methods": None,
        "ssrf_body_field": (),
        "burp_xml": None,
        "har": None,
        "allow_aggressive_ssrf": False,
        "ssrf_require_signature": False,
        "ssrf_match_status": None,
        "openapi": (),
        "postman": (),
    })
    assert cfg.callback_url == "https://xyz.interact.sh"


def test_apply_ssrf_internal_targets_merged():
    cfg = SSRFConfig()
    apply_ssrf_options(cfg, {
        "ssrf_callback_url": None,
        "ssrf_internal_targets": ("10.0.0.1", "172.16.0.1"),
        "ssrf_schemes": (),
        "ssrf_scan_ports": None,
        "ssrf_body_injection": False,
        "ssrf_body_methods": None,
        "ssrf_body_field": (),
        "burp_xml": None, "har": None,
        "allow_aggressive_ssrf": False,
        "ssrf_require_signature": False,
        "ssrf_match_status": None,
        "openapi": (), "postman": (),
    })
    assert "10.0.0.1" in cfg.additional_internal_targets
    assert "172.16.0.1" in cfg.additional_internal_targets


def test_apply_ssrf_scan_ports_comma_parsed():
    cfg = SSRFConfig()
    apply_ssrf_options(cfg, {
        "ssrf_callback_url": None,
        "ssrf_internal_targets": (),
        "ssrf_schemes": (),
        "ssrf_scan_ports": "22,80,443,8080",
        "ssrf_body_injection": False,
        "ssrf_body_methods": None,
        "ssrf_body_field": (),
        "burp_xml": None, "har": None,
        "allow_aggressive_ssrf": False,
        "ssrf_require_signature": False,
        "ssrf_match_status": None,
        "openapi": (), "postman": (),
    })
    assert cfg.scan_ports == [22, 80, 443, 8080]


def test_apply_ssrf_body_methods_implies_body_injection():
    cfg = SSRFConfig()
    apply_ssrf_options(cfg, {
        "ssrf_callback_url": None,
        "ssrf_internal_targets": (),
        "ssrf_schemes": (),
        "ssrf_scan_ports": None,
        "ssrf_body_injection": False,
        "ssrf_body_methods": "POST,PUT,PATCH",
        "ssrf_body_field": (),
        "burp_xml": None, "har": None,
        "allow_aggressive_ssrf": False,
        "ssrf_require_signature": False,
        "ssrf_match_status": None,
        "openapi": (), "postman": (),
    })
    assert cfg.body_injection is True
    assert cfg.body_injection_methods == ["POST", "PUT", "PATCH"]


def test_apply_ssrf_aggressive_enables_port_scan_gate():
    cfg = SSRFConfig()
    apply_ssrf_options(cfg, {
        "ssrf_callback_url": None,
        "ssrf_internal_targets": (),
        "ssrf_schemes": (),
        "ssrf_scan_ports": None,
        "ssrf_body_injection": False,
        "ssrf_body_methods": None,
        "ssrf_body_field": (),
        "burp_xml": None, "har": None,
        "allow_aggressive_ssrf": True,
        "ssrf_require_signature": False,
        "ssrf_match_status": None,
        "openapi": (), "postman": (),
    })
    assert cfg.allow_port_scan is True


def test_apply_ssrf_match_status_comma_parsed():
    cfg = SSRFConfig()
    apply_ssrf_options(cfg, {
        "ssrf_callback_url": None,
        "ssrf_internal_targets": (),
        "ssrf_schemes": (),
        "ssrf_scan_ports": None,
        "ssrf_body_injection": False,
        "ssrf_body_methods": None,
        "ssrf_body_field": (),
        "burp_xml": None, "har": None,
        "allow_aggressive_ssrf": False,
        "ssrf_require_signature": False,
        "ssrf_match_status": "200,201,301",
        "openapi": (), "postman": (),
    })
    assert 200 in cfg.success_status_codes
    assert 201 in cfg.success_status_codes
    assert 301 in cfg.success_status_codes
