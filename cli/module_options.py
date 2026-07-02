"""Module_Specific_Option decorators and appliers for the restructured CLI.

Each OWASP module that owns options declares a Click decorator that attaches
exactly its own Module_Specific_Options plus an applier that mutates the
module's config dataclass from the collected option values. Only ``bola`` and
``auth`` own options today; the other eight subcommands receive Transversal_
Options only until their owning spec adds options (Requirement 11 makes that
extension trivial).

The option definitions (names, dest, ``type``, ``default``, ``metavar``,
``is_flag``, ``multiple``, help text) are copied VERBATIM from the current
``full`` command in ``apileaks.py`` so behavior and validation are byte-identical
(Requirements 2.5, 2.6, 12.1, 12.2). The applier bodies are the post-load config
mutation blocks lifted verbatim from the ``full`` handler:

- ``apply_bola_options``: the ``bola_config`` assembly logic (destructive-methods
  parsing -> ``BOLAConfig`` fields).
- ``apply_auth_options``: the ``AuthTestingConfig`` mutation block (JWT crypto
  trio + advanced auth/JWT hardening inputs).

Both attach only their own options, so Click natively rejects a foreign module
option with ``No such option`` (nonzero, pre-request) — Requirement 2.7.

This module contains no OWASP detection logic; it only declares CLI options and
maps their values onto existing config dataclasses.

Requirements: 2.1, 2.2, 2.3, 2.5, 2.6, 12.1, 12.2
"""

import click


# ---------------------------------------------------------------------------
# BOLA Module_Specific_Options (Requirement 2.1). Copied verbatim from the
# ``full`` command definitions.
# ---------------------------------------------------------------------------

BOLA_OPTIONS = [
    click.option('--allow-write-bola', 'allow_write_bola', is_flag=True, default=False,
                 help='Destructive_Opt_In: authorize the BOLA module to issue destructive '
                      '(state-changing) probes. Off by default; when omitted the BOLA module '
                      'issues only safe-method probes (read-only).'),
    click.option('--bola-destructive-methods', 'bola_destructive_methods', metavar='METHODS', default=None,
                 help='Comma-separated HTTP methods treated as destructive when '
                      '--allow-write-bola is set (e.g. PATCH,PUT,DELETE). Values are '
                      'uppercased. Defaults to PATCH,PUT (DELETE excluded) when omitted.'),
    click.option('--bola-composite', 'bola_composite', is_flag=True, default=False,
                 help='Enable the composite-key BOLA probe (off by default).'),
    click.option('--bola-id-leakage', 'bola_id_leakage', is_flag=True, default=False,
                 help='Enable the object-identifier leakage BOLA probe (off by default).'),
    click.option('--bola-verb-tampering', 'bola_verb_tampering', is_flag=True, default=False,
                 help='Enable the HTTP verb-tampering BOLA technique (off by default).'),
    click.option('--bola-parameter-pollution', 'bola_parameter_pollution', is_flag=True, default=False,
                 help='Enable the HTTP parameter-pollution BOLA technique (off by default).'),
    click.option('--bola-dry-run', 'bola_dry_run', is_flag=True, default=False,
                 help='Plan destructive BOLA probes (method, URL, substituted id, body) '
                      'without issuing them (off by default).'),
]


def bola_options(func):
    """Attach the BOLA Module_Specific_Options to ``func`` (Requirement 2.1).

    Applies ``BOLA_OPTIONS`` in REVERSE order so that, once Click stacks the
    decorators, the options appear in declaration order on the resulting command
    (matching the legacy ``full`` help order).
    """
    for option in reversed(BOLA_OPTIONS):
        func = option(func)
    return func


def apply_bola_options(bola_cfg, opts: dict) -> None:
    """Mutate a ``BOLAConfig`` from collected option values (lifted from ``full``).

    Mirrors the ``bola_config`` assembly in the ``full`` handler: every boolean
    flag is applied unconditionally (its default is off), and
    ``--bola-destructive-methods`` is parsed from a comma-separated string into an
    uppercased set and only threaded when supplied so the ``BOLAConfig`` default
    ``{PATCH, PUT}`` otherwise applies (Requirements 34.2, 34.3, 34.4, preserved
    here per Requirements 2.5, 2.6).

    Args:
        bola_cfg: The ``BOLAConfig`` instance to mutate in place.
        opts: The collected Click option values (keyed by option dest name).
    """
    bola_destructive_methods = opts.get('bola_destructive_methods')
    destructive_methods_set = None
    if bola_destructive_methods:
        destructive_methods_set = {
            m.strip().upper()
            for m in bola_destructive_methods.split(',')
            if m.strip()
        }

    bola_cfg.allow_destructive = opts.get('allow_write_bola', False)
    if destructive_methods_set:
        bola_cfg.destructive_methods = destructive_methods_set
    bola_cfg.enable_composite = opts.get('bola_composite', False)
    bola_cfg.enable_id_leakage = opts.get('bola_id_leakage', False)
    bola_cfg.verb_tampering = opts.get('bola_verb_tampering', False)
    bola_cfg.parameter_pollution = opts.get('bola_parameter_pollution', False)
    bola_cfg.dry_run = opts.get('bola_dry_run', False)


# ---------------------------------------------------------------------------
# Auth Module_Specific_Options (Requirements 2.2, 2.3). The JWT_Module_Tests
# cryptographic trio (--public-key / --jwks-url / --signing-secret) leads the
# list, followed by the advanced auth hardening options. Copied verbatim from
# the ``full`` command definitions.
# ---------------------------------------------------------------------------

AUTH_OPTIONS = [
    # --- JWT_Module_Tests cryptographic trio (Requirement 2.3) ------------
    click.option('--public-key', 'public_key', metavar='PATH_OR_PEM',
                 help='RSA public key material (PEM/DER path or inline PEM) used by the '
                      'algorithm-confusion test to HMAC-sign with the real key bytes.'),
    click.option('--jwks-url', 'jwks_url', metavar='URL',
                 help='JWKS endpoint URL used to fetch RSA public key material for the '
                      'algorithm-confusion test when no --public-key is supplied.'),
    click.option('--signing-secret', 'signing_secret', metavar='SECRET',
                 help='Known HMAC signing secret used to construct a validly-signed but '
                      'expired token for the expired-token-acceptance test.'),
    # --- advanced auth hardening options (Requirement 2.2) ----------------
    click.option('--allow-aggressive-auth', 'allow_aggressive_auth', is_flag=True, default=False,
                 help='Aggressive_Opt_In: authorize the Auth_Module to issue high-volume or '
                      'concurrency probes (anti-automation / rate-limit burst and the '
                      'token-revocation race). Off by default; when omitted these probes are '
                      'skipped regardless of other flags.'),
    click.option('--auth-rate-limit-attempts', 'auth_rate_limit_attempts', type=int, default=None,
                 help='Number of bounded login attempts used by the anti-automation / '
                      'rate-limiting probe when aggressive auth testing is enabled '
                      '(default: 10).'),
    click.option('--auth-revocation-race-requests', 'auth_revocation_race_requests', type=int, default=None,
                 help='Bounded number of concurrent requests used by the token-revocation '
                      'race probe when aggressive auth testing is enabled (default: 8).'),
    click.option('--auth-benign-username', 'auth_benign_username', metavar='USER', default=None,
                 help='Benign account username used by the anti-automation probe (varied '
                      'passwords against one benign account so real accounts are not locked '
                      'out). When omitted, input-driven probes requiring it are skipped.'),
    click.option('--mfa-provisional-token', 'mfa_provisional_token', metavar='TOKEN', default=None,
                 help='Provisional_Token issued before the MFA step, submitted to a '
                      'protected endpoint by the MFA-bypass probe. Requires '
                      '--mfa-protected-endpoint; when omitted the MFA-bypass test is skipped.'),
    click.option('--mfa-protected-endpoint', 'mfa_protected_endpoint', metavar='URL', default=None,
                 help='Protected endpoint URL the MFA-bypass probe targets with the '
                      'provisional token. Requires --mfa-provisional-token; when omitted the '
                      'MFA-bypass test is skipped.'),
    click.option('--oauth-authorize-url', 'oauth_authorize_url', metavar='URL', default=None,
                 help='OAuth authorization endpoint URL exercised by the OAuth-flow abuse '
                      'probes. When no OAuth inputs are supplied, OAuth-flow testing is skipped.'),
    click.option('--oauth-attacker-redirect', 'oauth_attacker_redirect', metavar='URL', default=None,
                 help='Attacker-controlled or unregistered Redirect_URI submitted by the '
                      'OAuth redirect-URI manipulation probe.'),
    click.option('--oauth-foreign-aud-token', 'oauth_foreign_aud_token', metavar='TOKEN', default=None,
                 help='Token issued for a different application, presented by the OAuth '
                      'audience-confusion probe to detect missing aud-claim validation.'),
    click.option('--reset-token-sample', 'reset_token_sample', multiple=True, metavar='TOKEN',
                 help='Observed Password_Reset_Token to analyze for predictability. '
                      'Repeatable: pass once per sample. When none are supplied, reset-token '
                      'analysis is skipped.'),
    click.option('--reset-token-known-input', 'reset_token_known_input', multiple=True, metavar='VALUE',
                 help='Known input (e.g. an account email) used to classify a reset token as '
                      'a hash-of-known-input. Repeatable: pass once per value.'),
]


def auth_options(func):
    """Attach the Auth Module_Specific_Options to ``func`` (Requirements 2.2, 2.3).

    Applies ``AUTH_OPTIONS`` in REVERSE order so that, once Click stacks the
    decorators, the options appear in declaration order on the resulting command
    (matching the legacy ``full`` help order).
    """
    for option in reversed(AUTH_OPTIONS):
        func = option(func)
    return func


def apply_auth_options(auth_cfg, opts: dict) -> None:
    """Mutate an ``AuthTestingConfig`` from collected option values (from ``full``).

    Lifts the post-load ``AuthTestingConfig`` mutation block verbatim from the
    ``full`` handler. Each field is only overridden when its CLI flag is supplied
    so the SAFE defaults (no aggressive/state-changing/input-driven probes) are
    preserved when none are given (Requirements 46.1, 26.1, 26.3, preserved here
    per Requirements 2.5, 2.6). The ``--allow-aggressive-auth`` Aggressive_Opt_In
    only turns the gate ON when present; its absence leaves any file-config value
    untouched.

    Args:
        auth_cfg: The ``AuthTestingConfig`` instance to mutate in place.
        opts: The collected Click option values (keyed by option dest name).
    """
    # JWT_Module_Tests key inputs (Requirements 6.1, 6.2, 8.1). The CLI flags
    # override any file-config values when supplied.
    if opts.get('public_key'):
        auth_cfg.public_key_material = opts['public_key']
    if opts.get('jwks_url'):
        auth_cfg.jwks_url = opts['jwks_url']
    if opts.get('signing_secret'):
        auth_cfg.signing_secret = opts['signing_secret']

    # Advanced auth/JWT hardening inputs (Requirements 37, 39, 40, 41, 42, 46).
    if opts.get('allow_aggressive_auth'):
        auth_cfg.allow_aggressive = True
    if opts.get('auth_rate_limit_attempts') is not None:
        auth_cfg.rate_limit_attempts = opts['auth_rate_limit_attempts']
    if opts.get('auth_revocation_race_requests') is not None:
        auth_cfg.revocation_race_requests = opts['auth_revocation_race_requests']
    if opts.get('auth_benign_username'):
        auth_cfg.benign_username = opts['auth_benign_username']

    # MFA-flow inputs (Requirement 39): assemble the operator-supplied
    # provisional token + protected endpoint into the mfa_flow_inputs dict. Only
    # set when at least one input is supplied; None otherwise so the MFA-bypass
    # test is skipped (Requirement 39.5).
    mfa_flow_inputs = {}
    if opts.get('mfa_provisional_token'):
        mfa_flow_inputs['provisional_token'] = opts['mfa_provisional_token']
    if opts.get('mfa_protected_endpoint'):
        mfa_flow_inputs['protected_endpoint'] = opts['mfa_protected_endpoint']
    if mfa_flow_inputs:
        auth_cfg.mfa_flow_inputs = mfa_flow_inputs

    # OAuth-flow inputs (Requirement 41): assemble the authorization URL,
    # attacker-controlled Redirect_URI, and foreign-audience token into the
    # oauth_flow_inputs dict. Only set when at least one input is supplied; None
    # otherwise so OAuth-flow testing is skipped (Requirement 41.6).
    oauth_flow_inputs = {}
    if opts.get('oauth_authorize_url'):
        oauth_flow_inputs['authorize_url'] = opts['oauth_authorize_url']
    if opts.get('oauth_attacker_redirect'):
        oauth_flow_inputs['attacker_redirect'] = opts['oauth_attacker_redirect']
    if opts.get('oauth_foreign_aud_token'):
        oauth_flow_inputs['foreign_aud_token'] = opts['oauth_foreign_aud_token']
    if oauth_flow_inputs:
        auth_cfg.oauth_flow_inputs = oauth_flow_inputs

    # Reset-token samples / known inputs (Requirement 40): repeatable options
    # collected into lists. Only set when supplied so reset-token analysis is
    # skipped by default (Requirements 40.1, 26.3).
    if opts.get('reset_token_sample'):
        auth_cfg.reset_token_samples = list(opts['reset_token_sample'])
    if opts.get('reset_token_known_input'):
        auth_cfg.reset_token_known_inputs = list(opts['reset_token_known_input'])
