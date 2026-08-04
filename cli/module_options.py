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
# Function Level Authorization (BFLA) Module_Specific_Options (OWASP API5).
# Exposes the four grey-box BFLA attack configuration knobs:
#   --bfla-admin-endpoints   : custom admin URL path prefixes for L1 mapping
#   --bfla-dangerous-methods : HTTP methods used for L2 verb-tamper probes
#   --bfla-role-fields       : JSON field names for L3 mass-assignment injection
#   --bfla-role-values       : role values to inject in L3 probes
#   --bfla-api-versions      : version strings for L4 version-downgrade probes
#   --bfla-output-file       : persist full probe matrix to JSON
#   --allow-destructive-bfla : opt-in for state-changing (DELETE/PUT) probes
# ---------------------------------------------------------------------------

FUNCTION_AUTH_OPTIONS = [
    click.option(
        '--bfla-admin-endpoints', 'bfla_admin_endpoints',
        multiple=True, metavar='PATH',
        help=(
            'URL path prefix that identifies an administrative endpoint '
            '(repeatable). Used during the admin-endpoint mapping phase (L1). '
            'Replaces the built-in list when any value is supplied. '
            'Built-in defaults: /admin, /api/admin, /management, /dashboard.'
        ),
    ),
    click.option(
        '--bfla-dangerous-methods', 'bfla_dangerous_methods',
        metavar='METHODS', default=None,
        help=(
            'Comma-separated HTTP methods used for Level 2 verb-tampering '
            'probes (e.g. DELETE,PUT,PATCH). Replaces the built-in list '
            'when supplied. Defaults to DELETE,PUT,PATCH.'
        ),
    ),
    click.option(
        '--bfla-role-fields', 'bfla_role_fields',
        multiple=True, metavar='FIELD',
        help=(
            'JSON body field name to inject as a privilege-escalation payload '
            'during Level 3 mass-assignment probes (repeatable). '
            'Replaces the built-in list when any value is supplied. '
            'Built-in defaults: role, is_admin, admin, privilege, etc.'
        ),
    ),
    click.option(
        '--bfla-role-values', 'bfla_role_values',
        multiple=True, metavar='VALUE',
        help=(
            'Role value to inject into the --bfla-role-fields during Level 3 '
            'mass-assignment probes (repeatable). '
            'Replaces the built-in list when any value is supplied. '
            'Built-in defaults: admin, administrator, ADMIN, root, owner, etc.'
        ),
    ),
    click.option(
        '--bfla-api-versions', 'bfla_api_versions',
        metavar='VERSIONS', default=None,
        help=(
            'Comma-separated API version strings for Level 4 version-downgrade '
            'probes (e.g. v1,v2,v3). Replaces the built-in list when supplied. '
            'Defaults to v0,v1,v2,v3,v4.'
        ),
    ),
    click.option(
        '--bfla-output-file', 'bfla_output_file',
        metavar='PATH', default=None,
        help=(
            'Path to a JSON file where the full BFLA probe matrix is persisted '
            '(all probes, confirmed and denied). Useful for downstream analysis '
            'and chained attack tooling. When omitted, the matrix is not saved.'
        ),
    ),
    click.option(
        '--allow-destructive-bfla', 'allow_destructive_bfla',
        is_flag=True, default=False,
        help=(
            'Destructive_Opt_In: authorize the BFLA module to issue '
            'state-changing (DELETE/PUT/PATCH) replay probes against discovered '
            'admin endpoints. Off by default; when omitted only GET replays '
            'are issued.'
        ),
    ),
]


def function_auth_options(func):
    """Attach Function Level Auth (BFLA) Module_Specific_Options to ``func``."""
    for option in reversed(FUNCTION_AUTH_OPTIONS):
        func = option(func)
    return func


def apply_function_auth_options(fn_cfg, opts: dict) -> None:
    """Mutate a ``FunctionAuthConfig`` from collected option values.

    Args:
        fn_cfg: The ``FunctionAuthConfig`` instance to mutate.
        opts:   The collected Click option values (keyed by option dest name).
    """
    # --bfla-admin-endpoints (multiple=True) → replaces built-in list when supplied
    if opts.get('bfla_admin_endpoints'):
        fn_cfg.admin_endpoints = list(opts['bfla_admin_endpoints'])

    # --bfla-dangerous-methods → parse comma-separated, uppercase
    if opts.get('bfla_dangerous_methods'):
        fn_cfg.dangerous_methods = [
            m.strip().upper()
            for m in opts['bfla_dangerous_methods'].split(',')
            if m.strip()
        ]

    # --bfla-role-fields (multiple=True) → replaces built-in list when supplied
    if opts.get('bfla_role_fields'):
        fn_cfg.role_fields = list(opts['bfla_role_fields'])

    # --bfla-role-values (multiple=True) → replaces built-in list when supplied
    if opts.get('bfla_role_values'):
        fn_cfg.role_values = list(opts['bfla_role_values'])

    # --bfla-api-versions → parse comma-separated version strings
    if opts.get('bfla_api_versions'):
        fn_cfg.api_versions = [
            v.strip()
            for v in opts['bfla_api_versions'].split(',')
            if v.strip()
        ]

    # --bfla-output-file
    if opts.get('bfla_output_file'):
        fn_cfg.bfla_output_file = opts['bfla_output_file']

    # --allow-destructive-bfla
    if opts.get('allow_destructive_bfla'):
        fn_cfg.allow_destructive = True


# ---------------------------------------------------------------------------
# Business Flow Module_Specific_Options (OWASP API6).
# Exposes the three detector knobs:
#   --flow-patterns           : custom sensitive-flow URL patterns
#   --flow-repetitions        : how many times to repeat each flow
#   --flow-check-quota        : toggle quota/decrement detector
#   --flow-quota-fields       : custom field names to watch for decrement
#   --flow-delay-ms           : inter-request delay to surface timing controls
# ---------------------------------------------------------------------------

BUSINESS_FLOW_OPTIONS = [
    click.option(
        '--flow-patterns', 'flow_patterns',
        multiple=True, metavar='PATTERN',
        help=(
            'URL substring that identifies a sensitive business flow endpoint '
            '(repeatable). Replaces the built-in list when any value is supplied. '
            'Built-in defaults: /checkout, /purchase, /order, /transfer, '
            '/register, /coupon, /payment, /booking, /reserve, /redeem, '
            '/vote, /referral, /invite, /subscribe.'
        ),
    ),
    click.option(
        '--flow-repetitions', 'flow_repetitions',
        type=int, default=None, metavar='N',
        help=(
            'Number of times to repeat each sensitive-flow request to test for '
            'rate-limit absence (default: 50). Higher values increase confidence '
            'but also request count.'
        ),
    ),
    click.option(
        '--flow-check-quota/--no-flow-check-quota',
        'flow_check_quota',
        default=True, show_default=True,
        help=(
            'Enable (default) or disable the quota / resource-decrement detector. '
            'When enabled, the module compares quota-related fields (stock, '
            'remaining, seats, credits…) between the first and last response '
            'to detect cases where inventory is not being decremented.'
        ),
    ),
    click.option(
        '--flow-quota-fields', 'flow_quota_fields',
        multiple=True, metavar='FIELD',
        help=(
            'JSON response field name to watch for quota decrement (repeatable). '
            'Replaces the built-in list when any value is supplied. '
            'Built-in defaults: stock, quantity, remaining, available, count, '
            'seats, quota, credits, balance, limit.'
        ),
    ),
    click.option(
        '--flow-delay-ms', 'flow_delay_ms',
        type=int, default=None, metavar='MS',
        help=(
            'Delay in milliseconds between repeated flow requests (default: 0 — '
            'no delay). Use a non-zero value to surface timing-based controls '
            '(e.g. "max one request per second"). A delay of 0 simulates a '
            'fully automated bot — the worst-case attacker scenario.'
        ),
    ),
]


def business_flow_options(func):
    """Attach Business Flow Module_Specific_Options to ``func``."""
    for option in reversed(BUSINESS_FLOW_OPTIONS):
        func = option(func)
    return func


def apply_business_flow_options(flow_cfg, opts: dict) -> None:
    """Mutate a ``BusinessFlowConfig`` from collected option values.

    Args:
        flow_cfg: The ``BusinessFlowConfig`` instance to mutate.
        opts: The collected Click option values (keyed by option dest name).
    """
    # --flow-patterns (multiple=True) → replaces built-in list when supplied
    if opts.get('flow_patterns'):
        flow_cfg.sensitive_flow_patterns = list(opts['flow_patterns'])

    # --flow-repetitions
    if opts.get('flow_repetitions') is not None:
        flow_cfg.repetition_limit = int(opts['flow_repetitions'])

    # --flow-check-quota / --no-flow-check-quota
    if 'flow_check_quota' in opts:
        flow_cfg.check_quota_decrement = bool(opts['flow_check_quota'])

    # --flow-quota-fields (multiple=True) → replaces built-in list when supplied
    if opts.get('flow_quota_fields'):
        flow_cfg.quota_fields = list(opts['flow_quota_fields'])

    # --flow-delay-ms
    if opts.get('flow_delay_ms') is not None:
        flow_cfg.inter_request_delay_ms = int(opts['flow_delay_ms'])


# ---------------------------------------------------------------------------
# Property Level Authorization Module_Specific_Options (OWASP API3).
# ---------------------------------------------------------------------------

PROPERTY_OPTIONS = [
    click.option(
        '--property-sensitive-fields', 'property_sensitive_fields',
        multiple=True, metavar='FIELD',
        help=(
            'Field name considered sensitive in API responses (repeatable). '
            'Replaces the built-in list when any value is supplied. '
            'Built-in defaults: password, api_key, secret, token, ssn, credit_card.'
        ),
    ),
    click.option(
        '--property-mass-assignment-fields', 'property_mass_assignment_fields',
        multiple=True, metavar='FIELD',
        help=(
            'Dangerous JSON field name to inject during mass-assignment probes '
            '(repeatable). Replaces the built-in list when any value is supplied. '
            'Built-in defaults: is_admin, role, permissions, user_id.'
        ),
    ),
]


def property_options(func):
    """Attach Property Level Auth Module_Specific_Options to ``func``."""
    for option in reversed(PROPERTY_OPTIONS):
        func = option(func)
    return func


def apply_property_options(prop_cfg, opts: dict) -> None:
    """Mutate a ``PropertyTestingConfig`` from collected option values."""
    if opts.get('property_sensitive_fields'):
        prop_cfg.sensitive_fields = list(opts['property_sensitive_fields'])
    if opts.get('property_mass_assignment_fields'):
        prop_cfg.mass_assignment_fields = list(opts['property_mass_assignment_fields'])


# ---------------------------------------------------------------------------
# Resource Consumption Module_Specific_Options (OWASP API4).
# ---------------------------------------------------------------------------

RESOURCE_OPTIONS = [
    click.option(
        '--resource-burst-size', 'resource_burst_size',
        type=int, default=None, metavar='N',
        help=(
            'Number of concurrent requests in the rate-limit burst test '
            '(default: 100). Higher values increase detection confidence but '
            'also the load on the target.'
        ),
    ),
    click.option(
        '--resource-payload-sizes', 'resource_payload_sizes',
        metavar='BYTES', default=None,
        help=(
            'Comma-separated list of payload sizes in bytes for the large-payload '
            'acceptance test (e.g. 1048576,10485760). '
            'Defaults to 1MB and 10MB when omitted.'
        ),
    ),
    click.option(
        '--resource-json-depth', 'resource_json_depth',
        type=int, default=None, metavar='N',
        help=(
            'Maximum JSON nesting depth to probe in the deep-nesting test '
            '(default: 1000). A deeply nested JSON body that causes a '
            '5xx or timeout indicates the target has no recursion guard.'
        ),
    ),
]


def resource_options(func):
    """Attach Resource Consumption Module_Specific_Options to ``func``."""
    for option in reversed(RESOURCE_OPTIONS):
        func = option(func)
    return func


def apply_resource_options(res_cfg, opts: dict) -> None:
    """Mutate a ``ResourceTestingConfig`` from collected option values."""
    if opts.get('resource_burst_size') is not None:
        res_cfg.burst_size = int(opts['resource_burst_size'])
    if opts.get('resource_payload_sizes'):
        res_cfg.large_payload_sizes = [
            int(s.strip())
            for s in opts['resource_payload_sizes'].split(',')
            if s.strip().isdigit()
        ]
    if opts.get('resource_json_depth') is not None:
        res_cfg.json_depth_limit = int(opts['resource_json_depth'])


# ---------------------------------------------------------------------------
# Security Misconfiguration Module_Specific_Options (OWASP API8).
# ---------------------------------------------------------------------------

SECURITY_MISCONFIG_OPTIONS = [
    click.option(
        '--misconfig-required-headers', 'misconfig_required_headers',
        multiple=True, metavar='HEADER',
        help=(
            'HTTP response header name that must be present on every endpoint '
            '(repeatable). When absent the module emits MISSING_SECURITY_HEADERS. '
            'Replaces the built-in list when any value is supplied. '
            'Built-in defaults: Strict-Transport-Security, X-Content-Type-Options, '
            'X-Frame-Options, Content-Security-Policy.'
        ),
    ),
]


def security_misconfig_options(func):
    """Attach Security Misconfiguration Module_Specific_Options to ``func``."""
    for option in reversed(SECURITY_MISCONFIG_OPTIONS):
        func = option(func)
    return func


def apply_security_misconfig_options(misconfig_cfg, opts: dict) -> None:
    """Mutate a ``SecurityMisconfigConfig`` from collected option values."""
    if opts.get('misconfig_required_headers'):
        misconfig_cfg.required_headers = list(opts['misconfig_required_headers'])


# ---------------------------------------------------------------------------
# Inventory Management Module_Specific_Options (OWASP API9).
# ---------------------------------------------------------------------------

INVENTORY_OPTIONS = [
    click.option(
        '--inventory-detect-deprecated/--no-inventory-detect-deprecated',
        'inventory_detect_deprecated',
        default=True, show_default=True,
        help=(
            'Enable (default) or disable detection of deprecated API versions. '
            'When enabled, API versions flagged as deprecated by the version '
            'fuzzer emit DEPRECATED_API_VERSION findings.'
        ),
    ),
]


def inventory_options(func):
    """Attach Inventory Management Module_Specific_Options to ``func``."""
    for option in reversed(INVENTORY_OPTIONS):
        func = option(func)
    return func


def apply_inventory_options(inv_cfg, opts: dict) -> None:
    """Mutate an ``InventoryConfig`` from collected option values."""
    if 'inventory_detect_deprecated' in opts:
        inv_cfg.detect_deprecated = bool(opts['inventory_detect_deprecated'])


# ---------------------------------------------------------------------------
# Unsafe Consumption Module_Specific_Options (OWASP API10).
# Exposes the three new detector knobs introduced in the API10 hardening pass:
#   --unsafe-upstream-indicators  : custom upstream-indicator keywords
#   --unsafe-payloads             : custom malformed payloads to inject
#   --unsafe-check-redirects      : toggle the blind-redirect detector
#   --unsafe-redirect-url         : target URL for redirect probes
#   --no-unsafe-cleartext         : disable the cleartext-channel detector
# ---------------------------------------------------------------------------

UNSAFE_CONSUMPTION_OPTIONS = [
    click.option(
        '--unsafe-upstream-indicators', 'unsafe_upstream_indicators',
        multiple=True, metavar='KEYWORD',
        help=(
            'Keyword used to identify upstream-sourced endpoints (repeatable). '
            'Matched against the endpoint URL, response body, and response headers '
            '(case-insensitive). Replaces the built-in list when any value is '
            'supplied. Built-in defaults: proxy, upstream, external, aggregate.'
        ),
    ),
    click.option(
        '--unsafe-payloads', 'unsafe_payloads',
        multiple=True, metavar='PAYLOAD',
        help=(
            'Malformed payload to inject into upstream-sourced endpoints '
            '(repeatable). Verbatim reflection of any payload in the response '
            'triggers an UNSAFE_UPSTREAM_DATA finding. Replaces the built-in '
            'payload list when any value is supplied.'
        ),
    ),
    click.option(
        '--unsafe-check-redirects/--no-unsafe-check-redirects',
        'unsafe_check_redirects',
        default=True, show_default=True,
        help=(
            'Enable (default) or disable the blind-redirect-following detector. '
            'When enabled, a synthetic redirect URL is injected into URL-carrying '
            'query parameters to detect whether the API follows redirects without '
            'validating the destination (OWASP API10 Scenario #2).'
        ),
    ),
    click.option(
        '--unsafe-redirect-url', 'unsafe_redirect_url',
        metavar='URL', default=None,
        help=(
            'URL injected as a redirect target for the blind-redirect probe. '
            'In production scans point this at an OOB callback listener '
            '(e.g. Burp Collaborator, Interactsh). '
            'Defaults to http://169.254.169.254/latest/meta-data/ when omitted.'
        ),
    ),
    click.option(
        '--unsafe-check-cleartext/--no-unsafe-check-cleartext',
        'unsafe_check_cleartext',
        default=True, show_default=True,
        help=(
            'Enable (default) or disable the cleartext-upstream-channel detector. '
            'When enabled, endpoints whose URL uses http:// are flagged as '
            'UNSAFE_CLEARTEXT_UPSTREAM (OWASP API10 vector 3).'
        ),
    ),
]


def unsafe_consumption_options(func):
    """Attach Unsafe Consumption Module_Specific_Options to ``func``."""
    for option in reversed(UNSAFE_CONSUMPTION_OPTIONS):
        func = option(func)
    return func


def apply_unsafe_consumption_options(unsafe_cfg, opts: dict) -> None:
    """Mutate an ``UnsafeConsumptionConfig`` from collected option values.

    Args:
        unsafe_cfg: The ``UnsafeConsumptionConfig`` instance to mutate.
        opts: The collected Click option values (keyed by option dest name).
    """
    # --unsafe-upstream-indicators (multiple=True) → replaces built-in list
    # when at least one value is supplied so the default is preserved when the
    # flag is omitted entirely.
    if opts.get('unsafe_upstream_indicators'):
        unsafe_cfg.upstream_indicators = list(opts['unsafe_upstream_indicators'])

    # --unsafe-payloads (multiple=True) → replaces built-in payload list.
    if opts.get('unsafe_payloads'):
        unsafe_cfg.malformed_payloads = list(opts['unsafe_payloads'])

    # --unsafe-check-redirects / --no-unsafe-check-redirects
    # Click always populates the dest for boolean flags; only apply when the
    # value differs from the dataclass default (True) so an explicit
    # --no-unsafe-check-redirects is honoured while an omitted flag is a no-op.
    if 'unsafe_check_redirects' in opts:
        unsafe_cfg.check_redirects = bool(opts['unsafe_check_redirects'])

    # --unsafe-redirect-url → override the default IMDS probe URL.
    if opts.get('unsafe_redirect_url'):
        unsafe_cfg.redirect_test_url = opts['unsafe_redirect_url']

    # --unsafe-check-cleartext / --no-unsafe-check-cleartext
    if 'unsafe_check_cleartext' in opts:
        unsafe_cfg.check_cleartext_upstream = bool(opts['unsafe_check_cleartext'])


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
    # --- Advanced / Expert level attack options (NEW) ---------------------
    click.option('--otp-endpoint', 'otp_endpoint', metavar='URL', default=None,
                 help='OTP/MFA verification endpoint URL for brute-force and race-condition '
                      'probes (e.g. /api/v1/auth/otp/verify). Requires --allow-aggressive-auth.'),
    click.option('--otp-digits', 'otp_digits', type=int, default=None,
                 help='Number of digits in the OTP code space (4 or 6, default 6). '
                      'A 4-digit OTP has 10,000 combinations; 6 digits: 1,000,000.'),
    click.option('--otp-field', 'otp_field', metavar='FIELD', default=None,
                 help='JSON body field name carrying the OTP code (default: otp).'),
    click.option('--otp-session-field', 'otp_session_field', metavar='FIELD', default=None,
                 help='JSON body field name carrying the provisional session token (default: session_token).'),
    click.option('--otp-session-token', 'otp_session_token', metavar='TOKEN', default=None,
                 help='Provisional session/transaction token obtained before the OTP step. '
                      'Required for OTP brute-force and OTP race probes.'),
    click.option('--otp-race-concurrency', 'otp_race_concurrency', type=int, default=None,
                 help='Number of concurrent OTP requests for the race-condition probe (default: 50).'),
    click.option('--users-wordlist', 'users_wordlist', metavar='PATH', default=None,
                 help='Path to a newline-separated file of usernames/emails for the '
                      'password-spray probe. Requires --spray-password.'),
    click.option('--spray-password', 'spray_password', metavar='PASSWORD', default=None,
                 help='Single password to spray across all usernames in --users-wordlist. '
                      'Requires --allow-aggressive-auth.'),
    click.option('--spray-batch-size', 'spray_batch_size', type=int, default=None,
                 help='Maximum number of users in one spray batch (default: 50).'),
    click.option('--login-username-field', 'login_username_field', metavar='FIELD', default=None,
                 help='JSON body field name for the username in login requests (default: username).'),
    click.option('--login-password-field', 'login_password_field', metavar='FIELD', default=None,
                 help='JSON body field name for the password in login requests (default: password).'),
    click.option('--ip-rotation-burst', 'ip_rotation_burst', type=int, default=None,
                 help='Number of requests per IP-header rotation burst (default: 15). '
                      'Tests whether rate limiting trusts X-Forwarded-For and similar headers.'),
    click.option('--extra-ip-headers', 'extra_ip_headers', multiple=True, metavar='HEADER',
                 help='Additional IP-origin header name(s) to inject during the rotation probe '
                      '(repeatable). Merged with the built-in list.'),
    click.option('--timing-samples', 'timing_samples', type=int, default=None,
                 help='Number of response-time samples per username for the timing oracle '
                      '(default: 10). Higher values reduce noise.'),
    click.option('--timing-threshold', 'timing_threshold', type=float, default=None,
                 help='Minimum response-time delta (seconds) to classify as a timing leak '
                      '(default: 0.05 = 50ms).'),
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

    # Advanced / Expert attack options (Level 2, 3 & Expert probes).
    # Each is only applied when the CLI flag is explicitly supplied so all
    # safe defaults in AuthTestingConfig are preserved for omitted flags.
    if opts.get('otp_endpoint'):
        auth_cfg.otp_endpoint = opts['otp_endpoint']
    if opts.get('otp_digits') is not None:
        auth_cfg.otp_digits = opts['otp_digits']
    if opts.get('otp_field'):
        auth_cfg.otp_field = opts['otp_field']
    if opts.get('otp_session_field'):
        auth_cfg.otp_session_field = opts['otp_session_field']
    if opts.get('otp_session_token'):
        auth_cfg.otp_session_token = opts['otp_session_token']
    if opts.get('otp_race_concurrency') is not None:
        auth_cfg.otp_race_concurrency = opts['otp_race_concurrency']
    if opts.get('users_wordlist'):
        auth_cfg.users_wordlist = opts['users_wordlist']
    if opts.get('spray_password'):
        auth_cfg.spray_password = opts['spray_password']
    if opts.get('spray_batch_size') is not None:
        auth_cfg.spray_batch_size = opts['spray_batch_size']
    if opts.get('login_username_field'):
        auth_cfg.login_username_field = opts['login_username_field']
    if opts.get('login_password_field'):
        auth_cfg.login_password_field = opts['login_password_field']
    if opts.get('ip_rotation_burst') is not None:
        auth_cfg.ip_rotation_burst = opts['ip_rotation_burst']
    if opts.get('extra_ip_headers'):
        auth_cfg.extra_ip_headers = list(opts['extra_ip_headers'])
    if opts.get('timing_samples') is not None:
        auth_cfg.timing_samples = opts['timing_samples']
    if opts.get('timing_threshold') is not None:
        auth_cfg.timing_threshold = opts['timing_threshold']


# ---------------------------------------------------------------------------
# SSRF Module_Specific_Options (Requirement 9.1). Declares all six CLI options
# for the ``owasp ssrf`` subcommand. Do NOT import SSRFConfig here — the
# applier mutates via attribute assignment only to avoid circular imports.
# ---------------------------------------------------------------------------

SSRF_OPTIONS = [
    click.option('--openapi', 'openapi', multiple=True, type=click.Path(),
                 help='OpenAPI/Swagger document (JSON or YAML) that seeds the SSRF scan '
                      'with the API\'s known endpoints. Repeatable. Enables the SSRF module '
                      'to probe all spec-declared endpoints without running full discovery.'),
    click.option('--postman', 'postman', multiple=True, type=click.Path(),
                 help='Postman collection (JSON) that seeds the SSRF scan with known '
                      'endpoints. Repeatable. Merged with --openapi when both are supplied.'),
    click.option('--ssrf-callback-url', 'ssrf_callback_url', metavar='URL', default=None,
                 help='OOB callback URL for blind SSRF detection. '
                      'Inject this URL as a payload and check your listener '
                      '(e.g. Burp Collaborator, Interactsh) for incoming requests.'),
    click.option('--ssrf-internal-targets', 'ssrf_internal_targets',
                 multiple=True, metavar='HOST',
                 help='Additional internal host/IP to probe (repeatable). '
                      'Merged with the built-in cloud metadata target list, no duplicates.'),
    click.option('--ssrf-schemes', 'ssrf_schemes',
                 multiple=True, metavar='SCHEME',
                 help='Additional URL scheme to test (repeatable), e.g. gopher://. '
                      'Replaces the built-in scheme list when provided.'),
    click.option('--ssrf-scan-ports', 'ssrf_scan_ports', metavar='PORTS', default=None,
                 help='Comma-separated list of ports to probe via internal SSRF '
                      '(e.g. 22,80,443,8080). Requires --allow-aggressive-ssrf.'),
    click.option('--ssrf-body-injection', 'ssrf_body_injection', is_flag=True, default=False,
                 help='Enable SSRF payload injection into JSON request body fields on '
                      'POST/PUT/PATCH endpoints (off by default).'),
    click.option('--ssrf-body-methods', 'ssrf_body_methods', metavar='METHODS', default=None,
                 help='Comma-separated HTTP methods to use for body injection probes '
                      '(e.g. POST,PUT,PATCH). When set, body injection is attempted '
                      'with each method regardless of what the discovery engine recorded '
                      'for the endpoint. Requires --ssrf-body-injection.'),
    click.option('--ssrf-body-field', 'ssrf_body_field', multiple=True, metavar='FIELD',
                 help='Explicit JSON body field name to always inject SSRF payloads into '
                      '(repeatable, e.g. --ssrf-body-field imageUrl --ssrf-body-field callback). '
                      'Merged with auto-detected fields; does not replace them.'),
    click.option('--burp-xml', 'burp_xml', metavar='PATH', default=None,
                 help='Path to a Burp Suite XML Proxy-History export file. '
                      'Requests are replayed in Full_Replay_Mode: original headers and '
                      'cookies are preserved; only URL-like body field values are replaced '
                      'by SSRF payloads.'),
    click.option('--har', 'har', metavar='PATH', default=None,
                 help='Path to a HAR (HTTP Archive) JSON file exported from Burp Suite, '
                      'Caido, Hetty, Chrome DevTools, or Firefox. '
                      'Requests are replayed in Full_Replay_Mode.'),
    click.option('--allow-aggressive-ssrf', 'allow_aggressive_ssrf', is_flag=True, default=False,
                 help='Aggressive_Opt_In: authorize the SSRF module to issue high-impact '
                      'probes (internal port scanning, redirect-chain testing). '
                      'Off by default; when omitted these probes are skipped.'),
    click.option('--ssrf-require-signature', 'ssrf_require_signature', is_flag=True, default=False,
                 help='Only emit a finding when a known internal-target signature (e.g. '
                      '"iam/security-credentials", "ami-id") is matched in the response body. '
                      'Suppresses plain 2xx findings without body evidence. '
                      'Useful to eliminate false positives on APIs that return 200 for any URL.'),
    click.option('--ssrf-match-status', 'ssrf_match_status', metavar='CODES', default=None,
                 help='Comma-separated HTTP status codes (or ranges) that count as a '
                      '"success hit" for SSRF detection instead of the default 2xx range. '
                      'Example: --ssrf-match-status 200 restricts to exact 200 only. '
                      'Example: --ssrf-match-status 200,201,301 includes redirects. '
                      'Ignored when --ssrf-require-signature is set (signature match always wins).'),
]


def ssrf_options(func):
    """Attach the SSRF Module_Specific_Options to ``func`` (Requirement 9.1).

    Applies ``SSRF_OPTIONS`` in REVERSE order so that, once Click stacks the
    decorators, the options appear in declaration order on the resulting command.
    """
    for option in reversed(SSRF_OPTIONS):
        func = option(func)
    return func


def apply_ssrf_options(ssrf_cfg, opts: dict) -> None:
    """Mutate a ``SSRFConfig`` from collected option values (Requirement 9.2).

    Maps each SSRF CLI option to the corresponding ``SSRFConfig`` field via
    attribute assignment only — SSRFConfig is NOT imported here to avoid
    circular imports. When none of the options are provided the function is a
    no-op and all ``SSRFConfig`` defaults are preserved (Requirement 9.9).

    Emits a non-terminating stderr warning when ``--ssrf-scan-ports`` is
    given without ``--allow-aggressive-ssrf`` (Requirement 9.10).

    Args:
        ssrf_cfg: The ``SSRFConfig`` instance to mutate in place.
        opts: The collected Click option values (keyed by option dest name).
    """
    # --ssrf-callback-url → ssrf_cfg.callback_url (Requirement 9.3)
    if opts.get('ssrf_callback_url'):
        ssrf_cfg.callback_url = opts['ssrf_callback_url']

    # --ssrf-internal-targets (multiple=True, yields tuple) → merge into
    # ssrf_cfg.additional_internal_targets with no duplicates (Requirement 9.4)
    if opts.get('ssrf_internal_targets'):
        incoming = list(opts['ssrf_internal_targets'])
        existing = list(ssrf_cfg.additional_internal_targets)
        seen = set(existing)
        for host in incoming:
            if host not in seen:
                existing.append(host)
                seen.add(host)
        ssrf_cfg.additional_internal_targets = existing

    # --ssrf-schemes (multiple=True, yields tuple) → set additional_schemes
    # (Requirement 9.5)
    if opts.get('ssrf_schemes'):
        ssrf_cfg.additional_schemes = list(opts['ssrf_schemes'])

    # --ssrf-scan-ports → parse comma-separated integers, set scan_ports
    # (Requirement 9.6)
    if opts.get('ssrf_scan_ports'):
        ssrf_cfg.scan_ports = [
            int(p.strip())
            for p in opts['ssrf_scan_ports'].split(',')
            if p.strip()
        ]

    # --ssrf-body-injection flag → enable body injection (Requirement 9.7)
    if opts.get('ssrf_body_injection'):
        ssrf_cfg.body_injection = True

    # --ssrf-body-methods → parse comma-separated methods, set body_injection_methods.
    # Implicitly enables body_injection so the operator doesn't have to pass both flags.
    if opts.get('ssrf_body_methods'):
        methods = [
            m.strip().upper()
            for m in opts['ssrf_body_methods'].split(',')
            if m.strip()
        ]
        ssrf_cfg.body_injection_methods = methods
        ssrf_cfg.body_injection = True  # --ssrf-body-methods implies body injection
        if not opts.get('ssrf_body_injection'):
            click.echo(
                "Info: --ssrf-body-methods implies --ssrf-body-injection; "
                "body injection enabled automatically.",
                err=True,
            )

    # --ssrf-body-field (multiple=True) → merge into extra_body_fields
    if opts.get('ssrf_body_field'):
        ssrf_cfg.extra_body_fields = list(opts['ssrf_body_field'])

    # --burp-xml PATH → burp_xml_path
    if opts.get('burp_xml'):
        ssrf_cfg.burp_xml_path = opts['burp_xml']
        ssrf_cfg.body_injection = True  # import sources imply body injection

    # --har PATH → har_path
    if opts.get('har'):
        ssrf_cfg.har_path = opts['har']
        ssrf_cfg.body_injection = True  # import sources imply body injection

    # --allow-aggressive-ssrf flag → enable port scanning gate (Requirement 9.8)
    if opts.get('allow_aggressive_ssrf'):
        ssrf_cfg.allow_port_scan = True

    # --ssrf-require-signature → only emit findings when a known signature is matched
    if opts.get('ssrf_require_signature'):
        ssrf_cfg.require_signature = True

    # --ssrf-match-status → parse comma-separated status codes / ranges into
    # the list of codes that count as a success hit for SSRF detection.
    if opts.get('ssrf_match_status'):
        codes: list = []
        for part in opts['ssrf_match_status'].split(','):
            part = part.strip()
            if '-' in part and not part.startswith('http'):
                # range like 200-204
                lo, hi = part.split('-', 1)
                codes.extend(range(int(lo.strip()), int(hi.strip()) + 1))
            elif part.isdigit():
                codes.append(int(part))
        if codes:
            ssrf_cfg.success_status_codes = codes

    # Req 9.10: warn when --ssrf-scan-ports is supplied without
    # --allow-aggressive-ssrf so the operator knows the ports list has no effect.
    if opts.get('ssrf_scan_ports') and not opts.get('allow_aggressive_ssrf'):
        click.echo(
            "Warning: --ssrf-scan-ports has no effect without --allow-aggressive-ssrf.",
            err=True,
        )
