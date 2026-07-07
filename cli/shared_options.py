"""Shared_Option_Mechanism for the restructured APILeak CLI.

This module declares every Transversal_Option exactly once (design §2) and
exposes the ``transversal_options`` decorator that attaches the whole set to a
command. The option definitions (names, short flags, types, defaults, help,
``multiple``/``is_flag``, callbacks) are copied verbatim from the current
``full`` command in ``apileaks.py`` so behavior is byte-identical, with a single
deliberate, requirement-driven exception: the ``--fail-on`` default is ``high``
(Requirement 5.6 / design D5), whereas the legacy ``full`` default was
``critical``.

The discovery-scope options (``--depth``, ``--recursive``, ``--max-requests``,
``--extensions``, ``--recursion-status``, ``--recursion-type``) ride the same
shared list so a single-module subcommand still runs discovery uniformly
(design D4).

Requirements: 3.1, 3.2, 3.3, 3.4, 5.6, 11.2

This module contains no OWASP detection logic; it only declares CLI options.
"""

import click

# ---------------------------------------------------------------------------
# Validation callbacks (copied verbatim from apileaks.py so validation behavior
# on every command that accepts Transversal_Options is byte-identical to the
# legacy ``full`` command).
# ---------------------------------------------------------------------------

def _validate_depth(ctx, param, value):
    """Click callback: reject a negative --depth, naming the offending value.

    Click's ``type=int`` already rejects non-integers; this guards the lower
    bound so no Endpoint_Discovery runs on an invalid recursion depth
    (Requirement 17.9).
    """
    if value is not None and value < 0:
        raise click.BadParameter(f"--depth must be >= 0 (got {value})")
    return value


def _validate_max_requests(ctx, param, value):
    """Click callback: reject a --max-requests below 1, naming the value.

    ``default=None`` means "no budget"; any supplied value must be a positive
    request budget so discovery cannot be configured with an impossible limit
    (Requirement 18.7).
    """
    if value is not None and value < 1:
        raise click.BadParameter(f"--max-requests must be >= 1 (got {value})")
    return value


def _validate_concurrency(ctx, param, value):
    """Click callback: reject a --concurrency below 1, naming the value.

    ``default=None`` falls back to the built-in concurrency of 50; any supplied
    value must allow at least one in-flight request (Requirement 20.5).
    """
    if value is not None and value < 1:
        raise click.BadParameter(f"--concurrency must be >= 1 (got {value})")
    return value


def _validate_timeout(ctx, param, value):
    """Click callback: reject a non-positive --timeout, naming the value.

    The Request_Timeout is a per-request upper bound in seconds and must be a
    positive number; ``default=None`` falls back to the config default. Rejecting
    here guarantees no Endpoint_Discovery runs on an invalid timeout
    (Requirement 28.6).
    """
    if value is not None and value <= 0:
        raise click.BadParameter(f"--timeout must be a positive number of seconds (got {value})")
    return value


def _validate_retries(ctx, param, value):
    """Click callback: reject a negative --retries, naming the value.

    Click's ``type=int`` already rejects non-integers; this guards the lower
    bound so the Retry_Limit is never negative. ``default=None`` falls back to
    the config default. Rejecting here guarantees no Endpoint_Discovery runs on
    an invalid retry limit (Requirement 28.7).
    """
    if value is not None and value < 0:
        raise click.BadParameter(f"--retries must be a non-negative integer (got {value})")
    return value


# ---------------------------------------------------------------------------
# Transversal_Option declarations (single source of truth). Each entry is a
# ``click.option`` decorator object; ``transversal_options`` applies them all.
# Option definitions are copied verbatim from the legacy ``full`` command,
# except ``--fail-on`` whose default is intentionally ``high`` (Requirement 5.6).
# ---------------------------------------------------------------------------

TRANSVERSAL_OPTIONS = [
    # --- target -----------------------------------------------------------
    click.option('--target', '-t', help='Target URL to scan (overrides config)'),
    click.option('--target-file', 'target_file', default=None,
                 type=click.Path(exists=True, readable=True,
                                 file_okay=True, dir_okay=False),
                 metavar='FILE',
                 help='Plain-text file with one target URL per line (# comments and blank '
                      'lines are skipped). Lines without a scheme are auto-prefixed with '
                      'https://. When supplied, --target is optional; both can be given '
                      'together (--target becomes an implicit first entry).'),
    click.option('--max-hosts', 'max_hosts', type=int, default=None, metavar='N',
                 help='Maximum number of hosts to scan from --target-file (scans the first N).'),
    # --- output / logging -------------------------------------------------
    click.option('--output', '-o', help='Output filename for reports (files will be saved in reports/ directory)'),
    click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']),
                 default='WARNING', help='Logging level'),
    click.option('--log-file', help='Log file path (optional)'),
    click.option('--json-logs', is_flag=True, help='Output logs in JSON format'),
    # --- rate limit -------------------------------------------------------
    click.option('--rate-limit', type=int, help='Requests per second limit'),
    # --- timeout / retries / concurrency (validated) ----------------------
    click.option('--timeout', 'timeout', type=float, default=None, callback=_validate_timeout,
                 help='Per-request timeout in seconds applied to every discovery request '
                      '(must be > 0; default: 10).'),
    click.option('--retries', 'retries', type=int, default=None, callback=_validate_retries,
                 help='Number of automatic retries for each failed discovery request '
                      '(must be >= 0; default: 2).'),
    click.option('--concurrency', 'concurrency', type=int, default=None, callback=_validate_concurrency,
                 help='Max concurrent in-flight discovery requests (default: 50).'),
    # --- safe mode --------------------------------------------------------
    click.option('--safe-mode', is_flag=True, help='Enable Safe Mode: skip state-changing probes (POST/PUT/PATCH/DELETE) and restrict requests to safe methods (non-destructive scan)'),
    # --- auth context -----------------------------------------------------
    click.option('--jwt', help='JWT token to use for authentication'),
    click.option('--auth-context', 'auth_context', multiple=True, metavar='user:token[:privilege]',
                 help='Authenticated identity supplied as user:token with an optional '
                      ':privilege suffix. Repeatable: pass once per user to run multi-user '
                      'authorization tests (e.g. --auth-context alice:eyJ...:1 '
                      '--auth-context bob:eyJ...:1).'),
    # --- proxy ------------------------------------------------------------
    click.option('--proxy', help='Route all HTTP traffic through an intercepting proxy (e.g. Burp/Caido/Hetty: http://127.0.0.1:8080). TLS verification is disabled by default for proxied HTTPS targets.'),
    click.option('--proxy-verify-ssl', 'proxy_verify_ssl', is_flag=True, help='Keep TLS certificate verification enabled when using --proxy (use after installing the proxy CA).'),
    # --- CI options -------------------------------------------------------
    click.option('--ci-mode', is_flag=True, help='Enable CI/CD mode with appropriate exit codes and artifact generation'),
    click.option('--fail-on', type=click.Choice(['critical', 'high', 'medium', 'low']),
                 default='high', help='Fail CI pipeline on findings of this severity or higher'),
    click.option('--sarif', is_flag=True, help='Generate a SARIF 2.1.0 report (for code scanning / CI integration)'),
    click.option('--baseline', type=click.Path(), help='Path to a baseline JSON report. Findings matching the baseline by (category, endpoint, method) are treated as known; only new findings drive the CI severity gate. A missing path treats every finding as new.'),
    # --- user-agent trio (mutually exclusive) -----------------------------
    click.option('--user-agent-random', is_flag=True, help='Use random User-Agent headers to evade WAF'),
    click.option('--user-agent-custom', help='Custom User-Agent string to use for all requests'),
    click.option('--user-agent-file', help='File containing User-Agent strings (one per line) for rotation'),
    # --- discovery scope (design D4: available to module subcommands too) --
    click.option('--depth', 'depth', type=int, default=None, callback=_validate_depth,
                 help='Max recursion depth for discovery (0 = no recursion). '
                      'Overrides APILEAK_MAX_DEPTH and the config default (3).'),
    click.option('--recursive/--no-recursive', 'recursive', default=None,
                 help='Enable or disable recursive discovery (default: enabled).'),
    click.option('--max-requests', 'max_requests', type=int, default=None, callback=_validate_max_requests,
                 help='Global request budget for discovery (default: unbounded).'),
    click.option('--extensions', '-x', 'extensions', multiple=True, metavar='EXT',
                 help='File extensions to append to each wordlist entry (comma-separated, repeatable). '
                      'e.g. -x json,php or -x .json -x .php. Leading dots are optional.'),
    click.option('--recursion-status', 'recursion_status', metavar='CLASSES', default=None,
                 help='Restrict recursion to endpoints whose status class is in CLASSES: a '
                      "comma-separated list of status classes like '2xx,3xx'. Only narrows the "
                      'default VALID/AUTH_REQUIRED recursion; never relaxes it.'),
    click.option('--recursion-type', 'recursion_type', metavar='TYPES', default=None,
                 help='Restrict recursion to endpoints whose type is in TYPES: a comma-separated '
                      "list of endpoint types like 'admin,api_version'. Only narrows the default "
                      'recursion; never relaxes it.'),
]


def transversal_options(func):
    """Attach every Transversal_Option to ``func`` (Shared_Option_Mechanism).

    Applies ``TRANSVERSAL_OPTIONS`` in REVERSE order so that, once Click stacks
    the decorators, the options appear in declaration order on the resulting
    command. Declaring the list once and applying it everywhere makes the
    transversal-option uniformity invariant (Property 3) hold by construction.
    """
    for option in reversed(TRANSVERSAL_OPTIONS):
        func = option(func)
    return func
