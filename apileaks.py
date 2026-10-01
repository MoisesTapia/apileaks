#!/usr/bin/env python3
"""
APILeak Main Entry Point
Enterprise-grade API fuzzing and OWASP testing tool
"""

import click

from cli.commands.discovery_cmds import (
    DEFAULT_PARAMETER_WORDLIST,  # noqa: F401  re-exported (public surface / tests)
    ScanScopeError,  # noqa: F401  re-exported (public surface / tests)
    _build_discovery_progress,  # noqa: F401  re-exported (public surface / tests)
    _discover_endpoints_for_triage,  # noqa: F401  re-exported (public surface / tests)
    _read_wordlist_entries,  # noqa: F401  re-exported (public surface / tests)
    _resolve_par_candidates,  # noqa: F401  re-exported (public surface / tests)
    _run_dir_triage,  # noqa: F401  re-exported (public surface / tests)
    _run_scoped_owasp_scan,  # noqa: F401  re-exported (public surface / tests)
    _run_targeted_follow_up_scan,  # noqa: F401  re-exported (public surface / tests)
    brute_cmd,
    dir,
    par,
    run_interactive_triage,  # noqa: F401  re-exported (public surface / tests)
    select_scope_records,  # noqa: F401  re-exported (public surface / tests)
)
from cli.commands.jwt_cmds import jwt
from cli.commands.replay_cmds import replay_cmd
from cli.commands.scan_cmds import (
    _emit_deprecation_notice,  # noqa: F401  re-exported (public surface / tests)
    full,
    main,
    owasp,
    scan,  # noqa: F401  re-exported (public surface / tests)
)
from cli.commands.wordlist_cmds import wordlist_group
from cli.config_builders import (
    _load_spec_schema,  # noqa: F401  re-exported (public surface / tests)
    create_default_config,  # noqa: F401  re-exported (public surface / tests)
    create_enhanced_config,  # noqa: F401  re-exported (public surface / tests)
    resolve_max_depth,  # noqa: F401  re-exported (public surface / tests)
)
from cli.output import (
    print_banner,
)
from cli.parsers import (
    parse_auth_context_option,  # noqa: F401  re-exported (public surface / tests)
    parse_basic_auth,  # noqa: F401  re-exported (public surface / tests)
    parse_header_options,  # noqa: F401  re-exported (public surface / tests)
)
from cli.runner import (
    SEVERITY_LADDER,  # noqa: F401  re-exported (public surface / tests)
    _echo_discovery_control_status,  # noqa: F401  re-exported (public surface / tests)
    evaluate_severity_gate,  # noqa: F401  re-exported (public surface / tests)
)
from cli.shared_options import (
    _validate_ca_bundle,  # noqa: F401  re-exported (public surface / tests)
    _validate_client_cert,  # noqa: F401  re-exported (public surface / tests)
    _validate_concurrency,  # noqa: F401  re-exported: tests patch via apileaks namespace
    _validate_max_requests,  # noqa: F401  re-exported
    _validate_resolve,  # noqa: F401  re-exported (public surface / tests)
    _validate_retries,  # noqa: F401  re-exported
    _validate_timeout,  # noqa: F401  re-exported
)
from core import ConfigurationManager  # noqa: F401  re-exported (public surface / tests)
from utils.jwt_attack_engine import JWTAttackEngine  # noqa: F401  re-exported (public surface)

# ---------------------------------------------------------------------------
# Validation callbacks for --depth, --max-requests, --concurrency,
# --timeout, --retries are imported from cli.shared_options (single source of
# truth — BUG-013 fix). They are used directly by the Click option decorators
# on the ``dir`` and ``par`` commands below.
# ---------------------------------------------------------------------------


# Default parameter wordlist used by ``par`` when no ``--wordlist`` is supplied
# (Requirement 10.4).


# ---------------------------------------------------------------------------
# Shared CLI option decorator stacks
# ---------------------------------------------------------------------------
#
# These reusable Click decorator stacks group the transversal request-context,
# resilience, concurrency, TLS-transport, matcher/filter, and machine-output
# options so they can be applied identically to multiple commands (starting
# with ``dir``; ``par`` gains parity in a later task) without duplicating the
# option names, help text, defaults, or validator callbacks.
#
# Each stack applies its options bottom-up so that when it is used as a single
# decorator the resulting option display/registration order matches the order
# in which the options are written here (top to bottom).


@click.group()
@click.option("--no-banner", is_flag=True, help="Suppress banner output")
@click.pass_context
def cli(ctx, no_banner):
    """APILeak v0.3.0 - Enterprise API Fuzzing Tool


    \b
    Performs comprehensive security testing of APIs including:
    • Traditional endpoint and parameter fuzzing
    • OWASP API Security Top 10 testing
    • Advanced vulnerability detection with framework detection
    • Version fuzzing and subdomain discovery
    • WAF detection and evasion techniques
    • Advanced payload encoding and obfuscation
    • CORS analysis and security headers testing
    • Multi-format reporting with CI/CD integration
    • JWT token manipulation and analysis

    \b
    Discovery & fuzzing:
      python apileaks.py dir --target URL              # Directory/endpoint fuzzing
      python apileaks.py par --target URL              # Parameter fuzzing

    \b
    OWASP API Security Top 10:
      python apileaks.py owasp                          # List every OWASP module
      python apileaks.py owasp bola --target URL        # Run a single module (isolated)
      python apileaks.py owasp auth --target URL        # Run only the Auth module
      python apileaks.py scan --target URL              # Orchestrated scan (all modules)
      python apileaks.py scan --target URL --modules bola,auth   # Selected modules

    \b
    Advanced examples:
      python apileaks.py scan --target URL --enable-advanced
      python apileaks.py scan --target URL --detect-framework --fuzz-versions
      python apileaks.py scan --target URL --user-agent-random --enable-waf-evasion

    \b
    CI/CD integration (severity gate, SARIF, baseline):
      python apileaks.py scan --target URL --ci-mode --fail-on high --sarif

    \b
    JWT utilities (manual toolkit):
      python apileaks.py jwt decode TOKEN
      python apileaks.py jwt encode '{"sub":"user"}' --secret key
      python apileaks.py jwt --help                     # Full JWT toolkit listing
    """
    ctx.ensure_object(dict)
    ctx.obj["no_banner"] = no_banner

    # Print banner unless suppressed or showing help
    if not no_banner and ctx.info_name != "help":
        print_banner()


# Register command families extracted into cli/commands/ (monolith decomposition).
cli.add_command(jwt)
cli.add_command(wordlist_group)
cli.add_command(dir)
cli.add_command(par)
cli.add_command(brute_cmd)
cli.add_command(scan)
cli.add_command(owasp)
cli.add_command(full)
cli.add_command(main)
cli.add_command(replay_cmd)


# ---------------------------------------------------------------------------
# Spec-file brute-force discovery — integrated into ``dir --brute-spec``.
#
# Equivalent to ``sj brute``: sends a series of HTTP GET requests to a target
# trying well-known paths where Swagger/OpenAPI/RAML/AsyncAPI definition files
# are commonly exposed.  When a candidate returns a 2xx status whose body looks
# like a valid API specification, the result is reported and (optionally)
# auto-loaded for further use.
# ---------------------------------------------------------------------------

# Signatures that identify a response body as an API spec document.

# Default wordlist shipped with apileaks (relative to the script directory).


# Recognized non-interactive Batch_Scan_Scope selectors (Requirement 36.2): the
# four Status_Code_Class tokens and the two selectable EndpointStatus values.


# ---------------------------------------------------------------------------
# Multi-target orchestration helpers
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Shared execution core (design §6). ``_build_and_run`` centralizes the config
# assembly + dispatch that the legacy ``full`` handler performs inline,
# parameterized by the selected OWASP module set. Both the generated
# ``owasp <module>`` subcommands (task 6) and the ``scan`` orchestrator (task 7)
# call it, so a single-module run and a composed run build a byte-identical
# APILeakConfig for that module (Property 5). This function is CLI-surface only:
# it assembles config and dispatches to the UNCHANGED engine path
# (``run_enhanced_apileak`` -> ``APILeakCore``); it contains no OWASP detection
# logic.
#
# NOTE: this task only ADDS these functions; the live ``full`` command above is
# intentionally left untouched so it keeps working until the orchestrator swap
# in task 7.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Orchestrator helpers (design §5, §7): module-selection resolution and the
# deprecation notices for the ``full`` alias and hidden ``main`` command. These
# are CLI-surface only.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Orchestrator_Command surface (design §5). ``scan`` is the primary name; the
# entire legacy ``full`` option surface is preserved on it (transversal, BOLA,
# and Auth options plus --config/--modules and the discovery/spec inputs) so
# historical invocations parse byte-for-byte unchanged. ``_orchestrator_options``
# declares that surface once so ``scan`` and the ``full`` alias are guaranteed
# identical (design §5's single intentional duplication).
# ---------------------------------------------------------------------------

# Options carried by the orchestrator beyond the shared Transversal_Options and
# the BOLA / Auth Module_Specific_Options: the config/module selection plus the
# discovery-enhancement and Spec_Source inputs the legacy ``full`` accepted.


# ---------------------------------------------------------------------------
# owasp command group + dynamically generated Module_Subcommands (design §4).
#
# One first-class subcommand is generated per OWASP_MODULE_DESCRIPTORS entry,
# named character-for-character by the engine registration key. Each subcommand
# stacks the shared Transversal_Options (Shared_Option_Mechanism), the
# descriptor's own Module_Specific_Options (only when it owns any), and routes
# into the shared _build_and_run execution core with selected_keys=[desc.key]
# so exactly that one module runs.
#
# Unknown subcommand names and foreign specific options are rejected natively by
# Click (nonzero exit) — no extra code (Requirements 1.6, 2.7, 8.5). dir/par are
# never registered here (Requirement 8.5).
#
# Requirements: 1.1, 1.2, 1.3, 1.4, 1.6, 7.4, 7.5, 11.1, 11.3, 11.4
# ---------------------------------------------------------------------------


# Register exactly one generated subcommand per descriptor on the owasp group,
# then the owasp group on cli. Adding a descriptor row yields a fully wired
# subcommand automatically (Requirements 1.2, 11.1).


# ---------------------------------------------------------------------------
# JWT CLI helpers — route all attack-token generation and execution through the
# single-source-of-truth JWTAttackEngine (Requirements 14.2, 14.3) and issue
# HTTP through the shared HTTPRequestEngine (Requirement 17.1). No subcommand
# reimplements attack logic inline, and success is decided by the engine's
# JWTAttackResponseAnalyzer rather than admin/dashboard keyword presence
# (Requirement 19.2).
# ---------------------------------------------------------------------------


# JWT Command Group


# Severity ladder for CI/CD gate evaluation, ordered from highest to lowest.


# =============================================================================
# replay command
# =============================================================================


# =============================================================================
# wordlist command group
# =============================================================================


# =============================================================================
# brute command — discover exposed API specification files
# Equivalent to `sj brute`.  Reuses _run_spec_brute / _brute_spec_async from
# the dir --brute-spec implementation so there is zero logic duplication.
# =============================================================================


if __name__ == "__main__":
    cli()
