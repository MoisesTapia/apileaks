#!/usr/bin/env python3
"""
APILeak Main Entry Point
Enterprise-grade API fuzzing and OWASP testing tool
"""

import asyncio
import json
import os
import sys

import click

from cli import runner
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
from cli.commands.wordlist_cmds import wordlist_group
from cli.config_builders import (
    _collect_module_configs,
    _load_spec_schema,
    create_default_config,  # noqa: F401  re-exported (public surface / tests)
    create_enhanced_config,
    resolve_max_depth,
)
from cli.module_options import auth_options, bola_options
from cli.output import (
    _emit_module_selection_deprecation,
    _print_owasp_module_listing,
    print_banner,
)
from cli.owasp_descriptors import (
    OWASP_MODULE_DESCRIPTORS,
    OwaspModuleDescriptor,
    all_keys,
    get_descriptor,
)
from cli.parsers import (
    _require_target_or_config,
    load_user_agents_from_file,
    parse_auth_context_option,
    parse_basic_auth,  # noqa: F401  re-exported (public surface / tests)
    parse_header_options,
    parse_status_codes,
    parse_target_file,
    prepare_output_filename,
    validate_header_options,
    validate_user_agent_options,
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
    transversal_options,
)
from core import ConfigurationManager, setup_logging
from core import __version__ as APILEAK_VERSION
from core.config import load_actor_profiles, load_unauthorized_assertions
from core.logging import get_logger
from modules.fuzzing.orchestrator import normalize_extensions
from utils.discovery_scope import (
    RecursionScopeError,
    parse_recursion_scope,
)
from utils.jwt_attack_engine import JWTAttackEngine  # noqa: F401  re-exported (public surface)
from utils.spec_import import (
    SpecImportError,
)

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


def _validate_baseline_readable(baseline):
    """Fail before any request when ``--baseline`` names an unreadable file.

    Implements Requirement 5.7: when the ``--baseline`` option references a file
    that exists but is unreadable or not well-formed JSON, the run exits with a
    nonzero status, writes an error naming the baseline file, and runs no
    Severity_Gate against a partial baseline (the scan is aborted before any
    request is issued). A *missing* path is not an error — it is treated as an
    empty baseline so every finding is a New_Finding (documented ``--baseline``
    behavior), matching :meth:`utils.baseline.BaselineComparator.load`.
    """
    if not baseline:
        return
    if not os.path.exists(baseline):
        # A missing path yields an empty baseline (every finding treated as new);
        # this is documented behavior and NOT the malformed/unreadable case.
        return
    try:
        with open(baseline, encoding="utf-8") as handle:
            json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        click.echo(
            f"Error: --baseline file '{baseline}' is unreadable or malformed: {exc}",
            err=True,
        )
        sys.exit(1)


def _apply_transversal_overrides(cfg, opts, parsed_auth_contexts):
    """Apply every Transversal_Option override onto a loaded config object.

    Lifts the verbatim post-load override logic from the ``full`` handler so a
    Module_Subcommand and the Orchestrator_Command apply identical transversal
    effects on the run configuration (Requirements 3.5, 5.4). Works for both
    file-loaded and in-memory configs. Each override is applied only when its
    option is supplied so a file config's values are preserved when a flag is
    absent.

    Args:
        cfg: The loaded ``APILeakConfig`` to mutate in place.
        opts: Collected Click option values (keyed by option dest name).
        parsed_auth_contexts: The ``--auth-context`` values parsed up front into
            ``AuthContext`` objects (parsed before any request in
            ``_build_and_run``).
    """
    logger = get_logger("build_and_run")

    # --- target (CLI overrides config file) — mirrors merge_cli_overrides ---
    if opts.get("target") and hasattr(cfg, "target"):
        cfg.target.base_url = opts["target"]

    # --- rate limit — mirrors merge_cli_overrides ---
    if opts.get("rate_limit") and hasattr(cfg, "rate_limiting"):
        cfg.rate_limiting.requests_per_second = opts["rate_limit"]

    # --- jwt: historically threaded as a CLI override key ('jwt_token') that
    #     merge_cli_overrides does not consume, so it is a no-op on the run
    #     configuration. Preserved as a no-op here to avoid changing behavior;
    #     authenticated identities are supplied through --auth-context.

    # --- safe mode (CLI flag overrides config; Requirement 5.4) ---
    if opts.get("safe_mode") and hasattr(cfg, "safe_mode"):
        cfg.safe_mode = True

    # --- proxy / proxy-verify-ssl (CLI flag overrides config) ---
    if opts.get("proxy") and hasattr(cfg, "proxy"):
        cfg.proxy = opts["proxy"]
        cfg.proxy_verify_ssl = opts.get("proxy_verify_ssl", False)

    # --- SARIF report format ---
    if opts.get("sarif") and hasattr(cfg, "reporting"):
        if "sarif" not in cfg.reporting.formats:
            cfg.reporting.formats.append("sarif")

    # --- multi-user auth contexts (appended to the existing anonymous context) ---
    if parsed_auth_contexts and hasattr(cfg, "authentication"):
        cfg.authentication.contexts.extend(parsed_auth_contexts)
        logger.info(
            "Threaded multi-user auth contexts into OWASP modules",
            context_count=len(parsed_auth_contexts),
        )

    # --- discovery recursion / budget / concurrency / resilience controls ---
    fuzzing = getattr(cfg, "fuzzing", None)
    if fuzzing is not None:
        depth = opts.get("depth")
        # max_depth precedence: CLI --depth > APILEAK_MAX_DEPTH > config/default.
        # Only override when --depth is supplied or the env var is set so a file
        # config's max_depth is preserved otherwise (Requirements 17.6-17.8).
        if depth is not None:
            fuzzing.max_depth = resolve_max_depth(depth)
        elif os.getenv("APILEAK_MAX_DEPTH") is not None:
            fuzzing.max_depth = resolve_max_depth(None)
        if opts.get("recursive") is not None:
            fuzzing.recursive = opts["recursive"]
        if depth == 0:
            fuzzing.recursive = False  # depth 0 => depth-0 pass only (17.3)
        if opts.get("max_requests") is not None:
            fuzzing.max_requests = opts["max_requests"]
        if opts.get("concurrency") is not None:
            fuzzing.concurrency = opts["concurrency"]
        if opts.get("retries") is not None:
            fuzzing.retries = opts["retries"]
        # Extensions: only override when supplied so a file config's extensions
        # are preserved when the flag is absent. Values are comma-separated AND
        # repeatable: split each on commas, flatten, then normalize.
        if opts.get("extensions"):
            fuzzing.endpoints.extensions = normalize_extensions(
                [ext for value in opts["extensions"] for ext in value.split(",")]
            )
        # Recursion_Scope: only set when parsed from supplied flags so a file
        # config's scope is preserved otherwise (Requirements 34.3, 34.4).
        recursion_scope = opts.get("recursion_scope")
        if recursion_scope is not None:
            fuzzing.recursion_scope = recursion_scope

    # --- per-request timeout (target read timeout; Requirement 28.1) ---
    if opts.get("timeout") is not None and hasattr(cfg, "target"):
        cfg.target.timeout = opts["timeout"]


def _run_scan_multi_target(
    ctx, *, targets, selected_keys, descriptors, config_path=None, **opts_overrides
):
    """Run an orchestrated OWASP scan over multiple targets sequentially.

    Iterates ``targets``, calling ``_build_and_run`` for each with the target
    injected into ``opts`` and interactive triage suppressed. Prints a
    consolidated one-line-per-host result table at the end.

    Args:
        ctx:            Click context (forwarded to each ``_build_and_run`` call).
        targets:        Ordered list of target URL strings.
        selected_keys:  OWASP module keys to enable (forwarded unchanged).
        descriptors:    Module descriptor objects (forwarded unchanged).
        config_path:    Optional config file path (forwarded unchanged).
        **opts_overrides: All Click option values for the scan/full command.
    """
    _RESET = "\033[0m"
    _BOLD = "\033[1m"
    _GREEN = "\033[92m"
    _RED = "\033[91m"
    _CYAN = "\033[96m"

    total = len(targets)
    click.echo(f"\n{_BOLD}{_CYAN}Multi-target OWASP scan: {total} host(s){_RESET}\n{'─' * 60}")

    from urllib.parse import urlparse as _urlparse

    summaries = []
    for idx, t in enumerate(targets, 1):
        hostname = _urlparse(t).netloc or t
        click.echo(f"\n{_BOLD}[{idx}/{total}]{_RESET} {_CYAN}{t}{_RESET}")

        # Build per-target opts: inject the resolved target, suppress interactive.
        per_opts = dict(opts_overrides)
        per_opts["target"] = t
        per_opts["target_file"] = None  # don't recurse into file
        per_opts["max_hosts"] = None

        # Derive a per-host output filename so reports don't overwrite each other.
        base_output = per_opts.get("output")
        if base_output:
            per_opts["output"] = f"{base_output}_{hostname.replace(':', '_')}"
        else:
            safe = hostname.replace(":", "_").replace("/", "_")
            per_opts["output"] = f"scan_{safe}"

        error_msg = None
        try:
            _build_and_run(
                ctx,
                selected_keys=selected_keys,
                descriptors=descriptors,
                opts=per_opts,
                config_path=config_path,
            )
            click.echo(f"  {_GREEN}✓ Scan completed{_RESET}")
        except SystemExit as exc:
            # _build_and_run calls sys.exit on validation / config errors.
            error_msg = f"exited with code {exc.code}"
            click.echo(f"  {_RED}✗ {error_msg}{_RESET}")
        except Exception as exc:
            error_msg = str(exc)
            click.echo(f"  {_RED}✗ {error_msg}{_RESET}")

        summaries.append(
            {
                "hostname": hostname,
                "target": t,
                "error": error_msg,
            }
        )

    # Consolidated summary table
    col = 50
    click.echo(
        f"\n{_BOLD}{_CYAN}{'═' * 60}\n  MULTI-TARGET SCAN SUMMARY  ({total} hosts)\n"
        f"{'═' * 60}{_RESET}"
    )
    click.echo(f"{_BOLD}{'HOST':<{col}} {'STATUS'}{_RESET}")
    click.echo("─" * 65)
    success_count = error_count = 0
    for s in summaries:
        h = s["hostname"][: col - 1] if len(s["hostname"]) >= col else s["hostname"]
        if s["error"]:
            error_count += 1
            click.echo(f"{h:<{col}} {_RED}ERROR — {s['error'][:30]}{_RESET}")
        else:
            success_count += 1
            click.echo(f"{h:<{col}} {_GREEN}OK{_RESET}")
    click.echo("─" * 65)
    click.echo(
        f"\n{_BOLD}Total:{_RESET} {total}  "
        f"{_GREEN}Success: {success_count}{_RESET}  "
        f"{_RED}Errors: {error_count}{_RESET}\n"
    )


def _build_and_run(ctx, *, selected_keys, descriptors, opts, config_path=None):
    """Shared execution core for the ``owasp`` subcommands and the ``scan`` command.

    Centralizes the config assembly + dispatch that the legacy ``full`` handler
    performed inline, parameterized by the selected module set. A single
    Module_Subcommand and ``scan --modules <that-one>`` flow through the same
    steps 2-5 with the same option values, so they build a byte-identical
    ``APILeakConfig`` for that module — differing only in ``enabled_modules``
    cardinality (Property 5 / Requirement 4.3).

    Setting-resolution precedence is preserved (command-line option ->
    environment override -> config file -> built-in default): CLI overrides are
    applied last onto the loaded config, env fallbacks live in
    ``create_enhanced_config`` / ``resolve_max_depth``, and file settings are
    loaded by ``ConfigurationManager`` (Requirements 10.1-10.5).

    Args:
        ctx: The Click context (parity with the command handlers).
        selected_keys: Ordered engine module keys to enable for this run.
        descriptors: The ``OwaspModuleDescriptor`` objects for ``selected_keys``.
        opts: Collected Click option values (transversal + any module-specific).
        config_path: Optional ``--config`` file path; when given, run settings are
            loaded from it instead of built in memory.

    Requirements: 1.3, 1.5, 3.5, 3.6, 4.3, 5.4, 10.1, 10.2, 10.3, 10.4, 10.5
    """
    # --- 1. Pre-flight validation (each fails before any request is issued) ---
    # 1a. Mutually-exclusive User-Agent options (Requirement 3.6).
    validate_user_agent_options(
        opts.get("user_agent_random"),
        opts.get("user_agent_custom"),
        opts.get("user_agent_file"),
    )

    setup_logging(
        level=opts.get("log_level", "WARNING"),
        json_logs=opts.get("json_logs", False),
        log_file=opts.get("log_file"),
    )
    logger = get_logger("build_and_run")
    logger.info(
        "APILeak scan starting",
        version=APILEAK_VERSION,
        ci_mode=opts.get("ci_mode", False),
        modules=list(selected_keys),
    )

    # 1b. Parse --auth-context up front so a value missing the ':' separator is
    #     rejected with a descriptive click.BadParameter BEFORE any request.
    parsed_auth_contexts = parse_auth_context_option(opts.get("auth_context") or ())

    # 1c. Parse the Recursion_Scope up front so an unrecognized status class or
    #     endpoint type aborts with a descriptive error BEFORE any discovery.
    try:
        recursion_scope = parse_recursion_scope(
            opts.get("recursion_status"), opts.get("recursion_type")
        )
    except RecursionScopeError as exc:
        logger.error("Invalid discovery scope value", error=str(exc))
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    opts["recursion_scope"] = recursion_scope

    # 1d. Target-or-config requirement (Requirement 1.5).
    _require_target_or_config(opts, config_path)

    # 1d-bis. Multi-target resolution: if --target-file was supplied, expand
    #     the full list of targets and run each one sequentially via
    #     _run_scan_multi_target. This mirrors the dir command's multi-target
    #     behavior. When --target-file is absent, this block is a no-op and the
    #     single-target path below proceeds unchanged.
    target_file = opts.get("target_file")
    if target_file:
        try:
            file_targets = parse_target_file(target_file)
        except click.BadParameter as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)
        if not file_targets:
            click.echo(
                f"Error: --target-file '{target_file}' contains no valid targets.",
                err=True,
            )
            sys.exit(1)
        # Merge explicit --target (if any) as the first entry.
        explicit_target = opts.get("target")
        if explicit_target:
            all_targets = [explicit_target] + [t for t in file_targets if t != explicit_target]
        else:
            all_targets = file_targets
        max_hosts = opts.get("max_hosts")
        if max_hosts is not None and max_hosts > 0:
            all_targets = all_targets[:max_hosts]
        _run_scan_multi_target(
            ctx,
            targets=all_targets,
            selected_keys=selected_keys,
            descriptors=descriptors,
            config_path=config_path,
            **{k: v for k, v in opts.items() if k not in ("target_file", "max_hosts")},
        )
        return

    # 1d-ter. Baseline readability (Requirement 5.7): an existing but unreadable
    #     or malformed --baseline file aborts nonzero BEFORE any request, so no
    #     Severity_Gate is ever run against a partial baseline. A missing path is
    #     allowed (treated as an empty baseline downstream).
    _validate_baseline_readable(opts.get("baseline"))

    # 1e. Parse the --actor-profile source up front so a missing/unreadable/
    #     unparseable Actor_Profile source is rejected with a descriptive
    #     click.BadParameter naming the source and the scan aborts BEFORE any
    #     request is issued (Requirement 54.5). No-op when the option is absent
    #     (e.g. on the owasp subcommands, which do not expose it).
    actor_profiles = {}
    if opts.get("actor_profile"):
        try:
            actor_profiles = load_actor_profiles(opts["actor_profile"])
        except ValueError as exc:
            raise click.BadParameter(str(exc)) from exc

    # 1f. Parse the --unauthorized-assertions source up front (like
    #     --actor-profile) so a missing/unreadable/unparseable source, or a
    #     pattern that fails to compile, is rejected with a descriptive
    #     click.BadParameter naming the source BEFORE any request (Requirement
    #     55.1). No-op when the option is absent.
    unauthorized_endpoint_assertions = {}
    if opts.get("unauthorized_assertions"):
        try:
            unauthorized_endpoint_assertions = load_unauthorized_assertions(
                opts["unauthorized_assertions"]
            )
        except ValueError as exc:
            raise click.BadParameter(str(exc)) from exc

    # 1g. Parse the repeatable --openapi / --postman Spec_Sources into one merged
    #     Spec_Schema up front so an unreadable or unparseable source is surfaced
    #     as a descriptive CLI error naming the offending Spec_Source and the
    #     scan aborts BEFORE any request is issued (Requirements 49.1, 49.4). Left
    #     as ``None`` when no Spec_Source is supplied so the existing no-spec path
    #     is preserved (Requirement 49.3). No-op when the options are absent.
    merged_spec_schema = None
    if opts.get("openapi") or opts.get("postman"):
        try:
            merged_spec_schema = asyncio.run(
                _load_spec_schema(opts.get("openapi") or (), opts.get("postman") or ())
            )
        except SpecImportError as exc:
            logger.error("Spec import failed", error=str(exc))
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)

    try:
        config_manager = ConfigurationManager()

        # --- 2. Config assembly: file OR in-memory (identical to full's path) ---
        if config_path:
            # Load run settings from the supplied Config_File (Requirements 10.1,
            # 10.5). A missing/malformed file raises and is surfaced below.
            cfg = config_manager.load_config(config_path)
        else:
            # Prepare user agent configuration
            user_agent_config = None
            if opts.get("user_agent_random"):
                user_agent_config = {"random": True}
            elif opts.get("user_agent_custom"):
                user_agent_config = {"custom": opts["user_agent_custom"]}
            elif opts.get("user_agent_file"):
                user_agents = load_user_agents_from_file(opts["user_agent_file"])
                user_agent_config = {"file_list": user_agents}

            output_filename = prepare_output_filename(opts.get("output"))

            # Advanced discovery options are not part of the restructured option
            # surface (owasp subcommands / scan); default them off via opts.get so
            # the in-memory config matches the legacy full defaults when absent.
            advanced_config = {
                "detect_framework": opts.get("detect_framework", False)
                or opts.get("enable_advanced", False),
                "fuzz_versions": opts.get("fuzz_versions", False)
                or opts.get("enable_advanced", False),
                "framework_confidence": opts.get("framework_confidence", 0.6),
                "enable_payload_encoding": opts.get("enable_payload_encoding", False)
                or opts.get("enable_advanced", False),
                "enable_waf_evasion": opts.get("enable_waf_evasion", False)
                or opts.get("enable_advanced", False),
                "enable_subdomain_discovery": opts.get("enable_subdomain_discovery", False)
                or opts.get("enable_advanced", False),
                "enable_cors_analysis": opts.get("enable_cors_analysis", False)
                or opts.get("enable_advanced", False),
            }
            if opts.get("version_patterns"):
                advanced_config["version_patterns"] = [
                    p.strip() for p in opts["version_patterns"].split(",")
                ]

            status_code_filter = (
                parse_status_codes(opts["status_code"]) if opts.get("status_code") else None
            )

            config_dict = create_enhanced_config(
                opts.get("target"),
                None,
                "full",
                user_agent_config,
                output_filename,
                advanced_config,
                status_code_filter,
                opts.get("ci_mode", False),
                opts.get("fail_on", "high"),
                opts.get("safe_mode", False),
                module_configs=_collect_module_configs(descriptors, opts),
            )

            # Thread the discovery recursion / budget / concurrency / resilience
            # controls into the constructed config_dict PRE-load, reproducing the
            # legacy ``full`` in-memory assembly so the built config_dict (the
            # first consumer of the threaded settings) carries them (Requirements
            # 17, 18, 20, 23, 28). Post-load ``_apply_transversal_overrides``
            # re-applies the same values idempotently and additionally covers the
            # file-config path.
            config_dict["fuzzing"]["max_depth"] = resolve_max_depth(opts.get("depth"))
            if opts.get("recursive") is not None:
                config_dict["fuzzing"]["recursive"] = opts["recursive"]
            if opts.get("max_requests") is not None:
                config_dict["fuzzing"]["max_requests"] = opts["max_requests"]
            if opts.get("concurrency") is not None:
                config_dict["fuzzing"]["concurrency"] = opts["concurrency"]
            if opts.get("timeout") is not None:
                config_dict["target"]["timeout"] = opts["timeout"]
            if opts.get("retries") is not None:
                config_dict["fuzzing"]["retries"] = opts["retries"]
            config_dict["fuzzing"].setdefault("endpoints", {})
            config_dict["fuzzing"]["endpoints"]["extensions"] = normalize_extensions(
                [ext for value in (opts.get("extensions") or ()) for ext in value.split(",")]
            )
            if opts.get("depth") == 0:
                config_dict["fuzzing"]["recursive"] = False  # depth 0 => depth-0 pass only
            config_dict["fuzzing"]["recursion_scope"] = opts.get("recursion_scope")

            cfg = config_manager.load_config_from_dict(config_dict)

        # --- 3. enabled_modules = the selection (Requirements 1.3, 4.2, 4.6) ---
        cfg.owasp_testing.enabled_modules = list(selected_keys)

        # --- 4. Transversal overrides (verbatim from full) — Reqs 3.5, 5.4 ---
        _apply_transversal_overrides(cfg, opts, parsed_auth_contexts)

        # --- 4b. Attach the parsed Actor_Profiles to the AuthContext whose name
        #     matches each profile's context_name (Requirements 54.1, 54.2).
        #     Applied post-load (after the transversal overrides extend the
        #     contexts) so it works for both file and in-memory configs. Contexts
        #     without a matching profile keep ``actor_profile = None`` (Req 54.3).
        if actor_profiles and hasattr(cfg, "authentication"):
            for context in cfg.authentication.contexts:
                profile = actor_profiles.get(context.name)
                if profile is not None:
                    context.actor_profile = profile

        # --- 4c. Attach each context's compiled Unauthorized_Endpoint_Assertion
        #     patterns to the AuthContext whose name matches (Requirements 55.1,
        #     55.2). Contexts without a matching assertion keep
        #     ``unauthorized_patterns = None`` (Requirement 55.5).
        if unauthorized_endpoint_assertions and hasattr(cfg, "authentication"):
            for context in cfg.authentication.contexts:
                patterns = unauthorized_endpoint_assertions.get(context.name)
                if patterns is not None:
                    context.unauthorized_patterns = patterns

        # --- 4d. Attach the merged Spec_Schema so the modules can test the
        #     declared Spec_Operations in addition to discovered endpoints
        #     (Requirements 49.2, 49.5). Left as ``None`` when no Spec_Source was
        #     supplied, preserving the existing behavior (Requirement 49.3).
        if merged_spec_schema is not None and hasattr(cfg, "owasp_testing"):
            cfg.owasp_testing.spec_schema = merged_spec_schema

        # --- 5. Per-module specific-option application (Requirement 2.5) ---
        for desc in descriptors:
            if desc.apply_options:
                desc.apply_options(getattr(cfg.owasp_testing, desc.config_field), opts)

        # --- 6. Validate + dispatch to the UNCHANGED engine path ---
        validation_errors = config_manager.validate_configuration()
        if validation_errors:
            logger.error("Configuration validation failed", errors=validation_errors)
            for error in validation_errors:
                click.echo(f"Error: {error}", err=True)
            sys.exit(1)

        # --- 6b. Build scope_endpoints from spec when --openapi / --postman
        #     was supplied on an owasp subcommand (no wordlist discovery path).
        #     Convert each SpecOperation into a synthetic DiscoveryResult so the
        #     engine's scope-seeding path skips wordlist discovery entirely and
        #     feeds the SSRF (and other) modules exactly the spec-declared endpoints.
        scope_endpoints = None
        if merged_spec_schema is not None and merged_spec_schema.operations:
            from utils.discovery_session import DiscoveryResult

            base_url = cfg.target.base_url.rstrip("/")
            scope_endpoints = []
            for op in merged_spec_schema.operations:
                url = base_url + op.path
                scope_endpoints.append(
                    DiscoveryResult(
                        url=url,
                        method=op.method,
                        status_code=200,
                        endpoint_status="valid",
                    )
                )
            logger.info(
                "Seeding scan from spec",
                source="openapi/postman",
                endpoints=len(scope_endpoints),
            )
            click.echo(
                f"📋 Spec endpoints loaded: {len(scope_endpoints)} operations from OpenAPI/Postman"
            )
            # When endpoints come from a spec, skip parameter fuzzing — it
            # generates thousands of wordlist probes against endpoints the
            # operator already knows about and drowns the OWASP module output.
            if hasattr(cfg, "fuzzing") and hasattr(cfg.fuzzing, "parameters"):
                cfg.fuzzing.parameters.enabled = False
                cfg.fuzzing.headers.enabled = False

        asyncio.run(
            runner.run_enhanced_apileak(
                cfg,
                opts.get("ci_mode", False),
                opts.get("fail_on", "high"),
                opts.get("baseline"),
                scope_endpoints=scope_endpoints,
            )
        )

    except (click.ClickException, SystemExit):
        # Preserve Click parameter errors and explicit exits (validation, gate)
        # so the process exit code is decided by the run, not this handler.
        raise
    except Exception as e:
        logger.error("Scan failed", error=str(e))
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Orchestrator helpers (design §5, §7): module-selection resolution and the
# deprecation notices for the ``full`` alias and hidden ``main`` command. These
# are CLI-surface only.
# ---------------------------------------------------------------------------


def _emit_deprecation_notice(deprecated, replacement):
    """Write a single Deprecation_Notice to standard error (design §7).

    The notice names the deprecated invocation and its replacement. It is
    written ONLY to stderr and never alters standard output or the exit code
    (Requirements 6.4, 6.7). Handlers call this exactly once per invocation.
    """
    click.echo(
        f"[DEPRECATION] '{deprecated}' is deprecated and will be removed in a "
        f"future release. Use '{replacement}' instead.",
        err=True,
    )


def _resolve_modules(modules):
    """Resolve the ``--modules`` selection to an ordered list of engine keys.

    Resolution follows the setting-resolution precedence command-line option ->
    Environment_Override -> built-in default (Requirements 10.3, 10.4):

    * a non-empty ``--modules`` option is used as given;
    * otherwise a non-empty ``APILEAK_MODULES`` Environment_Override is used;
    * otherwise the full registered set is returned in OWASP category order
      (Requirement 4.2).

    Every selected key (from either the option or the Environment_Override) is
    validated against the descriptor registry; an unregistered key aborts with a
    nonzero exit and a stderr message naming the offending key BEFORE any module
    runs (Requirements 4.7, 9.4).
    """
    if not modules:
        # Environment_Override: APILEAK_MODULES selects modules when --modules is
        # absent (Requirements 10.3, 10.4). An empty/unset value falls through to
        # the full default set (Requirement 4.2).
        env_modules = os.getenv("APILEAK_MODULES")
        if env_modules and env_modules.strip():
            modules = env_modules
        else:
            return all_keys()
    selected = [m.strip() for m in modules.split(",") if m.strip()]
    if not selected:
        return all_keys()
    for key in selected:
        try:
            get_descriptor(key)
        except KeyError:
            click.echo(
                f"Error: unregistered OWASP module '{key}'. "
                f"Registered modules: {', '.join(all_keys())}.",
                err=True,
            )
            sys.exit(1)
    return selected


def _selected_descriptors(modules):
    """Return the descriptors for the resolved ``--modules`` selection.

    Reuses :func:`_resolve_modules` so an unregistered key aborts before any run
    (Requirements 4.7, 9.4). The returned descriptors preserve the selection
    order.
    """
    return [get_descriptor(key) for key in _resolve_modules(modules)]


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
_ORCHESTRATOR_EXTRA_OPTIONS = [
    click.option(
        "--config",
        "-c",
        type=click.Path(exists=True),
        help="Configuration file path (YAML or JSON) - optional",
    ),
    click.option(
        "--modules", help="Comma-separated list of OWASP modules to enable (default: all)"
    ),
    click.option(
        "--status-code",
        help="Show only HTTP requests with specific status codes (e.g., 200,404 or 200-300)",
    ),
    click.option(
        "--detect-framework",
        "--df",
        is_flag=True,
        help="Enable framework detection (FastAPI, Express, Django, Flask, etc.)",
    ),
    click.option(
        "--fuzz-versions",
        "--fv",
        is_flag=True,
        help="Enable API version fuzzing (/v1, /v2, /api/v1, etc.)",
    ),
    click.option(
        "--framework-confidence",
        type=float,
        default=0.6,
        help="Minimum confidence threshold for framework detection (0.0-1.0)",
    ),
    click.option(
        "--version-patterns",
        help="Custom version patterns for fuzzing (comma-separated, e.g., /v1,/v2,/api/v1)",
    ),
    click.option(
        "--enable-advanced",
        is_flag=True,
        help="Enable all advanced features (framework detection, version fuzzing, subdomain discovery, CORS analysis)",
    ),
    click.option(
        "--enable-payload-encoding",
        is_flag=True,
        help="Enable advanced payload encoding and obfuscation techniques",
    ),
    click.option(
        "--enable-waf-evasion", is_flag=True, help="Enable WAF detection and evasion techniques"
    ),
    click.option(
        "--enable-subdomain-discovery", is_flag=True, help="Enable subdomain discovery and testing"
    ),
    click.option(
        "--enable-cors-analysis",
        is_flag=True,
        help="Enable CORS policy analysis and security headers testing",
    ),
    click.option(
        "--openapi",
        "openapi",
        multiple=True,
        type=click.Path(),
        help="OpenAPI/Swagger document (JSON or YAML) consumed by the OWASP modules "
        "for spec-driven security testing. Repeatable; merged across all values.",
    ),
    click.option(
        "--postman",
        "postman",
        multiple=True,
        type=click.Path(),
        help="Postman collection (JSON) consumed by the OWASP modules for spec-driven "
        "security testing. Repeatable; merged across all values.",
    ),
    click.option(
        "--actor-profile",
        "actor_profile",
        type=click.Path(),
        help="Actor_Profile source (JSON or YAML) supplying per-identity typed "
        "query/body values keyed by context name and endpoint. Each profile is "
        "attached to the matching --auth-context so multi-user tests use realistic "
        "per-actor inputs. A parse failure aborts before any request is issued.",
    ),
    click.option(
        "--unauthorized-assertions",
        "unauthorized_assertions",
        type=click.Path(),
        help="Unauthorized_Endpoint_Assertion source (JSON or YAML) mapping each "
        "context name to one or more endpoint pattern regular expressions that "
        "SHOULD be forbidden for that identity. A parse/compile failure aborts "
        "before any request is issued.",
    ),
]


def _orchestrator_options(func):
    """Attach the complete orchestrator option surface to ``func``.

    Stacks (deepest first) the Auth and BOLA Module_Specific_Options, the shared
    Transversal_Options, and finally the orchestrator-only extras
    (``--config``/``--modules`` and the discovery/spec inputs), so the resulting
    help lists the extras first, then the transversal options, then BOLA, then
    Auth — matching the legacy ``full`` layout. Declaring the surface once here
    guarantees ``scan`` and the ``full`` alias are identical (design §5).
    """
    func = auth_options(func)
    func = bola_options(func)
    func = transversal_options(func)
    for option in reversed(_ORCHESTRATOR_EXTRA_OPTIONS):
        func = option(func)
    return func


@cli.command(name="scan")
@_orchestrator_options
@click.pass_context
def scan(ctx, **kwargs):
    """Run an orchestrated OWASP scan (discovery + selected OWASP modules).

    \b
    Runs every registered OWASP module by default, or only the modules named in
    --modules. Aggregates all findings through the unified reporting pipeline and
    drives the CI/CD severity gate.

    \b
    Examples:
      apileaks scan --target https://api.example.com
      apileaks scan --config config.yaml --target URL
      apileaks scan --target URL --modules bola,auth,property
      apileaks scan --target URL --ci-mode --fail-on high
    """
    config_path = kwargs.get("config")
    modules = kwargs.get("modules")
    _build_and_run(
        ctx,
        selected_keys=_resolve_modules(modules),
        descriptors=_selected_descriptors(modules),
        opts=kwargs,
        config_path=config_path,
    )


@cli.command(name="full", hidden=True)
@_orchestrator_options
@click.pass_context
def full(ctx, **kwargs):
    """[DEPRECATED] Alias of 'scan'. Use 'apileaks scan' instead.

    Retained for backward compatibility. Emits a deprecation notice to standard
    error and then runs identically to 'scan' (same modules, report, and exit
    code).
    """
    _emit_deprecation_notice("full", "scan")
    if kwargs.get("modules"):
        _emit_module_selection_deprecation(kwargs["modules"])
    # Forward the identical parsed option surface to ``scan`` so the run and exit
    # code are identical; the only difference is the stderr notice above
    # (Requirements 6.1, 6.2, 6.7).
    ctx.forward(scan)


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


def _module_help(desc: OwaspModuleDescriptor) -> str:
    """Build the ``--help`` description text for a module subcommand.

    The base text names the OWASP category and the module summary and states
    that the subcommand runs exactly that one module in isolation.

    For the ``auth`` descriptor specifically, the help additionally states that
    automated JWT detection during an orchestrated run is performed by the
    JWT_Module_Tests, and points to the ``jwt`` group as the location for manual
    JWT attacks (Requirements 7.4, 7.5).

    Args:
        desc: The descriptor whose subcommand help text is being built.

    Returns:
        The multi-paragraph help string for the subcommand.
    """
    base = (
        f"[{desc.owasp_category}] {desc.summary}.\n\n"
        f"Runs only the '{desc.key}' OWASP module against the target "
        f"(single-module run in isolation)."
    )

    if desc.key == "auth":
        base += (
            "\n\n"
            "Automated JWT detection during an orchestrated run is performed by "
            "the JWT_Module_Tests (the algorithm-confusion and expired-token "
            "acceptance checks governed by --public-key, --jwks-url, and "
            "--signing-secret).\n\n"
            "For manual JWT attacks and utilities, use the 'jwt' command group "
            "(e.g. 'apileaks jwt --help')."
        )

    return base


@cli.group(invoke_without_command=True)
@click.pass_context
def owasp(ctx):
    """OWASP API Security Top 10 testing modules (run one module in isolation).

    Each subcommand runs exactly one registered OWASP detection module against a
    target. Run 'apileaks owasp' with no subcommand to list every available
    module with its OWASP category and a one-line description.
    """
    if ctx.invoked_subcommand is None:
        _print_owasp_module_listing()
        ctx.exit(0)


def _make_module_subcommand(desc: OwaspModuleDescriptor):
    """Build the fully decorated ``owasp`` subcommand for ``desc`` (design §4).

    Stacks the decorators in this order (applied in reverse so Click composes
    them correctly):

    1. ``click.command(name=desc.key, help=_module_help(desc))`` — the command
       named character-for-character by the engine key.
    2. ``transversal_options`` — the Shared_Option_Mechanism.
    3. ``desc.specific_options`` — the module's own options (only when not None).
    4. ``click.pass_context`` — so the handler receives the Click context.

    The handler routes into the shared execution core with a single selected
    key, so exactly that one module runs (Requirement 1.3).

    Args:
        desc: The descriptor to generate a subcommand for.

    Returns:
        The fully decorated Click command.
    """
    decorators = [
        click.command(name=desc.key, help=_module_help(desc)),
        transversal_options,
    ]
    if desc.specific_options is not None:
        decorators.append(desc.specific_options)
    decorators.append(click.pass_context)

    def _handler(ctx, **kwargs):
        _build_and_run(ctx, selected_keys=[desc.key], descriptors=[desc], opts=kwargs)

    cmd = _handler
    for dec in reversed(decorators):
        cmd = dec(cmd)
    return cmd


# Register exactly one generated subcommand per descriptor on the owasp group,
# then the owasp group on cli. Adding a descriptor row yields a fully wired
# subcommand automatically (Requirements 1.2, 11.1).
for _desc in OWASP_MODULE_DESCRIPTORS:
    owasp.add_command(_make_module_subcommand(_desc))


# ---------------------------------------------------------------------------
# JWT CLI helpers — route all attack-token generation and execution through the
# single-source-of-truth JWTAttackEngine (Requirements 14.2, 14.3) and issue
# HTTP through the shared HTTPRequestEngine (Requirement 17.1). No subcommand
# reimplements attack logic inline, and success is decided by the engine's
# JWTAttackResponseAnalyzer rather than admin/dashboard keyword presence
# (Requirement 19.2).
# ---------------------------------------------------------------------------


# JWT Command Group


@cli.command(hidden=True)
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True),
    help="Configuration file path (YAML or JSON) - optional",
)
@click.option("--target", "-t", help="Target URL to scan (overrides config)")
@click.option("--output", "-o", default="reports", help="Output directory for reports")
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    default="WARNING",
    help="Logging level",
)
@click.option("--log-file", help="Log file path (optional)")
@click.option("--json-logs", is_flag=True, help="Output logs in JSON format")
@click.option("--modules", help="Comma-separated list of OWASP modules to enable")
@click.option("--rate-limit", type=int, help="Requests per second limit")
@click.pass_context
def main(ctx, config, target, output, log_level, log_file, json_logs, modules, rate_limit):
    """Legacy main command - redirects to scan (deprecated)"""
    _emit_deprecation_notice("main", "scan")
    # Forward the parsed options to ``scan`` so the run and exit code are
    # identical to the non-deprecated invocation; Click fills defaults for
    # ``scan`` options not present on ``main`` (Requirements 6.3, 6.7).
    ctx.forward(scan)


# Severity ladder for CI/CD gate evaluation, ordered from highest to lowest.


async def run_apileak(config):
    """
    Run APILeak scan with the provided configuration (legacy compatibility)

    Args:
        config: APILeak configuration
    """
    # Delegate to enhanced version with default CI settings
    await runner.run_enhanced_apileak(config, ci_mode=False, fail_on="critical")


# =============================================================================
# replay command
# =============================================================================


@cli.command(name="replay")
@click.argument("report", type=click.Path(exists=True, readable=True))
@click.option(
    "--url",
    "-u",
    "url_filter",
    default=None,
    help="Filter: only replay requests whose URL contains this substring.",
)
@click.option(
    "--method",
    "-m",
    "method_filter",
    default=None,
    help="Filter: only replay requests with this HTTP method (e.g. POST).",
)
@click.option(
    "--source",
    "source_filter",
    type=click.Choice(["endpoint", "finding"], case_sensitive=False),
    default=None,
    help="Filter: only replay items from 'endpoint' or 'finding' sections.",
)
@click.option(
    "--index",
    "-i",
    "index",
    type=int,
    default=None,
    help="Replay only the item at this index in the filtered list (0-based).",
)
@click.option(
    "--list",
    "-l",
    "list_only",
    is_flag=True,
    default=False,
    help="List all replayable requests from the report without replaying.",
)
@click.option(
    "--proxy",
    "proxy",
    default=None,
    metavar="URL",
    help="Forward the replayed request through an intercepting proxy "
    "(e.g. http://127.0.0.1:8080 for Burp/Caido).",
)
@click.option(
    "--jwt",
    "jwt_token",
    default=None,
    metavar="TOKEN",
    help="Bearer token to inject into the Authorization header.",
)
@click.option(
    "--header",
    "-H",
    "header",
    multiple=True,
    metavar="Name: Value",
    help="Additional request header (repeatable, e.g. -H 'X-API-Key: abc').",
)
@click.option(
    "--timeout",
    "timeout",
    type=float,
    default=30.0,
    show_default=True,
    help="Per-request timeout in seconds.",
)
@click.option(
    "--no-verify",
    "no_verify",
    is_flag=True,
    default=False,
    help="Disable TLS certificate verification.",
)
@click.option(
    "--all",
    "replay_all",
    is_flag=True,
    default=False,
    help="Replay ALL matching requests (default: only the first match).",
)
@click.pass_context
def replay_cmd(
    ctx,
    report,
    url_filter,
    method_filter,
    source_filter,
    index,
    list_only,
    proxy,
    jwt_token,
    header,
    timeout,
    no_verify,
    replay_all,
):
    """Replay HTTP requests from a prior apileaks scan report.

    REPORT is the path to a JSON report file generated by the ``dir``,
    ``par``, or ``scan`` commands.

    \b
    Examples:
      # List all replayable requests in a report
      apileaks replay reports/scan.json --list

      # Replay all POST findings through Burp
      apileaks replay reports/scan.json --source finding --method POST --proxy http://127.0.0.1:8080 --all

      # Replay item #3 from the list with a JWT
      apileaks replay reports/scan.json --index 3 --jwt eyJ...

      # Replay every endpoint containing '/admin'
      apileaks replay reports/scan.json --url /admin --all
    """
    import asyncio

    from utils.replay import (
        _extract_requests_from_report,
        filter_requests,
        load_report,
        print_request_list,
        replay_request,
    )

    no_banner = ctx.obj.get("no_banner", False) if ctx.obj else False
    if not no_banner:
        print_banner()

    # Load report
    rep = load_report(report)
    all_requests = _extract_requests_from_report(rep)

    if not all_requests:
        click.echo("No replayable requests found in this report.", err=True)
        sys.exit(1)

    # Apply filters
    filtered = filter_requests(
        all_requests,
        url_filter=url_filter,
        method_filter=method_filter,
        source_filter=source_filter,
        index=index,
    )

    if not filtered:
        click.echo(
            "No requests matched the supplied filters. Use --list to see what is available.",
            err=True,
        )
        sys.exit(1)

    # List mode: just print the table and exit
    if list_only:
        print_request_list(filtered)
        return

    # If not --all, replay only the first match (unless --index was supplied)
    targets = filtered if replay_all else [filtered[0]]

    if len(targets) > 1:
        click.echo(
            f"Replaying {len(targets)} request(s)…  "
            f"(pass --index N to target a specific one, or --list to browse)"
        )

    # Parse extra headers
    extra_headers = parse_header_options(header)
    validate_header_options(header)

    # Run replays
    for entry in targets:
        try:
            asyncio.run(
                replay_request(
                    entry,
                    extra_headers=extra_headers or None,
                    jwt_token=jwt_token,
                    proxy=proxy,
                    verify_ssl=not no_verify,
                    timeout=timeout,
                    verbose=True,
                )
            )
        except Exception as exc:
            click.echo(f"Replay failed for {entry['method']} {entry['url']}: {exc}", err=True)


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
