#!/usr/bin/env python3
"""
APILeak Main Entry Point
Enterprise-grade API fuzzing and OWASP testing tool
"""

import asyncio
import json
import os
import re
import sys
from datetime import UTC, datetime

import click

from cli.commands.jwt_cmds import jwt
from cli.commands.wordlist_cmds import wordlist_group
from cli.config_builders import (
    _collect_module_configs,
    _load_spec_schema,
    create_default_config,
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
    _assert_readable,
    _parse_selection_indices,
    _require_target_or_config,
    _validate_confirm_hits,
    load_user_agents_from_file,
    parse_auth_context_option,
    parse_basic_auth,
    parse_header_options,
    parse_response_codes,
    parse_status_codes,
    parse_target_file,
    prepare_output_filename,
    validate_basic_auth_options,
    validate_header_options,
    validate_user_agent_options,
)
from cli.runner import (
    SEVERITY_LADDER,  # noqa: F401  re-exported (public surface / tests)
    _echo_discovery_control_status,
    evaluate_severity_gate,  # noqa: F401  re-exported (public surface / tests)
    run_enhanced_apileak,
)
from cli.shared_options import (
    _validate_ca_bundle,  # noqa: F401  re-exported (public surface / tests)
    _validate_client_cert,  # noqa: F401  re-exported (public surface / tests)
    _validate_concurrency,  # noqa: F401  re-exported: tests patch via apileaks namespace
    _validate_depth,
    _validate_max_requests,  # noqa: F401  re-exported
    _validate_methods,
    _validate_resolve,  # noqa: F401  re-exported (public surface / tests)
    _validate_retries,  # noqa: F401  re-exported
    _validate_timeout,  # noqa: F401  re-exported
    concurrency_options,
    machine_output_options,
    matcher_filter_options,
    request_context_options,
    resilience_options,
    tls_options,
    transversal_options,
)
from core import APILeakCore, ConfigurationManager, setup_logging
from core import __version__ as APILEAK_VERSION
from core.config import load_actor_profiles, load_unauthorized_assertions
from core.logging import get_logger
from modules.fuzzing.markers import (
    FuzzMode,
    associate_wordlists,
    find_markers,
    parse_fuzz_mode,
    validate_fuzz_keyword,
)
from modules.fuzzing.orchestrator import normalize_extensions
from utils.discovery_checkpoint import (
    DiscoveryCheckpoint,
    DiscoveryCheckpointError,
)
from utils.discovery_export import DiscoveryExportError, write_discovery_export
from utils.discovery_output import (
    DiscoveryOutputError,
    write_discovery_output,
)
from utils.discovery_progress import DiscoveryProgress
from utils.discovery_scope import (
    PathScopeError,
    RecursionScopeError,
    StorageStatusError,
    parse_path_scope,
    parse_recursion_scope,
    parse_storage_status_selection,
)
from utils.discovery_session import (
    DiscoveryResult,
    DiscoverySession,
    DiscoverySessionError,
    apply_status_filter,
    group_by_status_class,
    parse_status_filter,
    status_code_class,
)
from utils.jwt_attack_engine import JWTAttackEngine  # noqa: F401  re-exported (public surface)
from utils.response_selector import (
    DiscoveryResultEx,
    SelectorError,
    apply_selectors,
    calibrate_soft_404,
    parse_selectors,
)
from utils.spec_import import (
    SpecImportError,
    SpecSchema,
    import_openapi,
    import_postman,
    import_postman_schema,
    import_schema,
    merge_candidates,
    normalize_candidate_path,
)
from utils.spec_import import _parse_document as _parse_spec_document
from utils.triage_table import render_triage_table

# ---------------------------------------------------------------------------
# Validation callbacks for --depth, --max-requests, --concurrency,
# --timeout, --retries are imported from cli.shared_options (single source of
# truth — BUG-013 fix). They are used directly by the Click option decorators
# on the ``dir`` and ``par`` commands below.
# ---------------------------------------------------------------------------


def _validate_secret_patterns(ctx, param, value):
    """Click callback: load and validate the --secret-patterns file.

    The file is a JSON object mapping Secret_Pattern names to regular expression
    strings (Requirement 30.6). The path must be readable, parse as a JSON
    object of string -> string entries, and every regex must compile; otherwise
    a descriptive error names the problem and no Endpoint_Discovery runs.
    Returns the parsed name -> regex map, or ``None`` when the option is not
    supplied (the built-in DEFAULT_SECRET_PATTERNS are then used).
    """
    if value is None:
        return None
    _assert_readable(value, "--secret-patterns")
    try:
        with open(value, encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise click.BadParameter(
            f"--secret-patterns file is not valid JSON: {value} ({exc})"
        ) from exc
    except OSError as exc:
        raise click.BadParameter(f"--secret-patterns file cannot be read: {value} ({exc})") from exc

    if not isinstance(data, dict) or not data:
        raise click.BadParameter(
            f"--secret-patterns file must be a non-empty JSON object mapping "
            f"pattern names to regex strings: {value}"
        )

    patterns = {}
    for name, pattern in data.items():
        if not isinstance(name, str) or not isinstance(pattern, str):
            raise click.BadParameter(
                f"--secret-patterns entries must map a string name to a string "
                f"regex (offending entry: {name!r})"
            )
        try:
            re.compile(pattern)
        except re.error as exc:
            raise click.BadParameter(
                f"--secret-patterns regex for '{name}' is invalid: {exc}"
            ) from exc
        patterns[name] = pattern
    return patterns


def _read_wordlist_entries(source):
    """Read one ``--wordlist`` source into entries.

    A ``source`` of ``-`` reads entries from standard input; a source with the
    ``assetnote:`` prefix is resolved to a local cache file (downloading it on
    demand when not already cached); any other value is treated as a file path.
    Blank lines and lines whose first non-whitespace character is ``#`` are
    skipped, using the same rule as ``_load_wordlist`` /
    :func:`load_user_agents_from_file` (Requirement 25.5).
    """
    from utils.wordlist_manager import ASSETNOTE_PREFIX, resolve_wordlist

    if source == "-":
        lines = sys.stdin.read().splitlines()
    elif source.startswith(ASSETNOTE_PREFIX):
        # Resolve (and auto-download) the Assetnote wordlist; then read it.
        resolved = resolve_wordlist(source, show_progress=True)
        with open(resolved, encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    else:
        with open(source, encoding="utf-8") as handle:
            lines = handle.readlines()

    entries = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            entries.append(stripped)
    return entries


def _load_spec_seeds(openapi_sources, postman_sources):
    """Parse ``--openapi`` / ``--postman`` sources into Spec_Import seeds.

    OpenAPI/Swagger sources are parsed with :func:`import_openapi` and Postman
    collections with :func:`import_postman` (Requirements 25.1-25.3). An
    unparseable or unrecognized source raises :class:`SpecImportError` naming the
    offending source so the caller can perform no discovery (Requirement 25.6).
    """
    seeds = []
    for path in openapi_sources:
        try:
            doc = _parse_spec_document(path)
            seeds.extend(import_openapi(doc))
        except SpecImportError as exc:
            raise SpecImportError(f"OpenAPI source '{path}': {exc}") from exc
    for path in postman_sources:
        try:
            doc = _parse_spec_document(path)
            seeds.extend(import_postman(doc))
        except SpecImportError as exc:
            raise SpecImportError(f"Postman source '{path}': {exc}") from exc
    return seeds


def _build_dir_spec_schema(openapi_sources, postman_sources):
    """Build a merged :class:`SpecSchema` from local spec files for ``dir`` discovery.

    Synchronous counterpart of :func:`_load_spec_schema` for the ``dir`` command,
    which does not run an async event loop at the point where the config is
    assembled. Only local file paths are supported (URL sources require the async
    path used by ``scan``). Returns ``None`` when no sources are supplied so the
    brute-force discovery path is preserved unchanged.
    """
    if not openapi_sources and not postman_sources:
        return None

    operations = []
    security_schemes = []
    seeds = []

    for path in list(openapi_sources or []):
        try:
            doc = _parse_spec_document(path)
            schema = import_schema(doc)
            operations.extend(schema.operations)
            security_schemes.extend(schema.security_schemes)
            seeds.extend(schema.seeds)
        except SpecImportError:
            raise  # re-raise; caller surfaces the error

    for path in list(postman_sources or []):
        try:
            doc = _parse_spec_document(path)
            schema = import_postman_schema(doc)
            operations.extend(schema.operations)
            seeds.extend(schema.seeds)
        except SpecImportError:
            raise

    if not operations and not seeds:
        return None

    return SpecSchema(
        operations=operations,
        security_schemes=security_schemes,
        seeds=seeds,
    )


def _resolve_dir_candidates(wordlists, openapi_sources, postman_sources):
    """Resolve discovery candidates from wordlists and Spec_Import sources.

    Returns a ``(candidate_set, seed_methods, wordlist_path)`` tuple:

    * Backward-compatible single-file case (no spec sources, no stdin, and at
      most one ``--wordlist``): ``candidate_set`` is ``None`` and ``seed_methods``
      is empty, while ``wordlist_path`` is the single file path (or ``None`` for
      the default wordlist). Discovery then loads the file via ``_load_wordlist``
      exactly as before.
    * Otherwise (any spec source, repeated ``--wordlist``, or ``--wordlist -``):
      all wordlist entries and spec seed paths are merged and de-duplicated by
      normalized path via :func:`merge_candidates` into an in-memory
      ``candidate_set`` (possibly empty, Requirement 25.4/25.7/25.8).
      ``seed_methods`` maps each spec seed's normalized path to its declared HTTP
      methods so those methods extend the per-path method set (Requirement 25.3),
      and ``wordlist_path`` is ``None``.

    Raises :class:`SpecImportError` naming an unparseable spec source
    (Requirement 25.6).
    """
    wordlists = list(wordlists or [])
    has_stdin = "-" in wordlists
    has_specs = bool(openapi_sources or postman_sources)

    # Backward-compatible single-file (or default) discovery path.
    if not has_specs and not has_stdin and len(wordlists) <= 1:
        return None, {}, (wordlists[0] if wordlists else None)

    # In-memory merged candidate set mode (Requirements 25.3, 25.4, 25.5).
    spec_seeds = _load_spec_seeds(openapi_sources, postman_sources)

    wordlist_entries = []
    for source in wordlists:
        wordlist_entries.extend(_read_wordlist_entries(source))

    candidate_set = merge_candidates(wordlist_entries, spec_seeds)

    # Spec methods extend the per-path method set for those seeds (Requirement
    # 25.3); keyed by normalized path so the fuzzer can match each candidate.
    seed_methods = {}
    for seed in spec_seeds:
        key = normalize_candidate_path(seed.path)
        if not key:
            continue
        methods = seed_methods.setdefault(key, [])
        if seed.method not in methods:
            methods.append(seed.method)

    return candidate_set, seed_methods, None


# Default parameter wordlist used by ``par`` when no ``--wordlist`` is supplied
# (Requirement 10.4).
DEFAULT_PARAMETER_WORDLIST = "wordlists/parameters.txt"


def _resolve_par_candidates(wordlists):
    """Resolve the merged, de-duplicated parameter candidate set for ``par``.

    Mirrors the ``dir`` command's repeatable ``--wordlist`` handling
    (Requirement 10.1): every provided ``--wordlist`` source is read via
    :func:`_read_wordlist_entries` (which strips surrounding whitespace and
    drops blank/comment lines), and the combined entries are de-duplicated
    while preserving first-seen order. Both query and body candidate sets are
    fed from this single merged set (Requirement 10.2).

    When no ``--wordlist`` is supplied, the default parameter wordlist
    ``wordlists/parameters.txt`` is used (Requirement 10.4).

    Raises :class:`ValueError` naming the unreadable file when a wordlist source
    cannot be read, so the caller can stop before any request (Requirement
    10.3).
    """
    sources = list(wordlists or [])
    if not sources:
        sources = [DEFAULT_PARAMETER_WORDLIST]

    seen = set()
    merged = []
    for source in sources:
        try:
            entries = _read_wordlist_entries(source)
        except OSError as exc:
            raise ValueError(f"unreadable wordlist file '{source}': {exc}") from exc
        for entry in entries:
            if entry not in seen:
                seen.add(entry)
                merged.append(entry)
    return merged


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


@cli.command()
@click.option(
    "--target",
    "-t",
    required=False,
    default=None,
    help="Target URL to scan. Required unless --target-file is supplied.",
)
@click.option(
    "--wordlist",
    "-w",
    "wordlist",
    multiple=True,
    help="Wordlist file for directory fuzzing. Repeatable; merged and "
    'de-duplicated across all values. Use "-" to read entries from stdin.',
)
@click.option(
    "--openapi",
    "openapi",
    multiple=True,
    type=click.Path(),
    help="OpenAPI/Swagger document (JSON or YAML) to seed discovery from. Repeatable.",
)
@click.option(
    "--postman",
    "postman",
    multiple=True,
    type=click.Path(),
    help="Postman collection to seed discovery from. Repeatable.",
)
@click.option(
    "--output", "-o", help="Output filename for reports (files will be saved in reports/ directory)"
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    default="WARNING",
    help="Logging level",
)
@click.option("--log-file", help="Log file path (optional)")
@click.option("--json-logs", is_flag=True, help="Output logs in JSON format")
@click.option("--rate-limit", type=int, help="Requests per second limit")
@click.option(
    "--methods", default="GET,POST,PUT,DELETE,PATCH", help="HTTP methods to test (comma-separated)"
)
@click.option(
    "--fuzz-keyword",
    "fuzz_keyword",
    default="FUZZ",
    show_default=True,
    metavar="KEYWORD",
    help="Literal token in the target URL marking positions to fuzz. "
    "Every occurrence becomes a marker; choose a distinct value to "
    "avoid colliding with legitimate URL text. In marker mode the "
    "repeatable --wordlist values are the per-marker wordlists in "
    "marker order.",
)
@click.option(
    "--fuzz-mode",
    "fuzz_mode",
    type=click.Choice(["clusterbomb", "pitchfork"], case_sensitive=False),
    default="clusterbomb",
    show_default=True,
    help="How multiple markers combine their wordlists: clusterbomb "
    "(cartesian product) or pitchfork (index-wise zip).",
)
@click.option(
    "--depth",
    "depth",
    type=int,
    default=None,
    callback=_validate_depth,
    help="Max recursion depth for discovery (0 = no recursion). "
    "Overrides APILEAK_MAX_DEPTH and the config default (3).",
)
@click.option(
    "--recursive/--no-recursive",
    "recursive",
    default=None,
    help="Enable or disable recursive discovery (default: enabled).",
)
@concurrency_options
@click.option(
    "--confirm-hits",
    "confirm_hits",
    type=int,
    default=None,
    callback=_validate_confirm_hits,
    metavar="N",
    help="Enable Hit_Confirmation: re-request each interesting candidate N times "
    "and record it only when the responses are consistent (must be >= 1; "
    "default: off).",
)
@resilience_options
@click.option(
    "--extensions",
    "-x",
    "extensions",
    multiple=True,
    metavar="EXT",
    help="File extensions to append to each wordlist entry (comma-separated, repeatable). "
    "e.g. -x json,php or -x .json -x .php. Leading dots are optional.",
)
@click.option(
    "--user-agent-random", is_flag=True, help="Use random User-Agent headers to evade WAF"
)
@click.option("--user-agent-custom", help="Custom User-Agent string to use for all requests")
@click.option(
    "--user-agent-file", help="File containing User-Agent strings (one per line) for rotation"
)
@click.option("--jwt", help="JWT token to use for authentication")
@request_context_options
@click.option(
    "--enumerate-methods",
    "enumerate_methods",
    is_flag=True,
    default=False,
    help="Enumerate allowed HTTP methods per discovered endpoint via an OPTIONS "
    "request (parses the Allow header; default: off).",
)
@click.option(
    "--graphql",
    "graphql",
    is_flag=True,
    default=False,
    help="Probe common GraphQL paths against the target and report whether "
    "introspection is enabled (read-only introspection query; default: off).",
)
@click.option("--response", help="Filter by response codes (e.g., 200,301,404 or 200-300)")
@click.option(
    "--status-code",
    help="Show only HTTP requests with specific status codes (e.g., 200,404 or 200-300)",
)
@matcher_filter_options
@click.option(
    "--detect-framework",
    "--df",
    is_flag=True,
    help="Enable framework detection during directory fuzzing",
)
@click.option(
    "--fuzz-versions",
    "--fv",
    is_flag=True,
    help="Enable API version fuzzing during directory discovery",
)
@click.option(
    "--save-session",
    "save_session",
    type=click.Path(),
    help="Save discovery results to a JSON session file (source of truth for reload)",
)
@click.option(
    "--load-session",
    "load_session",
    type=click.Path(),
    help="Reload discovery results exclusively from a JSON session file (skips discovery)",
)
@click.option(
    "--checkpoint",
    "checkpoint",
    type=click.Path(),
    help="Periodically write a discovery checkpoint to PATH so an interrupted run can be resumed (atomic writes)",
)
@click.option(
    "--resume",
    "resume",
    type=click.Path(),
    help="Resume an interrupted discovery run from the discovery checkpoint at PATH (loaded before discovery; combine with --checkpoint to keep checkpointing)",
)
@click.option(
    "--export",
    "export_format",
    type=click.Choice(["md", "txt"]),
    help="Write a human-readable discovery export in the selected format (md or txt)",
)
@click.option(
    "--export-file",
    "export_file",
    type=click.Path(),
    help="Destination path for the human-readable export (extension selects the format)",
)
@machine_output_options
@click.option(
    "--interactive",
    "--triage",
    "interactive",
    is_flag=True,
    help="Enable interactive triage mode (opt-in; auto-disabled in CI mode)",
)
@click.option(
    "--scan-scope",
    "scan_scope",
    metavar="SCOPE",
    default=None,
    help="Non-interactively define a Batch_Scan_Scope as all discovered records of a "
    "Status_Code_Class (2xx, 3xx, 4xx, 5xx) or an EndpointStatus (valid, "
    "auth_required) and run an OWASP scan over them. In CI mode this is the only "
    "way to define the scan scope (the interactive prompt never runs).",
)
@click.option(
    "--ci-mode",
    "ci_mode",
    is_flag=True,
    help="Enable CI mode (disables the interactive triage prompt so it never blocks a pipeline)",
)
@click.option(
    "--proxy",
    help="Route all HTTP traffic through an intercepting proxy (e.g. Burp/Caido/Hetty: http://127.0.0.1:8080). TLS verification is disabled by default for proxied HTTPS targets. SOCKS5 proxies with auth are supported, e.g. socks5://user:pass@host:port.",
)
@click.option(
    "--proxy-verify-ssl",
    "proxy_verify_ssl",
    is_flag=True,
    help="Keep TLS certificate verification enabled when using --proxy (use after installing the proxy CA).",
)
@tls_options
@click.option(
    "--allow-cross-domain-redirects",
    "allow_cross_domain_redirects",
    is_flag=True,
    default=False,
    help="Follow redirects to other domains during discovery. By default discovery "
    "follows redirects only to the same domain as the originating request.",
)
@click.option(
    "--detect-secrets",
    "detect_secrets",
    is_flag=True,
    default=False,
    help="Scan each discovery response body and headers for secrets/leaked "
    "credentials (read-only; default: off). Matched values are redacted.",
)
@click.option(
    "--secret-patterns",
    "secret_patterns",
    metavar="PATH",
    default=None,
    callback=_validate_secret_patterns,
    help="Path to a JSON file mapping pattern names to regex strings used for "
    "secret detection. Defaults to the built-in patterns when not supplied.",
)
@click.option(
    "--include-path",
    "include_path",
    multiple=True,
    metavar="REGEX",
    help="Only persist discovered endpoints whose path or URL matches REGEX "
    "(storage-time scope). Repeatable. Exclude takes precedence over include.",
)
@click.option(
    "--exclude-path",
    "exclude_path",
    multiple=True,
    metavar="REGEX",
    help="Never persist discovered endpoints whose path or URL matches REGEX "
    "(storage-time scope). Repeatable. Takes precedence over --include-path.",
)
@click.option(
    "--include-status",
    "include_status",
    metavar="SELECTION",
    default=None,
    help="Only persist discovered endpoints whose status matches SELECTION: a "
    "status class like '2xx' or explicit codes/ranges like '200,404' or "
    "'200-300' (storage-time scope).",
)
@click.option(
    "--exclude-status",
    "exclude_status",
    metavar="SELECTION",
    default=None,
    help="Never persist discovered endpoints whose status matches SELECTION: a "
    "status class like '2xx' or explicit codes/ranges like '200,404' or "
    "'200-300' (storage-time scope). Takes precedence over --include-status.",
)
@click.option(
    "--recursion-status",
    "recursion_status",
    metavar="CLASSES",
    default=None,
    help="Restrict recursion to endpoints whose status class is in CLASSES: a "
    "comma-separated list of status classes like '2xx,3xx'. Only narrows the "
    "default VALID/AUTH_REQUIRED recursion; never relaxes it.",
)
@click.option(
    "--recursion-type",
    "recursion_type",
    metavar="TYPES",
    default=None,
    help="Restrict recursion to endpoints whose type is in TYPES: a comma-separated "
    "list of endpoint types like 'admin,api_version'. Only narrows the default "
    "recursion; never relaxes it.",
)
@click.option(
    "--spec-methods-only",
    "spec_methods_only",
    is_flag=True,
    default=False,
    help="When an OpenAPI/Postman spec is supplied, probe each path with ONLY "
    "the HTTP method(s) declared in the spec — the base --methods set is "
    "ignored for spec-seeded paths. Paths from the wordlist that are not "
    "in the spec continue using --methods as before.",
)
@click.option(
    "--quarantine-threshold",
    "quarantine_threshold",
    type=int,
    default=None,
    metavar="N",
    help="Halt discovery after N consecutive non-404 responses — the host is "
    "likely responding to every path (wildcard). Set to 0 to disable. "
    "Default: 10.",
)
@click.option(
    "--target-file",
    "target_file",
    default=None,
    type=click.Path(exists=True, readable=True, file_okay=True, dir_okay=False),
    metavar="FILE",
    help="Path to a plain-text file with one target URL per line (comments "
    "starting with # and blank lines are skipped). When supplied, "
    "--target is optional and each line is scanned in sequence. "
    "Lines without a scheme are auto-prefixed with https://.",
)
@click.option(
    "--max-hosts",
    "max_hosts",
    type=int,
    default=None,
    metavar="N",
    help="Maximum number of hosts to scan from --target-file (scans the first N).",
)
@click.option(
    "--parallel-hosts",
    "-j",
    "parallel_hosts",
    type=int,
    default=1,
    metavar="N",
    help="Maximum number of hosts to scan concurrently from --target-file. "
    "Each host runs in its own thread. Default: 1 (sequential).",
)
# ── Spec-file brute-force options (equivalent to `sj brute`) ─────────────────
@click.option(
    "--brute-spec",
    "brute_spec",
    is_flag=True,
    default=False,
    help="Brute-force common paths to find exposed API specification files "
    "(Swagger, OpenAPI, RAML, AsyncAPI, etc.). Runs instead of normal "
    "directory fuzzing when set. Equivalent to `sj brute`.",
)
@click.option(
    "--brute-spec-wordlist",
    "brute_spec_wordlist",
    default=None,
    type=click.Path(exists=True, readable=True),
    metavar="FILE",
    help="Custom wordlist for spec-brute mode (one path per line). "
    "Defaults to the built-in wordlists/spec_files.txt.",
)
@click.option(
    "--brute-spec-extensions",
    "brute_spec_extensions",
    is_flag=True,
    default=False,
    help="Append .json/.yaml/.yml to every wordlist entry during spec-brute, "
    "tripling coverage at the cost of more requests.",
)
@click.option(
    "--brute-spec-concurrency",
    "brute_spec_concurrency",
    type=int,
    default=20,
    metavar="N",
    help="Max concurrent requests during spec-brute (default: 20).",
)
@click.option(
    "--brute-spec-output",
    "brute_spec_output",
    default=None,
    type=click.Path(),
    metavar="FILE",
    help="Write spec-brute results to a JSON file.",
)
@click.pass_context
def dir(
    ctx,
    target,
    wordlist,
    openapi,
    postman,
    output,
    log_level,
    log_file,
    json_logs,
    rate_limit,
    methods,
    fuzz_keyword,
    fuzz_mode,
    depth,
    recursive,
    max_requests,
    concurrency,
    confirm_hits,
    timeout,
    retries,
    extensions,
    user_agent_random,
    user_agent_custom,
    user_agent_file,
    jwt,
    header,
    cookie,
    basic_auth,
    enumerate_methods,
    graphql,
    response,
    status_code,
    match_size,
    match_words,
    match_lines,
    match_regex,
    match_time,
    filter_size,
    filter_words,
    filter_lines,
    filter_regex,
    filter_time,
    detect_framework,
    fuzz_versions,
    save_session,
    load_session,
    checkpoint,
    resume,
    export_format,
    export_file,
    output_format,
    output_file,
    interactive,
    scan_scope,
    ci_mode,
    proxy,
    proxy_verify_ssl,
    client_cert,
    ca_bundle,
    allow_cross_domain_redirects,
    resolve,
    detect_secrets,
    secret_patterns,
    include_path,
    exclude_path,
    include_status,
    exclude_status,
    recursion_status,
    recursion_type,
    spec_methods_only,
    quarantine_threshold,
    target_file,
    max_hosts,
    parallel_hosts,
    brute_spec,
    brute_spec_wordlist,
    brute_spec_extensions,
    brute_spec_concurrency,
    brute_spec_output,
):
    """Directory/endpoint fuzzing - discover hidden endpoints and directories

    \b
    Examples:
      python apileaks.py dir --target https://api.example.com
      python apileaks.py dir --target URL --wordlist custom.txt --rate-limit 5
      python apileaks.py dir --target URL --user-agent-random --detect-framework
      python apileaks.py dir --target URL --save-session session.json --export md --export-file results.md
      python apileaks.py dir --target URL --load-session session.json --status-code 2xx
      python apileaks.py dir --target URL --load-session session.json --interactive
      python apileaks.py dir --target URL --interactive --ci-mode --save-session session.json
      python apileaks.py dir --target URL --proxy http://127.0.0.1:8080 --jwt TOKEN
      python apileaks.py dir --target-file hosts.txt --wordlist custom.txt
      python apileaks.py dir --target-file hosts.txt --max-hosts 50 --proxy http://127.0.0.1:8080

    \b
    Spec-file brute-force (equivalent to `sj brute`):
      python apileaks.py dir --target https://api.example.com --brute-spec
      python apileaks.py dir --target URL --brute-spec --proxy http://127.0.0.1:8080
      python apileaks.py dir --target URL --brute-spec --brute-spec-extensions
      python apileaks.py dir --target URL --brute-spec --brute-spec-wordlist custom_spec_paths.txt
      python apileaks.py dir --target URL --brute-spec --brute-spec-output results.json
    """

    # ── Spec-file brute-force mode (--brute-spec) ────────────────────────────
    # When --brute-spec is set, skip normal directory fuzzing entirely and run
    # the spec-file discovery engine instead. This is the apileaks equivalent
    # of `sj brute -u https://target.com`.
    if brute_spec:
        # Resolve target — required for brute-spec mode.
        brute_target = target
        if not brute_target and target_file:
            try:
                file_targets = parse_target_file(target_file)
            except click.BadParameter as exc:
                click.echo(f"Error: {exc}", err=True)
                sys.exit(1)
            brute_target = file_targets[0] if file_targets else None
        if not brute_target:
            click.echo(
                "Error: --brute-spec requires --target (or --target-file with at least one URL).",
                err=True,
            )
            sys.exit(1)

        no_banner = ctx.obj.get("no_banner", False) if ctx.obj else False
        if not no_banner:
            print_banner()

        _run_spec_brute(
            brute_target,
            brute_spec_wordlist=brute_spec_wordlist,
            brute_spec_extensions=brute_spec_extensions,
            proxy=proxy,
            timeout=timeout or 10.0,
            concurrency=brute_spec_concurrency,
            verify_ssl=not bool(proxy) or proxy_verify_ssl,
            jwt=jwt,
            header=header,
            user_agent_random=user_agent_random,
            user_agent_custom=user_agent_custom,
            output_file=brute_spec_output,
            quiet=ci_mode,
            logger=get_logger("brute-spec"),
        )
        return
    # ── End brute-spec mode ──────────────────────────────────────────────────

    # -------------------------------------------------------------------------
    # Multi-target resolution: build the ordered list of targets to scan.
    #
    # Priority: --target-file wins over --target when both are supplied (the
    # file may contain --target as well; --target becomes an implicit first
    # entry when --target-file is not used).
    #
    # --target is required unless --target-file is supplied.  We enforce this
    # manually here (Click's required=False allows both to be absent) so the
    # error message is user-friendly.
    # -------------------------------------------------------------------------
    if target_file:
        try:
            file_targets = parse_target_file(target_file)
        except click.BadParameter as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)
        if not file_targets:
            click.echo(f"Error: --target-file '{target_file}' contains no valid targets.", err=True)
            sys.exit(1)
        # Prepend a CLI --target when explicitly supplied alongside --target-file
        if target:
            all_targets = [target] + [t for t in file_targets if t != target]
        else:
            all_targets = file_targets
        if max_hosts is not None and max_hosts > 0:
            all_targets = all_targets[:max_hosts]
    elif target:
        all_targets = [target]
    else:
        click.echo(
            "Error: Either --target or --target-file must be supplied.\n"
            "  --target URL            scan a single host\n"
            "  --target-file FILE      scan every host listed in FILE",
            err=True,
        )
        sys.exit(1)

    # When there are multiple targets, run each one sequentially and print a
    # consolidated summary at the end.  Single-target runs go straight through
    # the existing code path without any extra wrapping so nothing changes.

    # Compute whether a marker-only option was explicitly supplied on the CLI.
    # ctx.get_parameter_source is only available here (in the Click command
    # function), so we resolve it once and forward it to _run_dir_core /
    # _run_dir_multi_target.
    marker_only_requested = (
        ctx.get_parameter_source("fuzz_keyword") == click.core.ParameterSource.COMMANDLINE
        or ctx.get_parameter_source("fuzz_mode") == click.core.ParameterSource.COMMANDLINE
    )

    if len(all_targets) > 1:
        _run_dir_multi_target(
            targets=all_targets,
            ctx=ctx,
            # Forward every option unchanged
            wordlist=wordlist,
            openapi=openapi,
            postman=postman,
            output=output,
            log_level=log_level,
            log_file=log_file,
            json_logs=json_logs,
            rate_limit=rate_limit,
            methods=methods,
            fuzz_keyword=fuzz_keyword,
            fuzz_mode=fuzz_mode,
            depth=depth,
            recursive=recursive,
            max_requests=max_requests,
            concurrency=concurrency,
            confirm_hits=confirm_hits,
            timeout=timeout,
            retries=retries,
            extensions=extensions,
            user_agent_random=user_agent_random,
            user_agent_custom=user_agent_custom,
            user_agent_file=user_agent_file,
            jwt=jwt,
            header=header,
            cookie=cookie,
            basic_auth=basic_auth,
            enumerate_methods=enumerate_methods,
            graphql=graphql,
            response=response,
            status_code=status_code,
            match_size=match_size,
            match_words=match_words,
            match_lines=match_lines,
            match_regex=match_regex,
            match_time=match_time,
            filter_size=filter_size,
            filter_words=filter_words,
            filter_lines=filter_lines,
            filter_regex=filter_regex,
            filter_time=filter_time,
            detect_framework=detect_framework,
            fuzz_versions=fuzz_versions,
            save_session=save_session,
            load_session=load_session,
            checkpoint=checkpoint,
            resume=resume,
            export_format=export_format,
            export_file=export_file,
            output_format=output_format,
            output_file=output_file,
            interactive=False,  # never interactive in multi-target mode
            scan_scope=scan_scope,
            ci_mode=ci_mode,
            proxy=proxy,
            proxy_verify_ssl=proxy_verify_ssl,
            client_cert=client_cert,
            ca_bundle=ca_bundle,
            allow_cross_domain_redirects=allow_cross_domain_redirects,
            resolve=resolve,
            detect_secrets=detect_secrets,
            secret_patterns=secret_patterns,
            include_path=include_path,
            exclude_path=exclude_path,
            include_status=include_status,
            exclude_status=exclude_status,
            recursion_status=recursion_status,
            recursion_type=recursion_type,
            spec_methods_only=spec_methods_only,
            quarantine_threshold=quarantine_threshold,
            marker_only_requested=marker_only_requested,
            parallel_hosts=parallel_hosts,
        )
        return

    # Single-target: reassign `target` from the resolved list so the rest of
    # the function uses exactly this value regardless of how it was supplied.
    target = all_targets[0]

    # Delegate to _run_dir_core which contains the full single-target pipeline.
    _single_result = _run_dir_core(
        target=target,
        ctx=ctx,
        wordlist=wordlist,
        openapi=openapi,
        postman=postman,
        output=output,
        log_level=log_level,
        log_file=log_file,
        json_logs=json_logs,
        rate_limit=rate_limit,
        methods=methods,
        fuzz_keyword=fuzz_keyword,
        fuzz_mode=fuzz_mode,
        depth=depth,
        recursive=recursive,
        max_requests=max_requests,
        concurrency=concurrency,
        confirm_hits=confirm_hits,
        timeout=timeout,
        retries=retries,
        extensions=extensions,
        user_agent_random=user_agent_random,
        user_agent_custom=user_agent_custom,
        user_agent_file=user_agent_file,
        jwt=jwt,
        header=header,
        cookie=cookie,
        basic_auth=basic_auth,
        enumerate_methods=enumerate_methods,
        graphql=graphql,
        response=response,
        status_code=status_code,
        match_size=match_size,
        match_words=match_words,
        match_lines=match_lines,
        match_regex=match_regex,
        match_time=match_time,
        filter_size=filter_size,
        filter_words=filter_words,
        filter_lines=filter_lines,
        filter_regex=filter_regex,
        filter_time=filter_time,
        detect_framework=detect_framework,
        fuzz_versions=fuzz_versions,
        save_session=save_session,
        load_session=load_session,
        checkpoint=checkpoint,
        resume=resume,
        export_format=export_format,
        export_file=export_file,
        output_format=output_format,
        output_file=output_file,
        interactive=interactive,
        scan_scope=scan_scope,
        ci_mode=ci_mode,
        proxy=proxy,
        proxy_verify_ssl=proxy_verify_ssl,
        client_cert=client_cert,
        ca_bundle=ca_bundle,
        allow_cross_domain_redirects=allow_cross_domain_redirects,
        resolve=resolve,
        detect_secrets=detect_secrets,
        secret_patterns=secret_patterns,
        include_path=include_path,
        exclude_path=exclude_path,
        include_status=include_status,
        exclude_status=exclude_status,
        recursion_status=recursion_status,
        recursion_type=recursion_type,
        spec_methods_only=spec_methods_only,
        quarantine_threshold=quarantine_threshold,
        marker_only_requested=marker_only_requested,
    )
    # Propagate errors from _run_dir_core so single-target failures still
    # exit non-zero (matches pre-refactor behavior where click.echo + sys.exit
    # were called directly in the command body).
    if _single_result and _single_result.get("error"):
        click.echo(f"Error: {_single_result['error']}", err=True)
        sys.exit(1)


def _build_discovery_progress(ci_mode, max_requests):
    """Build the live Progress_Display for the ``dir`` command (Requirement 32).

    The display is enabled only for an interactive session that is **not** in
    CI_Mode and whose standard output is a TTY:
    ``enabled = (not ci_mode) and sys.stdout.isatty()`` — the exact gating that
    governs the interactive triage prompt. This disables it in CI_Mode
    (Requirement 32.3) and when stdout is not a TTY so it never interferes with
    piped output (Requirement 32.4). ``total`` is the Request_Budget
    (``max_requests``); when ``None`` the display omits the consumed/remaining
    budget figures (Requirement 32.5).
    """
    enabled = (not ci_mode) and sys.stdout.isatty()
    return DiscoveryProgress(enabled=enabled, total=max_requests)


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
_SPEC_BODY_SIGNATURES = (
    # OpenAPI 3.x
    b'"openapi"',
    b"'openapi'",
    b"openapi:",
    # Swagger 2.x
    b'"swagger"',
    b"'swagger'",
    b"swagger:",
    # RAML
    b"#%RAML",
    # AsyncAPI
    b'"asyncapi"',
    b"asyncapi:",
    # API Blueprint
    b"FORMAT: 1A",
    # JSON:API / Hydra hints
    b'"@context"',
    # Generic doc hints
    b'"info"',
    b'"paths"',
    b'"components"',
    b'"definitions"',
    b'"basePath"',
    b'"host"',
)

# Default wordlist shipped with apileaks (relative to the script directory).
_DEFAULT_SPEC_WORDLIST = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "wordlists", "spec_files.txt"
)


def _load_spec_brute_wordlist(wordlist_path: str) -> list:
    """Load and normalise the brute-force wordlist, stripping blanks/comments."""
    entries = []
    try:
        with open(wordlist_path, encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    # Normalise leading slash — we build the full URL ourselves.
                    entries.append(stripped.lstrip("/"))
    except OSError as exc:
        raise click.BadParameter(
            f"--brute-spec-wordlist cannot be read: {wordlist_path} ({exc})"
        ) from exc
    return entries


def _looks_like_spec(status_code: int, body: bytes, content_type: str) -> bool:
    """Return True when the response is likely an API specification document.

    Checks:
    1. HTTP status is 2xx.
    2. Content-Type is JSON, YAML, or plain text (spec files are never HTML-only).
    3. The body contains at least one known spec keyword.
    """
    if not (200 <= status_code < 300):
        return False

    ct = (content_type or "").lower()
    # Reject obvious HTML pages (Swagger UI HTML is not the raw spec).
    if "text/html" in ct and "json" not in ct and "yaml" not in ct:
        return False

    body_lower = body[:4096].lower()  # only inspect the first 4 KB
    return any(sig.lower() in body_lower for sig in _SPEC_BODY_SIGNATURES)


async def _brute_spec_async(
    target: str,
    entries: list,
    *,
    proxy: str = None,
    timeout: float = 10.0,
    concurrency: int = 20,
    verify_ssl: bool = True,
    jwt: str = None,
    header: tuple = (),
    user_agent_random: bool = False,
    user_agent_custom: str = None,
    output_file: str = None,
    quiet: bool = False,
) -> list:
    """Async core: probe *entries* paths under *target* and return spec hits.

    Returns a list of dicts with keys: url, status, content_type, size, spec.
    ``spec`` is True when _looks_like_spec() matched.
    """
    import asyncio as _asyncio

    import httpx

    base = target.rstrip("/")
    hits = []
    sem = _asyncio.Semaphore(concurrency)

    # Build shared headers.
    extra_headers = parse_header_options(header)
    if jwt:
        extra_headers["Authorization"] = f"Bearer {jwt}"
    if user_agent_custom:
        extra_headers["User-Agent"] = user_agent_custom
    elif user_agent_random:
        import random as _random

        _ua_pool = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "curl/7.88.1",
            "python-httpx/0.24.0",
            "Swagger Jacker (github.com/BishopFox/sj)",
            "PostmanRuntime/7.32.2",
        ]
        extra_headers["User-Agent"] = _random.choice(_ua_pool)

    proxies = proxy if proxy else None
    total = len(entries)
    done = 0

    async with httpx.AsyncClient(
        verify=verify_ssl,
        proxy=proxies,
        timeout=timeout,
        follow_redirects=True,
        headers=extra_headers,
    ) as client:

        async def _probe(path: str):
            nonlocal done
            url = f"{base}/{path}"
            async with sem:
                try:
                    resp = await client.get(url)
                    ct = resp.headers.get("content-type", "")
                    body = resp.content
                    is_spec = _looks_like_spec(resp.status_code, body, ct)
                    result = {
                        "url": str(resp.url),
                        "status": resp.status_code,
                        "content_type": ct,
                        "size": len(body),
                        "spec": is_spec,
                    }
                    if not quiet:
                        if is_spec:
                            click.echo(
                                click.style(
                                    f"✓  {resp.status_code}  {url}  [{len(body)} bytes]  ← SPEC FOUND",
                                    fg="green",
                                    bold=True,
                                )
                            )
                        elif 200 <= resp.status_code < 300:
                            click.echo(
                                click.style(
                                    f"⚠  {resp.status_code}  {url}  [{len(body)} bytes]",
                                    fg="yellow",
                                )
                            )
                    return result
                except (httpx.RequestError, httpx.HTTPStatusError):
                    return None
                finally:
                    done += 1
                    if not quiet and sys.stdout.isatty():
                        # In-place progress counter (overwrite same line).
                        sys.stdout.write(f"\r  Probing: {done}/{total} requests sent")
                        sys.stdout.flush()

        tasks = [_probe(path) for path in entries]
        results = await _asyncio.gather(*tasks)

    if not quiet and sys.stdout.isatty():
        sys.stdout.write("\n")

    hits = [r for r in results if r is not None and r["status"] != 404]
    spec_hits = [r for r in hits if r["spec"]]
    return hits, spec_hits


def _run_spec_brute(
    target: str,
    *,
    brute_spec_wordlist: str = None,
    brute_spec_extensions: bool = False,
    proxy: str = None,
    timeout: float = 10.0,
    concurrency: int = 20,
    verify_ssl: bool = True,
    jwt: str = None,
    header: tuple = (),
    user_agent_random: bool = False,
    user_agent_custom: str = None,
    output_file: str = None,
    quiet: bool = False,
    logger=None,
):
    """Entry point for ``dir --brute-spec``.

    Loads the wordlist, probes every path under *target*, prints a summary
    table with ✓/⚠/✗ status indicators (matching sj's UX), and optionally
    writes results to a JSON file.

    Returns (hits, spec_hits) — all non-404 responses and the subset that
    look like valid spec files respectively.
    """
    if logger is None:
        logger = get_logger("brute-spec")

    # Resolve wordlist.
    wl_path = brute_spec_wordlist or _DEFAULT_SPEC_WORDLIST
    try:
        entries = _load_spec_brute_wordlist(wl_path)
    except click.BadParameter as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if not entries:
        click.echo("Error: spec-brute wordlist is empty.", err=True)
        sys.exit(1)

    # Optionally expand each entry with common spec extensions.
    if brute_spec_extensions:
        extra = []
        extensions = [".json", ".yaml", ".yml"]
        for entry in entries:
            for ext in extensions:
                if not entry.endswith(ext):
                    extra.append(entry + ext)
        entries = entries + extra

    click.echo(f"\n🔍 Spec-file brute-force: {target}")
    click.echo(f"   Wordlist : {wl_path}  ({len(entries)} paths)")
    click.echo(f"   Proxy    : {proxy or 'none'}")
    click.echo(f"   Timeout  : {timeout}s   Concurrency: {concurrency}")
    click.echo("─" * 60)

    hits, spec_hits = asyncio.run(
        _brute_spec_async(
            target,
            entries,
            proxy=proxy,
            timeout=timeout,
            concurrency=concurrency,
            verify_ssl=verify_ssl,
            jwt=jwt,
            header=header,
            user_agent_random=user_agent_random,
            user_agent_custom=user_agent_custom,
            output_file=output_file,
            quiet=quiet,
        )
    )

    # ── Summary ──────────────────────────────────────────────────────────────
    click.echo("─" * 60)
    click.echo(f"\n📊 Spec-Brute Summary: {target}")
    click.echo(f"   Paths probed   : {len(entries)}")
    click.echo(f"   Non-404 hits   : {len(hits)}")
    click.echo(
        click.style(
            f"   Spec files found: {len(spec_hits)}",
            fg="green" if spec_hits else "white",
            bold=bool(spec_hits),
        )
    )

    if spec_hits:
        click.echo("\n✅ API specification files discovered:")
        for hit in spec_hits:
            click.echo(
                click.style(
                    f"   → {hit['url']}  [{hit['status']}]  {hit['size']} bytes", fg="green"
                )
            )

    if hits and not spec_hits:
        click.echo("\n⚠️  Accessible paths found (not confirmed as spec files):")
        for hit in hits[:20]:  # cap at 20 to avoid flooding
            click.echo(f"   • {hit['url']}  [{hit['status']}]")
        if len(hits) > 20:
            click.echo(f"   … and {len(hits) - 20} more. Use --output to save full results.")

    # ── Optional JSON output ──────────────────────────────────────────────────
    if output_file and (hits or spec_hits):
        import json as _json

        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        payload = {
            "target": target,
            "wordlist": wl_path,
            "total_probed": len(entries),
            "hits": hits,
            "spec_hits": spec_hits,
        }
        with open(output_file, "w", encoding="utf-8") as fh:
            _json.dump(payload, fh, indent=2)
        click.echo(f"\n💾 Results saved: {output_file}")

    logger.info(
        "Spec-brute complete",
        target=target,
        probed=len(entries),
        hits=len(hits),
        spec_hits=len(spec_hits),
    )
    return hits, spec_hits


async def _discover_endpoints_for_triage(
    apileak_config,
    discovery_progress=None,
    checkpoint_path=None,
    resume_checkpoint=None,
    streaming_output_path=None,
):
    """Run discovery for the triage workflow and return endpoints + soft-404 baseline.

    Builds an :class:`APILeakCore`, executes a scan against the configured target
    (in ``dir`` mode no OWASP modules are enabled, so this is effectively the
    endpoint discovery phase), and returns the discovered ``Endpoint`` objects so
    the caller can project them into :class:`DiscoveryResult` records, together
    with the :class:`Soft404Baseline` derived from the catch-all probes (or
    ``None`` when no baseline was captured).

    Args:
        apileak_config: The loaded APILeak configuration.
        discovery_progress: Optional live Progress_Display (Requirement 32),
            attached to the core before discovery runs so the endpoint fuzzer can
            render live progress. ``None`` (or a disabled instance) runs discovery
            without a display.

    Returns:
        A ``(endpoints, soft_404_baseline)`` tuple. ``soft_404_baseline`` is
        ``None`` when the discovery probes did not yield a single signature.
    """
    core = APILeakCore(apileak_config)

    # Attach the live Progress_Display (if any) before discovery runs so the
    # endpoint fuzzer can render it (Requirement 32).
    if discovery_progress is not None:
        core.discovery_progress = discovery_progress

    # Attach the resume/checkpoint state (Requirement 37) before discovery runs,
    # mirroring run_enhanced_apileak: ``checkpoint_path`` enables periodic writes
    # and ``resume_checkpoint`` (a pre-loaded DiscoveryCheckpoint) seeds the
    # fuzzer before discovery. Both default to None, leaving discovery unchanged.
    if checkpoint_path is not None:
        core.discovery_checkpoint_path = checkpoint_path
    if resume_checkpoint is not None:
        core.discovery_resume_checkpoint = resume_checkpoint

    # Streaming JSONL output: stash the path on the core so
    # _ensure_fuzzing_orchestrator can open the handle and attach it to the
    # EndpointFuzzer before any discovery request is issued.
    if streaming_output_path and streaming_output_path.endswith(".jsonl"):
        core.discovery_streaming_output_path = streaming_output_path

    health_status = await core.health_check()
    if health_status.get("status") != "healthy":
        get_logger("dir").warning("Health check indicates issues", status=health_status)

    try:
        await core.run_scan(apileak_config.target.base_url)
    finally:
        # Close the streaming handle cleanly even if the scan raised.
        orchestrator = getattr(core, "fuzzing_orchestrator", None)
        fuzzer = getattr(orchestrator, "endpoint_fuzzer", None) if orchestrator else None
        if fuzzer is not None and fuzzer.streaming_output_handle is not None:
            try:
                fuzzer.streaming_output_handle.close()
            except OSError as exc:
                get_logger("dir").debug("Failed to close streaming output handle", error=str(exc))
            fuzzer.streaming_output_handle = None

    _echo_discovery_control_status(core)

    # Reach the endpoint fuzzer defensively to derive the Soft_404_Baseline from
    # the catch-all probes that already ran (Requirement 22.5); deriving it issues
    # no extra requests. Absence of a fuzzer/baseline simply means no soft-404
    # suppression is applied.
    orchestrator = getattr(core, "fuzzing_orchestrator", None)
    fuzzer = getattr(orchestrator, "endpoint_fuzzer", None)
    soft_404_baseline = calibrate_soft_404(fuzzer) if fuzzer is not None else None

    return core.get_discovered_endpoints(), soft_404_baseline


def _select_records(
    records,
    *,
    endpoints=None,
    matchers,
    filters,
    soft_404_baseline,
):
    """Apply response selection as a post-discovery projection (Requirement 22).

    Builds in-memory-only :class:`DiscoveryResultEx` views over ``records`` (the
    persisted :class:`DiscoveryResult` projection is never widened, so the
    Requirement 14 session round-trip stays intact), applies the matchers and
    filters conjunctively (Requirements 22.2-22.4), then **independently** drops
    any record matching the Soft_404_Baseline (Requirements 22.6, 22.8). Returns
    the retained :class:`DiscoveryResult` records in their original relative
    order.

    These selections (response matchers/filters and soft-404 noise suppression)
    narrow the records that feed the table, session, export, and interactive
    selection. The existing ``Status_Code_Filter`` (Requirement 13) is applied
    separately as a **display-only** filter by the table renderer and the
    interactive prompt, so it never omits records from the persisted session or
    export (Requirement 14.1); the displayed/triaged set therefore still
    satisfies the status filter, matchers, and filters conjunctively
    (Requirement 22.7).

    When ``endpoints`` is provided it is aligned positionally with ``records``
    and supplies each view's response ``size`` and ``elapsed`` from the
    ``Endpoint``. The discovered ``Endpoint`` does not retain the response body
    text, so the word/line counts are best-effort ``0`` and the regex predicate
    sees an empty body. When ``endpoints`` is ``None`` (a reloaded session),
    those attributes default to ``0`` because the session file does not persist
    them.
    """
    if endpoints is not None:
        views = [
            DiscoveryResultEx(
                result=record,
                size=getattr(endpoint, "response_size", 0) or 0,
                words=0,  # Endpoint does not retain the response body text
                lines=0,  # Endpoint does not retain the response body text
                elapsed=getattr(endpoint, "response_time", 0.0) or 0.0,
                text="",
            )
            for record, endpoint in zip(records, endpoints, strict=False)
        ]
    else:
        views = [DiscoveryResultEx(result=record) for record in records]

    # Matchers + filters combine conjunctively (Requirements 22.2-22.4).
    selected = apply_selectors(views, matchers, filters)

    # Soft-404 suppression is applied independently of the matchers/filters and
    # of catch-all suppression: a record removed by either mechanism is excluded
    # (Requirements 22.6, 22.8).
    if soft_404_baseline is not None:
        selected = [view for view in selected if not soft_404_baseline.matches(view)]

    return [view.result for view in selected]


def _run_dir_triage(
    *,
    target,
    wordlist_path,
    candidate_set,
    seed_methods,
    output,
    rate_limit,
    methods,
    fuzz_keyword="FUZZ",
    fuzz_mode="clusterbomb",
    marker_wordlists=None,
    user_agent_random,
    user_agent_custom,
    user_agent_file,
    jwt,
    header,
    cookie,
    basic_auth,
    response,
    status_code,
    matchers,
    filters,
    detect_framework,
    fuzz_versions,
    save_session,
    load_session,
    export_format,
    export_file,
    output_format,
    output_file,
    interactive,
    scan_scope,
    ci_mode,
    proxy,
    proxy_verify_ssl,
    client_cert=None,
    ca_bundle=None,
    allow_cross_domain_redirects=False,
    resolve=None,
    detect_secrets=False,
    secret_patterns=None,
    path_scope=None,
    storage_status=None,
    checkpoint=None,
    resume_checkpoint=None,
    openapi_sources=None,
    postman_sources=None,
    spec_methods_only=False,
    quarantine_threshold=None,
    logger,
):
    """Run the discovery triage workflow for the ``dir`` command.

    Sources :class:`DiscoveryResult` records either from a reloaded
    ``Discovery_Session_File`` (``--load-session``; the session file is the sole
    source of truth, Requirements 14.6, 14.7) or from a fresh discovery whose
    ``Endpoint`` objects are projected into records. It then parses the optional
    status filter (Requirement 13.5), renders the triage table grouped by status
    class (Requirements 15.1-15.7), saves the full record set to a session file
    when requested (Requirements 14.1, 14.2), and writes a human-readable export
    grouped by status class when requested (Requirements 14.3-14.5).

    Filter, persistence, and export failures are surfaced as CLI errors.
    """
    from rich.console import Console

    console = Console()

    try:
        # Parse the optional status filter up front so an out-of-range explicit
        # code is reported before any discovery or I/O (Requirements 13.5, 13.6).
        status_filter = parse_status_filter(status_code) if status_code else None

        # Source the Discovery_Result records: reload is the source of truth and
        # skips discovery entirely (Requirements 14.6, 14.7, 15.6, 16.5).
        endpoints = None
        soft_404_baseline = None
        if load_session:
            session = DiscoverySession.load(load_session)
            records = list(session.results)
            logger.info("Loaded discovery session", path=load_session, records=len(records))
        else:
            # Build the discovery configuration exactly as the standard dir path.
            user_agent_config = None
            if user_agent_random:
                user_agent_config = {"random": True}
            elif user_agent_custom:
                user_agent_config = {"custom": user_agent_custom}
            elif user_agent_file:
                user_agents = load_user_agents_from_file(user_agent_file)
                user_agent_config = {"file_list": user_agents}

            output_filename = prepare_output_filename(output)

            advanced_config = {
                "detect_framework": detect_framework,
                "fuzz_versions": fuzz_versions,
                "framework_confidence": 0.6,
            }

            status_code_filter = parse_status_codes(status_code) if status_code else None

            # Parse operator-supplied discovery headers, cookie, and basic-auth
            # so the triage discovery path applies them to every Discovery_Request
            # exactly like the standard dir path (Requirements 24.2, 24.3, 24.4).
            extra_headers = parse_header_options(header)
            if cookie:
                extra_headers["Cookie"] = cookie
            basic_auth_creds = parse_basic_auth(basic_auth)

            config_dict = create_default_config(
                target,
                wordlist_path,
                "dir",
                user_agent_config,
                output_filename,
                advanced_config,
                status_code_filter,
                extra_headers,
                basic_auth_creds,
            )
            config_dict["proxy"] = proxy
            config_dict["proxy_verify_ssl"] = proxy_verify_ssl
            # Thread transport/TLS options for discovery (Requirement 29) exactly
            # like the standard dir path. The CLI validators have already
            # parsed/validated these before any discovery runs.
            config_dict["client_cert"] = client_cert
            config_dict["ca_bundle"] = ca_bundle
            config_dict["resolve"] = resolve
            config_dict["fuzzing"]["endpoints"]["allow_cross_domain_redirects"] = (
                allow_cross_domain_redirects
            )

            # Thread the Secret_Detection toggle and optional custom
            # Secret_Patterns into the secret_scan config exactly like the
            # standard dir path (Requirement 30.1/30.6).
            config_dict.setdefault("secret_scan", {})
            config_dict["secret_scan"]["enabled"] = detect_secrets
            if secret_patterns is not None:
                config_dict["secret_scan"]["patterns"] = secret_patterns

            # Thread the merged in-memory candidate set and per-seed methods into
            # the triage discovery config exactly like the standard dir path
            # (Requirements 25.3, 25.4); None preserves the single-file path.
            if candidate_set is not None:
                config_dict["fuzzing"]["endpoints"]["candidate_set"] = candidate_set
                config_dict["fuzzing"]["endpoints"]["seed_methods"] = seed_methods

            # Spec-aware mode: attach the full SpecSchema so the EndpointFuzzer
            # sends contextually correct requests for each spec-declared route.
            _triage_spec_schema = _build_dir_spec_schema(openapi_sources, postman_sources)
            if _triage_spec_schema is not None:
                config_dict["fuzzing"]["endpoints"]["spec_schema"] = _triage_spec_schema
            config_dict["fuzzing"]["endpoints"]["spec_methods_only"] = spec_methods_only
            # Thread quarantine_threshold so --quarantine-threshold N is honored
            # in the triage (interactive/session) path just like the direct path
            # (BUG-012 fix).
            if quarantine_threshold is not None:
                config_dict["fuzzing"]["endpoints"]["quarantine_threshold"] = quarantine_threshold

            if rate_limit:
                config_dict["rate_limiting"]["requests_per_second"] = rate_limit
            if methods:
                config_dict["fuzzing"]["endpoints"]["methods"] = [
                    m.strip() for m in methods.split(",")
                ]
            # Thread the resolved marker-mode selection into the triage discovery
            # config exactly like the standard dir path (Requirements 39.1, 43.1,
            # 39.3). marker_wordlists is None when the target has no keyword.
            config_dict["fuzzing"]["endpoints"]["fuzz_keyword"] = fuzz_keyword
            config_dict["fuzzing"]["endpoints"]["fuzz_mode"] = fuzz_mode
            config_dict["fuzzing"]["endpoints"]["marker_wordlists"] = marker_wordlists
            if jwt:
                config_dict["authentication"]["contexts"][0]["token"] = jwt
                config_dict["authentication"]["contexts"][0]["type"] = "bearer"
            if response:
                config_dict["fuzzing"]["response_filter"] = parse_response_codes(response)

            # Thread the storage-time Path_Scope and Storage_Status_Selection
            # onto the triage discovery config exactly like the standard dir
            # path so dropped records never enter the session/export/table
            # (Requirements 33.1-33.7). Only the live-discovery branch applies
            # these; the --load-session reload above sources records from the
            # session file and performs no discovery.
            config_dict["fuzzing"]["path_scope"] = path_scope
            config_dict["fuzzing"]["storage_status"] = storage_status

            config_manager = ConfigurationManager()
            apileak_config = config_manager.load_config_from_dict(config_dict)

            validation_errors = config_manager.validate_configuration()
            if validation_errors:
                logger.error("Configuration validation failed", errors=validation_errors)
                for error in validation_errors:
                    click.echo(f"Error: {error}", err=True)
                sys.exit(1)

            # Resolve the streaming output path: when the operator wants JSONL,
            # activate streaming so hits appear in real time. The same path is
            # used for both streaming AND the end-of-scan write so the file is
            # complete whether or not streaming succeeded.
            _streaming_path = None
            if output_format == "jsonl" or (output_file and output_file.endswith(".jsonl")):
                if output_file:
                    _streaming_path = output_file
                else:
                    os.makedirs("reports", exist_ok=True)
                    _streaming_path = os.path.join("reports", "discovery_output.jsonl")

            endpoints, soft_404_baseline = asyncio.run(
                _discover_endpoints_for_triage(
                    apileak_config,
                    _build_discovery_progress(ci_mode, apileak_config.fuzzing.max_requests),
                    checkpoint_path=checkpoint,
                    resume_checkpoint=resume_checkpoint,
                    streaming_output_path=_streaming_path,
                )
            )
            records = [DiscoveryResult.from_endpoint(endpoint) for endpoint in endpoints]
            logger.info("Projected discovery results", records=len(records))

        # Apply response matchers/filters and soft-404 suppression as a pure
        # post-discovery projection so the table, session, export, machine
        # output, and interactive selection all see the already-selected set
        # (Requirement 22). The Status_Code_Filter stays a display-only filter
        # (applied by the table/interactive helpers below), so it never omits
        # records from the persisted session/export (Requirement 14.1). Catch-all
        # suppression (applied during recursion) and soft-404 suppression remain
        # independent mechanisms.
        records = _select_records(
            records,
            endpoints=endpoints,
            matchers=matchers,
            filters=filters,
            soft_404_baseline=soft_404_baseline,
        )

        # Render the triage table from in-memory records, applying the filter to
        # the displayed rows (Requirements 15.1-15.5, 15.7).
        table = render_triage_table(records, status_filter)
        console.print(table)

        # Persist the full record set as the source-of-truth session file. Every
        # record is written, with none omitted (Requirements 14.1, 14.2).
        if save_session:
            session = DiscoverySession(
                target=target,
                timestamp=datetime.now(UTC).isoformat(),
                tool_version=APILEAK_VERSION,
                results=records,
            )
            session.save(save_session)
            click.echo(f"💾 Discovery session saved: {save_session}")

        # Write the human-readable export grouped by status class. The export path
        # extension selects the format and an unsupported format is rejected
        # without writing anything (Requirements 14.3-14.5).
        if export_format or export_file:
            if export_file:
                export_path = export_file
            else:
                output_dir = "reports"
                os.makedirs(output_dir, exist_ok=True)
                export_path = os.path.join(output_dir, f"discovery_export.{export_format}")
            write_discovery_export(records, export_path)
            click.echo(f"📄 Discovery export written: {export_path}")

        # Write the machine-readable discovery output (CSV/JSONL). This is
        # additional to the JSON session file (which remains the reload source of
        # truth) and to the human-readable export. The output path extension
        # selects the format; an unsupported format is rejected without writing
        # anything (Requirements 31.1, 31.4) and a write failure is surfaced as a
        # CLI error (Requirement 31.5).
        if output_format or output_file:
            if output_file:
                # Pass the user-supplied path through as-is and let
                # write_discovery_output validate the extension.
                output_path = output_file
            else:
                output_dir = "reports"
                os.makedirs(output_dir, exist_ok=True)
                output_path = os.path.join(output_dir, f"discovery_output.{output_format}")
            write_discovery_output(records, output_path)
            click.echo(f"📄 Discovery output written: {output_path}")

        # Define the follow-up scan callables used by both the non-interactive
        # --scan-scope path and the interactive triage selection below.
        def _follow_up(selected):
            _run_targeted_follow_up_scan(
                selected,
                rate_limit=rate_limit,
                user_agent_random=user_agent_random,
                user_agent_custom=user_agent_custom,
                user_agent_file=user_agent_file,
                jwt=jwt,
                response=response,
                output=output,
                detect_framework=detect_framework,
                fuzz_versions=fuzz_versions,
                header=header,
                cookie=cookie,
                basic_auth=basic_auth,
                proxy=proxy,
                proxy_verify_ssl=proxy_verify_ssl,
                logger=logger,
            )

        # Batch_Scan_Scope: launch one scoped OWASP scan over N selected records,
        # rebuilding the same rate-limit/User-Agent/header/auth config the
        # originating dir invocation used (Requirements 36.1, 36.3, 36.5). An
        # empty determined scope is reported as "nothing to scan" by the helper
        # (Requirement 36.6).
        def _batch_follow_up(selected_records):
            _run_scoped_owasp_scan(
                selected_records,
                target=target,
                rate_limit=rate_limit,
                user_agent_random=user_agent_random,
                user_agent_custom=user_agent_custom,
                user_agent_file=user_agent_file,
                jwt=jwt,
                response=response,
                output=output,
                detect_framework=detect_framework,
                fuzz_versions=fuzz_versions,
                header=header,
                cookie=cookie,
                basic_auth=basic_auth,
                proxy=proxy,
                proxy_verify_ssl=proxy_verify_ssl,
                logger=logger,
            )

        # A non-interactive --scan-scope determines the Batch_Scan_Scope from all
        # matching records and drives the scoped OWASP scan directly, with no
        # interactive prompt. In CI_Mode this is the ONLY way the scope is
        # determined and it never blocks (Requirements 36.2, 36.4). The token was
        # already validated up front, so selection cannot raise here.
        if scan_scope is not None:
            scoped_records = select_scope_records(records, scan_scope)
            _batch_follow_up(scoped_records)
            return

        # Interactive triage selection (opt-in). The helper enforces the full
        # contract: it is disabled by default, never prompts in CI mode, skips an
        # empty (filtered) table, bounds invalid selections to 3 consecutive
        # attempts, launches exactly one Targeted_Follow_Up_Scan on a single
        # valid selection, and launches one Batch_Scan_Scope OWASP scan on a
        # multi-index selection (Requirements 16.1-16.4, 16.6-16.8, 36.1).
        run_interactive_triage(
            records,
            ci_mode,
            interactive,
            status_filter=status_filter,
            follow_up=_follow_up,
            batch_follow_up=_batch_follow_up,
        )

    except ValueError as exc:
        # Invalid status filter (e.g. an out-of-range explicit code) — Req 13.6.
        logger.error("Discovery triage filter error", error=str(exc))
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    except DiscoverySessionError as exc:
        # Session persistence/reload failures — Requirements 14.2, 14.9, 14.10.
        logger.error("Discovery session error", error=str(exc))
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    except DiscoveryCheckpointError as exc:
        # Checkpoint write failure during a checkpointed (and possibly resumed)
        # triage discovery run — Requirement 37.6. The atomic save leaves no
        # partial file behind; surface the descriptive message as a CLI error.
        logger.error("Discovery checkpoint error", error=str(exc))
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    except DiscoveryExportError as exc:
        # Unsupported/failed human-readable export — Requirement 14.4.
        logger.error("Discovery export error", error=str(exc))
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    except DiscoveryOutputError as exc:
        # Unsupported machine-readable output format or write failure —
        # Requirements 31.4, 31.5. UnsupportedOutputFormatError is a subclass of
        # DiscoveryOutputError, so both are surfaced here as a CLI error.
        logger.error("Discovery output error", error=str(exc))
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001 - surface any other failure as a CLI error
        logger.error("Directory triage failed", error=str(exc))
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


class ScanScopeError(ValueError):
    """Raised when a ``--scan-scope`` value is not a recognized Status_Code_Class
    or EndpointStatus (Requirement 36.7).

    Subclasses :class:`ValueError` so the existing ``dir`` triage error handling
    surfaces it as a descriptive CLI error performing no scan.
    """


# Recognized non-interactive Batch_Scan_Scope selectors (Requirement 36.2): the
# four Status_Code_Class tokens and the two selectable EndpointStatus values.
SCAN_SCOPE_STATUS_CLASSES = ("2xx", "3xx", "4xx", "5xx")
SCAN_SCOPE_ENDPOINT_STATUSES = ("valid", "auth_required")


def select_scope_records(records, scan_scope):
    """Return every :class:`DiscoveryResult` matching the Batch_Scan_Scope token.

    The ``scan_scope`` token is one of the four Status_Code_Class values
    (``2xx``/``3xx``/``4xx``/``5xx``) or one of the selectable EndpointStatus
    values (``valid``/``auth_required``), selecting all matching records as the
    scope for an OWASP scan (Requirement 36.2). An unrecognized token raises a
    descriptive :class:`ScanScopeError` naming the value and selects nothing
    (Requirement 36.7).

    Args:
        records: The in-memory ``DiscoveryResult`` records to filter.
        scan_scope: The raw ``--scan-scope`` token.

    Returns:
        The list of records that match the scope (possibly empty).

    Raises:
        ScanScopeError: If ``scan_scope`` is not a recognized token.
    """
    token = (scan_scope or "").strip().lower()
    if token in SCAN_SCOPE_STATUS_CLASSES:
        return [r for r in records if status_code_class(r.status_code) == token]
    if token in SCAN_SCOPE_ENDPOINT_STATUSES:
        return [r for r in records if r.endpoint_status == token]
    raise ScanScopeError(
        f"Unrecognized --scan-scope value '{scan_scope}': expected one of "
        f"2xx, 3xx, 4xx, 5xx, valid, auth_required."
    )


def run_interactive_triage(
    records,
    ci_mode,
    interactive_flag,
    *,
    status_filter=None,
    follow_up=None,
    batch_follow_up=None,
    prompt_func=None,
    echo=None,
    max_invalid_attempts=3,
):
    """Run the opt-in interactive triage selection prompt (Requirement 16).

    Interactive triage is **disabled by default** and is engaged only when the
    caller explicitly opts in via ``interactive_flag`` (Requirement 16.4). It is
    **automatically disabled while CI_Mode is active** so no prompt is ever shown
    and execution continues without blocking a pipeline (Requirement 16.3). When
    the (filtered) record set is empty the prompt is skipped and no follow-up
    scan is initiated (Requirement 16.8).

    Otherwise the function presents the filtered records (in the same ascending
    status-class order as the triage table) and prompts for a selection
    (Requirement 16.1). The selection may name a single index, or multiple
    indices/ranges (e.g. ``1,3,5`` or ``2-4``). A single-index selection invokes
    ``follow_up`` exactly once with the chosen :class:`DiscoveryResult`,
    launching a single ``Targeted_Follow_Up_Scan`` scoped to that endpoint
    (Requirement 16.2). A selection of two or more records instead invokes
    ``batch_follow_up`` once with the selected records, defining a
    ``Batch_Scan_Scope`` (Requirement 36.1). An invalid selection re-prompts
    without starting a scan, up to a maximum of 3 consecutive invalid attempts;
    after the 3rd the function exits interactive mode without a scan and prints a
    "selection abandoned" message (Requirements 16.6, 16.7).

    Args:
        records: The in-memory discovery records (already the reload source of
            truth when ``--load-session`` was used, Requirement 16.5).
        ci_mode: Whether CI_Mode is active; ``True`` disables the prompt.
        interactive_flag: The explicit opt-in flag; ``False`` disables the prompt.
        status_filter: The parsed status filter so the selectable set matches the
            displayed (filtered) table.
        follow_up: Callable invoked with the selected record to launch the
            single-endpoint targeted follow-up scan. Optional so the selection
            logic stays testable in isolation.
        batch_follow_up: Callable invoked with the list of selected records when
            two or more are chosen, launching a Batch_Scan_Scope OWASP scan
            (Requirement 36.1). Optional.
        prompt_func: Callable taking a prompt message and returning the raw user
            input; defaults to a ``click.prompt`` wrapper. Injectable for tests.
        echo: Callable used for output; defaults to :func:`click.echo`.
        max_invalid_attempts: Maximum consecutive invalid selections before the
            prompt is abandoned (defaults to 3, Requirement 16.6).

    Returns:
        The selected :class:`DiscoveryResult` for a single-index selection, the
        list of selected records for a multi-index selection, otherwise ``None``
        (disabled, CI mode, empty table, or abandoned).
    """
    log = get_logger("dir")
    echo = echo or click.echo

    # Opt-in: disabled by default (Requirement 16.4).
    if not interactive_flag:
        return None

    # Automatically disabled in CI mode — no prompt, never blocks (Req 16.3).
    if ci_mode:
        log.info("Interactive triage disabled in CI mode")
        return None

    # Build the displayed record list in the same filtered, ascending
    # status-class order used by the triage table so selection indices line up
    # with what the user sees (Requirements 16.1, 15.4, 15.5).
    filtered = apply_status_filter(records, status_filter)
    grouped = group_by_status_class(filtered)
    displayed = [record for class_records in grouped.values() for record in class_records]

    # Empty (filtered) table: skip the prompt, initiate no scan (Req 16.8).
    if not displayed:
        log.info("Interactive triage skipped: no records to display")
        return None

    if prompt_func is None:

        def prompt_func(message):
            return click.prompt(message, default="", show_default=False)

    echo("\nSelect endpoint(s) for a follow-up scan:")
    echo(
        "  Enter a single index for a targeted scan, or multiple "
        "indices/ranges (e.g. 1,3,5 or 2-4) for a batch OWASP scan."
    )
    for index, record in enumerate(displayed, start=1):
        echo(f"  {index}. [{record.status_code}] {record.method} {record.url}")

    invalid_attempts = 0
    while invalid_attempts < max_invalid_attempts:
        try:
            raw = prompt_func(f"Enter selection (1-{len(displayed)})")
        except (EOFError, click.Abort):
            raw = ""

        selection = (raw or "").strip()
        chosen_indices = _parse_selection_indices(selection, len(displayed))

        if chosen_indices is None:
            # Invalid selection: re-prompt without launching a scan (Req 16.6).
            invalid_attempts += 1
            remaining = max_invalid_attempts - invalid_attempts
            if remaining > 0:
                echo(
                    f"Invalid selection. Please try again ({remaining} attempt(s) remaining).",
                    err=True,
                )
            continue

        selected_records = [displayed[index - 1] for index in chosen_indices]

        if len(selected_records) >= 2:
            # Two or more records: define a Batch_Scan_Scope (Req 36.1) and launch
            # a single scoped OWASP scan over the selected set.
            log.info(
                "Interactive triage batch selection",
                endpoints=len(selected_records),
            )
            if batch_follow_up is not None:
                batch_follow_up(selected_records)
            return selected_records

        # Single record: launch exactly one Targeted_Follow_Up_Scan (Req 16.2).
        selected = selected_records[0]
        log.info(
            "Interactive triage selection",
            url=selected.url,
            method=selected.method,
        )
        if follow_up is not None:
            follow_up(selected)
        return selected

    # 3 consecutive invalid selections: abandon without a scan (Req 16.6, 16.7).
    echo(
        "Selection abandoned after 3 invalid attempts. No follow-up scan was started.",
        err=True,
    )
    log.info("Interactive triage abandoned after invalid selections")
    return None


def _run_targeted_follow_up_scan(
    selected,
    *,
    rate_limit,
    user_agent_random,
    user_agent_custom,
    user_agent_file,
    jwt,
    response,
    output,
    detect_framework,
    fuzz_versions,
    header=(),
    cookie=None,
    basic_auth=None,
    proxy=None,
    proxy_verify_ssl=False,
    logger,
):
    """Launch one ``Targeted_Follow_Up_Scan`` scoped to ``selected`` (Req 16.2).

    Reuses the existing discovery/scan path (:func:`run_enhanced_apileak`) but
    scopes it to the single selected endpoint by using the record's URL as the
    scan target and restricting the tested methods to the selected method.

    Args:
        selected: The :class:`DiscoveryResult` chosen by the user.
        rate_limit, user_agent_*, jwt, response, output, detect_framework,
        fuzz_versions: The same discovery options passed to the ``dir`` command,
            so the follow-up honors the user's original settings.
        header, cookie, basic_auth: The same Discovery_Header_Option values
            supplied to the originating ``dir`` invocation, re-applied to the
            scoped config so the follow-up scan sends them on every request
            (Requirement 24.7).
        logger: The command logger.
    """
    logger.info(
        "Targeted follow-up scan starting",
        url=selected.url,
        method=selected.method,
    )
    click.echo(f"🎯 Starting targeted follow-up scan: {selected.method} {selected.url}")

    user_agent_config = None
    if user_agent_random:
        user_agent_config = {"random": True}
    elif user_agent_custom:
        user_agent_config = {"custom": user_agent_custom}
    elif user_agent_file:
        user_agents = load_user_agents_from_file(user_agent_file)
        user_agent_config = {"file_list": user_agents}

    output_filename = prepare_output_filename(output)

    advanced_config = {
        "detect_framework": detect_framework,
        "fuzz_versions": fuzz_versions,
        "framework_confidence": 0.6,
    }

    # Re-apply the operator-supplied discovery headers, cookie, and basic-auth so
    # the Targeted_Follow_Up_Scan inherits the same Discovery_Header_Option values
    # as the originating dir invocation (Requirement 24.7). The cookie rides the
    # same custom_headers path as --header.
    extra_headers = parse_header_options(header)
    if cookie:
        extra_headers["Cookie"] = cookie
    basic_auth_creds = parse_basic_auth(basic_auth)

    # Scope the scan to the single selected endpoint URL (no wordlist expansion).
    config_dict = create_default_config(
        selected.url,
        None,
        "dir",
        user_agent_config,
        output_filename,
        advanced_config,
        None,
        extra_headers,
        basic_auth_creds,
    )
    config_dict["proxy"] = proxy
    config_dict["proxy_verify_ssl"] = proxy_verify_ssl

    if rate_limit:
        config_dict["rate_limiting"]["requests_per_second"] = rate_limit
    # Restrict to the selected endpoint's method so the follow-up stays scoped.
    config_dict["fuzzing"]["endpoints"]["methods"] = [selected.method]
    if jwt:
        config_dict["authentication"]["contexts"][0]["token"] = jwt
        config_dict["authentication"]["contexts"][0]["type"] = "bearer"
    if response:
        config_dict["fuzzing"]["response_filter"] = parse_response_codes(response)

    config_manager = ConfigurationManager()
    apileak_config = config_manager.load_config_from_dict(config_dict)

    validation_errors = config_manager.validate_configuration()
    if validation_errors:
        logger.error(
            "Targeted follow-up scan configuration invalid",
            errors=validation_errors,
        )
        for error in validation_errors:
            click.echo(f"Error: {error}", err=True)
        return

    asyncio.run(run_enhanced_apileak(apileak_config))


def _run_scoped_owasp_scan(
    selected_records,
    *,
    target,
    rate_limit,
    user_agent_random,
    user_agent_custom,
    user_agent_file,
    jwt,
    response,
    output,
    detect_framework=False,
    fuzz_versions=False,
    header=(),
    cookie=None,
    basic_auth=None,
    proxy=None,
    proxy_verify_ssl=False,
    logger,
):
    """Launch one OWASP scan scoped to ``selected_records`` (Batch_Scan_Scope, Req 36).

    Generalizes :func:`_run_targeted_follow_up_scan` from a single endpoint to N
    selected :class:`DiscoveryResult` records. The selected set is threaded into
    ``run_enhanced_apileak(..., scope_endpoints=...)`` which seeds
    ``APILeakCore.run_scan(scope_endpoints=...)``, so the OWASP modules consume
    exactly the seeded endpoints and wordlist discovery is skipped
    (Requirements 36.3, 36.8). The scan runs through the Full_Command engine scan
    path so the OWASP_Modules execute against the seeded set.

    The same Rate_Limit, User_Agent_Option, Discovery_Header_Option, and auth
    values supplied to the originating ``dir`` invocation are rebuilt onto the
    scoped config so every request the scan issues inherits them
    (Requirement 36.5).

    An empty determined scope performs no scan and reports that there is nothing
    to scan (Requirement 36.6).

    Args:
        selected_records: The selected :class:`DiscoveryResult` records forming
            the Batch_Scan_Scope.
        target: The originating ``dir`` target URL, used as the scan's base URL.
        rate_limit, user_agent_*, jwt, response, output, detect_framework,
        fuzz_versions: The same discovery options supplied to the ``dir`` command,
            re-applied so the scoped scan honors the operator's settings.
        header, cookie, basic_auth: The same Discovery_Header_Option values
            supplied to the originating ``dir`` invocation, re-applied so the
            scoped scan sends them on every request (Requirement 36.5).
        proxy, proxy_verify_ssl: Proxy settings carried through unchanged.
        logger: The command logger.
    """
    # Empty determined scope: perform no scan, report nothing to scan (Req 36.6).
    if not selected_records:
        logger.info("Scoped OWASP scan skipped: empty scope")
        click.echo("Nothing to scan: the selected scope contains no endpoints.")
        return

    logger.info(
        "Scoped OWASP scan starting",
        endpoints=len(selected_records),
    )
    click.echo(f"🎯 Starting scoped OWASP scan over {len(selected_records)} endpoint(s)")

    user_agent_config = None
    if user_agent_random:
        user_agent_config = {"random": True}
    elif user_agent_custom:
        user_agent_config = {"custom": user_agent_custom}
    elif user_agent_file:
        user_agents = load_user_agents_from_file(user_agent_file)
        user_agent_config = {"file_list": user_agents}

    output_filename = prepare_output_filename(output)

    advanced_config = {
        "detect_framework": detect_framework,
        "fuzz_versions": fuzz_versions,
        "framework_confidence": 0.6,
    }

    # Re-apply the operator-supplied discovery headers, cookie, and basic-auth so
    # the scoped scan inherits the same Discovery_Header_Option values as the
    # originating dir invocation (Requirement 36.5). The cookie rides the same
    # custom_headers path as --header.
    extra_headers = parse_header_options(header)
    if cookie:
        extra_headers["Cookie"] = cookie
    basic_auth_creds = parse_basic_auth(basic_auth)

    # Build a "full" engine config so the OWASP_Modules run against the seeded
    # endpoints (Requirement 36.3). scope_endpoints seeds the discovery phase
    # directly, so no wordlist is needed.
    config_dict = create_enhanced_config(
        target,
        None,
        "full",
        user_agent_config,
        output_filename,
        advanced_config,
        None,
        False,
        "critical",
        False,
        extra_headers,
        basic_auth_creds,
    )
    config_dict["proxy"] = proxy
    config_dict["proxy_verify_ssl"] = proxy_verify_ssl

    # Rebuild the same rate-limit override the originating dir used (Req 36.5).
    if rate_limit:
        config_dict["rate_limiting"]["requests_per_second"] = rate_limit
    if jwt:
        config_dict["authentication"]["contexts"][0]["token"] = jwt
        config_dict["authentication"]["contexts"][0]["type"] = "bearer"
    if response:
        config_dict["fuzzing"]["response_filter"] = parse_response_codes(response)

    config_manager = ConfigurationManager()
    apileak_config = config_manager.load_config_from_dict(config_dict)

    validation_errors = config_manager.validate_configuration()
    if validation_errors:
        logger.error(
            "Scoped OWASP scan configuration invalid",
            errors=validation_errors,
        )
        for error in validation_errors:
            click.echo(f"Error: {error}", err=True)
        return

    # Thread the selected set into the engine scan path so the OWASP modules
    # consume exactly the seeded endpoints (Requirements 36.3, 36.8).
    asyncio.run(run_enhanced_apileak(apileak_config, scope_endpoints=selected_records))


# ---------------------------------------------------------------------------
# Multi-target orchestration helpers
# ---------------------------------------------------------------------------


def _run_dir_core(
    *,
    target,
    ctx,
    wordlist,
    openapi,
    postman,
    output,
    log_level,
    log_file,
    json_logs,
    rate_limit,
    methods,
    fuzz_keyword,
    fuzz_mode,
    depth,
    recursive,
    max_requests,
    concurrency,
    confirm_hits,
    timeout,
    retries,
    extensions,
    user_agent_random,
    user_agent_custom,
    user_agent_file,
    jwt,
    header,
    cookie,
    basic_auth,
    enumerate_methods,
    graphql,
    response,
    status_code,
    match_size,
    match_words,
    match_lines,
    match_regex,
    match_time,
    filter_size,
    filter_words,
    filter_lines,
    filter_regex,
    filter_time,
    detect_framework,
    fuzz_versions,
    save_session,
    load_session,
    checkpoint,
    resume,
    export_format,
    export_file,
    output_format,
    output_file,
    interactive,
    scan_scope,
    ci_mode,
    proxy,
    proxy_verify_ssl,
    client_cert,
    ca_bundle,
    allow_cross_domain_redirects,
    resolve,
    detect_secrets,
    secret_patterns,
    include_path,
    exclude_path,
    include_status,
    exclude_status,
    recursion_status,
    recursion_type,
    spec_methods_only,
    quarantine_threshold=None,
    marker_only_requested=False,
):
    """Core single-target discovery pipeline for the ``dir`` command.

    Returns a summary dict:
        target        – the URL scanned
        endpoints     – number of discovered (non-404) endpoints
        valid         – 2xx endpoint count
        auth_required – 401/403 endpoint count
        error         – error message string, or None on success
        report_files  – list of generated report file paths
    """
    import asyncio as _asyncio

    summary = {
        "target": target,
        "endpoints": 0,
        "valid": 0,
        "auth_required": 0,
        "error": None,
        "report_files": [],
    }

    validate_user_agent_options(user_agent_random, user_agent_custom, user_agent_file)
    validate_basic_auth_options(basic_auth, jwt)
    setup_logging(level=log_level, json_logs=json_logs, log_file=log_file)
    _logger = get_logger("dir")

    match_exprs = (
        [f"size:{e}" for e in match_size]
        + [f"words:{e}" for e in match_words]
        + [f"lines:{e}" for e in match_lines]
        + [f"regex:{e}" for e in match_regex]
        + [f"time:{e}" for e in match_time]
    )
    filter_exprs = (
        [f"size:{e}" for e in filter_size]
        + [f"words:{e}" for e in filter_words]
        + [f"lines:{e}" for e in filter_lines]
        + [f"regex:{e}" for e in filter_regex]
        + [f"time:{e}" for e in filter_time]
    )
    try:
        matchers, filters = parse_selectors(match_exprs, filter_exprs)
        path_scope = parse_path_scope(include_path, exclude_path)
        storage_status = parse_storage_status_selection(include_status, exclude_status)
        recursion_scope = parse_recursion_scope(recursion_status, recursion_type)
    except (SelectorError, PathScopeError, StorageStatusError, RecursionScopeError) as exc:
        summary["error"] = str(exc)
        return summary

    if scan_scope is not None:
        try:
            select_scope_records([], scan_scope)
        except ScanScopeError as exc:
            summary["error"] = str(exc)
            return summary

    marker_wordlists = None
    try:
        resolved_fuzz_keyword = validate_fuzz_keyword(fuzz_keyword)
        markers = find_markers(target, resolved_fuzz_keyword)
        resolved_fuzz_mode = parse_fuzz_mode(fuzz_mode)
        # marker_only_requested is True when --fuzz-keyword or --fuzz-mode were
        # explicitly given on the CLI (passed in from the dir command via ctx).
        # When True and no marker is found in the target URL, that is a config
        # error (Requirement 46.2).
        if not markers and marker_only_requested:
            raise ValueError(
                f"no Fuzz_Marker found in target URL {target!r} "
                f"for keyword {resolved_fuzz_keyword!r}"
            )
        if markers:
            wordlist_sources = [[src] for src in wordlist]
            associated_sources = associate_wordlists(markers, wordlist_sources)
            marker_wordlists = []
            for assoc in associated_sources:
                try:
                    marker_wordlists.append(_read_wordlist_entries(assoc[0]))
                except OSError as exc2:
                    raise ValueError(f"unreadable wordlist source '{assoc[0]}': {exc2}") from exc2
            if resolved_fuzz_mode == FuzzMode.PITCHFORK:
                for marker, entries in zip(markers, marker_wordlists, strict=False):
                    if not entries:
                        raise ValueError(
                            f"Pitchfork_Mode requires a non-empty wordlist for "
                            f"every marker; the wordlist for marker at order "
                            f"{marker.order} is empty"
                        )
    except ValueError as exc:
        summary["error"] = str(exc)
        return summary

    try:
        candidate_set, seed_methods, wordlist_path = _resolve_dir_candidates(
            wordlist, openapi, postman
        )
    except SpecImportError as exc:
        summary["error"] = str(exc)
        return summary

    if candidate_set is not None and not candidate_set and not load_session:
        click.echo("No candidates available: no wordlist entries or spec seeds to scan.")
        return summary

    resume_checkpoint = None
    if resume:
        try:
            resume_checkpoint = DiscoveryCheckpoint.load(resume)
        except DiscoveryCheckpointError as exc:
            summary["error"] = str(exc)
            return summary

    triage_requested = bool(
        save_session
        or load_session
        or export_format
        or export_file
        or output_format
        or output_file
        or interactive
        or scan_scope
        or matchers
        or filters
    )

    try:
        if triage_requested:
            _run_dir_triage(
                target=target,
                wordlist_path=wordlist_path,
                candidate_set=candidate_set,
                seed_methods=seed_methods,
                output=output,
                rate_limit=rate_limit,
                methods=methods,
                fuzz_keyword=resolved_fuzz_keyword,
                fuzz_mode=resolved_fuzz_mode.value,
                marker_wordlists=marker_wordlists,
                user_agent_random=user_agent_random,
                user_agent_custom=user_agent_custom,
                user_agent_file=user_agent_file,
                jwt=jwt,
                header=header,
                cookie=cookie,
                basic_auth=basic_auth,
                response=response,
                status_code=status_code,
                matchers=matchers,
                filters=filters,
                detect_framework=detect_framework,
                fuzz_versions=fuzz_versions,
                save_session=save_session,
                load_session=load_session,
                export_format=export_format,
                export_file=export_file,
                output_format=output_format,
                output_file=output_file,
                interactive=interactive,
                scan_scope=scan_scope,
                ci_mode=ci_mode,
                proxy=proxy,
                proxy_verify_ssl=proxy_verify_ssl,
                client_cert=client_cert,
                ca_bundle=ca_bundle,
                allow_cross_domain_redirects=allow_cross_domain_redirects,
                resolve=resolve,
                detect_secrets=detect_secrets,
                secret_patterns=secret_patterns,
                path_scope=path_scope,
                storage_status=storage_status,
                checkpoint=checkpoint,
                resume_checkpoint=resume_checkpoint,
                openapi_sources=openapi,
                postman_sources=postman,
                spec_methods_only=spec_methods_only,
                quarantine_threshold=quarantine_threshold,
                logger=_logger,
            )
            return summary

        # --- Non-triage path (direct scan) ---
        user_agent_config = None
        if user_agent_random:
            user_agent_config = {"random": True}
        elif user_agent_custom:
            user_agent_config = {"custom": user_agent_custom}
        elif user_agent_file:
            user_agents = load_user_agents_from_file(user_agent_file)
            user_agent_config = {"file_list": user_agents}

        output_filename = prepare_output_filename(output)
        advanced_config = {
            "detect_framework": detect_framework,
            "fuzz_versions": fuzz_versions,
            "framework_confidence": 0.6,
        }
        status_code_filter = parse_status_codes(status_code) if status_code else None
        extra_headers = parse_header_options(header)
        if cookie:
            extra_headers["Cookie"] = cookie
        basic_auth_creds = parse_basic_auth(basic_auth)

        config_dict = create_default_config(
            target,
            wordlist_path,
            "dir",
            user_agent_config,
            output_filename,
            advanced_config,
            status_code_filter,
            extra_headers,
            basic_auth_creds,
        )
        config_dict["proxy"] = proxy
        config_dict["proxy_verify_ssl"] = proxy_verify_ssl
        config_dict["client_cert"] = client_cert
        config_dict["ca_bundle"] = ca_bundle
        config_dict["resolve"] = resolve
        config_dict["fuzzing"]["endpoints"]["allow_cross_domain_redirects"] = (
            allow_cross_domain_redirects
        )

        if candidate_set is not None:
            config_dict["fuzzing"]["endpoints"]["candidate_set"] = candidate_set
            config_dict["fuzzing"]["endpoints"]["seed_methods"] = seed_methods

        _dir_spec_schema = _build_dir_spec_schema(openapi, postman)
        if _dir_spec_schema is not None:
            config_dict["fuzzing"]["endpoints"]["spec_schema"] = _dir_spec_schema
        config_dict["fuzzing"]["endpoints"]["spec_methods_only"] = spec_methods_only
        if quarantine_threshold is not None:
            config_dict["fuzzing"]["endpoints"]["quarantine_threshold"] = quarantine_threshold

        if rate_limit:
            config_dict["rate_limiting"]["requests_per_second"] = rate_limit
        if methods:
            config_dict["fuzzing"]["endpoints"]["methods"] = [m.strip() for m in methods.split(",")]
        config_dict["fuzzing"]["max_depth"] = resolve_max_depth(depth)
        if recursive is not None:
            config_dict["fuzzing"]["recursive"] = recursive
        if depth == 0:
            config_dict["fuzzing"]["recursive"] = False  # depth 0 => depth-0 pass only
        if max_requests is not None:
            config_dict["fuzzing"]["max_requests"] = max_requests
        if concurrency is not None:
            config_dict["fuzzing"]["concurrency"] = concurrency
        if confirm_hits is not None:
            config_dict["fuzzing"]["hit_confirmation"] = {"enabled": True, "count": confirm_hits}
        config_dict["fuzzing"]["endpoints"]["fuzz_keyword"] = resolved_fuzz_keyword
        config_dict["fuzzing"]["endpoints"]["fuzz_mode"] = resolved_fuzz_mode.value
        config_dict["fuzzing"]["endpoints"]["marker_wordlists"] = marker_wordlists
        config_dict["fuzzing"]["path_scope"] = path_scope
        config_dict["fuzzing"]["storage_status"] = storage_status
        config_dict["fuzzing"]["recursion_scope"] = recursion_scope
        if timeout is not None:
            config_dict["target"]["timeout"] = timeout
        if retries is not None:
            config_dict["fuzzing"]["retries"] = retries
        if enumerate_methods:
            config_dict["fuzzing"]["endpoints"]["enumerate_methods"] = True
        if graphql:
            config_dict["fuzzing"]["endpoints"]["graphql"] = True
        config_dict["fuzzing"]["endpoints"]["extensions"] = normalize_extensions(
            [ext for value in (extensions or ()) for ext in value.split(",")]
        )
        if jwt:
            config_dict["authentication"]["contexts"][0]["token"] = jwt
            config_dict["authentication"]["contexts"][0]["type"] = "bearer"
        if response:
            config_dict["fuzzing"]["response_filter"] = parse_response_codes(response)
        config_dict.setdefault("secret_scan", {})
        config_dict["secret_scan"]["enabled"] = detect_secrets
        if secret_patterns is not None:
            config_dict["secret_scan"]["patterns"] = secret_patterns

        config_manager = ConfigurationManager()
        apileak_config = config_manager.load_config_from_dict(config_dict)
        validation_errors = config_manager.validate_configuration()
        if validation_errors:
            summary["error"] = "; ".join(validation_errors)
            return summary

        discovery_progress = _build_discovery_progress(ci_mode, apileak_config.fuzzing.max_requests)
        _asyncio.run(
            run_enhanced_apileak(
                apileak_config,
                ci_mode=ci_mode,
                fail_on="critical",
                discovery_progress=discovery_progress,
                checkpoint_path=checkpoint,
                resume_checkpoint=resume_checkpoint,
            )
        )
        return summary

    except (
        DiscoveryCheckpointError,
        DiscoverySessionError,
        DiscoveryExportError,
        DiscoveryOutputError,
        SpecImportError,
        ValueError,
        OSError,
    ) as exc:
        # Only catch expected operational error types so that test sentinel
        # exceptions (and other BaseException subclasses) propagate naturally.
        summary["error"] = str(exc)
        _logger.error("Single-target dir scan failed", target=target, error=str(exc))
        return summary


def _run_dir_multi_target(*, targets, ctx, **kwargs):
    """Scan targets and print a summary table.

    When ``parallel_hosts`` > 1 (set via ``--parallel-hosts / -j``), scans up to
    that many hosts concurrently using a ``ThreadPoolExecutor``.  Each host runs
    ``_run_dir_core`` in its own thread (each thread has its own asyncio event
    loop, so ``asyncio.run()`` inside ``_run_dir_core`` works correctly).
    Sequential mode (``parallel_hosts`` <= 1, the default) preserves the existing
    behaviour exactly.
    """
    import concurrent.futures
    import threading
    from urllib.parse import urlparse as _urlparse

    _RESET = "\033[0m"
    _BOLD = "\033[1m"
    _GREEN = "\033[92m"
    _RED = "\033[91m"
    _CYAN = "\033[96m"
    _YELLOW = "\033[93m"

    parallel_hosts = kwargs.pop("parallel_hosts", 1) or 1
    total = len(targets)

    mode_label = f"parallel (j={parallel_hosts})" if parallel_hosts > 1 else "sequential"
    click.echo(
        f"\n{_BOLD}{_CYAN}Multi-target scan: {total} host(s) [{mode_label}]{_RESET}\n{'─' * 60}"
    )

    # Per-target work: build kwargs, run scan, return summary.
    _print_lock = threading.Lock()

    def _scan_one(idx_target):
        idx, t = idx_target
        hostname = _urlparse(t).netloc or t
        base_output = kwargs.get("output")
        if base_output:
            per_target_output = f"{base_output}_{hostname.replace(':', '_')}"
        else:
            safe_name = hostname.replace(":", "_").replace("/", "_")
            per_target_output = f"scan_{safe_name}"

        per_kwargs = dict(kwargs)
        per_kwargs["output"] = per_target_output
        per_kwargs["interactive"] = False

        if parallel_hosts > 1:
            with _print_lock:
                click.echo(f"\n{_BOLD}[{idx}/{total}]{_RESET} {_CYAN}{t}{_RESET} starting…")
        else:
            click.echo(f"\n{_BOLD}[{idx}/{total}]{_RESET} {_CYAN}{t}{_RESET}")

        result = _run_dir_core(target=t, ctx=ctx, **per_kwargs)
        result["hostname"] = hostname

        with _print_lock:
            if result["error"]:
                click.echo(f"  {_RED}✗ [{hostname}] Error: {result['error']}{_RESET}")
            else:
                click.echo(
                    f"  {_GREEN}✓{_RESET} [{hostname}] "
                    f"endpoints={result['endpoints']}  "
                    f"valid={result['valid']}  "
                    f"auth_req={result['auth_required']}"
                )
        return result

    # Run scans
    if parallel_hosts <= 1:
        summaries = [_scan_one((idx, t)) for idx, t in enumerate(targets, 1)]
    else:
        workers = min(parallel_hosts, total)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            summaries = list(pool.map(_scan_one, enumerate(targets, 1)))

    # Consolidated summary
    col_host = 40
    click.echo(
        f"\n{_BOLD}{_CYAN}{'═' * 60}\n  MULTI-TARGET SUMMARY  ({total} hosts)\n{'═' * 60}{_RESET}"
    )
    click.echo(
        f"{_BOLD}{'HOST':<{col_host}} {'ENDPOINTS':>9} {'VALID':>7}"
        f" {'AUTH_REQ':>9} {'STATUS':<8}{_RESET}"
    )
    click.echo("─" * 75)

    success_count = error_count = 0
    for s in summaries:
        host_d = s["hostname"][: col_host - 1] if len(s["hostname"]) > col_host else s["hostname"]
        if s["error"]:
            error_count += 1
            click.echo(f"{host_d:<{col_host}} {'—':>9} {'—':>7} {'—':>9} {_RED}ERROR{_RESET}")
        else:
            success_count += 1
            click.echo(
                f"{host_d:<{col_host}} {s['endpoints']:>9} {s['valid']:>7}"
                f" {s['auth_required']:>9} {_GREEN}OK{_RESET}"
            )

    click.echo("─" * 75)
    click.echo(
        f"\n{_BOLD}Total:{_RESET} {total}  "
        f"{_GREEN}Success: {success_count}{_RESET}  "
        f"{_RED}Errors: {error_count}{_RESET}\n"
    )


def _run_par_multi_target(targets, *, ctx, **kwargs):
    """Fuzz parameters across multiple targets sequentially and print a summary."""
    from urllib.parse import urlparse as _urlparse

    _RESET = "\033[0m"
    _BOLD = "\033[1m"
    _GREEN = "\033[92m"
    _RED = "\033[91m"
    _CYAN = "\033[96m"

    total = len(targets)
    click.echo(
        f"\n{_BOLD}{_CYAN}Multi-target parameter fuzzing: {total} host(s){_RESET}\n{'─' * 60}"
    )

    summaries = []
    for idx, t in enumerate(targets, 1):
        hostname = _urlparse(t).netloc or t
        click.echo(f"\n{_BOLD}[{idx}/{total}]{_RESET} {_CYAN}{t}{_RESET}")
        base_output = kwargs.get("output")
        per_output = (
            f"{base_output}_{hostname.replace(':', '_')}"
            if base_output
            else f"par_{hostname.replace(':', '_').replace('/', '_')}"
        )
        per_kwargs = dict(kwargs)
        per_kwargs["output"] = per_output

        error_msg = None
        try:
            # Re-invoke the par command body logic with the per-target URL by
            # calling the underlying ctx.invoke path — the simplest approach is
            # to call par.invoke(ctx) after patching, but Click doesn't support
            # that cleanly; instead we re-invoke the full command via
            # ctx.invoke so Click handles parameter injection.
            ctx.invoke(par, target=t, target_file=None, max_hosts=None, **per_kwargs)
            click.echo(f"  {_GREEN}✓ Completed{_RESET}")
        except SystemExit as exc:
            error_msg = f"exited with code {exc.code}"
            click.echo(f"  {_RED}✗ {error_msg}{_RESET}")
        except Exception as exc:
            error_msg = str(exc)
            click.echo(f"  {_RED}✗ {error_msg}{_RESET}")

        summaries.append({"hostname": hostname, "error": error_msg})

    # Summary table
    col = 50
    click.echo(
        f"\n{_BOLD}{_CYAN}{'═' * 60}\n  MULTI-TARGET PAR SUMMARY  ({total} hosts)\n"
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


@cli.command()
@click.option(
    "--target",
    "-t",
    required=False,
    default=None,
    help="Target URL to scan. Required unless --target-file is supplied.",
)
@click.option(
    "--target-file",
    "target_file",
    default=None,
    type=click.Path(exists=True, readable=True, file_okay=True, dir_okay=False),
    metavar="FILE",
    help="Plain-text file with one target URL per line (# comments and blank "
    "lines are skipped). Lines without a scheme are auto-prefixed with "
    "https://. When supplied, --target is optional.",
)
@click.option(
    "--max-hosts",
    "max_hosts",
    type=int,
    default=None,
    metavar="N",
    help="Maximum number of hosts to scan from --target-file (scans the first N).",
)
@click.option(
    "--wordlist",
    "-w",
    "wordlist",
    multiple=True,
    help="Wordlist file of candidate parameter names for parameter "
    "fuzzing. Repeatable; merged and de-duplicated across all "
    'values. Use "-" to read entries from stdin. Defaults to '
    "wordlists/parameters.txt when omitted.",
)
@click.option(
    "--output", "-o", help="Output filename for reports (files will be saved in reports/ directory)"
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    default="WARNING",
    help="Logging level",
)
@click.option("--log-file", help="Log file path (optional)")
@click.option("--json-logs", is_flag=True, help="Output logs in JSON format")
@click.option("--rate-limit", type=int, help="Requests per second limit")
@click.option(
    "--methods",
    default="GET,POST",
    callback=_validate_methods,
    help="HTTP methods to test (comma-separated)",
)
@click.option(
    "--user-agent-random", is_flag=True, help="Use random User-Agent headers to evade WAF"
)
@click.option("--user-agent-custom", help="Custom User-Agent string to use for all requests")
@click.option(
    "--user-agent-file", help="File containing User-Agent strings (one per line) for rotation"
)
@click.option("--jwt", help="JWT token to use for authentication")
@click.option("--response", help="Filter by response codes (e.g., 200,301,404 or 200-300)")
@click.option(
    "--status-code",
    help="Show only HTTP requests with specific status codes (e.g., 200,404 or 200-300)",
)
@click.option(
    "--detect-framework",
    "--df",
    is_flag=True,
    help="Enable framework detection during parameter fuzzing",
)
@click.option(
    "--proxy",
    help="Route all HTTP traffic through an intercepting proxy (e.g. Burp/Caido/Hetty: http://127.0.0.1:8080). TLS verification is disabled by default for proxied HTTPS targets.",
)
@click.option(
    "--proxy-verify-ssl",
    "proxy_verify_ssl",
    is_flag=True,
    help="Keep TLS certificate verification enabled when using --proxy (use after installing the proxy CA).",
)
@click.option(
    "--fuzz-keyword",
    "fuzz_keyword",
    default="FUZZ",
    show_default=True,
    metavar="KEYWORD",
    help="Literal token in the target URL marking positions to fuzz. "
    "When present, par runs in Marker_Mode and the repeatable "
    "--wordlist values are the per-marker wordlists in marker order.",
)
@click.option(
    "--fuzz-mode",
    "fuzz_mode",
    type=click.Choice(["clusterbomb", "pitchfork"], case_sensitive=False),
    default="clusterbomb",
    show_default=True,
    help="Combination strategy for multiple markers (Marker_Mode).",
)
@concurrency_options
@click.option(
    "--confirm-hits",
    "confirm_hits",
    type=int,
    default=None,
    callback=_validate_confirm_hits,
    metavar="N",
    help="Enable Hit_Confirmation: re-request each interesting candidate N times "
    "and record it only when the responses are consistent (must be >= 1; "
    "default: off).",
)
@resilience_options
@request_context_options
@matcher_filter_options
@machine_output_options
@tls_options
@click.pass_context
def par(
    ctx,
    target,
    target_file,
    max_hosts,
    wordlist,
    output,
    log_level,
    log_file,
    json_logs,
    rate_limit,
    methods,
    fuzz_keyword,
    fuzz_mode,
    user_agent_random,
    user_agent_custom,
    user_agent_file,
    jwt,
    response,
    status_code,
    detect_framework,
    proxy,
    proxy_verify_ssl,
    concurrency,
    confirm_hits,
    max_requests,
    timeout,
    retries,
    header,
    cookie,
    basic_auth,
    match_size,
    match_words,
    match_lines,
    match_regex,
    match_time,
    filter_size,
    filter_words,
    filter_lines,
    filter_regex,
    filter_time,
    output_format,
    output_file,
    client_cert,
    ca_bundle,
    resolve,
):
    """Parameter fuzzing - discover hidden parameters in API endpoints

    \b
    Examples:
      python apileaks.py par --target https://api.example.com/users/123
      python apileaks.py par --target URL --jwt TOKEN --wordlist params.txt
      python apileaks.py par --target URL --user-agent-random --rate-limit 3
      python apileaks.py par --target-file hosts.txt --wordlist params.txt
    """
    # -------------------------------------------------------------------------
    # Multi-target resolution for par — mirrors the dir command's logic.
    # -------------------------------------------------------------------------
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
        if target:
            all_targets = [target] + [t for t in file_targets if t != target]
        else:
            all_targets = file_targets
        if max_hosts is not None and max_hosts > 0:
            all_targets = all_targets[:max_hosts]
    elif target:
        all_targets = [target]
    else:
        click.echo(
            "Error: Either --target or --target-file must be supplied.\n"
            "  --target URL            fuzz parameters on a single endpoint\n"
            "  --target-file FILE      fuzz each endpoint listed in FILE",
            err=True,
        )
        sys.exit(1)

    # Forward shared kwargs so the multi-target helper can call par_core per host.
    _par_kwargs = {
        "wordlist": wordlist,
        "output": output,
        "log_level": log_level,
        "log_file": log_file,
        "json_logs": json_logs,
        "rate_limit": rate_limit,
        "methods": methods,
        "fuzz_keyword": fuzz_keyword,
        "fuzz_mode": fuzz_mode,
        "user_agent_random": user_agent_random,
        "user_agent_custom": user_agent_custom,
        "user_agent_file": user_agent_file,
        "jwt": jwt,
        "response": response,
        "status_code": status_code,
        "detect_framework": detect_framework,
        "proxy": proxy,
        "proxy_verify_ssl": proxy_verify_ssl,
        "concurrency": concurrency,
        "confirm_hits": confirm_hits,
        "max_requests": max_requests,
        "timeout": timeout,
        "retries": retries,
        "header": header,
        "cookie": cookie,
        "basic_auth": basic_auth,
        "match_size": match_size,
        "match_words": match_words,
        "match_lines": match_lines,
        "match_regex": match_regex,
        "match_time": match_time,
        "filter_size": filter_size,
        "filter_words": filter_words,
        "filter_lines": filter_lines,
        "filter_regex": filter_regex,
        "filter_time": filter_time,
        "output_format": output_format,
        "output_file": output_file,
        "client_cert": client_cert,
        "ca_bundle": ca_bundle,
        "resolve": resolve,
    }
    _par_kwargs = {
        "wordlist": wordlist,
        "output": output,
        "log_level": log_level,
        "log_file": log_file,
        "json_logs": json_logs,
        "rate_limit": rate_limit,
        "methods": methods,
        "fuzz_keyword": fuzz_keyword,
        "fuzz_mode": fuzz_mode,
        "user_agent_random": user_agent_random,
        "user_agent_custom": user_agent_custom,
        "user_agent_file": user_agent_file,
        "jwt": jwt,
        "response": response,
        "status_code": status_code,
        "detect_framework": detect_framework,
        "proxy": proxy,
        "proxy_verify_ssl": proxy_verify_ssl,
        "concurrency": concurrency,
        "confirm_hits": confirm_hits,
        "max_requests": max_requests,
        "timeout": timeout,
        "retries": retries,
        "header": header,
        "cookie": cookie,
        "basic_auth": basic_auth,
        "match_size": match_size,
        "match_words": match_words,
        "match_lines": match_lines,
        "match_regex": match_regex,
        "match_time": match_time,
        "filter_size": filter_size,
        "filter_words": filter_words,
        "filter_lines": filter_lines,
        "filter_regex": filter_regex,
        "filter_time": filter_time,
        "output_format": output_format,
        "output_file": output_file,
        "client_cert": client_cert,
        "ca_bundle": ca_bundle,
        "resolve": resolve,
    }

    if len(all_targets) > 1:
        _run_par_multi_target(all_targets, ctx=ctx, **_par_kwargs)
        return

    target = all_targets[0]

    # Legacy `par` option audit (Requirements 2.5, 2.6).
    #
    # Every legacy `par` option present before the `dir`-parity work is RETAINED
    # here with its original semantics (R2.5): --target, --wordlist (now also
    # repeatable, backward-compatible with a single value), --output, --log-level,
    # --log-file, --json-logs, --rate-limit, --methods, --user-agent-random/
    # --user-agent-custom/--user-agent-file, --jwt, --response, --status-code,
    # --detect-framework/--df, --proxy, and --proxy-verify-ssl are all accepted
    # without terminating execution. The parity options added by tasks 11.1-11.5
    # (request-context, resilience, concurrency, TLS, matcher/filter,
    # machine-output, --confirm-hits) are purely ADDITIVE and each mirrors the
    # option `dir` already exposes, so no legacy single-purpose flag was replaced
    # or superseded. `--methods` was previously accepted but ignored ("not used");
    # it is now wired to real injection-point semantics (R6), an enhancement of a
    # retained option rather than a deprecation.
    #
    # Consequently there are NO deprecated `par` options: no deprecation notice is
    # emitted because none is warranted (R2.6 is conditional on a deprecated
    # option existing). Should a `par` option ever be superseded in future, emit a
    # non-terminating notice via `_emit_deprecation_notice(<option>, <replacement>)`
    # (the same helper `full`/`main` use), which writes to stderr and leaves
    # stdout and the exit code unchanged.

    # Validate user agent options
    validate_user_agent_options(user_agent_random, user_agent_custom, user_agent_file)

    # Validate basic-auth conflicts/format before any parameter fuzzing runs so a
    # --basic-auth + --jwt conflict (Requirement 7.7) or a colon-less value
    # (Requirement 7.6) exits before any request is issued, identical to `dir`.
    validate_basic_auth_options(basic_auth, jwt)

    # Validate custom-header format before any parameter fuzzing runs so a
    # colon-less --header value (Requirement 7.5) is rejected with a descriptive
    # error naming the malformed header and exits before any request is issued.
    validate_header_options(header)

    # Setup logging
    setup_logging(level=log_level, json_logs=json_logs, log_file=log_file)
    logger = get_logger("par")

    logger.info("APILeak parameter fuzzing starting", version=APILEAK_VERSION, target=target)

    # Build --match-*/--filter-* expressions into the '<attribute>:<expression>'
    # grammar understood by parse_selectors, reusing `dir`'s selector plumbing
    # verbatim (Requirement 12.7). Status matching continues to use the existing
    # --status-code flag, so it is intentionally not included here.
    match_exprs = (
        [f"size:{expr}" for expr in match_size]
        + [f"words:{expr}" for expr in match_words]
        + [f"lines:{expr}" for expr in match_lines]
        + [f"regex:{expr}" for expr in match_regex]
        + [f"time:{expr}" for expr in match_time]
    )
    filter_exprs = (
        [f"size:{expr}" for expr in filter_size]
        + [f"words:{expr}" for expr in filter_words]
        + [f"lines:{expr}" for expr in filter_lines]
        + [f"regex:{expr}" for expr in filter_regex]
        + [f"time:{expr}" for expr in filter_time]
    )

    # Parse selectors at CLI parse time so a syntactically invalid matcher/filter
    # expression is surfaced as a descriptive CLI error and NO parameter fuzzing
    # request is issued (Requirement 12.4), consistent with `dir`. The parsed
    # matchers/filters are threaded into the finding-selection pipeline by a
    # later task; parsing here guarantees the exit-before-request behavior.
    try:
        matchers, filters = parse_selectors(match_exprs, filter_exprs)
    except SelectorError as exc:
        logger.error("Invalid response selector expression", error=str(exc))
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    try:
        # Prepare user agent configuration
        user_agent_config = None
        if user_agent_random:
            user_agent_config = {"random": True}
        elif user_agent_custom:
            user_agent_config = {"custom": user_agent_custom}
        elif user_agent_file:
            user_agents = load_user_agents_from_file(user_agent_file)
            user_agent_config = {"file_list": user_agents}

        # Prepare output filename
        output_filename = prepare_output_filename(output)

        # Prepare advanced configuration for parameter fuzzing
        advanced_config = {
            "detect_framework": detect_framework,
            "fuzz_versions": False,  # Version fuzzing not typically useful for parameter mode
            "framework_confidence": 0.6,  # Default confidence for par mode
        }

        # Parse status code filter for HTTP output
        status_code_filter = parse_status_codes(status_code) if status_code else None

        # Parse operator-supplied request-context headers, cookie, and basic-auth
        # reusing `dir`'s helpers verbatim (Requirements 7.1-7.3). The cookie is
        # carried as a 'Cookie' header so it rides the same custom_headers path as
        # --header (Requirement 7.2).
        extra_headers = parse_header_options(header)
        if cookie:
            extra_headers["Cookie"] = cookie
        basic_auth_creds = parse_basic_auth(basic_auth)

        # ------------------------------------------------------------------ #
        # Marker-mode validation (Requirements 1.5, 1.6, 2.3, 5.1, 7.4,   #
        # 7.5, 7.6, 10.1–10.7), strictly exit-before-request.              #
        # Mirrors the dir command marker-validation block verbatim but      #
        # threads into config_dict['fuzzing']['parameters'].                #
        # ------------------------------------------------------------------ #
        marker_only_requested = (
            ctx.get_parameter_source("fuzz_keyword") == click.core.ParameterSource.COMMANDLINE
            or ctx.get_parameter_source("fuzz_mode") == click.core.ParameterSource.COMMANDLINE
        )
        marker_wordlists = None
        try:
            # 1. Keyword validity (R1.5 / R10.1).
            resolved_fuzz_keyword = validate_fuzz_keyword(fuzz_keyword)

            # 2. Marker presence for marker-only mode (R1.6 / R10.2).
            markers = find_markers(target, resolved_fuzz_keyword)
            if not markers and marker_only_requested:
                raise ValueError(
                    "no Fuzz_Marker found in target URL "
                    f"{target!r} for keyword {resolved_fuzz_keyword!r}"
                )

            # 3. Fuzz-mode selection (R5.1 / R10.3).
            resolved_fuzz_mode = parse_fuzz_mode(fuzz_mode)

            if markers:
                # 4. Associate wordlists with markers in left-to-right order
                #    (R7.1–R7.4 / R10.4). Each --wordlist source is wrapped so
                #    associate_wordlists operates on source references.
                wordlist_sources = [[src] for src in wordlist]
                if not wordlist_sources:
                    # R7.7: no --wordlist supplied → default parameter wordlist
                    # covers every marker position.
                    wordlist_sources = [[DEFAULT_PARAMETER_WORDLIST]]
                associated_sources = associate_wordlists(markers, wordlist_sources)

                # 5. Read each associated wordlist (R7.6 / R10.6).
                marker_wordlists = []
                for assoc in associated_sources:
                    source = assoc[0]
                    try:
                        marker_wordlists.append(_read_wordlist_entries(source))
                    except OSError as exc:
                        raise ValueError(f"unreadable wordlist source '{source}': {exc}") from exc

                # 6. Pitchfork empty-wordlist check (R7.5 / R10.5).
                if resolved_fuzz_mode == FuzzMode.PITCHFORK:
                    for marker, entries in zip(markers, marker_wordlists, strict=False):
                        if not entries:
                            raise ValueError(
                                "Pitchfork_Mode requires a non-empty wordlist for "
                                "every marker; the wordlist for marker at order "
                                f"{marker.order} is empty"
                            )
        except ValueError as exc:
            logger.error("Invalid marker-mode configuration", error=str(exc))
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)

        # In Name_Discovery_Mode (no markers, no marker-only option) resolve
        # the merged, de-duplicated candidate parameter set from the repeatable
        # --wordlist sources BEFORE any request.  This path is gated on
        # marker_wordlists is None so Marker_Mode never runs it (R2.1).
        candidate_parameters = None
        if marker_wordlists is None:
            # Resolve the merged, de-duplicated candidate parameter set from the
            # repeatable --wordlist sources BEFORE any request, reusing `dir`'s
            # wordlist-reading helper. An unreadable source is surfaced as a
            # descriptive error naming the file and stops before any request
            # (Requirement 10.3). When --wordlist is omitted the default
            # wordlists/parameters.txt is used (Requirement 10.4).
            try:
                candidate_parameters = _resolve_par_candidates(wordlist)
            except ValueError as exc:
                logger.error("Unreadable parameter wordlist", error=str(exc))
                click.echo(f"Error: {exc}", err=True)
                sys.exit(1)

            # An empty merged candidate set completes WITHOUT issuing any request
            # and reports that no candidate parameters were available (R10.5).
            if not candidate_parameters:
                click.echo("No candidate parameters available: no wordlist entries to fuzz.")
                return

        # Create default configuration for parameter fuzzing. The wordlist file
        # path is left at its default; the merged candidate set below overrides
        # the file-based wordlists via query_candidates/body_candidates.
        #
        # The transversal transport/TLS options (--client-cert/--ca-bundle/
        # --resolve) and the parameter-fuzzing controls (--methods, --confirm-hits,
        # --max-requests, and the merged query/body candidate sets) are threaded
        # THROUGH create_default_config so the `par` wiring is centralized in the
        # config-creation path — mirroring how the transversal keys are
        # centralized there — rather than being patched onto config_dict inline.
        # The CLI validators have already parsed/validated each of these before
        # any request is issued (Requirements 5.1, 6.1, 9.1-9.3, 10.1, 10.2, 11.1).
        #
        # In Marker_Mode: query_candidates/body_candidates are None (name-discovery
        # path is skipped); fuzz_keyword, fuzz_mode, marker_wordlists are threaded.
        # In Name_Discovery_Mode: marker_wordlists is None (marker gate stays off).
        config_dict = create_default_config(
            target,
            None,
            "par",
            user_agent_config,
            output_filename,
            advanced_config,
            status_code_filter,
            extra_headers,
            basic_auth_creds,
            client_cert=client_cert,
            ca_bundle=ca_bundle,
            resolve=resolve,
            parameter_methods=methods,
            confirm_hits=confirm_hits,
            parameter_max_requests=max_requests,
            query_candidates=candidate_parameters,
            body_candidates=candidate_parameters,
            fuzz_keyword=resolved_fuzz_keyword,
            fuzz_mode=resolved_fuzz_mode.value,
            marker_wordlists=marker_wordlists,
        )
        config_dict["proxy"] = proxy
        config_dict["proxy_verify_ssl"] = proxy_verify_ssl

        # Apply CLI overrides
        if rate_limit:
            config_dict["rate_limiting"]["requests_per_second"] = rate_limit
        # Thread the per-request resilience and concurrency controls into the
        # config exactly as `dir` does (Requirement 8). --timeout becomes the
        # target read timeout (8.1), --retries becomes the RetryConfig source
        # (8.2), and --concurrency limits in-flight requests (8.3). Each falls
        # back to the config defaults when not supplied (8.6). These stay inline
        # here (as they do in `dir`) since they are shared fuzzing/target keys,
        # not part of the centralized par-path threading above.
        if timeout is not None:
            config_dict["target"]["timeout"] = timeout
        if retries is not None:
            config_dict["fuzzing"]["retries"] = retries
        if concurrency is not None:
            config_dict["fuzzing"]["concurrency"] = concurrency
        if jwt:
            config_dict["authentication"]["contexts"][0]["token"] = jwt
            config_dict["authentication"]["contexts"][0]["type"] = "bearer"
        if response:
            config_dict["fuzzing"]["response_filter"] = parse_response_codes(response)

        # Thread the parsed response matchers/filters into the shared FuzzingConfig
        # fields so parameter findings are narrowed by the SAME matcher-before-filter
        # pipeline `dir` uses: retain only findings satisfying every matcher, then
        # exclude any finding satisfying any filter (Requirements 12.1-12.3). The
        # selectors were already parsed above at CLI time (exit-before-request on an
        # invalid expression, Requirement 12.4); here they flow through to the
        # engine's finding-selection step. When no selectors were supplied both
        # lists are empty and selection is a no-op.
        config_dict["fuzzing"]["matchers"] = matchers
        config_dict["fuzzing"]["filters"] = filters

        # Thread the machine-readable output selections (--output-format/
        # --output-file) into the shared FuzzingConfig so the engine writes the
        # selected parameter findings (including their detection-signal fields)
        # through the same CSV/JSON Lines machine writer `dir` uses
        # (Requirements 12.5, 12.6). --output-format is already constrained to
        # csv/jsonl by click.Choice at parse time, so an unsupported format is
        # rejected before any request and no file is written (Requirement 12.6).
        # When neither option is supplied both stay None and no machine output
        # is written, leaving the default report behavior unchanged.
        config_dict["fuzzing"]["output_format"] = output_format
        config_dict["fuzzing"]["output_file"] = output_file

        # Load configuration through ConfigurationManager
        config_manager = ConfigurationManager()
        apileak_config = config_manager.load_config_from_dict(config_dict)

        # Validate configuration
        validation_errors = config_manager.validate_configuration()
        if validation_errors:
            logger.error("Configuration validation failed", errors=validation_errors)
            for error in validation_errors:
                click.echo(f"Error: {error}", err=True)
            sys.exit(1)

        # Run the scan
        asyncio.run(run_enhanced_apileak(apileak_config))

    except Exception as e:
        logger.error("Parameter fuzzing failed", error=str(e))
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


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
            run_enhanced_apileak(
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
    await run_enhanced_apileak(config, ci_mode=False, fail_on="critical")


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


@cli.command(name="brute")
@click.option(
    "--target",
    "-t",
    "target",
    required=False,
    default=None,
    help="Target URL to brute-force (e.g. https://api.example.com). "
    "Required unless --target-file is supplied.",
)
@click.option(
    "--target-file",
    "target_file",
    default=None,
    type=click.Path(exists=True, readable=True),
    metavar="FILE",
    help="Plain-text file with one target URL per line (comments "
    "starting with # and blank lines are skipped). "
    "Scanned sequentially.",
)
@click.option(
    "--wordlist",
    "-w",
    "brute_spec_wordlist",
    default=None,
    type=click.Path(exists=True, readable=True),
    metavar="FILE",
    help="Custom wordlist of spec-file paths to probe (one per line). "
    "Defaults to the built-in wordlists/spec_files.txt "
    f"({len(_load_spec_brute_wordlist(_DEFAULT_SPEC_WORDLIST))} paths).",
)
@click.option(
    "--extensions",
    "-e",
    "brute_spec_extensions",
    is_flag=True,
    default=False,
    help="Append .json / .yaml / .yml to every wordlist entry, "
    "tripling coverage at the cost of more requests.",
)
@click.option(
    "--concurrency",
    "-c",
    "brute_spec_concurrency",
    type=int,
    default=20,
    show_default=True,
    metavar="N",
    help="Maximum concurrent HTTP requests.",
)
@click.option(
    "--timeout",
    "timeout",
    type=float,
    default=10.0,
    show_default=True,
    help="Per-request timeout in seconds.",
)
@click.option(
    "--proxy",
    "-p",
    "proxy",
    default=None,
    metavar="URL",
    help="Route all requests through an intercepting proxy "
    "(e.g. http://127.0.0.1:8080 for Burp/Caido).",
)
@click.option(
    "--proxy-verify-ssl",
    "proxy_verify_ssl",
    is_flag=True,
    default=False,
    help="Keep TLS verification enabled when using --proxy "
    "(use after installing the proxy CA certificate).",
)
@click.option(
    "--insecure",
    "-i",
    "insecure",
    is_flag=True,
    default=False,
    help="Disable TLS certificate verification (equivalent to curl -k).",
)
@click.option(
    "--jwt",
    "jwt",
    default=None,
    metavar="TOKEN",
    help="Bearer token injected as Authorization: Bearer <TOKEN> on every request.",
)
@click.option(
    "--header",
    "-H",
    "header",
    multiple=True,
    metavar='"Name: Value"',
    help='Custom request header, "Name: Value" format. Repeatable.',
)
@click.option(
    "--user-agent-random",
    "user_agent_random",
    is_flag=True,
    default=False,
    help="Randomise the User-Agent header on every request.",
)
@click.option(
    "--user-agent-custom",
    "user_agent_custom",
    default=None,
    metavar="STRING",
    help="Use a fixed custom User-Agent string.",
)
@click.option(
    "--output",
    "-o",
    "brute_spec_output",
    default=None,
    type=click.Path(),
    metavar="FILE",
    help="Write results to a JSON file.",
)
@click.option(
    "--quiet",
    "-q",
    "quiet",
    is_flag=True,
    default=False,
    help="Suppress per-request output; only print the final summary.",
)
@click.pass_context
def brute_cmd(
    ctx,
    target,
    target_file,
    brute_spec_wordlist,
    brute_spec_extensions,
    brute_spec_concurrency,
    timeout,
    proxy,
    proxy_verify_ssl,
    insecure,
    jwt,
    header,
    user_agent_random,
    user_agent_custom,
    brute_spec_output,
    quiet,
):
    """Brute-force exposed API specification files on a target server.

    Sends requests to hundreds of well-known paths where Swagger, OpenAPI,
    RAML, AsyncAPI, and other API definition files are commonly exposed.
    Reports every hit with a ✓/⚠ indicator and flags confirmed spec files.

    Equivalent to `sj brute -u TARGET`.

    \b
    Examples:
      # Quick scan — use built-in wordlist (247 paths)
      python apileaks.py brute --target https://api.example.com

      # Route through Burp Suite
      python apileaks.py brute -t https://api.example.com -p http://127.0.0.1:8080

      # Expand coverage with extension variants (.json/.yaml/.yml)
      python apileaks.py brute -t https://api.example.com -e

      # Custom wordlist + save JSON results
      python apileaks.py brute -t https://api.example.com \\
          -w my_spec_paths.txt --output results.json

      # Scan a list of targets quietly
      python apileaks.py brute --target-file hosts.txt -q --output results.json

      # Authenticate with a JWT
      python apileaks.py brute -t https://api.example.com --jwt eyJ...

      # Quiet mode for CI/scripting (no per-request noise)
      python apileaks.py brute -t https://api.example.com -q
    """
    no_banner = ctx.obj.get("no_banner", False) if ctx.obj else False
    if not no_banner:
        print_banner()

    # ── Resolve target list ───────────────────────────────────────────────────
    targets = []
    if target_file:
        try:
            targets = parse_target_file(target_file)
        except click.BadParameter as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)
        if not targets:
            click.echo(f"Error: --target-file '{target_file}' contains no valid targets.", err=True)
            sys.exit(1)
    if target:
        # Prepend explicit --target; deduplicate preserving order.
        if target not in targets:
            targets.insert(0, target)
    if not targets:
        click.echo(
            "Error: Either --target or --target-file must be supplied.\n"
            "  --target URL           scan a single host\n"
            "  --target-file FILE     scan every host listed in FILE",
            err=True,
        )
        sys.exit(1)

    # ── TLS verification: --insecure wins; --proxy disables by default ────────
    verify_ssl = not insecure and (not proxy or proxy_verify_ssl)

    # ── Run brute-force for each target ───────────────────────────────────────
    all_spec_hits = []
    logger = get_logger("brute")

    for t in targets:
        hits, spec_hits = _run_spec_brute(
            t,
            brute_spec_wordlist=brute_spec_wordlist,
            brute_spec_extensions=brute_spec_extensions,
            proxy=proxy,
            timeout=timeout,
            concurrency=brute_spec_concurrency,
            verify_ssl=verify_ssl,
            jwt=jwt,
            header=header,
            user_agent_random=user_agent_random,
            user_agent_custom=user_agent_custom,
            # Per-target output only when a single target is scanned; for
            # multi-target runs the consolidated output goes to brute_spec_output.
            output_file=brute_spec_output if len(targets) == 1 else None,
            quiet=quiet,
            logger=logger,
        )
        all_spec_hits.extend(spec_hits)

    # ── Multi-target consolidated output ─────────────────────────────────────
    if len(targets) > 1:
        click.echo(f"\n{'═' * 60}")
        click.echo(f"🏁 Brute-Scan complete — {len(targets)} targets")
        click.echo(
            click.style(
                f"   Total spec files found: {len(all_spec_hits)}",
                fg="green" if all_spec_hits else "white",
                bold=bool(all_spec_hits),
            )
        )
        if all_spec_hits:
            for hit in all_spec_hits:
                click.echo(click.style(f"   → {hit['url']}", fg="green"))

        if brute_spec_output:
            import json as _json

            payload = {
                "targets": targets,
                "total_spec_hits": len(all_spec_hits),
                "spec_hits": all_spec_hits,
            }
            os.makedirs(os.path.dirname(os.path.abspath(brute_spec_output)) or ".", exist_ok=True)
            with open(brute_spec_output, "w", encoding="utf-8") as fh:
                _json.dump(payload, fh, indent=2)
            click.echo(f"\n💾 Consolidated results saved: {brute_spec_output}")


if __name__ == "__main__":
    cli()
