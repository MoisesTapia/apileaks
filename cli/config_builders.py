"""
Configuration builders — assemble the APILeak config dict from CLI inputs.

Extracted from ``apileaks.py`` (monolith decomposition, Phase 3). These functions
build the plain config dictionary that ``ConfigurationManager`` later materializes
into typed config objects; they do not depend on the rest of ``apileaks`` and are
re-imported there to preserve the public surface (tests import/call them directly).
"""

from __future__ import annotations

import os

from core import __version__ as APILEAK_VERSION
from utils.spec_import import (
    SpecSchema,
    load_schema,
)


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


def create_enhanced_config(
    target_url,
    wordlist_path=None,
    scan_type="full",
    user_agent_config=None,
    output_filename=None,
    advanced_config=None,
    status_code_filter=None,
    ci_mode=False,
    fail_on="critical",
    safe_mode=False,
    extra_headers=None,
    basic_auth=None,
    bola_config=None,
    module_configs=None,
    client_cert=None,
    ca_bundle=None,
    resolve=None,
    parameter_methods=None,
    confirm_hits=None,
    parameter_max_requests=None,
    query_candidates=None,
    body_candidates=None,
    fuzz_keyword="FUZZ",
    fuzz_mode="clusterbomb",
    marker_wordlists=None,
):
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
    target_url = target_url or os.getenv("APILEAK_TARGET", "")

    default_wordlists = {
        "endpoints": "wordlists/endpoints.txt",
        "parameters": "wordlists/parameters.txt",
        "headers": "wordlists/headers.txt",
        "jwt_secrets": "wordlists/jwt_secrets.txt",
    }

    # Use provided wordlist or default
    if wordlist_path:
        if scan_type == "dir":
            default_wordlists["endpoints"] = wordlist_path
        elif scan_type == "par":
            default_wordlists["parameters"] = wordlist_path

    # Configure user agent settings with environment variable support
    user_agent_settings = {
        "User-Agent": os.getenv("APILEAK_USER_AGENT", f"APILeak/{APILEAK_VERSION}"),
        "Accept": "application/json",
    }
    random_user_agent = False
    user_agent_list = None
    user_agent_rotation = False

    if user_agent_config:
        if user_agent_config.get("random"):
            random_user_agent = True
        elif user_agent_config.get("custom"):
            user_agent_settings["User-Agent"] = user_agent_config["custom"]
        elif user_agent_config.get("file_list"):
            user_agent_list = user_agent_config["file_list"]
            user_agent_rotation = True
            # Use first user agent as default
            user_agent_settings["User-Agent"] = user_agent_list[0]

    # Merge operator-supplied discovery headers (and the --cookie string, which
    # the caller places under the 'Cookie' key) into the header-fuzzing
    # custom_headers dict so they exist on the engine config and are applied to
    # every Discovery_Request (Requirements 24.2, 24.3).
    if extra_headers:
        user_agent_settings.update(extra_headers)

    # Configure enhanced advanced discovery settings
    advanced_discovery_config = {
        "enabled": True,  # Always enable for full integration
        "framework_detection": {
            "enabled": advanced_config.get("detect_framework", False) if advanced_config else False,
            "adapt_payloads": True,
            "test_framework_endpoints": True,
            "max_error_requests": 5,
            "timeout": 10.0,
            "confidence_threshold": advanced_config.get("framework_confidence", 0.6)
            if advanced_config
            else 0.6,
        },
        "version_fuzzing": {
            "enabled": advanced_config.get("fuzz_versions", False) if advanced_config else False,
            "version_patterns": advanced_config.get(
                "version_patterns",
                [
                    "/v1",
                    "/v2",
                    "/v3",
                    "/v4",
                    "/v5",
                    "/api/v1",
                    "/api/v2",
                    "/api/v3",
                    "/api/v4",
                    "/api/v5",
                    "/api/1",
                    "/api/2",
                    "/api/3",
                    "/1",
                    "/2",
                    "/3",
                ],
            )
            if advanced_config
            else [
                "/v1",
                "/v2",
                "/v3",
                "/v4",
                "/v5",
                "/api/v1",
                "/api/v2",
                "/api/v3",
                "/api/v4",
                "/api/v5",
            ],
            "test_endpoints": ["/", "/health", "/status", "/info", "/docs"],
            "max_concurrent_requests": 5,
            "timeout": 10.0,
            "compare_endpoints": True,
            "detect_deprecated": True,
        },
        "subdomain_discovery": advanced_config.get("enable_subdomain_discovery", False)
        if advanced_config
        else False,
        "cors_analysis": advanced_config.get("enable_cors_analysis", False)
        if advanced_config
        else False,
        "security_headers": advanced_config.get("enable_cors_analysis", False)
        if advanced_config
        else False,
        "waf_detection": {
            "enabled": advanced_config.get("enable_waf_evasion", False)
            if advanced_config
            else False,
            "adaptive_throttling": True,
            "evasion_techniques": True,
        },
        "payload_encoding": {
            "enabled": advanced_config.get("enable_payload_encoding", False)
            if advanced_config
            else False,
            "encodings": ["url", "base64", "html", "unicode"],
            "obfuscation_techniques": ["case_variation", "mutation"],
        },
    }

    # Enhanced OWASP modules configuration
    owasp_modules = (
        []
        if scan_type in ["dir", "par"]
        else [
            module.strip()
            for module in os.getenv(
                "APILEAK_MODULES", "bola,auth,property,resource,function_auth,ssrf"
            ).split(",")
        ]
        if os.getenv("APILEAK_MODULES")
        else ["bola", "auth", "property", "resource", "function_auth", "ssrf"]
    )

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
    owasp_testing = {"enabled_modules": owasp_modules}

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
            "allow_destructive": bola_config.get("allow_destructive", False),
            "enable_composite": bola_config.get("enable_composite", False),
            "enable_id_leakage": bola_config.get("enable_id_leakage", False),
            "verb_tampering": bola_config.get("verb_tampering", False),
            "parameter_pollution": bola_config.get("parameter_pollution", False),
            "dry_run": bola_config.get("dry_run", False),
        }
        destructive_methods = bola_config.get("destructive_methods")
        if destructive_methods:
            bola_testing["destructive_methods"] = destructive_methods
        normalized_module_configs.setdefault("bola_testing", bola_testing)

    for config_field, field_values in normalized_module_configs.items():
        if field_values:
            owasp_testing[config_field] = dict(field_values)

    config = {
        "target": {
            "base_url": target_url,
            "default_method": "GET",
            "timeout": int(os.getenv("APILEAK_TIMEOUT", "10")),
            "verify_ssl": os.getenv("APILEAK_VERIFY_SSL", "true").lower() == "true",
        },
        "fuzzing": {
            "endpoints": {
                "enabled": scan_type in ["full", "dir"],
                "wordlist": default_wordlists["endpoints"],
                "methods": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                "follow_redirects": True,
                "extensions": [],
                "enumerate_methods": False,
                "fuzz_keyword": "FUZZ",
                "fuzz_mode": "clusterbomb",
                "marker_wordlists": None,
            },
            "parameters": {
                "enabled": scan_type in ["full", "par"],
                "query_wordlist": default_wordlists["parameters"],
                "body_wordlist": default_wordlists["parameters"],
                "boundary_testing": scan_type == "full",  # Enable for full scans
            },
            "headers": {
                "enabled": scan_type == "full",
                "wordlist": default_wordlists["headers"],
                "custom_headers": user_agent_settings,
                "random_user_agent": random_user_agent,
                "user_agent_list": user_agent_list,
                "user_agent_rotation": user_agent_rotation,
            },
            "recursive": True,
            "max_depth": int(os.getenv("APILEAK_MAX_DEPTH", "3")),
            "response_filter": [],
            "max_requests": None,
            "concurrency": 50,
        },
        "authentication": {
            "contexts": [
                {
                    "name": "anonymous",
                    "type": "bearer",
                    "token": os.getenv("APILEAK_JWT_TOKEN", ""),
                    "privilege_level": 0,
                }
            ],
            "default_context": "anonymous",
        },
        "rate_limiting": {
            "requests_per_second": int(os.getenv("APILEAK_RATE_LIMIT", "10")),
            "burst_size": 20,
            "adaptive": True,
            "respect_retry_after": True,
            "backoff_factor": 2.0,
        },
        "reporting": {
            "formats": ["json", "html", "txt"],
            "output_dir": os.getenv("APILEAK_OUTPUT_DIR", "reports"),
            "output_filename": output_filename,
            "include_screenshots": False,
            "template_dir": "templates",
        },
        "advanced_discovery": advanced_discovery_config,
        "http_output": {"status_code_filter": status_code_filter},
        "owasp_testing": owasp_testing,
        "ci_cd_integration": {
            "enabled": ci_mode,
            "fail_on_severity": fail_on,
            "generate_artifacts": ci_mode,
            "exit_codes": {"critical": 2, "high": 1, "medium": 0, "low": 0},
        },
        "secret_scan": {
            # Secret/leak detection is opt-in (Requirement 30.1); the dir/full
            # override block flips 'enabled' and sets 'patterns' when
            # --detect-secrets/--secret-patterns are supplied. Omitting
            # 'patterns' here lets SecretScanConfig fall back to the built-in
            # DEFAULT_SECRET_PATTERNS (Requirement 30.6).
            "enabled": False
        },
        "safe_mode": safe_mode,
    }

    # Map --basic-auth onto the anonymous auth context as an HTTP Basic context
    # (type='basic' with username/password) so the existing
    # HTTPRequestEngine._apply_authentication branch emits a Basic Authorization
    # header on every Discovery_Request (Requirement 24.4).
    if basic_auth:
        username, password = basic_auth
        config["authentication"]["contexts"][0]["type"] = "basic"
        config["authentication"]["contexts"][0]["username"] = username
        config["authentication"]["contexts"][0]["password"] = password

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
        config["client_cert"] = client_cert
    if ca_bundle is not None:
        config["ca_bundle"] = ca_bundle
    if resolve is not None:
        config["resolve"] = resolve

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
    parameters_cfg = config["fuzzing"]["parameters"]
    if parameter_methods is not None:
        parameters_cfg["methods"] = parameter_methods
    if confirm_hits is not None:
        parameters_cfg["confirm_hits"] = confirm_hits
    if parameter_max_requests is not None:
        parameters_cfg["max_requests"] = parameter_max_requests
    if query_candidates is not None:
        parameters_cfg["query_candidates"] = query_candidates
    if body_candidates is not None:
        parameters_cfg["body_candidates"] = body_candidates

    # Thread the three marker-mode keys into ``fuzzing.parameters.*`` for the
    # ``par`` command (Requirements 2.4, 2.5, 5.1, 7.1). These are defaulted
    # so ``dir``/``scan``/``full``/OWASP callers that never pass them are
    # completely unaffected.
    if scan_type == "par":
        parameters_cfg["fuzz_keyword"] = fuzz_keyword
        parameters_cfg["fuzz_mode"] = fuzz_mode
        parameters_cfg["marker_wordlists"] = marker_wordlists

    # For parameter fuzzing, disable endpoint discovery and use the target directly
    if scan_type == "par":
        config["fuzzing"]["endpoints"]["enabled"] = False

    return config


def create_default_config(
    target_url,
    wordlist_path=None,
    scan_type="full",
    user_agent_config=None,
    output_filename=None,
    advanced_config=None,
    status_code_filter=None,
    extra_headers=None,
    basic_auth=None,
    client_cert=None,
    ca_bundle=None,
    resolve=None,
    parameter_methods=None,
    confirm_hits=None,
    parameter_max_requests=None,
    query_candidates=None,
    body_candidates=None,
    fuzz_keyword="FUZZ",
    fuzz_mode="clusterbomb",
    marker_wordlists=None,
):
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
    return create_enhanced_config(
        target_url,
        wordlist_path,
        scan_type,
        user_agent_config,
        output_filename,
        advanced_config,
        status_code_filter,
        False,
        "critical",
        False,
        extra_headers,
        basic_auth,
        None,
        None,
        client_cert,
        ca_bundle,
        resolve,
        parameter_methods,
        confirm_hits,
        parameter_max_requests,
        query_candidates,
        body_candidates,
        fuzz_keyword,
        fuzz_mode,
        marker_wordlists,
    )


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
            raw_methods = opts.get("bola_destructive_methods")
            bola_testing = {
                "allow_destructive": opts.get("allow_write_bola", False),
                "enable_composite": opts.get("bola_composite", False),
                "enable_id_leakage": opts.get("bola_id_leakage", False),
                "verb_tampering": opts.get("bola_verb_tampering", False),
                "parameter_pollution": opts.get("bola_parameter_pollution", False),
                "dry_run": opts.get("bola_dry_run", False),
            }
            if raw_methods:
                bola_testing["destructive_methods"] = {
                    m.strip().upper() for m in raw_methods.split(",") if m.strip()
                }
            module_configs["bola_testing"] = bola_testing
    return module_configs
