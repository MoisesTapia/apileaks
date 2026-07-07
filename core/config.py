"""
APILeak Configuration Manager
Handles YAML/JSON configuration with Pydantic validation
"""

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from .logging import get_logger

if TYPE_CHECKING:
    # Imported under TYPE_CHECKING only to avoid a circular import at module
    # load time: importing the ``utils`` package runs ``utils/__init__.py``,
    # which imports ``utils.http_client`` -> ``core.config`` (this module). The
    # ``path_scope``/``storage_status`` fields below default to ``None`` and are
    # populated later by the CLI (subtask 38.4), so no runtime import is needed.
    from utils.discovery_scope import PathScope, RecursionScope, StorageStatusSelection
    from utils.spec_import import SpecSchema

logger = get_logger(__name__)


def _default_secret_patterns() -> "dict[str, str]":
    """Return a copy of the built-in secret patterns (Requirement 30.6).

    Imported lazily inside the factory to avoid a circular import at module
    load time: ``utils`` package initialization imports ``utils.http_client``,
    which imports from ``core.config``. Deferring the import until a
    :class:`SecretScanConfig` is actually instantiated breaks that cycle.
    """
    from utils.secret_scanner import DEFAULT_SECRET_PATTERNS
    return dict(DEFAULT_SECRET_PATTERNS)


class Severity(str, Enum):
    """Finding severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AuthType(str, Enum):
    """Authentication types"""
    BEARER = "bearer"
    BASIC = "basic"
    API_KEY = "api_key"
    JWT = "jwt"


@dataclass
class TargetConfig:
    """Target configuration"""
    base_url: str
    api_version: str | None = None
    default_method: str = "GET"
    timeout: int = 10
    verify_ssl: bool = True


@dataclass
class EndpointFuzzingConfig:
    """Endpoint fuzzing configuration"""
    enabled: bool = True
    wordlist: str = "wordlists/endpoints.txt"
    methods: list[str] = field(default_factory=lambda: ["GET", "POST", "PUT", "DELETE"])
    follow_redirects: bool = True
    # Cross-domain redirect scope (Requirement 29.3). When False (the default),
    # discovery follows redirects only to the same domain as the originating
    # request, preserving the existing same-domain behavior. When True
    # (--allow-cross-domain-redirects), cross-domain redirect targets are also
    # followed.
    allow_cross_domain_redirects: bool = False
    extensions: list[str] = field(default_factory=list)
    # Method_Enumeration (Requirement 26). When enabled, an OPTIONS Discovery_Request
    # is issued for each discovered endpoint and its ``Allow`` response header is
    # parsed into the endpoint's allowed_methods. Disabled by default (26.1).
    enumerate_methods: bool = False
    # GraphQL endpoint discovery (Requirement 27). When enabled, common GraphQL
    # paths are probed against the base URL and, on detecting a GraphQL endpoint,
    # a read-only introspection query is issued to report whether introspection
    # is enabled. Disabled by default (27.1). The introspection query is a single
    # read-only operation (no mutation) so it remains Safe_Mode compatible (27.5).
    graphql: bool = False
    # In-memory merged candidate set (Spec_Import seeds + wordlist entries). When
    # not None, discovery uses these candidates directly instead of loading the
    # single ``wordlist`` file (Requirement 25.3/25.4). An empty list means no
    # candidates are available and discovery issues no Discovery_Request
    # (Requirement 25.7). None preserves the backward-compatible single-file path.
    candidate_set: list[str] | None = None
    # Per-candidate HTTP methods contributed by Spec_Import seeds, keyed by the
    # normalized candidate path. These extend the per-path method set for spec
    # seeds; brute-force entries keep ``methods`` (Requirement 25.3).
    seed_methods: dict[str, list[str]] = field(default_factory=dict)
    # Fuzz_Marker keyword substituted in the target for marker-mode discovery
    # (Requirement 39.1). Defaults to "FUZZ"; the CLI validates/overrides it.
    fuzz_keyword: str = "FUZZ"
    # Marker combination strategy across multiple Fuzz_Markers (Requirement
    # 43.1). "clusterbomb" (the default) takes the cartesian product of the
    # per-marker wordlists; "pitchfork" iterates them in lock-step.
    fuzz_mode: str = "clusterbomb"
    # Per-marker wordlists in marker order (Requirement 39/43). ``None`` means no
    # marker mode is configured, preserving the wordlist/candidate_set paths.
    marker_wordlists: list[list[str]] | None = None
    marker_wordlists: Optional[List[List[str]]] = None
    # Rich SpecSchema loaded from --openapi / --postman sources. When not None,
    # the EndpointFuzzer uses the declared per-route parameters, headers, and
    # request body to send contextually correct requests (spec-aware mode).
    # None (the default) preserves the existing brute-force behavior.
    spec_schema: "SpecSchema | None" = None
    spec_schema: Optional["SpecSchema"] = None
    # Spec-methods-only mode (--spec-methods-only). When True and a spec is
    # supplied, each spec-seeded path is probed with ONLY the method(s) declared
    # in the spec; the base ``methods`` set is suppressed for those paths.
    # Paths that come from the wordlist (not from the spec) continue using the
    # base ``methods`` set unchanged. False (the default) preserves the existing
    # extend behavior where spec methods are added on top of the base set.
    spec_methods_only: bool = False
    # Live quarantine threshold: if the host returns N consecutive "interesting"
    # (non-404) responses during scanning, discovery is halted early and the host
    # is flagged as a wildcard. 0 disables the feature. Defaults to 10, matching
    # the EndpointFuzzer.DEFAULT_QUARANTINE_THRESHOLD.
    quarantine_threshold: int | None = None  # None => use class default (10)
    quarantine_threshold: Optional[int] = None  # None => use class default (10)


@dataclass
class ParameterFuzzingConfig:
    """Parameter fuzzing configuration"""
    enabled: bool = True
    query_wordlist: str = "wordlists/parameters.txt"
    body_wordlist: str = "wordlists/parameters.txt"
    boundary_testing: bool = True
    # HTTP methods that drive injection-point selection (Requirement 6.1). The
    # fuzzer derives query fuzzing from query-carrying methods (GET/DELETE) and
    # body fuzzing from body-carrying methods (POST/PUT/PATCH). Defaults to
    # ["GET", "POST"] so both injection points run by default.
    methods: list[str] = field(default_factory=lambda: ["GET", "POST"])
    # Hit_Confirmation retest count (Requirement 5.1). None/0 => confirmation is
    # disabled and candidates are reported immediately; >=1 => the candidate is
    # re-tested N additional times (default 2 when enabled) and only reported if
    # every retest reproduces the signal.
    confirm_hits: int | None = None
    # Request_Budget upper bound (Requirement 11.1/11.5). None => unbounded; when
    # set, the total number of HTTP requests issued by the run must never exceed
    # this value.
    max_requests: int | None = None
    # In-memory merged/deduped query candidate set (Requirement 10.1/10.2). When
    # not None, it overrides the ``query_wordlist`` file for query fuzzing.
    query_candidates: list[str] | None = None
    # In-memory merged/deduped body candidate set (Requirement 10.1/10.2). When
    # not None, it overrides the ``body_wordlist`` file for body fuzzing.
    body_candidates: list[str] | None = None
    # Marker_Mode fields (identical shape to EndpointFuzzingConfig, Requirements
    # 1.1, 5.1, 7.1). All three are optional/defaulted so existing construction
    # calls are unaffected. ``marker_wordlists is None`` is the
    # Name_Discovery_Mode sentinel that keeps the existing query/body fuzzing
    # path untouched (R2.1).
    fuzz_keyword: str = "FUZZ"
    fuzz_mode: str = "clusterbomb"
    marker_wordlists: list[list[str]] | None = None


@dataclass
class HeaderFuzzingConfig:
    """Header fuzzing configuration"""
    enabled: bool = True
    wordlist: str = "wordlists/headers.txt"
    custom_headers: dict[str, str] = field(default_factory=dict)
    random_user_agent: bool = False
    user_agent_list: list[str] | None = None
    user_agent_rotation: bool = False


@dataclass
class HitConfirmationConfig:
    """Hit_Confirmation: re-request interesting candidates to reduce false
    positives (Requirement 35).

    Opt-in step in which Endpoint_Discovery re-requests each candidate
    interesting result ``count`` additional times and records it as a
    Discovery_Result only when the responses are consistent across the
    confirmation requests. ``enabled=False`` (the default) preserves the
    existing single-request behavior (Requirement 35.1).
    """
    enabled: bool = False
    count: int = 1


@dataclass
class FuzzingConfig:
    """Fuzzing configuration"""
    endpoints: EndpointFuzzingConfig = field(default_factory=EndpointFuzzingConfig)
    parameters: ParameterFuzzingConfig = field(default_factory=ParameterFuzzingConfig)
    headers: HeaderFuzzingConfig = field(default_factory=HeaderFuzzingConfig)
    recursive: bool = True
    max_depth: int = 3
    response_filter: list[int] = field(default_factory=list)
    max_requests: int | None = None  # Request_Budget; None = unbounded
    concurrency: int = 50  # Concurrency_Limit; matches the prior hardcoded batch size
    # Retry_Limit (Requirement 28). The number of automatic retries for a single
    # failed Discovery_Request. RetryConfig counts total attempts, so the engine
    # uses max_attempts = retries + 1 (the initial attempt plus the retries).
    # Defaults to 2 retries (3 attempts), preserving the prior hardcoded behavior.
    retries: int = 2
    # Discovery scope selections (Requirement 33). These are runtime selection
    # objects (not plain config primitives) compiled from CLI flags and populated
    # later by the CLI (subtask 38.4); they default to None so the keys always
    # exist on the config object.
    #   path_scope: Path_Scope include/exclude regex selection (33.1-33.4).
    #   storage_status: Storage_Status_Selection include/exclude status selection
    #     applied at storage time (33.5, 33.6).
    path_scope: "PathScope | None" = None
    storage_status: "StorageStatusSelection | None" = None
    # Recursion_Scope selection (Requirement 34). Optional runtime selection
    # object compiled from CLI flags (--recursion-status/--recursion-type) that
    # only ever narrows recursion eligibility, never relaxes it (34.3, 34.4).
    # Defaults to None so the key always exists on the config object and recursion
    # uses its default eligibility when no scope is supplied.
    recursion_scope: "RecursionScope | None" = None
    # Hit_Confirmation selection (Requirement 35). Off by default so discovery
    # keeps its existing single-request behavior (35.1); when enabled, interesting
    # candidates are re-requested ``count`` times and only recorded when the
    # responses are consistent (35.2-35.6).
    hit_confirmation: HitConfirmationConfig = field(default_factory=HitConfirmationConfig)
    # Response matchers/filters (Requirement 12.1-12.3). Shared with the ``dir``
    # selection pipeline: these are the SAME ``ResponseSelector`` objects
    # produced by ``utils.response_selector.parse_selectors`` that ``dir`` builds
    # from its ``--match-*``/``--filter-*`` flags. The ``par`` command threads
    # its parsed selectors through ``config_dict['fuzzing']['matchers']`` /
    # ``['filters']`` so parameter findings are narrowed by the identical
    # matcher-before-filter code path (retain every matcher, then exclude any
    # filter). Both default to empty lists so, when no selectors are supplied
    # (and for dir/scan/full, which never thread them here), selection is a
    # no-op and behavior is unchanged (Requirement 2 preservation).
    matchers: list[Any] = field(default_factory=list)
    filters: list[Any] = field(default_factory=list)
    # Machine-readable output settings for ``par`` findings (Requirement 12.5,
    # 12.6). Shared with the ``dir`` machine-output surface: ``par`` threads its
    # ``--output-format``/``--output-file`` selections through
    # ``config_dict['fuzzing']['output_format']`` / ``['output_file']`` so the
    # engine writes parameter findings (including their detection-signal fields)
    # through the same CSV/JSON Lines machine writer. Both default to None so,
    # when no machine output is requested (and for dir/scan/full, which never
    # thread them here), no file is written and behavior is unchanged
    # (Requirement 2 preservation).
    output_format: str | None = None
    output_file: str | None = None


@dataclass
class BOLAConfig:
    """BOLA testing configuration"""
    enabled: bool = True
    id_patterns: list[str] = field(default_factory=lambda: ["sequential", "guid", "uuid"])
    test_contexts: list[str] = field(default_factory=lambda: ["anonymous", "user", "admin"])
    # Upper bound for ownership-aware id enumeration (Requirement 4.2). Bounds the
    # sequential-id range probed by enumeration so it stays well-scoped; defaults
    # to 25 to preserve a modest, safe enumeration window.
    enumeration_bound: int = 25
    # Per-module Safe_Mode flag (Requirement 21.1). Populated by the engine from
    # the global safe_mode setting (subtask 4.2). Defaults to False so existing
    # configs and behavior are unchanged.
    safe_mode: bool = False
    # Advanced BOLA hardening options (Requirement 34). All default to the
    # current read-only behavior so existing YAML configs that omit these fields
    # load unchanged and resolve to safe defaults (Requirement 34.5).
    #   allow_destructive: gate for issuing destructive verbs; off by default (34.2).
    #   destructive_methods: verbs treated as destructive when allow_destructive
    #     is enabled. DELETE is intentionally excluded from the default set (34.2).
    #   enable_composite / enable_id_leakage: opt-in advanced probes, off by
    #     default (34.2).
    #   verb_tampering / parameter_pollution: opt-in tampering techniques, off by
    #     default (34.2).
    #   dry_run: when True, plan destructive actions without issuing them.
    allow_destructive: bool = False
    destructive_methods: set[str] = field(default_factory=lambda: {"PATCH", "PUT"})
    enable_composite: bool = False
    enable_id_leakage: bool = False
    verb_tampering: bool = False
    parameter_pollution: bool = False
    dry_run: bool = False


@dataclass
class AuthTestingConfig:
    """Authentication testing configuration"""
    enabled: bool = True
    jwt_testing: bool = True
    weak_secrets_wordlist: str = "wordlists/jwt_secrets.txt"
    test_logout_invalidation: bool = True
    # Operator-supplied public key material used for the JWT algorithm-confusion
    # attack (Requirement 6.1). When provided, it is preferred over fetching a
    # JWKS. Defaults to None so no placeholder key is ever used.
    public_key_material: str | None = None
    # JWKS endpoint URL used to fetch RSA public key material for algorithm
    # confusion when no key material is supplied directly (Requirement 6.2).
    jwks_url: str | None = None
    # Known signing secret used to construct a validly-signed-but-expired token
    # for expiration testing (Requirement 8.1). Defaults to None so the test is
    # skipped (and logged) when no signing key is known.
    signing_secret: str | None = None
    # Per-module Safe_Mode flag (Requirement 21.1). Populated by the engine from
    # the global safe_mode setting (subtask 4.2). Defaults to False.
    safe_mode: bool = False
    # Advanced authentication hardening options (Requirements 46.1, 26.1, 26.3).
    # Every default below preserves the current behavior: no aggressive or
    # state-changing probes run, and no operator-input-driven probes are issued.
    # Existing YAML configs that omit these fields load unchanged and resolve to
    # these safe defaults.
    #   allow_aggressive: opt-in gate for aggressive probes (e.g. rate-limit /
    #     revocation-race testing); off by default (26.1).
    #   allow_destructive: opt-in gate for state-changing probes; off by
    #     default (26.1).
    #   rate_limit_attempts: number of attempts used by rate-limit probes when
    #     aggressive testing is enabled.
    #   revocation_race_requests: number of concurrent requests used by
    #     token-revocation race probes when aggressive testing is enabled.
    #   benign_username: operator-supplied benign account username used by
    #     input-driven probes; None means no such probe runs (26.3).
    #   mfa_flow_inputs / oauth_flow_inputs: operator-supplied flow inputs for
    #     MFA / OAuth probes; None means those probes are skipped (26.3).
    #   reset_token_samples / reset_token_known_inputs: operator-supplied
    #     password-reset token samples / known inputs; None means reset-token
    #     analysis is skipped (26.3).
    allow_aggressive: bool = False
    allow_destructive: bool = False
    rate_limit_attempts: int = 10
    revocation_race_requests: int = 8
    benign_username: str | None = None
    mfa_flow_inputs: dict | None = None
    oauth_flow_inputs: dict | None = None
    reset_token_samples: list[str] | None = None
    reset_token_known_inputs: list[str] | None = None
    # JWT-complement hardening options (Requirements 59.1, 62.1, 67.3, 26.3).
    # All defaults preserve existing behavior so YAML configs that omit these
    # fields load unchanged and resolve to these safe, opt-in defaults.
    #   token_lifetime_threshold: upper bound (in seconds) above which a JWT
    #     lifetime is treated as excessively long (Requirement 59.1). Defaults
    #     to 3600 (one hour).
    #   ecdsa_algorithms: ECDSA algorithms considered when analyzing ES-signed
    #     tokens (Requirement 62.1). Defaults to the standard ES256/ES384/ES512.
    #   canary_value: operator-supplied canary string used by input-driven
    #     probes; None means no canary-based probe runs (Requirement 67.3, 26.3).
    token_lifetime_threshold: int = 3600
    ecdsa_algorithms: list[str] = field(default_factory=lambda: ["ES256", "ES384", "ES512"])
    canary_value: str | None = None
    ecdsa_algorithms: List[str] = field(default_factory=lambda: ["ES256", "ES384", "ES512"])
    canary_value: Optional[str] = None
    # -------------------------------------------------------------------
    # OTP / MFA brute-force fields (Levels 2 & Expert).
    # All default to None / 0 so existing configs load unchanged.
    # -------------------------------------------------------------------
    # URL of the OTP/MFA verification endpoint (e.g. /api/v1/auth/otp/verify).
    # Required for OTP brute-force and OTP race-condition probes.
    otp_endpoint: str | None = None
    otp_endpoint: Optional[str] = None
    # Number of digits in the OTP code (4 or 6 are the most common).
    otp_digits: int = 6
    # JSON field name carrying the OTP code in the verification request body.
    otp_field: str = "otp"
    # Session / provisional token field name sent alongside the OTP code.
    otp_session_field: str = "session_token"
    # Operator-supplied provisional/session token obtained before the OTP step.
    otp_session_token: str | None = None
    otp_session_token: Optional[str] = None
    # Number of parallel goroutines for the OTP race-condition probe.
    otp_race_concurrency: int = 50
    # -------------------------------------------------------------------
    # Password-spraying fields (Level 3 Advanced).
    # -------------------------------------------------------------------
    # Path to a file containing one username / email per line.
    users_wordlist: str | None = None
    # Single password to spray across all usernames.
    spray_password: str | None = None
    users_wordlist: Optional[str] = None
    # Single password to spray across all usernames.
    spray_password: Optional[str] = None
    # Maximum requests per spray batch before a pause (safety bound).
    spray_batch_size: int = 50
    # JSON field names for username and password in the login body.
    login_username_field: str = "username"
    login_password_field: str = "password"
    # -------------------------------------------------------------------
    # IP-rotation / header-injection fields (Level 3 Advanced).
    # -------------------------------------------------------------------
    # Number of requests per IP-rotation burst.
    ip_rotation_burst: int = 15
    # Extra override headers to test beyond the built-in list.
    extra_ip_headers: list[str] = field(default_factory=list)
    extra_ip_headers: List[str] = field(default_factory=list)
    # -------------------------------------------------------------------
    # Timing / Content-Length oracle fields (Expert level).
    # -------------------------------------------------------------------
    # Number of baseline samples per valid/invalid username for timing oracle.
    timing_samples: int = 10
    # Minimum timing difference (seconds) to classify as a timing leak.
    timing_threshold: float = 0.05


@dataclass
class PropertyTestingConfig:
    """Property level authorization testing configuration"""
    enabled: bool = True
    sensitive_fields: list[str] = field(default_factory=lambda: [
        "password", "api_key", "secret", "token", "ssn", "credit_card"
    ])
    mass_assignment_fields: list[str] = field(default_factory=lambda: [
        "is_admin", "role", "permissions", "user_id"
    ])
    # Per-module Safe_Mode flag (Requirement 21.1). Populated by the engine from
    # the global safe_mode setting (subtask 4.2). Defaults to False.
    safe_mode: bool = False


@dataclass
class ResourceTestingConfig:
    """Resource consumption testing configuration"""
    enabled: bool = True
    burst_size: int = 100
    large_payload_sizes: list[int] = field(default_factory=lambda: [1024*1024, 10*1024*1024])
    json_depth_limit: int = 1000


@dataclass
class FunctionAuthConfig:
    """Function level authorization testing configuration (OWASP API5)."""
    enabled: bool = True
    # Known administrative URL path prefixes to probe with low-privilege tokens.
    admin_endpoints: list[str] = field(default_factory=lambda: [
        "/admin", "/api/admin", "/management", "/dashboard"
    ])
    # HTTP methods treated as privileged for verb-tampering probes.
    dangerous_methods: list[str] = field(default_factory=lambda: ["DELETE", "PUT", "PATCH"])
    admin_endpoints: List[str] = field(default_factory=lambda: [
        "/admin", "/api/admin", "/management", "/dashboard"
    ])
    # HTTP methods treated as privileged for verb-tampering probes.
    dangerous_methods: List[str] = field(default_factory=lambda: ["DELETE", "PUT", "PATCH"])
    # -----------------------------------------------------------------------
    # Multi-token / grey-box BFLA fields (Levels 1-4).
    # -----------------------------------------------------------------------
    # Safe_Mode: when True only read-only (GET/HEAD/OPTIONS) probes are issued.
    safe_mode: bool = False
    # Opt-in for state-changing (destructive) replay probes (PUT/POST/DELETE).
    # When False only GET replays are issued against discovered admin endpoints.
    allow_destructive: bool = False
    # -----------------------------------------------------------------------
    # Level 3 – Mass-assignment role injection.
    # JSON field names and values tried as privilege-escalation payloads.
    # -----------------------------------------------------------------------
    role_fields: list[str] = field(default_factory=lambda: [
    role_fields: List[str] = field(default_factory=lambda: [
        "role", "roles", "user_role", "userRole", "user_type", "userType",
        "is_admin", "isAdmin", "admin", "privilege", "access_level",
        "accessLevel", "permission", "permissions",
    ])
    role_values: list[str] = field(default_factory=lambda: [
    role_values: List[str] = field(default_factory=lambda: [
        "admin", "administrator", "ADMIN", "SUPER_ADMIN", "superadmin",
        "root", "owner", "manager",
    ])
    # -----------------------------------------------------------------------
    # Level 4 – API version downgrade.
    # Version strings to try when downgrading discovered versioned endpoints.
    # -----------------------------------------------------------------------
    api_versions: list[str] = field(default_factory=lambda: [
    api_versions: List[str] = field(default_factory=lambda: [
        "v1", "v2", "v3", "v4", "v0",
    ])
    # -----------------------------------------------------------------------
    # Output – persist BFLA matrix to a JSON file for downstream analysis.
    # -----------------------------------------------------------------------
    bfla_output_file: str | None = None
    bfla_output_file: Optional[str] = None


@dataclass
class SSRFConfig:
    """SSRF testing configuration"""
    enabled: bool = True
    internal_targets: list[str] = field(default_factory=lambda: [
        "127.0.0.1", "localhost", "169.254.169.254", "metadata.google.internal"
    ])
    file_protocols: list[str] = field(default_factory=lambda: ["file://", "ftp://"])

    # Expanded fields (Requirement 1.1–1.7)
    # Authoritative safe-mode flag — replaces getattr fallbacks (Req 1.1, 10.6).
    safe_mode: bool = False
    # OOB callback listener URL for blind SSRF detection (Req 1.2).
    callback_url: str | None = None
    # Extra internal hosts/IPs to probe in addition to internal_targets (Req 1.3).
    additional_internal_targets: list[str] = field(default_factory=list)
    # Extra URL schemes to test in addition to file_protocols (Req 1.4).
    additional_schemes: list[str] = field(default_factory=list)
    # Gate for internal port-scanning probes (Req 1.5).
    allow_port_scan: bool = False
    # Ports to probe when allow_port_scan is True (Req 1.6).
    scan_ports: list[int] = field(default_factory=lambda: [
        22, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017
    ])
    # When True, IP-encoding bypass payloads (decimal, octal, hex, IPv6) are
    # generated and injected alongside the plain internal targets (Req 1.7).
    bypass_encodings: bool = True
    # When True, SSRF payloads are injected into JSON request body fields on
    # POST/PUT/PATCH endpoints (Req 1.4, 3.1–3.5).
    body_injection: bool = False
    # HTTP methods to use for body injection probes. When non-empty, body
    # injection is attempted with each of these methods regardless of the
    # method the discovery engine recorded for the endpoint. This lets the
    # operator force POST/PUT/PATCH body probes even when the endpoint was
    # discovered via GET. Defaults to empty list (use the endpoint's own method).
    body_injection_methods: list[str] = field(default_factory=list)
    # --- Import source fields (--burp-xml / --har / --ssrf-body-field) ----
    # Path to a Burp Suite XML Proxy-History export file.
    burp_xml_path: str | None = None
    # Path to a HAR (HTTP Archive) JSON file.
    har_path: str | None = None
    # Explicit body field names to always probe (merged with auto-detection).
    extra_body_fields: list[str] = field(default_factory=list)
    # --- Response filtering -----------------------------------------------
    # When True, only emit a finding when a known internal-target signature is
    # matched in the response body. Plain 2xx responses without a signature are
    # suppressed. Use this to eliminate false positives on APIs that return 200
    # for any URL parameter regardless of what was fetched.
    require_signature: bool = False
    # HTTP status codes considered a "success hit" for SSRF_INTERNAL_ACCESS
    # detection (in addition to signature matches). Defaults to the 2xx range.
    # Set to a narrower list (e.g. [200]) to reduce noise on APIs that return
    # other 2xx codes normally.
    success_status_codes: list[int] = field(default_factory=lambda: list(range(200, 300)))

    # Expanded fields (Requirement 1.1–1.7)
    # Authoritative safe-mode flag — replaces getattr fallbacks (Req 1.1, 10.6).
    safe_mode: bool = False
    # OOB callback listener URL for blind SSRF detection (Req 1.2).
    callback_url: Optional[str] = None
    # Extra internal hosts/IPs to probe in addition to internal_targets (Req 1.3).
    additional_internal_targets: List[str] = field(default_factory=list)
    # Extra URL schemes to test in addition to file_protocols (Req 1.4).
    additional_schemes: List[str] = field(default_factory=list)
    # Gate for internal port-scanning probes (Req 1.5).
    allow_port_scan: bool = False
    # Ports to probe when allow_port_scan is True (Req 1.6).
    scan_ports: List[int] = field(default_factory=lambda: [
        22, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017
    ])
    # When True, IP-encoding bypass payloads (decimal, octal, hex, IPv6) are
    # generated and injected alongside the plain internal targets (Req 1.7).
    bypass_encodings: bool = True
    # When True, SSRF payloads are injected into JSON request body fields on
    # POST/PUT/PATCH endpoints (Req 1.4, 3.1–3.5).
    body_injection: bool = False
    # HTTP methods to use for body injection probes. When non-empty, body
    # injection is attempted with each of these methods regardless of the
    # method the discovery engine recorded for the endpoint. This lets the
    # operator force POST/PUT/PATCH body probes even when the endpoint was
    # discovered via GET. Defaults to empty list (use the endpoint's own method).
    body_injection_methods: List[str] = field(default_factory=list)
    # --- Import source fields (--burp-xml / --har / --ssrf-body-field) ----
    # Path to a Burp Suite XML Proxy-History export file.
    burp_xml_path: Optional[str] = None
    # Path to a HAR (HTTP Archive) JSON file.
    har_path: Optional[str] = None
    # Explicit body field names to always probe (merged with auto-detection).
    extra_body_fields: List[str] = field(default_factory=list)
    # --- Response filtering -----------------------------------------------
    # When True, only emit a finding when a known internal-target signature is
    # matched in the response body. Plain 2xx responses without a signature are
    # suppressed. Use this to eliminate false positives on APIs that return 200
    # for any URL parameter regardless of what was fetched.
    require_signature: bool = False
    # HTTP status codes considered a "success hit" for SSRF_INTERNAL_ACCESS
    # detection (in addition to signature matches). Defaults to the 2xx range.
    # Set to a narrower list (e.g. [200]) to reduce noise on APIs that return
    # other 2xx codes normally.
    success_status_codes: List[int] = field(default_factory=lambda: list(range(200, 300)))


@dataclass
class BusinessFlowConfig:
    """Business flow (unrestricted access to sensitive flows) testing configuration"""
    enabled: bool = True
    sensitive_flow_patterns: list[str] = field(default_factory=lambda: [
        "/checkout", "/purchase", "/order", "/transfer", "/register", "/coupon", "/payment"])
    repetition_limit: int = 50


@dataclass
class SecurityMisconfigConfig:
    """Security misconfiguration testing configuration"""
    enabled: bool = True
    required_headers: list[str] = field(default_factory=lambda: [
        "Strict-Transport-Security", "X-Content-Type-Options",
        "X-Frame-Options", "Content-Security-Policy"])


@dataclass
class InventoryConfig:
    """Improper inventory management testing configuration"""
    enabled: bool = True
    detect_deprecated: bool = True


@dataclass
class UnsafeConsumptionConfig:
    """Unsafe consumption of APIs testing configuration"""
    enabled: bool = True
    upstream_indicators: list[str] = field(default_factory=lambda: ["proxy", "upstream", "external", "aggregate"])
    malformed_payloads: list[str] = field(default_factory=lambda: ['{"__proto__":{}}', "<script>", "' OR 1=1--", "\u0000"])


@dataclass
class OWASPConfig:
    """OWASP testing configuration"""
    enabled_modules: list[str] = field(default_factory=lambda: [
        "bola", "auth", "property", "resource", "function_auth", "ssrf",
        "business_flow", "security_misconfig", "inventory", "unsafe_consumption"
    ])
    bola_testing: BOLAConfig = field(default_factory=BOLAConfig)
    auth_testing: AuthTestingConfig = field(default_factory=AuthTestingConfig)
    property_testing: PropertyTestingConfig = field(default_factory=PropertyTestingConfig)
    resource_testing: ResourceTestingConfig = field(default_factory=ResourceTestingConfig)
    function_auth_testing: FunctionAuthConfig = field(default_factory=FunctionAuthConfig)
    ssrf_testing: SSRFConfig = field(default_factory=SSRFConfig)
    business_flow_testing: BusinessFlowConfig = field(default_factory=BusinessFlowConfig)
    security_misconfig_testing: SecurityMisconfigConfig = field(default_factory=SecurityMisconfigConfig)
    inventory_testing: InventoryConfig = field(default_factory=InventoryConfig)
    unsafe_consumption_testing: UnsafeConsumptionConfig = field(default_factory=UnsafeConsumptionConfig)
    # Optional Spec_Schema merged from the repeatable ``--openapi`` / ``--postman``
    # sources supplied to the ``full`` command (Requirement 49.2). Defaults to
    # ``None`` and is NOT sourced from YAML by ``_build_owasp_config``, so
    # existing configuration files load unchanged (Requirement 49.3). The CLI
    # attaches the merged schema post-load so the OWASP modules can test the
    # declared Spec_Operations in addition to discovered endpoints.
    spec_schema: "SpecSchema | None" = None


@dataclass
class ActorProfile:
    """Per-identity typed inputs keyed by endpoint (Requirement 54.1).

    An Actor_Profile carries the realistic per-actor inputs a specific
    :class:`AuthContext` should use when the OWASP modules issue requests under
    that identity, in addition to the token carried by ``--auth-context``. Both
    maps are keyed by endpoint (path) so a module can look up the values for the
    endpoint it is about to request:

    - ``query``: ``endpoint -> {param: value}`` query-string values.
    - ``body``:  ``endpoint -> {field: value}`` request-body values.

    Consumption (merging the values into requests) is handled by subtask 47.2;
    this model and its loader only make the inputs available.
    """
    context_name: str                                                  # matches AuthContext.name
    query: dict[str, dict[str, Any]] = field(default_factory=dict)      # endpoint -> {param: value}
    body: dict[str, dict[str, Any]] = field(default_factory=dict)       # endpoint -> {field: value}


def load_actor_profiles(source: str) -> dict[str, ActorProfile]:
    """Parse a JSON/YAML Actor_Profile source into ``{context_name: ActorProfile}``.

    The source is a JSON or YAML document (dispatched on the file suffix, with a
    JSON-then-YAML fallback for unrecognized suffixes) whose top level maps each
    Auth_Context name to a profile object carrying optional ``query`` and
    ``body`` maps (Requirement 54.1)::

        {
          "alice": {
            "query": {"/api/orders": {"tenant": "acme"}},
            "body":  {"/api/orders": {"owner": "alice"}}
          },
          "bob": {"body": {"/api/orders": {"owner": "bob"}}}
        }

    Returns a mapping keyed by ``context_name`` so the CLI can attach each
    profile to the matching :class:`AuthContext`.

    Raises a descriptive :class:`ValueError` that names the offending ``source``
    whenever the file is missing, cannot be parsed, or is not shaped as
    described, so the caller can abort BEFORE any request is issued
    (Requirement 54.5).
    """
    profile_file = Path(source)
    if not profile_file.exists():
        raise ValueError(f"Actor profile source '{source}' does not exist")

    try:
        raw_text = profile_file.read_text(encoding='utf-8')
    except OSError as exc:
        raise ValueError(f"Actor profile source '{source}' cannot be read: {exc}") from exc

    suffix = profile_file.suffix.lower()
    try:
        if suffix in ('.yaml', '.yml'):
            data = yaml.safe_load(raw_text)
        elif suffix == '.json':
            data = json.loads(raw_text)
        else:
            # Unknown/absent suffix: try JSON first (a strict subset of YAML),
            # then fall back to YAML so both formats are accepted.
            try:
                data = json.loads(raw_text)
            except json.JSONDecodeError:
                data = yaml.safe_load(raw_text)
    except (yaml.YAMLError, json.JSONDecodeError) as exc:
        raise ValueError(f"Actor profile source '{source}' could not be parsed: {exc}") from exc

    if data is None:
        raise ValueError(
            f"Actor profile source '{source}' is empty; expected a mapping of "
            f"context name to a profile with optional 'query'/'body' maps"
        )
    if not isinstance(data, dict):
        raise ValueError(
            f"Actor profile source '{source}' must be a mapping of context name "
            f"to a profile object (got {type(data).__name__})"
        )

    profiles: dict[str, ActorProfile] = {}
    for context_name, profile_data in data.items():
        if not isinstance(context_name, str):
            raise ValueError(
                f"Actor profile source '{source}' has a non-string context name: "
                f"{context_name!r}"
            )
        if not isinstance(profile_data, dict):
            raise ValueError(
                f"Actor profile source '{source}' entry for context "
                f"'{context_name}' must be a mapping with optional 'query'/'body' "
                f"maps (got {type(profile_data).__name__})"
            )

        query = profile_data.get('query', {}) or {}
        body = profile_data.get('body', {}) or {}
        for section_name, section in (('query', query), ('body', body)):
            if not isinstance(section, dict):
                raise ValueError(
                    f"Actor profile source '{source}' '{section_name}' for context "
                    f"'{context_name}' must map an endpoint to a {{name: value}} "
                    f"object (got {type(section).__name__})"
                )
            for endpoint, values in section.items():
                if not isinstance(values, dict):
                    raise ValueError(
                        f"Actor profile source '{source}' '{section_name}' for "
                        f"context '{context_name}' endpoint '{endpoint}' must be a "
                        f"{{name: value}} object (got {type(values).__name__})"
                    )

        profiles[context_name] = ActorProfile(
            context_name=context_name,
            query=query,
            body=body,
        )

    return profiles


@dataclass
class UnauthorizedEndpointAssertion:
    """Operator-declared expectation that a set of endpoints are forbidden for
    an identity (Requirement 55.1).

    An Unauthorized_Endpoint_Assertion is scoped to a specific
    :class:`AuthContext` (by ``context_name``) and declares one or more endpoint
    ``patterns`` (regular expressions) that SHOULD be forbidden for that
    identity. The relevant OWASP module later calibrates whether the context is
    actually granted access to a matching endpoint and, if so, reports a
    broken-access-control finding (Requirement 55.2); evaluation is handled by a
    later subtask, this model and its loader only make the assertions available.
    """
    context_name: str                       # matches AuthContext.name
    patterns: list[str] = field(default_factory=list)  # endpoint regular expressions


def load_unauthorized_assertions(source: str) -> dict[str, list["re.Pattern"]]:
    """Parse an Unauthorized_Endpoint_Assertion source into per-context patterns.

    The source is a JSON or YAML document (dispatched on the file suffix, with a
    JSON-then-YAML fallback for unrecognized suffixes) whose top level maps each
    Auth_Context name to one or more endpoint-pattern regular expressions
    (Requirement 55.1)::

        {
          "alice": ["^/admin", "/api/secret/.*"],
          "bob":   ["^/internal/"]
        }

    A single string is accepted as shorthand for a one-element list. Returns a
    mapping keyed by ``context_name`` to the list of COMPILED regex patterns so
    the CLI can attach the assertions to the matching :class:`AuthContext` and
    the OWASP modules can match endpoints directly.

    Raises a descriptive :class:`ValueError` that names the offending ``source``
    whenever the file is missing, cannot be parsed, is not shaped as described,
    or contains a pattern that fails to compile, so the caller can abort BEFORE
    any request is issued (consistent with Requirement 54.5 and Requirement
    55.1).
    """
    assertion_file = Path(source)
    if not assertion_file.exists():
        raise ValueError(f"Unauthorized assertion source '{source}' does not exist")

    try:
        raw_text = assertion_file.read_text(encoding='utf-8')
    except OSError as exc:
        raise ValueError(
            f"Unauthorized assertion source '{source}' cannot be read: {exc}"
        ) from exc

    suffix = assertion_file.suffix.lower()
    try:
        if suffix in ('.yaml', '.yml'):
            data = yaml.safe_load(raw_text)
        elif suffix == '.json':
            data = json.loads(raw_text)
        else:
            # Unknown/absent suffix: try JSON first (a strict subset of YAML),
            # then fall back to YAML so both formats are accepted.
            try:
                data = json.loads(raw_text)
            except json.JSONDecodeError:
                data = yaml.safe_load(raw_text)
    except (yaml.YAMLError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"Unauthorized assertion source '{source}' could not be parsed: {exc}"
        ) from exc

    if data is None:
        raise ValueError(
            f"Unauthorized assertion source '{source}' is empty; expected a "
            f"mapping of context name to a list of endpoint pattern regular "
            f"expressions"
        )
    if not isinstance(data, dict):
        raise ValueError(
            f"Unauthorized assertion source '{source}' must be a mapping of "
            f"context name to endpoint pattern regular expressions "
            f"(got {type(data).__name__})"
        )

    assertions: dict[str, list[re.Pattern]] = {}
    for context_name, raw_patterns in data.items():
        if not isinstance(context_name, str):
            raise ValueError(
                f"Unauthorized assertion source '{source}' has a non-string "
                f"context name: {context_name!r}"
            )

        # A single string is shorthand for a one-element pattern list.
        if isinstance(raw_patterns, str):
            pattern_list = [raw_patterns]
        elif isinstance(raw_patterns, list):
            pattern_list = raw_patterns
        else:
            raise ValueError(
                f"Unauthorized assertion source '{source}' entry for context "
                f"'{context_name}' must be a string or a list of endpoint "
                f"pattern regular expressions (got {type(raw_patterns).__name__})"
            )

        compiled: list[re.Pattern] = []
        for pattern in pattern_list:
            if not isinstance(pattern, str):
                raise ValueError(
                    f"Unauthorized assertion source '{source}' pattern for "
                    f"context '{context_name}' must be a string (got "
                    f"{type(pattern).__name__})"
                )
            try:
                compiled.append(re.compile(pattern))
            except re.error as exc:
                raise ValueError(
                    f"Unauthorized assertion source '{source}' has an invalid "
                    f"regular expression for context '{context_name}': "
                    f"{pattern!r} ({exc})"
                ) from exc

        assertions[context_name] = compiled

    return assertions


@dataclass
class AuthContext:
    """Authentication context"""
    name: str
    type: AuthType
    token: str
    username: str | None = None
    password: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    privilege_level: int = 1
    actor_profile: "ActorProfile | None" = None
    unauthorized_patterns: list["re.Pattern"] | None = None


@dataclass
class AuthConfig:
    """Authentication configuration"""
    contexts: list[AuthContext] = field(default_factory=list)
    default_context: str | None = None


@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""
    requests_per_second: int = 10
    burst_size: int = 20
    adaptive: bool = True
    respect_retry_after: bool = True
    backoff_factor: float = 2.0


@dataclass
class ReportConfig:
    """Report generation configuration"""
    formats: list[str] = field(default_factory=lambda: ["json", "html", "txt"])
    output_dir: str = "reports"
    output_filename: str | None = None
    include_screenshots: bool = False
    template_dir: str = "templates"


@dataclass
class AdvancedDiscoveryConfig:
    """Advanced discovery configuration"""
    enabled: bool = True

    # Framework Detection Configuration
    framework_detection: dict[str, Any] = field(default_factory=lambda: {
        'enabled': False,
        'adapt_payloads': True,
        'test_framework_endpoints': True,
        'max_error_requests': 5,
        'timeout': 10.0,
        'confidence_threshold': 0.6
    })

    # Version Fuzzing Configuration
    version_fuzzing: dict[str, Any] = field(default_factory=lambda: {
        'enabled': False,
        'version_patterns': [
            "/v1", "/v2", "/v3", "/v4", "/v5",
            "/api/v1", "/api/v2", "/api/v3", "/api/v4", "/api/v5",
            "/api/1", "/api/2", "/api/3",
            "/1", "/2", "/3"
        ],
        'test_endpoints': ["/", "/health", "/status", "/info", "/docs"],
        'max_concurrent_requests': 5,
        'timeout': 10.0,
        'compare_endpoints': True,
        'detect_deprecated': True
    })

    # Legacy subdomain discovery (kept for backward compatibility)
    subdomain_discovery: bool = True
    cors_analysis: bool = True
    security_headers: bool = True
    subdomain_wordlist: list[str] = field(default_factory=lambda: [
        "api", "dev", "staging", "test", "qa", "uat", "prod", "production",
        "www", "admin", "management", "dashboard", "portal", "app", "mobile",
        "v1", "v2", "v3", "beta", "alpha", "demo", "sandbox", "internal"
    ])
    cors_test_origins: list[str] = field(default_factory=lambda: [
        "https://evil.com", "https://attacker.com", "http://localhost:3000",
        "https://example.com", "null", "*"
    ])
    max_concurrent: int = 10
    timeout: float = 10.0

    # WAF detection / evasion configuration
    waf_detection: dict[str, Any] = field(default_factory=lambda: {
        'enabled': False,
        'adaptive_throttling': True,
        'evasion_techniques': True
    })

    # Payload encoding / obfuscation configuration
    payload_encoding: dict[str, Any] = field(default_factory=lambda: {
        'enabled': False,
        'encodings': ['url', 'base64', 'html', 'unicode'],
        'obfuscation_techniques': ['case_variation', 'mutation']
    })


@dataclass
class CICDIntegrationConfig:
    """CI/CD integration configuration"""
    enabled: bool = False
    fail_on_severity: str = "critical"  # critical, high, medium, low
    generate_artifacts: bool = True
    exit_codes: dict[str, int] = field(default_factory=lambda: {
        "critical": 2,
        "high": 1,
        "medium": 0,
        "low": 0
    })
    artifact_formats: list[str] = field(default_factory=lambda: ["json", "xml"])


@dataclass
class HTTPOutputConfig:
    """HTTP output configuration"""
    status_code_filter: list[int] | None = None


@dataclass
class SecretScanConfig:
    """Secret/leak detection configuration (Requirement 30).

    Opt-in scanning of discovery response bodies and headers for secrets and
    sensitive data. Disabled by default (Requirement 30.1). ``patterns`` is a
    configurable name -> regex map (Requirement 30.6); it defaults to
    :data:`DEFAULT_SECRET_PATTERNS` so enabling detection without supplying a
    custom pattern file uses the built-in high-signal patterns.
    """
    enabled: bool = False
    patterns: dict[str, str] = field(
        default_factory=_default_secret_patterns
    )


@dataclass
class APILeakConfig:
    """Main APILeak configuration"""
    target: TargetConfig
    fuzzing: FuzzingConfig = field(default_factory=FuzzingConfig)
    owasp_testing: OWASPConfig = field(default_factory=OWASPConfig)
    authentication: AuthConfig = field(default_factory=AuthConfig)
    rate_limiting: RateLimitConfig = field(default_factory=RateLimitConfig)
    reporting: ReportConfig = field(default_factory=ReportConfig)
    advanced_discovery: AdvancedDiscoveryConfig = field(default_factory=AdvancedDiscoveryConfig)
    http_output: HTTPOutputConfig = field(default_factory=HTTPOutputConfig)
    ci_cd_integration: CICDIntegrationConfig = field(default_factory=CICDIntegrationConfig)
    secret_scan: SecretScanConfig = field(default_factory=SecretScanConfig)
    safe_mode: bool = False
    proxy: str | None = None
    proxy_verify_ssl: bool = False
    # Transport/TLS options for discovery (Requirement 29). These are threaded
    # into the discovery HTTPRequestEngine construction.
    #   client_cert: mTLS client certificate. A path string, or a (cert, key)
    #     tuple when the CLI supplies the cert:key form (29.1).
    #   ca_bundle: custom CA bundle path used to verify target certificates;
    #     overrides the boolean verify only when supplied (29.2).
    #   resolve: a (host, ip) DNS override applied to every Discovery_Request
    #     for the named host (29.4).
    client_cert: str | tuple[str, str] | None = None
    ca_bundle: str | None = None
    resolve: tuple[str, str] | None = None


class ConfigurationManager:
    """
    Configuration Manager with YAML/JSON support and Pydantic validation
    """

    def __init__(self):
        self.config: APILeakConfig | None = None
        self.logger = get_logger(__name__)

    def load_config_from_dict(self, config_data: dict[str, Any]) -> APILeakConfig:
        """
        Load configuration from dictionary

        Args:
            config_data: Configuration dictionary

        Returns:
            Validated APILeakConfig instance

        Raises:
            ValidationError: If configuration is invalid
        """
        self.logger.info("Loading configuration from dictionary")

        try:
            # Convert dict to APILeakConfig
            self.config = self._dict_to_config(config_data)

            self.logger.info("Configuration loaded successfully from dictionary",
                           modules_enabled=len(self.config.owasp_testing.enabled_modules),
                           auth_contexts=len(self.config.authentication.contexts))

            return self.config

        except Exception as e:
            self.logger.error("Configuration loading from dictionary failed", error=str(e))
            raise

    def load_config(self, config_path: str) -> APILeakConfig:
        """
        Load configuration from YAML or JSON file

        Args:
            config_path: Path to configuration file

        Returns:
            Validated APILeakConfig instance

        Raises:
            FileNotFoundError: If config file doesn't exist
            ValidationError: If configuration is invalid
            ValueError: If file format is unsupported
        """
        config_file = Path(config_path)

        if not config_file.exists():
            self.logger.error("Configuration file not found", path=config_path)
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        self.logger.info("Loading configuration", path=config_path)

        try:
            with open(config_file, encoding='utf-8') as f:
                if config_file.suffix.lower() in ['.yaml', '.yml']:
                    config_data = yaml.safe_load(f)
                elif config_file.suffix.lower() == '.json':
                    config_data = json.load(f)
                else:
                    raise ValueError(f"Unsupported config format: {config_file.suffix}")

            # Convert dict to APILeakConfig
            self.config = self._dict_to_config(config_data)

            self.logger.info("Configuration loaded successfully",
                           modules_enabled=len(self.config.owasp_testing.enabled_modules),
                           auth_contexts=len(self.config.authentication.contexts))

            return self.config

        except yaml.YAMLError as e:
            self.logger.error("YAML parsing error", error=str(e))
            raise ValueError(f"Invalid YAML format: {e}") from e
        except json.JSONDecodeError as e:
            self.logger.error("JSON parsing error", error=str(e))
            raise ValueError(f"Invalid JSON format: {e}") from e
        except Exception as e:
            self.logger.error("Configuration loading failed", error=str(e))
            raise

    def _dict_to_config(self, config_data: dict[str, Any]) -> APILeakConfig:
        """Convert dictionary to APILeakConfig with validation"""
        try:
            # Extract target config (required)
            target_data = config_data.get('target', {})
            if not target_data.get('base_url'):
                raise ValueError("target.base_url is required")

            target = TargetConfig(**target_data)

            # Extract optional configs with defaults
            fuzzing_data = config_data.get('fuzzing', {})
            fuzzing = self._build_fuzzing_config(fuzzing_data)

            owasp_data = config_data.get('owasp_testing', {})
            owasp = self._build_owasp_config(owasp_data)

            auth_data = config_data.get('authentication', {})
            auth = self._build_auth_config(auth_data)

            rate_limit_data = config_data.get('rate_limiting', {})
            rate_limiting = RateLimitConfig(**rate_limit_data)

            report_data = config_data.get('reporting', {})
            reporting = ReportConfig(**report_data)

            advanced_data = config_data.get('advanced_discovery', {})
            advanced_discovery = AdvancedDiscoveryConfig(**advanced_data)

            http_output_data = config_data.get('http_output', {})
            http_output = HTTPOutputConfig(**http_output_data)

            ci_cd_data = config_data.get('ci_cd_integration', {})
            ci_cd_integration = CICDIntegrationConfig(**ci_cd_data)

            secret_scan_data = config_data.get('secret_scan', {})
            secret_scan = self._build_secret_scan_config(secret_scan_data)

            return APILeakConfig(
                target=target,
                fuzzing=fuzzing,
                owasp_testing=owasp,
                authentication=auth,
                rate_limiting=rate_limiting,
                reporting=reporting,
                advanced_discovery=advanced_discovery,
                http_output=http_output,
                ci_cd_integration=ci_cd_integration,
                secret_scan=secret_scan,
                safe_mode=config_data.get('safe_mode', False),
                proxy=config_data.get('proxy'),
                proxy_verify_ssl=config_data.get('proxy_verify_ssl', False),
                client_cert=config_data.get('client_cert'),
                ca_bundle=config_data.get('ca_bundle'),
                resolve=config_data.get('resolve')
            )

        except Exception as e:
            self.logger.error("Configuration validation failed", error=str(e))
            raise ValueError(f"Configuration validation failed: {e}") from e

    def _build_fuzzing_config(self, data: dict[str, Any]) -> FuzzingConfig:
        """Build fuzzing configuration from dict"""
        endpoints_data = data.get('endpoints', {})
        endpoints = EndpointFuzzingConfig(**endpoints_data)

        # Map ``fuzzing.parameters.*`` into the extended ParameterFuzzingConfig
        # (Requirements 11.4, 12.4; design §4). The dataclass was extended in
        # task 4.1 with defaulted fields ``methods``, ``confirm_hits``,
        # ``max_requests``, ``query_candidates`` and ``body_candidates`` in
        # addition to the original ``enabled``/``query_wordlist``/
        # ``body_wordlist``/``boundary_testing`` fields. The ``**params_data``
        # unpacking maps every key the CLI threads under this path
        # (apileaks.py::par writes methods/confirm_hits/max_requests/
        # query_candidates/body_candidates) onto the matching dataclass field;
        # any key the CLI omits falls back to the field's default. This is the
        # single mapping site, so ``validate_configuration()`` (invoked by the
        # CLI immediately after ``load_config_from_dict`` and before any request)
        # always runs against the fully-populated config.
        params_data = data.get('parameters', {})
        parameters = ParameterFuzzingConfig(**params_data)

        headers_data = data.get('headers', {})
        headers = HeaderFuzzingConfig(**headers_data)

        # Hit_Confirmation (Requirement 35). Defaults to disabled; when present
        # in the config dict it is built from the supplied mapping so it can be
        # threaded in by the CLI (subtask 40.3) via
        # ``config_dict['fuzzing']['hit_confirmation']``. Accept either a prebuilt
        # HitConfirmationConfig or a plain dict.
        hit_confirmation_data = data.get('hit_confirmation')
        if isinstance(hit_confirmation_data, HitConfirmationConfig):
            hit_confirmation = hit_confirmation_data
        elif hit_confirmation_data:
            hit_confirmation = HitConfirmationConfig(**hit_confirmation_data)
        else:
            hit_confirmation = HitConfirmationConfig()

        return FuzzingConfig(
            endpoints=endpoints,
            parameters=parameters,
            headers=headers,
            recursive=data.get('recursive', True),
            max_depth=data.get('max_depth', 3),
            max_requests=data.get('max_requests'),
            concurrency=data.get('concurrency', 50),
            retries=data.get('retries', 2),
            # Runtime selection objects threaded in by the CLI (subtask 38.4):
            # the parsed Path_Scope / Storage_Status_Selection objects flow
            # through ``config_dict['fuzzing']['path_scope']`` /
            # ``['storage_status']`` so they reach the EndpointFuzzer's
            # FuzzingConfig. Both default to None when absent so the keys always
            # exist on the config object (Requirements 33.1-33.7).
            path_scope=data.get('path_scope'),
            storage_status=data.get('storage_status'),
            # Recursion_Scope selection threaded in by the CLI; defaults to None
            # when absent so recursion uses its default eligibility (Req 34.3, 34.4).
            recursion_scope=data.get('recursion_scope'),
            # Hit_Confirmation built above; defaults to disabled (Req 35.1, 35.6).
            hit_confirmation=hit_confirmation,
            # Response matchers/filters threaded in by the ``par`` CLI
            # (Requirements 12.1-12.3). These are the parsed ``ResponseSelector``
            # objects from ``parse_selectors``; both default to empty lists when
            # absent so parameter-finding selection is a no-op unless selectors
            # were supplied, and dir/scan/full are unaffected.
            matchers=data.get('matchers', []),
            filters=data.get('filters', []),
            # Machine-readable output settings threaded in by the ``par`` CLI
            # (Requirements 12.5, 12.6). Both default to None when absent so no
            # machine output is written unless the operator requested it, and
            # dir/scan/full are unaffected.
            output_format=data.get('output_format'),
            output_file=data.get('output_file'),
        )

    def _build_secret_scan_config(self, data: dict[str, Any]) -> SecretScanConfig:
        """Build secret/leak detection configuration from dict (Requirement 30).

        ``enabled`` defaults to ``False`` (Requirement 30.1). When ``patterns``
        is omitted or empty, the built-in :data:`DEFAULT_SECRET_PATTERNS` are
        used via the dataclass default factory (Requirement 30.6); a supplied
        non-empty name -> regex map overrides them.
        """
        enabled = data.get('enabled', False)
        patterns = data.get('patterns')
        if patterns:
            return SecretScanConfig(enabled=enabled, patterns=dict(patterns))
        return SecretScanConfig(enabled=enabled)

    def _build_owasp_config(self, data: dict[str, Any]) -> OWASPConfig:
        """Build OWASP configuration from dict"""
        return OWASPConfig(
            enabled_modules=data.get('enabled_modules', [
                "bola", "auth", "property", "resource", "function_auth", "ssrf",
                "business_flow", "security_misconfig", "inventory", "unsafe_consumption"
            ]),
            bola_testing=BOLAConfig(**data.get('bola_testing', {})),
            auth_testing=AuthTestingConfig(**data.get('auth_testing', {})),
            property_testing=PropertyTestingConfig(**data.get('property_testing', {})),
            resource_testing=ResourceTestingConfig(**data.get('resource_testing', {})),
            function_auth_testing=FunctionAuthConfig(**data.get('function_auth_testing', {})),
            ssrf_testing=self._build_ssrf_config(data.get('ssrf_testing', {})),
            business_flow_testing=BusinessFlowConfig(**data.get('business_flow_testing', {})),
            security_misconfig_testing=SecurityMisconfigConfig(**data.get('security_misconfig_testing', {})),
            inventory_testing=InventoryConfig(**data.get('inventory_testing', {})),
            unsafe_consumption_testing=UnsafeConsumptionConfig(**data.get('unsafe_consumption_testing', {}))
        )

    def _build_ssrf_config(self, data: dict[str, Any]) -> SSRFConfig:
    
    def _build_ssrf_config(self, data: Dict[str, Any]) -> SSRFConfig:
        """Build SSRFConfig from a YAML/JSON config dict, mapping all known
        fields explicitly so new fields are always populated correctly even when
        the caller passes a partial or empty dict."""
        return SSRFConfig(
            enabled=data.get('enabled', True),
            internal_targets=data.get('internal_targets', [
                "127.0.0.1", "localhost", "169.254.169.254", "metadata.google.internal"
            ]),
            file_protocols=data.get('file_protocols', ["file://", "ftp://"]),
            # Safe mode and probe gating (Requirement 1.1–1.7)
            safe_mode=data.get('safe_mode', False),
            callback_url=data.get('callback_url', None),
            additional_internal_targets=data.get('additional_internal_targets', []),
            additional_schemes=data.get('additional_schemes', []),
            allow_port_scan=data.get('allow_port_scan', False),
            scan_ports=data.get('scan_ports', [
                22, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017
            ]),
            bypass_encodings=data.get('bypass_encodings', True),
            # Body injection fields (BUG-005 fix: these were silently ignored before)
            body_injection=data.get('body_injection', False),
            body_injection_methods=data.get('body_injection_methods', []),
            burp_xml_path=data.get('burp_xml_path', None),
            har_path=data.get('har_path', None),
            extra_body_fields=data.get('extra_body_fields', []),
            # Response filtering fields (BUG-005 fix)
            require_signature=data.get('require_signature', False),
            success_status_codes=data.get('success_status_codes', list(range(200, 300))),
        )

    def _build_auth_config(self, data: dict[str, Any]) -> AuthConfig:
    def _build_auth_config(self, data: Dict[str, Any]) -> AuthConfig:
        """Build authentication configuration from dict"""
        contexts_data = data.get('contexts', [])
        contexts = []

        for ctx_data in contexts_data:
            auth_type = AuthType(ctx_data.get('type', 'bearer'))
            context = AuthContext(
                name=ctx_data['name'],
                type=auth_type,
                token=ctx_data['token'],
                username=ctx_data.get('username'),
                password=ctx_data.get('password'),
                headers=ctx_data.get('headers', {}),
                privilege_level=ctx_data.get('privilege_level', 1)
            )
            contexts.append(context)

        return AuthConfig(
            contexts=contexts,
            default_context=data.get('default_context')
        )

    def validate_configuration(self) -> list[str]:
        """
        Validate current configuration

        Returns:
            List of validation errors (empty if valid)
        """
        if not self.config:
            return ["No configuration loaded"]

        errors = []

        # Validate target URL
        if not self.config.target.base_url:
            errors.append("target.base_url is required")

        # Validate wordlist files exist
        wordlists = [
            self.config.fuzzing.endpoints.wordlist,
            self.config.fuzzing.parameters.query_wordlist,
            self.config.fuzzing.headers.wordlist
        ]

        for wordlist in wordlists:
            if not Path(wordlist).exists():
                errors.append(f"Wordlist file not found: {wordlist}")

        # Validate auth contexts
        for ctx in self.config.authentication.contexts:
            # Allow anonymous contexts (empty token and no username/password)
            if ctx.name.lower() == "anonymous":
                continue
            if not ctx.token and not (ctx.username and ctx.password):
                errors.append(f"Auth context '{ctx.name}' missing credentials")

        return errors

    def get_fuzzing_config(self) -> FuzzingConfig:
        """Get fuzzing configuration"""
        if not self.config:
            raise ValueError("No configuration loaded")
        return self.config.fuzzing

    def get_owasp_config(self) -> OWASPConfig:
        """Get OWASP testing configuration"""
        if not self.config:
            raise ValueError("No configuration loaded")
        return self.config.owasp_testing

    def get_auth_contexts(self) -> list[AuthContext]:
        """Get authentication contexts"""
        if not self.config:
            raise ValueError("No configuration loaded")
        return self.config.authentication.contexts

    def merge_cli_overrides(self, cli_args: dict[str, Any]) -> None:
        """
        Merge CLI arguments with configuration

        Args:
            cli_args: Dictionary of CLI arguments to override
        """
        if not self.config:
            raise ValueError("No configuration loaded")

        self.logger.debug("Merging CLI overrides", overrides=list(cli_args.keys()))

        # Override target URL if provided
        if 'target_url' in cli_args:
            self.config.target.base_url = cli_args['target_url']

        # Override rate limiting if provided
        if 'rate_limit' in cli_args:
            self.config.rate_limiting.requests_per_second = cli_args['rate_limit']

        # Override output directory if provided
        if 'output_dir' in cli_args:
            self.config.reporting.output_dir = cli_args['output_dir']

        # Override enabled modules if provided
        if 'modules' in cli_args:
            self.config.owasp_testing.enabled_modules = cli_args['modules']
