"""
Fuzzing Orchestrator
Coordinates traditional fuzzing operations for endpoints, parameters, and headers
"""

import asyncio
import os
import json
import secrets
import string
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from enum import Enum
from uuid import uuid4

from core.logging import get_logger
from core.config import FuzzingConfig, SecretScanConfig, Severity
from utils.http_client import HTTPRequestEngine, Response
from utils.findings import Finding, FindingsCollector
from utils.secret_scanner import SecretFinding, scan_for_secrets
from utils.spec_import import normalize_candidate_path
from utils.url_normalize import normalize_url
from modules.fuzzing.markers import (
    find_markers,
    generate_marker_candidates,
    parse_fuzz_mode,
    substitute_markers,
)
from utils.discovery_progress import DiscoveryProgress
from utils.discovery_session import status_code_class, DiscoveryResult
from utils.discovery_checkpoint import DiscoveryCheckpoint, DiscoveryCheckpointError
from utils.graphql_probe import (
    COMMON_GRAPHQL_PATHS,
    INTROSPECTION_QUERY,
    is_graphql_response,
    introspection_enabled,
)

# Length of run-unique alphanumeric sentinel values injected during parameter
# fuzzing. Must be >= 16 to satisfy reflection-detection requirements (R3.1).
SENTINEL_LEN = 20


def normalize_extensions(raw: List[str]) -> List[str]:
    """
    Normalize a list of raw extension strings into canonical form.

    Each extension is lower-cased, stripped of surrounding whitespace, and
    given exactly one leading dot (e.g. both ``json`` and ``.json`` normalize
    to ``.json``). Blank entries are dropped and duplicates are removed while
    preserving first-seen order.

    Args:
        raw: Raw extension strings (with or without leading dots).

    Returns:
        Normalized, de-duplicated extensions, each with a single leading dot.
    """
    normalized: List[str] = []
    seen: Set[str] = set()

    for item in raw or []:
        if item is None:
            continue
        cleaned = str(item).strip().lower()
        if not cleaned:
            continue
        # Collapse any leading dots into exactly one.
        cleaned = "." + cleaned.lstrip(".")
        # A value consisting solely of dots becomes "." which has no extension.
        if cleaned == ".":
            continue
        if cleaned not in seen:
            seen.add(cleaned)
            normalized.append(cleaned)

    return normalized


def expand_candidates(word: str, extensions: List[str]) -> List[str]:
    """
    Expand a single discovery word into candidate words with extensions.

    Returns the bare ``word`` followed by ``word + ext`` for each distinct
    extension. When ``extensions`` is empty, only ``[word]`` is returned.

    Args:
        word: The base discovery word.
        extensions: Normalized extensions to append (see ``normalize_extensions``).

    Returns:
        List of candidate words, always beginning with the bare ``word``.
    """
    candidates: List[str] = [word]
    for ext in normalize_extensions(extensions):
        candidates.append(f"{word}{ext}")
    return candidates


def parse_allow_header(value: Optional[str]) -> List[str]:
    """
    Parse an HTTP ``Allow`` response header into supported method tokens.

    Splits the comma-separated header into upper-cased, whitespace-trimmed
    method tokens, dropping blanks and de-duplicating while preserving
    first-seen order. An absent (``None``) or empty/whitespace-only header
    yields an empty list (Method_Enumeration, Requirement 26.6).

    Args:
        value: Raw ``Allow`` header value, or ``None`` when the header is absent.

    Returns:
        Upper-cased, de-duplicated HTTP method tokens (``[]`` when none).
    """
    if not value:
        return []

    methods: List[str] = []
    seen: Set[str] = set()
    for token in str(value).split(","):
        method = token.strip().upper()
        if not method:
            continue
        if method not in seen:
            seen.add(method)
            methods.append(method)
    return methods


class EndpointStatus(str, Enum):
    """Endpoint status classification"""
    VALID = "valid"              # 2xx responses
    AUTH_REQUIRED = "auth_required"  # 401/403 responses
    NOT_FOUND = "not_found"      # 404 responses
    REDIRECT = "redirect"        # 3xx responses
    ERROR = "error"              # 5xx responses
    UNKNOWN = "unknown"          # Other responses


@dataclass
class Endpoint:
    """Discovered endpoint representation"""
    url: str
    method: str
    status_code: int
    response_size: int
    response_time: float
    headers: Dict[str, str] = field(default_factory=dict)
    auth_required: bool = False
    discovered_via: str = "wordlist"  # wordlist, recursive, redirect
    endpoint_type: str = "standard"   # standard, admin, api_version, etc.
    redirect_location: Optional[str] = None
    # Enumerated HTTP methods from an OPTIONS Allow header (Method_Enumeration,
    # Requirement 26). Populated only when enumerate_methods is enabled; an absent
    # or empty Allow header leaves this as an empty list (Requirement 26.6).
    allowed_methods: List[str] = field(default_factory=list)
    
    @property
    def status(self) -> EndpointStatus:
        """Get endpoint status classification"""
        if 200 <= self.status_code < 300:
            return EndpointStatus.VALID
        elif self.status_code in [401, 403]:
            return EndpointStatus.AUTH_REQUIRED
        elif self.status_code == 404:
            return EndpointStatus.NOT_FOUND
        elif 300 <= self.status_code < 400:
            return EndpointStatus.REDIRECT
        elif 500 <= self.status_code < 600:
            return EndpointStatus.ERROR
        else:
            return EndpointStatus.UNKNOWN


@dataclass
class FuzzingStats:
    """Fuzzing execution statistics"""
    endpoints_tested: int = 0
    endpoints_discovered: int = 0
    parameters_tested: int = 0
    headers_tested: int = 0
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    redirects_followed: int = 0
    recursive_depth_reached: int = 0
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate percentage"""
        if self.total_requests == 0:
            return 0.0
        return (self.successful_requests / self.total_requests) * 100.0


class EndpointFuzzer:
    """
    Endpoint Fuzzer with wordlist support and intelligent detection
    
    Features:
    - Wordlist-based endpoint discovery
    - Multiple HTTP methods support
    - Intelligent endpoint classification
    - Recursive fuzzing with configurable depth
    - Automatic redirect following
    """
    
    # Number of randomly generated non-existent paths probed to detect
    # Catch_All_Response behavior (Requirement 19.1).
    CATCH_ALL_PROBES = 3
    
    # Relative tolerance applied when comparing confirmation response body sizes
    # for Hit_Confirmation consistency (Requirement 35.3). Two body sizes are
    # "comparable" when their difference is within this fraction of the larger
    # size, allowing for minor, benign body variation (timestamps, request ids)
    # between otherwise-identical responses.
    HIT_CONFIRMATION_SIZE_TOLERANCE = 0.05
    
    def __init__(self, http_client: HTTPRequestEngine, config: FuzzingConfig,
                 secret_scan_config: Optional[SecretScanConfig] = None,
                 progress: Optional[DiscoveryProgress] = None,
                 checkpoint_path: Optional[str] = None):
        self.http_client = http_client
        self.config = config
        self.logger = get_logger(__name__).bind(component="endpoint_fuzzer")
        
        # Secret/leak detection configuration (Requirement 30). When None or
        # disabled, discovery responses are not scanned. When enabled, each
        # discovery response body and headers are scanned against the configured
        # Secret_Patterns and any matches are accumulated as redacted
        # SecretFinding records tagged to the originating endpoint. The scan is
        # pure/read-only so it stays Safe_Mode compatible (Requirement 30.5).
        self.secret_scan_config = secret_scan_config
        self.secret_findings: List[SecretFinding] = []
        
        # Discovery state
        self.discovered_endpoints: Dict[str, Endpoint] = {}
        self.tested_urls: Set[str] = set()
        self.wordlist_cache: Dict[str, List[str]] = {}

        # Resume/checkpoint state (Requirement 37). When ``checkpoint_path`` is
        # set, a checkpoint is written periodically (after each completed
        # ``_execute_batch`` slice and after each recursion depth) so an
        # interrupted ``dir`` run can resume without re-requesting (37.1, 37.6).
        # When None, all checkpoint logic is fully inert. ``_tested_methods``
        # records the HTTP method that first caused each normalized URL to be
        # added to ``tested_urls`` so the checkpoint ``tested`` field can carry
        # ``(normalized url, method)`` pairs; ``tested_urls`` itself remains the
        # url-keyed dedup set used by ``_fuzz_wordlist``. ``_checkpoint_target``
        # is the base URL captured when discovery starts, used only as checkpoint
        # metadata.
        self.checkpoint_path = checkpoint_path
        self._tested_methods: Dict[str, str] = {}
        self._checkpoint_target: str = ""
        
        # Request budget tracking (Request_Budget; None = unbounded discovery)
        self.requests_issued = 0
        self.budget_reached = False
        self.max_requests = config.max_requests
        
        # Live progress display (Progress_Display, Requirement 32). Defaults to a
        # disabled no-op so discovery can report progress unconditionally; the
        # dir command supplies an enabled instance only for an interactive,
        # non-CI, TTY session (gated exactly like the interactive triage prompt).
        self.progress = progress or DiscoveryProgress(
            enabled=False, total=config.max_requests
        )
        # Count of Discovery_Requests issued for the Progress_Display. Tracked
        # separately from ``requests_issued`` (which stays budget-only and is not
        # advanced when discovery is unbounded) so the display reports the issued
        # count in both bounded and unbounded discovery (Requirement 32.5).
        self._progress_issued = 0
        # Monotonic timestamp captured when discovery starts, used to compute the
        # elapsed time and rate reported by the Progress_Display.
        self._discovery_started_at: Optional[float] = None
        
        # Concurrency limit (Concurrency_Limit). The semaphore caps the number of
        # in-flight Discovery_Requests so they never exceed self.concurrency.
        self.concurrency = config.concurrency or 50
        self._semaphore = asyncio.Semaphore(self.concurrency)

        # Marker mode / positional fuzzing state (Fuzz_Marker, Requirements 39/45).
        # The marker config is read once from ``self.config.endpoints`` and cached
        # so ``_fuzz_wordlist`` only has to branch on ``if self._markers``:
        #   * ``self._raw_target`` is the RAW target string (before any
        #     trailing-slash normalization / urljoin) that the user supplied, so
        #     marker offsets refer to exactly the characters typed. It is captured
        #     here as an empty string and refreshed in ``discover_endpoints`` once
        #     the actual target arrives.
        #   * ``self._markers`` is the precomputed list of Marker_Positions found
        #     in ``self._raw_target`` for the configured Fuzz_Keyword. An empty
        #     list (no keyword occurrence) means marker mode is inactive and the
        #     legacy base-path append path is used unchanged (Requirement 39.3).
        #   * ``self._marker_wordlists`` are the per-marker Marker_Wordlists in
        #     marker order (``None`` ⇒ marker mode not configured).
        #   * ``self._fuzz_mode`` is the parsed Fuzz_Mode (CLUSTERBOMB default,
        #     PITCHFORK), controlling how the per-marker wordlists are combined.
        self._raw_target: str = ""
        self._marker_wordlists = self.config.endpoints.marker_wordlists
        self._fuzz_mode = parse_fuzz_mode(self.config.endpoints.fuzz_mode)
        self._markers = find_markers(
            self._raw_target, self.config.endpoints.fuzz_keyword
        )
        
        # Catch-all / wildcard detection state (Catch_All_Response, Requirement 19).
        # catch_all_signature is the (status_code, response_size) recorded when the
        # base URL answers random non-existent paths with 2xx responses.
        self.catch_all_detected = False
        self.catch_all_signature: Optional[Tuple[int, int]] = None
        
        # Soft-404 baseline signature (Soft_404_Baseline, Requirement 22.5/22.6).
        # The (status_code, response_size, word_count) signature of the responses
        # returned for paths that are not expected to exist, captured from the same
        # catch-all probes so calibration adds no requests beyond those probes
        # (which already count toward the Request_Budget). Distinct from and
        # complementary to catch_all_signature (Requirement 22.8): catch-all needs
        # every probe to be 2xx, whereas the soft-404 baseline only needs the probe
        # responses to agree on a single (status, size, words) signature.
        self.soft_404_signature: Optional[Tuple[int, int, int]] = None
        
        # GraphQL endpoint discovery state (Requirement 27). When GraphQL probing
        # is enabled and a GraphQL endpoint is detected with introspection turned
        # on, ``graphql_introspection_endpoint`` records that endpoint's URL so the
        # dir command can surface a GRAPHQL_INTROSPECTION_ENABLED finding tagged to
        # it (27.4). It stays None when GraphQL probing is disabled, no GraphQL
        # endpoint is found, or introspection is not enabled (27.6).
        self.graphql_introspection_endpoint: Optional[str] = None
        
        self.logger.info("Endpoint Fuzzer initialized",
                        recursive=config.recursive,
                        max_depth=config.max_depth,
                        max_requests=config.max_requests,
                        concurrency=self.concurrency)
    
    def _advance_progress(self, count: int) -> None:
        """Advance the live Progress_Display by ``count`` issued requests.

        A no-op unless the Progress_Display is enabled (interactive, non-CI,
        TTY — Requirements 32.3, 32.4), so it is cheap to call from every
        request-issuing path. When enabled, it advances the dedicated
        ``_progress_issued`` counter (which tracks issued requests for the
        display in both bounded and unbounded discovery, Requirement 32.5) and
        refreshes the display with the issued count, current rate, budget figures,
        elapsed time, and ETA (Requirement 32.2).
        """
        if not self.progress.enabled:
            return
        self._progress_issued += count
        if self._discovery_started_at is not None:
            elapsed = max(time.monotonic() - self._discovery_started_at, 0.0)
        else:
            elapsed = 0.0
        self.progress.update(issued=self._progress_issued, elapsed=elapsed)
    
    def _write_checkpoint(self) -> None:
        """Atomically persist the current discovery progress to ``checkpoint_path``.

        Captures the current ``tested_urls`` as ``(normalized url, method)`` pairs
        (the method recorded when each URL was first tested) and the current
        ``discovered_endpoints`` projected via
        :meth:`~utils.discovery_session.DiscoveryResult.from_endpoint`, then writes
        them through :meth:`DiscoveryCheckpoint.save`, whose temp-file +
        ``os.replace`` discipline guarantees an interruption mid-write never
        corrupts the checkpoint (Requirement 37.1, 37.6).

        Fully inert when ``checkpoint_path`` is ``None``: it returns immediately
        without touching the filesystem, so discovery that does not opt into
        checkpointing is unaffected. A write failure surfaces as
        :class:`~utils.discovery_checkpoint.DiscoveryCheckpointWriteError`.
        """
        if not self.checkpoint_path:
            return

        # tool_version mirrors the value the dir command stamps onto a
        # DiscoverySession. Imported lazily to avoid a top-level dependency on the
        # core package initializer from this module.
        try:
            from core import __version__ as tool_version
        except Exception:  # pragma: no cover - defensive: version is metadata only
            tool_version = ""

        tested = sorted(
            (url, self._tested_methods.get(url, "GET")) for url in self.tested_urls
        )
        results = [
            DiscoveryResult.from_endpoint(endpoint)
            for endpoint in self.discovered_endpoints.values()
        ]

        checkpoint = DiscoveryCheckpoint(
            target=self._checkpoint_target,
            timestamp=datetime.now(timezone.utc).isoformat(),
            tool_version=tool_version,
            tested=tested,
            results=results,
        )
        checkpoint.save(self.checkpoint_path)

    def seed_from_checkpoint(self, checkpoint: DiscoveryCheckpoint) -> None:
        """Seed resume state from a loaded :class:`DiscoveryCheckpoint`.

        Pre-populates ``self.tested_urls`` with every checkpoint ``tested`` URL
        (normalized) so ``_fuzz_wordlist``'s ``if url not in self.tested_urls``
        guard skips re-issuing any already-tested candidate (Requirement 37.3,
        no-recompute), and pre-populates ``self.discovered_endpoints`` from the
        checkpoint ``results`` keyed by normalized URL so resumed discovery
        merges newly discovered records with the checkpointed ones (Requirement
        37.4). Because both seeds key on the normalized URL and
        ``discovered_endpoints`` is url-keyed, the merged result contains no two
        records sharing the same ``(url, method)`` pair (Requirement 37.7).

        Call before discovery starts. Idempotent re-seeding is safe.
        """
        for url, method in checkpoint.tested:
            normalized = normalize_url(url)
            self.tested_urls.add(normalized)
            # Preserve the recorded method so a subsequent checkpoint write
            # round-trips the (url, method) pair.
            self._tested_methods.setdefault(normalized, method)

        for result in checkpoint.results:
            normalized = normalize_url(result.url)
            # Reconstruct a minimal Endpoint from the projected DiscoveryResult.
            # Only the triage fields (url, method, status_code) are persisted in a
            # checkpoint; response size/time/headers are unknown on resume and
            # default to empty. The status classification is derived from the
            # status code via Endpoint.status, matching the checkpointed
            # endpoint_status.
            self.discovered_endpoints[normalized] = Endpoint(
                url=normalized,
                method=result.method,
                status_code=result.status_code,
                response_size=0,
                response_time=0.0,
                discovered_via="checkpoint",
            )
    
    async def discover_endpoints(self, base_url: str, wordlist_path: str) -> List[Endpoint]:
        """
        Discover endpoints using wordlist fuzzing
        
        Args:
            base_url: Base URL to fuzz
            wordlist_path: Path to wordlist file
            
        Returns:
            List of discovered endpoints
        """
        self.logger.info("Starting endpoint discovery",
                        base_url=base_url,
                        wordlist=wordlist_path)

        # Capture the RAW target string (exactly as supplied, before the
        # trailing-slash normalization below) and recompute the Fuzz_Markers now
        # that the target is known (Requirements 39.2, 45). Marker offsets refer to
        # the characters the user typed, so this must precede any slash-append /
        # urljoin. A keyword-free target yields an empty marker list, so discovery
        # transparently falls back to the unchanged legacy base-path append path
        # (Requirement 39.3). This is the single point where markers are computed
        # for a discovery run.
        self._raw_target = base_url
        self._markers = find_markers(
            base_url, self.config.endpoints.fuzz_keyword
        )

        # Mark the discovery start so the Progress_Display can report elapsed time
        # and request rate (Requirement 32.2). Harmless when the display is
        # disabled.
        self._discovery_started_at = time.monotonic()
        
        # Prefer an in-memory merged candidate set when one was supplied via the
        # configuration (Spec_Import seeds + one or more wordlists/stdin merged by
        # the CLI, Requirements 25.3/25.4). Otherwise fall back to loading the
        # single wordlist file, preserving the backward-compatible default path.
        candidate_set = getattr(self.config.endpoints, "candidate_set", None)
        if candidate_set is not None:
            wordlist = list(candidate_set)
            if not wordlist:
                # An empty merged candidate set yields no Discovery_Request
                # (Requirement 25.7); the CLI surfaces the user-facing message.
                self.logger.info("No candidates available; skipping discovery")
                return []
        else:
            # Load wordlist
            wordlist = await self._load_wordlist(wordlist_path)
            if not wordlist:
                self.logger.error("Failed to load wordlist", path=wordlist_path)
                return []
        
        # Normalize base URL
        if not base_url.endswith('/'):
            base_url += '/'

        # Record the (normalized) base URL as the checkpoint target metadata.
        # No-op effect when checkpointing is disabled.
        self._checkpoint_target = base_url
        
        # Phase 0: Catch-all / wildcard detection (Requirement 19). Runs before the
        # depth-0 pass so its probes also count toward requests_issued / the budget.
        await self._detect_catch_all(base_url)
        
        # Phase 0.5: GraphQL endpoint discovery (Requirement 27). When enabled,
        # probe common GraphQL paths and, on detection, issue a read-only
        # introspection query. Probes flow through the same semaphore +
        # http_client.request path as every other Discovery_Request, so they count
        # toward the Request_Budget and respect the Concurrency_Limit. Disabled by
        # default (27.1); a non-GraphQL target records no finding and continues
        # discovery without error (27.6).
        if getattr(self.config.endpoints, "graphql", False):
            await self._probe_graphql(base_url)
        
        # Phase 1: Initial wordlist fuzzing
        initial_endpoints = await self._fuzz_wordlist(base_url, wordlist, depth=0)
        
        # Phase 2: Recursive fuzzing if enabled
        if self.config.recursive and self.config.max_depth > 0:
            await self._recursive_fuzzing(initial_endpoints, wordlist)
        
        # Convert to list and sort by URL
        discovered = list(self.discovered_endpoints.values())
        discovered.sort(key=lambda e: e.url)
        
        # Tear down the live Progress_Display now that discovery is complete.
        # No-op when the display was disabled (Requirements 32.3, 32.4).
        self.progress.stop()
        
        self.logger.info("Endpoint discovery completed",
                        total_discovered=len(discovered),
                        valid_endpoints=len([e for e in discovered if e.status == EndpointStatus.VALID]),
                        auth_required=len([e for e in discovered if e.status == EndpointStatus.AUTH_REQUIRED]))
        
        return discovered
    
    async def _load_wordlist(self, wordlist_path: str) -> List[str]:
        """Load wordlist from file with caching"""
        if wordlist_path in self.wordlist_cache:
            return self.wordlist_cache[wordlist_path]
        
        try:
            wordlist_file = Path(wordlist_path)
            if not wordlist_file.exists():
                self.logger.error("Wordlist file not found", path=wordlist_path)
                return []
            
            with open(wordlist_file, 'r', encoding='utf-8') as f:
                # Filter out comments and empty lines
                words = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        words.append(line)
            
            self.wordlist_cache[wordlist_path] = words
            self.logger.debug("Wordlist loaded", path=wordlist_path, words_count=len(words))
            return words
            
        except Exception as e:
            self.logger.error("Failed to load wordlist", path=wordlist_path, error=str(e))
            return []
    
    async def _fuzz_wordlist(self, base_url: str, wordlist: List[str], depth: int = 0) -> List[Endpoint]:
        """Fuzz endpoints using wordlist"""
        self.logger.debug("Fuzzing wordlist", base_url=base_url, words=len(wordlist), depth=depth)
        
        # Create requests for all word/method combinations. Each word is first
        # expanded into candidate words (the bare word plus word+extension for
        # each configured extension, Requirements 23.2/23.7) so extension-bearing
        # candidates are generated here, before the budget-trim and semaphore
        # dispatch below. This keeps every expanded candidate counted toward the
        # Request_Budget and bounded by the Concurrency_Limit.
        requests = []
        seed_methods = getattr(self.config.endpoints, "seed_methods", None) or {}
        # Path_Scope selection (Requirement 33.1-33.4). When configured, a
        # candidate excluded by the scope is dropped here, BEFORE it is added to
        # tested_urls, dispatched, or counted toward the Request_Budget below, so
        # an excluded candidate consumes no budget and issues no Discovery_Request
        # (Requirements 33.2, 33.3, 33.4).
        path_scope = self.config.path_scope

        # Marker mode / positional fuzzing (Requirement 45). At the depth-0 pass,
        # when the raw target carries at least one Fuzz_Marker AND per-marker
        # Marker_Wordlists are configured, the base-path append loop is REPLACED by
        # draining ``generate_marker_candidates``, which yields FULL candidate URLs
        # produced by substituting each Marker_Wordlist combination into the raw
        # target. Otherwise the existing ``expand_candidates`` + ``urljoin`` loop
        # runs unchanged (Requirement 39.3). Marker generation is a FLAT depth-0
        # sweep only: the keyword is never re-applied at depth > 0, so recursive
        # passes always take the legacy base-path append branch
        # (Requirement 45.7). ``generate_marker_candidates`` is a lazy iterator, so
        # hitting the Request_Budget mid-stream (see the budget trim below) stops
        # pulling further product/zip combinations and terminates discovery
        # gracefully (Requirements 42.3, 42.4, 43.4).
        use_markers = (
            depth == 0
            and bool(self._markers)
            and self._marker_wordlists is not None
        )
        if use_markers:
            # ``cand`` is already a full candidate URL; the base-path urljoin is
            # bypassed for marker candidates. ``word`` is None so per-path
            # seed_methods do not apply — marker candidates use the base method set.
            candidate_source = (
                (None, cand)
                for cand in generate_marker_candidates(
                    self._raw_target,
                    self._markers,
                    self._marker_wordlists,
                    self._fuzz_mode,
                )
            )
        else:
            # Legacy path: expand each word into candidate words (the bare word
            # plus word+extension for each configured extension,
            # Requirements 23.2/23.7) so extension-bearing candidates are generated
            # here, before the budget-trim and semaphore dispatch below. This keeps
            # every expanded candidate counted toward the Request_Budget and
            # bounded by the Concurrency_Limit.
            candidate_source = (
                (word, cand)
                for word in wordlist
                for cand in expand_candidates(word, self.config.endpoints.extensions)
            )

        for word, candidate in candidate_source:
            # Brute-force entries keep config.endpoints.methods; Spec_Import seeds
            # extend that per-path method set with the methods declared for the
            # seed's path (Requirement 25.3). Marker candidates carry no wordlist
            # word (``word is None``) so they use the base method set. The dedup
            # below is keyed by URL, so this preserves the existing per-path
            # dispatch behavior for brute-force entries while making the
            # spec-derived methods part of the candidate's method set.
            methods = list(self.config.endpoints.methods)
            if seed_methods and word is not None:
                extra = seed_methods.get(normalize_candidate_path(word))
                if extra:
                    for method in extra:
                        if method not in methods:
                            methods.append(method)
            for method in methods:
                # Marker candidates are full URLs; legacy candidates are joined to
                # the base path. Canonicalize the candidate URL with normalize_url
                # before the tested_urls membership check so two candidates that
                # normalize to the same canonical URL add a single tested_urls
                # entry and issue a single Discovery_Request (Requirements 38.1,
                # 38.3, 45.1, 45.2). This EXTENDS the existing tested_urls dedup.
                raw = candidate if use_markers else urljoin(base_url, candidate)
                url = normalize_url(raw)
                # Drop candidates excluded by the Path_Scope before any tested_urls
                # insertion or budget accounting (Requirements 33.2-33.4).
                # Evaluated against the candidate (a full URL in marker mode, a
                # path fragment otherwise) and the constructed URL; exclude takes
                # precedence over include.
                if path_scope is not None and not path_scope.admits(candidate, url):
                    continue
                if url not in self.tested_urls:
                    requests.append((method, url, candidate, depth))
                    self.tested_urls.add(url)
                    # Record the method that first caused this URL to be tested so
                    # the checkpoint can carry (url, method) pairs (Requirement
                    # 37.1). Inert when checkpointing is off.
                    self._tested_methods[url] = method
        
        # Execute requests. Concurrency is now bounded by the asyncio.Semaphore
        # in _test_endpoint (Concurrency_Limit), not by a hardcoded batch size.
        discovered_endpoints = []
        
        # Enforce the request budget (Request_Budget). Skip when unbounded.
        if self.max_requests is not None:
            remaining = self.max_requests - self.requests_issued
            if remaining <= 0:
                self.budget_reached = True
                return discovered_endpoints
            # Trim the dispatched requests to the remaining budget
            if len(requests) > remaining:
                requests = requests[:remaining]
        
        if not requests:
            return discovered_endpoints
        
        # Show progress
        self.logger.info(f"Testing {len(requests)} endpoints", base_url=base_url, depth=depth)
        
        # Count the requests being issued toward the budget
        if self.max_requests is not None:
            self.requests_issued += len(requests)
        
        # Advance the live Progress_Display by the number of requests being
        # issued in this batch (Requirement 32.2). No-op when disabled.
        self._advance_progress(len(requests))
        
        discovered_endpoints = await self._execute_batch(requests)

        # Persist a checkpoint after this completed _execute_batch slice so an
        # interrupted run can resume without re-requesting (Requirement 37.1).
        # Atomic and fully inert when checkpointing is disabled.
        self._write_checkpoint()

        # Flag budget exhaustion so recursive fuzzing can short-circuit
        if self.max_requests is not None and self.requests_issued >= self.max_requests:
            self.budget_reached = True
        
        return discovered_endpoints
    
    async def _execute_batch(self, batch: List[Tuple[str, str, str, int]]) -> List[Endpoint]:
        """Execute a batch of requests"""
        tasks = []
        for method, url, word, depth in batch:
            task = self._test_endpoint(method, url, word, depth)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        endpoints = []
        for result in results:
            if isinstance(result, Endpoint):
                endpoints.append(result)
            elif isinstance(result, Exception):
                self.logger.debug("Request failed", error=str(result))
        
        return endpoints
    
    async def _test_endpoint(self, method: str, url: str, word: str, depth: int) -> Optional[Endpoint]:
        """Test a single endpoint"""
        try:
            # Canonicalize the URL used for storage and dedup. _fuzz_wordlist
            # already passes a normalized URL, but redirect targets routed
            # through _handle_redirect may not be, so normalize here too so the
            # stored Endpoint.url and discovered_endpoints key are canonical
            # (Requirement 38.2). Idempotent, so an already-canonical URL is
            # unchanged.
            canonical_url = normalize_url(url)
            # Cap in-flight Discovery_Requests at the Concurrency_Limit. Every
            # request still flows through HTTPRequestEngine.request, so the rate
            # limiter continues to apply to each Discovery_Request.
            async with self._semaphore:
                response = await self.http_client.request(method, url)
            
            # Create endpoint object
            endpoint = Endpoint(
                url=canonical_url,
                method=method,
                status_code=response.status_code,
                response_size=len(response.content),
                response_time=response.elapsed,
                headers=response.headers,
                discovered_via="wordlist" if depth == 0 else "recursive"
            )
            
            # Classify endpoint
            self._classify_endpoint(endpoint, word)
            
            # Handle redirects if enabled
            if (endpoint.status == EndpointStatus.REDIRECT and 
                self.config.endpoints.follow_redirects):
                await self._handle_redirect(endpoint, response)
            
            # Hit_Confirmation (Requirement 35). When enabled and the first
            # response is interesting (anything other than a true 404 NOT_FOUND),
            # re-request the candidate ``count`` additional times and record it
            # only when every response is consistent (35.2-35.4). An inconsistent
            # set means the candidate is dropped (return None) and never stored
            # (35.4). When disabled, this branch is skipped entirely and the
            # existing single-request behavior is preserved (35.6).
            if (
                self.config.hit_confirmation.enabled
                and endpoint.status != EndpointStatus.NOT_FOUND
            ):
                confirmations = await self._confirm_candidate(method, url, response)
                if not self.responses_consistent([response, *confirmations]):
                    return None
            
            # Store interesting endpoints. Only true 404 (NOT_FOUND) responses are
            # discarded. A 405 (Method Not Allowed) is intentionally kept: it is
            # evidence of a valid path served by a different allowed method, so it
            # is recorded as a Discovery_Result (Method_Enumeration, Requirement
            # 26.3) rather than discarded like a 404.
            #
            # Storage-time scope selection (Requirement 33). A record is persisted
            # only when both the Path_Scope admits the candidate path/URL
            # (33.2-33.4) AND the Storage_Status_Selection admits the response
            # status code (33.5). A record dropped here never enters
            # discovered_endpoints, so it is absent from the discovery session,
            # CSV/JSONL output, and triage table regardless of any later
            # display-only --status-code filter (Requirements 33.6, 33.7).
            path_scope = self.config.path_scope
            storage_status = self.config.storage_status
            if (
                endpoint.status != EndpointStatus.NOT_FOUND
                and (path_scope is None or path_scope.admits(word, endpoint.url))
                and (storage_status is None or storage_status.admits(endpoint.status_code))
            ):
                self.discovered_endpoints[canonical_url] = endpoint
                self.logger.debug("Endpoint discovered",
                                url=canonical_url,
                                method=method,
                                status=endpoint.status_code,
                                size=endpoint.response_size)
                
                # Secret/leak detection (Requirement 30). When enabled, scan the
                # already-received response body and headers against the
                # configured Secret_Patterns and accumulate redacted findings
                # tagged to this endpoint (30.2-30.4). The scan inspects only the
                # response we already hold and issues no new requests, so it adds
                # no state-changing traffic and stays Safe_Mode compatible (30.5).
                self._scan_response_for_secrets(endpoint, response)
                
                # Method_Enumeration (Requirement 26.2/26.4): when enabled, issue a
                # single OPTIONS Discovery_Request for the discovered endpoint and
                # record the parsed Allow methods. The OPTIONS request flows through
                # the same semaphore + http_client.request path so it counts toward
                # the Request_Budget and stays within the Concurrency_Limit (26.5).
                if getattr(self.config.endpoints, "enumerate_methods", False):
                    await self._enumerate_methods(endpoint)
                
                return endpoint
            
        except Exception as e:
            self.logger.debug("Endpoint test failed", url=url, method=method, error=str(e))
        
        return None
    
    @staticmethod
    def responses_consistent(responses: List[Response]) -> bool:
        """Return True when confirmation responses are mutually consistent.

        Consistency for Hit_Confirmation (Requirement 35.3) requires that every
        response share the same Status_Code_Class (via
        :func:`utils.discovery_session.status_code_class`) AND have a comparable
        body size, where "comparable" means all body sizes fall within
        :data:`HIT_CONFIRMATION_SIZE_TOLERANCE` of the largest observed size.

        An empty list or a singleton is trivially consistent and returns True
        (there is nothing to disagree).

        Args:
            responses: The first response plus its confirmation responses.

        Returns:
            True when the responses agree on Status_Code_Class and body size
            within tolerance; False otherwise.
        """
        if len(responses) <= 1:
            return True
        
        # All responses must share the same Status_Code_Class (Requirement 35.3).
        # A leading digit outside 2-5 yields None; the set comparison still holds
        # the responses to a single shared class (or shared None).
        classes = {status_code_class(r.status_code) for r in responses}
        if len(classes) > 1:
            return False
        
        sizes = [len(r.content) for r in responses]
        largest = max(sizes)
        if largest == 0:
            # All bodies empty -> identical size, trivially comparable.
            return True
        spread = largest - min(sizes)
        return spread <= EndpointFuzzer.HIT_CONFIRMATION_SIZE_TOLERANCE * largest
    
    async def _confirm_candidate(
        self, method: str, url: str, first_response: Response
    ) -> List[Response]:
        """Issue Hit_Confirmation re-requests for a candidate interesting result.

        Re-requests ``self.config.hit_confirmation.count`` additional times using
        the SAME ``async with self._semaphore:`` + ``self.http_client.request``
        path as :meth:`_test_endpoint`. Consequently each confirmation request
        counts toward the Request_Budget (incrementing ``self.requests_issued``),
        stays within the Concurrency_Limit semaphore, and is paced by the
        configured Rate_Limit because every request flows through
        :class:`HTTPRequestEngine` (Requirement 35.5).

        Args:
            method: HTTP method of the candidate.
            url: Candidate URL to re-request.
            first_response: The already-received first response (the caller
                combines it with the returned confirmations for the consistency
                check; not re-issued here).

        Returns:
            The list of confirmation responses (length up to ``count``; a request
            that raises is skipped so consistency is judged on the responses that
            were actually received).
        """
        count = self.config.hit_confirmation.count
        confirmations: List[Response] = []
        for _ in range(count):
            # Count each confirmation request toward the Request_Budget and flag
            # exhaustion, mirroring the budget accounting in other request-issuing
            # paths (Requirement 35.5).
            if self.max_requests is not None:
                self.requests_issued += 1
                if self.requests_issued >= self.max_requests:
                    self.budget_reached = True
            
            # Advance the live Progress_Display for the confirmation request being
            # issued (Requirement 32.2). No-op when disabled.
            self._advance_progress(1)
            
            try:
                async with self._semaphore:
                    response = await self.http_client.request(method, url)
                confirmations.append(response)
            except Exception as exc:  # defensive: a failed re-request is skipped
                self.logger.debug(
                    "Hit_Confirmation request failed",
                    url=url,
                    method=method,
                    error=str(exc),
                )
        
        return confirmations
    
    def _scan_response_for_secrets(self, endpoint: Endpoint, response: Response) -> None:
        """Scan a discovery response for secrets and accumulate redacted findings.

        No-op unless secret detection is enabled via ``self.secret_scan_config``
        (Requirement 30.1). When enabled, the already-received response body
        (``response.text``) and headers are scanned against the configured
        Secret_Patterns (Requirement 30.2) using the pure, read-only
        :func:`scan_for_secrets`. Each match yields a redacted
        :class:`SecretFinding` tagged to the originating endpoint's URL/method
        (Requirements 30.3, 30.4), appended to ``self.secret_findings``. A
        response with no matching content contributes nothing (Requirement 30.7).

        Because it inspects only content already held in memory and issues no
        further requests, it adds no state-changing traffic and stays Safe_Mode
        compatible (Requirement 30.5).
        """
        config = self.secret_scan_config
        if config is None or not getattr(config, "enabled", False):
            return

        patterns = getattr(config, "patterns", None)
        try:
            if patterns:
                findings = scan_for_secrets(
                    body=response.text or "",
                    headers=response.headers or {},
                    patterns=patterns,
                    endpoint=endpoint.url,
                    method=endpoint.method,
                )
            else:
                # Fall back to the built-in DEFAULT_SECRET_PATTERNS by omitting
                # the patterns argument (Requirement 30.6).
                findings = scan_for_secrets(
                    body=response.text or "",
                    headers=response.headers or {},
                    endpoint=endpoint.url,
                    method=endpoint.method,
                )
        except Exception as exc:  # defensive: never let scanning abort discovery
            self.logger.debug(
                "Secret scan failed for endpoint",
                url=endpoint.url,
                method=endpoint.method,
                error=str(exc),
            )
            return

        if findings:
            self.secret_findings.extend(findings)
    
    async def _enumerate_methods(self, endpoint: Endpoint) -> None:
        """Enumerate allowed HTTP methods for a discovered endpoint via OPTIONS.

        Issues exactly one OPTIONS Discovery_Request to the endpoint URL and parses
        the ``Allow`` response header into ``endpoint.allowed_methods``
        (Method_Enumeration, Requirement 26.2/26.4). The request is dispatched
        through the same ``self._semaphore`` + ``self.http_client.request`` path as
        every other Discovery_Request, so it counts toward the Request_Budget and
        respects the Concurrency_Limit (Requirement 26.5). An absent or empty
        ``Allow`` header records an empty method set and discovery continues
        (Requirement 26.6).
        """
        # Count the OPTIONS request toward the Request_Budget (Requirement 26.5).
        if self.max_requests is not None:
            self.requests_issued += 1
            if self.requests_issued >= self.max_requests:
                self.budget_reached = True
        
        # Advance the live Progress_Display for the OPTIONS request being issued
        # (Requirement 32.2). No-op when disabled.
        self._advance_progress(1)
        
        try:
            async with self._semaphore:
                response = await self.http_client.request("OPTIONS", endpoint.url)
            
            allow = response.headers.get('Allow') or response.headers.get('allow')
            endpoint.allowed_methods = parse_allow_header(allow)
            self.logger.debug("Method enumeration completed",
                            url=endpoint.url,
                            allowed_methods=endpoint.allowed_methods)
        except Exception as e:
            # On failure record an empty method set and continue (Requirement 26.6).
            endpoint.allowed_methods = []
            self.logger.debug("Method enumeration failed",
                            url=endpoint.url, error=str(e))
    
    def _classify_endpoint(self, endpoint: Endpoint, word: str) -> None:
        """Classify endpoint type based on URL patterns"""
        url_lower = endpoint.url.lower()
        word_lower = word.lower()
        
        # Admin endpoints
        admin_patterns = ['admin', 'management', 'dashboard', 'control']
        if any(pattern in word_lower for pattern in admin_patterns):
            endpoint.endpoint_type = "admin"
        
        # API version endpoints
        api_patterns = ['v1', 'v2', 'v3', 'api']
        if any(pattern in word_lower for pattern in api_patterns):
            endpoint.endpoint_type = "api_version"
        
        # Authentication endpoints
        auth_patterns = ['auth', 'login', 'oauth', 'token']
        if any(pattern in word_lower for pattern in auth_patterns):
            endpoint.endpoint_type = "authentication"
        
        # Development/debug endpoints
        dev_patterns = ['debug', 'test', 'dev', 'staging']
        if any(pattern in word_lower for pattern in dev_patterns):
            endpoint.endpoint_type = "development"
        
        # Set auth_required flag for 401/403 responses
        if endpoint.status_code in [401, 403]:
            endpoint.auth_required = True
        
        # A 405 (Method Not Allowed) marks a valid path served by a different
        # allowed method (Method_Enumeration, Requirement 26.3). Tag it so it is
        # recorded as a Discovery_Result rather than treated like a 404.
        if endpoint.status_code == 405:
            endpoint.endpoint_type = "method_not_allowed"
    
    async def _handle_redirect(self, endpoint: Endpoint, response: Response) -> None:
        """Handle redirect responses"""
        location = response.headers.get('Location') or response.headers.get('location')
        if not location:
            return
        
        endpoint.redirect_location = location
        
        # Follow redirect if it's to the same domain. When the operator opts in
        # via --allow-cross-domain-redirects, cross-domain targets are also
        # followed; otherwise the same-domain default is preserved (Req 29.3).
        try:
            original_domain = urlparse(endpoint.url).netloc
            redirect_domain = urlparse(location).netloc
            allow_cross_domain = getattr(
                self.config.endpoints, "allow_cross_domain_redirects", False
            )
            
            if (redirect_domain == original_domain or not redirect_domain
                    or allow_cross_domain):
                # Resolve relative redirects
                if not redirect_domain:
                    location = urljoin(endpoint.url, location)
                
                # Test the redirect target if we haven't already. Canonicalize
                # the redirect target before the tested_urls membership check so
                # an equivalent redirect target is not re-tested (Requirement
                # 38.1, 38.3); this EXTENDS the existing tested_urls dedup.
                normalized_location = normalize_url(location)
                if normalized_location not in self.tested_urls:
                    self.logger.debug("Following redirect", from_url=endpoint.url, to_url=location)
                    self.tested_urls.add(normalized_location)
                    # Record the method used for the redirect target so the
                    # checkpoint carries it as a (url, method) pair (Req 37.1).
                    self._tested_methods[normalized_location] = endpoint.method
                    redirect_endpoint = await self._test_endpoint(endpoint.method, location, "redirect", 0)
                    if redirect_endpoint:
                        redirect_endpoint.discovered_via = "redirect"
                        
        except Exception as e:
            self.logger.debug("Failed to handle redirect", error=str(e))
    
    async def _detect_catch_all(self, base_url: str) -> None:
        """Detect Catch_All_Response behavior (Requirement 19).
        
        Issues GET requests to CATCH_ALL_PROBES randomly generated, almost-certainly
        non-existent paths. If EVERY probe returns a successful (2xx) response, the
        base URL is classified as exhibiting catch-all behavior and the
        (status_code, response_size) signature of the response is recorded so
        matching endpoints can be excluded from recursion (19.4). If any probe
        returns a non-2xx response (or errors), catch_all_detected stays False and
        recursion proceeds normally (19.3).
        
        The probes count toward requests_issued so they remain within the
        Request_Budget, consistent with _fuzz_wordlist.
        
        The same probe responses also feed the Soft_404_Baseline (Requirement
        22.5): when every valid probe response shares one (status_code, size,
        word_count) signature, that signature is recorded in soft_404_signature so
        calibrate_soft_404 can suppress matching records without issuing extra
        requests. This is independent of catch-all detection (Requirement 22.8) --
        the soft-404 baseline does not require the probes to be 2xx.
        """
        # Respect the request budget (Request_Budget). Skip when unbounded.
        probe_count = self.CATCH_ALL_PROBES
        if self.max_requests is not None:
            remaining = self.max_requests - self.requests_issued
            if remaining <= 0:
                self.budget_reached = True
                return
            # Trim the probes to whatever budget remains
            if probe_count > remaining:
                probe_count = remaining
        
        if probe_count <= 0:
            return
        
        # Generate random, non-existent paths (e.g. uuid4().hex)
        probes = [urljoin(base_url, f"{uuid4().hex}{i}") for i in range(probe_count)]
        
        # Count the probes being issued toward the budget
        if self.max_requests is not None:
            self.requests_issued += len(probes)
        
        # Advance the live Progress_Display for the catch-all probes being issued
        # (Requirement 32.2). No-op when disabled.
        self._advance_progress(len(probes))
        
        async def _probe(url: str) -> Response:
            # Cap in-flight probes at the Concurrency_Limit, like _test_endpoint.
            async with self._semaphore:
                return await self.http_client.request("GET", url)
        
        responses = await asyncio.gather(
            *(_probe(u) for u in probes),
            return_exceptions=True
        )
        
        # Tolerate probe failures: an errored probe is not a 2xx, so it simply
        # prevents the "all 2xx" condition and defaults to "not catch-all" (19.3).
        oks = [
            r for r in responses
            if isinstance(r, Response) and 200 <= r.status_code < 300
        ]
        
        # Soft_404_Baseline calibration (Requirement 22.5): capture the
        # (status_code, size, words) signature shared by the probe responses to
        # non-existent paths. Recorded only when every valid probe response agrees
        # on a single signature, so the baseline reliably reflects what this base
        # URL returns for paths that do not exist. Reuses the catch-all probes, so
        # no extra requests are issued beyond those already counted (22.8).
        valid = [r for r in responses if isinstance(r, Response)]
        if valid and len(valid) == len(probes):
            signatures = {
                (r.status_code, len(r.content), len(r.text.split()))
                for r in valid
            }
            if len(signatures) == 1:
                self.soft_404_signature = next(iter(signatures))
        
        if oks and len(oks) == len(probes):  # every probe returned 2xx (19.2)
            self.catch_all_detected = True
            self.catch_all_signature = (oks[0].status_code, len(oks[0].content))
            self.logger.info("Catch-all response behavior detected",
                            base_url=base_url,
                            status_code=oks[0].status_code,
                            response_size=len(oks[0].content))
        
        # Flag budget exhaustion so the depth-0 pass / recursion can short-circuit
        if self.max_requests is not None and self.requests_issued >= self.max_requests:
            self.budget_reached = True
    
    def _is_catch_all(self, endpoint: Endpoint) -> bool:
        """Return True when the endpoint matches the detected Catch_All_Response
        signature (status code and response size). Used to exclude wildcard
        responses from recursion (Requirement 19.4)."""
        return (self.catch_all_detected
                and self.catch_all_signature == (endpoint.status_code, endpoint.response_size))
    
    async def _probe_graphql(self, base_url: str) -> None:
        """Probe common GraphQL paths and report whether introspection is enabled.

        Issues a single read-only GraphQL introspection request
        (``INTROSPECTION_QUERY`` sent as a raw ``data=`` body with a
        ``Content-Type: application/json`` header) to each path in
        ``COMMON_GRAPHQL_PATHS`` against ``base_url`` (Requirement 27.2). The first
        path whose response is classified as GraphQL by ``is_graphql_response`` is
        treated as the detected GraphQL endpoint; probing then stops. When
        ``introspection_enabled`` is ``True`` for that endpoint's response, the
        endpoint URL is recorded in ``self.graphql_introspection_endpoint`` so the
        dir command can surface a GRAPHQL_INTROSPECTION_ENABLED finding tagged to
        it (Requirements 27.3/27.4).

        The introspection query is a single read-only operation (no mutation), so
        the request is Safe_Mode compatible and is intentionally not gated behind
        the state-changing-method skip (Requirement 27.5).

        Every probe is dispatched through the same ``self._semaphore`` +
        ``self.http_client.request`` path as any other Discovery_Request, so each
        counts toward the Request_Budget and respects the Concurrency_Limit. A
        non-GraphQL target records no finding and discovery continues without
        error (Requirement 27.6); probe failures are tolerated likewise.
        """
        headers = {"Content-Type": "application/json"}
        
        for path in COMMON_GRAPHQL_PATHS:
            # Respect the Request_Budget (Request_Budget). Skip when unbounded.
            if self.max_requests is not None:
                if self.requests_issued >= self.max_requests:
                    self.budget_reached = True
                    return
                # Count this probe toward the budget before issuing it.
                self.requests_issued += 1
                if self.requests_issued >= self.max_requests:
                    self.budget_reached = True
            
            url = urljoin(base_url, path.lstrip("/"))
            
            # Advance the live Progress_Display for this GraphQL probe
            # (Requirement 32.2). No-op when disabled.
            self._advance_progress(1)
            
            try:
                # Cap in-flight probes at the Concurrency_Limit, like every other
                # Discovery_Request, and route through http_client.request so the
                # rate limiter applies. The read-only introspection query is sent
                # as a raw JSON body via data= (Requirements 27.3/27.5).
                async with self._semaphore:
                    response = await self.http_client.request(
                        "POST", url, data=INTROSPECTION_QUERY, headers=headers
                    )
            except Exception as e:
                # Tolerate probe failures: continue probing remaining paths
                # (Requirement 27.6).
                self.logger.debug("GraphQL probe failed", url=url, error=str(e))
                continue
            
            # A response classified as GraphQL marks the detected endpoint
            # (Requirement 27.2). Stop at the first GraphQL endpoint found.
            if not is_graphql_response(response):
                continue
            
            self.logger.info("GraphQL endpoint detected", url=url)
            
            # Record a GRAPHQL_INTROSPECTION_ENABLED finding only when the
            # introspection response shows introspection is enabled on the
            # detected endpoint (Requirement 27.4).
            if introspection_enabled(response):
                self.graphql_introspection_endpoint = url
                self.logger.info("GraphQL introspection enabled", url=url)
            return
    
    async def _recursive_fuzzing(self, initial_endpoints: List[Endpoint], wordlist: List[str]) -> None:
        """Perform recursive fuzzing on discovered endpoints"""
        self.logger.debug("Starting recursive fuzzing", max_depth=self.config.max_depth)
        
        # Optional Recursion_Scope selection (Requirement 34). When configured it
        # is conjoined into the default recursion eligibility below, so it can only
        # ever narrow the recursable set (logical AND), never relax it (34.3). When
        # None (the default), recursion keeps its existing VALID/AUTH_REQUIRED
        # eligibility unchanged (34.4). Depth, budget, and Catch_All_Response
        # suppression are enforced separately and remain unchanged (34.5-34.7).
        recursion_scope = self.config.recursion_scope
        
        # Find valid endpoints that could have sub-paths
        base_endpoints = [
            e for e in initial_endpoints 
            if e.status in [EndpointStatus.VALID, EndpointStatus.AUTH_REQUIRED]
            and not e.url.endswith('.html')  # Skip file-like endpoints
            and not e.url.endswith('.json')
            and not e.url.endswith('.xml')
            and not self._is_catch_all(e)  # Skip catch-all/wildcard responses (19.4)
            and (recursion_scope is None or recursion_scope.admits(e))  # Recursion_Scope narrows only (34.3)
        ]
        
        for depth in range(1, self.config.max_depth + 1):
            # Short-circuit the depth loop once the request budget is reached
            if self.budget_reached:
                self.logger.debug("Request budget reached, stopping recursive fuzzing", depth=depth)
                break
            
            self.logger.debug("Recursive fuzzing depth", depth=depth, base_endpoints=len(base_endpoints))
            
            new_endpoints = []
            for base_endpoint in base_endpoints:
                # Short-circuit the per-endpoint loop once the budget is reached
                if self.budget_reached:
                    break
                
                # Create sub-paths by appending wordlist items
                base_url = base_endpoint.url
                if not base_url.endswith('/'):
                    base_url += '/'
                
                depth_endpoints = await self._fuzz_wordlist(base_url, wordlist, depth)
                new_endpoints.extend(depth_endpoints)
            
            # Stop further recursion if the budget was exhausted during this depth
            if self.budget_reached:
                self.logger.debug("Request budget reached during recursive fuzzing", depth=depth)
                break
            
            # Persist a checkpoint after each completed recursion depth so an
            # interrupted run can resume without re-requesting (Requirement 37.1).
            # Atomic and fully inert when checkpointing is disabled.
            self._write_checkpoint()
            
            # Update base endpoints for next depth level
            base_endpoints = [
                e for e in new_endpoints 
                if e.status in [EndpointStatus.VALID, EndpointStatus.AUTH_REQUIRED]
                and not self._is_catch_all(e)  # Skip catch-all/wildcard responses (19.4)
                and (recursion_scope is None or recursion_scope.admits(e))  # Recursion_Scope narrows only (34.3)
            ]
            
            # Stop if no new endpoints found
            if not base_endpoints:
                self.logger.debug("No new endpoints found, stopping recursive fuzzing", depth=depth)
                break


@dataclass
class Parameter:
    """Discovered parameter representation"""
    name: str
    location: str  # query, body, header
    value_type: str  # string, integer, boolean, array, object
    discovered_via: str = "wordlist"  # wordlist, response_analysis
    endpoint: str = ""
    method: str = "GET"
    evidence: str = ""
    response_difference: bool = False


# Sentinel marking a response body that could not be parsed as JSON. Distinct
# from any valid JSON value (including ``None`` from ``json.loads("null")``), so
# new-JSON-field detection can tell "invalid JSON" apart from a real null value.
_INVALID_JSON = object()


@dataclass
class ResponseDifference:
    """Signal-aware result of comparing a fuzz response against a baseline.

    Internal to the ParameterFuzzer detection pipeline. Records whether a
    Response_Difference was triggered and which signals fired so a finding can
    carry the specific detection evidence (R3.5, R4.2).

    Fields:
        triggered: True when at least one difference signal fired.
        signals: The signal names that fired
            (e.g. ["status_code", "reflection:body", "new_json_field"]).
        reflection_location: Where the sentinel was reflected ("body"/"header"),
            or None when no reflection was detected.
        new_json_fields: Sorted top-level JSON keys present in the test response
            but absent from the baseline, or None when not applicable.
    """
    triggered: bool
    signals: List[str]
    reflection_location: Optional[str] = None
    new_json_fields: Optional[List[str]] = None


class ParameterFuzzer:
    """
    Parameter Fuzzer with wordlist support and boundary testing
    
    Features:
    - Query parameter fuzzing with specialized wordlists
    - Body parameter fuzzing (JSON, XML, form-data)
    - Boundary testing with min/max/empty/null values
    - Response difference detection
    - Parameter type inference
    """
    
    def __init__(self, http_client: HTTPRequestEngine, config: FuzzingConfig):
        self.http_client = http_client
        self.config = config
        self.logger = get_logger(__name__).bind(component="parameter_fuzzer")
        
        # Fuzzing state
        self.parameters_tested = 0
        self.requests_made = 0
        self.successful_requests = 0
        self.discovered_parameters: List[Parameter] = []
        self.parameter_test_details: List[Dict] = []  # Track parameter testing details

        # Track sentinel values issued during the run so each candidate
        # parameter receives a run-unique sentinel (R3.1).
        self._sentinels: Dict[str, str] = {}

        # Candidates excluded by Hit_Confirmation (R5.3/R5.5). Each carries a
        # ``confirmation_status`` of "excluded_failed_retest" so a candidate that
        # failed to reproduce (or whose retest hit a transport error/timeout) is
        # observable even though it is deliberately kept out of the reported
        # findings.
        self.excluded_findings: List[Finding] = []

        # Request budget (R11). ``config.parameters.max_requests`` bounds the
        # total number of HTTP requests this fuzzer issues (baseline + fuzz +
        # boundary + confirmation, all counted). ``None`` means the run is
        # unbounded, so existing runs are unaffected (no behavior change). When
        # the budget is reached mid-run the fuzzer stops issuing requests,
        # records the stop reason here, and returns the findings gathered so far
        # (R11.3). ``budget_stop_reason`` stays ``None`` for an unbounded run or
        # a bounded run that never reaches its limit.
        self.budget_stop_reason: Optional[str] = None
        
        # Boundary test values
        self.boundary_values = {
            'string': ['', 'a', 'A' * 1000, 'A' * 10000, None, 'null', '0', '-1', '999999999'],
            'integer': [0, 1, -1, 999999999, -999999999, None, 'null', '', 'abc'],
            'boolean': [True, False, 'true', 'false', '1', '0', None, 'null', ''],
            'array': [[], ['test'], ['a'] * 1000, None, 'null', '', 'not_array'],
            'object': [{}, {'test': 'value'}, None, 'null', '', 'not_object']
        }
        
        # Marker mode / positional fuzzing state (Requirements 1.1, 5.1, 7.1).
        # Mirror EndpointFuzzer's pattern: precompute the three marker-related
        # fields from config so fuzz_parameters only needs a simple branch check.
        # ``_param_marker_wordlists is None`` is the Name_Discovery_Mode sentinel
        # — when None, the marker gate never fires and the existing name-discovery
        # path runs unchanged (R2.1).
        self._param_marker_wordlists = self.config.parameters.marker_wordlists
        self._param_fuzz_keyword = self.config.parameters.fuzz_keyword
        self._param_fuzz_mode = parse_fuzz_mode(self.config.parameters.fuzz_mode)

        self.logger.info("Parameter Fuzzer initialized",
                        boundary_testing=config.parameters.boundary_testing)

    def _make_sentinel(self, param_name: str) -> str:
        """Return a run-unique alphanumeric sentinel for ``param_name``.

        The sentinel is ``SENTINEL_LEN`` (>= 16) characters drawn from ASCII
        letters and digits using a cryptographically strong source. Uniqueness
        within the run is enforced by tracking issued sentinels in
        ``self._sentinels`` (R3.1).
        """
        alphabet = string.ascii_letters + string.digits
        issued = set(self._sentinels.values())
        while True:
            candidate = ''.join(secrets.choice(alphabet) for _ in range(SENTINEL_LEN))
            if candidate not in issued:
                self._sentinels[param_name] = candidate
                return candidate

    def _injection_points(self) -> Set[str]:
        """Derive the enabled injection points from the selected HTTP methods.

        Query-carrying methods (GET/DELETE) enable ``'query'`` fuzzing and
        body-carrying methods (POST/PUT/PATCH) enable ``'body'`` fuzzing. The
        selection reads ``config.parameters.methods`` case-insensitively; no
        request is issued for a disabled injection point (R6.1, R6.2, R6.3).
        """
        methods = {m.upper() for m in self.config.parameters.methods}
        points: Set[str] = set()
        if methods & {'GET', 'DELETE'}:
            points.add('query')
        if methods & {'POST', 'PUT', 'PATCH'}:
            points.add('body')
        return points

    def _confirmation_count(self) -> int:
        """Return the number of Hit_Confirmation retests (0 when disabled).

        ``config.parameters.confirm_hits`` of None or 0 disables confirmation,
        so candidates are reported immediately with no retest (R5.6). Any
        positive value is the retest count N (>= 1); the CLI supplies the
        default of 2 when a user enables confirmation (R5.1).
        """
        n = self.config.parameters.confirm_hits
        if not n:
            return 0
        return max(int(n), 1)

    def _budget_exhausted(self) -> bool:
        """Return True when the configured request budget has been reached.

        The budget is ``config.parameters.max_requests``. When it is ``None``
        the run is unbounded and this always returns False, so existing runs
        that do not set a budget are unaffected. Otherwise the run is bounded
        and this returns True once ``requests_made`` has reached the budget.

        This is checked before every HTTP request (baseline, fuzz, boundary,
        confirmation). Because ``requests_made`` already increments on every
        issued request and the check happens *before* issuing, the total number
        of requests the run issues can never exceed the budget B (R11.1, R11.2).
        The first time the budget is reached the stop reason is recorded so the
        run can be reported as partial while retaining the findings gathered so
        far (R11.3).
        """
        max_requests = self.config.parameters.max_requests
        if max_requests is not None and self.requests_made >= max_requests:
            if self.budget_stop_reason is None:
                self.budget_stop_reason = (
                    f"request budget reached "
                    f"({self.requests_made}/{max_requests} requests)"
                )
            return True
        return False

    async def _reissue_candidate(self, endpoint: Endpoint, injection: str,
                                 param_name: str,
                                 sentinel: str) -> Optional[Response]:
        """Re-issue the candidate request through the same path used at fuzz time.

        Routing by ``injection`` ("query"/"json"/"form"/"xml") to the matching
        ``_test_*`` helper guarantees the retest increments ``requests_made``
        exactly like the original request, so every retest counts toward the
        request budget (R5.4). Returns the Response, or None on a transport
        error/timeout (the ``_test_*`` helpers swallow the exception and return
        None).
        """
        if injection == "query":
            return await self._test_query_parameter(endpoint, param_name, sentinel)
        if injection == "json":
            return await self._test_json_parameter(endpoint, {param_name: sentinel})
        if injection == "form":
            return await self._test_form_parameter(endpoint, {param_name: sentinel})
        if injection == "xml":
            xml_payload = (
                f"<?xml version='1.0'?><root><{param_name}>{sentinel}"
                f"</{param_name}></root>"
            )
            return await self._test_xml_parameter(endpoint, xml_payload)
        return None

    async def _confirm_candidate(self, endpoint: Endpoint, injection: str,
                                 param_name: str, sentinel: str,
                                 baseline: Response,
                                 expected: "ResponseDifference") -> bool:
        """Re-issue the candidate request N times and report whether it reproduces.

        N is ``config.parameters.confirm_hits`` (default 2 when enabled, >= 1).
        Returns True only if every one of the N retests reproduces the expected
        ResponseDifference signals (R5.2). A transport error or timeout in any
        retest — surfaced as a None response from the shared request path —
        counts as a non-reproduction and returns False (R5.5). Every retest is
        issued via the same ``_test_*`` path used during fuzzing, so each counts
        toward the request budget (R5.4).
        """
        retests = self._confirmation_count()
        expected_signals = set(expected.signals)
        for _ in range(retests):
            response = await self._reissue_candidate(
                endpoint, injection, param_name, sentinel
            )
            if response is None:
                # Transport error/timeout => non-reproduction (R5.5).
                return False
            diff = self._evaluate_difference(sentinel, baseline, response)
            if not diff.triggered or set(diff.signals) != expected_signals:
                return False
        return True

    async def _confirm_and_annotate(self, finding: Finding, endpoint: Endpoint,
                                    injection: str, param_name: str,
                                    sentinel: str, baseline: Response,
                                    expected: "ResponseDifference") -> bool:
        """Apply Hit_Confirmation to a candidate finding and record its status.

        When confirmation is disabled (``confirm_hits`` None/0), the candidate is
        reported immediately with ``confirmation_status`` left as None and True
        is returned (R5.6). When enabled, the candidate is retested via
        :meth:`_confirm_candidate`: a reproduced candidate is annotated
        ``confirmation_status="confirmed"`` and reported (True), while a
        candidate that fails to reproduce (including a retest transport
        error/timeout) is annotated
        ``confirmation_status="excluded_failed_retest"``, recorded in
        ``self.excluded_findings`` for observability, and excluded from the
        reported findings (False) (R5.2, R5.3, R5.5).
        """
        if self._confirmation_count() <= 0:
            return True
        confirmed = await self._confirm_candidate(
            endpoint, injection, param_name, sentinel, baseline, expected
        )
        if confirmed:
            finding.confirmation_status = "confirmed"
            return True
        finding.confirmation_status = "excluded_failed_retest"
        self.excluded_findings.append(finding)
        return False

    async def fuzz_parameters(self, endpoints: List[Endpoint]) -> List[Finding]:
        """
        Fuzz parameters on discovered endpoints
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of findings from parameter fuzzing
        """
        self.logger.info("Starting parameter fuzzing", endpoints_count=len(endpoints))
        
        findings = []
        
        # Filter endpoints suitable for parameter fuzzing
        suitable_endpoints = [
            e for e in endpoints 
            if e.status in [EndpointStatus.VALID, EndpointStatus.AUTH_REQUIRED]
        ]
        
        # Injection points derived from the selected methods (R6). No request
        # is issued for a disabled injection point.
        injection_points = self._injection_points()

        for endpoint in suitable_endpoints:
            # Stop cleanly once the request budget is reached, returning the
            # findings gathered so far (R11.3).
            if self._budget_exhausted():
                break

            self.logger.debug("Fuzzing parameters for endpoint", 
                            url=endpoint.url, 
                            method=endpoint.method)
            
            # Marker_Mode gate (R2.1, R2.2, R2.7): when the endpoint URL contains
            # at least one Fuzz_Marker AND per-marker wordlists are configured,
            # delegate entirely to _fuzz_markers and skip the name-discovery path.
            # The name-discovery branches below remain byte-for-byte unchanged.
            markers = find_markers(endpoint.url, self._param_fuzz_keyword)
            use_markers = bool(markers) and self._param_marker_wordlists is not None
            if use_markers:
                findings.extend(await self._fuzz_markers(endpoint, markers))
                continue

            # Query parameter fuzzing
            if 'query' in injection_points and endpoint.method in ['GET', 'DELETE']:
                query_findings = await self._fuzz_query_parameters(endpoint)
                findings.extend(query_findings)
            
            # Body parameter fuzzing
            if 'body' in injection_points and endpoint.method in ['POST', 'PUT', 'PATCH']:
                body_findings = await self._fuzz_body_parameters(endpoint)
                findings.extend(body_findings)
        
        self.logger.info("Parameter fuzzing completed",
                        parameters_tested=self.parameters_tested,
                        requests_made=self.requests_made,
                        findings_count=len(findings))
        
        return findings
    
    async def _test_marker_candidate(
        self, method: str, candidate_url: str
    ) -> Optional[Response]:
        """Issue one request for a fully-substituted Marker_Candidate URL.

        Wraps ``http_client.request`` with the budget check and ``requests_made``
        increment so every candidate request AND every Hit_Confirmation retest
        count toward the Request_Budget, identical to the bookkeeping in
        ``_test_query_parameter`` (R5.4, R6.3, R11.1).
        """
        if self._budget_exhausted():
            return None
        try:
            response = await self.http_client.request(method.upper(), candidate_url)
            self.requests_made += 1
            if response.status_code < 500:
                self.successful_requests += 1
            return response
        except Exception as exc:
            self.logger.debug(
                "Marker candidate request failed",
                method=method,
                url=candidate_url,
                error=str(exc),
            )
            return None

    async def _fuzz_markers(
        self, endpoint: "Endpoint", markers: list
    ) -> "List[Finding]":
        """Marker_Mode: sweep marked positions in endpoint.url with candidate values.

        Reuses generate_marker_candidates (URL production), _evaluate_difference
        (signals), _confirm_and_annotate (Hit_Confirmation), _budget_exhausted
        (Request_Budget), and the shared finding/selection pipeline. The
        name-discovery path is untouched (R2.1).
        """
        import itertools as _itertools

        findings: "List[Finding]" = []

        # ------------------------------------------------------------------ #
        # 1. Selected methods (R8)
        # ------------------------------------------------------------------ #
        methods_cfg = [m.upper() for m in self.config.parameters.methods]
        query_methods = [m for m in methods_cfg if m in ("GET", "DELETE")]
        body_methods = [m for m in methods_cfg if m in ("POST", "PUT", "PATCH")]
        selected_methods = query_methods + body_methods

        if not selected_methods:
            self.logger.debug("No selected methods for Marker_Mode; skipping", url=endpoint.url)
            return findings

        # ------------------------------------------------------------------ #
        # 2. Neutral-sentinel baseline per selected method (R9.1, R11.1,
        #    Design Decision 3)
        # ------------------------------------------------------------------ #
        s = self._make_sentinel(endpoint.url)
        baseline_url = substitute_markers(endpoint.url, markers, [s] * len(markers))

        baselines: "Dict[str, Optional[Response]]" = {}
        for method in selected_methods:
            if self._budget_exhausted():
                return findings
            try:
                if method in ("POST", "PUT", "PATCH"):
                    # Body-carrying method: empty body, value stays in URL (R8.3)
                    resp = await self.http_client.request(method, baseline_url, data="")
                else:
                    resp = await self.http_client.request(method, baseline_url)
                self.requests_made += 1
                if resp.status_code < 500:
                    self.successful_requests += 1
                baselines[method] = resp
            except Exception as exc:
                self.logger.debug(
                    "Marker baseline request failed",
                    method=method,
                    url=baseline_url,
                    error=str(exc),
                )
                baselines[method] = None

        # ------------------------------------------------------------------ #
        # 3. Candidate generation and request composition (R3, R4, R5, R6, R8)
        #
        #    generate_marker_candidates yields the fully-substituted URLs.
        #    We iterate the combination logic in lockstep to get the value
        #    tuples for provenance (finding payload).  The URL always comes
        #    from generate_marker_candidates / substitute_markers.
        # ------------------------------------------------------------------ #
        wordlists = self._param_marker_wordlists  # List[List[str]]
        fuzz_mode = self._param_fuzz_mode

        if fuzz_mode.value == "pitchfork":
            value_combos = _itertools.zip_longest(*wordlists)
        else:
            value_combos = _itertools.product(*wordlists)

        candidate_gen = generate_marker_candidates(
            endpoint.url, markers, wordlists, fuzz_mode
        )

        for candidate_url, value_combo in zip(candidate_gen, value_combos):
            if self._budget_exhausted():
                break

            self.parameters_tested += 1

            # Issue one request per selected method (R8.1, R8.2, R8.3)
            for method in selected_methods:
                if self._budget_exhausted():
                    break

                baseline_resp = baselines.get(method)

                if method in ("POST", "PUT", "PATCH"):
                    # Body-carrying method: issue against candidate_url with
                    # empty body; value stays at its literal URL position (R8.3)
                    test_resp = await self._test_marker_candidate(method, candidate_url)
                else:
                    # Query-carrying method: no body (R8.1)
                    test_resp = await self._test_marker_candidate(method, candidate_url)

                if test_resp is None or baseline_resp is None:
                    continue

                # ---------------------------------------------------------- #
                # 4. Detection (R9)
                # Evaluate with sentinel=None: Marker_Mode uses operator
                # wordlist values, not a generated sentinel, so only the
                # baseline-vs-test body/header/JSON/status/size/time signals
                # apply (R9.2).
                # ---------------------------------------------------------- #
                diff = self._evaluate_difference(None, baseline_resp, test_resp)
                if not diff.triggered:
                    continue

                # Build the payload representation
                substituted_values = [
                    v for v in (value_combo or []) if v is not None
                ]
                payload_str = (
                    substituted_values[0]
                    if len(substituted_values) == 1
                    else str(substituted_values)
                )

                finding = Finding(
                    id=str(uuid4()),
                    scan_id="",
                    category="PARAMETER_FOUND",
                    owasp_category=None,
                    severity=Severity.INFO,
                    endpoint=candidate_url,
                    method=method,
                    status_code=test_resp.status_code,
                    response_size=len(test_resp.content),
                    response_time=test_resp.elapsed,
                    evidence=(
                        f"Marker candidate {candidate_url!r} differs from baseline"
                    ),
                    recommendation=(
                        "Review the parameter value at the marked position and "
                        "ensure proper validation"
                    ),
                    payload=payload_str,
                    headers=dict(test_resp.headers),
                    detection_signal=self._primary_signal(diff),
                    detection_signals=diff.signals,
                    reflection_location=diff.reflection_location,
                    new_json_fields=diff.new_json_fields,
                )

                # ---------------------------------------------------------- #
                # 5. Hit_Confirmation (R11.3) — reuse _confirm_and_annotate
                # For marker retests we wrap _test_marker_candidate so retests
                # also count toward the budget (R11.1).
                # ---------------------------------------------------------- #
                if self._confirmation_count() > 0:
                    retests = self._confirmation_count()
                    expected_signals = set(diff.signals)
                    confirmed = True
                    for _ in range(retests):
                        retest_resp = await self._test_marker_candidate(method, candidate_url)
                        if retest_resp is None:
                            confirmed = False
                            break
                        retest_diff = self._evaluate_difference(
                            None, baseline_resp, retest_resp
                        )
                        if not retest_diff.triggered or set(retest_diff.signals) != expected_signals:
                            confirmed = False
                            break

                    if confirmed:
                        finding.confirmation_status = "confirmed"
                    else:
                        finding.confirmation_status = "excluded_failed_retest"
                        self.excluded_findings.append(finding)
                        continue

                findings.append(finding)

        return findings

    async def _fuzz_query_parameters(self, endpoint: Endpoint) -> List[Finding]:
        """Fuzz query parameters for an endpoint"""
        findings = []
        
        # Load query parameter wordlist
        wordlist = await self._load_wordlist(self.config.parameters.query_wordlist)
        if not wordlist:
            return findings
        
        # Get baseline response
        baseline_response = await self._get_baseline_response(endpoint)
        if not baseline_response:
            return findings
        
        # Test each parameter from wordlist
        for i, param_name in enumerate(wordlist, 1):
            # Stop cleanly once the request budget is reached (R11.3).
            if self._budget_exhausted():
                break

            self.parameters_tested += 1
            
            # Show progress
            self.logger.info(f"Testing parameter {i}/{len(wordlist)}: {param_name}", 
                           endpoint=endpoint.url, parameter=param_name)
            
            # Test with a run-unique sentinel value
            sentinel = self._make_sentinel(param_name)
            test_response = await self._test_query_parameter(endpoint, param_name, sentinel)
            
            # Record parameter test details
            param_detail = {
                'name': param_name,
                'baseline_size': len(baseline_response.content) if baseline_response else 0,
                'test_size': len(test_response.content) if test_response else 0,
                'status': 'no_difference'
            }
            
            diff = (self._evaluate_difference(sentinel, baseline_response, test_response)
                    if test_response else None)
            if diff and diff.triggered:
                param_detail['status'] = 'difference_found'
                
                # Parameter seems to be accepted, create finding
                parameter = Parameter(
                    name=param_name,
                    location="query",
                    value_type="string",
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    evidence=f"Parameter '{param_name}' caused response difference",
                    response_difference=True
                )
                self.discovered_parameters.append(parameter)
                
                finding = Finding(
                    id=str(uuid4()),
                    scan_id="",  # Will be set by findings collector
                    category="PARAMETER_FOUND",
                    owasp_category=None,
                    severity=Severity.INFO,
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    status_code=test_response.status_code,
                    response_size=len(test_response.content),
                    response_time=test_response.elapsed,
                    evidence=f"Query parameter '{param_name}' discovered - response differs from baseline",
                    recommendation="Review parameter usage and ensure proper validation",
                    payload=f"?{param_name}={sentinel}",
                    headers=dict(test_response.headers),
                    detection_signal=self._primary_signal(diff),
                    detection_signals=diff.signals,
                    reflection_location=diff.reflection_location,
                    new_json_fields=diff.new_json_fields
                )
                if await self._confirm_and_annotate(
                    finding, endpoint, "query", param_name, sentinel,
                    baseline_response, diff
                ):
                    findings.append(finding)
                else:
                    param_detail['status'] = 'excluded_failed_retest'
            
            # Add parameter details to tracking list
            self.parameter_test_details.append(param_detail)
            
            # Perform boundary testing if enabled
            if self.config.parameters.boundary_testing:
                boundary_findings = await self._boundary_test_parameter(
                    endpoint, param_name, "query", baseline_response
                )
                findings.extend(boundary_findings)
        
        return findings
    
    async def _fuzz_body_parameters(self, endpoint: Endpoint) -> List[Finding]:
        """Fuzz body parameters for an endpoint"""
        findings = []
        
        # Load body parameter wordlist
        wordlist = await self._load_wordlist(self.config.parameters.body_wordlist)
        if not wordlist:
            return findings
        
        # Get baseline response
        baseline_response = await self._get_baseline_response(endpoint)
        if not baseline_response:
            return findings
        
        # Test JSON parameters
        json_findings = await self._fuzz_json_parameters(endpoint, wordlist, baseline_response)
        findings.extend(json_findings)
        
        # Test form-data parameters
        form_findings = await self._fuzz_form_parameters(endpoint, wordlist, baseline_response)
        findings.extend(form_findings)
        
        # Test XML parameters (basic)
        xml_findings = await self._fuzz_xml_parameters(endpoint, wordlist, baseline_response)
        findings.extend(xml_findings)
        
        return findings
    
    async def _fuzz_json_parameters(self, endpoint: Endpoint, wordlist: List[str], 
                                  baseline_response: Response) -> List[Finding]:
        """Fuzz JSON body parameters"""
        findings = []
        
        for param_name in wordlist:
            # Stop cleanly once the request budget is reached (R11.3).
            if self._budget_exhausted():
                break

            self.parameters_tested += 1
            
            # Test with JSON payload using a run-unique sentinel value
            sentinel = self._make_sentinel(param_name)
            json_payload = {param_name: sentinel}
            test_response = await self._test_json_parameter(endpoint, json_payload)
            
            diff = (self._evaluate_difference(sentinel, baseline_response, test_response)
                    if test_response else None)
            if diff and diff.triggered:
                parameter = Parameter(
                    name=param_name,
                    location="body",
                    value_type="string",
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    evidence=f"JSON parameter '{param_name}' caused response difference",
                    response_difference=True
                )
                self.discovered_parameters.append(parameter)
                
                finding = Finding(
                    id=str(uuid4()),
                    scan_id="",
                    category="PARAMETER_FOUND",
                    owasp_category=None,
                    severity=Severity.INFO,
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    status_code=test_response.status_code,
                    response_size=len(test_response.content),
                    response_time=test_response.elapsed,
                    evidence=f"JSON body parameter '{param_name}' discovered - response differs from baseline",
                    recommendation="Review parameter usage and ensure proper validation",
                    payload=json.dumps(json_payload),
                    headers=dict(test_response.headers),
                    detection_signal=self._primary_signal(diff),
                    detection_signals=diff.signals,
                    reflection_location=diff.reflection_location,
                    new_json_fields=diff.new_json_fields
                )
                if await self._confirm_and_annotate(
                    finding, endpoint, "json", param_name, sentinel,
                    baseline_response, diff
                ):
                    findings.append(finding)
                
                # Boundary testing
                if self.config.parameters.boundary_testing:
                    boundary_findings = await self._boundary_test_json_parameter(
                        endpoint, param_name, baseline_response
                    )
                    findings.extend(boundary_findings)
        
        return findings
    
    async def _fuzz_form_parameters(self, endpoint: Endpoint, wordlist: List[str], 
                                  baseline_response: Response) -> List[Finding]:
        """Fuzz form-data parameters"""
        findings = []
        
        for param_name in wordlist:
            # Stop cleanly once the request budget is reached (R11.3).
            if self._budget_exhausted():
                break

            self.parameters_tested += 1
            
            # Test with form data using a run-unique sentinel value
            sentinel = self._make_sentinel(param_name)
            form_data = {param_name: sentinel}
            test_response = await self._test_form_parameter(endpoint, form_data)
            
            diff = (self._evaluate_difference(sentinel, baseline_response, test_response)
                    if test_response else None)
            if diff and diff.triggered:
                parameter = Parameter(
                    name=param_name,
                    location="body",
                    value_type="string",
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    evidence=f"Form parameter '{param_name}' caused response difference",
                    response_difference=True
                )
                self.discovered_parameters.append(parameter)
                
                finding = Finding(
                    id=str(uuid4()),
                    scan_id="",
                    category="PARAMETER_FOUND",
                    owasp_category=None,
                    severity=Severity.INFO,
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    status_code=test_response.status_code,
                    response_size=len(test_response.content),
                    response_time=test_response.elapsed,
                    evidence=f"Form parameter '{param_name}' discovered - response differs from baseline",
                    recommendation="Review parameter usage and ensure proper validation",
                    payload=f"form-data: {param_name}={sentinel}",
                    headers=dict(test_response.headers),
                    detection_signal=self._primary_signal(diff),
                    detection_signals=diff.signals,
                    reflection_location=diff.reflection_location,
                    new_json_fields=diff.new_json_fields
                )
                if await self._confirm_and_annotate(
                    finding, endpoint, "form", param_name, sentinel,
                    baseline_response, diff
                ):
                    findings.append(finding)
        
        return findings
    
    async def _fuzz_xml_parameters(self, endpoint: Endpoint, wordlist: List[str], 
                                 baseline_response: Response) -> List[Finding]:
        """Fuzz XML parameters (basic implementation)"""
        findings = []
        
        for param_name in wordlist[:10]:  # Limit XML testing to first 10 parameters
            # Stop cleanly once the request budget is reached (R11.3).
            if self._budget_exhausted():
                break

            self.parameters_tested += 1
            
            # Create simple XML payload using a run-unique sentinel value
            sentinel = self._make_sentinel(param_name)
            xml_payload = f"<?xml version='1.0'?><root><{param_name}>{sentinel}</{param_name}></root>"
            test_response = await self._test_xml_parameter(endpoint, xml_payload)
            
            diff = (self._evaluate_difference(sentinel, baseline_response, test_response)
                    if test_response else None)
            if diff and diff.triggered:
                parameter = Parameter(
                    name=param_name,
                    location="body",
                    value_type="string",
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    evidence=f"XML parameter '{param_name}' caused response difference",
                    response_difference=True
                )
                self.discovered_parameters.append(parameter)
                
                finding = Finding(
                    id=str(uuid4()),
                    scan_id="",
                    category="PARAMETER_FOUND",
                    owasp_category=None,
                    severity=Severity.INFO,
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    status_code=test_response.status_code,
                    response_size=len(test_response.content),
                    response_time=test_response.elapsed,
                    evidence=f"XML parameter '{param_name}' discovered - response differs from baseline",
                    recommendation="Review parameter usage and ensure proper validation",
                    payload=xml_payload,
                    headers=dict(test_response.headers),
                    detection_signal=self._primary_signal(diff),
                    detection_signals=diff.signals,
                    reflection_location=diff.reflection_location,
                    new_json_fields=diff.new_json_fields
                )
                if await self._confirm_and_annotate(
                    finding, endpoint, "xml", param_name, sentinel,
                    baseline_response, diff
                ):
                    findings.append(finding)
        
        return findings
    
    async def _boundary_test_parameter(self, endpoint: Endpoint, param_name: str, 
                                     location: str, baseline_response: Response) -> List[Finding]:
        """Perform boundary testing on a parameter"""
        findings = []
        
        for value_type, test_values in self.boundary_values.items():
            for test_value in test_values:
                # Stop cleanly once the request budget is reached (R11.3).
                if self._budget_exhausted():
                    return findings
                try:
                    if location == "query":
                        test_response = await self._test_query_parameter(endpoint, param_name, test_value)
                    else:
                        # For body parameters, test as JSON
                        json_payload = {param_name: test_value}
                        test_response = await self._test_json_parameter(endpoint, json_payload)
                    
                    if test_response:
                        # Check for error responses that might indicate vulnerabilities
                        if test_response.status_code >= 500:
                            finding = Finding(
                                id=str(uuid4()),
                                scan_id="",
                                category="BOUNDARY_TEST_ERROR",
                                owasp_category=None,
                                severity=Severity.MEDIUM,
                                endpoint=endpoint.url,
                                method=endpoint.method,
                                status_code=test_response.status_code,
                                response_size=len(test_response.content),
                                response_time=test_response.elapsed,
                                evidence=f"Parameter '{param_name}' with boundary value '{test_value}' caused server error",
                                recommendation="Implement proper input validation and error handling",
                                payload=f"{param_name}={test_value}",
                                headers=dict(test_response.headers)
                            )
                            findings.append(finding)
                        
                        # Check for response time anomalies (potential DoS)
                        if test_response.elapsed > baseline_response.elapsed * 3:
                            finding = Finding(
                                id=str(uuid4()),
                                scan_id="",
                                category="TIMING_ANOMALY",
                                owasp_category=None,
                                severity=Severity.LOW,
                                endpoint=endpoint.url,
                                method=endpoint.method,
                                status_code=test_response.status_code,
                                response_size=len(test_response.content),
                                response_time=test_response.elapsed,
                                evidence=f"Parameter '{param_name}' with value '{test_value}' caused timing anomaly ({test_response.elapsed:.2f}s vs baseline {baseline_response.elapsed:.2f}s)",
                                recommendation="Review parameter processing for potential DoS vulnerabilities",
                                payload=f"{param_name}={test_value}",
                                headers=dict(test_response.headers)
                            )
                            findings.append(finding)
                
                except Exception as e:
                    self.logger.debug("Boundary test failed", 
                                    param=param_name, 
                                    value=test_value, 
                                    error=str(e))
        
        return findings
    
    async def _boundary_test_json_parameter(self, endpoint: Endpoint, param_name: str, 
                                          baseline_response: Response) -> List[Finding]:
        """Perform boundary testing on JSON parameters"""
        findings = []
        
        for value_type, test_values in self.boundary_values.items():
            for test_value in test_values:
                # Stop cleanly once the request budget is reached (R11.3).
                if self._budget_exhausted():
                    return findings
                try:
                    json_payload = {param_name: test_value}
                    test_response = await self._test_json_parameter(endpoint, json_payload)
                    
                    if test_response:
                        # Check for server errors
                        if test_response.status_code >= 500:
                            finding = Finding(
                                id=str(uuid4()),
                                scan_id="",
                                category="JSON_BOUNDARY_ERROR",
                                owasp_category=None,
                                severity=Severity.MEDIUM,
                                endpoint=endpoint.url,
                                method=endpoint.method,
                                status_code=test_response.status_code,
                                response_size=len(test_response.content),
                                response_time=test_response.elapsed,
                                evidence=f"JSON parameter '{param_name}' with boundary value caused server error",
                                recommendation="Implement proper JSON input validation",
                                payload=json.dumps(json_payload),
                                headers=dict(test_response.headers)
                            )
                            findings.append(finding)
                
                except Exception as e:
                    self.logger.debug("JSON boundary test failed", 
                                    param=param_name, 
                                    value=test_value, 
                                    error=str(e))
        
        return findings
    
    async def _get_baseline_response(self, endpoint: Endpoint) -> Optional[Response]:
        """Get baseline response for comparison"""
        # Enforce the request budget before issuing (R11.2): once the budget is
        # reached no further request is issued, so the total never exceeds B.
        if self._budget_exhausted():
            return None
        try:
            response = await self.http_client.request(endpoint.method, endpoint.url)
            self.requests_made += 1
            if response.status_code < 500:
                self.successful_requests += 1
            return response
        except Exception as e:
            self.logger.debug("Failed to get baseline response", 
                            url=endpoint.url, 
                            error=str(e))
            return None
    
    async def _test_query_parameter(self, endpoint: Endpoint, param_name: str, 
                                  param_value: Any) -> Optional[Response]:
        """Test a query parameter"""
        # Enforce the request budget before issuing (R11.2).
        if self._budget_exhausted():
            return None
        try:
            params = {param_name: param_value}
            response = await self.http_client.request(endpoint.method, endpoint.url, params=params)
            self.requests_made += 1
            if response.status_code < 500:
                self.successful_requests += 1
            return response
        except Exception as e:
            self.logger.debug("Query parameter test failed", 
                            param=param_name, 
                            error=str(e))
            return None
    
    async def _test_json_parameter(self, endpoint: Endpoint, json_payload: Dict[str, Any]) -> Optional[Response]:
        """Test JSON parameters"""
        # Enforce the request budget before issuing (R11.2).
        if self._budget_exhausted():
            return None
        try:
            headers = {'Content-Type': 'application/json'}
            response = await self.http_client.request(
                endpoint.method, 
                endpoint.url, 
                json=json_payload,
                headers=headers
            )
            self.requests_made += 1
            if response.status_code < 500:
                self.successful_requests += 1
            return response
        except Exception as e:
            self.logger.debug("JSON parameter test failed", 
                            payload=json_payload, 
                            error=str(e))
            return None
    
    async def _test_form_parameter(self, endpoint: Endpoint, form_data: Dict[str, Any]) -> Optional[Response]:
        """Test form parameters"""
        # Enforce the request budget before issuing (R11.2).
        if self._budget_exhausted():
            return None
        try:
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            response = await self.http_client.request(
                endpoint.method, 
                endpoint.url, 
                data=urlencode(form_data),
                headers=headers
            )
            self.requests_made += 1
            if response.status_code < 500:
                self.successful_requests += 1
            return response
        except Exception as e:
            self.logger.debug("Form parameter test failed", 
                            data=form_data, 
                            error=str(e))
            return None
    
    async def _test_xml_parameter(self, endpoint: Endpoint, xml_payload: str) -> Optional[Response]:
        """Test XML parameters"""
        # Enforce the request budget before issuing (R11.2).
        if self._budget_exhausted():
            return None
        try:
            headers = {'Content-Type': 'application/xml'}
            response = await self.http_client.request(
                endpoint.method, 
                endpoint.url, 
                data=xml_payload,
                headers=headers
            )
            self.requests_made += 1
            if response.status_code < 500:
                self.successful_requests += 1
            return response
        except Exception as e:
            self.logger.debug("XML parameter test failed", 
                            payload=xml_payload, 
                            error=str(e))
            return None
    
    def _baseline_signals(self, baseline: Response, test: Response) -> List[str]:
        """Return the existing status/size/time/content-type difference signals.

        These are the four comparisons the fuzzer has always used to detect a
        Response_Difference. Unlike the historical early-return implementation,
        this collects *every* signal that fired (order: status_code, body_size,
        response_time, content_type) so callers can record the full set while
        still preserving the original triggering conditions exactly (R3.4).
        """
        signals: List[str] = []

        # Status code difference
        if baseline.status_code != test.status_code:
            signals.append("status_code")

        # Significant size difference (more than 10% or 100 bytes)
        size_diff = abs(len(baseline.content) - len(test.content))
        if size_diff > max(len(baseline.content) * 0.1, 100):
            signals.append("body_size")

        # Response time difference (more than 2x)
        if test.elapsed > baseline.elapsed * 2 and test.elapsed > 1.0:
            signals.append("response_time")

        # Content type difference
        baseline_ct = baseline.headers.get('content-type', '').lower()
        test_ct = test.headers.get('content-type', '').lower()
        if baseline_ct != test_ct:
            signals.append("content_type")

        return signals

    def _has_response_difference(self, baseline: Response, test: Response) -> bool:
        """Check if test response differs significantly from baseline.

        Thin bool wrapper preserved for existing callers (e.g. header fuzzing
        paths) that compare responses without a sentinel. It reflects only the
        historical status/size/time/content-type signals; reflection and
        new-JSON-field detection require a sentinel and are routed exclusively
        through :meth:`_evaluate_difference`.
        """
        return bool(self._baseline_signals(baseline, test))

    def _evaluate_difference(self, sentinel: Optional[str], baseline: Response,
                             test: Response) -> ResponseDifference:
        """Classify a test response against the baseline into a signal record.

        Runs the existing status/size/time/content-type comparisons first, then
        reflection detection (via :meth:`_detect_reflection`), then
        new-JSON-field detection (via :meth:`_detect_new_json_fields`). Any
        signal sets ``triggered=True`` (R3.4, R3.5, R4.2). Signal names follow
        the design, e.g. ``"status_code"``, ``"reflection:body"``,
        ``"new_json_field"``.
        """
        signals = self._baseline_signals(baseline, test)

        # Reflection detection (requires a sentinel).
        reflection_location: Optional[str] = None
        if sentinel:
            reflection_location = self._detect_reflection(sentinel, baseline, test)
            if reflection_location is not None:
                signals.append(f"reflection:{reflection_location}")

        # New-JSON-field detection (graceful skip when either body is non-JSON).
        new_json_fields = self._detect_new_json_fields(baseline, test)
        if new_json_fields:
            signals.append("new_json_field")

        return ResponseDifference(
            triggered=bool(signals),
            signals=signals,
            reflection_location=reflection_location,
            new_json_fields=new_json_fields if new_json_fields else None,
        )

    @staticmethod
    def _primary_signal(diff: "ResponseDifference") -> Optional[str]:
        """Return the representative detection signal for a finding.

        Reflection takes precedence so a reflected candidate always records
        ``detection_signal == "reflection"`` (Property 3); otherwise the first
        signal that fired is used (which is ``"new_json_field"`` when only the
        JSON-field diff triggered, satisfying Property 4).
        """
        if not diff.signals:
            return None
        if diff.reflection_location is not None:
            return "reflection"
        return diff.signals[0]

    @staticmethod
    def _serialize_headers(headers: Optional[Dict[str, str]]) -> str:
        """Serialize response headers into a single string for substring matching.

        Each header is rendered as ``name: value`` on its own line so a sentinel
        reflected in any header name or value can be located with an exact
        substring match.
        """
        if not headers:
            return ""
        return "\n".join(f"{name}: {value}" for name, value in headers.items())

    def _detect_reflection(self, sentinel: str, baseline: Response,
                           test: Response) -> Optional[str]:
        """Return ``'body'`` or ``'header'`` if ``sentinel`` is reflected, else None.

        The sentinel is reflected when it appears verbatim (exact substring
        match) in the test response body or headers AND is absent from the
        corresponding baseline location (R3.2, R3.4). A sentinel that already
        appears in the corresponding baseline location is excluded so
        pre-existing occurrences are never reported as reflections (R3.3).

        The body is checked before the headers; the location string where the
        reflection is found is returned so the finding can record it (R3.5).
        Returns None when the sentinel is not reflected anywhere new.
        """
        if not sentinel:
            return None

        # Body reflection: present in the test body, absent from baseline body.
        baseline_body = baseline.text or ""
        test_body = test.text or ""
        if sentinel in test_body and sentinel not in baseline_body:
            return 'body'

        # Header reflection: present in serialized test headers, absent from
        # the serialized baseline headers.
        baseline_headers = self._serialize_headers(baseline.headers)
        test_headers = self._serialize_headers(test.headers)
        if sentinel in test_headers and sentinel not in baseline_headers:
            return 'header'

        return None

    def _detect_new_json_fields(self, baseline: Response,
                                test: Response) -> Optional[List[str]]:
        """Return sorted top-level JSON keys present in test but not baseline.

        Both response bodies are parsed as JSON. When both parse successfully,
        this returns the sorted list of top-level object keys present in the
        test response but absent from the baseline response (R4.1, R4.2). The
        list is empty when the test introduces no new top-level keys, which is
        distinct from ``None``.

        Returns ``None`` (a graceful skip, never an error) when either body is
        not valid JSON, so remaining candidate parameters keep processing
        (R4.3).

        Only top-level keys are considered. JSON that does not parse to an
        object (e.g. a list or scalar) is treated as having no top-level keys.
        """
        def _parse(response: Response):
            try:
                return json.loads(response.text or "")
            except (ValueError, TypeError):
                return _INVALID_JSON

        baseline_json = _parse(baseline)
        test_json = _parse(test)

        # Either body is not valid JSON -> skip without error (R4.3).
        if baseline_json is _INVALID_JSON or test_json is _INVALID_JSON:
            return None

        baseline_keys = set(baseline_json.keys()) if isinstance(baseline_json, dict) else set()
        test_keys = set(test_json.keys()) if isinstance(test_json, dict) else set()

        return sorted(test_keys - baseline_keys)

    async def _load_wordlist(self, wordlist_path: str) -> List[str]:
        """Load wordlist from file"""
        try:
            wordlist_file = Path(wordlist_path)
            if not wordlist_file.exists():
                self.logger.error("Wordlist file not found", path=wordlist_path)
                return []
            
            with open(wordlist_file, 'r', encoding='utf-8') as f:
                words = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        words.append(line)
            
            self.logger.debug("Wordlist loaded", path=wordlist_path, words_count=len(words))
            return words
            
        except Exception as e:
            self.logger.error("Failed to load wordlist", path=wordlist_path, error=str(e))
            return []


class HeaderFuzzer:
    """
    Header Fuzzer for testing custom headers
    
    Features:
    - Custom header fuzzing with specialized wordlists
    - Authentication bypass testing via headers
    - Admin access testing via headers (X-Admin, X-Role, etc.)
    - Response difference detection
    - Security header analysis
    """
    
    def __init__(self, http_client: HTTPRequestEngine, config: FuzzingConfig):
        self.http_client = http_client
        self.config = config
        self.logger = get_logger(__name__).bind(component="header_fuzzer")
        
        # Fuzzing state
        self.headers_tested = 0
        self.requests_made = 0
        self.successful_requests = 0
        self.discovered_headers: List[str] = []
        
        # Special header values for testing
        self.test_values = {
            'admin': ['true', '1', 'yes', 'admin', 'administrator'],
            'role': ['admin', 'administrator', 'root', 'superuser', 'manager'],
            'user': ['admin', 'root', '1', '0', 'administrator'],
            'auth': ['true', '1', 'bypass', 'admin', 'authenticated'],
            'debug': ['true', '1', 'on', 'enabled'],
            'test': ['true', '1', 'on', 'enabled', 'test', 'testing']
        }
        
        self.logger.info("Header Fuzzer initialized")
    
    async def fuzz_headers(self, endpoints: List[Endpoint]) -> List[Finding]:
        """
        Fuzz headers on discovered endpoints
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of findings from header fuzzing
        """
        self.logger.info("Starting header fuzzing", endpoints_count=len(endpoints))
        
        findings = []
        
        # Filter endpoints suitable for header fuzzing
        suitable_endpoints = [
            e for e in endpoints 
            if e.status in [EndpointStatus.VALID, EndpointStatus.AUTH_REQUIRED]
        ]
        
        for endpoint in suitable_endpoints:
            self.logger.debug("Fuzzing headers for endpoint", 
                            url=endpoint.url, 
                            method=endpoint.method)
            
            # Custom header fuzzing
            header_findings = await self._fuzz_custom_headers(endpoint)
            findings.extend(header_findings)
            
            # Admin/auth bypass header testing
            bypass_findings = await self._test_bypass_headers(endpoint)
            findings.extend(bypass_findings)
        
        self.logger.info("Header fuzzing completed",
                        headers_tested=self.headers_tested,
                        requests_made=self.requests_made,
                        findings_count=len(findings))
        
        return findings
    
    async def _fuzz_custom_headers(self, endpoint: Endpoint) -> List[Finding]:
        """Fuzz custom headers for an endpoint"""
        findings = []
        
        # Load header wordlist
        wordlist = await self._load_wordlist(self.config.headers.wordlist)
        if not wordlist:
            return findings
        
        # Get baseline response
        baseline_response = await self._get_baseline_response(endpoint)
        if not baseline_response:
            return findings
        
        # Test each header from wordlist
        for header_name in wordlist:
            self.headers_tested += 1
            
            # Test with simple value first
            test_response = await self._test_header(endpoint, header_name, "test_value")
            if test_response and self._has_response_difference(baseline_response, test_response):
                self.discovered_headers.append(header_name)
                
                finding = Finding(
                    id=str(uuid4()),
                    scan_id="",
                    category="HEADER_FOUND",
                    owasp_category=None,
                    severity=Severity.INFO,
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    status_code=test_response.status_code,
                    response_size=len(test_response.content),
                    response_time=test_response.elapsed,
                    evidence=f"Custom header '{header_name}' discovered - response differs from baseline",
                    recommendation="Review header usage and ensure proper validation",
                    payload=f"{header_name}: test_value",
                    headers=dict(test_response.headers)
                )
                findings.append(finding)
        
        return findings
    
    async def _test_bypass_headers(self, endpoint: Endpoint) -> List[Finding]:
        """Test headers for authentication/authorization bypass"""
        findings = []
        
        # Get baseline response
        baseline_response = await self._get_baseline_response(endpoint)
        if not baseline_response:
            return findings
        
        # Test admin bypass headers
        admin_headers = [
            'X-Admin', 'X-Admin-User', 'X-Is-Admin', 'X-Role', 'X-User-Role',
            'X-Privilege-Level', 'X-Access-Level', 'X-Auth-Level'
        ]
        
        for header_name in admin_headers:
            # Test different admin values
            for test_value in self.test_values.get('admin', ['true']):
                self.headers_tested += 1
                
                test_response = await self._test_header(endpoint, header_name, test_value)
                if test_response:
                    # Check for privilege escalation
                    if self._indicates_privilege_escalation(baseline_response, test_response):
                        finding = Finding(
                            id=str(uuid4()),
                            scan_id="",
                            category="HEADER_BYPASS",
                            owasp_category="API5",  # Broken Function Level Authorization
                            severity=Severity.HIGH,
                            endpoint=endpoint.url,
                            method=endpoint.method,
                            status_code=test_response.status_code,
                            response_size=len(test_response.content),
                            response_time=test_response.elapsed,
                            evidence=f"Header '{header_name}: {test_value}' may allow privilege escalation",
                            recommendation="Implement proper authorization checks that don't rely on client-controlled headers",
                            payload=f"{header_name}: {test_value}",
                            headers=dict(test_response.headers)
                        )
                        findings.append(finding)
        
        # Test authentication bypass headers
        auth_headers = [
            'X-Auth-Token', 'X-Authenticated', 'X-User-Authenticated', 'X-Bypass-Auth'
        ]
        
        for header_name in auth_headers:
            for test_value in self.test_values.get('auth', ['true']):
                self.headers_tested += 1
                
                test_response = await self._test_header(endpoint, header_name, test_value)
                if test_response:
                    # Check for authentication bypass
                    if self._indicates_auth_bypass(baseline_response, test_response):
                        finding = Finding(
                            id=str(uuid4()),
                            scan_id="",
                            category="AUTH_BYPASS_HEADER",
                            owasp_category="API2",  # Broken Authentication
                            severity=Severity.CRITICAL,
                            endpoint=endpoint.url,
                            method=endpoint.method,
                            status_code=test_response.status_code,
                            response_size=len(test_response.content),
                            response_time=test_response.elapsed,
                            evidence=f"Header '{header_name}: {test_value}' may allow authentication bypass",
                            recommendation="Remove authentication bypass mechanisms and implement proper authentication",
                            payload=f"{header_name}: {test_value}",
                            headers=dict(test_response.headers)
                        )
                        findings.append(finding)
        
        return findings
    
    async def _get_baseline_response(self, endpoint: Endpoint) -> Optional[Response]:
        """Get baseline response for comparison"""
        try:
            response = await self.http_client.request(endpoint.method, endpoint.url)
            self.requests_made += 1
            if response.status_code < 500:
                self.successful_requests += 1
            return response
        except Exception as e:
            self.logger.debug("Failed to get baseline response", 
                            url=endpoint.url, 
                            error=str(e))
            return None
    
    async def _test_header(self, endpoint: Endpoint, header_name: str, 
                         header_value: str) -> Optional[Response]:
        """Test a custom header"""
        try:
            headers = {header_name: header_value}
            response = await self.http_client.request(
                endpoint.method, 
                endpoint.url, 
                headers=headers
            )
            self.requests_made += 1
            if response.status_code < 500:
                self.successful_requests += 1
            return response
        except Exception as e:
            self.logger.debug("Header test failed", 
                            header=header_name, 
                            error=str(e))
            return None
    
    def _has_response_difference(self, baseline: Response, test: Response) -> bool:
        """Check if test response differs significantly from baseline"""
        # Status code difference
        if baseline.status_code != test.status_code:
            return True
        
        # Significant size difference (more than 10% or 100 bytes)
        size_diff = abs(len(baseline.content) - len(test.content))
        if size_diff > max(len(baseline.content) * 0.1, 100):
            return True
        
        # Response time difference (more than 2x)
        if test.elapsed > baseline.elapsed * 2 and test.elapsed > 1.0:
            return True
        
        return False
    
    def _indicates_privilege_escalation(self, baseline: Response, test: Response) -> bool:
        """Check if response indicates potential privilege escalation"""
        # Status code changed from 403/401 to 200
        if baseline.status_code in [401, 403] and test.status_code == 200:
            return True
        
        # Significant increase in response size (might indicate more data)
        if len(test.content) > len(baseline.content) * 1.5 and len(test.content) > 1000:
            return True
        
        # Look for admin-related content in response
        response_text = test.text.lower()
        admin_indicators = ['admin', 'administrator', 'dashboard', 'management', 'privileged']
        if any(indicator in response_text for indicator in admin_indicators):
            return True
        
        return False
    
    def _indicates_auth_bypass(self, baseline: Response, test: Response) -> bool:
        """Check if response indicates potential authentication bypass"""
        # Status code changed from 401 to 200
        if baseline.status_code == 401 and test.status_code == 200:
            return True
        
        # Status code changed from 403 to 200 (might be auth bypass)
        if baseline.status_code == 403 and test.status_code == 200:
            return True
        
        # Significant increase in response size
        if len(test.content) > len(baseline.content) * 2:
            return True
        
        return False
    
    async def _load_wordlist(self, wordlist_path: str) -> List[str]:
        """Load wordlist from file"""
        try:
            wordlist_file = Path(wordlist_path)
            if not wordlist_file.exists():
                self.logger.error("Wordlist file not found", path=wordlist_path)
                return []
            
            with open(wordlist_file, 'r', encoding='utf-8') as f:
                words = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        words.append(line)
            
            self.logger.debug("Wordlist loaded", path=wordlist_path, words_count=len(words))
            return words
            
        except Exception as e:
            self.logger.error("Failed to load wordlist", path=wordlist_path, error=str(e))
            return []


class FuzzingOrchestrator:
    """
    Fuzzing Orchestrator for traditional fuzzing operations
    
    Coordinates fuzzing of endpoints, parameters, and headers
    Manages wordlists and payload generation
    Handles endpoint discovery and response analysis
    """
    
    def __init__(self, config: FuzzingConfig, http_client: HTTPRequestEngine,
                 secret_scan_config: Optional[SecretScanConfig] = None,
                 progress: Optional[DiscoveryProgress] = None,
                 checkpoint_path: Optional[str] = None):
        """
        Initialize Fuzzing Orchestrator
        
        Args:
            config: Fuzzing configuration
            http_client: HTTP client for requests
            secret_scan_config: Optional secret/leak detection configuration
                (Requirement 30). When provided and enabled, discovery responses
                are scanned for secrets by the endpoint fuzzer.
            progress: Optional live Progress_Display (Requirement 32). When
                provided (an enabled instance for an interactive, non-CI, TTY
                session) the endpoint fuzzer renders live discovery progress;
                otherwise the fuzzer defaults to a disabled no-op display.
            checkpoint_path: Optional destination for periodic discovery
                checkpoints (Requirement 37). When provided it is forwarded to
                the endpoint fuzzer so an interrupted ``dir`` run can be resumed;
                ``None`` leaves all checkpoint logic inert.
        """
        self.config = config
        self.http_client = http_client
        self.logger = get_logger(__name__)
        self.stats = FuzzingStats()
        
        # Initialize specialized fuzzers
        self.endpoint_fuzzer = EndpointFuzzer(
            http_client, config, secret_scan_config, progress, checkpoint_path
        )
        self.parameter_fuzzer = ParameterFuzzer(http_client, config)
        self.header_fuzzer = HeaderFuzzer(http_client, config)
        
        self.logger.info("Fuzzing Orchestrator initialized",
                        endpoint_fuzzing=config.endpoints.enabled,
                        parameter_fuzzing=config.parameters.enabled,
                        header_fuzzing=config.headers.enabled)
    
    async def discover_endpoints(self, base_url: str) -> List[Endpoint]:
        """
        Discover endpoints using wordlist fuzzing
        
        Args:
            base_url: Base URL to discover endpoints on
            
        Returns:
            List of discovered endpoints
        """
        if not self.config.endpoints.enabled:
            self.logger.info("Endpoint fuzzing disabled")
            return []
        
        self.logger.info("Starting endpoint discovery", base_url=base_url)
        
        try:
            # Use configured wordlist
            wordlist_path = self.config.endpoints.wordlist
            endpoints = await self.endpoint_fuzzer.discover_endpoints(base_url, wordlist_path)
            
            # Update statistics
            self.stats.endpoints_tested = len(self.endpoint_fuzzer.tested_urls)
            self.stats.endpoints_discovered = len(endpoints)
            self.stats.total_requests += self.stats.endpoints_tested
            self.stats.successful_requests += len([e for e in endpoints if e.status == EndpointStatus.VALID])
            self.stats.redirects_followed = len([e for e in endpoints if e.discovered_via == "redirect"])
            
            self.logger.info("Endpoint discovery completed",
                            endpoints_found=len(endpoints),
                            requests_made=self.stats.endpoints_tested,
                            success_rate=f"{self.stats.success_rate:.1f}%")
            
            return endpoints
            
        except DiscoveryCheckpointError:
            # A checkpoint write failure must surface to the dir command as a
            # descriptive error (Requirement 37.6); never swallow it as an
            # ordinary discovery failure.
            raise
        except Exception as e:
            self.logger.error("Endpoint discovery failed", error=str(e))
            return []
    
    async def fuzz_parameters(self, endpoints: List[Endpoint]) -> List[Finding]:
        """
        Fuzz parameters on discovered endpoints
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of findings from parameter fuzzing
        """
        if not self.config.parameters.enabled:
            self.logger.info("Parameter fuzzing disabled")
            return []
        
        self.logger.info("Starting parameter fuzzing", 
                        endpoints_count=len(endpoints))
        
        try:
            findings = await self.parameter_fuzzer.fuzz_parameters(endpoints)
            
            # Update statistics
            self.stats.parameters_tested = self.parameter_fuzzer.parameters_tested
            self.stats.total_requests += self.parameter_fuzzer.requests_made
            self.stats.successful_requests += self.parameter_fuzzer.successful_requests
            
            self.logger.info("Parameter fuzzing completed",
                            parameters_tested=self.stats.parameters_tested,
                            findings_count=len(findings))
            
            return findings
            
        except Exception as e:
            self.logger.error("Parameter fuzzing failed", error=str(e))
            return []
    
    async def fuzz_headers(self, endpoints: List[Endpoint]) -> List[Finding]:
        """
        Fuzz headers on discovered endpoints
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of findings from header fuzzing
        """
        if not self.config.headers.enabled:
            self.logger.info("Header fuzzing disabled")
            return []
        
        self.logger.info("Starting header fuzzing",
                        endpoints_count=len(endpoints))
        
        try:
            findings = await self.header_fuzzer.fuzz_headers(endpoints)
            
            # Update statistics
            self.stats.headers_tested = self.header_fuzzer.headers_tested
            self.stats.total_requests += self.header_fuzzer.requests_made
            self.stats.successful_requests += self.header_fuzzer.successful_requests
            
            self.logger.info("Header fuzzing completed",
                            headers_tested=self.stats.headers_tested,
                            findings_count=len(findings))
            
            return findings
            
        except Exception as e:
            self.logger.error("Header fuzzing failed", error=str(e))
            return []
    
    def get_fuzzing_statistics(self) -> FuzzingStats:
        """
        Get fuzzing execution statistics
        
        Returns:
            Current fuzzing statistics
        """
        return self.stats
    
    def get_discovered_endpoints(self) -> List[Endpoint]:
        """
        Get list of discovered endpoints
        
        Returns:
            List of discovered endpoints
        """
        return list(self.endpoint_fuzzer.discovered_endpoints.values())
    
    def get_endpoints_by_status(self, status: EndpointStatus) -> List[Endpoint]:
        """
        Get endpoints filtered by status
        
        Args:
            status: Endpoint status to filter by
            
        Returns:
            List of endpoints with specified status
        """
        return [e for e in self.get_discovered_endpoints() if e.status == status]
    
    def get_endpoints_by_type(self, endpoint_type: str) -> List[Endpoint]:
        """
        Get endpoints filtered by type
        
        Args:
            endpoint_type: Endpoint type to filter by
            
        Returns:
            List of endpoints with specified type
        """
        return [e for e in self.get_discovered_endpoints() if e.endpoint_type == endpoint_type]