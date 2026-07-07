"""
APILeak Core Engine
Main orchestrator for fuzzing and OWASP testing operations
"""

import asyncio
import os
import time
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from uuid import uuid4

from .config import APILeakConfig, ConfigurationManager
from .logging import get_logger, APILeakLogger
from utils.findings import FindingsCollector, Finding
from utils.discovery_checkpoint import DiscoveryCheckpointError


class ParameterFuzzingError(Exception):
    """Raised when a parameter fuzzing run cannot proceed (Requirements 1.5, 1.6).

    Signals a fatal, run-aborting condition surfaced by
    :meth:`APILeakCore._execute_fuzzing_phase`:

    * the fuzzing orchestrator / HTTP stack could not be constructed, so no
      parameters were tested (Requirement 1.5); or
    * the baseline request to the target returned no HTTP response, so the
      target is unreachable and no parameters were tested (Requirement 1.6).

    In both cases ``parameters_tested`` is 0. This mirrors how the discovery
    phase surfaces :class:`DiscoveryCheckpointError` as a critical failure: the
    orchestrator propagates it instead of swallowing it, so the ``par`` command
    reports a descriptive error and terminates with a non-success exit status.
    """


def _select_parameter_findings(
    findings: List[Finding],
    matchers: List[Any],
    filters: List[Any],
) -> List[Finding]:
    """Narrow parameter ``findings`` through the shared response-selector pipeline.

    Routes parameter findings through the SAME matcher-before-filter selection
    ``dir`` uses (Requirements 12.1-12.3): a finding is retained only when it
    satisfies **every** matcher, and any finding satisfying **any** filter is
    excluded. Matchers are applied before filters, identical to the ``dir``
    selection pipeline.

    Each :class:`~utils.findings.Finding` is adapted into the in-memory-only
    :class:`~utils.response_selector.DiscoveryResultEx` view the selector
    operates on, mapping the finding's response attributes onto the view's
    selectable fields (``size``/``words``/``lines``/``time``/``regex`` body
    ``text``). The selection reuses ``utils.response_selector.apply_selectors``
    verbatim so the ``par`` selection is literally the same code path as ``dir``.

    When both ``matchers`` and ``filters`` are empty the original list is
    returned unchanged (order-preserving no-op), so runs without selectors and
    other commands are unaffected.
    """
    if not matchers and not filters:
        return findings

    # Imported lazily so the engine module import stays lightweight and to keep
    # this selection concern local to the parameter-finding path.
    from utils.discovery_session import DiscoveryResult
    from utils.response_selector import DiscoveryResultEx, apply_selectors

    view_by_id: Dict[int, Finding] = {}
    views: List[DiscoveryResultEx] = []
    for finding in findings:
        snippet = finding.response_snippet or ""
        # ``endpoint_status`` is not carried on a Finding; the ``par`` selectors
        # cover size/words/lines/regex/time (status matching stays on the
        # existing --status-code flag), so a neutral placeholder is sufficient.
        result = DiscoveryResult(
            url=finding.endpoint,
            method=finding.method,
            status_code=finding.status_code,
            endpoint_status="valid",
        )
        view = DiscoveryResultEx(
            result=result,
            size=finding.response_size,
            words=len(snippet.split()),
            lines=len(snippet.splitlines()),
            elapsed=finding.response_time,
            text=snippet,
        )
        view_by_id[id(view)] = finding
        views.append(view)

    selected_views = apply_selectors(views, matchers, filters)
    return [view_by_id[id(view)] for view in selected_views]


def _get_status_code_filter(config):
    """Helper function to get status code filter from configuration"""
    if hasattr(config, 'http_output') and config.http_output.status_code_filter:
        return config.http_output.status_code_filter
    return None


def _get_proxy_settings(config):
    """Resolve the proxy URL and TLS verification flag from configuration.

    When an intercepting proxy (Burp Suite, Caido, Hetty, ...) is configured,
    TLS verification is disabled by default because the proxy terminates TLS
    with its own CA. The user can opt back into verification via
    ``proxy_verify_ssl`` (e.g. after installing the proxy CA).

    Returns:
        A ``(proxy, verify_ssl)`` tuple.
    """
    proxy = getattr(config, 'proxy', None)
    if proxy:
        verify_ssl = getattr(config, 'proxy_verify_ssl', False)
    else:
        verify_ssl = getattr(config.target, 'verify_ssl', True)
    return proxy, verify_ssl


def _get_retry_settings(config):
    """Resolve RetryConfig.max_attempts from the configured Retry_Limit.

    The user-supplied Retry_Limit (``--retries``) is the number of automatic
    retries for a single failed Discovery_Request (Requirement 28.2/28.3).
    RetryConfig counts total attempts, so max_attempts = Retry_Limit + 1 (the
    initial attempt plus the retries). Defaults to 2 retries (3 attempts) when
    not configured, preserving the prior hardcoded behavior.

    Returns:
        The resolved ``max_attempts`` integer (always >= 1).
    """
    retries = getattr(config.fuzzing, 'retries', 2)
    return retries + 1


@dataclass
class ScanStatistics:
    """Scan execution statistics"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    endpoints_discovered: int = 0
    findings_count: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0


@dataclass
class PerformanceMetrics:
    """Performance metrics for scan execution"""
    start_time: datetime
    end_time: Optional[datetime] = None
    duration: Optional[timedelta] = None
    requests_per_second: float = 0.0
    average_response_time: float = 0.0
    memory_usage_mb: float = 0.0


@dataclass
class ScanResults:
    """Complete scan results"""
    scan_id: str
    timestamp: datetime
    target_url: str
    configuration: APILeakConfig
    statistics: ScanStatistics
    performance_metrics: PerformanceMetrics
    findings_collector: Optional[FindingsCollector] = None
    findings: List[Finding] = field(default_factory=list)  # Deprecated - use findings_collector
    fuzzing_results: Optional[Any] = None  # Will be FuzzingResults
    owasp_results: Optional[Any] = None    # Will be OWASPResults


class APILeakCore:
    """
    APILeak Core Engine - Main orchestrator for fuzzing and OWASP testing
    
    Responsibilities:
    - Orchestrate complete fuzzing and OWASP testing execution
    - Manage module lifecycle and coordination
    - Coordinate between discovery, traditional fuzzing, and specialized testing
    - Collect and aggregate results from all modules
    """
    
    def __init__(self, config: APILeakConfig):
        """
        Initialize APILeak Core Engine
        
        Args:
            config: APILeak configuration
        """
        self.config = config
        self.scan_id = str(uuid4())
        self.logger = get_logger(__name__).bind(scan_id=self.scan_id)
        
        # Initialize findings collector
        self.findings_collector = FindingsCollector(self.scan_id)
        
        # Module registries
        self.fuzzing_modules: Dict[str, Any] = {}
        self.owasp_modules: Dict[str, Any] = {}
        
        # Scan state
        self.discovered_endpoints: List[Any] = []  # Will be Endpoint objects
        self.scan_results: Optional[ScanResults] = None
        self.is_running = False
        
        self.logger.info("APILeak Core Engine initialized", 
                        target=config.target.base_url,
                        enabled_modules=config.owasp_testing.enabled_modules)
    
    async def run_scan(self, target: str, scope_endpoints: Optional[List[Any]] = None) -> ScanResults:
        """
        Execute complete APILeak scan with enhanced orchestration
        
        Args:
            target: Target URL to scan
            scope_endpoints: Optional pre-selected discovered records
                (``DiscoveryResult`` objects carrying ``url``, ``method`` and
                ``status_code``) used to seed discovery for a Batch_Scan_Scope.
                When a non-empty set is provided, wordlist discovery is skipped
                and the OWASP phase consumes exactly the seeded endpoints
                (Requirements 36.3, 36.8). ``None`` or an empty set preserves the
                normal wordlist-driven discovery behavior.
            
        Returns:
            Complete scan results
            
        Raises:
            RuntimeError: If scan is already running
            ValueError: If target is invalid
        """
        if self.is_running:
            raise RuntimeError("Scan is already running")
        
        if not target:
            raise ValueError("Target URL is required")
        
        # Stash the optional Batch_Scan_Scope seed so the discovery phase (invoked
        # by the orchestrator without extra arguments) can consume it.
        self._scope_endpoints = scope_endpoints

        # Record the target on the instance so phases invoked by the orchestrator
        # without an explicit target argument (e.g. the traditional fuzzing
        # phase) can reach it. The fuzzing phase uses this to lazily seed the
        # synthetic parameter target for a parameter-only (``par``) run.
        self.target = target
        
        self.is_running = True
        start_time = datetime.now()
        
        self.logger.info("Starting APILeak scan with enhanced orchestration", target=target)
        
        try:
            # Initialize scan results
            statistics = ScanStatistics()
            performance_metrics = PerformanceMetrics(start_time=start_time)
            
            self.scan_results = ScanResults(
                scan_id=self.scan_id,
                timestamp=start_time,
                target_url=target,
                configuration=self.config,
                statistics=statistics,
                performance_metrics=performance_metrics,
                findings_collector=self.findings_collector
            )
            
            # Initialize Enhanced Orchestrator
            from .orchestrator import EnhancedOrchestrator
            orchestrator = EnhancedOrchestrator(self.config, self.findings_collector)
            
            # Execute enhanced orchestration
            self.logger.info("Starting enhanced orchestration")
            orchestration_results = await orchestrator.execute_orchestration(target, self)
            
            # Store orchestration results
            self.scan_results.orchestration_results = orchestration_results
            
            # Get advanced results from orchestrator
            advanced_results = orchestrator.get_advanced_results()
            if advanced_results:
                setattr(self.scan_results, 'advanced_results', advanced_results)
            
            # Finalize performance metrics
            end_time = datetime.now()
            duration = end_time - start_time
            
            self.scan_results.performance_metrics.end_time = end_time
            self.scan_results.performance_metrics.duration = duration
            
            if statistics.total_requests > 0:
                self.scan_results.performance_metrics.requests_per_second = (
                    statistics.total_requests / duration.total_seconds()
                )
            
            self.logger.info("APILeak scan completed successfully with enhanced orchestration",
                           duration=duration.total_seconds(),
                           total_requests=statistics.total_requests,
                           findings=statistics.findings_count,
                           critical_findings=statistics.critical_findings,
                           phases_executed=len(orchestration_results.phases_executed),
                           advanced_features=len(orchestration_results.advanced_features_used))
            
            return self.scan_results
            
        except Exception as e:
            self.logger.error("Enhanced scan execution failed", error=str(e))
            raise
        finally:
            self.is_running = False
    
    async def _execute_discovery_phase(self, target: str, scope_endpoints: Optional[List[Any]] = None) -> None:
        """Execute endpoint discovery phase.

        Args:
            target: Target URL to scan.
            scope_endpoints: Optional pre-selected discovered records
                (``DiscoveryResult`` objects exposing ``url``, ``method`` and
                ``status_code``). When a non-empty set is provided (directly or
                via the seed stashed on ``run_scan``), wordlist discovery is
                skipped and ``self.discovered_endpoints`` is set directly to
                synthetic ``Endpoint`` objects reconstructed from the selected
                records so the OWASP phase consumes exactly the seeded set
                (Requirements 36.3, 36.8).
        """
        self.logger.debug("Executing endpoint discovery phase")
        
        # Resolve the Batch_Scan_Scope seed: the explicit argument wins, falling
        # back to the seed stashed by run_scan (the orchestrator invokes this
        # method without extra arguments).
        if scope_endpoints is None:
            scope_endpoints = getattr(self, '_scope_endpoints', None)
        
        # When a non-empty scope is provided, skip wordlist discovery entirely and
        # seed discovered_endpoints from the selected records. Each record is
        # reconstructed into a synthetic Endpoint carrying url/method/status_code;
        # the Endpoint.status classification derives from status_code via the
        # existing Endpoint.status property (Requirements 36.3, 36.8).
        if scope_endpoints:
            from modules.fuzzing.orchestrator import Endpoint
            
            seeded_endpoints = []
            for record in scope_endpoints:
                endpoint = Endpoint(
                    url=record.url,
                    method=record.method,
                    status_code=record.status_code,
                    response_size=0,
                    response_time=0.0,
                    discovered_via="scope",
                    endpoint_type="scope_seed",
                )
                # Mirror the discovery-time auth_required flag so the OWASP phase
                # sees the same classification a real discovery would produce.
                if endpoint.status_code in (401, 403):
                    endpoint.auth_required = True
                seeded_endpoints.append(endpoint)
            
            self.discovered_endpoints = seeded_endpoints
            
            self.logger.info("Discovery phase seeded from scope endpoints",
                            endpoints_seeded=len(self.discovered_endpoints))
            return
        
        # Idempotently build the fuzzing orchestrator, and (when endpoint
        # discovery is disabled but parameter fuzzing is enabled) seed the
        # synthetic parameter target. Calling both here first keeps the
        # discovery-enabled path byte-for-byte unchanged: the orchestrator is
        # constructed exactly as before and _prepare_parameter_target() is a
        # no-op whenever endpoints.enabled is True.
        self._ensure_fuzzing_orchestrator()
        self._prepare_parameter_target(target)
        
        # Check if we should do endpoint discovery or just use target for parameter fuzzing
        if self.config.fuzzing.endpoints.enabled:
            # Discover endpoints using fuzzing orchestrator
            try:
                discovered_endpoints = await self.fuzzing_orchestrator.discover_endpoints(target)
                self.discovered_endpoints = discovered_endpoints
                
                self.logger.info("Endpoint discovery phase completed", 
                                endpoints_found=len(self.discovered_endpoints),
                                valid_endpoints=len([e for e in discovered_endpoints if e.status.value == "valid"]),
                                auth_required=len([e for e in discovered_endpoints if e.auth_required]))
                
            except DiscoveryCheckpointError:
                # A checkpoint write failure must surface to the dir command as a
                # descriptive error (Requirement 37.6); never swallow it as an
                # ordinary discovery failure.
                raise
            except Exception as e:
                self.logger.error("Endpoint discovery failed", error=str(e))
                self.discovered_endpoints = []
        else:
            # For parameter fuzzing mode the synthetic target was already
            # seeded above by _prepare_parameter_target(). When parameter
            # fuzzing is also disabled there are no endpoints to test.
            if not self.config.fuzzing.parameters.enabled:
                self.discovered_endpoints = []
    
    def _ensure_fuzzing_orchestrator(self) -> None:
        """Idempotently build ``self.fuzzing_orchestrator`` and its HTTP stack.

        Builds the ``FuzzingOrchestrator`` together with its
        ``HTTPRequestEngine``/``RateLimiter``/``RetryConfig`` and configured
        authentication contexts. The construction block was moved verbatim out
        of ``_execute_discovery_phase`` and remains guarded by
        ``if not hasattr(self, 'fuzzing_orchestrator')`` so it is a no-op when
        the orchestrator has already been built (Design Decision 3 / Option C).
        Discovery-enabled runs (``dir``/``scan``/``full``) build it here exactly
        as before; parameter-only (``par``) runs build it lazily.
        """
        # Initialize fuzzing orchestrator if not already done
        if not hasattr(self, 'fuzzing_orchestrator'):
            from modules.fuzzing.orchestrator import FuzzingOrchestrator
            from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig, UserAgentRotator
            
            # Create HTTP client for fuzzing
            rate_limiter = RateLimiter(self.config.rate_limiting)
            retry_config = RetryConfig(
                max_attempts=_get_retry_settings(self.config),
                backoff_factor=2.0,
                retry_on_status=[429, 502, 503, 504]
            )
            
            # Create user agent rotator based on configuration
            user_agent_rotator = None
            headers_config = self.config.fuzzing.headers
            
            if headers_config.random_user_agent:
                user_agent_rotator = UserAgentRotator(mode="random")
            elif headers_config.user_agent_rotation and headers_config.user_agent_list:
                user_agent_rotator = UserAgentRotator(mode="rotate", user_agent_list=headers_config.user_agent_list)
            elif headers_config.custom_headers.get('User-Agent'):
                custom_ua = headers_config.custom_headers['User-Agent']
                if custom_ua != 'APILeak/0.2.0':  # Only use custom if it's not the default
                    user_agent_rotator = UserAgentRotator(mode="custom", custom_user_agent=custom_ua)
            
            # Get status code filter for HTTP output
            status_code_filter = _get_status_code_filter(self.config)
            
            proxy, verify_ssl = _get_proxy_settings(self.config)
            # Forward operator-supplied discovery headers and the --cookie string
            # (carried in HeaderFuzzingConfig.custom_headers) as engine-level
            # default headers so they are applied to every Discovery_Request
            # (Requirements 24.2, 24.3). User-Agent stays managed by the rotator.
            discovery_headers = {
                k: v for k, v in headers_config.custom_headers.items()
                if k.lower() != 'user-agent'
            }
            # Transport/TLS options for discovery (Requirement 29): mTLS client
            # cert (29.1), custom CA bundle (29.2), and the --resolve DNS override
            # (29.4) are read off the config and threaded into the engine so they
            # apply to every Discovery_Request.
            client_cert = getattr(self.config, 'client_cert', None)
            ca_bundle = getattr(self.config, 'ca_bundle', None)
            resolve = getattr(self.config, 'resolve', None)
            http_client = HTTPRequestEngine(rate_limiter, retry_config, timeout=self.config.target.timeout, verify_ssl=verify_ssl, user_agent_rotator=user_agent_rotator, status_code_filter=status_code_filter, proxy=proxy, default_headers=discovery_headers, cert=client_cert, ca_bundle=ca_bundle, resolve=resolve)

            # Wire configured authentication contexts into the discovery HTTP
            # client so that --jwt (and other auth contexts) are applied to
            # endpoint discovery requests, not just to OWASP modules. Without
            # this, authenticated discovery would still hit protected endpoints
            # anonymously and see 401/403.
            auth_contexts = self.config.authentication.contexts
            for auth_context in auth_contexts:
                http_client.add_auth_context(auth_context.name, auth_context)
            active_auth_context = next(
                (ctx for ctx in auth_contexts if getattr(ctx, "token", None)),
                auth_contexts[0] if auth_contexts else None,
            )
            if active_auth_context is not None:
                http_client.set_auth_context(active_auth_context)

            # Create fuzzing orchestrator
            self.fuzzing_orchestrator = FuzzingOrchestrator(
                self.config.fuzzing, 
                http_client,
                getattr(self.config, 'secret_scan', None),
                getattr(self, 'discovery_progress', None),
                getattr(self, 'discovery_checkpoint_path', None)
            )

            # Resume seeding (Requirement 37.3, 37.4). When the dir command loaded
            # a Discovery_Checkpoint up front and stashed it on the core, seed the
            # freshly built endpoint fuzzer before any discovery runs so already-
            # tested candidates are skipped and checkpointed results merge with
            # newly discovered ones.
            resume_checkpoint = getattr(self, 'discovery_resume_checkpoint', None)
            if resume_checkpoint is not None:
                self.fuzzing_orchestrator.endpoint_fuzzer.seed_from_checkpoint(
                    resume_checkpoint
                )

            # Streaming JSONL output (Streaming_Hit_Output). When the dir command
            # stashed a path on the core via ``discovery_streaming_output_path``,
            # open the file now and attach the handle to the EndpointFuzzer so
            # each hit is written immediately as it is discovered.
            streaming_path = getattr(self, 'discovery_streaming_output_path', None)
            if streaming_path:
                try:
                    import os as _os
                    _os.makedirs(
                        _os.path.dirname(_os.path.abspath(streaming_path)),
                        exist_ok=True,
                    )
                    self.fuzzing_orchestrator.endpoint_fuzzer.streaming_output_handle = open(
                        streaming_path, "w", encoding="utf-8"
                    )
                except OSError as exc:
                    self.logger.warning(
                        "Could not open streaming output file",
                        path=streaming_path, error=str(exc),
                    )

    def _prepare_parameter_target(self, target: str) -> None:
        """Seed ``self.discovered_endpoints`` with a synthetic parameter target.

        Moved verbatim out of ``_execute_discovery_phase``. Guarded so it only
        seeds when endpoint discovery is disabled, parameter fuzzing is enabled,
        and ``discovered_endpoints`` is still empty. This makes it idempotent and
        safe to call from both the discovery and fuzzing phases.
        """
        if (
            not self.config.fuzzing.endpoints.enabled
            and self.config.fuzzing.parameters.enabled
            and not self.discovered_endpoints
        ):
            from modules.fuzzing.orchestrator import Endpoint

            # Create a synthetic endpoint from the target URL
            target_endpoint = Endpoint(
                url=target,
                method="GET",
                status_code=200,  # Assume it's valid for parameter testing
                response_size=0,
                response_time=0.0,
                discovered_via="target",
                endpoint_type="parameter_target"
            )

            self.discovered_endpoints = [target_endpoint]

            self.logger.info("Using target URL for parameter fuzzing", 
                            target=target,
                            endpoints_found=1)

    async def _execute_fuzzing_phase(self) -> Any:
        """Execute traditional fuzzing phase"""
        self.logger.debug("Executing traditional fuzzing phase")

        # Idempotently ensure the fuzzing orchestrator and (for a parameter-only
        # run where endpoint discovery is disabled) the synthetic parameter
        # target exist before fuzzing begins. For dir/scan/full these were built
        # during the discovery phase, so both calls are no-ops (Design Decision
        # 3 / Option C); a ``par`` run — which skips discovery — builds them
        # lazily here so the fuzzing phase actually has something to test.
        try:
            self._ensure_fuzzing_orchestrator()
            target = getattr(self, 'target', None)
            if target is not None:
                self._prepare_parameter_target(target)
        except Exception as e:
            # The orchestrator / HTTP stack could not be constructed. Parameter
            # fuzzing cannot run: report a descriptive error, keep
            # parameters_tested at 0, and propagate a non-success exit status
            # (Requirement 1.5).
            self.logger.error("Parameter fuzzing did not run", error=str(e))
            raise ParameterFuzzingError(
                "parameter fuzzing did not run: the fuzzing orchestrator could "
                f"not be constructed ({e})"
            ) from e

        # If, after both idempotent setup calls, the orchestrator still could not
        # be constructed, parameter fuzzing cannot run (Requirement 1.5).
        if not hasattr(self, 'fuzzing_orchestrator'):
            self.logger.error(
                "Parameter fuzzing did not run: fuzzing orchestrator unavailable"
            )
            raise ParameterFuzzingError(
                "parameter fuzzing did not run: the fuzzing orchestrator could "
                "not be constructed"
            )

        try:
            # Execute parameter fuzzing
            parameter_findings = []
            if self.config.fuzzing.parameters.enabled:
                parameter_findings = await self.fuzzing_orchestrator.fuzz_parameters(self.discovered_endpoints)
                # Apply response matcher/filter selection to the parameter
                # findings through the SAME pipeline `dir` uses: retain only
                # findings satisfying every matcher, then exclude any finding
                # satisfying any filter (Requirements 12.1-12.3). The selectors
                # live on the shared FuzzingConfig; when none were supplied this
                # is an order-preserving no-op, so dir/scan/full are unaffected.
                parameter_findings = _select_parameter_findings(
                    parameter_findings,
                    getattr(self.config.fuzzing, 'matchers', []),
                    getattr(self.config.fuzzing, 'filters', []),
                )
            
            # Execute header fuzzing
            header_findings = []
            if self.config.fuzzing.headers.enabled:
                header_findings = await self.fuzzing_orchestrator.fuzz_headers(self.discovered_endpoints)
            
            # Get statistics
            stats = self.fuzzing_orchestrator.get_fuzzing_statistics()
            
            # Get parameter details if parameter fuzzing was enabled
            parameter_details = []
            if self.config.fuzzing.parameters.enabled and hasattr(self.fuzzing_orchestrator, 'parameter_fuzzer'):
                parameter_details = getattr(self.fuzzing_orchestrator.parameter_fuzzer, 'parameter_test_details', [])
            
            fuzzing_results = {
                "endpoints_tested": stats.endpoints_tested,
                "endpoints_discovered": stats.endpoints_discovered,
                "parameters_tested": stats.parameters_tested,
                "headers_tested": stats.headers_tested,
                "total_requests": stats.total_requests,
                "success_rate": stats.success_rate,
                "findings": parameter_findings + header_findings,
                "parameter_details": parameter_details
            }
            
            self.logger.info("Traditional fuzzing phase completed",
                            endpoints_tested=stats.endpoints_tested,
                            total_requests=stats.total_requests,
                            findings=len(fuzzing_results["findings"]))
            
        except Exception as e:
            self.logger.error("Fuzzing phase failed", error=str(e))
            return {
                "endpoints_tested": 0,
                "parameters_tested": 0,
                "headers_tested": 0,
                "findings": []
            }

        # Parameter-only unreachable-target detection (Requirement 1.6). In
        # parameter fuzzing mode the synthetic target endpoint is the only thing
        # tested; when its baseline request returns no HTTP response the fuzzer
        # tests nothing and parameters_tested stays 0 (the baseline failure is
        # handled gracefully inside the fuzzer, not raised). Surface a
        # descriptive "target unreachable" error, keep parameters_tested at 0,
        # and propagate a non-success exit status. Scoped to parameter-only mode
        # (endpoint discovery disabled) so dir/scan/full behavior is unchanged.
        if (
            self.config.fuzzing.parameters.enabled
            and not self.config.fuzzing.endpoints.enabled
            and self.discovered_endpoints
            and fuzzing_results["parameters_tested"] == 0
        ):
            unreachable_target = getattr(self, 'target', None) or self.config.target.base_url
            self.logger.error(
                "Parameter fuzzing did not run: target unreachable",
                target=unreachable_target,
            )
            raise ParameterFuzzingError(
                f"target unreachable: the baseline request to '{unreachable_target}' "
                "returned no response; parameters_tested=0"
            )

        # Write the machine-readable parameter-findings output (CSV/JSONL) when
        # the ``par`` command threaded --output-format/--output-file onto the
        # shared FuzzingConfig (Requirements 12.5, 12.6). Only the SELECTED
        # parameter findings are written (header findings are excluded), through
        # the same machine writer `dir` uses. This runs on the success path only
        # (an unreachable target raises above, so no file is written) and is a
        # no-op for dir/scan/full, which never thread these settings.
        self._write_parameter_machine_output(parameter_findings)

        return fuzzing_results

    def _write_parameter_machine_output(self, parameter_findings: List[Any]) -> None:
        """Write selected parameter findings to a machine-readable output file.

        Gated on the ``--output-format``/``--output-file`` selections threaded
        onto the shared :class:`~core.config.FuzzingConfig` by the ``par``
        command (Requirements 12.5, 12.6). When neither is set this is a no-op,
        so dir/scan/full — which never thread these settings — are unaffected.

        The destination path is the operator-supplied ``--output-file`` when
        present; otherwise a default ``reports/parameter_findings.<format>`` path
        is used, mirroring how ``dir`` derives its default machine-output path.
        The findings (including their detection-signal fields) are serialized
        through :func:`utils.discovery_output.write_parameter_findings_output`,
        the same CSV/JSON Lines machine writer used for discovery output. An
        unsupported ``--output-file`` extension raises before any file is
        written (Requirement 12.6); the error propagates to the CLI, which
        surfaces it and exits nonzero.
        """
        output_format = getattr(self.config.fuzzing, 'output_format', None)
        output_file = getattr(self.config.fuzzing, 'output_file', None)
        if not output_format and not output_file:
            return

        # Imported lazily so the engine import stays lightweight and the
        # machine-output concern stays local to the parameter-finding path.
        from utils.discovery_output import write_parameter_findings_output

        if output_file:
            # Pass the user-supplied path through as-is and let the writer
            # validate the extension (Requirement 12.6).
            output_path = output_file
        else:
            output_dir = "reports"
            os.makedirs(output_dir, exist_ok=True)
            output_path = os.path.join(
                output_dir, f"parameter_findings.{output_format}"
            )

        write_parameter_findings_output(parameter_findings, output_path)
        self.logger.info(
            "Parameter findings output written",
            path=output_path,
            findings=len(parameter_findings),
        )
    
    def _build_fuzzing_results(self, findings: Optional[List[Any]] = None,
                               parameter_details: Optional[List[Any]] = None) -> dict:
        """Build a fuzzing-results dict from the current orchestrator statistics.

        Used to populate ``scan_results.fuzzing_results`` in the enhanced
        orchestration path. Endpoint discovery already updates the orchestrator
        statistics (endpoints_tested, total_requests, success_rate, ...), so this
        can be called after the discovery phase even when no parameter/header
        fuzzing runs.
        """
        if not hasattr(self, 'fuzzing_orchestrator'):
            return {
                "endpoints_tested": 0,
                "endpoints_discovered": 0,
                "parameters_tested": 0,
                "headers_tested": 0,
                "total_requests": 0,
                "success_rate": 0.0,
                "findings": findings or [],
                "parameter_details": parameter_details or [],
            }

        stats = self.fuzzing_orchestrator.get_fuzzing_statistics()
        return {
            "endpoints_tested": stats.endpoints_tested,
            "endpoints_discovered": stats.endpoints_discovered,
            "parameters_tested": stats.parameters_tested,
            "headers_tested": stats.headers_tested,
            "total_requests": stats.total_requests,
            "success_rate": stats.success_rate,
            "findings": findings or [],
            "parameter_details": parameter_details or [],
        }

    async def _execute_owasp_phase(self) -> Any:
        """Execute OWASP specialized testing phase"""
        self.logger.debug("Executing OWASP testing phase")
        
        owasp_results = {
            "modules_executed": [],
            "coverage_by_category": {},
            "findings": []
        }
        
        # Initialize OWASP modules if not already done
        if not self.owasp_modules:
            await self._initialize_owasp_modules()
        
        # Execute enabled OWASP modules
        enabled_modules = self.config.owasp_testing.enabled_modules
        
        for module_name in enabled_modules:
            if module_name in self.owasp_modules:
                try:
                    self.logger.debug("Executing OWASP module", module=module_name)
                    
                    # Execute the module
                    module = self.owasp_modules[module_name]
                    module_findings = await module.execute_tests(self.discovered_endpoints)
                    
                    # Add findings to results
                    owasp_results["findings"].extend(module_findings)
                    owasp_results["modules_executed"].append(module_name)
                    
                    # Add findings to collector
                    if module_findings:
                        self.findings_collector.add_findings(module_findings)
                    
                    self.logger.info("OWASP module completed",
                                   module=module_name,
                                   findings_count=len(module_findings))
                    
                except Exception as e:
                    self.logger.error("OWASP module execution failed",
                                    module=module_name,
                                    error=str(e))
            else:
                self.logger.warning("OWASP module not registered", module=module_name)
        
        # Execute Advanced Discovery if enabled
        if self.config.advanced_discovery.enabled:
            try:
                self.logger.info("Executing Advanced Discovery phase")
                await self._execute_advanced_discovery_phase()
                owasp_results["modules_executed"].append("advanced_discovery")
            except Exception as e:
                self.logger.error("Advanced Discovery execution failed", error=str(e))
        
        self.logger.info("OWASP testing phase completed",
                        modules_executed=len(owasp_results["modules_executed"]),
                        total_findings=len(owasp_results["findings"]))
        
        return owasp_results
    
    async def _initialize_owasp_modules(self) -> None:
        """Initialize OWASP testing modules.

        Module naming reconciliation (Requirement 23.2)
        ------------------------------------------------
        Three distinct identifiers exist for each module and intentionally do
        not all match. They are reconciled here so engine keys, module names,
        and config field names do not silently diverge:

            engine registration key | get_module_name() value | config field name
            ------------------------ | ----------------------- | -----------------
            bola                     | bola_testing            | bola_testing
            auth                     | auth_testing            | auth_testing
            property                 | property_level_auth     | property_testing

        The engine registration keys ``bola``, ``auth`` and ``property`` are
        preserved exactly and MUST NOT be renamed (Requirements 23.1, 26.3).

        Note on ``registry.OWASPModuleRegistry`` (Requirement 23.3)
        -----------------------------------------------------------
        ``registry.OWASPModuleRegistry`` is unused by the engine. The engine
        registers modules directly via ``register_owasp_module`` (see the
        ``register_owasp_module`` calls below); it does not consult the
        registry. The registry is retained as a standalone helper and is not
        part of this engine's module wiring.
        """
        self.logger.debug("Initializing OWASP modules")
        
        try:
            # Import OWASP modules
            from modules.owasp import (
                BOLATestingModule, 
                AuthenticationTestingModule, 
                PropertyLevelAuthModule,
                FunctionLevelAuthModule,
                ResourceConsumptionModule,
                SSRFTestingModule,
                BusinessFlowsTestingModule,
                SecurityMisconfigModule,
                InventoryManagementModule,
                UnsafeConsumptionModule
            )
            
            # Create HTTP client for OWASP modules
            from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig, UserAgentRotator
            
            rate_limiter = RateLimiter(self.config.rate_limiting)
            retry_config = RetryConfig(
                max_attempts=_get_retry_settings(self.config),
                backoff_factor=2.0,
                retry_on_status=[429, 502, 503, 504]
            )
            
            # Create user agent rotator based on configuration
            user_agent_rotator = None
            headers_config = self.config.fuzzing.headers
            
            if headers_config.random_user_agent:
                user_agent_rotator = UserAgentRotator(mode="random")
            elif headers_config.user_agent_rotation and headers_config.user_agent_list:
                user_agent_rotator = UserAgentRotator(mode="rotate", user_agent_list=headers_config.user_agent_list)
            elif headers_config.custom_headers.get('User-Agent'):
                custom_ua = headers_config.custom_headers['User-Agent']
                if custom_ua != 'APILeak/0.2.0':  # Only use custom if it's not the default
                    user_agent_rotator = UserAgentRotator(mode="custom", custom_user_agent=custom_ua)
            
            # Get status code filter for HTTP output
            status_code_filter = _get_status_code_filter(self.config)
            
            proxy, verify_ssl = _get_proxy_settings(self.config)
            http_client = HTTPRequestEngine(rate_limiter, retry_config, timeout=self.config.target.timeout, verify_ssl=verify_ssl, user_agent_rotator=user_agent_rotator, status_code_filter=status_code_filter, proxy=proxy)
            
            # Get authentication contexts
            auth_contexts = self.config.authentication.contexts
            
            # Propagate the global Safe Mode flag onto each OWASP module's
            # configuration object so modules can honor it via self.config.
            # When enabled, modules skip state-changing probes and restrict to
            # safe methods (Requirements 10.1, 10.2). In particular, the BOLA,
            # Auth, and Property modules (bola_testing, auth_testing,
            # property_testing configs) read safe_mode from their config per
            # Requirement 21.1.
            safe_mode = getattr(self.config, 'safe_mode', False)
            owasp_cfg = self.config.owasp_testing
            for module_cfg in (
                owasp_cfg.bola_testing,
                owasp_cfg.auth_testing,
                owasp_cfg.property_testing,
                owasp_cfg.resource_testing,
                owasp_cfg.function_auth_testing,
                owasp_cfg.ssrf_testing,
                owasp_cfg.business_flow_testing,
                owasp_cfg.security_misconfig_testing,
                owasp_cfg.inventory_testing,
                owasp_cfg.unsafe_consumption_testing,
            ):
                setattr(module_cfg, 'safe_mode', safe_mode)
            
            # Optional merged Spec_Schema attached to owasp_testing by the
            # ``full`` command (Task 43.1). Threaded as an additive keyword into
            # the three hardened modules so they can test declared Spec_Operations
            # in addition to discovered endpoints (Requirements 49.2, 49.5). It
            # defaults to ``None`` and every consumer guards on
            # ``if self.spec_schema is not None`` so the no-spec path is
            # unchanged (Requirements 49.3, 52.6, 53.2, 54.3, 55.5).
            spec_schema = getattr(self.config.owasp_testing, 'spec_schema', None)
            
            # Initialize modules with their specific configurations
            if "bola" not in self.owasp_modules:
                bola_module = BOLATestingModule(self.config.owasp_testing.bola_testing, http_client, auth_contexts, spec_schema=spec_schema)
                self.register_owasp_module("bola", bola_module)
            
            if "auth" not in self.owasp_modules:
                auth_module = AuthenticationTestingModule(self.config.owasp_testing.auth_testing, http_client, auth_contexts, spec_schema=spec_schema)
                self.register_owasp_module("auth", auth_module)
            
            if "property" not in self.owasp_modules:
                property_module = PropertyLevelAuthModule(self.config.owasp_testing.property_testing, http_client, auth_contexts, spec_schema=spec_schema)
                self.register_owasp_module("property", property_module)
            
            if "function_auth" not in self.owasp_modules:
                function_auth_module = FunctionLevelAuthModule(self.config.owasp_testing.function_auth_testing, http_client, auth_contexts)
                self.register_owasp_module("function_auth", function_auth_module)
            
            if "resource" not in self.owasp_modules:
                resource_module = ResourceConsumptionModule(self.config.owasp_testing.resource_testing, http_client, auth_contexts)
                self.register_owasp_module("resource", resource_module)
            
            if "ssrf" not in self.owasp_modules:
                ssrf_module = SSRFTestingModule(self.config.owasp_testing.ssrf_testing, http_client, auth_contexts)
                self.register_owasp_module("ssrf", ssrf_module)
            
            if "business_flow" not in self.owasp_modules:
                business_flow_module = BusinessFlowsTestingModule(self.config.owasp_testing.business_flow_testing, http_client, auth_contexts)
                self.register_owasp_module("business_flow", business_flow_module)
            
            if "security_misconfig" not in self.owasp_modules:
                security_misconfig_module = SecurityMisconfigModule(self.config.owasp_testing.security_misconfig_testing, http_client, auth_contexts)
                self.register_owasp_module("security_misconfig", security_misconfig_module)
            
            if "inventory" not in self.owasp_modules:
                inventory_module = InventoryManagementModule(self.config.owasp_testing.inventory_testing, http_client, auth_contexts)
                self.register_owasp_module("inventory", inventory_module)
            
            if "unsafe_consumption" not in self.owasp_modules:
                unsafe_consumption_module = UnsafeConsumptionModule(self.config.owasp_testing.unsafe_consumption_testing, http_client, auth_contexts)
                self.register_owasp_module("unsafe_consumption", unsafe_consumption_module)
            
            # Initialize Advanced Discovery Engine if enabled
            if self.config.advanced_discovery.enabled and not hasattr(self, 'advanced_discovery_engine'):
                await self._initialize_advanced_discovery()
            
            self.logger.info("OWASP modules initialized",
                           modules_count=len(self.owasp_modules))
            
        except ImportError as e:
            self.logger.error("Failed to import OWASP modules", error=str(e))
        except Exception as e:
            self.logger.error("Failed to initialize OWASP modules", error=str(e))
    
    async def _initialize_advanced_discovery(self) -> None:
        """Initialize Advanced Discovery Engine"""
        try:
            from modules.advanced import AdvancedDiscoveryEngine
            from modules.advanced.subdomain_discovery import SubdomainDiscoveryConfig
            from modules.advanced.cors_analyzer import CORSAnalyzerConfig
            from modules.advanced.security_headers_analyzer import SecurityHeadersConfig
            from modules.advanced.advanced_discovery_engine import AdvancedDiscoveryConfig
            
            # Create HTTP client for advanced discovery
            from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig, UserAgentRotator
            
            rate_limiter = RateLimiter(self.config.rate_limiting)
            retry_config = RetryConfig(
                max_attempts=_get_retry_settings(self.config),
                backoff_factor=2.0,
                retry_on_status=[429, 502, 503, 504]
            )
            
            # Create user agent rotator
            user_agent_rotator = None
            headers_config = self.config.fuzzing.headers
            
            if headers_config.random_user_agent:
                user_agent_rotator = UserAgentRotator(mode="random")
            elif headers_config.user_agent_rotation and headers_config.user_agent_list:
                user_agent_rotator = UserAgentRotator(mode="rotate", user_agent_list=headers_config.user_agent_list)
            elif headers_config.custom_headers.get('User-Agent'):
                custom_ua = headers_config.custom_headers['User-Agent']
                if custom_ua != 'APILeak/0.2.0':
                    user_agent_rotator = UserAgentRotator(mode="custom", custom_user_agent=custom_ua)
            
            # Get status code filter for HTTP output
            status_code_filter = _get_status_code_filter(self.config)
            
            proxy, verify_ssl = _get_proxy_settings(self.config)
            http_client = HTTPRequestEngine(rate_limiter, retry_config, timeout=self.config.target.timeout, verify_ssl=verify_ssl, user_agent_rotator=user_agent_rotator, status_code_filter=status_code_filter, proxy=proxy)
            
            # Create advanced discovery configuration
            subdomain_config = SubdomainDiscoveryConfig(
                enabled=self.config.advanced_discovery.subdomain_discovery,
                wordlist=self.config.advanced_discovery.subdomain_wordlist,
                timeout=self.config.advanced_discovery.timeout,
                max_concurrent=self.config.advanced_discovery.max_concurrent
            )
            
            cors_config = CORSAnalyzerConfig(
                enabled=self.config.advanced_discovery.cors_analysis,
                test_origins=self.config.advanced_discovery.cors_test_origins,
                timeout=self.config.advanced_discovery.timeout,
                max_concurrent=self.config.advanced_discovery.max_concurrent
            )
            
            security_headers_config = SecurityHeadersConfig(
                enabled=self.config.advanced_discovery.security_headers,
                timeout=self.config.advanced_discovery.timeout,
                max_concurrent=self.config.advanced_discovery.max_concurrent
            )
            
            advanced_config = AdvancedDiscoveryConfig(
                subdomain_discovery=subdomain_config,
                cors_analysis=cors_config,
                security_headers=security_headers_config,
                timeout=self.config.advanced_discovery.timeout
            )
            
            # Initialize Advanced Discovery Engine
            self.advanced_discovery_engine = AdvancedDiscoveryEngine(advanced_config, http_client)
            
            self.logger.info("Advanced Discovery Engine initialized")
            
        except ImportError as e:
            self.logger.error("Failed to import Advanced Discovery modules", error=str(e))
        except Exception as e:
            self.logger.error("Failed to initialize Advanced Discovery Engine", error=str(e))
    
    async def _execute_advanced_discovery_phase(self) -> None:
        """Execute Advanced Discovery phase"""
        if not hasattr(self, 'advanced_discovery_engine'):
            self.logger.warning("Advanced Discovery Engine not initialized")
            return
        
        try:
            # Collect additional endpoints from discovered endpoints
            additional_endpoints = [endpoint.url for endpoint in self.discovered_endpoints]
            
            # Map attack surface
            attack_surface = await self.advanced_discovery_engine.map_attack_surface(
                target=self.config.target.base_url,
                additional_endpoints=additional_endpoints
            )
            
            # Get findings from advanced discovery
            advanced_findings = self.advanced_discovery_engine.get_findings()
            
            # Add findings to collector
            if advanced_findings:
                self.findings_collector.add_findings(advanced_findings)
            
            # Store attack surface in scan results
            if hasattr(self.scan_results, 'advanced_results'):
                self.scan_results.advanced_results = attack_surface
            else:
                # Add advanced_results attribute dynamically
                setattr(self.scan_results, 'advanced_results', attack_surface)
            
            self.logger.info("Advanced Discovery phase completed",
                           subdomains_found=len(attack_surface.discovered_subdomains),
                           total_findings=len(advanced_findings),
                           high_risk_findings=attack_surface.high_risk_findings)
            
        except Exception as e:
            self.logger.error("Advanced Discovery phase failed", error=str(e))
    
    async def _aggregate_results(self) -> None:
        """Aggregate results from all phases using enhanced findings collector"""
        self.logger.debug("Aggregating scan results with enhanced classification")
        
        # Aggregate findings from fuzzing and OWASP phases into findings collector
        if self.scan_results.fuzzing_results:
            fuzzing_findings = self.scan_results.fuzzing_results.get("findings", [])
            if fuzzing_findings:
                self.findings_collector.add_findings(fuzzing_findings)
        
        if self.scan_results.owasp_results:
            owasp_findings = self.scan_results.owasp_results.get("findings", [])
            if owasp_findings:
                self.findings_collector.add_findings(owasp_findings)
        
        # Update legacy findings list for backward compatibility
        self.scan_results.findings = self.findings_collector.findings
        
        # Add discovered endpoints to scan results
        self.scan_results.discovered_endpoints = self.discovered_endpoints
        
        # Update statistics with enhanced metrics
        collector_stats = self.findings_collector.get_statistics()
        self.scan_results.statistics.findings_count = collector_stats["total_findings"]
        self.scan_results.statistics.critical_findings = collector_stats["critical_findings"]
        self.scan_results.statistics.high_findings = collector_stats["high_findings"]
        self.scan_results.statistics.medium_findings = collector_stats["medium_findings"]
        self.scan_results.statistics.low_findings = collector_stats["low_findings"]
        self.scan_results.statistics.info_findings = collector_stats["info_findings"]
        self.scan_results.statistics.endpoints_discovered = len(self.discovered_endpoints)
        
        # Update fuzzing statistics from fuzzing results
        if self.scan_results.fuzzing_results:
            fuzzing_stats = self.scan_results.fuzzing_results
            self.scan_results.statistics.total_requests = fuzzing_stats.get("total_requests", 0)
            # Add parameters_tested to statistics if not already there
            if hasattr(self.scan_results.statistics, 'parameters_tested'):
                self.scan_results.statistics.parameters_tested = fuzzing_stats.get("parameters_tested", 0)
            else:
                # Add the attribute dynamically
                setattr(self.scan_results.statistics, 'parameters_tested', fuzzing_stats.get("parameters_tested", 0))
            
            # Add endpoints_tested to statistics
            if hasattr(self.scan_results.statistics, 'endpoints_tested'):
                self.scan_results.statistics.endpoints_tested = fuzzing_stats.get("endpoints_tested", 0)
            else:
                # Add the attribute dynamically
                setattr(self.scan_results.statistics, 'endpoints_tested', fuzzing_stats.get("endpoints_tested", 0))
        
        # Log OWASP coverage information
        owasp_coverage = self.findings_collector.get_owasp_coverage()
        self.logger.info("OWASP coverage analysis completed",
                        tested_categories=owasp_coverage["tested_categories"],
                        coverage_percentage=owasp_coverage["coverage_percentage"],
                        most_critical=collector_stats.get("most_critical_category"))
        
        self.logger.debug("Results aggregation completed",
                         total_findings=collector_stats["total_findings"],
                         unique_endpoints=collector_stats["unique_endpoints"],
                         owasp_categories=collector_stats["owasp_categories_tested"])
    
    def register_fuzzing_module(self, module_name: str, module: Any) -> None:
        """
        Register a fuzzing module
        
        Args:
            module_name: Name of the module
            module: Module instance
        """
        self.fuzzing_modules[module_name] = module
        self.logger.debug("Fuzzing module registered", module=module_name)
    
    def register_owasp_module(self, module_name: str, module: Any) -> None:
        """
        Register an OWASP testing module
        
        Args:
            module_name: Name of the module
            module: Module instance
        """
        self.owasp_modules[module_name] = module
        self.logger.debug("OWASP module registered", module=module_name)
    
    def get_findings_collector(self) -> FindingsCollector:
        """
        Get the findings collector instance
        
        Returns:
            FindingsCollector instance
        """
        return self.findings_collector
    
    def add_finding(self, category: str, severity: Optional[Any], endpoint: str, 
                   method: str, evidence: str, recommendation: str, **kwargs) -> Finding:
        """
        Add a finding directly to the collector
        
        Args:
            category: Finding category
            severity: Finding severity (auto-classified if None)
            endpoint: Affected endpoint
            method: HTTP method
            evidence: Evidence of the finding
            recommendation: Remediation recommendation
            **kwargs: Additional finding attributes
            
        Returns:
            Created finding
        """
        return self.findings_collector.add_finding(
            category=category,
            severity=severity,
            endpoint=endpoint,
            method=method,
            evidence=evidence,
            recommendation=recommendation,
            **kwargs
        )
    
    def get_discovered_endpoints(self) -> List[Any]:
        """
        Get list of discovered endpoints
        
        Returns:
            List of discovered endpoints
        """
        return self.discovered_endpoints.copy()
    
    def get_discovery_status(self) -> Dict[str, Any]:
        """
        Get discovery recursion-control status flags from the endpoint fuzzer.
        
        Surfaces ``budget_reached`` (the Request_Budget was reached and discovery
        stopped early), ``catch_all_detected`` (Catch_All_Response behavior was
        detected), and ``graphql_introspection_endpoint`` (the URL of a detected
        GraphQL endpoint with introspection enabled, or ``None``; Requirement 27).
        The values are read defensively and default to ``False``/``None`` so the
        accessor is safe to call even when no discovery ran or when the underlying
        fuzzer attributes are not present.
        
        Returns:
            Dictionary with ``budget_reached`` and ``catch_all_detected`` booleans
            and the ``graphql_introspection_endpoint`` URL (or ``None``).
        """
        orchestrator = getattr(self, 'fuzzing_orchestrator', None)
        fuzzer = getattr(orchestrator, 'endpoint_fuzzer', None)
        return {
            "budget_reached": bool(getattr(fuzzer, 'budget_reached', False)),
            "catch_all_detected": bool(getattr(fuzzer, 'catch_all_detected', False)),
            "graphql_introspection_endpoint": getattr(
                fuzzer, 'graphql_introspection_endpoint', None
            ),
        }
    
    def get_secret_findings(self) -> List[Any]:
        """Return redacted secret findings collected during discovery.

        Surfaces the :class:`SecretFinding` records accumulated by the endpoint
        fuzzer when secret detection is enabled (Requirement 30). The fuzzer and
        its findings list are read defensively, so this returns an empty list
        when discovery has not run, secret detection was disabled, or no match
        was found (Requirement 30.7). Each finding's matched value is already
        redacted (Requirement 30.4).
        """
        orchestrator = getattr(self, 'fuzzing_orchestrator', None)
        fuzzer = getattr(orchestrator, 'endpoint_fuzzer', None)
        return list(getattr(fuzzer, 'secret_findings', []) or [])
    
    def get_fuzzing_stats(self) -> Optional[Any]:
        """Return the fuzzing/discovery execution statistics, or ``None``.

        Surfaces the :class:`FuzzingStats` object accumulated by the fuzzing
        orchestrator during discovery (endpoints tested/discovered, total
        requests, success rate, recursion depth reached; Requirement 31.3). The
        orchestrator and its statistics are read defensively, so this returns
        ``None`` when discovery has not run or the orchestrator is not present,
        keeping callers safe to invoke even when no discovery occurred.

        Returns:
            The current ``FuzzingStats`` object, or ``None`` when unavailable.
        """
        orchestrator = getattr(self, 'fuzzing_orchestrator', None)
        if orchestrator is None:
            return None
        getter = getattr(orchestrator, 'get_fuzzing_statistics', None)
        if getter is None:
            return None
        try:
            return getter()
        except Exception:  # noqa: BLE001 - defensive: never break the summary
            return None
    
    def get_scan_status(self) -> Dict[str, Any]:
        """
        Get current scan status
        
        Returns:
            Dictionary with scan status information
        """
        status = {
            "scan_id": self.scan_id,
            "is_running": self.is_running,
            "target": self.config.target.base_url,
            "registered_fuzzing_modules": list(self.fuzzing_modules.keys()),
            "registered_owasp_modules": list(self.owasp_modules.keys()),
            "enabled_owasp_modules": self.config.owasp_testing.enabled_modules,
            "endpoints_discovered": len(self.discovered_endpoints),
            "findings_statistics": self.findings_collector.get_statistics()
        }
        
        if self.scan_results:
            status.update({
                "scan_start_time": self.scan_results.timestamp.isoformat(),
                "total_findings": self.scan_results.statistics.findings_count,
                "critical_findings": self.scan_results.statistics.critical_findings
            })
        
        return status
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check of the core engine
        
        Returns:
            Health check results
        """
        health_status = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "scan_id": self.scan_id,
            "configuration_loaded": self.config is not None,
            "fuzzing_modules_count": len(self.fuzzing_modules),
            "owasp_modules_count": len(self.owasp_modules),
            "is_scan_running": self.is_running
        }
        
        # Check configuration validity
        config_manager = ConfigurationManager()
        config_manager.config = self.config
        validation_errors = config_manager.validate_configuration()
        
        if validation_errors:
            health_status["status"] = "degraded"
            health_status["configuration_errors"] = validation_errors
        
        self.logger.debug("Health check completed", status=health_status["status"])
        
        return health_status