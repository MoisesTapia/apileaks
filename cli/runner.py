"""
Scan runner — orchestrates a full APILeak run and the CI severity gate.

Extracted from ``apileaks.py`` (monolith decomposition, Phase 4a). Hosts
``run_enhanced_apileak`` (the core scan execution consumed by the dir/par/scan
commands), the severity-gate evaluation, and the discovery-control status echo.
Re-imported by ``apileaks.py`` so existing callers and test patch targets
(``patch.object(apileaks, "run_enhanced_apileak")``) keep working while the
command families still live in ``apileaks``.
"""

from __future__ import annotations

import sys

import click

from cli.output import _echo_fuzzing_stats, _echo_secret_findings
from cli.parsers import _count_by_severity
from core import APILeakCore
from core.logging import get_logger

logger = get_logger(__name__)


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
        click.echo("⚠️  Request budget reached: discovery stopped early, results may be partial")
    if status.get("catch_all_detected"):
        click.echo(
            "⚠️  Catch-all response detected: wildcard endpoints excluded from recursive discovery"
        )
    graphql_endpoint = status.get("graphql_introspection_endpoint")
    if graphql_endpoint:
        click.echo(
            f"🔎 GRAPHQL_INTROSPECTION_ENABLED: introspection is enabled on {graphql_endpoint}"
        )
    _echo_fuzzing_stats(core)
    _echo_secret_findings(core)


SEVERITY_LADDER = ["critical", "high", "medium", "low"]


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


def _run_ai_triage_section(results, ai_config) -> None:
    """Run AI-assisted finding triage and print the result as a console section.

    This helper is called synchronously from within the already-running asyncio
    event loop of ``run_enhanced_apileak`` via ``asyncio.run_coroutine_threadsafe``
    — actually, since we ARE in an async context we call the coroutine directly
    via a new small event loop on a thread, OR we delegate to a sync wrapper that
    calls ``asyncio.run``.  Because ``run_enhanced_apileak`` itself is awaited
    inside an outer ``asyncio.run`` we cannot nest ``asyncio.run`` directly; we
    therefore use ``asyncio.get_event_loop().run_until_complete`` — but the
    cleanest approach given the existing code pattern is to accept the coroutine
    here and run it with the already-running loop via ``await``.

    To keep the call-site simple this function is intentionally **synchronous**:
    it creates a tiny new event loop so it can be called from within a running
    loop context without nesting.  Failures at every stage are caught and logged
    as WARNING — the scan result is never affected (Requirement 5.3).

    Args:
        results: Scan results object produced by ``APILeakCore.run_scan``.
        ai_config: ``AIConfig`` instance (may be ``None`` — treated as
            no-provider config in that case).
    """
    import asyncio as _asyncio

    try:
        from utils.ai.provider_base import AIConfig, build_llm_provider
        from utils.ai.triage_assistant import FindingTriageAssistant
    except ImportError:
        logger.warning(
            "ai_triage_import_error: utils.ai module is not available — "
            "AI triage section omitted. Install the 'apileaks[ai]' extra to enable it."
        )
        return

    # Resolve findings — mirrors the baseline comparison path in the caller.
    if hasattr(results, "findings_collector") and results.findings_collector:
        all_findings = results.findings_collector.get_prioritized_findings()
    else:
        all_findings = list(getattr(results, "findings", []) or [])

    # Build the LLM provider.  build_llm_provider returns None when
    # ai_config.provider is None, or when the config is None — both are safe.
    if ai_config is None:
        ai_config = AIConfig()  # provider=None -> safe_triage returns None + WARNING

    try:
        llm_provider = build_llm_provider(ai_config)
    except (ValueError, ImportError) as exc:
        logger.warning(
            "ai_triage_provider_build_failed: Could not build LLM provider — "
            "AI triage section omitted.",
            error=str(exc),
        )
        return

    assistant = FindingTriageAssistant(llm_provider)

    # Run the coroutine.  We are inside a synchronous helper called from an
    # async context that is itself already executing inside an asyncio event
    # loop (the one created by ``asyncio.run`` in ``_build_and_run``). Running a
    # *nested* asyncio.run is forbidden; instead we use a fresh thread with its
    # own event loop so there is no nesting.
    import concurrent.futures as _futures

    triage_report = None
    with _futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            lambda: _asyncio.run(assistant.safe_triage(all_findings))
        )
        try:
            triage_report = future.result()
        except Exception as exc:
            logger.warning(
                "ai_triage_unexpected_error: AI triage raised an unexpected error — "
                "AI triage section omitted.",
                error=str(exc),
            )
            return

    if triage_report is None:
        # safe_triage already logged an appropriate WARNING; nothing more to do.
        return

    # Render the triage section — strictly additive (Requirement 5.2).
    click.echo("\n" + "=" * 60)
    click.echo("AI Triage Report")
    click.echo("=" * 60)
    click.echo(f"\n{triage_report.narrative_summary}")

    if triage_report.prioritized_finding_ids:
        click.echo("\nPriority Order (highest → lowest):")
        for rank, fid in enumerate(triage_report.prioritized_finding_ids, 1):
            note = triage_report.per_finding_notes.get(fid, "")
            note_str = f"  ↳ {note}" if note else ""
            click.echo(f"  {rank:>3}. {fid}")
            if note_str:
                click.echo(f"       {note_str}")

    click.echo("=" * 60)
    logger.info(
        "ai_triage_section_appended",
        finding_count=len(triage_report.prioritized_finding_ids),
    )


def _run_ai_dedup_section(results, ai_config) -> None:
    """Run AI-assisted semantic deduplication and print grouped findings.

    Groups findings that share the same root cause and renders both the
    consolidated group summary AND the full detail of each individual finding
    within each group so no information is lost (Requirements 6.1, 6.2).

    When no LLM provider is configured, ``SemanticDeduplicator`` transparently
    falls back to a deterministic grouping strategy so the section is always
    populated when ``--ai-dedup`` is requested (Requirement 6.3).

    Failures at every stage are caught and logged as WARNING — the scan result
    is never affected (Requirement 5.3 applied to the dedup feature).

    Args:
        results: Scan results object produced by ``APILeakCore.run_scan``.
        ai_config: ``AIConfig`` instance (may be ``None`` — treated as
            no-provider config in that case).
    """
    import asyncio as _asyncio

    try:
        from utils.ai.provider_base import AIConfig, build_llm_provider
        from utils.ai.semantic_dedup import SemanticDeduplicator
    except ImportError:
        logger.warning(
            "ai_dedup_import_error: utils.ai module is not available — "
            "AI dedup section omitted. Install the 'apileaks[ai]' extra to enable it."
        )
        return

    # Resolve findings — mirrors the baseline comparison path in the caller.
    if hasattr(results, "findings_collector") and results.findings_collector:
        all_findings = results.findings_collector.get_prioritized_findings()
    else:
        all_findings = list(getattr(results, "findings", []) or [])

    if not all_findings:
        click.echo("\n" + "=" * 60)
        click.echo("AI Semantic Deduplication Report")
        click.echo("=" * 60)
        click.echo("No findings to deduplicate.")
        click.echo("=" * 60)
        return

    # Build the LLM provider.  build_llm_provider returns None when
    # ai_config.provider is None — SemanticDeduplicator uses its deterministic
    # fallback in that case (graceful degradation, Requirement 6.3 / 7.2).
    if ai_config is None:
        ai_config = AIConfig()  # provider=None -> deterministic fallback

    try:
        llm_provider = build_llm_provider(ai_config)
    except (ValueError, ImportError) as exc:
        logger.warning(
            "ai_dedup_provider_build_failed: Could not build LLM provider — "
            "falling back to deterministic deduplication.",
            error=str(exc),
        )
        llm_provider = None  # SemanticDeduplicator handles None gracefully

    deduplicator = SemanticDeduplicator(llm_provider)

    # Run the coroutine in a fresh thread to avoid nesting event loops (same
    # pattern as _run_ai_triage_section).
    import concurrent.futures as _futures

    groups = None
    with _futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            lambda: _asyncio.run(deduplicator.safe_deduplicate(all_findings))
        )
        try:
            groups = future.result()
        except Exception as exc:
            logger.warning(
                "ai_dedup_unexpected_error: AI deduplication raised an unexpected "
                "error — AI dedup section omitted.",
                error=str(exc),
            )
            return

    if groups is None:
        # safe_deduplicate already logged the appropriate WARNING; nothing more.
        return

    # Build a lookup so individual Finding details can be rendered for each
    # member — this is the no-information-loss requirement (Requirement 6.2).
    finding_by_id: dict = {f.id: f for f in all_findings}

    multi_groups = [g for g in groups if len(g.member_finding_ids) > 1]
    singleton_groups = [g for g in groups if len(g.member_finding_ids) == 1]

    click.echo("\n" + "=" * 60)
    click.echo("AI Semantic Deduplication Report")
    click.echo("=" * 60)
    click.echo(
        f"\nTotal findings: {len(all_findings)}  →  "
        f"{len(groups)} group(s)  "
        f"({len(multi_groups)} consolidated, {len(singleton_groups)} singleton)"
    )

    if multi_groups:
        click.echo("\n── Consolidated Groups ──")
        for group in multi_groups:
            short_id = group.group_id[:8]
            click.echo(f"\n  Group {short_id}…  ({len(group.member_finding_ids)} findings)")
            click.echo(f"  Root cause: {group.root_cause_summary}")
            click.echo(f"  Members:")
            for fid in group.member_finding_ids:
                finding = finding_by_id.get(fid)
                if finding is not None:
                    severity_label = getattr(
                        getattr(finding, "severity", None), "value",
                        str(getattr(finding, "severity", "unknown"))
                    ).upper()
                    click.echo(
                        f"    • [{severity_label}] {fid}"
                        f"  {getattr(finding, 'method', '')} {getattr(finding, 'endpoint', '')}"
                        f"  — {getattr(finding, 'category', '')}"
                    )
                    evidence = getattr(finding, "evidence", "") or ""
                    if evidence:
                        preview = evidence[:120].replace("\n", " ")
                        click.echo(f"      Evidence: {preview}")
                    recommendation = getattr(finding, "recommendation", "") or ""
                    if recommendation:
                        rec_preview = recommendation[:100].replace("\n", " ")
                        click.echo(f"      Recommendation: {rec_preview}")
                else:
                    click.echo(f"    • {fid}")

    if singleton_groups:
        click.echo(f"\n── Ungrouped Findings ({len(singleton_groups)}) ──")
        for group in singleton_groups:
            fid = group.member_finding_ids[0]
            finding = finding_by_id.get(fid)
            if finding is not None:
                severity_label = getattr(
                    getattr(finding, "severity", None), "value",
                    str(getattr(finding, "severity", "unknown"))
                ).upper()
                click.echo(
                    f"  • [{severity_label}] {fid}"
                    f"  {getattr(finding, 'method', '')} {getattr(finding, 'endpoint', '')}"
                    f"  — {getattr(finding, 'category', '')}"
                )
            else:
                click.echo(f"  • {fid}")

    click.echo("=" * 60)
    logger.info(
        "ai_dedup_section_appended",
        total_findings=len(all_findings),
        group_count=len(groups),
        consolidated_group_count=len(multi_groups),
    )


async def run_enhanced_apileak(
    config,
    ci_mode=False,
    fail_on="critical",
    baseline=None,
    discovery_progress=None,
    scope_endpoints=None,
    checkpoint_path=None,
    resume_checkpoint=None,
    ai_triage=False,
    ai_config=None,
    ai_dedup=False,
    ai_dedup_config=None,
):
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
        ai_triage: When ``True``, run AI-assisted triage on findings after the
                  scan and append the triage section to the console output
                  (Requirement 5.1).  Failures are always logged as WARNING and
                  never fail the scan (Requirement 5.3).
        ai_config: :class:`~utils.ai.provider_base.AIConfig` instance built by
                  the CLI from the configured provider settings.  Defaults to a
                  no-provider config when ``None`` (triage will be skipped with a
                  warning). Only consulted when ``ai_triage=True``.
        ai_dedup: When ``True``, run AI-assisted semantic deduplication on
                  findings after the scan and append the dedup section to the
                  console output (Requirements 6.1, 6.2).  When no LLM provider
                  is configured, the deterministic fallback is used transparently
                  (Requirement 6.3).  Failures are logged as WARNING and never
                  fail the scan.
        ai_dedup_config: :class:`~utils.ai.provider_base.AIConfig` instance for
                  the deduplication step.  Defaults to a no-provider config when
                  ``None``.  Only consulted when ``ai_dedup=True``.
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
    if hasattr(
        config.advanced_discovery, "framework_detection"
    ) and config.advanced_discovery.framework_detection.get("enabled"):
        advanced_features.append("Framework Detection")
    if hasattr(
        config.advanced_discovery, "version_fuzzing"
    ) and config.advanced_discovery.version_fuzzing.get("enabled"):
        advanced_features.append("Version Fuzzing")
    if hasattr(
        config.advanced_discovery, "payload_encoding"
    ) and config.advanced_discovery.payload_encoding.get("enabled"):
        advanced_features.append("Payload Encoding")
    if hasattr(
        config.advanced_discovery, "waf_detection"
    ) and config.advanced_discovery.waf_detection.get("enabled"):
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

    if hasattr(config.fuzzing, "response_filter") and config.fuzzing.response_filter:
        click.echo(f"📊 Response Filter: {config.fuzzing.response_filter}")
    if hasattr(config, "http_output") and config.http_output.status_code_filter:
        click.echo(f"🎨 Status Code Filter: {config.http_output.status_code_filter}")
    if config.authentication.contexts[0].token:
        click.echo("🔐 Authentication: JWT Token provided")
    if (
        hasattr(config.fuzzing.headers, "random_user_agent")
        and config.fuzzing.headers.random_user_agent
    ):
        click.echo("🎭 WAF Evasion: Random User-Agent enabled")

    click.echo(f"⚡ Rate Limit: {config.rate_limiting.requests_per_second} req/sec")

    if getattr(config, "safe_mode", False):
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
        output_filename = getattr(config.reporting, "output_filename", None)
        report_files = report_generator.save_reports(
            results,
            config.reporting.output_dir,
            scan_type,
            output_filename,
            formats=getattr(config.reporting, "formats", None),
        )

        # Display enhanced summary with advanced features results
        click.echo("\n" + "=" * 60)
        click.echo("APILeak Enhanced Scan Completed Successfully")
        click.echo("=" * 60)
        click.echo(f"Target: {target_url}")
        click.echo(f"Scan ID: {results.scan_id}")
        click.echo(f"Duration: {results.performance_metrics.duration}")

        # Surface discovery recursion-control status (budget reached / catch-all
        # detected) so the operator sees when discovery was truncated or wildcard
        # responses were excluded (Requirements 18.5, 19.5).
        _echo_discovery_control_status(core)

        # Get enhanced statistics from findings collector
        if hasattr(results, "findings_collector") and results.findings_collector:
            stats = results.findings_collector.get_statistics()
            owasp_coverage = results.findings_collector.get_owasp_coverage()

            # Show advanced discovery results if available
            if hasattr(results, "advanced_results"):
                advanced_results = results.advanced_results
                if (
                    hasattr(advanced_results, "framework_detected")
                    and advanced_results.framework_detected
                ):
                    click.echo(
                        f"🔍 Framework Detected: {advanced_results.framework_detected.name} (confidence: {advanced_results.framework_detected.confidence:.2f})"
                    )
                if (
                    hasattr(advanced_results, "api_versions_found")
                    and advanced_results.api_versions_found
                ):
                    click.echo(f"📋 API Versions Found: {len(advanced_results.api_versions_found)}")
                if (
                    hasattr(advanced_results, "subdomains_discovered")
                    and advanced_results.subdomains_discovered
                ):
                    click.echo(
                        f"🌐 Subdomains Discovered: {len(advanced_results.subdomains_discovered)}"
                    )
                if hasattr(advanced_results, "waf_detected") and advanced_results.waf_detected:
                    click.echo(
                        f"🛡️  WAF Detected: {advanced_results.waf_detected.name} (confidence: {advanced_results.waf_detected.confidence:.2f})"
                    )

            # Show scan-specific metrics
            if scan_type == "dir":
                endpoints_tested = getattr(results.statistics, "endpoints_tested", 0)
                click.echo(f"Total Endpoints Tested: {endpoints_tested}")
                if hasattr(results, "discovered_endpoints"):
                    valid_endpoints = [
                        e
                        for e in core.get_discovered_endpoints()
                        if hasattr(e, "status_code") and e.status_code in [200, 201, 202, 204]
                    ]
                    if valid_endpoints:
                        click.echo("📍 Endpoints Found:")
                        for endpoint in valid_endpoints[:10]:  # Show first 10
                            click.echo(
                                f"  - {endpoint.method} {endpoint.url} ({endpoint.status_code})"
                            )
                        if len(valid_endpoints) > 10:
                            click.echo(f"  ... and {len(valid_endpoints) - 10} more")
                    else:
                        click.echo("No valid endpoints found (all returned 404 or errors)")
            elif scan_type == "param":
                click.echo(
                    f"Total Parameters Tested: {getattr(results.statistics, 'parameters_tested', 0)}"
                )

            click.echo(f"Total Findings: {stats['total_findings']}")
            click.echo(f"Critical: {stats['critical_findings']}")
            click.echo(f"High: {stats['high_findings']}")
            click.echo(f"Medium: {stats['medium_findings']}")
            click.echo(f"Low: {stats['low_findings']}")
            click.echo(f"Info: {stats['info_findings']}")
            click.echo(
                f"OWASP Coverage: {owasp_coverage['coverage_percentage']:.1f}% ({owasp_coverage['tested_categories']}/{owasp_coverage['total_categories']} categories)"
            )

            # Show most critical category if any
            if stats.get("most_critical_category"):
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
        # ReportGenerator.save_reports normally returns list[dict] (each a
        # {"path": ..., "format": ..., ...} file_info record) — printing the
        # raw dict showed its Python repr instead of the file path on every
        # completed scan (see technical-debt/code-quality-audit.md #16).
        # Some test doubles stub save_reports with a plain list[str] of paths,
        # so accept either shape rather than assuming every caller returns dicts.
        for report_file in report_files:
            path = (
                report_file.get("path", report_file)
                if isinstance(report_file, dict)
                else report_file
            )
            click.echo(f"  - {path}")

        # Baseline comparison: classify findings into new vs known relative to a
        # baseline JSON report (Requirements 11.1-11.3). A missing baseline path
        # yields an empty baseline so every finding is treated as new (11.5).
        new_findings = None
        if baseline:
            from utils.baseline import BaselineComparator

            comparator = BaselineComparator()
            baseline_keys = comparator.load(baseline)

            if hasattr(results, "findings_collector") and results.findings_collector:
                all_findings = results.findings_collector.get_prioritized_findings()
            else:
                all_findings = list(getattr(results, "findings", []) or [])

            new_findings, known_findings = comparator.classify(all_findings, baseline_keys)

            click.echo("\n📊 Baseline Comparison:")
            click.echo(f"  - Baseline: {baseline}")
            click.echo(f"  - New findings: {len(new_findings)}")
            click.echo(f"  - Known findings: {len(known_findings)}")

        # --- AI triage section (Requirements 5.1, 5.2, 5.3) ---
        # Appended AFTER the baseline comparison so the operator sees it before
        # the CI/CD exit banner.  The original findings and already-written report
        # files are never modified — the triage output is strictly additive
        # (Requirement 5.2).  safe_triage() returns None on any AI failure so
        # the scan is never failed by AI errors (Requirement 5.3).
        if ai_triage:
            _run_ai_triage_section(results, ai_config)

        # --- AI dedup section (Requirements 6.1, 6.2, 6.3) ---
        # Appended after the triage section (if present). Groups semantically
        # equivalent findings and renders both the consolidated group summary
        # AND the full detail of each individual member Finding — no information
        # loss (Requirement 6.2). The deterministic fallback runs transparently
        # when no LLM provider is configured (Requirement 6.3). Failures are
        # always logged as WARNING; the scan result is never affected.
        if ai_dedup:
            _run_ai_dedup_section(results, ai_dedup_config)

        # Enhanced CI/CD integration with configurable exit codes
        if ci_mode:
            if new_findings is not None:
                # With a baseline, the severity gate evaluates only the
                # New_Finding set (Requirement 11.4).
                counts = _count_by_severity(new_findings)
            else:
                counts = {
                    "critical": getattr(results.statistics, "critical_findings", 0),
                    "high": getattr(results.statistics, "high_findings", 0),
                    "medium": getattr(results.statistics, "medium_findings", 0),
                    "low": getattr(results.statistics, "low_findings", 0),
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
            critical_count = getattr(results.statistics, "critical_findings", 0)
            high_count = getattr(results.statistics, "high_findings", 0)

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
