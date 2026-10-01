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


async def run_enhanced_apileak(
    config,
    ci_mode=False,
    fail_on="critical",
    baseline=None,
    discovery_progress=None,
    scope_endpoints=None,
    checkpoint_path=None,
    resume_checkpoint=None,
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

            if hasattr(results, "findings_collector") and results.findings_collector:
                all_findings = results.findings_collector.get_prioritized_findings()
            else:
                all_findings = list(getattr(results, "findings", []) or [])

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
