"""
CLI output / display helpers.

Console-rendering helpers extracted from ``apileaks.py`` as part of the monolith
decomposition: banner, discovery/secret summaries, OWASP module listing, token
display, and attack-result rendering. All output goes through ``click.echo``.
Re-imported by ``apileaks.py`` to preserve the public surface.
"""

from __future__ import annotations

import click

from cli.owasp_descriptors import OWASP_MODULE_DESCRIPTORS
from core import __version__ as APILEAK_VERSION


def print_banner():
    """Print APILeak banner"""
    banner = (
        r"""
      .o.       ooooooooo.   ooooo ooooo                            oooo
     .888.      `888   `Y88. `888' `888'                            `888
    .8"888.      888   .d88'  888   888          .ooooo.   .oooo.    888  oooo   .oooo.o
   .8' `888.     888ooo88P'   888   888         d88' `88b `P  )88b   888 .8P'   d88(  "8
  .88ooo8888.    888          888   888         888ooo888  .oP"888   888888.    `"Y88b.
 .8'     `888.   888          888   888       o 888    .o d8(  888   888 `88b.  o.  )88b
o88o     o8888o o888o        o888o o888ooooood8 `Y8bod8P' `Y888""8o o888o o888o 8""888P'
"""
        + f"\nAPILeak v{APILEAK_VERSION} - Enterprise API Fuzzing Tool - by Cl0wnR3v\n"
    )
    click.echo(banner, color=True)


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


def _emit_module_selection_deprecation(modules):
    """Write the module-selection Deprecation_Notice for ``full --modules``.

    Maps a single selected key to its ``apileaks owasp <key>`` equivalent and a
    multi-key selection to ``apileaks scan --modules ...`` (Requirement 6.6).
    Written ONLY to stderr, exactly once, and never alters stdout or the exit
    code.
    """
    selected = [m.strip() for m in modules.split(",") if m.strip()]
    if len(selected) == 1:
        replacement = f"apileaks owasp {selected[0]}"
    else:
        replacement = f"apileaks scan --modules {','.join(selected)}"
    click.echo(
        f"[DEPRECATION] Selecting modules through 'full --modules' is "
        f"deprecated. Use '{replacement}' instead.",
        err=True,
    )


def _print_owasp_module_listing() -> None:
    """Write one line per descriptor to stdout (Requirements 1.4, 11.4).

    Each line contains the module's engine registration key, its OWASP category
    identifier, and its single-line (<= 80 char) summary, in OWASP category
    order (API1..API10).
    """
    for desc in OWASP_MODULE_DESCRIPTORS:
        click.echo(f"{desc.key}\t{desc.owasp_category}\t{desc.summary}")


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
            f"(len Δ {bc.get('content_length_diff')})"
        )

    if assessment.is_vulnerable:
        click.echo(
            f"   🚨 VULNERABILITY CONFIRMED: {assessment.vulnerability_type} "
            f"({assessment.severity.value})"
        )
        for ev in assessment.evidence:
            click.echo(f"   💀 {ev}")
        if response.body and response.body.strip():
            click.echo(f"   📄 Response: {response.body.strip()}")
        return True

    # Show response body when content length differs significantly from
    # baseline — the server may have accepted the token even if the status code
    # did not change (common in CTF/lab environments).
    if result.baseline_comparison:
        length_diff = abs(result.baseline_comparison.get("content_length_diff", 0))
        if length_diff > 20 and response.body and response.body.strip():
            click.echo("   ⚠️  Response body differs from baseline:")
            click.echo(f"   📄 Response: {response.body.strip()}")

    click.echo("   ✅ Attack blocked - server rejected the malicious token")
    return False
