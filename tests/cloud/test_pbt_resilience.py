"""
Property-based tests for Task 7.3: Partial-failure resilience.

**Property 4: Resiliencia ante Fallos Parciales**
For any execution of ``cloud-audit --provider all`` where at least one
auditor lacks valid credentials or an individual resource is inaccessible
due to permissions, the execution SHALL complete with the findings from the
accessible providers/resources, without terminating with an unhandled
exception.

**Validates: Requirements 9.1, 9.3, 9.4**

Properties encoded:

  4a — run() NEVER raises an exception regardless of which auditors fail.
  4b — Findings from successful auditors are preserved; InsufficientPermissions
       errors produce exactly one INFO finding each; other failures add nothing.
  4c — Summary counters (_skipped_providers, _not_audited_resources) are
       consistent with the error breakdown of the auditor list.
  4d — Calling run() twice never accumulates summary state across calls.
"""

from __future__ import annotations

import asyncio
from typing import Literal
from unittest.mock import AsyncMock, MagicMock

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from core.config import CloudAuditConfig
from modules.cloud.base import (
    CredentialResolutionError,
    GatewayFinding,
    GatewaySeverity,
    InsufficientPermissionsError,
    ProviderThrottledError,
)
from modules.cloud.normalizer import GatewayFindingNormalizer
from modules.cloud.orchestrator import CloudAuditOrchestrator

# ---------------------------------------------------------------------------
# Outcome type alias
# ---------------------------------------------------------------------------

AuditorOutcome = Literal[
    "success",
    "credential_error",
    "permission_error",
    "throttle_error",
    "runtime_error",
]

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# One of the five possible outcomes for a single auditor
_auditor_outcome: st.SearchStrategy[AuditorOutcome] = st.one_of(
    st.just("success"),
    st.just("credential_error"),
    st.just("permission_error"),
    st.just("throttle_error"),
    st.just("runtime_error"),
)

# A non-empty list of 1..8 outcomes (keeps tests snappy)
_auditor_outcomes: st.SearchStrategy[list[AuditorOutcome]] = st.lists(
    _auditor_outcome,
    min_size=1,
    max_size=8,
)

# Small integer: 0..5 findings per successful auditor
_finding_count: st.SearchStrategy[int] = st.integers(min_value=0, max_value=5)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PROVIDERS = ["aws", "gcp", "azure"]


def _make_gateway_finding(provider: str, idx: int) -> GatewayFinding:
    """Create a minimal GatewayFinding for testing."""
    return GatewayFinding(
        provider=provider,
        resource_id=f"arn::{provider}::res-{idx}",
        resource_type="rest_api",
        check_id="test_check",
        title=f"Test finding {idx}",
        severity=GatewaySeverity.MEDIUM,
        evidence={"key": "value"},
        remediation="Fix it.",
        account_context=f"{provider}:ctx-{idx}",
    )


def _make_mock_auditor(
    outcome: AuditorOutcome,
    auditor_idx: int,
    finding_count: int,
) -> MagicMock:
    """
    Build a mock CloudGatewayAuditor whose audit() behaves according to *outcome*.

    For "success" outcomes the auditor returns *finding_count* GatewayFindings.
    """
    provider = _PROVIDERS[auditor_idx % len(_PROVIDERS)]
    account_ctx = f"{provider}:ctx-{auditor_idx}"

    mock = MagicMock()
    mock.get_provider_name.return_value = provider
    mock._account_context = account_ctx

    if outcome == "success":
        findings = [_make_gateway_finding(provider, i) for i in range(finding_count)]
        mock.audit = AsyncMock(return_value=findings)
    elif outcome == "credential_error":
        mock.audit = AsyncMock(side_effect=CredentialResolutionError("No credentials"))
    elif outcome == "permission_error":
        mock.audit = AsyncMock(side_effect=InsufficientPermissionsError("Access denied"))
    elif outcome == "throttle_error":
        mock.audit = AsyncMock(side_effect=ProviderThrottledError("Rate limit exceeded"))
    else:  # "runtime_error"
        mock.audit = AsyncMock(side_effect=RuntimeError("Unexpected failure"))

    return mock


def _build_orchestrator(auditors: list[MagicMock]) -> CloudAuditOrchestrator:
    """
    Construct an orchestrator that bypasses __init__ (no real SDK calls) and
    directly injects the supplied mock auditors.
    """
    config = CloudAuditConfig(providers=["aws"])
    orch = CloudAuditOrchestrator.__new__(CloudAuditOrchestrator)
    orch._config = config
    orch._normalizer = GatewayFindingNormalizer()
    orch.auditors = auditors
    orch._skipped_providers = []
    orch._not_audited_resources = []
    return orch


# ---------------------------------------------------------------------------
# Property 4a — run() never raises, regardless of error mix
# ---------------------------------------------------------------------------


@given(
    outcomes=_auditor_outcomes,
    finding_counts=st.lists(_finding_count, min_size=8, max_size=8),
)
@settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
def test_4a_run_never_raises(
    outcomes: list[AuditorOutcome],
    finding_counts: list[int],
) -> None:
    """
    **Validates: Requirements 9.1, 9.3, 9.4**

    For any list of 1–8 auditors, each independently succeeding or raising
    any of the four handled error types (or an unexpected RuntimeError),
    CloudAuditOrchestrator.run() MUST complete without propagating any
    exception to the caller.
    """
    auditors = [
        _make_mock_auditor(outcome, idx, finding_counts[idx])
        for idx, outcome in enumerate(outcomes)
    ]
    orch = _build_orchestrator(auditors)

    # Should NEVER raise — this is the core invariant
    try:
        asyncio.run(orch.run())
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"run() raised {type(exc).__name__}: {exc} "
            f"with outcomes={outcomes}"
        ) from exc


# ---------------------------------------------------------------------------
# Property 4b — Findings from successful auditors are preserved
# ---------------------------------------------------------------------------


@given(
    outcomes=_auditor_outcomes,
    finding_counts=st.lists(_finding_count, min_size=8, max_size=8),
)
@settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
def test_4b_successful_findings_preserved(
    outcomes: list[AuditorOutcome],
    finding_counts: list[int],
) -> None:
    """
    **Validates: Requirements 9.1, 9.3, 9.4**

    The findings returned by run() MUST be exactly:
    - All normalized findings from successful auditors
    - Plus exactly one INFO Finding per InsufficientPermissionsError auditor

    No findings are generated for CredentialResolutionError, ProviderThrottledError,
    or unexpected RuntimeError outcomes.
    """
    auditors = [
        _make_mock_auditor(outcome, idx, finding_counts[idx])
        for idx, outcome in enumerate(outcomes)
    ]

    expected_success_findings = sum(
        finding_counts[idx]
        for idx, outcome in enumerate(outcomes)
        if outcome == "success"
    )
    expected_perm_findings = sum(
        1 for outcome in outcomes if outcome == "permission_error"
    )
    expected_total = expected_success_findings + expected_perm_findings

    orch = _build_orchestrator(auditors)
    findings = asyncio.run(orch.run())

    assert len(findings) == expected_total, (
        f"Expected {expected_total} findings "
        f"({expected_success_findings} success + {expected_perm_findings} perm), "
        f"got {len(findings)}. Outcomes: {outcomes}"
    )

    # Every finding must carry owasp_category="API8"
    for f in findings:
        assert f.owasp_category == "API8", (
            f"Finding {f} has owasp_category={f.owasp_category!r}, expected 'API8'"
        )


# ---------------------------------------------------------------------------
# Property 4c — Summary tracking is consistent with error counts
# ---------------------------------------------------------------------------


@given(
    outcomes=_auditor_outcomes,
    finding_counts=st.lists(_finding_count, min_size=8, max_size=8),
)
@settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
def test_4c_summary_tracking_consistent(
    outcomes: list[AuditorOutcome],
    finding_counts: list[int],
) -> None:
    """
    **Validates: Requirements 9.3, 9.4**

    After run() completes:
    - len(_skipped_providers) == number of CredentialResolutionError auditors
    - len(_not_audited_resources) == number of (InsufficientPermissionsError
      + ProviderThrottledError) auditors
    - Both are non-negative integers
    """
    auditors = [
        _make_mock_auditor(outcome, idx, finding_counts[idx])
        for idx, outcome in enumerate(outcomes)
    ]

    expected_skipped = sum(1 for o in outcomes if o == "credential_error")
    expected_not_audited = sum(
        1 for o in outcomes if o in ("permission_error", "throttle_error")
    )

    orch = _build_orchestrator(auditors)
    asyncio.run(orch.run())

    assert len(orch._skipped_providers) == expected_skipped, (
        f"Expected {expected_skipped} skipped providers, "
        f"got {len(orch._skipped_providers)}. Outcomes: {outcomes}"
    )
    assert len(orch._not_audited_resources) == expected_not_audited, (
        f"Expected {expected_not_audited} not-audited resources, "
        f"got {len(orch._not_audited_resources)}. Outcomes: {outcomes}"
    )

    # Invariant: counts are non-negative
    assert len(orch._skipped_providers) >= 0
    assert len(orch._not_audited_resources) >= 0


# ---------------------------------------------------------------------------
# Property 4d — Summary state is reset between consecutive run() calls
# ---------------------------------------------------------------------------


@given(
    outcomes_run1=_auditor_outcomes,
    outcomes_run2=_auditor_outcomes,
    finding_counts=st.lists(_finding_count, min_size=8, max_size=8),
)
@settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
def test_4d_summary_resets_between_runs(
    outcomes_run1: list[AuditorOutcome],
    outcomes_run2: list[AuditorOutcome],
    finding_counts: list[int],
) -> None:
    """
    **Validates: Requirements 9.3, 9.4**

    Calling run() twice MUST NOT accumulate summary state from the first call.
    After the second run(), _skipped_providers and _not_audited_resources MUST
    reflect ONLY the second run's auditor outcomes.
    """
    # First run
    auditors_run1 = [
        _make_mock_auditor(outcome, idx, finding_counts[idx])
        for idx, outcome in enumerate(outcomes_run1)
    ]
    orch = _build_orchestrator(auditors_run1)
    asyncio.run(orch.run())

    # Second run — replace auditors and call run() again
    auditors_run2 = [
        _make_mock_auditor(outcome, idx, finding_counts[idx])
        for idx, outcome in enumerate(outcomes_run2)
    ]
    orch.auditors = auditors_run2
    asyncio.run(orch.run())

    # Summary must reflect run2 only, not run1 + run2
    expected_skipped_run2 = sum(1 for o in outcomes_run2 if o == "credential_error")
    expected_not_audited_run2 = sum(
        1 for o in outcomes_run2 if o in ("permission_error", "throttle_error")
    )

    assert len(orch._skipped_providers) == expected_skipped_run2, (
        f"After run2: expected {expected_skipped_run2} skipped, "
        f"got {len(orch._skipped_providers)}. run1={outcomes_run1}, run2={outcomes_run2}"
    )
    assert len(orch._not_audited_resources) == expected_not_audited_run2, (
        f"After run2: expected {expected_not_audited_run2} not-audited, "
        f"got {len(orch._not_audited_resources)}. run1={outcomes_run1}, run2={outcomes_run2}"
    )
