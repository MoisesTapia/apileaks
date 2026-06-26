"""
Property-Based Tests for CI/CD Severity-Gate Monotonicity

**Feature: owasp-complete-purple-teaming-cicd, Property 4: Severity-gate
monotonicity**

Property 4 (from design.md):
    FOR ALL finding-count vectors and a fixed ``fail_on``, increasing the
    highest severity present never decreases the exit code returned by
    ``evaluate_severity_gate``. The gate is a pure, deterministic function of
    ``(counts, fail_on)``.

These tests use Hypothesis to generate arbitrary finding-count vectors and
assert the monotonicity property, alongside representative example-based cases
pinning the documented exit codes (Requirements 9.1, 9.2, 9.3).
"""

import pytest
from hypothesis import given, settings, strategies as st
from hypothesis.strategies import composite

from apileaks import evaluate_severity_gate, SEVERITY_LADDER


# fail_on values to exercise: the valid ladder plus malformed/unknown values
# that must fall back to the strictest threshold ("critical").
FAIL_ON_VALUES = SEVERITY_LADDER + ["", "unknown", "CRITICAL", "High", None]


@composite
def counts_strategy(draw):
    """Generate an arbitrary finding-count vector over the severity ladder."""
    return {
        severity: draw(st.integers(min_value=0, max_value=10))
        for severity in SEVERITY_LADDER
    }


@given(
    counts=counts_strategy(),
    fail_on=st.sampled_from(FAIL_ON_VALUES),
    add_count=st.integers(min_value=1, max_value=5),
)
@settings(max_examples=300, deadline=5000)
def test_raising_highest_severity_never_lowers_exit_code(counts, fail_on, add_count):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 4: Severity-gate
    monotonicity**
    **Validates: Requirements 9.1, 9.2, 9.3**

    FOR ALL finding-count vectors and a fixed ``fail_on``, adding findings at a
    severity at least as severe as the highest severity currently present (i.e.
    raising the highest severity present) never lowers the exit code.
    """
    base_code = evaluate_severity_gate(counts, fail_on)

    # Rank (index) of the highest severity currently present; lower index == more
    # severe. If no findings are present, len(SEVERITY_LADDER) marks "none".
    highest_present_rank = next(
        (rank for rank, sev in enumerate(SEVERITY_LADDER) if counts.get(sev, 0) > 0),
        len(SEVERITY_LADDER),
    )

    # Raising the highest severity present means adding findings at any rank that
    # is at least as severe as the current highest (rank <= highest_present_rank).
    # Every such promotion must produce an exit code >= the baseline.
    max_target_rank = min(highest_present_rank, len(SEVERITY_LADDER) - 1)
    for target_rank in range(0, max_target_rank + 1):
        raised = dict(counts)
        target_severity = SEVERITY_LADDER[target_rank]
        raised[target_severity] = raised.get(target_severity, 0) + add_count

        raised_code = evaluate_severity_gate(raised, fail_on)
        assert raised_code >= base_code, (
            f"Raising severity to '{target_severity}' lowered the exit code: "
            f"base={base_code} ({counts}) -> raised={raised_code} ({raised}) "
            f"with fail_on={fail_on!r}"
        )


@given(
    counts=counts_strategy(),
    fail_on=st.sampled_from(FAIL_ON_VALUES),
)
@settings(max_examples=200, deadline=5000)
def test_gate_is_deterministic_and_returns_valid_exit_code(counts, fail_on):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 4: Severity-gate
    monotonicity (purity)**
    **Validates: Requirements 9.1, 9.2, 9.3**

    The gate is a pure, deterministic function: repeated calls with the same
    inputs return the same value, and that value is always a valid CI exit code
    in {0, 1, 2}.
    """
    first = evaluate_severity_gate(counts, fail_on)
    second = evaluate_severity_gate(dict(counts), fail_on)

    assert first == second
    assert first in (0, 1, 2)


# ---------------------------------------------------------------------------
# Representative example-based cases pinning the documented exit codes.
# ---------------------------------------------------------------------------


def test_critical_present_and_threshold_met_returns_2():
    """
    **Validates: Requirement 9.2**

    fail_on="critical" with at least one critical finding present -> exit code 2.
    """
    assert evaluate_severity_gate({"critical": 1}, "critical") == 2
    assert evaluate_severity_gate({"critical": 3, "high": 2, "low": 5}, "critical") == 2
    # Critical present always meets even the most lenient threshold.
    assert evaluate_severity_gate({"critical": 1, "low": 1}, "low") == 2


def test_threshold_met_without_critical_returns_1():
    """
    **Validates: Requirement 9.2**

    Threshold met/exceeded but no critical finding present -> exit code 1.
    """
    assert evaluate_severity_gate({"high": 1}, "high") == 1
    assert evaluate_severity_gate({"high": 2, "medium": 4}, "medium") == 1
    assert evaluate_severity_gate({"low": 1}, "low") == 1


def test_highest_present_below_threshold_returns_0():
    """
    **Validates: Requirement 9.3**

    Highest severity present is below the threshold -> exit code 0 (pass).
    """
    assert evaluate_severity_gate({"high": 5, "medium": 2}, "critical") == 0
    assert evaluate_severity_gate({"medium": 3, "low": 9}, "high") == 0
    assert evaluate_severity_gate({"low": 7}, "medium") == 0


def test_no_findings_returns_0():
    """
    **Validates: Requirement 9.3**

    No findings present -> exit code 0 (pass), regardless of threshold.
    """
    assert evaluate_severity_gate({}, "critical") == 0
    assert evaluate_severity_gate({"critical": 0, "high": 0, "medium": 0, "low": 0}, "low") == 0


def test_unknown_or_empty_fail_on_falls_back_to_critical():
    """
    **Validates: Requirements 9.1, 9.3**

    Unknown/empty fail_on falls back to the strictest threshold ("critical"),
    so only critical findings trip the gate.
    """
    # High findings under a critical-equivalent (unknown) threshold -> pass.
    assert evaluate_severity_gate({"high": 4}, "unknown") == 0
    assert evaluate_severity_gate({"high": 4}, "") == 0
    # Critical findings still trip the gate under the fallback threshold.
    assert evaluate_severity_gate({"critical": 1}, "unknown") == 2
