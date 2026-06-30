"""
Unit tests for the live discovery progress display.

**Feature: owasp-complete-purple-teaming-cicd, Task 36.2**

These example-based tests pin down the contract of
:class:`utils.discovery_progress.DiscoveryProgress` and the
:func:`apileaks._build_discovery_progress` gating that wires it into the
``dir`` command:

- the display is enabled only for an interactive session that is **not** in
  CI_Mode and whose standard output is a TTY, and is disabled in CI_Mode and
  when stdout is not a TTY (Requirements 32.1, 32.3, 32.4)
- while active the status line reports the requests issued, the current rate,
  the budget consumed/remaining, the elapsed time, and the ETA
  (Requirement 32.2)
- when no Request_Budget is configured (``total is None``) the status line
  reports the requests issued and omits the consumed/remaining budget figures
  and the ETA rather than reporting a remaining count (Requirement 32.5)
"""

import sys

import apileaks
from utils.discovery_progress import DiscoveryProgress


class _FakeStdout:
    """Minimal stdout stand-in whose ``isatty`` returns a fixed value."""

    def __init__(self, is_tty: bool):
        self._is_tty = is_tty

    def isatty(self) -> bool:
        return self._is_tty


# ---------------------------------------------------------------------------
# Gating: enabled only when interactive + non-CI + TTY (Reqs 32.1, 32.3, 32.4)
# ---------------------------------------------------------------------------


def test_enabled_when_non_ci_and_tty(monkeypatch):
    """Interactive (non-CI) + TTY stdout renders the display (Requirement 32.1)."""
    monkeypatch.setattr(sys, "stdout", _FakeStdout(is_tty=True))

    progress = apileaks._build_discovery_progress(ci_mode=False, max_requests=100)

    assert isinstance(progress, DiscoveryProgress)
    assert progress.enabled is True


def test_disabled_in_ci_mode_even_with_tty(monkeypatch):
    """CI_Mode disables the display regardless of TTY (Requirement 32.3)."""
    monkeypatch.setattr(sys, "stdout", _FakeStdout(is_tty=True))

    progress = apileaks._build_discovery_progress(ci_mode=True, max_requests=100)

    assert progress.enabled is False


def test_disabled_when_stdout_not_a_tty(monkeypatch):
    """Non-TTY stdout disables the display so piped output is untouched (Req 32.4)."""
    monkeypatch.setattr(sys, "stdout", _FakeStdout(is_tty=False))

    progress = apileaks._build_discovery_progress(ci_mode=False, max_requests=100)

    assert progress.enabled is False


def test_disabled_when_ci_mode_and_not_a_tty(monkeypatch):
    """Both gates closed keeps the display disabled (Requirements 32.3, 32.4)."""
    monkeypatch.setattr(sys, "stdout", _FakeStdout(is_tty=False))

    progress = apileaks._build_discovery_progress(ci_mode=True, max_requests=100)

    assert progress.enabled is False


def test_disabled_progress_has_no_underlying_rich_progress():
    """A disabled display constructs no ``rich`` progress object."""
    progress = DiscoveryProgress(enabled=False, total=100)

    assert progress.enabled is False
    assert progress._progress is None


def test_update_is_noop_when_disabled():
    """``update`` on a disabled display never starts a render (Reqs 32.3, 32.4)."""
    progress = DiscoveryProgress(enabled=False, total=100)

    # Should not raise and should not start an underlying render.
    progress.update(issued=5, elapsed=1.0)

    assert progress._progress is None
    assert progress._started is False


# ---------------------------------------------------------------------------
# Reported fields while active (Requirement 32.2)
# ---------------------------------------------------------------------------


def test_status_reports_all_required_fields_when_budget_set():
    """With a budget, the status reports issued, rate, consumed/remaining,
    elapsed and ETA (Requirement 32.2)."""
    progress = DiscoveryProgress(enabled=True, total=100)

    status = progress.format_status(issued=20, elapsed=10.0)

    # Requests issued.
    assert "20 requests" in status
    # Current rate: 20 / 10 = 2.0 req/s.
    assert "2.0 req/s" in status
    # Budget consumed and remaining (100 - 20 = 80).
    assert "budget 20/100 consumed" in status
    assert "80 remaining" in status
    # Elapsed time.
    assert "elapsed 10.0s" in status
    # Estimated remaining time: 80 / 2.0 = 40.0s.
    assert "ETA 40.0s" in status


def test_status_remaining_never_negative_past_budget():
    """Once issued exceeds the budget the remaining figure clamps to zero."""
    progress = DiscoveryProgress(enabled=True, total=100)

    status = progress.format_status(issued=120, elapsed=10.0)

    assert "budget 120/100 consumed" in status
    assert "0 remaining" in status
    assert "ETA 0.0s" in status


def test_status_rate_is_zero_before_any_time_elapses():
    """A zero elapsed time yields a 0.0 rate rather than dividing by zero."""
    progress = DiscoveryProgress(enabled=True, total=100)

    status = progress.format_status(issued=0, elapsed=0.0)

    assert "0.0 req/s" in status
    # No positive rate => no ETA extrapolation.
    assert "ETA" not in status


# ---------------------------------------------------------------------------
# Unbounded discovery omits budget figures (Requirement 32.5)
# ---------------------------------------------------------------------------


def test_status_omits_budget_figures_when_unbounded():
    """``total is None`` reports issued but omits consumed/remaining and ETA
    rather than reporting a remaining count (Requirement 32.5)."""
    progress = DiscoveryProgress(enabled=True, total=None)

    status = progress.format_status(issued=20, elapsed=10.0)

    # Still reports issued, rate and elapsed.
    assert "20 requests" in status
    assert "2.0 req/s" in status
    assert "elapsed 10.0s" in status
    # No budget consumed/remaining figures and no ETA.
    assert "budget" not in status
    assert "remaining" not in status
    assert "ETA" not in status


def test_build_progress_unbounded_when_max_requests_none(monkeypatch):
    """No configured budget threads ``total=None`` into the display (Req 32.5)."""
    monkeypatch.setattr(sys, "stdout", _FakeStdout(is_tty=True))

    progress = apileaks._build_discovery_progress(ci_mode=False, max_requests=None)

    assert progress.total is None
    status = progress.format_status(issued=7, elapsed=2.0)
    assert "7 requests" in status
    assert "remaining" not in status
