"""
Live progress display during interactive discovery.

This module provides :class:`DiscoveryProgress`, a thin helper around
``rich.progress.Progress`` that renders a live, in-place ``Progress_Display``
while Endpoint_Discovery is running (Requirement 32.1). The display reports the
number of Discovery_Requests issued, the current request rate
(``issued / elapsed``), the Request_Budget consumed and remaining
(``total - issued``) when a budget is configured, the elapsed time, and the
estimated remaining time (ETA) (Requirement 32.2).

The display is gated exactly like the interactive triage prompt: the caller
computes ``enabled = (not ci_mode) and sys.stdout.isatty()`` and passes it in.
When ``enabled`` is ``False`` the helper is a no-op, so the display is disabled
in CI_Mode (Requirement 32.3) and whenever standard output is not a TTY so it
never interferes with piped output (Requirement 32.4).

When no Request_Budget is configured (``total is None``), the display reports the
Discovery_Requests issued and **omits** the consumed/remaining budget figures
rather than reporting a remaining count (Requirement 32.5).
"""

from typing import Optional

from rich.progress import Progress, SpinnerColumn, TextColumn

from core.logging import get_logger

logger = get_logger(__name__)


class DiscoveryProgress:
    """Live progress indicator for interactive Endpoint_Discovery.

    Wraps ``rich.progress.Progress``. When ``enabled`` is ``False`` every method
    is a no-op so the surrounding discovery code can call :meth:`update`
    unconditionally without worrying about CI_Mode/TTY gating.

    Args:
        enabled: Whether the display should render. The caller computes this as
            ``(not ci_mode) and sys.stdout.isatty()`` so the display is disabled
            in CI_Mode (Requirement 32.3) and when stdout is not a TTY
            (Requirement 32.4).
        total: The Request_Budget (``max_requests``) when one is configured, or
            ``None`` for unbounded discovery. When ``None`` the rendered status
            omits the consumed/remaining budget figures (Requirement 32.5).
    """

    def __init__(self, *, enabled: bool, total: Optional[int]):
        self.enabled = bool(enabled)
        self.total = total
        self._progress: Optional[Progress] = None
        self._task_id = None
        self._started = False

        if self.enabled:
            # A single text column renders the status string we build in
            # :meth:`format_status`; the spinner gives a live "working" cue.
            self._progress = Progress(
                SpinnerColumn(),
                TextColumn("{task.description}"),
                transient=False,
            )

    def format_status(self, *, issued: int, elapsed: float) -> str:
        """Build the human-readable status line for the given counters.

        Always reports the Discovery_Requests issued, the current request rate
        (``issued / elapsed``), and the elapsed time (Requirement 32.2). When a
        Request_Budget is configured (``total`` is not ``None``) it also reports
        the budget consumed/remaining and the estimated remaining time (ETA).
        When ``total is None`` the consumed/remaining budget figures and the ETA
        are omitted (Requirement 32.5).

        Args:
            issued: Number of Discovery_Requests issued so far.
            elapsed: Seconds elapsed since discovery started.

        Returns:
            A single-line status string suitable for the progress display.
        """
        rate = issued / elapsed if elapsed > 0 else 0.0

        parts = [
            f"{issued} requests",
            f"{rate:.1f} req/s",
        ]

        if self.total is not None:
            remaining = max(self.total - issued, 0)
            parts.append(f"budget {issued}/{self.total} consumed")
            parts.append(f"{remaining} remaining")

        parts.append(f"elapsed {elapsed:.1f}s")

        # ETA is only meaningful when a budget bounds the work and we have a
        # non-zero rate to extrapolate from. Omitted entirely when unbounded
        # (Requirement 32.5) so no remaining count is implied.
        if self.total is not None and rate > 0:
            eta = max(self.total - issued, 0) / rate
            parts.append(f"ETA {eta:.1f}s")

        return " | ".join(parts)

    def _ensure_started(self) -> None:
        """Start the underlying ``rich`` progress and add the task lazily."""
        if not self.enabled or self._progress is None or self._started:
            return
        self._progress.start()
        self._task_id = self._progress.add_task("starting discovery", total=self.total)
        self._started = True

    def update(self, *, issued: int, elapsed: float) -> None:
        """Refresh the display with the latest counters.

        A no-op when the display is disabled (Requirements 32.3, 32.4), so the
        discovery code can call this unconditionally.

        Args:
            issued: Number of Discovery_Requests issued so far.
            elapsed: Seconds elapsed since discovery started.
        """
        if not self.enabled or self._progress is None:
            return

        self._ensure_started()
        description = self.format_status(issued=issued, elapsed=elapsed)
        if self.total is not None:
            self._progress.update(
                self._task_id,
                completed=min(issued, self.total),
                description=description,
            )
        else:
            # No total => indeterminate progress; only the description advances.
            self._progress.update(self._task_id, description=description)

    def stop(self) -> None:
        """Stop the display, releasing the live render. Safe to call repeatedly."""
        if self._progress is not None and self._started:
            self._progress.stop()
            self._started = False

    def __enter__(self) -> "DiscoveryProgress":
        return self

    def __exit__(self, *exc_info) -> bool:
        self.stop()
        return False
