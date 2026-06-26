"""
Unit tests for interactive discovery triage behaviour.

**Feature: owasp-complete-purple-teaming-cicd, Task 18.3**

These example-based tests pin down the contract of
:func:`apileaks.run_interactive_triage`:

- interactive triage is opt-in and disabled by default; ``interactive_flag``
  ``False`` never prompts and never launches a follow-up scan (Requirement 16.4)
- CI_Mode disables the prompt and continues without blocking, even when the
  opt-in flag is set (Requirement 16.3)
- a valid selection initiates exactly one ``Targeted_Follow_Up_Scan`` scoped to
  the selected endpoint and returns it (Requirements 16.1, 16.2)
- 3 consecutive invalid selections abandon the prompt without a follow-up scan
  and print an "abandoned" message (Requirements 16.6, 16.7)
- an empty (or empty-after-filtering) record set skips the prompt and launches
  no follow-up scan (Requirement 16.8)
- on reload, the selectable endpoints are sourced exclusively from the
  ``Discovery_Session_File`` (Requirement 16.5)
"""

from apileaks import run_interactive_triage
from utils.discovery_session import (
    DiscoveryResult,
    DiscoverySession,
    parse_status_filter,
)


def _record(status_code: int, url: str, method: str = "GET") -> DiscoveryResult:
    """Build a DiscoveryResult with the given status code, URL and method."""
    return DiscoveryResult(
        url=url,
        method=method,
        status_code=status_code,
        endpoint_status="valid",
    )


def _mixed_records():
    """Return records spanning all four status classes, in shuffled class order."""
    return [
        _record(404, "https://api.example.com/missing"),
        _record(200, "https://api.example.com/ok"),
        _record(503, "https://api.example.com/down"),
        _record(301, "https://api.example.com/moved"),
    ]


class _Spy:
    """A callable that records every invocation and its single argument."""

    def __init__(self):
        self.calls = []

    def __call__(self, arg):
        self.calls.append(arg)

    @property
    def count(self):
        return len(self.calls)


class _Prompter:
    """A prompt_func stub returning a scripted sequence of raw inputs.

    Each call pops the next scripted response. It also tallies how many times it
    was invoked so tests can assert the prompt was (or was not) shown.
    """

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    def __call__(self, message):
        self.calls += 1
        if not self._responses:
            # Defensive: a test asked for more prompts than it scripted.
            raise AssertionError("prompt_func called more times than scripted")
        return self._responses.pop(0)


def _echo_collector(sink):
    """Return an echo stub that appends every emitted message to ``sink``."""

    def _echo(message, *args, **kwargs):
        sink.append(message)

    return _echo


# ---------------------------------------------------------------------------
# 16.4 — opt-in, disabled by default
# ---------------------------------------------------------------------------


def test_disabled_by_default_returns_none_and_never_prompts():
    """interactive_flag=False returns None and never prompts or follows up (16.4)."""
    follow_up = _Spy()
    prompter = _Prompter(["1"])  # would select if ever consulted
    messages = []

    result = run_interactive_triage(
        _mixed_records(),
        False,  # ci_mode
        False,  # interactive_flag -> opt-out (default)
        follow_up=follow_up,
        prompt_func=prompter,
        echo=_echo_collector(messages),
    )

    assert result is None
    assert follow_up.count == 0
    assert prompter.calls == 0
    # No selection UI is rendered when the mode is disabled.
    assert messages == []


# ---------------------------------------------------------------------------
# 16.3 — CI_Mode disables the prompt and continues without blocking
# ---------------------------------------------------------------------------


def test_ci_mode_disables_prompt_even_when_opted_in():
    """ci_mode=True returns None without prompting, even with interactive_flag=True (16.3)."""
    follow_up = _Spy()
    prompter = _Prompter(["1"])
    messages = []

    result = run_interactive_triage(
        _mixed_records(),
        True,   # ci_mode -> auto-disable
        True,   # interactive_flag -> opted in, but CI wins
        follow_up=follow_up,
        prompt_func=prompter,
        echo=_echo_collector(messages),
    )

    assert result is None
    # Never blocks on input and never launches a follow-up scan in CI.
    assert prompter.calls == 0
    assert follow_up.count == 0


# ---------------------------------------------------------------------------
# 16.1 / 16.2 — a valid selection launches exactly one follow-up scan
# ---------------------------------------------------------------------------


def test_valid_selection_launches_one_follow_up_and_returns_record():
    """A valid selection invokes follow_up exactly once with the chosen record (16.1, 16.2)."""
    records = _mixed_records()
    follow_up = _Spy()
    # "2" selects the second displayed row. Displayed order is ascending by
    # status class: 200 (2xx), 301 (3xx), 404 (4xx), 503 (5xx) -> index 2 = 301.
    prompter = _Prompter(["2"])

    result = run_interactive_triage(
        records,
        False,
        True,
        follow_up=follow_up,
        prompt_func=prompter,
        echo=_echo_collector([]),
    )

    expected = _record(301, "https://api.example.com/moved")
    assert result == expected
    # Exactly one Targeted_Follow_Up_Scan, scoped to the selected endpoint.
    assert follow_up.count == 1
    assert follow_up.calls[0] == expected
    assert prompter.calls == 1


def test_valid_selection_first_row_maps_to_lowest_status_class():
    """Selection "1" maps to the first displayed row (lowest status class) (16.1, 16.2)."""
    records = _mixed_records()
    follow_up = _Spy()
    prompter = _Prompter(["1"])

    result = run_interactive_triage(
        records,
        False,
        True,
        follow_up=follow_up,
        prompt_func=prompter,
        echo=_echo_collector([]),
    )

    assert result == _record(200, "https://api.example.com/ok")
    assert follow_up.count == 1


def test_invalid_then_valid_selection_launches_exactly_one_scan():
    """An invalid attempt re-prompts; the next valid one launches one scan (16.2, 16.6)."""
    records = _mixed_records()
    follow_up = _Spy()
    # First input is invalid (out of range), then a valid "1".
    prompter = _Prompter(["99", "1"])

    result = run_interactive_triage(
        records,
        False,
        True,
        follow_up=follow_up,
        prompt_func=prompter,
        echo=_echo_collector([]),
    )

    assert result == _record(200, "https://api.example.com/ok")
    assert follow_up.count == 1
    assert prompter.calls == 2


# ---------------------------------------------------------------------------
# 16.6 / 16.7 — 3 invalid selections abandon without a scan
# ---------------------------------------------------------------------------


def test_three_invalid_selections_abandon_without_scan():
    """3 consecutive invalid selections abandon without a follow-up scan (16.6, 16.7)."""
    follow_up = _Spy()
    prompter = _Prompter(["0", "abc", "999"])  # three invalid attempts
    messages = []

    result = run_interactive_triage(
        _mixed_records(),
        False,
        True,
        follow_up=follow_up,
        prompt_func=prompter,
        echo=_echo_collector(messages),
    )

    assert result is None
    assert follow_up.count == 0
    # Exactly the bounded number of attempts were consumed (16.6).
    assert prompter.calls == 3
    # An "abandoned" message is surfaced to the user (16.7).
    assert any("abandoned" in str(message).lower() for message in messages)


def test_abandon_respects_custom_max_invalid_attempts():
    """The invalid-attempt bound is honoured for a custom max (16.6)."""
    follow_up = _Spy()
    prompter = _Prompter(["x", "y"])

    result = run_interactive_triage(
        _mixed_records(),
        False,
        True,
        follow_up=follow_up,
        prompt_func=prompter,
        max_invalid_attempts=2,
    )

    assert result is None
    assert follow_up.count == 0
    assert prompter.calls == 2


# ---------------------------------------------------------------------------
# 16.8 — empty table skips the prompt
# ---------------------------------------------------------------------------


def test_empty_record_set_skips_prompt():
    """An empty record set skips the prompt and launches no scan (16.8)."""
    follow_up = _Spy()
    prompter = _Prompter(["1"])

    result = run_interactive_triage(
        [],
        False,
        True,
        follow_up=follow_up,
        prompt_func=prompter,
    )

    assert result is None
    assert prompter.calls == 0
    assert follow_up.count == 0


def test_empty_after_filtering_skips_prompt():
    """A filter that excludes every record skips the prompt (16.8)."""
    follow_up = _Spy()
    prompter = _Prompter(["1"])
    # Only 2xx-5xx records exist; filter to 1xx-equivalent via an explicit code
    # that matches nothing in the set.
    status_filter = parse_status_filter("418")

    result = run_interactive_triage(
        _mixed_records(),
        False,
        True,
        status_filter=status_filter,
        follow_up=follow_up,
        prompt_func=prompter,
    )

    assert result is None
    assert prompter.calls == 0
    assert follow_up.count == 0


def test_filter_constrains_selectable_set():
    """The selectable set matches the filtered table; index 1 is the only match (16.1, 16.8)."""
    follow_up = _Spy()
    prompter = _Prompter(["1"])
    status_filter = parse_status_filter("4xx")

    result = run_interactive_triage(
        _mixed_records(),
        False,
        True,
        status_filter=status_filter,
        follow_up=follow_up,
        prompt_func=prompter,
    )

    # Only the single 4xx record is selectable.
    assert result == _record(404, "https://api.example.com/missing")
    assert follow_up.count == 1


def test_filtered_out_of_range_index_re_prompts():
    """With a filter active, an index beyond the filtered set is invalid (16.6)."""
    follow_up = _Spy()
    # Only one 4xx record is displayed, so "2" is out of range, then "1" is valid.
    prompter = _Prompter(["2", "1"])
    status_filter = parse_status_filter("4xx")

    result = run_interactive_triage(
        _mixed_records(),
        False,
        True,
        status_filter=status_filter,
        follow_up=follow_up,
        prompt_func=prompter,
    )

    assert result == _record(404, "https://api.example.com/missing")
    assert prompter.calls == 2
    assert follow_up.count == 1


# ---------------------------------------------------------------------------
# 16.5 — reload sources selectable endpoints from the session file
# ---------------------------------------------------------------------------


def test_reloaded_session_records_are_the_selectable_source(tmp_path):
    """Records reloaded from a session file are the selectable endpoints (16.5).

    The session JSON file is the source of truth on reload; the prompt's
    selectable set is built from the reconstructed in-memory records, never from
    any export artifact.
    """
    records = _mixed_records()
    session = DiscoverySession(
        target="https://api.example.com",
        timestamp="2024-01-01T00:00:00Z",
        tool_version="0.2.0",
        results=records,
    )
    path = str(tmp_path / "session.json")
    session.save(path)

    reloaded = DiscoverySession.load(path)
    follow_up = _Spy()
    # "3" -> third displayed row in ascending class order = 404 (4xx).
    prompter = _Prompter(["3"])

    result = run_interactive_triage(
        reloaded.results,
        False,
        True,
        follow_up=follow_up,
        prompt_func=prompter,
    )

    assert result == _record(404, "https://api.example.com/missing")
    assert follow_up.count == 1
    # The selected record is one of the records that came from the session file.
    assert result in reloaded.results


def test_reloaded_empty_session_skips_prompt(tmp_path):
    """A reloaded empty session yields no selectable endpoints and skips the prompt (16.5, 16.8)."""
    session = DiscoverySession(
        target="https://api.example.com",
        timestamp="2024-01-01T00:00:00Z",
        tool_version="0.2.0",
        results=[],
    )
    path = str(tmp_path / "empty_session.json")
    session.save(path)

    reloaded = DiscoverySession.load(path)
    follow_up = _Spy()
    prompter = _Prompter(["1"])

    result = run_interactive_triage(
        reloaded.results,
        False,
        True,
        follow_up=follow_up,
        prompt_func=prompter,
    )

    assert result is None
    assert prompter.calls == 0
    assert follow_up.count == 0
