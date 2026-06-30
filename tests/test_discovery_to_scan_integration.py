"""
Unit tests for discovery-to-scan integration for multiple endpoints.

**Feature: owasp-complete-purple-teaming-cicd, Task 41.3**

These example-based tests pin down Requirement 36 (Discovery-to-Scan
Integration for Multiple Endpoints). They mirror the patterns used by
``tests/test_interactive_triage.py`` (selection prompting with injected
spies/prompters) and ``tests/test_rate_limit_user_agent_cli.py`` (capturing the
threaded ``config_dict`` at the ``ConfigurationManager`` boundary, and driving
the ``dir`` command with ``CliRunner`` while patching the scoped-scan helper).

Covered behaviour:

- an interactive multi-select and a non-interactive ``--scan-scope`` both
  produce exactly the selected set of ``DiscoveryResult`` records
  (Requirements 36.1, 36.2);
- the scoped scan rebuilds the same Rate_Limit, User_Agent_Option,
  Discovery_Header_Option, and auth values supplied to the originating ``dir``
  invocation (Requirement 36.5);
- in CI_Mode the Batch_Scan_Scope is determined ONLY from ``--scan-scope`` with
  no interactive prompt and without blocking (Requirement 36.4);
- an empty determined scope performs no scan and reports "nothing to scan"
  (Requirement 36.6);
- an unrecognized ``--scan-scope`` token returns a descriptive error naming the
  value and performs no scan (Requirement 36.7).
"""

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

import apileaks
from apileaks import (
    ScanScopeError,
    cli,
    run_interactive_triage,
    select_scope_records,
    _run_scoped_owasp_scan,
)
from utils.discovery_session import DiscoverySession, DiscoveryResult


TARGET = "https://api.example.com"


def _record(status_code, url, method="GET", endpoint_status="valid"):
    """Build a DiscoveryResult with the given fields."""
    return DiscoveryResult(
        url=url,
        method=method,
        status_code=status_code,
        endpoint_status=endpoint_status,
    )


def _mixed_records():
    """Records spanning all four status classes, in shuffled class order."""
    return [
        _record(404, f"{TARGET}/missing"),
        _record(200, f"{TARGET}/ok"),
        _record(503, f"{TARGET}/down"),
        _record(301, f"{TARGET}/moved"),
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
    """A prompt_func stub returning a scripted sequence of raw inputs."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    def __call__(self, message):
        self.calls += 1
        if not self._responses:
            raise AssertionError("prompt_func called more times than scripted")
        return self._responses.pop(0)


# ---------------------------------------------------------------------------
# 36.1 — interactive multi-select produces exactly the selected set
# ---------------------------------------------------------------------------


def test_interactive_multi_select_produces_selected_set():
    """A multi-index selection yields a Batch_Scan_Scope of exactly those records.

    Displayed order is ascending by status class: 200 (2xx), 301 (3xx),
    404 (4xx), 503 (5xx). Selecting ``"1,3"`` picks the 200 and 404 records.

    **Validates: Requirements 36.1**
    """
    records = _mixed_records()
    batch = _Spy()
    follow_up = _Spy()
    prompter = _Prompter(["1,3"])

    result = run_interactive_triage(
        records,
        False,  # ci_mode
        True,   # interactive_flag
        follow_up=follow_up,
        batch_follow_up=batch,
        prompt_func=prompter,
        echo=lambda *a, **k: None,
    )

    expected = [_record(200, f"{TARGET}/ok"), _record(404, f"{TARGET}/missing")]
    assert result == expected
    # Exactly one batch scan launched, over exactly the selected set.
    assert batch.count == 1
    assert batch.calls[0] == expected
    # A multi-select never launches a single-endpoint follow-up.
    assert follow_up.count == 0


def test_interactive_range_select_produces_selected_set():
    """A range selection ``"2-4"`` produces exactly the 3xx, 4xx, 5xx records.

    **Validates: Requirements 36.1**
    """
    records = _mixed_records()
    batch = _Spy()
    prompter = _Prompter(["2-4"])

    result = run_interactive_triage(
        records,
        False,
        True,
        batch_follow_up=batch,
        prompt_func=prompter,
        echo=lambda *a, **k: None,
    )

    expected = [
        _record(301, f"{TARGET}/moved"),
        _record(404, f"{TARGET}/missing"),
        _record(503, f"{TARGET}/down"),
    ]
    assert result == expected
    assert batch.count == 1
    assert batch.calls[0] == expected


# ---------------------------------------------------------------------------
# 36.2 — non-interactive --scan-scope produces exactly the selected set
# ---------------------------------------------------------------------------


def test_scan_scope_status_class_selects_matching_records():
    """A Status_Code_Class token selects exactly the matching records (36.2)."""
    records = _mixed_records()

    selected = select_scope_records(records, "2xx")

    assert selected == [_record(200, f"{TARGET}/ok")]


def test_scan_scope_status_class_5xx_selects_matching_records():
    """A 5xx token selects exactly the 5xx record (36.2)."""
    records = _mixed_records()

    selected = select_scope_records(records, "5xx")

    assert selected == [_record(503, f"{TARGET}/down")]


def test_scan_scope_endpoint_status_valid_selects_matching_records():
    """An EndpointStatus token (``valid``) selects all VALID records (36.2)."""
    records = [
        _record(200, f"{TARGET}/ok", endpoint_status="valid"),
        _record(401, f"{TARGET}/secret", endpoint_status="auth_required"),
        _record(204, f"{TARGET}/empty", endpoint_status="valid"),
    ]

    selected = select_scope_records(records, "valid")

    assert selected == [
        _record(200, f"{TARGET}/ok", endpoint_status="valid"),
        _record(204, f"{TARGET}/empty", endpoint_status="valid"),
    ]


def test_scan_scope_endpoint_status_auth_required_selects_matching_records():
    """An EndpointStatus token (``auth_required``) selects all AUTH_REQUIRED records (36.2)."""
    records = [
        _record(200, f"{TARGET}/ok", endpoint_status="valid"),
        _record(401, f"{TARGET}/secret", endpoint_status="auth_required"),
        _record(403, f"{TARGET}/admin", endpoint_status="auth_required"),
    ]

    selected = select_scope_records(records, "auth_required")

    assert selected == [
        _record(401, f"{TARGET}/secret", endpoint_status="auth_required"),
        _record(403, f"{TARGET}/admin", endpoint_status="auth_required"),
    ]


def test_scan_scope_contains_no_unselected_record():
    """The selected set contains no record outside the chosen scope (36.2, 36.8)."""
    records = _mixed_records()

    selected = select_scope_records(records, "4xx")

    # Exactly the 4xx subset, nothing else.
    assert selected == [_record(404, f"{TARGET}/missing")]
    assert all(r.status_code // 100 == 4 for r in selected)


def _build_session_file(tmp_path, records, name="session.json"):
    """Persist a DiscoverySession and return the file path (reload source)."""
    session = DiscoverySession(
        target=TARGET,
        timestamp="2024-01-01T00:00:00Z",
        tool_version="0.2.0",
        results=records,
    )
    path = str(tmp_path / name)
    session.save(path)
    return path


def test_cli_scan_scope_drives_scoped_scan_with_selected_set(tmp_path):
    """``dir --scan-scope`` feeds exactly the matching records to the scoped scan.

    Records are sourced from a reloaded session file (the source of truth) so the
    test is deterministic and performs no real discovery.

    **Validates: Requirements 36.2, 36.3**
    """
    session_path = _build_session_file(tmp_path, _mixed_records())
    captured = {}

    def _capture(selected_records, **kwargs):
        captured["selected_records"] = selected_records

    runner = CliRunner()
    with patch.object(apileaks, "_run_scoped_owasp_scan", _capture):
        result = runner.invoke(
            cli,
            [
                "--no-banner",
                "dir",
                "--target",
                TARGET,
                "--load-session",
                session_path,
                "--scan-scope",
                "2xx",
            ],
        )

    assert result.exit_code == 0, result.output
    assert "selected_records" in captured
    assert captured["selected_records"] == [_record(200, f"{TARGET}/ok")]


# ---------------------------------------------------------------------------
# 36.4 — CI_Mode determines the scope ONLY from --scan-scope, never blocks
# ---------------------------------------------------------------------------


def test_ci_mode_scan_scope_drives_scoped_scan_without_prompt(tmp_path):
    """In CI_Mode the scope comes only from ``--scan-scope`` and never prompts.

    Even with ``--interactive`` set, CI_Mode determines the Batch_Scan_Scope
    solely from ``--scan-scope`` and runs the scoped scan without displaying a
    selection prompt or waiting for input.

    **Validates: Requirements 36.4**
    """
    session_path = _build_session_file(tmp_path, _mixed_records())
    captured = {}

    def _capture(selected_records, **kwargs):
        captured["selected_records"] = selected_records

    runner = CliRunner()
    with patch.object(apileaks, "_run_scoped_owasp_scan", _capture):
        # No stdin is provided; if the command blocked on an interactive prompt
        # it would consume input/EOF instead of running the scoped scan.
        result = runner.invoke(
            cli,
            [
                "--no-banner",
                "dir",
                "--target",
                TARGET,
                "--load-session",
                session_path,
                "--scan-scope",
                "4xx",
                "--ci-mode",
                "--interactive",
            ],
        )

    assert result.exit_code == 0, result.output
    # Scope determined exclusively from --scan-scope (the 4xx record).
    assert captured.get("selected_records") == [_record(404, f"{TARGET}/missing")]


def test_ci_mode_interactive_helper_never_prompts_or_batches():
    """``run_interactive_triage`` in CI mode never prompts and launches no batch (36.4)."""
    batch = _Spy()
    follow_up = _Spy()
    prompter = _Prompter(["1,2"])

    result = run_interactive_triage(
        _mixed_records(),
        True,   # ci_mode -> auto-disable
        True,   # interactive_flag opted in, but CI wins
        follow_up=follow_up,
        batch_follow_up=batch,
        prompt_func=prompter,
    )

    assert result is None
    assert prompter.calls == 0
    assert batch.count == 0
    assert follow_up.count == 0


# ---------------------------------------------------------------------------
# 36.5 — the scoped scan inherits rate-limit / User-Agent / header / auth
# ---------------------------------------------------------------------------


class _ShortCircuit(Exception):
    """Sentinel raised once the scoped ``config_dict`` is captured."""


def _run_scoped_capturing_config(records=None, **overrides):
    """Call ``_run_scoped_owasp_scan`` and capture its built ``config_dict``.

    Patches the config loader to capture the config and raise a sentinel before
    any real scan, mirroring ``tests/test_rate_limit_user_agent_cli.py``.
    """
    captured = {}

    def _capture(self, config_dict):
        captured["config_dict"] = config_dict
        raise _ShortCircuit()

    params = dict(
        target=TARGET,
        rate_limit=None,
        user_agent_random=False,
        user_agent_custom=None,
        user_agent_file=None,
        jwt=None,
        response=None,
        output=None,
        logger=MagicMock(),
    )
    params.update(overrides)
    selected = records if records is not None else [_record(200, f"{TARGET}/ok")]

    with patch.object(
        apileaks.ConfigurationManager, "load_config_from_dict", _capture
    ):
        with pytest.raises(_ShortCircuit):
            _run_scoped_owasp_scan(selected, **params)
    return captured["config_dict"]


def test_scoped_scan_inherits_rate_limit():
    """The scoped scan rebuilds the same Rate_Limit override (36.5)."""
    config_dict = _run_scoped_capturing_config(rate_limit=17)

    assert config_dict["rate_limiting"]["requests_per_second"] == 17


def test_scoped_scan_inherits_custom_user_agent():
    """The scoped scan rebuilds the custom User-Agent header (36.5)."""
    custom_ua = "ScopedScanner/3.0"
    config_dict = _run_scoped_capturing_config(user_agent_custom=custom_ua)

    headers = config_dict["fuzzing"]["headers"]
    assert headers["custom_headers"]["User-Agent"] == custom_ua
    assert headers["random_user_agent"] is False
    assert headers["user_agent_rotation"] is False


def test_scoped_scan_inherits_random_user_agent():
    """The scoped scan rebuilds the random-UA flag (36.5)."""
    config_dict = _run_scoped_capturing_config(user_agent_random=True)

    assert config_dict["fuzzing"]["headers"]["random_user_agent"] is True


def test_scoped_scan_inherits_user_agent_file_rotation(tmp_path):
    """The scoped scan rebuilds the rotation list/flag from a UA file (36.5)."""
    ua_file = tmp_path / "agents.txt"
    ua_file.write_text("Agent-A\n# comment\nAgent-B\n")

    config_dict = _run_scoped_capturing_config(user_agent_file=str(ua_file))

    headers = config_dict["fuzzing"]["headers"]
    assert headers["user_agent_list"] == ["Agent-A", "Agent-B"]
    assert headers["user_agent_rotation"] is True
    assert headers["custom_headers"]["User-Agent"] == "Agent-A"


def test_scoped_scan_inherits_discovery_headers():
    """The scoped scan re-applies operator-supplied ``--header`` values (36.5)."""
    config_dict = _run_scoped_capturing_config(
        header=("X-Api-Key: abc123", "X-Trace: on")
    )

    custom = config_dict["fuzzing"]["headers"]["custom_headers"]
    assert custom["X-Api-Key"] == "abc123"
    assert custom["X-Trace"] == "on"


def test_scoped_scan_inherits_cookie_header():
    """The scoped scan re-applies the ``--cookie`` value as a Cookie header (36.5)."""
    config_dict = _run_scoped_capturing_config(cookie="session=deadbeef")

    custom = config_dict["fuzzing"]["headers"]["custom_headers"]
    assert custom["Cookie"] == "session=deadbeef"


def test_scoped_scan_inherits_jwt_auth():
    """The scoped scan threads the ``--jwt`` token as a bearer context (36.5)."""
    config_dict = _run_scoped_capturing_config(jwt="header.payload.sig")

    context = config_dict["authentication"]["contexts"][0]
    assert context["token"] == "header.payload.sig"
    assert context["type"] == "bearer"


def test_scoped_scan_inherits_basic_auth():
    """The scoped scan threads ``--basic-auth`` as an HTTP Basic context (36.5)."""
    config_dict = _run_scoped_capturing_config(basic_auth="alice:s3cret")

    context = config_dict["authentication"]["contexts"][0]
    assert context["type"] == "basic"
    assert context["username"] == "alice"
    assert context["password"] == "s3cret"


def test_scoped_scan_combines_rate_limit_user_agent_and_headers():
    """Rate-limit, User-Agent, and headers are threaded together (36.5)."""
    config_dict = _run_scoped_capturing_config(
        rate_limit=9,
        user_agent_custom="ComboScoped/1.0",
        header=("X-Env: ci",),
    )

    assert config_dict["rate_limiting"]["requests_per_second"] == 9
    headers = config_dict["fuzzing"]["headers"]
    assert headers["custom_headers"]["User-Agent"] == "ComboScoped/1.0"
    assert headers["custom_headers"]["X-Env"] == "ci"


# ---------------------------------------------------------------------------
# 36.6 — an empty determined scope performs no scan ("nothing to scan")
# ---------------------------------------------------------------------------


def test_empty_scope_performs_no_scan_and_reports_nothing_to_scan():
    """An empty selected set runs no scan and reports nothing to scan (36.6)."""
    messages = []
    logger = MagicMock()

    with patch.object(apileaks, "run_enhanced_apileak") as run_scan:
        with patch.object(apileaks.click, "echo", lambda msg, *a, **k: messages.append(msg)):
            result = _run_scoped_owasp_scan(
                [],
                target=TARGET,
                rate_limit=None,
                user_agent_random=False,
                user_agent_custom=None,
                user_agent_file=None,
                jwt=None,
                response=None,
                output=None,
                logger=logger,
            )

    assert result is None
    run_scan.assert_not_called()
    assert any("nothing to scan" in str(m).lower() for m in messages)


def test_cli_empty_scope_reports_nothing_to_scan(tmp_path):
    """``dir --scan-scope`` with no matching records reports nothing to scan (36.6)."""
    # Session has only a 2xx record, so a 5xx scope matches nothing.
    session_path = _build_session_file(tmp_path, [_record(200, f"{TARGET}/ok")])

    runner = CliRunner()
    with patch.object(apileaks, "run_enhanced_apileak") as run_scan:
        result = runner.invoke(
            cli,
            [
                "--no-banner",
                "dir",
                "--target",
                TARGET,
                "--load-session",
                session_path,
                "--scan-scope",
                "5xx",
            ],
        )

    assert result.exit_code == 0, result.output
    assert "nothing to scan" in result.output.lower()
    run_scan.assert_not_called()


# ---------------------------------------------------------------------------
# 36.7 — an unrecognized --scan-scope token errors with no scan
# ---------------------------------------------------------------------------


def test_select_scope_records_rejects_unknown_token_naming_value():
    """An unrecognized token raises ScanScopeError naming the value (36.7)."""
    with pytest.raises(ScanScopeError) as excinfo:
        select_scope_records(_mixed_records(), "bogus")

    assert "bogus" in str(excinfo.value)


def test_cli_invalid_scan_scope_errors_with_no_scan(tmp_path):
    """An invalid ``--scan-scope`` token errors before any discovery or scan (36.7)."""
    session_path = _build_session_file(tmp_path, _mixed_records())

    runner = CliRunner()
    with patch.object(apileaks, "run_enhanced_apileak") as run_scan:
        with patch.object(apileaks, "_run_scoped_owasp_scan") as scoped:
            result = runner.invoke(
                cli,
                [
                    "--no-banner",
                    "dir",
                    "--target",
                    TARGET,
                    "--load-session",
                    session_path,
                    "--scan-scope",
                    "not-a-class",
                ],
            )

    assert result.exit_code != 0
    # The offending value is named in the error output.
    assert "not-a-class" in result.output
    run_scan.assert_not_called()
    scoped.assert_not_called()
