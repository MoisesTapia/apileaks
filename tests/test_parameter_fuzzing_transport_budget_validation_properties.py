"""Property-based test for the ``par`` transport/budget option validation.

# Feature: parameter-fuzzing, Property 9: Invalid transport/budget values are rejected before any request

Property 9 (from design.md / tasks.md task 11.8):
    FOR ANY numeric option value in an invalid range -- ``--timeout`` <= 0,
    ``--retries`` < 0, ``--concurrency`` < 1, or ``--max-requests`` < 1 -- the
    ``par`` command SHALL fail with a descriptive validation error naming the
    offending option and its value and SHALL issue ZERO HTTP requests.

The test drives the real ``par`` Click command through ``click.testing.CliRunner``
so the genuine ``_validate_timeout`` / ``_validate_retries`` /
``_validate_concurrency`` / ``_validate_max_requests`` callbacks run during
parameter processing. Because those callbacks raise ``click.BadParameter`` before
the command body executes, the ``HTTPRequestEngine`` is never constructed and no
request is issued.

To make "zero HTTP requests" an observable, checked fact (not merely an
inference), the single ``HTTPRequestEngine`` construction point is patched with a
recording offline stub built on the task-1.1 harness
(:mod:`tests.support.http_stub`). Every request any engine instance issues is
appended to a shared module-level ledger; the test asserts that ledger stays
empty. The run is therefore fully offline and deterministic.

**Validates: Requirements 8.5, 11.4**
"""

from __future__ import annotations

from unittest import mock

import apileaks
import utils.http_client as hc
from click.testing import CliRunner
from hypothesis import given, settings, strategies as st

from tests.support.http_stub import HTTPRequestEngineStub, ScriptedResponse


TARGET = "https://api.example.test/resource"

# Shared ledger of every request issued through any patched engine instance.
# The whole point of Property 9 is that this stays empty for invalid input.
_ISSUED_REQUESTS: list = []


class _RecordingOfflineEngine(HTTPRequestEngineStub):
    """Offline ``HTTPRequestEngine`` stand-in that records into a shared ledger.

    Any request issued (there should be none for invalid input) is appended to
    the module-level ``_ISSUED_REQUESTS`` list so the test can assert a hard
    zero-request guarantee across every engine instance.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(default=ScriptedResponse(status_code=200, body={"ok": True}))

    async def request(self, method, url, **kwargs):  # type: ignore[override]
        _ISSUED_REQUESTS.append((str(method).upper(), url))
        return await super().request(method, url, **kwargs)


def _combined_output(result) -> str:
    """Return stdout + stderr from a CliRunner result, robust to separation."""
    parts = []
    for attr in ("stdout", "stderr"):
        try:
            text = getattr(result, attr)
        except ValueError:
            continue
        if text:
            parts.append(text)
    if not parts and result.output:
        parts.append(result.output)
    return "".join(parts)


# ---------------------------------------------------------------------------
# Generators: one invalid numeric value per transport/budget option.
# Each returns (option_flag, arg_string, expected_value_substring).
# ---------------------------------------------------------------------------
@st.composite
def _invalid_transport_budget_option(draw):
    kind = draw(st.sampled_from(["timeout", "retries", "concurrency", "max_requests"]))

    if kind == "timeout":
        # Request_Timeout must be > 0, so any value <= 0 is invalid (R8.5).
        value = draw(
            st.floats(min_value=-1_000_000.0, max_value=0.0,
                      allow_nan=False, allow_infinity=False)
        )
        arg = repr(value)
        expected_value = str(float(arg))
        return "--timeout", arg, expected_value

    if kind == "retries":
        # Retry_Limit must be >= 0, so any negative integer is invalid (R8.5).
        value = draw(st.integers(min_value=-1_000_000, max_value=-1))
        return "--retries", str(value), str(value)

    if kind == "concurrency":
        # Concurrency must be >= 1, so any value < 1 is invalid (R8.5).
        value = draw(st.integers(min_value=-1_000_000, max_value=0))
        return "--concurrency", str(value), str(value)

    # max_requests: Request_Budget must be an integer >= 1 (R11.4).
    value = draw(st.integers(min_value=-1_000_000, max_value=0))
    return "--max-requests", str(value), str(value)


@given(case=_invalid_transport_budget_option())
@settings(max_examples=200, deadline=None)
def test_invalid_transport_budget_values_rejected_before_any_request(case):
    """Invalid transport/budget values fail naming the option and issue no request.

    # Feature: parameter-fuzzing, Property 9: Invalid transport/budget values are rejected before any request
    **Validates: Requirements 8.5, 11.4**

    For each of ``--timeout`` <= 0, ``--retries`` < 0, ``--concurrency`` < 1, and
    ``--max-requests`` < 1, invoking ``par`` fails (non-zero exit) with a
    validation error that names the offending option AND its invalid value, and
    the shared request ledger stays empty -- proving the command stopped before
    issuing any HTTP request.
    """
    option_flag, arg, expected_value = case

    # Patch the single engine construction point and clear the shared ledger so
    # any request issued by any engine instance would be observed. A context
    # manager is used (not the monkeypatch fixture) so the patch is applied and
    # reverted for every Hypothesis-generated input.
    _ISSUED_REQUESTS.clear()

    runner = CliRunner()
    with mock.patch.object(hc, "HTTPRequestEngine", _RecordingOfflineEngine):
        result = runner.invoke(
            apileaks.cli,
            ["--no-banner", "par", "--target", TARGET, option_flag, arg],
        )

    output = _combined_output(result)

    # The command must fail (parameter validation error), not run to success.
    assert result.exit_code != 0, (result.exit_code, output)

    # The error names the offending option and its invalid value (R8.5 / R11.4).
    assert option_flag in output, (
        f"error did not name the offending option {option_flag!r}: {output!r}"
    )
    assert expected_value in output, (
        f"error did not name the invalid value {expected_value!r}: {output!r}"
    )

    # ZERO HTTP requests were issued: the run stopped before any request (R8.5 / R11.4).
    assert _ISSUED_REQUESTS == [], (
        f"expected zero HTTP requests for invalid {option_flag}={arg!r}, "
        f"but observed: {_ISSUED_REQUESTS!r}"
    )


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
