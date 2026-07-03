"""Regression guard for the disconnected-``par`` defect.

**Feature: parameter-fuzzing, Task 2.4 (regression example test)**

This is a concrete, deterministic *example* test (not a property/Hypothesis
test). It exercises the ``par`` flow end-to-end — a config built for scan_type
``"par"`` driven through the real ``APILeakCore`` engine/orchestrator — against
the offline stub :class:`~tests.support.http_stub.HTTPRequestEngineStub` from
task 1.1, with **no real network access**.

The bug it guards against
    The ``par`` command runs in "parameter-only" mode: it disables endpoint
    discovery (``fuzzing.endpoints.enabled=False``) and enables parameter
    fuzzing (``fuzzing.parameters.enabled=True``). Originally the
    ``FuzzingOrchestrator`` and the synthetic parameter-target ``Endpoint`` were
    constructed *only* inside the discovery phase. Because ``par`` skips
    discovery, neither was ever built, so ``_execute_fuzzing_phase`` bailed out
    early and reported ``parameters_tested = 0`` — the ``par`` command tested
    nothing.

    Tasks 2.1/2.2 fixed this by extracting ``_ensure_fuzzing_orchestrator()``
    and ``_prepare_parameter_target(target)`` and invoking them from
    ``_execute_fuzzing_phase``.

The guard
    After a full ``par`` run, ``parameters_tested`` MUST be ``>= 1``. If a future
    change re-disconnects ``par`` (the orchestrator is never constructed or the
    synthetic target is never seeded), ``parameters_tested`` collapses back to
    ``0`` and this test fails — exactly the regression we want to catch.

_Requirements: 13.1, 13.3_
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from tests.support.http_stub import (
    HTTPRequestEngineStub,
    RecordedRequest,
    ScriptedResponse,
)


TARGET = "https://api.example.test"


# ---------------------------------------------------------------------------
# Offline HTTP layer (reuses the task 1.1 stub)
# ---------------------------------------------------------------------------

def _reachable_responder(recorded: RecordedRequest) -> ScriptedResponse:
    """Deterministic offline responder: the target is always reachable.

    Every request (baseline and each candidate parameter) gets a stable 200
    JSON response, so the run is fully reproducible and the synthetic
    parameter target is treated as a live, reachable endpoint.
    """
    return ScriptedResponse(status_code=200, body={"ok": True})


class _OfflineHTTPRequestEngine(HTTPRequestEngineStub):
    """Drop-in replacement for ``HTTPRequestEngine`` used in this regression.

    Accepts (and ignores) the real engine's constructor arguments so it can be
    substituted at the single ``HTTPRequestEngine(...)`` construction point,
    while returning deterministic scripted responses with no network access.
    """

    def __init__(self, *args, **kwargs):  # noqa: D401 - see class docstring
        super().__init__(responder=_reachable_responder)


@pytest.fixture
def offline_http(monkeypatch):
    """Patch the single ``HTTPRequestEngine`` construction point to the stub.

    ``core.engine`` imports ``HTTPRequestEngine`` function-locally from
    ``utils.http_client`` inside ``_ensure_fuzzing_orchestrator``, so patching
    the attribute on ``utils.http_client`` transparently replaces the engine the
    ``par`` fuzzing phase builds.
    """
    import utils.http_client as hc

    monkeypatch.setattr(hc, "HTTPRequestEngine", _OfflineHTTPRequestEngine)
    return _OfflineHTTPRequestEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_wordlist(tmp_path: Path, entries) -> str:
    wl = tmp_path / "parameters.txt"
    wl.write_text("\n".join(entries) + "\n", encoding="utf-8")
    return str(wl)


def _run_par_offline(tmp_path: Path):
    """Build the real ``par`` command config and run the engine fully offline.

    Mirrors how the CLI wires ``par``: ``create_default_config(..., "par", ...)``
    → ``ConfigurationManager.load_config_from_dict`` → ``APILeakCore.run_scan``.
    Returns the completed ``APILeakCore`` so callers can read statistics.
    """
    from apileaks import create_default_config
    from core.config import ConfigurationManager
    from core.engine import APILeakCore

    wordlist = _write_wordlist(tmp_path, ["id", "debug", "admin"])
    config_dict = create_default_config(TARGET, wordlist, "par")

    # Sanity: this is genuinely the parameter-only ("par") configuration whose
    # disconnected state the guard protects against.
    assert config_dict["fuzzing"]["endpoints"]["enabled"] is False
    assert config_dict["fuzzing"]["parameters"]["enabled"] is True

    apileak_config = ConfigurationManager().load_config_from_dict(config_dict)
    core = APILeakCore(apileak_config)
    asyncio.run(core.run_scan(TARGET))
    return core


def _parameters_tested(core) -> int:
    """Read the reported ``parameters_tested`` count from a completed run."""
    results = core.scan_results
    assert results is not None, "run_scan did not populate scan_results"

    fuzzing_results = getattr(results, "fuzzing_results", None)
    if fuzzing_results is not None and "parameters_tested" in fuzzing_results:
        return fuzzing_results["parameters_tested"]

    # Fall back to the statistics object, which the engine also populates.
    return getattr(results.statistics, "parameters_tested", 0)


# ---------------------------------------------------------------------------
# Regression test
# ---------------------------------------------------------------------------

def test_par_flow_tests_at_least_one_parameter(offline_http, tmp_path):
    """``par`` fuzzes parameters end-to-end: ``parameters_tested >= 1``.

    Regression guard for the disconnected-``par`` defect. This assertion FAILS
    if ``parameters_tested == 0`` — the exact symptom of the original bug where
    the fuzzing orchestrator / synthetic parameter target were never
    constructed for a discovery-disabled ``par`` run.

    _Requirements: 13.1, 13.3_
    """
    core = _run_par_offline(tmp_path)

    parameters_tested = _parameters_tested(core)

    assert parameters_tested >= 1, (
        "par ran but tested zero parameters (parameters_tested == 0): the "
        "fuzzing orchestrator or synthetic parameter target was not wired up "
        "for the discovery-disabled 'par' flow — the disconnected-par bug has "
        "regressed."
    )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
