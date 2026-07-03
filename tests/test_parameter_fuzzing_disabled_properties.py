"""Property-based test for disabled parameter fuzzing.

# Feature: parameter-fuzzing, Property 13: Disabled parameter fuzzing produces no parameter findings

Property 13 (from design.md / tasks.md task 14.1):
    FOR ALL parameter-only (``par``) runs configured with
    ``fuzzing.parameters.enabled=false``, driving the engine's traditional
    fuzzing phase against the offline stub ``HTTPRequestEngine``, the run reports
    exactly zero parameter findings (no ``PARAMETER_FOUND`` records) and tests
    zero parameters -- regardless of what the target would have returned had
    fuzzing been enabled.

The test runs fully offline against the shared task-1.1 stub
(:mod:`tests.support.http_stub`); no real network access occurs. The stub is
substituted at the single ``HTTPRequestEngine`` construction point that
``APILeakCore._ensure_fuzzing_orchestrator`` imports function-locally from
``utils.http_client``.

Strength of the oracle
    The offline responder is deliberately "hostile": every candidate request it
    ever sees returns a ``500`` (a status-code ``Response_Difference`` relative
    to the ``200`` baseline). So if parameter fuzzing were mistakenly to run
    while disabled, every candidate would produce a ``PARAMETER_FOUND`` finding
    and the assertion ``findings == 0`` would fail loudly. Because the feature is
    disabled, the fuzzer is never invoked: no synthetic parameter target is
    seeded, ``parameters_tested`` stays ``0``, and no candidate request is ever
    issued.

**Validates: Requirements 13.6**
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from typing import Tuple
from unittest.mock import patch

from hypothesis import given, settings, strategies as st

import utils.http_client as hc
from apileaks import create_default_config
from core.config import ConfigurationManager
from core.engine import APILeakCore
from tests.support.http_stub import HTTPRequestEngineStub, RecordedRequest, ScriptedResponse


TARGET = "https://api.example.test"

# Candidate parameter names: start with a letter, then letters/digits/underscore.
# Valid, whitespace-free wordlist entries that never start with '#', so every
# generated name survives wordlist loading intact.
_param_name = st.from_regex(r"[A-Za-z][A-Za-z0-9_]{0,9}", fullmatch=True)

# A run's candidate wordlist: a non-empty set of unique names. Even with real
# candidates present, a disabled run must fuzz none of them.
_wordlists = st.lists(_param_name, min_size=1, max_size=8, unique=True)


def _hostile_responder(recorded: RecordedRequest) -> ScriptedResponse:
    """Return a difference-producing response for every candidate request.

    The baseline (no params) returns ``200``; any injected candidate returns
    ``500`` -- a status-code difference. This guarantees that if fuzzing ran at
    all it would report findings, sharpening the "zero findings when disabled"
    oracle.
    """
    if not recorded.params:
        return ScriptedResponse(status_code=200, body={"ok": True})
    return ScriptedResponse(status_code=500, body={"ok": True})


def _write_wordlist(names) -> str:
    """Write candidate parameter names to a temp wordlist and return its path."""
    handle = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    )
    handle.write("\n".join(names) + "\n")
    handle.close()
    return handle.name


def _run_par_fuzzing_disabled(names) -> Tuple[APILeakCore, HTTPRequestEngineStub, dict]:
    """Drive the engine's fuzzing phase with parameter fuzzing disabled.

    Builds a real ``par`` configuration over a wordlist of ``names`` but flips
    ``fuzzing.parameters.enabled`` to ``False``, substitutes the offline stub for
    the single ``HTTPRequestEngine`` construction point, and executes the
    traditional fuzzing phase. Returns the core, the stub, and the phase result.
    """
    wordlist_path = _write_wordlist(list(names))
    stub = HTTPRequestEngineStub(responder=_hostile_responder)

    try:
        config_dict = create_default_config(TARGET, wordlist_path, "par")

        # The ``par`` command enables parameter fuzzing by default; this property
        # is about the disabled case, so flip the switch off explicitly.
        assert config_dict["fuzzing"]["parameters"]["enabled"] is True
        config_dict["fuzzing"]["parameters"]["enabled"] = False

        apileak_config = ConfigurationManager().load_config_from_dict(config_dict)

        core = APILeakCore(apileak_config)
        core.target = TARGET

        with patch.object(hc, "HTTPRequestEngine", lambda *a, **k: stub):
            result = asyncio.run(core._execute_fuzzing_phase())
    finally:
        os.unlink(wordlist_path)

    return core, stub, result


@given(names=_wordlists)
@settings(max_examples=100, deadline=None)
def test_disabled_parameter_fuzzing_produces_no_findings(names):
    """Disabled parameter fuzzing produces no parameter findings.

    # Feature: parameter-fuzzing, Property 13: Disabled parameter fuzzing produces no parameter findings
    **Validates: Requirements 13.6**
    """
    core, stub, result = _run_par_fuzzing_disabled(names)

    # R13.6: zero parameter findings are reported when parameter fuzzing is
    # disabled, no matter how many candidates the wordlist carried.
    param_findings = [f for f in result["findings"] if f.category == "PARAMETER_FOUND"]
    assert param_findings == [], (
        f"expected 0 parameter findings when parameter fuzzing is disabled, "
        f"got {len(param_findings)}"
    )

    # Nothing was tested: parameters_tested stays 0.
    assert result["parameters_tested"] == 0

    # No synthetic parameter target is seeded and no candidate request is issued
    # when the feature is disabled (the hostile responder is never consulted for
    # a candidate, so its 500s can never become findings).
    assert core.discovered_endpoints == []
    assert stub.call_count == 0


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
