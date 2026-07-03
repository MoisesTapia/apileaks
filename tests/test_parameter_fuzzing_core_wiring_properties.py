"""Property-based tests for the parameter-fuzzing core wiring fix.

# Feature: parameter-fuzzing, Property 1: Parameter fuzzing wires up and tests candidates without discovery

Property 1 (from design.md / tasks.md task 2.3):
    FOR ALL parameter-only (``par``) runs configured with
    ``fuzzing.parameters.enabled=true`` and ``fuzzing.endpoints.enabled=false``,
    driving the engine's traditional fuzzing phase against the offline stub
    ``HTTPRequestEngine``:

      * the run builds the ``ParameterFuzzer`` (via the lazily constructed
        ``FuzzingOrchestrator``),
      * seeds exactly one synthetic ``parameter_target`` ``Endpoint`` into
        ``discovered_endpoints`` (never triggering endpoint discovery),
      * reports ``parameters_tested >= 1`` (every candidate from the wordlist is
        exercised), and
      * reports one ``PARAMETER_FOUND`` finding for every candidate parameter
        that produced a ``Response_Difference`` -- and only those.

The test runs fully offline against the shared task-1.1 stub
(:mod:`tests.support.http_stub`); no real network access occurs. The stub is
substituted at the single ``HTTPRequestEngine`` construction point that
``APILeakCore._ensure_fuzzing_orchestrator`` imports function-locally from
``utils.http_client``.

Difference model
    A deterministic responder scripts the offline target so that a chosen subset
    of candidate parameters produce a ``Response_Difference`` and the rest do
    not:

      * the baseline request (no query params) returns ``200`` with a fixed JSON
        body;
      * a candidate marked "diff" returns a different status code (``500``),
        which ``ParameterFuzzer._has_response_difference`` flags as a difference;
      * a candidate marked "no-diff" returns a response byte-identical to the
        baseline (same status, body, content-type, timing), which is flagged as
        no difference.

    Consequently the number and identity of ``PARAMETER_FOUND`` findings is
    exactly the set of "diff" candidates, giving a precise oracle for the
    "a finding for every candidate that produced a difference" clause.

**Validates: Requirements 1.1, 1.2, 1.3, 1.4, 13.1, 13.3**
"""

from __future__ import annotations

import asyncio
import os
import re
import tempfile
from typing import Dict, Tuple
from unittest.mock import patch

from hypothesis import given, settings, strategies as st

import utils.http_client as hc
from apileaks import create_default_config
from core.config import ConfigurationManager
from core.engine import APILeakCore
from modules.fuzzing.orchestrator import ParameterFuzzer
from tests.support.http_stub import HTTPRequestEngineStub, RecordedRequest, ScriptedResponse


TARGET = "https://api.example.test"

# A fixed baseline body shared by the baseline request and every "no-diff"
# candidate response so those requests are byte-identical to the baseline.
_BASELINE_BODY = {"ok": True}

# Extracts the candidate parameter name from a PARAMETER_FOUND finding's
# evidence string ("Query parameter '<name>' discovered - ...").
_EVIDENCE_NAME_RE = re.compile(r"Query parameter '(?P<name>[^']*)' discovered")

# Candidate parameter names: start with a letter, then letters/digits/underscore.
# This keeps them valid, whitespace-free wordlist entries that never start with
# '#', so every generated name survives wordlist loading intact.
_param_name = st.from_regex(r"[A-Za-z][A-Za-z0-9_]{0,9}", fullmatch=True)

# A run's candidate set: name -> "does this candidate produce a difference?".
# min_size=1 guarantees parameters_tested >= 1; dict keys are unique so the
# wordlist has no duplicates.
_candidate_maps = st.dictionaries(
    keys=_param_name, values=st.booleans(), min_size=1, max_size=8
)


def _make_responder(diff_map: Dict[str, bool]):
    """Build a deterministic responder for ``diff_map``.

    The baseline request (no params) and every "no-diff" candidate return a
    byte-identical ``200`` JSON response; a "diff" candidate returns a ``500``
    so ``_has_response_difference`` flags exactly the diff candidates.
    """

    def responder(recorded: RecordedRequest) -> ScriptedResponse:
        if not recorded.params:
            # Baseline request: no query parameter injected.
            return ScriptedResponse(status_code=200, body=dict(_BASELINE_BODY))
        # A query test injects exactly one candidate parameter.
        name = next(iter(recorded.params.keys()))
        if diff_map.get(name):
            return ScriptedResponse(status_code=500, body=dict(_BASELINE_BODY))
        return ScriptedResponse(status_code=200, body=dict(_BASELINE_BODY))

    return responder


def _write_wordlist(names) -> str:
    """Write candidate parameter names to a temp wordlist and return its path."""
    handle = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    )
    handle.write("\n".join(names) + "\n")
    handle.close()
    return handle.name


def _run_par_fuzzing(diff_map: Dict[str, bool]) -> Tuple[APILeakCore, HTTPRequestEngineStub, dict]:
    """Drive the engine's parameter-fuzzing phase fully offline.

    Builds a real ``par`` configuration (endpoints disabled, parameters enabled)
    over a wordlist of the ``diff_map`` candidates, substitutes the offline stub
    for the single ``HTTPRequestEngine`` construction point, and executes the
    traditional fuzzing phase. Returns the core, the stub, and the phase result.
    """
    wordlist_path = _write_wordlist(list(diff_map.keys()))
    stub = HTTPRequestEngineStub(responder=_make_responder(diff_map))

    try:
        config_dict = create_default_config(TARGET, wordlist_path, "par")
        apileak_config = ConfigurationManager().load_config_from_dict(config_dict)

        core = APILeakCore(apileak_config)
        # The fuzzing phase reads the target off the instance (set by run_scan).
        core.target = TARGET

        # Substitute the offline stub at the single construction point
        # _ensure_fuzzing_orchestrator imports function-locally.
        with patch.object(hc, "HTTPRequestEngine", lambda *a, **k: stub):
            result = asyncio.run(core._execute_fuzzing_phase())
    finally:
        os.unlink(wordlist_path)

    return core, stub, result


@given(diff_map=_candidate_maps)
@settings(max_examples=50, deadline=None)
def test_parameter_fuzzing_wires_up_without_discovery(diff_map):
    """Parameter fuzzing wires up and tests candidates without discovery.

    # Feature: parameter-fuzzing, Property 1: Parameter fuzzing wires up and tests candidates without discovery
    **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 13.1, 13.3**
    """
    core, stub, result = _run_par_fuzzing(diff_map)

    candidate_count = len(diff_map)
    expected_diff = {name for name, is_diff in diff_map.items() if is_diff}

    # R1.1 / R13.1: the fuzzing orchestrator and its ParameterFuzzer are built
    # lazily for a parameter-only run (no discovery phase required).
    assert hasattr(core, "fuzzing_orchestrator"), "fuzzing orchestrator was not built"
    assert isinstance(core.fuzzing_orchestrator.parameter_fuzzer, ParameterFuzzer)

    # R1.2: exactly one synthetic parameter_target endpoint is seeded, and no
    # endpoint discovery ran (the stub only ever saw baseline + candidate tests,
    # never wordlist discovery probes).
    assert len(core.discovered_endpoints) == 1, (
        f"expected exactly one seeded endpoint, got {len(core.discovered_endpoints)}"
    )
    seeded = core.discovered_endpoints[0]
    assert seeded.endpoint_type == "parameter_target"
    assert seeded.discovered_via == "target"
    assert seeded.url == TARGET
    assert seeded.method == "GET"

    # R1.3: every candidate parameter from the wordlist is tested.
    assert result["parameters_tested"] == candidate_count
    assert result["parameters_tested"] >= 1

    # R1.4 / R13.3: exactly one PARAMETER_FOUND finding per candidate that
    # produced a Response_Difference -- and only those candidates.
    param_findings = [f for f in result["findings"] if f.category == "PARAMETER_FOUND"]
    reported_names = set()
    for finding in param_findings:
        match = _EVIDENCE_NAME_RE.search(finding.evidence)
        assert match is not None, f"unexpected finding evidence: {finding.evidence!r}"
        reported_names.add(match.group("name"))

    assert reported_names == expected_diff, (
        f"reported findings {sorted(reported_names)} != "
        f"difference-producing candidates {sorted(expected_diff)}"
    )
    assert len(param_findings) == len(expected_diff), (
        f"expected {len(expected_diff)} findings, got {len(param_findings)}"
    )

    # Offline guarantee: at least the baseline plus one request per candidate
    # flowed through the stub, and nothing touched the real network.
    assert stub.call_count >= candidate_count + 1


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
