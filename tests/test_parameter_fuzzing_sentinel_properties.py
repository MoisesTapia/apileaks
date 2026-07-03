"""Property-based tests for the parameter-fuzzing sentinel generator.

# Feature: parameter-fuzzing, Property 2: Sentinel uniqueness and format

Property 2 (from design.md / tasks.md task 5.2):
    FOR ALL sets of candidate parameter names fuzzed within a single run, every
    sentinel produced by ``ParameterFuzzer._make_sentinel`` SHALL be at least 16
    alphanumeric characters and SHALL be pairwise distinct across all candidates
    in that run.

The test drives ``ParameterFuzzer._make_sentinel`` directly. The fuzzer is
constructed against the offline stub ``HTTPRequestEngine`` from task 1.1
(:mod:`tests.support.http_stub`) so the test runs fully offline with no real
network access -- although ``_make_sentinel`` itself issues no requests, wiring
the stub keeps the fuzzer construction identical to the rest of the suite.

Input model
    Each example is a set of distinct candidate parameter names (mirroring a
    real, de-duplicated wordlist). Every name is passed once to
    ``_make_sentinel`` within a single fuzzer instance (one run), and the
    returned sentinels are collected for inspection. ``min_size=1`` guarantees
    at least one sentinel is produced.

Oracles
    * format: every sentinel is non-empty, consists solely of ASCII letters and
      digits, and is at least 16 characters long (R3.1 -- the implementation
      draws ``SENTINEL_LEN`` = 20 chars, comfortably above the >= 16 floor).
    * uniqueness: the collected sentinels are pairwise distinct, i.e. the number
      of unique sentinels equals the number of candidates fuzzed in the run.

**Validates: Requirements 3.1**
"""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from core.config import FuzzingConfig
from modules.fuzzing.orchestrator import ParameterFuzzer, SENTINEL_LEN
from tests.support.http_stub import HTTPRequestEngineStub


# Minimum sentinel length mandated by R3.1. The implementation uses
# SENTINEL_LEN = 20, which must never dip below this floor.
_MIN_SENTINEL_LEN = 16

# Candidate parameter names: start with a letter, then letters/digits/underscore
# -- the same shape used by the core-wiring property test and representative of
# real wordlist entries. Uniqueness across the set mirrors a de-duplicated run.
_param_name = st.from_regex(r"[A-Za-z][A-Za-z0-9_]{0,15}", fullmatch=True)

# A run's candidate set: a set of distinct parameter names, always non-empty so
# at least one sentinel is generated.
_candidate_name_sets = st.sets(_param_name, min_size=1, max_size=32)


def _make_fuzzer() -> ParameterFuzzer:
    """Construct a ParameterFuzzer wired to the offline stub engine."""
    stub = HTTPRequestEngineStub()
    return ParameterFuzzer(stub, FuzzingConfig())


@given(param_names=_candidate_name_sets)
@settings(max_examples=50, deadline=None)
def test_sentinels_are_long_alphanumeric_and_pairwise_distinct(param_names):
    """Sentinel uniqueness and format across all candidates in a run.

    # Feature: parameter-fuzzing, Property 2: Sentinel uniqueness and format
    **Validates: Requirements 3.1**
    """
    fuzzer = _make_fuzzer()

    sentinels = [fuzzer._make_sentinel(name) for name in param_names]

    # Format: every sentinel is >= 16 chars and strictly alphanumeric (R3.1).
    for sentinel in sentinels:
        assert isinstance(sentinel, str)
        assert len(sentinel) >= _MIN_SENTINEL_LEN, (
            f"sentinel {sentinel!r} shorter than {_MIN_SENTINEL_LEN} chars"
        )
        assert sentinel.isalnum(), f"sentinel {sentinel!r} is not alphanumeric"
        assert sentinel.isascii(), f"sentinel {sentinel!r} is not ASCII"

    # Uniqueness: sentinels are pairwise distinct across all candidates in the
    # run -- one distinct sentinel per fuzzed candidate (R3.1).
    assert len(set(sentinels)) == len(sentinels), (
        f"sentinels are not pairwise distinct: {sentinels}"
    )


def test_sentinel_length_constant_meets_floor():
    """The configured sentinel length honours the R3.1 >= 16 floor."""
    assert SENTINEL_LEN >= _MIN_SENTINEL_LEN


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
