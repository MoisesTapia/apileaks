"""Property-based tests for injection-point selection in ``ParameterFuzzer``.

# Feature: parameter-fuzzing, Property 7: Injection points follow selected methods

Property 7 (from design.md / tasks.md task 7.2):
    FOR ALL non-empty sets of supported HTTP methods
    (subset of ``{GET, POST, PUT, PATCH, DELETE}``), the fuzzer SHALL:

      * fuzz **query** parameters if and only if the set contains a
        query-carrying method (``GET`` or ``DELETE``); and
      * fuzz **body** parameters if and only if the set contains a
        body-carrying method (``POST``, ``PUT``, or ``PATCH``); and
      * issue **no request** for a disabled injection point.

The test drives the real :class:`~modules.fuzzing.orchestrator.ParameterFuzzer`
fully offline against the shared task-1.1 stub
(:mod:`tests.support.http_stub`); no real network access occurs.

Isolating the injection-point decision
    ``fuzz_parameters`` gates each injection point on *both* the derived
    injection points (``_injection_points()``, which reads
    ``config.parameters.methods``) *and* the individual ``endpoint.method``.
    To isolate the ``methods`` -> injection-point mapping under test from the
    per-endpoint method gate, the run is given two suitable endpoints -- one
    query-carrying (``GET``) and one body-carrying (``POST``). That way, whenever
    the selected methods enable an injection point, a matching endpoint is always
    available to exercise it, so the observed query/body request activity depends
    solely on the selected-methods -> injection-point mapping.

Request classification (via the stub's recorded requests)
    * a **query** request carries non-empty query ``params``;
    * a **body** request carries a ``json`` body or a ``data`` body;
    * a **baseline** request carries neither.

    Asserting on the stub's recorded requests directly verifies the
    "no request SHALL be issued for a disabled injection point" clause.

**Validates: Requirements 6.2, 6.3**
"""

from __future__ import annotations

import asyncio
import os
import tempfile

import pytest
from hypothesis import given, settings, strategies as st

from core.config import (
    EndpointFuzzingConfig,
    FuzzingConfig,
    HeaderFuzzingConfig,
    ParameterFuzzingConfig,
)
from modules.fuzzing.orchestrator import Endpoint, ParameterFuzzer
from tests.support.http_stub import HTTPRequestEngineStub, ScriptedResponse


TARGET = "https://api.example.test"

SUPPORTED_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]
QUERY_METHODS = {"GET", "DELETE"}
BODY_METHODS = {"POST", "PUT", "PATCH"}

# A non-empty subset of the supported HTTP methods.
_method_sets = st.sets(st.sampled_from(SUPPORTED_METHODS), min_size=1)


@pytest.fixture(scope="module")
def wordlist_path():
    """A small candidate wordlist shared across all generated examples."""
    handle = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    )
    handle.write("alpha\nbeta\ngamma\n")
    handle.close()
    yield handle.name
    os.unlink(handle.name)


def _make_config(methods, wordlist_path: str) -> FuzzingConfig:
    """Build a FuzzingConfig whose injection points derive from ``methods``.

    Boundary testing is disabled so the only requests issued are the baseline
    and the per-candidate query/body injections, keeping the request-activity
    classification unambiguous.
    """
    return FuzzingConfig(
        endpoints=EndpointFuzzingConfig(enabled=False),
        parameters=ParameterFuzzingConfig(
            enabled=True,
            query_wordlist=wordlist_path,
            body_wordlist=wordlist_path,
            boundary_testing=False,
            methods=sorted(methods),
        ),
        headers=HeaderFuzzingConfig(enabled=False),
    )


def _suitable_endpoints():
    """One query-carrying (GET) and one body-carrying (POST) 2xx endpoint.

    Both are VALID (``status_code=200``) so ``fuzz_parameters`` treats them as
    suitable; providing both ensures the per-endpoint method gate never masks an
    injection point that the selected methods enabled.
    """
    return [
        Endpoint(url=TARGET, method="GET", status_code=200,
                 response_size=0, response_time=0.01, endpoint_type="parameter_target"),
        Endpoint(url=TARGET, method="POST", status_code=200,
                 response_size=0, response_time=0.01, endpoint_type="parameter_target"),
    ]


def _run(methods, wordlist_path: str) -> HTTPRequestEngineStub:
    """Run parameter fuzzing offline for ``methods`` and return the stub."""
    stub = HTTPRequestEngineStub(
        default=ScriptedResponse(status_code=200, body={"ok": True})
    )
    fuzzer = ParameterFuzzer(stub, _make_config(methods, wordlist_path))
    asyncio.run(fuzzer.fuzz_parameters(_suitable_endpoints()))
    return stub


@given(methods=_method_sets)
@settings(max_examples=150, deadline=None)
def test_injection_points_follow_selected_methods(methods, wordlist_path):
    """Injection points follow selected methods.

    # Feature: parameter-fuzzing, Property 7: Injection points follow selected methods
    **Validates: Requirements 6.2, 6.3**
    """
    stub = _run(methods, wordlist_path)

    expect_query = bool(methods & QUERY_METHODS)
    expect_body = bool(methods & BODY_METHODS)

    # Classify every recorded request by its injection point.
    query_requests = [r for r in stub.requests if r.params]
    body_requests = [
        r for r in stub.requests if r.json is not None or r.data is not None
    ]

    # R6.2/R6.3: query fuzzing happens iff a query-carrying method was selected.
    assert bool(query_requests) == expect_query, (
        f"methods={sorted(methods)}: expected query fuzzing={expect_query}, "
        f"observed {len(query_requests)} query requests"
    )
    # R6.2/R6.3: body fuzzing happens iff a body-carrying method was selected.
    assert bool(body_requests) == expect_body, (
        f"methods={sorted(methods)}: expected body fuzzing={expect_body}, "
        f"observed {len(body_requests)} body requests"
    )

    # No request SHALL be issued for a disabled injection point.
    if not expect_query:
        assert query_requests == [], (
            f"methods={sorted(methods)}: query injection point is disabled but "
            f"{len(query_requests)} query requests were issued"
        )
    if not expect_body:
        assert body_requests == [], (
            f"methods={sorted(methods)}: body injection point is disabled but "
            f"{len(body_requests)} body requests were issued"
        )

    # A non-empty method set always enables at least one injection point, so the
    # run must have issued at least one injecting request.
    assert query_requests or body_requests


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
