"""
Property-Based Tests for Batch-Scan-Scope Exactness

**Feature: owasp-complete-purple-teaming-cicd, Property 20: Batch-scan-scope
exactness**

Property 20 (from design.md):
    FOR ALL non-empty ``Batch_Scan_Scope`` selections, the set of endpoints
    passed to (and consumed by) the OWASP scan equals the set of selected
    ``DiscoveryResult`` records -- same membership, containing no endpoint that
    was not selected and omitting no endpoint that was. Verified by seeding the
    engine with a generated record set and asserting
    ``set(engine.get_discovered_endpoints()) == set(selected)`` keyed by
    ``(url, method)``.

These tests use Hypothesis to generate non-empty sets of ``DiscoveryResult``
records spanning all four status classes (2xx/3xx/4xx/5xx and beyond), varied
HTTP methods, and unicode URLs. Each generated set is seeded into the engine's
discovery phase via ``APILeakCore._execute_discovery_phase(target,
scope_endpoints=...)`` (the same seam ``run_scan(scope_endpoints=...)`` stashes
and consumes), which skips wordlist discovery entirely and performs no network
I/O. We then assert the engine's discovered endpoints equal exactly the seeded
records keyed by ``(url, method)``.

The seeding seam is deterministic and offline: it reconstructs synthetic
``Endpoint`` objects directly from the selected records, so no HTTP client,
mock, or fake transport is required.
"""

import asyncio

import pytest
from hypothesis import given, settings, strategies as st
from hypothesis.strategies import composite

from core.engine import APILeakCore
from core.config import (
    APILeakConfig,
    TargetConfig,
    FuzzingConfig,
    EndpointFuzzingConfig,
    ParameterFuzzingConfig,
    HeaderFuzzingConfig,
    OWASPConfig,
    AuthConfig,
    RateLimitConfig,
    ReportConfig,
)
from utils.discovery_session import DiscoveryResult


TARGET = "https://api.example.com"

# Varied HTTP methods, including a couple of less common ones.
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]

# EndpointStatus string values projected into DiscoveryResult.endpoint_status.
ENDPOINT_STATUSES = [
    "valid",
    "auth_required",
    "redirect",
    "not_found",
    "server_error",
    "unknown",
]


def _build_engine() -> APILeakCore:
    """Construct a minimal, offline ``APILeakCore`` for scope seeding.

    The configuration is intentionally light: the seeding path of
    ``_execute_discovery_phase`` never touches the HTTP client, fuzzing
    orchestrator, or network, so no wordlist or transport setup is needed.
    """
    config = APILeakConfig(
        target=TargetConfig(base_url=TARGET),
        fuzzing=FuzzingConfig(
            endpoints=EndpointFuzzingConfig(enabled=True),
            parameters=ParameterFuzzingConfig(enabled=False),
            headers=HeaderFuzzingConfig(enabled=False),
            recursive=False,
            max_depth=1,
        ),
        owasp_testing=OWASPConfig(enabled_modules=[]),
        authentication=AuthConfig(),
        rate_limiting=RateLimitConfig(requests_per_second=2, burst_size=5),
        reporting=ReportConfig(),
    )
    return APILeakCore(config)


@composite
def unique_record_set_strategy(draw):
    """Generate a non-empty list of DiscoveryResult records with unique keys.

    Records are deduplicated by ``(url, method)`` so the seeded set has a
    well-defined cardinality: every selected record maps to a distinct
    discovered endpoint. Status codes deliberately span 1xx-5xx and beyond, URLs
    draw from the full unicode space (including commas/newlines), and methods
    vary across common and uncommon verbs.
    """
    # Generate (url, method) keys first and dedup, then attach status/endpoint
    # status. min_size=1 enforces the "non-empty selection" precondition of the
    # property.
    keys = draw(
        st.lists(
            st.tuples(
                st.text(min_size=0, max_size=80),
                st.sampled_from(HTTP_METHODS),
            ),
            min_size=1,
            max_size=30,
            unique=True,
        )
    )

    records = []
    for url, method in keys:
        status_code = draw(st.integers(min_value=0, max_value=799))
        endpoint_status = draw(st.sampled_from(ENDPOINT_STATUSES))
        records.append(
            DiscoveryResult(
                url=url,
                method=method,
                status_code=status_code,
                endpoint_status=endpoint_status,
            )
        )
    return records


def _seed_and_get_keys(records):
    """Seed the discovery phase with ``records`` and return discovered keys.

    Drives ``_execute_discovery_phase`` (the offline seeding seam) synchronously
    via ``asyncio.run`` and projects the resulting discovered endpoints to their
    ``(url, method)`` keys.
    """
    engine = _build_engine()
    asyncio.run(engine._execute_discovery_phase(TARGET, scope_endpoints=records))
    return {(e.url, e.method) for e in engine.get_discovered_endpoints()}


@given(records=unique_record_set_strategy())
@settings(max_examples=200, deadline=5000)
def test_batch_scan_scope_exactness(records):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 20: Batch-scan-scope
    exactness**
    **Validates: Requirements 36.8, 36.3**

    FOR ALL non-empty Batch_Scan_Scope selections, seeding the engine yields
    discovered endpoints whose ``(url, method)`` set equals exactly the selected
    records' ``(url, method)`` set -- no endpoint that was not selected, and none
    omitted.
    """
    selected_keys = {(r.url, r.method) for r in records}
    discovered_keys = _seed_and_get_keys(records)

    # Same membership: no extra endpoint, none omitted.
    assert discovered_keys == selected_keys
    # No endpoint that was not selected.
    assert discovered_keys - selected_keys == set()
    # No selected endpoint omitted.
    assert selected_keys - discovered_keys == set()


@given(records=unique_record_set_strategy())
@settings(max_examples=200, deadline=5000)
def test_batch_scan_scope_preserves_cardinality(records):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 20: Batch-scan-scope
    exactness (cardinality)**
    **Validates: Requirements 36.8, 36.3**

    With unique ``(url, method)`` keys, the number of discovered endpoints equals
    the number of selected records -- the seeded set neither grows nor shrinks.
    """
    engine = _build_engine()
    asyncio.run(engine._execute_discovery_phase(TARGET, scope_endpoints=records))
    discovered = engine.get_discovered_endpoints()

    assert len(discovered) == len(records)


def test_single_record_scope_is_exact():
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 20: Batch-scan-scope
    exactness (single record)**
    **Validates: Requirements 36.8, 36.3**

    A single-record scope seeds exactly that one endpoint by ``(url, method)``.
    """
    records = [
        DiscoveryResult(
            url=f"{TARGET}/only",
            method="GET",
            status_code=200,
            endpoint_status="valid",
        )
    ]

    discovered_keys = _seed_and_get_keys(records)

    assert discovered_keys == {(f"{TARGET}/only", "GET")}


def test_same_url_different_methods_are_distinct():
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 20: Batch-scan-scope
    exactness (method-keyed)**
    **Validates: Requirements 36.8, 36.3**

    Two records sharing a URL but differing in method are seeded as two distinct
    endpoints keyed by ``(url, method)``.
    """
    records = [
        DiscoveryResult(url=f"{TARGET}/r", method="GET", status_code=200, endpoint_status="valid"),
        DiscoveryResult(url=f"{TARGET}/r", method="POST", status_code=201, endpoint_status="valid"),
    ]

    discovered_keys = _seed_and_get_keys(records)

    assert discovered_keys == {(f"{TARGET}/r", "GET"), (f"{TARGET}/r", "POST")}


def test_mixed_status_class_scope_seeds_all_records():
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 20: Batch-scan-scope
    exactness (mixed status classes)**
    **Validates: Requirements 36.8, 36.3**

    A scope spanning 2xx/3xx/4xx/5xx seeds every selected record with no
    status-class-based omission.
    """
    records = [
        DiscoveryResult(url=f"{TARGET}/ok", method="GET", status_code=200, endpoint_status="valid"),
        DiscoveryResult(url=f"{TARGET}/moved", method="GET", status_code=301, endpoint_status="redirect"),
        DiscoveryResult(url=f"{TARGET}/secret", method="GET", status_code=401, endpoint_status="auth_required"),
        DiscoveryResult(url=f"{TARGET}/down", method="GET", status_code=503, endpoint_status="server_error"),
    ]

    discovered_keys = _seed_and_get_keys(records)

    assert discovered_keys == {(r.url, r.method) for r in records}
