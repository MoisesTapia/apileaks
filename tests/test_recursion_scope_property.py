"""
Property-Based Tests for Recursion-Scope Subset

**Feature: owasp-complete-purple-teaming-cicd, Property 18: Recursion-scope subset**

Property 18 (from design.md):
    FOR ALL ``Recursion_Scope`` configurations (any selection of
    ``Status_Code_Class`` values and endpoint types), the set of
    ``Discovery_Result`` records recursed into is a subset of the records
    satisfying BOTH the supplied ``Recursion_Scope`` selections AND the default
    recursion eligibility (status VALID or AUTH_REQUIRED and not file-like and
    not a ``Catch_All_Response`` match). The scope only narrows the
    default-eligible set; it never expands it and never exceeds ``Recursion_Depth``.

These tests drive the real ``EndpointFuzzer._recursive_fuzzing``
(modules/fuzzing/orchestrator.py) against an in-memory fake HTTPRequestEngine
(no network), reusing the ``RecordingClient`` fake and the
``_make_config`` / ``_ep`` / ``_recursed_base_urls`` helpers introduced by the
deterministic unit tests in tests/test_recursion_scope.py (task 39.5) so the
property exercises the exact orchestrator wiring from task 39.3.

**Validates: Requirements 34.9, 34.3, 34.4, 34.5, 34.7**
"""

import asyncio
from urllib.parse import urlparse

from hypothesis import given, settings, strategies as st

from modules.fuzzing.orchestrator import EndpointFuzzer, Endpoint, EndpointStatus
from utils.discovery_scope import RecursionScope, VALID_ENDPOINT_TYPES

# Reuse the fake HTTPRequestEngine and config/endpoint helpers from the task
# 39.5 unit tests for consistency (same fake-client patterns/fixtures).
from tests.test_recursion_scope import (
    RecordingClient,
    _make_config,
    _recursed_base_urls,
)


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

# Status codes spanning 2xx / 3xx / 4xx / 5xx, mapping to the full range of
# EndpointStatus classifications (VALID / REDIRECT / AUTH_REQUIRED / NOT_FOUND /
# ERROR).
_STATUS_CODES = [200, 201, 204, 301, 302, 401, 403, 404, 500, 503]

# User-selectable endpoint types (Requirement 34.2).
_ENDPOINT_TYPES = sorted(VALID_ENDPOINT_TYPES)

# File-like suffixes are excluded from recursion by the default eligibility.
_FILE_EXTS = [None, ".json", ".html", ".xml"]

# The Status_Code_Class tokens a Recursion_Scope may select.
_STATUS_CLASSES = ["2xx", "3xx", "4xx", "5xx"]

# A reserved (status_code, response_size) signature used to mark some endpoints
# as Catch_All_Response matches. The normal response sizes assigned below never
# collide with this size, so only the explicitly-flagged catch-all endpoints
# match the detected signature.
_CATCH_ALL_STATUS = 200
_CATCH_ALL_SIZE = 987654


@st.composite
def _endpoint_specs(draw):
    """Generate a non-empty list of endpoint specifications.

    Each spec is ``(status_code, endpoint_type, file_ext, is_catch_all)``. The
    list spans varied status classes, endpoint types, file-like endpoints, and
    catch-all-matching endpoints.
    """
    return draw(
        st.lists(
            st.tuples(
                st.sampled_from(_STATUS_CODES),
                st.sampled_from(_ENDPOINT_TYPES),
                st.sampled_from(_FILE_EXTS),
                st.booleans(),  # is_catch_all
            ),
            min_size=1,
            max_size=8,
        )
    )


def _build_endpoints(specs):
    """Materialize endpoint specs into unique ``Endpoint`` records.

    Each endpoint gets a unique single-segment path (``/ep{i}`` plus any file
    extension) so recursion depth is recoverable from the request URL. Catch-all
    endpoints are forced to the reserved ``(status, size)`` signature; all other
    endpoints get small, distinct response sizes that never match it.
    """
    endpoints = []
    for i, (status_code, endpoint_type, file_ext, is_catch_all) in enumerate(specs):
        name = f"ep{i}"
        if file_ext:
            name += file_ext
        url = f"http://example.com/{name}"
        if is_catch_all:
            status_code = _CATCH_ALL_STATUS
            response_size = _CATCH_ALL_SIZE
        else:
            # 100..900 range, guaranteed != _CATCH_ALL_SIZE.
            response_size = 100 + i
        endpoints.append(
            Endpoint(
                url=url,
                method="GET",
                status_code=status_code,
                response_size=response_size,
                response_time=0.01,
                endpoint_type=endpoint_type,
            )
        )
    return endpoints


def _scopes():
    """Strategy for ``RecursionScope`` configurations.

    Either dimension may be empty (= unrestricted on that dimension), so this
    covers the fully-unrestricted scope through to both dimensions constrained.
    """
    return st.builds(
        RecursionScope,
        status_classes=st.frozensets(st.sampled_from(_STATUS_CLASSES), max_size=4),
        endpoint_types=st.frozensets(st.sampled_from(_ENDPOINT_TYPES), max_size=5),
    )


def _request_depth(base_endpoints, url: str) -> int:
    """Recursion depth at which a Discovery_Request for ``url`` was issued.

    Every base endpoint has a single-segment path, and each recursion level
    appends exactly one further segment, so the depth is ``segments - 1``.
    """
    path = urlparse(url).path
    segments = [s for s in path.split("/") if s]
    return len(segments) - 1


# ---------------------------------------------------------------------------
# Property 18
# ---------------------------------------------------------------------------

@given(
    specs=_endpoint_specs(),
    scope=_scopes(),
    max_depth=st.integers(min_value=0, max_value=3),
)
@settings(max_examples=120, deadline=None)
def test_recursed_set_is_subset_of_scoped_and_eligible(specs, scope, max_depth):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 18: Recursion-scope
    subset**
    **Validates: Requirements 34.9, 34.3, 34.4, 34.5, 34.7**

    Driving the real ``_recursive_fuzzing`` with an in-memory fake client, the
    set of base records recursion descends into is always a SUBSET of the
    records satisfying BOTH ``scope.admits(e)`` AND the default recursion
    eligibility (VALID/AUTH_REQUIRED, not file-like, not a Catch_All_Response
    match). Recursion never descends deeper than the configured Recursion_Depth.
    """
    endpoints = _build_endpoints(specs)

    # Sub-paths answer 404 (not recursable), so recursion descends exactly one
    # level from each admitted base; the subset relation under test concerns
    # which initial base records are recursed into.
    client = RecordingClient(status_code=404)
    fuzzer = EndpointFuzzer(
        client, _make_config(max_depth=max_depth, recursion_scope=scope)
    )
    # A detected Catch_All_Response signature so flagged endpoints are suppressed
    # (Requirement 34.7).
    fuzzer.catch_all_detected = True
    fuzzer.catch_all_signature = (_CATCH_ALL_STATUS, _CATCH_ALL_SIZE)

    asyncio.run(fuzzer._recursive_fuzzing(endpoints, ["sub"]))

    recursed = _recursed_base_urls(client, endpoints)

    # Independently compute the scoped + default-eligible reference set.
    eligible_and_scoped = {
        e.url
        for e in endpoints
        if e.status in (EndpointStatus.VALID, EndpointStatus.AUTH_REQUIRED)
        and not e.url.endswith((".html", ".json", ".xml"))
        and not fuzzer._is_catch_all(e)
        and scope.admits(e)
    }

    # Core subset property (34.9, 34.3, 34.4, 34.5, 34.7): recursion only ever
    # descends into records that satisfy BOTH the scope and the default
    # eligibility -- it never expands beyond that intersection.
    assert recursed <= eligible_and_scoped, (
        f"recursed set {recursed - eligible_and_scoped} is outside the scoped + "
        f"default-eligible set (scope={scope}, max_depth={max_depth})"
    )

    # Recursion never exceeds the configured Recursion_Depth; with max_depth == 0
    # no recursive Discovery_Request is issued at all.
    observed_depths = [_request_depth(endpoints, url) for _, url in client.calls]
    if max_depth == 0:
        assert observed_depths == [], (
            "max_depth=0 must issue no recursive Discovery_Request, "
            f"saw depths {observed_depths}"
        )
    else:
        assert all(d <= max_depth for d in observed_depths), (
            f"observed recursion depth {max(observed_depths)} exceeds bound "
            f"{max_depth}"
        )


@given(max_depth=st.integers(min_value=0, max_value=4))
@settings(max_examples=25, deadline=None)
def test_scope_never_exceeds_recursion_depth_when_always_recursable(max_depth):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 18: Recursion-scope
    subset**
    **Validates: Requirements 34.9, 34.5**

    With a fake target that makes every sub-path scope-admitted and recursable
    (2xx / standard), recursion would descend forever if it were not bounded.
    Even under a permissive Recursion_Scope, the deepest level at which a
    Discovery_Request is issued is at most the configured Recursion_Depth, and
    a Recursion_Depth of 0 issues no recursive Discovery_Request.
    """
    # Every request returns 200 (=> VALID, 2xx) and the appended "sub" segment
    # classifies as the "standard" endpoint type, so the scope below admits each
    # generated sub-path: recursion is bounded only by Recursion_Depth.
    client = RecordingClient(status_code=200, content=b"{}")
    scope = RecursionScope(
        status_classes=frozenset({"2xx"}),
        endpoint_types=frozenset({"standard"}),
    )
    fuzzer = EndpointFuzzer(
        client, _make_config(max_depth=max_depth, recursion_scope=scope)
    )

    base = Endpoint(
        url="http://example.com/admin",
        method="GET",
        status_code=200,
        response_size=100,
        response_time=0.01,
        endpoint_type="standard",
    )

    asyncio.run(fuzzer._recursive_fuzzing([base], ["sub"]))

    observed_depths = [_request_depth([base], url) for _, url in client.calls]

    if max_depth == 0:
        assert observed_depths == [], (
            "max_depth=0 must issue no recursive Discovery_Request, "
            f"saw depths {observed_depths}"
        )
    else:
        assert max(observed_depths) <= max_depth, (
            f"observed recursion depth {max(observed_depths)} exceeds bound "
            f"{max_depth}"
        )
        # The bound is actually reached (recursion is not stopping early), so the
        # depth bound is a meaningful constraint here.
        assert max(observed_depths) == max_depth
