"""Property-based tests for wordlist merge/dedupe and injection routing.

# Feature: parameter-fuzzing, Property 10: Wordlist merge/dedupe and injection routing

Property 10 (from design.md / tasks.md task 11.9):
    *For any* collection of query and body wordlist sources, the merged candidate
    set SHALL equal the normalized, de-duplicated union of those sources, and the
    fuzzer SHALL use the query candidate set for query-parameter fuzzing and the
    body candidate set for body-parameter fuzzing.

**Validates: Requirements 10.1, 10.2**

The property has two independent, verifiable halves, exercised by the two tests
below against the *real* production code, fully offline:

Half 1 - merge/dedupe (R10.1)
    ``apileaks._resolve_par_candidates`` is the production merge/dedupe used by
    the repeatable ``par --wordlist`` option. It reads every source with
    ``_read_wordlist_entries`` (strip surrounding whitespace, drop blank and
    ``#``-comment lines) and de-duplicates the combined entries, preserving
    first-seen order. ``test_merge_equals_normalized_deduped_union`` asserts the
    merged set equals the normalized, de-duplicated union of all sources for an
    arbitrary collection of source files.

Half 2 - injection routing (R10.2)
    The ``par`` CLI feeds the merged candidate set into both the
    ``query_candidates`` and ``body_candidates`` config fields, which back the
    fuzzer's ``query_wordlist`` / ``body_wordlist`` inputs. R10.2 states that,
    *where distinct query and body wordlists are configured*, the fuzzer SHALL
    use the query wordlist for Query_Parameters and the body wordlist for
    Body_Parameters. ``test_fuzzer_routes_query_and_body_candidate_sets`` drives
    the real :class:`~modules.fuzzing.orchestrator.ParameterFuzzer` with *disjoint*
    query and body wordlists and asserts, from the shared task-1.1 stub's
    recorded requests, that every query-parameter request carries only names from
    the query wordlist and every body-parameter request carries only names from
    the body wordlist.

Both tests run against the shared task-1.1 stub
(:mod:`tests.support.http_stub`); no real network access occurs.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from typing import List, Set
from urllib.parse import parse_qsl

import pytest
from hypothesis import given, settings, strategies as st

from apileaks import _resolve_par_candidates
from core.config import (
    EndpointFuzzingConfig,
    FuzzingConfig,
    HeaderFuzzingConfig,
    ParameterFuzzingConfig,
)
from modules.fuzzing.orchestrator import Endpoint, ParameterFuzzer
from tests.support.http_stub import HTTPRequestEngineStub, ScriptedResponse


TARGET = "https://api.example.test"


# --------------------------------------------------------------------------- #
# Half 1: merge/dedupe (R10.1)
# --------------------------------------------------------------------------- #

# A small pool of candidate words so duplicates recur within/across sources,
# reliably exercising the de-duplication path.
_WORDS = ["id", "user", "token", "page", "limit", "q", "name", "sort", "offset"]
_PAD = st.sampled_from(["", " ", "  ", "\t"])


def _padded(word: str, lead: str, trail: str) -> str:
    return f"{lead}{word}{trail}"


# A single raw line as it would appear in a wordlist file: a plain word, a
# whitespace-padded word, a blank/whitespace-only line, or a ``#`` comment. These
# mirror exactly what ``_read_wordlist_entries`` must normalize away.
_raw_line = st.one_of(
    st.builds(_padded, st.sampled_from(_WORDS), _PAD, _PAD),
    st.just(""),
    st.just("   "),
    st.just("\t"),
    st.builds(lambda w: f"# {w}", st.sampled_from(_WORDS)),
    st.builds(lambda w, p: f"{p}#{w}", st.sampled_from(_WORDS), _PAD),
)

# A collection of wordlist sources, each a list of raw lines.
_sources = st.lists(st.lists(_raw_line, max_size=8), min_size=1, max_size=4)


def _expected_merge(sources_lines: List[List[str]]) -> List[str]:
    """Reference normalized, de-duplicated union preserving first-seen order.

    Applies the same normalization ``_read_wordlist_entries`` applies (strip
    surrounding whitespace; drop blank lines and ``#`` comments) and then the
    same first-seen de-duplication ``_resolve_par_candidates`` applies.
    """
    seen = set()
    merged: List[str] = []
    for lines in sources_lines:
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                if stripped not in seen:
                    seen.add(stripped)
                    merged.append(stripped)
    return merged


@given(sources_lines=_sources)
@settings(max_examples=200, deadline=None)
def test_merge_equals_normalized_deduped_union(sources_lines):
    """Merged candidate set equals the normalized, de-duplicated union of sources.

    # Feature: parameter-fuzzing, Property 10: Wordlist merge/dedupe and injection routing
    **Validates: Requirements 10.1**
    """
    paths: List[str] = []
    try:
        for lines in sources_lines:
            handle = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, encoding="utf-8"
            )
            handle.write("\n".join(lines))
            handle.close()
            paths.append(handle.name)

        merged = _resolve_par_candidates(paths)
    finally:
        for path in paths:
            os.unlink(path)

    expected = _expected_merge(sources_lines)

    # Exact match: same members, same first-seen order.
    assert merged == expected
    # The merged set carries no duplicates.
    assert len(merged) == len(set(merged))
    # Set-equality with the normalized union of every source (order-independent).
    assert set(merged) == set(expected)


# --------------------------------------------------------------------------- #
# Half 2: injection routing (R10.2)
# --------------------------------------------------------------------------- #

_ident = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=6)
# Disjoint query/body candidate sets: the ``q_``/``b_`` prefixes guarantee no
# name can belong to both sets, so a name observed in a request unambiguously
# identifies which wordlist it was routed from.
_query_names = st.lists(_ident, min_size=1, max_size=5, unique=True).map(
    lambda xs: [f"q_{x}" for x in xs]
)
_body_names = st.lists(_ident, min_size=1, max_size=5, unique=True).map(
    lambda xs: [f"b_{x}" for x in xs]
)


def _write_wordlist(names: List[str]) -> str:
    handle = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    )
    handle.write("\n".join(names) + "\n")
    handle.close()
    return handle.name


def _make_config(query_wordlist: str, body_wordlist: str) -> FuzzingConfig:
    """FuzzingConfig with distinct query/body wordlists and both injection points.

    ``methods=["GET", "POST"]`` enables both the query and body injection points;
    boundary testing is disabled so the only requests issued are the baseline and
    the per-candidate query/body injections, keeping the routing classification
    unambiguous.
    """
    return FuzzingConfig(
        endpoints=EndpointFuzzingConfig(enabled=False),
        parameters=ParameterFuzzingConfig(
            enabled=True,
            query_wordlist=query_wordlist,
            body_wordlist=body_wordlist,
            boundary_testing=False,
            methods=["GET", "POST"],
        ),
        headers=HeaderFuzzingConfig(enabled=False),
    )


def _suitable_endpoints():
    """One query-carrying (GET) and one body-carrying (POST) 2xx endpoint."""
    return [
        Endpoint(url=TARGET, method="GET", status_code=200, response_size=0,
                 response_time=0.01, endpoint_type="parameter_target"),
        Endpoint(url=TARGET, method="POST", status_code=200, response_size=0,
                 response_time=0.01, endpoint_type="parameter_target"),
    ]


@given(query_names=_query_names, body_names=_body_names)
@settings(max_examples=150, deadline=None)
def test_fuzzer_routes_query_and_body_candidate_sets(query_names, body_names):
    """The fuzzer uses the query wordlist for query params and the body wordlist for body params.

    # Feature: parameter-fuzzing, Property 10: Wordlist merge/dedupe and injection routing
    **Validates: Requirements 10.2**
    """
    query_set = set(query_names)
    body_set = set(body_names)
    # Guaranteed disjoint by the ``q_``/``b_`` prefixes; assert it to make the
    # routing assertions below unambiguous.
    assert query_set.isdisjoint(body_set)

    query_wordlist = _write_wordlist(query_names)
    body_wordlist = _write_wordlist(body_names)
    try:
        stub = HTTPRequestEngineStub(
            default=ScriptedResponse(status_code=200, body={"ok": True})
        )
        fuzzer = ParameterFuzzer(stub, _make_config(query_wordlist, body_wordlist))
        asyncio.run(fuzzer.fuzz_parameters(_suitable_endpoints()))
    finally:
        os.unlink(query_wordlist)
        os.unlink(body_wordlist)

    observed_query = set()
    observed_body = set()

    for req in stub.requests:
        ctype = (req.content_type or "").lower()

        if req.params:
            # Query-parameter injection request (no body content-type set).
            names = set(req.params.keys())
            # R10.2: query fuzzing draws ONLY from the query wordlist.
            assert names <= query_set, (
                f"query request carried non-query names {names - query_set}"
            )
            assert names.isdisjoint(body_set)
            observed_query |= names

        elif req.json is not None:
            # JSON body-parameter injection request.
            names = set(req.json.keys())
            # R10.2: body fuzzing draws ONLY from the body wordlist.
            assert names <= body_set, (
                f"json body request carried non-body names {names - body_set}"
            )
            assert names.isdisjoint(query_set)
            observed_body |= names

        elif "form-urlencoded" in ctype and isinstance(req.data, str):
            # Form body-parameter injection request.
            names = {k for k, _ in parse_qsl(req.data, keep_blank_values=True)}
            assert names <= body_set, (
                f"form body request carried non-body names {names - body_set}"
            )
            assert names.isdisjoint(query_set)
            observed_body |= names

        elif "xml" in ctype and isinstance(req.data, str):
            # XML body-parameter injection request: the candidate name is embedded
            # as an element. It must be a body name and never a query name.
            assert not any(f"<{q}>" in req.data for q in query_set), (
                "xml body request embedded a query-wordlist name"
            )
            for b in body_set:
                if f"<{b}>" in req.data:
                    observed_body.add(b)
        # else: baseline request (no params, no body) - nothing to route.

    # Every query candidate was fuzzed as a query parameter and every body
    # candidate as a body parameter (json + form both iterate the full wordlist).
    assert observed_query == query_set, (
        f"query candidates not fully routed: missing {query_set - observed_query}, "
        f"unexpected {observed_query - query_set}"
    )
    assert observed_body == body_set, (
        f"body candidates not fully routed: missing {body_set - observed_body}, "
        f"unexpected {observed_body - body_set}"
    )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
