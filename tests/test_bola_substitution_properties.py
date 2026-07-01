"""
Property-based tests for BOLA identifier substitution.

Feature: owasp-auth-modules-hardening

Property 1: Identifier substitution preserves everything but the target id.
For all URLs (whether the identifier appears in a path segment or a query
parameter) and all candidate ids, substituting a candidate identifier changes
only the target id and yields a URL that differs from the original if and only
if the candidate differs from the original id.

**Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5**
"""

import string
from urllib.parse import urlparse, parse_qs, urlencode
from unittest.mock import Mock, AsyncMock

from hypothesis import given, settings, strategies as st

from modules.owasp.bola_testing import BOLATestingModule, ObjectIdentifier
from utils.http_client import HTTPRequestEngine
from core.config import BOLAConfig


# Safe alphabet that survives URL encode/decode round-trips without ambiguity
# and contains no path/query delimiters.
_SAFE_ALPHABET = string.ascii_letters + string.digits + "-_"
_safe_text = st.text(alphabet=_SAFE_ALPHABET, min_size=1, max_size=10)


def _make_module():
    """Build a BOLATestingModule with stubbed dependencies.

    ``_substitute_identifier`` is a pure function of its arguments (it does not
    read instance state), so a stub HTTP client and empty auth contexts suffice.
    """
    client = Mock(spec=HTTPRequestEngine)
    client.request = AsyncMock()
    client.set_auth_context = Mock()
    return BOLATestingModule(BOLAConfig(enabled=True), client, [])


_MODULE = _make_module()


@st.composite
def _path_case(draw):
    """Generate a path-identifier endpoint plus a candidate id."""
    id_value = draw(_safe_text)
    # Other segments must not coincide with the id value so that exactly the
    # target segment(s) are affected by substitution.
    other = _safe_text.filter(lambda s: s != id_value)
    before = draw(st.lists(other, min_size=0, max_size=3))
    after = draw(st.lists(other, min_size=0, max_size=3))
    segments = before + [id_value] + after
    endpoint = "https://api.example.com/" + "/".join(segments)
    identifier = ObjectIdentifier(
        value=id_value,
        type="custom",
        endpoint=endpoint,
        parameter_name="id",
        location="path",
    )
    # Candidate is sometimes equal to the original to exercise the no-op branch.
    candidate = draw(st.one_of(st.just(id_value), _safe_text))
    return identifier, candidate


@st.composite
def _query_case(draw):
    """Generate a query-identifier endpoint plus a candidate id."""
    keys = draw(st.lists(_safe_text, min_size=1, max_size=4, unique=True))
    target_key = draw(st.sampled_from(keys))
    params = {k: draw(_safe_text) for k in keys}
    id_value = params[target_key]
    endpoint = "https://api.example.com/resource?" + urlencode(params)
    identifier = ObjectIdentifier(
        value=id_value,
        type="custom",
        endpoint=endpoint,
        parameter_name=target_key,
        location="query",
    )
    candidate = draw(st.one_of(st.just(id_value), _safe_text))
    return identifier, target_key, candidate


@settings(max_examples=200)
@given(_path_case())
def test_path_substitution_preserves_everything_but_target_id(case):
    # Feature: owasp-auth-modules-hardening, Property 1: Identifier substitution preserves everything but the target id
    identifier, candidate = case

    baseline_url = _MODULE._substitute_identifier(identifier, identifier.value)
    candidate_url = _MODULE._substitute_identifier(identifier, candidate)

    base_segs = urlparse(baseline_url).path.split("/")
    cand_segs = urlparse(candidate_url).path.split("/")

    # Same structure: identical number of path segments.
    assert len(base_segs) == len(cand_segs)

    # Only segments equal to the original id value change, and they change to
    # exactly the candidate (Requirements 1.2, 1.5).
    for base_seg, cand_seg in zip(base_segs, cand_segs):
        if base_seg == identifier.value:
            assert cand_seg == candidate
        else:
            assert cand_seg == base_seg

    # The query component is untouched for a path identifier.
    assert urlparse(baseline_url).query == urlparse(candidate_url).query

    # The URL differs iff the candidate differs from the original (Requirement 1.4).
    assert (candidate_url != baseline_url) == (candidate != identifier.value)


@settings(max_examples=200)
@given(_query_case())
def test_query_substitution_preserves_everything_but_target_id(case):
    # Feature: owasp-auth-modules-hardening, Property 1: Identifier substitution preserves everything but the target id
    identifier, target_key, candidate = case

    baseline_url = _MODULE._substitute_identifier(identifier, identifier.value)
    candidate_url = _MODULE._substitute_identifier(identifier, candidate)

    # The path is untouched for a query identifier (Requirement 1.5).
    assert urlparse(baseline_url).path == urlparse(candidate_url).path

    base_q = parse_qs(urlparse(baseline_url).query, keep_blank_values=True)
    cand_q = parse_qs(urlparse(candidate_url).query, keep_blank_values=True)

    # Same set of query parameters before and after substitution.
    assert set(base_q.keys()) == set(cand_q.keys())

    # Only the target query parameter changes; it becomes exactly the candidate
    # while every other parameter is preserved (Requirements 1.3, 1.5).
    for key in base_q:
        if key == target_key:
            assert cand_q[key] == [candidate]
        else:
            assert cand_q[key] == base_q[key]

    # The URL differs iff the candidate differs from the original (Requirement 1.4).
    assert (candidate_url != baseline_url) == (candidate != identifier.value)


if __name__ == "__main__":
    import pytest
    pytest.main([__file__])
