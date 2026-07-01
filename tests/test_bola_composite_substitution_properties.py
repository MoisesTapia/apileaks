"""
Property-based tests for composite (multi-tenant) BOLA slot substitution.

Feature: owasp-auth-modules-hardening

Property 10: Composite substitution changes only the targeted slot.
For all composite identifiers with >= 2 slots, all slot indices, and all
candidate values, substituting a single slot changes ONLY the targeted slot's
path segment; every other identifier slot, every non-identifier path segment,
and every query parameter is preserved unchanged.

**Validates: Requirements 29.1, 29.2, 36.2**
"""

import string
from urllib.parse import urlparse
from unittest.mock import Mock, AsyncMock

from hypothesis import given, settings, strategies as st

from modules.owasp.bola_testing import BOLATestingModule
from utils.http_client import HTTPRequestEngine
from core.config import BOLAConfig


# Collection names that are guaranteed NOT to be detected as identifiers by
# ``ID_PATTERNS`` (they are not all-digits and contain non-hex letters), so the
# only identifier slots come from the generated numeric id segments.
_COLLECTIONS = [
    "tenants", "projects", "users", "groups", "orgs",
    "items", "teams", "workspaces", "regions", "vaults",
]

# Safe candidate alphabet: no path/query delimiters, survives round-trips.
_SAFE_ALPHABET = string.ascii_letters + string.digits + "-_"
_candidate = st.text(alphabet=_SAFE_ALPHABET, min_size=1, max_size=10)

# Sequential numeric ids are detected by the 'sequential' id pattern (^\d+$).
_id_value = st.integers(min_value=0, max_value=10_000_000).map(str)


def _make_module():
    """Build a BOLATestingModule with stubbed dependencies.

    ``_substitute_composite_slot`` and ``_extract_composite_from_path`` are pure
    functions of their arguments, so a stub HTTP client and empty auth contexts
    suffice.
    """
    client = Mock(spec=HTTPRequestEngine)
    client.request = AsyncMock()
    client.set_auth_context = Mock()
    return BOLATestingModule(BOLAConfig(enabled=True), client, [])


_MODULE = _make_module()


@st.composite
def _composite_case(draw):
    """Generate a composite URL with >= 2 identifier slots plus a candidate.

    Builds paths shaped like ``/{collection}/{id}/{collection2}/{id2}[/...]``
    with an optional query string, then returns the built URL alongside a
    candidate value used for the single-slot substitution.
    """
    n_pairs = draw(st.integers(min_value=2, max_value=4))
    collections = draw(
        st.lists(
            st.sampled_from(_COLLECTIONS),
            min_size=n_pairs,
            max_size=n_pairs,
        )
    )
    ids = draw(st.lists(_id_value, min_size=n_pairs, max_size=n_pairs))

    segments = []
    for collection, id_value in zip(collections, ids):
        segments.append(collection)
        segments.append(id_value)
    path = "/" + "/".join(segments)

    # Optional query string with safe, non-empty keys/values.
    query_pairs = draw(
        st.lists(
            st.tuples(
                st.text(alphabet=_SAFE_ALPHABET, min_size=1, max_size=6),
                st.text(alphabet=_SAFE_ALPHABET, min_size=1, max_size=6),
            ),
            min_size=0,
            max_size=3,
            unique_by=lambda kv: kv[0],
        )
    )
    query = "&".join(f"{k}={v}" for k, v in query_pairs)

    url = "https://api.example.com" + path
    if query:
        url += "?" + query

    candidate = draw(_candidate)
    return url, candidate


@settings(max_examples=200)
@given(_composite_case())
def test_composite_substitution_changes_only_targeted_slot(case):
    # Feature: owasp-auth-modules-hardening, Property 10: Composite substitution changes only the targeted slot
    url, candidate = case

    composite = _MODULE._extract_composite_from_path(url)
    # By construction the path has >= 2 numeric id slots.
    assert composite is not None
    assert len(composite.slots) >= 2

    original_parsed = urlparse(url)
    original_segments = original_parsed.path.split("/")

    # The exact raw-path indices that hold identifier slots.
    slot_indices = {slot.segment_index for slot in composite.slots}

    for slot_index in range(len(composite.slots)):
        result = _MODULE._substitute_composite_slot(composite, slot_index, candidate)
        result_parsed = urlparse(result)
        result_segments = result_parsed.path.split("/")

        target_index = composite.slots[slot_index].segment_index

        # Structure is preserved: same number of path segments (Req 29.2).
        assert len(result_segments) == len(original_segments)

        # Only the targeted slot's segment changes; it becomes exactly the
        # candidate. Every other segment -- including other identifier slots and
        # every non-identifier segment -- is preserved (Requirements 29.1, 29.2).
        for idx, (orig_seg, new_seg) in enumerate(
            zip(original_segments, result_segments)
        ):
            if idx == target_index:
                assert new_seg == candidate
            else:
                assert new_seg == orig_seg

        # Every OTHER identifier slot segment is unchanged.
        for other_index in slot_indices:
            if other_index != target_index:
                assert result_segments[other_index] == original_segments[other_index]

        # All query parameters are preserved unchanged (Requirement 36.2).
        assert result_parsed.query == original_parsed.query


if __name__ == "__main__":
    import pytest
    pytest.main([__file__])
