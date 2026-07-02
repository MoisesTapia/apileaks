"""
Property-based tests for spec-driven BOLA identifier targeting.

Feature: owasp-auth-modules-hardening

Property 31: Spec-driven substitution changes only the targeted path-parameter
slot. For all endpoints whose Spec_Operation declares one or more ``path``
Spec_Parameters, all targeted slot indices, and all candidate identifiers, the
URL produced via ``_identifier_from_spec`` + ``_substitute_identifier`` replaces
only the identifier in the targeted declared ``path`` position while every other
path segment (including every other declared path-parameter slot) and every
query parameter is preserved unchanged.

**Validates: Requirements 57.4, 53.1, 53.3, 53.4**
"""

import string
from urllib.parse import urlparse
from unittest.mock import Mock, AsyncMock

from hypothesis import given, settings, strategies as st

from modules.owasp.bola_testing import BOLATestingModule
from utils.http_client import HTTPRequestEngine
from utils.spec_import import SpecOperation, SpecParameter
from core.config import BOLAConfig


# Collection names that are alphabetic words, so they never collide with the
# numeric concrete id values used for the declared path slots.
_COLLECTIONS = [
    "users", "posts", "projects", "orgs", "teams",
    "items", "groups", "files", "orders", "accounts",
]

# Declared path-parameter names. Drawn UNIQUE per operation so each ``{name}``
# placeholder resolves to a single template position.
_PARAM_NAMES = [
    "user_id", "post_id", "project_id", "org_id", "team_id",
    "item_id", "group_id", "file_id", "order_id", "account_id",
]

# Optional base prefixes present on the concrete endpoint but not the declared
# template path -- exercises the right-align tolerance of _identifier_from_spec.
# All alphabetic, so they never collide with numeric id values.
_PREFIXES = [[], ["v1"], ["api"], ["api", "v2"]]

# Safe candidate/query alphabet: no path or query delimiters, survives round-trips.
_SAFE_ALPHABET = string.ascii_letters + string.digits + "-_"
_candidate = st.text(alphabet=_SAFE_ALPHABET, min_size=1, max_size=10)

# Concrete id values are all-digit strings. Drawn UNIQUE across a single URL so
# the value-based ``_substitute_identifier`` targets exactly one path segment.
_id_value = st.integers(min_value=0, max_value=10_000_000).map(str)


def _make_module():
    """Build a BOLATestingModule with stubbed dependencies.

    ``_identifier_from_spec``, ``_spec_path_slots`` and ``_substitute_identifier``
    are pure functions of their arguments, so a stub HTTP client and empty auth
    contexts suffice.
    """
    client = Mock(spec=HTTPRequestEngine)
    client.request = AsyncMock()
    client.set_auth_context = Mock()
    return BOLATestingModule(BOLAConfig(enabled=True), client, [])


_MODULE = _make_module()


@st.composite
def _spec_case(draw):
    """Generate a Spec_Operation with 1..4 declared ``path`` params + endpoint.

    Builds a declared template path shaped like
    ``/{collection}/{param}[/{collection}/{param}...]`` and a matching concrete
    endpoint carrying unique numeric ids in each declared slot, optionally with a
    base prefix and a query string. Returns ``(operation, url, candidate)``.
    """
    n = draw(st.integers(min_value=1, max_value=4))
    param_names = draw(
        st.lists(st.sampled_from(_PARAM_NAMES), min_size=n, max_size=n, unique=True)
    )
    collections = draw(
        st.lists(st.sampled_from(_COLLECTIONS), min_size=n, max_size=n)
    )
    ids = draw(st.lists(_id_value, min_size=n, max_size=n, unique=True))

    template_segments = []
    concrete_segments = []
    for collection, pname, id_value in zip(collections, param_names, ids):
        template_segments.append(collection)
        template_segments.append("{" + pname + "}")
        concrete_segments.append(collection)
        concrete_segments.append(id_value)

    prefix = draw(st.sampled_from(_PREFIXES))

    template_path = "/" + "/".join(template_segments)
    concrete_path = "/" + "/".join(prefix + concrete_segments)

    # Optional query string with safe, non-empty, unique keys/values.
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

    url = "https://api.example.com" + concrete_path
    if query:
        url += "?" + query

    operation = SpecOperation(
        path=template_path,
        method="GET",
        parameters=[
            SpecParameter(name=pname, location="path") for pname in param_names
        ],
    )

    candidate = draw(_candidate)
    return operation, url, candidate


@settings(max_examples=200)
@given(_spec_case())
def test_spec_substitution_changes_only_targeted_slot(case):
    # Feature: owasp-auth-modules-hardening, Property 31: Spec-driven substitution changes only the targeted path-parameter slot
    operation, url, candidate = case

    original_parsed = urlparse(url)
    original_segments = original_parsed.path.split("/")

    slots = _MODULE._spec_path_slots(operation)
    n = len(slots)
    # By construction the operation declares one or more path parameters.
    assert n >= 1

    for slot_index in range(n):
        identifier = _MODULE._identifier_from_spec(operation, url, slot_index)
        # A declared, resolvable path slot always yields a path-located identifier
        # (Requirement 53.1).
        assert identifier is not None
        assert identifier.location == "path"

        result = _MODULE._substitute_identifier(identifier, candidate)
        result_parsed = urlparse(result)
        result_segments = result_parsed.path.split("/")

        # The concrete value sits at exactly one path segment (ids are unique).
        target_index = original_segments.index(identifier.value)

        # Structure is preserved: same number of path segments.
        assert len(result_segments) == len(original_segments)

        # Only the targeted declared slot changes -- it becomes exactly the
        # candidate. Every other path segment (including every OTHER declared
        # path-parameter slot and every non-identifier segment) is preserved
        # unchanged (Requirements 53.3, 53.4).
        for idx, (orig_seg, new_seg) in enumerate(
            zip(original_segments, result_segments)
        ):
            if idx == target_index:
                assert new_seg == candidate
            else:
                assert new_seg == orig_seg

        # Every query parameter is preserved unchanged (Requirement 53.3).
        assert result_parsed.query == original_parsed.query


if __name__ == "__main__":
    import pytest
    pytest.main([__file__])
