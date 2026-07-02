"""
Property-Based Tests for Clusterbomb candidate generation.

# Feature: owasp-complete-purple-teaming-cicd, Property 28: Clusterbomb generated
# set equals the cartesian product

Validates Property 28 from design.md for
``modules.fuzzing.markers.generate_marker_candidates`` in Clusterbomb_Mode:

FOR ALL marker counts M >= 1 and all associated Marker_Wordlists of sizes
W1..WM (each Wi >= 1), the multiset of candidate URLs produced by
``generate_marker_candidates(url, markers, wordlists, FuzzMode.CLUSTERBOMB)``
equals ``{ substitute_markers(url, markers, combo)
           for combo in itertools.product(W1..WM) }``,
and its cardinality before URL_Normalization/deduplication equals the product
``W1 x ... x WM``. The single-marker case (M = 1) reduces to exactly W1
candidates, one per wordlist entry.

The expected candidate multiset is computed INDEPENDENTLY of
``generate_marker_candidates`` via a direct :func:`itertools.product` over the
wordlists, mapped through :func:`substitute_markers`, rather than by reusing the
function under test.

Validates: Requirements 47.4, 42.1, 42.2, 42.5, 41.1, 41.2

These tests mirror the established Hypothesis conventions in
``tests/test_markers_count_properties.py`` and
``tests/test_marker_wordlist_association_properties.py``.
"""

import itertools
from collections import Counter

from hypothesis import given, settings, strategies as st

from modules.fuzzing.markers import (
    FuzzMode,
    find_markers,
    generate_marker_candidates,
    substitute_markers,
)


# --------------------------------------------------------------------------- #
# Independent oracle (does NOT reuse generate_marker_candidates' logic)
# --------------------------------------------------------------------------- #
def _expected_candidates(url, markers, wordlists):
    """Independently derive the expected Clusterbomb candidate list.

    Closed-form from Property 28 / Requirements 42.1, 42.2, 42.5, 41.1, 41.2:
    the cartesian product across all Marker_Wordlists, each combination tuple
    mapped through :func:`substitute_markers`. Materialized as a plain ``list``
    (multiset, order preserved) so it can be compared directly to the function
    output.
    """
    return [
        substitute_markers(url, markers, list(combo))
        for combo in itertools.product(*wordlists)
    ]


# --------------------------------------------------------------------------- #
# Strategies
# --------------------------------------------------------------------------- #
_KEYWORD = "FUZZ"

# A single Marker_Wordlist is a small NON-EMPTY list of candidate value strings.
# Non-empty (min_size=1) guarantees Wi >= 1 so the cartesian product is
# non-empty. Duplicate and empty-string values are allowed and carried through
# verbatim; product size is kept small (Wi <= 4) so the test stays fast.
_wordlist_strategy = st.lists(
    st.text(alphabet="abv0123.-_", min_size=0, max_size=5),
    min_size=1,
    max_size=4,
)


@st.composite
def markers_and_wordlists(draw):
    """Draw M >= 1 real Marker_Positions plus exactly M non-empty wordlists.

    The M markers are produced by :func:`find_markers` over a URL built from M
    literal ``FUZZ`` occurrences, so the ``order`` fields are genuine 0-based
    left-to-right indices. Exactly one Marker_Wordlist is supplied per marker
    (the fully-associated Clusterbomb input). Both M (<= 4) and each Wi (<= 4)
    are bounded so the product ``W1 x ... x WM`` stays small and the test runs
    fast even at >= 100 examples.
    """
    n_markers = draw(st.integers(min_value=1, max_value=4))
    # A realistic-looking URL carrying exactly M FUZZ markers in the path.
    url = "https://api.example.com/" + "seg/FUZZ/" * n_markers
    markers = find_markers(url, _KEYWORD)
    # Sanity: the constructed URL yields exactly M non-overlapping markers.
    assert len(markers) == n_markers

    wordlists = draw(
        st.lists(_wordlist_strategy, min_size=n_markers, max_size=n_markers)
    )
    return url, markers, wordlists


# --------------------------------------------------------------------------- #
# Property 28
# --------------------------------------------------------------------------- #
@given(data=markers_and_wordlists())
@settings(max_examples=250, deadline=None)
def test_clusterbomb_equals_cartesian_product(data):
    """
    # Feature: owasp-complete-purple-teaming-cicd, Property 28: Clusterbomb
    # generated set equals the cartesian product
    **Validates: Requirements 47.4, 42.1, 42.2, 42.5, 41.1, 41.2**

    FOR ALL marker counts M >= 1 and associated Marker_Wordlists of sizes
    W1..WM (each >= 1), the Clusterbomb candidate multiset equals the
    independently computed ``itertools.product`` mapping through
    ``substitute_markers``, and its cardinality equals the product
    ``W1 x ... x WM``.
    """
    url, markers, wordlists = data

    generated = list(
        generate_marker_candidates(
            url, markers, wordlists, FuzzMode.CLUSTERBOMB
        )
    )
    expected = _expected_candidates(url, markers, wordlists)

    # Cardinality equals the product of wordlist sizes (Reqs 42.2, 42.5).
    product_size = 1
    for wl in wordlists:
        product_size *= len(wl)
    assert len(generated) == product_size

    # Multiset (order-independent) equality with the independent oracle so
    # duplicate candidate URLs are accounted for (Reqs 42.1, 47.4).
    assert Counter(generated) == Counter(expected)

    # Ordered equality: itertools.product is deterministic, so the generator
    # yields candidates in exactly product order (Req 42.1).
    assert generated == expected


@given(w1=_wordlist_strategy)
@settings(max_examples=150, deadline=None)
def test_single_marker_reduces_to_wordlist(w1):
    """
    # Feature: owasp-complete-purple-teaming-cicd, Property 28: Clusterbomb
    # generated set equals the cartesian product
    **Validates: Requirements 41.1, 41.2**

    Boundary M = 1: a single Marker_Position yields exactly W1 candidates, one
    per wordlist entry (each the URL with the sole marked span replaced by that
    entry).
    """
    url = "https://api.example.com/users/FUZZ/detail"
    markers = find_markers(url, _KEYWORD)
    assert len(markers) == 1

    generated = list(
        generate_marker_candidates(url, markers, [w1], FuzzMode.CLUSTERBOMB)
    )

    # Exactly W1 candidates (Req 41.1).
    assert len(generated) == len(w1)
    # Each candidate is the URL with the single marker replaced by an entry,
    # in wordlist order (Req 41.2).
    assert generated == [substitute_markers(url, markers, [v]) for v in w1]
