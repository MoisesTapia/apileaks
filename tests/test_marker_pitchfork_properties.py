"""
Property-Based Tests for Pitchfork candidate generation.

# Feature: owasp-complete-purple-teaming-cicd, Property 29: Pitchfork generated
# set equals the index-wise zip truncated to the shortest list

Validates Property 29 from design.md for
``modules.fuzzing.markers.generate_marker_candidates`` in Pitchfork_Mode:

FOR ALL marker counts M >= 1 and all associated Marker_Wordlists of sizes
W1..WM, the sequence of candidate URLs produced by
``generate_marker_candidates(url, markers, wordlists, FuzzMode.PITCHFORK)``
equals ``[ substitute_markers(url, markers, tuple_i)
           for tuple_i in zip(W1..WM) ]``,
pairing the i-th entry of every Marker_Wordlist together and stopping at the
shortest list, so its cardinality before URL_Normalization and deduplication
equals ``min(W1, ..., WM)``. When any Marker_Wordlist is empty the shortest
length is 0 and no candidates are produced.

The expected candidate sequence is computed INDEPENDENTLY of
``generate_marker_candidates`` via a direct :func:`zip` over the wordlists,
mapped through :func:`substitute_markers`, rather than by reusing the function
under test.

Validates: Requirements 47.5, 43.2, 43.3, 43.5

These tests mirror the established Hypothesis conventions in
``tests/test_marker_clusterbomb_properties.py`` and
``tests/test_markers_count_properties.py``.
"""

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
    """Independently derive the expected Pitchfork candidate list.

    Closed-form from Property 29 / Requirements 43.2, 43.3, 43.5: the index-wise
    ``zip`` across all Marker_Wordlists (pairing the i-th entry of each list and
    stopping at the shortest), each combination tuple mapped through
    :func:`substitute_markers`. Materialized as a plain ``list`` (order
    preserved) so it can be compared directly to the function output.
    """
    return [
        substitute_markers(url, markers, list(combo))
        for combo in zip(*wordlists)
    ]


# --------------------------------------------------------------------------- #
# Strategies
# --------------------------------------------------------------------------- #
_KEYWORD = "FUZZ"

# A single Marker_Wordlist is a small list of candidate value strings whose
# size VARIES from 0 (empty) to 5. Allowing min_size=0 exercises the shortest-
# list truncation, including the case where an empty list drives the Pitchfork
# cardinality to 0. Duplicate and empty-string values are allowed and carried
# through verbatim; sizes are kept small so the test stays fast.
_wordlist_strategy = st.lists(
    st.text(alphabet="abv0123.-_", min_size=0, max_size=5),
    min_size=0,
    max_size=5,
)


@st.composite
def markers_and_wordlists(draw):
    """Draw M >= 1 real Marker_Positions plus exactly M wordlists of varying size.

    The M markers are produced by :func:`find_markers` over a URL built from M
    literal ``FUZZ`` occurrences, so the ``order`` fields are genuine 0-based
    left-to-right indices. Exactly one Marker_Wordlist is supplied per marker.
    Each wordlist's size is drawn independently in ``[0, 5]`` so runs mix empty
    and non-empty lists, deliberately exercising the min/truncation behavior --
    including cases where the shortest list makes the cardinality 0.
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
# Property 29
# --------------------------------------------------------------------------- #
@given(data=markers_and_wordlists())
@settings(max_examples=250, deadline=None)
def test_pitchfork_equals_indexwise_zip(data):
    """
    # Feature: owasp-complete-purple-teaming-cicd, Property 29: Pitchfork
    # generated set equals the index-wise zip truncated to the shortest list
    **Validates: Requirements 47.5, 43.2, 43.3, 43.5**

    FOR ALL marker counts M >= 1 and associated Marker_Wordlists of varying
    sizes W1..WM, the Pitchfork candidate sequence equals the independently
    computed ``zip`` mapping through ``substitute_markers``, and its cardinality
    equals ``min(W1, ..., WM)`` (0 when any list is empty).
    """
    url, markers, wordlists = data

    generated = list(
        generate_marker_candidates(
            url, markers, wordlists, FuzzMode.PITCHFORK
        )
    )
    expected = _expected_candidates(url, markers, wordlists)

    # Cardinality equals the minimum of the wordlist sizes (Reqs 43.3, 43.5),
    # which is 0 whenever any associated Marker_Wordlist is empty.
    min_size = min(len(wl) for wl in wordlists)
    assert len(generated) == min_size

    # Ordered equality: zip is deterministic, so the generator yields candidates
    # in exactly index order, pairing the i-th entry of every list (Req 43.2).
    assert generated == expected

    # Multiset (order-independent) equality with the independent oracle so
    # duplicate candidate URLs are accounted for (Reqs 43.2, 47.5).
    assert Counter(generated) == Counter(expected)


@given(
    w1=_wordlist_strategy,
    w2=_wordlist_strategy,
)
@settings(max_examples=150, deadline=None)
def test_pitchfork_two_markers_truncates_to_shortest(w1, w2):
    """
    # Feature: owasp-complete-purple-teaming-cicd, Property 29: Pitchfork
    # generated set equals the index-wise zip truncated to the shortest list
    **Validates: Requirements 47.5, 43.2, 43.3, 43.5**

    Two Marker_Positions with independently sized wordlists: the Pitchfork
    output pairs entries index-wise, stops at the shorter list, and has
    cardinality ``min(len(w1), len(w2))`` -- including 0 when either list is
    empty.
    """
    url = "https://api.example.com/FUZZ/users/FUZZ/detail"
    markers = find_markers(url, _KEYWORD)
    assert len(markers) == 2

    generated = list(
        generate_marker_candidates(url, markers, [w1, w2], FuzzMode.PITCHFORK)
    )

    expected = [
        substitute_markers(url, markers, [a, b]) for a, b in zip(w1, w2)
    ]

    assert len(generated) == min(len(w1), len(w2))
    assert generated == expected
