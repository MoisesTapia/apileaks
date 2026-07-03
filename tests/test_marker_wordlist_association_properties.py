"""
Property-Based Tests for per-marker wordlist association.

# Feature: owasp-complete-purple-teaming-cicd, Property 27: Per-marker wordlist
# association order

Validates Property 27 from design.md for
``modules.fuzzing.markers.associate_wordlists``:

FOR ALL marker counts M >= 1 and all supplied wordlist sequences whose length is
between 1 and M inclusive, ``associate_wordlists(markers, wordlists)`` returns
exactly M lists in which the i-th associated list is the i-th supplied wordlist
when it exists, and otherwise the LAST supplied wordlist (single-list case =>
every position gets that list). The association preserves left-to-right marker
order so ``result[markers[i].order]`` is the Marker_Wordlist that will be
substituted at marker i.

The expected association is computed INDEPENDENTLY of ``associate_wordlists``
via the closed-form rule ``expected[i] = wordlists[i] if i < len(wordlists)
else wordlists[-1]`` rather than by reusing the function under test.

Validates: Requirements 44.1, 44.2, 44.3

These tests mirror the established Hypothesis conventions in
``tests/test_markers_count_properties.py`` and
``tests/test_marker_substitution_properties.py``.
"""

from hypothesis import given, settings, strategies as st

from modules.fuzzing.markers import associate_wordlists, find_markers


# --------------------------------------------------------------------------- #
# Independent oracle (does NOT reuse associate_wordlists' internal logic)
# --------------------------------------------------------------------------- #
def _expected_association(n_markers, wordlists):
    """Independently derive the expected per-marker Marker_Wordlists.

    Closed-form rule from Property 27 / Requirements 44.1-44.3: the i-th
    Marker_Position takes the i-th supplied wordlist when it exists and
    otherwise the last supplied wordlist. Materialized as plain ``list``s so it
    can be compared directly to the function output.
    """
    return [
        list(wordlists[i] if i < len(wordlists) else wordlists[-1])
        for i in range(n_markers)
    ]


# --------------------------------------------------------------------------- #
# Strategies
# --------------------------------------------------------------------------- #
_KEYWORD = "FUZZ"

# A single wordlist is a small list of candidate value strings. The empty string
# and duplicate values are allowed; wordlist contents are irrelevant to the
# association ORDER but are carried through verbatim, so we keep them varied.
_wordlist_strategy = st.lists(
    st.text(alphabet="abv0123.-_", min_size=0, max_size=6),
    min_size=0,
    max_size=5,
)


@st.composite
def markers_and_wordlists(draw):
    """Draw M >= 1 real Marker_Positions plus 1..M supplied wordlists.

    The M markers are produced by :func:`find_markers` over a URL built from M
    literal ``FUZZ`` occurrences ("/" + "FUZZ/" * M), so the ``order`` fields are
    genuine 0-based left-to-right indices rather than hand-set values. The number
    of supplied wordlists ``K`` is constrained to ``1 <= K <= M`` (the in-scope
    band for Property 27's fallback/broadcast rules).
    """
    n_markers = draw(st.integers(min_value=1, max_value=6))
    url = "/" + "FUZZ/" * n_markers
    markers = find_markers(url, _KEYWORD)
    # Sanity: the constructed URL yields exactly M non-overlapping markers.
    assert len(markers) == n_markers

    n_wordlists = draw(st.integers(min_value=1, max_value=n_markers))
    wordlists = draw(
        st.lists(
            _wordlist_strategy, min_size=n_wordlists, max_size=n_wordlists
        )
    )
    return markers, wordlists


# --------------------------------------------------------------------------- #
# Property 27
# --------------------------------------------------------------------------- #
@given(data=markers_and_wordlists())
@settings(max_examples=250, deadline=None)
def test_association_order_and_fallback(data):
    """
    # Feature: owasp-complete-purple-teaming-cicd, Property 27: Per-marker
    # wordlist association order
    **Validates: Requirements 44.1, 44.2, 44.3**

    FOR ALL marker counts M >= 1 and supplied wordlist sequences of length
    1..M, ``associate_wordlists`` returns exactly M lists where the i-th list is
    the i-th supplied wordlist when it exists and otherwise the last supplied
    wordlist, preserving left-to-right marker order. Matches the independent
    closed-form oracle.
    """
    markers, wordlists = data
    result = associate_wordlists(markers, wordlists)

    # Returns exactly one Marker_Wordlist per Marker_Position (Req 44.1).
    assert len(result) == len(markers)

    # Order-preserving, index-paired, last-list fallback (Reqs 44.1, 44.2, 44.3).
    assert result == _expected_association(len(markers), wordlists)

    # Left-to-right order alignment: result[markers[i].order] is the wordlist
    # resolved for marker i (markers already carry 0-based order).
    for i, marker in enumerate(markers):
        assert marker.order == i
        expected = wordlists[i] if i < len(wordlists) else wordlists[-1]
        assert result[marker.order] == list(expected)


@given(
    n_markers=st.integers(min_value=2, max_value=6),
    single=_wordlist_strategy,
)
@settings(max_examples=150, deadline=None)
def test_single_wordlist_broadcasts_to_every_marker(n_markers, single):
    """
    # Feature: owasp-complete-purple-teaming-cicd, Property 27: Per-marker
    # wordlist association order
    **Validates: Requirement 44.3**

    Boundary of the fallback rule: with exactly one supplied wordlist and two or
    more Marker_Positions, that single wordlist becomes the Marker_Wordlist of
    EVERY position.
    """
    url = "/" + "FUZZ/" * n_markers
    markers = find_markers(url, _KEYWORD)
    assert len(markers) == n_markers

    result = associate_wordlists(markers, [single])

    assert len(result) == n_markers
    assert all(entry == list(single) for entry in result)


@given(
    n_markers=st.integers(min_value=1, max_value=6),
    wordlists=st.lists(_wordlist_strategy, min_size=1, max_size=6),
)
@settings(max_examples=200, deadline=None)
def test_full_pairing_when_counts_equal(n_markers, wordlists):
    """
    # Feature: owasp-complete-purple-teaming-cicd, Property 27: Per-marker
    # wordlist association order
    **Validates: Requirements 44.1, 44.2**

    When exactly one wordlist is supplied per marker (K == M), the i-th marker
    gets the i-th supplied wordlist verbatim with no fallback in play; when
    K < M the remaining positions all take the last supplied wordlist. Only the
    in-scope band ``1 <= K <= M`` is exercised.
    """
    # Constrain to the in-scope band 1 <= len(wordlists) <= n_markers.
    if len(wordlists) > n_markers:
        wordlists = wordlists[:n_markers]

    url = "/" + "FUZZ/" * n_markers
    markers = find_markers(url, _KEYWORD)

    result = associate_wordlists(markers, wordlists)

    assert result == _expected_association(n_markers, wordlists)
    # The leading K positions are the supplied lists verbatim, in order.
    for i in range(len(wordlists)):
        assert result[i] == list(wordlists[i])
