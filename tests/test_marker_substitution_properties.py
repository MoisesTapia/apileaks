"""
Property-Based Tests for positional fuzz marker substitution.

# Feature: owasp-complete-purple-teaming-cicd, Property 26: Substitution changes
# only marked spans and preserves the rest

Validates Property 26 from design.md for
``modules.fuzzing.markers.substitute_markers``:

FOR ALL raw target URLs containing at least one Fuzz_Marker and all candidate
value tuples (one value per marker), ``substitute_markers(url, markers, values)``
produces a string in which (a) each marked span has been replaced by its paired
candidate value and (b) every character of the URL outside the marked spans is
preserved byte-for-byte. Equivalently, deleting the marked/substituted regions
from the original and from the result leaves identical remainders, so no other
path segment, query-parameter name, or query-parameter value is altered. As the
boundary case, when ``markers`` is empty ``substitute_markers`` returns the
target URL unchanged.

The expected output and the preserved remainder are computed INDEPENDENTLY of
``substitute_markers`` (by splitting the raw URL at the marker spans to recover
the fixed inter-marker segments, then interleaving them with the paired values)
rather than by reusing the function under test.

Validates: Requirements 47.3, 40.1, 40.8, 39.3

These tests mirror the established Hypothesis conventions in
``tests/test_markers_count_properties.py`` and
``tests/test_bola_substitution_properties.py``.
"""

from hypothesis import given, settings, strategies as st

from modules.fuzzing.markers import (
    MarkerPosition,
    find_markers,
    substitute_markers,
)


# --------------------------------------------------------------------------- #
# Independent oracles (do NOT reuse substitute_markers' internal logic)
# --------------------------------------------------------------------------- #
def _fixed_segments(url: str, markers):
    """Return the fixed inter-marker segments of ``url``.

    Splitting the raw URL at each marker's ``[start:end)`` span yields
    ``len(markers) + 1`` fixed segments: everything OUTSIDE the marked spans,
    in left-to-right order. These are the bytes that substitution must preserve
    verbatim. Computed directly from the raw URL string, independent of
    ``substitute_markers``.
    """
    ordered = sorted(markers, key=lambda m: m.start)
    segments = []
    prev = 0
    for m in ordered:
        segments.append(url[prev : m.start])
        prev = m.end
    segments.append(url[prev:])
    return segments


def _expected_substitution(url: str, markers, values) -> str:
    """Independently rebuild the expected substituted URL.

    ``markers[i]`` pairs with ``values[i]`` (markers are already left-to-right
    from ``find_markers``). The expected string interleaves the fixed segments
    with the paired candidate values:

        fixed[0] + values[0] + fixed[1] + values[1] + ... + fixed[N]

    This is an independent re-derivation used as the ground-truth oracle.
    """
    ordered = sorted(zip(markers, values), key=lambda mv: mv[0].start)
    fixed = _fixed_segments(url, markers)
    out = [fixed[0]]
    for i, (_marker, value) in enumerate(ordered):
        out.append(value)
        out.append(fixed[i + 1])
    return "".join(out)


def _result_remainder(url: str, markers, values, result: str) -> str:
    """Delete the substituted value regions from ``result`` independently.

    Computes where each candidate value lands in ``result`` purely from the
    fixed-segment and value lengths (never by inspecting ``substitute_markers``),
    then removes those regions. The bytes that remain are the preserved
    remainder of the actual function output, which must equal the remainder of
    the original URL with the marked spans deleted.
    """
    ordered = sorted(zip(markers, values), key=lambda mv: mv[0].start)
    fixed = _fixed_segments(url, markers)
    remainder = [fixed[0]]
    cursor = len(fixed[0])
    for i, (_marker, value) in enumerate(ordered):
        # Skip the value region [cursor : cursor + len(value)) in result.
        cursor += len(value)
        remainder.append(result[cursor : cursor + len(fixed[i + 1])])
        cursor += len(fixed[i + 1])
    return "".join(remainder)


# --------------------------------------------------------------------------- #
# Strategies
# --------------------------------------------------------------------------- #
# Filler alphabet for spliced URLs: URL structural characters plus a non-ASCII
# char, matching the codebase's Unicode-friendly conventions. It intentionally
# avoids the literal keyword so spliced fillers do not create extra markers; the
# assertions nonetheless rely on find_markers, so accidental extras stay sound.
_FILLER_ALPHABET = "abc/.?=&-_§01"

_KEYWORD = "FUZZ"

# Candidate values may be arbitrary strings, including the empty string and
# strings that themselves contain the keyword (substitution is a single pass).
_value_strategy = st.text(
    alphabet="xyzFUZZ/.?=&-_§0", min_size=0, max_size=8
)

# Curated realistic marker URLs exercising each documented region from
# Requirements 40.2-40.7 (path-substring, full-segment, query-value,
# query-name, filename, extension) plus multi-marker cases.
_realistic_marker_urls = st.sampled_from(
    [
        "https://api.example.com/vFUZZ/users",          # path substring (40.2)
        "https://api.example.com/api/FUZZ/users",       # full segment  (40.3)
        "https://api.example.com/?id=FUZZ",             # query value   (40.4)
        "https://api.example.com/?FUZZ=1",              # query name    (40.5)
        "https://api.example.com/FUZZ.txt",             # filename      (40.6)
        "https://api.example.com/backup.FUZZ",          # extension     (40.7)
        "https://h/a/FUZZ/b/FUZZ.php",                  # two markers
        "/search?q=FUZZ&page=FUZZ",                      # relative, two markers
        "FUZZ",                                          # whole URL is a marker
        "https://h/FUZZ/FUZZ/FUZZ",                      # three markers
    ]
)


@st.composite
def spliced_url_markers_values(draw):
    """Build a URL by interleaving keyword copies between keyword-free fillers.

    Guarantees at least one Fuzz_Marker so the substitution branch is always
    exercised, then draws exactly ``len(find_markers(url))`` candidate values so
    every Marker_Position is paired with one value.
    """
    n = draw(st.integers(min_value=1, max_value=4))
    fillers = draw(
        st.lists(
            st.text(alphabet=_FILLER_ALPHABET, min_size=0, max_size=8),
            min_size=n + 1,
            max_size=n + 1,
        )
    )
    parts = [fillers[0]]
    for i in range(n):
        parts.append(_KEYWORD)
        parts.append(fillers[i + 1])
    url = "".join(parts)
    markers = find_markers(url, _KEYWORD)
    values = draw(
        st.lists(
            _value_strategy, min_size=len(markers), max_size=len(markers)
        )
    )
    return url, markers, values


@st.composite
def realistic_url_markers_values(draw):
    """Draw a curated realistic marker URL plus one value per Marker_Position."""
    url = draw(_realistic_marker_urls)
    markers = find_markers(url, _KEYWORD)
    values = draw(
        st.lists(
            _value_strategy, min_size=len(markers), max_size=len(markers)
        )
    )
    return url, markers, values


def _assert_substitution_invariants(url, markers, values):
    """Assert Property 26 for one (url, markers, values) example."""
    assert len(markers) >= 1  # in scope: at least one Fuzz_Marker
    assert len(values) == len(markers)

    result = substitute_markers(url, list(markers), list(values))

    # (a) The result equals the independently rebuilt interleaving of the fixed
    #     inter-marker segments with the paired candidate values. This proves
    #     both that each marked span carries its value AND that the surrounding
    #     bytes are preserved byte-for-byte (Requirements 40.1, 47.3).
    assert result == _expected_substitution(url, markers, values)

    # (b) Deleting the marked spans from the original and deleting the
    #     substituted value regions from the actual result leaves identical
    #     remainders (the "preserve everything else" formulation of 40.1/47.3).
    original_remainder = "".join(_fixed_segments(url, markers))
    assert _result_remainder(url, markers, values, result) == original_remainder


# --------------------------------------------------------------------------- #
# Property 26
# --------------------------------------------------------------------------- #
@given(data=spliced_url_markers_values())
@settings(max_examples=250, deadline=None)
def test_substitution_changes_only_marked_spans_spliced(data):
    """
    # Feature: owasp-complete-purple-teaming-cicd, Property 26: Substitution
    # changes only marked spans and preserves the rest
    **Validates: Requirements 47.3, 40.1, 39.3**

    FOR ALL spliced URLs with at least one Fuzz_Marker and all candidate value
    tuples, ``substitute_markers`` replaces each marked span with its paired
    value and preserves every non-marked byte, matching the independent
    fixed-segment interleaving oracle.
    """
    url, markers, values = data
    _assert_substitution_invariants(url, markers, values)


@given(data=realistic_url_markers_values())
@settings(max_examples=250, deadline=None)
def test_substitution_preserves_regions_realistic(data):
    """
    # Feature: owasp-complete-purple-teaming-cicd, Property 26: Substitution
    # changes only marked spans and preserves the rest
    **Validates: Requirements 47.3, 40.1**

    Over realistic marker URLs covering path-substring, full-segment,
    query-name, query-value, filename, and extension positions (Requirements
    40.2-40.7), substitution changes only the marked spans and leaves every
    other path segment, query-parameter name, and query-parameter value intact.
    """
    url, markers, values = data
    _assert_substitution_invariants(url, markers, values)


@given(
    url=st.text(
        alphabet=_FILLER_ALPHABET + "FUZ", min_size=0, max_size=60
    )
)
@settings(max_examples=200, deadline=None)
def test_empty_markers_returns_url_unchanged(url):
    """
    # Feature: owasp-complete-purple-teaming-cicd, Property 26: Substitution
    # changes only marked spans and preserves the rest
    **Validates: Requirements 40.8, 39.3**

    Boundary case: when ``markers`` is empty, ``substitute_markers`` returns the
    target URL unchanged, regardless of the supplied value list. This is the
    no-Fuzz_Marker identity that keeps legacy ``dir`` behavior intact.
    """
    assert substitute_markers(url, [], []) == url
    # Extra values are ignored on the empty-markers identity path.
    assert substitute_markers(url, [], ["ignored", "values"]) == url


@given(
    value=_value_strategy,
    prefix=st.text(alphabet=_FILLER_ALPHABET, min_size=0, max_size=10),
    suffix=st.text(alphabet=_FILLER_ALPHABET, min_size=0, max_size=10),
)
@settings(max_examples=150, deadline=None)
def test_single_marker_replaces_exact_span(value, prefix, suffix):
    """
    # Feature: owasp-complete-purple-teaming-cicd, Property 26: Substitution
    # changes only marked spans and preserves the rest
    **Validates: Requirements 47.3, 40.1**

    A single marker embedded between arbitrary keyword-free prefix/suffix is
    replaced by exactly its candidate value, yielding ``prefix + value + suffix``
    with the surrounding bytes preserved.
    """
    url = prefix + _KEYWORD + suffix
    markers = find_markers(url, _KEYWORD)
    # prefix/suffix are keyword-free, so exactly one marker exists.
    assert len(markers) == 1
    result = substitute_markers(url, markers, [value])
    assert result == prefix + value + suffix
