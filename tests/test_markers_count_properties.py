"""
Property-Based Tests for positional fuzz marker detection.

# Feature: owasp-complete-purple-teaming-cicd, Property 25: Marker count equals
# non-overlapping literal occurrences

Validates Property 25 from design.md for ``modules.fuzzing.markers.find_markers``:

FOR ALL raw target URLs and all valid Fuzz_Keywords, the number of
``MarkerPosition`` records returned by ``find_markers(url, keyword)`` equals the
number of non-overlapping, left-to-right literal occurrences of the keyword in
the URL; each returned marker satisfies ``url[m.start:m.end] == keyword`` with
strictly increasing, non-overlapping spans; and when the keyword does not occur
``find_markers`` returns the empty list.

The expected non-overlapping occurrence count is computed INDEPENDENTLY of
``find_markers`` (via ``str.count``, which counts non-overlapping occurrences,
and via a manual left-to-right cursor loop) rather than by reusing the
function under test.

Validates: Requirements 39.2, 39.4, 39.3

These tests mirror the established Hypothesis conventions in
``tests/test_baseline_properties.py``.
"""

from hypothesis import assume, given, settings, strategies as st

from modules.fuzzing.markers import find_markers, validate_fuzz_keyword


# --------------------------------------------------------------------------- #
# Independent oracles (do NOT reuse find_markers' internal logic)
# --------------------------------------------------------------------------- #
def _expected_count(url: str, keyword: str) -> int:
    """Non-overlapping left-to-right occurrence count, computed independently.

    ``str.count`` counts non-overlapping occurrences of a substring, which is
    exactly the semantics ``find_markers`` must implement (advance the scan
    cursor by ``len(keyword)`` after every match). Used as the ground-truth
    oracle for the marker count.
    """
    return url.count(keyword)


def _expected_spans(url: str, keyword: str):
    """Non-overlapping ``(start, end)`` spans via a manual cursor loop.

    An independent re-derivation of the expected marker spans used to
    cross-check both the count and the slice invariant without relying on the
    implementation under test.
    """
    spans = []
    cursor = 0
    step = len(keyword)
    while True:
        idx = url.find(keyword, cursor)
        if idx == -1:
            break
        spans.append((idx, idx + step))
        cursor = idx + step  # advance past the whole match => non-overlapping
    return spans


# --------------------------------------------------------------------------- #
# Strategies
# --------------------------------------------------------------------------- #
# A small alphabet biased toward characters that appear in the sampled keywords
# so that generated URLs contain occurrences frequently, exercising the
# counting branch. Includes URL structural characters and a non-ASCII char to
# match the codebase's Unicode-friendly conventions.
_URL_ALPHABET = "abFUZAX/.?=&-_§0"

# Curated interesting keywords plus arbitrary short valid keywords. "AA" and
# "aa" specifically stress non-overlapping counting (e.g. "AA" in "AAAA" => 2).
_valid_short_keyword = st.text(
    alphabet="abFUZAX§", min_size=1, max_size=5
).filter(lambda k: k.strip() != "")

keyword_strategy = st.one_of(
    st.sampled_from(["FUZZ", "AA", "aa", "X", "§", "ab", "FU"]),
    _valid_short_keyword,
)

url_strategy = st.text(alphabet=_URL_ALPHABET, min_size=0, max_size=60)


@st.composite
def url_with_guaranteed_occurrences(draw):
    """Build a URL by interleaving keyword copies between random fillers.

    Guarantees the keyword appears in the URL so the counting/span branch is
    always exercised. The expected count is still derived independently with
    ``str.count`` (boundary effects between fillers and copies are handled by
    the oracle, never assumed).
    """
    keyword = draw(keyword_strategy)
    n = draw(st.integers(min_value=1, max_value=5))
    fillers = draw(
        st.lists(
            st.text(alphabet=_URL_ALPHABET, min_size=0, max_size=8),
            min_size=n + 1,
            max_size=n + 1,
        )
    )
    parts = [fillers[0]]
    for i in range(n):
        parts.append(keyword)
        parts.append(fillers[i + 1])
    return "".join(parts), keyword


def _assert_marker_invariants(url: str, keyword: str):
    """Assert every documented invariant of ``find_markers`` for one input."""
    markers = find_markers(url, keyword)

    # (1) Count equals the independently computed non-overlapping occurrences.
    assert len(markers) == _expected_count(url, keyword)

    # (2) Spans match the independent cursor-loop derivation, in order.
    assert [(m.start, m.end) for m in markers] == _expected_spans(url, keyword)

    prev_start = -1
    prev_end = 0
    for i, m in enumerate(markers):
        # (3) Slice invariant: the marked span is exactly the keyword.
        assert url[m.start : m.end] == keyword
        # (4) 0-based left-to-right order index.
        assert m.order == i
        # (5) Strictly increasing starts.
        assert m.start > prev_start
        # (6) Non-overlapping: this span starts at or after the previous end.
        assert m.start >= prev_end
        prev_start = m.start
        prev_end = m.end


# --------------------------------------------------------------------------- #
# Property 25
# --------------------------------------------------------------------------- #
@given(url=url_strategy, keyword=keyword_strategy)
@settings(max_examples=250, deadline=None)
def test_marker_count_matches_non_overlapping_occurrences(url, keyword):
    """
    # Feature: owasp-complete-purple-teaming-cicd, Property 25: Marker count
    # equals non-overlapping literal occurrences
    **Validates: Requirements 39.2, 39.4**

    FOR ALL raw URLs and valid keywords, ``len(find_markers(url, keyword))``
    equals the independently computed non-overlapping occurrence count, and
    every returned marker has ``url[start:end] == keyword`` with strictly
    increasing, non-overlapping spans.
    """
    # Only valid Fuzz_Keywords are in scope (non-empty, not whitespace-only).
    assert validate_fuzz_keyword(keyword) == keyword
    _assert_marker_invariants(url, keyword)


@given(data=url_with_guaranteed_occurrences())
@settings(max_examples=250, deadline=None)
def test_marker_invariants_when_keyword_present(data):
    """
    # Feature: owasp-complete-purple-teaming-cicd, Property 25: Marker count
    # equals non-overlapping literal occurrences
    **Validates: Requirements 39.2, 39.4**

    With a keyword spliced into the URL at least once, the count still equals
    the independent non-overlapping oracle and every span/order invariant
    holds. Exercises the branch where at least one marker is produced.
    """
    url, keyword = data
    # At least one occurrence exists by construction.
    assert _expected_count(url, keyword) >= 1
    _assert_marker_invariants(url, keyword)


@given(
    ch=st.sampled_from(["A", "a", "§", "x"]),
    k=st.integers(min_value=1, max_value=5),
    n=st.integers(min_value=0, max_value=20),
)
@settings(max_examples=200, deadline=None)
def test_overlapping_keyword_counted_non_overlapping(ch, k, n):
    """
    # Feature: owasp-complete-purple-teaming-cicd, Property 25: Marker count
    # equals non-overlapping literal occurrences
    **Validates: Requirement 39.4**

    A repeated-character keyword over a repeated-character URL (e.g. ``AA`` in
    ``AAAA``) is counted NON-overlapping: ``len(find_markers) == n // k`` and
    matches the ``str.count`` oracle. This pins down that overlapping textual
    matches never inflate the marker count.
    """
    keyword = ch * k
    url = ch * n
    markers = find_markers(url, keyword)
    assert len(markers) == n // k
    assert len(markers) == _expected_count(url, keyword)
    _assert_marker_invariants(url, keyword)


@given(url=url_strategy, keyword=keyword_strategy)
@settings(max_examples=200, deadline=None)
def test_empty_list_when_keyword_absent(url, keyword):
    """
    # Feature: owasp-complete-purple-teaming-cicd, Property 25: Marker count
    # equals non-overlapping literal occurrences
    **Validates: Requirement 39.3**

    FOR ALL URLs that do not contain the keyword, ``find_markers`` returns the
    empty list.
    """
    assume(keyword not in url)
    assert find_markers(url, keyword) == []
