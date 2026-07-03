"""
Example-based unit tests for per-marker wordlist association and its
fewer-wordlists-than-markers fallbacks.

**Feature: owasp-complete-purple-teaming-cicd, Task 49.2**

These tests pin down the concrete association rules of
``modules.fuzzing.associate_wordlists`` (the real pure function; no network, no
mocks), exercising markers detected by the real ``find_markers``:

- Left-to-right association pairs the i-th ``--wordlist`` with the i-th
  Marker_Position, so the first wordlist is the Marker_Wordlist of the first
  marker (Requirement 44.1).
- A single supplied wordlist and two or more Marker_Positions uses that single
  wordlist as the Marker_Wordlist of every position (Requirement 44.3).
- Fewer wordlists than Marker_Positions reuse the LAST supplied wordlist for
  every remaining position that has no explicitly associated wordlist
  (Requirement 44.2).

These example-based tests complement the property-based coverage required by
Requirement 47.1.
"""

import pytest

from modules.fuzzing.markers import (
    associate_wordlists,
    find_markers,
)


def _markers(url, keyword="FUZZ"):
    """Detect markers in ``url`` (left-to-right, non-overlapping)."""
    return find_markers(url, keyword)


# --------------------------------------------------------------------------- #
# Left-to-right association: i-th wordlist -> i-th marker (Requirement 44.1)
# --------------------------------------------------------------------------- #
class TestLeftToRightAssociation:
    """The first supplied wordlist is the Marker_Wordlist of the first
    Marker_Position, the second of the second, and so on in the left-to-right
    order the Fuzz_Markers occur in the target URL."""

    def test_two_markers_pair_by_index(self):
        url = "/api/FUZZ/FUZZ.txt"
        markers = _markers(url)
        assert len(markers) == 2
        versions = ["v1", "v2"]
        general = ["admin", "login"]
        associated = associate_wordlists(markers, [versions, general])
        # One resolved Marker_Wordlist per Marker_Position, paired by order.
        assert associated == [versions, general]

    def test_three_markers_pair_by_index(self):
        url = "/FUZZ/FUZZ/FUZZ"
        markers = _markers(url)
        assert len(markers) == 3
        first = ["a"]
        second = ["b", "c"]
        third = ["d", "e", "f"]
        associated = associate_wordlists(markers, [first, second, third])
        assert associated == [first, second, third]

    def test_result_has_one_entry_per_marker(self):
        url = "/api/FUZZ/FUZZ.txt"
        markers = _markers(url)
        associated = associate_wordlists(markers, [["1"], ["2"]])
        assert len(associated) == len(markers)

    def test_result_entries_are_materialized_lists(self):
        # A generator/tuple source is materialized to a list so downstream
        # sweeps can iterate it repeatably.
        url = "/api/FUZZ/FUZZ.txt"
        markers = _markers(url)
        associated = associate_wordlists(markers, [("v1", "v2"), ("x", "y")])
        assert associated == [["v1", "v2"], ["x", "y"]]
        assert all(isinstance(entry, list) for entry in associated)

    def test_single_marker_single_wordlist(self):
        url = "/vFUZZ/users"
        markers = _markers(url)
        assert len(markers) == 1
        associated = associate_wordlists(markers, [["1", "2", "3"]])
        assert associated == [["1", "2", "3"]]

    def test_no_markers_yields_empty_association(self):
        # No Marker_Positions => nothing to associate.
        markers = _markers("/api/users")
        assert markers == []
        assert associate_wordlists(markers, []) == []


# --------------------------------------------------------------------------- #
# Single wordlist, many markers => that list for every marker (Req 44.3)
# --------------------------------------------------------------------------- #
class TestSingleWordlistAppliesToEveryMarker:
    def test_one_wordlist_two_markers(self):
        url = "/api/FUZZ/FUZZ.txt"
        markers = _markers(url)
        assert len(markers) == 2
        shared = ["admin", "login", "config"]
        associated = associate_wordlists(markers, [shared])
        # Every Marker_Position resolves to the single supplied wordlist.
        assert associated == [shared, shared]

    def test_one_wordlist_three_markers(self):
        url = "/FUZZ/FUZZ/FUZZ"
        markers = _markers(url)
        assert len(markers) == 3
        shared = ["x", "y"]
        associated = associate_wordlists(markers, [shared])
        assert associated == [shared, shared, shared]
        assert len(associated) == 3

    @pytest.mark.parametrize("n_markers", [2, 3, 4, 5])
    def test_one_wordlist_applies_to_all_positions(self, n_markers):
        url = "/" + "/".join(["FUZZ"] * n_markers)
        markers = _markers(url)
        assert len(markers) == n_markers
        shared = ["a", "b"]
        associated = associate_wordlists(markers, [shared])
        assert associated == [shared] * n_markers


# --------------------------------------------------------------------------- #
# Fewer wordlists than markers => LAST list fills the remaining (Req 44.2)
# --------------------------------------------------------------------------- #
class TestLastWordlistFillsRemaining:
    def test_two_wordlists_three_markers_reuses_last(self):
        url = "/FUZZ/FUZZ/FUZZ"
        markers = _markers(url)
        assert len(markers) == 3
        first = ["v1", "v2"]
        last = ["admin", "login"]
        associated = associate_wordlists(markers, [first, last])
        # Positions 0 and 1 pair by index; position 2 has no explicit list and
        # reuses the LAST supplied wordlist.
        assert associated == [first, last, last]

    def test_three_wordlists_five_markers_reuses_last(self):
        url = "/" + "/".join(["FUZZ"] * 5)
        markers = _markers(url)
        assert len(markers) == 5
        w0 = ["a"]
        w1 = ["b"]
        w2 = ["c"]
        associated = associate_wordlists(markers, [w0, w1, w2])
        # First three pair by index; positions 3 and 4 reuse the last list (w2).
        assert associated == [w0, w1, w2, w2, w2]

    def test_explicit_positions_are_not_overwritten_by_fallback(self):
        url = "/FUZZ/FUZZ/FUZZ/FUZZ"
        markers = _markers(url)
        assert len(markers) == 4
        w0 = ["0"]
        w1 = ["1"]
        associated = associate_wordlists(markers, [w0, w1])
        # Only positions without an explicit list get the last wordlist; the
        # explicitly paired positions keep their own list.
        assert associated[0] == w0
        assert associated[1] == w1
        assert associated[2] == w1
        assert associated[3] == w1

    @pytest.mark.parametrize(
        "n_wordlists,n_markers",
        [(2, 3), (2, 4), (3, 4), (2, 5), (4, 6)],
    )
    def test_fill_count_and_last_reuse(self, n_wordlists, n_markers):
        url = "/" + "/".join(["FUZZ"] * n_markers)
        markers = _markers(url)
        assert len(markers) == n_markers
        wordlists = [[f"w{i}"] for i in range(n_wordlists)]
        associated = associate_wordlists(markers, wordlists)
        # One entry per Marker_Position.
        assert len(associated) == n_markers
        # Index-paired positions keep their own list.
        for i in range(n_wordlists):
            assert associated[i] == wordlists[i]
        # Remaining positions reuse the LAST supplied wordlist.
        for i in range(n_wordlists, n_markers):
            assert associated[i] == wordlists[-1]
