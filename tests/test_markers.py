"""
Unit tests for positional fuzz marker pure functions.

**Feature: owasp-complete-purple-teaming-cicd, Task 45.1**

Example-based tests pinning down:

- ``validate_fuzz_keyword`` returns valid keywords unchanged and raises
  ``ValueError`` naming empty/whitespace-only input (Requirement 39.5)
- ``find_markers`` returns one non-overlapping ``MarkerPosition`` per literal
  occurrence with ``url[start:end] == keyword`` and ``[]`` when absent
  (Requirements 39.2, 39.3, 39.4)
- ``classify_marker_region`` labels the six URL regions using the worked
  examples from Requirement 40 (informational classification)
"""

import pytest

from modules.fuzzing.markers import (
    FuzzMode,
    MarkerPosition,
    associate_wordlists,
    classify_marker_region,
    find_markers,
    generate_marker_candidates,
    parse_fuzz_mode,
    substitute_markers,
    validate_fuzz_keyword,
)


# --------------------------------------------------------------------------- #
# validate_fuzz_keyword (Requirement 39.5)
# --------------------------------------------------------------------------- #
class TestValidateFuzzKeyword:
    def test_returns_valid_keyword_unchanged(self):
        assert validate_fuzz_keyword("FUZZ") == "FUZZ"
        assert validate_fuzz_keyword("__X__") == "__X__"
        assert validate_fuzz_keyword(" wrapped ".strip()) == "wrapped"

    def test_empty_string_raises_naming_keyword(self):
        with pytest.raises(ValueError) as exc:
            validate_fuzz_keyword("")
        assert repr("") in str(exc.value)

    @pytest.mark.parametrize("ws", [" ", "   ", "\t", "\n", " \t\n "])
    def test_whitespace_only_raises_naming_keyword(self, ws):
        with pytest.raises(ValueError) as exc:
            validate_fuzz_keyword(ws)
        assert repr(ws) in str(exc.value)


# --------------------------------------------------------------------------- #
# find_markers (Requirements 39.2, 39.3, 39.4)
# --------------------------------------------------------------------------- #
class TestFindMarkers:
    def test_no_occurrence_returns_empty(self):
        assert find_markers("/api/v1/users", "FUZZ") == []

    def test_single_occurrence(self):
        markers = find_markers("/vFUZZ/users", "FUZZ")
        assert len(markers) == 1
        m = markers[0]
        assert m.start == 2 and m.end == 6
        assert m.order == 0

    def test_offsets_satisfy_slice_invariant(self):
        url = "/api/FUZZ/thing/FUZZ.txt?id=FUZZ"
        markers = find_markers(url, "FUZZ")
        for m in markers:
            assert url[m.start : m.end] == "FUZZ"

    def test_counts_non_overlapping_occurrences(self):
        url = "/FUZZ/FUZZ/FUZZ"
        markers = find_markers(url, "FUZZ")
        assert len(markers) == 3
        assert [m.order for m in markers] == [0, 1, 2]

    def test_overlapping_keyword_advances_by_length(self):
        # "aa" over "aaaa" yields two non-overlapping matches, not three.
        markers = find_markers("aaaa", "aa")
        assert len(markers) == 2
        assert [(m.start, m.end) for m in markers] == [(0, 2), (2, 4)]

    def test_default_keyword_is_fuzz(self):
        assert len(find_markers("/vFUZZ/users")) == 1

    def test_zero_length_keyword_returns_empty(self):
        assert find_markers("/anything", "") == []

    def test_custom_keyword(self):
        markers = find_markers("/v§/users", "§")
        assert len(markers) == 1
        assert markers[0].order == 0


# --------------------------------------------------------------------------- #
# classify_marker_region (Requirement 40 worked examples)
# --------------------------------------------------------------------------- #
class TestClassifyMarkerRegion:
    def _region_for(self, url, keyword="FUZZ"):
        markers = find_markers(url, keyword)
        assert len(markers) == 1
        return markers[0].region

    def test_path_substring(self):
        # /vFUZZ/users -> FUZZ is a proper substring inside a non-final segment
        assert self._region_for("/vFUZZ/users") == "path-substring"

    def test_full_segment(self):
        # /api/FUZZ/users -> FUZZ spans an entire path segment
        assert self._region_for("/api/FUZZ/users") == "full-segment"

    def test_query_value(self):
        # /?id=FUZZ -> FUZZ is a query-parameter value
        assert self._region_for("/?id=FUZZ") == "query-value"

    def test_query_name(self):
        # /?FUZZ=1 -> FUZZ is a query-parameter name
        assert self._region_for("/?FUZZ=1") == "query-name"

    def test_filename(self):
        # /FUZZ.txt -> FUZZ is the filename portion before the extension
        assert self._region_for("/FUZZ.txt") == "filename"

    def test_extension(self):
        # /backup.FUZZ -> FUZZ is the file extension portion
        assert self._region_for("/backup.FUZZ") == "extension"

    def test_absolute_url_query_value(self):
        assert self._region_for("https://host/api?id=FUZZ") == "query-value"

    def test_absolute_url_full_segment(self):
        assert self._region_for("https://host/api/FUZZ/users") == "full-segment"

    def test_second_query_param_value(self):
        assert self._region_for("/?a=1&id=FUZZ") == "query-value"

    def test_second_query_param_name(self):
        assert self._region_for("/?a=1&FUZZ=2") == "query-name"


class TestMarkerPositionModel:
    def test_is_frozen_and_hashable(self):
        m = MarkerPosition(start=1, end=5, region="filename", order=0)
        with pytest.raises(Exception):
            m.start = 9  # frozen dataclass rejects assignment
        # hashable => usable in sets/dicts
        assert m in {m}


# --------------------------------------------------------------------------- #
# substitute_markers (Requirement 40 worked examples, Task 45.2)
# --------------------------------------------------------------------------- #
class TestSubstituteMarkers:
    def _substitute(self, url, values, keyword="FUZZ"):
        markers = find_markers(url, keyword)
        return substitute_markers(url, markers, values)

    # --- The six worked examples from Requirement 40 --------------------- #
    def test_path_substring_example(self):
        # /vFUZZ/users + "2" -> /v2/users (Requirement 40.2)
        assert self._substitute("/vFUZZ/users", ["2"]) == "/v2/users"

    def test_full_segment_example(self):
        # /api/FUZZ/users + "admin" -> /api/admin/users (Requirement 40.3)
        assert self._substitute("/api/FUZZ/users", ["admin"]) == "/api/admin/users"

    def test_query_value_example(self):
        # /?id=FUZZ + "5" -> /?id=5 (Requirement 40.4)
        assert self._substitute("/?id=FUZZ", ["5"]) == "/?id=5"

    def test_query_name_example(self):
        # /?FUZZ=1 + "debug" -> /?debug=1 (Requirement 40.5)
        assert self._substitute("/?FUZZ=1", ["debug"]) == "/?debug=1"

    def test_filename_example(self):
        # /FUZZ.txt + "config" -> /config.txt (Requirement 40.6)
        assert self._substitute("/FUZZ.txt", ["config"]) == "/config.txt"

    def test_extension_example(self):
        # /backup.FUZZ + "zip" -> /backup.zip (Requirement 40.7)
        assert self._substitute("/backup.FUZZ", ["zip"]) == "/backup.zip"

    # --- Empty markers => URL unchanged (Requirement 40.8) --------------- #
    def test_no_markers_returns_url_unchanged(self):
        assert substitute_markers("/api/v1/users", [], []) == "/api/v1/users"

    def test_no_markers_ignores_provided_values(self):
        # With no markers the URL is returned untouched regardless of values.
        assert substitute_markers("/api/v1/users", [], ["x"]) == "/api/v1/users"

    # --- Multiple markers spliced right-to-left (Requirement 40.1) ------- #
    def test_multiple_markers_all_replaced(self):
        url = "/api/FUZZ/thing/FUZZ.txt?id=FUZZ"
        markers = find_markers(url, "FUZZ")
        out = substitute_markers(url, markers, ["admin", "config", "5"])
        assert out == "/api/admin/thing/config.txt?id=5"

    def test_multiple_markers_preserve_surrounding_bytes(self):
        url = "/FUZZ/FUZZ/FUZZ"
        markers = find_markers(url, "FUZZ")
        out = substitute_markers(url, markers, ["a", "bb", "ccc"])
        assert out == "/a/bb/ccc"

    def test_repeated_value_positions_independent(self):
        # Same marker text, different candidate per position (pairing by index).
        url = "/vFUZZ/vFUZZ"
        markers = find_markers(url, "FUZZ")
        out = substitute_markers(url, markers, ["1", "2"])
        assert out == "/v1/v2"

    def test_absolute_url_query_value(self):
        url = "https://host/api?id=FUZZ"
        markers = find_markers(url, "FUZZ")
        assert substitute_markers(url, markers, ["5"]) == "https://host/api?id=5"

    def test_empty_value_removes_marked_span(self):
        # Replacing with "" splices out only the marked span, keeping the rest.
        assert self._substitute("/vFUZZ/users", [""]) == "/v/users"

    # --- Count mismatch raises ValueError naming both counts ------------- #
    def test_too_few_values_raises_naming_counts(self):
        url = "/FUZZ/FUZZ"
        markers = find_markers(url, "FUZZ")
        with pytest.raises(ValueError) as exc:
            substitute_markers(url, markers, ["only-one"])
        msg = str(exc.value)
        assert "2" in msg and "1" in msg

    def test_too_many_values_raises_naming_counts(self):
        url = "/vFUZZ/users"
        markers = find_markers(url, "FUZZ")
        with pytest.raises(ValueError) as exc:
            substitute_markers(url, markers, ["a", "b"])
        msg = str(exc.value)
        assert "1" in msg and "2" in msg


# --------------------------------------------------------------------------- #
# associate_wordlists (Requirements 44.1, 44.2, 44.3, 44.4, Task 45.3)
# --------------------------------------------------------------------------- #
class TestAssociateWordlists:
    def _markers(self, url, keyword="FUZZ"):
        return find_markers(url, keyword)

    # --- Requirement 44.1: i-th wordlist pairs with i-th marker ---------- #
    def test_pairs_by_order_left_to_right(self):
        markers = self._markers("/api/FUZZ/thing/FUZZ.txt?id=FUZZ")
        assert len(markers) == 3
        wordlists = [["a1", "a2"], ["b1"], ["c1", "c2", "c3"]]
        out = associate_wordlists(markers, wordlists)
        assert out == [["a1", "a2"], ["b1"], ["c1", "c2", "c3"]]

    def test_single_marker_single_wordlist(self):
        markers = self._markers("/vFUZZ/users")
        out = associate_wordlists(markers, [["1", "2", "3"]])
        assert out == [["1", "2", "3"]]

    def test_returns_one_list_per_marker(self):
        markers = self._markers("/FUZZ/FUZZ/FUZZ")
        out = associate_wordlists(markers, [["x"], ["y"], ["z"]])
        assert len(out) == len(markers) == 3

    # --- Requirement 44.3: single wordlist applies to all markers -------- #
    def test_single_wordlist_used_for_every_marker(self):
        markers = self._markers("/FUZZ/FUZZ/FUZZ")
        out = associate_wordlists(markers, [["shared"]])
        assert out == [["shared"], ["shared"], ["shared"]]

    # --- Requirement 44.2: last supplied list fills remaining markers ---- #
    def test_fewer_wordlists_reuse_last_supplied(self):
        markers = self._markers("/FUZZ/FUZZ/FUZZ/FUZZ")
        wordlists = [["first"], ["second"]]
        out = associate_wordlists(markers, wordlists)
        # first->list0, second->list1, remaining two reuse the LAST (second).
        assert out == [["first"], ["second"], ["second"], ["second"]]

    def test_exact_count_pairs_one_to_one(self):
        markers = self._markers("/FUZZ/FUZZ")
        out = associate_wordlists(markers, [["a"], ["b"]])
        assert out == [["a"], ["b"]]

    # --- Requirement 44.4: more wordlists than markers is a mismatch ----- #
    def test_too_many_wordlists_raises_naming_counts(self):
        markers = self._markers("/vFUZZ/users")  # one marker
        with pytest.raises(ValueError) as exc:
            associate_wordlists(markers, [["a"], ["b"]])
        msg = str(exc.value)
        assert "1" in msg and "2" in msg

    def test_two_markers_three_wordlists_raises(self):
        markers = self._markers("/FUZZ/FUZZ")
        with pytest.raises(ValueError) as exc:
            associate_wordlists(markers, [["a"], ["b"], ["c"]])
        msg = str(exc.value)
        assert "2" in msg and "3" in msg

    # --- Edge cases ------------------------------------------------------ #
    def test_no_markers_returns_empty(self):
        assert associate_wordlists([], []) == []

    def test_markers_but_no_wordlists_raises_naming_counts(self):
        markers = self._markers("/vFUZZ/users")
        with pytest.raises(ValueError) as exc:
            associate_wordlists(markers, [])
        msg = str(exc.value)
        assert "0" in msg and "1" in msg

    def test_returned_lists_are_independent_copies(self):
        markers = self._markers("/FUZZ/FUZZ")
        shared = ["v"]
        out = associate_wordlists(markers, [shared])
        # Each associated entry is a fresh list, not an alias of the input.
        out[0].append("mutated")
        assert shared == ["v"]
        assert out[1] == ["v"]

    def test_empty_wordlist_entries_preserved(self):
        # An empty associated list is allowed here (Pitchfork emptiness is
        # validated downstream, not by association).
        markers = self._markers("/FUZZ/FUZZ")
        out = associate_wordlists(markers, [[], ["b"]])
        assert out == [[], ["b"]]


# --------------------------------------------------------------------------- #
# parse_fuzz_mode (Requirements 43.1, 46.5, Task 45.4)
# --------------------------------------------------------------------------- #
class TestParseFuzzMode:
    def test_none_defaults_to_clusterbomb(self):
        assert parse_fuzz_mode(None) == FuzzMode.CLUSTERBOMB

    def test_clusterbomb_token(self):
        assert parse_fuzz_mode("clusterbomb") == FuzzMode.CLUSTERBOMB

    def test_pitchfork_token(self):
        assert parse_fuzz_mode("pitchfork") == FuzzMode.PITCHFORK

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("CLUSTERBOMB", FuzzMode.CLUSTERBOMB),
            ("Pitchfork", FuzzMode.PITCHFORK),
            ("  clusterbomb  ", FuzzMode.CLUSTERBOMB),
            ("PitchFork", FuzzMode.PITCHFORK),
        ],
    )
    def test_case_insensitive_and_trimmed(self, raw, expected):
        assert parse_fuzz_mode(raw) == expected

    @pytest.mark.parametrize("bad", ["sniper", "battering-ram", "", "cluster bomb"])
    def test_invalid_value_raises_naming_mode(self, bad):
        with pytest.raises(ValueError) as exc:
            parse_fuzz_mode(bad)
        assert repr(bad) in str(exc.value)

    def test_enum_values_are_config_native_strings(self):
        # FuzzMode subclasses str, so .value is a plain string usable in config.
        assert FuzzMode.CLUSTERBOMB.value == "clusterbomb"
        assert FuzzMode.PITCHFORK.value == "pitchfork"


# --------------------------------------------------------------------------- #
# generate_marker_candidates (Requirements 41, 42, 43, Task 45.4)
# --------------------------------------------------------------------------- #
class TestGenerateMarkerCandidates:
    def _markers(self, url, keyword="FUZZ"):
        return find_markers(url, keyword)

    # --- Single marker reduces to a straight sweep (Requirement 41) ------ #
    def test_single_marker_yields_one_per_entry(self):
        url = "/vFUZZ/users"
        markers = self._markers(url)
        out = list(
            generate_marker_candidates(
                url, markers, [["1", "2", "3"]], FuzzMode.CLUSTERBOMB
            )
        )
        assert out == ["/v1/users", "/v2/users", "/v3/users"]

    def test_single_marker_count_equals_wordlist_size(self):
        url = "/FUZZ.txt"
        markers = self._markers(url)
        wordlist = [str(i) for i in range(7)]
        out = list(
            generate_marker_candidates(url, markers, [wordlist], FuzzMode.CLUSTERBOMB)
        )
        assert len(out) == 7

    # --- Clusterbomb = cartesian product (Requirements 42.1, 42.2, 42.5) - #
    def test_clusterbomb_cartesian_product_values(self):
        url = "/api/FUZZ/FUZZ.txt"
        markers = self._markers(url)
        out = list(
            generate_marker_candidates(
                url, markers, [["a", "b"], ["1", "2"]], FuzzMode.CLUSTERBOMB
            )
        )
        assert out == [
            "/api/a/1.txt",
            "/api/a/2.txt",
            "/api/b/1.txt",
            "/api/b/2.txt",
        ]

    def test_clusterbomb_count_is_product_of_sizes(self):
        url = "/FUZZ/FUZZ/FUZZ"
        markers = self._markers(url)
        wordlists = [["a", "b", "c"], ["1", "2"], ["x", "y", "z", "w"]]
        out = list(
            generate_marker_candidates(url, markers, wordlists, FuzzMode.CLUSTERBOMB)
        )
        assert len(out) == 3 * 2 * 4

    def test_clusterbomb_is_default_when_mode_parsed_from_none(self):
        url = "/api/FUZZ/FUZZ"
        markers = self._markers(url)
        mode = parse_fuzz_mode(None)
        out = list(
            generate_marker_candidates(url, markers, [["a", "b"], ["1"]], mode)
        )
        assert out == ["/api/a/1", "/api/b/1"]

    # --- Pitchfork = index-wise zip (Requirements 43.2, 43.3, 43.5) ------ #
    def test_pitchfork_pairs_index_wise(self):
        url = "/api/FUZZ/FUZZ.txt"
        markers = self._markers(url)
        out = list(
            generate_marker_candidates(
                url, markers, [["a", "b", "c"], ["1", "2", "3"]], FuzzMode.PITCHFORK
            )
        )
        assert out == ["/api/a/1.txt", "/api/b/2.txt", "/api/c/3.txt"]

    def test_pitchfork_stops_at_shortest_list(self):
        url = "/FUZZ/FUZZ/FUZZ"
        markers = self._markers(url)
        wordlists = [["a", "b", "c"], ["1", "2"], ["x", "y", "z", "w"]]
        out = list(
            generate_marker_candidates(url, markers, wordlists, FuzzMode.PITCHFORK)
        )
        # min(3, 2, 4) == 2 candidates.
        assert out == ["/a/1/x", "/b/2/y"]
        assert len(out) == 2

    def test_pitchfork_count_is_min_of_sizes(self):
        url = "/FUZZ/FUZZ"
        markers = self._markers(url)
        out = list(
            generate_marker_candidates(
                url, markers, [["a"] * 5, ["b"] * 3], FuzzMode.PITCHFORK
            )
        )
        assert len(out) == 3

    # --- Lazy iteration (Requirements 42.3/42.4/43.4 budget cut-off) ----- #
    def test_returns_lazy_iterator(self):
        url = "/vFUZZ/users"
        markers = self._markers(url)
        gen = generate_marker_candidates(
            url, markers, [["1", "2", "3"]], FuzzMode.CLUSTERBOMB
        )
        # It is an iterator, not a materialized list; taking the first value
        # does not require exhausting the whole space.
        assert iter(gen) is gen
        assert next(gen) == "/v1/users"

    def test_lazy_stops_without_full_consumption(self):
        # A huge clusterbomb space can be partially drained cheaply.
        url = "/FUZZ/FUZZ"
        markers = self._markers(url)
        big = [str(i) for i in range(1000)]
        gen = generate_marker_candidates(url, markers, [big, big], FuzzMode.CLUSTERBOMB)
        first_three = [next(gen) for _ in range(3)]
        assert first_three == ["/0/0", "/0/1", "/0/2"]
