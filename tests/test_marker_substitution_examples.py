"""
Example-based unit tests for positional Fuzz_Marker substitution and the
single/clusterbomb/pitchfork candidate sweeps.

**Feature: owasp-complete-purple-teaming-cicd, Task 49.1**

These tests pin down the concrete, worked examples from the design's
Marker_Substitution table and the candidate-count guarantees of the three
sweep shapes, exercising the real pure functions in
``modules.fuzzing.markers`` (no network, no mocks):

- The six region worked examples of Marker_Substitution
  (`/vFUZZ/users`→`/v2/users` path-substring, `/api/FUZZ/users`→`/api/admin/users`
  full-segment, `/?id=FUZZ`→`/?id=5` query-value, `/?FUZZ=1`→`/?debug=1`
  query-name, `/FUZZ.txt`→`/config.txt` filename, `/backup.FUZZ`→`/backup.zip`
  extension) — Requirements 40.2, 40.3, 40.4, 40.5, 40.6, 40.7.
- A single-marker wordlist of ``W`` entries yields exactly ``W`` candidates
  (Requirement 41.1).
- Clusterbomb over two markers yields the cartesian product of the two
  Marker_Wordlists (Requirement 42.1).
- Pitchfork yields the index-wise zip truncated to the shortest list
  (Requirement 43.2).

These example-based tests complement the property-based coverage required by
Requirement 47.1.
"""

import pytest

from modules.fuzzing.markers import (
    FuzzMode,
    find_markers,
    generate_marker_candidates,
    substitute_markers,
)


def _substitute(url, values, keyword="FUZZ"):
    """Detect markers in ``url`` and substitute ``values`` positionally."""
    markers = find_markers(url, keyword)
    return substitute_markers(url, markers, values)


# --------------------------------------------------------------------------- #
# The six Marker_Substitution worked examples (Requirements 40.2-40.7)
# --------------------------------------------------------------------------- #
class TestSixRegionExamples:
    """Each worked example from the design's Marker_Substitution table:
    only the marked span changes; every other byte is preserved."""

    @pytest.mark.parametrize(
        "url,value,expected,region,requirement",
        [
            ("/vFUZZ/users", "2", "/v2/users", "path-substring", "40.2"),
            ("/api/FUZZ/users", "admin", "/api/admin/users", "full-segment", "40.3"),
            ("/?id=FUZZ", "5", "/?id=5", "query-value", "40.4"),
            ("/?FUZZ=1", "debug", "/?debug=1", "query-name", "40.5"),
            ("/FUZZ.txt", "config", "/config.txt", "filename", "40.6"),
            ("/backup.FUZZ", "zip", "/backup.zip", "extension", "40.7"),
        ],
    )
    def test_worked_example_substitution(
        self, url, value, expected, region, requirement
    ):
        assert _substitute(url, [value]) == expected

    @pytest.mark.parametrize(
        "url,expected_region",
        [
            ("/vFUZZ/users", "path-substring"),
            ("/api/FUZZ/users", "full-segment"),
            ("/?id=FUZZ", "query-value"),
            ("/?FUZZ=1", "query-name"),
            ("/FUZZ.txt", "filename"),
            ("/backup.FUZZ", "extension"),
        ],
    )
    def test_worked_example_region_classification(self, url, expected_region):
        # Region classification is informational, but the six examples are the
        # canonical labels for each URL area (Requirements 40.2-40.7).
        markers = find_markers(url, "FUZZ")
        assert len(markers) == 1
        assert markers[0].region == expected_region

    def test_query_value_preserves_parameter_name(self):
        # /?id=FUZZ -> /?id=5 keeps the parameter name "id" intact (40.4).
        assert _substitute("/?id=FUZZ", ["5"]) == "/?id=5"

    def test_query_name_preserves_parameter_value(self):
        # /?FUZZ=1 -> /?debug=1 keeps the parameter value "1" intact (40.5).
        assert _substitute("/?FUZZ=1", ["debug"]) == "/?debug=1"

    def test_filename_preserves_extension(self):
        # /FUZZ.txt -> /config.txt keeps the ".txt" extension (40.6).
        assert _substitute("/FUZZ.txt", ["config"]) == "/config.txt"

    def test_extension_preserves_filename(self):
        # /backup.FUZZ -> /backup.zip keeps the "backup" filename (40.7).
        assert _substitute("/backup.FUZZ", ["zip"]) == "/backup.zip"


# --------------------------------------------------------------------------- #
# Single-marker sweep: W entries => exactly W candidates (Requirement 41.1)
# --------------------------------------------------------------------------- #
class TestSingleMarkerSweep:
    @pytest.mark.parametrize("w", [1, 2, 3, 5, 10, 50])
    def test_single_marker_yields_exactly_w_candidates(self, w):
        url = "/vFUZZ/users"
        markers = find_markers(url, "FUZZ")
        wordlist = [str(i) for i in range(w)]
        out = list(
            generate_marker_candidates(url, markers, [wordlist], FuzzMode.CLUSTERBOMB)
        )
        assert len(out) == w

    def test_single_marker_values_are_positional_substitutions(self):
        url = "/vFUZZ/users"
        markers = find_markers(url, "FUZZ")
        out = list(
            generate_marker_candidates(
                url, markers, [["1", "2", "3"]], FuzzMode.CLUSTERBOMB
            )
        )
        assert out == ["/v1/users", "/v2/users", "/v3/users"]


# --------------------------------------------------------------------------- #
# Clusterbomb over two markers => cartesian product (Requirement 42.1)
# --------------------------------------------------------------------------- #
class TestClusterbombTwoMarkers:
    def test_cartesian_product_values(self):
        url = "/api/FUZZ/FUZZ.txt"
        markers = find_markers(url, "FUZZ")
        assert len(markers) == 2
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

    @pytest.mark.parametrize(
        "w1,w2",
        [(1, 1), (2, 3), (3, 2), (4, 5), (1, 6)],
    )
    def test_count_equals_product_of_sizes(self, w1, w2):
        url = "/api/FUZZ/FUZZ.txt"
        markers = find_markers(url, "FUZZ")
        list1 = [f"a{i}" for i in range(w1)]
        list2 = [f"b{j}" for j in range(w2)]
        out = list(
            generate_marker_candidates(
                url, markers, [list1, list2], FuzzMode.CLUSTERBOMB
            )
        )
        assert len(out) == w1 * w2

    def test_covers_every_combination_exactly_once(self):
        url = "/FUZZ/FUZZ"
        markers = find_markers(url, "FUZZ")
        list1 = ["x", "y", "z"]
        list2 = ["1", "2"]
        out = list(
            generate_marker_candidates(url, markers, [list1, list2], FuzzMode.CLUSTERBOMB)
        )
        expected = {f"/{a}/{b}" for a in list1 for b in list2}
        assert set(out) == expected
        assert len(out) == len(expected)  # no duplicates


# --------------------------------------------------------------------------- #
# Pitchfork => index-wise zip truncated to the shortest list (Requirement 43.2)
# --------------------------------------------------------------------------- #
class TestPitchforkTwoMarkers:
    def test_index_wise_pairing_equal_lengths(self):
        url = "/api/FUZZ/FUZZ.txt"
        markers = find_markers(url, "FUZZ")
        out = list(
            generate_marker_candidates(
                url, markers, [["a", "b", "c"], ["1", "2", "3"]], FuzzMode.PITCHFORK
            )
        )
        assert out == ["/api/a/1.txt", "/api/b/2.txt", "/api/c/3.txt"]

    def test_truncates_to_shortest_list(self):
        url = "/FUZZ/FUZZ"
        markers = find_markers(url, "FUZZ")
        out = list(
            generate_marker_candidates(
                url, markers, [["a", "b", "c", "d"], ["1", "2"]], FuzzMode.PITCHFORK
            )
        )
        # min(4, 2) == 2 candidates, paired index-wise.
        assert out == ["/a/1", "/b/2"]

    @pytest.mark.parametrize(
        "w1,w2",
        [(1, 1), (2, 5), (5, 2), (3, 3), (7, 4)],
    )
    def test_count_equals_min_of_sizes(self, w1, w2):
        url = "/FUZZ/FUZZ"
        markers = find_markers(url, "FUZZ")
        list1 = [f"a{i}" for i in range(w1)]
        list2 = [f"b{j}" for j in range(w2)]
        out = list(
            generate_marker_candidates(url, markers, [list1, list2], FuzzMode.PITCHFORK)
        )
        assert len(out) == min(w1, w2)
