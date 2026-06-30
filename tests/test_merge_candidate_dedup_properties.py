"""
Property-Based Tests for Merged Candidate Set Deduplication

**Feature: owasp-complete-purple-teaming-cicd, Property 14: Merged candidate set
has no duplicates**

Property 14 (from design.md):
    FOR ALL combinations of Spec_Import seeds and one or more wordlists
    (including stdin-sourced entries), the merged candidate set produced by
    ``merge_candidates`` contains no duplicate normalized candidate paths.

These tests exercise the real ``merge_candidates`` / ``normalize_candidate_path``
helpers in ``utils.spec_import`` -- the candidate-merge point used by the ``dir``
command after collecting spec seeds and one or more wordlists (Requirement 25.4).
``merge_candidates`` flattens every wordlist's entries (file-sourced and the
single ``--wordlist -`` stdin source alike) into one ``wordlist_entries``
iterable, then appends the spec seed paths; the generators below mirror that by
building several independent wordlists (one of which stands in for the
stdin-sourced list) plus a list of ``SpecSeed`` records and flattening them.

Generators deliberately produce overlapping and normalization-equal spellings of
the same logical path -- ``users``, ``/users``, ``/users/``, ``http://h/users``,
whitespace-padded variants -- spread across the multiple wordlists and the spec
seeds, so collisions are dense and the dedup-by-normalized-path contract is
genuinely stressed.

**Validates: Requirements 25.8, 25.4**
"""

import string

from hypothesis import given, settings, strategies as st
from hypothesis.strategies import composite

from utils.spec_import import (
    SpecSeed,
    merge_candidates,
    normalize_candidate_path,
)


# Base path segments are drawn from a dot/slash/whitespace-free alphabet so that
# the only normalization-collapsing performed on a variant is the scheme/host,
# leading-slash and trailing-slash handling we add explicitly below. This keeps
# each generated variant's normalized form exactly equal to its base name, so we
# can reason precisely about which logical paths collide.
BASE_ALPHABET = string.ascii_letters + string.digits + "_-"

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]


def _variants(base):
    """Return raw spellings of ``base`` that all normalize to the same key.

    Mirrors the equivalence classes ``normalize_candidate_path`` collapses:
    bare, leading-slash, trailing-slash, both slashes, full-URL, and
    whitespace-padded forms (Requirement 25.4). Every element here satisfies
    ``normalize_candidate_path(v) == base``.
    """
    return [
        base,
        f"/{base}",
        f"{base}/",
        f"/{base}/",
        f"http://h/{base}",
        f"https://example.test/{base}/",
        f"  {base}  ",
        f"\t/{base}\n",
    ]


@composite
def base_names(draw):
    """Draw a set of distinct base path segments (the logical candidate paths)."""
    return draw(
        st.lists(
            st.text(alphabet=BASE_ALPHABET, min_size=1, max_size=8),
            min_size=0,
            max_size=10,
            unique=True,
        )
    )


@composite
def merge_inputs(draw):
    """Build (wordlists, spec_seeds, expected_keys) with dense collisions.

    For each distinct base name we emit one or more normalization-equal raw
    spellings, scattering them across several wordlists (one standing in for the
    ``--wordlist -`` stdin source) and the spec seed list. Blank/whitespace-only
    entries are sprinkled in to exercise the blank-skipping path. The returned
    ``expected_keys`` is the set of normalized keys that should survive the merge.
    """
    bases = draw(base_names())

    num_wordlists = draw(st.integers(min_value=1, max_value=4))
    wordlists = [[] for _ in range(num_wordlists)]
    spec_seeds = []

    for base in bases:
        variants = _variants(base)
        # Emit several spellings of this base across random destinations so the
        # same normalized key recurs in multiple wordlists and/or the spec seeds.
        count = draw(st.integers(min_value=1, max_value=4))
        for _ in range(count):
            variant = draw(st.sampled_from(variants))
            dest = draw(st.integers(min_value=0, max_value=num_wordlists))
            if dest == num_wordlists:
                method = draw(st.sampled_from(HTTP_METHODS))
                spec_seeds.append(SpecSeed(path=variant, method=method))
            else:
                wordlists[dest].append(variant)

    # Sprinkle blank / whitespace-only entries that must be ignored entirely.
    for _ in range(draw(st.integers(min_value=0, max_value=3))):
        wordlists[draw(st.integers(min_value=0, max_value=num_wordlists - 1))].append(
            draw(st.sampled_from(["", "   ", "\t", "\n", "  \n "]))
        )

    # Shuffle each wordlist so first-seen order is not trivially sorted.
    wordlists = [list(draw(st.permutations(wl))) for wl in wordlists]
    spec_seeds = list(draw(st.permutations(spec_seeds)))

    expected_keys = set(bases)
    return wordlists, spec_seeds, expected_keys


@given(data=merge_inputs())
@settings(max_examples=300, deadline=None)
def test_merged_candidate_set_has_no_duplicates(data):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 14: Merged candidate
    set has no duplicates**
    **Validates: Requirements 25.8, 25.4**

    FOR ALL combinations of spec seeds and one or more wordlists (including a
    stdin-sourced list) with overlapping and normalization-equal entries:

      - 25.8: applying ``normalize_candidate_path`` to every element of the
        merged candidate set yields all-distinct values -- the merged set
        contains no duplicate normalized candidate path.
      - 25.4: the merge is exactly a normalized-path dedup -- the set of
        surviving normalized keys equals the set of normalized keys present in
        the inputs (no logical path is dropped and none is invented), so the
        no-duplicates guarantee is non-trivial (it is not vacuously satisfied by
        an empty result).
    """
    wordlists, spec_seeds, expected_keys = data

    # merge_candidates consumes a single flattened wordlist_entries iterable;
    # the ``dir`` command flattens every --wordlist (file- and stdin-sourced)
    # into one list before calling it.
    flattened_entries = [entry for wl in wordlists for entry in wl]

    merged = merge_candidates(flattened_entries, spec_seeds)

    normalized = [normalize_candidate_path(c) for c in merged]

    # 25.8: no duplicate normalized candidate paths in the merged set.
    assert len(normalized) == len(set(normalized)), (
        f"merged candidate set contains duplicate normalized paths: "
        f"{[k for k in set(normalized) if normalized.count(k) > 1]}"
    )

    # Every surviving entry is non-blank and normalizes to a non-empty key.
    assert all(k for k in normalized)

    # 25.4: dedup is loss-free and faithful -- surviving keys are exactly the
    # distinct normalized keys present in the inputs (guards against a vacuous
    # empty-set pass and against dropping real candidates).
    assert set(normalized) == expected_keys


def test_known_normalization_equal_entries_collapse_to_one():
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 14: Merged candidate
    set has no duplicates (worked example)**
    **Validates: Requirements 25.8, 25.4**

    A concrete spread of the documented equivalent spellings across two
    wordlists and a spec seed collapses to a single candidate with one
    normalized key.
    """
    wordlist_a = ["users", "/users", "  users  "]
    wordlist_b = ["/users/", "http://h/users"]
    seeds = [SpecSeed(path="https://example.test/users/", method="GET")]

    merged = merge_candidates(wordlist_a + wordlist_b, seeds)
    normalized = [normalize_candidate_path(c) for c in merged]

    assert normalized == ["users"]
    assert len(normalized) == len(set(normalized))


def test_empty_inputs_yield_empty_merged_set():
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 14: Merged candidate
    set has no duplicates (empty input)**
    **Validates: Requirements 25.8, 25.4**

    Merging empty/blank wordlists and no spec seeds yields an empty candidate
    set, which trivially contains no duplicate normalized paths.
    """
    merged = merge_candidates(["", "  ", "\t"], [])
    assert merged == []
