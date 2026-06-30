"""
Property-Based Tests for Extension Expansion Candidate Count

**Feature: owasp-complete-purple-teaming-cicd, Property 13: Extension expansion
candidate count**

Property 13 (from design.md):
    FOR ALL wordlists of ``W`` distinct entries and Extension_Sets normalizing to
    ``E`` distinct extensions, the number of distinct candidate paths generated
    per HTTP method is exactly ``W × (E + 1)`` -- the original entry plus one
    appended candidate per distinct normalized extension -- and each normalized
    extension (whether supplied with or without a leading dot) is appended at
    most once. When ``E == 0`` the count is exactly ``W``.

These tests exercise the real ``normalize_extensions`` / ``expand_candidates``
helpers in ``modules.fuzzing.orchestrator`` -- the candidate-generation point used
by ``_fuzz_wordlist``. Candidate paths are method-independent (the fuzzer pairs
each generated candidate with every configured method), so the distinct candidate
count "per HTTP method" equals the size of the union of ``expand_candidates``
over the wordlist.

Generators mix dotted, undotted, differently-cased, whitespace-padded, and
duplicate raw extension spellings that collapse to ``E`` distinct normalized
extensions (Requirements 23.3, 23.4, 23.5). To keep the candidate space free of
incidental collisions, wordlist entries are drawn from a dot-free alphabet and
are unique, and the normalized extensions are distinct base names: a candidate is
then either a bare (dot-free) entry or ``entry + "." + name`` whose ``(entry,
name)`` pair is uniquely recoverable, so the distinct-candidate count is exactly
``W × (E + 1)``.

**Validates: Requirements 23.9, 23.2, 23.3, 23.4, 23.5, 23.6**
"""

import string

from hypothesis import given, settings, strategies as st

from modules.fuzzing.orchestrator import normalize_extensions, expand_candidates


# Wordlist entries: dot-free so a candidate's text before its first "." is always
# the originating entry (no bare/expanded or cross-entry collisions can occur).
WORD_ALPHABET = string.ascii_lowercase + string.digits + "_-"

# Extension base names: dot-free, lower-case so distinct names normalize to
# distinct ".name" extensions and E == len(names).
EXT_NAME_ALPHABET = string.ascii_lowercase + string.digits


words_strategy = st.lists(
    st.text(alphabet=WORD_ALPHABET, min_size=1, max_size=8),
    min_size=0,
    max_size=12,
    unique=True,
)


@st.composite
def extension_sets(draw):
    """
    Build a raw Extension_Set and its expected distinct-count ``E``.

    Draws ``E`` distinct lower-case base names, then for each name emits one or
    more raw spellings mixing leading dots (0..3 -> normalize to exactly one),
    letter case, and surrounding whitespace. The raw list therefore contains
    duplicate-by-normalization entries (23.5) and both dotted (23.3) and undotted
    (23.4) spellings, yet collapses to exactly ``E`` distinct normalized
    extensions.
    """
    names = draw(
        st.lists(
            st.text(alphabet=EXT_NAME_ALPHABET, min_size=1, max_size=5),
            min_size=0,
            max_size=5,
            unique=True,
        )
    )

    raw = []
    for name in names:
        variant_count = draw(st.integers(min_value=1, max_value=3))
        for _ in range(variant_count):
            dots = "." * draw(st.integers(min_value=0, max_value=3))
            cased = draw(st.sampled_from([name, name.upper(), name.title()]))
            pad = draw(st.sampled_from(["", " ", "  "]))
            raw.append(f"{pad}{dots}{cased}{pad}")

    raw = list(draw(st.permutations(raw)))
    return raw, len(names)


@given(words=words_strategy, ext=extension_sets())
@settings(max_examples=300, deadline=None)
def test_extension_expansion_candidate_count(words, ext):
    """
    **Feature: owasp-complete-purple-teaming-cicd, Property 13: Extension
    expansion candidate count**
    **Validates: Requirements 23.9, 23.2, 23.3, 23.4, 23.5, 23.6**

    For any wordlist of ``W`` distinct entries and Extension_Set normalizing to
    ``E`` distinct extensions:

      - 23.3 / 23.4 / 23.5: duplicate, dotted, undotted, cased, and
        whitespace-padded raw spellings collapse to exactly ``E`` distinct
        normalized extensions, each appended at most once.
      - 23.2 / 23.9: the distinct candidate paths per HTTP method -- the union of
        ``expand_candidates`` over the wordlist -- number exactly ``W × (E + 1)``
        (the bare entry plus one candidate per distinct normalized extension).
      - 23.6: when ``E == 0`` (no/empty Extension_Set) the count is exactly ``W``
        and every candidate is a bare, unexpanded entry.
    """
    raw_extensions, expected_E = ext

    normalized = normalize_extensions(raw_extensions)
    E = len(normalized)

    # 23.3 / 23.4 / 23.5: raw spellings collapse to the expected distinct set,
    # each normalized to a single-leading-dot, lower-cased form.
    assert E == expected_E
    assert normalized == list(dict.fromkeys(normalized))  # de-duplicated, ordered
    assert all(x.startswith(".") and not x[1:].startswith(".") for x in normalized)

    W = len(words)

    # Distinct candidate paths generated per HTTP method.
    candidates = set()
    for word in words:
        expanded = expand_candidates(word, raw_extensions)
        # 23.2: each entry yields the bare entry first, then one per distinct ext.
        assert expanded[0] == word
        assert len(expanded) == E + 1
        candidates.update(expanded)

    # 23.9: exactly W × (E + 1) distinct candidates.
    assert len(candidates) == W * (E + 1), (
        f"expected {W} * ({E} + 1) = {W * (E + 1)} distinct candidates, "
        f"got {len(candidates)}"
    )

    # 23.6: no extensions => only the original entries, exactly W of them.
    if E == 0:
        assert len(candidates) == W
        assert candidates == set(words)
