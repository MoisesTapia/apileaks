"""
CliRunner unit tests for marker-mode (positional fuzzing) validation errors.

**Feature: owasp-complete-purple-teaming-cicd, Task 49.3**

These tests exercise the ``dir`` command's marker-mode validation surface. Every
invalid configuration must be rejected with a descriptive, value-naming error
and must perform NO Endpoint_Discovery, mirroring the exit-before-discovery test
pattern in ``test_discovery_controls_cli.py``.

Cases covered (Requirement 46 validation, exit-before-discovery):

- empty / whitespace-only ``--fuzz-keyword`` (Requirements 39.5, 46.1)
- a marker-only option supplied with a keyword-free target (Requirements 39.6, 46.2)
- more ``--wordlist`` values than Marker_Positions (Requirements 44.4, 46.3)
- Pitchfork_Mode with an empty required Marker_Wordlist (Requirements 44.5, 46.4)
- an unrecognized ``--fuzz-mode`` value (Requirement 46.5)
- an unreadable ``--wordlist`` source (Requirement 44.6)
- exit-before-discovery ordering for all of the above (Requirement 46.7)

No real HTTP requests are made: the single discovery entry point shared by the
``dir`` command (``run_enhanced_apileak``) is patched out so we can prove that
validation fails *before* any Discovery_Request is issued.
"""

from unittest.mock import patch

import pytest
from click.testing import CliRunner

import apileaks
from apileaks import cli


# A target with exactly one literal ``FUZZ`` occurrence => one Marker_Position.
_TARGET_ONE_MARKER = "https://api.example.com/FUZZ"
# A target with no ``FUZZ`` occurrence => keyword-free (legacy base-path) target.
_TARGET_NO_MARKER = "https://api.example.com"


def _invoke_dir(args):
    """Invoke ``dir`` with discovery patched out; return (result, discovery mock).

    Patching ``apileaks.run_enhanced_apileak`` (the single discovery entry point
    the ``dir`` command calls) lets each test assert that a rejected marker-mode
    configuration performs NO Endpoint_Discovery (Requirement 46.7).
    """
    runner = CliRunner()
    with patch.object(apileaks, "run_enhanced_apileak") as discovery:
        result = runner.invoke(cli, ["--no-banner", "dir", *args])
    return result, discovery


# ---------------------------------------------------------------------------
# Empty / whitespace-only --fuzz-keyword (Requirements 39.5, 46.1)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("keyword", ["", "   ", "\t"])
def test_empty_or_whitespace_fuzz_keyword_rejected_and_no_discovery(keyword):
    """An empty/whitespace ``--fuzz-keyword`` errors, names the value, no discovery.

    **Validates: Requirements 39.5, 46.1, 46.7**
    """
    result, discovery = _invoke_dir(
        ["--target", _TARGET_ONE_MARKER, "--fuzz-keyword", keyword]
    )

    assert result.exit_code != 0
    # Descriptive error that names the offending keyword value.
    assert "Invalid Fuzz_Keyword" in result.output
    assert repr(keyword) in result.output
    assert "empty or whitespace-only" in result.output
    # Exit-before-discovery: no Endpoint_Discovery was performed.
    discovery.assert_not_called()


# ---------------------------------------------------------------------------
# Marker-only option with a keyword-free target (Requirements 39.6, 46.2)
# ---------------------------------------------------------------------------

# Each row supplies a marker-only option explicitly on the command line while the
# target contains no Fuzz_Marker, which is a configuration error.
_MARKER_ONLY_OPTIONS = [
    ["--fuzz-mode", "pitchfork"],
    ["--fuzz-mode", "clusterbomb"],
    ["--fuzz-keyword", "FUZZ"],
]


@pytest.mark.parametrize("marker_option", _MARKER_ONLY_OPTIONS)
def test_marker_only_option_with_no_marker_rejected_and_no_discovery(marker_option):
    """A marker-only option on a keyword-free target errors, names it, no discovery.

    **Validates: Requirements 39.6, 46.2, 46.7**
    """
    result, discovery = _invoke_dir(
        ["--target", _TARGET_NO_MARKER, *marker_option]
    )

    assert result.exit_code != 0
    # Descriptive error naming the target URL and keyword with no marker found.
    assert "no Fuzz_Marker found in target URL" in result.output
    assert repr(_TARGET_NO_MARKER) in result.output
    discovery.assert_not_called()


# ---------------------------------------------------------------------------
# More --wordlist values than Marker_Positions (Requirements 44.4, 46.3)
# ---------------------------------------------------------------------------

def test_too_many_wordlists_vs_markers_rejected_and_no_discovery():
    """More wordlists than markers errors, names both counts, no discovery.

    The target has one Marker_Position but two ``--wordlist`` values are supplied;
    the count mismatch is detected during association, before any wordlist is read
    or any Discovery_Request is issued.

    **Validates: Requirements 44.4, 46.3, 46.7**
    """
    result, discovery = _invoke_dir(
        [
            "--target",
            _TARGET_ONE_MARKER,
            "--wordlist",
            "first.txt",
            "--wordlist",
            "second.txt",
        ]
    )

    assert result.exit_code != 0
    # Descriptive error naming both the wordlist count and the marker count.
    assert "mismatch" in result.output
    assert "2 wordlist" in result.output
    assert "1 marker position" in result.output
    discovery.assert_not_called()


# ---------------------------------------------------------------------------
# Pitchfork_Mode with an empty required Marker_Wordlist (Requirements 44.5, 46.4)
# ---------------------------------------------------------------------------

def test_pitchfork_with_empty_wordlist_rejected_and_no_discovery(tmp_path):
    """Pitchfork_Mode with an empty required wordlist errors, no discovery.

    A wordlist file with no usable entries (only blanks/comments) yields an empty
    Marker_Wordlist; in Pitchfork_Mode every marker requires a non-empty wordlist.

    **Validates: Requirements 44.5, 46.4, 46.7**
    """
    empty_wordlist = tmp_path / "empty.txt"
    # Only blank lines and a comment => no usable entries after filtering.
    empty_wordlist.write_text("\n   \n# only a comment\n", encoding="utf-8")

    result, discovery = _invoke_dir(
        [
            "--target",
            _TARGET_ONE_MARKER,
            "--fuzz-mode",
            "pitchfork",
            "--wordlist",
            str(empty_wordlist),
        ]
    )

    assert result.exit_code != 0
    # Descriptive error identifying the empty Pitchfork_Mode wordlist.
    assert "Pitchfork_Mode requires a non-empty wordlist" in result.output
    assert "is empty" in result.output
    discovery.assert_not_called()


# ---------------------------------------------------------------------------
# Unrecognized --fuzz-mode value (Requirement 46.5)
# ---------------------------------------------------------------------------

def test_unrecognized_fuzz_mode_rejected_and_no_discovery():
    """An unknown ``--fuzz-mode`` value errors, names the value, no discovery.

    ``--fuzz-mode`` is a constrained choice, so an unrecognized selector is
    rejected during option parsing, before any Discovery_Request.

    **Validates: Requirements 46.5, 46.7**
    """
    result, discovery = _invoke_dir(
        ["--target", _TARGET_ONE_MARKER, "--fuzz-mode", "bogusmode"]
    )

    assert result.exit_code != 0
    # The invalid Fuzz_Mode value is named in the error output.
    assert "bogusmode" in result.output
    assert "--fuzz-mode" in result.output
    discovery.assert_not_called()


# ---------------------------------------------------------------------------
# Unreadable --wordlist source (Requirement 44.6)
# ---------------------------------------------------------------------------

def test_unreadable_wordlist_source_rejected_and_no_discovery(tmp_path):
    """An unreadable ``--wordlist`` source errors, names the source, no discovery.

    The target has one Marker_Position and a single ``--wordlist`` pointing at a
    path that does not exist; loading it raises, surfaced as a descriptive
    value-naming CLI error before any Discovery_Request.

    **Validates: Requirements 44.6, 46.7**
    """
    missing = tmp_path / "does_not_exist.txt"

    result, discovery = _invoke_dir(
        ["--target", _TARGET_ONE_MARKER, "--wordlist", str(missing)]
    )

    assert result.exit_code != 0
    # Descriptive error naming the unreadable wordlist source.
    assert "unreadable wordlist source" in result.output
    assert str(missing) in result.output
    discovery.assert_not_called()
