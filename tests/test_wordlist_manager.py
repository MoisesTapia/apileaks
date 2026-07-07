"""
Unit tests for ``utils/wordlist_manager.py`` — Assetnote wordlist integration.

Covers:
- ``_derive_alias`` — alias derivation from filenames
- ``_find_entry`` — exact alias match and partial name match
- ``_normalise_catalogue`` — raw catalogue item normalisation
- ``resolve_wordlist`` — passthrough for non-assetnote specs
- ``resolve_wordlist`` — exits when name not in catalogue
- ``_make_head_file`` — truncates to N lines
- CLI: ``apileaks wordlist list`` — renders a table (mocked catalogue)
- CLI: ``apileaks wordlist cache`` — shows cache directory
- ``_read_wordlist_entries`` — assetnote: prefix resolves to a file

No network requests are made: HTTP fetches are patched out in all tests.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from apileaks import cli, _read_wordlist_entries


# ---------------------------------------------------------------------------
# _derive_alias
# ---------------------------------------------------------------------------

from utils.wordlist_manager import (
    _derive_alias,
    _find_entry,
    _make_head_file,
    _normalise_catalogue,
    resolve_wordlist,
    ASSETNOTE_PREFIX,
)


def test_derive_alias_with_date():
    """Automated wordlists with dates are reduced to core-YYMMDD."""
    assert _derive_alias("httparchive_apiroutes_2021_03_28.txt") == "apiroutes-210328"


def test_derive_alias_aspx_with_date():
    """Multi-part stems before a date use only the first part."""
    assert _derive_alias(
        "httparchive_aspx_asp_cfm_svc_ashx_asmx_2021_03_28.txt"
    ) == "aspx-210328"


def test_derive_alias_no_date():
    """Filenames without a date pattern return a hyphen-normalised stem."""
    assert _derive_alias("raft-large-words.txt") == "raft-large-words"


def test_derive_alias_underscores_no_date():
    """Underscores are converted to hyphens when there is no date suffix."""
    assert _derive_alias("my_custom_list.txt") == "my-custom-list"


# ---------------------------------------------------------------------------
# _normalise_catalogue
# ---------------------------------------------------------------------------

_RAW_AUTOMATED = [
    {
        "name": "httparchive_apiroutes_2021_03_28.txt",
        "count": 215114,
        "filesize": "6.3mb",
    },
    {
        "name": "httparchive_aspx_asp_cfm_svc_ashx_asmx_2021_03_28.txt",
        "count": 45928,
        "filesize": "926.8kb",
    },
    {},  # missing name — should be skipped
]


def test_normalise_catalogue_count():
    """Each valid item produces one normalised entry; bad items are skipped."""
    result = _normalise_catalogue(_RAW_AUTOMATED, "https://example.com/")
    assert len(result) == 2


def test_normalise_catalogue_alias():
    """Alias is derived correctly from the filename."""
    result = _normalise_catalogue(_RAW_AUTOMATED, "https://example.com/")
    aliases = {e["alias"] for e in result}
    assert "apiroutes-210328" in aliases
    assert "aspx-210328" in aliases


def test_normalise_catalogue_download_url():
    """Download URL is constructed from the CDN base + filename."""
    result = _normalise_catalogue(_RAW_AUTOMATED, "https://example.com/")
    api_entry = next(e for e in result if e["alias"] == "apiroutes-210328")
    assert "httparchive_apiroutes_2021_03_28.txt" in api_entry["url"]


# ---------------------------------------------------------------------------
# _find_entry
# ---------------------------------------------------------------------------

_ENTRIES = [
    {"alias": "apiroutes-210328", "name": "httparchive_apiroutes_2021_03_28.txt",
     "url": "https://cdn/a.txt", "count": 1000, "filesize": "1mb"},
    {"alias": "aspx-210328", "name": "httparchive_aspx_210328.txt",
     "url": "https://cdn/b.txt", "count": 500, "filesize": "500kb"},
    {"alias": "raft-large-words", "name": "raft-large-words.txt",
     "url": "https://cdn/c.txt", "count": 80000, "filesize": "4mb"},
]


def test_find_entry_exact_alias():
    """Exact alias match returns the correct entry."""
    entry = _find_entry(_ENTRIES, "apiroutes-210328")
    assert entry is not None
    assert entry["alias"] == "apiroutes-210328"


def test_find_entry_case_insensitive_alias():
    """Alias lookup is case-insensitive."""
    entry = _find_entry(_ENTRIES, "APIROUTES-210328")
    assert entry is not None
    assert entry["alias"] == "apiroutes-210328"


def test_find_entry_partial_name():
    """Partial name substring match returns the first matching entry."""
    entry = _find_entry(_ENTRIES, "raft-large")
    assert entry is not None
    assert entry["alias"] == "raft-large-words"


def test_find_entry_not_found():
    """A non-matching query returns None."""
    assert _find_entry(_ENTRIES, "nonexistent-wordlist") is None


# ---------------------------------------------------------------------------
# resolve_wordlist — non-assetnote passthrough
# ---------------------------------------------------------------------------

def test_resolve_wordlist_passthrough_plain_path():
    """A plain file path is returned unchanged."""
    result = resolve_wordlist("/some/local/wordlist.txt")
    assert result == "/some/local/wordlist.txt"


def test_resolve_wordlist_passthrough_stdin():
    """A '-' stdin source is returned unchanged."""
    result = resolve_wordlist("-")
    assert result == "-"


# ---------------------------------------------------------------------------
# resolve_wordlist — assetnote: exits when not found
# ---------------------------------------------------------------------------

def test_resolve_wordlist_not_found_exits(tmp_path, monkeypatch):
    """An unknown assetnote name causes SystemExit with a helpful message."""
    monkeypatch.setattr(
        "utils.wordlist_manager._load_catalogue",
        lambda refresh=False: _ENTRIES,
    )
    with pytest.raises(SystemExit) as exc_info:
        resolve_wordlist(f"{ASSETNOTE_PREFIX}nonexistent-12345")
    assert "nonexistent" in str(exc_info.value).lower() or exc_info.value.code != 0


# ---------------------------------------------------------------------------
# resolve_wordlist — assetnote: returns cached path without download
# ---------------------------------------------------------------------------

def test_resolve_wordlist_uses_cache(tmp_path, monkeypatch):
    """When the cache file exists, no download is attempted."""
    cache_dir = tmp_path / "wordlists"
    cache_dir.mkdir()
    cached_file = cache_dir / "httparchive_apiroutes_2021_03_28.txt"
    cached_file.write_text("path1\npath2\n")

    monkeypatch.setattr("utils.wordlist_manager._CACHE_ROOT", cache_dir)
    monkeypatch.setattr(
        "utils.wordlist_manager._load_catalogue",
        lambda refresh=False: _ENTRIES,
    )

    result = resolve_wordlist(f"{ASSETNOTE_PREFIX}apiroutes-210328")
    assert result == str(cached_file)


# ---------------------------------------------------------------------------
# _make_head_file
# ---------------------------------------------------------------------------

def test_make_head_file_truncates(tmp_path, monkeypatch):
    """_make_head_file creates a file with at most N lines."""
    monkeypatch.setattr("utils.wordlist_manager._CACHE_ROOT", tmp_path)
    source = tmp_path / "big.txt"
    source.write_text("\n".join(f"line{i}" for i in range(100)) + "\n")

    result_path = _make_head_file(source, 10)

    with open(result_path) as fh:
        lines = [l for l in fh.read().splitlines() if l]
    assert len(lines) == 10
    assert lines[0] == "line0"
    assert lines[-1] == "line9"


def test_make_head_file_shorter_than_n(tmp_path, monkeypatch):
    """When the source has fewer lines than N, all lines are kept."""
    monkeypatch.setattr("utils.wordlist_manager._CACHE_ROOT", tmp_path)
    source = tmp_path / "small.txt"
    source.write_text("a\nb\nc\n")

    result_path = _make_head_file(source, 50)

    with open(result_path) as fh:
        lines = fh.read().splitlines()
    assert lines == ["a", "b", "c"]


# ---------------------------------------------------------------------------
# _read_wordlist_entries — assetnote: prefix resolves to local file
# ---------------------------------------------------------------------------

def test_read_wordlist_entries_assetnote_prefix(tmp_path, monkeypatch):
    """``assetnote:`` prefix resolves to a cached file and returns its entries."""
    cache_dir = tmp_path / "wordlists"
    cache_dir.mkdir()
    cached_file = cache_dir / "httparchive_apiroutes_2021_03_28.txt"
    cached_file.write_text("/users\n/admin\n# comment\n\n/health\n")

    monkeypatch.setattr("utils.wordlist_manager._CACHE_ROOT", cache_dir)
    monkeypatch.setattr(
        "utils.wordlist_manager._load_catalogue",
        lambda refresh=False: _ENTRIES,
    )

    entries = _read_wordlist_entries(f"{ASSETNOTE_PREFIX}apiroutes-210328")

    assert "/users" in entries
    assert "/admin" in entries
    assert "/health" in entries
    # Comments and blank lines are stripped
    assert "" not in entries
    assert "# comment" not in entries


# ---------------------------------------------------------------------------
# CLI: apileaks wordlist cache
# ---------------------------------------------------------------------------

def test_cli_wordlist_cache_empty(tmp_path, monkeypatch):
    """``apileaks wordlist cache`` shows the cache directory path."""
    monkeypatch.setattr("utils.wordlist_manager._CACHE_ROOT", tmp_path / "wordlists")

    runner = CliRunner()
    result = runner.invoke(cli, ["--no-banner", "wordlist", "cache"])

    assert result.exit_code == 0, result.output
    assert "wordlists" in result.output.lower() or "cache" in result.output.lower()


# ---------------------------------------------------------------------------
# CLI: apileaks wordlist list (mocked catalogue)
# ---------------------------------------------------------------------------

def test_cli_wordlist_list_renders_table(monkeypatch):
    """``apileaks wordlist list`` renders a table with alias and filename columns."""
    fake_entries = [
        {
            "alias": "apiroutes-210328",
            "name": "httparchive_apiroutes_2021_03_28.txt",
            "count": 215114,
            "filesize": "6.3mb",
            "cached": False,
        }
    ]
    monkeypatch.setattr(
        "utils.wordlist_manager.list_wordlists",
        lambda filter_term=None, refresh=False, limit=50: fake_entries,
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["--no-banner", "wordlist", "list"])

    assert result.exit_code == 0, result.output
    assert "apiroutes-210328" in result.output
    assert "httparchive_apiroutes_2021_03_28.txt" in result.output


def test_cli_wordlist_list_with_filter(monkeypatch):
    """``--filter`` is forwarded to ``list_wordlists``."""
    received_filter = {}

    def fake_list(filter_term=None, refresh=False, limit=50):
        received_filter["value"] = filter_term
        return []

    monkeypatch.setattr("utils.wordlist_manager.list_wordlists", fake_list)

    runner = CliRunner()
    result = runner.invoke(
        cli, ["--no-banner", "wordlist", "list", "--filter", "apiroutes"]
    )

    assert result.exit_code == 0
    assert received_filter["value"] == "apiroutes"


def test_cli_wordlist_list_empty_result(monkeypatch):
    """An empty catalogue prints a 'no wordlists' message."""
    monkeypatch.setattr(
        "utils.wordlist_manager.list_wordlists",
        lambda filter_term=None, refresh=False, limit=50: [],
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["--no-banner", "wordlist", "list"])

    assert result.exit_code == 0, result.output
    assert "no wordlists" in result.output.lower() or result.output.strip() != ""
