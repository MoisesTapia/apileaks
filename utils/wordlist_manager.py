"""
Wordlist Manager — Assetnote wordlist integration.

Provides on-demand download, caching, and listing of wordlists hosted on
`wordlists.assetnote.io` (the Assetnote public wordlist CDN).

Design principles:
- Cache directory: ``~/.cache/apileaks/wordlists/`` (XDG-compatible).
- Catalogue is fetched once and cached locally for 24 h; individual wordlist
  files are cached until explicitly refreshed with ``--refresh``.
- The ``--wordlist assetnote:<name>`` syntax in ``dir`` / ``par`` triggers
  an auto-download when the file is not already cached.
- Zero new third-party dependencies: uses ``httpx`` (already a requirement)
  and the stdlib only.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from core.logging import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Base CDN URL for the Assetnote wordlist catalogue files.
_CATALOGUE_URLS = [
    "https://wordlists-cdn.assetnote.io/data/automated.json",
    "https://wordlists-cdn.assetnote.io/data/manual.json",
]

# Base download URL pattern for individual wordlists.
_DOWNLOAD_BASE = "https://wordlists-cdn.assetnote.io/data/"

# Local cache root: ~/.cache/apileaks/wordlists/
_CACHE_ROOT = Path.home() / ".cache" / "apileaks" / "wordlists"

# Catalogue cache TTL in seconds (24 hours).
_CATALOGUE_TTL = 86_400

# Sentinel prefix that tells the CLI a wordlist comes from Assetnote.
ASSETNOTE_PREFIX = "assetnote:"


# ---------------------------------------------------------------------------
# Catalogue helpers
# ---------------------------------------------------------------------------

def _catalogue_path(url: str) -> Path:
    """Local cache path for a catalogue JSON file."""
    name = url.rstrip("/").split("/")[-1]
    return _CACHE_ROOT / f"_catalogue_{name}"


def _catalogue_is_fresh(path: Path) -> bool:
    """True when the cached catalogue is younger than the TTL."""
    if not path.exists():
        return False
    return (time.time() - path.stat().st_mtime) < _CATALOGUE_TTL


def _fetch_text(url: str, timeout: float = 30.0) -> str:
    """Synchronous HTTP GET via httpx (already a project dependency)."""
    try:
        import httpx
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            response = client.get(url)
            response.raise_for_status()
            return response.text
    except Exception as exc:
        raise RuntimeError(f"Failed to fetch {url}: {exc}") from exc


def _load_catalogue(refresh: bool = False) -> list[dict]:
    """Load the merged Assetnote wordlist catalogue.

    Fetches both ``automated.json`` and ``manual.json`` from the CDN on the
    first call (or when ``refresh=True``) and caches them locally. Subsequent
    calls within the TTL window return the cached data instantly.

    Returns a flat list of entry dicts, each with at minimum:
        ``name``      – display name / filename
        ``url``       – full download URL
        ``count``     – approximate line count (may be 0 when not declared)
        ``filesize``  – human-readable size string (may be empty)
        ``alias``     – short alias used with the ``assetnote:`` prefix
    """
    _CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    entries: list[dict] = []

    for cat_url in _CATALOGUE_URLS:
        cache_path = _catalogue_path(cat_url)
        if not refresh and _catalogue_is_fresh(cache_path):
            try:
                with open(cache_path, encoding="utf-8") as fh:
                    raw = json.load(fh)
                entries.extend(_normalise_catalogue(raw, cat_url))
                continue
            except (json.JSONDecodeError, OSError):
                pass  # fall through to re-fetch

        try:
            text = _fetch_text(cat_url)
            raw = json.loads(text)
            # Persist catalogue
            with open(cache_path, "w", encoding="utf-8") as fh:
                fh.write(text)
            logger.debug("Wordlist catalogue cached", url=cat_url, path=str(cache_path))
            entries.extend(_normalise_catalogue(raw, cat_url))
        except Exception as exc:
            logger.warning("Could not fetch wordlist catalogue", url=cat_url, error=str(exc))
            # Use stale cache if present
            if cache_path.exists():
                try:
                    with open(cache_path, encoding="utf-8") as fh:
                        raw = json.load(fh)
                    entries.extend(_normalise_catalogue(raw, cat_url))
                    logger.info("Using stale catalogue cache", url=cat_url)
                except (json.JSONDecodeError, OSError):
                    pass

    return entries


def _normalise_catalogue(raw: list, base_url: str) -> list[dict]:
    """Normalise a raw catalogue list into a consistent entry format."""
    normalised: list[dict] = []
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        filename = item.get("name") or item.get("filename") or ""
        if not filename:
            continue

        # Build download URL.  Assetnote CDN serves wordlists under
        # https://wordlists-cdn.assetnote.io/data/<filename>
        if filename.startswith("http"):
            download_url = filename
            filename = filename.rstrip("/").split("/")[-1]
        else:
            download_url = _DOWNLOAD_BASE + filename

        # Derive a short alias: strip date suffixes and extension.
        # e.g. "httparchive_apiroutes_2021_03_28.txt" -> "apiroutes-210328"
        alias = _derive_alias(filename)

        normalised.append({
            "name": filename,
            "alias": alias,
            "url": download_url,
            "count": int(item.get("count", 0) or 0),
            "filesize": item.get("filesize") or item.get("size") or "",
            "description": item.get("description") or "",
        })
    return normalised


def _derive_alias(filename: str) -> str:
    """Derive a short, memorable alias from an Assetnote filename.

    Examples:
        httparchive_apiroutes_2021_03_28.txt  -> apiroutes-210328
        httparchive_aspx_asp_cfm_...2021_03_28.txt -> aspx-210328
        raft-large-words.txt -> raft-large-words
    """
    stem = Path(filename).stem.lower()

    # Strip leading "httparchive_" prefix (common in automated wordlists).
    stem = stem.replace("httparchive_", "")

    # Detect a trailing date pattern _YYYY_MM_DD.
    import re
    date_match = re.search(r"_(\d{4})_(\d{2})_(\d{2})$", stem)
    if date_match:
        y, m, d = date_match.groups()
        date_tag = f"{y[2:]}{m}{d}"
        stem = stem[: date_match.start()]
        # Collapse long names like "aspx_asp_cfm_svc_ashx_asmx" to first part.
        parts = stem.split("_")
        core = parts[0] if parts else stem
        return f"{core}-{date_tag}"

    # Normalise underscores to hyphens for consistency.
    return stem.replace("_", "-")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def list_wordlists(
    filter_term: str | None = None,
    refresh: bool = False,
    limit: int = 50,
) -> list[dict]:
    """Return wordlist metadata, optionally filtered by a substring.

    Args:
        filter_term: Case-insensitive substring to match against name/alias.
        refresh:     Force re-fetch of the catalogue even if fresh.
        limit:       Maximum entries to return (0 = unlimited).

    Returns:
        List of dicts with keys: name, alias, url, count, filesize, cached.
    """
    entries = _load_catalogue(refresh=refresh)

    if filter_term:
        ft = filter_term.lower()
        entries = [
            e for e in entries
            if ft in e["name"].lower() or ft in e["alias"].lower()
        ]

    # Annotate with cache status.
    for entry in entries:
        entry["cached"] = _wordlist_cache_path(entry["name"]).exists()

    if limit > 0:
        entries = entries[:limit]

    return entries


def _wordlist_cache_path(filename: str) -> Path:
    """Local cache path for a downloaded wordlist file."""
    return _CACHE_ROOT / filename


def resolve_wordlist(
    spec: str,
    refresh: bool = False,
    show_progress: bool = True,
) -> str:
    """Resolve an ``assetnote:<name>`` spec to a local file path.

    Downloads and caches the wordlist if not already present (or if
    ``refresh=True``). Returns the absolute path to the local file.

    Args:
        spec:          Either a plain path/``-`` OR ``assetnote:<name>``.
                       Non-assetnote specs are returned unchanged.
        refresh:       Re-download even if already cached.
        show_progress: Print a one-line progress indicator to stdout.

    Returns:
        Resolved local file path (unchanged when not an assetnote spec).

    Raises:
        SystemExit: When the named wordlist is not found in the catalogue or
                    the download fails.
    """
    if not spec.startswith(ASSETNOTE_PREFIX):
        return spec

    name_or_alias = spec[len(ASSETNOTE_PREFIX):]
    # Support "assetnote:apiroutes-210328:20000" head-syntax: strip the :N suffix
    # for resolution; the caller handles slicing the file to N lines.
    head_n: int | None = None
    if ":" in name_or_alias:
        name_or_alias, head_part = name_or_alias.rsplit(":", 1)
        try:
            head_n = int(head_part)
        except ValueError:
            pass  # not a head suffix; leave name_or_alias as-is with the colon

    entries = _load_catalogue(refresh=refresh)
    match = _find_entry(entries, name_or_alias)
    if match is None:
        import sys
        logger.error("Assetnote wordlist not found", query=name_or_alias)
        sys.exit(
            f"Error: no Assetnote wordlist matching '{name_or_alias}'.\n"
            f"Run `apileaks wordlist list` to browse available wordlists."
        )

    cache_path = _wordlist_cache_path(match["name"])
    if not refresh and cache_path.exists():
        logger.debug("Using cached wordlist", path=str(cache_path))
        if head_n is not None:
            return _make_head_file(cache_path, head_n)
        return str(cache_path)

    # Download
    _CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    if show_progress:
        print(f"Downloading Assetnote wordlist '{match['alias']}' ({match['filesize']})…")

    try:
        import httpx
        with httpx.Client(timeout=120.0, follow_redirects=True) as client:
            with client.stream("GET", match["url"]) as resp:
                resp.raise_for_status()
                with open(cache_path, "wb") as fh:
                    for chunk in resp.iter_bytes(chunk_size=65536):
                        fh.write(chunk)
        if show_progress:
            size_kb = cache_path.stat().st_size // 1024
            print(f"  ✓ Cached to {cache_path}  ({size_kb} KB)")
        logger.info("Wordlist downloaded", alias=match["alias"], path=str(cache_path))
    except Exception as exc:
        import sys
        sys.exit(f"Error downloading wordlist '{match['alias']}': {exc}")

    if head_n is not None:
        return _make_head_file(cache_path, head_n)
    return str(cache_path)


def _make_head_file(source: Path, n: int) -> str:
    """Write the first ``n`` lines of ``source`` to a temp file and return its path."""
    head_path = _CACHE_ROOT / f"{source.stem}_head{n}{source.suffix}"
    if head_path.exists():
        return str(head_path)
    _CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(source, encoding="utf-8", errors="replace") as src, \
         open(head_path, "w", encoding="utf-8") as dst:
        for line in src:
            if count >= n:
                break
            dst.write(line)
            count += 1
    logger.debug("Head file created", path=str(head_path), lines=count)
    return str(head_path)


def _find_entry(entries: list[dict], query: str) -> dict | None:
    """Find a catalogue entry by alias (exact) or name (substring)."""
    query_lower = query.lower()
    # Exact alias match first
    for e in entries:
        if e["alias"].lower() == query_lower:
            return e
    # Partial name match
    for e in entries:
        if query_lower in e["name"].lower():
            return e
    return None


def fetch_wordlist(name_or_alias: str, refresh: bool = False) -> str:
    """Download a named Assetnote wordlist and return the local cache path.

    Convenience wrapper around :func:`resolve_wordlist` for use from the
    ``wordlist fetch`` CLI subcommand.
    """
    return resolve_wordlist(
        f"{ASSETNOTE_PREFIX}{name_or_alias}",
        refresh=refresh,
        show_progress=True,
    )
