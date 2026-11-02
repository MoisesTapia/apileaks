"""
Wordlist command family — Assetnote wordlist catalogue (list/fetch/cache).

Extracted from ``apileaks.py`` (monolith decomposition, Phase 2). Registered onto
the root ``cli`` by ``apileaks.py`` via ``cli.add_command(wordlist_group)``.
"""

from __future__ import annotations

import sys

import click


@click.group(name="wordlist")
def wordlist_group():
    """Manage Assetnote wordlists (download, cache, list).

    \b
    Wordlists are fetched from wordlists.assetnote.io and cached in
    ~/.cache/apileaks/wordlists/.

    \b
    Use the assetnote: prefix in --wordlist to auto-download on demand:
      apileaks dir --target https://api.example.com \\
                   --wordlist assetnote:apiroutes-210328:20000
    """


@wordlist_group.command(name="list")
@click.option(
    "--filter",
    "-f",
    "filter_term",
    default=None,
    metavar="TERM",
    help="Filter wordlists by name/alias substring (e.g. 'apiroutes').",
)
@click.option(
    "--refresh",
    is_flag=True,
    default=False,
    help="Force re-fetch of the catalogue even if recently cached.",
)
@click.option(
    "--limit",
    type=int,
    default=50,
    show_default=True,
    help="Maximum number of entries to display (0 = unlimited).",
)
def wordlist_list(filter_term, refresh, limit):
    """List available Assetnote wordlists.

    \b
    Examples:
      apileaks wordlist list
      apileaks wordlist list --filter apiroutes
      apileaks wordlist list --filter aspx --limit 20
    """
    from utils.wordlist_manager import list_wordlists

    try:
        entries = list_wordlists(
            filter_term=filter_term, refresh=refresh, limit=limit if limit > 0 else 0
        )
    except Exception as exc:
        click.echo(f"Error fetching catalogue: {exc}", err=True)
        sys.exit(1)

    if not entries:
        click.echo("No wordlists matched the filter." if filter_term else "No wordlists found.")
        return

    # Header
    col_alias = 36
    col_count = 9
    col_size = 10
    col_cached = 8
    header = (
        f"{'ALIAS':<{col_alias}} {'COUNT':>{col_count}} {'SIZE':>{col_size}}"
        f"  {'CACHED':<{col_cached}}  FILENAME"
    )
    click.echo(f"\n{header}")
    click.echo("─" * 100)
    for e in entries:
        alias = e["alias"][: col_alias - 1] if len(e["alias"]) > col_alias else e["alias"]
        count = f"{e['count']:,}" if e["count"] else "—"
        size = e["filesize"] or "—"
        cached = "✓" if e["cached"] else ""
        click.echo(
            f"{alias:<{col_alias}} {count:>{col_count}} {size:>{col_size}}"
            f"  {cached:<{col_cached}}  {e['name']}"
        )
    click.echo()
    click.echo(
        "Usage: apileaks dir --target URL "
        "--wordlist assetnote:<ALIAS>  (or  assetnote:<ALIAS>:<N> for first N lines)"
    )
    click.echo()


@wordlist_group.command(name="fetch")
@click.argument("name")
@click.option("--refresh", is_flag=True, default=False, help="Re-download even if already cached.")
def wordlist_fetch(name, refresh):
    """Download and cache an Assetnote wordlist by alias or filename.

    NAME is the alias (e.g. apiroutes-210328) or filename
    (e.g. httparchive_apiroutes_2021_03_28.txt).

    \b
    Examples:
      apileaks wordlist fetch apiroutes-210328
      apileaks wordlist fetch raft-large-words --refresh
    """
    from utils.wordlist_manager import fetch_wordlist

    try:
        path = fetch_wordlist(name, refresh=refresh)
        click.echo(f"Wordlist ready: {path}")
    except SystemExit as exc:
        click.echo(str(exc), err=True)
        sys.exit(1)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


@wordlist_group.command(name="cache")
def wordlist_cache():
    """Show the local wordlist cache location and its contents."""
    from utils.wordlist_manager import _CACHE_ROOT

    click.echo(f"\nCache directory: {_CACHE_ROOT}")

    if not _CACHE_ROOT.exists():
        click.echo("  (empty — no wordlists downloaded yet)")
        return

    files = sorted(_CACHE_ROOT.glob("*"))
    total_bytes = 0
    shown = 0
    for f in files:
        if f.name.startswith("_catalogue_"):
            continue  # skip catalogue files
        size = f.stat().st_size
        total_bytes += size
        size_kb = size // 1024
        click.echo(f"  {size_kb:>8} KB  {f.name}")
        shown += 1

    if shown == 0:
        click.echo("  (no wordlists cached yet)")
    else:
        click.echo(f"\n  {shown} file(s), {total_bytes // 1024:,} KB total")
    click.echo()
