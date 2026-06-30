"""
URL normalization for discovery deduplication (Requirement 38).

This module defines a single pure, idempotent helper, :func:`normalize_url`,
that canonicalizes a discovered or candidate URL so that the same logical
endpoint is tested and stored only once. It is consumed by ``EndpointFuzzer``
(see task 42.2) before the existing ``tested_urls`` membership check in
``_fuzz_wordlist`` and before storage in ``_test_endpoint``/``_handle_redirect``,
extending — not replacing — the existing ``tested_urls`` deduplication.

The canonical form (Requirement 38.2) comprises:

1. **Scheme / host lower-casing** — the scheme and host are case-insensitive,
   so both are lower-cased. User-info (``user:pass@``) is case-sensitive and is
   preserved.
2. **Default-port removal** — ``:80`` is dropped for ``http`` and ``:443`` for
   ``https``. Ports for other schemes, and non-default ports, are preserved.
3. **Percent-encoding case normalization** — the two hex digits of every
   ``%XX`` escape are upper-cased (e.g. ``%2f`` → ``%2F``). No characters are
   otherwise decoded or re-encoded, which keeps the operation idempotent.
4. **Dot-segment resolution** — ``.`` and ``..`` path segments are collapsed per
   RFC 3986 §5.2.4 (e.g. ``/a/./b/../c`` → ``/a/c``).
5. **Trailing-slash policy** — trailing slashes are stripped from a non-root
   path (``/users/`` → ``/users``, ``/users//`` → ``/users``); a path that
   collapses to empty normalizes to the root ``/`` (``///`` → ``/``), which is
   itself preserved. Stripping all trailing slashes (rather than one) keeps the
   policy a fixed point so the operation stays idempotent. Internal
   (non-trailing) empty segments are preserved per RFC.

The query and fragment are preserved as-is apart from percent-encoding case
normalization; the query is **not** reordered.

The function is pure (no I/O, no global state) and idempotent
(``normalize_url(normalize_url(u)) == normalize_url(u)``), satisfying
Requirements 38.4 and 38.5.
"""

import re
from urllib.parse import urlsplit, urlunsplit

__all__ = ["normalize_url"]

# Matches a single percent-encoding escape (a '%' followed by two hex digits).
_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")

# Default ports that are dropped when they match the URL scheme (Requirement 38.2).
_DEFAULT_PORTS = {"http": "80", "https": "443"}


def _upper_percent_escapes(text: str) -> str:
    """Upper-case the hex digits of every ``%XX`` escape in ``text``.

    Only well-formed escapes (``%`` followed by exactly two hex digits) are
    touched; a lone ``%`` or any other character is left unchanged, so the
    transformation is idempotent (Requirement 38.2, 38.5).
    """
    return _PERCENT_ESCAPE.sub(lambda match: match.group(0).upper(), text)


def _normalize_netloc(netloc: str, scheme: str) -> str:
    """Normalize the network location: lower-case host and drop default ports.

    User-info is case-sensitive and preserved (only its percent-encoding case is
    normalized). The host is lower-cased (case-insensitive). A port equal to the
    scheme's default (``80``/``http``, ``443``/``https``) is removed, and an
    empty port (a bare trailing ``:``) is dropped. IPv6 literals in brackets are
    handled without disturbing their contents.
    """
    if not netloc:
        return netloc

    userinfo = ""
    hostport = netloc
    if "@" in hostport:
        userinfo, hostport = hostport.rsplit("@", 1)

    # Separate host from port, accounting for bracketed IPv6 literals.
    if hostport.startswith("["):
        end = hostport.find("]")
        if end != -1:
            host = hostport[: end + 1]
            rest = hostport[end + 1 :]
            port = rest[1:] if rest.startswith(":") else ""
        else:
            # Malformed bracket; treat the whole thing as the host.
            host = hostport
            port = ""
    elif ":" in hostport:
        host, _, port = hostport.rpartition(":")
    else:
        host = hostport
        port = ""

    host = _upper_percent_escapes(host).lower()

    # Drop a default or empty port; keep any other explicit port.
    if port == "" or _DEFAULT_PORTS.get(scheme) == port:
        authority = host
    else:
        authority = f"{host}:{port}"

    if userinfo:
        authority = f"{_upper_percent_escapes(userinfo)}@{authority}"

    return authority


def _remove_dot_segments(path: str) -> str:
    """Collapse ``.`` and ``..`` segments per RFC 3986 §5.2.4.

    Implements the reference ``remove_dot_segments`` algorithm. Empty segments
    (``//``) are intentionally preserved, matching the RFC. The transformation
    is idempotent: a path with no ``.``/``..`` segments is returned unchanged.
    """
    output = []
    buf = path
    while buf:
        if buf.startswith("../"):
            buf = buf[3:]
        elif buf.startswith("./"):
            buf = buf[2:]
        elif buf.startswith("/./"):
            buf = "/" + buf[3:]
        elif buf == "/.":
            buf = "/"
        elif buf.startswith("/../"):
            buf = "/" + buf[4:]
            if output:
                output.pop()
        elif buf == "/..":
            buf = "/"
            if output:
                output.pop()
        elif buf in (".", ".."):
            buf = ""
        else:
            # Move the first path segment (including any leading '/') to output.
            start = 1 if buf.startswith("/") else 0
            slash = buf.find("/", start)
            if slash == -1:
                output.append(buf)
                buf = ""
            else:
                output.append(buf[:slash])
                buf = buf[slash:]
    return "".join(output)


def _normalize_path(path: str) -> str:
    """Resolve dot-segments, normalize escape case, and apply trailing-slash policy."""
    path = _upper_percent_escapes(path)
    path = _remove_dot_segments(path)
    # Trailing-slash policy: strip all trailing slashes from a non-root path so
    # the result is a fixed point (idempotent), regardless of how many trailing
    # slashes the dot-segment-resolved path carries. A path that collapses to
    # empty (e.g. '/', '///') normalizes to the root '/'. Internal (non-trailing)
    # empty segments are left untouched, preserving RFC behaviour.
    if path.endswith("/"):
        stripped = path.rstrip("/")
        path = stripped if stripped else "/"
    return path


def normalize_url(url: str) -> str:
    """Return the canonical form of ``url``.

    Applies, in order: scheme/host lower-casing, default-port removal,
    percent-encoding case normalization, RFC 3986 dot-segment resolution, and
    the trailing-slash policy (strip trailing slashes from non-root
    paths down to a stable form; collapse-to-empty paths and the root are
    normalized to ``/``). The query and fragment are preserved as-is
    apart from percent-encoding case normalization, and the query is not
    reordered.

    The function is pure and idempotent: for all URLs,
    ``normalize_url(normalize_url(u)) == normalize_url(u)`` (Requirements 38.4,
    38.5), and a URL already in canonical form is returned unchanged.

    Args:
        url: The candidate or discovered URL to canonicalize.

    Returns:
        The canonical URL string.
    """
    scheme, netloc, path, query, fragment = urlsplit(url)

    scheme = scheme.lower()
    netloc = _normalize_netloc(netloc, scheme)
    path = _normalize_path(path)
    query = _upper_percent_escapes(query)
    fragment = _upper_percent_escapes(fragment)

    return urlunsplit((scheme, netloc, path, query, fragment))
