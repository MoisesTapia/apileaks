"""
Discovery seed inputs from API specifications and multiple wordlists.

This module is a small, pure (no network, no global state) helper that turns API
descriptions into discovery seeds and merges them with brute-force wordlist
entries into a single, de-duplicated candidate set (Requirement 25).

It supports three Spec_Import sources:

* OpenAPI / Swagger documents (v2 and v3), parsed by :func:`import_openapi`,
  which yields one :class:`SpecSeed` per ``(path, operation)`` pair.
* Postman collections, parsed by :func:`import_postman`, which walks the
  collection's nested ``item`` tree and yields one :class:`SpecSeed` per request.
* :func:`load_spec` sniffs JSON vs YAML, parses the document, detects which kind
  of spec it is, and dispatches to the right importer. An unparseable or
  unrecognized document raises :class:`SpecImportError` naming the source so the
  caller can perform no discovery (Requirement 25.6).

:func:`merge_candidates` merges spec seed paths with one or more wordlists,
de-duplicating by normalized path while preserving first-seen order so the merged
candidate set never contains a duplicate normalized path (Requirements 25.4,
25.8).
"""

import json
from dataclasses import dataclass
from typing import Iterable, List
from urllib.parse import urlsplit

import yaml

from core.logging import get_logger

logger = get_logger(__name__)

# HTTP method keys recognized as per-path operations inside an OpenAPI/Swagger
# path item object. Anything else under a path item (``parameters``, ``$ref``,
# ``summary``, vendor extensions, ...) is not an operation and is ignored.
OPENAPI_OPERATION_KEYS = (
    "get",
    "put",
    "post",
    "delete",
    "options",
    "head",
    "patch",
    "trace",
)

# Default method recorded for a seed whose source does not declare one.
DEFAULT_METHOD = "GET"


class SpecImportError(Exception):
    """Raised when a Spec_Import source cannot be parsed or recognized.

    The message names the offending source so the CLI layer can surface a
    descriptive error and perform no discovery (Requirement 25.6).
    """


@dataclass(frozen=True)
class SpecSeed:
    """A single discovery seed extracted from an API specification.

    ``path`` is the declared request path (e.g. ``/users/{id}``) and ``method``
    is the upper-cased HTTP method for the declared operation.
    """

    path: str
    method: str


def _normalize_method(method: str) -> str:
    """Upper-case and strip an HTTP method token, defaulting when blank."""
    cleaned = (method or "").strip().upper()
    return cleaned or DEFAULT_METHOD


def normalize_candidate_path(value: str) -> str:
    """Return the normalized key used to de-duplicate candidate paths.

    Normalization strips surrounding whitespace, drops a leading scheme/host if
    a full URL was supplied (keeping only the path), removes a single leading
    slash, and strips a trailing slash (except for the bare root). This lets a
    brute-force entry like ``users`` and a spec path like ``/users/`` collapse to
    the same candidate so the merged set holds no duplicate normalized paths
    (Requirements 25.4, 25.8). Case is preserved because URL paths are
    case-sensitive.
    """
    candidate = (value or "").strip()
    if not candidate:
        return ""

    # If a full URL slipped in, keep only the path component.
    if "://" in candidate:
        candidate = urlsplit(candidate).path

    # Drop a single leading slash so "/users" and "users" are equal.
    if candidate.startswith("/"):
        candidate = candidate[1:]

    # Strip a trailing slash but keep a non-empty path otherwise intact.
    if len(candidate) > 1 and candidate.endswith("/"):
        candidate = candidate.rstrip("/")

    return candidate


def import_openapi(doc: dict) -> List[SpecSeed]:
    """Extract ``(path, method)`` seeds from an OpenAPI/Swagger document.

    Handles both Swagger v2 and OpenAPI v3, which share the same ``paths``
    structure: a mapping of path strings to path item objects whose HTTP-method
    keys (``get``, ``post``, ...) declare operations (Requirements 25.1, 25.3).
    Non-operation keys on a path item (``parameters``, ``$ref``, ``summary``,
    vendor extensions) are ignored. Seeds preserve document order; a path with
    no recognized operation yields a single ``GET`` seed so the path still
    becomes a candidate.
    """
    if not isinstance(doc, dict):
        raise SpecImportError("OpenAPI document is not a JSON/YAML object")

    paths = doc.get("paths")
    if not isinstance(paths, dict):
        raise SpecImportError("OpenAPI document has no 'paths' object")

    seeds: List[SpecSeed] = []
    for path, path_item in paths.items():
        if not isinstance(path, str) or not path.strip():
            continue

        operations: List[str] = []
        if isinstance(path_item, dict):
            for key in path_item:
                if isinstance(key, str) and key.lower() in OPENAPI_OPERATION_KEYS:
                    operations.append(key)

        if operations:
            for op in operations:
                seeds.append(SpecSeed(path=path, method=_normalize_method(op)))
        else:
            # A documented path with no explicit operation is still a candidate.
            seeds.append(SpecSeed(path=path, method=DEFAULT_METHOD))

    return seeds


def _postman_request_path(url) -> str:
    """Extract a request path from a Postman ``request.url`` value.

    Postman URLs may be a raw string or a structured object with a ``path``
    array and/or a ``raw`` string. Returns a leading-slash path or an empty
    string when no path can be determined.
    """
    # Structured URL object: prefer the explicit path segment array.
    if isinstance(url, dict):
        segments = url.get("path")
        if isinstance(segments, list) and segments:
            parts = [str(seg).strip("/") for seg in segments if str(seg).strip("/")]
            if parts:
                return "/" + "/".join(parts)
        raw = url.get("raw")
        if isinstance(raw, str):
            return _path_from_raw_url(raw)
        return ""

    # Raw string URL.
    if isinstance(url, str):
        return _path_from_raw_url(url)

    return ""


def _path_from_raw_url(raw: str) -> str:
    """Reduce a raw Postman URL string to its leading-slash path component."""
    raw = (raw or "").strip()
    if not raw:
        return ""
    # Postman raw URLs frequently use {{baseUrl}} variables in place of a host.
    if "://" in raw:
        path = urlsplit(raw).path
    elif raw.startswith("{{"):
        # Strip a leading {{var}} template, keep the remainder as the path.
        closing = raw.find("}}")
        path = raw[closing + 2:] if closing != -1 else ""
        # Drop any query/fragment that trailed the template.
        path = urlsplit(path).path
    else:
        path = urlsplit(raw).path
    if path and not path.startswith("/"):
        path = "/" + path
    return path


def import_postman(doc: dict) -> List[SpecSeed]:
    """Extract ``(path, method)`` seeds from a Postman collection.

    Walks the collection's nested ``item`` tree (folders contain ``item`` arrays;
    leaves contain a ``request``) and yields one :class:`SpecSeed` per request,
    using the request method and URL path (Requirements 25.2, 25.3). Requests
    whose URL yields no path are skipped. Document order is preserved.
    """
    if not isinstance(doc, dict):
        raise SpecImportError("Postman collection is not a JSON/YAML object")

    items = doc.get("item")
    if not isinstance(items, list):
        raise SpecImportError("Postman collection has no 'item' array")

    seeds: List[SpecSeed] = []

    def walk(node_list) -> None:
        for node in node_list:
            if not isinstance(node, dict):
                continue
            request = node.get("request")
            if request is not None:
                if isinstance(request, dict):
                    method = request.get("method", DEFAULT_METHOD)
                    url = request.get("url")
                elif isinstance(request, str):
                    # Shorthand: request is a raw URL string, method defaults.
                    method = DEFAULT_METHOD
                    url = request
                else:
                    method, url = DEFAULT_METHOD, None
                path = _postman_request_path(url)
                if path:
                    seeds.append(SpecSeed(path=path, method=_normalize_method(method)))
            # Folders nest further items; recurse regardless of a request above.
            children = node.get("item")
            if isinstance(children, list):
                walk(children)

    walk(items)
    return seeds


def _looks_like_openapi(doc: dict) -> bool:
    """True when a parsed document looks like an OpenAPI/Swagger spec."""
    return isinstance(doc, dict) and (
        "openapi" in doc or "swagger" in doc or "paths" in doc
    )


def _looks_like_postman(doc: dict) -> bool:
    """True when a parsed document looks like a Postman collection."""
    if not isinstance(doc, dict):
        return False
    if "item" in doc:
        return True
    info = doc.get("info")
    if isinstance(info, dict):
        # Postman's info block references the collection schema.
        schema = info.get("schema", "")
        if isinstance(schema, str) and "getpostman.com" in schema:
            return True
    return False


def _parse_document(path: str) -> dict:
    """Read and parse ``path`` as JSON, falling back to YAML.

    YAML is a superset of JSON, so a single ``yaml.safe_load`` would parse both,
    but trying JSON first keeps error messages precise and avoids surprising
    YAML coercions for JSON files. Raises :class:`SpecImportError` naming the
    source when the file cannot be read or parsed (Requirement 25.6).
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise SpecImportError(f"Cannot read spec source '{path}': {exc}") from exc

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SpecImportError(
            f"Spec source '{path}' is not valid JSON or YAML: {exc}"
        ) from exc

    if parsed is None:
        raise SpecImportError(f"Spec source '{path}' is empty")
    return parsed


def load_spec(path: str) -> List[SpecSeed]:
    """Load, sniff, and parse a Spec_Import source into :class:`SpecSeed` records.

    Sniffs JSON vs YAML, detects whether the document is an OpenAPI/Swagger spec
    or a Postman collection, and dispatches to the matching importer
    (Requirements 25.1, 25.2, 25.3). Raises :class:`SpecImportError` naming the
    source when the document cannot be parsed or is not a recognized spec format
    (Requirement 25.6).
    """
    doc = _parse_document(path)

    if not isinstance(doc, dict):
        raise SpecImportError(
            f"Spec source '{path}' is not a recognized OpenAPI/Swagger or "
            "Postman document"
        )

    # Prefer Postman detection only when it does not also look like OpenAPI:
    # an OpenAPI doc never carries a Postman 'item' array, so checks are
    # mutually exclusive in practice.
    if _looks_like_openapi(doc):
        return import_openapi(doc)
    if _looks_like_postman(doc):
        return import_postman(doc)

    raise SpecImportError(
        f"Spec source '{path}' is not a recognized OpenAPI/Swagger or "
        "Postman document"
    )


def merge_candidates(
    wordlist_entries: Iterable[str],
    spec_seeds: Iterable[SpecSeed],
) -> List[str]:
    """Merge wordlist entries and spec paths into one de-duplicated candidate set.

    Entries are de-duplicated by :func:`normalize_candidate_path` while first-seen
    order is preserved (Requirements 25.4, 25.8). Wordlist entries are considered
    first (preserving their original textual form for discovery), then spec seed
    paths; the first occurrence of each normalized path wins and later duplicates
    are dropped. Blank entries are ignored.
    """
    seen = set()
    merged: List[str] = []

    def add(raw: str) -> None:
        if raw is None:
            return
        text = raw.strip()
        if not text:
            return
        key = normalize_candidate_path(text)
        if not key or key in seen:
            return
        seen.add(key)
        merged.append(text)

    for entry in wordlist_entries:
        add(entry)
    for seed in spec_seeds:
        add(seed.path)

    return merged
