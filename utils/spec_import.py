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
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional
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


# ===========================================================================
# Rich Spec_Schema model + enriched extraction (Requirement 50)
#
# Everything below this line is STRICTLY ADDITIVE. The symbols above
# (``SpecSeed``, ``import_openapi``, ``import_postman``, ``load_spec``,
# ``_parse_document``, ``merge_candidates``, ``normalize_candidate_path``,
# ``OPENAPI_OPERATION_KEYS``, ``DEFAULT_METHOD``, ``SpecImportError``) are
# untouched so ``dir`` discovery seeding and every existing test keep working
# (Requirement 50.6). ``import_schema`` / ``import_postman_schema`` are new and
# populate ``SpecSchema.seeds`` by delegating to the unchanged importers, so the
# ``(path, method)`` seed records are byte-for-byte identical to today's.
# ===========================================================================

# Parameter/body locations recognized in a Spec_Operation. Body parameters (v2
# ``in: body``) and cookie parameters are handled separately / ignored here.
PARAMETER_LOCATIONS = ("path", "query", "header")


@dataclass(frozen=True)
class SpecParameter:
    """A single declared operation parameter (Spec_Parameter, Reqs 50.1, 50.3).

    ``location`` is one of :data:`PARAMETER_LOCATIONS`; ``type`` is the declared
    JSON Schema type (``schema.type`` for OpenAPI v3, the top-level ``type`` for
    Swagger v2), defaulting to ``"string"`` when none is declared. ``enum``,
    ``example``, and ``examples`` carry the declared values when present.
    """

    name: str
    location: str
    type: str = "string"
    required: bool = False
    enum: Optional[List[Any]] = None
    example: Optional[Any] = None
    examples: Optional[List[Any]] = None


@dataclass(frozen=True)
class SpecOperation:
    """A single declared API operation (Spec_Operation, Reqs 50.1, 50.2).

    ``path`` is the declared request path, ``method`` the upper-cased HTTP method
    (normalized via :func:`_normalize_method`). ``parameters`` lists the declared
    path/query/header parameters, ``request_body_schema`` is the raw JSON Schema
    of the request body when the operation declares one (Req 50.2), and
    ``security`` lists the names of the security schemes applied to the operation.
    """

    path: str
    method: str
    parameters: List[SpecParameter] = field(default_factory=list)
    request_body_schema: Optional[Dict[str, Any]] = None
    security: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class SpecSecurityScheme:
    """A declared security scheme (Req 50.4).

    ``type`` is the scheme type (``http``, ``apiKey``, ``oauth2``,
    ``openIdConnect``, ``basic`` ...). ``location`` records an ``apiKey`` scheme's
    ``in`` value (``header``/``query``/``cookie``); ``scheme`` records an ``http``
    scheme's mechanism (``bearer``/``basic``). Both are ``None`` when not declared.
    """

    name: str
    type: str
    location: Optional[str] = None
    scheme: Optional[str] = None


@dataclass(frozen=True)
class SpecSchema:
    """The structured model produced by Spec_Import for a Spec_Source (Req 50).

    Carries the enriched operations AND the legacy ``(path, method)`` seeds so a
    single object serves both discovery seeding and security testing. ``seeds``
    is exactly what :func:`import_openapi` / :func:`import_postman` produce today
    (Req 50.6).
    """

    operations: List[SpecOperation] = field(default_factory=list)
    security_schemes: List[SpecSecurityScheme] = field(default_factory=list)
    seeds: List[SpecSeed] = field(default_factory=list)

    def operation_for(self, path: str, method: str) -> Optional[SpecOperation]:
        """Look up an operation by ``(path, method)``; ``None`` when absent.

        Methods are compared case-insensitively via :func:`_normalize_method`
        so a lookup with ``"get"`` matches a stored ``"GET"`` operation
        (Req 52.6).
        """
        wanted = _normalize_method(method)
        for operation in self.operations:
            if operation.path == path and operation.method == wanted:
                return operation
        return None

    def path_parameters(self, path: str, method: str) -> List[SpecParameter]:
        """Return the declared ``path`` parameters for one operation (Req 53.1).

        Returns an empty list when the operation is unknown or declares no path
        parameters.
        """
        operation = self.operation_for(path, method)
        if operation is None:
            return []
        return [p for p in operation.parameters if p.location == "path"]


def _is_swagger_v2(doc: dict) -> bool:
    """True when the document is a Swagger v2 spec rather than OpenAPI v3.

    OpenAPI v3 documents carry an ``openapi`` key; Swagger v2 documents carry a
    ``swagger`` key. When only ``paths`` is present we default to v3-style
    extraction (``schema.type`` for parameters, ``requestBody`` for bodies).
    """
    return "openapi" not in doc and "swagger" in doc


def _normalize_examples(examples: Any) -> Optional[List[Any]]:
    """Normalize a declared ``examples`` value into a flat list of values.

    OpenAPI v3 declares ``examples`` as a mapping of name -> example object
    (each with a ``value``); Swagger and ad-hoc specs may use a plain list.
    Returns ``None`` when no examples are declared.
    """
    if examples is None:
        return None
    if isinstance(examples, dict):
        values: List[Any] = []
        for entry in examples.values():
            if isinstance(entry, dict) and "value" in entry:
                values.append(entry["value"])
            else:
                values.append(entry)
        return values or None
    if isinstance(examples, list):
        return list(examples) or None
    # Single scalar example under an 'examples' key: wrap it.
    return [examples]


def _extract_parameters(raw_params: Any, is_v2: bool) -> List[SpecParameter]:
    """Map a list of declared parameter objects to :class:`SpecParameter` records.

    Reads ``name``, ``in`` -> ``location``, the declared type (``schema.type`` for
    v3, top-level ``type`` for v2), the ``required`` flag, and ``enum`` /
    ``example`` / ``examples`` values (Reqs 50.1, 50.3). Only parameters whose
    location is in :data:`PARAMETER_LOCATIONS` are kept; body/cookie parameters
    are handled elsewhere or ignored.
    """
    parameters: List[SpecParameter] = []
    if not isinstance(raw_params, list):
        return parameters

    for raw in raw_params:
        if not isinstance(raw, dict):
            continue
        name = raw.get("name")
        location = raw.get("in")
        if not isinstance(name, str) or location not in PARAMETER_LOCATIONS:
            continue

        schema = raw.get("schema") if isinstance(raw.get("schema"), dict) else {}
        if is_v2:
            declared_type = raw.get("type")
            enum = raw.get("enum")
            example = raw.get("example")
        else:
            declared_type = schema.get("type", raw.get("type"))
            enum = schema.get("enum", raw.get("enum"))
            example = raw.get("example", schema.get("example"))

        examples = _normalize_examples(raw.get("examples", schema.get("examples")))

        parameters.append(
            SpecParameter(
                name=name,
                location=location,
                type=declared_type if isinstance(declared_type, str) else "string",
                required=bool(raw.get("required", False)),
                enum=list(enum) if isinstance(enum, list) else None,
                example=example,
                examples=examples,
            )
        )

    return parameters


def _extract_request_body(operation: dict, is_v2: bool) -> Optional[Dict[str, Any]]:
    """Extract the request body schema for an operation, or ``None`` (Req 50.2).

    For OpenAPI v3 the schema is read from ``requestBody.content[*].schema``
    (preferring ``application/json`` when present). For Swagger v2 it is read
    from the operation's ``parameters`` entry whose ``in`` is ``body``.
    """
    if is_v2:
        params = operation.get("parameters")
        if isinstance(params, list):
            for raw in params:
                if isinstance(raw, dict) and raw.get("in") == "body":
                    schema = raw.get("schema")
                    if isinstance(schema, dict):
                        return schema
        return None

    request_body = operation.get("requestBody")
    if not isinstance(request_body, dict):
        return None
    content = request_body.get("content")
    if not isinstance(content, dict) or not content:
        return None

    # Prefer application/json, otherwise take the first declared media type.
    preferred = content.get("application/json")
    if isinstance(preferred, dict) and isinstance(preferred.get("schema"), dict):
        return preferred["schema"]
    for media in content.values():
        if isinstance(media, dict) and isinstance(media.get("schema"), dict):
            return media["schema"]
    return None


def _extract_security(operation: dict) -> List[str]:
    """Return the security scheme names applied to an operation.

    The ``security`` value is a list of requirement objects, each a mapping of
    scheme name -> scope list. The scheme names are flattened, preserving order
    and dropping duplicates.
    """
    security = operation.get("security")
    if not isinstance(security, list):
        return []
    names: List[str] = []
    for requirement in security:
        if isinstance(requirement, dict):
            for scheme_name in requirement:
                if isinstance(scheme_name, str) and scheme_name not in names:
                    names.append(scheme_name)
    return names


def _extract_security_schemes(doc: dict, is_v2: bool) -> List[SpecSecurityScheme]:
    """Extract declared security schemes from a document (Req 50.4).

    Reads ``components.securitySchemes`` for OpenAPI v3 and ``securityDefinitions``
    for Swagger v2. Each declaration becomes a :class:`SpecSecurityScheme` record
    carrying its ``type``, ``in`` -> ``location``, and http ``scheme``.
    """
    if is_v2:
        definitions = doc.get("securityDefinitions")
    else:
        components = doc.get("components")
        definitions = (
            components.get("securitySchemes") if isinstance(components, dict) else None
        )

    schemes: List[SpecSecurityScheme] = []
    if not isinstance(definitions, dict):
        return schemes

    for name, declaration in definitions.items():
        if not isinstance(name, str) or not isinstance(declaration, dict):
            continue
        scheme_type = declaration.get("type")
        schemes.append(
            SpecSecurityScheme(
                name=name,
                type=scheme_type if isinstance(scheme_type, str) else "",
                location=declaration.get("in"),
                scheme=declaration.get("scheme"),
            )
        )
    return schemes


def _extract_operation(
    path: str,
    method: str,
    operation: dict,
    path_level_params: Any,
    is_v2: bool,
) -> SpecOperation:
    """Build a :class:`SpecOperation` from one declared path-item operation.

    Path-item-level parameters (shared by all operations on the path) are merged
    ahead of the operation's own parameters, matching OpenAPI/Swagger semantics.
    """
    combined_params: List[Any] = []
    if isinstance(path_level_params, list):
        combined_params.extend(path_level_params)
    op_params = operation.get("parameters")
    if isinstance(op_params, list):
        combined_params.extend(op_params)

    return SpecOperation(
        path=path,
        method=_normalize_method(method),
        parameters=_extract_parameters(combined_params, is_v2),
        request_body_schema=_extract_request_body(operation, is_v2),
        security=_extract_security(operation),
    )


def import_schema(doc: dict) -> SpecSchema:
    """Extract a rich :class:`SpecSchema` from an OpenAPI v3 / Swagger v2 document.

    Walks the SAME ``paths`` structure used by :func:`import_openapi` (v2 and v3
    share it) and, for each declared operation, extracts its parameters, request
    body schema, and applied security scheme names (Reqs 50.1-50.3, 50.5).
    Top-level security schemes populate ``security_schemes`` (Req 50.4). It also
    calls the unchanged :func:`import_openapi` to populate ``seeds``, guaranteeing
    the ``(path, method)`` records are identical to today's extraction (Req 50.6).
    """
    # Delegate validation + seed extraction to the untouched importer. This
    # raises SpecImportError for a non-dict doc or a doc without a 'paths' object.
    seeds = import_openapi(doc)

    is_v2 = _is_swagger_v2(doc)
    paths = doc.get("paths")

    operations: List[SpecOperation] = []
    if isinstance(paths, dict):
        for path, path_item in paths.items():
            if not isinstance(path, str) or not path.strip():
                continue
            if not isinstance(path_item, dict):
                continue
            path_level_params = path_item.get("parameters")
            for key, operation in path_item.items():
                if (
                    isinstance(key, str)
                    and key.lower() in OPENAPI_OPERATION_KEYS
                    and isinstance(operation, dict)
                ):
                    operations.append(
                        _extract_operation(
                            path, key, operation, path_level_params, is_v2
                        )
                    )

    return SpecSchema(
        operations=operations,
        security_schemes=_extract_security_schemes(doc, is_v2),
        seeds=seeds,
    )


def _postman_query_parameters(url) -> List[SpecParameter]:
    """Best-effort query parameters from a structured Postman ``request.url``."""
    parameters: List[SpecParameter] = []
    if not isinstance(url, dict):
        return parameters
    query = url.get("query")
    if isinstance(query, list):
        for entry in query:
            if isinstance(entry, dict):
                key = entry.get("key")
                if isinstance(key, str) and key:
                    parameters.append(
                        SpecParameter(name=key, location="query")
                    )
    variables = url.get("variable")
    if isinstance(variables, list):
        for entry in variables:
            if isinstance(entry, dict):
                key = entry.get("key")
                if isinstance(key, str) and key:
                    parameters.append(
                        SpecParameter(name=key, location="path")
                    )
    return parameters


def _postman_header_parameters(request: dict) -> List[SpecParameter]:
    """Best-effort header parameters from a Postman ``request.header`` list."""
    parameters: List[SpecParameter] = []
    headers = request.get("header")
    if isinstance(headers, list):
        for entry in headers:
            if isinstance(entry, dict):
                key = entry.get("key")
                if isinstance(key, str) and key:
                    parameters.append(
                        SpecParameter(name=key, location="header")
                    )
    return parameters


def _postman_request_body(request: dict) -> Optional[Dict[str, Any]]:
    """Best-effort request body from a Postman ``request.body`` (raw JSON)."""
    body = request.get("body")
    if not isinstance(body, dict):
        return None
    if body.get("mode") == "raw":
        raw = body.get("raw")
        if isinstance(raw, str) and raw.strip():
            try:
                parsed = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                return None
            if isinstance(parsed, dict):
                return parsed
    return None


def import_postman_schema(doc: dict) -> SpecSchema:
    """Postman analogue of :func:`import_schema` (best-effort enrichment).

    Operations carry best-effort query/header parameters and a raw JSON request
    body derived from each request definition; enum/example values are not
    declared by Postman. ``seeds`` reuses the unchanged :func:`import_postman`,
    so the ``(path, method)`` records are identical to today's extraction
    (Req 50.6).
    """
    seeds = import_postman(doc)

    operations: List[SpecOperation] = []

    def walk(node_list) -> None:
        for node in node_list:
            if not isinstance(node, dict):
                continue
            request = node.get("request")
            if isinstance(request, dict):
                method = request.get("method", DEFAULT_METHOD)
                url = request.get("url")
                path = _postman_request_path(url)
                if path:
                    parameters = _postman_query_parameters(url)
                    parameters.extend(_postman_header_parameters(request))
                    operations.append(
                        SpecOperation(
                            path=path,
                            method=_normalize_method(method),
                            parameters=parameters,
                            request_body_schema=_postman_request_body(request),
                            security=[],
                        )
                    )
            elif isinstance(request, str):
                path = _postman_request_path(request)
                if path:
                    operations.append(
                        SpecOperation(path=path, method=DEFAULT_METHOD)
                    )
            children = node.get("item")
            if isinstance(children, list):
                walk(children)

    items = doc.get("item") if isinstance(doc, dict) else None
    if isinstance(items, list):
        walk(items)

    return SpecSchema(operations=operations, security_schemes=[], seeds=seeds)


# ===========================================================================
# Unified Spec_Source loading: local file OR remote URL (Requirement 51)
#
# STRICTLY ADDITIVE. ``load_schema`` is the single entry point that accepts
# either a local path or an http(s) URL and returns a :class:`SpecSchema`.
# Remote documents are fetched through the shared ``HTTPRequestEngine`` so an
# operator's rate-limit/proxy/TLS controls apply to spec retrieval exactly as
# they do to discovery traffic (Reqs 51.1, 51.5). URL and file sources share
# ONE parsing/dispatch path via the existing OpenAPI/Postman sniffers so the two
# origins produce identical schemas (Req 51.3). The legacy symbols above are
# untouched.
# ===========================================================================


def _is_spec_url(source: str) -> bool:
    """True when ``source`` is a remote Spec_Source_URL rather than a local path.

    A source is treated as a URL when it begins with ``http://`` or ``https://``
    (Req 51.1); anything else is a local filesystem path (Req 51.2).
    """
    return isinstance(source, str) and (
        source.startswith("http://") or source.startswith("https://")
    )


def _parse_spec_text(text: str, source: str) -> dict:
    """Parse a spec document body as JSON, falling back to YAML.

    Mirrors :func:`_parse_document`'s JSON-then-YAML strategy but operates on an
    already-retrieved body (e.g. a fetched URL response). Raises
    :class:`SpecImportError` naming ``source`` when the body is neither valid
    JSON nor valid YAML, or is empty (Req 51.4).
    """
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SpecImportError(
            f"Spec source '{source}' is not valid JSON or YAML: {exc}"
        ) from exc

    if parsed is None:
        raise SpecImportError(f"Spec source '{source}' is empty")
    return parsed


async def _fetch_spec_document(url: str, http_engine) -> dict:
    """Fetch and parse a remote Spec_Source_URL into a parsed document.

    The document is retrieved by issuing a request through the shared
    :class:`~utils.http_client.HTTPRequestEngine` so the operator's
    rate-limit/proxy/TLS controls apply to spec retrieval as well (Reqs 51.1,
    51.5). The response body is parsed as JSON with a YAML fallback via
    :func:`_parse_spec_text`. A failed fetch (status ``0`` / non-2xx) or an
    unparseable body raises :class:`SpecImportError` naming the URL rather than
    crashing (Req 51.4).
    """
    if http_engine is None:
        raise SpecImportError(
            f"Cannot fetch spec source '{url}': no HTTP engine was provided"
        )

    try:
        response = await http_engine.request("GET", url)
    except Exception as exc:  # network/transport failure surfaces as a clean error
        raise SpecImportError(
            f"Cannot fetch spec source '{url}': {exc}"
        ) from exc

    if response is None or not getattr(response, "is_success", False):
        status = getattr(response, "status_code", 0)
        raise SpecImportError(
            f"Cannot fetch spec source '{url}': HTTP status {status}"
        )

    return _parse_spec_text(response.text or "", url)


async def load_schema(source: str, http_engine=None) -> SpecSchema:
    """Load a Spec_Source (local file OR remote URL) into a :class:`SpecSchema`.

    Unified entry point for enriched Spec_Import. When ``source`` is a
    Spec_Source_URL the document is fetched through ``http_engine`` (required for
    URLs) via :func:`_fetch_spec_document` (Reqs 51.1, 51.5); otherwise it is
    read from disk via the existing :func:`_parse_document` routine (Req 51.2).
    The parsed document is dispatched to :func:`import_schema` /
    :func:`import_postman_schema` using the existing
    :func:`_looks_like_openapi` / :func:`_looks_like_postman` sniffers so URL and
    file sources share ONE parsing path (Req 51.3). An unrecognized or
    unparseable document raises :class:`SpecImportError` naming the offending
    source (Reqs 51.4, 49.4).
    """
    if _is_spec_url(source):
        if http_engine is None:
            raise SpecImportError(
                f"Spec source '{source}' is a URL but no HTTP engine was "
                "provided to fetch it"
            )
        doc = await _fetch_spec_document(source, http_engine)
    else:
        doc = _parse_document(source)

    if not isinstance(doc, dict):
        raise SpecImportError(
            f"Spec source '{source}' is not a recognized OpenAPI/Swagger or "
            "Postman document"
        )

    if _looks_like_openapi(doc):
        return import_schema(doc)
    if _looks_like_postman(doc):
        return import_postman_schema(doc)

    raise SpecImportError(
        f"Spec source '{source}' is not a recognized OpenAPI/Swagger or "
        "Postman document"
    )
