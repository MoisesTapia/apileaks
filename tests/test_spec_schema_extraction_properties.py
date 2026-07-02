"""
Property-Based Tests for rich Spec_Schema extraction (Requirement 50, 57.2).

**Feature: owasp-auth-modules-hardening, Task 50.1**

Two Hypothesis property tests over the additive ``import_schema`` /
``import_postman_schema`` extraction in ``utils/spec_import.py``:

* **Property 28** — the enriched importers preserve the *exact* ``(path, method)``
  seed set produced by the unchanged ``import_openapi`` / ``import_postman``
  extraction (seed round-trip; Req 50.6, 57.2).
* **Property 29** — the enriched importers capture *every* declared parameter
  (with its correct ``location`` / ``type`` / ``required``), every request body,
  every declared ``enum`` / ``example`` / ``examples`` value, and every declared
  security scheme (extraction completeness; Reqs 50.1–50.5).

Generators build minimal-but-valid OpenAPI v3, Swagger v2, and Postman document
dicts, carrying alongside each document the expected metadata so completeness can
be asserted precisely.
"""

import string

from hypothesis import given, settings
from hypothesis import strategies as st
from hypothesis.strategies import composite

from utils.spec_import import (
    PARAMETER_LOCATIONS,
    SpecParameter,
    SpecSecurityScheme,
    import_openapi,
    import_postman,
    import_postman_schema,
    import_schema,
)

# ---------------------------------------------------------------------------
# Shared building-block strategies
# ---------------------------------------------------------------------------

# Names / path segments are drawn from an identifier-safe alphabet so generated
# path strings are non-blank and distinct, and parameter/scheme names are valid
# mapping keys.
NAME_ALPHABET = string.ascii_letters + string.digits + "_"

OPENAPI_METHODS = ["get", "put", "post", "delete", "options", "head", "patch"]

JSON_TYPES = ["string", "integer", "boolean", "number", "array", "object"]


def _names(min_size, max_size):
    """A strategy for lists of distinct identifier-safe names."""
    return st.lists(
        st.text(alphabet=NAME_ALPHABET, min_size=1, max_size=8),
        min_size=min_size,
        max_size=max_size,
        unique=True,
    )


# JSON scalar values used for enum / example / examples. ``None`` is excluded so
# a generated example is always distinguishable from "no example declared".
json_scalars = st.one_of(
    st.text(alphabet=NAME_ALPHABET, min_size=0, max_size=6),
    st.integers(min_value=-1000, max_value=1000),
    st.booleans(),
)


@composite
def param_specs(draw, count_min=0, count_max=4):
    """Draw a list of parameter descriptors with globally distinct names.

    Each descriptor is a plain dict carrying the fields we will emit into a
    document AND compare against the extracted :class:`SpecParameter`.
    """
    names = draw(_names(count_min, count_max))
    specs = []
    for name in names:
        location = draw(st.sampled_from(PARAMETER_LOCATIONS))
        type_str = draw(st.sampled_from(JSON_TYPES))
        required = draw(st.booleans())
        enum = draw(
            st.one_of(
                st.none(),
                st.lists(json_scalars, min_size=1, max_size=4),
            )
        )
        example = draw(st.one_of(st.none(), json_scalars))
        examples = draw(
            st.one_of(
                st.none(),
                st.lists(json_scalars, min_size=1, max_size=3),
            )
        )
        specs.append(
            {
                "name": name,
                "location": location,
                "type": type_str,
                "required": required,
                "enum": enum,
                "example": example,
                "examples": examples,
            }
        )
    return specs


def _expected_param(spec):
    """The :class:`SpecParameter` the extractor should produce for ``spec``."""
    return SpecParameter(
        name=spec["name"],
        location=spec["location"],
        type=spec["type"],
        required=spec["required"],
        enum=list(spec["enum"]) if spec["enum"] is not None else None,
        example=spec["example"],
        examples=list(spec["examples"]) if spec["examples"] is not None else None,
    )


@composite
def body_schemas(draw):
    """Draw a small but structurally-valid JSON-schema-ish request body dict."""
    prop_names = draw(_names(0, 3))
    properties = {
        name: {"type": draw(st.sampled_from(JSON_TYPES))} for name in prop_names
    }
    return {"type": "object", "properties": properties}


@composite
def security_declarations(draw, count_min=0, count_max=3):
    """Draw a mapping of scheme name -> declaration dict, plus expected records."""
    names = draw(_names(count_min, count_max))
    declarations = {}
    expected = {}
    for name in names:
        type_str = draw(
            st.sampled_from(["http", "apiKey", "oauth2", "openIdConnect", "basic"])
        )
        decl = {"type": type_str}
        if draw(st.booleans()):
            decl["in"] = draw(st.sampled_from(["header", "query", "cookie"]))
        if draw(st.booleans()):
            decl["scheme"] = draw(st.sampled_from(["bearer", "basic"]))
        declarations[name] = decl
        expected[name] = SpecSecurityScheme(
            name=name,
            type=type_str,
            location=decl.get("in"),
            scheme=decl.get("scheme"),
        )
    return declarations, expected


# ---------------------------------------------------------------------------
# OpenAPI v3 / Swagger v2 document generators
# ---------------------------------------------------------------------------


def _emit_param(spec, is_v2):
    """Render a parameter descriptor as a v3 or v2 parameter object dict."""
    raw = {"name": spec["name"], "in": spec["location"], "required": spec["required"]}
    if is_v2:
        raw["type"] = spec["type"]
        if spec["enum"] is not None:
            raw["enum"] = spec["enum"]
    else:
        schema = {"type": spec["type"]}
        if spec["enum"] is not None:
            schema["enum"] = spec["enum"]
        raw["schema"] = schema
    if spec["example"] is not None:
        raw["example"] = spec["example"]
    if spec["examples"] is not None:
        raw["examples"] = spec["examples"]
    return raw


@composite
def openapi_document(draw, is_v2):
    """Build a minimal-but-valid v2/v3 doc plus its expected extraction metadata.

    Returns ``(doc, expected_ops, expected_schemes)`` where ``expected_ops`` maps
    ``(path, METHOD)`` to ``{"params": {name: SpecParameter}, "body": schema}``.
    A handful of operation-free "noise" paths are added to stress seed handling;
    they contribute no expected operations.
    """
    path_segments = draw(_names(1, 4))
    paths_obj = {}
    expected_ops = {}

    for seg in path_segments:
        path = "/" + seg
        methods = draw(
            st.lists(st.sampled_from(OPENAPI_METHODS), min_size=1, max_size=3,
                     unique=True)
        )
        path_item = {}
        for method in methods:
            specs = draw(param_specs())
            operation = {}
            if specs:
                operation["parameters"] = [_emit_param(s, is_v2) for s in specs]

            body = None
            if draw(st.booleans()):
                body = draw(body_schemas())
                if is_v2:
                    operation.setdefault("parameters", []).append(
                        {"name": "body", "in": "body", "schema": body}
                    )
                else:
                    operation["requestBody"] = {
                        "content": {"application/json": {"schema": body}}
                    }

            path_item[method] = operation
            expected_ops[(path, method.upper())] = {
                "params": {s["name"]: _expected_param(s) for s in specs},
                "body": body,
            }
        paths_obj[path] = path_item

    # Noise: operation-free paths (only a summary, or empty) still yield seeds.
    for seg in draw(_names(0, 2)):
        noise_path = "/noise_" + seg
        if noise_path not in paths_obj:
            paths_obj[noise_path] = draw(
                st.sampled_from([{}, {"summary": "no operations"}])
            )

    declarations, expected_schemes = draw(security_declarations())

    if is_v2:
        doc = {"swagger": "2.0", "paths": paths_obj}
        if declarations:
            doc["securityDefinitions"] = declarations
    else:
        doc = {"openapi": "3.0.3", "paths": paths_obj}
        if declarations:
            doc["components"] = {"securitySchemes": declarations}

    return doc, expected_ops, expected_schemes


# ---------------------------------------------------------------------------
# Postman collection generator
# ---------------------------------------------------------------------------


@composite
def postman_document(draw):
    """Build a minimal-but-valid Postman collection with a nested item tree."""

    def request_leaf():
        method = draw(st.sampled_from(["GET", "POST", "PUT", "DELETE", "PATCH"]))
        segments = draw(_names(1, 3))
        return {
            "name": "req_" + "_".join(segments),
            "request": {"method": method, "url": {"path": segments}},
        }

    def item_tree(depth):
        leaves = [request_leaf() for _ in range(draw(st.integers(0, 3)))]
        if depth > 0 and draw(st.booleans()):
            folder = {
                "name": "folder",
                "item": [request_leaf() for _ in range(draw(st.integers(1, 3)))],
            }
            leaves.append(folder)
        return leaves

    return {
        "info": {"schema": "https://schema.getpostman.com/json/collection/v2.1.0/"},
        "item": item_tree(depth=1),
    }


# ---------------------------------------------------------------------------
# Property 28 — seed round-trip
# ---------------------------------------------------------------------------


@given(payload=st.one_of(openapi_document(is_v2=False), openapi_document(is_v2=True)))
@settings(max_examples=150, deadline=None)
def test_rich_extraction_preserves_openapi_seed_records(payload):
    # Feature: owasp-auth-modules-hardening, Property 28: Rich extraction preserves the existing (path, method) seed records
    """
    **Feature: owasp-auth-modules-hardening, Property 28: Rich extraction
    preserves the existing (path, method) seed records**
    **Validates: Requirements 50.6, 57.2**

    FOR ALL OpenAPI v3 and Swagger v2 documents, the set of ``(path, method)``
    records in ``import_schema(doc).seeds`` is exactly the set produced by the
    unchanged ``import_openapi(doc)`` extraction — no seed is added, dropped, or
    altered by the enriched importer.
    """
    doc, _expected_ops, _expected_schemes = payload

    rich_seeds = import_schema(doc).seeds
    legacy_seeds = import_openapi(doc)

    rich_set = {(s.path, s.method) for s in rich_seeds}
    legacy_set = {(s.path, s.method) for s in legacy_seeds}

    assert rich_set == legacy_set
    # The invariant is non-vacuous: a document with at least one operation
    # produces at least one seed.
    if _expected_ops:
        assert rich_set


@given(doc=postman_document())
@settings(max_examples=150, deadline=None)
def test_rich_extraction_preserves_postman_seed_records(doc):
    # Feature: owasp-auth-modules-hardening, Property 28: Rich extraction preserves the existing (path, method) seed records
    """
    **Feature: owasp-auth-modules-hardening, Property 28: Rich extraction
    preserves the existing (path, method) seed records**
    **Validates: Requirements 50.6, 57.2**

    FOR ALL Postman documents, the set of ``(path, method)`` records in
    ``import_postman_schema(doc).seeds`` is exactly the set produced by the
    unchanged ``import_postman(doc)`` extraction.
    """
    rich_seeds = import_postman_schema(doc).seeds
    legacy_seeds = import_postman(doc)

    rich_set = {(s.path, s.method) for s in rich_seeds}
    legacy_set = {(s.path, s.method) for s in legacy_seeds}

    assert rich_set == legacy_set


# ---------------------------------------------------------------------------
# Property 29 — extraction completeness
# ---------------------------------------------------------------------------


@given(payload=st.one_of(openapi_document(is_v2=False), openapi_document(is_v2=True)))
@settings(max_examples=150, deadline=None)
def test_rich_extraction_captures_all_declared_metadata(payload):
    # Feature: owasp-auth-modules-hardening, Property 29: Rich extraction captures every declared parameter, body, enum, and security scheme
    """
    **Feature: owasp-auth-modules-hardening, Property 29: Rich extraction
    captures every declared parameter, body, enum, and security scheme**
    **Validates: Requirements 50.1, 50.2, 50.3, 50.4, 50.5**

    FOR ALL generated OpenAPI v3 and Swagger v2 documents:

      - every declared path/query/header parameter appears on its operation with
        the correct ``location``, ``type``, and ``required`` flag (Reqs 50.1,
        50.5), along with any declared ``enum`` / ``example`` / ``examples``
        values (Req 50.3);
      - every operation that declares a request body has that body schema
        recorded (Req 50.2);
      - every declared security scheme is recorded as a ``SpecSecurityScheme``
        (Req 50.4).
    """
    doc, expected_ops, expected_schemes = payload

    schema = import_schema(doc)

    for (path, method), expected in expected_ops.items():
        op = schema.operation_for(path, method)
        assert op is not None, f"missing operation {method} {path}"

        got = {p.name: p for p in op.parameters}
        # Completeness: exactly the declared path/query/header params, no more.
        assert set(got) == set(expected["params"]), (
            f"parameter name set mismatch for {method} {path}: "
            f"{set(got)} != {set(expected['params'])}"
        )
        for name, expected_param in expected["params"].items():
            assert got[name] == expected_param, (
                f"parameter {name} on {method} {path} mismatched: "
                f"{got[name]} != {expected_param}"
            )

        assert op.request_body_schema == expected["body"], (
            f"request body mismatch for {method} {path}"
        )

    by_name = {s.name: s for s in schema.security_schemes}
    for name, expected_scheme in expected_schemes.items():
        assert by_name.get(name) == expected_scheme, (
            f"security scheme {name} mismatched: "
            f"{by_name.get(name)} != {expected_scheme}"
        )
