"""
tests/test_openapi_discoverer.py
Tests for ci-cd/scripts/openapi_discoverer.py

Requirements: 1.1–1.6, 4.1
"""

import json
import logging
import os
import sys
import tempfile

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# Import path injection — ci-cd/scripts has a hyphen so we inject manually.
# ---------------------------------------------------------------------------
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "ci-cd", "scripts"),
)

from openapi_discoverer import (  # noqa: E402
    OpenAPIDiscoverer,
    DiscoveredEndpoint,
    EndpointParameter,
    ScanMeta,
    ID_PARAM_PATTERN,
)

# ===========================================================================
# Fixtures — spec payloads
# ===========================================================================

SPEC_V2_JSON = {
    "swagger": "2.0",
    "info": {"title": "Bank API", "version": "1.0"},
    "basePath": "/api",
    "securityDefinitions": {
        "bearerAuth": {"type": "apiKey", "in": "header", "name": "Authorization"},
    },
    "security": [{"bearerAuth": []}],
    "paths": {
        "/users/{user_id}": {
            "get": {
                "parameters": [
                    {"name": "user_id", "in": "path", "type": "integer", "required": True},
                ],
                "responses": {"200": {"description": "ok"}},
            },
        },
        "/users/{user_id}/accounts/{account_id}": {
            "get": {
                "security": [],   # explicit no-auth override
                "parameters": [
                    {"name": "user_id",    "in": "path",  "type": "integer", "required": True},
                    {"name": "account_id", "in": "path",  "type": "string",  "format": "uuid"},
                ],
                "responses": {"200": {"description": "ok"}},
            },
        },
        "/health": {
            "get": {
                "security": [],
                "responses": {"200": {"description": "ok"}},
            },
        },
    },
}

SPEC_V3_YAML = """
openapi: "3.0.3"
info:
  title: Bank API
  version: "1.0"
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
security:
  - bearerAuth: []
paths:
  /payments/{payment_id}:
    get:
      parameters:
        - name: payment_id
          in: path
          schema:
            type: string
            format: uuid
      responses:
        "200":
          description: ok
  /status:
    get:
      security: []
      responses:
        "200":
          description: ok
"""

SPEC_V31_YAML = """
openapi: "3.1.0"
info:
  title: Inventory API
  version: "2.0"
components:
  securitySchemes:
    apiKey:
      type: apiKey
      in: header
      name: X-API-Key
paths:
  /items/{item_id}:
    get:
      security:
        - apiKey: []
      parameters:
        - name: item_id
          in: path
          schema:
            type: integer
      responses:
        "200":
          description: ok
    post:
      security:
        - apiKey: []
      requestBody:
        content:
          application/json:
            schema:
              type: object
      responses:
        "201":
          description: created
  /items:
    get:
      security: []
      parameters:
        - name: page
          in: query
          schema:
            type: integer
        - name: ref_id
          in: query
          schema:
            type: string
      responses:
        "200":
          description: ok
"""


# ===========================================================================
# Helpers
# ===========================================================================

def _make_file_discoverer(content: str, suffix: str = ".json") -> OpenAPIDiscoverer:
    """Write content to a temp file and return an OpenAPIDiscoverer for it."""
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    )
    tmp.write(content)
    tmp.close()
    return OpenAPIDiscoverer(source_file=tmp.name)


def _make_spec_discoverer(spec_dict: dict) -> OpenAPIDiscoverer:
    """Serialize spec_dict to a temp JSON file and return a discoverer."""
    return _make_file_discoverer(json.dumps(spec_dict), suffix=".json")


# ===========================================================================
# 1. Priority: APILEAK_OPENAPI_FILE > APILEAK_OPENAPI_URL
# ===========================================================================

def test_file_priority_over_url(tmp_path, caplog):
    """When both source_file and source_url are given, file takes priority (Req 1.1)."""
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(SPEC_V2_JSON), encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        d = OpenAPIDiscoverer(
            source_url="https://example.com/openapi.json",
            source_file=str(spec_file),
        )
        d.load()

    # A warning about the URL being ignored must be emitted
    warnings = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("APILEAK_OPENAPI_URL" in w for w in warnings), (
        f"Expected a warning about APILEAK_OPENAPI_URL being ignored, got: {warnings}"
    )
    # The spec should have loaded from the file successfully
    assert d._spec is not None


def test_file_only_no_warning(tmp_path, caplog):
    """When only source_file is given, no 'ignored' warning is emitted."""
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(SPEC_V2_JSON), encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        d = OpenAPIDiscoverer(source_file=str(spec_file))
        d.load()

    url_warnings = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "APILEAK_OPENAPI_URL" in r.message
    ]
    assert url_warnings == []


# ===========================================================================
# 2. load() — JSON and YAML parsing
# ===========================================================================

def test_load_json_spec(tmp_path):
    """load() successfully parses a JSON spec."""
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(SPEC_V2_JSON), encoding="utf-8")
    d = OpenAPIDiscoverer(source_file=str(spec_file))
    result = d.load()
    assert result is not None
    assert result.get("swagger") == "2.0"


def test_load_yaml_spec_v3(tmp_path):
    """load() successfully parses a YAML OpenAPI 3.0.3 spec."""
    spec_file = tmp_path / "spec.yaml"
    spec_file.write_text(SPEC_V3_YAML, encoding="utf-8")
    d = OpenAPIDiscoverer(source_file=str(spec_file))
    result = d.load()
    assert result is not None
    assert result.get("openapi", "").startswith("3.0")


def test_load_yaml_spec_v31(tmp_path):
    """load() successfully parses a YAML OpenAPI 3.1.0 spec."""
    spec_file = tmp_path / "spec.yaml"
    spec_file.write_text(SPEC_V31_YAML, encoding="utf-8")
    d = OpenAPIDiscoverer(source_file=str(spec_file))
    result = d.load()
    assert result is not None
    assert result.get("openapi", "").startswith("3.1")


def test_load_missing_file_logs_warning_continues(caplog):
    """load() on a missing file logs a WARNING and returns None (no exit)."""
    d = OpenAPIDiscoverer(source_file="/nonexistent/path/spec.json")
    with caplog.at_level(logging.WARNING):
        result = d.load()
    assert result is None
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) > 0
    assert any("/nonexistent/path/spec.json" in w.message for w in warnings)


def test_load_invalid_json_yaml_logs_warning_continues(tmp_path, caplog):
    """load() on unparseable content logs a WARNING and returns None (no exit)."""
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{this is: not: valid json or yaml:::}", encoding="utf-8")
    d = OpenAPIDiscoverer(source_file=str(bad_file))
    with caplog.at_level(logging.WARNING):
        result = d.load()
    assert result is None
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) > 0


def test_load_network_error_logs_warning_continues(caplog, monkeypatch):
    """load() on a network error logs a WARNING and returns None (no exit)."""
    import openapi_discoverer as mod

    def _fake_get(*args, **kwargs):
        raise ConnectionError("simulated network failure")

    monkeypatch.setattr(mod, "_REQUESTS_AVAILABLE", True)
    import types
    fake_requests = types.SimpleNamespace(get=_fake_get)
    monkeypatch.setattr(mod, "requests", fake_requests)

    d = OpenAPIDiscoverer(source_url="http://broken.example.com/spec.json")
    with caplog.at_level(logging.WARNING):
        result = d.load()
    assert result is None
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) > 0
    assert any("broken.example.com" in w.message for w in warnings)


# ===========================================================================
# 3. discover_endpoints() — OpenAPI 2.0 (Swagger)
# ===========================================================================

def test_v2_endpoint_count(tmp_path):
    """All three paths from the v2 spec are discovered."""
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(SPEC_V2_JSON), encoding="utf-8")
    d = OpenAPIDiscoverer(source_file=str(spec_file))
    d.load()
    endpoints = d.discover_endpoints()
    paths = {ep.path for ep in endpoints}
    assert "/users/{user_id}" in paths
    assert "/users/{user_id}/accounts/{account_id}" in paths
    assert "/health" in paths


def test_v2_global_security_inherited(tmp_path):
    """/users/{user_id} inherits the global security (is_authenticated=True)."""
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(SPEC_V2_JSON), encoding="utf-8")
    d = OpenAPIDiscoverer(source_file=str(spec_file))
    d.load()
    endpoints = {ep.path: ep for ep in d.discover_endpoints()}
    assert endpoints["/users/{user_id}"].is_authenticated is True
    assert "bearerAuth" in endpoints["/users/{user_id}"].security_schemes


def test_v2_explicit_empty_security_overrides_global(tmp_path):
    """`security: []` on an operation overrides the global security → not authenticated."""
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(SPEC_V2_JSON), encoding="utf-8")
    d = OpenAPIDiscoverer(source_file=str(spec_file))
    d.load()
    endpoints = {ep.path: ep for ep in d.discover_endpoints()}
    assert endpoints["/health"].is_authenticated is False
    assert endpoints["/users/{user_id}/accounts/{account_id}"].is_authenticated is False


def test_v2_id_parameter_detection(tmp_path):
    """user_id (integer) and account_id (string uuid) are detected as ID params."""
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(SPEC_V2_JSON), encoding="utf-8")
    d = OpenAPIDiscoverer(source_file=str(spec_file))
    d.load()
    endpoints = {ep.path: ep for ep in d.discover_endpoints()}
    assert "user_id" in endpoints["/users/{user_id}"].id_parameters
    user_accounts_ep = endpoints["/users/{user_id}/accounts/{account_id}"]
    assert "account_id" in user_accounts_ep.id_parameters


# ===========================================================================
# 4. discover_endpoints() — OpenAPI 3.0.3 (YAML)
# ===========================================================================

def test_v3_endpoint_count(tmp_path):
    """Both paths from the v3 spec are discovered."""
    spec_file = tmp_path / "spec.yaml"
    spec_file.write_text(SPEC_V3_YAML, encoding="utf-8")
    d = OpenAPIDiscoverer(source_file=str(spec_file))
    d.load()
    endpoints = d.discover_endpoints()
    paths = {ep.path for ep in endpoints}
    assert "/payments/{payment_id}" in paths
    assert "/status" in paths


def test_v3_authenticated_endpoint(tmp_path):
    """/payments/{payment_id} inherits global bearerAuth (is_authenticated=True)."""
    spec_file = tmp_path / "spec.yaml"
    spec_file.write_text(SPEC_V3_YAML, encoding="utf-8")
    d = OpenAPIDiscoverer(source_file=str(spec_file))
    d.load()
    endpoints = {ep.path: ep for ep in d.discover_endpoints()}
    assert endpoints["/payments/{payment_id}"].is_authenticated is True
    assert "bearerAuth" in endpoints["/payments/{payment_id}"].security_schemes


def test_v3_unauthenticated_endpoint(tmp_path):
    """/status has security:[] → is_authenticated=False."""
    spec_file = tmp_path / "spec.yaml"
    spec_file.write_text(SPEC_V3_YAML, encoding="utf-8")
    d = OpenAPIDiscoverer(source_file=str(spec_file))
    d.load()
    endpoints = {ep.path: ep for ep in d.discover_endpoints()}
    assert endpoints["/status"].is_authenticated is False


def test_v3_uuid_format_id_param(tmp_path):
    """payment_id (string, uuid) is identified as an ID parameter."""
    spec_file = tmp_path / "spec.yaml"
    spec_file.write_text(SPEC_V3_YAML, encoding="utf-8")
    d = OpenAPIDiscoverer(source_file=str(spec_file))
    d.load()
    endpoints = {ep.path: ep for ep in d.discover_endpoints()}
    assert "payment_id" in endpoints["/payments/{payment_id}"].id_parameters


# ===========================================================================
# 5. discover_endpoints() — OpenAPI 3.1.0 (YAML)
# ===========================================================================

def test_v31_multiple_methods_on_same_path(tmp_path):
    """/items/{item_id} has both GET and POST methods."""
    spec_file = tmp_path / "spec.yaml"
    spec_file.write_text(SPEC_V31_YAML, encoding="utf-8")
    d = OpenAPIDiscoverer(source_file=str(spec_file))
    d.load()
    endpoints = {ep.path: ep for ep in d.discover_endpoints()}
    assert "GET" in endpoints["/items/{item_id}"].methods
    assert "POST" in endpoints["/items/{item_id}"].methods


def test_v31_item_id_and_ref_id_detected(tmp_path):
    """item_id (integer) and ref_id (name matches pattern) are ID parameters."""
    spec_file = tmp_path / "spec.yaml"
    spec_file.write_text(SPEC_V31_YAML, encoding="utf-8")
    d = OpenAPIDiscoverer(source_file=str(spec_file))
    d.load()
    endpoints = {ep.path: ep for ep in d.discover_endpoints()}
    assert "item_id" in endpoints["/items/{item_id}"].id_parameters
    # ref_id matches the pattern .*[_-]?id$
    assert "ref_id" in endpoints["/items"].id_parameters


def test_v31_page_is_id_param_because_integer_type(tmp_path):
    """'page' has type=integer, which is one of the ID-detection criteria (Req 4.1).
    Even though its name doesn't match the pattern, integer type qualifies it."""
    spec_file = tmp_path / "spec.yaml"
    spec_file.write_text(SPEC_V31_YAML, encoding="utf-8")
    d = OpenAPIDiscoverer(source_file=str(spec_file))
    d.load()
    endpoints = {ep.path: ep for ep in d.discover_endpoints()}
    items_ep = endpoints["/items"]
    # Per Req 4.1: type=integer qualifies as an ID parameter
    assert "page" in items_ep.id_parameters


# ===========================================================================
# 6. Filters: get_id_endpoints() and get_authenticated_endpoints()
# ===========================================================================

def test_get_id_endpoints_returns_only_endpoints_with_id_params(tmp_path):
    """get_id_endpoints() returns only endpoints that have id_parameters."""
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(SPEC_V2_JSON), encoding="utf-8")
    d = OpenAPIDiscoverer(source_file=str(spec_file))
    d.load()
    id_eps = d.get_id_endpoints()
    for ep in id_eps:
        assert len(ep.id_parameters) > 0, (
            f"Expected only endpoints with id_parameters, but {ep.path} has none"
        )
    # /health has no parameters at all → must not appear
    paths = {ep.path for ep in id_eps}
    assert "/health" not in paths


def test_get_authenticated_endpoints_returns_only_auth_endpoints(tmp_path):
    """get_authenticated_endpoints() returns only endpoints where is_authenticated=True."""
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(SPEC_V2_JSON), encoding="utf-8")
    d = OpenAPIDiscoverer(source_file=str(spec_file))
    d.load()
    auth_eps = d.get_authenticated_endpoints()
    for ep in auth_eps:
        assert ep.is_authenticated is True, (
            f"Expected only authenticated endpoints, but {ep.path} is not"
        )
    # /health has security:[] → must not appear
    paths = {ep.path for ep in auth_eps}
    assert "/health" not in paths


# ===========================================================================
# 7. write_output()
# ===========================================================================

def test_write_output_creates_file(tmp_path):
    """write_output() creates the JSON file at the expected path."""
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(SPEC_V2_JSON), encoding="utf-8")
    d = OpenAPIDiscoverer(source_file=str(spec_file))
    d.load()
    reports_dir = str(tmp_path / "reports")
    output_path = d.write_output(pipeline_id="test-123", output_dir=reports_dir)
    assert os.path.isfile(output_path)
    assert "openapi-endpoints-test-123.json" in output_path


def test_write_output_valid_json(tmp_path):
    """write_output() produces valid JSON that is a list."""
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(SPEC_V2_JSON), encoding="utf-8")
    d = OpenAPIDiscoverer(source_file=str(spec_file))
    d.load()
    reports_dir = str(tmp_path / "reports")
    output_path = d.write_output(pipeline_id="abc", output_dir=reports_dir)
    with open(output_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    assert isinstance(data, list)
    assert len(data) == 3  # SPEC_V2_JSON has 3 paths


def test_write_output_correct_structure(tmp_path):
    """write_output() serializes DiscoveredEndpoint fields correctly."""
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(SPEC_V2_JSON), encoding="utf-8")
    d = OpenAPIDiscoverer(source_file=str(spec_file))
    d.load()
    reports_dir = str(tmp_path / "reports")
    output_path = d.write_output(pipeline_id="p1", output_dir=reports_dir)
    with open(output_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    # Every serialized endpoint must have the required keys
    required_keys = {"path", "methods", "security_schemes", "is_authenticated",
                     "parameters", "id_parameters"}
    for item in data:
        assert required_keys <= item.keys(), (
            f"Missing keys in serialized endpoint: {required_keys - item.keys()}"
        )


def test_write_output_empty_spec_creates_empty_list(tmp_path):
    """write_output() on an empty paths spec produces an empty JSON array."""
    empty_spec = {"openapi": "3.0.3", "info": {"title": "Empty", "version": "1"}, "paths": {}}
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(empty_spec), encoding="utf-8")
    d = OpenAPIDiscoverer(source_file=str(spec_file))
    d.load()
    reports_dir = str(tmp_path / "reports")
    output_path = d.write_output(pipeline_id="empty", output_dir=reports_dir)
    with open(output_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    assert data == []


# ===========================================================================
# 8. discover_endpoints() returns empty list when load() not called / failed
# ===========================================================================

def test_discover_endpoints_without_load_returns_empty():
    """discover_endpoints() returns [] when _spec is None (load not yet called)."""
    d = OpenAPIDiscoverer(source_file="/nonexistent.json")
    # Do NOT call load(); _spec stays None
    assert d.discover_endpoints() == []


def test_discover_endpoints_after_failed_load_returns_empty(caplog):
    """discover_endpoints() returns [] when load() encountered an error."""
    d = OpenAPIDiscoverer(source_file="/nonexistent.json")
    with caplog.at_level(logging.WARNING):
        d.load()
    assert d.discover_endpoints() == []


# ===========================================================================
# 9. ID_PARAM_PATTERN — unit tests for the regex
# ===========================================================================

@pytest.mark.parametrize("name,expected", [
    ("user_id", True),
    ("userId", True),
    ("id", True),
    ("account-id", True),
    ("ref_id", True),
    ("payment_id", True),
    ("ID", True),
    ("name", False),
    ("page", False),
    ("limit", False),
    ("idempotency_key", False),
    ("child", False),
])
def test_id_param_pattern(name, expected):
    assert bool(ID_PARAM_PATTERN.match(name)) == expected, (
        f"ID_PARAM_PATTERN.match({name!r}) expected {expected}"
    )


# ===========================================================================
# 10. Property 3 — Round-trip stability (Req 1.6)
#
#     For any valid spec, serializing discover_endpoints() to JSON and
#     re-parsing must produce the identical set of DiscoveredEndpoint objects.
#
#     **Validates: Requirements 1.6**
# ===========================================================================

def _minimal_v2_spec_with_endpoints(paths_dict: dict) -> dict:
    """Build a minimal OpenAPI 2.0 spec from a paths dict."""
    return {
        "swagger": "2.0",
        "info": {"title": "T", "version": "1"},
        "paths": paths_dict,
    }


# Hypothesis strategies
_param_location = st.sampled_from(["path", "query"])
_param_type     = st.sampled_from(["integer", "string", "boolean"])
_param_name_st  = st.from_regex(r"[a-z][a-z0-9_]{0,15}", fullmatch=True)

@st.composite
def _raw_parameter_strategy(draw):
    name     = draw(_param_name_st)
    location = draw(_param_location)
    ptype    = draw(_param_type)
    fmt      = draw(st.one_of(st.none(), st.just("uuid")))
    p = {"name": name, "in": location, "type": ptype}
    if fmt:
        p["format"] = fmt
    return p


@st.composite
def _operation_strategy(draw):
    params = draw(st.lists(_raw_parameter_strategy(), min_size=0, max_size=4))
    has_security = draw(st.booleans())
    op: dict = {"responses": {"200": {"description": "ok"}}, "parameters": params}
    if not has_security:
        op["security"] = []
    return op


@st.composite
def _spec_strategy(draw):
    """Generate a minimal but varied OpenAPI 2.0 spec dict."""
    path_count = draw(st.integers(min_value=1, max_value=5))
    paths = {}
    for i in range(path_count):
        path = f"/resource{i}/{{id{i}}}"
        method = draw(st.sampled_from(["get", "post", "put", "delete"]))
        op = draw(_operation_strategy())
        paths[path] = {method: op}
    return _minimal_v2_spec_with_endpoints(paths)


@given(spec=_spec_strategy())
@settings(max_examples=100, deadline=5000)
def test_round_trip_stability(spec):
    """
    Property 3 — Round-trip stability (Req 1.6)

    For any valid spec, serializing discover_endpoints() to JSON and
    re-parsing it must produce the identical set of DiscoveredEndpoint objects.

    **Validates: Requirements 1.6**
    """
    import tempfile

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(json.dumps(spec))
        tmp_path = tmp.name

    try:
        d = OpenAPIDiscoverer(source_file=tmp_path)
        d.load()
        original_endpoints = d.discover_endpoints()

        # Serialize
        serialized = json.dumps([ep.to_dict() for ep in original_endpoints])

        # Re-parse
        restored_endpoints = [
            DiscoveredEndpoint.from_dict(item) for item in json.loads(serialized)
        ]

        assert set(original_endpoints) == set(restored_endpoints), (
            "Round-trip serialization produced a different set of DiscoveredEndpoint objects"
        )
    finally:
        os.unlink(tmp_path)
