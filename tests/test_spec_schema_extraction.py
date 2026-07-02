"""
Unit tests for the rich Spec_Schema extraction (Requirement 50).

**Feature: owasp-auth-modules-hardening, Task 41.1**

These tests cover the additive ``import_schema`` / ``import_postman_schema``
extraction in ``utils/spec_import.py``:

* parameters with location/type/required for OpenAPI v3 and Swagger v2
  (Requirements 50.1, 50.5),
* request body schema extraction (v3 ``requestBody.content[*].schema`` and v2
  body parameter ``schema``) (Requirement 50.2),
* enum/example/examples recording (Requirement 50.3),
* declared security schemes (v3 ``components.securitySchemes`` / v2
  ``securityDefinitions``) (Requirement 50.4),
* ``SpecSchema.seeds`` equalling the unchanged ``import_openapi`` /
  ``import_postman`` extraction (Requirement 50.6),
* the ``operation_for`` / ``path_parameters`` lookup helpers.
"""

from utils.spec_import import (
    PARAMETER_LOCATIONS,
    SpecOperation,
    SpecParameter,
    SpecSchema,
    SpecSecurityScheme,
    SpecSeed,
    import_openapi,
    import_postman,
    import_postman_schema,
    import_schema,
)


# ===========================================================================
# PARAMETER_LOCATIONS constant
# ===========================================================================

def test_parameter_locations_constant():
    """PARAMETER_LOCATIONS lists the three recognized parameter locations."""
    assert PARAMETER_LOCATIONS == ("path", "query", "header")


# ===========================================================================
# import_schema: OpenAPI v3 (Requirements 50.1, 50.2, 50.3, 50.5)
# ===========================================================================

def test_import_schema_v3_extracts_parameters_with_location_type_required():
    """v3 parameters record name, location, schema.type, and required flag.

    **Validates: Requirements 50.1, 50.5**
    """
    doc = {
        "openapi": "3.0.3",
        "paths": {
            "/users/{id}": {
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }
                ],
                "get": {
                    "parameters": [
                        {
                            "name": "verbose",
                            "in": "query",
                            "schema": {"type": "boolean"},
                        },
                        {
                            "name": "X-Trace",
                            "in": "header",
                            "schema": {"type": "string"},
                        },
                        # Cookie params are not in PARAMETER_LOCATIONS -> ignored.
                        {"name": "sid", "in": "cookie", "schema": {"type": "string"}},
                    ]
                },
            }
        },
    }

    schema = import_schema(doc)
    op = schema.operation_for("/users/{id}", "GET")

    assert op is not None
    assert op.method == "GET"
    params = {p.name: p for p in op.parameters}
    assert params["id"] == SpecParameter(
        name="id", location="path", type="integer", required=True
    )
    assert params["verbose"].location == "query"
    assert params["verbose"].type == "boolean"
    assert params["verbose"].required is False
    assert params["X-Trace"].location == "header"
    assert "sid" not in params  # cookie params excluded


def test_import_schema_v3_extracts_request_body_schema():
    """v3 requestBody.content[*].schema is recorded (application/json preferred).

    **Validates: Requirements 50.2**
    """
    body_schema = {
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
    }
    doc = {
        "openapi": "3.0.0",
        "paths": {
            "/users": {
                "post": {
                    "requestBody": {
                        "content": {"application/json": {"schema": body_schema}}
                    }
                }
            }
        },
    }

    schema = import_schema(doc)
    op = schema.operation_for("/users", "POST")

    assert op is not None
    assert op.request_body_schema == body_schema


def test_import_schema_v3_records_enum_example_examples():
    """enum/example/examples values are recorded for parameters (Req 50.3).

    **Validates: Requirements 50.3**
    """
    doc = {
        "openapi": "3.0.0",
        "paths": {
            "/items": {
                "get": {
                    "parameters": [
                        {
                            "name": "status",
                            "in": "query",
                            "schema": {
                                "type": "string",
                                "enum": ["active", "inactive"],
                            },
                            "example": "active",
                            "examples": {
                                "first": {"value": "active"},
                                "second": {"value": "inactive"},
                            },
                        }
                    ]
                }
            }
        },
    }

    schema = import_schema(doc)
    op = schema.operation_for("/items", "GET")
    param = op.parameters[0]

    assert param.enum == ["active", "inactive"]
    assert param.example == "active"
    assert param.examples == ["active", "inactive"]


def test_import_schema_v3_extracts_security_schemes_and_op_security():
    """v3 components.securitySchemes and per-op security are recorded (Req 50.4).

    **Validates: Requirements 50.4**
    """
    doc = {
        "openapi": "3.0.0",
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer"},
                "apiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
            }
        },
        "paths": {
            "/secure": {
                "get": {"security": [{"bearerAuth": []}]}
            }
        },
    }

    schema = import_schema(doc)

    by_name = {s.name: s for s in schema.security_schemes}
    assert by_name["bearerAuth"] == SpecSecurityScheme(
        name="bearerAuth", type="http", location=None, scheme="bearer"
    )
    assert by_name["apiKeyAuth"] == SpecSecurityScheme(
        name="apiKeyAuth", type="apiKey", location="header", scheme=None
    )

    op = schema.operation_for("/secure", "GET")
    assert op.security == ["bearerAuth"]


# ===========================================================================
# import_schema: Swagger v2 (Requirements 50.1, 50.2, 50.4, 50.5)
# ===========================================================================

def test_import_schema_v2_extracts_parameters_and_body_and_schemes():
    """Swagger v2 uses top-level type, body params, and securityDefinitions.

    **Validates: Requirements 50.1, 50.2, 50.4, 50.5**
    """
    body_schema = {"type": "object", "properties": {"q": {"type": "string"}}}
    doc = {
        "swagger": "2.0",
        "securityDefinitions": {
            "basicAuth": {"type": "basic"},
            "keyAuth": {"type": "apiKey", "in": "query", "name": "token"},
        },
        "paths": {
            "/search": {
                "post": {
                    "parameters": [
                        {
                            "name": "q",
                            "in": "query",
                            "required": True,
                            "type": "string",
                            "enum": ["a", "b"],
                        },
                        {"name": "body", "in": "body", "schema": body_schema},
                    ]
                }
            }
        },
    }

    schema = import_schema(doc)
    op = schema.operation_for("/search", "POST")

    q = next(p for p in op.parameters if p.name == "q")
    assert q.location == "query"
    assert q.type == "string"
    assert q.required is True
    assert q.enum == ["a", "b"]
    # The body parameter is captured as the request body schema, not a param.
    assert op.request_body_schema == body_schema
    assert all(p.location in PARAMETER_LOCATIONS for p in op.parameters)

    by_name = {s.name: s for s in schema.security_schemes}
    assert by_name["basicAuth"].type == "basic"
    assert by_name["keyAuth"].type == "apiKey"
    assert by_name["keyAuth"].location == "query"


# ===========================================================================
# import_schema: seed preservation (Requirement 50.6)
# ===========================================================================

def test_import_schema_seeds_match_import_openapi():
    """SpecSchema.seeds equals the unchanged import_openapi extraction.

    **Validates: Requirements 50.6**
    """
    doc = {
        "openapi": "3.0.0",
        "paths": {
            "/users": {"get": {}, "post": {}},
            "/ping": {"summary": "no ops"},
        },
    }

    schema = import_schema(doc)

    assert schema.seeds == import_openapi(doc)
    # A path with no operation yields a seed but no enriched operation.
    assert SpecSeed(path="/ping", method="GET") in schema.seeds
    assert schema.operation_for("/ping", "GET") is None


def test_import_schema_invalid_document_raises_like_import_openapi():
    """import_schema delegates validation to import_openapi (naming the issue).

    **Validates: Requirements 50.6**
    """
    import pytest

    from utils.spec_import import SpecImportError

    with pytest.raises(SpecImportError):
        import_schema({"openapi": "3.0.0"})  # no 'paths'


# ===========================================================================
# SpecSchema helpers
# ===========================================================================

def test_operation_for_is_case_insensitive_on_method():
    """operation_for matches methods case-insensitively; missing -> None."""
    schema = SpecSchema(
        operations=[SpecOperation(path="/x", method="GET")],
    )
    assert schema.operation_for("/x", "get") is not None
    assert schema.operation_for("/x", "POST") is None
    assert schema.operation_for("/missing", "GET") is None


def test_path_parameters_returns_only_path_location_params():
    """path_parameters returns only path-location params for an operation."""
    op = SpecOperation(
        path="/users/{id}",
        method="GET",
        parameters=[
            SpecParameter(name="id", location="path"),
            SpecParameter(name="verbose", location="query"),
        ],
    )
    schema = SpecSchema(operations=[op])

    path_params = schema.path_parameters("/users/{id}", "GET")
    assert [p.name for p in path_params] == ["id"]
    assert schema.path_parameters("/missing", "GET") == []


# ===========================================================================
# import_postman_schema (Requirement 50.6 + best-effort enrichment)
# ===========================================================================

def test_import_postman_schema_seeds_match_import_postman():
    """import_postman_schema.seeds equals the unchanged import_postman.

    **Validates: Requirements 50.6**
    """
    doc = {
        "info": {"schema": "https://schema.getpostman.com/v2.1.0"},
        "item": [
            {
                "name": "List",
                "request": {
                    "method": "GET",
                    "url": {
                        "raw": "{{baseUrl}}/users?verbose=1",
                        "path": ["users"],
                        "query": [{"key": "verbose", "value": "1"}],
                    },
                    "header": [{"key": "X-Trace", "value": "1"}],
                },
            },
            {
                "name": "Create",
                "request": {
                    "method": "POST",
                    "url": {"path": ["users"]},
                    "body": {"mode": "raw", "raw": "{\"name\": \"a\"}"},
                },
            },
        ],
    }

    schema = import_postman_schema(doc)

    assert schema.seeds == import_postman(doc)

    get_op = schema.operation_for("/users", "GET")
    assert get_op is not None
    param_locations = {(p.name, p.location) for p in get_op.parameters}
    assert ("verbose", "query") in param_locations
    assert ("X-Trace", "header") in param_locations

    post_op = schema.operation_for("/users", "POST")
    assert post_op.request_body_schema == {"name": "a"}
