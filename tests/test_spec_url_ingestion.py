"""
Example-based unit tests for URL-based Spec_Source ingestion (Requirement 51).

**Feature: owasp-auth-modules-hardening, Task 51.1**

``utils.spec_import.load_schema`` is the single entry point that accepts either a
local file path or an ``http(s)`` Spec_Source_URL and returns a ``SpecSchema``.
These worked examples pin the four required behaviors:

* a ``http(s)`` source is retrieved by issuing a request through the shared
  ``HTTPRequestEngine`` (Req 51.1);
* a local path is read from disk via the file reader, never the engine (Req 51.2);
* a URL and a local file carrying the same document produce identical schemas,
  because both share one parsing/dispatch path (Req 51.3);
* a failing fetch or an unparseable body raises a descriptive error naming the
  offending URL (Req 51.4).

A mocked ``HTTPRequestEngine`` stands in for the network so no real request is
issued.
"""

import asyncio
import json

import pytest

from utils.http_client import HTTPRequestEngine, Response
from utils.spec_import import SpecImportError, load_schema


SPEC_URL = "https://api.example.com/openapi.json"

OPENAPI_DOC = {
    "openapi": "3.0.3",
    "paths": {
        "/users/{id}": {
            "get": {
                "parameters": [
                    {"name": "id", "in": "path", "required": True,
                     "schema": {"type": "integer"}},
                ]
            },
            "post": {},
        },
        "/orders": {"get": {}},
    },
    "components": {
        "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}
    },
}


def _response(body, status_code=200, url=SPEC_URL):
    text = body if isinstance(body, str) else json.dumps(body)
    return Response(
        status_code=status_code,
        headers={"content-type": "application/json"},
        content=text.encode(),
        text=text,
        url=url,
        elapsed=0.01,
        request_method="GET",
    )


class FakeEngine:
    """Async HTTP engine double recording every issued ``(method, url)``."""

    def __init__(self, response=None, raise_exc=None):
        self._response = response
        self._raise = raise_exc
        self.calls = []

    async def request(self, method, url, **kwargs):
        self.calls.append((str(method).upper(), url))
        if self._raise is not None:
            raise self._raise
        return self._response


def _write(tmp_path, name, doc):
    path = tmp_path / name
    path.write_text(json.dumps(doc))
    return str(path)


# ---------------------------------------------------------------------------
# 51.1 - URL source fetched through the HTTP engine
# ---------------------------------------------------------------------------

def test_url_source_fetched_through_http_engine():
    """An ``http(s)`` source is retrieved via ``engine.request('GET', url)``.

    **Validates: Requirement 51.1**
    """
    engine = FakeEngine(response=_response(OPENAPI_DOC))

    schema = asyncio.run(load_schema(SPEC_URL, http_engine=engine))

    assert engine.calls == [("GET", SPEC_URL)]
    op_paths = {op.path for op in schema.operations}
    assert {"/users/{id}", "/orders"} <= op_paths
    assert any(s.name == "bearerAuth" for s in schema.security_schemes)


def test_url_source_without_engine_errors_naming_url():
    """A URL source with no engine supplied raises naming the URL.

    **Validates: Requirement 51.1**
    """
    with pytest.raises(SpecImportError) as exc:
        asyncio.run(load_schema(SPEC_URL, http_engine=None))
    assert SPEC_URL in str(exc.value)


# ---------------------------------------------------------------------------
# 51.2 - local path uses the file reader, never the engine
# ---------------------------------------------------------------------------

def test_local_path_uses_file_reader_not_engine(tmp_path):
    """A local file path is read from disk and never touches the HTTP engine.

    **Validates: Requirement 51.2**
    """
    engine = FakeEngine(response=_response(OPENAPI_DOC))
    local_path = _write(tmp_path, "api.json", OPENAPI_DOC)

    schema = asyncio.run(load_schema(local_path, http_engine=engine))

    assert engine.calls == []  # file reader path, no request issued
    assert {"/users/{id}", "/orders"} <= {op.path for op in schema.operations}


# ---------------------------------------------------------------------------
# 51.3 - URL and file produce identical schemas
# ---------------------------------------------------------------------------

def test_url_and_file_produce_identical_schemas(tmp_path):
    """The same document via URL and via file yields identical schemas.

    **Validates: Requirement 51.3**
    """
    engine = FakeEngine(response=_response(OPENAPI_DOC))
    local_path = _write(tmp_path, "api.json", OPENAPI_DOC)

    url_schema = asyncio.run(load_schema(SPEC_URL, http_engine=engine))
    file_schema = asyncio.run(load_schema(local_path, http_engine=engine))

    def _ops(schema):
        return sorted((op.path, op.method) for op in schema.operations)

    def _seeds(schema):
        return sorted((s.path, s.method) for s in schema.seeds)

    assert _ops(url_schema) == _ops(file_schema)
    assert _seeds(url_schema) == _seeds(file_schema)
    assert (
        sorted(s.name for s in url_schema.security_schemes)
        == sorted(s.name for s in file_schema.security_schemes)
    )


# ---------------------------------------------------------------------------
# 51.4 - failing fetch / bad body errors naming the URL
# ---------------------------------------------------------------------------

def test_failing_fetch_status_errors_naming_url():
    """A non-2xx fetch raises a descriptive error naming the URL.

    **Validates: Requirement 51.4**
    """
    engine = FakeEngine(response=_response("gateway down", status_code=502))
    with pytest.raises(SpecImportError) as exc:
        asyncio.run(load_schema(SPEC_URL, http_engine=engine))
    assert SPEC_URL in str(exc.value)


def test_fetch_transport_failure_errors_naming_url():
    """A transport-level failure raises a clean error naming the URL.

    **Validates: Requirement 51.4**
    """
    engine = FakeEngine(raise_exc=ConnectionError("connection refused"))
    with pytest.raises(SpecImportError) as exc:
        asyncio.run(load_schema(SPEC_URL, http_engine=engine))
    assert SPEC_URL in str(exc.value)


def test_bad_body_errors_naming_url():
    """A retrieved but unparseable body raises naming the URL.

    **Validates: Requirement 51.4**
    """
    engine = FakeEngine(response=_response("{ not valid json ]", status_code=200))
    with pytest.raises(SpecImportError) as exc:
        asyncio.run(load_schema(SPEC_URL, http_engine=engine))
    assert SPEC_URL in str(exc.value)


def test_engine_spec_matches_real_engine_shape():
    """Sanity: the fake engine exposes the ``request`` coroutine the loader calls."""
    assert hasattr(HTTPRequestEngine, "request")


if __name__ == "__main__":
    pytest.main([__file__])
