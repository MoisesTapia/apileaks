"""
Consolidated example-based unit tests for the spec-driven ``full`` scan wiring,
typed payload generation, and spec-driven BOLA identifier targeting.

**Feature: owasp-auth-modules-hardening, Task 51.1**

These are worked, example-based (not property-based) tests that pin the observable
behavior of the spec-consumption path end to end:

* ``full`` spec wiring - ``--openapi`` / ``--postman`` are accepted and repeatable
  (Req 49.1), every source is merged and threaded into the OWASP module init
  (Reqs 49.2, 49.5), a no-spec run preserves the existing full-scan path (Req 49.3),
  and an unparseable source aborts the scan naming the offending source before any
  request is issued (Req 49.4);
* typed payloads - a declared ``example`` is preferred (Req 52.3), an operation
  with no request body falls back to the existing empty payload (Req 52.6), and a
  state-changing typed probe is issued only when Safe_Mode is off AND the
  Destructive_Opt_In is present (Req 56.4);
* spec-driven BOLA targeting - a declared ``path`` Spec_Parameter lands the
  candidate in that exact slot, and the module falls back to regex inference when
  the operation declares no path parameter (Req 53.2).

Companion capabilities (URL ingestion, actor profiles, unauthorized-endpoint
assertions) are covered by the sibling files ``test_spec_url_ingestion.py``,
``test_actor_profiles.py`` and ``test_unauthorized_assertions.py``.
"""

import asyncio
import json
from unittest.mock import AsyncMock, Mock, patch

from click.testing import CliRunner

import apileaks
from apileaks import cli, _load_spec_schema
from core.config import (
    AuthContext,
    AuthType,
    BOLAConfig,
    OWASPConfig,
    TargetConfig,
    APILeakConfig,
)
from core.engine import APILeakCore
from modules.owasp.bola_testing import BOLATestingModule, ObjectIdentifier
from utils.http_client import HTTPRequestEngine, Response
from utils.safe_mode import SAFE_METHODS, STATE_CHANGING_METHODS
from utils.spec_import import (
    SpecImportError,
    SpecOperation,
    SpecParameter,
    SpecSchema,
)
from utils.typed_payload import build_typed_payload


TARGET = "https://api.example.com"


OPENAPI_DOC = {
    "openapi": "3.0.3",
    "paths": {
        "/users/{id}": {
            "get": {
                "parameters": [
                    {"name": "id", "in": "path", "required": True,
                     "schema": {"type": "integer"}},
                ]
            }
        }
    },
    "components": {
        "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}
    },
}

SECOND_OPENAPI_DOC = {
    "openapi": "3.0.3",
    "paths": {"/accounts": {"get": {}}},
}

POSTMAN_DOC = {
    "info": {"name": "collection", "schema": "https://schema.getpostman.com/"},
    "item": [
        {
            "name": "list orders",
            "request": {"method": "GET", "url": "https://api.example.com/orders"},
        }
    ],
}


def _write(tmp_path, name, doc):
    path = tmp_path / name
    path.write_text(json.dumps(doc))
    return str(path)


# ---------------------------------------------------------------------------
# Recording HTTP engine double (records every issued (method, url))
# ---------------------------------------------------------------------------

class RecordingHTTPEngine:
    """Async HTTP engine double recording every issued ``(method, url)``."""

    def __init__(self):
        self.calls = []
        self.current_auth_context = None

    def set_auth_context(self, auth_context):
        self.current_auth_context = auth_context

    async def request(self, method, url, **kwargs):
        self.calls.append((str(method).upper(), url))
        body = '{"id": 1, "user_id": 1, "email": "u@example.com"}'
        return Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=body.encode(),
            text=body,
            url=url,
            elapsed=0.001,
            request_method=str(method).upper(),
        )

    @property
    def issued_methods(self):
        return {method for method, _ in self.calls}


def _invoke_full_capturing_config(args):
    """Invoke ``full`` and capture the fully threaded ``apileak_config``.

    ``run_enhanced_apileak`` is the first consumer of the threaded config, so
    replacing it lets us inspect ``owasp_testing.spec_schema`` without running a
    real scan.
    """
    captured = {}

    def _capture(config, *rest, **kwargs):
        captured["config"] = config

        async def _noop():
            return None

        return _noop()

    runner = CliRunner()
    with patch.object(
        apileaks.ConfigurationManager, "validate_configuration", return_value=[]
    ), patch.object(apileaks, "run_enhanced_apileak", _capture):
        result = runner.invoke(
            cli, ["--no-banner", "full", "--target", TARGET, *args]
        )
    return result, captured.get("config")


# ===========================================================================
# full spec wiring (Reqs 49.1-49.5)
# ===========================================================================

def test_full_accepts_repeatable_openapi_and_postman(tmp_path):
    """``--openapi`` (x2) and ``--postman`` are accepted, repeatable, and merged.

    **Validates: Requirements 49.1, 49.2, 49.5**
    """
    first = _write(tmp_path, "one.json", OPENAPI_DOC)
    second = _write(tmp_path, "two.json", SECOND_OPENAPI_DOC)
    postman = _write(tmp_path, "collection.json", POSTMAN_DOC)

    result, config = _invoke_full_capturing_config(
        ["--openapi", first, "--openapi", second, "--postman", postman]
    )

    assert result.exit_code == 0, result.output
    schema = config.owasp_testing.spec_schema
    assert isinstance(schema, SpecSchema)
    op_paths = {op.path for op in schema.operations}
    assert {"/users/{id}", "/accounts", "/orders"} <= op_paths
    assert any(s.name == "bearerAuth" for s in schema.security_schemes)


def test_full_no_spec_preserves_existing_behavior():
    """No ``--openapi`` / ``--postman`` leaves ``spec_schema`` None (no-spec path).

    **Validates: Requirement 49.3**
    """
    result, config = _invoke_full_capturing_config([])
    assert result.exit_code == 0, result.output
    assert config.owasp_testing.spec_schema is None


def test_full_unparseable_spec_aborts_before_request_naming_source(tmp_path):
    """A bad Spec_Source aborts naming that source with no scan issued.

    **Validates: Requirement 49.4**
    """
    bad_path = tmp_path / "broken.json"
    bad_path.write_text("{ not valid json ]")

    runner = CliRunner()
    with patch.object(apileaks, "run_enhanced_apileak") as scan:
        result = runner.invoke(
            cli,
            ["--no-banner", "full", "--target", TARGET, "--openapi", str(bad_path)],
        )

    assert result.exit_code != 0
    assert "broken.json" in result.output
    scan.assert_not_called()


def test_engine_threads_small_spec_into_module_init():
    """A merged Spec_Schema is threaded into bola/auth/property module init.

    **Validates: Requirements 49.2, 49.5**
    """
    config = APILeakConfig(target=TargetConfig(base_url=TARGET))
    schema = asyncio.run(_load_spec_schema((), ()))  # sanity: None with no source
    assert schema is None

    sentinel = SpecSchema(operations=[SpecOperation(path="/users/{id}", method="GET")])
    config.owasp_testing.spec_schema = sentinel

    core = APILeakCore(config)
    asyncio.run(core._initialize_owasp_modules())

    for key in ("bola", "auth", "property"):
        assert key in core.owasp_modules
        assert core.owasp_modules[key].spec_schema is sentinel


def test_discovered_and_spec_operations_both_available(tmp_path):
    """The merged schema exposes both spec operations and legacy (path,method) seeds.

    The seeds feed discovery/the discovered-endpoint path while ``operations``
    drive spec-operation testing, so both are tested in addition to each other.

    **Validates: Requirement 49.5**
    """
    openapi_path = _write(tmp_path, "api.json", OPENAPI_DOC)
    postman_path = _write(tmp_path, "collection.json", POSTMAN_DOC)

    schema = asyncio.run(_load_spec_schema((openapi_path,), (postman_path,)))

    op_paths = {op.path for op in schema.operations}
    seed_paths = {seed.path for seed in schema.seeds}
    assert {"/users/{id}", "/orders"} <= op_paths
    assert {"/users/{id}", "/orders"} <= seed_paths


# ===========================================================================
# typed payloads (Reqs 52.3, 52.6, 56.4)
# ===========================================================================

def test_typed_payload_prefers_declared_example():
    """A declared ``example`` is preferred over a canonical type value.

    **Validates: Requirement 52.3**
    """
    operation = SpecOperation(
        path="/orders",
        method="POST",
        request_body_schema={
            "type": "object",
            "required": ["status"],
            "properties": {
                "status": {"type": "string", "example": "shipped"},
                "qty": {"type": "integer", "example": 42},
            },
        },
    )

    body = build_typed_payload(operation)
    assert body["status"] == "shipped"
    assert body["qty"] == 42


def test_typed_payload_no_schema_fallback_returns_empty():
    """An operation with no request body yields the existing empty payload.

    **Validates: Requirement 52.6**
    """
    operation = SpecOperation(path="/orders", method="POST", request_body_schema=None)
    assert build_typed_payload(operation) == {}
    # Overrides still apply on top of the empty base (injected field under test).
    assert build_typed_payload(operation, overrides={"is_admin": True}) == {"is_admin": True}


def _write_bola_module(safe_mode, allow_destructive):
    config = BOLAConfig(
        enabled=True,
        safe_mode=safe_mode,
        allow_destructive=allow_destructive,
        destructive_methods={"PATCH"},
    )
    engine = RecordingHTTPEngine()
    contexts = [AuthContext(name="u1", type=AuthType.BEARER, token="t", privilege_level=1)]
    return BOLATestingModule(config, engine, contexts), engine


def test_typed_state_changing_probe_blocked_when_safe_mode_on():
    """Safe_Mode on -> no state-changing typed probe is issued.

    **Validates: Requirement 56.4**
    """
    module, engine = _write_bola_module(safe_mode=True, allow_destructive=True)
    result = asyncio.run(
        module._issue_guarded_write_probe(f"{TARGET}/users/2", "2", body={"role": "admin"})
    )
    assert result is None
    assert not (engine.issued_methods & STATE_CHANGING_METHODS)


def test_typed_state_changing_probe_blocked_when_optin_absent():
    """Destructive_Opt_In absent -> no state-changing typed probe is issued.

    **Validates: Requirement 56.4**
    """
    module, engine = _write_bola_module(safe_mode=False, allow_destructive=False)
    result = asyncio.run(
        module._issue_guarded_write_probe(f"{TARGET}/users/2", "2", body={"role": "admin"})
    )
    assert result is None
    assert not (engine.issued_methods & STATE_CHANGING_METHODS)


def test_typed_state_changing_probe_issued_when_safe_off_and_optin_present():
    """Safe_Mode off AND opt-in present -> the state-changing typed probe is issued.

    **Validates: Requirement 56.4**
    """
    module, engine = _write_bola_module(safe_mode=False, allow_destructive=True)
    result = asyncio.run(
        module._issue_guarded_write_probe(f"{TARGET}/users/2", "2", body={"role": "admin"})
    )
    assert result is not None
    assert engine.calls == [("PATCH", f"{TARGET}/users/2")]
    assert engine.issued_methods <= (SAFE_METHODS | {"PATCH"})


# ===========================================================================
# spec-driven BOLA identifier targeting (Req 53.2)
# ===========================================================================

def _pure_bola_module():
    client = Mock(spec=HTTPRequestEngine)
    client.request = AsyncMock()
    client.set_auth_context = Mock()
    return BOLATestingModule(BOLAConfig(enabled=True), client, [])


def test_spec_declared_path_param_hits_the_slot():
    """A declared ``path`` Spec_Parameter targets that exact concrete slot.

    **Validates: Requirement 53.2 (spec-driven targeting)**
    """
    module = _pure_bola_module()
    operation = SpecOperation(
        path="/users/{user_id}/orders/{order_id}",
        method="GET",
        parameters=[
            SpecParameter(name="user_id", location="path"),
            SpecParameter(name="order_id", location="path"),
        ],
    )
    url = f"{TARGET}/users/7/orders/99"

    # Slot 0 -> the user_id segment; slot 1 -> the order_id segment.
    ident0 = module._identifier_from_spec(operation, url, slot_index=0)
    assert ident0 is not None and ident0.location == "path"
    assert ident0.parameter_name == "user_id" and ident0.value == "7"

    ident1 = module._identifier_from_spec(operation, url, slot_index=1)
    assert ident1 is not None and ident1.parameter_name == "order_id"
    assert ident1.value == "99"

    # Substituting into the targeted slot preserves the other slot + segments.
    assert module._substitute_identifier(ident1, "42") == f"{TARGET}/users/7/orders/42"


def test_regex_fallback_when_operation_declares_no_path_param():
    """No declared path parameter -> ``_identifier_from_spec`` yields None (regex fallback).

    **Validates: Requirement 53.2 (regex fallback otherwise)**
    """
    module = _pure_bola_module()
    operation = SpecOperation(
        path="/users",
        method="GET",
        parameters=[SpecParameter(name="q", location="query")],
    )
    assert module._spec_path_slots(operation) == []
    assert module._identifier_from_spec(operation, f"{TARGET}/users/7") is None


if __name__ == "__main__":
    import pytest

    pytest.main([__file__])
