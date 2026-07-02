"""
Unit tests for the ``full`` command Spec_Source wiring (Requirement 49).

**Feature: owasp-auth-modules-hardening, Task 43.1**

These tests lock in the behavior added by Task 43.1:

* the repeatable ``--openapi`` / ``--postman`` options on the ``full`` command,
  consistent with the ``dir`` command (Requirement 49.1);
* the ``_load_spec_schema`` helper that routes every Spec_Source through
  ``spec_import.load_schema`` and concatenates ``operations`` /
  ``security_schemes`` / ``seeds`` into one merged ``SpecSchema`` (Req 49.2),
  returning ``None`` when no source is supplied (Requirement 49.3);
* the merged schema being attached to ``owasp_testing.spec_schema`` (Req 49.2);
* an unreadable / unparseable Spec_Source aborting the scan with a descriptive
  error naming the offending source BEFORE any request is issued (Req 49.4);
* the new optional ``OWASPConfig.spec_schema`` field defaulting to ``None`` so
  existing YAML configs load unchanged.

They mirror the CLI-testing patterns in
``tests/test_multi_auth_context_cli.py`` (``CliRunner`` invocation, capturing
the fully threaded ``apileak_config`` at the ``run_enhanced_apileak`` boundary,
and patching so no real network scan runs).
"""

import asyncio
import json

from unittest.mock import patch

from click.testing import CliRunner

import apileaks
from apileaks import cli, _load_spec_schema
from core.config import ConfigurationManager, OWASPConfig
from utils.spec_import import SpecImportError, SpecSchema


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
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"}
        }
    },
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
# Helpers mirroring tests/test_multi_auth_context_cli.py
# ---------------------------------------------------------------------------

def _invoke_full_capturing_config(args):
    """Invoke ``full`` and capture the fully threaded ``apileak_config``.

    ``run_enhanced_apileak`` is the first consumer of the loaded and threaded
    configuration, so replacing it lets us inspect ``owasp_testing.spec_schema``
    without performing a real scan. Configuration validation is stubbed to
    isolate the spec-wiring behavior from unrelated file-system checks.
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
            cli,
            ["--no-banner", "full", "--target", TARGET, *args],
        )
    return result, captured.get("config"), captured


# ---------------------------------------------------------------------------
# OWASPConfig.spec_schema default (existing YAML loads unchanged)
# ---------------------------------------------------------------------------

def test_owasp_config_spec_schema_defaults_to_none():
    """A freshly constructed OWASPConfig carries ``spec_schema=None``."""
    assert OWASPConfig().spec_schema is None


def test_build_owasp_config_from_empty_dict_leaves_spec_schema_none():
    """Building the OWASP config from a YAML-style dict never sets spec_schema.

    Existing configuration files never declare ``spec_schema``; the field is
    attached only by the CLI post-load, so a dict-built config must load with
    ``spec_schema`` still ``None`` (existing YAML loads unchanged).
    """
    manager = ConfigurationManager()
    owasp = manager._build_owasp_config({})
    assert owasp.spec_schema is None

    # A populated (but spec_schema-free) owasp block still loads unchanged.
    owasp2 = manager._build_owasp_config({"enabled_modules": ["bola", "auth"]})
    assert owasp2.spec_schema is None
    assert owasp2.enabled_modules == ["bola", "auth"]


# ---------------------------------------------------------------------------
# _load_spec_schema helper (Requirements 49.2, 49.3, 49.4)
# ---------------------------------------------------------------------------

def test_load_spec_schema_returns_none_without_sources():
    """No Spec_Source supplied -> ``None`` (no-spec full-scan path preserved).

    **Validates: Requirements 49.3**
    """
    assert asyncio.run(_load_spec_schema((), ())) is None
    assert asyncio.run(_load_spec_schema([], [])) is None


def test_load_spec_schema_merges_operations_schemes_and_seeds(tmp_path):
    """Every source is merged into one concatenated SpecSchema.

    **Validates: Requirements 49.2**
    """
    openapi_path = _write(tmp_path, "api.json", OPENAPI_DOC)
    postman_path = _write(tmp_path, "collection.json", POSTMAN_DOC)

    schema = asyncio.run(_load_spec_schema((openapi_path,), (postman_path,)))

    assert isinstance(schema, SpecSchema)
    # OpenAPI contributes the /users/{id} GET operation + its bearer scheme;
    # Postman contributes the /orders GET operation. Seeds concatenate both.
    op_paths = {op.path for op in schema.operations}
    assert "/users/{id}" in op_paths
    assert "/orders" in op_paths
    assert any(s.name == "bearerAuth" for s in schema.security_schemes)

    seed_paths = {seed.path for seed in schema.seeds}
    assert "/users/{id}" in seed_paths
    assert "/orders" in seed_paths


def test_load_spec_schema_names_offending_source_on_parse_error(tmp_path):
    """An unparseable source raises SpecImportError naming that source.

    **Validates: Requirements 49.4**
    """
    bad_path = tmp_path / "broken.json"
    bad_path.write_text("{ this is not valid json ]")

    try:
        asyncio.run(_load_spec_schema((str(bad_path),), ()))
    except SpecImportError as exc:
        assert "broken.json" in str(exc)
    else:  # pragma: no cover - defensive
        raise AssertionError("expected SpecImportError for an unparseable source")


# ---------------------------------------------------------------------------
# full command: no spec -> spec_schema stays None (Requirement 49.3)
# ---------------------------------------------------------------------------

def test_full_without_spec_sources_leaves_spec_schema_none():
    """No ``--openapi`` / ``--postman`` preserves the existing full-scan path.

    **Validates: Requirements 49.3**
    """
    result, config, _ = _invoke_full_capturing_config([])

    assert result.exit_code == 0, result.output
    assert config is not None
    assert config.owasp_testing.spec_schema is None


# ---------------------------------------------------------------------------
# full command: spec sources attached and merged (Requirements 49.1, 49.2)
# ---------------------------------------------------------------------------

def test_full_attaches_merged_spec_schema(tmp_path):
    """Supplying both options attaches one merged schema to owasp_testing.

    **Validates: Requirements 49.1, 49.2, 49.5**
    """
    openapi_path = _write(tmp_path, "api.json", OPENAPI_DOC)
    postman_path = _write(tmp_path, "collection.json", POSTMAN_DOC)

    result, config, _ = _invoke_full_capturing_config(
        ["--openapi", openapi_path, "--postman", postman_path]
    )

    assert result.exit_code == 0, result.output
    assert config is not None

    schema = config.owasp_testing.spec_schema
    assert isinstance(schema, SpecSchema)
    op_paths = {op.path for op in schema.operations}
    assert {"/users/{id}", "/orders"} <= op_paths
    assert any(s.name == "bearerAuth" for s in schema.security_schemes)


def test_full_accepts_repeatable_openapi_option(tmp_path):
    """``--openapi`` is repeatable and every value is merged.

    **Validates: Requirements 49.1, 49.2**
    """
    first = _write(tmp_path, "one.json", OPENAPI_DOC)
    second_doc = {
        "openapi": "3.0.3",
        "paths": {"/accounts": {"get": {}}},
    }
    second = _write(tmp_path, "two.json", second_doc)

    result, config, _ = _invoke_full_capturing_config(
        ["--openapi", first, "--openapi", second]
    )

    assert result.exit_code == 0, result.output
    op_paths = {op.path for op in config.owasp_testing.spec_schema.operations}
    assert {"/users/{id}", "/accounts"} <= op_paths


# ---------------------------------------------------------------------------
# full command: bad spec aborts before any request (Requirement 49.4)
# ---------------------------------------------------------------------------

def test_full_aborts_before_request_on_unparseable_spec(tmp_path):
    """A bad Spec_Source aborts with a descriptive error, no scan issued.

    **Validates: Requirements 49.4**
    """
    bad_path = tmp_path / "broken.json"
    bad_path.write_text("{ not valid json ]")

    runner = CliRunner()
    with patch.object(apileaks, "run_enhanced_apileak") as scan:
        result = runner.invoke(
            cli,
            ["--no-banner", "full", "--target", TARGET,
             "--openapi", str(bad_path)],
        )

    # Non-zero exit, the offending source is named, and NO scan ran.
    assert result.exit_code != 0
    assert "broken.json" in result.output
    scan.assert_not_called()


def test_full_aborts_before_request_on_missing_spec_file(tmp_path):
    """A nonexistent Spec_Source aborts with a descriptive error, no scan.

    **Validates: Requirements 49.4**
    """
    missing = str(tmp_path / "does-not-exist.json")

    runner = CliRunner()
    with patch.object(apileaks, "run_enhanced_apileak") as scan:
        result = runner.invoke(
            cli,
            ["--no-banner", "full", "--target", TARGET,
             "--postman", missing],
        )

    assert result.exit_code != 0
    assert "does-not-exist.json" in result.output
    scan.assert_not_called()
