"""
Unit tests for Spec_Import and multi-wordlist / stdin discovery seeding.

**Feature: owasp-complete-purple-teaming-cicd, Task 29.4**

Two layers are covered:

1. The pure ``utils/spec_import.py`` helpers (task 29.1):
   - ``import_openapi`` extracts ``(path, method)`` seeds from OpenAPI v3 and
     Swagger v2 documents, one seed per declared operation, defaulting a path
     with no operation to a single ``GET`` seed (Requirements 25.1, 25.3).
   - ``import_postman`` walks a collection's nested ``item`` folder tree and
     yields a seed per request, handling both raw-string and structured URLs
     (Requirements 25.2, 25.3).
   - ``load_spec`` sniffs JSON vs YAML, detects the spec kind, dispatches to the
     right importer, and raises ``SpecImportError`` naming the source for an
     unparseable or unrecognized document (Requirements 25.1, 25.2, 25.6).
   - ``merge_candidates`` merges wordlist entries with spec paths, de-duplicating
     by normalized path while preserving first-seen order (Requirements 25.4,
     25.8).

2. The ``dir`` command wiring (task 29.2) via Click's ``CliRunner``:
   - repeatable ``--wordlist`` values are merged and de-duplicated into the
     in-memory candidate set threaded into the fuzzing config (Requirement 25.4).
   - ``--wordlist -`` reads entries from stdin, skipping blank lines and ``#``
     comments (Requirement 25.5).
   - an unparseable spec source surfaces as a descriptive CLI error naming the
     source and performs no discovery (Requirement 25.6).
   - an empty merged candidate set completes with a "no candidates available"
     message and issues no discovery (Requirement 25.7).

No real HTTP requests are made: the CLI tests either capture the threaded
``config_dict`` before any scan runs, or patch the discovery entry point to prove
discovery never happens.
"""

import json
from unittest.mock import patch

import pytest
import yaml
from click.testing import CliRunner

import apileaks
from apileaks import cli
from utils.spec_import import (
    DEFAULT_METHOD,
    SpecImportError,
    SpecSeed,
    import_openapi,
    import_postman,
    load_spec,
    merge_candidates,
    normalize_candidate_path,
)


TARGET = "https://api.example.com"


class _ShortCircuit(Exception):
    """Sentinel raised to stop the command once ``config_dict`` is captured."""


# ===========================================================================
# import_openapi: OpenAPI v3 + Swagger v2 (Requirements 25.1, 25.3)
# ===========================================================================

def test_import_openapi_v3_extracts_paths_and_methods():
    """An OpenAPI v3 doc yields one seed per (path, operation) with its method.

    **Validates: Requirements 25.1, 25.3**
    """
    doc = {
        "openapi": "3.0.3",
        "info": {"title": "demo", "version": "1.0.0"},
        "paths": {
            "/users": {
                "get": {"summary": "list"},
                "post": {"summary": "create"},
            },
            "/users/{id}": {
                "get": {"summary": "read"},
                "delete": {"summary": "remove"},
                # Non-operation keys must be ignored.
                "parameters": [{"name": "id", "in": "path"}],
            },
        },
    }

    seeds = import_openapi(doc)

    assert SpecSeed(path="/users", method="GET") in seeds
    assert SpecSeed(path="/users", method="POST") in seeds
    assert SpecSeed(path="/users/{id}", method="GET") in seeds
    assert SpecSeed(path="/users/{id}", method="DELETE") in seeds
    # The 'parameters' key is not an operation, so no extra seed is created.
    assert len(seeds) == 4
    assert all(isinstance(s.method, str) and s.method.isupper() for s in seeds)


def test_import_openapi_v2_swagger_extracts_paths_and_methods():
    """A Swagger v2 doc shares the v3 ``paths`` shape and yields method seeds.

    **Validates: Requirements 25.1, 25.3**
    """
    doc = {
        "swagger": "2.0",
        "info": {"title": "legacy", "version": "1.0"},
        "paths": {
            "/login": {"post": {"operationId": "login"}},
            "/health": {"get": {"operationId": "health"}},
        },
    }

    seeds = import_openapi(doc)

    assert SpecSeed(path="/login", method="POST") in seeds
    assert SpecSeed(path="/health", method="GET") in seeds
    assert len(seeds) == 2


def test_import_openapi_path_without_operation_defaults_to_get():
    """A documented path with no recognized operation still becomes a GET seed.

    **Validates: Requirements 25.1, 25.3**
    """
    doc = {"openapi": "3.0.0", "paths": {"/ping": {"summary": "no ops here"}}}

    seeds = import_openapi(doc)

    assert seeds == [SpecSeed(path="/ping", method=DEFAULT_METHOD)]


def test_import_openapi_without_paths_raises_naming_problem():
    """A doc missing a ``paths`` object is rejected (Requirement 25.6 upstream).

    **Validates: Requirements 25.1, 25.6**
    """
    with pytest.raises(SpecImportError):
        import_openapi({"openapi": "3.0.0"})


# ===========================================================================
# import_postman: nested folders, raw + structured URLs (Requirements 25.2, 25.3)
# ===========================================================================

def test_import_postman_extracts_nested_requests_with_methods():
    """Postman seeds are extracted from nested folders with their methods.

    Covers a structured URL object (``path`` segment array), a raw-string URL
    with a ``{{baseUrl}}`` template, and a request nested inside a folder.

    **Validates: Requirements 25.2, 25.3**
    """
    doc = {
        "info": {"schema": "https://schema.getpostman.com/json/collection/v2.1.0/"},
        "item": [
            {
                "name": "Top level GET",
                "request": {
                    "method": "GET",
                    "url": {"raw": "{{baseUrl}}/users", "path": ["users"]},
                },
            },
            {
                "name": "Folder",
                "item": [
                    {
                        "name": "Create user",
                        "request": {
                            "method": "POST",
                            "url": {"path": ["users"]},
                        },
                    },
                    {
                        "name": "Raw URL request",
                        "request": {
                            "method": "PUT",
                            "url": "{{baseUrl}}/users/42",
                        },
                    },
                ],
            },
        ],
    }

    seeds = import_postman(doc)

    assert SpecSeed(path="/users", method="GET") in seeds
    assert SpecSeed(path="/users", method="POST") in seeds
    assert SpecSeed(path="/users/42", method="PUT") in seeds
    assert len(seeds) == 3


def test_import_postman_skips_requests_without_a_path():
    """A request whose URL yields no path is skipped, not turned into a seed.

    **Validates: Requirements 25.2**
    """
    doc = {
        "item": [
            {"name": "No url", "request": {"method": "GET"}},
            {"name": "Empty raw", "request": {"method": "GET", "url": ""}},
            {"name": "Good", "request": {"method": "GET", "url": "{{baseUrl}}/ok"}},
        ]
    }

    seeds = import_postman(doc)

    assert seeds == [SpecSeed(path="/ok", method="GET")]


def test_import_postman_without_item_array_raises():
    """A collection lacking an ``item`` array is rejected (Requirement 25.6).

    **Validates: Requirements 25.2, 25.6**
    """
    with pytest.raises(SpecImportError):
        import_postman({"info": {"name": "no items"}})


# ===========================================================================
# load_spec: JSON vs YAML dispatch + error handling (Requirements 25.1, 25.2, 25.6)
# ===========================================================================

def test_load_spec_dispatches_json_openapi(tmp_path):
    """A JSON OpenAPI file is sniffed and dispatched to the OpenAPI importer.

    **Validates: Requirements 25.1, 25.3**
    """
    spec = tmp_path / "api.json"
    spec.write_text(
        json.dumps({"openapi": "3.0.0", "paths": {"/a": {"get": {}}}}),
        encoding="utf-8",
    )

    seeds = load_spec(str(spec))

    assert seeds == [SpecSeed(path="/a", method="GET")]


def test_load_spec_dispatches_yaml_openapi(tmp_path):
    """A YAML OpenAPI file is sniffed and dispatched to the OpenAPI importer.

    **Validates: Requirements 25.1, 25.3**
    """
    spec = tmp_path / "api.yaml"
    spec.write_text(
        yaml.safe_dump({"openapi": "3.0.0", "paths": {"/b": {"post": {}}}}),
        encoding="utf-8",
    )

    seeds = load_spec(str(spec))

    assert seeds == [SpecSeed(path="/b", method="POST")]


def test_load_spec_dispatches_postman(tmp_path):
    """A JSON Postman collection is sniffed and dispatched to import_postman.

    **Validates: Requirements 25.2, 25.3**
    """
    spec = tmp_path / "collection.json"
    spec.write_text(
        json.dumps(
            {
                "info": {"schema": "https://schema.getpostman.com/v2.1.0"},
                "item": [
                    {"request": {"method": "DELETE", "url": "{{baseUrl}}/things/1"}}
                ],
            }
        ),
        encoding="utf-8",
    )

    seeds = load_spec(str(spec))

    assert seeds == [SpecSeed(path="/things/1", method="DELETE")]


def test_load_spec_unparseable_raises_naming_source(tmp_path):
    """An unparseable (not JSON/YAML) source raises naming the source.

    **Validates: Requirements 25.6**
    """
    spec = tmp_path / "broken.json"
    # Invalid JSON and invalid YAML (unclosed bracket + bad indentation).
    spec.write_text("{not valid: [json or yaml", encoding="utf-8")

    with pytest.raises(SpecImportError) as exc_info:
        load_spec(str(spec))

    assert str(spec) in str(exc_info.value)


def test_load_spec_unrecognized_document_raises_naming_source(tmp_path):
    """A well-formed but unrecognized document raises naming the source.

    **Validates: Requirements 25.6**
    """
    spec = tmp_path / "random.json"
    spec.write_text(json.dumps({"hello": "world"}), encoding="utf-8")

    with pytest.raises(SpecImportError) as exc_info:
        load_spec(str(spec))

    assert str(spec) in str(exc_info.value)


# ===========================================================================
# merge_candidates: dedup by normalized path, order preserved (25.4, 25.8)
# ===========================================================================

def test_merge_candidates_dedupes_normalized_paths_preserving_order():
    """Wordlist entries and spec paths merge with no duplicate normalized paths.

    ``users`` (wordlist) and ``/users/`` (spec) normalize to the same key, so the
    first-seen textual form wins and the spec duplicate is dropped. ``admin`` is
    spec-only and kept. Order is wordlist-first, then spec.

    **Validates: Requirements 25.4, 25.8**
    """
    wordlist_entries = ["users", "login", "users"]  # duplicate within wordlist
    spec_seeds = [
        SpecSeed(path="/users/", method="GET"),  # dup of wordlist "users"
        SpecSeed(path="/admin", method="POST"),  # new
    ]

    merged = merge_candidates(wordlist_entries, spec_seeds)

    # Each entry keeps its original textual form (wordlist "users" wins over the
    # spec "/users/" duplicate; the new spec "/admin" is kept verbatim).
    assert merged == ["users", "login", "/admin"]
    # No duplicate normalized keys in the merged set (Requirement 25.8).
    normalized = [normalize_candidate_path(c) for c in merged]
    assert len(normalized) == len(set(normalized))


def test_merge_candidates_empty_inputs_yield_empty_set():
    """No wordlist entries and no spec seeds produce an empty candidate set.

    **Validates: Requirements 25.7**
    """
    assert merge_candidates([], []) == []


# ===========================================================================
# dir command wiring: repeatable --wordlist + stdin (Requirements 25.4, 25.5)
# ===========================================================================

def _invoke_dir_capturing_config(args, *, input=None):
    """Invoke ``dir`` and capture the ``config_dict`` handed to the loader.

    ``ConfigurationManager.load_config_from_dict`` is the first consumer of the
    fully threaded config, so capturing its argument lets us inspect the merged
    candidate set without performing a real scan.
    """
    captured = {}

    def _capture(self, config_dict):
        captured["config_dict"] = config_dict
        raise _ShortCircuit()

    runner = CliRunner()
    with patch.object(
        apileaks.ConfigurationManager, "load_config_from_dict", _capture
    ):
        runner.invoke(
            cli,
            ["--no-banner", "dir", "--target", TARGET, *args],
            input=input,
        )
    return captured.get("config_dict")


def test_repeatable_wordlist_merged_and_deduped_into_candidate_set(tmp_path):
    """Multiple ``--wordlist`` files are merged and de-duplicated for discovery.

    **Validates: Requirements 25.4, 25.8**
    """
    wl1 = tmp_path / "wl1.txt"
    wl1.write_text("users\nlogin\n", encoding="utf-8")
    wl2 = tmp_path / "wl2.txt"
    # "users" duplicates wl1; "admin" is new.
    wl2.write_text("admin\nusers\n", encoding="utf-8")

    config_dict = _invoke_dir_capturing_config(
        ["--wordlist", str(wl1), "--wordlist", str(wl2)]
    )
    assert config_dict is not None

    candidate_set = config_dict["fuzzing"]["endpoints"]["candidate_set"]
    assert candidate_set == ["users", "login", "admin"]
    normalized = [normalize_candidate_path(c) for c in candidate_set]
    assert len(normalized) == len(set(normalized))


def test_stdin_wordlist_skips_blank_and_comment_lines(tmp_path):
    """``--wordlist -`` reads stdin, skipping blank lines and ``#`` comments.

    **Validates: Requirements 25.5**
    """
    stdin_text = "\n".join(
        [
            "users",
            "",  # blank line skipped
            "# a comment line",  # comment skipped
            "   ",  # whitespace-only skipped
            "   # indented comment",  # leading-whitespace comment skipped
            "login",
        ]
    )

    config_dict = _invoke_dir_capturing_config(
        ["--wordlist", "-"], input=stdin_text
    )
    assert config_dict is not None

    candidate_set = config_dict["fuzzing"]["endpoints"]["candidate_set"]
    assert candidate_set == ["users", "login"]


def test_spec_seed_methods_threaded_into_config(tmp_path):
    """Spec seed methods are threaded into ``seed_methods`` keyed by norm path.

    **Validates: Requirements 25.1, 25.3**
    """
    spec = tmp_path / "api.json"
    spec.write_text(
        json.dumps(
            {
                "openapi": "3.0.0",
                "paths": {"/users": {"get": {}, "post": {}}},
            }
        ),
        encoding="utf-8",
    )

    config_dict = _invoke_dir_capturing_config(["--openapi", str(spec)])
    assert config_dict is not None

    candidate_set = config_dict["fuzzing"]["endpoints"]["candidate_set"]
    assert "users" in [normalize_candidate_path(c) for c in candidate_set]

    seed_methods = config_dict["fuzzing"]["endpoints"]["seed_methods"]
    assert set(seed_methods["users"]) == {"GET", "POST"}


# ===========================================================================
# dir command wiring: unparseable spec + empty set (Requirements 25.6, 25.7)
# ===========================================================================

def test_unparseable_spec_errors_and_runs_no_discovery(tmp_path):
    """An unparseable spec yields a CLI error naming the source and no discovery.

    **Validates: Requirements 25.6**
    """
    spec = tmp_path / "broken.json"
    spec.write_text("{not valid: [json or yaml", encoding="utf-8")

    runner = CliRunner()
    with patch.object(apileaks, "run_enhanced_apileak") as discovery:
        result = runner.invoke(
            cli,
            ["--no-banner", "dir", "--target", TARGET, "--openapi", str(spec)],
        )

    assert result.exit_code != 0
    # The descriptive error identifies the offending source.
    assert str(spec) in result.output
    assert "Error" in result.output
    discovery.assert_not_called()


def test_empty_merged_candidate_set_reports_and_runs_no_discovery(tmp_path):
    """An empty merged set reports no candidates and issues no discovery.

    **Validates: Requirements 25.7**
    """
    # A wordlist containing only blank lines and comments yields no entries, and
    # with no spec sources the merged candidate set is empty.
    wl = tmp_path / "empty.txt"
    wl.write_text("\n# only a comment\n   \n", encoding="utf-8")
    wl2 = tmp_path / "empty2.txt"
    wl2.write_text("# another comment\n", encoding="utf-8")

    runner = CliRunner()
    with patch.object(apileaks, "run_enhanced_apileak") as discovery:
        result = runner.invoke(
            cli,
            [
                "--no-banner",
                "dir",
                "--target",
                TARGET,
                "--wordlist",
                str(wl),
                "--wordlist",
                str(wl2),
            ],
        )

    assert result.exit_code == 0
    assert "No candidates available" in result.output
    discovery.assert_not_called()
