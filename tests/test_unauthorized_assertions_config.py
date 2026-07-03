"""
Unit tests for the Unauthorized_Endpoint_Assertion model and loader.

**Feature: owasp-auth-modules-hardening, Task 48.1**

These tests lock in the config-layer building blocks added by Task 48.1:

- ``UnauthorizedEndpointAssertion`` carries a ``context_name`` plus a list of
  endpoint pattern regular expressions and defaults ``patterns`` to an empty
  list (Requirement 55.1).
- ``load_unauthorized_assertions`` parses both JSON and YAML sources into
  ``{context_name: [compiled patterns]}`` (Requirement 55.1) and raises a
  descriptive error naming the offending ``source`` on any parse/shape/compile
  failure so the CLI can abort before any request is issued (Requirement 55.1,
  consistent with Requirement 54.5).
"""

import json
import re

import pytest

from core.config import UnauthorizedEndpointAssertion, load_unauthorized_assertions


# ---------------------------------------------------------------------------
# UnauthorizedEndpointAssertion dataclass defaults
# ---------------------------------------------------------------------------

def test_assertion_defaults_empty_patterns():
    """A bare ``UnauthorizedEndpointAssertion`` has an empty ``patterns`` list.

    **Validates: Requirement 55.1**
    """
    assertion = UnauthorizedEndpointAssertion(context_name="alice")
    assert assertion.context_name == "alice"
    assert assertion.patterns == []


def test_assertion_carries_patterns():
    """``UnauthorizedEndpointAssertion`` can carry declared patterns."""
    assertion = UnauthorizedEndpointAssertion(
        context_name="alice", patterns=["^/admin", "/api/secret/.*"]
    )
    assert assertion.patterns == ["^/admin", "/api/secret/.*"]


# ---------------------------------------------------------------------------
# load_unauthorized_assertions: JSON/YAML parsing
# ---------------------------------------------------------------------------

def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_load_assertions_json(tmp_path):
    """A JSON source parses into ``{context_name: [compiled patterns]}``.

    **Validates: Requirement 55.1**
    """
    source = _write(
        tmp_path,
        "assertions.json",
        json.dumps(
            {
                "alice": ["^/admin", "/api/secret/.*"],
                "bob": ["^/internal/"],
            }
        ),
    )

    assertions = load_unauthorized_assertions(source)

    assert set(assertions) == {"alice", "bob"}
    # Patterns are compiled regexes ready for matching.
    assert all(isinstance(p, re.Pattern) for p in assertions["alice"])
    assert [p.pattern for p in assertions["alice"]] == ["^/admin", "/api/secret/.*"]
    assert assertions["alice"][0].match("/admin/users")
    assert assertions["bob"][0].match("/internal/metrics")


def test_load_assertions_yaml(tmp_path):
    """A YAML source parses equivalently to JSON.

    **Validates: Requirement 55.1**
    """
    source = _write(
        tmp_path,
        "assertions.yaml",
        """
alice:
  - "^/admin"
  - "/api/secret/.*"
bob:
  - "^/internal/"
""",
    )

    assertions = load_unauthorized_assertions(source)

    assert set(assertions) == {"alice", "bob"}
    assert [p.pattern for p in assertions["alice"]] == ["^/admin", "/api/secret/.*"]


def test_load_assertions_single_string_shorthand(tmp_path):
    """A single string value is shorthand for a one-element pattern list.

    **Validates: Requirement 55.1**
    """
    source = _write(tmp_path, "assertions.json", json.dumps({"alice": "^/admin"}))
    assertions = load_unauthorized_assertions(source)
    assert [p.pattern for p in assertions["alice"]] == ["^/admin"]


def test_load_assertions_unknown_suffix_json_fallback(tmp_path):
    """An unknown suffix still parses JSON content."""
    source = _write(tmp_path, "assertions.txt", json.dumps({"alice": ["^/x"]}))
    assertions = load_unauthorized_assertions(source)
    assert [p.pattern for p in assertions["alice"]] == ["^/x"]


# ---------------------------------------------------------------------------
# load_unauthorized_assertions: descriptive errors naming the source
# ---------------------------------------------------------------------------

def test_load_assertions_missing_source_names_source(tmp_path):
    """A missing source raises an error naming the source.

    **Validates: Requirement 55.1**
    """
    missing = str(tmp_path / "nope.json")
    with pytest.raises(ValueError) as exc:
        load_unauthorized_assertions(missing)
    assert missing in str(exc.value)


def test_load_assertions_malformed_json_names_source(tmp_path):
    """A malformed JSON source raises an error naming the source.

    **Validates: Requirement 55.1**
    """
    source = _write(tmp_path, "bad.json", "{ this is : not valid json ")
    with pytest.raises(ValueError) as exc:
        load_unauthorized_assertions(source)
    assert source in str(exc.value)


def test_load_assertions_malformed_yaml_names_source(tmp_path):
    """A malformed YAML source raises an error naming the source.

    **Validates: Requirement 55.1**
    """
    source = _write(tmp_path, "bad.yaml", "alice: [unclosed\n")
    with pytest.raises(ValueError) as exc:
        load_unauthorized_assertions(source)
    assert source in str(exc.value)


def test_load_assertions_non_mapping_top_level_names_source(tmp_path):
    """A non-mapping top level raises an error naming the source.

    **Validates: Requirement 55.1**
    """
    source = _write(tmp_path, "list.json", json.dumps(["alice", "bob"]))
    with pytest.raises(ValueError) as exc:
        load_unauthorized_assertions(source)
    assert source in str(exc.value)


def test_load_assertions_bad_entry_shape_names_source(tmp_path):
    """A context entry that is neither string nor list raises a naming error.

    **Validates: Requirement 55.1**
    """
    source = _write(tmp_path, "bad_entry.json", json.dumps({"alice": {"x": 1}}))
    with pytest.raises(ValueError) as exc:
        load_unauthorized_assertions(source)
    assert source in str(exc.value)
    assert "alice" in str(exc.value)


def test_load_assertions_non_string_pattern_names_source(tmp_path):
    """A non-string pattern raises an error naming the source.

    **Validates: Requirement 55.1**
    """
    source = _write(tmp_path, "bad_pattern.json", json.dumps({"alice": [123]}))
    with pytest.raises(ValueError) as exc:
        load_unauthorized_assertions(source)
    assert source in str(exc.value)
    assert "alice" in str(exc.value)


def test_load_assertions_invalid_regex_names_source(tmp_path):
    """A pattern that fails to compile raises an error naming the source.

    **Validates: Requirement 55.1**
    """
    source = _write(tmp_path, "bad_regex.json", json.dumps({"alice": ["("]}))
    with pytest.raises(ValueError) as exc:
        load_unauthorized_assertions(source)
    assert source in str(exc.value)
    assert "alice" in str(exc.value)
