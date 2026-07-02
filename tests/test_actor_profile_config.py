"""
Unit tests for the Actor_Profile model, loader, and AuthContext field.

**Feature: owasp-auth-modules-hardening, Task 47.1**

These tests lock in the config-layer building blocks added by Task 47.1:

- ``ActorProfile`` carries a ``context_name`` plus per-endpoint ``query`` and
  ``body`` maps and defaults both maps to empty (Requirement 54.1).
- ``AuthContext`` gains an optional ``actor_profile`` field defaulting to
  ``None`` so existing construction stays backward compatible (Requirement 54,
  design §5).
- ``load_actor_profiles`` parses both JSON and YAML sources into
  ``{context_name: ActorProfile}`` (Requirement 54.1) and raises a descriptive
  error naming the offending ``source`` on any parse/shape failure so the CLI
  can abort before any request is issued (Requirement 54.5).
"""

import json

import pytest

from core.config import ActorProfile, AuthContext, AuthType, load_actor_profiles


# ---------------------------------------------------------------------------
# ActorProfile dataclass + AuthContext field defaults
# ---------------------------------------------------------------------------

def test_actor_profile_defaults_empty_maps():
    """A bare ``ActorProfile`` has empty ``query``/``body`` maps.

    **Validates: Requirement 54.1**
    """
    profile = ActorProfile(context_name="alice")
    assert profile.context_name == "alice"
    assert profile.query == {}
    assert profile.body == {}


def test_auth_context_actor_profile_defaults_none():
    """``AuthContext`` stays backward compatible with ``actor_profile=None``.

    **Validates: Requirement 54 (design §5)**
    """
    ctx = AuthContext(name="alice", type=AuthType.BEARER, token="tok")
    assert ctx.actor_profile is None


def test_auth_context_accepts_actor_profile():
    """``AuthContext`` can carry an attached ``ActorProfile``."""
    profile = ActorProfile(context_name="alice", body={"/api/orders": {"owner": "alice"}})
    ctx = AuthContext(name="alice", type=AuthType.BEARER, token="tok", actor_profile=profile)
    assert ctx.actor_profile is profile


# ---------------------------------------------------------------------------
# load_actor_profiles: JSON parsing
# ---------------------------------------------------------------------------

def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_load_actor_profiles_json(tmp_path):
    """A JSON source parses into ``{context_name: ActorProfile}``.

    **Validates: Requirement 54.1**
    """
    source = _write(
        tmp_path,
        "profiles.json",
        json.dumps(
            {
                "alice": {
                    "query": {"/api/orders": {"tenant": "acme"}},
                    "body": {"/api/orders": {"owner": "alice"}},
                },
                "bob": {"body": {"/api/orders": {"owner": "bob"}}},
            }
        ),
    )

    profiles = load_actor_profiles(source)

    assert set(profiles) == {"alice", "bob"}
    assert profiles["alice"].context_name == "alice"
    assert profiles["alice"].query == {"/api/orders": {"tenant": "acme"}}
    assert profiles["alice"].body == {"/api/orders": {"owner": "alice"}}
    # A profile omitting 'query' defaults it to an empty map.
    assert profiles["bob"].query == {}
    assert profiles["bob"].body == {"/api/orders": {"owner": "bob"}}


def test_load_actor_profiles_yaml(tmp_path):
    """A YAML source parses equivalently to JSON.

    **Validates: Requirement 54.1**
    """
    source = _write(
        tmp_path,
        "profiles.yaml",
        """
alice:
  query:
    /api/orders:
      tenant: acme
  body:
    /api/orders:
      owner: alice
""",
    )

    profiles = load_actor_profiles(source)

    assert set(profiles) == {"alice"}
    assert profiles["alice"].query == {"/api/orders": {"tenant": "acme"}}
    assert profiles["alice"].body == {"/api/orders": {"owner": "alice"}}


def test_load_actor_profiles_unknown_suffix_json_fallback(tmp_path):
    """An unknown suffix still parses JSON content."""
    source = _write(
        tmp_path,
        "profiles.txt",
        json.dumps({"alice": {"body": {"/x": {"a": 1}}}}),
    )
    profiles = load_actor_profiles(source)
    assert profiles["alice"].body == {"/x": {"a": 1}}


# ---------------------------------------------------------------------------
# load_actor_profiles: descriptive errors naming the source (Req 54.5)
# ---------------------------------------------------------------------------

def test_load_actor_profiles_missing_source_names_source(tmp_path):
    """A missing source raises an error naming the source.

    **Validates: Requirement 54.5**
    """
    missing = str(tmp_path / "nope.json")
    with pytest.raises(ValueError) as exc:
        load_actor_profiles(missing)
    assert missing in str(exc.value)


def test_load_actor_profiles_malformed_json_names_source(tmp_path):
    """A malformed JSON source raises an error naming the source.

    **Validates: Requirement 54.5**
    """
    source = _write(tmp_path, "bad.json", "{ this is : not valid json ")
    with pytest.raises(ValueError) as exc:
        load_actor_profiles(source)
    assert source in str(exc.value)


def test_load_actor_profiles_malformed_yaml_names_source(tmp_path):
    """A malformed YAML source raises an error naming the source.

    **Validates: Requirement 54.5**
    """
    source = _write(tmp_path, "bad.yaml", "alice:\n  query: [unclosed\n")
    with pytest.raises(ValueError) as exc:
        load_actor_profiles(source)
    assert source in str(exc.value)


def test_load_actor_profiles_non_mapping_top_level_names_source(tmp_path):
    """A non-mapping top level raises an error naming the source.

    **Validates: Requirement 54.5**
    """
    source = _write(tmp_path, "list.json", json.dumps(["alice", "bob"]))
    with pytest.raises(ValueError) as exc:
        load_actor_profiles(source)
    assert source in str(exc.value)


def test_load_actor_profiles_bad_entry_shape_names_source(tmp_path):
    """A profile entry that is not a mapping raises an error naming the source.

    **Validates: Requirement 54.5**
    """
    source = _write(tmp_path, "bad_entry.json", json.dumps({"alice": "not-a-mapping"}))
    with pytest.raises(ValueError) as exc:
        load_actor_profiles(source)
    assert source in str(exc.value)
    assert "alice" in str(exc.value)


def test_load_actor_profiles_bad_section_shape_names_source(tmp_path):
    """A non-mapping 'query'/'body' section raises an error naming the source.

    **Validates: Requirement 54.5**
    """
    source = _write(tmp_path, "bad_section.json", json.dumps({"alice": {"query": [1, 2]}}))
    with pytest.raises(ValueError) as exc:
        load_actor_profiles(source)
    assert source in str(exc.value)
