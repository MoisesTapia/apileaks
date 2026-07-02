"""
Example-based unit tests for typed Actor_Profiles in multi-user testing
(Requirement 54).

**Feature: owasp-auth-modules-hardening, Task 51.1**

Actor_Profiles supply per-identity, per-endpoint ``query`` and ``body`` values on
top of the token carried by ``--auth-context``. These worked examples exercise the
loader (``core.config.load_actor_profiles``) and the shared consumption helper
(``utils.typed_payload.apply_actor_profile``) together, pinning:

* per-context per-endpoint load and apply - a source parses into one
  ``ActorProfile`` per Auth_Context and the profile's ``query``/``body`` overlay
  the typed base with the profile value winning (Reqs 54.1, 54.2);
* missing-profile fallback - an Auth_Context with no profile leaves the base
  unchanged (Req 54.3);
* endpoint-omitting fallback - a profile that omits an endpoint leaves the base
  unchanged for that endpoint (Req 54.4);
* malformed source aborts naming the offending source before any request
  (Req 54.5).
"""

import json

import pytest

from core.config import ActorProfile, AuthContext, AuthType, load_actor_profiles
from utils.typed_payload import apply_actor_profile


ORDERS = "https://api.example.com/orders"
ITEMS = "https://api.example.com/items"


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def _ctx(name, profile=None, privilege_level=1):
    return AuthContext(
        name=name,
        type=AuthType.BEARER,
        token=f"{name}-token",
        privilege_level=privilege_level,
        actor_profile=profile,
    )


# ---------------------------------------------------------------------------
# 54.1 / 54.2 - per-context per-endpoint load and apply
# ---------------------------------------------------------------------------

def test_load_profiles_per_context_and_apply_per_endpoint(tmp_path):
    """A source loads one profile per context; values apply per endpoint, profile wins.

    **Validates: Requirements 54.1, 54.2**
    """
    source = _write(
        tmp_path,
        "profiles.json",
        json.dumps(
            {
                "alice": {
                    "query": {ORDERS: {"tenant": "acme", "shared": "profile"}},
                    "body": {ORDERS: {"owner": "alice"}},
                },
                "bob": {"body": {ITEMS: {"owner": "bob"}}},
            }
        ),
    )

    profiles = load_actor_profiles(source)
    assert set(profiles) == {"alice", "bob"}

    alice = _ctx("alice", profiles["alice"])
    bob = _ctx("bob", profiles["bob"])

    # Alice on /orders: profile query overlays the base, profile value wins on
    # the shared key; profile body is applied on top of the base body.
    query, body = apply_actor_profile(
        alice, ORDERS, query={"page": 1, "shared": "base"}, body={"note": "keep"}
    )
    assert query == {"page": 1, "shared": "profile", "tenant": "acme"}
    assert body == {"note": "keep", "owner": "alice"}

    # Bob on /items: only body declared for /items.
    query, body = apply_actor_profile(bob, ITEMS, query={"page": 2}, body=None)
    assert query == {"page": 2}
    assert body == {"owner": "bob"}


def test_apply_none_base_with_profile_builds_fresh_values():
    """With a profile but no base, apply builds fresh query/body dicts.

    **Validates: Requirement 54.2**
    """
    profile = ActorProfile(
        context_name="alice",
        query={ORDERS: {"tenant": "acme"}},
        body={ORDERS: {"owner": "alice"}},
    )
    query, body = apply_actor_profile(_ctx("alice", profile), ORDERS)
    assert query == {"tenant": "acme"}
    assert body == {"owner": "alice"}


# ---------------------------------------------------------------------------
# 54.3 - missing-profile fallback
# ---------------------------------------------------------------------------

def test_missing_profile_leaves_base_unchanged():
    """An Auth_Context with no profile preserves the base exactly (incl. None).

    **Validates: Requirement 54.3**
    """
    ctx = _ctx("bob", profile=None)
    query, body = apply_actor_profile(ctx, ORDERS, query={"a": 1}, body=None)
    assert query == {"a": 1}
    assert body is None

    query, body = apply_actor_profile(ctx, ORDERS)
    assert query is None
    assert body is None


# ---------------------------------------------------------------------------
# 54.4 - endpoint-omitting fallback
# ---------------------------------------------------------------------------

def test_endpoint_omitting_profile_leaves_base_unchanged():
    """A profile that omits the endpoint applies the base unchanged for it.

    **Validates: Requirement 54.4**
    """
    profile = ActorProfile(
        context_name="alice",
        query={ITEMS: {"x": 1}},
        body={ITEMS: {"y": 2}},
    )
    base_query = {"page": 1}
    base_body = {"field": "value"}
    query, body = apply_actor_profile(
        _ctx("alice", profile), ORDERS, query=base_query, body=base_body
    )
    assert query == base_query
    assert body == base_body


# ---------------------------------------------------------------------------
# 54.5 - malformed source aborts naming the source
# ---------------------------------------------------------------------------

def test_missing_source_aborts_naming_source(tmp_path):
    """A missing source raises a descriptive error naming the source.

    **Validates: Requirement 54.5**
    """
    missing = str(tmp_path / "nope.json")
    with pytest.raises(ValueError) as exc:
        load_actor_profiles(missing)
    assert missing in str(exc.value)


def test_malformed_json_aborts_naming_source(tmp_path):
    """A malformed JSON source raises naming the source.

    **Validates: Requirement 54.5**
    """
    source = _write(tmp_path, "bad.json", "{ this is : not valid json ")
    with pytest.raises(ValueError) as exc:
        load_actor_profiles(source)
    assert source in str(exc.value)


def test_non_mapping_top_level_aborts_naming_source(tmp_path):
    """A non-mapping top level raises naming the source.

    **Validates: Requirement 54.5**
    """
    source = _write(tmp_path, "list.json", json.dumps(["alice", "bob"]))
    with pytest.raises(ValueError) as exc:
        load_actor_profiles(source)
    assert source in str(exc.value)


if __name__ == "__main__":
    pytest.main([__file__])
