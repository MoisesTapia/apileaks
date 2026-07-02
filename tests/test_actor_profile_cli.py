"""
Unit tests for the ``--actor-profile`` option on the ``full`` command.

**Feature: owasp-auth-modules-hardening, Task 47.1**

These tests lock in the CLI behavior added by Task 47.1:

- A valid ``--actor-profile`` source is parsed up front and each profile is
  attached to the ``AuthContext`` whose name matches its ``context_name``
  (Requirements 54.1, 54.2).
- A malformed/unreadable source aborts with a ``click.BadParameter`` naming the
  offending source BEFORE any request is issued (Requirement 54.5) — the scan
  boundary (``run_enhanced_apileak``) is never reached.
- With no ``--actor-profile`` supplied, contexts keep ``actor_profile = None``
  and the existing behavior is preserved (Requirement 54.3).

They mirror the CLI-testing patterns in
``tests/test_multi_auth_context_cli.py`` (``CliRunner`` invocation, capturing
the threaded config via a patch, and patching so no real network scan runs).
"""

import json
from unittest.mock import patch

from click.testing import CliRunner

import apileaks
from apileaks import cli


TARGET = "https://api.example.com"


def _invoke_full_capturing_config(args):
    """Invoke ``full`` and capture the fully threaded ``apileak_config``.

    ``run_enhanced_apileak`` is the first consumer of the loaded, auth-context-
    and actor-profile-threaded configuration, so replacing it lets us inspect
    the effective contexts without performing a real scan. If it is *not*
    reached (e.g. the CLI aborted during up-front parsing), ``captured`` stays
    empty — which is exactly what the abort-before-request tests assert.
    """
    captured = {}

    def _capture(config, *rest, **kwargs):
        captured["config"] = config
        captured["reached_scan"] = True

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
    return result, captured


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------------------
# Valid profile is attached to the matching AuthContext (54.1, 54.2)
# ---------------------------------------------------------------------------

def test_actor_profile_attached_to_matching_context(tmp_path):
    """A profile is attached to the AuthContext with the matching name.

    **Validates: Requirements 54.1, 54.2**
    """
    source = _write(
        tmp_path,
        "profiles.json",
        json.dumps(
            {
                "alice": {
                    "query": {"/api/orders": {"tenant": "acme"}},
                    "body": {"/api/orders": {"owner": "alice"}},
                }
            }
        ),
    )

    result, captured = _invoke_full_capturing_config(
        [
            "--auth-context", "alice:alice-token:2",
            "--auth-context", "bob:bob-token",
            "--actor-profile", source,
        ]
    )

    assert result.exit_code == 0, result.output
    config = captured["config"]
    by_name = {ctx.name: ctx for ctx in config.authentication.contexts}

    # alice matches the profile...
    assert by_name["alice"].actor_profile is not None
    assert by_name["alice"].actor_profile.query == {"/api/orders": {"tenant": "acme"}}
    assert by_name["alice"].actor_profile.body == {"/api/orders": {"owner": "alice"}}
    # ...bob has no matching profile and keeps None.
    assert by_name["bob"].actor_profile is None


def test_no_actor_profile_leaves_contexts_unprofiled():
    """With no ``--actor-profile`` supplied, contexts keep ``actor_profile=None``.

    **Validates: Requirement 54.3**
    """
    result, captured = _invoke_full_capturing_config(
        ["--auth-context", "alice:alice-token"]
    )

    assert result.exit_code == 0, result.output
    config = captured["config"]
    for ctx in config.authentication.contexts:
        assert ctx.actor_profile is None


# ---------------------------------------------------------------------------
# Parse failure aborts before any request naming the source (54.5)
# ---------------------------------------------------------------------------

def test_malformed_actor_profile_aborts_before_request(tmp_path):
    """A malformed source aborts with a BadParameter naming the source.

    **Validates: Requirement 54.5**
    """
    source = _write(tmp_path, "bad.json", "{ not valid json ")

    result, captured = _invoke_full_capturing_config(
        ["--auth-context", "alice:alice-token", "--actor-profile", source]
    )

    # Non-zero exit (click.BadParameter -> usage error, exit code 2).
    assert result.exit_code != 0
    # The offending source is named in the error output.
    assert source in result.output
    # No request/scan was ever reached.
    assert "reached_scan" not in captured


def test_missing_actor_profile_aborts_before_request(tmp_path):
    """A missing source aborts with a BadParameter naming the source.

    **Validates: Requirement 54.5**
    """
    missing = str(tmp_path / "nope.json")

    result, captured = _invoke_full_capturing_config(
        ["--actor-profile", missing]
    )

    assert result.exit_code != 0
    assert missing in result.output
    assert "reached_scan" not in captured
