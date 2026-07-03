"""
Unit tests for the ``--unauthorized-assertions`` option on the ``full`` command.

**Feature: owasp-auth-modules-hardening, Task 48.1**

These tests lock in the CLI behavior added by Task 48.1 (consistent with the
``--actor-profile`` handling of Task 47.1):

- A valid ``--unauthorized-assertions`` source is parsed up front and the scan
  proceeds normally (Requirement 55.1).
- A malformed/unreadable/uncompilable source aborts with a ``click.BadParameter``
  naming the offending source BEFORE any request is issued (Requirement 55.1) —
  the scan boundary (``run_enhanced_apileak``) is never reached.
- With no ``--unauthorized-assertions`` supplied, the existing behavior is
  preserved (Requirement 55.5).

They mirror the CLI-testing patterns in ``tests/test_actor_profile_cli.py``.
"""

import json
from unittest.mock import patch

from click.testing import CliRunner

import apileaks
from apileaks import cli


TARGET = "https://api.example.com"


def _invoke_full_capturing_config(args):
    """Invoke ``full`` and capture whether the scan boundary was reached.

    ``run_enhanced_apileak`` is the first consumer of the loaded, threaded
    configuration, so replacing it lets us confirm the scan boundary without
    performing a real scan. If it is *not* reached (e.g. the CLI aborted during
    up-front parsing), ``captured`` stays empty — which is exactly what the
    abort-before-request tests assert.
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
# Valid source is parsed and the scan proceeds (55.1)
# ---------------------------------------------------------------------------

def test_valid_assertions_source_reaches_scan(tmp_path):
    """A valid source is parsed up front and the scan proceeds.

    **Validates: Requirement 55.1**
    """
    source = _write(
        tmp_path,
        "assertions.json",
        json.dumps({"alice": ["^/admin", "/api/secret/.*"]}),
    )

    result, captured = _invoke_full_capturing_config(
        ["--auth-context", "alice:alice-token", "--unauthorized-assertions", source]
    )

    assert result.exit_code == 0, result.output
    assert captured.get("reached_scan") is True


def test_no_assertions_preserves_existing_behavior():
    """With no ``--unauthorized-assertions`` supplied, the scan proceeds.

    **Validates: Requirement 55.5**
    """
    result, captured = _invoke_full_capturing_config(
        ["--auth-context", "alice:alice-token"]
    )

    assert result.exit_code == 0, result.output
    assert captured.get("reached_scan") is True


# ---------------------------------------------------------------------------
# Parse/compile failure aborts before any request naming the source (55.1)
# ---------------------------------------------------------------------------

def test_malformed_assertions_aborts_before_request(tmp_path):
    """A malformed source aborts with a BadParameter naming the source.

    **Validates: Requirement 55.1**
    """
    source = _write(tmp_path, "bad.json", "{ not valid json ")

    result, captured = _invoke_full_capturing_config(
        ["--auth-context", "alice:alice-token", "--unauthorized-assertions", source]
    )

    assert result.exit_code != 0
    assert source in result.output
    assert "reached_scan" not in captured


def test_invalid_regex_assertions_aborts_before_request(tmp_path):
    """A source with an uncompilable regex aborts naming the source.

    **Validates: Requirement 55.1**
    """
    source = _write(tmp_path, "bad_regex.json", json.dumps({"alice": ["("]}))

    result, captured = _invoke_full_capturing_config(
        ["--auth-context", "alice:alice-token", "--unauthorized-assertions", source]
    )

    assert result.exit_code != 0
    assert source in result.output
    assert "reached_scan" not in captured


def test_missing_assertions_aborts_before_request(tmp_path):
    """A missing source aborts with a BadParameter naming the source.

    **Validates: Requirement 55.1**
    """
    missing = str(tmp_path / "nope.json")

    result, captured = _invoke_full_capturing_config(
        ["--unauthorized-assertions", missing]
    )

    assert result.exit_code != 0
    assert missing in result.output
    assert "reached_scan" not in captured
