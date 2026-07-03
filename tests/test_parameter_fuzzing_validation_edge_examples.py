"""Validation-edge example tests for the ``par`` command (task 11.10).

**Feature: parameter-fuzzing, Task 11.10**

Each test invokes the real ``par`` Click command through
:class:`click.testing.CliRunner` with a single invalid input and asserts three
things:

1. The command fails with a non-zero exit status.
2. The descriptive error names the offending option and/or value.
3. ZERO HTTP requests are issued (the run stops before any network activity),
   and for the machine-output case no output file is written.

To make "zero HTTP requests" an observable, checked fact, the single
``HTTPRequestEngine`` construction point (:data:`utils.http_client.HTTPRequestEngine`)
is patched with a recording offline stub built on the task-1.1 harness
(:mod:`tests.support.http_stub`). Every request any engine instance would issue
is appended to a shared ledger; the tests assert that ledger stays empty. The
run is therefore fully offline and deterministic.

Covered invalid-input cases:

* ``--methods`` empty & whitespace-only & unsupported ...... R6.4, R6.5
* ``--header`` missing colon ............................... R7.5
* malformed ``--basic-auth`` .............................. R7.6
* ``--basic-auth`` + ``--jwt`` mutually exclusive ......... R7.7
* missing/unreadable ``--client-cert`` / ``--ca-bundle`` .. R9.5
* malformed ``--resolve`` ................................. R9.6
* unreadable ``--wordlist`` ............................... R10.3
* ``--max-requests`` < 1 .................................. R11.4
* invalid matcher / filter expression .................... R12.4
* unsupported ``--output-format`` ......................... R12.6

**Validates: Requirements 6.4, 6.5, 7.5, 7.6, 7.7, 9.5, 9.6, 10.3, 11.4, 12.4, 12.6**
"""

from __future__ import annotations

from unittest import mock

import pytest
from click.testing import CliRunner

import apileaks
import utils.http_client as hc
from tests.support.http_stub import HTTPRequestEngineStub, ScriptedResponse


TARGET = "https://api.example.test/resource"

# Shared ledger of every request issued through any patched engine instance.
# The whole point of these tests is that this stays empty for invalid input.
_ISSUED_REQUESTS: list = []


class _RecordingOfflineEngine(HTTPRequestEngineStub):
    """Offline ``HTTPRequestEngine`` stand-in that records into a shared ledger.

    Any request issued (there should be none for invalid input) is appended to
    the module-level ``_ISSUED_REQUESTS`` list so the tests can assert a hard
    zero-request guarantee across every engine instance.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(default=ScriptedResponse(status_code=200, body={"ok": True}))

    async def request(self, method, url, **kwargs):  # type: ignore[override]
        _ISSUED_REQUESTS.append((str(method).upper(), url))
        return await super().request(method, url, **kwargs)


def _combined_output(result) -> str:
    """Return stdout + stderr from a CliRunner result, robust to separation."""
    parts = []
    for attr in ("stdout", "stderr"):
        try:
            text = getattr(result, attr)
        except ValueError:
            continue
        if text:
            parts.append(text)
    if not parts and result.output:
        parts.append(result.output)
    return "".join(parts)


def _invoke_par(extra_args):
    """Invoke ``par`` offline with ``extra_args`` and return (result, output).

    Patches the single ``HTTPRequestEngine`` construction point with the
    recording offline stub and clears the shared ledger first, so any request
    any engine instance issues is observed.
    """
    _ISSUED_REQUESTS.clear()
    runner = CliRunner()
    with mock.patch.object(hc, "HTTPRequestEngine", _RecordingOfflineEngine):
        result = runner.invoke(
            apileaks.cli,
            ["--no-banner", "par", "--target", TARGET, *extra_args],
        )
    return result, _combined_output(result)


def _assert_rejected_no_requests(result, output, expected_substrings):
    """Assert non-zero exit, error names the offending option/value, no request."""
    assert result.exit_code != 0, (result.exit_code, output)
    for needle in expected_substrings:
        assert needle in output, (
            f"error did not mention {needle!r}: {output!r}"
        )
    assert _ISSUED_REQUESTS == [], (
        f"expected zero HTTP requests, but observed: {_ISSUED_REQUESTS!r}"
    )


# ---------------------------------------------------------------------------
# R6.4 / R6.5 — --methods empty, whitespace-only, unsupported
# ---------------------------------------------------------------------------

def test_methods_empty_rejected_no_requests():
    """An empty ``--methods`` value is rejected before any request (R6.4)."""
    result, output = _invoke_par(["--methods", ""])
    _assert_rejected_no_requests(result, output, ["--methods"])


def test_methods_whitespace_only_rejected_no_requests():
    """A whitespace-only ``--methods`` value is rejected before any request (R6.4)."""
    result, output = _invoke_par(["--methods", "   "])
    _assert_rejected_no_requests(result, output, ["--methods"])


def test_methods_unsupported_rejected_naming_value_no_requests():
    """A ``--methods`` value with no supported HTTP method is rejected (R6.5)."""
    result, output = _invoke_par(["--methods", "FOO,BAR"])
    _assert_rejected_no_requests(result, output, ["--methods", "FOO"])


# ---------------------------------------------------------------------------
# R7.5 — --header missing colon
# ---------------------------------------------------------------------------

def test_header_missing_colon_rejected_naming_header_no_requests():
    """A colon-less ``--header`` value is rejected naming it, no request (R7.5)."""
    bad_header = "X-No-Colon-Here"
    result, output = _invoke_par(["--header", bad_header])
    _assert_rejected_no_requests(result, output, ["--header", bad_header])


# ---------------------------------------------------------------------------
# R7.6 — malformed --basic-auth
# ---------------------------------------------------------------------------

def test_malformed_basic_auth_rejected_naming_value_no_requests():
    """A colon-less ``--basic-auth`` value is rejected naming it, no request (R7.6)."""
    bad_value = "alicenocolon"
    result, output = _invoke_par(["--basic-auth", bad_value])
    _assert_rejected_no_requests(result, output, ["--basic-auth", bad_value])


# ---------------------------------------------------------------------------
# R7.7 — --basic-auth + --jwt are mutually exclusive
# ---------------------------------------------------------------------------

def test_basic_auth_and_jwt_conflict_rejected_no_requests():
    """``--basic-auth`` together with ``--jwt`` is rejected before any request (R7.7)."""
    result, output = _invoke_par(
        ["--basic-auth", "alice:s3cret", "--jwt", "header.payload.signature"]
    )
    _assert_rejected_no_requests(result, output, ["--basic-auth", "--jwt"])


# ---------------------------------------------------------------------------
# R9.5 — missing/unreadable --client-cert / --ca-bundle
# ---------------------------------------------------------------------------

def test_missing_client_cert_rejected_naming_path_no_requests():
    """A nonexistent ``--client-cert`` path is rejected naming it, no request (R9.5)."""
    bad_path = "/nonexistent/path/client-cert.pem"
    result, output = _invoke_par(["--client-cert", bad_path])
    _assert_rejected_no_requests(result, output, ["--client-cert", bad_path])


def test_unreadable_client_cert_rejected_naming_path_no_requests(tmp_path):
    """An unreadable ``--client-cert`` path is rejected naming it, no request (R9.5)."""
    cert = tmp_path / "client-cert.pem"
    cert.write_text("dummy", encoding="utf-8")
    cert.chmod(0o000)
    try:
        result, output = _invoke_par(["--client-cert", str(cert)])
    finally:
        cert.chmod(0o644)
    _assert_rejected_no_requests(result, output, ["--client-cert", str(cert)])


def test_missing_ca_bundle_rejected_naming_path_no_requests():
    """A nonexistent ``--ca-bundle`` path is rejected naming it, no request (R9.5)."""
    bad_path = "/nonexistent/path/ca-bundle.pem"
    result, output = _invoke_par(["--ca-bundle", bad_path])
    _assert_rejected_no_requests(result, output, ["--ca-bundle", bad_path])


# ---------------------------------------------------------------------------
# R9.6 — malformed --resolve
# ---------------------------------------------------------------------------

def test_malformed_resolve_rejected_naming_value_no_requests():
    """A malformed ``--resolve`` value is rejected naming it, no request (R9.6)."""
    bad_value = "not-a-host-ip-pair"
    result, output = _invoke_par(["--resolve", bad_value])
    _assert_rejected_no_requests(result, output, [bad_value])


# ---------------------------------------------------------------------------
# R10.3 — unreadable --wordlist
# ---------------------------------------------------------------------------

def test_unreadable_wordlist_rejected_naming_file_no_requests():
    """A nonexistent ``--wordlist`` file is rejected naming it, no request (R10.3)."""
    bad_path = "/nonexistent/path/wordlist.txt"
    result, output = _invoke_par(["--wordlist", bad_path])
    _assert_rejected_no_requests(result, output, [bad_path])


# ---------------------------------------------------------------------------
# R11.4 — --max-requests < 1
# ---------------------------------------------------------------------------

def test_max_requests_below_one_rejected_naming_value_no_requests():
    """A ``--max-requests`` value below 1 is rejected naming it, no request (R11.4)."""
    result, output = _invoke_par(["--max-requests", "0"])
    _assert_rejected_no_requests(result, output, ["--max-requests", "0"])


# ---------------------------------------------------------------------------
# R12.4 — invalid matcher / filter expression
# ---------------------------------------------------------------------------

def test_invalid_matcher_regex_rejected_no_requests():
    """An unparseable ``--match-regex`` is rejected before any request (R12.4)."""
    result, output = _invoke_par(["--match-regex", "["])
    _assert_rejected_no_requests(result, output, ["invalid regex"])


def test_invalid_filter_numeric_bound_rejected_no_requests():
    """A non-numeric ``--filter-size`` bound is rejected before any request (R12.4)."""
    result, output = _invoke_par(["--filter-size", "not-a-number"])
    _assert_rejected_no_requests(result, output, ["not-a-number"])


# ---------------------------------------------------------------------------
# R12.6 — unsupported --output-format (no output file written)
# ---------------------------------------------------------------------------

def test_unsupported_output_format_rejected_no_file_no_requests(tmp_path):
    """An unsupported ``--output-format`` is rejected and writes no output file (R12.6)."""
    out_file = tmp_path / "findings.out"
    result, output = _invoke_par(
        ["--output-format", "xml", "--output-file", str(out_file)]
    )
    _assert_rejected_no_requests(result, output, ["--output-format"])
    # No machine-readable output file is written for an unsupported format.
    assert not out_file.exists(), (
        f"expected no output file for unsupported format, but found: {out_file}"
    )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
