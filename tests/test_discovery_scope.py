"""
Unit tests for path/status scope parsing and storage-level filtering.

**Feature: owasp-complete-purple-teaming-cicd, Task 38.5**

These example-based unit tests cover the storage-time discovery scope
(Requirement 33):

- ``parse_path_scope`` rejects an invalid regex, raising ``PathScopeError`` that
  names the offending pattern (Requirement 33.8).
- ``parse_storage_status_selection`` rejects an out-of-range explicit code and an
  unrecognized token, raising ``StorageStatusError`` that names the offending
  value (Requirement 33.9).
- Via the ``dir`` command (CliRunner), an invalid ``--include-path`` /
  ``--exclude-path`` regex and an out-of-range / unrecognized ``--include-status``
  / ``--exclude-status`` value each fail naming the value and perform NO
  Endpoint_Discovery (the discovery entry points are patched and asserted never
  called) — mirroring tests/test_discovery_controls_cli.py.
- Driving the real ``EndpointFuzzer`` against an in-memory fake
  ``HTTPRequestEngine``, a record dropped by the ``Storage_Status_Selection`` (or
  the ``Path_Scope``) never enters ``discovered_endpoints`` and therefore never
  reaches the discovery session / output, and CANNOT be resurrected by a later
  display-only ``--status-code`` filter (Requirements 33.6, 33.7) because it was
  never stored.

The Hypothesis property test for exclude precedence is Task 38.6 and lives
elsewhere; this file is example-based only.
"""

import asyncio
import os
import tempfile
from urllib.parse import urlparse

import pytest
from click.testing import CliRunner

import apileaks
from apileaks import cli
from core.config import (
    FuzzingConfig,
    EndpointFuzzingConfig,
    ParameterFuzzingConfig,
    HeaderFuzzingConfig,
)
from modules.fuzzing.orchestrator import EndpointFuzzer, Endpoint
from utils.discovery_scope import (
    PathScopeError,
    StorageStatusError,
    parse_path_scope,
    parse_storage_status_selection,
)
from utils.discovery_session import (
    DiscoveryResult,
    apply_status_filter,
    parse_status_filter,
)
from utils.http_client import Response


# ===========================================================================
# parse_path_scope: invalid regex rejection (Requirement 33.8)
# ===========================================================================

def test_parse_path_scope_rejects_invalid_include_regex():
    """An invalid ``--include-path`` regex raises PathScopeError naming it.

    **Validates: Requirements 33.8**
    """
    bad = "ad[min"  # unterminated character class
    with pytest.raises(PathScopeError) as exc_info:
        parse_path_scope([bad], [])
    # The offending pattern is named in the message.
    assert bad in str(exc_info.value)


def test_parse_path_scope_rejects_invalid_exclude_regex():
    """An invalid ``--exclude-path`` regex raises PathScopeError naming it.

    **Validates: Requirements 33.8**
    """
    bad = "(unclosed"  # unbalanced parenthesis
    with pytest.raises(PathScopeError) as exc_info:
        parse_path_scope([], [bad])
    assert bad in str(exc_info.value)


def test_parse_path_scope_accepts_valid_regexes():
    """Valid include/exclude regexes compile into a usable PathScope.

    **Validates: Requirements 33.8**
    """
    scope = parse_path_scope([r"^/api/"], [r"admin"])
    # Sanity: the compiled scope admits an /api path and excludes an admin path.
    assert scope.admits("/api/users", "http://h/api/users") is True
    assert scope.admits("/admin", "http://h/admin") is False


# ===========================================================================
# parse_storage_status_selection: invalid status rejection (Requirement 33.9)
# ===========================================================================

@pytest.mark.parametrize("bad_value", ["600", "99", "1000"])
def test_parse_storage_status_selection_rejects_out_of_range_include(bad_value):
    """An out-of-range explicit ``--include-status`` code is rejected by name.

    **Validates: Requirements 33.9**
    """
    with pytest.raises(StorageStatusError) as exc_info:
        parse_storage_status_selection(bad_value, None)
    assert bad_value in str(exc_info.value)


@pytest.mark.parametrize("bad_value", ["600", "99"])
def test_parse_storage_status_selection_rejects_out_of_range_exclude(bad_value):
    """An out-of-range explicit ``--exclude-status`` code is rejected by name.

    **Validates: Requirements 33.9**
    """
    with pytest.raises(StorageStatusError) as exc_info:
        parse_storage_status_selection(None, bad_value)
    assert bad_value in str(exc_info.value)


def test_parse_storage_status_selection_rejects_unrecognized_token():
    """A token that is neither a status class nor a code is rejected by name.

    **Validates: Requirements 33.9**
    """
    bad = "banana"
    with pytest.raises(StorageStatusError) as exc_info:
        parse_storage_status_selection(bad, None)
    assert bad in str(exc_info.value)


def test_parse_storage_status_selection_accepts_class_and_codes():
    """A status class and explicit codes parse into a usable selection.

    **Validates: Requirements 33.9**
    """
    selection = parse_storage_status_selection("2xx", "500,503")
    # 2xx admitted by include; 500 dropped by exclude.
    assert selection.admits(200) is True
    assert selection.admits(500) is False


# ===========================================================================
# CLI: invalid scope values exit before discovery (Requirements 33.8, 33.9)
# ===========================================================================

# Each row: (flag, invalid value) that must be rejected, naming the value, and
# perform NO Endpoint_Discovery.
_INVALID_SCOPE_CASES = [
    ("--include-path", "ad[min"),   # invalid regex (33.8)
    ("--exclude-path", "(unclosed"),  # invalid regex (33.8)
    ("--include-status", "600"),    # out-of-range code (33.9)
    ("--exclude-status", "99"),     # out-of-range code (33.9)
    ("--include-status", "banana"),  # unrecognized token (33.9)
]


@pytest.mark.parametrize("flag, value", _INVALID_SCOPE_CASES)
def test_invalid_scope_value_rejected_and_no_discovery(flag, value):
    """Invalid scope values fail naming the value and run no discovery.

    The Path_Scope / Storage_Status_Selection are parsed up front in the ``dir``
    command body, before any candidate resolution or discovery, so an invalid
    value exits with a descriptive error and neither the standard discovery path
    (``run_enhanced_apileak``) nor the triage path (``_run_dir_triage``) is ever
    reached.

    **Validates: Requirements 33.8, 33.9**
    """
    runner = CliRunner()

    with patch_discovery_entrypoints() as (standard, triage):
        result = runner.invoke(
            cli,
            [
                "--no-banner",
                "dir",
                "--target",
                "https://api.example.com",
                f"{flag}={value}",
            ],
        )

    # Non-zero exit and the offending value is surfaced in the error output.
    assert result.exit_code != 0
    assert value in result.output
    # No discovery was performed by either path.
    standard.assert_not_called()
    triage.assert_not_called()


class patch_discovery_entrypoints:
    """Context manager patching both the standard and triage discovery paths.

    Patching both ``run_enhanced_apileak`` and ``_run_dir_triage`` lets the
    tests prove that an invalid scope value exits *before* any discovery runs,
    regardless of which path the command would otherwise take.
    """

    def __enter__(self):
        from unittest.mock import patch

        self._p1 = patch.object(apileaks, "run_enhanced_apileak")
        self._p2 = patch.object(apileaks, "_run_dir_triage")
        return self._p1.start(), self._p2.start()

    def __exit__(self, *exc):
        self._p1.stop()
        self._p2.stop()
        return False


# ===========================================================================
# Storage-drop: dropped records never stored, cannot be resurrected (33.6, 33.7)
# ===========================================================================

BASE_URL = "http://example.com"

# Catch-all detection probes target uuid4().hex paths (33 chars); the genuine
# wordlist segments below are short, so a length threshold reliably tells a
# probe path apart from a real candidate path.
_PROBE_SEGMENT_MIN_LEN = 20

# word -> status code returned by the fake client for that genuine path.
_STATUS_BY_WORD = {
    "alpha": 200,   # kept: 2xx, not path-excluded
    "beta": 500,    # dropped by Storage_Status_Selection (include 2xx)
    "admin": 200,   # dropped by Path_Scope (exclude "admin"), despite 2xx
}


class ScopedStatusFakeClient:
    """In-memory fake HTTPRequestEngine returning a configured status per word.

    Genuine wordlist paths return the status mapped in ``_STATUS_BY_WORD``. The
    long, random catch-all detection probe paths return 404 so
    Catch_All_Response detection stays off and does not interfere with the
    storage-scope behavior under test. Every (method, url) call is recorded.
    """

    def __init__(self):
        self.calls = []

    async def request(self, method: str, url: str, **kwargs) -> Response:
        self.calls.append((method, url))
        await asyncio.sleep(0)

        path = urlparse(url).path
        segments = [s for s in path.split("/") if s]
        last_segment = segments[-1] if segments else ""

        if len(last_segment) >= _PROBE_SEGMENT_MIN_LEN:
            # Catch-all probe path: keep detection off.
            status_code = 404
        else:
            status_code = _STATUS_BY_WORD.get(last_segment, 404)

        body = b'{"ok": true}'
        return Response(
            status_code=status_code,
            headers={"Content-Type": "application/json"},
            content=body,
            text=body.decode(),
            url=url,
            elapsed=0.01,
            request_method=method,
        )


def _make_scoped_config(path_scope, storage_status) -> FuzzingConfig:
    """Build a non-recursive FuzzingConfig wired with the given scope objects."""
    return FuzzingConfig(
        endpoints=EndpointFuzzingConfig(
            enabled=True,
            wordlist="unused.txt",
            methods=["GET"],
            follow_redirects=False,
        ),
        parameters=ParameterFuzzingConfig(enabled=False),
        headers=HeaderFuzzingConfig(enabled=False),
        recursive=False,
        max_depth=0,
        max_requests=None,
        concurrency=50,
        path_scope=path_scope,
        storage_status=storage_status,
    )


def _write_wordlist(words):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    f.write("\n".join(words) + "\n")
    f.close()
    return f.name


async def _run_scoped_discovery(path_scope, storage_status):
    fake_client = ScopedStatusFakeClient()
    fuzzer = EndpointFuzzer(fake_client, _make_scoped_config(path_scope, storage_status))
    wordlist_path = _write_wordlist(list(_STATUS_BY_WORD.keys()))
    try:
        discovered = await fuzzer.discover_endpoints(BASE_URL, wordlist_path)
    finally:
        os.unlink(wordlist_path)
    return fake_client, fuzzer, discovered


def test_storage_status_dropped_record_never_stored():
    """A status excluded by Storage_Status_Selection never enters discovery state.

    With ``--include-status 2xx``, the 500 ("beta") response is dropped at
    storage time: it is absent from ``discovered_endpoints`` and the returned
    result list, while the admitted 200 ("alpha") record is present.

    **Validates: Requirements 33.6**
    """
    storage_status = parse_storage_status_selection("2xx", None)
    fake_client, fuzzer, discovered = asyncio.run(
        _run_scoped_discovery(path_scope=None, storage_status=storage_status)
    )

    stored_urls = set(fuzzer.discovered_endpoints.keys())
    alpha_url = f"{BASE_URL}/alpha"
    beta_url = f"{BASE_URL}/beta"

    # The 2xx record is stored; the 5xx record is dropped at storage time.
    assert alpha_url in stored_urls
    assert beta_url not in stored_urls
    # The returned discovery list mirrors discovered_endpoints (no dropped 5xx).
    assert all(isinstance(e, Endpoint) for e in discovered)
    assert all(e.status_code != 500 for e in discovered)
    # The 5xx request *was* issued (path scope did not drop it); it was dropped
    # purely at storage time, proving storage filtering — not request avoidance.
    assert (("GET", beta_url)) in fake_client.calls


def test_path_scope_excluded_record_never_stored():
    """A path excluded by Path_Scope never enters discovery state, even at 2xx.

    With ``--exclude-path admin``, the "admin" candidate (which would answer
    200) is dropped: it is absent from ``discovered_endpoints``.

    **Validates: Requirements 33.6**
    """
    path_scope = parse_path_scope([], ["admin"])
    fake_client, fuzzer, discovered = asyncio.run(
        _run_scoped_discovery(path_scope=path_scope, storage_status=None)
    )

    stored_urls = set(fuzzer.discovered_endpoints.keys())
    admin_url = f"{BASE_URL}/admin"
    alpha_url = f"{BASE_URL}/alpha"

    assert alpha_url in stored_urls
    assert admin_url not in stored_urls
    # The excluded candidate consumed no Discovery_Request (dropped before
    # dispatch in _fuzz_wordlist).
    assert not any(url == admin_url for _, url in fake_client.calls)


def test_dropped_record_cannot_be_resurrected_by_display_status_filter():
    """A storage-dropped record cannot reappear via a display ``--status-code``.

    The display-only Status_Code_Filter (Requirement 13, ``apply_status_filter``)
    operates on the records that were actually persisted. Because the 500
    ("beta") record was dropped at storage time, no display filter — including
    one that explicitly matches 5xx — can resurrect it: it is not in the stored
    set to begin with.

    **Validates: Requirements 33.6, 33.7**
    """
    storage_status = parse_storage_status_selection("2xx", None)
    _, fuzzer, _ = asyncio.run(
        _run_scoped_discovery(path_scope=None, storage_status=storage_status)
    )

    # Project the persisted endpoints exactly as the triage/output layer would.
    records = [
        DiscoveryResult.from_endpoint(e)
        for e in fuzzer.discovered_endpoints.values()
    ]
    beta_url = f"{BASE_URL}/beta"

    # The dropped 5xx record is not even in the stored projection.
    assert all(r.url != beta_url for r in records)

    # Apply a display-only filter that matches the dropped status (5xx). It
    # cannot surface the record because it was never stored.
    status_filter = parse_status_filter("5xx")
    displayed = apply_status_filter(records, status_filter)
    assert displayed == []
    assert all(r.url != beta_url for r in displayed)

    # An explicit display filter for code 500 is likewise unable to resurrect it.
    displayed_explicit = apply_status_filter(records, parse_status_filter("500"))
    assert all(r.url != beta_url for r in displayed_explicit)
