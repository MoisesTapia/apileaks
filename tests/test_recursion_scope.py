"""
Unit tests for Recursion_Scope parsing and orchestrator wiring.

**Feature: owasp-complete-purple-teaming-cicd, Task 39.5**

These deterministic, example-based unit tests cover the Recursion_Scope control
(Requirement 34):

- ``parse_recursion_scope`` rejects an unrecognized Status_Code_Class token AND
  an unrecognized endpoint type, raising ``RecursionScopeError`` that names the
  offending value (Requirement 34.8); and, via the ``dir`` / ``full`` commands
  (CliRunner), such an invalid value exits with a descriptive error and performs
  NO Endpoint_Discovery (the discovery entry points are patched and asserted
  never called) — mirroring tests/test_discovery_controls_cli.py.
- With ``recursion_scope=None`` (the default, no flags) the real
  ``EndpointFuzzer._recursive_fuzzing`` recurses into EXACTLY the same records as
  before: VALID / AUTH_REQUIRED, not file-like, and not Catch_All_Response
  (Requirement 34.4).
- A supplied Recursion_Scope only narrows the recursable set (Requirement 34.3)
  while Recursion_Depth (34.5), Request_Budget (34.6) and Catch_All_Response
  suppression (34.7) are all still honored.

The Hypothesis property test for the recursion-scope subset property is Task
39.6 and lives elsewhere; this file is example-based only.
"""

import asyncio

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
from modules.fuzzing.orchestrator import EndpointFuzzer, Endpoint, EndpointStatus
from utils.discovery_scope import (
    RecursionScope,
    RecursionScopeError,
    parse_recursion_scope,
)
from utils.http_client import Response


# ===========================================================================
# parse_recursion_scope: invalid value rejection (Requirement 34.8)
# ===========================================================================

def test_parse_recursion_scope_rejects_unrecognized_status_class():
    """An unrecognized ``--recursion-status`` class raises naming the value.

    **Validates: Requirements 34.8**
    """
    bad = "9xx"  # not one of 2xx..5xx
    with pytest.raises(RecursionScopeError) as exc_info:
        parse_recursion_scope(f"2xx,{bad}", None)
    # The offending token is named in the message.
    assert bad in str(exc_info.value)


def test_parse_recursion_scope_rejects_unrecognized_endpoint_type():
    """An unrecognized ``--recursion-type`` value raises naming the value.

    **Validates: Requirements 34.8**
    """
    bad = "bogus"  # not in VALID_ENDPOINT_TYPES
    with pytest.raises(RecursionScopeError) as exc_info:
        parse_recursion_scope(None, f"admin,{bad}")
    assert bad in str(exc_info.value)


def test_parse_recursion_scope_accepts_valid_classes_and_types():
    """Valid status classes and endpoint types parse into a usable scope.

    **Validates: Requirements 34.8**
    """
    scope = parse_recursion_scope("2xx,3xx", "admin,api_version")
    assert scope.status_classes == frozenset({"2xx", "3xx"})
    assert scope.endpoint_types == frozenset({"admin", "api_version"})


# ===========================================================================
# CLI: invalid recursion-scope value exits before discovery (Requirement 34.8)
# ===========================================================================

# Each row: (command, flag, invalid value) that must be rejected, naming the
# value, and perform NO Endpoint_Discovery.
_INVALID_RECURSION_CASES = [
    ("dir", "--recursion-status", "9xx"),    # unrecognized status class
    ("full", "--recursion-status", "9xx"),
    ("dir", "--recursion-type", "bogus"),    # unrecognized endpoint type
    ("full", "--recursion-type", "bogus"),
]


class _patch_discovery_entrypoints:
    """Context manager patching both the standard and triage discovery paths.

    Patching both ``run_enhanced_apileak`` (used by ``dir`` and ``full``) and
    ``_run_dir_triage`` (the ``dir`` triage path) lets the tests prove that an
    invalid Recursion_Scope value exits *before* any discovery runs, regardless
    of which path the command would otherwise take.
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


@pytest.mark.parametrize("command, flag, value", _INVALID_RECURSION_CASES)
def test_invalid_recursion_value_rejected_and_no_discovery(command, flag, value):
    """An invalid recursion-scope value fails naming it and runs no discovery.

    The Recursion_Scope is parsed up front in both command bodies, before any
    discovery runs, so an unrecognized status class or endpoint type exits with a
    descriptive error and neither the standard discovery path
    (``run_enhanced_apileak``) nor the triage path (``_run_dir_triage``) is ever
    reached.

    **Validates: Requirements 34.8**
    """
    runner = CliRunner()

    with _patch_discovery_entrypoints() as (standard, triage):
        result = runner.invoke(
            cli,
            [
                "--no-banner",
                command,
                "--target",
                "https://api.example.com",
                f"{flag}={value}",
            ],
        )

    # Non-zero exit and the offending value is surfaced in the error output.
    assert result.exit_code != 0
    assert value in result.output
    # No Endpoint_Discovery was performed by either path.
    standard.assert_not_called()
    triage.assert_not_called()


# ===========================================================================
# Orchestrator wiring helpers
# ===========================================================================

class RecordingClient:
    """Fake HTTPRequestEngine recording every request, with a fixed response.

    Mirrors the fake clients used by the budget / catch-all unit tests
    (tasks 21.3 / 22.2): every ``request(...)`` is recorded in ``calls`` so the
    tests can assert exactly which base URLs recursion descended into, and a
    configurable ``status_code`` lets each test control whether depth-N sub-paths
    are themselves recursable.
    """

    def __init__(self, status_code: int = 404, content: bytes = b"nope"):
        self.status_code = status_code
        self.content = content
        self.calls = []  # list of (method, url) in call order

    @property
    def call_count(self) -> int:
        return len(self.calls)

    async def request(self, method: str, url: str, **kwargs) -> Response:
        self.calls.append((method, url))
        await asyncio.sleep(0)
        return Response(
            status_code=self.status_code,
            headers={"Content-Type": "application/json"},
            content=self.content,
            text=self.content.decode("utf-8", "ignore"),
            url=url,
            elapsed=0.01,
            request_method=method,
        )


def _make_config(
    *,
    recursive: bool = True,
    max_depth: int = 1,
    max_requests=None,
    recursion_scope=None,
    methods=None,
):
    return FuzzingConfig(
        endpoints=EndpointFuzzingConfig(
            enabled=True,
            wordlist="unused.txt",
            methods=methods or ["GET"],
            follow_redirects=False,
        ),
        parameters=ParameterFuzzingConfig(enabled=False),
        headers=HeaderFuzzingConfig(enabled=False),
        recursive=recursive,
        max_depth=max_depth,
        max_requests=max_requests,
        concurrency=50,
        recursion_scope=recursion_scope,
    )


def _ep(url, status_code, endpoint_type="standard", response_size=100) -> Endpoint:
    return Endpoint(
        url=url,
        method="GET",
        status_code=status_code,
        response_size=response_size,
        response_time=0.01,
        endpoint_type=endpoint_type,
    )


def _recursed_base_urls(client: RecordingClient, endpoints) -> set:
    """Return the set of endpoint URLs that recursion descended into.

    ``_recursive_fuzzing`` recurses into a base endpoint by appending wordlist
    items to ``base_url + '/'``, so an endpoint was recursed into iff some
    recorded request URL is under its ``url + '/'`` prefix.
    """
    request_urls = [url for _, url in client.calls]
    recursed = set()
    for endpoint in endpoints:
        prefix = endpoint.url.rstrip("/") + "/"
        if any(url.startswith(prefix) for url in request_urls):
            recursed.add(endpoint.url)
    return recursed


# ===========================================================================
# Default (no scope) preserves VALID/AUTH_REQUIRED recursion (Requirement 34.4)
# ===========================================================================

@pytest.mark.asyncio
async def test_default_recursion_preserved_when_scope_is_none():
    """With ``recursion_scope=None`` the recursable set is byte-for-byte the
    default: VALID / AUTH_REQUIRED, not file-like, not Catch_All_Response.

    **Validates: Requirements 34.4**
    """
    catch_all_size = 4242
    client = RecordingClient(status_code=404)
    fuzzer = EndpointFuzzer(client, _make_config(max_depth=1, recursion_scope=None))

    # Pretend catch-all was detected during phase 0 so a matching record is
    # suppressed by the default eligibility (19.4 / 34.4).
    fuzzer.catch_all_detected = True
    fuzzer.catch_all_signature = (200, catch_all_size)

    endpoints = [
        _ep("http://example.com/admin", 200, "admin", response_size=100),
        _ep("http://example.com/login", 401, "authentication", response_size=110),
        _ep("http://example.com/api", 200, "api_version", response_size=120),
        # File-like VALID endpoints are excluded from recursion.
        _ep("http://example.com/data.json", 200, "standard", response_size=130),
        _ep("http://example.com/page.html", 200, "standard", response_size=140),
        _ep("http://example.com/feed.xml", 200, "standard", response_size=150),
        # Non VALID/AUTH_REQUIRED statuses are excluded.
        _ep("http://example.com/redirect", 302, "standard", response_size=160),
        _ep("http://example.com/error", 500, "standard", response_size=170),
        _ep("http://example.com/missing", 404, "standard", response_size=180),
        # Matches the catch-all signature -> suppressed.
        _ep("http://example.com/wildcard", 200, "standard", response_size=catch_all_size),
    ]

    await fuzzer._recursive_fuzzing(endpoints, ["sub"])

    recursed = _recursed_base_urls(client, endpoints)

    # Independently compute the default eligibility predicate and assert the
    # recursed set is exactly equal to it (byte-for-byte preservation, 34.4).
    expected = {
        e.url
        for e in endpoints
        if e.status in (EndpointStatus.VALID, EndpointStatus.AUTH_REQUIRED)
        and not e.url.endswith((".html", ".json", ".xml"))
        and not fuzzer._is_catch_all(e)
    }

    assert recursed == expected
    assert recursed == {
        "http://example.com/admin",
        "http://example.com/login",
        "http://example.com/api",
    }


# ===========================================================================
# A supplied scope narrows the recursable set (Requirements 34.3, 34.5-34.7)
# ===========================================================================

@pytest.mark.asyncio
async def test_status_class_scope_narrows_recursable_set():
    """A status-class scope recurses only into matching-class endpoints, a strict
    subset of the default-eligible set.

    **Validates: Requirements 34.5**
    """
    client = RecordingClient(status_code=404)
    scope = RecursionScope(status_classes=frozenset({"2xx"}))
    fuzzer = EndpointFuzzer(client, _make_config(max_depth=1, recursion_scope=scope))

    endpoints = [
        _ep("http://example.com/admin", 200, "admin", response_size=100),
        _ep("http://example.com/login", 401, "authentication", response_size=110),
        _ep("http://example.com/api", 200, "api_version", response_size=120),
    ]

    await fuzzer._recursive_fuzzing(endpoints, ["sub"])

    recursed = _recursed_base_urls(client, endpoints)
    # 401 (4xx) is dropped; the 2xx endpoints remain. Subset of the default set.
    assert recursed == {"http://example.com/admin", "http://example.com/api"}


@pytest.mark.asyncio
async def test_endpoint_type_scope_narrows_recursable_set():
    """An endpoint-type scope recurses only into matching-type endpoints.

    **Validates: Requirements 34.5**
    """
    client = RecordingClient(status_code=404)
    scope = RecursionScope(endpoint_types=frozenset({"admin"}))
    fuzzer = EndpointFuzzer(client, _make_config(max_depth=1, recursion_scope=scope))

    endpoints = [
        _ep("http://example.com/admin", 200, "admin", response_size=100),
        _ep("http://example.com/login", 401, "authentication", response_size=110),
        _ep("http://example.com/api", 200, "api_version", response_size=120),
    ]

    await fuzzer._recursive_fuzzing(endpoints, ["sub"])

    recursed = _recursed_base_urls(client, endpoints)
    assert recursed == {"http://example.com/admin"}


@pytest.mark.asyncio
async def test_scope_still_honors_recursion_depth():
    """A supplied scope does not relax Recursion_Depth: with max_depth=2 the
    deepest requests are at depth 2 and depth 3 is never issued.

    **Validates: Requirements 34.5**
    """
    # Every response is 200/standard so each depth-N sub-path is itself scope-
    # admitted and would recurse forever if depth were not bounded.
    client = RecordingClient(status_code=200, content=b"{}")
    scope = RecursionScope(status_classes=frozenset({"2xx"}),
                           endpoint_types=frozenset({"standard"}))
    fuzzer = EndpointFuzzer(client, _make_config(max_depth=2, recursion_scope=scope))

    base = _ep("http://example.com/admin", 200, "standard", response_size=100)

    await fuzzer._recursive_fuzzing([base], ["sub"])

    request_urls = [url for _, url in client.calls]
    # Depth 1 and depth 2 sub-paths were issued...
    assert "http://example.com/admin/sub" in request_urls
    assert "http://example.com/admin/sub/sub" in request_urls
    # ...but recursion never descended to depth 3.
    assert not any(
        url.startswith("http://example.com/admin/sub/sub/sub")
        for url in request_urls
    )


@pytest.mark.asyncio
async def test_scope_counts_recursive_requests_toward_budget():
    """A supplied scope still counts recursive Discovery_Requests toward the
    Request_Budget and stops once the budget is reached.

    **Validates: Requirements 34.6**
    """
    max_requests = 4
    client = RecordingClient(status_code=404)
    scope = RecursionScope(endpoint_types=frozenset({"admin"}))
    fuzzer = EndpointFuzzer(
        client,
        _make_config(max_depth=2, max_requests=max_requests, recursion_scope=scope),
    )

    # Two scope-admitted base endpoints; a wordlist large enough to exceed the
    # budget on the first base alone.
    endpoints = [
        _ep("http://example.com/admin", 200, "admin", response_size=100),
        _ep("http://example.com/admin2", 200, "admin", response_size=110),
    ]
    words = [f"w{i}" for i in range(10)]

    await fuzzer._recursive_fuzzing(endpoints, words)

    # Never more than the budget of recursive Discovery_Requests were issued.
    assert client.call_count <= max_requests
    assert client.call_count == max_requests
    assert fuzzer.budget_reached is True


@pytest.mark.asyncio
async def test_scope_still_suppresses_catch_all():
    """A supplied scope still suppresses recursion into records matching the
    detected Catch_All_Response, even when the scope would otherwise admit them.

    **Validates: Requirements 34.7**
    """
    catch_all_size = 777
    client = RecordingClient(status_code=404)
    scope = RecursionScope(status_classes=frozenset({"2xx"}),
                           endpoint_types=frozenset({"standard"}))
    fuzzer = EndpointFuzzer(client, _make_config(max_depth=1, recursion_scope=scope))

    fuzzer.catch_all_detected = True
    fuzzer.catch_all_signature = (200, catch_all_size)

    real = _ep("http://example.com/real", 200, "standard", response_size=100)
    # Scope admits this (2xx + standard) but it matches the catch-all signature.
    wildcard = _ep("http://example.com/wildcard", 200, "standard",
                   response_size=catch_all_size)

    await fuzzer._recursive_fuzzing([real, wildcard], ["sub"])

    recursed = _recursed_base_urls(client, [real, wildcard])
    assert "http://example.com/real" in recursed
    assert "http://example.com/wildcard" not in recursed
