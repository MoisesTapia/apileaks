"""
Tests for GraphQL endpoint discovery and introspection (Requirement 27).

Two layers are covered:

1. Pure helpers in ``utils.graphql_probe`` (``is_graphql_response`` /
   ``introspection_enabled``) exercised against tiny fake response objects that
   expose only ``status_code`` and ``text`` -- matching the project's
   ``utils.http_client.Response`` surface (no ``.json()``).

2. ``EndpointFuzzer._probe_graphql`` / ``discover_endpoints`` behavior driven by
   a recording fake ``HTTPRequestEngine`` (the same fake-client pattern used by
   the existing fuzzer/orchestrator tests in ``test_fuzzing_orchestrator.py``),
   so every probe is deterministic and no real network call is made.

Requirement mapping:
- 27.1  opt-in default OFF                       -> TestGraphQLDefaultOff
- 27.2  common-path probing detects endpoint     -> TestGraphQLDiscovery
- 27.3  read-only introspection query issued      -> TestGraphQLSafeMode
- 27.4  GRAPHQL_INTROSPECTION_ENABLED finding     -> TestGraphQLDiscovery
- 27.5  Safe_Mode read-only (no state change)     -> TestGraphQLSafeMode
- 27.6  non-GraphQL target -> no finding, no err  -> TestGraphQLNonGraphQLTarget
"""

import asyncio
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

import pytest

from core.config import (
    FuzzingConfig,
    EndpointFuzzingConfig,
    ParameterFuzzingConfig,
    HeaderFuzzingConfig,
)
from modules.fuzzing.orchestrator import EndpointFuzzer
from utils.http_client import HTTPRequestEngine, Response
from utils.graphql_probe import (
    COMMON_GRAPHQL_PATHS,
    INTROSPECTION_QUERY,
    is_graphql_response,
    introspection_enabled,
)


# ---------------------------------------------------------------------------
# Tiny fake response object for the pure-helper tests. The real Response carries
# more fields, but the helpers only read ``status_code`` / ``text`` / ``content``.
# ---------------------------------------------------------------------------
@dataclass
class FakeResp:
    status_code: int = 200
    text: str = ""


# Canonical bodies reused across helper and fuzzer tests.
INTROSPECTION_ON_BODY = '{"data":{"__schema":{"queryType":{"name":"Query"}}}}'
GRAPHQL_ERRORS_BODY = '{"errors":[{"message":"introspection is disabled"}]}'
NON_GRAPHQL_HTML_BODY = "<html><body>Not Found</body></html>"


class TestGraphQLHelpers:
    """Pure detection predicates in utils.graphql_probe (Requirements 27.2/27.4)."""

    def test_is_graphql_response_detects_data_key(self):
        assert is_graphql_response(FakeResp(200, INTROSPECTION_ON_BODY)) is True

    def test_is_graphql_response_detects_errors_key(self):
        assert is_graphql_response(FakeResp(200, GRAPHQL_ERRORS_BODY)) is True

    def test_is_graphql_response_false_for_html(self):
        assert is_graphql_response(FakeResp(404, NON_GRAPHQL_HTML_BODY)) is False

    def test_is_graphql_response_false_for_empty_or_non_object(self):
        assert is_graphql_response(FakeResp(200, "")) is False
        assert is_graphql_response(FakeResp(200, "[1, 2, 3]")) is False

    def test_introspection_enabled_true_for_populated_schema(self):
        assert introspection_enabled(FakeResp(200, INTROSPECTION_ON_BODY)) is True

    def test_introspection_enabled_false_for_errors_response(self):
        # A GraphQL endpoint that rejects the probe is still GraphQL, but
        # introspection is not enabled (Requirement 27.4).
        assert introspection_enabled(FakeResp(200, GRAPHQL_ERRORS_BODY)) is False

    def test_introspection_enabled_false_for_non_200(self):
        assert introspection_enabled(FakeResp(400, INTROSPECTION_ON_BODY)) is False

    def test_introspection_enabled_false_for_empty_schema(self):
        assert introspection_enabled(FakeResp(200, '{"data":{"__schema":{}}}')) is False


# ---------------------------------------------------------------------------
# Recording fake HTTPRequestEngine. Mirrors the fake-client pattern in
# test_fuzzing_orchestrator.py: it records every request(...) call (method, url,
# and kwargs such as data=/headers=) so tests can assert exactly what was issued,
# and answers via a configurable responder so detection is deterministic.
# ---------------------------------------------------------------------------
class RecordingGraphQLClient:
    """Fake client recording every request and answering via a responder.

    ``responder`` maps ``(method, url) -> (status_code, body_text)``. Every call
    is captured in ``self.calls`` as a dict with method/url/data/headers so tests
    can verify the read-only introspection probe is the only GraphQL request
    issued (Safe_Mode, Requirement 27.5).
    """

    def __init__(self, responder: Callable[[str, str], Tuple[int, str]]):
        self.responder = responder
        self.calls: List[dict] = []

    @property
    def graphql_calls(self) -> List[dict]:
        """Recorded calls that carry a GraphQL introspection body."""
        return [c for c in self.calls if c.get("data") == INTROSPECTION_QUERY]

    async def request(self, method: str, url: str, **kwargs) -> Response:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "data": kwargs.get("data"),
                "headers": kwargs.get("headers"),
            }
        )
        await asyncio.sleep(0)
        status_code, body = self.responder(method, url)
        return Response(
            status_code=status_code,
            headers={"Content-Type": "application/json"},
            content=body.encode("utf-8"),
            text=body,
            url=url,
            elapsed=0.01,
            request_method=method,
        )


def _make_config(graphql: bool) -> FuzzingConfig:
    """Minimal fuzzing config with recursion off so probes are deterministic."""
    return FuzzingConfig(
        endpoints=EndpointFuzzingConfig(
            enabled=True,
            wordlist="unused.txt",
            methods=["GET"],
            follow_redirects=False,
            graphql=graphql,
        ),
        parameters=ParameterFuzzingConfig(enabled=False),
        headers=HeaderFuzzingConfig(enabled=False),
        recursive=False,
        max_depth=0,
        max_requests=None,
        concurrency=50,
    )


def _graphql_on_responder(method: str, url: str) -> Tuple[int, str]:
    """First common GraphQL path answers with introspection enabled; else 404."""
    first_path = COMMON_GRAPHQL_PATHS[0].lstrip("/")
    if method == "POST" and url.endswith(first_path):
        return (200, INTROSPECTION_ON_BODY)
    return (404, NON_GRAPHQL_HTML_BODY)


def _graphql_introspection_off_responder(method: str, url: str) -> Tuple[int, str]:
    """First GraphQL path is detected but rejects introspection (errors body)."""
    first_path = COMMON_GRAPHQL_PATHS[0].lstrip("/")
    if method == "POST" and url.endswith(first_path):
        return (200, GRAPHQL_ERRORS_BODY)
    return (404, NON_GRAPHQL_HTML_BODY)


def _non_graphql_responder(method: str, url: str) -> Tuple[int, str]:
    """Every path returns a non-GraphQL 404 HTML response."""
    return (404, NON_GRAPHQL_HTML_BODY)


class TestGraphQLDefaultOff:
    """Requirement 27.1: GraphQL probing is opt-in and OFF by default."""

    def test_config_default_is_off(self):
        assert EndpointFuzzingConfig().graphql is False

    @pytest.mark.asyncio
    async def test_no_introspection_probe_when_disabled(self, tmp_path):
        """With graphql=False, discovery issues no introspection probe and
        records no GraphQL finding."""
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("admin\napi\n")

        client = RecordingGraphQLClient(_graphql_on_responder)
        fuzzer = EndpointFuzzer(client, _make_config(graphql=False))

        await fuzzer.discover_endpoints("http://example.com", str(wordlist))

        # No read-only introspection body was ever sent (no _probe_graphql run).
        assert client.graphql_calls == []
        # No GraphQL finding recorded.
        assert fuzzer.graphql_introspection_endpoint is None


class TestGraphQLDiscovery:
    """Requirements 27.2/27.4: detection + GRAPHQL_INTROSPECTION_ENABLED finding."""

    @pytest.mark.asyncio
    async def test_detects_endpoint_and_records_introspection_finding(self):
        client = RecordingGraphQLClient(_graphql_on_responder)
        fuzzer = EndpointFuzzer(client, _make_config(graphql=True))

        await fuzzer._probe_graphql("http://example.com/")

        expected = "http://example.com/" + COMMON_GRAPHQL_PATHS[0].lstrip("/")
        # 27.2: the common-path probe detected the GraphQL endpoint, and
        # 27.4: introspection-enabled -> the endpoint URL is recorded.
        assert fuzzer.graphql_introspection_endpoint == expected

    @pytest.mark.asyncio
    async def test_discover_endpoints_sets_finding_when_enabled(self, tmp_path):
        """End-to-end through discover_endpoints with graphql=True."""
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("admin\n")

        client = RecordingGraphQLClient(_graphql_on_responder)
        fuzzer = EndpointFuzzer(client, _make_config(graphql=True))

        await fuzzer.discover_endpoints("http://example.com", str(wordlist))

        expected = "http://example.com/" + COMMON_GRAPHQL_PATHS[0].lstrip("/")
        assert fuzzer.graphql_introspection_endpoint == expected

    @pytest.mark.asyncio
    async def test_endpoint_detected_but_introspection_disabled_records_no_finding(self):
        """A GraphQL endpoint with introspection turned off is detected but
        leaves graphql_introspection_endpoint None (Requirement 27.4)."""
        client = RecordingGraphQLClient(_graphql_introspection_off_responder)
        fuzzer = EndpointFuzzer(client, _make_config(graphql=True))

        await fuzzer._probe_graphql("http://example.com/")

        assert fuzzer.graphql_introspection_endpoint is None
        # Probing stopped at the first detected GraphQL endpoint rather than
        # continuing through every remaining path.
        assert len(client.graphql_calls) == 1


class TestGraphQLSafeMode:
    """Requirements 27.3/27.5: the only GraphQL request issued is the read-only
    introspection query -- no mutation / state-changing operation is sent."""

    @pytest.mark.asyncio
    async def test_only_read_only_introspection_query_is_issued(self):
        client = RecordingGraphQLClient(_graphql_on_responder)
        fuzzer = EndpointFuzzer(client, _make_config(graphql=True))

        await fuzzer._probe_graphql("http://example.com/")

        graphql_calls = client.graphql_calls
        assert graphql_calls, "expected at least one introspection probe"
        for call in graphql_calls:
            # 27.3/27.5: the probe body is exactly the read-only introspection
            # document and is sent as a raw data= body with a JSON content type.
            assert call["data"] == INTROSPECTION_QUERY
            assert "__schema" in call["data"]
            # No mutation / state-changing GraphQL operation is sent.
            assert "mutation" not in call["data"].lower()
            assert (call["headers"] or {}).get("Content-Type") == "application/json"

        # The probe never used a state-changing HTTP verb beyond the read-only
        # introspection POST: no PUT/PATCH/DELETE requests were issued at all.
        assert all(c["method"] not in ("PUT", "PATCH", "DELETE") for c in client.calls)


class TestGraphQLNonGraphQLTarget:
    """Requirement 27.6: a non-GraphQL target produces no finding and no error."""

    @pytest.mark.asyncio
    async def test_no_finding_and_no_error_for_non_graphql_target(self):
        client = RecordingGraphQLClient(_non_graphql_responder)
        fuzzer = EndpointFuzzer(client, _make_config(graphql=True))

        # Completes without raising.
        await fuzzer._probe_graphql("http://example.com/")

        assert fuzzer.graphql_introspection_endpoint is None
        # Every common path was probed (none matched), and all stayed read-only.
        assert len(client.graphql_calls) == len(COMMON_GRAPHQL_PATHS)

    @pytest.mark.asyncio
    async def test_probe_failures_are_tolerated(self):
        """A probe that raises is tolerated; discovery continues without error
        and records no finding (Requirement 27.6)."""

        class FailingClient:
            def __init__(self):
                self.calls = 0

            async def request(self, method, url, **kwargs):
                self.calls += 1
                await asyncio.sleep(0)
                raise ConnectionError("probe failed")

        client = FailingClient()
        fuzzer = EndpointFuzzer(client, _make_config(graphql=True))

        await fuzzer._probe_graphql("http://example.com/")

        assert fuzzer.graphql_introspection_endpoint is None
        # All paths were attempted despite each raising.
        assert client.calls == len(COMMON_GRAPHQL_PATHS)
