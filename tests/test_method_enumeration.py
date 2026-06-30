"""
Unit tests for HTTP Method Enumeration on discovered endpoints.

**Feature: owasp-complete-purple-teaming-cicd, Task 30.3**

These tests cover Requirement 26 (HTTP Method Enumeration for Discovered
Endpoints) end-to-end across the config default, the `Allow`-header parser, the
OPTIONS dispatch path, 405-as-valid recording, and the budget/concurrency
composition:

- 26.1: Method_Enumeration is opt-in and disabled by default (config default,
  CLI flag threading, and "no OPTIONS issued when disabled" behavior).
- 26.2 / 26.4: when enabled, a discovered endpoint triggers exactly one OPTIONS
  Discovery_Request whose `Allow` header is parsed into
  `endpoint.allowed_methods`.
- 26.3: a 405 response is kept and recorded as a valid Discovery_Result (tagged
  `method_not_allowed`) rather than discarded like a 404.
- 26.5: each OPTIONS Discovery_Request counts toward the Request_Budget and
  flows through the same `_semaphore` + `http_client.request` path, so it stays
  within the Concurrency_Limit.
- 26.6: an absent or empty `Allow` header records an empty method set and
  discovery continues.

No real HTTP requests are made: discovery drives an in-memory fake
HTTPRequestEngine that records every request and answers OPTIONS with a
configurable `Allow` header, matching the existing fake-client conventions used
by the budget/concurrency/catch-all tests in this suite.
"""

import asyncio
import os
import tempfile
from unittest.mock import patch
from urllib.parse import urlparse

import pytest
from click.testing import CliRunner

import apileaks
from apileaks import cli
from modules.fuzzing.orchestrator import (
    EndpointFuzzer,
    Endpoint,
    EndpointStatus,
    parse_allow_header,
)
from core.config import (
    FuzzingConfig,
    EndpointFuzzingConfig,
    ParameterFuzzingConfig,
    HeaderFuzzingConfig,
)
from utils.http_client import Response


BASE_URL = "http://example.com"

# Catch-all detection probes target uuid4().hex-based paths (33 chars); genuine
# wordlist segments below are short, so a length threshold distinguishes a
# catch-all probe path from a real candidate path.
_PROBE_SEGMENT_MIN_LEN = 20


class MethodEnumFakeClient:
    """
    In-memory fake HTTPRequestEngine for Method_Enumeration tests.

    Records every (method, url) call and tracks live/peak in-flight concurrency.
    OPTIONS requests are answered with a configurable ``Allow`` header
    (``allow_header``; ``None`` means the header is absent). Non-OPTIONS requests
    are answered with ``status_code`` (default 200), except long uuid-like
    catch-all probe paths, which always answer 404 so Catch_All_Response
    detection stays off.
    """

    def __init__(self, status_code: int = 200, allow_header=None):
        self.status_code = status_code
        self.allow_header = allow_header
        self.calls = []          # list of (method, url) in call order
        self.in_flight = 0
        self.peak_in_flight = 0

    @property
    def call_count(self) -> int:
        return len(self.calls)

    @property
    def options_calls(self):
        return [(m, u) for (m, u) in self.calls if m == "OPTIONS"]

    async def request(self, method: str, url: str, **kwargs) -> Response:
        self.in_flight += 1
        self.peak_in_flight = max(self.peak_in_flight, self.in_flight)
        self.calls.append((method, url))
        try:
            await asyncio.sleep(0)  # yield so concurrent requests overlap

            if method == "OPTIONS":
                headers = {"Content-Type": "application/json"}
                if self.allow_header is not None:
                    headers["Allow"] = self.allow_header
                return Response(
                    status_code=204,
                    headers=headers,
                    content=b"",
                    text="",
                    url=url,
                    elapsed=0.01,
                    request_method=method,
                )

            path = urlparse(url).path
            segments = [s for s in path.split("/") if s]
            last_segment = segments[-1] if segments else ""
            status_code = (
                404 if len(last_segment) >= _PROBE_SEGMENT_MIN_LEN else self.status_code
            )
            return Response(
                status_code=status_code,
                headers={"Content-Type": "application/json"},
                content=b'{"ok": true}',
                text='{"ok": true}',
                url=url,
                elapsed=0.01,
                request_method=method,
            )
        finally:
            self.in_flight -= 1


def _make_config(
    enumerate_methods=False,
    max_requests=None,
    concurrency=50,
    methods=None,
) -> FuzzingConfig:
    return FuzzingConfig(
        endpoints=EndpointFuzzingConfig(
            enabled=True,
            wordlist="unused.txt",
            methods=methods or ["GET"],
            follow_redirects=False,
            enumerate_methods=enumerate_methods,
        ),
        parameters=ParameterFuzzingConfig(enabled=False),
        headers=HeaderFuzzingConfig(enabled=False),
        recursive=False,
        max_depth=0,
        max_requests=max_requests,
        concurrency=concurrency,
    )


def _write_wordlist(words):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    f.write("\n".join(words) + "\n")
    f.close()
    return f.name


async def _run_discovery(fake_client, config, words):
    fuzzer = EndpointFuzzer(fake_client, config)
    wordlist_path = _write_wordlist(words)
    try:
        discovered = await fuzzer.discover_endpoints(BASE_URL, wordlist_path)
    finally:
        os.unlink(wordlist_path)
    return fuzzer, discovered


# ---------------------------------------------------------------------------
# 26.1 -- opt-in, disabled by default
# ---------------------------------------------------------------------------

class TestMethodEnumerationOptIn:
    """Method_Enumeration is opt-in and off by default (Requirement 26.1)."""

    def test_config_default_is_disabled(self):
        """`EndpointFuzzingConfig.enumerate_methods` defaults to False.

        **Validates: Requirements 26.1**
        """
        assert EndpointFuzzingConfig().enumerate_methods is False

    @pytest.mark.asyncio
    async def test_no_options_request_issued_when_disabled(self):
        """With enumeration off, discovery issues no OPTIONS Discovery_Request.

        **Validates: Requirements 26.1**
        """
        fake_client = MethodEnumFakeClient(status_code=200, allow_header="GET, POST")
        config = _make_config(enumerate_methods=False)

        fuzzer, discovered = await _run_discovery(
            fake_client, config, ["admin", "api"]
        )

        # Endpoints were discovered, but no OPTIONS request was ever sent...
        assert len(discovered) == 2
        assert fake_client.options_calls == []
        # ...and no methods were enumerated onto any Discovery_Result.
        assert all(e.allowed_methods == [] for e in discovered)


class TestEnumerateMethodsCliFlag:
    """The `--enumerate-methods` flag threads the opt-in toggle (Req 26.1)."""

    class _ShortCircuit(Exception):
        """Sentinel raised to stop the command after config_dict is captured."""

    def _invoke_dir_capturing_config(self, args):
        captured = {}

        def _capture(self, config_dict):
            captured["config_dict"] = config_dict
            raise TestEnumerateMethodsCliFlag._ShortCircuit()

        runner = CliRunner()
        with patch.object(
            apileaks.ConfigurationManager, "load_config_from_dict", _capture
        ):
            runner.invoke(
                cli,
                ["--no-banner", "dir", "--target", "https://api.example.com", *args],
            )
        return captured.get("config_dict")

    def test_flag_absent_threads_disabled(self):
        """Without the flag, `enumerate_methods` is threaded as False.

        **Validates: Requirements 26.1**
        """
        config_dict = self._invoke_dir_capturing_config([])
        assert config_dict is not None
        assert config_dict["fuzzing"]["endpoints"]["enumerate_methods"] is False

    def test_flag_present_threads_enabled(self):
        """`--enumerate-methods` threads `enumerate_methods` as True.

        **Validates: Requirements 26.1**
        """
        config_dict = self._invoke_dir_capturing_config(["--enumerate-methods"])
        assert config_dict is not None
        assert config_dict["fuzzing"]["endpoints"]["enumerate_methods"] is True


# ---------------------------------------------------------------------------
# 26.2 / 26.4 / 26.6 -- Allow header parsing
# ---------------------------------------------------------------------------

class TestParseAllowHeader:
    """`parse_allow_header` normalizes an `Allow` header (Req 26.2/26.4/26.6)."""

    def test_parses_comma_separated_methods(self):
        """Comma-separated methods are upper-cased and trimmed.

        **Validates: Requirements 26.2, 26.4**
        """
        assert parse_allow_header("GET, POST, options") == ["GET", "POST", "OPTIONS"]

    def test_deduplicates_preserving_first_seen_order(self):
        """Duplicate tokens are dropped, first-seen order preserved.

        **Validates: Requirements 26.2, 26.4**
        """
        assert parse_allow_header("GET, get, POST, GET") == ["GET", "POST"]

    @pytest.mark.parametrize("value", [None, "", "   ", ",", " , , "])
    def test_absent_or_empty_yields_empty_list(self, value):
        """Absent/empty/blank-only `Allow` values map to an empty set.

        **Validates: Requirements 26.6**
        """
        assert parse_allow_header(value) == []


class TestMethodEnumerationRecording:
    """OPTIONS Allow header is recorded on the Discovery_Result (26.2/26.4)."""

    @pytest.mark.asyncio
    async def test_enabled_issues_options_and_records_methods(self):
        """Each discovered endpoint gets one OPTIONS call and parsed methods.

        **Validates: Requirements 26.2, 26.4**
        """
        fake_client = MethodEnumFakeClient(
            status_code=200, allow_header="GET, POST, OPTIONS"
        )
        config = _make_config(enumerate_methods=True)

        fuzzer, discovered = await _run_discovery(
            fake_client, config, ["admin", "api"]
        )

        assert len(discovered) == 2
        # Exactly one OPTIONS request per discovered endpoint (26.2).
        assert len(fake_client.options_calls) == 2
        options_urls = sorted(u for _, u in fake_client.options_calls)
        assert options_urls == [
            "http://example.com/admin",
            "http://example.com/api",
        ]
        # The parsed Allow methods are recorded on each Discovery_Result (26.4).
        for endpoint in discovered:
            assert endpoint.allowed_methods == ["GET", "POST", "OPTIONS"]

    @pytest.mark.asyncio
    async def test_options_targets_the_discovered_endpoint_url(self):
        """The OPTIONS request is issued to the discovered endpoint's URL.

        **Validates: Requirements 26.2**
        """
        fake_client = MethodEnumFakeClient(status_code=200, allow_header="GET")
        fuzzer = EndpointFuzzer(fake_client, _make_config(enumerate_methods=True))

        endpoint = Endpoint(
            url="http://example.com/users",
            method="GET",
            status_code=200,
            response_size=10,
            response_time=0.01,
        )
        await fuzzer._enumerate_methods(endpoint)

        assert fake_client.options_calls == [("OPTIONS", "http://example.com/users")]
        assert endpoint.allowed_methods == ["GET"]

    @pytest.mark.asyncio
    async def test_absent_allow_header_records_empty_set_and_continues(self):
        """No `Allow` header -> empty method set, discovery still returns results.

        **Validates: Requirements 26.6**
        """
        fake_client = MethodEnumFakeClient(status_code=200, allow_header=None)
        config = _make_config(enumerate_methods=True)

        fuzzer, discovered = await _run_discovery(fake_client, config, ["admin"])

        # OPTIONS was issued, but with no Allow header the set is empty (26.6)...
        assert len(fake_client.options_calls) == 1
        assert len(discovered) == 1
        assert discovered[0].allowed_methods == []
        # ...and the endpoint is still a valid recorded Discovery_Result.
        assert discovered[0].status == EndpointStatus.VALID

    @pytest.mark.asyncio
    async def test_empty_allow_header_records_empty_set(self):
        """An empty `Allow` header value records an empty method set.

        **Validates: Requirements 26.6**
        """
        fake_client = MethodEnumFakeClient(status_code=200, allow_header="")
        fuzzer = EndpointFuzzer(fake_client, _make_config(enumerate_methods=True))

        endpoint = Endpoint(
            url="http://example.com/x",
            method="GET",
            status_code=200,
            response_size=10,
            response_time=0.01,
        )
        await fuzzer._enumerate_methods(endpoint)

        assert endpoint.allowed_methods == []

    @pytest.mark.asyncio
    async def test_enumeration_failure_records_empty_set_and_continues(self):
        """An OPTIONS request error records an empty set without raising (26.6).

        **Validates: Requirements 26.6**
        """

        class FailingClient:
            async def request(self, method, url, **kwargs):
                raise ConnectionError("OPTIONS failed")

        fuzzer = EndpointFuzzer(FailingClient(), _make_config(enumerate_methods=True))
        endpoint = Endpoint(
            url="http://example.com/x",
            method="GET",
            status_code=200,
            response_size=10,
            response_time=0.01,
        )

        # Should not raise; records an empty method set so discovery continues.
        await fuzzer._enumerate_methods(endpoint)
        assert endpoint.allowed_methods == []


# ---------------------------------------------------------------------------
# 26.3 -- 405 recorded as a valid Discovery_Result
# ---------------------------------------------------------------------------

class TestMethodNotAllowedRecording:
    """A 405 path is kept as a valid Discovery_Result (Requirement 26.3)."""

    @pytest.mark.asyncio
    async def test_405_is_recorded_and_classified(self):
        """A 405 response is returned (not discarded) and tagged accordingly.

        **Validates: Requirements 26.3**
        """
        fake_client = MethodEnumFakeClient(status_code=405)
        fuzzer = EndpointFuzzer(fake_client, _make_config(enumerate_methods=False))

        endpoint = await fuzzer._test_endpoint(
            "GET", "http://example.com/admin", "admin", 0
        )

        assert endpoint is not None  # not discarded like a 404
        assert endpoint.status_code == 405
        assert endpoint.endpoint_type == "method_not_allowed"
        # Recorded as a Discovery_Result in the fuzzer's discovered set.
        assert "http://example.com/admin" in fuzzer.discovered_endpoints

    @pytest.mark.asyncio
    async def test_404_is_discarded_unlike_405(self):
        """A 404 stays discarded, confirming the 405 exception is deliberate.

        **Validates: Requirements 26.3**
        """
        fake_client = MethodEnumFakeClient(status_code=404)
        fuzzer = EndpointFuzzer(fake_client, _make_config(enumerate_methods=False))

        endpoint = await fuzzer._test_endpoint(
            "GET", "http://example.com/missing", "missing", 0
        )

        assert endpoint is None
        assert "http://example.com/missing" not in fuzzer.discovered_endpoints

    @pytest.mark.asyncio
    async def test_405_endpoint_in_full_discovery_results(self):
        """A 405-answering target yields the path in the discovered set (26.3).

        **Validates: Requirements 26.3**
        """
        fake_client = MethodEnumFakeClient(status_code=405)
        fuzzer, discovered = await _run_discovery(
            fake_client, _make_config(enumerate_methods=False), ["admin"]
        )

        assert len(discovered) == 1
        assert discovered[0].status_code == 405
        assert discovered[0].endpoint_type == "method_not_allowed"


# ---------------------------------------------------------------------------
# 26.5 -- OPTIONS counts toward Request_Budget and Concurrency_Limit
# ---------------------------------------------------------------------------

class TestMethodEnumerationBudgetAndConcurrency:
    """OPTIONS requests respect Request_Budget / Concurrency_Limit (Req 26.5)."""

    @pytest.mark.asyncio
    async def test_options_counts_toward_request_budget(self):
        """A single OPTIONS request advances `requests_issued` by exactly one.

        **Validates: Requirements 26.5**
        """
        fake_client = MethodEnumFakeClient(allow_header="GET")
        fuzzer = EndpointFuzzer(
            fake_client, _make_config(enumerate_methods=True, max_requests=10)
        )
        endpoint = Endpoint(
            url="http://example.com/x",
            method="GET",
            status_code=200,
            response_size=10,
            response_time=0.01,
        )

        before = fuzzer.requests_issued
        await fuzzer._enumerate_methods(endpoint)

        assert fuzzer.requests_issued == before + 1
        assert len(fake_client.options_calls) == 1

    @pytest.mark.asyncio
    async def test_options_sets_budget_reached_at_limit(self):
        """The OPTIONS request that hits the budget marks budget_reached.

        **Validates: Requirements 26.5**
        """
        fake_client = MethodEnumFakeClient(allow_header="GET")
        fuzzer = EndpointFuzzer(
            fake_client, _make_config(enumerate_methods=True, max_requests=1)
        )
        endpoint = Endpoint(
            url="http://example.com/x",
            method="GET",
            status_code=200,
            response_size=10,
            response_time=0.01,
        )

        await fuzzer._enumerate_methods(endpoint)

        assert fuzzer.requests_issued == 1
        assert fuzzer.budget_reached is True

    @pytest.mark.asyncio
    async def test_options_counts_toward_budget_in_full_discovery(self):
        """OPTIONS Discovery_Requests are included in the run's request count.

        With enumeration on, an unbounded run issues the catch-all probes, one
        GET per discovered endpoint, and one OPTIONS per discovered endpoint;
        every one of those flows through the rate-limited client.

        **Validates: Requirements 26.5**
        """
        words = ["admin", "api", "login"]
        fake_client = MethodEnumFakeClient(status_code=200, allow_header="GET, POST")
        fuzzer, discovered = await _run_discovery(
            fake_client, _make_config(enumerate_methods=True), words
        )

        # One OPTIONS request per discovered endpoint flowed through the client.
        assert len(discovered) == len(words)
        assert len(fake_client.options_calls) == len(words)

        # Total client calls = catch-all probes + one GET + one OPTIONS per word.
        expected = EndpointFuzzer.CATCH_ALL_PROBES + 2 * len(words)
        assert fake_client.call_count == expected

    @pytest.mark.asyncio
    async def test_options_requests_stay_within_concurrency_limit(self):
        """In-flight requests (GET + OPTIONS) never exceed the Concurrency_Limit.

        **Validates: Requirements 26.5**
        """
        concurrency = 2
        words = [f"path{i}" for i in range(8)]
        fake_client = MethodEnumFakeClient(status_code=200, allow_header="GET")
        fuzzer, discovered = await _run_discovery(
            fake_client,
            _make_config(enumerate_methods=True, concurrency=concurrency),
            words,
        )

        # Enumeration happened (so OPTIONS shared the semaphore with GETs)...
        assert len(fake_client.options_calls) == len(words)
        # ...and the peak in-flight count never exceeded the Concurrency_Limit.
        assert fake_client.peak_in_flight <= concurrency
        assert fuzzer.concurrency == concurrency
