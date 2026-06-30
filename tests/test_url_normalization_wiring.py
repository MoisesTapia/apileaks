"""
Unit tests for URL_Normalization wiring in EndpointFuzzer (Requirement 38).

Covers:
- The canonical form produced by ``normalize_url`` for trailing-slash,
  percent-encoding case, default-port removal, and dot-segment resolution
  (Requirement 38.2).
- That two candidates equal after normalization collapse to a single
  ``tested_urls`` entry and a single Discovery_Request in ``_fuzz_wordlist``
  (Requirement 38.1, 38.3).
- That ``_test_endpoint`` stores the canonical URL (Requirement 38.2).
- That a redirect to an equivalent (post-normalization) URL is not re-tested
  in ``_handle_redirect`` (Requirement 38.3).

These exercise the existing _fuzz_wordlist / _test_endpoint / _handle_redirect
flow with a deterministic in-memory fake HTTPRequestEngine (no network),
following the conventions in test_fuzzing_orchestrator.py.
"""

import asyncio

import pytest

from modules.fuzzing.orchestrator import EndpointFuzzer, Endpoint, EndpointStatus
from core.config import (
    FuzzingConfig,
    EndpointFuzzingConfig,
    ParameterFuzzingConfig,
    HeaderFuzzingConfig,
)
from utils.http_client import HTTPRequestEngine, Response
from utils.url_normalize import normalize_url


class RecordingFakeClient:
    """Deterministic fake HTTPRequestEngine that records every request.

    Every ``request(...)`` call is appended to ``calls`` as a ``(method, url)``
    tuple so tests can assert exactly which URLs were (and were not) requested.
    """

    def __init__(self, status_code: int = 200, headers=None):
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "application/json"}
        self.calls = []

    @property
    def call_count(self) -> int:
        return len(self.calls)

    async def request(self, method: str, url: str, **kwargs) -> Response:
        self.calls.append((method, url))
        await asyncio.sleep(0)
        return Response(
            status_code=self.status_code,
            headers=dict(self.headers),
            content=b'{"ok": true}',
            text='{"ok": true}',
            url=url,
            elapsed=0.01,
            request_method=method,
        )


def _make_config(methods=None, follow_redirects=False):
    """Build a minimal FuzzingConfig with discovery enabled and no budget."""
    return FuzzingConfig(
        endpoints=EndpointFuzzingConfig(
            enabled=True,
            wordlist="unused.txt",
            methods=methods or ["GET"],
            follow_redirects=follow_redirects,
        ),
        parameters=ParameterFuzzingConfig(enabled=False),
        headers=HeaderFuzzingConfig(enabled=False),
        recursive=False,
        max_depth=0,
        max_requests=None,
        concurrency=50,
    )


class TestNormalizeUrlCanonicalForm:
    """The canonical form produced by normalize_url (Requirement 38.2)."""

    def test_trailing_slash_stripped_from_non_root_path(self):
        # A single trailing slash on a non-root path is removed...
        assert normalize_url("http://example.com/users/") == "http://example.com/users"
        # ...but the root path is preserved.
        assert normalize_url("http://example.com/") == "http://example.com/"

    def test_percent_encoding_hex_case_upper_cased(self):
        assert (
            normalize_url("http://example.com/a%2fb%2Fc")
            == "http://example.com/a%2Fb%2Fc"
        )

    def test_default_port_removed_for_scheme(self):
        assert normalize_url("http://example.com:80/users") == "http://example.com/users"
        assert (
            normalize_url("https://example.com:443/users")
            == "https://example.com/users"
        )
        # A non-default port is preserved.
        assert (
            normalize_url("http://example.com:8080/users")
            == "http://example.com:8080/users"
        )

    def test_dot_segments_resolved(self):
        assert normalize_url("http://example.com/a/./b/../c") == "http://example.com/a/c"

    def test_combined_canonicalization(self):
        # Default port + dot-segments + trailing slash + percent-case together.
        assert (
            normalize_url("http://example.com:80/a/./b/../c%2fd/")
            == "http://example.com/a/c%2Fd"
        )


class TestFuzzWordlistDeduplication:
    """Candidates equal after normalization collapse to one entry (38.1, 38.3)."""

    @pytest.mark.asyncio
    async def test_equivalent_candidates_collapse_to_single_request(self):
        # "users" and "users/" normalize to the same canonical URL, so only a
        # single tested_urls entry and a single Discovery_Request result.
        fake_client = RecordingFakeClient(status_code=200)
        fuzzer = EndpointFuzzer(fake_client, _make_config(methods=["GET"]))

        await fuzzer._fuzz_wordlist("http://example.com/", ["users", "users/"], depth=0)

        assert fake_client.call_count == 1
        assert fuzzer.tested_urls == {"http://example.com/users"}

    @pytest.mark.asyncio
    async def test_percent_encoding_case_variants_collapse(self):
        # Two candidates differing only in percent-encoding hex case are
        # equivalent after normalization -> one request, one entry.
        fake_client = RecordingFakeClient(status_code=200)
        fuzzer = EndpointFuzzer(fake_client, _make_config(methods=["GET"]))

        await fuzzer._fuzz_wordlist("http://example.com/", ["a%2fb", "a%2Fb"], depth=0)

        assert fake_client.call_count == 1
        assert fuzzer.tested_urls == {"http://example.com/a%2Fb"}

    @pytest.mark.asyncio
    async def test_distinct_candidates_each_issue_one_request(self):
        # Genuinely distinct candidates are NOT collapsed.
        fake_client = RecordingFakeClient(status_code=200)
        fuzzer = EndpointFuzzer(fake_client, _make_config(methods=["GET"]))

        await fuzzer._fuzz_wordlist("http://example.com/", ["users", "admin"], depth=0)

        assert fake_client.call_count == 2
        assert fuzzer.tested_urls == {
            "http://example.com/users",
            "http://example.com/admin",
        }


class TestTestEndpointStoresCanonicalUrl:
    """_test_endpoint stores the canonical URL (Requirement 38.2)."""

    @pytest.mark.asyncio
    async def test_stored_endpoint_url_is_canonical(self):
        fake_client = RecordingFakeClient(status_code=200)
        fuzzer = EndpointFuzzer(fake_client, _make_config(methods=["GET"]))

        # Pass a non-canonical URL (default port + trailing slash) to storage.
        endpoint = await fuzzer._test_endpoint(
            "GET", "http://example.com:80/users/", "users", 0
        )

        assert endpoint is not None
        assert endpoint.status == EndpointStatus.VALID
        assert endpoint.url == "http://example.com/users"
        assert "http://example.com/users" in fuzzer.discovered_endpoints


class TestHandleRedirectDeduplication:
    """A redirect to an equivalent URL is not re-tested (Requirement 38.3)."""

    @pytest.mark.asyncio
    async def test_redirect_to_already_tested_equivalent_not_retested(self):
        fake_client = RecordingFakeClient(status_code=200)
        fuzzer = EndpointFuzzer(fake_client, _make_config(follow_redirects=True))

        # The canonical form of the redirect target has already been tested.
        fuzzer.tested_urls.add("http://example.com/login")

        endpoint = Endpoint(
            url="http://example.com/admin",
            method="GET",
            status_code=302,
            response_size=0,
            response_time=0.01,
        )
        # Location is equivalent to an already-tested URL after normalization
        # (trailing slash + default port both collapse to /login).
        redirect_response = Response(
            status_code=302,
            headers={"Location": "http://example.com:80/login/"},
            content=b"",
            text="",
            url="http://example.com/admin",
            elapsed=0.01,
            request_method="GET",
        )

        await fuzzer._handle_redirect(endpoint, redirect_response)

        # The redirect location is recorded, but no new Discovery_Request is made.
        assert endpoint.redirect_location == "http://example.com:80/login/"
        assert fake_client.call_count == 0

    @pytest.mark.asyncio
    async def test_redirect_to_new_equivalent_tested_once(self):
        fake_client = RecordingFakeClient(status_code=200)
        fuzzer = EndpointFuzzer(fake_client, _make_config(follow_redirects=True))

        endpoint = Endpoint(
            url="http://example.com/admin",
            method="GET",
            status_code=302,
            response_size=0,
            response_time=0.01,
        )
        redirect_response = Response(
            status_code=302,
            headers={"Location": "http://example.com/login/"},
            content=b"",
            text="",
            url="http://example.com/admin",
            elapsed=0.01,
            request_method="GET",
        )

        # First redirect: the equivalent target is not yet tested -> one request,
        # and its canonical form is recorded in tested_urls.
        await fuzzer._handle_redirect(endpoint, redirect_response)

        assert fake_client.call_count == 1
        assert "http://example.com/login" in fuzzer.tested_urls

        # A second endpoint redirects to an equivalent target (no trailing
        # slash); it must NOT be re-tested (Requirement 38.3).
        endpoint2 = Endpoint(
            url="http://example.com/dashboard",
            method="GET",
            status_code=302,
            response_size=0,
            response_time=0.01,
        )
        redirect_response2 = Response(
            status_code=302,
            headers={"Location": "http://example.com/login"},
            content=b"",
            text="",
            url="http://example.com/dashboard",
            elapsed=0.01,
            request_method="GET",
        )

        await fuzzer._handle_redirect(endpoint2, redirect_response2)

        # Still only the single request from the first redirect.
        assert fake_client.call_count == 1
