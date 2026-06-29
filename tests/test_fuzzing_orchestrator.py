"""
Tests for Fuzzing Orchestrator and Endpoint Discovery
"""

import pytest
import asyncio
import tempfile
import os
from unittest.mock import Mock, AsyncMock, patch
from pathlib import Path

from modules.fuzzing.orchestrator import (
    FuzzingOrchestrator, EndpointFuzzer, Endpoint, EndpointStatus, FuzzingStats
)
from core.config import FuzzingConfig, EndpointFuzzingConfig, ParameterFuzzingConfig, HeaderFuzzingConfig
from utils.http_client import HTTPRequestEngine, Response


class TestEndpointFuzzer:
    """Test endpoint fuzzer functionality"""
    
    @pytest.fixture
    def mock_http_client(self):
        """Create mock HTTP client"""
        client = Mock(spec=HTTPRequestEngine)
        client.request = AsyncMock()
        return client
    
    @pytest.fixture
    def fuzzing_config(self):
        """Create fuzzing configuration"""
        return FuzzingConfig(
            endpoints=EndpointFuzzingConfig(
                enabled=True,
                wordlist="test_wordlist.txt",
                methods=["GET", "POST"],
                follow_redirects=True
            ),
            parameters=ParameterFuzzingConfig(enabled=False),
            headers=HeaderFuzzingConfig(enabled=False),
            recursive=True,
            max_depth=2
        )
    
    @pytest.fixture
    def endpoint_fuzzer(self, mock_http_client, fuzzing_config):
        """Create endpoint fuzzer"""
        return EndpointFuzzer(mock_http_client, fuzzing_config)
    
    @pytest.fixture
    def temp_wordlist(self):
        """Create temporary wordlist file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("admin\napi\ntest\nlogin\n")
            temp_path = f.name
        
        yield temp_path
        
        # Cleanup
        os.unlink(temp_path)
    
    @pytest.mark.asyncio
    async def test_load_wordlist(self, endpoint_fuzzer, temp_wordlist):
        """Test wordlist loading"""
        wordlist = await endpoint_fuzzer._load_wordlist(temp_wordlist)
        
        assert len(wordlist) == 4
        assert "admin" in wordlist
        assert "api" in wordlist
        assert "test" in wordlist
        assert "login" in wordlist
    
    @pytest.mark.asyncio
    async def test_load_wordlist_with_comments(self, endpoint_fuzzer):
        """Test wordlist loading with comments and empty lines"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("# This is a comment\nadmin\n\n# Another comment\napi\n\ntest\n")
            temp_path = f.name
        
        try:
            wordlist = await endpoint_fuzzer._load_wordlist(temp_path)
            
            assert len(wordlist) == 3
            assert "admin" in wordlist
            assert "api" in wordlist
            assert "test" in wordlist
            assert "# This is a comment" not in wordlist
        finally:
            os.unlink(temp_path)
    
    @pytest.mark.asyncio
    async def test_test_endpoint_success(self, endpoint_fuzzer, mock_http_client):
        """Test successful endpoint testing"""
        # Mock successful response
        mock_response = Response(
            status_code=200,
            headers={'Content-Type': 'application/json'},
            content=b'{"success": true}',
            text='{"success": true}',
            url='http://example.com/admin',
            elapsed=0.5,
            request_method='GET'
        )
        mock_http_client.request.return_value = mock_response
        
        endpoint = await endpoint_fuzzer._test_endpoint('GET', 'http://example.com/admin', 'admin', 0)
        
        assert endpoint is not None
        assert endpoint.url == 'http://example.com/admin'
        assert endpoint.method == 'GET'
        assert endpoint.status_code == 200
        assert endpoint.status == EndpointStatus.VALID
        assert endpoint.endpoint_type == "admin"  # Should be classified as admin
        assert endpoint.discovered_via == "wordlist"
    
    @pytest.mark.asyncio
    async def test_test_endpoint_auth_required(self, endpoint_fuzzer, mock_http_client):
        """Test endpoint requiring authentication"""
        # Mock 401 response
        mock_response = Response(
            status_code=401,
            headers={'WWW-Authenticate': 'Bearer'},
            content=b'Unauthorized',
            text='Unauthorized',
            url='http://example.com/admin',
            elapsed=0.2,
            request_method='GET'
        )
        mock_http_client.request.return_value = mock_response
        
        endpoint = await endpoint_fuzzer._test_endpoint('GET', 'http://example.com/admin', 'admin', 0)
        
        assert endpoint is not None
        assert endpoint.status == EndpointStatus.AUTH_REQUIRED
        assert endpoint.auth_required is True
    
    @pytest.mark.asyncio
    async def test_test_endpoint_not_found(self, endpoint_fuzzer, mock_http_client):
        """Test endpoint not found (404)"""
        # Mock 404 response
        mock_response = Response(
            status_code=404,
            headers={},
            content=b'Not Found',
            text='Not Found',
            url='http://example.com/nonexistent',
            elapsed=0.1,
            request_method='GET'
        )
        mock_http_client.request.return_value = mock_response
        
        endpoint = await endpoint_fuzzer._test_endpoint('GET', 'http://example.com/nonexistent', 'nonexistent', 0)
        
        # Should return None for 404s (not interesting)
        assert endpoint is None
    
    @pytest.mark.asyncio
    async def test_test_endpoint_redirect(self, endpoint_fuzzer, mock_http_client):
        """Test endpoint with redirect"""
        # Mock redirect response
        mock_response = Response(
            status_code=302,
            headers={'Location': '/login'},
            content=b'Redirecting...',
            text='Redirecting...',
            url='http://example.com/admin',
            elapsed=0.1,
            request_method='GET'
        )
        mock_http_client.request.return_value = mock_response
        
        endpoint = await endpoint_fuzzer._test_endpoint('GET', 'http://example.com/admin', 'admin', 0)
        
        assert endpoint is not None
        assert endpoint.status == EndpointStatus.REDIRECT
        assert endpoint.redirect_location == '/login'
    
    def test_classify_endpoint(self, endpoint_fuzzer):
        """Test endpoint classification"""
        # Test admin endpoint
        admin_endpoint = Endpoint(
            url='http://example.com/admin',
            method='GET',
            status_code=200,
            response_size=100,
            response_time=0.5
        )
        endpoint_fuzzer._classify_endpoint(admin_endpoint, 'admin')
        assert admin_endpoint.endpoint_type == "admin"
        
        # Test API endpoint
        api_endpoint = Endpoint(
            url='http://example.com/api',
            method='GET',
            status_code=200,
            response_size=100,
            response_time=0.5
        )
        endpoint_fuzzer._classify_endpoint(api_endpoint, 'api')
        assert api_endpoint.endpoint_type == "api_version"
        
        # Test auth endpoint
        auth_endpoint = Endpoint(
            url='http://example.com/login',
            method='GET',
            status_code=200,
            response_size=100,
            response_time=0.5
        )
        endpoint_fuzzer._classify_endpoint(auth_endpoint, 'login')
        assert auth_endpoint.endpoint_type == "authentication"


class FakeHTTPRequestEngine:
    """
    Fake HTTPRequestEngine that records every request(...) call.

    Used to verify that every Discovery_Request flows through the
    (rate-limited) client (Requirement 20.4) and to count exactly how many
    Discovery_Requests Endpoint_Discovery issues (Requirements 18.2/18.3).
    """

    def __init__(self, status_code: int = 200):
        self.status_code = status_code
        self.calls = []            # list of (method, url) tuples in call order
        self.in_flight = 0         # current number of in-flight requests
        self.peak_in_flight = 0    # peak observed concurrency

    @property
    def call_count(self) -> int:
        return len(self.calls)

    async def request(self, method: str, url: str, **kwargs) -> Response:
        # Track concurrency: increment on entry, yield, then decrement.
        self.in_flight += 1
        self.peak_in_flight = max(self.peak_in_flight, self.in_flight)
        self.calls.append((method, url))
        try:
            # Yield control so concurrent requests can overlap.
            await asyncio.sleep(0)
            return Response(
                status_code=self.status_code,
                headers={'Content-Type': 'application/json'},
                content=b'{"ok": true}',
                text='{"ok": true}',
                url=url,
                elapsed=0.01,
                request_method=method,
            )
        finally:
            self.in_flight -= 1


def _write_wordlist(words):
    """Write words to a temp wordlist file and return its path."""
    f = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    f.write("\n".join(words) + "\n")
    f.close()
    return f.name


class TestBudgetAndConcurrency:
    """
    Unit tests for Request_Budget truncation and concurrency-limited dispatch
    in EndpointFuzzer (Requirements 18.2, 18.3, 18.4, 18.6, 20.4).

    Note: EndpointFuzzer dedupes candidate requests by URL within a wordlist
    pass, so each unique word yields one Discovery_Request at depth 0
    regardless of how many HTTP methods are configured.
    """

    def _make_config(self, max_requests=None, concurrency=50):
        return FuzzingConfig(
            endpoints=EndpointFuzzingConfig(
                enabled=True,
                wordlist="unused.txt",
                methods=["GET", "POST"],
                follow_redirects=False,
            ),
            parameters=ParameterFuzzingConfig(enabled=False),
            headers=HeaderFuzzingConfig(enabled=False),
            recursive=False,
            max_depth=0,
            max_requests=max_requests,
            concurrency=concurrency,
        )

    @pytest.mark.asyncio
    async def test_budget_truncates_requests_and_returns_partial_set(self):
        """
        With max_requests=N against a wordlist exceeding N, exactly N
        Discovery_Requests are issued, budget_reached is set, and the partial
        discovered set is returned (Requirements 18.2, 18.3, 18.4).

        Note: catch-all detection (Requirement 19.1) issues CATCH_ALL_PROBES
        probes first, and those also count toward the Request_Budget, so the
        wordlist pass only receives the leftover budget.
        """
        wordlist_budget = 3
        max_requests = EndpointFuzzer.CATCH_ALL_PROBES + wordlist_budget
        words = [f"word{i}" for i in range(10)]  # 10 unique words > leftover budget
        wordlist_path = _write_wordlist(words)
        fake_client = FakeHTTPRequestEngine(status_code=200)
        fuzzer = EndpointFuzzer(fake_client, self._make_config(max_requests=max_requests))

        try:
            discovered = await fuzzer.discover_endpoints('http://example.com', wordlist_path)
        finally:
            os.unlink(wordlist_path)

        # 18.2: exactly N requests counted toward the budget (probes + wordlist)
        assert fuzzer.requests_issued == max_requests
        # 18.2 / 20.4: every issued request flowed through the client
        assert fake_client.call_count == max_requests
        # 18.3: discovery stopped once the budget was reached
        assert fuzzer.budget_reached is True
        # 18.4: the partial discovered set is returned (catch-all probes target
        # random paths and are not stored as endpoints, so only the wordlist
        # hits found before the budget was reached appear)
        assert len(discovered) == wordlist_budget
        assert all(isinstance(e, Endpoint) for e in discovered)

    @pytest.mark.asyncio
    async def test_budget_never_exceeded_when_wordlist_larger(self):
        """
        FOR a Request_Budget N, the total Discovery_Requests issued is at most N
        even when many more candidates exist (Requirement 18.3).
        """
        max_requests = 5
        words = [f"path{i}" for i in range(50)]
        wordlist_path = _write_wordlist(words)
        fake_client = FakeHTTPRequestEngine(status_code=200)
        fuzzer = EndpointFuzzer(fake_client, self._make_config(max_requests=max_requests))

        try:
            await fuzzer.discover_endpoints('http://example.com', wordlist_path)
        finally:
            os.unlink(wordlist_path)

        assert fake_client.call_count <= max_requests
        assert fake_client.call_count == max_requests
        assert fuzzer.budget_reached is True

    @pytest.mark.asyncio
    async def test_unbounded_discovery_when_max_requests_none(self):
        """
        WHERE no max_requests is provided, discovery runs without a budget
        limit: every candidate is issued, budget is never marked reached, and
        every request still flows through the rate-limited client
        (Requirements 18.6, 20.4).
        """
        words = [f"endpoint{i}" for i in range(12)]
        wordlist_path = _write_wordlist(words)
        fake_client = FakeHTTPRequestEngine(status_code=200)
        fuzzer = EndpointFuzzer(fake_client, self._make_config(max_requests=None))

        try:
            discovered = await fuzzer.discover_endpoints('http://example.com', wordlist_path)
        finally:
            os.unlink(wordlist_path)

        # 18.6: unbounded -> all unique words are issued as Discovery_Requests,
        # plus the CATCH_ALL_PROBES catch-all probes (Requirement 19.1).
        expected_calls = len(words) + EndpointFuzzer.CATCH_ALL_PROBES
        assert fake_client.call_count == expected_calls
        # 20.4: every Discovery_Request passed through the (rate-limited) client
        assert len(fake_client.calls) == expected_calls
        # No budget configured, so budget_reached stays False and the issued
        # counter is not advanced.
        assert fuzzer.budget_reached is False
        assert fuzzer.requests_issued == 0
        # All discovered endpoints returned (each unique word -> one endpoint)
        assert len(discovered) == len(words)


class CatchAllFakeClient:
    """
    Fake HTTPRequestEngine for catch-all / wildcard detection tests
    (Requirement 19).

    ``responder`` is a callable ``(method, url) -> (status_code, content_bytes)``
    that lets each test decide how the target answers each request, so we can
    simulate both genuine endpoints and Catch_All_Response behavior. Every
    request(...) call is recorded in ``calls`` so tests can assert which URLs
    were (and were not) probed.
    """

    def __init__(self, responder):
        self.responder = responder
        self.calls = []  # list of (method, url) in call order

    @property
    def call_count(self) -> int:
        return len(self.calls)

    async def request(self, method: str, url: str, **kwargs) -> Response:
        self.calls.append((method, url))
        await asyncio.sleep(0)
        status_code, content = self.responder(method, url)
        return Response(
            status_code=status_code,
            headers={'Content-Type': 'application/json'},
            content=content,
            text=content.decode('utf-8', 'ignore'),
            url=url,
            elapsed=0.01,
            request_method=method,
        )


class TestCatchAllDetection:
    """
    Unit tests for Catch_All_Response / wildcard detection in EndpointFuzzer
    (Requirement 19).

    These exercise _detect_catch_all and the recursion-exclusion behavior with
    a configurable fake HTTPRequestEngine, matching the existing test
    conventions (pytest + asyncio, real Response objects, temp wordlists).
    """

    def _make_config(self, recursive=False, max_depth=0, methods=None):
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
            max_requests=None,
            concurrency=50,
        )

    @pytest.mark.asyncio
    async def test_all_2xx_probes_set_detection_and_record_signature(self):
        """
        19.1 / 19.2: WHEN every randomly generated non-existent path returns a
        successful (2xx) response, THE base URL is classified as Catch_All and
        the (status_code, response_size) signature is recorded.
        """
        body = b'{"spa": "index"}'  # every probe answers with the same SPA body
        fake_client = CatchAllFakeClient(lambda method, url: (200, body))
        fuzzer = EndpointFuzzer(fake_client, self._make_config())

        await fuzzer._detect_catch_all('http://example.com/')

        # 19.1: one probe per CATCH_ALL_PROBES was issued to non-existent paths
        assert fake_client.call_count == EndpointFuzzer.CATCH_ALL_PROBES
        assert all(method == 'GET' for method, _ in fake_client.calls)
        # 19.2: all-2xx -> catch-all detected, signature is (status, size)
        assert fuzzer.catch_all_detected is True
        assert fuzzer.catch_all_signature == (200, len(body))

    @pytest.mark.asyncio
    async def test_non_2xx_probe_leaves_detection_off(self):
        """
        19.3: IF any randomly generated non-existent path returns a non-success
        response, THEN catch-all is NOT detected and no signature is recorded,
        so recursion proceeds normally.
        """
        # Return 2xx for some probes but a 404 for one of them. Order of the
        # concurrently-dispatched probes does not matter: a single non-2xx is
        # enough to leave detection off.
        statuses = iter([200, 404, 200])

        def responder(method, url):
            return (next(statuses), b'body')

        fake_client = CatchAllFakeClient(responder)
        fuzzer = EndpointFuzzer(fake_client, self._make_config())

        await fuzzer._detect_catch_all('http://example.com/')

        assert fake_client.call_count == EndpointFuzzer.CATCH_ALL_PROBES
        # 19.3: not all probes were 2xx -> detection stays off, no signature
        assert fuzzer.catch_all_detected is False
        assert fuzzer.catch_all_signature is None

    @pytest.mark.asyncio
    async def test_probe_failures_count_as_non_2xx(self):
        """
        19.3 (failure tolerance): a probe that raises is tolerated and counts as
        a non-2xx result, so catch-all detection stays off rather than crashing.
        """
        call_index = {'n': 0}

        async def failing_request(method, url, **kwargs):
            call_index['n'] += 1
            # First probe raises; remaining probes return 2xx.
            if call_index['n'] == 1:
                raise ConnectionError("probe failed")
            await asyncio.sleep(0)
            return Response(
                status_code=200,
                headers={},
                content=b'ok',
                text='ok',
                url=url,
                elapsed=0.01,
                request_method=method,
            )

        fake_client = Mock(spec=HTTPRequestEngine)
        fake_client.request = failing_request
        fuzzer = EndpointFuzzer(fake_client, self._make_config())

        # Should not raise even though one probe errored.
        await fuzzer._detect_catch_all('http://example.com/')

        assert fuzzer.catch_all_detected is False
        assert fuzzer.catch_all_signature is None

    @pytest.mark.asyncio
    async def test_catch_all_endpoints_excluded_from_recursable_base_endpoints(self):
        """
        19.4: WHILE a base URL exhibits Catch_All_Response behavior, recursion
        SHALL NOT descend into Discovery_Result records whose status code and
        response size match the detected signature. Endpoints with a different
        signature are still recursed normally.
        """
        catch_all_size = 16
        signature = (200, catch_all_size)

        # Depth-1 sub-paths all 404 so recursion stops after one level; this
        # keeps the test focused on which base endpoints get recursed into.
        fake_client = CatchAllFakeClient(lambda method, url: (404, b'nope'))
        fuzzer = EndpointFuzzer(fake_client, self._make_config(recursive=True, max_depth=1))

        # Pretend catch-all was already detected during phase 0.
        fuzzer.catch_all_detected = True
        fuzzer.catch_all_signature = signature

        # A wildcard endpoint (matches the signature) and a genuine endpoint
        # (different response size) discovered at depth 0.
        wildcard_endpoint = Endpoint(
            url='http://example.com/wildcard',
            method='GET',
            status_code=200,
            response_size=catch_all_size,   # matches signature -> excluded
            response_time=0.01,
        )
        real_endpoint = Endpoint(
            url='http://example.com/real',
            method='GET',
            status_code=200,
            response_size=catch_all_size + 100,  # differs -> recursable
            response_time=0.01,
        )

        await fuzzer._recursive_fuzzing([wildcard_endpoint, real_endpoint], ["sub"])

        recursed_urls = [url for _, url in fake_client.calls]
        # The genuine endpoint was recursed into...
        assert any(url.startswith('http://example.com/real/') for url in recursed_urls)
        # ...but the catch-all/wildcard endpoint was excluded from recursion.
        assert not any(
            url.startswith('http://example.com/wildcard/') for url in recursed_urls
        )

    @pytest.mark.asyncio
    async def test_is_catch_all_matches_only_on_signature(self):
        """
        19.4 (signature matching): _is_catch_all returns True only for endpoints
        whose (status_code, response_size) equals the detected signature, and
        only while catch-all is active.
        """
        fuzzer = EndpointFuzzer(CatchAllFakeClient(lambda m, u: (200, b'')),
                                self._make_config())

        matching = Endpoint(url='http://example.com/a', method='GET',
                            status_code=200, response_size=42, response_time=0.0)
        different_size = Endpoint(url='http://example.com/b', method='GET',
                                 status_code=200, response_size=43, response_time=0.0)

        # Not active yet -> never catch-all.
        assert fuzzer._is_catch_all(matching) is False

        fuzzer.catch_all_detected = True
        fuzzer.catch_all_signature = (200, 42)

        assert fuzzer._is_catch_all(matching) is True
        assert fuzzer._is_catch_all(different_size) is False


class TestFuzzingOrchestrator:
    """Test fuzzing orchestrator functionality"""
    
    @pytest.fixture
    def mock_http_client(self):
        """Create mock HTTP client"""
        client = Mock(spec=HTTPRequestEngine)
        client.request = AsyncMock()
        return client
    
    @pytest.fixture
    def fuzzing_config(self):
        """Create fuzzing configuration"""
        return FuzzingConfig(
            endpoints=EndpointFuzzingConfig(
                enabled=True,
                wordlist="wordlists/endpoints.txt",
                methods=["GET", "POST"],
                follow_redirects=True
            ),
            parameters=ParameterFuzzingConfig(enabled=True),
            headers=HeaderFuzzingConfig(enabled=True),
            recursive=False,
            max_depth=1
        )
    
    @pytest.fixture
    def fuzzing_orchestrator(self, fuzzing_config, mock_http_client):
        """Create fuzzing orchestrator"""
        return FuzzingOrchestrator(fuzzing_config, mock_http_client)
    
    def test_initialization(self, fuzzing_orchestrator, fuzzing_config):
        """Test orchestrator initialization"""
        assert fuzzing_orchestrator.config == fuzzing_config
        assert fuzzing_orchestrator.http_client is not None
        assert isinstance(fuzzing_orchestrator.stats, FuzzingStats)
        assert fuzzing_orchestrator.endpoint_fuzzer is not None
    
    @pytest.mark.asyncio
    async def test_discover_endpoints_disabled(self, fuzzing_orchestrator):
        """Test endpoint discovery when disabled"""
        fuzzing_orchestrator.config.endpoints.enabled = False
        
        endpoints = await fuzzing_orchestrator.discover_endpoints('http://example.com')
        
        assert len(endpoints) == 0
    
    @pytest.mark.asyncio
    async def test_discover_endpoints_success(self, fuzzing_orchestrator, mock_http_client):
        """Test successful endpoint discovery"""
        # Mock the endpoint fuzzer's discover_endpoints method
        mock_endpoints = [
            Endpoint(
                url='http://example.com/admin',
                method='GET',
                status_code=200,
                response_size=100,
                response_time=0.5,
                endpoint_type="admin"
            ),
            Endpoint(
                url='http://example.com/api',
                method='GET',
                status_code=401,
                response_size=50,
                response_time=0.2,
                auth_required=True
            )
        ]
        
        with patch.object(fuzzing_orchestrator.endpoint_fuzzer, 'discover_endpoints', 
                         return_value=mock_endpoints) as mock_discover:
            endpoints = await fuzzing_orchestrator.discover_endpoints('http://example.com')
            
            assert len(endpoints) == 2
            assert endpoints[0].url == 'http://example.com/admin'
            assert endpoints[1].auth_required is True
            mock_discover.assert_called_once_with('http://example.com', 'wordlists/endpoints.txt')
    
    @pytest.mark.asyncio
    async def test_fuzz_parameters_disabled(self, fuzzing_orchestrator):
        """Test parameter fuzzing when disabled"""
        fuzzing_orchestrator.config.parameters.enabled = False
        
        findings = await fuzzing_orchestrator.fuzz_parameters([])
        
        assert len(findings) == 0
    
    @pytest.mark.asyncio
    async def test_fuzz_headers_disabled(self, fuzzing_orchestrator):
        """Test header fuzzing when disabled"""
        fuzzing_orchestrator.config.headers.enabled = False
        
        findings = await fuzzing_orchestrator.fuzz_headers([])
        
        assert len(findings) == 0
    
    def test_get_fuzzing_statistics(self, fuzzing_orchestrator):
        """Test getting fuzzing statistics"""
        stats = fuzzing_orchestrator.get_fuzzing_statistics()
        
        assert isinstance(stats, FuzzingStats)
        assert stats.endpoints_tested == 0
        assert stats.success_rate == 0.0
    
    def test_get_discovered_endpoints(self, fuzzing_orchestrator):
        """Test getting discovered endpoints"""
        # Add some mock endpoints to the endpoint fuzzer
        mock_endpoint = Endpoint(
            url='http://example.com/test',
            method='GET',
            status_code=200,
            response_size=100,
            response_time=0.5
        )
        fuzzing_orchestrator.endpoint_fuzzer.discovered_endpoints['http://example.com/test'] = mock_endpoint
        
        endpoints = fuzzing_orchestrator.get_discovered_endpoints()
        
        assert len(endpoints) == 1
        assert endpoints[0].url == 'http://example.com/test'
    
    def test_get_endpoints_by_status(self, fuzzing_orchestrator):
        """Test filtering endpoints by status"""
        # Add mock endpoints with different statuses
        valid_endpoint = Endpoint(
            url='http://example.com/valid',
            method='GET',
            status_code=200,
            response_size=100,
            response_time=0.5
        )
        auth_endpoint = Endpoint(
            url='http://example.com/auth',
            method='GET',
            status_code=401,
            response_size=50,
            response_time=0.2
        )
        
        fuzzing_orchestrator.endpoint_fuzzer.discovered_endpoints.update({
            'http://example.com/valid': valid_endpoint,
            'http://example.com/auth': auth_endpoint
        })
        
        valid_endpoints = fuzzing_orchestrator.get_endpoints_by_status(EndpointStatus.VALID)
        auth_endpoints = fuzzing_orchestrator.get_endpoints_by_status(EndpointStatus.AUTH_REQUIRED)
        
        assert len(valid_endpoints) == 1
        assert valid_endpoints[0].url == 'http://example.com/valid'
        assert len(auth_endpoints) == 1
        assert auth_endpoints[0].url == 'http://example.com/auth'
    
    def test_get_endpoints_by_type(self, fuzzing_orchestrator):
        """Test filtering endpoints by type"""
        # Add mock endpoints with different types
        admin_endpoint = Endpoint(
            url='http://example.com/admin',
            method='GET',
            status_code=200,
            response_size=100,
            response_time=0.5,
            endpoint_type="admin"
        )
        api_endpoint = Endpoint(
            url='http://example.com/api',
            method='GET',
            status_code=200,
            response_size=100,
            response_time=0.5,
            endpoint_type="api_version"
        )
        
        fuzzing_orchestrator.endpoint_fuzzer.discovered_endpoints.update({
            'http://example.com/admin': admin_endpoint,
            'http://example.com/api': api_endpoint
        })
        
        admin_endpoints = fuzzing_orchestrator.get_endpoints_by_type("admin")
        api_endpoints = fuzzing_orchestrator.get_endpoints_by_type("api_version")
        
        assert len(admin_endpoints) == 1
        assert admin_endpoints[0].url == 'http://example.com/admin'
        assert len(api_endpoints) == 1
        assert api_endpoints[0].url == 'http://example.com/api'


class TestEndpoint:
    """Test Endpoint model functionality"""
    
    def test_endpoint_status_properties(self):
        """Test endpoint status classification"""
        # Test valid endpoint (2xx)
        valid_endpoint = Endpoint(
            url='http://example.com/test',
            method='GET',
            status_code=200,
            response_size=100,
            response_time=0.5
        )
        assert valid_endpoint.status == EndpointStatus.VALID
        
        # Test auth required (401/403)
        auth_endpoint = Endpoint(
            url='http://example.com/admin',
            method='GET',
            status_code=401,
            response_size=50,
            response_time=0.2
        )
        assert auth_endpoint.status == EndpointStatus.AUTH_REQUIRED
        
        # Test not found (404)
        not_found_endpoint = Endpoint(
            url='http://example.com/missing',
            method='GET',
            status_code=404,
            response_size=20,
            response_time=0.1
        )
        assert not_found_endpoint.status == EndpointStatus.NOT_FOUND
        
        # Test redirect (3xx)
        redirect_endpoint = Endpoint(
            url='http://example.com/old',
            method='GET',
            status_code=302,
            response_size=30,
            response_time=0.1
        )
        assert redirect_endpoint.status == EndpointStatus.REDIRECT
        
        # Test server error (5xx)
        error_endpoint = Endpoint(
            url='http://example.com/error',
            method='GET',
            status_code=500,
            response_size=100,
            response_time=1.0
        )
        assert error_endpoint.status == EndpointStatus.ERROR


class TestFuzzingStats:
    """Test FuzzingStats functionality"""
    
    def test_success_rate_calculation(self):
        """Test success rate calculation"""
        stats = FuzzingStats()
        
        # Test with no requests
        assert stats.success_rate == 0.0
        
        # Test with some requests
        stats.total_requests = 100
        stats.successful_requests = 80
        assert stats.success_rate == 80.0
        
        # Test with all successful
        stats.successful_requests = 100
        assert stats.success_rate == 100.0
        
        # Test with no successful
        stats.successful_requests = 0
        assert stats.success_rate == 0.0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])