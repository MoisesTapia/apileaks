"""
Fuzzing Orchestrator
Coordinates traditional fuzzing operations for endpoints, parameters, and headers
"""

import asyncio
import os
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from enum import Enum
from uuid import uuid4

from core.logging import get_logger
from core.config import FuzzingConfig, Severity
from utils.http_client import HTTPRequestEngine, Response
from utils.findings import Finding, FindingsCollector


class EndpointStatus(str, Enum):
    """Endpoint status classification"""
    VALID = "valid"              # 2xx responses
    AUTH_REQUIRED = "auth_required"  # 401/403 responses
    NOT_FOUND = "not_found"      # 404 responses
    REDIRECT = "redirect"        # 3xx responses
    ERROR = "error"              # 5xx responses
    UNKNOWN = "unknown"          # Other responses


@dataclass
class Endpoint:
    """Discovered endpoint representation"""
    url: str
    method: str
    status_code: int
    response_size: int
    response_time: float
    headers: Dict[str, str] = field(default_factory=dict)
    auth_required: bool = False
    discovered_via: str = "wordlist"  # wordlist, recursive, redirect
    endpoint_type: str = "standard"   # standard, admin, api_version, etc.
    redirect_location: Optional[str] = None
    
    @property
    def status(self) -> EndpointStatus:
        """Get endpoint status classification"""
        if 200 <= self.status_code < 300:
            return EndpointStatus.VALID
        elif self.status_code in [401, 403]:
            return EndpointStatus.AUTH_REQUIRED
        elif self.status_code == 404:
            return EndpointStatus.NOT_FOUND
        elif 300 <= self.status_code < 400:
            return EndpointStatus.REDIRECT
        elif 500 <= self.status_code < 600:
            return EndpointStatus.ERROR
        else:
            return EndpointStatus.UNKNOWN


@dataclass
class FuzzingStats:
    """Fuzzing execution statistics"""
    endpoints_tested: int = 0
    endpoints_discovered: int = 0
    parameters_tested: int = 0
    headers_tested: int = 0
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    redirects_followed: int = 0
    recursive_depth_reached: int = 0
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate percentage"""
        if self.total_requests == 0:
            return 0.0
        return (self.successful_requests / self.total_requests) * 100.0


class EndpointFuzzer:
    """
    Endpoint Fuzzer with wordlist support and intelligent detection
    
    Features:
    - Wordlist-based endpoint discovery
    - Multiple HTTP methods support
    - Intelligent endpoint classification
    - Recursive fuzzing with configurable depth
    - Automatic redirect following
    """
    
    # Number of randomly generated non-existent paths probed to detect
    # Catch_All_Response behavior (Requirement 19.1).
    CATCH_ALL_PROBES = 3
    
    def __init__(self, http_client: HTTPRequestEngine, config: FuzzingConfig):
        self.http_client = http_client
        self.config = config
        self.logger = get_logger(__name__).bind(component="endpoint_fuzzer")
        
        # Discovery state
        self.discovered_endpoints: Dict[str, Endpoint] = {}
        self.tested_urls: Set[str] = set()
        self.wordlist_cache: Dict[str, List[str]] = {}
        
        # Request budget tracking (Request_Budget; None = unbounded discovery)
        self.requests_issued = 0
        self.budget_reached = False
        self.max_requests = config.max_requests
        
        # Concurrency limit (Concurrency_Limit). The semaphore caps the number of
        # in-flight Discovery_Requests so they never exceed self.concurrency.
        self.concurrency = config.concurrency or 50
        self._semaphore = asyncio.Semaphore(self.concurrency)
        
        # Catch-all / wildcard detection state (Catch_All_Response, Requirement 19).
        # catch_all_signature is the (status_code, response_size) recorded when the
        # base URL answers random non-existent paths with 2xx responses.
        self.catch_all_detected = False
        self.catch_all_signature: Optional[Tuple[int, int]] = None
        
        # Soft-404 baseline signature (Soft_404_Baseline, Requirement 22.5/22.6).
        # The (status_code, response_size, word_count) signature of the responses
        # returned for paths that are not expected to exist, captured from the same
        # catch-all probes so calibration adds no requests beyond those probes
        # (which already count toward the Request_Budget). Distinct from and
        # complementary to catch_all_signature (Requirement 22.8): catch-all needs
        # every probe to be 2xx, whereas the soft-404 baseline only needs the probe
        # responses to agree on a single (status, size, words) signature.
        self.soft_404_signature: Optional[Tuple[int, int, int]] = None
        
        self.logger.info("Endpoint Fuzzer initialized",
                        recursive=config.recursive,
                        max_depth=config.max_depth,
                        max_requests=config.max_requests,
                        concurrency=self.concurrency)
    
    async def discover_endpoints(self, base_url: str, wordlist_path: str) -> List[Endpoint]:
        """
        Discover endpoints using wordlist fuzzing
        
        Args:
            base_url: Base URL to fuzz
            wordlist_path: Path to wordlist file
            
        Returns:
            List of discovered endpoints
        """
        self.logger.info("Starting endpoint discovery",
                        base_url=base_url,
                        wordlist=wordlist_path)
        
        # Load wordlist
        wordlist = await self._load_wordlist(wordlist_path)
        if not wordlist:
            self.logger.error("Failed to load wordlist", path=wordlist_path)
            return []
        
        # Normalize base URL
        if not base_url.endswith('/'):
            base_url += '/'
        
        # Phase 0: Catch-all / wildcard detection (Requirement 19). Runs before the
        # depth-0 pass so its probes also count toward requests_issued / the budget.
        await self._detect_catch_all(base_url)
        
        # Phase 1: Initial wordlist fuzzing
        initial_endpoints = await self._fuzz_wordlist(base_url, wordlist, depth=0)
        
        # Phase 2: Recursive fuzzing if enabled
        if self.config.recursive and self.config.max_depth > 0:
            await self._recursive_fuzzing(initial_endpoints, wordlist)
        
        # Convert to list and sort by URL
        discovered = list(self.discovered_endpoints.values())
        discovered.sort(key=lambda e: e.url)
        
        self.logger.info("Endpoint discovery completed",
                        total_discovered=len(discovered),
                        valid_endpoints=len([e for e in discovered if e.status == EndpointStatus.VALID]),
                        auth_required=len([e for e in discovered if e.status == EndpointStatus.AUTH_REQUIRED]))
        
        return discovered
    
    async def _load_wordlist(self, wordlist_path: str) -> List[str]:
        """Load wordlist from file with caching"""
        if wordlist_path in self.wordlist_cache:
            return self.wordlist_cache[wordlist_path]
        
        try:
            wordlist_file = Path(wordlist_path)
            if not wordlist_file.exists():
                self.logger.error("Wordlist file not found", path=wordlist_path)
                return []
            
            with open(wordlist_file, 'r', encoding='utf-8') as f:
                # Filter out comments and empty lines
                words = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        words.append(line)
            
            self.wordlist_cache[wordlist_path] = words
            self.logger.debug("Wordlist loaded", path=wordlist_path, words_count=len(words))
            return words
            
        except Exception as e:
            self.logger.error("Failed to load wordlist", path=wordlist_path, error=str(e))
            return []
    
    async def _fuzz_wordlist(self, base_url: str, wordlist: List[str], depth: int = 0) -> List[Endpoint]:
        """Fuzz endpoints using wordlist"""
        self.logger.debug("Fuzzing wordlist", base_url=base_url, words=len(wordlist), depth=depth)
        
        # Create requests for all word/method combinations
        requests = []
        for word in wordlist:
            for method in self.config.endpoints.methods:
                url = urljoin(base_url, word)
                if url not in self.tested_urls:
                    requests.append((method, url, word, depth))
                    self.tested_urls.add(url)
        
        # Execute requests. Concurrency is now bounded by the asyncio.Semaphore
        # in _test_endpoint (Concurrency_Limit), not by a hardcoded batch size.
        discovered_endpoints = []
        
        # Enforce the request budget (Request_Budget). Skip when unbounded.
        if self.max_requests is not None:
            remaining = self.max_requests - self.requests_issued
            if remaining <= 0:
                self.budget_reached = True
                return discovered_endpoints
            # Trim the dispatched requests to the remaining budget
            if len(requests) > remaining:
                requests = requests[:remaining]
        
        if not requests:
            return discovered_endpoints
        
        # Show progress
        self.logger.info(f"Testing {len(requests)} endpoints", base_url=base_url, depth=depth)
        
        # Count the requests being issued toward the budget
        if self.max_requests is not None:
            self.requests_issued += len(requests)
        
        discovered_endpoints = await self._execute_batch(requests)
        
        # Flag budget exhaustion so recursive fuzzing can short-circuit
        if self.max_requests is not None and self.requests_issued >= self.max_requests:
            self.budget_reached = True
        
        return discovered_endpoints
    
    async def _execute_batch(self, batch: List[Tuple[str, str, str, int]]) -> List[Endpoint]:
        """Execute a batch of requests"""
        tasks = []
        for method, url, word, depth in batch:
            task = self._test_endpoint(method, url, word, depth)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        endpoints = []
        for result in results:
            if isinstance(result, Endpoint):
                endpoints.append(result)
            elif isinstance(result, Exception):
                self.logger.debug("Request failed", error=str(result))
        
        return endpoints
    
    async def _test_endpoint(self, method: str, url: str, word: str, depth: int) -> Optional[Endpoint]:
        """Test a single endpoint"""
        try:
            # Cap in-flight Discovery_Requests at the Concurrency_Limit. Every
            # request still flows through HTTPRequestEngine.request, so the rate
            # limiter continues to apply to each Discovery_Request.
            async with self._semaphore:
                response = await self.http_client.request(method, url)
            
            # Create endpoint object
            endpoint = Endpoint(
                url=url,
                method=method,
                status_code=response.status_code,
                response_size=len(response.content),
                response_time=response.elapsed,
                headers=response.headers,
                discovered_via="wordlist" if depth == 0 else "recursive"
            )
            
            # Classify endpoint
            self._classify_endpoint(endpoint, word)
            
            # Handle redirects if enabled
            if (endpoint.status == EndpointStatus.REDIRECT and 
                self.config.endpoints.follow_redirects):
                await self._handle_redirect(endpoint, response)
            
            # Only store interesting endpoints (not 404s)
            if endpoint.status != EndpointStatus.NOT_FOUND:
                self.discovered_endpoints[url] = endpoint
                self.logger.debug("Endpoint discovered",
                                url=url,
                                method=method,
                                status=endpoint.status_code,
                                size=endpoint.response_size)
                return endpoint
            
        except Exception as e:
            self.logger.debug("Endpoint test failed", url=url, method=method, error=str(e))
        
        return None
    
    def _classify_endpoint(self, endpoint: Endpoint, word: str) -> None:
        """Classify endpoint type based on URL patterns"""
        url_lower = endpoint.url.lower()
        word_lower = word.lower()
        
        # Admin endpoints
        admin_patterns = ['admin', 'management', 'dashboard', 'control']
        if any(pattern in word_lower for pattern in admin_patterns):
            endpoint.endpoint_type = "admin"
        
        # API version endpoints
        api_patterns = ['v1', 'v2', 'v3', 'api']
        if any(pattern in word_lower for pattern in api_patterns):
            endpoint.endpoint_type = "api_version"
        
        # Authentication endpoints
        auth_patterns = ['auth', 'login', 'oauth', 'token']
        if any(pattern in word_lower for pattern in auth_patterns):
            endpoint.endpoint_type = "authentication"
        
        # Development/debug endpoints
        dev_patterns = ['debug', 'test', 'dev', 'staging']
        if any(pattern in word_lower for pattern in dev_patterns):
            endpoint.endpoint_type = "development"
        
        # Set auth_required flag for 401/403 responses
        if endpoint.status_code in [401, 403]:
            endpoint.auth_required = True
    
    async def _handle_redirect(self, endpoint: Endpoint, response: Response) -> None:
        """Handle redirect responses"""
        location = response.headers.get('Location') or response.headers.get('location')
        if not location:
            return
        
        endpoint.redirect_location = location
        
        # Follow redirect if it's to the same domain
        try:
            original_domain = urlparse(endpoint.url).netloc
            redirect_domain = urlparse(location).netloc
            
            if redirect_domain == original_domain or not redirect_domain:
                # Resolve relative redirects
                if not redirect_domain:
                    location = urljoin(endpoint.url, location)
                
                # Test the redirect target if we haven't already
                if location not in self.tested_urls:
                    self.logger.debug("Following redirect", from_url=endpoint.url, to_url=location)
                    redirect_endpoint = await self._test_endpoint(endpoint.method, location, "redirect", 0)
                    if redirect_endpoint:
                        redirect_endpoint.discovered_via = "redirect"
                        
        except Exception as e:
            self.logger.debug("Failed to handle redirect", error=str(e))
    
    async def _detect_catch_all(self, base_url: str) -> None:
        """Detect Catch_All_Response behavior (Requirement 19).
        
        Issues GET requests to CATCH_ALL_PROBES randomly generated, almost-certainly
        non-existent paths. If EVERY probe returns a successful (2xx) response, the
        base URL is classified as exhibiting catch-all behavior and the
        (status_code, response_size) signature of the response is recorded so
        matching endpoints can be excluded from recursion (19.4). If any probe
        returns a non-2xx response (or errors), catch_all_detected stays False and
        recursion proceeds normally (19.3).
        
        The probes count toward requests_issued so they remain within the
        Request_Budget, consistent with _fuzz_wordlist.
        
        The same probe responses also feed the Soft_404_Baseline (Requirement
        22.5): when every valid probe response shares one (status_code, size,
        word_count) signature, that signature is recorded in soft_404_signature so
        calibrate_soft_404 can suppress matching records without issuing extra
        requests. This is independent of catch-all detection (Requirement 22.8) --
        the soft-404 baseline does not require the probes to be 2xx.
        """
        # Respect the request budget (Request_Budget). Skip when unbounded.
        probe_count = self.CATCH_ALL_PROBES
        if self.max_requests is not None:
            remaining = self.max_requests - self.requests_issued
            if remaining <= 0:
                self.budget_reached = True
                return
            # Trim the probes to whatever budget remains
            if probe_count > remaining:
                probe_count = remaining
        
        if probe_count <= 0:
            return
        
        # Generate random, non-existent paths (e.g. uuid4().hex)
        probes = [urljoin(base_url, f"{uuid4().hex}{i}") for i in range(probe_count)]
        
        # Count the probes being issued toward the budget
        if self.max_requests is not None:
            self.requests_issued += len(probes)
        
        async def _probe(url: str) -> Response:
            # Cap in-flight probes at the Concurrency_Limit, like _test_endpoint.
            async with self._semaphore:
                return await self.http_client.request("GET", url)
        
        responses = await asyncio.gather(
            *(_probe(u) for u in probes),
            return_exceptions=True
        )
        
        # Tolerate probe failures: an errored probe is not a 2xx, so it simply
        # prevents the "all 2xx" condition and defaults to "not catch-all" (19.3).
        oks = [
            r for r in responses
            if isinstance(r, Response) and 200 <= r.status_code < 300
        ]
        
        # Soft_404_Baseline calibration (Requirement 22.5): capture the
        # (status_code, size, words) signature shared by the probe responses to
        # non-existent paths. Recorded only when every valid probe response agrees
        # on a single signature, so the baseline reliably reflects what this base
        # URL returns for paths that do not exist. Reuses the catch-all probes, so
        # no extra requests are issued beyond those already counted (22.8).
        valid = [r for r in responses if isinstance(r, Response)]
        if valid and len(valid) == len(probes):
            signatures = {
                (r.status_code, len(r.content), len(r.text.split()))
                for r in valid
            }
            if len(signatures) == 1:
                self.soft_404_signature = next(iter(signatures))
        
        if oks and len(oks) == len(probes):  # every probe returned 2xx (19.2)
            self.catch_all_detected = True
            self.catch_all_signature = (oks[0].status_code, len(oks[0].content))
            self.logger.info("Catch-all response behavior detected",
                            base_url=base_url,
                            status_code=oks[0].status_code,
                            response_size=len(oks[0].content))
        
        # Flag budget exhaustion so the depth-0 pass / recursion can short-circuit
        if self.max_requests is not None and self.requests_issued >= self.max_requests:
            self.budget_reached = True
    
    def _is_catch_all(self, endpoint: Endpoint) -> bool:
        """Return True when the endpoint matches the detected Catch_All_Response
        signature (status code and response size). Used to exclude wildcard
        responses from recursion (Requirement 19.4)."""
        return (self.catch_all_detected
                and self.catch_all_signature == (endpoint.status_code, endpoint.response_size))
    
    async def _recursive_fuzzing(self, initial_endpoints: List[Endpoint], wordlist: List[str]) -> None:
        """Perform recursive fuzzing on discovered endpoints"""
        self.logger.debug("Starting recursive fuzzing", max_depth=self.config.max_depth)
        
        # Find valid endpoints that could have sub-paths
        base_endpoints = [
            e for e in initial_endpoints 
            if e.status in [EndpointStatus.VALID, EndpointStatus.AUTH_REQUIRED]
            and not e.url.endswith('.html')  # Skip file-like endpoints
            and not e.url.endswith('.json')
            and not e.url.endswith('.xml')
            and not self._is_catch_all(e)  # Skip catch-all/wildcard responses (19.4)
        ]
        
        for depth in range(1, self.config.max_depth + 1):
            # Short-circuit the depth loop once the request budget is reached
            if self.budget_reached:
                self.logger.debug("Request budget reached, stopping recursive fuzzing", depth=depth)
                break
            
            self.logger.debug("Recursive fuzzing depth", depth=depth, base_endpoints=len(base_endpoints))
            
            new_endpoints = []
            for base_endpoint in base_endpoints:
                # Short-circuit the per-endpoint loop once the budget is reached
                if self.budget_reached:
                    break
                
                # Create sub-paths by appending wordlist items
                base_url = base_endpoint.url
                if not base_url.endswith('/'):
                    base_url += '/'
                
                depth_endpoints = await self._fuzz_wordlist(base_url, wordlist, depth)
                new_endpoints.extend(depth_endpoints)
            
            # Stop further recursion if the budget was exhausted during this depth
            if self.budget_reached:
                self.logger.debug("Request budget reached during recursive fuzzing", depth=depth)
                break
            
            # Update base endpoints for next depth level
            base_endpoints = [
                e for e in new_endpoints 
                if e.status in [EndpointStatus.VALID, EndpointStatus.AUTH_REQUIRED]
                and not self._is_catch_all(e)  # Skip catch-all/wildcard responses (19.4)
            ]
            
            # Stop if no new endpoints found
            if not base_endpoints:
                self.logger.debug("No new endpoints found, stopping recursive fuzzing", depth=depth)
                break


@dataclass
class Parameter:
    """Discovered parameter representation"""
    name: str
    location: str  # query, body, header
    value_type: str  # string, integer, boolean, array, object
    discovered_via: str = "wordlist"  # wordlist, response_analysis
    endpoint: str = ""
    method: str = "GET"
    evidence: str = ""
    response_difference: bool = False


class ParameterFuzzer:
    """
    Parameter Fuzzer with wordlist support and boundary testing
    
    Features:
    - Query parameter fuzzing with specialized wordlists
    - Body parameter fuzzing (JSON, XML, form-data)
    - Boundary testing with min/max/empty/null values
    - Response difference detection
    - Parameter type inference
    """
    
    def __init__(self, http_client: HTTPRequestEngine, config: FuzzingConfig):
        self.http_client = http_client
        self.config = config
        self.logger = get_logger(__name__).bind(component="parameter_fuzzer")
        
        # Fuzzing state
        self.parameters_tested = 0
        self.requests_made = 0
        self.successful_requests = 0
        self.discovered_parameters: List[Parameter] = []
        self.parameter_test_details: List[Dict] = []  # Track parameter testing details
        
        # Boundary test values
        self.boundary_values = {
            'string': ['', 'a', 'A' * 1000, 'A' * 10000, None, 'null', '0', '-1', '999999999'],
            'integer': [0, 1, -1, 999999999, -999999999, None, 'null', '', 'abc'],
            'boolean': [True, False, 'true', 'false', '1', '0', None, 'null', ''],
            'array': [[], ['test'], ['a'] * 1000, None, 'null', '', 'not_array'],
            'object': [{}, {'test': 'value'}, None, 'null', '', 'not_object']
        }
        
        self.logger.info("Parameter Fuzzer initialized",
                        boundary_testing=config.parameters.boundary_testing)
    
    async def fuzz_parameters(self, endpoints: List[Endpoint]) -> List[Finding]:
        """
        Fuzz parameters on discovered endpoints
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of findings from parameter fuzzing
        """
        self.logger.info("Starting parameter fuzzing", endpoints_count=len(endpoints))
        
        findings = []
        
        # Filter endpoints suitable for parameter fuzzing
        suitable_endpoints = [
            e for e in endpoints 
            if e.status in [EndpointStatus.VALID, EndpointStatus.AUTH_REQUIRED]
        ]
        
        for endpoint in suitable_endpoints:
            self.logger.debug("Fuzzing parameters for endpoint", 
                            url=endpoint.url, 
                            method=endpoint.method)
            
            # Query parameter fuzzing
            if endpoint.method in ['GET', 'DELETE']:
                query_findings = await self._fuzz_query_parameters(endpoint)
                findings.extend(query_findings)
            
            # Body parameter fuzzing
            if endpoint.method in ['POST', 'PUT', 'PATCH']:
                body_findings = await self._fuzz_body_parameters(endpoint)
                findings.extend(body_findings)
        
        self.logger.info("Parameter fuzzing completed",
                        parameters_tested=self.parameters_tested,
                        requests_made=self.requests_made,
                        findings_count=len(findings))
        
        return findings
    
    async def _fuzz_query_parameters(self, endpoint: Endpoint) -> List[Finding]:
        """Fuzz query parameters for an endpoint"""
        findings = []
        
        # Load query parameter wordlist
        wordlist = await self._load_wordlist(self.config.parameters.query_wordlist)
        if not wordlist:
            return findings
        
        # Get baseline response
        baseline_response = await self._get_baseline_response(endpoint)
        if not baseline_response:
            return findings
        
        # Test each parameter from wordlist
        for i, param_name in enumerate(wordlist, 1):
            self.parameters_tested += 1
            
            # Show progress
            self.logger.info(f"Testing parameter {i}/{len(wordlist)}: {param_name}", 
                           endpoint=endpoint.url, parameter=param_name)
            
            # Test with simple value first
            test_response = await self._test_query_parameter(endpoint, param_name, "test_value")
            
            # Record parameter test details
            param_detail = {
                'name': param_name,
                'baseline_size': len(baseline_response.content) if baseline_response else 0,
                'test_size': len(test_response.content) if test_response else 0,
                'status': 'no_difference'
            }
            
            if test_response and self._has_response_difference(baseline_response, test_response):
                param_detail['status'] = 'difference_found'
                
                # Parameter seems to be accepted, create finding
                parameter = Parameter(
                    name=param_name,
                    location="query",
                    value_type="string",
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    evidence=f"Parameter '{param_name}' caused response difference",
                    response_difference=True
                )
                self.discovered_parameters.append(parameter)
                
                finding = Finding(
                    id=str(uuid4()),
                    scan_id="",  # Will be set by findings collector
                    category="PARAMETER_FOUND",
                    owasp_category=None,
                    severity=Severity.INFO,
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    status_code=test_response.status_code,
                    response_size=len(test_response.content),
                    response_time=test_response.elapsed,
                    evidence=f"Query parameter '{param_name}' discovered - response differs from baseline",
                    recommendation="Review parameter usage and ensure proper validation",
                    payload=f"?{param_name}=test_value",
                    headers=dict(test_response.headers)
                )
                findings.append(finding)
            
            # Add parameter details to tracking list
            self.parameter_test_details.append(param_detail)
            
            # Perform boundary testing if enabled
            if self.config.parameters.boundary_testing:
                boundary_findings = await self._boundary_test_parameter(
                    endpoint, param_name, "query", baseline_response
                )
                findings.extend(boundary_findings)
        
        return findings
    
    async def _fuzz_body_parameters(self, endpoint: Endpoint) -> List[Finding]:
        """Fuzz body parameters for an endpoint"""
        findings = []
        
        # Load body parameter wordlist
        wordlist = await self._load_wordlist(self.config.parameters.body_wordlist)
        if not wordlist:
            return findings
        
        # Get baseline response
        baseline_response = await self._get_baseline_response(endpoint)
        if not baseline_response:
            return findings
        
        # Test JSON parameters
        json_findings = await self._fuzz_json_parameters(endpoint, wordlist, baseline_response)
        findings.extend(json_findings)
        
        # Test form-data parameters
        form_findings = await self._fuzz_form_parameters(endpoint, wordlist, baseline_response)
        findings.extend(form_findings)
        
        # Test XML parameters (basic)
        xml_findings = await self._fuzz_xml_parameters(endpoint, wordlist, baseline_response)
        findings.extend(xml_findings)
        
        return findings
    
    async def _fuzz_json_parameters(self, endpoint: Endpoint, wordlist: List[str], 
                                  baseline_response: Response) -> List[Finding]:
        """Fuzz JSON body parameters"""
        findings = []
        
        for param_name in wordlist:
            self.parameters_tested += 1
            
            # Test with JSON payload
            json_payload = {param_name: "test_value"}
            test_response = await self._test_json_parameter(endpoint, json_payload)
            
            if test_response and self._has_response_difference(baseline_response, test_response):
                parameter = Parameter(
                    name=param_name,
                    location="body",
                    value_type="string",
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    evidence=f"JSON parameter '{param_name}' caused response difference",
                    response_difference=True
                )
                self.discovered_parameters.append(parameter)
                
                finding = Finding(
                    id=str(uuid4()),
                    scan_id="",
                    category="PARAMETER_FOUND",
                    owasp_category=None,
                    severity=Severity.INFO,
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    status_code=test_response.status_code,
                    response_size=len(test_response.content),
                    response_time=test_response.elapsed,
                    evidence=f"JSON body parameter '{param_name}' discovered - response differs from baseline",
                    recommendation="Review parameter usage and ensure proper validation",
                    payload=json.dumps(json_payload),
                    headers=dict(test_response.headers)
                )
                findings.append(finding)
                
                # Boundary testing
                if self.config.parameters.boundary_testing:
                    boundary_findings = await self._boundary_test_json_parameter(
                        endpoint, param_name, baseline_response
                    )
                    findings.extend(boundary_findings)
        
        return findings
    
    async def _fuzz_form_parameters(self, endpoint: Endpoint, wordlist: List[str], 
                                  baseline_response: Response) -> List[Finding]:
        """Fuzz form-data parameters"""
        findings = []
        
        for param_name in wordlist:
            self.parameters_tested += 1
            
            # Test with form data
            form_data = {param_name: "test_value"}
            test_response = await self._test_form_parameter(endpoint, form_data)
            
            if test_response and self._has_response_difference(baseline_response, test_response):
                parameter = Parameter(
                    name=param_name,
                    location="body",
                    value_type="string",
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    evidence=f"Form parameter '{param_name}' caused response difference",
                    response_difference=True
                )
                self.discovered_parameters.append(parameter)
                
                finding = Finding(
                    id=str(uuid4()),
                    scan_id="",
                    category="PARAMETER_FOUND",
                    owasp_category=None,
                    severity=Severity.INFO,
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    status_code=test_response.status_code,
                    response_size=len(test_response.content),
                    response_time=test_response.elapsed,
                    evidence=f"Form parameter '{param_name}' discovered - response differs from baseline",
                    recommendation="Review parameter usage and ensure proper validation",
                    payload=f"form-data: {param_name}=test_value",
                    headers=dict(test_response.headers)
                )
                findings.append(finding)
        
        return findings
    
    async def _fuzz_xml_parameters(self, endpoint: Endpoint, wordlist: List[str], 
                                 baseline_response: Response) -> List[Finding]:
        """Fuzz XML parameters (basic implementation)"""
        findings = []
        
        for param_name in wordlist[:10]:  # Limit XML testing to first 10 parameters
            self.parameters_tested += 1
            
            # Create simple XML payload
            xml_payload = f"<?xml version='1.0'?><root><{param_name}>test_value</{param_name}></root>"
            test_response = await self._test_xml_parameter(endpoint, xml_payload)
            
            if test_response and self._has_response_difference(baseline_response, test_response):
                parameter = Parameter(
                    name=param_name,
                    location="body",
                    value_type="string",
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    evidence=f"XML parameter '{param_name}' caused response difference",
                    response_difference=True
                )
                self.discovered_parameters.append(parameter)
                
                finding = Finding(
                    id=str(uuid4()),
                    scan_id="",
                    category="PARAMETER_FOUND",
                    owasp_category=None,
                    severity=Severity.INFO,
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    status_code=test_response.status_code,
                    response_size=len(test_response.content),
                    response_time=test_response.elapsed,
                    evidence=f"XML parameter '{param_name}' discovered - response differs from baseline",
                    recommendation="Review parameter usage and ensure proper validation",
                    payload=xml_payload,
                    headers=dict(test_response.headers)
                )
                findings.append(finding)
        
        return findings
    
    async def _boundary_test_parameter(self, endpoint: Endpoint, param_name: str, 
                                     location: str, baseline_response: Response) -> List[Finding]:
        """Perform boundary testing on a parameter"""
        findings = []
        
        for value_type, test_values in self.boundary_values.items():
            for test_value in test_values:
                try:
                    if location == "query":
                        test_response = await self._test_query_parameter(endpoint, param_name, test_value)
                    else:
                        # For body parameters, test as JSON
                        json_payload = {param_name: test_value}
                        test_response = await self._test_json_parameter(endpoint, json_payload)
                    
                    if test_response:
                        # Check for error responses that might indicate vulnerabilities
                        if test_response.status_code >= 500:
                            finding = Finding(
                                id=str(uuid4()),
                                scan_id="",
                                category="BOUNDARY_TEST_ERROR",
                                owasp_category=None,
                                severity=Severity.MEDIUM,
                                endpoint=endpoint.url,
                                method=endpoint.method,
                                status_code=test_response.status_code,
                                response_size=len(test_response.content),
                                response_time=test_response.elapsed,
                                evidence=f"Parameter '{param_name}' with boundary value '{test_value}' caused server error",
                                recommendation="Implement proper input validation and error handling",
                                payload=f"{param_name}={test_value}",
                                headers=dict(test_response.headers)
                            )
                            findings.append(finding)
                        
                        # Check for response time anomalies (potential DoS)
                        if test_response.elapsed > baseline_response.elapsed * 3:
                            finding = Finding(
                                id=str(uuid4()),
                                scan_id="",
                                category="TIMING_ANOMALY",
                                owasp_category=None,
                                severity=Severity.LOW,
                                endpoint=endpoint.url,
                                method=endpoint.method,
                                status_code=test_response.status_code,
                                response_size=len(test_response.content),
                                response_time=test_response.elapsed,
                                evidence=f"Parameter '{param_name}' with value '{test_value}' caused timing anomaly ({test_response.elapsed:.2f}s vs baseline {baseline_response.elapsed:.2f}s)",
                                recommendation="Review parameter processing for potential DoS vulnerabilities",
                                payload=f"{param_name}={test_value}",
                                headers=dict(test_response.headers)
                            )
                            findings.append(finding)
                
                except Exception as e:
                    self.logger.debug("Boundary test failed", 
                                    param=param_name, 
                                    value=test_value, 
                                    error=str(e))
        
        return findings
    
    async def _boundary_test_json_parameter(self, endpoint: Endpoint, param_name: str, 
                                          baseline_response: Response) -> List[Finding]:
        """Perform boundary testing on JSON parameters"""
        findings = []
        
        for value_type, test_values in self.boundary_values.items():
            for test_value in test_values:
                try:
                    json_payload = {param_name: test_value}
                    test_response = await self._test_json_parameter(endpoint, json_payload)
                    
                    if test_response:
                        # Check for server errors
                        if test_response.status_code >= 500:
                            finding = Finding(
                                id=str(uuid4()),
                                scan_id="",
                                category="JSON_BOUNDARY_ERROR",
                                owasp_category=None,
                                severity=Severity.MEDIUM,
                                endpoint=endpoint.url,
                                method=endpoint.method,
                                status_code=test_response.status_code,
                                response_size=len(test_response.content),
                                response_time=test_response.elapsed,
                                evidence=f"JSON parameter '{param_name}' with boundary value caused server error",
                                recommendation="Implement proper JSON input validation",
                                payload=json.dumps(json_payload),
                                headers=dict(test_response.headers)
                            )
                            findings.append(finding)
                
                except Exception as e:
                    self.logger.debug("JSON boundary test failed", 
                                    param=param_name, 
                                    value=test_value, 
                                    error=str(e))
        
        return findings
    
    async def _get_baseline_response(self, endpoint: Endpoint) -> Optional[Response]:
        """Get baseline response for comparison"""
        try:
            response = await self.http_client.request(endpoint.method, endpoint.url)
            self.requests_made += 1
            if response.status_code < 500:
                self.successful_requests += 1
            return response
        except Exception as e:
            self.logger.debug("Failed to get baseline response", 
                            url=endpoint.url, 
                            error=str(e))
            return None
    
    async def _test_query_parameter(self, endpoint: Endpoint, param_name: str, 
                                  param_value: Any) -> Optional[Response]:
        """Test a query parameter"""
        try:
            params = {param_name: param_value}
            response = await self.http_client.request(endpoint.method, endpoint.url, params=params)
            self.requests_made += 1
            if response.status_code < 500:
                self.successful_requests += 1
            return response
        except Exception as e:
            self.logger.debug("Query parameter test failed", 
                            param=param_name, 
                            error=str(e))
            return None
    
    async def _test_json_parameter(self, endpoint: Endpoint, json_payload: Dict[str, Any]) -> Optional[Response]:
        """Test JSON parameters"""
        try:
            headers = {'Content-Type': 'application/json'}
            response = await self.http_client.request(
                endpoint.method, 
                endpoint.url, 
                json=json_payload,
                headers=headers
            )
            self.requests_made += 1
            if response.status_code < 500:
                self.successful_requests += 1
            return response
        except Exception as e:
            self.logger.debug("JSON parameter test failed", 
                            payload=json_payload, 
                            error=str(e))
            return None
    
    async def _test_form_parameter(self, endpoint: Endpoint, form_data: Dict[str, Any]) -> Optional[Response]:
        """Test form parameters"""
        try:
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            response = await self.http_client.request(
                endpoint.method, 
                endpoint.url, 
                data=urlencode(form_data),
                headers=headers
            )
            self.requests_made += 1
            if response.status_code < 500:
                self.successful_requests += 1
            return response
        except Exception as e:
            self.logger.debug("Form parameter test failed", 
                            data=form_data, 
                            error=str(e))
            return None
    
    async def _test_xml_parameter(self, endpoint: Endpoint, xml_payload: str) -> Optional[Response]:
        """Test XML parameters"""
        try:
            headers = {'Content-Type': 'application/xml'}
            response = await self.http_client.request(
                endpoint.method, 
                endpoint.url, 
                data=xml_payload,
                headers=headers
            )
            self.requests_made += 1
            if response.status_code < 500:
                self.successful_requests += 1
            return response
        except Exception as e:
            self.logger.debug("XML parameter test failed", 
                            payload=xml_payload, 
                            error=str(e))
            return None
    
    def _has_response_difference(self, baseline: Response, test: Response) -> bool:
        """Check if test response differs significantly from baseline"""
        # Status code difference
        if baseline.status_code != test.status_code:
            return True
        
        # Significant size difference (more than 10% or 100 bytes)
        size_diff = abs(len(baseline.content) - len(test.content))
        if size_diff > max(len(baseline.content) * 0.1, 100):
            return True
        
        # Response time difference (more than 2x)
        if test.elapsed > baseline.elapsed * 2 and test.elapsed > 1.0:
            return True
        
        # Content type difference
        baseline_ct = baseline.headers.get('content-type', '').lower()
        test_ct = test.headers.get('content-type', '').lower()
        if baseline_ct != test_ct:
            return True
        
        return False
    
    async def _load_wordlist(self, wordlist_path: str) -> List[str]:
        """Load wordlist from file"""
        try:
            wordlist_file = Path(wordlist_path)
            if not wordlist_file.exists():
                self.logger.error("Wordlist file not found", path=wordlist_path)
                return []
            
            with open(wordlist_file, 'r', encoding='utf-8') as f:
                words = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        words.append(line)
            
            self.logger.debug("Wordlist loaded", path=wordlist_path, words_count=len(words))
            return words
            
        except Exception as e:
            self.logger.error("Failed to load wordlist", path=wordlist_path, error=str(e))
            return []


class HeaderFuzzer:
    """
    Header Fuzzer for testing custom headers
    
    Features:
    - Custom header fuzzing with specialized wordlists
    - Authentication bypass testing via headers
    - Admin access testing via headers (X-Admin, X-Role, etc.)
    - Response difference detection
    - Security header analysis
    """
    
    def __init__(self, http_client: HTTPRequestEngine, config: FuzzingConfig):
        self.http_client = http_client
        self.config = config
        self.logger = get_logger(__name__).bind(component="header_fuzzer")
        
        # Fuzzing state
        self.headers_tested = 0
        self.requests_made = 0
        self.successful_requests = 0
        self.discovered_headers: List[str] = []
        
        # Special header values for testing
        self.test_values = {
            'admin': ['true', '1', 'yes', 'admin', 'administrator'],
            'role': ['admin', 'administrator', 'root', 'superuser', 'manager'],
            'user': ['admin', 'root', '1', '0', 'administrator'],
            'auth': ['true', '1', 'bypass', 'admin', 'authenticated'],
            'debug': ['true', '1', 'on', 'enabled'],
            'test': ['true', '1', 'on', 'enabled', 'test', 'testing']
        }
        
        self.logger.info("Header Fuzzer initialized")
    
    async def fuzz_headers(self, endpoints: List[Endpoint]) -> List[Finding]:
        """
        Fuzz headers on discovered endpoints
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of findings from header fuzzing
        """
        self.logger.info("Starting header fuzzing", endpoints_count=len(endpoints))
        
        findings = []
        
        # Filter endpoints suitable for header fuzzing
        suitable_endpoints = [
            e for e in endpoints 
            if e.status in [EndpointStatus.VALID, EndpointStatus.AUTH_REQUIRED]
        ]
        
        for endpoint in suitable_endpoints:
            self.logger.debug("Fuzzing headers for endpoint", 
                            url=endpoint.url, 
                            method=endpoint.method)
            
            # Custom header fuzzing
            header_findings = await self._fuzz_custom_headers(endpoint)
            findings.extend(header_findings)
            
            # Admin/auth bypass header testing
            bypass_findings = await self._test_bypass_headers(endpoint)
            findings.extend(bypass_findings)
        
        self.logger.info("Header fuzzing completed",
                        headers_tested=self.headers_tested,
                        requests_made=self.requests_made,
                        findings_count=len(findings))
        
        return findings
    
    async def _fuzz_custom_headers(self, endpoint: Endpoint) -> List[Finding]:
        """Fuzz custom headers for an endpoint"""
        findings = []
        
        # Load header wordlist
        wordlist = await self._load_wordlist(self.config.headers.wordlist)
        if not wordlist:
            return findings
        
        # Get baseline response
        baseline_response = await self._get_baseline_response(endpoint)
        if not baseline_response:
            return findings
        
        # Test each header from wordlist
        for header_name in wordlist:
            self.headers_tested += 1
            
            # Test with simple value first
            test_response = await self._test_header(endpoint, header_name, "test_value")
            if test_response and self._has_response_difference(baseline_response, test_response):
                self.discovered_headers.append(header_name)
                
                finding = Finding(
                    id=str(uuid4()),
                    scan_id="",
                    category="HEADER_FOUND",
                    owasp_category=None,
                    severity=Severity.INFO,
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    status_code=test_response.status_code,
                    response_size=len(test_response.content),
                    response_time=test_response.elapsed,
                    evidence=f"Custom header '{header_name}' discovered - response differs from baseline",
                    recommendation="Review header usage and ensure proper validation",
                    payload=f"{header_name}: test_value",
                    headers=dict(test_response.headers)
                )
                findings.append(finding)
        
        return findings
    
    async def _test_bypass_headers(self, endpoint: Endpoint) -> List[Finding]:
        """Test headers for authentication/authorization bypass"""
        findings = []
        
        # Get baseline response
        baseline_response = await self._get_baseline_response(endpoint)
        if not baseline_response:
            return findings
        
        # Test admin bypass headers
        admin_headers = [
            'X-Admin', 'X-Admin-User', 'X-Is-Admin', 'X-Role', 'X-User-Role',
            'X-Privilege-Level', 'X-Access-Level', 'X-Auth-Level'
        ]
        
        for header_name in admin_headers:
            # Test different admin values
            for test_value in self.test_values.get('admin', ['true']):
                self.headers_tested += 1
                
                test_response = await self._test_header(endpoint, header_name, test_value)
                if test_response:
                    # Check for privilege escalation
                    if self._indicates_privilege_escalation(baseline_response, test_response):
                        finding = Finding(
                            id=str(uuid4()),
                            scan_id="",
                            category="HEADER_BYPASS",
                            owasp_category="API5",  # Broken Function Level Authorization
                            severity=Severity.HIGH,
                            endpoint=endpoint.url,
                            method=endpoint.method,
                            status_code=test_response.status_code,
                            response_size=len(test_response.content),
                            response_time=test_response.elapsed,
                            evidence=f"Header '{header_name}: {test_value}' may allow privilege escalation",
                            recommendation="Implement proper authorization checks that don't rely on client-controlled headers",
                            payload=f"{header_name}: {test_value}",
                            headers=dict(test_response.headers)
                        )
                        findings.append(finding)
        
        # Test authentication bypass headers
        auth_headers = [
            'X-Auth-Token', 'X-Authenticated', 'X-User-Authenticated', 'X-Bypass-Auth'
        ]
        
        for header_name in auth_headers:
            for test_value in self.test_values.get('auth', ['true']):
                self.headers_tested += 1
                
                test_response = await self._test_header(endpoint, header_name, test_value)
                if test_response:
                    # Check for authentication bypass
                    if self._indicates_auth_bypass(baseline_response, test_response):
                        finding = Finding(
                            id=str(uuid4()),
                            scan_id="",
                            category="AUTH_BYPASS_HEADER",
                            owasp_category="API2",  # Broken Authentication
                            severity=Severity.CRITICAL,
                            endpoint=endpoint.url,
                            method=endpoint.method,
                            status_code=test_response.status_code,
                            response_size=len(test_response.content),
                            response_time=test_response.elapsed,
                            evidence=f"Header '{header_name}: {test_value}' may allow authentication bypass",
                            recommendation="Remove authentication bypass mechanisms and implement proper authentication",
                            payload=f"{header_name}: {test_value}",
                            headers=dict(test_response.headers)
                        )
                        findings.append(finding)
        
        return findings
    
    async def _get_baseline_response(self, endpoint: Endpoint) -> Optional[Response]:
        """Get baseline response for comparison"""
        try:
            response = await self.http_client.request(endpoint.method, endpoint.url)
            self.requests_made += 1
            if response.status_code < 500:
                self.successful_requests += 1
            return response
        except Exception as e:
            self.logger.debug("Failed to get baseline response", 
                            url=endpoint.url, 
                            error=str(e))
            return None
    
    async def _test_header(self, endpoint: Endpoint, header_name: str, 
                         header_value: str) -> Optional[Response]:
        """Test a custom header"""
        try:
            headers = {header_name: header_value}
            response = await self.http_client.request(
                endpoint.method, 
                endpoint.url, 
                headers=headers
            )
            self.requests_made += 1
            if response.status_code < 500:
                self.successful_requests += 1
            return response
        except Exception as e:
            self.logger.debug("Header test failed", 
                            header=header_name, 
                            error=str(e))
            return None
    
    def _has_response_difference(self, baseline: Response, test: Response) -> bool:
        """Check if test response differs significantly from baseline"""
        # Status code difference
        if baseline.status_code != test.status_code:
            return True
        
        # Significant size difference (more than 10% or 100 bytes)
        size_diff = abs(len(baseline.content) - len(test.content))
        if size_diff > max(len(baseline.content) * 0.1, 100):
            return True
        
        # Response time difference (more than 2x)
        if test.elapsed > baseline.elapsed * 2 and test.elapsed > 1.0:
            return True
        
        return False
    
    def _indicates_privilege_escalation(self, baseline: Response, test: Response) -> bool:
        """Check if response indicates potential privilege escalation"""
        # Status code changed from 403/401 to 200
        if baseline.status_code in [401, 403] and test.status_code == 200:
            return True
        
        # Significant increase in response size (might indicate more data)
        if len(test.content) > len(baseline.content) * 1.5 and len(test.content) > 1000:
            return True
        
        # Look for admin-related content in response
        response_text = test.text.lower()
        admin_indicators = ['admin', 'administrator', 'dashboard', 'management', 'privileged']
        if any(indicator in response_text for indicator in admin_indicators):
            return True
        
        return False
    
    def _indicates_auth_bypass(self, baseline: Response, test: Response) -> bool:
        """Check if response indicates potential authentication bypass"""
        # Status code changed from 401 to 200
        if baseline.status_code == 401 and test.status_code == 200:
            return True
        
        # Status code changed from 403 to 200 (might be auth bypass)
        if baseline.status_code == 403 and test.status_code == 200:
            return True
        
        # Significant increase in response size
        if len(test.content) > len(baseline.content) * 2:
            return True
        
        return False
    
    async def _load_wordlist(self, wordlist_path: str) -> List[str]:
        """Load wordlist from file"""
        try:
            wordlist_file = Path(wordlist_path)
            if not wordlist_file.exists():
                self.logger.error("Wordlist file not found", path=wordlist_path)
                return []
            
            with open(wordlist_file, 'r', encoding='utf-8') as f:
                words = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        words.append(line)
            
            self.logger.debug("Wordlist loaded", path=wordlist_path, words_count=len(words))
            return words
            
        except Exception as e:
            self.logger.error("Failed to load wordlist", path=wordlist_path, error=str(e))
            return []


class FuzzingOrchestrator:
    """
    Fuzzing Orchestrator for traditional fuzzing operations
    
    Coordinates fuzzing of endpoints, parameters, and headers
    Manages wordlists and payload generation
    Handles endpoint discovery and response analysis
    """
    
    def __init__(self, config: FuzzingConfig, http_client: HTTPRequestEngine):
        """
        Initialize Fuzzing Orchestrator
        
        Args:
            config: Fuzzing configuration
            http_client: HTTP client for requests
        """
        self.config = config
        self.http_client = http_client
        self.logger = get_logger(__name__)
        self.stats = FuzzingStats()
        
        # Initialize specialized fuzzers
        self.endpoint_fuzzer = EndpointFuzzer(http_client, config)
        self.parameter_fuzzer = ParameterFuzzer(http_client, config)
        self.header_fuzzer = HeaderFuzzer(http_client, config)
        
        self.logger.info("Fuzzing Orchestrator initialized",
                        endpoint_fuzzing=config.endpoints.enabled,
                        parameter_fuzzing=config.parameters.enabled,
                        header_fuzzing=config.headers.enabled)
    
    async def discover_endpoints(self, base_url: str) -> List[Endpoint]:
        """
        Discover endpoints using wordlist fuzzing
        
        Args:
            base_url: Base URL to discover endpoints on
            
        Returns:
            List of discovered endpoints
        """
        if not self.config.endpoints.enabled:
            self.logger.info("Endpoint fuzzing disabled")
            return []
        
        self.logger.info("Starting endpoint discovery", base_url=base_url)
        
        try:
            # Use configured wordlist
            wordlist_path = self.config.endpoints.wordlist
            endpoints = await self.endpoint_fuzzer.discover_endpoints(base_url, wordlist_path)
            
            # Update statistics
            self.stats.endpoints_tested = len(self.endpoint_fuzzer.tested_urls)
            self.stats.endpoints_discovered = len(endpoints)
            self.stats.total_requests += self.stats.endpoints_tested
            self.stats.successful_requests += len([e for e in endpoints if e.status == EndpointStatus.VALID])
            self.stats.redirects_followed = len([e for e in endpoints if e.discovered_via == "redirect"])
            
            self.logger.info("Endpoint discovery completed",
                            endpoints_found=len(endpoints),
                            requests_made=self.stats.endpoints_tested,
                            success_rate=f"{self.stats.success_rate:.1f}%")
            
            return endpoints
            
        except Exception as e:
            self.logger.error("Endpoint discovery failed", error=str(e))
            return []
    
    async def fuzz_parameters(self, endpoints: List[Endpoint]) -> List[Finding]:
        """
        Fuzz parameters on discovered endpoints
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of findings from parameter fuzzing
        """
        if not self.config.parameters.enabled:
            self.logger.info("Parameter fuzzing disabled")
            return []
        
        self.logger.info("Starting parameter fuzzing", 
                        endpoints_count=len(endpoints))
        
        try:
            findings = await self.parameter_fuzzer.fuzz_parameters(endpoints)
            
            # Update statistics
            self.stats.parameters_tested = self.parameter_fuzzer.parameters_tested
            self.stats.total_requests += self.parameter_fuzzer.requests_made
            self.stats.successful_requests += self.parameter_fuzzer.successful_requests
            
            self.logger.info("Parameter fuzzing completed",
                            parameters_tested=self.stats.parameters_tested,
                            findings_count=len(findings))
            
            return findings
            
        except Exception as e:
            self.logger.error("Parameter fuzzing failed", error=str(e))
            return []
    
    async def fuzz_headers(self, endpoints: List[Endpoint]) -> List[Finding]:
        """
        Fuzz headers on discovered endpoints
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of findings from header fuzzing
        """
        if not self.config.headers.enabled:
            self.logger.info("Header fuzzing disabled")
            return []
        
        self.logger.info("Starting header fuzzing",
                        endpoints_count=len(endpoints))
        
        try:
            findings = await self.header_fuzzer.fuzz_headers(endpoints)
            
            # Update statistics
            self.stats.headers_tested = self.header_fuzzer.headers_tested
            self.stats.total_requests += self.header_fuzzer.requests_made
            self.stats.successful_requests += self.header_fuzzer.successful_requests
            
            self.logger.info("Header fuzzing completed",
                            headers_tested=self.stats.headers_tested,
                            findings_count=len(findings))
            
            return findings
            
        except Exception as e:
            self.logger.error("Header fuzzing failed", error=str(e))
            return []
    
    def get_fuzzing_statistics(self) -> FuzzingStats:
        """
        Get fuzzing execution statistics
        
        Returns:
            Current fuzzing statistics
        """
        return self.stats
    
    def get_discovered_endpoints(self) -> List[Endpoint]:
        """
        Get list of discovered endpoints
        
        Returns:
            List of discovered endpoints
        """
        return list(self.endpoint_fuzzer.discovered_endpoints.values())
    
    def get_endpoints_by_status(self, status: EndpointStatus) -> List[Endpoint]:
        """
        Get endpoints filtered by status
        
        Args:
            status: Endpoint status to filter by
            
        Returns:
            List of endpoints with specified status
        """
        return [e for e in self.get_discovered_endpoints() if e.status == status]
    
    def get_endpoints_by_type(self, endpoint_type: str) -> List[Endpoint]:
        """
        Get endpoints filtered by type
        
        Args:
            endpoint_type: Endpoint type to filter by
            
        Returns:
            List of endpoints with specified type
        """
        return [e for e in self.get_discovered_endpoints() if e.endpoint_type == endpoint_type]