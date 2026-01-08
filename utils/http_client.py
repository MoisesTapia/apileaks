"""
APILeak HTTP Request Engine
Advanced HTTP client with rate limiting, retry logic, and authentication support
"""

import asyncio
import time
import random
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
import httpx
import structlog
from urllib.parse import urljoin, urlparse

from core.config import AuthContext, AuthType, RateLimitConfig
from core.logging import get_logger


class UserAgentRotator:
    """
    User Agent rotation manager for WAF evasion
    
    Supports:
    - Random user agent selection from built-in list
    - Custom user agent string
    - User agent rotation from file list
    - Thread-safe rotation for concurrent requests
    """
    
    # Built-in user agents for random selection
    RANDOM_USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        'curl/8.4.0',
        'Postman/10.20.0'
    ]
    
    def __init__(self, mode: str = "default", custom_user_agent: str = None, user_agent_list: List[str] = None):
        """
        Initialize User Agent Rotator
        
        Args:
            mode: "default", "random", "custom", or "rotate"
            custom_user_agent: Custom user agent string (for "custom" mode)
            user_agent_list: List of user agents for rotation (for "rotate" mode)
        """
        self.mode = mode
        self.custom_user_agent = custom_user_agent
        self.user_agent_list = user_agent_list or []
        self.current_index = 0
        self.lock = threading.Lock()
        
        self.logger = get_logger(__name__).bind(component="user_agent_rotator")
        
        if mode == "rotate" and not user_agent_list:
            raise ValueError("user_agent_list is required for rotate mode")
        
        self.logger.debug("User Agent Rotator initialized", 
                         mode=mode, 
                         list_size=len(self.user_agent_list) if user_agent_list else 0)
    
    def get_user_agent(self) -> str:
        """Get the next user agent based on the configured mode"""
        if self.mode == "custom" and self.custom_user_agent:
            return self.custom_user_agent
        elif self.mode == "random":
            return random.choice(self.RANDOM_USER_AGENTS)
        elif self.mode == "rotate" and self.user_agent_list:
            with self.lock:
                user_agent = self.user_agent_list[self.current_index]
                self.current_index = (self.current_index + 1) % len(self.user_agent_list)
                return user_agent
        else:
            # Default user agent
            return "APILeak/0.1.0"


class RequestMethod(str, Enum):
    """HTTP request methods"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


@dataclass
class Request:
    """HTTP request representation"""
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, Any] = field(default_factory=dict)
    data: Optional[Union[str, bytes, Dict[str, Any]]] = None
    json: Optional[Dict[str, Any]] = None
    timeout: Optional[float] = None
    auth_context: Optional[str] = None


@dataclass
class Response:
    """HTTP response representation"""
    status_code: int
    headers: Dict[str, str]
    content: bytes
    text: str
    url: str
    elapsed: float
    request_method: str
    timestamp: datetime = field(default_factory=datetime.now)
    
    @property
    def is_success(self) -> bool:
        """Check if response indicates success (2xx status)"""
        return 200 <= self.status_code < 300
    
    @property
    def is_redirect(self) -> bool:
        """Check if response is a redirect (3xx status)"""
        return 300 <= self.status_code < 400
    
    @property
    def is_client_error(self) -> bool:
        """Check if response is a client error (4xx status)"""
        return 400 <= self.status_code < 500
    
    @property
    def is_server_error(self) -> bool:
        """Check if response is a server error (5xx status)"""
        return 500 <= self.status_code < 600


@dataclass
class RetryConfig:
    """Retry configuration"""
    max_attempts: int = 3
    backoff_factor: float = 2.0
    max_backoff: float = 60.0
    retry_on_status: List[int] = field(default_factory=lambda: [429, 502, 503, 504])
    retry_on_timeout: bool = True


@dataclass
class PerformanceMetrics:
    """HTTP client performance metrics"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_response_time: float = 0.0
    min_response_time: float = float('inf')
    max_response_time: float = 0.0
    rate_limited_requests: int = 0
    retried_requests: int = 0
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate percentage"""
        if self.total_requests == 0:
            return 0.0
        return (self.successful_requests / self.total_requests) * 100
    
    @property
    def average_response_time(self) -> float:
        """Calculate average response time"""
        if self.total_requests == 0:
            return 0.0
        return self.total_response_time / self.total_requests


class RateLimiter:
    """
    Adaptive rate limiter with exponential backoff and Retry-After header support
    
    Features:
    - Configurable requests per second
    - Burst capacity
    - Adaptive throttling based on server responses
    - Retry-After header respect
    - Exponential backoff on rate limiting
    """
    
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.logger = get_logger(__name__).bind(component="rate_limiter")
        
        # Rate limiting state
        self.tokens = float(config.burst_size)
        self.last_update = time.time()
        self.requests_this_second = 0
        self.current_second = int(time.time())
        
        # Adaptive throttling state
        self.current_rps = float(config.requests_per_second)
        self.consecutive_rate_limits = 0
        self.last_rate_limit_time = 0.0
        
        # Backoff state
        self.backoff_until = 0.0
        
        self.logger.info("Rate limiter initialized",
                        rps=config.requests_per_second,
                        burst_size=config.burst_size,
                        adaptive=config.adaptive)
    
    async def acquire(self) -> None:
        """
        Acquire permission to make a request
        
        This method implements token bucket algorithm with adaptive throttling
        """
        current_time = time.time()
        
        # Check if we're in backoff period
        if current_time < self.backoff_until:
            wait_time = self.backoff_until - current_time
            self.logger.debug("Waiting for backoff period", wait_time=wait_time)
            await asyncio.sleep(wait_time)
            current_time = time.time()
        
        # Update token bucket
        await self._update_tokens(current_time)
        
        # Wait if no tokens available
        if self.tokens < 1.0:
            wait_time = 1.0 / self.current_rps
            self.logger.debug("Rate limit reached, waiting", wait_time=wait_time)
            await asyncio.sleep(wait_time)
            await self._update_tokens(time.time())
        
        # Consume token
        self.tokens -= 1.0
        self.requests_this_second += 1
        
        self.logger.debug("Request permission acquired",
                         tokens_remaining=self.tokens,
                         current_rps=self.current_rps)
    
    async def _update_tokens(self, current_time: float) -> None:
        """Update token bucket based on elapsed time"""
        time_passed = current_time - self.last_update
        self.last_update = current_time
        
        # Add tokens based on configured rate
        tokens_to_add = time_passed * self.current_rps
        self.tokens = min(self.config.burst_size, self.tokens + tokens_to_add)
        
        # Reset per-second counter if needed
        current_second = int(current_time)
        if current_second != self.current_second:
            self.current_second = current_second
            self.requests_this_second = 0
    
    async def handle_rate_limit_response(self, response: Response) -> None:
        """
        Handle rate limiting response from server
        
        Args:
            response: HTTP response that indicates rate limiting
        """
        self.consecutive_rate_limits += 1
        self.last_rate_limit_time = time.time()
        
        self.logger.warning("Rate limit detected",
                           status_code=response.status_code,
                           consecutive_limits=self.consecutive_rate_limits)
        
        # Check for Retry-After header
        retry_after = None
        if self.config.respect_retry_after:
            retry_after_header = response.headers.get('Retry-After') or response.headers.get('retry-after')
            if retry_after_header:
                try:
                    retry_after = float(retry_after_header)
                    self.logger.info("Respecting Retry-After header", retry_after=retry_after)
                except ValueError:
                    # Retry-After might be a date, but we'll ignore that for now
                    pass
        
        # Calculate backoff time
        if retry_after:
            backoff_time = retry_after
        else:
            # Exponential backoff
            backoff_time = min(
                self.config.backoff_factor ** (self.consecutive_rate_limits - 1),
                60.0  # Max 60 seconds backoff
            )
        
        self.backoff_until = time.time() + backoff_time
        
        # Adaptive throttling - reduce RPS if enabled
        if self.config.adaptive and self.consecutive_rate_limits >= 2:
            old_rps = self.current_rps
            self.current_rps = max(1.0, self.current_rps * 0.5)  # Halve the rate
            self.logger.info("Adaptive throttling activated",
                           old_rps=old_rps,
                           new_rps=self.current_rps)
    
    def reset_rate_limit_state(self) -> None:
        """Reset rate limiting state after successful requests"""
        if self.consecutive_rate_limits > 0:
            self.consecutive_rate_limits = 0
            
            # Gradually restore original RPS if adaptive
            if self.config.adaptive and self.current_rps < self.config.requests_per_second:
                self.current_rps = min(
                    self.config.requests_per_second,
                    self.current_rps * 1.2  # Increase by 20%
                )
                self.logger.debug("Restoring RPS after successful requests",
                                current_rps=self.current_rps)


class HTTPRequestEngine:
    """
    Advanced HTTP request engine with rate limiting, retry logic, and authentication
    
    Features:
    - Async HTTP client with connection pooling
    - Adaptive rate limiting with backoff
    - Configurable retry logic
    - Multiple authentication methods support
    - User agent rotation for WAF evasion
    - Performance metrics tracking
    - Health check capabilities
    """
    
    def __init__(self, rate_limiter: RateLimiter, retry_config: RetryConfig, 
                 timeout: float = 30.0, verify_ssl: bool = True, user_agent_rotator: UserAgentRotator = None,
                 status_code_filter: List[int] = None):
        self.rate_limiter = rate_limiter
        self.retry_config = retry_config
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.user_agent_rotator = user_agent_rotator or UserAgentRotator()
        self.status_code_filter = status_code_filter  # Filter for status codes to display
        
        self.logger = get_logger(__name__).bind(component="http_engine")
        self.metrics = PerformanceMetrics()
        
        # Authentication contexts
        self.auth_contexts: Dict[str, AuthContext] = {}
        self.current_auth_context: Optional[AuthContext] = None
        
        # HTTP client (will be initialized in async context)
        self.client: Optional[httpx.AsyncClient] = None
        self._client_initialized = False
        
        self.logger.info("HTTP Request Engine initialized",
                        timeout=timeout,
                        verify_ssl=verify_ssl,
                        max_retries=retry_config.max_attempts,
                        user_agent_mode=self.user_agent_rotator.mode,
                        status_code_filter=status_code_filter)
    
    async def _ensure_client(self) -> None:
        """Ensure HTTP client is initialized"""
        if not self._client_initialized:
            # Disable httpx logging to avoid duplicate request logs
            import logging
            logging.getLogger("httpx").setLevel(logging.WARNING)
            
            # Connection limits for performance
            limits = httpx.Limits(
                max_keepalive_connections=20,
                max_connections=100,
                keepalive_expiry=30.0
            )
            
            # Timeout configuration
            timeout = httpx.Timeout(
                connect=10.0,
                read=self.timeout,
                write=10.0,
                pool=5.0
            )
            
            self.client = httpx.AsyncClient(
                limits=limits,
                timeout=timeout,
                verify=self.verify_ssl,
                follow_redirects=False,  # We'll handle redirects manually
                http2=False  # Disable HTTP/2 to avoid h2 dependency
            )
            
            self._client_initialized = True
            self.logger.debug("HTTP client initialized")
    
    async def request(self, method: str, url: str, **kwargs) -> Response:
        """
        Make a single HTTP request with rate limiting and retry logic
        
        Args:
            method: HTTP method
            url: Request URL
            **kwargs: Additional request parameters
            
        Returns:
            Response object
            
        Raises:
            httpx.RequestError: On request failure after all retries
        """
        await self._ensure_client()
        
        # Create request object
        request = Request(
            method=method.upper(),
            url=url,
            headers=kwargs.get('headers', {}),
            params=kwargs.get('params', {}),
            data=kwargs.get('data'),
            json=kwargs.get('json'),
            timeout=kwargs.get('timeout'),
            auth_context=kwargs.get('auth_context')
        )
        
        # Apply user agent rotation if not already set
        if 'User-Agent' not in request.headers:
            request.headers['User-Agent'] = self.user_agent_rotator.get_user_agent()
        
        # Apply authentication if specified
        if request.auth_context and request.auth_context in self.auth_contexts:
            self._apply_authentication(request, self.auth_contexts[request.auth_context])
        elif self.current_auth_context:
            self._apply_authentication(request, self.current_auth_context)
        
        # Execute request with retry logic
        return await self._execute_with_retry(request)
    
    async def batch_request(self, requests: List[Request]) -> List[Response]:
        """
        Execute multiple requests concurrently with rate limiting
        
        Args:
            requests: List of Request objects
            
        Returns:
            List of Response objects in same order as input
        """
        await self._ensure_client()
        
        self.logger.info("Executing batch requests", count=len(requests))
        
        # Create semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(10)  # Max 10 concurrent requests
        
        async def _execute_single(req: Request) -> Response:
            async with semaphore:
                return await self._execute_with_retry(req)
        
        # Execute all requests concurrently
        tasks = [_execute_single(req) for req in requests]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Convert exceptions to error responses
        result = []
        for i, response in enumerate(responses):
            if isinstance(response, Exception):
                self.logger.error("Batch request failed", 
                                request_index=i, 
                                error=str(response))
                # Create error response
                error_response = Response(
                    status_code=0,
                    headers={},
                    content=b'',
                    text=str(response),
                    url=requests[i].url,
                    elapsed=0.0,
                    request_method=requests[i].method
                )
                result.append(error_response)
            else:
                result.append(response)
        
        return result
    
    async def _execute_with_retry(self, request: Request) -> Response:
        """Execute request with retry logic"""
        last_exception = None
        
        for attempt in range(self.retry_config.max_attempts):
            try:
                # Rate limiting
                await self.rate_limiter.acquire()
                
                # Execute request
                start_time = time.time()
                
                # Prepare httpx request parameters
                request_kwargs = {
                    'headers': request.headers,
                    'params': request.params,
                    'timeout': request.timeout or self.timeout
                }
                
                if request.data is not None:
                    request_kwargs['content'] = request.data
                if request.json is not None:
                    request_kwargs['json'] = request.json
                
                # Make the request
                httpx_response = await self.client.request(
                    method=request.method,
                    url=request.url,
                    **request_kwargs
                )
                
                elapsed = time.time() - start_time
                
                # Create response object
                response = Response(
                    status_code=httpx_response.status_code,
                    headers=dict(httpx_response.headers),
                    content=httpx_response.content,
                    text=httpx_response.text,
                    url=str(httpx_response.url),
                    elapsed=elapsed,
                    request_method=request.method
                )
                
                # Log colored HTTP request (always shown, regardless of log level)
                self._log_colored_request(request.method, request.url, response.status_code, self.status_code_filter)
                
                # Update metrics
                self._update_metrics(response, elapsed)
                
                # Handle rate limiting response
                if response.status_code == 429:
                    await self.rate_limiter.handle_rate_limit_response(response)
                    self.metrics.rate_limited_requests += 1
                    
                    # Retry if not last attempt
                    if attempt < self.retry_config.max_attempts - 1:
                        self.metrics.retried_requests += 1
                        continue
                else:
                    # Reset rate limit state on successful response
                    self.rate_limiter.reset_rate_limit_state()
                
                # Check if we should retry based on status code
                if (response.status_code in self.retry_config.retry_on_status and 
                    attempt < self.retry_config.max_attempts - 1):
                    
                    backoff_time = self.retry_config.backoff_factor ** attempt
                    backoff_time = min(backoff_time, self.retry_config.max_backoff)
                    
                    self.logger.debug("Retrying request due to status code",
                                    status_code=response.status_code,
                                    attempt=attempt + 1,
                                    backoff_time=backoff_time)
                    
                    self.metrics.retried_requests += 1
                    await asyncio.sleep(backoff_time)
                    continue
                
                return response
                
            except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError) as e:
                last_exception = e
                self.logger.warning("Request failed",
                                  url=request.url,
                                  attempt=attempt + 1,
                                  error=str(e))
                
                # Retry on timeout if configured
                if (self.retry_config.retry_on_timeout and 
                    attempt < self.retry_config.max_attempts - 1):
                    
                    backoff_time = self.retry_config.backoff_factor ** attempt
                    backoff_time = min(backoff_time, self.retry_config.max_backoff)
                    
                    self.metrics.retried_requests += 1
                    await asyncio.sleep(backoff_time)
                    continue
                
                # Update metrics for failed request
                self.metrics.total_requests += 1
                self.metrics.failed_requests += 1
                
                # Create error response for last attempt
                if attempt == self.retry_config.max_attempts - 1:
                    error_response = Response(
                        status_code=0,
                        headers={},
                        content=b'',
                        text=str(e),
                        url=request.url,
                        elapsed=0.0,
                        request_method=request.method
                    )
                    
                    # Log failed request (always shown, regardless of log level)
                    self._log_colored_request(request.method, request.url, 0, self.status_code_filter)
                    
                    return error_response
        
        # This should not be reached, but just in case
        raise last_exception or Exception("Request failed after all retries")
    
    def _apply_authentication(self, request: Request, auth_context: AuthContext) -> None:
        """Apply authentication to request based on auth context"""
        if auth_context.type == AuthType.BEARER:
            request.headers['Authorization'] = f'Bearer {auth_context.token}'
        
        elif auth_context.type == AuthType.BASIC:
            if auth_context.username and auth_context.password:
                import base64
                credentials = f"{auth_context.username}:{auth_context.password}"
                encoded = base64.b64encode(credentials.encode()).decode()
                request.headers['Authorization'] = f'Basic {encoded}'
        
        elif auth_context.type == AuthType.API_KEY:
            # API key can be in header or query param
            if 'X-API-Key' not in request.headers:
                request.headers['X-API-Key'] = auth_context.token
        
        elif auth_context.type == AuthType.JWT:
            request.headers['Authorization'] = f'Bearer {auth_context.token}'
        
        # Add any additional headers from auth context
        request.headers.update(auth_context.headers)
        
        self.logger.debug("Authentication applied",
                         auth_type=auth_context.type.value,
                         auth_name=auth_context.name)
    
    def _update_metrics(self, response: Response, elapsed: float) -> None:
        """Update performance metrics"""
        self.metrics.total_requests += 1
        self.metrics.total_response_time += elapsed
        
        if response.is_success:
            self.metrics.successful_requests += 1
        else:
            self.metrics.failed_requests += 1
        
        # Update min/max response times
        self.metrics.min_response_time = min(self.metrics.min_response_time, elapsed)
        self.metrics.max_response_time = max(self.metrics.max_response_time, elapsed)
    
    def _log_colored_request(self, method: str, url: str, status_code: int, status_code_filter: List[int] = None) -> None:
        """Log HTTP request with colored status indicators"""
        # Check if we should filter by status code
        if status_code_filter and status_code not in status_code_filter:
            return  # Skip this request if it doesn't match the filter
        
        # ANSI color codes
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        GRAY = '\033[90m'
        RED = '\033[91m'
        RESET = '\033[0m'
        
        # Determine color and symbol based on status code
        if status_code == 0:
            color = RED
            symbol = "[x]"
            status_message = "CONNECTION ERROR"
        elif 200 <= status_code < 300:
            color = GREEN
            symbol = "[+]"
        elif 300 <= status_code < 400:
            color = YELLOW
            symbol = "[-]"
        elif 400 <= status_code < 500:
            color = GRAY
            symbol = "[*]"
        elif 500 <= status_code < 600:
            color = RED
            symbol = "[x]"
        else:
            color = GRAY
            symbol = "[?]"
        
        # Format the HTTP status message (only if not connection error)
        if status_code != 0:
            status_messages = {
                200: "200 OK",
                201: "201 CREATED",
                204: "204 NO CONTENT",
                301: "301 MOVED PERMANENTLY",
                302: "302 FOUND",
                304: "304 NOT MODIFIED",
                400: "400 BAD REQUEST",
                401: "401 UNAUTHORIZED",
                403: "403 FORBIDDEN",
                404: "404 NOT FOUND",
                405: "405 METHOD NOT ALLOWED",
                429: "429 TOO MANY REQUESTS",
                500: "500 INTERNAL SERVER ERROR",
                502: "502 BAD GATEWAY",
                503: "503 SERVICE UNAVAILABLE",
                504: "504 GATEWAY TIMEOUT"
            }
            
            status_message = status_messages.get(status_code, f"{status_code}")
        
        # Print colored request log directly to stdout (bypassing structlog)
        # This ensures it always shows regardless of log level
        if status_code == 0:
            print(f"{color}{symbol} HTTP Request: {method} {url} \"{status_message}\"{RESET}", flush=True)
        else:
            print(f"{color}{symbol} HTTP Request: {method} {url} \"HTTP/1.1 {status_message}\"{RESET}", flush=True)
    
    
    
    
    def set_auth_context(self, auth: AuthContext) -> None:
        """
        Set current authentication context
        
        Args:
            auth: Authentication context to use for requests
        """
        self.current_auth_context = auth
        self.logger.info("Authentication context set",
                        auth_name=auth.name,
                        auth_type=auth.type.value,
                        privilege_level=auth.privilege_level)
    
    def add_auth_context(self, name: str, auth: AuthContext) -> None:
        """
        Add named authentication context
        
        Args:
            name: Name for the auth context
            auth: Authentication context
        """
        self.auth_contexts[name] = auth
        self.logger.debug("Authentication context added", name=name)
    
    def get_performance_metrics(self) -> PerformanceMetrics:
        """Get current performance metrics"""
        return self.metrics
    
    async def health_check(self) -> bool:
        """
        Perform health check by making a simple request
        
        Returns:
            True if healthy, False otherwise
        """
        try:
            await self._ensure_client()
            
            # Make a simple HEAD request to a reliable endpoint
            response = await self.request('HEAD', 'https://httpbin.org/status/200')
            return response.status_code == 200
            
        except Exception as e:
            self.logger.error("Health check failed", error=str(e))
            return False
    
    async def close(self) -> None:
        """Close HTTP client and cleanup resources"""
        if self.client:
            await self.client.aclose()
            self._client_initialized = False
            self.logger.debug("HTTP client closed")
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self._ensure_client()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()