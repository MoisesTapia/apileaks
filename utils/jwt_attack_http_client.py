"""
JWT Attack HTTP Client
Specialized HTTP client for JWT attack testing with custom header support
"""

import asyncio
import time
from typing import Dict, Optional
import httpx
from urllib.parse import urljoin

from core.logging import get_logger
from .jwt_attack_models import RequestDetails, ResponseDetails


class JWTAttackHTTPClient:
    """
    HTTP client specialized for JWT attack testing
    
    Features:
    - JWT token injection in Authorization header
    - Custom header support
    - POST data handling
    - Timeout and retry logic
    - Response analysis for attack detection
    """
    
    def __init__(self, base_url: str, custom_headers: Dict[str, str] = None, 
                 timeout: int = 30, verify_ssl: bool = True, max_retries: int = 3):
        """
        Initialize JWT attack HTTP client
        
        Args:
            base_url: Target URL for attacks
            custom_headers: Additional headers to include in requests
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            max_retries: Maximum number of retry attempts
        """
        self.base_url = base_url
        self.custom_headers = custom_headers or {}
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_retries = max_retries
        
        self.logger = get_logger(__name__).bind(component="jwt_attack_http_client")
        
        # HTTP client will be initialized in async context
        self.client: Optional[httpx.AsyncClient] = None
        self._client_initialized = False
        
        self.logger.info("JWT Attack HTTP Client initialized",
                        base_url=base_url,
                        timeout=timeout,
                        verify_ssl=verify_ssl,
                        custom_headers_count=len(self.custom_headers))
    
    async def _ensure_client(self) -> None:
        """Ensure HTTP client is initialized"""
        if not self._client_initialized:
            # Connection limits for performance
            limits = httpx.Limits(
                max_keepalive_connections=10,
                max_connections=20,
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
                follow_redirects=False  # Handle redirects manually for analysis
            )
            
            self._client_initialized = True
            self.logger.debug("HTTP client initialized")
    
    def build_headers(self, jwt_token: str, method: str = "GET", has_body: bool = False) -> Dict[str, str]:
        """
        Build complete headers including JWT and custom headers
        
        Args:
            jwt_token: JWT token to include in Authorization header
            method: HTTP method being used
            has_body: Whether the request has a body
            
        Returns:
            Complete headers dictionary
        """
        headers = {
            'Authorization': f'Bearer {jwt_token}',
            'User-Agent': 'APILeak-JWT-Attack-Tester/0.1.0',
            'Accept': 'application/json'
        }
        
        # Only set Content-Type for requests with bodies
        if has_body and method.upper() in ['POST', 'PUT', 'PATCH']:
            headers['Content-Type'] = 'application/json'
        
        # Add custom headers (they can override defaults)
        headers.update(self.custom_headers)
        
        return headers
    
    async def send_attack_request(self, jwt_token: str, post_data: str = None, 
                                 method: str = "GET") -> tuple[RequestDetails, ResponseDetails]:
        """
        Send HTTP request with attack JWT token
        
        Args:
            jwt_token: Malicious JWT token to test
            post_data: Optional POST data for request body
            method: HTTP method to use (GET, POST, PUT, etc.)
            
        Returns:
            Tuple of (RequestDetails, ResponseDetails)
        """
        await self._ensure_client()
        
        method = method.upper()
        has_body = post_data is not None
        headers = self.build_headers(jwt_token, method, has_body)
        
        # Prepare request parameters
        request_kwargs = {
            'headers': headers,
            'timeout': self.timeout
        }
        
        # Handle different content types for POST data
        if post_data and method in ['POST', 'PUT', 'PATCH']:
            # Try to determine if it's JSON or form data
            try:
                import json
                json.loads(post_data)
                # It's valid JSON
                request_kwargs['json'] = json.loads(post_data)
                headers['Content-Type'] = 'application/json'
            except (json.JSONDecodeError, ValueError):
                # Treat as form data or plain text
                request_kwargs['content'] = post_data
                # Don't override if Content-Type is already set in custom headers
                if 'Content-Type' not in self.custom_headers:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
        
        # Create request details for logging
        request_details = RequestDetails(
            url=self.base_url,
            method=method,
            headers=headers.copy(),
            body=post_data
        )
        
        # Execute request with retry logic
        response_details = await self._execute_with_retry(method, self.base_url, **request_kwargs)
        
        return request_details, response_details
    
    async def send_baseline_request(self, jwt_token: str, post_data: str = None, 
                                   method: str = "GET") -> tuple[RequestDetails, ResponseDetails]:
        """
        Send baseline request with original token to establish baseline behavior
        
        Args:
            jwt_token: Original JWT token for baseline
            post_data: Optional POST data for request body
            method: HTTP method to use
            
        Returns:
            Tuple of (RequestDetails, ResponseDetails)
        """
        self.logger.info("Sending baseline request",
                        method=method,
                        url=self.base_url,
                        has_post_data=post_data is not None)
        
        try:
            request_details, response_details = await self.send_attack_request(
                jwt_token, post_data, method
            )
            
            self.logger.info("Baseline request completed successfully",
                           status_code=response_details.status_code,
                           response_time=response_details.response_time,
                           content_length=response_details.content_length)
            
            return request_details, response_details
            
        except Exception as e:
            self.logger.error("Baseline request failed",
                            error=str(e),
                            error_type=type(e).__name__)
            
            # Create error request details
            error_request_details = RequestDetails(
                url=self.base_url,
                method=method.upper(),
                headers=self.build_headers(jwt_token, method, post_data is not None),
                body=post_data
            )
            
            # Create error response details
            error_response_details = ResponseDetails(
                status_code=0,
                headers={},
                body=f"Baseline request failed: {str(e)}",
                response_time=0.0,
                content_length=0
            )
            
            return error_request_details, error_response_details
    
    async def _execute_with_retry(self, method: str, url: str, **kwargs) -> ResponseDetails:
        """
        Execute HTTP request with retry logic and exponential backoff
        
        Args:
            method: HTTP method
            url: Request URL
            **kwargs: Request parameters
            
        Returns:
            ResponseDetails object
        """
        last_exception = None
        
        for attempt in range(self.max_retries):
            try:
                start_time = time.time()
                
                # Make the request
                response = await self.client.request(method, url, **kwargs)
                
                elapsed = time.time() - start_time
                
                # Create response details
                response_details = ResponseDetails(
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=response.text,
                    response_time=elapsed,
                    content_length=len(response.content)
                )
                
                self.logger.debug("Request completed",
                                method=method,
                                url=url,
                                status_code=response.status_code,
                                response_time=elapsed,
                                attempt=attempt + 1)
                
                return response_details
                
            except httpx.TimeoutException as e:
                last_exception = e
                self.logger.warning("Request timeout",
                                  url=url,
                                  method=method,
                                  attempt=attempt + 1,
                                  timeout=self.timeout,
                                  error=str(e))
                
                # Retry with exponential backoff for timeouts
                if attempt < self.max_retries - 1:
                    backoff_time = min(2.0 ** attempt, 30.0)  # Cap at 30 seconds
                    self.logger.info("Retrying request after timeout",
                                   backoff_time=backoff_time,
                                   attempt=attempt + 2)
                    await asyncio.sleep(backoff_time)
                    continue
                    
            except httpx.ConnectError as e:
                last_exception = e
                self.logger.warning("Connection error",
                                  url=url,
                                  method=method,
                                  attempt=attempt + 1,
                                  error=str(e))
                
                # Retry with exponential backoff for connection errors
                if attempt < self.max_retries - 1:
                    backoff_time = min(2.0 ** attempt, 30.0)  # Cap at 30 seconds
                    self.logger.info("Retrying request after connection error",
                                   backoff_time=backoff_time,
                                   attempt=attempt + 2)
                    await asyncio.sleep(backoff_time)
                    continue
                    
            except httpx.ReadError as e:
                last_exception = e
                self.logger.warning("Read error",
                                  url=url,
                                  method=method,
                                  attempt=attempt + 1,
                                  error=str(e))
                
                # Retry with exponential backoff for read errors
                if attempt < self.max_retries - 1:
                    backoff_time = min(2.0 ** attempt, 30.0)  # Cap at 30 seconds
                    self.logger.info("Retrying request after read error",
                                   backoff_time=backoff_time,
                                   attempt=attempt + 2)
                    await asyncio.sleep(backoff_time)
                    continue
                    
            except Exception as e:
                # Handle any other unexpected errors
                last_exception = e
                self.logger.error("Unexpected error during request",
                                url=url,
                                method=method,
                                attempt=attempt + 1,
                                error=str(e),
                                error_type=type(e).__name__)
                
                # Don't retry for unexpected errors, fail immediately
                break
        
        # Create error response for failed request
        error_response = ResponseDetails(
            status_code=0,
            headers={},
            body=f"Request failed after {self.max_retries} attempts: {str(last_exception)}",
            response_time=0.0,
            content_length=0
        )
        
        self.logger.error("Request failed after all retries",
                        url=url,
                        method=method,
                        max_retries=self.max_retries,
                        final_error=str(last_exception))
        
        return error_response
    
    async def test_connectivity(self) -> bool:
        """
        Test connectivity to target URL with comprehensive error handling
        
        Returns:
            True if target is reachable, False otherwise
        """
        try:
            await self._ensure_client()
            
            self.logger.info("Testing connectivity to target URL", url=self.base_url)
            
            # Try multiple methods to test connectivity
            methods_to_try = ['HEAD', 'GET', 'OPTIONS']
            
            for method in methods_to_try:
                try:
                    response = await self.client.request(
                        method, 
                        self.base_url, 
                        timeout=10.0,
                        headers={'User-Agent': 'APILeak-JWT-Attack-Tester/0.1.0'}
                    )
                    
                    self.logger.info("Connectivity test successful",
                                   method=method,
                                   status_code=response.status_code,
                                   reachable=True)
                    
                    return True
                    
                except httpx.HTTPStatusError:
                    # HTTP errors (4xx, 5xx) still mean the server is reachable
                    self.logger.info("Connectivity test successful (HTTP error response)",
                                   method=method,
                                   reachable=True)
                    return True
                    
                except (httpx.TimeoutException, httpx.ConnectError) as e:
                    self.logger.debug("Connectivity test failed for method",
                                    method=method,
                                    error=str(e))
                    continue  # Try next method
            
            # All methods failed
            self.logger.error("Connectivity test failed - target unreachable",
                            url=self.base_url,
                            reachable=False)
            return False
            
        except Exception as e:
            self.logger.error("Connectivity test failed with unexpected error",
                            error=str(e),
                            error_type=type(e).__name__,
                            reachable=False)
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