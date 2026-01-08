"""
Adaptive Throttling and Rate Limit Detection Module
Automatically detects rate limits and adjusts request rates
"""

import asyncio
import time
import random
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
import statistics

from core.logging import get_logger


class ThrottleStrategy(str, Enum):
    """Throttling strategies"""
    FIXED = "fixed"
    ADAPTIVE = "adaptive"
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    BURST_THEN_THROTTLE = "burst_then_throttle"


class RateLimitType(str, Enum):
    """Types of rate limiting detected"""
    REQUESTS_PER_SECOND = "requests_per_second"
    REQUESTS_PER_MINUTE = "requests_per_minute"
    REQUESTS_PER_HOUR = "requests_per_hour"
    CONCURRENT_CONNECTIONS = "concurrent_connections"
    BURST_LIMIT = "burst_limit"
    UNKNOWN = "unknown"


@dataclass
class RateLimitInfo:
    """Rate limit detection information"""
    detected: bool = False
    limit_type: Optional[RateLimitType] = None
    limit_value: Optional[int] = None
    window_size: Optional[int] = None  # in seconds
    reset_time: Optional[int] = None  # timestamp when limit resets
    retry_after: Optional[int] = None  # seconds to wait
    detection_confidence: float = 0.0
    detection_method: str = ""
    headers_found: Dict[str, str] = field(default_factory=dict)


@dataclass
class ThrottleState:
    """Current throttling state"""
    current_rate: float  # requests per second
    strategy: ThrottleStrategy
    backoff_multiplier: float = 1.0
    consecutive_rate_limits: int = 0
    last_rate_limit_time: Optional[float] = None
    success_streak: int = 0
    total_requests: int = 0
    rate_limited_requests: int = 0


@dataclass
class RequestMetrics:
    """Request performance metrics"""
    timestamp: float
    response_time: float
    status_code: int
    rate_limited: bool
    success: bool


class UserAgentRotator:
    """Rotates user agents to avoid detection"""
    
    def __init__(self):
        self.user_agents = [
            # Chrome
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            
            # Firefox
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            
            # Safari
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
            
            # Edge
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            
            # API clients
            "curl/8.4.0",
            "HTTPie/3.2.2",
            "Postman/10.20.0",
            "insomnia/2023.8.0",
            
            # Security tools (sometimes needed)
            "Nmap Scripting Engine",
            "sqlmap/1.7.11",
            "Burp Suite Professional",
        ]
        self.current_index = 0
    
    def get_next_user_agent(self) -> str:
        """Get next user agent in rotation"""
        user_agent = self.user_agents[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.user_agents)
        return user_agent
    
    def get_random_user_agent(self) -> str:
        """Get random user agent"""
        return random.choice(self.user_agents)


class RateLimitDetector:
    """
    Detects rate limiting patterns and characteristics
    """
    
    def __init__(self):
        """Initialize rate limit detector"""
        self.logger = get_logger("rate_limit_detector")
        self.detection_history: List[RequestMetrics] = []
        self.rate_limit_headers = [
            # Standard headers
            "x-ratelimit-limit",
            "x-ratelimit-remaining", 
            "x-ratelimit-reset",
            "x-rate-limit-limit",
            "x-rate-limit-remaining",
            "x-rate-limit-reset",
            
            # Provider-specific headers
            "retry-after",
            "x-retry-after",
            "ratelimit-limit",
            "ratelimit-remaining",
            "ratelimit-reset",
            
            # GitHub
            "x-github-request-id",
            "x-ratelimit-resource",
            
            # Twitter/X
            "x-rate-limit-reset-time",
            
            # Cloudflare
            "cf-ray",
            
            # AWS
            "x-amzn-requestid",
        ]
    
    async def detect_rate_limits(self, http_client, target_url: str, 
                                test_requests: int = 20) -> RateLimitInfo:
        """
        Detect rate limiting by analyzing response patterns
        
        Args:
            http_client: HTTP client instance
            target_url: Target URL to test
            test_requests: Number of test requests to send
            
        Returns:
            Rate limit information
        """
        self.logger.info(f"Starting rate limit detection for {target_url}")
        
        # Clear previous detection history
        self.detection_history.clear()
        
        # Phase 1: Baseline requests (slow)
        baseline_info = await self._baseline_detection(http_client, target_url)
        
        # Phase 2: Burst testing
        burst_info = await self._burst_detection(http_client, target_url, test_requests)
        
        # Phase 3: Header analysis
        header_info = await self._header_analysis(http_client, target_url)
        
        # Combine results
        final_info = self._combine_detection_results([baseline_info, burst_info, header_info])
        
        if final_info.detected:
            self.logger.info(
                f"Rate limiting detected",
                limit_type=final_info.limit_type.value if final_info.limit_type else "unknown",
                limit_value=final_info.limit_value,
                confidence=final_info.detection_confidence
            )
        else:
            self.logger.info("No rate limiting detected")
        
        return final_info
    
    async def _baseline_detection(self, http_client, target_url: str) -> RateLimitInfo:
        """Baseline detection with slow requests"""
        try:
            for i in range(5):
                start_time = time.time()
                
                try:
                    response = await http_client.request("GET", target_url)
                    response_time = time.time() - start_time
                    
                    metrics = RequestMetrics(
                        timestamp=start_time,
                        response_time=response_time,
                        status_code=response.status_code,
                        rate_limited=response.status_code in [429, 503],
                        success=200 <= response.status_code < 300
                    )
                    self.detection_history.append(metrics)
                    
                    # Check for rate limit headers
                    rate_limit_info = self._analyze_rate_limit_headers(response.headers)
                    if rate_limit_info.detected:
                        return rate_limit_info
                
                except Exception as e:
                    self.logger.debug(f"Request failed during baseline: {e}")
                
                # Wait between requests
                await asyncio.sleep(2)
        
        except Exception as e:
            self.logger.error(f"Error in baseline detection: {e}")
        
        return RateLimitInfo(detected=False)
    
    async def _burst_detection(self, http_client, target_url: str, 
                              test_requests: int) -> RateLimitInfo:
        """Burst detection with rapid requests"""
        try:
            rate_limited_count = 0
            start_time = time.time()
            
            # Send rapid requests
            for i in range(test_requests):
                request_start = time.time()
                
                try:
                    response = await http_client.request("GET", target_url)
                    response_time = time.time() - request_start
                    
                    is_rate_limited = response.status_code in [429, 503, 502]
                    if is_rate_limited:
                        rate_limited_count += 1
                    
                    metrics = RequestMetrics(
                        timestamp=request_start,
                        response_time=response_time,
                        status_code=response.status_code,
                        rate_limited=is_rate_limited,
                        success=200 <= response.status_code < 300
                    )
                    self.detection_history.append(metrics)
                    
                    # If we get rate limited, analyze the response
                    if is_rate_limited:
                        rate_limit_info = self._analyze_rate_limit_headers(response.headers)
                        if rate_limit_info.detected:
                            rate_limit_info.detection_method = "burst_testing"
                            return rate_limit_info
                
                except Exception as e:
                    self.logger.debug(f"Request failed during burst: {e}")
                    # Connection errors might indicate rate limiting
                    if "connection" in str(e).lower() or "timeout" in str(e).lower():
                        rate_limited_count += 1
                
                # Small delay to avoid overwhelming
                await asyncio.sleep(0.1)
            
            total_time = time.time() - start_time
            
            # Analyze burst results
            if rate_limited_count > 0:
                # Calculate approximate rate limit
                successful_requests = test_requests - rate_limited_count
                if successful_requests > 0:
                    estimated_rate = successful_requests / total_time
                    
                    return RateLimitInfo(
                        detected=True,
                        limit_type=RateLimitType.REQUESTS_PER_SECOND,
                        limit_value=int(estimated_rate),
                        detection_confidence=min(0.8, rate_limited_count / test_requests),
                        detection_method="burst_analysis"
                    )
        
        except Exception as e:
            self.logger.error(f"Error in burst detection: {e}")
        
        return RateLimitInfo(detected=False)
    
    async def _header_analysis(self, http_client, target_url: str) -> RateLimitInfo:
        """Analyze headers for rate limit information"""
        try:
            response = await http_client.request("GET", target_url)
            return self._analyze_rate_limit_headers(response.headers)
        
        except Exception as e:
            self.logger.error(f"Error in header analysis: {e}")
        
        return RateLimitInfo(detected=False)
    
    def _analyze_rate_limit_headers(self, headers: Dict[str, str]) -> RateLimitInfo:
        """Analyze response headers for rate limit information"""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        found_headers = {}
        
        # Check for rate limit headers
        for header in self.rate_limit_headers:
            if header.lower() in headers_lower:
                found_headers[header] = headers_lower[header.lower()]
        
        if not found_headers:
            return RateLimitInfo(detected=False)
        
        # Parse rate limit information
        limit_value = None
        remaining = None
        reset_time = None
        window_size = None
        
        # Standard X-RateLimit headers
        if "x-ratelimit-limit" in found_headers:
            try:
                limit_value = int(found_headers["x-ratelimit-limit"])
            except ValueError:
                pass
        
        if "x-ratelimit-remaining" in found_headers:
            try:
                remaining = int(found_headers["x-ratelimit-remaining"])
            except ValueError:
                pass
        
        if "x-ratelimit-reset" in found_headers:
            try:
                reset_time = int(found_headers["x-ratelimit-reset"])
            except ValueError:
                pass
        
        # Retry-After header
        retry_after = None
        if "retry-after" in found_headers:
            try:
                retry_after = int(found_headers["retry-after"])
            except ValueError:
                pass
        
        # Determine rate limit type
        limit_type = RateLimitType.UNKNOWN
        if limit_value:
            if reset_time:
                # If reset time is in the future, it's likely per-hour or per-day
                current_time = int(time.time())
                if reset_time > current_time:
                    time_diff = reset_time - current_time
                    if time_diff <= 3600:  # 1 hour
                        limit_type = RateLimitType.REQUESTS_PER_HOUR
                        window_size = time_diff
                    else:
                        limit_type = RateLimitType.REQUESTS_PER_HOUR
                        window_size = 3600
            else:
                # Default to per-minute if no reset time
                limit_type = RateLimitType.REQUESTS_PER_MINUTE
                window_size = 60
        
        confidence = 0.9 if limit_value else 0.6
        
        return RateLimitInfo(
            detected=True,
            limit_type=limit_type,
            limit_value=limit_value,
            window_size=window_size,
            reset_time=reset_time,
            retry_after=retry_after,
            detection_confidence=confidence,
            detection_method="header_analysis",
            headers_found=found_headers
        )
    
    def _combine_detection_results(self, results: List[RateLimitInfo]) -> RateLimitInfo:
        """Combine multiple detection results"""
        detected_results = [r for r in results if r.detected]
        
        if not detected_results:
            return RateLimitInfo(detected=False)
        
        # Use result with highest confidence
        best_result = max(detected_results, key=lambda x: x.detection_confidence)
        
        # Combine headers from all results
        all_headers = {}
        for result in detected_results:
            all_headers.update(result.headers_found)
        
        best_result.headers_found = all_headers
        return best_result


class AdaptiveThrottling:
    """
    Adaptive throttling system that adjusts request rates based on server responses
    """
    
    def __init__(self, 
                 initial_rate: float = 1.0,
                 min_rate: float = 0.1,
                 max_rate: float = 10.0,
                 strategy: ThrottleStrategy = ThrottleStrategy.ADAPTIVE):
        """
        Initialize adaptive throttling
        
        Args:
            initial_rate: Initial requests per second
            min_rate: Minimum requests per second
            max_rate: Maximum requests per second
            strategy: Throttling strategy to use
        """
        self.initial_rate = initial_rate
        self.min_rate = min_rate
        self.max_rate = max_rate
        self.strategy = strategy
        
        self.state = ThrottleState(
            current_rate=initial_rate,
            strategy=strategy
        )
        
        self.user_agent_rotator = UserAgentRotator()
        self.rate_limit_detector = RateLimitDetector()
        
        self.logger = get_logger("adaptive_throttling")
        
        # Performance tracking
        self.recent_metrics: deque = deque(maxlen=100)
        self.last_request_time = 0.0
    
    async def initialize_for_target(self, http_client, target_url: str):
        """
        Initialize throttling parameters for a specific target
        
        Args:
            http_client: HTTP client instance
            target_url: Target URL to analyze
        """
        self.logger.info(f"Initializing adaptive throttling for {target_url}")
        
        # Detect rate limits
        rate_limit_info = await self.rate_limit_detector.detect_rate_limits(
            http_client, target_url
        )
        
        if rate_limit_info.detected:
            self._adjust_for_rate_limits(rate_limit_info)
        
        self.logger.info(
            f"Throttling initialized",
            initial_rate=self.state.current_rate,
            strategy=self.state.strategy.value
        )
    
    def _adjust_for_rate_limits(self, rate_limit_info: RateLimitInfo):
        """Adjust throttling based on detected rate limits"""
        if not rate_limit_info.limit_value:
            return
        
        # Calculate safe rate (80% of detected limit)
        if rate_limit_info.limit_type == RateLimitType.REQUESTS_PER_SECOND:
            safe_rate = rate_limit_info.limit_value * 0.8
        elif rate_limit_info.limit_type == RateLimitType.REQUESTS_PER_MINUTE:
            safe_rate = (rate_limit_info.limit_value / 60) * 0.8
        elif rate_limit_info.limit_type == RateLimitType.REQUESTS_PER_HOUR:
            safe_rate = (rate_limit_info.limit_value / 3600) * 0.8
        else:
            safe_rate = self.initial_rate
        
        # Ensure within bounds
        safe_rate = max(self.min_rate, min(safe_rate, self.max_rate))
        
        self.state.current_rate = safe_rate
        self.logger.info(
            f"Adjusted rate based on detected limits",
            detected_limit=rate_limit_info.limit_value,
            limit_type=rate_limit_info.limit_type.value,
            new_rate=safe_rate
        )
    
    async def throttled_request(self, http_client, method: str, url: str, **kwargs):
        """
        Make a throttled request with adaptive rate limiting
        
        Args:
            http_client: HTTP client instance
            method: HTTP method
            url: Request URL
            **kwargs: Additional request parameters
            
        Returns:
            Response object
        """
        # Wait for throttling
        await self._wait_for_throttle()
        
        # Rotate user agent if not specified
        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        
        if 'user-agent' not in kwargs['headers']:
            kwargs['headers']['user-agent'] = self.user_agent_rotator.get_next_user_agent()
        
        # Make request and track metrics
        start_time = time.time()
        
        try:
            response = await http_client.request(method, url, **kwargs)
            response_time = time.time() - start_time
            
            # Analyze response for rate limiting
            is_rate_limited = response.status_code in [429, 503, 502]
            is_success = 200 <= response.status_code < 300
            
            # Update metrics
            metrics = RequestMetrics(
                timestamp=start_time,
                response_time=response_time,
                status_code=response.status_code,
                rate_limited=is_rate_limited,
                success=is_success
            )
            self.recent_metrics.append(metrics)
            
            # Update state
            self.state.total_requests += 1
            
            if is_rate_limited:
                self.state.rate_limited_requests += 1
                self.state.consecutive_rate_limits += 1
                self.state.last_rate_limit_time = start_time
                self.state.success_streak = 0
                
                # Handle rate limiting
                await self._handle_rate_limit(response)
            else:
                self.state.consecutive_rate_limits = 0
                if is_success:
                    self.state.success_streak += 1
                
                # Adapt rate based on success
                self._adapt_rate_on_success()
            
            return response
        
        except Exception as e:
            # Handle connection errors (might indicate rate limiting)
            if "connection" in str(e).lower() or "timeout" in str(e).lower():
                self.state.consecutive_rate_limits += 1
                await self._handle_connection_error()
            
            raise e
    
    async def _wait_for_throttle(self):
        """Wait according to current throttling rate"""
        if self.state.current_rate <= 0:
            return
        
        # Calculate delay
        delay = 1.0 / self.state.current_rate
        
        # Account for time since last request
        current_time = time.time()
        if self.last_request_time > 0:
            elapsed = current_time - self.last_request_time
            remaining_delay = max(0, delay - elapsed)
            
            if remaining_delay > 0:
                await asyncio.sleep(remaining_delay)
        
        self.last_request_time = time.time()
    
    async def _handle_rate_limit(self, response):
        """Handle rate limiting response"""
        self.logger.warning(
            f"Rate limit detected",
            status_code=response.status_code,
            consecutive_limits=self.state.consecutive_rate_limits
        )
        
        # Check for Retry-After header
        retry_after = response.headers.get('retry-after')
        if retry_after:
            try:
                wait_time = int(retry_after)
                self.logger.info(f"Retry-After header found, waiting {wait_time} seconds")
                await asyncio.sleep(wait_time)
            except ValueError:
                pass
        
        # Apply throttling strategy
        if self.state.strategy == ThrottleStrategy.EXPONENTIAL_BACKOFF:
            self.state.backoff_multiplier *= 2
            self.state.current_rate = max(
                self.min_rate,
                self.initial_rate / self.state.backoff_multiplier
            )
        elif self.state.strategy == ThrottleStrategy.ADAPTIVE:
            # Reduce rate by 50%
            self.state.current_rate = max(
                self.min_rate,
                self.state.current_rate * 0.5
            )
        
        self.logger.info(f"Adjusted rate to {self.state.current_rate} req/s")
    
    async def _handle_connection_error(self):
        """Handle connection errors that might indicate rate limiting"""
        self.logger.warning("Connection error detected, reducing rate")
        
        # Reduce rate more aggressively for connection errors
        self.state.current_rate = max(
            self.min_rate,
            self.state.current_rate * 0.3
        )
        
        # Wait before next request
        await asyncio.sleep(5)
    
    def _adapt_rate_on_success(self):
        """Adapt rate based on successful requests"""
        if self.state.strategy != ThrottleStrategy.ADAPTIVE:
            return
        
        # If we have a good success streak, gradually increase rate
        if self.state.success_streak >= 10:
            # Increase rate by 10%
            new_rate = min(
                self.max_rate,
                self.state.current_rate * 1.1
            )
            
            if new_rate != self.state.current_rate:
                self.state.current_rate = new_rate
                self.logger.debug(f"Increased rate to {new_rate} req/s")
        
        # Reset backoff multiplier on success
        if self.state.consecutive_rate_limits == 0:
            self.state.backoff_multiplier = max(1.0, self.state.backoff_multiplier * 0.9)
    
    def get_throttle_stats(self) -> Dict[str, Any]:
        """Get current throttling statistics"""
        success_rate = 0.0
        avg_response_time = 0.0
        
        if self.recent_metrics:
            successful_requests = sum(1 for m in self.recent_metrics if m.success)
            success_rate = successful_requests / len(self.recent_metrics)
            avg_response_time = statistics.mean(m.response_time for m in self.recent_metrics)
        
        return {
            "current_rate": self.state.current_rate,
            "strategy": self.state.strategy.value,
            "total_requests": self.state.total_requests,
            "rate_limited_requests": self.state.rate_limited_requests,
            "consecutive_rate_limits": self.state.consecutive_rate_limits,
            "success_streak": self.state.success_streak,
            "success_rate": success_rate,
            "avg_response_time": avg_response_time,
            "backoff_multiplier": self.state.backoff_multiplier
        }
    
    def reset_throttling(self):
        """Reset throttling state"""
        self.state = ThrottleState(
            current_rate=self.initial_rate,
            strategy=self.strategy
        )
        self.recent_metrics.clear()
        self.last_request_time = 0.0
        
        self.logger.info("Throttling state reset")