"""
Intelligent WAF Detection and Adaptive Throttling System
Integrates WAF detection, rate limiting, and adaptive throttling
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field

from .waf_detector import WAFDetector, WAFDetectionResult, WAFType
from .adaptive_throttling import (
    AdaptiveThrottling, 
    RateLimitDetector, 
    UserAgentRotator,
    ThrottleStrategy,
    RateLimitInfo
)
from core.logging import get_logger
from core.monitoring import MonitoringSystem


@dataclass
class IntelligentWAFConfig:
    """Configuration for intelligent WAF system"""
    enable_waf_detection: bool = True
    enable_adaptive_throttling: bool = True
    enable_user_agent_rotation: bool = True
    initial_throttle_rate: float = 1.0
    min_throttle_rate: float = 0.1
    max_throttle_rate: float = 10.0
    throttle_strategy: ThrottleStrategy = ThrottleStrategy.ADAPTIVE
    waf_evasion_enabled: bool = True
    rate_limit_detection_requests: int = 20


@dataclass
class WAFSystemState:
    """Current state of the WAF system"""
    waf_detected: bool = False
    waf_info: Optional[WAFDetectionResult] = None
    rate_limits_detected: bool = False
    rate_limit_info: Optional[RateLimitInfo] = None
    current_throttle_rate: float = 1.0
    evasion_techniques_active: List[str] = field(default_factory=list)
    total_requests: int = 0
    blocked_requests: int = 0
    successful_evasions: int = 0


class IntelligentWAFSystem:
    """
    Intelligent WAF detection and adaptive throttling system
    Combines WAF detection, rate limiting, and evasion techniques
    """
    
    def __init__(self, 
                 config: IntelligentWAFConfig = None,
                 monitoring_system: MonitoringSystem = None):
        """
        Initialize intelligent WAF system
        
        Args:
            config: WAF system configuration
            monitoring_system: Monitoring system instance
        """
        self.config = config or IntelligentWAFConfig()
        self.monitoring = monitoring_system
        
        # Initialize components
        self.waf_detector = WAFDetector()
        self.rate_limit_detector = RateLimitDetector()
        self.adaptive_throttling = AdaptiveThrottling(
            initial_rate=self.config.initial_throttle_rate,
            min_rate=self.config.min_throttle_rate,
            max_rate=self.config.max_throttle_rate,
            strategy=self.config.throttle_strategy
        )
        self.user_agent_rotator = UserAgentRotator()
        
        # System state
        self.state = WAFSystemState()
        self.target_url = None
        self.http_client = None
        
        self.logger = get_logger("intelligent_waf_system")
    
    async def initialize_for_target(self, http_client, target_url: str):
        """
        Initialize the system for a specific target
        
        Args:
            http_client: HTTP client instance
            target_url: Target URL to analyze
        """
        self.http_client = http_client
        self.target_url = target_url
        
        self.logger.info(f"Initializing intelligent WAF system for {target_url}")
        
        # Phase 1: WAF Detection
        if self.config.enable_waf_detection:
            await self._detect_waf()
        
        # Phase 2: Rate Limit Detection
        if self.config.enable_adaptive_throttling:
            await self._detect_rate_limits()
        
        # Phase 3: Initialize Adaptive Throttling
        await self.adaptive_throttling.initialize_for_target(http_client, target_url)
        
        # Update state
        self.state.current_throttle_rate = self.adaptive_throttling.state.current_rate
        
        self.logger.info(
            "WAF system initialization complete",
            waf_detected=self.state.waf_detected,
            waf_type=self.state.waf_info.waf_type.value if self.state.waf_info else None,
            rate_limits_detected=self.state.rate_limits_detected,
            throttle_rate=self.state.current_throttle_rate
        )
    
    async def _detect_waf(self):
        """Detect WAF presence and type"""
        try:
            self.logger.info("Starting WAF detection")
            
            waf_result = await self.waf_detector.detect_waf(
                self.http_client, 
                self.target_url
            )
            
            if waf_result.detected:
                self.state.waf_detected = True
                self.state.waf_info = waf_result
                self.state.evasion_techniques_active = waf_result.evasion_techniques
                
                self.logger.info(
                    f"WAF detected: {waf_result.waf_type.value}",
                    confidence=waf_result.confidence,
                    evasion_techniques=len(waf_result.evasion_techniques)
                )
                
                # Notify monitoring system
                if self.monitoring:
                    self.monitoring.logger.warning(
                        "WAF detected - enabling evasion techniques",
                        waf_type=waf_result.waf_type.value,
                        confidence=waf_result.confidence
                    )
            else:
                self.logger.info("No WAF detected")
        
        except Exception as e:
            self.logger.error(f"Error during WAF detection: {e}")
    
    async def _detect_rate_limits(self):
        """Detect rate limiting patterns"""
        try:
            self.logger.info("Starting rate limit detection")
            
            rate_limit_result = await self.rate_limit_detector.detect_rate_limits(
                self.http_client,
                self.target_url,
                self.config.rate_limit_detection_requests
            )
            
            if rate_limit_result.detected:
                self.state.rate_limits_detected = True
                self.state.rate_limit_info = rate_limit_result
                
                self.logger.info(
                    f"Rate limiting detected",
                    limit_type=rate_limit_result.limit_type.value,
                    limit_value=rate_limit_result.limit_value,
                    confidence=rate_limit_result.detection_confidence
                )
                
                # Notify monitoring system
                if self.monitoring:
                    self.monitoring.logger.info(
                        "Rate limiting detected - adjusting throttling",
                        limit_type=rate_limit_result.limit_type.value,
                        limit_value=rate_limit_result.limit_value
                    )
            else:
                self.logger.info("No rate limiting detected")
        
        except Exception as e:
            self.logger.error(f"Error during rate limit detection: {e}")
    
    async def make_intelligent_request(self, method: str, url: str, 
                                     payload: str = None, **kwargs) -> Any:
        """
        Make an intelligent request with WAF evasion and adaptive throttling
        
        Args:
            method: HTTP method
            url: Request URL
            payload: Request payload (will be modified for evasion if needed)
            **kwargs: Additional request parameters
            
        Returns:
            Response object
        """
        # Prepare request with evasion techniques
        modified_kwargs = await self._prepare_evasive_request(
            method, url, payload, **kwargs
        )
        
        # Make throttled request
        start_time = time.time()
        
        try:
            response = await self.adaptive_throttling.throttled_request(
                self.http_client, method, url, **modified_kwargs
            )
            
            # Analyze response for WAF/rate limiting
            await self._analyze_response(response, start_time)
            
            self.state.total_requests += 1
            
            # Check if request was blocked
            if response.status_code in [403, 429, 503]:
                self.state.blocked_requests += 1
                
                # Try evasion if WAF detected
                if self.state.waf_detected and self.config.waf_evasion_enabled:
                    evasion_response = await self._attempt_evasion(
                        method, url, payload, **kwargs
                    )
                    if evasion_response and evasion_response.status_code not in [403, 429, 503]:
                        self.state.successful_evasions += 1
                        return evasion_response
            
            return response
        
        except Exception as e:
            self.logger.error(f"Error in intelligent request: {e}")
            
            # Record error in monitoring
            if self.monitoring:
                self.monitoring.record_timeout()
            
            raise e
    
    async def _prepare_evasive_request(self, method: str, url: str, 
                                      payload: str = None, **kwargs) -> Dict[str, Any]:
        """Prepare request with evasion techniques"""
        modified_kwargs = kwargs.copy()
        
        # Ensure headers exist
        if 'headers' not in modified_kwargs:
            modified_kwargs['headers'] = {}
        
        # User agent rotation
        if self.config.enable_user_agent_rotation:
            if 'user-agent' not in modified_kwargs['headers']:
                modified_kwargs['headers']['user-agent'] = \
                    self.user_agent_rotator.get_next_user_agent()
        
        # Apply WAF-specific evasion techniques
        if self.state.waf_detected and payload:
            modified_payload = await self._apply_waf_evasion(payload)
            
            # Update payload in appropriate location
            if method.upper() in ['POST', 'PUT', 'PATCH']:
                if 'json' in modified_kwargs:
                    # Modify JSON payload
                    modified_kwargs['json'] = self._modify_json_payload(
                        modified_kwargs['json'], modified_payload
                    )
                elif 'data' in modified_kwargs:
                    modified_kwargs['data'] = modified_payload
            else:
                # Modify URL parameters for GET requests
                if '?' in url:
                    url += f"&evasion_payload={modified_payload}"
                else:
                    url += f"?evasion_payload={modified_payload}"
        
        return modified_kwargs
    
    async def _apply_waf_evasion(self, payload: str) -> str:
        """Apply WAF-specific evasion techniques to payload"""
        if not self.state.waf_info:
            return payload
        
        # Get evasion payloads from WAF detector
        evasion_payloads = self.waf_detector.get_evasion_payloads(
            self.state.waf_info.waf_type,
            payload
        )
        
        # Return first evasion payload (could be randomized)
        return evasion_payloads[0] if evasion_payloads else payload
    
    def _modify_json_payload(self, json_data: Dict[str, Any], 
                           evasion_payload: str) -> Dict[str, Any]:
        """Modify JSON payload with evasion techniques"""
        modified_data = json_data.copy()
        
        # Add evasion payload to a test field
        modified_data['_evasion_test'] = evasion_payload
        
        return modified_data
    
    async def _analyze_response(self, response, start_time: float):
        """Analyze response for WAF/rate limiting indicators"""
        response_time = time.time() - start_time
        
        # Record metrics in monitoring system
        if self.monitoring:
            success = 200 <= response.status_code < 300
            self.monitoring.record_request(response_time, success)
            
            # Check for rate limiting
            if response.status_code == 429:
                self.monitoring.record_rate_limit()
        
        # Update throttling state
        self.state.current_throttle_rate = self.adaptive_throttling.state.current_rate
    
    async def _attempt_evasion(self, method: str, url: str, 
                              payload: str = None, **kwargs) -> Optional[Any]:
        """Attempt to evade WAF blocking using different techniques"""
        if not self.state.waf_info or not self.state.evasion_techniques_active:
            return None
        
        self.logger.info("Attempting WAF evasion")
        
        # Try different evasion techniques
        for technique in self.state.evasion_techniques_active[:3]:  # Try first 3
            try:
                # Modify request based on technique
                evasive_kwargs = await self._apply_evasion_technique(
                    technique, method, url, payload, **kwargs
                )
                
                # Make evasive request with longer delay
                await asyncio.sleep(2)
                
                response = await self.http_client.request(method, url, **evasive_kwargs)
                
                if response.status_code not in [403, 429, 503]:
                    self.logger.info(f"Successful evasion using technique: {technique}")
                    return response
            
            except Exception as e:
                self.logger.debug(f"Evasion technique {technique} failed: {e}")
                continue
        
        return None
    
    async def _apply_evasion_technique(self, technique: str, method: str, 
                                     url: str, payload: str = None, 
                                     **kwargs) -> Dict[str, Any]:
        """Apply specific evasion technique"""
        modified_kwargs = kwargs.copy()
        
        if 'headers' not in modified_kwargs:
            modified_kwargs['headers'] = {}
        
        if technique == "user_agent_rotation":
            modified_kwargs['headers']['user-agent'] = \
                self.user_agent_rotator.get_random_user_agent()
        
        elif technique == "case_variation" and payload:
            # Apply case variation to payload
            import random
            varied_payload = ''.join(
                char.upper() if random.choice([True, False]) else char.lower()
                for char in payload
            )
            if 'data' in modified_kwargs:
                modified_kwargs['data'] = varied_payload
        
        elif technique == "header_injection":
            # Add random headers
            modified_kwargs['headers'].update({
                'X-Forwarded-For': '127.0.0.1',
                'X-Real-IP': '127.0.0.1',
                'X-Originating-IP': '127.0.0.1',
                'X-Remote-IP': '127.0.0.1'
            })
        
        elif technique == "content_type_variation":
            # Vary content type
            if method.upper() in ['POST', 'PUT', 'PATCH']:
                modified_kwargs['headers']['content-type'] = 'application/x-www-form-urlencoded'
        
        return modified_kwargs
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status and statistics"""
        throttle_stats = self.adaptive_throttling.get_throttle_stats()
        
        return {
            "waf_detection": {
                "detected": self.state.waf_detected,
                "type": self.state.waf_info.waf_type.value if self.state.waf_info else None,
                "confidence": self.state.waf_info.confidence if self.state.waf_info else 0.0,
                "evasion_techniques": self.state.evasion_techniques_active
            },
            "rate_limiting": {
                "detected": self.state.rate_limits_detected,
                "type": self.state.rate_limit_info.limit_type.value if self.state.rate_limit_info else None,
                "limit_value": self.state.rate_limit_info.limit_value if self.state.rate_limit_info else None
            },
            "throttling": throttle_stats,
            "statistics": {
                "total_requests": self.state.total_requests,
                "blocked_requests": self.state.blocked_requests,
                "successful_evasions": self.state.successful_evasions,
                "block_rate": self.state.blocked_requests / max(1, self.state.total_requests),
                "evasion_success_rate": self.state.successful_evasions / max(1, self.state.blocked_requests)
            }
        }
    
    def reset_system(self):
        """Reset system state"""
        self.state = WAFSystemState()
        self.adaptive_throttling.reset_throttling()
        
        self.logger.info("WAF system state reset")