"""
JWT Attack Response Analyzer
Analyzes HTTP responses to detect JWT vulnerabilities and authentication bypasses
"""

import re
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime

from core.logging import get_logger
from .jwt_attack_models import (
    ResponseDetails, VulnerabilityAssessment, VulnerabilitySeverity, 
    AttackType, BaselineResponse
)


class JWTAttackResponseAnalyzer:
    """
    Analyzes HTTP responses from JWT attack testing to detect vulnerabilities
    
    Features:
    - Response comparison logic (status codes, content length, timing)
    - Authentication bypass detection
    - Vulnerability confidence scoring system
    - Success detection and flagging
    - Privilege escalation detection
    """
    
    def __init__(self, baseline_response: BaselineResponse):
        """
        Initialize response analyzer with baseline response
        
        Args:
            baseline_response: Baseline response from original JWT token
        """
        self.baseline_response = baseline_response
        self.logger = get_logger(__name__).bind(component="jwt_attack_response_analyzer")
        
        # Authentication success indicators
        self.success_indicators = [
            # Common success patterns
            r'"success":\s*true',
            r'"authenticated":\s*true',
            r'"authorized":\s*true',
            r'"valid":\s*true',
            r'"access_granted":\s*true',
            
            # User data patterns
            r'"user":\s*{',
            r'"profile":\s*{',
            r'"account":\s*{',
            r'"dashboard"',
            r'"admin_panel"',
            
            # Token patterns
            r'"token":\s*"[^"]+',
            r'"access_token":\s*"[^"]+',
            r'"jwt":\s*"[^"]+',
            
            # Role/permission patterns
            r'"role":\s*"(admin|administrator|root|superuser)"',
            r'"permissions":\s*\[',
            r'"admin":\s*true',
            r'"is_admin":\s*true',
            
            # Navigation/menu patterns
            r'<nav[^>]*>',
            r'class="(nav|menu|sidebar)"',
            r'href="/(admin|dashboard|profile)"',
        ]
        
        # Authentication failure indicators
        self.failure_indicators = [
            r'"error":\s*"(unauthorized|forbidden|access_denied)"',
            r'"message":\s*"(invalid|expired|unauthorized)"',
            r'"authenticated":\s*false',
            r'"valid":\s*false',
            r'<title>[^<]*login[^<]*</title>',
            r'class="(login|signin|auth)"',
        ]
        
        # Privilege escalation indicators
        self.privilege_indicators = [
            r'"role":\s*"(admin|administrator|root|superuser)"',
            r'"admin":\s*true',
            r'"is_admin":\s*true',
            r'"permissions":\s*\[[^\]]*"admin"',
            r'"capabilities":\s*\[[^\]]*"admin"',
            r'admin_panel',
            r'administrator_dashboard',
            r'/admin/',
            r'class="admin-',
        ]
        
        self.logger.info("JWT Attack Response Analyzer initialized",
                        baseline_status=baseline_response.response_details.status_code,
                        baseline_length=baseline_response.response_details.content_length)
    
    def analyze_attack_response(self, attack_response: ResponseDetails, 
                               attack_type: AttackType) -> VulnerabilityAssessment:
        """
        Analyze attack response against baseline to detect vulnerabilities
        
        Args:
            attack_response: Response from attack request
            attack_type: Type of JWT attack performed
            
        Returns:
            VulnerabilityAssessment with detailed analysis
        """
        self.logger.debug("Analyzing attack response",
                         attack_type=attack_type.value,
                         status_code=attack_response.status_code,
                         content_length=attack_response.content_length)
        
        # Initialize assessment
        evidence = []
        exploitation_steps = []
        is_vulnerable = False
        confidence_score = 0.0
        severity = VulnerabilitySeverity.INFO
        
        baseline = self.baseline_response.response_details
        
        # 1. Success Detection and Flagging (2xx responses)
        success_analysis = self.flag_success_responses(attack_response, baseline)
        evidence.extend(success_analysis['evidence'])
        if success_analysis['is_vulnerable']:
            is_vulnerable = True
            confidence_score = max(confidence_score, success_analysis['confidence'])
            severity = self._escalate_severity(severity, success_analysis['severity'])
        
        # 2. Status Code Analysis
        status_analysis = self._analyze_status_codes(attack_response, baseline)
        evidence.extend(status_analysis['evidence'])
        if status_analysis['is_vulnerable']:
            is_vulnerable = True
            confidence_score = max(confidence_score, status_analysis['confidence'])
            severity = self._escalate_severity(severity, status_analysis['severity'])
        
        # 3. Authentication Bypass Detection
        auth_analysis = self.detect_authentication_bypass(attack_response)
        evidence.extend(auth_analysis['evidence'])
        if auth_analysis['is_vulnerable']:
            is_vulnerable = True
            confidence_score = max(confidence_score, auth_analysis['confidence'])
            severity = self._escalate_severity(severity, auth_analysis['severity'])
        
        # 4. Enhanced Privilege Escalation Detection
        priv_analysis = self.detect_privilege_escalation_indicators(attack_response, baseline)
        evidence.extend(priv_analysis['evidence'])
        if priv_analysis['is_vulnerable']:
            is_vulnerable = True
            confidence_score = max(confidence_score, priv_analysis['confidence'])
            severity = self._escalate_severity(severity, priv_analysis['severity'])
        
        # 5. Content Analysis
        content_analysis = self._analyze_content_differences(attack_response, baseline)
        evidence.extend(content_analysis['evidence'])
        if content_analysis['confidence'] > 0:
            confidence_score = max(confidence_score, content_analysis['confidence'])
        
        # 6. Timing Analysis
        timing_analysis = self._analyze_timing_differences(attack_response, baseline)
        evidence.extend(timing_analysis['evidence'])
        if timing_analysis['confidence'] > 0:
            confidence_score = max(confidence_score, timing_analysis['confidence'])
        
        # Generate exploitation steps
        if is_vulnerable:
            exploitation_steps = self._generate_exploitation_steps(attack_type, evidence)
        
        # Determine vulnerability type and remediation
        vulnerability_type, remediation_advice = self._get_vulnerability_details(attack_type)
        
        # Final confidence adjustment based on evidence quality
        final_confidence = self.calculate_confidence_score(evidence, is_vulnerable)
        
        # Handle ambiguous responses
        ambiguous_analysis = self.handle_ambiguous_responses(attack_response, attack_type, final_confidence)
        if ambiguous_analysis['requires_manual_review']:
            evidence.extend(ambiguous_analysis['evidence'])
            # For ambiguous cases, return special assessment
            if final_confidence < 0.4 and not is_vulnerable:
                return self.create_ambiguous_response_assessment(attack_response, attack_type, evidence)
        
        assessment = VulnerabilityAssessment(
            is_vulnerable=is_vulnerable,
            vulnerability_type=vulnerability_type,
            severity=severity,
            evidence=evidence,
            exploitation_steps=exploitation_steps,
            remediation_advice=remediation_advice,
            confidence_score=final_confidence
        )
        
        self.logger.info("Response analysis completed",
                        attack_type=attack_type.value,
                        is_vulnerable=is_vulnerable,
                        confidence_score=final_confidence,
                        severity=severity.value,
                        evidence_count=len(evidence))
        
        return assessment
    
    def detect_authentication_bypass(self, response: ResponseDetails) -> Dict[str, Any]:
        """
        Detect if authentication was bypassed based on response analysis
        
        Args:
            response: HTTP response to analyze
            
        Returns:
            Dictionary with bypass detection results
        """
        evidence = []
        is_vulnerable = False
        confidence = 0.0
        severity = VulnerabilitySeverity.INFO
        
        baseline = self.baseline_response.response_details
        
        # Check for authentication bypass patterns
        if baseline.status_code in [401, 403] and 200 <= response.status_code < 300:
            evidence.append(f"Authentication bypass: {baseline.status_code} → {response.status_code}")
            is_vulnerable = True
            confidence = 0.9
            severity = VulnerabilitySeverity.CRITICAL
        
        # Check for success indicators in response body
        success_matches = self._find_pattern_matches(response.body, self.success_indicators)
        if success_matches:
            evidence.extend([f"Success indicator found: {match}" for match in success_matches[:3]])
            if baseline.status_code in [401, 403]:
                is_vulnerable = True
                confidence = max(confidence, 0.8)
                severity = VulnerabilitySeverity.HIGH
            else:
                confidence = max(confidence, 0.4)
        
        # Check if failure indicators disappeared
        baseline_failures = self._find_pattern_matches(baseline.body, self.failure_indicators)
        response_failures = self._find_pattern_matches(response.body, self.failure_indicators)
        
        if baseline_failures and not response_failures:
            evidence.append("Authentication failure indicators removed from response")
            is_vulnerable = True
            confidence = max(confidence, 0.7)
            severity = VulnerabilitySeverity.HIGH
        
        return {
            'is_vulnerable': is_vulnerable,
            'evidence': evidence,
            'confidence': confidence,
            'severity': severity
        }
    
    def detect_privilege_escalation(self, response: ResponseDetails) -> Dict[str, Any]:
        """
        Detect if privileges were escalated based on response content
        
        Args:
            response: HTTP response to analyze
            
        Returns:
            Dictionary with privilege escalation detection results
        """
        evidence = []
        is_vulnerable = False
        confidence = 0.0
        severity = VulnerabilitySeverity.INFO
        
        baseline = self.baseline_response.response_details
        
        # Check for privilege escalation indicators
        priv_matches = self._find_pattern_matches(response.body, self.privilege_indicators)
        baseline_priv_matches = self._find_pattern_matches(baseline.body, self.privilege_indicators)
        
        # New privilege indicators appeared
        new_privileges = set(priv_matches) - set(baseline_priv_matches)
        if new_privileges:
            evidence.extend([f"New privilege indicator: {priv}" for priv in list(new_privileges)[:3]])
            is_vulnerable = True
            confidence = 0.8
            severity = VulnerabilitySeverity.HIGH
        
        # Check for admin-specific content
        admin_patterns = [
            r'admin_panel',
            r'administrator_dashboard',
            r'user_management',
            r'system_settings',
            r'/admin/',
            r'class="admin-'
        ]
        
        admin_matches = self._find_pattern_matches(response.body, admin_patterns)
        baseline_admin_matches = self._find_pattern_matches(baseline.body, admin_patterns)
        
        new_admin_content = set(admin_matches) - set(baseline_admin_matches)
        if new_admin_content:
            evidence.extend([f"Admin content appeared: {content}" for content in list(new_admin_content)[:2]])
            is_vulnerable = True
            confidence = max(confidence, 0.7)
            severity = VulnerabilitySeverity.HIGH
        
        return {
            'is_vulnerable': is_vulnerable,
            'evidence': evidence,
            'confidence': confidence,
            'severity': severity
        }
    
    def calculate_confidence_score(self, evidence: List[str], is_vulnerable: bool) -> float:
        """
        Calculate confidence score based on evidence quality and quantity
        
        Args:
            evidence: List of evidence strings
            is_vulnerable: Whether vulnerability was detected
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        if not evidence:
            return 0.0
        
        # Base confidence from evidence count
        evidence_count_score = min(len(evidence) * 0.1, 0.3)
        
        # Quality scoring based on evidence types
        quality_score = 0.0
        
        for item in evidence:
            item_lower = item.lower()
            
            # High confidence indicators
            if any(keyword in item_lower for keyword in [
                'authentication bypass', 'status code changed', 'success indicator',
                'admin content', 'privilege indicator'
            ]):
                quality_score += 0.2
            
            # Medium confidence indicators
            elif any(keyword in item_lower for keyword in [
                'content length', 'response time', 'failure indicators removed'
            ]):
                quality_score += 0.1
            
            # Low confidence indicators
            else:
                quality_score += 0.05
        
        # Cap quality score
        quality_score = min(quality_score, 0.7)
        
        # Combine scores
        base_score = evidence_count_score + quality_score
        
        # Boost confidence if vulnerability is detected
        if is_vulnerable:
            base_score = min(base_score * 1.2, 1.0)
        
        return round(base_score, 2)
    
    def _analyze_status_codes(self, attack_response: ResponseDetails, 
                             baseline_response: ResponseDetails) -> Dict[str, Any]:
        """Analyze status code differences"""
        evidence = []
        is_vulnerable = False
        confidence = 0.0
        severity = VulnerabilitySeverity.INFO
        
        if attack_response.status_code != baseline_response.status_code:
            evidence.append(f"Status code changed: {baseline_response.status_code} → {attack_response.status_code}")
            
            # Authentication bypass detection
            if baseline_response.status_code in [401, 403] and 200 <= attack_response.status_code < 300:
                evidence.append("Potential authentication bypass detected")
                is_vulnerable = True
                confidence = 0.9
                severity = VulnerabilitySeverity.CRITICAL
            
            # Success response with attack token
            elif 200 <= attack_response.status_code < 300:
                evidence.append("Attack request returned success status")
                is_vulnerable = True
                confidence = 0.7
                severity = VulnerabilitySeverity.HIGH
            
            # Other status changes
            else:
                confidence = 0.3
        
        return {
            'is_vulnerable': is_vulnerable,
            'evidence': evidence,
            'confidence': confidence,
            'severity': severity
        }
    
    def _analyze_content_differences(self, attack_response: ResponseDetails, 
                                   baseline_response: ResponseDetails) -> Dict[str, Any]:
        """Analyze content length and body differences"""
        evidence = []
        confidence = 0.0
        
        # Content length analysis
        length_diff = abs(attack_response.content_length - baseline_response.content_length)
        if length_diff > 100:
            evidence.append(f"Significant content length change: {length_diff} bytes")
            confidence = 0.3
        elif length_diff > 50:
            evidence.append(f"Content length changed by {length_diff} bytes")
            confidence = 0.2
        
        # Content similarity analysis (basic)
        if attack_response.body and baseline_response.body:
            # Check for completely different responses
            if len(attack_response.body) > 0 and len(baseline_response.body) > 0:
                # Simple similarity check
                common_words = set(attack_response.body.split()) & set(baseline_response.body.split())
                total_words = set(attack_response.body.split()) | set(baseline_response.body.split())
                
                if total_words:
                    similarity = len(common_words) / len(total_words)
                    if similarity < 0.3:  # Very different content
                        evidence.append("Response content significantly different from baseline")
                        confidence = max(confidence, 0.4)
        
        return {
            'evidence': evidence,
            'confidence': confidence
        }
    
    def _analyze_timing_differences(self, attack_response: ResponseDetails, 
                                  baseline_response: ResponseDetails) -> Dict[str, Any]:
        """Analyze response timing differences"""
        evidence = []
        confidence = 0.0
        
        time_diff = abs(attack_response.response_time - baseline_response.response_time)
        
        if time_diff > 5.0:
            evidence.append(f"Significant timing difference: {time_diff:.2f}s")
            confidence = 0.3
        elif time_diff > 2.0:
            evidence.append(f"Notable timing difference: {time_diff:.2f}s")
            confidence = 0.2
        elif time_diff > 1.0:
            evidence.append(f"Minor timing difference: {time_diff:.2f}s")
            confidence = 0.1
        
        return {
            'evidence': evidence,
            'confidence': confidence
        }
    
    def _detect_success_responses(self, response: ResponseDetails) -> Dict[str, Any]:
        """Detect success responses and flag them appropriately"""
        evidence = []
        is_vulnerable = False
        confidence = 0.0
        severity = VulnerabilitySeverity.INFO
        
        # 2xx status codes indicate success
        if 200 <= response.status_code < 300:
            evidence.append(f"Success status code: {response.status_code}")
            
            # If baseline was unauthorized, this is likely a bypass
            if self.baseline_response.response_details.status_code in [401, 403]:
                is_vulnerable = True
                confidence = 0.8
                severity = VulnerabilitySeverity.HIGH
            else:
                confidence = 0.4
        
        return {
            'is_vulnerable': is_vulnerable,
            'evidence': evidence,
            'confidence': confidence,
            'severity': severity
        }
    
    def _find_pattern_matches(self, text: str, patterns: List[str]) -> List[str]:
        """Find pattern matches in text"""
        matches = []
        if not text:
            return matches
        
        for pattern in patterns:
            try:
                if re.search(pattern, text, re.IGNORECASE):
                    matches.append(pattern)
            except re.error:
                # Skip invalid regex patterns
                continue
        
        return matches
    
    def _escalate_severity(self, current: VulnerabilitySeverity, 
                          new: VulnerabilitySeverity) -> VulnerabilitySeverity:
        """Escalate severity to higher level"""
        severity_order = [
            VulnerabilitySeverity.INFO,
            VulnerabilitySeverity.LOW,
            VulnerabilitySeverity.MEDIUM,
            VulnerabilitySeverity.HIGH,
            VulnerabilitySeverity.CRITICAL
        ]
        
        current_idx = severity_order.index(current)
        new_idx = severity_order.index(new)
        
        return severity_order[max(current_idx, new_idx)]
    
    def _generate_exploitation_steps(self, attack_type: AttackType, 
                                   evidence: List[str]) -> List[str]:
        """Generate exploitation steps based on attack type and evidence"""
        steps = []
        
        if attack_type in [AttackType.ALG_NONE, AttackType.NULL_SIGNATURE]:
            steps.extend([
                "1. Modify JWT header to set 'alg' field to 'none'",
                "2. Remove the signature portion of the JWT token",
                "3. Send request with modified token to bypass authentication"
            ])
        
        elif attack_type == AttackType.KID_INJECTION:
            steps.extend([
                "1. Modify JWT header 'kid' parameter with path traversal payload",
                "2. Use '../../../etc/passwd' or similar to access system files",
                "3. Exploit file inclusion to compromise key validation"
            ])
        
        elif attack_type in [AttackType.JWKS_SPOOF, AttackType.INLINE_JWKS]:
            steps.extend([
                "1. Create malicious JWKS with attacker-controlled keys",
                "2. Modify JWT header to reference malicious JWKS",
                "3. Sign token with attacker's private key",
                "4. Server validates against attacker's public key"
            ])
        
        elif attack_type in [AttackType.PRIVILEGE_ESCALATION, AttackType.USER_IMPERSONATION]:
            steps.extend([
                "1. Decode original JWT token to understand structure",
                "2. Modify claims to escalate privileges or impersonate users",
                "3. Re-sign token (if signature validation is weak)",
                "4. Use modified token to access restricted resources"
            ])
        
        else:
            steps.append(f"1. Use {attack_type.value} technique to bypass JWT validation")
            steps.append("2. Leverage vulnerability to gain unauthorized access")
        
        # Add evidence-based steps
        if any("admin" in ev.lower() for ev in evidence):
            steps.append("3. Exploit admin access to perform privileged operations")
        
        return steps
    
    def _get_vulnerability_details(self, attack_type: AttackType) -> Tuple[str, str]:
        """Get vulnerability type and remediation advice"""
        if attack_type in [AttackType.ALG_NONE, AttackType.NULL_SIGNATURE]:
            return (
                "Algorithm Confusion / Signature Bypass",
                "Ensure JWT signature verification is properly implemented and cannot be bypassed. "
                "Reject tokens with 'alg': 'none' and validate signatures for all algorithms."
            )
        
        elif attack_type == AttackType.KID_INJECTION:
            return (
                "Key ID Injection Vulnerability",
                "Validate and sanitize the 'kid' parameter to prevent path traversal attacks. "
                "Use a whitelist of allowed key identifiers and reject suspicious values."
            )
        
        elif attack_type in [AttackType.JWKS_SPOOF, AttackType.INLINE_JWKS]:
            return (
                "JWKS Manipulation Vulnerability",
                "Use a trusted, static JWKS endpoint and validate key sources. "
                "Do not allow arbitrary JWKS URLs or inline keys in JWT headers."
            )
        
        elif attack_type in [AttackType.PRIVILEGE_ESCALATION, AttackType.USER_IMPERSONATION]:
            return (
                "Authorization Bypass Vulnerability",
                "Implement proper JWT signature verification and claim validation. "
                "Verify user permissions on the server side for each request."
            )
        
        elif attack_type == AttackType.EXPIRATION_BYPASS:
            return (
                "Token Expiration Bypass",
                "Always validate token expiration claims ('exp', 'iat') and reject expired tokens. "
                "Implement proper token lifecycle management."
            )
        
        else:
            return (
                f"{attack_type.value.replace('_', ' ').title()} Vulnerability",
                "Review JWT implementation for security vulnerabilities and follow OWASP guidelines."
            )
    
    def flag_success_responses(self, response: ResponseDetails, 
                              baseline_response: ResponseDetails) -> Dict[str, Any]:
        """
        Flag 2xx response success and analyze for potential vulnerabilities
        
        Args:
            response: Attack response to analyze
            baseline_response: Baseline response for comparison
            
        Returns:
            Dictionary with success flagging results
        """
        evidence = []
        is_success = False
        is_vulnerable = False
        confidence = 0.0
        severity = VulnerabilitySeverity.INFO
        
        # Check for 2xx success status codes
        if 200 <= response.status_code < 300:
            is_success = True
            evidence.append(f"Success response detected: HTTP {response.status_code}")
            
            # Compare with baseline to determine if this indicates a vulnerability
            if baseline_response.status_code in [401, 403]:
                # Baseline was unauthorized, success response indicates bypass
                evidence.append("Authentication bypass: unauthorized baseline → success response")
                is_vulnerable = True
                confidence = 0.9
                severity = VulnerabilitySeverity.CRITICAL
                
            elif baseline_response.status_code in [400, 404, 405]:
                # Baseline was client error, success might indicate bypass
                evidence.append("Potential bypass: client error baseline → success response")
                is_vulnerable = True
                confidence = 0.7
                severity = VulnerabilitySeverity.HIGH
                
            elif baseline_response.status_code >= 500:
                # Baseline was server error, success might indicate fix or bypass
                evidence.append("Server error resolved: server error baseline → success response")
                confidence = 0.5
                severity = VulnerabilitySeverity.MEDIUM
                
            elif 200 <= baseline_response.status_code < 300:
                # Both baseline and attack were successful
                evidence.append("Both baseline and attack responses successful")
                confidence = 0.3
                
                # Check for content differences that might indicate privilege escalation
                if response.content_length > baseline_response.content_length + 100:
                    evidence.append("Attack response contains significantly more content")
                    confidence = 0.6
                    severity = VulnerabilitySeverity.MEDIUM
        
        return {
            'is_success': is_success,
            'is_vulnerable': is_vulnerable,
            'evidence': evidence,
            'confidence': confidence,
            'severity': severity
        }
    
    def detect_privilege_escalation_indicators(self, response: ResponseDetails, 
                                             baseline_response: ResponseDetails) -> Dict[str, Any]:
        """
        Enhanced privilege escalation detection with detailed analysis
        
        Args:
            response: Attack response to analyze
            baseline_response: Baseline response for comparison
            
        Returns:
            Dictionary with privilege escalation detection results
        """
        evidence = []
        is_vulnerable = False
        confidence = 0.0
        severity = VulnerabilitySeverity.INFO
        
        # Check for new administrative content
        admin_patterns = [
            r'admin_panel',
            r'administrator_dashboard',
            r'user_management',
            r'system_settings',
            r'admin_console',
            r'/admin/',
            r'class="admin-',
            r'role="admin"',
            r'data-role="admin"'
        ]
        
        attack_admin_matches = self._find_pattern_matches(response.body, admin_patterns)
        baseline_admin_matches = self._find_pattern_matches(baseline_response.body, admin_patterns)
        
        new_admin_content = set(attack_admin_matches) - set(baseline_admin_matches)
        if new_admin_content:
            evidence.extend([f"New admin content: {content}" for content in list(new_admin_content)[:3]])
            is_vulnerable = True
            confidence = 0.8
            severity = VulnerabilitySeverity.HIGH
        
        # Check for privilege-related JSON responses
        privilege_json_patterns = [
            r'"role":\s*"(admin|administrator|root|superuser)"',
            r'"admin":\s*true',
            r'"is_admin":\s*true',
            r'"permissions":\s*\[[^\]]*"admin"',
            r'"capabilities":\s*\[[^\]]*"admin"',
            r'"access_level":\s*"(admin|administrator|high)"',
            r'"user_type":\s*"admin"'
        ]
        
        attack_priv_matches = self._find_pattern_matches(response.body, privilege_json_patterns)
        baseline_priv_matches = self._find_pattern_matches(baseline_response.body, privilege_json_patterns)
        
        new_privileges = set(attack_priv_matches) - set(baseline_priv_matches)
        if new_privileges:
            evidence.extend([f"New privilege indicator: {priv}" for priv in list(new_privileges)[:3]])
            is_vulnerable = True
            confidence = max(confidence, 0.9)
            severity = VulnerabilitySeverity.CRITICAL
        
        # Check for navigation/menu changes indicating elevated access
        nav_patterns = [
            r'<nav[^>]*admin[^>]*>',
            r'href="[^"]*admin[^"]*"',
            r'href="[^"]*dashboard[^"]*"',
            r'class="[^"]*admin-menu[^"]*"',
            r'class="[^"]*admin-nav[^"]*"'
        ]
        
        attack_nav_matches = self._find_pattern_matches(response.body, nav_patterns)
        baseline_nav_matches = self._find_pattern_matches(baseline_response.body, nav_patterns)
        
        new_navigation = set(attack_nav_matches) - set(baseline_nav_matches)
        if new_navigation:
            evidence.extend([f"New admin navigation: {nav}" for nav in list(new_navigation)[:2]])
            is_vulnerable = True
            confidence = max(confidence, 0.7)
            severity = VulnerabilitySeverity.HIGH
        
        return {
            'is_vulnerable': is_vulnerable,
            'evidence': evidence,
            'confidence': confidence,
            'severity': severity
        }
    
    def handle_ambiguous_responses(self, response: ResponseDetails, 
                                 attack_type: AttackType, 
                                 confidence_score: float) -> Dict[str, Any]:
        """
        Handle ambiguous responses that require manual review
        
        Args:
            response: HTTP response details
            attack_type: Type of attack performed
            confidence_score: Current confidence score
            
        Returns:
            Dictionary with ambiguous response handling results
        """
        evidence = []
        requires_manual_review = False
        
        # Determine if response is ambiguous based on confidence and characteristics
        if confidence_score < 0.5:
            requires_manual_review = True
            evidence.append(f"Low confidence score ({confidence_score:.2f}) indicates ambiguous results")
        
        # Check for mixed signals in response
        if 200 <= response.status_code < 300:
            # Success status but check for error indicators in body
            error_patterns = [
                r'"error":\s*"[^"]+',
                r'"message":\s*"[^"]*error[^"]*"',
                r'"success":\s*false',
                r'class="error"',
                r'<div[^>]*error[^>]*>'
            ]
            
            error_matches = self._find_pattern_matches(response.body, error_patterns)
            if error_matches:
                requires_manual_review = True
                evidence.append("Mixed signals: success status code with error indicators in body")
                evidence.extend([f"Error indicator: {err}" for err in error_matches[:2]])
        
        # Check for partial content or incomplete responses
        if response.content_length < 100 and response.status_code == 200:
            requires_manual_review = True
            evidence.append("Unusually short response body for success status")
        
        # Check for redirect responses that might indicate different behavior
        if 300 <= response.status_code < 400:
            requires_manual_review = True
            evidence.append(f"Redirect response ({response.status_code}) requires manual analysis")
        
        # Check for timeout or connection issues
        if response.response_time > 30.0:
            requires_manual_review = True
            evidence.append(f"Slow response time ({response.response_time:.2f}s) may indicate issues")
        
        if requires_manual_review:
            evidence.append("Manual review recommended for accurate vulnerability assessment")
        
        return {
            'requires_manual_review': requires_manual_review,
            'evidence': evidence,
            'review_priority': 'high' if confidence_score < 0.3 else 'medium'
        }
    
    def create_ambiguous_response_assessment(self, response: ResponseDetails, 
                                           attack_type: AttackType, 
                                           evidence: List[str]) -> VulnerabilityAssessment:
        """
        Create assessment for ambiguous responses that require manual review
        
        Args:
            response: HTTP response details
            attack_type: Type of attack performed
            evidence: Evidence collected during analysis
            
        Returns:
            VulnerabilityAssessment marked for manual review
        """
        vulnerability_type, remediation_advice = self._get_vulnerability_details(attack_type)
        
        # Add manual review indicators
        evidence.append("Response requires manual review for accurate assessment")
        evidence.append("Automated analysis could not determine vulnerability status with high confidence")
        
        return VulnerabilityAssessment(
            is_vulnerable=False,  # Conservative approach for ambiguous cases
            vulnerability_type=f"Potential {vulnerability_type}",
            severity=VulnerabilitySeverity.MEDIUM,
            evidence=evidence,
            exploitation_steps=["Manual analysis required to confirm vulnerability"],
            remediation_advice=f"Manual review recommended. {remediation_advice}",
            confidence_score=0.3  # Low confidence indicates need for manual review
        )