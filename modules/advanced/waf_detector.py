"""
WAF Detection Module
Detects Web Application Firewalls and adapts testing strategies
"""

import re
import asyncio
import random
import time
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urljoin

from core.logging import get_logger


class WAFType(str, Enum):
    """Known WAF types"""
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    AKAMAI = "akamai"
    CORAZA = "coraza"
    MODSECURITY = "modsecurity"
    IMPERVA = "imperva"
    F5_BIG_IP = "f5_big_ip"
    BARRACUDA = "barracuda"
    FORTINET = "fortinet"
    UNKNOWN = "unknown"


@dataclass
class WAFSignature:
    """WAF detection signature"""
    name: str
    waf_type: WAFType
    headers: Dict[str, str] = field(default_factory=dict)
    response_patterns: List[str] = field(default_factory=list)
    status_codes: List[int] = field(default_factory=list)
    server_headers: List[str] = field(default_factory=list)
    cookies: List[str] = field(default_factory=list)
    confidence_weight: float = 1.0


@dataclass
class WAFDetectionResult:
    """WAF detection result"""
    detected: bool
    waf_type: Optional[WAFType] = None
    confidence: float = 0.0
    detection_method: str = ""
    signatures_matched: List[str] = field(default_factory=list)
    response_patterns: List[str] = field(default_factory=list)
    evasion_techniques: List[str] = field(default_factory=list)
    recommended_payloads: List[str] = field(default_factory=list)


class WAFDetector:
    """
    Web Application Firewall detection system
    """
    
    def __init__(self):
        """Initialize WAF detector with signatures"""
        self.logger = get_logger("waf_detector")
        self.signatures = self._load_waf_signatures()
        self.detection_payloads = self._load_detection_payloads()
        self.evasion_techniques = self._load_evasion_techniques()
    
    def _load_waf_signatures(self) -> List[WAFSignature]:
        """Load WAF detection signatures"""
        return [
            # Cloudflare
            WAFSignature(
                name="Cloudflare",
                waf_type=WAFType.CLOUDFLARE,
                headers={"cf-ray": r".*", "server": r"cloudflare"},
                response_patterns=[
                    r"attention required.*cloudflare",
                    r"cloudflare ray id",
                    r"cf-error-details",
                    r"cloudflare.*security.*check"
                ],
                status_codes=[403, 429, 503],
                server_headers=["cloudflare", "cloudflare-nginx"],
                cookies=["__cfduid", "__cf_bm", "cf_clearance"],
                confidence_weight=0.9
            ),
            
            # AWS WAF
            WAFSignature(
                name="AWS WAF",
                waf_type=WAFType.AWS_WAF,
                headers={"x-amzn-requestid": r".*", "x-amz-cf-id": r".*"},
                response_patterns=[
                    r"aws.*waf",
                    r"request blocked.*aws",
                    r"x-amzn-errortype",
                    r"amazon.*cloudfront"
                ],
                status_codes=[403, 429],
                server_headers=["awselb", "amazon"],
                confidence_weight=0.85
            ),
            
            # Akamai
            WAFSignature(
                name="Akamai",
                waf_type=WAFType.AKAMAI,
                headers={"akamai-ghost-ip": r".*", "x-akamai-transformed": r".*"},
                response_patterns=[
                    r"akamai.*reference",
                    r"access.*denied.*akamai",
                    r"akamai.*ghost",
                    r"kona.*security"
                ],
                status_codes=[403, 429],
                server_headers=["akamaighost", "akamai"],
                confidence_weight=0.8
            ),
            
            # Coraza (Open Source WAF)
            WAFSignature(
                name="Coraza",
                waf_type=WAFType.CORAZA,
                headers={"x-coraza-id": r".*"},
                response_patterns=[
                    r"coraza.*waf",
                    r"request.*blocked.*coraza",
                    r"coraza.*security.*engine"
                ],
                status_codes=[403, 406],
                confidence_weight=0.9
            ),
            
            # ModSecurity
            WAFSignature(
                name="ModSecurity",
                waf_type=WAFType.MODSECURITY,
                headers={"x-mod-security-message": r".*"},
                response_patterns=[
                    r"mod_security",
                    r"modsecurity.*rule",
                    r"request.*rejected.*policy",
                    r"apache.*security.*filter"
                ],
                status_codes=[403, 406, 501],
                confidence_weight=0.85
            ),
            
            # Imperva
            WAFSignature(
                name="Imperva",
                waf_type=WAFType.IMPERVA,
                headers={"x-iinfo": r".*"},
                response_patterns=[
                    r"imperva.*incapsula",
                    r"incapsula.*incident",
                    r"imperva.*security",
                    r"blocked.*imperva"
                ],
                status_codes=[403, 429],
                confidence_weight=0.8
            ),
            
            # F5 BIG-IP
            WAFSignature(
                name="F5 BIG-IP",
                waf_type=WAFType.F5_BIG_IP,
                headers={"x-wa-info": r".*", "bigipserver": r".*"},
                response_patterns=[
                    r"f5.*big.*ip",
                    r"bigip.*blocked",
                    r"f5.*security.*policy",
                    r"request.*rejected.*f5"
                ],
                status_codes=[403, 412],
                server_headers=["bigip", "f5"],
                confidence_weight=0.8
            ),
            
            # Barracuda
            WAFSignature(
                name="Barracuda",
                waf_type=WAFType.BARRACUDA,
                response_patterns=[
                    r"barracuda.*waf",
                    r"blocked.*barracuda",
                    r"barracuda.*security"
                ],
                status_codes=[403, 429],
                confidence_weight=0.75
            ),
            
            # Fortinet
            WAFSignature(
                name="Fortinet",
                waf_type=WAFType.FORTINET,
                response_patterns=[
                    r"fortinet.*fortigate",
                    r"blocked.*fortinet",
                    r"fortigate.*security"
                ],
                status_codes=[403],
                confidence_weight=0.75
            )
        ]
    
    def _load_detection_payloads(self) -> List[str]:
        """Load payloads designed to trigger WAF responses"""
        return [
            # SQL Injection payloads
            "' OR '1'='1",
            "1' UNION SELECT NULL--",
            "<script>alert('xss')</script>",
            "javascript:alert(1)",
            
            # Command injection
            "; cat /etc/passwd",
            "| whoami",
            "`id`",
            
            # Path traversal
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            
            # XXE
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
            
            # LDAP injection
            "*)(&(objectClass=*)",
            
            # Common attack patterns
            "<img src=x onerror=alert(1)>",
            "eval(String.fromCharCode(97,108,101,114,116,40,49,41))",
            "<?php system($_GET['cmd']); ?>",
            
            # WAF-specific triggers
            "union all select",
            "drop table",
            "exec master..xp_cmdshell",
            "<iframe src=javascript:alert(1)>",
        ]
    
    def _load_evasion_techniques(self) -> Dict[WAFType, List[str]]:
        """Load WAF-specific evasion techniques"""
        return {
            WAFType.CLOUDFLARE: [
                "case_variation",
                "url_encoding",
                "unicode_encoding",
                "comment_insertion",
                "user_agent_rotation"
            ],
            WAFType.AWS_WAF: [
                "parameter_pollution",
                "content_type_variation",
                "header_injection",
                "chunked_encoding"
            ],
            WAFType.AKAMAI: [
                "ip_rotation",
                "request_splitting",
                "protocol_confusion",
                "timing_variation"
            ],
            WAFType.MODSECURITY: [
                "rule_bypass",
                "encoding_chains",
                "whitespace_manipulation",
                "comment_evasion"
            ],
            WAFType.UNKNOWN: [
                "basic_encoding",
                "case_variation",
                "user_agent_rotation"
            ]
        }
    
    async def detect_waf(self, http_client, target_url: str) -> WAFDetectionResult:
        """
        Detect WAF presence and type
        
        Args:
            http_client: HTTP client instance
            target_url: Target URL to test
            
        Returns:
            WAF detection result
        """
        self.logger.info(f"Starting WAF detection for {target_url}")
        
        detection_results = []
        
        # 1. Passive detection through normal requests
        passive_result = await self._passive_detection(http_client, target_url)
        if passive_result.detected:
            detection_results.append(passive_result)
        
        # 2. Active detection using attack payloads
        active_result = await self._active_detection(http_client, target_url)
        if active_result.detected:
            detection_results.append(active_result)
        
        # 3. Behavioral analysis
        behavioral_result = await self._behavioral_analysis(http_client, target_url)
        if behavioral_result.detected:
            detection_results.append(behavioral_result)
        
        # Combine results
        final_result = self._combine_detection_results(detection_results)
        
        if final_result.detected:
            self.logger.info(
                f"WAF detected: {final_result.waf_type.value}",
                confidence=final_result.confidence,
                method=final_result.detection_method
            )
        else:
            self.logger.info("No WAF detected")
        
        return final_result
    
    async def _passive_detection(self, http_client, target_url: str) -> WAFDetectionResult:
        """Passive WAF detection through normal requests"""
        try:
            response = await http_client.request("GET", target_url)
            
            for signature in self.signatures:
                confidence = 0.0
                matched_signatures = []
                
                # Check headers
                for header_name, pattern in signature.headers.items():
                    if header_name.lower() in [h.lower() for h in response.headers]:
                        header_value = response.headers.get(header_name, "")
                        if re.search(pattern, header_value, re.IGNORECASE):
                            confidence += 0.3
                            matched_signatures.append(f"header_{header_name}")
                
                # Check server headers
                server_header = response.headers.get("server", "").lower()
                for server_pattern in signature.server_headers:
                    if server_pattern.lower() in server_header:
                        confidence += 0.4
                        matched_signatures.append(f"server_{server_pattern}")
                
                # Check cookies
                cookies = response.headers.get("set-cookie", "")
                for cookie_pattern in signature.cookies:
                    if cookie_pattern in cookies:
                        confidence += 0.2
                        matched_signatures.append(f"cookie_{cookie_pattern}")
                
                # Apply confidence weight
                confidence *= signature.confidence_weight
                
                if confidence > 0.5:
                    return WAFDetectionResult(
                        detected=True,
                        waf_type=signature.waf_type,
                        confidence=confidence,
                        detection_method="passive",
                        signatures_matched=matched_signatures,
                        evasion_techniques=self.evasion_techniques.get(
                            signature.waf_type, 
                            self.evasion_techniques[WAFType.UNKNOWN]
                        )
                    )
            
        except Exception as e:
            self.logger.error(f"Error in passive WAF detection: {e}")
        
        return WAFDetectionResult(detected=False)
    
    async def _active_detection(self, http_client, target_url: str) -> WAFDetectionResult:
        """Active WAF detection using attack payloads"""
        try:
            # Test with malicious payloads
            for payload in self.detection_payloads[:5]:  # Test first 5 payloads
                test_url = f"{target_url}?test={payload}"
                
                try:
                    response = await http_client.request("GET", test_url)
                    
                    # Check for WAF response patterns
                    response_text = response.text.lower() if hasattr(response, 'text') else ""
                    
                    for signature in self.signatures:
                        confidence = 0.0
                        matched_patterns = []
                        
                        # Check status codes
                        if response.status_code in signature.status_codes:
                            confidence += 0.3
                        
                        # Check response patterns
                        for pattern in signature.response_patterns:
                            if re.search(pattern, response_text, re.IGNORECASE):
                                confidence += 0.4
                                matched_patterns.append(pattern)
                        
                        # Apply confidence weight
                        confidence *= signature.confidence_weight
                        
                        if confidence > 0.6:
                            return WAFDetectionResult(
                                detected=True,
                                waf_type=signature.waf_type,
                                confidence=confidence,
                                detection_method="active",
                                response_patterns=matched_patterns,
                                evasion_techniques=self.evasion_techniques.get(
                                    signature.waf_type,
                                    self.evasion_techniques[WAFType.UNKNOWN]
                                )
                            )
                
                except Exception as e:
                    # Connection errors might indicate blocking
                    if "connection" in str(e).lower() or "timeout" in str(e).lower():
                        return WAFDetectionResult(
                            detected=True,
                            waf_type=WAFType.UNKNOWN,
                            confidence=0.7,
                            detection_method="active_blocking",
                            evasion_techniques=self.evasion_techniques[WAFType.UNKNOWN]
                        )
                
                # Small delay between requests
                await asyncio.sleep(0.5)
        
        except Exception as e:
            self.logger.error(f"Error in active WAF detection: {e}")
        
        return WAFDetectionResult(detected=False)
    
    async def _behavioral_analysis(self, http_client, target_url: str) -> WAFDetectionResult:
        """Behavioral analysis for WAF detection"""
        try:
            # Test rate limiting behavior
            start_time = time.time()
            responses = []
            
            # Send rapid requests
            for i in range(10):
                try:
                    response = await http_client.request("GET", target_url)
                    responses.append(response)
                except Exception as e:
                    responses.append(None)
                
                if i < 9:  # Don't sleep after last request
                    await asyncio.sleep(0.1)
            
            end_time = time.time()
            
            # Analyze responses for WAF behavior
            status_codes = [r.status_code for r in responses if r is not None]
            blocked_requests = sum(1 for code in status_codes if code in [403, 429, 503])
            
            # If more than 30% of requests are blocked, likely WAF
            if blocked_requests > 3:
                return WAFDetectionResult(
                    detected=True,
                    waf_type=WAFType.UNKNOWN,
                    confidence=0.6,
                    detection_method="behavioral",
                    evasion_techniques=self.evasion_techniques[WAFType.UNKNOWN]
                )
        
        except Exception as e:
            self.logger.error(f"Error in behavioral WAF analysis: {e}")
        
        return WAFDetectionResult(detected=False)
    
    def _combine_detection_results(self, results: List[WAFDetectionResult]) -> WAFDetectionResult:
        """Combine multiple detection results into final result"""
        if not results:
            return WAFDetectionResult(detected=False)
        
        # Sort by confidence
        results.sort(key=lambda x: x.confidence, reverse=True)
        best_result = results[0]
        
        # Combine signatures and patterns from all results
        all_signatures = []
        all_patterns = []
        all_techniques = set()
        
        for result in results:
            all_signatures.extend(result.signatures_matched)
            all_patterns.extend(result.response_patterns)
            all_techniques.update(result.evasion_techniques)
        
        return WAFDetectionResult(
            detected=True,
            waf_type=best_result.waf_type,
            confidence=best_result.confidence,
            detection_method=best_result.detection_method,
            signatures_matched=list(set(all_signatures)),
            response_patterns=list(set(all_patterns)),
            evasion_techniques=list(all_techniques)
        )
    
    def get_evasion_payloads(self, waf_type: WAFType, base_payload: str) -> List[str]:
        """
        Generate evasion payloads for detected WAF
        
        Args:
            waf_type: Detected WAF type
            base_payload: Base payload to modify
            
        Returns:
            List of evasion payloads
        """
        techniques = self.evasion_techniques.get(waf_type, self.evasion_techniques[WAFType.UNKNOWN])
        evasion_payloads = [base_payload]  # Include original
        
        for technique in techniques:
            if technique == "case_variation":
                evasion_payloads.extend(self._apply_case_variation(base_payload))
            elif technique == "url_encoding":
                evasion_payloads.extend(self._apply_url_encoding(base_payload))
            elif technique == "unicode_encoding":
                evasion_payloads.extend(self._apply_unicode_encoding(base_payload))
            elif technique == "comment_insertion":
                evasion_payloads.extend(self._apply_comment_insertion(base_payload))
            elif technique == "whitespace_manipulation":
                evasion_payloads.extend(self._apply_whitespace_manipulation(base_payload))
        
        return list(set(evasion_payloads))  # Remove duplicates
    
    def _apply_case_variation(self, payload: str) -> List[str]:
        """Apply case variation evasion"""
        variations = []
        
        # Random case
        random_case = ''.join(
            char.upper() if random.choice([True, False]) else char.lower()
            for char in payload
        )
        variations.append(random_case)
        
        # Alternating case
        alternating = ''.join(
            char.upper() if i % 2 == 0 else char.lower()
            for i, char in enumerate(payload)
        )
        variations.append(alternating)
        
        return variations
    
    def _apply_url_encoding(self, payload: str) -> List[str]:
        """Apply URL encoding evasion"""
        import urllib.parse
        
        variations = []
        
        # Standard URL encoding
        variations.append(urllib.parse.quote(payload))
        
        # Double URL encoding
        variations.append(urllib.parse.quote(urllib.parse.quote(payload)))
        
        # Selective encoding (encode only special characters)
        special_chars = ['<', '>', '"', "'", '&', '=', ' ']
        selective = payload
        for char in special_chars:
            selective = selective.replace(char, urllib.parse.quote(char))
        variations.append(selective)
        
        return variations
    
    def _apply_unicode_encoding(self, payload: str) -> List[str]:
        """Apply Unicode encoding evasion"""
        variations = []
        
        # Unicode escape sequences
        unicode_payload = ''.join(f'\\u{ord(char):04x}' for char in payload)
        variations.append(unicode_payload)
        
        # HTML entity encoding
        html_entities = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '&': '&amp;'
        }
        html_encoded = payload
        for char, entity in html_entities.items():
            html_encoded = html_encoded.replace(char, entity)
        variations.append(html_encoded)
        
        return variations
    
    def _apply_comment_insertion(self, payload: str) -> List[str]:
        """Apply comment insertion evasion"""
        variations = []
        
        # SQL comments
        if 'select' in payload.lower() or 'union' in payload.lower():
            variations.append(payload.replace(' ', '/**/'))
            variations.append(payload.replace('select', 'sel/**/ect'))
            variations.append(payload.replace('union', 'uni/**/on'))
        
        # HTML comments
        if '<script>' in payload.lower():
            variations.append(payload.replace('<script>', '<script<!---->'))
        
        return variations
    
    def _apply_whitespace_manipulation(self, payload: str) -> List[str]:
        """Apply whitespace manipulation evasion"""
        variations = []
        
        # Tab instead of space
        variations.append(payload.replace(' ', '\t'))
        
        # Multiple spaces
        variations.append(payload.replace(' ', '  '))
        
        # Newline insertion
        variations.append(payload.replace(' ', '\n'))
        
        # Mixed whitespace
        variations.append(payload.replace(' ', ' \t\n '))
        
        return variations