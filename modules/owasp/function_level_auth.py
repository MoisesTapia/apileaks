"""
Function Level Authorization Testing Module
OWASP API5:2023 - Broken Function Level Authorization

This module tests for function-level authorization vulnerabilities where
users can access administrative or privileged functions they shouldn't have access to.
"""

import asyncio
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from .registry import OWASPModule
from utils.http_client import HTTPRequestEngine
from utils.findings import Finding
from core.config import Severity, FunctionAuthConfig, AuthContext


@dataclass
class AdminEndpoint:
    """Represents a potentially administrative endpoint"""
    url: str
    method: str
    admin_indicators: List[str]
    confidence: float


class FunctionLevelAuthModule(OWASPModule):
    """
    Function Level Authorization Testing Module
    
    Tests for OWASP API5:2023 - Broken Function Level Authorization
    """
    
    def __init__(self, config: FunctionAuthConfig, http_client: HTTPRequestEngine, auth_contexts: List[AuthContext]):
        super().__init__(config)
        self.http_client = http_client
        self.auth_contexts = auth_contexts
        
        # Create auth context mapping
        self.auth_context_map = {ctx.name: ctx for ctx in auth_contexts}
        
        # Add anonymous context if not present
        if 'anonymous' not in self.auth_context_map:
            from core.config import AuthType
            anonymous_ctx = AuthContext(
                name='anonymous',
                type=AuthType.BEARER,
                token='',
                privilege_level=0
            )
            self.auth_context_map['anonymous'] = anonymous_ctx
        
        # Administrative endpoint patterns
        self.admin_patterns = [
            'admin', 'administrator', 'management', 'manage', 'control',
            'dashboard', 'panel', 'console', 'config', 'configuration',
            'settings', 'system', 'internal', 'private', 'restricted',
            'privileged', 'secure', 'protected', 'staff', 'employee',
            'moderator', 'supervisor', 'operator', 'maintenance',
            'debug', 'test', 'dev', 'development', 'staging'
        ]
        
        # Administrative function keywords
        self.admin_functions = [
            'delete', 'remove', 'destroy', 'purge', 'clear', 'reset',
            'create', 'add', 'insert', 'new', 'generate', 'make',
            'update', 'modify', 'edit', 'change', 'alter', 'set',
            'approve', 'reject', 'ban', 'unban', 'block', 'unblock',
            'enable', 'disable', 'activate', 'deactivate', 'suspend',
            'promote', 'demote', 'grant', 'revoke', 'assign', 'unassign',
            'backup', 'restore', 'export', 'import', 'migrate', 'sync'
        ]
        
        # Bypass parameters to test
        self.bypass_params = [
            {'admin': 'true'}, {'admin': '1'}, {'admin': 'yes'},
            {'is_admin': 'true'}, {'is_admin': '1'}, {'is_admin': 'yes'},
            {'role': 'admin'}, {'role': 'administrator'}, {'role': 'root'},
            {'user_type': 'admin'}, {'user_type': 'administrator'},
            {'privilege': 'admin'}, {'privilege': 'high'}, {'privilege': '1'},
            {'access_level': 'admin'}, {'access_level': '9'}, {'access_level': 'high'},
            {'debug': 'true'}, {'debug': '1'}, {'test': 'true'}, {'test': '1'},
            {'bypass': 'true'}, {'bypass': '1'}, {'override': 'true'},
            {'force': 'true'}, {'force': '1'}, {'sudo': 'true'}
        ]
        
        # Bypass headers to test
        self.bypass_headers = [
            {'X-Admin': 'true'}, {'X-Admin': '1'}, {'X-Admin': 'yes'},
            {'X-Is-Admin': 'true'}, {'X-Is-Admin': '1'},
            {'X-Role': 'admin'}, {'X-Role': 'administrator'},
            {'X-User-Type': 'admin'}, {'X-User-Type': 'administrator'},
            {'X-Privilege': 'admin'}, {'X-Privilege': 'high'},
            {'X-Access-Level': 'admin'}, {'X-Access-Level': '9'},
            {'X-Debug': 'true'}, {'X-Debug': '1'},
            {'X-Test': 'true'}, {'X-Test': '1'},
            {'X-Bypass': 'true'}, {'X-Bypass': '1'},
            {'X-Override': 'true'}, {'X-Override': '1'},
            {'X-Force': 'true'}, {'X-Force': '1'},
            {'X-Sudo': 'true'}, {'X-Sudo': '1'},
            {'X-Original-User': 'admin'}, {'X-Original-User': 'administrator'},
            {'X-Forwarded-User': 'admin'}, {'X-Forwarded-User': 'administrator'},
            {'X-Remote-User': 'admin'}, {'X-Remote-User': 'administrator'}
        ]
        
        # HTTP methods that often require higher privileges
        self.privileged_methods = ['DELETE', 'PUT', 'PATCH', 'POST']
    
    def get_module_name(self) -> str:
        """Get module name"""
        return "function_auth"
    
    async def execute_tests(self, endpoints: List[Any]) -> List[Finding]:
        """
        Execute function level authorization tests
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            List of findings
        """
        findings = []
        
        self.logger.info("Starting function level authorization testing",
                        endpoints_count=len(endpoints))
        
        # Step 1: Identify potential administrative endpoints
        admin_endpoints = self._identify_admin_endpoints(endpoints)
        
        self.logger.info("Identified potential admin endpoints",
                        admin_endpoints_count=len(admin_endpoints))
        
        # Step 2: Test anonymous access to administrative functions
        anonymous_findings = await self._test_anonymous_admin_access(admin_endpoints)
        findings.extend(anonymous_findings)
        
        # Step 3: Test HTTP method bypass
        method_bypass_findings = await self._test_http_method_bypass(endpoints)
        findings.extend(method_bypass_findings)
        
        # Step 4: Test parameter bypass
        param_bypass_findings = await self._test_parameter_bypass(endpoints)
        findings.extend(param_bypass_findings)
        
        # Step 5: Test header bypass
        header_bypass_findings = await self._test_header_bypass(endpoints)
        findings.extend(header_bypass_findings)
        
        self.logger.info("Function level authorization testing completed",
                        findings_count=len(findings))
        
        return findings
    
    def _identify_admin_endpoints(self, endpoints: List[Any]) -> List[AdminEndpoint]:
        """
        Identify potentially administrative endpoints
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            List of administrative endpoints
        """
        admin_endpoints = []
        
        for endpoint in endpoints:
            url = getattr(endpoint, 'url', str(endpoint))
            method = getattr(endpoint, 'method', 'GET')
            
            admin_indicators = []
            confidence = 0.0
            
            # Check URL path for admin patterns
            url_lower = url.lower()
            path_parts = urlparse(url).path.lower().split('/')
            
            for pattern in self.admin_patterns:
                if pattern in url_lower:
                    admin_indicators.append(f"admin_pattern:{pattern}")
                    confidence += 0.3
            
            # Check for administrative functions in path
            for func in self.admin_functions:
                if func in url_lower:
                    admin_indicators.append(f"admin_function:{func}")
                    confidence += 0.2
            
            # Higher confidence for certain HTTP methods
            if method in self.privileged_methods:
                admin_indicators.append(f"privileged_method:{method}")
                confidence += 0.1
            
            # Check for ID patterns that might indicate object manipulation
            if any(pattern in url_lower for pattern in ['/id/', '/{id}', '/user/', '/users/']):
                admin_indicators.append("object_manipulation")
                confidence += 0.1
            
            # If we found admin indicators, add to list
            if admin_indicators and confidence > 0.2:
                admin_endpoints.append(AdminEndpoint(
                    url=url,
                    method=method,
                    admin_indicators=admin_indicators,
                    confidence=min(confidence, 1.0)
                ))
        
        # Sort by confidence (highest first)
        admin_endpoints.sort(key=lambda x: x.confidence, reverse=True)
        
        return admin_endpoints
    
    async def _test_anonymous_admin_access(self, admin_endpoints: List[AdminEndpoint]) -> List[Finding]:
        """
        Test anonymous access to administrative endpoints
        
        Args:
            admin_endpoints: List of administrative endpoints
            
        Returns:
            List of findings
        """
        findings = []
        
        for admin_endpoint in admin_endpoints:
            try:
                # Test without authentication
                response = await self.http_client.request(
                    method=admin_endpoint.method,
                    url=admin_endpoint.url,
                    headers={'User-Agent': 'APILeak-FunctionAuth/1.0'}
                )
                
                # Check if access was granted (not 401/403)
                if response.status_code not in [401, 403, 404]:
                    severity = self._determine_severity(response.status_code, admin_endpoint.confidence)
                    
                    finding = Finding(
                        title="Anonymous Access to Administrative Function",
                        description=f"Administrative endpoint '{admin_endpoint.url}' is accessible without authentication",
                        severity=severity,
                        confidence=admin_endpoint.confidence,
                        owasp_category="API5:2023",
                        cwe_id="CWE-862",
                        endpoint=admin_endpoint.url,
                        method=admin_endpoint.method,
                        evidence=f"HTTP {response.status_code} response received for admin endpoint",
                        payload=f"{admin_endpoint.method} {admin_endpoint.url}",
                        response_snippet=response.text[:500] if hasattr(response, 'text') else "",
                        remediation="Implement proper function-level authorization checks for administrative endpoints"
                    )
                    
                    findings.append(finding)
                    
                    self.logger.warning("Anonymous admin access detected",
                                      url=admin_endpoint.url,
                                      method=admin_endpoint.method,
                                      status_code=response.status_code)
                
                # Small delay to avoid overwhelming the server
                await asyncio.sleep(0.1)
                
            except Exception as e:
                self.logger.debug("Error testing anonymous admin access",
                                url=admin_endpoint.url,
                                error=str(e))
        
        return findings
    
    async def _test_http_method_bypass(self, endpoints: List[Any]) -> List[Finding]:
        """
        Test HTTP method bypass for authorization
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of findings
        """
        findings = []
        
        # Test a subset of endpoints to avoid too many requests
        test_endpoints = endpoints[:20] if len(endpoints) > 20 else endpoints
        
        for endpoint in test_endpoints:
            url = getattr(endpoint, 'url', str(endpoint))
            original_method = getattr(endpoint, 'method', 'GET')
            
            # Test different HTTP methods
            for test_method in self.privileged_methods:
                if test_method == original_method:
                    continue
                
                try:
                    # First, test original method (baseline)
                    baseline_response = await self.http_client.request(
                        method=original_method,
                        url=url,
                        headers={'User-Agent': 'APILeak-FunctionAuth/1.0'}
                    )
                    
                    # Then test with different method
                    test_response = await self.http_client.request(
                        method=test_method,
                        url=url,
                        headers={'User-Agent': 'APILeak-FunctionAuth/1.0'}
                    )
                    
                    # Check for bypass (different response than baseline)
                    if (baseline_response.status_code in [401, 403] and 
                        test_response.status_code not in [401, 403, 404, 405]):
                        
                        finding = Finding(
                            title="HTTP Method Authorization Bypass",
                            description=f"Endpoint '{url}' allows access via {test_method} method bypassing authorization",
                            severity=Severity.HIGH,
                            confidence=0.8,
                            owasp_category="API5:2023",
                            cwe_id="CWE-862",
                            endpoint=url,
                            method=test_method,
                            evidence=f"Baseline {original_method} returned {baseline_response.status_code}, {test_method} returned {test_response.status_code}",
                            payload=f"{test_method} {url}",
                            response_snippet=test_response.text[:500] if hasattr(test_response, 'text') else "",
                            remediation="Implement consistent authorization checks across all HTTP methods"
                        )
                        
                        findings.append(finding)
                        
                        self.logger.warning("HTTP method bypass detected",
                                          url=url,
                                          original_method=original_method,
                                          bypass_method=test_method,
                                          baseline_status=baseline_response.status_code,
                                          bypass_status=test_response.status_code)
                    
                    await asyncio.sleep(0.1)
                    
                except Exception as e:
                    self.logger.debug("Error testing HTTP method bypass",
                                    url=url,
                                    method=test_method,
                                    error=str(e))
        
        return findings
    
    async def _test_parameter_bypass(self, endpoints: List[Any]) -> List[Finding]:
        """
        Test parameter-based authorization bypass
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of findings
        """
        findings = []
        
        # Test a subset of endpoints
        test_endpoints = endpoints[:15] if len(endpoints) > 15 else endpoints
        
        for endpoint in test_endpoints:
            url = getattr(endpoint, 'url', str(endpoint))
            method = getattr(endpoint, 'method', 'GET')
            
            # Test each bypass parameter
            for bypass_param in self.bypass_params:
                try:
                    # Baseline request without bypass parameter
                    baseline_response = await self.http_client.request(
                        method=method,
                        url=url,
                        headers={'User-Agent': 'APILeak-FunctionAuth/1.0'}
                    )
                    
                    # Test with bypass parameter
                    if method in ['GET', 'DELETE']:
                        # Add as query parameter
                        test_response = await self.http_client.request(
                            method=method,
                            url=url,
                            params=bypass_param,
                            headers={'User-Agent': 'APILeak-FunctionAuth/1.0'}
                        )
                    else:
                        # Add as body parameter
                        test_response = await self.http_client.request(
                            method=method,
                            url=url,
                            json=bypass_param,
                            headers={'User-Agent': 'APILeak-FunctionAuth/1.0'}
                        )
                    
                    # Check for bypass
                    if (baseline_response.status_code in [401, 403] and 
                        test_response.status_code not in [401, 403, 404]):
                        
                        param_name = list(bypass_param.keys())[0]
                        param_value = list(bypass_param.values())[0]
                        
                        finding = Finding(
                            title="Parameter-Based Authorization Bypass",
                            description=f"Endpoint '{url}' allows authorization bypass using parameter '{param_name}={param_value}'",
                            severity=Severity.HIGH,
                            confidence=0.9,
                            owasp_category="API5:2023",
                            cwe_id="CWE-862",
                            endpoint=url,
                            method=method,
                            evidence=f"Baseline returned {baseline_response.status_code}, with {param_name}={param_value} returned {test_response.status_code}",
                            payload=f"{method} {url} with {param_name}={param_value}",
                            response_snippet=test_response.text[:500] if hasattr(test_response, 'text') else "",
                            remediation="Remove or properly validate authorization bypass parameters"
                        )
                        
                        findings.append(finding)
                        
                        self.logger.warning("Parameter bypass detected",
                                          url=url,
                                          method=method,
                                          parameter=f"{param_name}={param_value}",
                                          baseline_status=baseline_response.status_code,
                                          bypass_status=test_response.status_code)
                    
                    await asyncio.sleep(0.1)
                    
                except Exception as e:
                    self.logger.debug("Error testing parameter bypass",
                                    url=url,
                                    parameter=bypass_param,
                                    error=str(e))
        
        return findings
    
    async def _test_header_bypass(self, endpoints: List[Any]) -> List[Finding]:
        """
        Test header-based authorization bypass
        
        Args:
            endpoints: List of endpoints to test
            
        Returns:
            List of findings
        """
        findings = []
        
        # Test a subset of endpoints
        test_endpoints = endpoints[:15] if len(endpoints) > 15 else endpoints
        
        for endpoint in test_endpoints:
            url = getattr(endpoint, 'url', str(endpoint))
            method = getattr(endpoint, 'method', 'GET')
            
            # Test each bypass header
            for bypass_header in self.bypass_headers:
                try:
                    # Baseline request without bypass header
                    baseline_response = await self.http_client.request(
                        method=method,
                        url=url,
                        headers={'User-Agent': 'APILeak-FunctionAuth/1.0'}
                    )
                    
                    # Test with bypass header
                    test_headers = {
                        'User-Agent': 'APILeak-FunctionAuth/1.0',
                        **bypass_header
                    }
                    
                    test_response = await self.http_client.request(
                        method=method,
                        url=url,
                        headers=test_headers
                    )
                    
                    # Check for bypass
                    if (baseline_response.status_code in [401, 403] and 
                        test_response.status_code not in [401, 403, 404]):
                        
                        header_name = list(bypass_header.keys())[0]
                        header_value = list(bypass_header.values())[0]
                        
                        finding = Finding(
                            title="Header-Based Authorization Bypass",
                            description=f"Endpoint '{url}' allows authorization bypass using header '{header_name}: {header_value}'",
                            severity=Severity.HIGH,
                            confidence=0.9,
                            owasp_category="API5:2023",
                            cwe_id="CWE-862",
                            endpoint=url,
                            method=method,
                            evidence=f"Baseline returned {baseline_response.status_code}, with {header_name}: {header_value} returned {test_response.status_code}",
                            payload=f"{method} {url} with header {header_name}: {header_value}",
                            response_snippet=test_response.text[:500] if hasattr(test_response, 'text') else "",
                            remediation="Remove or properly validate authorization bypass headers"
                        )
                        
                        findings.append(finding)
                        
                        self.logger.warning("Header bypass detected",
                                          url=url,
                                          method=method,
                                          header=f"{header_name}: {header_value}",
                                          baseline_status=baseline_response.status_code,
                                          bypass_status=test_response.status_code)
                    
                    await asyncio.sleep(0.1)
                    
                except Exception as e:
                    self.logger.debug("Error testing header bypass",
                                    url=url,
                                    header=bypass_header,
                                    error=str(e))
        
        return findings
    
    def _determine_severity(self, status_code: int, confidence: float) -> Severity:
        """
        Determine severity based on response and confidence
        
        Args:
            status_code: HTTP response status code
            confidence: Confidence level of admin endpoint detection
            
        Returns:
            Severity level
        """
        if status_code == 200 and confidence > 0.7:
            return Severity.CRITICAL
        elif status_code in [200, 201, 202] and confidence > 0.5:
            return Severity.HIGH
        elif status_code in [200, 201, 202, 204]:
            return Severity.MEDIUM
        else:
            return Severity.LOW