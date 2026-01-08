#!/usr/bin/env python3
"""
Authentication Testing Module Demo
Demonstrates the capabilities of the Authentication Testing Module
"""

import asyncio
import json
import base64
import hmac
import hashlib
import time
import sys
import os
from dataclasses import dataclass

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.owasp.auth_testing import AuthenticationTestingModule
from utils.http_client import HTTPRequestEngine, Response, RateLimiter, RetryConfig
from core.config import AuthTestingConfig, AuthContext, AuthType, RateLimitConfig
from core.logging import get_logger


@dataclass
class MockEndpoint:
    """Mock endpoint for demonstration"""
    url: str
    method: str = "GET"


class MockHTTPClient:
    """Mock HTTP client for demonstration"""
    
    def __init__(self):
        self.current_auth_context = None
        self.request_count = 0
    
    def set_auth_context(self, auth_context):
        self.current_auth_context = auth_context
    
    async def request(self, method, url):
        self.request_count += 1
        
        # Simulate different responses based on URL and auth context
        if "/admin" in url:
            if self.current_auth_context and "admin" in self.current_auth_context.name:
                return self._create_response(200, '{"admin": "access granted"}')
            elif self.current_auth_context is None:
                # Vulnerable: admin endpoint accessible without auth
                return self._create_response(200, '{"admin": "vulnerable access"}')
            else:
                return self._create_response(403, '{"error": "forbidden"}')
        
        elif "/logout" in url:
            return self._create_response(200, '{"message": "logged out"}')
        
        elif "/users" in url:
            if self.current_auth_context is None:
                # Vulnerable: users endpoint accessible without auth
                return self._create_response(200, '{"users": [{"id": 1, "email": "user@example.com", "password": "hashed"}]}')
            else:
                return self._create_response(200, '{"users": [{"id": 1, "name": "John"}]}')
        
        else:
            # Default response
            return self._create_response(200, '{"data": "public"}')
    
    def _create_response(self, status_code, text):
        return Response(
            status_code=status_code,
            headers={"content-type": "application/json"},
            content=text.encode(),
            text=text,
            url="mock://example.com",
            elapsed=0.1,
            request_method="GET"
        )


async def create_demo_jwt_tokens():
    """Create demo JWT tokens with various vulnerabilities"""
    
    # 1. JWT with weak secret
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": "user123",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "role": "user"
    }
    
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    
    # Sign with weak secret "secret"
    signature = hmac.new(
        b"secret",
        f"{header_b64}.{payload_b64}".encode(),
        hashlib.sha256
    ).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
    
    weak_jwt = f"{header_b64}.{payload_b64}.{signature_b64}"
    
    # 2. JWT with 'none' algorithm
    none_header = {"alg": "none", "typ": "JWT"}
    none_header_b64 = base64.urlsafe_b64encode(json.dumps(none_header).encode()).decode().rstrip('=')
    none_jwt = f"{none_header_b64}.{payload_b64}."
    
    # 3. Expired JWT
    expired_payload = payload.copy()
    expired_payload["exp"] = int(time.time()) - 3600  # Expired 1 hour ago
    
    expired_payload_b64 = base64.urlsafe_b64encode(json.dumps(expired_payload).encode()).decode().rstrip('=')
    expired_signature = hmac.new(
        b"secret",
        f"{header_b64}.{expired_payload_b64}".encode(),
        hashlib.sha256
    ).digest()
    expired_signature_b64 = base64.urlsafe_b64encode(expired_signature).decode().rstrip('=')
    
    expired_jwt = f"{header_b64}.{expired_payload_b64}.{expired_signature_b64}"
    
    # 4. JWT without expiration
    no_exp_payload = {"sub": "user123", "iat": int(time.time()), "role": "user"}
    no_exp_payload_b64 = base64.urlsafe_b64encode(json.dumps(no_exp_payload).encode()).decode().rstrip('=')
    no_exp_signature = hmac.new(
        b"secret",
        f"{header_b64}.{no_exp_payload_b64}".encode(),
        hashlib.sha256
    ).digest()
    no_exp_signature_b64 = base64.urlsafe_b64encode(no_exp_signature).decode().rstrip('=')
    
    no_exp_jwt = f"{header_b64}.{no_exp_payload_b64}.{no_exp_signature_b64}"
    
    return {
        "weak_secret": weak_jwt,
        "none_algorithm": none_jwt,
        "expired": expired_jwt,
        "no_expiration": no_exp_jwt
    }


async def main():
    """Main demonstration function"""
    
    logger = get_logger(__name__)
    logger.info("Starting Authentication Testing Module Demo")
    
    # Create demo JWT tokens
    jwt_tokens = await create_demo_jwt_tokens()
    
    # Create authentication contexts with various vulnerabilities
    auth_contexts = [
        AuthContext(
            name="user_weak_secret",
            type=AuthType.JWT,
            token=jwt_tokens["weak_secret"],
            privilege_level=1
        ),
        AuthContext(
            name="user_none_algorithm",
            type=AuthType.JWT,
            token=jwt_tokens["none_algorithm"],
            privilege_level=1
        ),
        AuthContext(
            name="expired_user",
            type=AuthType.JWT,
            token=jwt_tokens["expired"],
            privilege_level=1
        ),
        AuthContext(
            name="no_exp_user",
            type=AuthType.JWT,
            token=jwt_tokens["no_expiration"],
            privilege_level=1
        ),
        AuthContext(
            name="admin_user",
            type=AuthType.BEARER,
            token="admin_bearer_token",
            privilege_level=3
        )
    ]
    
    # Create authentication testing configuration
    auth_config = AuthTestingConfig(
        enabled=True,
        jwt_testing=True,
        weak_secrets_wordlist="wordlists/jwt_secrets.txt",
        test_logout_invalidation=True
    )
    
    # Create mock HTTP client
    mock_client = MockHTTPClient()
    
    # Create authentication testing module
    auth_module = AuthenticationTestingModule(auth_config, mock_client, auth_contexts)
    
    # Create test endpoints
    endpoints = [
        MockEndpoint("https://api.example.com/users"),
        MockEndpoint("https://api.example.com/admin/config"),
        MockEndpoint("https://api.example.com/public/info"),
        MockEndpoint("https://api.example.com/logout", "POST"),
        MockEndpoint("https://api.example.com/profile")
    ]
    
    logger.info("Executing authentication tests...")
    
    # Execute authentication tests
    findings = await auth_module.execute_tests(endpoints)
    
    # Display results
    print("\n" + "="*80)
    print("AUTHENTICATION TESTING RESULTS")
    print("="*80)
    
    if not findings:
        print("No authentication vulnerabilities detected.")
        return
    
    # Group findings by category
    findings_by_category = {}
    for finding in findings:
        category = finding.category
        if category not in findings_by_category:
            findings_by_category[category] = []
        findings_by_category[category].append(finding)
    
    # Display findings by category
    for category, category_findings in findings_by_category.items():
        print(f"\n{category} ({len(category_findings)} findings):")
        print("-" * 60)
        
        for i, finding in enumerate(category_findings, 1):
            print(f"{i}. Severity: {finding.severity.value}")
            print(f"   Endpoint: {finding.endpoint}")
            print(f"   Method: {finding.method}")
            print(f"   Evidence: {finding.evidence[:100]}...")
            print(f"   Recommendation: {finding.recommendation[:100]}...")
            print()
    
    # Summary statistics
    severity_counts = {}
    for finding in findings:
        severity = finding.severity.value
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    print("\nSUMMARY:")
    print("-" * 20)
    print(f"Total findings: {len(findings)}")
    for severity, count in sorted(severity_counts.items()):
        print(f"{severity}: {count}")
    
    print(f"\nTotal HTTP requests made: {mock_client.request_count}")
    
    logger.info("Authentication testing demo completed")


if __name__ == "__main__":
    asyncio.run(main())