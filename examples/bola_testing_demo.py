#!/usr/bin/env python3
"""
BOLA Testing Module Demo
Demonstrates the BOLA (Broken Object Level Authorization) testing capabilities
"""

import asyncio
import sys
import os
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from modules.owasp.bola_testing import BOLATestingModule
from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig
from core.config import BOLAConfig, AuthContext, AuthType, RateLimitConfig
from core.logging import get_logger


class MockEndpoint:
    """Mock endpoint for demonstration"""
    def __init__(self, url: str, method: str = "GET"):
        self.url = url
        self.method = method


async def demo_bola_testing():
    """Demonstrate BOLA testing functionality"""
    logger = get_logger(__name__)
    logger.info("Starting BOLA Testing Demo")
    
    # Configure BOLA testing
    bola_config = BOLAConfig(
        enabled=True,
        id_patterns=["sequential", "guid", "uuid"],
        test_contexts=["anonymous", "user", "admin"]
    )
    
    # Create authentication contexts for testing
    auth_contexts = [
        AuthContext(
            name="user1",
            type=AuthType.BEARER,
            token="user1_token_abc123",
            privilege_level=1
        ),
        AuthContext(
            name="user2",
            type=AuthType.BEARER,
            token="user2_token_def456",
            privilege_level=1
        ),
        AuthContext(
            name="admin",
            type=AuthType.BEARER,
            token="admin_token_xyz789",
            privilege_level=3
        )
    ]
    
    # Set up HTTP client with rate limiting
    rate_limit_config = RateLimitConfig(
        requests_per_second=5,
        burst_size=10,
        adaptive=True
    )
    
    retry_config = RetryConfig(
        max_attempts=2,
        backoff_factor=1.5
    )
    
    rate_limiter = RateLimiter(rate_limit_config)
    http_client = HTTPRequestEngine(rate_limiter, retry_config)
    
    # Initialize BOLA testing module
    bola_module = BOLATestingModule(bola_config, http_client, auth_contexts)
    
    logger.info("BOLA Testing Module initialized successfully")
    logger.info(f"Module name: {bola_module.get_module_name()}")
    logger.info(f"Auth contexts: {len(bola_module.auth_contexts)}")
    logger.info(f"ID patterns: {list(bola_module.ID_PATTERNS.keys())}")
    
    # Create mock endpoints with various ID patterns
    test_endpoints = [
        MockEndpoint("https://jsonplaceholder.typicode.com/users/1"),
        MockEndpoint("https://jsonplaceholder.typicode.com/posts/123"),
        MockEndpoint("https://jsonplaceholder.typicode.com/albums/456"),
        MockEndpoint("https://httpbin.org/uuid"),  # This will generate a UUID
    ]
    
    logger.info(f"Testing {len(test_endpoints)} endpoints")
    
    try:
        # Execute BOLA tests
        findings = await bola_module.execute_tests(test_endpoints)
        
        logger.info(f"BOLA testing completed. Found {len(findings)} findings")
        
        # Display findings
        if findings:
            logger.info("=== BOLA Testing Findings ===")
            for i, finding in enumerate(findings, 1):
                logger.info(f"Finding {i}:")
                logger.info(f"  Category: {finding.category}")
                logger.info(f"  Severity: {finding.severity.value}")
                logger.info(f"  OWASP Category: {finding.owasp_category}")
                logger.info(f"  Endpoint: {finding.endpoint}")
                logger.info(f"  Evidence: {finding.evidence[:100]}...")
                logger.info(f"  Recommendation: {finding.recommendation[:100]}...")
                logger.info("")
        else:
            logger.info("No BOLA vulnerabilities detected in the test endpoints")
        
        # Demonstrate ID extraction capabilities
        logger.info("=== ID Extraction Demo ===")
        test_urls = [
            "https://api.example.com/users/123",
            "https://api.example.com/accounts/550e8400-e29b-41d4-a716-446655440000",
            "https://api.example.com/orders/456/items/789",
            "https://api.example.com/documents/abc123def456"
        ]
        
        for url in test_urls:
            identifiers = bola_module._extract_ids_from_path(url)
            logger.info(f"URL: {url}")
            for identifier in identifiers:
                logger.info(f"  Found ID: {identifier.value} (type: {identifier.type}, param: {identifier.parameter_name})")
            logger.info("")
        
        # Demonstrate ID type determination
        logger.info("=== ID Type Detection Demo ===")
        test_ids = [
            "123",
            "550e8400-e29b-41d4-a716-446655440000",
            "abc123def456789",
            "dGVzdCBzdHJpbmc=",
            "not_an_id"
        ]
        
        for test_id in test_ids:
            id_type = bola_module._determine_id_type(test_id)
            logger.info(f"ID: {test_id} -> Type: {id_type or 'Unknown'}")
        
    except Exception as e:
        logger.error(f"BOLA testing failed: {e}")
        raise
    
    finally:
        # Clean up HTTP client
        await http_client.close()
        logger.info("BOLA Testing Demo completed")


async def main():
    """Main demo function"""
    try:
        await demo_bola_testing()
    except KeyboardInterrupt:
        print("\nDemo interrupted by user")
    except Exception as e:
        print(f"Demo failed: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    # Run the demo
    exit_code = asyncio.run(main())
    sys.exit(exit_code)