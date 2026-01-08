#!/usr/bin/env python3
"""
WAF Detection and Adaptive Throttling Demo
Demonstrates the intelligent WAF system capabilities
"""

import asyncio
import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
from modules.advanced.intelligent_waf_system import (
    IntelligentWAFSystem, 
    IntelligentWAFConfig
)
from modules.advanced.adaptive_throttling import ThrottleStrategy
from core.logging import setup_logging
from core.monitoring import MonitoringSystem


async def demo_waf_system():
    """Demonstrate WAF detection and adaptive throttling"""
    
    # Setup logging
    logger = setup_logging(level="INFO")
    logger.info("Starting WAF Detection and Adaptive Throttling Demo")
    
    # Create monitoring system
    monitoring = MonitoringSystem(log_dir="demo_logs")
    monitoring.start_monitoring()
    
    # Configure WAF system
    config = IntelligentWAFConfig(
        enable_waf_detection=True,
        enable_adaptive_throttling=True,
        enable_user_agent_rotation=True,
        initial_throttle_rate=2.0,
        min_throttle_rate=0.5,
        max_throttle_rate=5.0,
        throttle_strategy=ThrottleStrategy.ADAPTIVE,
        waf_evasion_enabled=True
    )
    
    # Create WAF system
    waf_system = IntelligentWAFSystem(config, monitoring)
    
    # Create HTTP client
    async with httpx.AsyncClient(timeout=10.0) as client:
        
        # Test targets (use httpbin.org for safe testing)
        test_targets = [
            "https://httpbin.org/get",
            "https://httpbin.org/status/200",
            "https://httpbin.org/delay/1"
        ]
        
        for target in test_targets:
            logger.info(f"\n=== Testing target: {target} ===")
            
            try:
                # Initialize WAF system for target
                await waf_system.initialize_for_target(client, target)
                
                # Get initial system status
                status = waf_system.get_system_status()
                logger.info(f"WAF Detection: {status['waf_detection']}")
                logger.info(f"Rate Limiting: {status['rate_limiting']}")
                logger.info(f"Initial Throttle Rate: {status['throttling']['current_rate']} req/s")
                
                # Make some intelligent requests
                logger.info("Making intelligent requests...")
                
                for i in range(5):
                    try:
                        response = await waf_system.make_intelligent_request(
                            "GET", 
                            target,
                            payload="test_payload"
                        )
                        
                        logger.info(
                            f"Request {i+1}: Status {response.status_code}, "
                            f"Size: {len(response.text) if hasattr(response, 'text') else 0} bytes"
                        )
                        
                        # Small delay between requests
                        await asyncio.sleep(0.5)
                        
                    except Exception as e:
                        logger.error(f"Request {i+1} failed: {e}")
                
                # Get final system status
                final_status = waf_system.get_system_status()
                logger.info(f"\nFinal Statistics:")
                logger.info(f"  Total Requests: {final_status['statistics']['total_requests']}")
                logger.info(f"  Blocked Requests: {final_status['statistics']['blocked_requests']}")
                logger.info(f"  Block Rate: {final_status['statistics']['block_rate']:.2%}")
                logger.info(f"  Final Throttle Rate: {final_status['throttling']['current_rate']:.2f} req/s")
                
                # Reset for next target
                waf_system.reset_system()
                
            except Exception as e:
                logger.error(f"Error testing {target}: {e}")
    
    # Demonstrate WAF evasion techniques
    logger.info("\n=== Demonstrating WAF Evasion Techniques ===")
    
    # Test payloads that might trigger WAF
    test_payloads = [
        "' OR '1'='1",
        "<script>alert('xss')</script>",
        "../../etc/passwd",
        "SELECT * FROM users",
        "javascript:alert(1)"
    ]
    
    for payload in test_payloads:
        logger.info(f"\nOriginal payload: {payload}")
        
        # Generate evasion payloads
        evasion_payloads = waf_system.waf_detector.get_evasion_payloads(
            waf_system.waf_detector.signatures[0].waf_type,  # Use first WAF type
            payload
        )
        
        logger.info(f"Evasion variants ({len(evasion_payloads)}):")
        for i, evasion in enumerate(evasion_payloads[:3]):  # Show first 3
            logger.info(f"  {i+1}: {evasion}")
    
    # Demonstrate user agent rotation
    logger.info("\n=== Demonstrating User Agent Rotation ===")
    
    for i in range(5):
        ua = waf_system.user_agent_rotator.get_next_user_agent()
        logger.info(f"User Agent {i+1}: {ua}")
    
    # Get final monitoring metrics
    logger.info("\n=== Final Monitoring Metrics ===")
    metrics = monitoring.get_metrics_summary()
    logger.info(f"System Performance: {metrics['performance']}")
    logger.info(f"Active Alerts: {metrics['alerts']['active_count']}")
    
    # Stop monitoring
    monitoring.stop_monitoring()
    
    logger.info("\n✅ WAF Detection and Adaptive Throttling Demo completed!")


if __name__ == "__main__":
    asyncio.run(demo_waf_system())