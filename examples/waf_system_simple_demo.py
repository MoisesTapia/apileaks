#!/usr/bin/env python3
"""
Simple WAF System Demo
Quick demonstration of WAF detection and adaptive throttling capabilities
"""

import asyncio
import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.advanced.intelligent_waf_system import (
    IntelligentWAFSystem, 
    IntelligentWAFConfig
)
from modules.advanced.waf_detector import WAFType
from modules.advanced.adaptive_throttling import ThrottleStrategy
from core.logging import setup_logging


def demo_waf_evasion():
    """Demonstrate WAF evasion payload generation"""
    print("=== WAF Evasion Payload Generation Demo ===")
    
    waf_system = IntelligentWAFSystem()
    
    # Test payloads that might trigger WAF
    test_payloads = [
        "' OR '1'='1",
        "<script>alert('xss')</script>",
        "../../etc/passwd",
        "SELECT * FROM users WHERE id=1",
        "javascript:alert(1)"
    ]
    
    # Test different WAF types
    waf_types = [WAFType.CLOUDFLARE, WAFType.AWS_WAF, WAFType.MODSECURITY]
    
    for waf_type in waf_types:
        print(f"\n--- {waf_type.value.upper()} WAF Evasion ---")
        
        for payload in test_payloads[:2]:  # Test first 2 payloads
            print(f"\nOriginal: {payload}")
            
            evasion_payloads = waf_system.waf_detector.get_evasion_payloads(
                waf_type, payload
            )
            
            print(f"Evasions ({len(evasion_payloads)}):")
            for i, evasion in enumerate(evasion_payloads[:3]):  # Show first 3
                print(f"  {i+1}: {evasion}")


def demo_user_agent_rotation():
    """Demonstrate user agent rotation"""
    print("\n=== User Agent Rotation Demo ===")
    
    waf_system = IntelligentWAFSystem()
    
    print("Sequential rotation:")
    for i in range(5):
        ua = waf_system.user_agent_rotator.get_next_user_agent()
        print(f"  {i+1}: {ua}")
    
    print("\nRandom selection:")
    for i in range(3):
        ua = waf_system.user_agent_rotator.get_random_user_agent()
        print(f"  {i+1}: {ua}")


def demo_waf_signatures():
    """Demonstrate WAF signature detection"""
    print("\n=== WAF Signature Detection Demo ===")
    
    waf_system = IntelligentWAFSystem()
    
    print("Available WAF signatures:")
    for signature in waf_system.waf_detector.signatures:
        print(f"  - {signature.name} ({signature.waf_type.value})")
        print(f"    Confidence Weight: {signature.confidence_weight}")
        print(f"    Response Patterns: {len(signature.response_patterns)}")
        print(f"    Server Headers: {signature.server_headers}")
        print()


def demo_throttling_strategies():
    """Demonstrate different throttling strategies"""
    print("\n=== Throttling Strategies Demo ===")
    
    strategies = [
        ThrottleStrategy.FIXED,
        ThrottleStrategy.ADAPTIVE,
        ThrottleStrategy.EXPONENTIAL_BACKOFF,
        ThrottleStrategy.BURST_THEN_THROTTLE
    ]
    
    for strategy in strategies:
        config = IntelligentWAFConfig(
            throttle_strategy=strategy,
            initial_throttle_rate=2.0,
            min_throttle_rate=0.5,
            max_throttle_rate=10.0
        )
        
        waf_system = IntelligentWAFSystem(config)
        
        print(f"Strategy: {strategy.value}")
        print(f"  Initial Rate: {waf_system.adaptive_throttling.state.current_rate} req/s")
        print(f"  Min Rate: {waf_system.adaptive_throttling.min_rate} req/s")
        print(f"  Max Rate: {waf_system.adaptive_throttling.max_rate} req/s")
        print()


def demo_system_status():
    """Demonstrate system status reporting"""
    print("\n=== System Status Demo ===")
    
    waf_system = IntelligentWAFSystem()
    
    # Simulate some activity
    waf_system.state.waf_detected = True
    waf_system.state.total_requests = 100
    waf_system.state.blocked_requests = 15
    waf_system.state.successful_evasions = 12
    
    status = waf_system.get_system_status()
    
    print("System Status:")
    print(f"  WAF Detected: {status['waf_detection']['detected']}")
    print(f"  Total Requests: {status['statistics']['total_requests']}")
    print(f"  Blocked Requests: {status['statistics']['blocked_requests']}")
    print(f"  Block Rate: {status['statistics']['block_rate']:.2%}")
    print(f"  Successful Evasions: {status['statistics']['successful_evasions']}")
    print(f"  Evasion Success Rate: {status['statistics']['evasion_success_rate']:.2%}")


def main():
    """Run all demos"""
    print("🔒 APILeak WAF Detection and Adaptive Throttling System Demo")
    print("=" * 60)
    
    # Setup basic logging
    setup_logging(level="ERROR")  # Reduce log noise for demo
    
    try:
        demo_waf_signatures()
        demo_waf_evasion()
        demo_user_agent_rotation()
        demo_throttling_strategies()
        demo_system_status()
        
        print("\n✅ All demos completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()