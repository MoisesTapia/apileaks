"""
Prueba directa del módulo SSRF contra la API vulnerable del lab.
Bypasa el CLI y el discovery — alimenta los endpoints directamente.
Ejecutar desde el directorio apileaks/:
    python test_ssrf_direct.py
"""

import asyncio
import json
import sys

# Endpoints del lab que aceptan una URL en el body
ENDPOINTS = [
    ("POST", "http://localhost:8000/api/v1/fetch-url"),
    ("POST", "http://localhost:8000/api/v1/avatar"),
    ("POST", "http://localhost:8000/api/v2/webhook"),
    ("POST", "http://localhost:8000/api/v2/import-feed"),
    ("POST", "http://localhost:8000/api/v2/pdf-export"),
    ("POST", "http://localhost:8000/api/v3/validate-url"),
    ("POST", "http://localhost:8000/api/v3/internal-redirect"),
    ("POST", "http://localhost:8000/api/v4/notify"),
    ("POST", "http://localhost:8000/api/v4/async-screenshot"),
    ("GET",  "http://localhost:8000/api/v1/proxy"),
    ("GET",  "http://localhost:8000/api/v2/metadata"),
]


class FakeEndpoint:
    def __init__(self, method, url):
        self.method = method
        self.url = url
        self.status_code = 200


async def run():
    from core.config import SSRFConfig, AuthContext, AuthType
    from modules.owasp.ssrf_testing import SSRFTestingModule
    from utils.http_client import HTTPRequestEngine

    cfg = SSRFConfig(
        body_injection=True,
        body_injection_methods=["POST"],
        additional_internal_targets=["172.28.0.10", "internal-service"],
        # Solo probar con el target interno del lab — rápido y efectivo
        internal_targets=["127.0.0.1", "169.254.169.254", "172.28.0.10"],
        bypass_encodings=True,
    )

    auth = AuthContext(name="anon", type=AuthType.BEARER, token="", privilege_level=0)

    from utils.http_client import RateLimiter, RetryConfig, RateLimitConfig
    rate_limiter = RateLimiter(RateLimitConfig(requests_per_second=50))
    retry_config = RetryConfig()
    http_client = HTTPRequestEngine(rate_limiter=rate_limiter, retry_config=retry_config, timeout=10.0)

    module = SSRFTestingModule(cfg, http_client, [auth])

    endpoints = [FakeEndpoint(m, u) for m, u in ENDPOINTS]

    print(f"\n{'='*60}")
    print("apileaks SSRF Module — Direct Test vs SSRF Lab")
    print(f"{'='*60}")
    print(f"Endpoints: {len(endpoints)}")
    print(f"Internal targets: {cfg.internal_targets + cfg.additional_internal_targets}")
    print(f"Body injection: POST with fields from JSON_BODY_FIELDS")
    print(f"{'='*60}\n")

    findings = await module.execute_tests(endpoints)

    print(f"\n{'='*60}")
    print(f"RESULTS — {len(findings)} finding(s)")
    print(f"{'='*60}")

    if not findings:
        print("No findings.")
    else:
        by_sev = {}
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            by_sev.setdefault(sev, []).append(f)

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev not in by_sev:
                continue
            print(f"\n[{sev}] {len(by_sev[sev])} finding(s)")
            for f in by_sev[sev]:
                print(f"  • {f.category}")
                print(f"    Endpoint : {f.endpoint}")
                print(f"    Evidence : {f.evidence[:200]}")
                print()

    # Summary
    critical = sum(1 for f in findings if str(getattr(f.severity, 'value', f.severity)).upper() == "CRITICAL")
    high = sum(1 for f in findings if str(getattr(f.severity, 'value', f.severity)).upper() == "HIGH")
    medium = sum(1 for f in findings if str(getattr(f.severity, 'value', f.severity)).upper() == "MEDIUM")

    print(f"{'='*60}")
    print(f"Critical: {critical}  High: {high}  Medium: {medium}  Total: {len(findings)}")
    print(f"{'='*60}\n")

    return findings


if __name__ == "__main__":
    findings = asyncio.run(run())
    sys.exit(0 if not findings else 1)
