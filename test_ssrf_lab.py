"""
apileaks SSRF Module — 3-Level Test vs SSRF Lab
================================================

Nivel 1  — BÁSICO    : query params + headers (sin body injection)
Nivel 2  — INTERMEDIO: body injection en todos los POST endpoints
Nivel 3  — AVANZADO  : bypass encodings + scheme probes + targets extra

Ejecutar desde el directorio apileaks/:
    source venv/bin/activate && python test_ssrf_lab.py
"""

import asyncio
import sys
from collections import Counter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_endpoint(method, url):
    class EP:
        pass
    e = EP()
    e.method = method
    e.url = url
    return e


def _make_module(cfg):
    from core.config import AuthContext, AuthType
    from modules.owasp.ssrf_testing import SSRFTestingModule
    from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig, RateLimitConfig

    auth = AuthContext(name="anon", type=AuthType.BEARER, token="", privilege_level=0)
    rl = RateLimiter(RateLimitConfig(requests_per_second=50))
    rc = RetryConfig()
    client = HTTPRequestEngine(rate_limiter=rl, retry_config=rc, timeout=8.0)
    return SSRFTestingModule(cfg, client, [auth])


def _print_summary(level_name, findings):
    from collections import Counter
    cats = Counter(f.category for f in findings)
    sevs = Counter(str(getattr(f.severity, 'value', f.severity)).upper() for f in findings)

    print(f"\n{'='*64}")
    print(f"  {level_name}")
    print(f"{'='*64}")
    print(f"  Total findings : {len(findings)}")
    print(f"  By severity    : {dict(sevs)}")
    print(f"  By category    : {dict(cats)}")

    # Print one unique example per (category, endpoint) pair
    seen = set()
    for f in findings:
        k = (f.category, f.url if hasattr(f, 'url') else f.endpoint)
        if k in seen:
            continue
        seen.add(k)
        sev = str(getattr(f.severity, 'value', f.severity)).upper()
        ep  = getattr(f, 'endpoint', getattr(f, 'url', ''))
        ev  = getattr(f, 'evidence', '')[:160]
        print(f"\n  [{sev}] {f.category}")
        print(f"  Endpoint : {ep}")
        print(f"  Evidence : {ev}")
    print()


# ---------------------------------------------------------------------------
# NIVEL 1 — BÁSICO: query params + headers únicamente
# ---------------------------------------------------------------------------

async def nivel1_basico():
    """Solo inyección en query params y headers. Sin body injection."""
    from core.config import SSRFConfig

    print("\n" + "="*64)
    print("  NIVEL 1 — BÁSICO: Query Params + Headers")
    print("  Endpoints: proxy (GET), metadata (GET)")
    print("="*64)

    cfg = SSRFConfig(
        body_injection=False,
        bypass_encodings=True,
        internal_targets=["127.0.0.1", "169.254.169.254"],
        additional_internal_targets=["172.28.0.10", "internal-service"],
    )
    module = _make_module(cfg)

    endpoints = [
        _make_endpoint("GET",  "http://localhost:8000/api/v1/proxy"),
        _make_endpoint("GET",  "http://localhost:8000/api/v2/metadata"),
    ]

    findings = await module.execute_tests(endpoints)
    _print_summary("NIVEL 1 — BÁSICO RESULTS", findings)
    return findings


# ---------------------------------------------------------------------------
# NIVEL 2 — INTERMEDIO: body injection en todos los POST endpoints
# ---------------------------------------------------------------------------

async def nivel2_intermedio():
    """Body injection activado — prueba los 9 endpoints POST del lab."""
    from core.config import SSRFConfig

    print("\n" + "="*64)
    print("  NIVEL 2 — INTERMEDIO: Body Injection (POST endpoints)")
    print("  Endpoints: fetch-url, avatar, webhook, import-feed,")
    print("             pdf-export, validate-url, notify, async-screenshot")
    print("="*64)

    cfg = SSRFConfig(
        body_injection=True,
        body_injection_methods=["POST"],
        bypass_encodings=False,          # solo probes directos, sin bypass
        internal_targets=["127.0.0.1", "169.254.169.254"],
        additional_internal_targets=["172.28.0.10", "internal-service"],
    )
    module = _make_module(cfg)

    endpoints = [
        _make_endpoint("POST", "http://localhost:8000/api/v1/fetch-url"),
        _make_endpoint("POST", "http://localhost:8000/api/v1/avatar"),
        _make_endpoint("POST", "http://localhost:8000/api/v2/webhook"),
        _make_endpoint("POST", "http://localhost:8000/api/v2/import-feed"),
        _make_endpoint("POST", "http://localhost:8000/api/v2/pdf-export"),
        _make_endpoint("POST", "http://localhost:8000/api/v3/validate-url"),
        _make_endpoint("POST", "http://localhost:8000/api/v4/notify"),
        _make_endpoint("POST", "http://localhost:8000/api/v4/async-screenshot"),
    ]

    findings = await module.execute_tests(endpoints)
    _print_summary("NIVEL 2 — INTERMEDIO RESULTS", findings)
    return findings


# ---------------------------------------------------------------------------
# NIVEL 3 — AVANZADO: bypass encodings + scheme probes + todos los endpoints
# ---------------------------------------------------------------------------

async def nivel3_avanzado():
    """Full red-team: body injection + bypass encodings + scheme probes."""
    from core.config import SSRFConfig

    print("\n" + "="*64)
    print("  NIVEL 3 — AVANZADO: Bypass Encodings + Scheme Probes")
    print("  Endpoints: todos (11) — GET + POST")
    print("="*64)

    cfg = SSRFConfig(
        body_injection=True,
        body_injection_methods=["POST"],
        bypass_encodings=True,           # decimal, hex, octal, IPv6, credentials
        internal_targets=["127.0.0.1", "169.254.169.254"],
        additional_internal_targets=["172.28.0.10", "internal-service"],
    )
    module = _make_module(cfg)

    endpoints = [
        # GET endpoints (query param + header injection)
        _make_endpoint("GET",  "http://localhost:8000/api/v1/proxy"),
        _make_endpoint("GET",  "http://localhost:8000/api/v2/metadata"),
        # POST endpoints (body injection)
        _make_endpoint("POST", "http://localhost:8000/api/v1/fetch-url"),
        _make_endpoint("POST", "http://localhost:8000/api/v1/avatar"),
        _make_endpoint("POST", "http://localhost:8000/api/v2/webhook"),
        _make_endpoint("POST", "http://localhost:8000/api/v2/import-feed"),
        _make_endpoint("POST", "http://localhost:8000/api/v2/pdf-export"),
        _make_endpoint("POST", "http://localhost:8000/api/v3/validate-url"),
        _make_endpoint("POST", "http://localhost:8000/api/v3/internal-redirect"),
        _make_endpoint("POST", "http://localhost:8000/api/v4/notify"),
        _make_endpoint("POST", "http://localhost:8000/api/v4/async-screenshot"),
    ]

    findings = await module.execute_tests(endpoints)
    _print_summary("NIVEL 3 — AVANZADO RESULTS", findings)
    return findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main():
    print("\n" + "="*64)
    print("  apileaks SSRF Module vs SSRF Lab API")
    print("  Target : http://localhost:8000")
    print("  Lab    : BurpXML + HAR + 4 attack levels")
    print("="*64)

    f1 = await nivel1_basico()
    f2 = await nivel2_intermedio()
    f3 = await nivel3_avanzado()

    all_f = f1 + f2 + f3
    sevs  = Counter(str(getattr(f.severity, 'value', f.severity)).upper() for f in all_f)
    cats  = Counter(f.category for f in all_f)

    print("\n" + "="*64)
    print("  RESUMEN FINAL — Todos los niveles")
    print("="*64)
    print(f"  Total findings  : {len(all_f)}")
    print(f"  CRITICAL        : {sevs.get('CRITICAL', 0)}")
    print(f"  HIGH            : {sevs.get('HIGH', 0)}")
    print(f"  MEDIUM          : {sevs.get('MEDIUM', 0)}")
    print(f"  By category     : {dict(cats)}")
    print("="*64)


if __name__ == "__main__":
    asyncio.run(main())
