#!/usr/bin/env python3
"""
jwt_attack_suite.py — CI/CD orchestrator for JWTAttackEngine.

This script is a thin bridge between pipeline environment variables and the
existing JWTAttackEngine core.  It does NOT reimplement any JWT attack vector.
All attack logic lives in utils/jwt_attack_engine.py.

Exit codes:
    0  — success
    1  — invalid config / unrecognised attack name / missing required env vars
"""

import asyncio
import dataclasses
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Add the apileaks root to sys.path so that utils/ and core/ are importable
# when this script is invoked from the ci-cd/scripts/ directory.
# ---------------------------------------------------------------------------
_SCRIPT_DIR = os.path.dirname(__file__)
_REPO_ROOT = os.path.abspath(os.path.join(_SCRIPT_DIR, "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from core.config import RateLimitConfig               # noqa: E402
from core.logging import get_logger                    # noqa: E402
from utils.findings import Finding                     # noqa: E402
from utils.http_client import (                        # noqa: E402
    HTTPRequestEngine,
    RateLimiter,
    RetryConfig,
)
from utils.jwt_attack_engine import JWTAttackEngine    # noqa: E402
from utils.jwt_attack_models import AttackSummary, AttackType  # noqa: E402

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# 4.1 — CI/CD name → AttackType mapping
# ---------------------------------------------------------------------------

VALID_ATTACK_NAMES: Dict[str, Optional[AttackType]] = {
    "alg_none":             AttackType.ALG_NONE,
    "null_signature":       AttackType.NULL_SIGNATURE,
    "weak_secret":          AttackType.WEAK_SECRET,
    "kid_injection":        AttackType.KID_INJECTION,
    "jwks_spoof":           AttackType.JWKS_SPOOF,
    "inline_jwks":          AttackType.INLINE_JWKS,
    "privilege_escalation": AttackType.PRIVILEGE_ESCALATION,
    "user_impersonation":   AttackType.USER_IMPERSONATION,
    "expiration_bypass":    AttackType.EXPIRATION_BYPASS,
    "psychic_signature":    AttackType.PSYCHIC_SIGNATURE,
    "timestamp_tampering":  AttackType.TIMESTAMP_TAMPERING,
    "claim_fuzzing":        AttackType.CLAIM_FUZZING,
    "algorithm_confusion":  AttackType.ALGORITHM_CONFUSION,
    # sentinel — expands to all 13 AttackType values
    "all":                  None,
}

# Ordered list of all 13 real attack types (used when attacks == ["all"])
ALL_ATTACK_TYPES: List[AttackType] = [
    AttackType.ALG_NONE,
    AttackType.NULL_SIGNATURE,
    AttackType.WEAK_SECRET,
    AttackType.KID_INJECTION,
    AttackType.JWKS_SPOOF,
    AttackType.INLINE_JWKS,
    AttackType.PRIVILEGE_ESCALATION,
    AttackType.USER_IMPERSONATION,
    AttackType.EXPIRATION_BYPASS,
    AttackType.PSYCHIC_SIGNATURE,
    AttackType.TIMESTAMP_TAMPERING,
    AttackType.CLAIM_FUZZING,
    AttackType.ALGORITHM_CONFUSION,
]


# ---------------------------------------------------------------------------
# 4.2 — Config dataclass
# ---------------------------------------------------------------------------

@dataclass
class JWTAttackSuiteConfig:
    """Configuration for the JWTAttackSuite CI/CD orchestrator."""

    token: str
    target_url: str
    attacks: List[str]
    wordlist_path: str = "wordlists/jwt_secrets.txt"
    rsa_public_key: Optional[str] = None
    timeout_seconds: int = 30
    pipeline_id: str = ""


# ---------------------------------------------------------------------------
# 4.3 / 4.4 / 4.5 — JWTAttackSuite class
# ---------------------------------------------------------------------------

class JWTAttackSuite:
    """CI/CD orchestrator for the JWTAttackEngine.

    Bridges pipeline environment variables to the existing engine.  Zero attack
    logic lives here — every attack vector is executed by JWTAttackEngine.
    """

    def __init__(self, config: JWTAttackSuiteConfig) -> None:
        self.config = config

    # 4.3
    def _validate_attacks(self, attacks: List[str]) -> List[AttackType]:
        """Validate attack names and return the corresponding AttackType list.

        If *any* name is not in VALID_ATTACK_NAMES: log the unrecognised name
        and call sys.exit(1) — zero attacks are executed (Req 3.7).
        If attacks == ["all"]: return all 13 AttackType values (Req 3.5).
        Otherwise: map each name to its AttackType.
        """
        for name in attacks:
            if name not in VALID_ATTACK_NAMES:
                logger.error(
                    "Unrecognised JWT attack name",
                    name=name,
                    valid_names=", ".join(sorted(VALID_ATTACK_NAMES)),
                )
                sys.exit(1)

        if attacks == ["all"]:
            return list(ALL_ATTACK_TYPES)

        return [VALID_ATTACK_NAMES[name] for name in attacks]  # type: ignore[misc]

    # 4.4
    def _build_engine(self) -> JWTAttackEngine:
        """Instantiate HTTPRequestEngine and JWTAttackEngine from config.

        No attack logic in this method — construction only.
        """
        proxy = os.environ.get("APILEAK_PROXY")
        verify_ssl_env = os.environ.get("APILEAK_VERIFY_SSL", "true").lower()
        verify_ssl = verify_ssl_env not in ("false", "0", "no")

        rate_limiter = RateLimiter(RateLimitConfig())
        retry_config = RetryConfig()

        http_engine = HTTPRequestEngine(
            rate_limiter=rate_limiter,
            retry_config=retry_config,
            timeout=float(self.config.timeout_seconds),
            verify_ssl=verify_ssl,
            proxy=proxy,
        )

        # Read wordlist file and pass as weak_secrets list; fall back to engine
        # defaults if the file does not exist.
        weak_secrets: Optional[List[str]] = None
        wordlist_path = self.config.wordlist_path
        if wordlist_path and os.path.isfile(wordlist_path):
            try:
                with open(wordlist_path, "r", encoding="utf-8", errors="replace") as fh:
                    weak_secrets = [line.strip() for line in fh if line.strip()]
                logger.info(
                    "Loaded weak-secret candidates",
                    count=len(weak_secrets),
                    wordlist=wordlist_path,
                )
            except OSError as exc:
                logger.warning(
                    "Could not read wordlist — using engine defaults",
                    wordlist=wordlist_path,
                    error=str(exc),
                )
        else:
            if wordlist_path:
                logger.warning(
                    "Wordlist file not found — using engine defaults",
                    wordlist=wordlist_path,
                )

        engine = JWTAttackEngine(
            target_url=self.config.target_url,
            original_token=self.config.token,
            http_engine=http_engine,
            public_key_material=self.config.rsa_public_key,
            weak_secrets=weak_secrets,
        )
        return engine

    # 4.5
    async def run(self) -> List[Finding]:
        """Validate, execute, and serialize JWT attacks (Req 3.1 – 3.8).

        Step 1 — validate attack names (Req 3.7).
        Step 2 — build engine.
        Step 3 — execute attacks (all or per-vector with per-vector timeout).
        Step 4 — convert AttackSummary to findings.
        Step 5 — write reports/apileak-jwt-attacks-{pipeline_id}.json.
        """
        # Step 1 — validate
        attack_types = self._validate_attacks(self.config.attacks)

        # Step 2 — build engine
        engine = self._build_engine()

        # Step 3 — execute
        if self.config.attacks == ["all"]:
            summary: AttackSummary = await engine.execute_all()
        else:
            results = []
            engine._initialize_session()
            for attack_type in attack_types:
                try:
                    result = await asyncio.wait_for(
                        engine.execute_attack(attack_type),
                        timeout=self.config.timeout_seconds,
                    )
                    if result is not None:
                        results.append(result)
                        engine.session.total_attacks += 1
                        if result.vulnerability_assessment.is_vulnerable:
                            engine.session.successful_attacks += 1
                except asyncio.TimeoutError:
                    logger.warning(
                        "Attack timed out",
                        timeout_seconds=self.config.timeout_seconds,
                        attack_type=attack_type.name,
                    )

            from datetime import datetime as _dt
            engine.session.end_time = _dt.now()
            engine.session.attack_results = results
            engine.attack_results = results
            summary = engine._generate_summary()

        # Step 4 — convert to findings
        findings: List[Finding] = engine.to_findings(summary)

        # Step 5 — write report
        output_dir = "reports"
        os.makedirs(output_dir, exist_ok=True)
        pipeline_id = self.config.pipeline_id or "unknown"
        output_path = os.path.join(output_dir, f"apileak-jwt-attacks-{pipeline_id}.json")

        def _serialize(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, Enum):
                return obj.value
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

        findings_dicts = [dataclasses.asdict(f) for f in findings]
        output_data = {"findings": findings_dicts}

        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(output_data, fh, indent=2, default=_serialize)

        logger.info(
            "JWT attack report written",
            output_path=output_path,
            finding_count=len(findings),
        )

        return findings


# ---------------------------------------------------------------------------
# 4.6 — CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    import logging

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    token = os.environ.get("APILEAK_JWT_TOKEN")
    target = os.environ.get("APILEAK_TARGET")
    attacks_raw = os.environ.get("APILEAK_JWT_ATTACKS", "")

    # If JWT token is absent but login vars are present, guide the user.
    login_url = os.environ.get("APILEAK_LOGIN_URL")
    login_user = os.environ.get("APILEAK_LOGIN_USERNAME")
    login_pass = os.environ.get("APILEAK_LOGIN_PASSWORD")

    if not token and (login_url or login_user or login_pass):
        logger.error(
            "APILEAK_JWT_TOKEN not set but login variables are present; "
            "run auth_flow.py first to capture the JWT token",
        )
        sys.exit(1)

    # Validate required vars
    missing = []
    if not token:
        missing.append("APILEAK_JWT_TOKEN")
    if not target:
        missing.append("APILEAK_TARGET")
    if not attacks_raw:
        missing.append("APILEAK_JWT_ATTACKS")

    if missing:
        logger.error(
            "Missing required environment variable(s)",
            missing=", ".join(missing),
        )
        sys.exit(1)

    attacks = [a.strip() for a in attacks_raw.split(",") if a.strip()]

    config = JWTAttackSuiteConfig(
        token=token,
        target_url=target,
        attacks=attacks,
        wordlist_path=os.environ.get(
            "APILEAK_JWT_SECRETS_WORDLIST", "wordlists/jwt_secrets.txt"
        ),
        rsa_public_key=os.environ.get("APILEAK_RSA_PUBLIC_KEY"),
        timeout_seconds=int(os.environ.get("APILEAK_JWT_TIMEOUT", "30")),
        pipeline_id=os.environ.get("APILEAK_PIPELINE_ID", ""),
    )

    suite = JWTAttackSuite(config)
    asyncio.run(suite.run())
    sys.exit(0)
