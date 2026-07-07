#!/usr/bin/env python3
"""
validate_config.py — CI/CD config validator for APILeaks pipelines.

Validates the coherence of environment variables before any scan starts.
Exit 0 on success, exit 1 on any validation error.
"""

import logging
import sys
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class ValidationRule:
    """A single named validation rule.

    ``check`` receives the full environment dict and returns an error string
    when the rule is violated, or ``None`` when the config is valid.
    """
    name: str
    check: Callable[[Dict[str, str]], Optional[str]]


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class ConfigValidator:
    """Validates APILeaks pipeline environment variables for consistency."""

    # Groups of variables that must all be present together when any one is set.
    REQUIRED_GROUPS: Dict[str, List[str]] = {
        "auth_flow": [
            "APILEAK_LOGIN_URL",
            "APILEAK_LOGIN_USERNAME",
            "APILEAK_LOGIN_PASSWORD",
        ],
        "jwt_attacks": ["APILEAK_JWT_TOKEN", "APILEAK_TARGET"],
        "bola_test":  ["APILEAK_BOLA_OWNER_ID"],
    }

    # The 13 valid attack vector names plus the special "all" value.
    VALID_JWT_ATTACK_NAMES: frozenset = frozenset([
        "alg_none",
        "null_signature",
        "weak_secret",
        "kid_injection",
        "jwks_spoof",
        "inline_jwks",
        "privilege_escalation",
        "user_impersonation",
        "expiration_bypass",
        "psychic_signature",
        "timestamp_tampering",
        "claim_fuzzing",
        "algorithm_confusion",
        "all",
    ])

    # Default values applied by apply_defaults() when a key is absent.
    DEFAULT_VALUES: Dict[str, str] = {
        "APILEAK_LOGIN_TOKEN_FIELD":    "access_token",
        "APILEAK_LOGIN_MFA_FIELD":      "totp_code",
        "APILEAK_CRITICAL_THRESHOLD":   "0",
        "APILEAK_HIGH_THRESHOLD":       "5",
        "APILEAK_MEDIUM_THRESHOLD":     "20",
        "APILEAK_AUTH_CONCURRENCY":     "10",
        "APILEAK_CSV_DELIMITER":        ";",
        "APILEAK_SAFE_MODE":            "false",
        "APILEAK_BOLA_TEST":            "false",
        "APILEAK_AUTH_TEST":            "false",
        "APILEAK_GATE_FAIL_ON_WARN":    "false",
        "APILEAK_USE_VPC_ENDPOINT":     "false",
        "APILEAK_REPORT_FORMATS":       "html,json",
        "APILEAK_JWT_SECRETS_WORDLIST": "wordlists/jwt_secrets.txt",
    }

    # -----------------------------------------------------------------------
    # Rule helpers (static so they can be tested in isolation)
    # -----------------------------------------------------------------------

    @staticmethod
    def _check_partial_login_vars(env: Dict[str, str]) -> Optional[str]:
        """Req 2.10 — partial login vars are not allowed.

        If 1 or 2 of the three login variables are defined but not all 3,
        return an error listing which variable(s) are missing.
        """
        login_vars = [
            "APILEAK_LOGIN_URL",
            "APILEAK_LOGIN_USERNAME",
            "APILEAK_LOGIN_PASSWORD",
        ]
        present = [v for v in login_vars if v in env and env[v]]
        if 0 < len(present) < 3:
            missing = [v for v in login_vars if v not in present]
            return (
                "Partial login configuration: all three login variables must be "
                "defined together. Missing: " + ", ".join(missing)
            )
        return None

    @staticmethod
    def _check_jwt_attacks_require_token_and_target(env: Dict[str, str]) -> Optional[str]:
        """Req 3.9 — APILEAK_JWT_ATTACKS requires APILEAK_JWT_TOKEN + APILEAK_TARGET."""
        if not env.get("APILEAK_JWT_ATTACKS"):
            return None
        missing = [
            v for v in ("APILEAK_JWT_TOKEN", "APILEAK_TARGET")
            if not env.get(v)
        ]
        if missing:
            return (
                "APILEAK_JWT_ATTACKS is defined but the following required "
                "variables are missing: " + ", ".join(missing)
            )
        return None

    @classmethod
    def _check_jwt_attack_names(cls, env: Dict[str, str]) -> Optional[str]:
        """Req 3.7 — each comma-separated value in APILEAK_JWT_ATTACKS must be valid."""
        raw = env.get("APILEAK_JWT_ATTACKS", "")
        if not raw:
            return None
        names = [n.strip() for n in raw.split(",") if n.strip()]
        invalid = [n for n in names if n not in cls.VALID_JWT_ATTACK_NAMES]
        if invalid:
            return (
                "Unrecognised JWT attack name(s) in APILEAK_JWT_ATTACKS: "
                + ", ".join(invalid)
                + ". Valid values are: "
                + ", ".join(sorted(cls.VALID_JWT_ATTACK_NAMES))
            )
        return None

    @staticmethod
    def _check_bola_test_requires_spec_or_target(env: Dict[str, str]) -> Optional[str]:
        """Req 4.5 — APILEAK_BOLA_TEST=true requires at least one discovery source."""
        if env.get("APILEAK_BOLA_TEST", "").lower() != "true":
            return None
        has_source = any(
            env.get(v)
            for v in ("APILEAK_OPENAPI_URL", "APILEAK_OPENAPI_FILE", "APILEAK_TARGET")
        )
        if not has_source:
            return (
                "APILEAK_BOLA_TEST=true requires at least one of "
                "APILEAK_OPENAPI_URL, APILEAK_OPENAPI_FILE, or APILEAK_TARGET to be defined."
            )
        return None

    @staticmethod
    def _check_bola_roles_token_count(env: Dict[str, str]) -> Optional[str]:
        """Req 4.4 — APILEAK_BOLA_ROLES and APILEAK_BOLA_ROLE_TOKENS must have equal counts."""
        roles_raw = env.get("APILEAK_BOLA_ROLES", "")
        tokens_raw = env.get("APILEAK_BOLA_ROLE_TOKENS", "")
        if not roles_raw:
            return None
        if not tokens_raw:
            return (
                "APILEAK_BOLA_ROLES is defined but APILEAK_BOLA_ROLE_TOKENS is missing."
            )
        roles = [r.strip() for r in roles_raw.split(",") if r.strip()]
        tokens = [t.strip() for t in tokens_raw.split(",") if t.strip()]
        if len(roles) != len(tokens):
            return (
                f"APILEAK_BOLA_ROLES has {len(roles)} item(s) but "
                f"APILEAK_BOLA_ROLE_TOKENS has {len(tokens)} item(s). "
                "Both must have the same number of comma-separated elements."
            )
        return None

    @staticmethod
    def _check_csv_delimiter(env: Dict[str, str]) -> Optional[str]:
        """Req 8.2 — APILEAK_CSV_DELIMITER must be exactly one character when defined."""
        delimiter = env.get("APILEAK_CSV_DELIMITER", "")
        if delimiter and len(delimiter) != 1:
            return (
                f"APILEAK_CSV_DELIMITER must be exactly 1 character, "
                f"but got {len(delimiter)!r} characters: {delimiter!r}"
            )
        return None

    # -----------------------------------------------------------------------
    # Build the rule list
    # -----------------------------------------------------------------------

    @classmethod
    def _build_validation_rules(cls) -> List[ValidationRule]:
        return [
            ValidationRule(
                name="partial_login_vars",
                check=cls._check_partial_login_vars,
            ),
            ValidationRule(
                name="jwt_attacks_require_token_and_target",
                check=cls._check_jwt_attacks_require_token_and_target,
            ),
            ValidationRule(
                name="jwt_attack_names_valid",
                check=cls._check_jwt_attack_names,
            ),
            ValidationRule(
                name="bola_test_requires_spec_or_target",
                check=cls._check_bola_test_requires_spec_or_target,
            ),
            ValidationRule(
                name="bola_roles_token_count_match",
                check=cls._check_bola_roles_token_count,
            ),
            ValidationRule(
                name="csv_delimiter_single_char",
                check=cls._check_csv_delimiter,
            ),
        ]

    # Eager instantiation so the list is shared across instances.
    VALIDATION_RULES: List[ValidationRule]

    def __init__(self) -> None:
        self.VALIDATION_RULES = self._build_validation_rules()

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def validate(self, env: Dict[str, str]) -> List[str]:
        """Run all validation rules against *env*.

        Returns a list of error strings; an empty list means the config is valid.
        """
        errors: List[str] = []
        for rule in self.VALIDATION_RULES:
            result = rule.check(env)
            if result is not None:
                errors.append(result)
        return errors

    def apply_defaults(self, env: Dict[str, str]) -> Dict[str, str]:
        """Return a copy of *env* with missing keys filled in from DEFAULT_VALUES.

        Each default that is applied is logged at INFO level.
        """
        result = dict(env)
        for key, value in self.DEFAULT_VALUES.items():
            if key not in result:
                result[key] = value
                logging.info("Config default applied: %s=%s", key, value)
        return result


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import os

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    validator = ConfigValidator()
    env = dict(os.environ)
    errors = validator.validate(env)
    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        sys.exit(1)
    else:
        print("Config validation passed.")
        sys.exit(0)
