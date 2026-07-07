#!/usr/bin/env python3
"""
auth_flow.py — CI/CD authentication flow handler for APILeaks pipelines.

Handles login (with optional TOTP/MFA), token refresh, and broken-auth
testing against discovered endpoints.

Standalone script — does NOT import from apileaks utils/ or core/.
Uses only: stdlib + httpx + pyotp.

Exit codes:
    0  — success
    1  — login / config failure
    2  — exhausted all refresh + re-login retries
"""

import asyncio
import json
import logging
import os
import random
import string
import sys
import tempfile
from dataclasses import dataclass
from typing import List, Optional

import httpx

# ---------------------------------------------------------------------------
# Optional TOTP support
# ---------------------------------------------------------------------------
try:
    import pyotp
    _PYOTP_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PYOTP_AVAILABLE = False

# ---------------------------------------------------------------------------
# DiscoveredEndpoint import (sibling script)
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(__file__))
from openapi_discoverer import DiscoveredEndpoint  # noqa: E402

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class AuthFlowConfig:
    """Configuration for the AutoAuthFlow."""

    login_url: str
    username: str          # NEVER logged in plaintext
    password: str          # NEVER logged in plaintext
    token_field: str = "access_token"
    refresh_token_field: Optional[str] = None
    mfa_totp_secret: Optional[str] = None
    mfa_field: str = "totp_code"
    concurrency: int = 10  # APILEAK_AUTH_CONCURRENCY, clamped 1–50


@dataclass
class AuthResult:
    """Result of a successful authentication."""

    access_token: str
    refresh_token: Optional[str]   # in-memory ONLY, never written to disk
    token_field: str
    expires_in: Optional[int]


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class AutoAuthFlow:
    """Handles authentication flows for CI/CD pipelines.

    Credentials are NEVER logged in plaintext — use mask_credentials().
    Refresh tokens stay in-memory only and are never written to disk.
    """

    _MAX_REFRESH_ATTEMPTS = 3

    def __init__(self, config: AuthFlowConfig) -> None:
        # Clamp concurrency to [1, 50]
        clamped = max(1, min(50, config.concurrency))
        if clamped != config.concurrency:
            logger.warning(
                "APILEAK_AUTH_CONCURRENCY %d out of range [1, 50]; clamped to %d",
                config.concurrency,
                clamped,
            )
        self._config = config
        self._config.concurrency = clamped

    # -----------------------------------------------------------------------
    # Credential masking
    # -----------------------------------------------------------------------

    @staticmethod
    def mask_credentials(value: str) -> str:
        """Return a string of '*' with the same length as *value*."""
        return "*" * len(value)

    # -----------------------------------------------------------------------
    # Login
    # -----------------------------------------------------------------------

    async def login(self) -> AuthResult:
        """POST credentials to the configured login URL and return an AuthResult.

        Logs all activity with MASKED credentials.
        Exits with code 1 on HTTP error or missing JWT field.
        """
        config = self._config
        logger.info(
            "Attempting login to %s as %s",
            config.login_url,
            self.mask_credentials(config.username),
        )

        body: dict = {
            "username": config.username,
            "password": config.password,
        }

        # Include TOTP code if configured
        if config.mfa_totp_secret:
            if not _PYOTP_AVAILABLE:
                logger.error("pyotp is required for TOTP/MFA but is not installed.")
                sys.exit(1)
            totp_code = pyotp.TOTP(config.mfa_totp_secret).now()
            body[config.mfa_field] = totp_code
            logger.info("TOTP code included in login request (field: %s)", config.mfa_field)

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(config.login_url, json=body)
            except httpx.ConnectError as exc:
                logger.error(
                    "Connection error while attempting login to %s: %s",
                    config.login_url,
                    exc,
                )
                sys.exit(1)

        if response.status_code not in (200, 201):
            body_preview = response.text[:500]
            logger.error(
                "Login failed: HTTP %d — %s",
                response.status_code,
                body_preview,
            )
            sys.exit(1)

        try:
            data = response.json()
        except Exception:
            logger.error(
                "Login response is not valid JSON (status %d). "
                "Body (first 500 chars): %s",
                response.status_code,
                response.text[:500],
            )
            sys.exit(1)

        if config.token_field not in data:
            logger.error(
                "JWT field %r not found in login response. "
                "Present fields: %s",
                config.token_field,
                list(data.keys()),
            )
            sys.exit(1)

        access_token: str = data[config.token_field]
        refresh_token: Optional[str] = None
        if config.refresh_token_field and config.refresh_token_field in data:
            refresh_token = data[config.refresh_token_field]

        expires_in: Optional[int] = data.get("expires_in")

        logger.info(
            "Login successful. Token field: %s. Token: %s",
            config.token_field,
            self.mask_credentials(access_token),
        )

        return AuthResult(
            access_token=access_token,
            refresh_token=refresh_token,
            token_field=config.token_field,
            expires_in=expires_in,
        )

    # -----------------------------------------------------------------------
    # Refresh
    # -----------------------------------------------------------------------

    async def refresh(
        self, auth_result: AuthResult, attempt: int = 0
    ) -> AuthResult:
        """Attempt to refresh the access token using the stored refresh token.

        Retries up to _MAX_REFRESH_ATTEMPTS times, then falls back to a
        full re-login.  Exits with code 2 if everything fails.
        """
        config = self._config
        last_error: Optional[str] = None

        # Try refresh token up to _MAX_REFRESH_ATTEMPTS times
        if config.refresh_token_field and auth_result.refresh_token:
            for i in range(self._MAX_REFRESH_ATTEMPTS):
                logger.info(
                    "Token refresh attempt %d/%d",
                    i + 1,
                    self._MAX_REFRESH_ATTEMPTS,
                )
                body = {config.refresh_token_field: auth_result.refresh_token}
                async with httpx.AsyncClient() as client:
                    try:
                        response = await client.post(config.login_url, json=body)
                    except httpx.ConnectError as exc:
                        last_error = str(exc)
                        logger.warning("Refresh attempt %d connection error: %s", i + 1, exc)
                        continue

                if response.status_code in (200, 201):
                    try:
                        data = response.json()
                    except Exception:
                        last_error = "Response is not valid JSON"
                        continue
                    if config.token_field in data:
                        new_refresh = data.get(config.refresh_token_field)
                        logger.info(
                            "Token refresh succeeded on attempt %d.", i + 1
                        )
                        return AuthResult(
                            access_token=data[config.token_field],
                            refresh_token=new_refresh,
                            token_field=config.token_field,
                            expires_in=data.get("expires_in"),
                        )
                    last_error = f"Token field {config.token_field!r} missing in refresh response"
                else:
                    last_error = f"HTTP {response.status_code}"
                    logger.warning(
                        "Refresh attempt %d failed with HTTP %d",
                        i + 1,
                        response.status_code,
                    )

        # Fall back to full re-login
        logger.info("Refresh token exhausted or unavailable; attempting full re-login.")
        try:
            return await self.login()
        except SystemExit:
            pass

        # Everything failed
        total_attempts = (self._MAX_REFRESH_ATTEMPTS if config.refresh_token_field else 0) + 1
        logger.error(
            "All token refresh and re-login attempts failed after %d attempt(s). "
            "Last error: %s",
            total_attempts,
            last_error,
        )
        sys.exit(2)

    # -----------------------------------------------------------------------
    # Broken-auth testing (Req 12)
    # -----------------------------------------------------------------------

    async def test_broken_auth(
        self, endpoints: List[DiscoveredEndpoint]
    ) -> List[dict]:
        """Test authenticated endpoints for broken authentication vulnerabilities.

        For each authenticated endpoint:
        1. Request WITHOUT Authorization header → CRITICAL if 200
        2. Request WITH invalid JWT (32 random alphanumeric chars) → HIGH if 200

        Uses asyncio.Semaphore with config.concurrency.
        Unreachable/connection-error endpoints are logged and skipped.

        Returns a list of finding dicts with keys:
            severity, endpoint, method, evidence
        """
        semaphore = asyncio.Semaphore(self._config.concurrency)
        findings: List[dict] = []
        findings_lock = asyncio.Lock()

        authenticated_endpoints = [ep for ep in endpoints if ep.is_authenticated]

        async def _test_endpoint(ep: DiscoveredEndpoint) -> None:
            # Use the first method listed (or GET as fallback)
            method = ep.methods[0] if ep.methods else "GET"
            # Build a simple URL — endpoints often don't have a base, use path as-is
            url = ep.path

            async with semaphore:
                async with httpx.AsyncClient() as client:
                    # --- Test 1: no Authorization header ---
                    try:
                        response = await client.request(method, url)
                        if response.status_code == 200:
                            finding = {
                                "severity": "CRITICAL",
                                "endpoint": ep.path,
                                "method": method,
                                "evidence": (
                                    f"Endpoint returned HTTP 200 with no Authorization header "
                                    f"(expected 401/403)."
                                ),
                            }
                            async with findings_lock:
                                findings.append(finding)
                            logger.warning(
                                "CRITICAL: %s %s accessible without Authorization header",
                                method,
                                ep.path,
                            )
                    except httpx.ConnectError as exc:
                        logger.warning(
                            "Could not reach %s %s (no-auth test): %s — skipping.",
                            method,
                            ep.path,
                            exc,
                        )
                        return
                    except Exception as exc:
                        logger.warning(
                            "Unexpected error testing %s %s (no-auth): %s — skipping.",
                            method,
                            ep.path,
                            exc,
                        )
                        return

                    # --- Test 2: invalid JWT ---
                    invalid_jwt = "".join(
                        random.choices(string.ascii_letters + string.digits, k=32)
                    )
                    headers = {"Authorization": f"Bearer {invalid_jwt}"}
                    try:
                        response = await client.request(method, url, headers=headers)
                        if response.status_code == 200:
                            finding = {
                                "severity": "HIGH",
                                "endpoint": ep.path,
                                "method": method,
                                "evidence": (
                                    "Endpoint returned HTTP 200 with an invalid JWT token "
                                    "(expected 401/403)."
                                ),
                            }
                            async with findings_lock:
                                findings.append(finding)
                            logger.warning(
                                "HIGH: %s %s accepted invalid JWT token",
                                method,
                                ep.path,
                            )
                    except httpx.ConnectError as exc:
                        logger.warning(
                            "Could not reach %s %s (invalid-jwt test): %s — skipping.",
                            method,
                            ep.path,
                            exc,
                        )
                    except Exception as exc:
                        logger.warning(
                            "Unexpected error testing %s %s (invalid-jwt): %s — skipping.",
                            method,
                            ep.path,
                            exc,
                        )

        await asyncio.gather(*[_test_endpoint(ep) for ep in authenticated_endpoints])
        return findings

    # -----------------------------------------------------------------------
    # Token file helper
    # -----------------------------------------------------------------------

    @staticmethod
    def write_token_to_env_file(token: str, env_file_path: str) -> None:
        """Write ``APILEAK_JWT_TOKEN=<token>`` to *env_file_path*.

        This is a temporary file — never a persistent artifact.
        """
        with open(env_file_path, "w", encoding="utf-8") as fh:
            fh.write(f"APILEAK_JWT_TOKEN={token}\n")
        logger.info("JWT token written to temp env file: %s", env_file_path)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    login_url = os.environ.get("APILEAK_LOGIN_URL")
    username = os.environ.get("APILEAK_LOGIN_USERNAME")
    password = os.environ.get("APILEAK_LOGIN_PASSWORD")

    # Guard: require all three login vars or none
    _present = [v for v in [login_url, username, password] if v]
    if 1 <= len(_present) < 3:
        missing = []
        if not login_url:
            missing.append("APILEAK_LOGIN_URL")
        if not username:
            missing.append("APILEAK_LOGIN_USERNAME")
        if not password:
            missing.append("APILEAK_LOGIN_PASSWORD")
        logger.error(
            "Partial login configuration: missing %s", ", ".join(missing)
        )
        sys.exit(1)

    if not login_url or not username or not password:
        logger.error(
            "APILEAK_LOGIN_URL, APILEAK_LOGIN_USERNAME, and "
            "APILEAK_LOGIN_PASSWORD must all be set to run auth_flow."
        )
        sys.exit(1)

    concurrency = int(os.environ.get("APILEAK_AUTH_CONCURRENCY", "10"))
    config = AuthFlowConfig(
        login_url=login_url,
        username=username,
        password=password,
        token_field=os.environ.get("APILEAK_LOGIN_TOKEN_FIELD", "access_token"),
        refresh_token_field=os.environ.get("APILEAK_LOGIN_REFRESH_TOKEN_FIELD"),
        mfa_totp_secret=os.environ.get("APILEAK_MFA_TOTP_SECRET"),
        mfa_field=os.environ.get("APILEAK_LOGIN_MFA_FIELD", "totp_code"),
        concurrency=concurrency,
    )

    flow = AutoAuthFlow(config)
    auth_result = asyncio.run(flow.login())

    # Write token to temp env file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".env", mode="w") as tmp:
        tmp_path = tmp.name

    AutoAuthFlow.write_token_to_env_file(auth_result.access_token, tmp_path)
    print(tmp_path)

    # Optional broken-auth testing
    auth_test = os.environ.get("APILEAK_AUTH_TEST", "").lower() == "true"
    endpoints_file = os.environ.get("APILEAK_OPENAPI_ENDPOINTS_FILE")

    if auth_test and endpoints_file:
        try:
            with open(endpoints_file, "r", encoding="utf-8") as fh:
                raw_endpoints = json.load(fh)
            endpoints = [DiscoveredEndpoint.from_dict(ep) for ep in raw_endpoints]
        except Exception as exc:
            logger.error("Failed to load endpoints from %s: %s", endpoints_file, exc)
            sys.exit(1)

        findings = asyncio.run(flow.test_broken_auth(endpoints))
        if findings:
            logger.warning("Broken auth findings: %d", len(findings))
            for f in findings:
                logger.warning(
                    "[%s] %s %s — %s",
                    f["severity"],
                    f["method"],
                    f["endpoint"],
                    f["evidence"],
                )
        else:
            logger.info("No broken-auth findings.")

    sys.exit(0)
