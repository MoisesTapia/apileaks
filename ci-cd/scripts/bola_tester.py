#!/usr/bin/env python3
"""
bola_tester.py — BOLA CI/CD Tester for APILeaks pipelines.

Tests endpoints discovered via OpenAPI spec for BOLA/IDOR vulnerabilities
by substituting IDs and detecting cross-user access.

Exit codes:
    0 — success (tests ran, results written)
    1 — config error (mismatch ROLES/ROLE_TOKENS, no spec + no target, etc.)
"""

import asyncio
import json
import logging
import os
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import httpx

# ---------------------------------------------------------------------------
# Sibling import
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(__file__))
from openapi_discoverer import DiscoveredEndpoint  # noqa: E402

logger = logging.getLogger(__name__)

# Common ID path patterns used when running fuzzing fallback (Req 4.5)
FUZZING_ID_PATHS = [
    "/users/{id}",
    "/accounts/{id}",
    "/orders/{id}",
    "/profiles/{id}",
    "/items/{id}",
    "/resources/{id}",
]

# HTTP methods considered "unsafe" and skipped in safe mode (Req 4.6)
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class BOLATesterConfig:
    """Configuration for the BOLATester."""

    owner_id: str                           # APILEAK_BOLA_OWNER_ID
    user_ids: List[str]                     # parsed from APILEAK_BOLA_USER_IDS
    jwt_token: Optional[str] = None        # default Bearer token
    roles: List[str] = field(default_factory=list)        # from APILEAK_BOLA_ROLES
    role_tokens: List[str] = field(default_factory=list)  # from APILEAK_BOLA_ROLE_TOKENS
    safe_mode: bool = False                # APILEAK_SAFE_MODE == "true"
    pipeline_id: str = "local"             # APILEAK_PIPELINE_ID
    target_url: Optional[str] = None       # APILEAK_TARGET (fuzzing fallback)
    output_dir: str = "reports"


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class BOLATester:
    """Tests endpoints for BOLA/IDOR vulnerabilities via ID substitution."""

    def __init__(self, config: BOLATesterConfig) -> None:
        self._config = config
        self._substitutions_made = 0
        self._endpoints_tested = 0

    # -----------------------------------------------------------------------
    # Public entry point
    # -----------------------------------------------------------------------

    async def run(
        self, endpoints: Optional[List[DiscoveredEndpoint]] = None
    ) -> List[dict]:
        """
        Main entry point.
        - If endpoints is None or empty, uses fuzzing fallback (Req 4.5)
        - If safe_mode, filters endpoints to GET-only (Req 4.6)
        - Validates ROLES/ROLE_TOKENS count match (Req 4.4)
        - For each ID endpoint, substitutes each user_id (Req 4.2)
        - Returns list of finding dicts
        """
        config = self._config

        # Fallback to fuzzing when no endpoints provided (Req 4.5)
        if not endpoints:
            return await self._run_fuzzing_fallback()

        # Validate roles/tokens count match (Req 4.4)
        if config.roles and config.role_tokens:
            if len(config.roles) != len(config.role_tokens):
                logger.error(
                    "APILEAK_BOLA_ROLES has %d element(s) but APILEAK_BOLA_ROLE_TOKENS "
                    "has %d element(s). Counts must match.",
                    len(config.roles),
                    len(config.role_tokens),
                )
                sys.exit(1)

        # Apply safe mode filter (Req 4.6)
        if config.safe_mode:
            endpoints = self._apply_safe_mode(endpoints)

        # Filter to endpoints that have ID parameters (Req 4.1)
        id_endpoints = self._get_id_endpoints(endpoints)

        findings: List[dict] = []

        # Determine which tokens to use for testing (Req 4.4)
        if config.roles and config.role_tokens:
            token_context = list(zip(config.roles, config.role_tokens))
        elif config.jwt_token:
            token_context = [(None, config.jwt_token)]
        else:
            token_context = [(None, None)]

        for endpoint in id_endpoints:
            for param_name in endpoint.id_parameters:
                for substitute_id in config.user_ids:
                    self._substitutions_made += 1
                    for role_label, token in token_context:
                        finding = await self._test_endpoint(
                            endpoint,
                            param_name,
                            substitute_id,
                            token,
                            role_label=role_label,
                        )
                        if finding:
                            findings.append(finding)
            self._endpoints_tested += 1

        return findings

    # -----------------------------------------------------------------------
    # Filtering helpers
    # -----------------------------------------------------------------------

    def _get_id_endpoints(
        self, endpoints: List[DiscoveredEndpoint]
    ) -> List[DiscoveredEndpoint]:
        """Return endpoints that have id_parameters."""
        return [ep for ep in endpoints if ep.id_parameters]

    def _apply_safe_mode(
        self, endpoints: List[DiscoveredEndpoint]
    ) -> List[DiscoveredEndpoint]:
        """When safe_mode=True, filter methods to GET only.

        Endpoints with no GET method are excluded entirely.
        """
        result: List[DiscoveredEndpoint] = []
        for ep in endpoints:
            safe_methods = [m for m in ep.methods if m.upper() == "GET"]
            if not safe_methods:
                logger.debug(
                    "Safe mode: skipping %s — no GET method available (methods: %s)",
                    ep.path,
                    ep.methods,
                )
                continue
            # Return endpoint with only GET methods
            import dataclasses
            result.append(dataclasses.replace(ep, methods=safe_methods))
        return result

    # -----------------------------------------------------------------------
    # URL building
    # -----------------------------------------------------------------------

    def _build_url(
        self,
        base_url: str,
        path: str,
        param_name: str,
        substitute_id: str,
    ) -> str:
        """Build a test URL by substituting {param_name} in the path.

        If base_url is provided, prepend it. Otherwise use path as-is.
        Also handles paths where the literal owner_id value is embedded.
        """
        # Replace template placeholder like {user_id}
        substituted = path.replace(f"{{{param_name}}}", substitute_id)

        # Also replace literal owner_id embedded in path
        owner_id = self._config.owner_id
        if owner_id and owner_id in substituted:
            substituted = substituted.replace(owner_id, substitute_id)

        if base_url:
            base = base_url.rstrip("/")
            if not substituted.startswith("/"):
                substituted = "/" + substituted
            return base + substituted

        return substituted

    # -----------------------------------------------------------------------
    # Response analysis
    # -----------------------------------------------------------------------

    def _check_id_in_response(
        self, body: str, substitute_id: str
    ) -> Optional[str]:
        """Parse JSON body. Return the field name whose value equals substitute_id, or None."""
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return None

        return self._search_id_in_json(data, substitute_id)

    def _search_id_in_json(self, data: Any, substitute_id: str) -> Optional[str]:
        """Recursively search JSON structure for a field whose value equals substitute_id."""
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (str, int)) and str(value) == str(substitute_id):
                    return key
                nested = self._search_id_in_json(value, substitute_id)
                if nested:
                    return nested
        elif isinstance(data, list):
            for item in data:
                nested = self._search_id_in_json(item, substitute_id)
                if nested:
                    return nested
        return None

    # -----------------------------------------------------------------------
    # Single endpoint test
    # -----------------------------------------------------------------------

    async def _test_endpoint(
        self,
        endpoint: DiscoveredEndpoint,
        param_name: str,
        substitute_id: str,
        jwt_token: Optional[str],
        role_label: Optional[str] = None,
    ) -> Optional[dict]:
        """Issue request with Authorization: Bearer jwt_token.

        On HTTP 200 + body contains substitute_id value → return CRITICAL finding.
        Returns None if no vulnerability found.
        """
        config = self._config

        # Determine base URL from target or use path directly
        base_url = config.target_url or ""
        url = self._build_url(base_url, endpoint.path, param_name, substitute_id)

        # Use GET preferably, fall back to first method
        method = "GET"
        if endpoint.methods:
            if "GET" in [m.upper() for m in endpoint.methods]:
                method = "GET"
            else:
                method = endpoint.methods[0].upper()

        headers: Dict[str, str] = {}
        if jwt_token:
            headers["Authorization"] = f"Bearer {jwt_token}"

        try:
            async with httpx.AsyncClient() as client:
                response = await client.request(method, url, headers=headers)
        except httpx.ConnectError as exc:
            logger.warning(
                "Connection error testing %s %s (param=%s, sub_id=%s): %s — skipping.",
                method,
                url,
                param_name,
                substitute_id,
                exc,
            )
            return None
        except Exception as exc:
            logger.warning(
                "Unexpected error testing %s %s: %s — skipping.",
                method,
                url,
                exc,
            )
            return None

        if response.status_code != 200:
            return None

        # Check if substitute_id appears in the response body (Req 4.3)
        body = response.text
        matched_field = self._check_id_in_response(body, substitute_id)
        if matched_field is None:
            return None

        # CRITICAL finding detected
        role_info = f" (role: {role_label})" if role_label else ""
        logger.warning(
            "CRITICAL BOLA: %s %s — substitute_id %r found in field %r%s",
            method,
            url,
            substitute_id,
            matched_field,
            role_info,
        )

        finding: dict = {
            "finding_id": str(uuid.uuid4()),
            "severity": "CRITICAL",
            "owasp_category": "API1:2023",
            "endpoint": url,
            "method": method,
            "status_code": response.status_code,
            "parameter": param_name,
            "evidence": matched_field,
            "recommendation": (
                "Implement proper object-level authorization checks. "
                "Verify that the authenticated user owns or is permitted to access "
                "the requested resource before returning data."
            ),
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if role_label:
            finding["role"] = role_label

        return finding

    # -----------------------------------------------------------------------
    # Fuzzing fallback (Req 4.5)
    # -----------------------------------------------------------------------

    async def _run_fuzzing_fallback(self) -> List[dict]:
        """When no OpenAPI spec is available, run basic ID substitution fuzzing.

        Requires APILEAK_TARGET to be set; otherwise exits with code 1.
        """
        config = self._config

        if not config.target_url:
            logger.error(
                "APILEAK_BOLA_TEST is enabled but no OpenAPI spec is available and "
                "APILEAK_TARGET is not defined. Cannot run BOLA tests. "
                "Set APILEAK_TARGET or provide an OpenAPI spec via "
                "APILEAK_OPENAPI_FILE or APILEAK_OPENAPI_URL."
            )
            sys.exit(1)

        logger.info(
            "No OpenAPI spec available. Running fuzzing fallback against %s",
            config.target_url,
        )

        # Validate roles/tokens count match (Req 4.4)
        if config.roles and config.role_tokens:
            if len(config.roles) != len(config.role_tokens):
                logger.error(
                    "APILEAK_BOLA_ROLES has %d element(s) but APILEAK_BOLA_ROLE_TOKENS "
                    "has %d element(s). Counts must match.",
                    len(config.roles),
                    len(config.role_tokens),
                )
                sys.exit(1)

        if config.roles and config.role_tokens:
            token_context = list(zip(config.roles, config.role_tokens))
        elif config.jwt_token:
            token_context = [(None, config.jwt_token)]
        else:
            token_context = [(None, None)]

        findings: List[dict] = []
        base = config.target_url.rstrip("/")

        for path_template in FUZZING_ID_PATHS:
            for substitute_id in config.user_ids:
                # Build URL by replacing {id} placeholder
                path = path_template.replace("{id}", substitute_id)
                url = base + path

                headers: Dict[str, str] = {}
                method = "GET"

                self._substitutions_made += 1

                for role_label, token in token_context:
                    if token:
                        headers["Authorization"] = f"Bearer {token}"

                    try:
                        async with httpx.AsyncClient() as client:
                            response = await client.request(method, url, headers=headers)
                    except httpx.ConnectError as exc:
                        logger.warning(
                            "Fuzzing: connection error for %s: %s — skipping.", url, exc
                        )
                        continue
                    except Exception as exc:
                        logger.warning(
                            "Fuzzing: unexpected error for %s: %s — skipping.", url, exc
                        )
                        continue

                    if response.status_code != 200:
                        continue

                    matched_field = self._check_id_in_response(response.text, substitute_id)
                    if matched_field is None:
                        continue

                    role_info = f" (role: {role_label})" if role_label else ""
                    logger.warning(
                        "CRITICAL BOLA (fuzzing): %s — substitute_id %r found in field %r%s",
                        url,
                        substitute_id,
                        matched_field,
                        role_info,
                    )

                    finding: dict = {
                        "finding_id": str(uuid.uuid4()),
                        "severity": "CRITICAL",
                        "owasp_category": "API1:2023",
                        "endpoint": url,
                        "method": method,
                        "status_code": response.status_code,
                        "parameter": "id",
                        "evidence": matched_field,
                        "recommendation": (
                            "Implement proper object-level authorization checks. "
                            "Verify that the authenticated user owns or is permitted "
                            "to access the requested resource before returning data."
                        ),
                        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                    }

                    if role_label:
                        finding["role"] = role_label

                    findings.append(finding)

            self._endpoints_tested += 1

        return findings

    # -----------------------------------------------------------------------
    # Output
    # -----------------------------------------------------------------------

    def write_output(self, findings: List[dict]) -> str:
        """Write findings to reports/apileak-bola-{pipeline_id}.json. Returns path."""
        config = self._config
        Path(config.output_dir).mkdir(parents=True, exist_ok=True)
        output_path = os.path.join(
            config.output_dir, f"apileak-bola-{config.pipeline_id}.json"
        )
        payload = {
            "findings": findings,
            "scan_meta": {
                "pipeline_id": config.pipeline_id,
                "endpoints_tested": self._endpoints_tested,
                "substitutions_made": self._substitutions_made,
            },
        }
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        logger.info(
            "BOLA report written: %s (%d finding(s))", output_path, len(findings)
        )
        return output_path


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    owner_id = os.environ.get("APILEAK_BOLA_OWNER_ID", "")
    user_ids_raw = os.environ.get("APILEAK_BOLA_USER_IDS", "")
    user_ids = [u.strip() for u in user_ids_raw.split(",") if u.strip()]

    if not owner_id:
        logger.error("APILEAK_BOLA_OWNER_ID is required but not set.")
        sys.exit(1)

    if not user_ids:
        logger.error("APILEAK_BOLA_USER_IDS is required but not set.")
        sys.exit(1)

    roles_raw = os.environ.get("APILEAK_BOLA_ROLES", "")
    roles = [r.strip() for r in roles_raw.split(",") if r.strip()]

    role_tokens_raw = os.environ.get("APILEAK_BOLA_ROLE_TOKENS", "")
    role_tokens = [t.strip() for t in role_tokens_raw.split(",") if t.strip()]

    config = BOLATesterConfig(
        owner_id=owner_id,
        user_ids=user_ids,
        jwt_token=os.environ.get("APILEAK_JWT_TOKEN"),
        roles=roles,
        role_tokens=role_tokens,
        safe_mode=os.environ.get("APILEAK_SAFE_MODE", "").lower() == "true",
        pipeline_id=os.environ.get("APILEAK_PIPELINE_ID", "local"),
        target_url=os.environ.get("APILEAK_TARGET"),
        output_dir="reports",
    )

    endpoints: Optional[List[DiscoveredEndpoint]] = None
    endpoints_file = os.environ.get("APILEAK_OPENAPI_ENDPOINTS_FILE")
    if endpoints_file:
        try:
            with open(endpoints_file, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            endpoints = [DiscoveredEndpoint.from_dict(ep) for ep in raw]
        except Exception as exc:
            logger.error("Failed to load endpoints from %s: %s", endpoints_file, exc)
            sys.exit(1)

    tester = BOLATester(config)
    findings = asyncio.run(tester.run(endpoints))
    tester.write_output(findings)
    sys.exit(0)
