"""
mcp_server.jwt_tools — MCP tool spec for ``apileak.jwt.attack_test``.

Implements Task 2.3 (JWT portion): register the ``apileak.jwt.attack_test``
tool that maps to ``utils/jwt_attack_engine.py::JWTAttackEngine``.

The handler runs the JWT attack engine programmatically using the same
``JWTAttackEngine`` that the CLI ``jwt attack-test`` command uses, reusing
its response analysis and finding generation logic.  It avoids any dependency
on Click context or subprocess invocation (Requirement 4.6 / OWASP MCP05).

Tool name: ``apileak.jwt.attack_test``

Attack vectors covered by the engine:
  - Algorithm-none bypass
  - Null-signature attacks
  - Weak HMAC secret brute-force
  - Algorithm confusion (RS256 → HS256)
  - Key ID (kid) injection
  - JWKS URL spoofing (jku manipulation)
  - Inline JWKS injection
  - Privilege escalation via claim modification
  - User impersonation (subject/user-id claim tampering)
  - Expiration bypass

Requirements: 1.2, 1.4
"""

from __future__ import annotations

import dataclasses
import uuid
from typing import Any

from core.config import RateLimitConfig
from core.logging import get_logger
from mcp_server.schemas import MCPToolError, MCPToolResult, MCPToolSpec
from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig
from utils.jwt_attack_engine import JWTAttackEngine

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# JSON Schema — input parameters for apileak.jwt.attack_test
#
# Derived from the options accepted by ``jwt attack-test`` in
# ``cli/commands/jwt_cmds.py``.  Property names use snake_case to match the
# Click ``dest`` names where relevant.
# ---------------------------------------------------------------------------

JWT_ATTACK_TEST_INPUT_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["token", "url"],
    "additionalProperties": False,
    "properties": {
        # --- Required -----------------------------------------------------------
        "token": {
            "type": "string",
            "description": (
                "JWT token to use as the base for attack generation. "
                "Must be a syntactically valid JWT (header.payload.signature). "
                "The engine validates and decodes this token before any request "
                "is issued."
            ),
        },
        "url": {
            "type": "string",
            "description": (
                "Target endpoint URL to test the generated attack tokens against "
                "(e.g. https://api.example.com/protected). "
                "A live URL is required for end-to-end attack execution."
            ),
        },
        # --- Request configuration ------------------------------------------
        "method": {
            "type": "string",
            "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
            "description": (
                "HTTP method to use when sending attack tokens (default: inferred "
                "from the target or GET when no body is supplied, POST otherwise)."
            ),
        },
        "headers": {
            "type": "array",
            "items": {
                "type": "string",
                "pattern": "^[^:]+:.+$",
                "description": "Custom header in 'Name: Value' format.",
            },
            "description": (
                "Additional HTTP headers to include in every request "
                "(e.g. ['X-API-Key: secret', 'Content-Type: application/json']). "
                "Values for Authorization, Cookie, and X-API-Key are masked in logs."
            ),
        },
        "data": {
            "type": "string",
            "description": (
                "POST body data to include in each request. "
                "Use JSON string for APIs expecting application/json payloads "
                "(e.g. '{\"userId\": 123}')."
            ),
        },
        "timeout": {
            "type": "integer",
            "minimum": 1,
            "default": 30,
            "description": "Per-request HTTP timeout in seconds (default: 30).",
        },
        "no_ssl_verify": {
            "type": "boolean",
            "default": False,
            "description": (
                "Disable SSL certificate verification. "
                "Use only in test environments with self-signed certificates."
            ),
        },
        "max_retries": {
            "type": "integer",
            "minimum": 0,
            "default": 3,
            "description": "Maximum retry attempts for failed requests (default: 3).",
        },
        # --- Attack-vector configuration ------------------------------------
        "signing_secret": {
            "type": "string",
            "description": (
                "Known HMAC signing secret for the algorithm-confusion and "
                "expired-token-acceptance tests. When supplied, the engine uses "
                "this key instead of common-weak-secret brute-force."
            ),
        },
        "public_key": {
            "type": "string",
            "description": (
                "RSA public key material (PEM/DER path or inline PEM string) for "
                "the algorithm-confusion attack (RS256 → HS256 downgrade). "
                "When supplied, the engine uses the server's own public key as "
                "the HMAC signing secret."
            ),
        },
    },
}

#: JSON Schema for the tool's structured output.
JWT_ATTACK_TEST_OUTPUT_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["tool_name", "findings"],
    "properties": {
        "tool_name": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "description": "APILeak Finding in standard format.",
            },
        },
        "metadata": {
            "type": "object",
            "description": (
                "Attack session statistics: session_id, total_attacks, "
                "successful_attacks, success_rate, duration_seconds."
            ),
        },
        "untrusted_content": {
            "type": "boolean",
            "description": (
                "Always True — findings contain verbatim target response data. "
                "Clients SHOULD apply prompt-injection defences (OWASP MCP06)."
            ),
        },
    },
}


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


async def _jwt_attack_test_handler(params: dict[str, Any]) -> MCPToolResult:
    """Execute the JWT attack test suite and return findings in structured MCP format.

    This is the ``handler`` for the ``apileak.jwt.attack_test``
    :class:`~mcp_server.schemas.MCPToolSpec`.  It is called by
    :meth:`~mcp_server.tool_registry.MCPToolRegistry.invoke` after schema
    validation.

    The handler:
    1. Constructs an :class:`~utils.http_client.HTTPRequestEngine` using the
       caller-supplied timeout / SSL settings.
    2. Initialises :class:`~utils.jwt_attack_engine.JWTAttackEngine` with the
       token, target URL, and optional signing/public-key material.
    3. Calls ``engine.execute_all()`` to run every attack vector.
    4. Converts the :class:`~utils.jwt_attack_models.AttackSummary` to
       standard :class:`~utils.findings.Finding` objects via
       ``engine.to_findings()``.
    5. Serialises findings to plain dicts for MCP transport.

    Parameters are passed as data objects — **no shell interpolation or
    ``shell=True``** (Requirement 4.6 / OWASP MCP05).

    Requirements: 1.2, 1.4
    """
    token = params["token"]
    url = params["url"]
    timeout = params.get("timeout", 30)
    verify_ssl = not params.get("no_ssl_verify", False)
    max_retries = params.get("max_retries", 3)

    logger.info(
        "mcp_jwt_attack_test_starting",
        url=url,
        timeout=timeout,
        verify_ssl=verify_ssl,
    )

    # --- Parse custom headers (as data, never via shell interpolation) ------
    custom_headers: dict[str, str] = {}
    for raw_header in params.get("headers") or []:
        if ":" not in raw_header:
            raise MCPToolError(
                f"Invalid header format: {raw_header!r}. Use 'Name: Value' format.",
                error_code="INVALID_PARAMS",
            )
        name, value = raw_header.split(":", 1)
        custom_headers[name.strip()] = value.strip()

    # --- Build HTTP engine --------------------------------------------------
    rate_limiter = RateLimiter(RateLimitConfig())
    retry_config = RetryConfig(max_attempts=max_retries + 1)
    http_engine = HTTPRequestEngine(
        rate_limiter,
        retry_config,
        timeout=timeout,
        verify_ssl=verify_ssl,
    )

    # --- Build JWT attack engine and run ------------------------------------
    try:
        engine = JWTAttackEngine(
            target_url=url,
            original_token=token,
            http_engine=http_engine,
            signing_secret=params.get("signing_secret"),
            public_key_material=params.get("public_key"),
            custom_headers=custom_headers,
            post_data=params.get("data"),
            method=params.get("method"),
        )

        attack_summary = await engine.execute_all()
    except ValueError as exc:
        raise MCPToolError(
            f"JWT token validation failed: {exc}",
            error_code="INVALID_JWT",
        ) from exc
    except Exception as exc:
        raise MCPToolError(
            f"JWT attack test execution failed: {exc}",
            error_code="ATTACK_ERROR",
        ) from exc
    finally:
        await http_engine.close()

    # --- Convert summary to standard Finding objects -----------------------
    scan_id = str(uuid.uuid4())[:8]
    raw_findings = engine.to_findings(attack_summary, scan_id=scan_id)

    # --- Serialise findings to plain dicts ---------------------------------
    serialised: list[dict[str, Any]] = []
    for f in raw_findings:
        try:
            d = dataclasses.asdict(f)
            # Severity enum → string value
            if hasattr(d.get("severity"), "value"):
                d["severity"] = d["severity"].value
            elif not isinstance(d.get("severity"), str):
                from core.config import Severity

                if isinstance(f.severity, Severity):
                    d["severity"] = f.severity.value
            # datetime → ISO string
            if hasattr(d.get("timestamp"), "isoformat"):
                d["timestamp"] = d["timestamp"].isoformat()
            serialised.append(d)
        except Exception as exc:
            logger.warning(
                "mcp_jwt_finding_serialise_error",
                finding_id=getattr(f, "id", None),
                error=str(exc),
            )

    # --- Build metadata from attack session ---------------------------------
    session = attack_summary.session
    metadata: dict[str, Any] = {
        "target": url,
        "finding_count": len(serialised),
        "session_id": getattr(session, "session_id", None),
        "total_attacks": getattr(session, "total_attacks", None),
        "successful_attacks": getattr(session, "successful_attacks", None),
        "success_rate": getattr(session, "success_rate", None),
        "duration_seconds": getattr(session, "duration", None),
    }

    logger.info(
        "mcp_jwt_attack_test_completed",
        url=url,
        finding_count=len(serialised),
        successful_attacks=metadata.get("successful_attacks"),
    )

    # Findings include verbatim target response data → mark untrusted
    # (Requirement 4.8 / OWASP MCP06).
    return MCPToolResult(
        tool_name="apileak.jwt.attack_test",
        findings=serialised,
        metadata=metadata,
        untrusted_content=True,
    )


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------


def build_jwt_tool_specs() -> list[MCPToolSpec]:
    """Return the :class:`MCPToolSpec` list for JWT attack testing tools.

    Currently exposes a single tool:

    - ``apileak.jwt.attack_test``: comprehensive JWT attack test suite mapping
      to ``utils/jwt_attack_engine.py::JWTAttackEngine``.

    Called by :meth:`~mcp_server.server.APILeakMCPServer._register_default_tools`
    to register the tool with the
    :class:`~mcp_server.tool_registry.MCPToolRegistry`.

    Requirements: 1.2, 1.4
    """
    return [
        MCPToolSpec(
            name="apileak.jwt.attack_test",
            description=(
                "Comprehensive JWT attack test suite against a live API endpoint. "
                "Runs all attack vectors: algorithm-none bypass, null-signature, "
                "weak-secret brute-force, algorithm-confusion (RS256→HS256), "
                "kid injection, JWKS spoofing, inline JWKS injection, privilege "
                "escalation, user impersonation, and expiration bypass. "
                "Compares each attack response against the baseline to detect "
                "authentication bypass with confidence scoring. "
                "Maps to `apileaks jwt attack-test` on the CLI."
            ),
            input_schema=JWT_ATTACK_TEST_INPUT_SCHEMA,
            output_schema=JWT_ATTACK_TEST_OUTPUT_SCHEMA,
            # JWT attack testing is non-destructive (read-only probes that
            # carry forged tokens — no write operations on the target).
            is_destructive=False,
            handler=_jwt_attack_test_handler,
            max_execution_seconds=300.0,
        ),
    ]
