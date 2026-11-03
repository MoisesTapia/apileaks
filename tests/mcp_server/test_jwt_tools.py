"""
Tests for the ``apileak.jwt.attack_test`` MCP tool (Task 2.3).

Covers:
- Tool spec construction (name, schema presence, is_destructive flag)
- JSON Schema validation: required fields, enum constraints, type constraints
- Handler integration: MCPToolResult structure and untrusted_content=True flag
- Server registration: apileak.jwt.attack_test appears in the registry after init

Validates: Requirements 1.2, 1.4

Uses in-process mocks for the JWT attack engine so no real network calls are
made (Requirement 11.1 — in-memory invocation, no real MCP SDK required).
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_server.jwt_tools import (
    JWT_ATTACK_TEST_INPUT_SCHEMA,
    JWT_ATTACK_TEST_OUTPUT_SCHEMA,
    _jwt_attack_test_handler,
    build_jwt_tool_specs,
)
from mcp_server.schemas import (
    MCPServerConfig,
    MCPToolError,
    MCPToolResult,
    MCPToolSpec,
    SchemaValidationError,
)
from mcp_server.server import APILeakMCPServer
from mcp_server.tool_registry import MCPToolRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_registry_with_jwt() -> MCPToolRegistry:
    registry = MCPToolRegistry()
    for spec in build_jwt_tool_specs():
        registry.register(spec)
    return registry


def _make_attack_summary_mock(*, finding_count: int = 1):
    """Return a minimal AttackSummary-like mock for handler tests."""
    session = MagicMock()
    session.session_id = "test-session-id"
    session.total_attacks = 10
    session.successful_attacks = finding_count
    session.success_rate = finding_count * 10.0
    session.duration = 2.5

    summary = MagicMock()
    summary.session = session
    summary.vulnerabilities_found = []
    return summary


def _make_finding_mock():
    """Return a minimal Finding-like mock."""
    import dataclasses
    from utils.findings import Finding, Severity

    return Finding(
        id="test-finding-001",
        title="JWT Algorithm None Bypass",
        description="The server accepted a token with alg:none",
        severity=Severity.HIGH,
        url="https://api.example.com/protected",
        module="jwt",
        owasp_category="API2",
    )


# ---------------------------------------------------------------------------
# build_jwt_tool_specs — spec construction
# ---------------------------------------------------------------------------


class TestBuildJwtToolSpecs:
    def test_returns_nonempty_list(self):
        specs = build_jwt_tool_specs()
        assert len(specs) >= 1

    def test_attack_test_present(self):
        specs = build_jwt_tool_specs()
        names = {s.name for s in specs}
        assert "apileak.jwt.attack_test" in names

    def test_all_are_mcp_tool_spec_instances(self):
        for spec in build_jwt_tool_specs():
            assert isinstance(spec, MCPToolSpec)

    def test_attack_test_not_destructive(self):
        """JWT attack testing sends read-only forged tokens — non-destructive."""
        spec = next(s for s in build_jwt_tool_specs() if s.name == "apileak.jwt.attack_test")
        assert spec.is_destructive is False

    def test_attack_test_has_input_schema(self):
        spec = next(s for s in build_jwt_tool_specs() if s.name == "apileak.jwt.attack_test")
        assert isinstance(spec.input_schema, dict)
        assert spec.input_schema.get("type") == "object"

    def test_attack_test_has_output_schema(self):
        spec = next(s for s in build_jwt_tool_specs() if s.name == "apileak.jwt.attack_test")
        assert isinstance(spec.output_schema, dict)

    def test_attack_test_handler_is_callable(self):
        spec = next(s for s in build_jwt_tool_specs() if s.name == "apileak.jwt.attack_test")
        assert callable(spec.handler)

    def test_attack_test_timeout_ample(self):
        spec = next(s for s in build_jwt_tool_specs() if s.name == "apileak.jwt.attack_test")
        assert spec.max_execution_seconds >= 60.0


# ---------------------------------------------------------------------------
# JSON Schema — apileak.jwt.attack_test
# ---------------------------------------------------------------------------


class TestJwtAttackTestInputSchema:
    def test_required_token(self):
        assert "token" in JWT_ATTACK_TEST_INPUT_SCHEMA["required"]

    def test_required_url(self):
        assert "url" in JWT_ATTACK_TEST_INPUT_SCHEMA["required"]

    def test_token_is_string(self):
        assert JWT_ATTACK_TEST_INPUT_SCHEMA["properties"]["token"]["type"] == "string"

    def test_url_is_string(self):
        assert JWT_ATTACK_TEST_INPUT_SCHEMA["properties"]["url"]["type"] == "string"

    def test_method_enum_values(self):
        enum_vals = JWT_ATTACK_TEST_INPUT_SCHEMA["properties"]["method"]["enum"]
        assert "GET" in enum_vals
        assert "POST" in enum_vals
        assert "DELETE" in enum_vals

    def test_headers_is_array(self):
        assert JWT_ATTACK_TEST_INPUT_SCHEMA["properties"]["headers"]["type"] == "array"

    def test_timeout_minimum_one(self):
        assert JWT_ATTACK_TEST_INPUT_SCHEMA["properties"]["timeout"]["minimum"] == 1

    def test_max_retries_minimum_zero(self):
        assert JWT_ATTACK_TEST_INPUT_SCHEMA["properties"]["max_retries"]["minimum"] == 0

    def test_additional_properties_false(self):
        assert JWT_ATTACK_TEST_INPUT_SCHEMA.get("additionalProperties") is False

    def test_no_ssl_verify_is_boolean(self):
        assert JWT_ATTACK_TEST_INPUT_SCHEMA["properties"]["no_ssl_verify"]["type"] == "boolean"

    def test_signing_secret_present(self):
        assert "signing_secret" in JWT_ATTACK_TEST_INPUT_SCHEMA["properties"]

    def test_public_key_present(self):
        assert "public_key" in JWT_ATTACK_TEST_INPUT_SCHEMA["properties"]


# ---------------------------------------------------------------------------
# Registry: schema validation (Req 1.3)
# ---------------------------------------------------------------------------


class TestJwtAttackTestSchemaValidation:
    def setup_method(self):
        self.registry = _make_registry_with_jwt()

    def test_missing_token_raises_schema_validation_error(self):
        with pytest.raises(SchemaValidationError):
            asyncio.run(
                self.registry.invoke(
                    "apileak.jwt.attack_test",
                    {"url": "https://api.example.com/protected"},
                )
            )

    def test_missing_url_raises_schema_validation_error(self):
        with pytest.raises(SchemaValidationError):
            asyncio.run(
                self.registry.invoke(
                    "apileak.jwt.attack_test",
                    {"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.signature"},
                )
            )

    def test_invalid_method_raises_schema_validation_error(self):
        with pytest.raises(SchemaValidationError):
            asyncio.run(
                self.registry.invoke(
                    "apileak.jwt.attack_test",
                    {
                        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.sig",
                        "url": "https://api.example.com/protected",
                        "method": "INVALID",
                    },
                )
            )

    def test_negative_timeout_raises_schema_validation_error(self):
        with pytest.raises(SchemaValidationError):
            asyncio.run(
                self.registry.invoke(
                    "apileak.jwt.attack_test",
                    {
                        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.sig",
                        "url": "https://api.example.com/protected",
                        "timeout": -5,
                    },
                )
            )

    def test_unknown_param_raises_schema_validation_error(self):
        with pytest.raises(SchemaValidationError):
            asyncio.run(
                self.registry.invoke(
                    "apileak.jwt.attack_test",
                    {
                        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.sig",
                        "url": "https://api.example.com/protected",
                        "nonexistent_param": "oops",
                    },
                )
            )

    def test_headers_must_be_array(self):
        with pytest.raises(SchemaValidationError):
            asyncio.run(
                self.registry.invoke(
                    "apileak.jwt.attack_test",
                    {
                        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.sig",
                        "url": "https://api.example.com/protected",
                        "headers": "Authorization: Bearer xxx",  # string, not array
                    },
                )
            )


# ---------------------------------------------------------------------------
# Handler: MCPToolResult structure (Req 1.4)
# ---------------------------------------------------------------------------


class TestJwtAttackTestHandler:
    """Verify handler returns correct MCPToolResult structure using mocked engine."""

    def _valid_jwt(self):
        """A syntactically valid (but test-only) JWT string."""
        # header: {"alg":"HS256","typ":"JWT"}, payload: {"sub":"test"}
        import base64
        import json

        def b64url(d):
            return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

        header = b64url({"alg": "HS256", "typ": "JWT"})
        payload = b64url({"sub": "test", "iat": 1700000000})
        return f"{header}.{payload}.fakesig"

    @patch("mcp_server.jwt_tools.HTTPRequestEngine")
    @patch("mcp_server.jwt_tools.RateLimiter")
    @patch("mcp_server.jwt_tools.RetryConfig")
    @patch("mcp_server.jwt_tools.JWTAttackEngine")
    def test_returns_mcp_tool_result(
        self, MockEngine, MockRetry, MockRateLimiter, MockHTTPEngine
    ):
        """Handler must return an MCPToolResult instance (Requirement 1.4)."""
        # Mock HTTP engine
        mock_http = AsyncMock()
        MockHTTPEngine.return_value = mock_http

        # Mock JWT engine
        mock_engine = MagicMock()
        attack_summary = _make_attack_summary_mock(finding_count=0)
        mock_engine.execute_all = AsyncMock(return_value=attack_summary)
        mock_engine.to_findings = MagicMock(return_value=[])
        MockEngine.return_value = mock_engine

        result = asyncio.run(
            _jwt_attack_test_handler(
                {
                    "token": self._valid_jwt(),
                    "url": "https://api.example.com/protected",
                }
            )
        )

        assert isinstance(result, MCPToolResult)

    @patch("mcp_server.jwt_tools.HTTPRequestEngine")
    @patch("mcp_server.jwt_tools.RateLimiter")
    @patch("mcp_server.jwt_tools.RetryConfig")
    @patch("mcp_server.jwt_tools.JWTAttackEngine")
    def test_tool_name_is_correct(
        self, MockEngine, MockRetry, MockRateLimiter, MockHTTPEngine
    ):
        mock_http = AsyncMock()
        MockHTTPEngine.return_value = mock_http

        mock_engine = MagicMock()
        attack_summary = _make_attack_summary_mock()
        mock_engine.execute_all = AsyncMock(return_value=attack_summary)
        mock_engine.to_findings = MagicMock(return_value=[])
        MockEngine.return_value = mock_engine

        result = asyncio.run(
            _jwt_attack_test_handler(
                {
                    "token": self._valid_jwt(),
                    "url": "https://api.example.com/protected",
                }
            )
        )

        assert result.tool_name == "apileak.jwt.attack_test"

    @patch("mcp_server.jwt_tools.HTTPRequestEngine")
    @patch("mcp_server.jwt_tools.RateLimiter")
    @patch("mcp_server.jwt_tools.RetryConfig")
    @patch("mcp_server.jwt_tools.JWTAttackEngine")
    def test_untrusted_content_is_true(
        self, MockEngine, MockRetry, MockRateLimiter, MockHTTPEngine
    ):
        """Findings contain verbatim target data — untrusted_content MUST be True (Req 4.8)."""
        mock_http = AsyncMock()
        MockHTTPEngine.return_value = mock_http

        mock_engine = MagicMock()
        attack_summary = _make_attack_summary_mock()
        mock_engine.execute_all = AsyncMock(return_value=attack_summary)
        mock_engine.to_findings = MagicMock(return_value=[])
        MockEngine.return_value = mock_engine

        result = asyncio.run(
            _jwt_attack_test_handler(
                {
                    "token": self._valid_jwt(),
                    "url": "https://api.example.com/protected",
                }
            )
        )

        assert result.untrusted_content is True

    @patch("mcp_server.jwt_tools.HTTPRequestEngine")
    @patch("mcp_server.jwt_tools.RateLimiter")
    @patch("mcp_server.jwt_tools.RetryConfig")
    @patch("mcp_server.jwt_tools.JWTAttackEngine")
    def test_findings_is_list(
        self, MockEngine, MockRetry, MockRateLimiter, MockHTTPEngine
    ):
        mock_http = AsyncMock()
        MockHTTPEngine.return_value = mock_http

        mock_engine = MagicMock()
        attack_summary = _make_attack_summary_mock()
        mock_engine.execute_all = AsyncMock(return_value=attack_summary)
        mock_engine.to_findings = MagicMock(return_value=[])
        MockEngine.return_value = mock_engine

        result = asyncio.run(
            _jwt_attack_test_handler(
                {
                    "token": self._valid_jwt(),
                    "url": "https://api.example.com/protected",
                }
            )
        )

        assert isinstance(result.findings, list)

    @patch("mcp_server.jwt_tools.HTTPRequestEngine")
    @patch("mcp_server.jwt_tools.RateLimiter")
    @patch("mcp_server.jwt_tools.RetryConfig")
    @patch("mcp_server.jwt_tools.JWTAttackEngine")
    def test_metadata_contains_target(
        self, MockEngine, MockRetry, MockRateLimiter, MockHTTPEngine
    ):
        mock_http = AsyncMock()
        MockHTTPEngine.return_value = mock_http

        mock_engine = MagicMock()
        attack_summary = _make_attack_summary_mock()
        mock_engine.execute_all = AsyncMock(return_value=attack_summary)
        mock_engine.to_findings = MagicMock(return_value=[])
        MockEngine.return_value = mock_engine

        target = "https://api.example.com/protected"
        result = asyncio.run(
            _jwt_attack_test_handler(
                {"token": self._valid_jwt(), "url": target}
            )
        )

        assert result.metadata.get("target") == target

    @patch("mcp_server.jwt_tools.HTTPRequestEngine")
    @patch("mcp_server.jwt_tools.RateLimiter")
    @patch("mcp_server.jwt_tools.RetryConfig")
    @patch("mcp_server.jwt_tools.JWTAttackEngine")
    def test_invalid_header_format_raises_mcp_tool_error(
        self, MockEngine, MockRetry, MockRateLimiter, MockHTTPEngine
    ):
        """Malformed headers (missing ':') must raise MCPToolError before engine is called."""
        with pytest.raises(MCPToolError) as exc_info:
            asyncio.run(
                _jwt_attack_test_handler(
                    {
                        "token": self._valid_jwt(),
                        "url": "https://api.example.com/protected",
                        "headers": ["BadHeaderWithoutColon"],
                    }
                )
            )
        assert exc_info.value.error_code == "INVALID_PARAMS"
        # Engine must NOT have been instantiated
        MockEngine.assert_not_called()

    @patch("mcp_server.jwt_tools.HTTPRequestEngine")
    @patch("mcp_server.jwt_tools.RateLimiter")
    @patch("mcp_server.jwt_tools.RetryConfig")
    @patch("mcp_server.jwt_tools.JWTAttackEngine")
    def test_engine_error_wrapped_in_mcp_tool_error(
        self, MockEngine, MockRetry, MockRateLimiter, MockHTTPEngine
    ):
        """Engine exceptions must be wrapped in MCPToolError (Requirement 1.5)."""
        mock_http = AsyncMock()
        MockHTTPEngine.return_value = mock_http

        mock_engine = MagicMock()
        mock_engine.execute_all = AsyncMock(side_effect=RuntimeError("network timeout"))
        MockEngine.return_value = mock_engine

        with pytest.raises(MCPToolError) as exc_info:
            asyncio.run(
                _jwt_attack_test_handler(
                    {
                        "token": self._valid_jwt(),
                        "url": "https://api.example.com/protected",
                    }
                )
            )
        assert exc_info.value.error_code == "ATTACK_ERROR"


# ---------------------------------------------------------------------------
# Server registration (Req 1.2)
# ---------------------------------------------------------------------------


class TestJwtToolsServerRegistration:
    """Verify tools appear in registry after server initialisation."""

    def test_jwt_attack_test_in_registry(self):
        config = MCPServerConfig(transport="stdio")
        server = APILeakMCPServer(transport="stdio", config=config)
        tool_names = {spec.name for spec in server.registry.list_tools()}
        assert "apileak.jwt.attack_test" in tool_names

    def test_jwt_tool_count(self):
        """At least one JWT tool must be registered."""
        config = MCPServerConfig(transport="stdio")
        server = APILeakMCPServer(transport="stdio", config=config)
        jwt_tools = [
            spec for spec in server.registry.list_tools()
            if spec.name.startswith("apileak.jwt.")
        ]
        assert len(jwt_tools) >= 1
