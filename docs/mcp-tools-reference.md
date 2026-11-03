# APILeak MCP Tools — Complete Reference

This reference covers every MCP tool exposed by `apileaks mcp-server`, including its JSON Schema, parameters, outputs, and example invocations from an AI conversation.

---

## Table of Contents

- [apileak.scan](#apileakscan) — Full orchestrated scan
- [apileak.owasp.bola_testing](#apileakowaspbola_testing) — API1: BOLA
- [apileak.owasp.auth_testing](#apileakowaspauth_testing) — API2: Auth
- [apileak.owasp.property_level_auth](#apileakowaspproperty_level_auth) — API3: Mass Assignment
- [apileak.owasp.resource_consumption](#apileakowaspresource_consumption) — API4: Rate Limiting
- [apileak.owasp.function_level_auth](#apileakowaspfunction_level_auth) — API5: BFLA
- [apileak.owasp.business_flows](#apileakowaspbusiness_flows) — API6: Business Flows
- [apileak.owasp.ssrf_testing](#apileakowaspssrf_testing) — API7: SSRF
- [apileak.owasp.security_misconfiguration](#apileakowaspsecurity_misconfiguration) — API8: Misconfig
- [apileak.owasp.inventory_management](#apileakowaspinventory_management) — API9: Inventory
- [apileak.owasp.unsafe_consumption](#apileakowaspunsafe_consumption) — API10: Unsafe Consumption
- [apileak.owasp.parameter_pollution](#apileakowaspparameter_pollution) — HPP
- [apileak.owasp.spec_driven_testing](#apileakowaspspec_driven_testing) — Spec Audit
- [apileak.jwt.attack_test](#apileakjwtattack_test) — JWT Attacks
- [apileak.discovery.dir](#apileakdiscoverydir) — Endpoint Fuzzing
- [apileak.discovery.par](#apileakdiscoverypar) — Parameter Discovery
- [apileak.cloud_audit](#apileakcloud_audit) — Cloud Audit ⚠️ Destructive

---

## Schema conventions

All tools follow the same request/response structure:

**Request** (MCP `tools/call`):
```json
{
  "name": "<tool_name>",
  "arguments": { ... }
}
```

**Response** (MCPToolResult):
```json
{
  "tool_name": "<tool_name>",
  "findings": [ ... ],
  "metadata": { ... },
  "raw_output": "...",
  "untrusted_content": true
}
```

**Finding structure** (each item in `findings`):
```json
{
  "id": "uuid-v4",
  "scan_id": "scan-uuid",
  "category": "BOLA",
  "owasp_category": "API1",
  "severity": "HIGH",
  "endpoint": "https://api.example.com/users/42",
  "method": "GET",
  "status_code": 200,
  "response_size": 1234,
  "response_time": 0.23,
  "evidence": "Response body contains user data for user ID 42...",
  "recommendation": "Implement ABAC checks on the /users/{id} endpoint.",
  "payload": "GET /users/42",
  "response_snippet": "{\"id\": 42, \"email\": \"victim@example.com\"}",
  "timestamp": "2026-11-03T10:00:01Z"
}
```

Severity levels: `CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `INFO`

---

## apileak.scan

Full orchestrated scan. Runs endpoint discovery then all selected OWASP modules in sequence, aggregating findings.

**Destructive**: No (unless modules with destructive mode are selected)

### Input Schema

```json
{
  "type": "object",
  "required": ["target"],
  "properties": {
    "target": {
      "type": "string",
      "format": "uri",
      "description": "Base URL of the API to scan (e.g. https://api.example.com)"
    },
    "modules": {
      "type": "array",
      "items": {
        "type": "string",
        "enum": [
          "bola_testing", "auth_testing", "property_level_auth",
          "resource_consumption", "function_level_auth", "business_flows",
          "ssrf_testing", "security_misconfiguration", "inventory_management",
          "unsafe_consumption", "parameter_pollution", "spec_driven_testing"
        ]
      },
      "description": "Modules to run. Omit to run all modules."
    },
    "rate_limit": {
      "type": "integer",
      "minimum": 1,
      "maximum": 100,
      "default": 10,
      "description": "Maximum requests per second"
    },
    "auth_token": {
      "type": "string",
      "description": "JWT or API key to include in Authorization header"
    },
    "openapi": {
      "type": "string",
      "description": "URL or file path to an OpenAPI/Swagger spec"
    },
    "output_format": {
      "type": "string",
      "enum": ["json", "markdown", "sarif"],
      "default": "json"
    },
    "ai_triage": {
      "type": "boolean",
      "default": false,
      "description": "Append AI-generated triage report (requires [ai] extra)"
    },
    "ai_dedup": {
      "type": "boolean",
      "default": false,
      "description": "Group semantically duplicate findings (requires [ai] extra)"
    }
  }
}
```

### Example — full scan

AI prompt:
```
Run a complete OWASP scan against https://api.example.com.
Use Bearer token eyJhbGci... and limit to 5 req/s.
```

MCP call:
```json
{
  "name": "apileak.scan",
  "arguments": {
    "target": "https://api.example.com",
    "rate_limit": 5,
    "auth_token": "eyJhbGci..."
  }
}
```

### Example — targeted scan with spec

```json
{
  "name": "apileak.scan",
  "arguments": {
    "target": "https://api.example.com",
    "modules": ["bola_testing", "ssrf_testing", "auth_testing"],
    "openapi": "https://api.example.com/openapi.json",
    "rate_limit": 10,
    "ai_triage": true
  }
}
```

---

## apileak.owasp.bola_testing

Tests for **Broken Object Level Authorization (BOLA / IDOR)** — API1:2023.

Sends requests to object endpoints with manipulated IDs (integer iteration, UUID enumeration, encoded variants) and observes whether cross-user data is returned.

**Destructive**: Yes (write-mode BOLA requires confirmation)

### Key Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string (URI) | Yes | Base API URL |
| `endpoint_pattern` | string | No | URL pattern with `{id}` placeholder |
| `auth_token` | string | No | Auth token for requests |
| `id_range` | array[int, int] | No | Min/max for integer ID testing |
| `test_writes` | boolean | No | Test BOLA on write operations (destructive) |

### Example

AI prompt:
```
Test the /api/orders/{id} endpoint for BOLA. I have a valid session token.
The order IDs are UUIDs. My order ID is 550e8400-e29b-41d4-a716-446655440000.
```

MCP call:
```json
{
  "name": "apileak.owasp.bola_testing",
  "arguments": {
    "target": "https://api.example.com",
    "endpoint_pattern": "/api/orders/{id}",
    "auth_token": "Bearer eyJhbGci...",
    "object_type": "uuid"
  }
}
```

---

## apileak.owasp.auth_testing

Tests for **Broken Authentication** — API2:2023.

Checks JWT configuration (none algorithm, weak secrets, algorithm confusion), token expiry enforcement, credential stuffing susceptibility, and authentication bypass.

**Destructive**: No

### Key Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string (URI) | Yes | Base API URL |
| `auth_endpoint` | string | No | Login endpoint path |
| `token` | string | No | Existing JWT token to analyse |
| `wordlist` | string | No | Secret wordlist path for JWT brute-force |

### Example

AI prompt:
```
Test the authentication on https://api.example.com.
The login endpoint is /auth/login. Here's a sample JWT: eyJhbGciOiJIUzI1NiJ9...
```

MCP call:
```json
{
  "name": "apileak.owasp.auth_testing",
  "arguments": {
    "target": "https://api.example.com",
    "auth_endpoint": "/auth/login",
    "token": "eyJhbGciOiJIUzI1NiJ9..."
  }
}
```

---

## apileak.owasp.property_level_auth

Tests for **Broken Object Property Level Authorization (BOPLA / Mass Assignment)** — API3:2023.

Sends requests with extra fields in request bodies and observes whether the server assigns them (mass assignment). Also checks read-only property bypass and sensitive data over-exposure in responses.

**Destructive**: No

### Example

AI prompt:
```
Test /api/users/{id} for mass assignment. Can I set my own role or isAdmin field?
```

MCP call:
```json
{
  "name": "apileak.owasp.property_level_auth",
  "arguments": {
    "target": "https://api.example.com",
    "endpoint_pattern": "/api/users/{id}",
    "auth_token": "Bearer eyJhbGci..."
  }
}
```

---

## apileak.owasp.resource_consumption

Tests for **Unrestricted Resource Consumption** — API4:2023.

Sends payloads designed to trigger resource exhaustion: large request bodies, deep JSON nesting, high pagination values, and burst requests to detect missing rate limiting.

**Destructive**: No

### Example

MCP call:
```json
{
  "name": "apileak.owasp.resource_consumption",
  "arguments": {
    "target": "https://api.example.com",
    "rate_limit": 50,
    "max_burst": 100
  }
}
```

---

## apileak.owasp.function_level_auth

Tests for **Broken Function Level Authorization (BFLA)** — API5:2023.

Probes admin endpoints, alternative HTTP methods on sensitive routes, and privilege-escalation paths using non-privileged credentials.

**Destructive**: Yes (HTTP DELETE / write operations require confirmation)

### Example

AI prompt:
```
Test if regular user token can access admin functions on https://api.example.com.
User token: eyJhbGci...  Admin token (for comparison): eyJhbGci...
```

MCP call:
```json
{
  "name": "apileak.owasp.function_level_auth",
  "arguments": {
    "target": "https://api.example.com",
    "user_token": "eyJhbGci...",
    "admin_token": "eyJhbGci..."
  }
}
```

---

## apileak.owasp.business_flows

Tests for **Unrestricted Business Flows** — API6:2023.

Checks for rate-limit absence on business-critical operations (password reset, purchase, promo code redemption), quota enforcement bypasses, and multi-step flow manipulation.

**Destructive**: No

### Example

MCP call:
```json
{
  "name": "apileak.owasp.business_flows",
  "arguments": {
    "target": "https://api.example.com",
    "auth_token": "Bearer eyJhbGci...",
    "flow_endpoints": ["/checkout", "/promo/apply", "/password/reset"]
  }
}
```

---

## apileak.owasp.ssrf_testing

Tests for **Server-Side Request Forgery (SSRF)** — API7:2023.

Injects internal/cloud-metadata URLs into parameters that accept URLs, and checks whether the server fetches them. Covers cloud metadata endpoints (AWS, GCP, Azure), internal subnet probes, blind SSRF via timing, and SSRF via URL scheme tricks.

**Destructive**: No

### Example

AI prompt:
```
Test the webhook registration endpoint /webhooks for SSRF.
It accepts a callback_url parameter.
```

MCP call:
```json
{
  "name": "apileak.owasp.ssrf_testing",
  "arguments": {
    "target": "https://api.example.com",
    "endpoint_pattern": "/webhooks",
    "url_param": "callback_url"
  }
}
```

---

## apileak.owasp.security_misconfiguration

Tests for **Security Misconfiguration** — API8:2023.

Checks for CORS misconfigurations (wildcard origins, credential-bearing requests from untrusted origins), missing security headers (HSTS, X-Content-Type-Options, etc.), exposed debug endpoints, and directory listing.

**Destructive**: No

### Example

MCP call:
```json
{
  "name": "apileak.owasp.security_misconfiguration",
  "arguments": {
    "target": "https://api.example.com",
    "test_cors": true,
    "test_headers": true
  }
}
```

---

## apileak.owasp.inventory_management

Tests for **Improper Inventory Management** — API9:2023.

Probes deprecated API versions (`/v1/`, `/v0/`, `/beta/`, `/legacy/`) and shadow endpoints that may have weaker security controls than the current production version.

**Destructive**: No

### Example

MCP call:
```json
{
  "name": "apileak.owasp.inventory_management",
  "arguments": {
    "target": "https://api.example.com",
    "current_version": "v3",
    "depth": 3
  }
}
```

---

## apileak.owasp.unsafe_consumption

Tests for **Unsafe Consumption of APIs** — API10:2023.

Checks how the target API handles upstream data it receives from other APIs: whether it reflects input data without sanitisation, follows blind redirects, or communicates over cleartext channels with upstream providers.

**Destructive**: No

### Example

MCP call:
```json
{
  "name": "apileak.owasp.unsafe_consumption",
  "arguments": {
    "target": "https://api.example.com",
    "upstream_endpoints": ["/social/share", "/payment/verify"]
  }
}
```

---

## apileak.owasp.parameter_pollution

Tests for **HTTP Parameter Pollution (HPP)** — beyond OWASP Top 10.

Injects duplicate parameter names into query strings and request bodies to confuse server-side parsing and bypass input validation.

**Destructive**: No

### Example

MCP call:
```json
{
  "name": "apileak.owasp.parameter_pollution",
  "arguments": {
    "target": "https://api.example.com",
    "endpoint_pattern": "/search",
    "param": "q"
  }
}
```

---

## apileak.owasp.spec_driven_testing

Tests for **OpenAPI Contract Violations** — beyond OWASP Top 10.

Uses an OpenAPI/Swagger spec to verify that the live API honours its contract: checks for undocumented routes, responses that don't match declared schemas, and type mismatches.

**Destructive**: No

### Example

AI prompt:
```
Audit the live API at https://api.example.com against its OpenAPI spec at /openapi.json.
Report any undocumented routes or type violations.
```

MCP call:
```json
{
  "name": "apileak.owasp.spec_driven_testing",
  "arguments": {
    "target": "https://api.example.com",
    "openapi": "https://api.example.com/openapi.json"
  }
}
```

---

## apileak.jwt.attack_test

Runs the full JWT attack suite against a target endpoint.

**Destructive**: No

### Attacks performed

| Attack | Description |
|--------|-------------|
| None algorithm | Strips the signature and sets `alg: none` |
| Weak secret brute-force | Tries secrets from a wordlist (HS256/HS384/HS512) |
| RS256 → HS256 confusion | Uses the public key as an HMAC secret |
| JWK injection | Embeds a crafted public key in the token header |
| `kid` SQL injection | Injects SQL into the `kid` header parameter |
| `kid` path traversal | Injects path traversal into `kid` |
| Expired token replay | Tests whether the server validates `exp` |
| `sub` manipulation | Replaces the subject claim |

### Input Schema

```json
{
  "type": "object",
  "required": ["target"],
  "properties": {
    "target": {
      "type": "string",
      "format": "uri",
      "description": "Endpoint to test (must return HTTP 200 for a valid token)"
    },
    "token": {
      "type": "string",
      "description": "Valid JWT token to use as a baseline"
    },
    "wordlist": {
      "type": "string",
      "description": "Path to secret wordlist (default: jwt.secrets.list)"
    },
    "attacks": {
      "type": "array",
      "items": {"type": "string"},
      "description": "Subset of attacks to run (omit to run all)"
    }
  }
}
```

### Example

AI prompt:
```
Test the /api/protected endpoint for JWT vulnerabilities.
Here's a valid token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

MCP call:
```json
{
  "name": "apileak.jwt.attack_test",
  "arguments": {
    "target": "https://api.example.com/api/protected",
    "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

---

## apileak.discovery.dir

Directory and endpoint fuzzing with configurable wordlists, status-code filtering, and triage.

**Destructive**: No

### Example

MCP call:
```json
{
  "name": "apileak.discovery.dir",
  "arguments": {
    "target": "https://api.example.com",
    "wordlist": "wordlists/endpoints.txt",
    "rate_limit": 20,
    "status_codes": ["200", "201", "301", "302", "403"]
  }
}
```

---

## apileak.discovery.par

Hidden parameter discovery — fuzzes query string and body parameters on discovered endpoints.

**Destructive**: No

### Example

MCP call:
```json
{
  "name": "apileak.discovery.par",
  "arguments": {
    "target": "https://api.example.com",
    "endpoint": "/api/users",
    "method": "GET",
    "wordlist": "wordlists/parameters.txt"
  }
}
```

---

## apileak.cloud_audit

Cloud API gateway security audit covering AWS API Gateway, Google Cloud API Gateway, and Azure API Management.

**⚠️ Destructive: Yes** — write-mode cloud audit modifies cloud resources and requires explicit confirmation.

### Confirmation required

When the server is started with `--allow-destructive-mcp`, you must supply a `ConfirmationToken` in the request:

```json
{
  "name": "apileak.cloud_audit",
  "arguments": {
    "target": "https://api-id.execute-api.us-east-1.amazonaws.com",
    "provider": "aws",
    "allow_destructive_cloud_audit": true,
    "confirmation": {
      "tool_name": "apileak.cloud_audit",
      "confirmed_by": "alice@example.com",
      "timestamp": "2026-11-03T10:00:00Z"
    }
  }
}
```

Without a confirmation token, the server returns:
```json
{
  "error_code": "CONFIRMATION_REQUIRED",
  "message": "Tool 'apileak.cloud_audit' requires explicit human confirmation..."
}
```

### Example — read-only audit (no confirmation needed)

```json
{
  "name": "apileak.cloud_audit",
  "arguments": {
    "target": "https://api-id.execute-api.us-east-1.amazonaws.com",
    "provider": "aws",
    "allow_destructive_cloud_audit": false
  }
}
```

---

## Error Codes Reference

All structured errors returned by MCP tools:

| Error Code | Trigger |
|------------|---------|
| `TOOL_NOT_FOUND` | Tool name not registered in the server |
| `SCHEMA_VALIDATION_ERROR` | Input parameters don't match the tool's JSON Schema |
| `RATE_LIMIT_EXCEEDED` | Client exceeded invocations-per-minute limit |
| `DESTRUCTIVE_NOT_ENABLED` | Destructive tool called, but server started in safe mode |
| `CONFIRMATION_REQUIRED` | Destructive tool called without a `ConfirmationToken` |
| `EXECUTION_TIMEOUT` | Tool exceeded `max_execution_seconds` |
| `INTERNAL_ERROR` | Unexpected handler error (details in server logs) |

---

## See Also

- [MCP Server Guide](mcp-server.md) — quick start, transports, configuration
- [Docker Deployment](mcp-docker.md) — container deployment
- [AI Providers](mcp-ai-providers.md) — LLM provider setup
- [Security Documentation](mcp_server_security.md) — OWASP controls
