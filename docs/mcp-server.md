# APILeak MCP Server — Complete Guide

APILeak v0.3.0 exposes its full API security-testing capability as **MCP tools** that any AI agent (Claude Desktop, Kiro, custom LLM workflows) can invoke via natural language. This guide covers everything from installation to production deployment.

---

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Quick Start — stdio (5 minutes)](#quick-start--stdio-5-minutes)
4. [Quick Start — HTTP/SSE](#quick-start--httpsse)
5. [Connecting AI Clients](#connecting-ai-clients)
   - [Claude Desktop](#claude-desktop)
   - [Kiro (AWS)](#kiro-aws)
   - [Generic MCP client](#generic-mcp-client)
6. [Available MCP Tools](#available-mcp-tools)
7. [AI-Assisted Features](#ai-assisted-features)
8. [Security Guardrails](#security-guardrails)
9. [Audit Logging](#audit-logging)
10. [Rate Limiting and Timeouts](#rate-limiting-and-timeouts)
11. [CLI Reference](#cli-reference)
12. [Configuration File Reference](#configuration-file-reference)
13. [Troubleshooting](#troubleshooting)

---

## Overview

The MCP server is a **transport layer** on top of the existing APILeak engine. It translates between the MCP protocol (what your AI agent speaks) and APILeak's internal scan / module system. The engine itself is unchanged — if `apileaks scan` found it before, the MCP tool finds it too.

```
AI Agent (Claude / Kiro / custom)
       │  MCP protocol (stdio or HTTP/SSE)
       ▼
┌─────────────────────────────┐
│     APILeakMCPServer        │
│   ┌─────────────────────┐   │
│   │   MCPToolRegistry   │   │   ← schema validation, rate limiting,
│   │                     │   │     destructive gate, audit log
│   └──────────┬──────────┘   │
└──────────────┼──────────────┘
               │
    ┌──────────▼──────────┐
    │   core/engine.py    │   ← same engine the CLI uses
    │   modules/owasp/    │
    │   utils/            │
    └─────────────────────┘
```

**Key design guarantees**:

- Every invocation is validated against a JSON Schema *before* the handler runs.
- Destructive tools (BOLA writes, BFLA, cloud-audit destructive mode) require an explicit `ConfirmationToken` — the AI cannot execute them autonomously.
- A SHA-256 hash of the tool manifest is logged at startup; tampering is detectable.
- Every invocation (success or failure) is written to an append-only JSON Lines audit log.
- Raw scan-target data returned to the AI is marked `untrusted_content: true` so the client applies its own prompt-injection defences.

---

## Installation

### Option A — pip (recommended)

```bash
# MCP server only
pip install 'apileaks[mcp]'

# MCP server + AI triage/dedup features
pip install 'apileaks[mcp,ai]'

# MCP server + AI + Amazon Bedrock support
pip install 'apileaks[mcp,ai,aws]'
```

### Option B — from source

```bash
git clone https://github.com/MoisesTapia/apileaks.git
cd apileaks

# MCP server only
pip install -e '.[mcp]'

# MCP + AI (all providers)
pip install -e '.[mcp,ai,aws]'
```

### Verify the installation

```bash
apileaks mcp-server --help
```

Expected output:

```
Usage: apileaks mcp-server [OPTIONS]

  Start the APILeak MCP server.

  Exposes all APILeak scan capabilities (scan, OWASP modules, JWT testing,
  discovery, cloud audit) as MCP tools invocable by an AI agent such as
  Claude or Kiro.
...
```

---

## Quick Start — stdio (5 minutes)

**stdio** is the simplest transport. Your AI client (Claude Desktop, Kiro) launches the server as a subprocess and communicates over stdin/stdout. No port, no token, no TLS needed.

### Step 1 — Confirm the binary path

```bash
which apileaks        # Linux/macOS
where apileaks        # Windows
# e.g. /usr/local/bin/apileaks
```

### Step 2 — Configure your AI client (see [Connecting AI Clients](#connecting-ai-clients))

That's it. When the client starts a new session it will launch the process and call `initialize` / `tools/list` automatically.

### Step 3 — Test manually (optional)

You can verify the server works standalone:

```bash
apileaks mcp-server --transport stdio
```

Send a JSON-RPC `initialize` message on stdin:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}
```

You should receive a response listing the server capabilities. Press `Ctrl+C` to stop.

---

## Quick Start — HTTP/SSE

HTTP mode runs the server as a persistent service, accessible over the network. This is useful when:
- Your AI agent runs in a container or remote machine.
- Multiple agents need to share the same server instance.
- You want a stable endpoint that survives client disconnections.

### Step 1 — Generate a secret token

```bash
# Linux/macOS
export APILEAKS_MCP_AUTH_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
echo $APILEAKS_MCP_AUTH_TOKEN   # save this!

# Windows PowerShell
$env:APILEAKS_MCP_AUTH_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Step 2 — Start the server

```bash
# Plain HTTP (no TLS — use behind a reverse proxy in production)
apileaks mcp-server \
  --transport http \
  --port 8080 \
  --mcp-auth-token "$APILEAKS_MCP_AUTH_TOKEN"

# With native TLS (self-signed cert example)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=apileak-mcp"

apileaks mcp-server \
  --transport http \
  --port 8443 \
  --mcp-auth-token "$APILEAKS_MCP_AUTH_TOKEN" \
  --tls-cert cert.pem \
  --tls-key key.pem
```

### Step 3 — Verify

```bash
curl -N \
  -H "Authorization: Bearer $APILEAKS_MCP_AUTH_TOKEN" \
  http://localhost:8080/sse
```

You should see the SSE stream open (server-sent events connection established). Press `Ctrl+C` to stop.

### Step 4 — Configure your AI client

Use `http://localhost:8080/sse` as the MCP server URL with the token from Step 1.

---

## Connecting AI Clients

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

**stdio transport** (simplest):
```json
{
  "mcpServers": {
    "apileaks": {
      "command": "apileaks",
      "args": ["mcp-server", "--transport", "stdio"],
      "description": "APILeak API Security Testing"
    }
  }
}
```

**stdio with Docker** (no local Python install needed):
```json
{
  "mcpServers": {
    "apileaks": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--network", "host",
        "apileak-mcp:latest",
        "mcp-server", "--transport", "stdio"
      ],
      "description": "APILeak MCP Server (Docker)"
    }
  }
}
```

**HTTP transport**:
```json
{
  "mcpServers": {
    "apileaks-remote": {
      "url": "http://localhost:8080/sse",
      "headers": {
        "Authorization": "Bearer YOUR_TOKEN_HERE"
      },
      "description": "APILeak MCP Server (HTTP)"
    }
  }
}
```

Restart Claude Desktop after saving the config. You'll see "apileaks" in the tools panel.

---

### Kiro (AWS)

In Kiro, open the MCP settings panel (`.kiro/settings/mcp.json`) and add:

**stdio**:
```json
{
  "mcpServers": {
    "apileaks": {
      "command": "apileaks",
      "args": ["mcp-server", "--transport", "stdio"]
    }
  }
}
```

**HTTP** (useful when the server runs in a separate container):
```json
{
  "mcpServers": {
    "apileaks": {
      "command": "apileaks",
      "args": [
        "mcp-server",
        "--transport", "http",
        "--port", "8080",
        "--mcp-auth-token", "${APILEAKS_MCP_AUTH_TOKEN}"
      ]
    }
  }
}
```

Or connect to an already-running HTTP server (the Kiro MCP server needs to accept SSE connections):
```json
{
  "mcpServers": {
    "apileaks": {
      "url": "http://localhost:8080/sse",
      "headers": {
        "Authorization": "Bearer YOUR_TOKEN_HERE"
      }
    }
  }
}
```

---

### Generic MCP client

Any client that implements the MCP specification can connect to APILeak.

**List available tools** (JSON-RPC over stdio):
```bash
echo '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | \
  apileaks mcp-server --transport stdio
```

**Invoke a tool** (example: JWT attack test):
```bash
echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"apileak.jwt.attack_test","arguments":{"target":"https://api.example.com/auth","token":"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMifQ."}}}' | \
  apileaks mcp-server --transport stdio
```

---

## Available MCP Tools

The server exposes 16+ tools (one per CLI command / OWASP module):

### Scan tools

| Tool Name | Maps to CLI | Description |
|-----------|-------------|-------------|
| `apileak.scan` | `apileaks scan` | Full orchestrated scan: discovery + all selected OWASP modules |

**Example invocation** (as AI agent):
```
Run a full OWASP scan against https://api.example.com with rate limit 5 req/s
```
The tool accepts these parameters:
```json
{
  "target": "https://api.example.com",
  "modules": ["bola_testing", "auth_testing", "ssrf_testing"],
  "rate_limit": 5,
  "openapi": "https://api.example.com/openapi.json",
  "output_format": "json"
}
```

---

### OWASP API Security Top 10 modules

| Tool Name | OWASP Category | Description |
|-----------|----------------|-------------|
| `apileak.owasp.bola_testing` | API1:2023 | Broken Object Level Authorization — tests horizontal/vertical privilege escalation via object ID manipulation |
| `apileak.owasp.auth_testing` | API2:2023 | Broken Authentication — JWT attacks, token replay, null algorithm, credential stuffing |
| `apileak.owasp.property_level_auth` | API3:2023 | Broken Object Property Level Authorization — mass assignment, sensitive field exposure |
| `apileak.owasp.resource_consumption` | API4:2023 | Unrestricted Resource Consumption — rate-limit bypass, large payloads, deep nesting |
| `apileak.owasp.function_level_auth` | API5:2023 | BFLA — admin endpoint exposure, HTTP method elevation, privilege escalation |
| `apileak.owasp.business_flows` | API6:2023 | Unrestricted Business Flows — rate-limit absence, quota bypass, multi-step flow attacks |
| `apileak.owasp.ssrf_testing` | API7:2023 | SSRF — cloud metadata, internal network probes, blind SSRF, SSRF schemes |
| `apileak.owasp.security_misconfiguration` | API8:2023 | Security Misconfiguration — CORS misconfig, missing headers, debug endpoints |
| `apileak.owasp.inventory_management` | API9:2023 | Improper Inventory Management — deprecated/shadow API version detection |
| `apileak.owasp.unsafe_consumption` | API10:2023 | Unsafe Consumption of APIs — upstream data reflection, blind redirects, cleartext channels |
| `apileak.owasp.parameter_pollution` | *(beyond top 10)* | HTTP Parameter Pollution — duplicate parameter injection |
| `apileak.owasp.spec_driven_testing` | *(beyond top 10)* | OpenAPI contract enforcement — undocumented routes, type mismatches |

**Example: BOLA scan via AI conversation**:
```
Scan https://api.example.com/users/{id} for broken object-level authorization.
Use JWT token eyJhbGci... and test IDs 1 through 100.
```

The AI will call `apileak.owasp.bola_testing` with:
```json
{
  "target": "https://api.example.com",
  "endpoint_pattern": "/users/{id}",
  "auth_token": "eyJhbGci...",
  "id_range": [1, 100]
}
```

---

### JWT attack tools

| Tool Name | Maps to CLI | Description |
|-----------|-------------|-------------|
| `apileak.jwt.attack_test` | `apileaks jwt attack-test` | Automated JWT attack suite: none algorithm, weak secrets, alg confusion, key injection |

**Example**:
```json
{
  "target": "https://api.example.com/protected",
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "wordlist": "jwt.secrets.list"
}
```

---

### Discovery tools

| Tool Name | Maps to CLI | Description |
|-----------|-------------|-------------|
| `apileak.discovery.dir` | `apileaks dir` | Directory/endpoint fuzzing with configurable wordlists and triage |
| `apileak.discovery.par` | `apileaks par` | Hidden parameter discovery |

---

### Cloud audit tool

| Tool Name | Maps to CLI | Description |
|-----------|-------------|-------------|
| `apileak.cloud_audit` | `apileaks cloud-audit` | Cloud API gateway security audit (AWS API Gateway, GCP, Azure APIM) |

> **Note**: `apileak.cloud_audit` is marked `is_destructive=True` and requires a `ConfirmationToken`. See [Security Guardrails](#security-guardrails).

---

## AI-Assisted Features

The `[ai]` extra adds optional AI assistance on top of scan results. It does **not** change how the scanner works — the LLM only sees completed `Finding` objects.

### Finding Triage (`--ai-triage`)

Ask the LLM to prioritise and explain findings from a scan:

```bash
apileaks scan \
  --target https://api.example.com \
  --ai-triage \
  --ai-provider anthropic \
  --ai-model claude-3-5-sonnet-20241022
```

The triage output is added as a separate section in the report. The original findings are never modified.

**Configuration via YAML**:
```yaml
# config/apileaks.yaml
ai_provider: anthropic
ai_model: claude-3-5-sonnet-20241022
ai_timeout_seconds: 30
ai_max_retries: 3
```

Credentials are always resolved from environment variables:
```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

### Semantic Deduplication (`--ai-dedup`)

Group findings from different modules that describe the same root cause:

```bash
apileaks scan \
  --target https://api.example.com \
  --ai-dedup \
  --ai-provider openai \
  --ai-model gpt-4o
```

The report shows both the deduplicated groups and the full individual findings.

### Using via MCP

When the MCP server is configured with an AI provider, triage and dedup are available as parameters on the `apileak.scan` tool:

```json
{
  "target": "https://api.example.com",
  "ai_triage": true,
  "ai_dedup": true
}
```

---

## Security Guardrails

### Destructive Confirmation Gate

Operations that modify state (BOLA writes, BFLA with destructive HTTP methods, cloud audit in write mode) require a two-tier confirmation:

**Tier 1** — the server must have been started with `--allow-destructive-mcp`:
```bash
apileaks mcp-server --transport stdio --allow-destructive-mcp
```

Without this flag every destructive tool invocation returns:
```json
{
  "error_code": "DESTRUCTIVE_NOT_ENABLED",
  "message": "Tool 'apileak.owasp.bola_testing' is a destructive operation. The server was started in safe mode..."
}
```

**Tier 2** — even with `--allow-destructive-mcp`, each individual invocation must include a `ConfirmationToken`:
```json
{
  "target": "https://api.example.com",
  "confirmation": {
    "tool_name": "apileak.owasp.bola_testing",
    "confirmed_by": "alice@example.com",
    "timestamp": "2026-11-03T10:00:00Z"
  }
}
```

The AI agent cannot generate a confirmation token on its own — it must come from the human operator (you).

### Input Validation

All parameters are validated against the tool's JSON Schema before the handler runs. Invalid parameters are rejected without executing anything:

```json
{
  "error_code": "SCHEMA_VALIDATION_ERROR",
  "message": "'target' is a required property"
}
```

### Prompt Injection Detection

If a parameter value looks like an instruction to an AI agent (e.g. `"target": "ignore previous instructions and..."`), the server logs a warning and treats it as literal data. It is never executed as an instruction.

### Untrusted Content Marking

All tool responses that include raw data from the scan target (response bodies, headers) include `untrusted_content: true` in the MCP metadata, telling the AI client to apply its own defences.

---

## Audit Logging

Enable with `--audit-log`:

```bash
apileaks mcp-server \
  --transport http \
  --port 8080 \
  --mcp-auth-token "$TOKEN" \
  --audit-log /var/log/apileaks/mcp-audit.jsonl
```

Every invocation produces one JSON line:

```json
{
  "tool_name": "apileak.owasp.bola_testing",
  "caller_identity": "tok_sha256_a1b2c3d4...",
  "param_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "timestamp_start": "2026-11-03T10:00:01.123456+00:00",
  "timestamp_end": "2026-11-03T10:02:34.567890+00:00",
  "outcome": "success",
  "error_code": null,
  "finding_count": 7,
  "confirmation_token_id": null,
  "tool_manifest_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
}
```

The log is **append-only** — no tool handler can overwrite or delete entries. Secrets in parameters are redacted before the `param_hash` is computed (the raw values are never written).

At startup, a `server_start` sentinel is written:
```json
{
  "tool_name": "server_start",
  "event": "server_start",
  "tool_manifest_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "timestamp": "2026-11-03T09:59:58.000000+00:00",
  "pid": 12345
}
```

---

## Rate Limiting and Timeouts

### Rate limiting

The sliding-window rate limiter is applied per-client:

```bash
# Default: 60 invocations per minute per client
apileaks mcp-server --transport http --mcp-rate-limit 60 ...

# Stricter limit for sensitive environments
apileaks mcp-server --transport http --mcp-rate-limit 10 ...
```

When the limit is exceeded:
```json
{
  "error_code": "RATE_LIMIT_EXCEEDED",
  "message": "Rate limit exceeded: client '192.168.1.5' has made 60 invocations in the last 60s..."
}
```

### Execution timeout

Each tool has a `max_execution_seconds` limit (default: 300 s). When a scan exceeds it:
```json
{
  "error_code": "EXECUTION_TIMEOUT",
  "message": "Tool 'apileak.scan' exceeded its maximum execution time of 300.0s."
}
```

---

## CLI Reference

```
apileaks mcp-server [OPTIONS]

Options:
  --transport [stdio|http]      Transport protocol.                [default: stdio]
  --port INTEGER                TCP port for HTTP transport.       [default: 8080]
  --mcp-auth-token TEXT         Bearer token for HTTP clients.
                                Also: APILEAKS_MCP_AUTH_TOKEN env var.
  --tls-cert PATH               TLS certificate file (HTTP, optional).
  --tls-key PATH                TLS private-key file (HTTP, optional).
  --mcp-rate-limit INTEGER      Max invocations/min per client.    [default: 60]
  --allow-destructive-mcp       Enable destructive tools (process-level).
  --audit-log PATH              Path for the append-only audit log.
  --help                        Show this message and exit.
```

```
apileaks mcp-audit [OPTIONS]

Options:
  --target TEXT                 Target MCP server URL or command.   [required]
  -o, --output [text|json]      Output format.                     [default: text]
  --fail-on-findings            Exit 1 on HIGH/CRITICAL findings (for CI).
  --help                        Show this message and exit.
```

---

## Configuration File Reference

You can set AI provider configuration in your APILeak YAML config:

```yaml
# config/apileaks.yaml

# AI provider configuration
ai_provider: anthropic          # anthropic | openai | bedrock | null
ai_model: claude-3-5-sonnet-20241022
ai_timeout_seconds: 30
ai_max_retries: 3

# Scan defaults
rate_limit: 10
verify_ssl: true
timeout: 10
```

Credentials must come from environment variables, not the config file:

```bash
# Anthropic
export ANTHROPIC_API_KEY=sk-ant-api03-...

# OpenAI
export OPENAI_API_KEY=sk-proj-...

# Bedrock (uses AWS credentials chain)
export AWS_PROFILE=my-profile
# or
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
```

---

## Troubleshooting

### `ImportError: No module named 'mcp'`
The MCP extra is not installed:
```bash
pip install 'apileaks[mcp]'
```

### `HTTP transport requires an authentication token`
Set the token before starting:
```bash
export APILEAKS_MCP_AUTH_TOKEN=your-secret-token
apileaks mcp-server --transport http --port 8080
```

### Tool not found by AI client
The client's tool list might be cached. In Claude Desktop, restart the app. In Kiro, reload the MCP server from the MCP panel.

### `RATE_LIMIT_EXCEEDED` from AI agent loop
Increase the rate limit or add a delay between invocations on the client side:
```bash
apileaks mcp-server --mcp-rate-limit 120 ...
```

### Destructive tool rejected despite `--allow-destructive-mcp`
Each destructive invocation still requires a per-invocation `ConfirmationToken`. The AI agent must ask the human for one. This is intentional — see [Security Guardrails](#security-guardrails).

### Audit log not created
The parent directory must exist and be writable by the server process:
```bash
mkdir -p /var/log/apileaks
apileaks mcp-server --audit-log /var/log/apileaks/mcp-audit.jsonl ...
```

### Self-audit fails with HIGH findings
Run the audit locally and inspect the report:
```bash
pip install 'apileaks[mcp]'
apileaks mcp-audit \
  --target "apileaks mcp-server --transport stdio" \
  --output json
```

Review each finding. Most false positives come from tool descriptions that contain example HTTP verbs (DELETE, REMOVE) which trigger the `appears_destructive` heuristic. These are informational — the actual destructive gate is enforced by `is_destructive=True` on the `MCPToolSpec`.

---

## See Also

- [Docker Deployment Guide](mcp-docker.md) — running the MCP server in containers
- [AI Provider Configuration](mcp-ai-providers.md) — Anthropic, OpenAI, Bedrock setup
- [MCP Tools Reference](mcp-tools-reference.md) — full schema for every tool
- [MCP Server Security](mcp_server_security.md) — OWASP MCP Top 10 controls
- [DEPLOYMENT.md](../DEPLOYMENT.md) — nginx/Caddy reverse proxy TLS configuration
