# MCP Server Security Documentation

This document describes the security model of the APILeak MCP server, the OWASP MCP Top 10 controls it implements, and the results of its mandatory self-audit (dogfooding).

---

## Table of Contents

1. [Overview](#overview)
2. [Security Model](#security-model)
   - [Destructive Confirmation Gates](#destructive-confirmation-gates)
   - [Audit Logging](#audit-logging)
   - [Rate Limiting and Timeouts](#rate-limiting-and-timeouts)
   - [Transport Security (TLS)](#transport-security-tls)
   - [Input Validation and Command Injection Prevention](#input-validation-and-command-injection-prevention)
   - [Tool Manifest Integrity](#tool-manifest-integrity)
   - [Session Isolation](#session-isolation)
3. [OWASP MCP Top 10 Controls](#owasp-mcp-top-10-controls)
4. [Self-Audit (Dogfooding)](#self-audit-dogfooding)
   - [What the Self-Audit Tests](#what-the-self-audit-tests)
   - [Latest Self-Audit Results](#latest-self-audit-results)
   - [How to Run the Self-Audit Locally](#how-to-run-the-self-audit-locally)
5. [Security Policies](#security-policies)
   - [MCP SDK Dependency Policy](#mcp-sdk-dependency-policy)
   - [TLS Requirements](#tls-requirements)
   - [Rate Limiting Defaults](#rate-limiting-defaults)
   - [AI Provider Credential Handling](#ai-provider-credential-handling)
6. [Reporting a Vulnerability](#reporting-a-vulnerability)

---

## Overview

The APILeak MCP server (`apileaks mcp-server`) exposes APILeak's penetration-testing capabilities as invocable MCP tools to AI agents (Claude, Kiro, or any MCP-compatible client). Because it turns APILeak itself into the same kind of MCP server that `apileaks mcp-audit` is designed to attack, it is held to the same security standards it audits in third parties.

The server supports two transports:

- **stdio** — for local agent clients (Claude Desktop, Kiro). The host process is considered trusted at the OS level.
- **HTTP/SSE** — for remote agent clients. Requires Bearer token authentication and TLS.

Key security properties:

- No AI agent can execute a destructive operation without explicit human confirmation (`DestructiveConfirmationGate`).
- Every tool invocation is logged to an append-only structured audit trail.
- Raw target data returned to the AI client is marked `untrusted_content: true` to trigger client-side prompt-injection defences.
- All parameters are passed to underlying CLI modules as positional arguments with `shell=False`, preventing command injection.
- A SHA-256 hash of the registered tool manifest is computed at startup and written to the audit log, making any runtime alteration of the tool registry detectable.

---

## Security Model

### Destructive Confirmation Gates

Any `MCPToolSpec` with `is_destructive=True` (e.g. BOLA writes, BFLA destructive verbs, `cloud-audit --allow-destructive-cloud-audit`) requires a valid `ConfirmationToken` on every invocation. The `allow_destructive` server-level flag does **not** bypass this per-invocation check — the confirmation must come from the human operator for each destructive call.

Invocations without a valid `ConfirmationToken` are rejected with a structured `ConfirmationRequiredError` before any part of the underlying operation runs. (Requirements 4.1, 4.2)

### Audit Logging

`MCPAuditLogger` writes every tool invocation — successful or failed — as a JSON Lines entry to a configurable append-only file. Each entry contains:

| Field | Description |
|---|---|
| `tool_name` | Name of the MCP tool invoked |
| `caller_identity` | Bearer token hash (HTTP) or `stdio:<pid>` |
| `param_hash` | SHA-256 of input parameters after secret redaction |
| `timestamp_start` | ISO-8601 UTC timestamp of invocation start |
| `timestamp_end` | ISO-8601 UTC timestamp of invocation end |
| `outcome` | `success` / `error` / `cancelled` |
| `error_code` | Structured error code, if applicable |
| `finding_count` | Number of `Finding` objects produced |
| `confirmation_token_id` | Set only for destructive tool invocations |
| `tool_manifest_hash` | SHA-256 of the active tool manifest at invocation time |

The log file is opened in append mode by the server process; no tool handler can overwrite or truncate existing entries. Secret values matching known patterns (API keys, tokens, credentials) are redacted before the `param_hash` is computed and are never written in plain text. (Requirements 12.1–12.4 / OWASP MCP08)

### Rate Limiting and Timeouts

By default the server enforces:

- **60 invocations per minute per client** (sliding window). Clients that exceed this limit receive an `MCPToolError` with `error_code="RATE_LIMIT_EXCEEDED"` and the tool is never executed.
- **300-second maximum execution time per tool invocation**. Invocations that exceed this are cancelled and a structured timeout error is returned to the client.

Both defaults are logged at startup and can be overridden via CLI flags:

```
--mcp-rate-limit <N>               # invocations per minute (default: 60)
```

Per-tool timeouts are configured on each `MCPToolSpec.max_execution_seconds`. (Requirements 15.1–15.3 / OWASP MCP05)

### Transport Security (TLS)

**HTTP transport** requires TLS. Two deployment modes are supported:

1. **Native TLS** — pass `--tls-cert <path>` and `--tls-key <path>` to start the server with uvicorn in HTTPS mode. Plain-HTTP clients receive a TLS handshake error before application code is reached.
2. **Reverse proxy TLS** — if no certificate is provided, the server starts in plain-HTTP mode but logs a prominent `WARNING` instructing the operator to place the server behind a TLS-terminating reverse proxy (nginx, Caddy, Traefik). See [`DEPLOYMENT.md`](../DEPLOYMENT.md) for a reference nginx configuration.

Plain HTTP connections to an untrusted network are not supported. (Requirement 2.5 / OWASP MCP07)

**stdio transport** documents at startup that the client process is trusted at the OS level (same user account). The server logs a warning if the parent process does not match a known MCP client. (Requirement 2.6 / OWASP MCP07)

### Input Validation and Command Injection Prevention

- All tool parameters are validated against their published JSON Schema before the handler runs. Invocations with non-conforming parameters are rejected before any logic executes. (Requirement 1.3)
- Parameters passed to underlying CLI modules are passed as positional argument lists to `subprocess.run` with `shell=False`. Dynamic string concatenation and shell interpolation of user-supplied values are prohibited. (Requirement 4.6 / OWASP MCP05)
- An allowlist of permitted characters is applied to parameters that map to filesystem paths or network targets.
- Values that look like AI instructions embedded in tool parameters (inverse tool-poisoning attempt by a malicious client) are treated as literal data and never executed by the server. (Requirement 4.4)
- Raw data from scan targets returned in tool responses is annotated with `untrusted_content: true` in the MCP response metadata, signalling the AI client to apply its own prompt-injection defences. (Requirement 4.8 / OWASP MCP06)

### Tool Manifest Integrity

At startup, `APILeakMCPServer` computes a SHA-256 hash of the complete set of registered `MCPToolSpec` objects and logs it under `tool_manifest_hash`. The same hash is written as a `server_start` sentinel in the audit log. Any runtime modification of the tool registry would produce a different hash on the next startup, making silent alterations detectable. (Requirement 4.7 / OWASP MCP03)

### Session Isolation

In HTTP mode, each concurrent client connection operates in a fully isolated execution context. `Finding` objects, scan state, progress counters, and `ConfirmationToken`s are never shared between sessions. Resources associated with a completed invocation are released before the concurrency slot becomes available for a new invocation. (Requirements 14.1, 14.2 / OWASP MCP10)

---

## OWASP MCP Top 10 Controls

| Control | ID | Status | Implementation |
|---|---|---|---|
| Prompt Injection prevention | MCP01 | ✅ Implemented | Secret redaction in audit log params; `untrusted_content` metadata on responses |
| Tool access control / allowlist | MCP02 | ✅ Implemented | `MCPServerConfig.allowed_tools` per-client allowlist |
| Tool registry integrity | MCP03 | ✅ Implemented | SHA-256 manifest hash at startup and in audit log |
| Supply chain verification | MCP04 | ✅ Implemented | `pip-compile --generate-hashes` lockfile; `pip-audit` in CI; CycloneDX SBOM on release |
| Injection / resource abuse prevention | MCP05 | ✅ Implemented | Positional args with `shell=False`; character allowlist; per-invocation timeout; rate limiter |
| Untrusted content marking | MCP06 | ✅ Implemented | `untrusted_content: true` in all tool responses containing raw target data |
| Transport security | MCP07 | ✅ Implemented | TLS enforcement for HTTP; stdio trust-level warning |
| Audit logging | MCP08 | ✅ Implemented | Append-only JSON Lines audit log with all required fields |
| Least privilege | MCP09 | ✅ Implemented | Destructive tools require explicit `ConfirmationToken`; safe mode is the default |
| Session isolation | MCP10 | ✅ Implemented | Per-client execution context; findings not shared between sessions |

Reference: [A Practical Guide for Secure MCP Server Development v1.0](./A-Practical-Guide-for-Secure-MCP-Server-Development.v.1.0.pdf)

---

## Self-Audit (Dogfooding)

As required by Requirement 9, the APILeak MCP server must pass its own MCP security audit before any release. The `modules/mcp_security/` module (`MCPTargetAuditor`) is run against the server itself in CI.

### What the Self-Audit Tests

The dogfooding self-audit exercises the following attack classes:

| Attack Class | How it is Tested |
|---|---|
| **Tool Poisoning** | `ToolPoisoningDetector` scans every tool description for hidden prompt-injection instructions, known prompt delimiters, and text hidden in HTML/Markdown comments. |
| **SSRF** | For each tool that accepts a URL parameter, the auditor probes it with internal/metadata URLs (reusing `modules/owasp/ssrf_testing.py` payloads) and checks whether the server fetches them. |
| **Missing Confirmation Gates** | Tools whose descriptions indicate destructive behaviour are invoked without a `ConfirmationToken`; the auditor verifies that the server rejects the call. |
| **Credential Leaks in Responses** | All tool responses are scanned with the same secret-detection patterns used in `property_level_auth.py` to ensure no credentials from scan targets bleed into MCP responses. |

Any `Finding` of **High** or **Critical** severity produced by the self-audit fails the CI pipeline before the release job can proceed. (Requirements 9.1, 9.2)

### Latest Self-Audit Results

> **Note:** This section is populated automatically by the CI pipeline on every release build.  
> The canonical, up-to-date results are attached as an artifact to the latest release job in  
> [`.github/workflows/publish.yml`](../.github/workflows/publish.yml).

<!--
  CI PLACEHOLDER — DO NOT EDIT MANUALLY
  The release workflow runs:
    apileaks mcp-audit --target "apileaks mcp-server --transport stdio"
  and overwrites the table below with the structured findings output.
-->

| Run Date | Tool Version | High Findings | Critical Findings | Overall Result |
|---|---|---|---|---|
| *(generated by CI)* | *(generated by CI)* | *(generated by CI)* | *(generated by CI)* | *(generated by CI)* |

**Self-audit finding detail** (last run):

```
No results yet — run apileaks mcp-audit locally or trigger a release build to populate.
```

---

### How to Run the Self-Audit Locally

Any developer can reproduce the CI self-audit locally in three steps.

#### 1. Install the MCP extra

```bash
pip install -e ".[mcp]"
```

#### 2. Start the MCP server in stdio test mode (background)

The self-audit uses stdio transport so no network port or auth token is required:

```bash
# In a separate terminal, or use the --target argument to launch it automatically:
apileaks mcp-server --transport stdio
```

#### 3. Run the audit

```bash
apileaks mcp-audit --target "apileaks mcp-server --transport stdio"
```

The auditor will:
1. Launch the MCP server as a subprocess connected via stdio.
2. Enumerate all registered tools.
3. Run tool-poisoning detection, SSRF probes, confirmation-gate checks, and credential-leak scanning.
4. Print a structured report to stdout and exit with code `0` (no high/critical findings) or `1` (findings present).

#### Interpreting the output

- **No findings / Low severity only** — the server passes the self-audit. This is the expected state.
- **Medium findings** — review and address before the next release; they do not block CI.
- **High or Critical findings** — the release pipeline will be blocked until they are resolved.

#### Running only the self-audit step from CI locally

```bash
# Mirrors exactly what the CI release job does
python -m pytest tests/mcp_server/test_self_audit.py -v
```

---

## Security Policies

### MCP SDK Dependency Policy

The official MCP Python SDK is added as an optional dependency under the `[mcp]` extra in `pyproject.toml`. The version is pinned with an exact `==` specifier. The hash-verified lockfile `requirements-mcp.txt` is generated via:

```bash
pip-compile requirements-mcp.in --generate-hashes -o requirements-mcp.txt
```

**When updating the MCP SDK version**, a maintainer must:

1. Review the SDK changelog before bumping the version (see the [SDK Review Policy in CONTRIBUTING.md](../CONTRIBUTING.md)).
2. Regenerate `requirements-mcp.txt` with `--generate-hashes`.
3. Ensure the `pip-audit` step in CI passes with the new version.
4. Update this document if any new OWASP MCP controls are affected.

The `dependency-audit` job in [`.github/workflows/code-quality.yml`](../.github/workflows/code-quality.yml) runs `pip-audit -r requirements-mcp.txt` on every push and PR, failing the pipeline on any CVE of High or Critical severity. (Requirement 13.1, 13.2 / OWASP MCP04)

A CycloneDX SBOM is generated as part of the release pipeline and attached as a workflow artifact. (Requirement 13.3 / OWASP MCP04)

### TLS Requirements

| Deployment mode | Requirement |
|---|---|
| HTTP transport with `--tls-cert` / `--tls-key` | TLS is handled natively by uvicorn. No reverse proxy needed. |
| HTTP transport without certificates | **Mandatory**: deploy behind a TLS-terminating reverse proxy. See [`DEPLOYMENT.md`](../DEPLOYMENT.md). |
| stdio transport | N/A — transport is over a local pipe to a trusted process. |

Never expose the HTTP MCP server on a plain-HTTP port to any untrusted network. The server enforces this by logging a `WARNING` and documenting the requirement at startup when TLS certificates are not provided.

### Rate Limiting Defaults

| Parameter | Default | Override |
|---|---|---|
| Max invocations per client per minute | 60 | `--mcp-rate-limit <N>` |
| Max execution time per tool invocation | 300 seconds | `MCPToolSpec.max_execution_seconds` per tool |

Both values are logged at server startup. Exceeding the rate limit returns an `MCPToolError` with `error_code="RATE_LIMIT_EXCEEDED"` without executing the tool. Exceeding the per-invocation timeout cancels the task and returns a structured timeout error.

### AI Provider Credential Handling

When AI-assisted features (`--ai-triage`, `--ai-dedup`) are used, credentials for the configured `LLM_Provider` (Anthropic, OpenAI, Bedrock) are resolved exclusively from environment variables or a secrets vault — never from plain-text values in the YAML configuration file. (Requirement 7.3)

Before any `Finding` evidence is sent to an LLM provider, `redact_secrets` is applied to remove credentials and tokens present in the scan target's responses. Prompt and response content is not logged at INFO level; it is available only under `DEBUG` logging. (Requirements 5.5, 7.4)

---

## Reporting a Vulnerability

If you discover a security vulnerability in the MCP server or any other part of APILeak, please follow the responsible disclosure process described in [SECURITY.md](../SECURITY.md).

Do **not** open a public GitHub issue for security vulnerabilities.
