# APILeak MCP Server — AI Provider Configuration

APILeak v1.0.0 includes an optional AI assistance layer (`apileaks[ai]`) that uses a large language model to triage scan findings, generate contextualised remediation advice, and semantically deduplicate overlapping findings from different OWASP modules.

This guide covers setup and configuration for all three supported providers: **Anthropic**, **OpenAI**, and **Amazon Bedrock**.

---

## Table of Contents

1. [Overview](#overview)
2. [Installing the AI extra](#installing-the-ai-extra)
3. [Anthropic (Claude)](#anthropic-claude)
4. [OpenAI (GPT)](#openai-gpt)
5. [Amazon Bedrock](#amazon-bedrock)
6. [Configuration File](#configuration-file)
7. [Using AI Triage (`--ai-triage`)](#using-ai-triage---ai-triage)
8. [Using Semantic Deduplication (`--ai-dedup`)](#using-semantic-deduplication---ai-dedup)
9. [AI Features via MCP](#ai-features-via-mcp)
10. [Graceful Degradation](#graceful-degradation)
11. [Security Considerations](#security-considerations)
12. [Troubleshooting](#troubleshooting)

---

## Overview

The AI assistance layer is **entirely optional** and **completely non-blocking**:

- If no provider is configured, `--ai-triage` / `--ai-dedup` output a warning and the scan completes without AI sections.
- If the provider is unreachable (timeout, rate limit), the scan continues without the AI section.
- The LLM **never** modifies original `Finding` objects — it only appends metadata.
- Secrets found in scan evidence are **redacted** before being sent to the provider.

```
┌─────────────────────────────────────────────────────┐
│                  APILeak scan results                │
│                                                     │
│  Finding #1: BOLA on /users/123                     │
│  Finding #2: Weak JWT secret                        │
│  Finding #3: CORS misconfiguration                  │
└─────────────────────┬───────────────────────────────┘
                      │  redact_secrets() applied
                      ▼
           ┌──────────────────────┐
           │   FindingTriageAssistant   │
           │   (LLMProvider.complete)   │
           └──────────┬───────────┘
                      │
                      ▼
             TriageReport (separate section,
             original findings unchanged)
```

---

## Installing the AI extra

```bash
# Anthropic + OpenAI providers
pip install 'apileaks[mcp,ai]'

# All providers (including Amazon Bedrock via boto3)
pip install 'apileaks[mcp,ai,aws]'
```

Verify:
```bash
python -c "from utils.ai.provider_base import build_llm_provider; print('AI layer available')"
```

---

## Anthropic (Claude)

### 1. Get your API key

Sign in at [console.anthropic.com](https://console.anthropic.com) → API Keys → Create key.

### 2. Set the environment variable

```bash
# Linux / macOS
export ANTHROPIC_API_KEY=sk-ant-api03-...

# Windows PowerShell
$env:ANTHROPIC_API_KEY = "sk-ant-api03-..."
```

> **Never** put the key in `apileaks.yaml` or any file committed to version control.

### 3. Configure in YAML

```yaml
# config/apileaks.yaml
ai_provider: anthropic
ai_model: claude-3-5-sonnet-20241022  # recommended
ai_timeout_seconds: 30
ai_max_retries: 3
```

### 4. Run

```bash
ANTHROPIC_API_KEY=sk-ant-... apileaks scan \
  --target https://api.example.com \
  --ai-triage
```

### Supported Claude models

| Model ID | Notes |
|----------|-------|
| `claude-3-5-sonnet-20241022` | Recommended — best balance of quality and speed |
| `claude-3-5-haiku-20241022` | Faster, lower cost |
| `claude-3-opus-20240229` | Highest quality, slower |

---

## OpenAI (GPT)

### 1. Get your API key

Sign in at [platform.openai.com](https://platform.openai.com) → API Keys → Create new secret key.

### 2. Set the environment variable

```bash
export OPENAI_API_KEY=sk-proj-...
```

### 3. Configure in YAML

```yaml
ai_provider: openai
ai_model: gpt-4o        # recommended
ai_timeout_seconds: 30
ai_max_retries: 3
```

### 4. Run

```bash
OPENAI_API_KEY=sk-proj-... apileaks scan \
  --target https://api.example.com \
  --ai-triage \
  --ai-dedup
```

### Supported OpenAI models

| Model ID | Notes |
|----------|-------|
| `gpt-4o` | Recommended — best quality |
| `gpt-4o-mini` | Faster, lower cost |
| `gpt-4-turbo` | Good quality, slightly older |

---

## Amazon Bedrock

Amazon Bedrock lets you use Claude and other foundation models within your AWS VPC, without data leaving your AWS environment. This is ideal for organisations with strict data-residency requirements.

### 1. Prerequisites

- An AWS account with Bedrock access enabled in your region.
- Model access granted in the AWS Bedrock console (Models → Request access).
- `boto3` installed (`pip install 'apileaks[ai,aws]'`).

### 2. Set up AWS credentials

APILeak uses the standard AWS credential chain — no special configuration needed:

```bash
# Option A — AWS profile
export AWS_PROFILE=my-pentest-profile
export AWS_DEFAULT_REGION=us-east-1

# Option B — explicit credentials (CI/CD)
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1

# Option C — IAM role (ECS, EC2, Lambda)
# No configuration needed — boto3 picks up the instance metadata credentials automatically.
```

### 3. Configure in YAML

```yaml
ai_provider: bedrock
ai_model: anthropic.claude-3-5-sonnet-20241022-v2:0   # Claude via Bedrock
ai_timeout_seconds: 60    # Bedrock can be slower on cold starts
ai_max_retries: 3
```

### 4. Run

```bash
AWS_PROFILE=my-profile apileaks scan \
  --target https://api.example.com \
  --ai-triage
```

### Supported Bedrock models

| Model ID | Provider | Notes |
|----------|----------|-------|
| `anthropic.claude-3-5-sonnet-20241022-v2:0` | Anthropic | Recommended |
| `anthropic.claude-3-haiku-20240307-v1:0` | Anthropic | Faster, lower cost |
| `amazon.titan-text-premier-v1:0` | Amazon | Available without special access |

---

## Configuration File

All AI settings can be placed in `config/apileaks.yaml`:

```yaml
# ── AI provider ──────────────────────────────────────────────────────────────
# Supported: anthropic | openai | bedrock | null (disabled)
ai_provider: anthropic
ai_model: claude-3-5-sonnet-20241022

# Per-request timeout in seconds (Requirement 10.1)
ai_timeout_seconds: 30

# Max retries on rate-limit errors (Requirement 10.3)
ai_max_retries: 3

# Log level for AI prompts/responses
# INFO (default): prompts and responses are NOT logged
# DEBUG: full prompt and response are logged (sensitive!)
log_level: INFO
```

**Credential resolution order** (highest to lowest priority):

1. Environment variable (e.g. `ANTHROPIC_API_KEY`)
2. AWS credential chain (for Bedrock — `~/.aws/credentials`, `AWS_PROFILE`, instance role)
3. *(No plain-text in YAML — never supported)*

---

## Using AI Triage (`--ai-triage`)

```bash
apileaks scan \
  --target https://api.example.com \
  --ai-triage
```

What happens:

1. The scan runs normally and produces a list of `Finding` objects.
2. All findings are serialised to JSON. Secrets in the `evidence` fields are redacted with `redact_secrets()`.
3. The redacted findings are sent to the configured LLM with a prompt asking for prioritisation and explanation.
4. The LLM response is parsed into a `TriageReport` containing:
   - `prioritized_finding_ids` — findings sorted by risk
   - `narrative_summary` — plain-language summary for the report consumer
   - `per_finding_notes` — per-finding contextual explanation
5. The `TriageReport` is appended to the final report as a separate section. Original `Finding` objects are **never modified**.

**Output example** (JSON report):
```json
{
  "findings": [...],
  "triage_report": {
    "prioritized_finding_ids": ["finding-001", "finding-003", "finding-007"],
    "narrative_summary": "The most critical issue is an unauthenticated BOLA on /users/{id}. An attacker can enumerate all user profiles without authentication. The weak JWT signing secret compounds this risk by allowing token forgery...",
    "per_finding_notes": {
      "finding-001": "Directly exploitable without authentication. Fix immediately.",
      "finding-003": "Weak HS256 secret enables full token forgery. Rotate secret and upgrade to RS256."
    }
  }
}
```

---

## Using Semantic Deduplication (`--ai-dedup`)

When multiple OWASP modules report findings that share the same root cause, deduplication groups them:

```bash
apileaks scan \
  --target https://api.example.com \
  --ai-dedup
```

**Example**: SSRF testing (API7) and Parameter Pollution both flag the same `callback_url` parameter. Without dedup, you'd see two findings. With dedup, you see one group with both individual findings preserved inside.

**Output structure**:
```json
{
  "findings": [...],
  "dedup_groups": [
    {
      "group_id": "group-001",
      "root_cause_summary": "The callback_url parameter in /api/webhook accepts arbitrary URLs and is not validated against an allowlist, enabling SSRF and parameter pollution attacks.",
      "member_finding_ids": ["finding-007", "finding-012"]
    }
  ]
}
```

The deduplicated groups are presented **alongside** the original findings — no information is lost. The deduplicator prefers *not* grouping (false negative) over incorrect grouping (false positive).

---

## AI Features via MCP

When the MCP server is started with an AI provider configured, triage and dedup become parameters on the `apileak.scan` MCP tool.

**MCP invocation with AI triage**:
```json
{
  "tool": "apileak.scan",
  "arguments": {
    "target": "https://api.example.com",
    "modules": ["bola_testing", "auth_testing"],
    "ai_triage": true,
    "ai_dedup": true
  }
}
```

**Start the server with AI enabled**:
```bash
export ANTHROPIC_API_KEY=sk-ant-...
apileaks mcp-server \
  --transport http \
  --port 8080 \
  --mcp-auth-token "$TOKEN"
```

The AI config is read from `config/apileaks.yaml` at server startup. You can also set it via environment variables at runtime (the server reads them for each invocation):

```bash
AI_PROVIDER=anthropic \
AI_MODEL=claude-3-5-sonnet-20241022 \
ANTHROPIC_API_KEY=sk-ant-... \
apileaks mcp-server --transport stdio
```

---

## Graceful Degradation

All AI errors are handled gracefully — the scan never fails because of an AI problem:

| Error Condition | Behaviour |
|-----------------|-----------|
| No provider configured | AI section skipped, warning logged |
| Provider timeout | AI section skipped, timeout logged |
| Rate limit (HTTP 429) | Retried with exponential backoff (up to `ai_max_retries` times), then skipped |
| Unparseable response | AI section skipped, parse error logged |
| Network error | AI section skipped, error logged |

Example warning in the report:
```json
{
  "ai_triage_status": "unavailable",
  "ai_triage_reason": "LLMProviderUnavailableError: Anthropic API timed out after 30s"
}
```

---

## Security Considerations

### Secret Redaction

Before any finding data is sent to an LLM provider, `redact_secrets()` is applied to all evidence fields. This removes:

- API keys matching known prefixes (`sk_`, `pk_`, `AKIA`, `ghp_`, `xoxb-`, etc.)
- Bearer tokens, JWT tokens
- Email addresses
- High-entropy strings (potential secrets)
- Common credential patterns (SSN, credit card numbers)

Redacted values are replaced with `[REDACTED]` placeholders before the LLM sees them.

### No Raw Parameters in Logs

Prompt and response content is logged **only** at `DEBUG` level. At the default `INFO` level, only metadata (provider name, token count, duration) is logged. Never enable `DEBUG` level in production if the AI prompt may contain sensitive finding evidence.

### Credential Storage

LLM provider credentials (API keys, AWS credentials) are resolved exclusively from:
- Environment variables (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`)
- AWS credential chain (for Bedrock — `~/.aws/credentials`, instance role, ECS task role)

They are **never** stored in `apileaks.yaml`, scan reports, or the audit log.

---

## Troubleshooting

### `ValueError: Unknown LLM provider 'anthropic'`
The `[ai]` extra is not installed:
```bash
pip install 'apileaks[ai]'
```

### `LLMProviderUnavailableError: Authentication failed`
The API key is incorrect or not set:
```bash
echo $ANTHROPIC_API_KEY   # should print your key
```

### `LLMRateLimitError: Rate limit exceeded`
The provider's rate limit was hit. APILeak will retry automatically. If it keeps happening, reduce scan frequency or upgrade your provider plan.

### Bedrock `AccessDeniedException`
Model access not enabled in the Bedrock console. Go to AWS → Bedrock → Model access → Request access for the model you're using.

### `LLMResponseParseError: Expected JSON, got...`
The model returned an unexpected response format. Try a different model (e.g. `claude-3-5-sonnet` instead of `claude-3-opus`) or file an issue.

### AI triage section missing from report
Check the `ai_triage_status` field in the report JSON. Common reasons:
- Provider not configured (`no_provider`)
- Provider unavailable (`unavailable`)
- Response parse failure (`parse_error`)

For details, run with `--log-level DEBUG`:
```bash
apileaks scan --target ... --ai-triage --log-level DEBUG
```

---

## See Also

- [MCP Server Guide](mcp-server.md) — connecting AI clients
- [Docker Deployment](mcp-docker.md) — running with AI in containers
- [MCP Security](mcp_server_security.md) — OWASP controls (including credential redaction)
