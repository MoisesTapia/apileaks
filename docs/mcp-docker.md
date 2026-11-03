# APILeak MCP Server — Docker Deployment Guide

This guide covers everything you need to run the APILeak MCP server in Docker, from a single `docker run` to a full `docker compose` stack with the audit tool.

---

## Table of Contents

1. [Docker Images: base vs MCP](#docker-images-base-vs-mcp)
2. [Building the MCP image](#building-the-mcp-image)
3. [stdio transport with Docker](#stdio-transport-with-docker)
4. [HTTP transport with Docker](#http-transport-with-docker)
5. [docker compose — full stack](#docker-compose--full-stack)
6. [Environment Variables Reference](#environment-variables-reference)
7. [Volume Mounts](#volume-mounts)
8. [TLS Configuration](#tls-configuration)
9. [Reverse Proxy Setup (nginx / Caddy / Traefik)](#reverse-proxy-setup)
10. [Running mcp-audit in Docker](#running-mcp-audit-in-docker)
11. [Security Hardening](#security-hardening)
12. [CI/CD Integration](#cicd-integration)

---

## Docker Images: base vs MCP

APILeak ships two Dockerfiles:

| File | Image Tag | Contents | Extras |
|------|-----------|----------|--------|
| `Dockerfile` | `apileak:latest` | Core scanner, OWASP modules, JWT, discovery | None (`requirements.txt` only) |
| `Dockerfile.mcp` | `apileak-mcp:latest` | Everything above **+** MCP server, CLI, AI providers | `mcp` + optional `ai` |

Use `apileak-mcp` whenever you need to run `apileaks mcp-server` or `apileaks mcp-audit`.

---

## Building the MCP image

```bash
# From the repository root
docker build -f Dockerfile.mcp -t apileak-mcp:latest .

# Tag with version
docker build -f Dockerfile.mcp \
  -t apileak-mcp:0.3.0 \
  -t apileak-mcp:latest .

# Multi-platform build (for distribution)
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f Dockerfile.mcp \
  -t apileak-mcp:latest \
  --push .
```

Verify the build:
```bash
docker run --rm apileak-mcp:latest python apileaks.py mcp-server --help
```

---

## stdio transport with Docker

In stdio mode the AI client (Claude Desktop, Kiro) launches the container as a subprocess. The container's stdin/stdout carry the MCP protocol frames.

### Configure Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "apileaks": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "--interactive",
        "--network", "host",
        "apileak-mcp:latest",
        "mcp-server",
        "--transport", "stdio"
      ]
    }
  }
}
```

> **`--network host`** lets the container reach your local APIs (e.g. `http://localhost:3000`). On macOS/Windows, replace it with `--add-host=host.docker.internal:host-gateway` and use `http://host.docker.internal:3000` as the target.

### Configure Kiro

In `.kiro/settings/mcp.json`:

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
      ]
    }
  }
}
```

### With persistent audit log

Mount a local directory to keep the audit log between container runs:

```bash
# Claude Desktop config
{
  "command": "docker",
  "args": [
    "run", "--rm", "-i",
    "--network", "host",
    "-v", "/var/log/apileaks:/app/logs",
    "apileak-mcp:latest",
    "mcp-server", "--transport", "stdio",
    "--audit-log", "/app/logs/mcp-audit.jsonl"
  ]
}
```

---

## HTTP transport with Docker

```bash
# 1. Set a secure token
export APILEAKS_MCP_AUTH_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")

# 2. Run the server
docker run -d \
  --name apileak-mcp-server \
  -p 8080:8080 \
  -e APILEAKS_MCP_AUTH_TOKEN="$APILEAKS_MCP_AUTH_TOKEN" \
  -e MCP_AUDIT_LOG=/app/logs/mcp-audit.jsonl \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/reports:/app/reports \
  apileak-mcp:latest

# 3. Check logs
docker logs -f apileak-mcp-server

# 4. Verify
curl -N \
  -H "Authorization: Bearer $APILEAKS_MCP_AUTH_TOKEN" \
  http://localhost:8080/sse
```

### Stop and clean up

```bash
docker stop apileak-mcp-server
docker rm apileak-mcp-server
```

---

## docker compose — full stack

The included `docker-compose.yml` has a complete MCP stack under the `mcp` profile.

### Setup

```bash
# 1. Copy the example environment file
cp .env.example .env   # or create .env manually

# 2. Set the required secret token
echo "APILEAKS_MCP_AUTH_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")" >> .env

# 3. (Optional) Set AI provider credentials
echo "AI_PROVIDER=anthropic" >> .env
echo "ANTHROPIC_API_KEY=sk-ant-..." >> .env
```

Create `.env` (if starting from scratch):

```dotenv
# .env — copy this to .env and fill in the values

# ── Required ──────────────────────────────────────────────────────────────
# Bearer token that all MCP HTTP clients must present.
# Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
APILEAKS_MCP_AUTH_TOKEN=change-me-before-use

# ── MCP server options ────────────────────────────────────────────────────
MCP_HOST_PORT=8080          # port exposed on the host
MCP_RATE_LIMIT=60           # max invocations per client per minute
MCP_ALLOW_DESTRUCTIVE=false # set to true to allow destructive tools

# ── TLS (optional) ────────────────────────────────────────────────────────
# Leave empty to use a reverse proxy for TLS termination.
MCP_TLS_CERT=
MCP_TLS_KEY=

# ── AI providers (optional) ───────────────────────────────────────────────
AI_PROVIDER=            # anthropic | openai | bedrock | (leave empty)
AI_MODEL=
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
# For Bedrock, also set AWS credentials:
# AWS_ACCESS_KEY_ID=
# AWS_SECRET_ACCESS_KEY=
# AWS_DEFAULT_REGION=us-east-1
```

### Start the MCP server

```bash
# Build and start
docker compose --profile mcp up -d --build

# Follow logs
docker compose logs -f apileak-mcp

# Check health
docker compose ps
```

Expected output when healthy:
```
NAME                    IMAGE               STATUS
apileak-mcp-server      apileak-mcp:latest  Up (healthy)
```

### Connect your AI client

Point your AI client at `http://localhost:8080/sse` (or the host's IP if connecting remotely) with:
```
Authorization: Bearer <your-APILEAKS_MCP_AUTH_TOKEN>
```

### Run the security self-audit

```bash
# Starts apileak-mcp if not running, then audits it
docker compose --profile mcp-audit up --abort-on-container-exit
```

The auditor connects to the running MCP server, enumerates all tools, and runs:
- Tool-poisoning detection
- SSRF probes
- Missing confirmation gate check
- Credential leak scan

Exit code `0` = clean. Exit code `1` = HIGH/CRITICAL findings (blocks CI).

### Stop everything

```bash
docker compose --profile mcp down
```

---

## Environment Variables Reference

All environment variables accepted by `apileak-mcp:latest`:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `APILEAKS_MCP_AUTH_TOKEN` | **Yes** (HTTP) | — | Bearer token for HTTP clients |
| `MCP_TRANSPORT` | No | `http` | `http` or `stdio` |
| `MCP_PORT` | No | `8080` | TCP port for HTTP transport |
| `MCP_ALLOW_DESTRUCTIVE` | No | `false` | Enable destructive tools (`true`/`false`) |
| `MCP_RATE_LIMIT` | No | `60` | Max invocations per client per minute |
| `MCP_AUDIT_LOG` | No | `/app/logs/mcp-audit.jsonl` | Audit log path |
| `MCP_TLS_CERT` | No | — | Path to TLS certificate file |
| `MCP_TLS_KEY` | No | — | Path to TLS private key file |
| `AI_PROVIDER` | No | — | `anthropic` \| `openai` \| `bedrock` |
| `AI_MODEL` | No | *(provider default)* | Model identifier |
| `ANTHROPIC_API_KEY` | No | — | Anthropic API key |
| `OPENAI_API_KEY` | No | — | OpenAI API key |
| `AWS_ACCESS_KEY_ID` | No | — | AWS credentials (Bedrock) |
| `AWS_SECRET_ACCESS_KEY` | No | — | AWS credentials (Bedrock) |
| `AWS_DEFAULT_REGION` | No | — | AWS region (Bedrock) |
| `APILEAK_LOG_LEVEL` | No | `INFO` | Log level: `DEBUG` \| `INFO` \| `WARNING` \| `ERROR` |

---

## Volume Mounts

| Container path | Purpose | Suggested host path |
|----------------|---------|---------------------|
| `/app/logs` | MCP audit log, server logs | `./logs` |
| `/app/reports` | Scan reports (JSON, Markdown, SARIF) | `./reports` |
| `/app/config` | Optional `apileaks.yaml` config | `./config` |
| `/app/wordlists` | Custom wordlists | `./wordlists` |

Mount example:
```bash
docker run -d \
  -v ./logs:/app/logs \
  -v ./reports:/app/reports \
  -v ./config:/app/config:ro \
  -e APILEAKS_MCP_AUTH_TOKEN=secret \
  apileak-mcp:latest
```

---

## TLS Configuration

### Option A — native TLS (uvicorn handles it)

```bash
# Generate self-signed cert (development only)
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -days 365 -nodes \
  -subj "/CN=apileak-mcp"

docker run -d \
  -p 8443:8443 \
  -v $(pwd)/certs:/app/certs:ro \
  -e APILEAKS_MCP_AUTH_TOKEN=secret \
  -e MCP_PORT=8443 \
  -e MCP_TLS_CERT=/app/certs/cert.pem \
  -e MCP_TLS_KEY=/app/certs/key.pem \
  apileak-mcp:latest
```

In `docker-compose.yml`:
```yaml
environment:
  - MCP_TLS_CERT=/app/certs/cert.pem
  - MCP_TLS_KEY=/app/certs/key.pem
volumes:
  - ./certs:/app/certs:ro
```

### Option B — reverse proxy (recommended for production)

See the full reference configuration in [`DEPLOYMENT.md`](../DEPLOYMENT.md). Quick reference below.

---

## Reverse Proxy Setup

### nginx

```nginx
# /etc/nginx/sites-available/apileak-mcp
server {
    listen 443 ssl http2;
    server_name mcp.yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/mcp.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mcp.yourdomain.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    # SSE requires unbuffered streaming
    proxy_buffering       off;
    proxy_cache           off;
    proxy_read_timeout    3600s;   # long-running scans

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_set_header   Connection        "";
    }
}
```

### Caddy

```caddyfile
# Caddyfile
mcp.yourdomain.com {
    reverse_proxy localhost:8080 {
        flush_interval -1   # required for SSE streaming
        transport http {
            read_timeout 1h
        }
    }
}
```

### Traefik (docker-compose labels)

```yaml
# docker-compose.yml
apileak-mcp:
  ...
  labels:
    - "traefik.enable=true"
    - "traefik.http.routers.apileak-mcp.rule=Host(`mcp.yourdomain.com`)"
    - "traefik.http.routers.apileak-mcp.entrypoints=websecure"
    - "traefik.http.routers.apileak-mcp.tls.certresolver=letsencrypt"
    - "traefik.http.services.apileak-mcp.loadbalancer.server.port=8080"
    - "traefik.http.middlewares.apileak-strip.stripprefix.prefixes=/"
```

---

## Running mcp-audit in Docker

### Audit a running HTTP server

```bash
docker run --rm \
  --network host \
  apileak-mcp:latest \
  mcp-audit \
  --target http://localhost:8080 \
  --output json \
  --fail-on-findings
```

### Audit with docker compose (recommended)

```bash
# Start the MCP server first
docker compose --profile mcp up -d

# Then audit it (waits for server to be healthy before running)
docker compose --profile mcp-audit up --abort-on-container-exit
```

### Self-audit before release

```bash
# mirrors the CI pipeline job
docker compose --profile mcp up -d --build
docker compose --profile mcp-audit up --abort-on-container-exit

# Cleanup
docker compose --profile mcp down
```

---

## Security Hardening

The `apileak-mcp` image already applies several security hardening measures:

| Measure | Implementation |
|---------|----------------|
| Non-root user | UID 1000 (`apileak`) — process cannot write outside `/app` |
| Minimal base image | `python:3.11-alpine` — no shell utilities, no package manager in production |
| Read-only config volume | `./config:/app/config:ro` |
| No privileged mode | Default Docker capabilities are sufficient |
| Supply chain verification | MCP SDK installed from hash-verified `requirements-mcp.txt` |

Additional hardening for production:

```bash
docker run -d \
  --read-only \
  --tmpfs /tmp \
  --security-opt=no-new-privileges:true \
  --cap-drop=ALL \
  -p 8080:8080 \
  -e APILEAKS_MCP_AUTH_TOKEN=secret \
  apileak-mcp:latest
```

---

## CI/CD Integration

### GitHub Actions — run mcp-audit on every push

```yaml
# .github/workflows/mcp-self-audit.yml
name: MCP Self-Audit

on: [push, pull_request]

jobs:
  mcp-self-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build MCP image
        run: docker build -f Dockerfile.mcp -t apileak-mcp:ci .

      - name: Start MCP server
        run: |
          docker run -d \
            --name apileak-mcp-ci \
            -p 8080:8080 \
            -e APILEAKS_MCP_AUTH_TOKEN=ci-test-token \
            apileak-mcp:ci

          # Wait for healthy
          for i in $(seq 1 30); do
            if curl -sf -H "Authorization: Bearer ci-test-token" \
               http://localhost:8080/sse --max-time 2 -o /dev/null; then
              echo "Server ready"; break
            fi
            sleep 2
          done

      - name: Run mcp-audit
        run: |
          docker run --rm --network host \
            apileak-mcp:ci \
            mcp-audit \
            --target http://localhost:8080 \
            --output json \
            --fail-on-findings | tee mcp-audit-results.json

      - name: Upload findings
        uses: actions/upload-artifact@v4
        with:
          name: mcp-audit-results
          path: mcp-audit-results.json
        if: always()

      - name: Stop server
        run: docker stop apileak-mcp-ci && docker rm apileak-mcp-ci
        if: always()
```

---

## See Also

- [MCP Server Guide](mcp-server.md) — full feature overview and CLI reference
- [AI Provider Configuration](mcp-ai-providers.md) — Anthropic, OpenAI, Bedrock
- [MCP Security Documentation](mcp_server_security.md) — OWASP controls
- [DEPLOYMENT.md](../DEPLOYMENT.md) — full TLS proxy reference configurations
