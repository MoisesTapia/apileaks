# `apileaks req` — Single HTTP Request

`apileaks req` (alias `apileaks request`) sends a single arbitrary HTTP request and prints a rich, coloured request/response dump directly in the terminal. It is the `curl` / `httpie` of the APILeak toolchain — with native proxy routing, secret scanning, and session persistence built in.

---

## Table of Contents

1. [Why use `req` instead of curl?](#why-use-req-instead-of-curl)
2. [Quick reference](#quick-reference)
3. [Basic usage](#basic-usage)
4. [Request body](#request-body)
5. [Authentication](#authentication)
6. [Proxy routing (Burp / Caido / Hetty)](#proxy-routing)
7. [Query parameters](#query-parameters)
8. [Form data](#form-data)
9. [Coloured output explained](#coloured-output-explained)
10. [Scripting and piping](#scripting-and-piping)
11. [Secret scanning (`--scan-response`)](#secret-scanning)
12. [Save for later replay](#save-for-later-replay)
13. [JSON output mode](#json-output-mode)
14. [CI / exit codes](#ci--exit-codes)
15. [Full options reference](#full-options-reference)

---

## Why use `req` instead of curl?

| Feature | `apileaks req` | curl | httpie |
|---------|---------------|------|--------|
| Coloured request/response dump | ✅ auto | needs `-v` | ✅ |
| Proxy config from `apileaks.yaml` | ✅ | ❌ | ❌ |
| Secret scan on response | ✅ `--scan-response` | ❌ | ❌ |
| Save to replay session | ✅ `--save-session` | ❌ | ❌ |
| httpie-style `key=value` body | ✅ | ❌ | ✅ |
| No context switch | ✅ same tool you already use | separate install | separate install |

---

## Quick reference

```bash
# GET
apileaks req GET https://api.example.com/users

# POST with JSON string
apileaks req POST https://api.example.com/users --json '{"name":"alice","role":"admin"}'

# POST with httpie-style fields (builds JSON body automatically)
apileaks req POST https://api.example.com/users name=alice role=admin

# PATCH through Burp Suite
apileaks req PATCH https://api.example.com/users/42 \
  --json '{"role":"superadmin"}' \
  --proxy http://127.0.0.1:8080

# With JWT
apileaks req GET https://api.example.com/admin --jwt eyJhbGci...

# With extra headers
apileaks req GET https://api.example.com/internal -H "X-Internal: true" -H "X-Debug: 1"

# Only response body (pipe to jq)
apileaks req GET https://api.example.com/token --quiet | jq .access_token

# Scan response for leaked credentials
apileaks req GET https://api.example.com/config --scan-response

# Delete
apileaks req DELETE https://api.example.com/users/42 --jwt eyJhbGci...
```

---

## Basic usage

```
apileaks req METHOD URL [KEY=VALUE ...] [OPTIONS]
```

`METHOD` is the HTTP verb — any standard or custom string is accepted. Common values: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`.

`URL` must start with `http://` or `https://`. If you omit the scheme, `https://` is added automatically.

```bash
# These are equivalent:
apileaks req GET https://api.example.com/users
apileaks req get api.example.com/users   # lowercase method + auto-https
```

---

## Request body

### JSON string (`--json`)

```bash
apileaks req POST https://api.example.com/users \
  --json '{"name":"alice","role":"admin","active":true}'
```

Sets `Content-Type: application/json` automatically.

### httpie-style `key=value` fields

```bash
# String values — builds {"name":"alice","role":"admin"}
apileaks req POST https://api.example.com/users name=alice role=admin

# Typed values with :=  — builds {"name":"alice","age":30,"active":true,"tags":["a","b"]}
apileaks req POST https://api.example.com/users \
  name=alice age:=30 active:=true tags:='["a","b"]'
```

| Syntax | Type | Example |
|--------|------|---------|
| `key=value` | string | `name=alice` → `"name":"alice"` |
| `key:=number` | integer / float | `age:=30` → `"age":30` |
| `key:=true/false` | boolean | `active:=true` → `"active":true` |
| `key:=[…]` | array | `tags:=["a","b"]` → `"tags":["a","b"]` |
| `key:={…}` | object | `meta:={"k":"v"}` → `"meta":{"k":"v"}` |

Sets `Content-Type: application/json` automatically.

### Raw body (`--raw`)

```bash
apileaks req POST https://api.example.com/graphql \
  --raw '{"query":"{ users { id name } }"}' \
  -H "Content-Type: application/json"
```

No Content-Type is added automatically — set it manually with `-H`.

---

## Authentication

### Bearer token (JWT)

```bash
apileaks req GET https://api.example.com/admin --jwt eyJhbGci...
```

Equivalent to `-H "Authorization: Bearer eyJhbGci..."`.

### Manual `Authorization` header

```bash
# Bearer
apileaks req GET https://api.example.com/resource -H "Authorization: Bearer eyJhbGci..."

# Basic auth
apileaks req GET https://api.example.com/admin \
  -H "Authorization: Basic $(echo -n user:pass | base64)"

# API key in header
apileaks req GET https://api.example.com/resource -H "X-API-Key: sk-abc123"
```

### Multiple headers

```bash
apileaks req GET https://api.example.com/users \
  --jwt eyJhbGci... \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "Accept: application/json" \
  -H "X-Request-ID: test-001"
```

---

## Proxy routing

Route the request through an intercepting proxy for inspection, modification, and replay.

### Burp Suite

```bash
# Default Burp listener: http://127.0.0.1:8080
apileaks req POST https://api.example.com/users \
  name=alice role=admin \
  --proxy http://127.0.0.1:8080
```

TLS verification is disabled automatically when `--proxy` is set (the proxy terminates TLS with its own CA). Install the proxy's CA certificate and use `--no-verify` explicitly if you prefer not to do that.

### Caido

```bash
apileaks req GET https://api.example.com/admin \
  --jwt eyJhbGci... \
  --proxy http://127.0.0.1:8080   # Caido default listener
```

### Hetty

```bash
apileaks req PATCH https://api.example.com/users/42 \
  --json '{"role":"admin"}' \
  --proxy http://127.0.0.1:8080   # Hetty default listener
```

### SOCKS5 (Tor, SSH tunnels)

```bash
apileaks req GET https://api.example.com/users \
  --proxy socks5://127.0.0.1:9050
```

Requires `httpx[socks]` (included in the default install).

### Complete Burp example

```bash
# 1. Set up Burp Intercept ON
# 2. Run the request
apileaks req POST https://api.staging.com/api/v1/users \
  --json '{"username":"admin","email":"admin@test.com","role":"superadmin"}' \
  --jwt eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9... \
  -H "X-Internal-API: true" \
  --proxy http://127.0.0.1:8080

# 3. The request appears in Burp — modify, forward, repeat as needed
```

---

## Query parameters

```bash
# Simple
apileaks req GET https://api.example.com/search -p q=admin

# Multiple params
apileaks req GET https://api.example.com/users \
  -p page=2 -p limit=100 -p sort=created_at -p order=desc

# Combined with other options
apileaks req GET https://api.example.com/api/v2/audit-log \
  -p from=2026-01-01 -p to=2026-11-03 \
  --jwt eyJhbGci... \
  --proxy http://127.0.0.1:8080
```

---

## Form data

```bash
# Login form
apileaks req POST https://api.example.com/auth/login \
  -F username=admin -F password=hunter2

# With extra headers
apileaks req POST https://api.example.com/upload \
  -F file=@report.json \
  -H "X-Upload-Token: abc123"
```

Sets `Content-Type: application/x-www-form-urlencoded` automatically.

---

## Coloured output explained

By default, `req` prints a full request/response dump with ANSI colours:

```
════════════════════════════════════════════════════════════
  HTTP REQUEST
════════════════════════════════════════════════════════════
POST /api/v1/users  HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsIn…  ← token redacted to 16 chars
Content-Type: application/json

{
  "username": "alice",
  "role": "admin"
}

────────────────────────────────────────────────────────────
  RESPONSE
────────────────────────────────────────────────────────────
HTTP/1.1 201  (0.243s)              ← green = 2xx success
content-type: application/json
location: /api/v1/users/99
x-request-id: abc-123

{
  "id": 99,
  "username": "alice",
  "role": "admin",
  "created_at": "2026-11-03T10:00:00Z"
}
════════════════════════════════════════════════════════════
```

### Colour key

| Colour | Meaning |
|--------|---------|
| 🟢 Green | 2xx success |
| 🟡 Yellow | 3xx redirect |
| ⬜ Gray | 4xx client error |
| 🔴 Red | 5xx server error |
| 🔵 Cyan | Section headers |
| 🟣 Magenta | HTTP method |

- **Authorization** header: token value is redacted to the first 16 characters.
- **JSON bodies**: pretty-printed with 2-space indentation.
- **Large bodies**: truncated at 8 KB with a byte count shown.

---

## Scripting and piping

### Extract a field with `jq`

```bash
# Get just the access token from a login response
apileaks req POST https://api.example.com/auth/login \
  --json '{"username":"admin","password":"hunter2"}' \
  --quiet | jq -r .access_token
```

### Assign to a variable (bash)

```bash
TOKEN=$(apileaks req POST https://api.example.com/auth/login \
  --json '{"username":"admin","password":"hunter2"}' \
  --quiet | jq -r .access_token)

# Use the token in a follow-up request
apileaks req GET https://api.example.com/admin/users \
  --jwt "$TOKEN"
```

### Check status in a script

```bash
apileaks req DELETE https://api.example.com/users/42 \
  --jwt "$TOKEN" \
  --fail-on-error

if [ $? -eq 0 ]; then
  echo "User deleted"
else
  echo "Delete failed (4xx or 5xx)"
fi
```

### JSON output for further processing

```bash
apileaks req GET https://api.example.com/users \
  --output json | jq '.response.headers["content-type"]'

apileaks req GET https://api.example.com/users \
  --output json | python3 -c "
import json, sys
r = json.load(sys.stdin)
print(f\"Status: {r['status_code']}, Elapsed: {r['elapsed']}s\")
"
```

---

## Secret scanning

`--scan-response` runs APILeak's built-in credential pattern library against the response body and headers after the request completes.

```bash
apileaks req GET https://api.example.com/config --scan-response
```

Detects:

| Pattern | Examples |
|---------|---------|
| `aws_access_key` | `AKIA…` |
| `aws_secret_key` | `aws_secret_access_key = …` |
| `gcp_api_key` | `AIza…` |
| `github_token` | `ghp_…`, `gho_…` |
| `slack_token` | `xoxb-…` |
| `jwt` | `eyJ…` JWTs in response bodies |
| `private_key` | `-----BEGIN RSA PRIVATE KEY-----` |
| `bearer_token` | Any `Bearer <long-value>` |
| `generic_api_key` | `api_key`, `secret`, `token`, `password` patterns |

Example output when a secret is found:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SECRET SCAN — 2 match(es) found
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ▶ aws_access_key    redacted: AKIA****EXAMPLE
  ▶ github_token      redacted: ghp_****XYZ

⚠  Sensitive data detected in the response.
   Review the endpoint's access controls.
```

Combine with `--output json` to get findings in a structured format:

```bash
apileaks req GET https://api.example.com/config \
  --output json --scan-response | jq .secrets_found
```

---

## Save for later replay

`--save-session` appends the request/response to a JSON session file compatible with `apileaks replay`:

```bash
# Send and save
apileaks req POST https://api.example.com/users \
  --json '{"username":"alice","role":"admin"}' \
  --jwt eyJhbGci... \
  --save-session sessions/pentest.json

# Later: replay through Burp
apileaks replay sessions/pentest.json \
  --proxy http://127.0.0.1:8080

# List all saved requests in the session
apileaks replay sessions/pentest.json --list
```

Multiple requests can be saved to the same session file — they are appended on each run.

---

## JSON output mode

`--output json` returns a machine-readable object instead of the coloured dump:

```json
{
  "method": "POST",
  "url": "https://api.example.com/users",
  "status_code": 201,
  "elapsed": 0.243,
  "request": {
    "headers": {
      "Authorization": "Bearer eyJhbGci…",
      "Content-Type": "application/json"
    },
    "body": {"username": "alice", "role": "admin"},
    "params": {}
  },
  "response": {
    "headers": {
      "content-type": "application/json",
      "location": "/api/v1/users/99"
    },
    "body": "{\"id\":99,\"username\":\"alice\"}"
  }
}
```

With `--scan-response`:
```json
{
  ...
  "secrets_found": [
    {"pattern": "aws_access_key", "redacted": "AKIA****EXAMPLE"},
    {"pattern": "github_token",   "redacted": "ghp_****XYZ"}
  ]
}
```

---

## CI / exit codes

| Exit code | Condition |
|-----------|-----------|
| `0` | Request succeeded (any HTTP status), unless `--fail-on-error` |
| `0` | Request succeeded AND status < 400 (with `--fail-on-error`) |
| `1` | Request succeeded but status ≥ 400 (with `--fail-on-error`) |
| `1` | Connection error / timeout |

```bash
# Fail pipeline if endpoint returns 4xx or 5xx
apileaks req GET https://api.example.com/health \
  --fail-on-error || echo "Health check failed!"
```

---

## Full options reference

```
apileaks req METHOD URL [KEY=VALUE ...] [OPTIONS]

Positional arguments:
  METHOD            HTTP verb — GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, …
  URL               Full URL (https:// added automatically if missing)
  KEY=VALUE ...     httpie-style JSON body fields (optional)

Body options (mutually exclusive):
  --json JSON       Body as a JSON string. Sets Content-Type: application/json.
  -F, --form K=V    Form field (repeatable). Sets Content-Type: application/x-www-form-urlencoded.
  --raw TEXT        Raw body string (no Content-Type set automatically).

Request options:
  -H, --header Name: Value   Extra request header (repeatable)
  --jwt TOKEN                Authorization: Bearer <token>
  -p, --param K=V            Query-string parameter (repeatable)
  --proxy URL                Intercepting proxy (Burp/Caido/Hetty/mitmproxy)
  --follow-redirects         Follow 3xx redirects (default: stop at first redirect)
  --no-verify                Disable TLS certificate verification
  --timeout SECS             Per-request timeout [default: 30.0]

Output options:
  -q, --quiet                Print only the response body (for piping)
  -o, --output [text|json]   Output format: text (coloured dump) or json [default: text]
  --scan-response            Scan response for leaked secrets/credentials
  --save-session FILE        Append request/response to a replay session file

Control options:
  --fail-on-error            Exit 1 on HTTP 4xx or 5xx response
  --no-banner                Suppress the APILeak banner
  --help                     Show this message and exit
```

---

## See Also

- [`apileaks replay`](docs/cli-reference.md) — re-issue saved requests with modifications
- [MCP Tools Reference](mcp-tools-reference.md) — use all APILeak capabilities via AI agents
- [Docker Deployment](mcp-docker.md) — run APILeak in containers
