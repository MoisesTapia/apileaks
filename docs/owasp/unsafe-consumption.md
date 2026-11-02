# Unsafe Consumption of APIs (API10)

The Unsafe Consumption Testing Module detects **OWASP API10 - Unsafe Consumption of APIs** vulnerabilities: cases where an API consumes data from upstream or third-party services without proper validation, sanitization, or transport security — allowing attackers to inject malicious payloads through those trusted external channels.

The module runs in isolation as `apileaks owasp unsafe_consumption --target URL` or as part of an orchestrated `scan` run. This page documents all three detectors, every CLI option, and the YAML configuration reference.

## 📋 Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [How the Module Identifies Upstream-Sourced Endpoints](#how-the-module-identifies-upstream-sourced-endpoints)
- [Detector 1 — Unvalidated Upstream Data Reflection](#detector-1--unvalidated-upstream-data-reflection)
- [Detector 2 — Blind Redirect Following](#detector-2--blind-redirect-following)
- [Detector 3 — Cleartext Upstream Channel](#detector-3--cleartext-upstream-channel)
- [Command Reference](#command-reference)
- [Safe Mode Behavior](#safe-mode-behavior)
- [Configuration (YAML)](#configuration-yaml)
- [Finding Categories](#finding-categories)
- [Attack Scenarios (OWASP API10:2023)](#attack-scenarios-owasp-api102023)
- [Remediation](#remediation)

---

## 🎯 Overview

Developers tend to trust data from third-party APIs more than direct user input, leading to weaker validation rules at the integration boundary. An API is vulnerable under OWASP API10 when it:

- Does not validate or sanitize data received from upstream services before processing or reflecting it.
- Blindly follows redirects returned by a third-party API without verifying the redirect target.
- Communicates with upstream services over an unencrypted channel (plain HTTP).
- Does not implement timeouts or resource limits for third-party service interactions.

The module covers the first three vectors, which are detectable with automated HTTP probing. Timeout and resource-limit issues are covered by the `resource` module (API4).

**Three independent detectors, all on by default:**

| Detector | Finding | Severity |
|----------|---------|----------|
| Unvalidated data reflection | `UNSAFE_UPSTREAM_DATA` | HIGH |
| Blind redirect following | `UNSAFE_BLIND_REDIRECT` | HIGH |
| Cleartext upstream channel | `UNSAFE_CLEARTEXT_UPSTREAM` | MEDIUM |

---

## 🚀 Quick Start

```bash
# Minimal scan — all three detectors, built-in defaults
python apileaks.py owasp unsafe_consumption --target https://api.example.com

# With authentication
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Custom upstream indicators to match your target's architecture
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --unsafe-upstream-indicators proxy \
  --unsafe-upstream-indicators fetch \
  --unsafe-upstream-indicators webhook

# Full red-team: custom payloads + OOB redirect listener + cleartext check
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --unsafe-upstream-indicators proxy \
  --unsafe-upstream-indicators aggregate \
  --unsafe-payloads "<script>alert(1)</script>" \
  --unsafe-payloads "' OR 1=1--" \
  --unsafe-check-redirects \
  --unsafe-redirect-url "https://xyz.interact.sh" \
  --unsafe-check-cleartext

# Safe read-only mode — no state-changing probes
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --safe-mode

# Run alongside other modules in an orchestrated scan
python apileaks.py scan \
  --target https://api.example.com \
  --modules unsafe_consumption,ssrf,auth
```

---

## How the Module Identifies Upstream-Sourced Endpoints

Before running any injection probe, the module performs a baseline GET request to each endpoint and classifies it as **upstream-sourced** when any configured `upstream_indicator` keyword appears (case-insensitive) in:

1. The endpoint URL path (e.g. `/api/v1/proxy/fetch`, `/v2/external-data`)
2. The baseline response body
3. Any response header (key or value)

Only endpoints classified as upstream-sourced receive Detector 1 (reflection) and Detector 2 (redirect) probes. Detector 3 (cleartext) is static — it fires on any `http://` endpoint regardless of upstream-sourced status.

**Built-in upstream indicators** (overridable with `--unsafe-upstream-indicators`):

```
proxy, upstream, external, aggregate
```

Extend this list to match your target's naming conventions:

```bash
--unsafe-upstream-indicators fetch
--unsafe-upstream-indicators webhook
--unsafe-upstream-indicators "third-party"
--unsafe-upstream-indicators import
```

---

## Detector 1 — Unvalidated Upstream Data Reflection

**Finding:** `UNSAFE_UPSTREAM_DATA` · **Severity:** HIGH · **OWASP:** API10

### What it tests

For each upstream-sourced endpoint, the module injects each configured `malformed_payload` into:

- **Query parameters** (`q`, `data`, `input`, `query`, `search`, `value`, `url`) — always.
- **Request body** (`{"data": "<payload>"}`) — only for POST/PUT/PATCH endpoints when Safe Mode is disabled.

If the response body reflects the exact injected payload verbatim (unencoded, unsanitized), the module emits an `UNSAFE_UPSTREAM_DATA` finding.

**Built-in payloads** (overridable with `--unsafe-payloads`):

| Payload | Attack class |
|---------|-------------|
| `{"__proto__":{}}` | Prototype pollution |
| `<script>` | XSS / HTML injection |
| `' OR 1=1--` | SQL injection |
| `\u0000` (null byte) | Null-byte injection |

### Detection logic

```
endpoint URL / response body / headers contains upstream_indicator?
  → YES: classified as upstream-sourced
        → inject malformed_payload into query params
        → if payload appears verbatim in response body → UNSAFE_UPSTREAM_DATA (HIGH)
        → if state-changing method and not safe mode:
            → inject payload into request body
            → if payload appears verbatim in response body → UNSAFE_UPSTREAM_DATA (HIGH)
  → NO: skipped (no injection probes issued)
```

### Examples

```bash
# Default payload set (prototype-pollution, XSS, SQLi, null-byte)
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Custom payloads targeting a specific injection class
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --unsafe-upstream-indicators proxy \
  --unsafe-payloads "{{7*7}}" \
  --unsafe-payloads "{{config}}" \
  --unsafe-payloads "${7*7}"

# Disable body injection (query params only)
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --safe-mode
```

---

## Detector 2 — Blind Redirect Following

**Finding:** `UNSAFE_BLIND_REDIRECT` · **Severity:** HIGH · **OWASP:** API10

This detector addresses **OWASP API10:2023 Scenario #2**: a third-party API starts responding with `308 Permanent Redirect` to an attacker-controlled server, and the consuming API blindly follows the redirect — forwarding sensitive user data to the attacker's endpoint.

### What it tests

For each upstream-sourced endpoint, the module injects `redirect_test_url` (default: `http://169.254.169.254/latest/meta-data/`) into URL-carrying query parameters:

```
url, redirect, callback, next, location, target, dest, destination,
return, returnUrl, redirectUrl, forward, link, src, source, fetch
```

A finding is emitted when **either** of two signals is detected:

**Signal 1 — Server-issued redirect:** The server responds with a `3xx` status whose `Location` header contains the injected URL. This means the server passed the redirect target through to the client unchanged.

**Signal 2 — IMDS/cloud-metadata body signature:** The response body contains a known cloud-metadata content pattern, indicating the server fetched the injected URL and returned its content:

```
ami-id, instance-id, iam/security-credentials, latest/meta-data,
computeMetadata, metadata/instance
```

### Examples

```bash
# Default — uses the AWS IMDS URL as the redirect probe target
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --unsafe-check-redirects

# OOB listener — most effective in production; hit confirms blind following
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --unsafe-check-redirects \
  --unsafe-redirect-url "https://xyz.interact.sh"

# Disable redirect detector (reflection + cleartext only)
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --no-unsafe-check-redirects
```

> **Tip:** In real-world assessments, point `--unsafe-redirect-url` at an Interactsh or Burp Collaborator subdomain and watch for incoming DNS/HTTP hits. A server-side hit confirms that the API is fetching the URL without verifying the destination — even when the response body gives no indication.

---

## Detector 3 — Cleartext Upstream Channel

**Finding:** `UNSAFE_CLEARTEXT_UPSTREAM` · **Severity:** MEDIUM · **OWASP:** API10

### What it tests

This is a **static check** — no HTTP probe is issued. When an endpoint's URL starts with `http://`, all communication with that upstream service is transmitted in plain text. A network-layer attacker between the API and the upstream service can intercept and tamper with the data in transit.

This fires independently of whether the endpoint is upstream-sourced. It applies to any `http://` endpoint in the scan scope — including internal microservice integrations and third-party API calls.

### Examples

```bash
# Cleartext check enabled by default
python apileaks.py owasp unsafe_consumption \
  --target http://api.internal.corp/v1

# Run cleartext check only (disable the other two detectors)
python apileaks.py owasp unsafe_consumption \
  --target http://api.internal.corp/v1 \
  --no-unsafe-check-redirects \
  --unsafe-upstream-indicators ""    # empty indicator list → no reflection probes

# Disable cleartext check
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --no-unsafe-check-cleartext
```

> **Note on scope:** The cleartext check reports on each `http://` endpoint in the **scan's discovered endpoint list**, not on the API's outbound connections to external services (those aren't visible from the outside). If the target API calls a third-party service over HTTP internally, that will only be visible if the endpoint URL itself is `http://` or if the response leaks the internal URL.

---

## 📖 Command Reference

All options are supplied to `apileaks owasp unsafe_consumption`.

**Options at a glance:**

| Option | What it controls | Default |
|--------|-----------------|---------|
| `--unsafe-upstream-indicators KEYWORD` | Keyword used to identify upstream-sourced endpoints (repeatable). Replaces built-in list when any value is supplied. | `proxy, upstream, external, aggregate` |
| `--unsafe-payloads PAYLOAD` | Malformed payload to inject into upstream-sourced endpoints (repeatable). Replaces built-in list when any value is supplied. | prototype-pollution, XSS, SQLi, null-byte |
| `--unsafe-check-redirects` / `--no-unsafe-check-redirects` | Enable or disable the blind-redirect-following detector. | enabled |
| `--unsafe-redirect-url URL` | URL injected as the redirect probe target. Use an OOB listener in production scans. | `http://169.254.169.254/latest/meta-data/` |
| `--unsafe-check-cleartext` / `--no-unsafe-check-cleartext` | Enable or disable the cleartext-upstream-channel detector. | enabled |

### `--unsafe-upstream-indicators`

**Description.** Keyword matched case-insensitively against the endpoint URL, baseline response body, and response headers to decide whether the endpoint returns data sourced from an upstream or third-party API. The option is **repeatable** — pass it once per keyword. When any value is supplied, it **replaces** the built-in list (`proxy`, `upstream`, `external`, `aggregate`) entirely, so include all the keywords you need.

**Example:**

```bash
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --unsafe-upstream-indicators fetch \
  --unsafe-upstream-indicators webhook \
  --unsafe-upstream-indicators "third-party" \
  --unsafe-upstream-indicators import
```

### `--unsafe-payloads`

**Description.** Malformed payload injected into query parameters and (when safe mode is off) request bodies of upstream-sourced endpoints. Verbatim reflection of any payload in the response triggers an `UNSAFE_UPSTREAM_DATA` finding. The option is **repeatable**. When any value is supplied, it **replaces** the built-in payload list entirely.

**Example:**

```bash
# Template injection payloads
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --unsafe-payloads "{{7*7}}" \
  --unsafe-payloads "{{config.items()}}" \
  --unsafe-payloads "<%= 7*7 %>"

# Combined with custom indicators
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --unsafe-upstream-indicators "data-source" \
  --unsafe-payloads "' OR '1'='1" \
  --unsafe-payloads "admin'--"
```

### `--unsafe-check-redirects` / `--no-unsafe-check-redirects`

**Description.** Toggles the blind-redirect-following detector (Detector 2). Enabled by default. Pass `--no-unsafe-check-redirects` to disable it when you only want to test for unvalidated data reflection and cleartext channels — for example, when the redirect probe URL would trigger alerts in a WAF or IDS.

**Example:**

```bash
# Reflection + cleartext only
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --no-unsafe-check-redirects
```

### `--unsafe-redirect-url`

**Description.** The URL injected as the redirect probe target in Detector 2. In lab environments the default (`http://169.254.169.254/latest/meta-data/`) is useful because it returns recognizable IMDS content if the server fetches it. In production assessments, use an OOB listener so you can detect blind following even when the response body is empty or generic.

**Example:**

```bash
# Interactsh OOB listener
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --unsafe-redirect-url "https://xyz.interact.sh"

# Burp Collaborator
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --unsafe-redirect-url "https://xyz.burpcollaborator.net"

# Internal target — useful when scanning internal APIs
python apileaks.py owasp unsafe_consumption \
  --target https://api.internal.corp \
  --unsafe-redirect-url "http://10.0.0.1/admin"
```

### `--unsafe-check-cleartext` / `--no-unsafe-check-cleartext`

**Description.** Toggles the cleartext-upstream-channel detector (Detector 3). Enabled by default. The check is purely static: it inspects the URL scheme of each endpoint without issuing any HTTP request. Pass `--no-unsafe-check-cleartext` when you know the target is HTTP-only by design (e.g. an internal lab environment) and you don't want MEDIUM findings for every endpoint.

**Example:**

```bash
# Reflection + redirect only
python apileaks.py owasp unsafe_consumption \
  --target http://localhost:8000 \
  --no-unsafe-check-cleartext
```

---

## 🔒 Safe Mode Behavior

When `--safe-mode` is active the module adjusts its behavior as follows:

| Behavior | Normal mode | Safe mode |
|----------|-------------|-----------|
| Upstream-sourced detection (baseline GET) | ✅ | ✅ |
| Reflection probe — query params | ✅ | ✅ |
| Reflection probe — request body (POST/PUT/PATCH) | ✅ | ❌ skipped |
| POST/PUT/PATCH/DELETE endpoints | ✅ | ❌ skipped entirely |
| Redirect detector | ✅ | ✅ (GET only) |
| Cleartext check (static) | ✅ | ✅ |

State-changing methods are skipped completely in safe mode — not just the body probe. A POST endpoint that is also upstream-sourced will not receive any probe, including the baseline request used to identify it.

---

## 🗂️ Configuration (YAML)

```yaml
owasp_testing:
  enabled_modules: ["unsafe_consumption"]

  unsafe_consumption_testing:
    enabled: true

    # Keywords matched against URL, response body, and headers to identify
    # endpoints that return data sourced from upstream/third-party APIs.
    upstream_indicators:
      - "proxy"
      - "upstream"
      - "external"
      - "aggregate"

    # Malformed payloads injected into upstream-sourced endpoints.
    # Verbatim reflection of any payload triggers UNSAFE_UPSTREAM_DATA.
    malformed_payloads:
      - '{"__proto__":{}}'
      - "<script>"
      - "' OR 1=1--"
      - "\u0000"

    # Detector 2: blind redirect following.
    # Set redirect_test_url to an OOB listener for production assessments.
    check_redirects: true
    redirect_test_url: "http://169.254.169.254/latest/meta-data/"

    # Detector 3: cleartext upstream channel (static URL scheme check).
    check_cleartext_upstream: true
```

**Field reference:**

| Field | CLI equivalent | Default | Purpose |
|-------|----------------|---------|---------|
| `upstream_indicators` | `--unsafe-upstream-indicators` | `["proxy","upstream","external","aggregate"]` | Keywords that identify upstream-sourced endpoints |
| `malformed_payloads` | `--unsafe-payloads` | 4 built-in payloads | Injected into upstream-sourced endpoints |
| `check_redirects` | `--unsafe-check-redirects` | `true` | Enable/disable Detector 2 |
| `redirect_test_url` | `--unsafe-redirect-url` | `http://169.254.169.254/latest/meta-data/` | Redirect probe target URL |
| `check_cleartext_upstream` | `--unsafe-check-cleartext` | `true` | Enable/disable Detector 3 |

---

## 📊 Finding Categories

### `UNSAFE_UPSTREAM_DATA`

| Field | Value |
|-------|-------|
| Severity | HIGH |
| OWASP | API10 |
| Description | Endpoint returns upstream-sourced data and reflected an unvalidated malformed payload verbatim. |
| Evidence | Injection point, reflected payload, indicator that triggered upstream-sourced classification, response status. |
| Recommendation | Validate, sanitize, and strictly type-check all data consumed from upstream/third-party APIs before forwarding or reflecting it. Apply schema validation and output encoding. Do not trust data returned by integrated services. |

### `UNSAFE_BLIND_REDIRECT`

| Field | Value |
|-------|-------|
| Severity | HIGH |
| OWASP | API10 |
| Description | Endpoint follows redirects from upstream APIs without validating the redirect target (OWASP API10 Scenario #2). |
| Evidence | Injected parameter name, evidence signal (3xx Location header or IMDS body signature), status code. |
| Recommendation | Do not blindly follow redirects from upstream APIs or user-supplied URLs. Maintain an allowlist of permitted redirect destinations and reject any Location target not on the list. |

### `UNSAFE_CLEARTEXT_UPSTREAM`

| Field | Value |
|-------|-------|
| Severity | MEDIUM |
| OWASP | API10 |
| Description | Endpoint URL uses `http://` — communication with the upstream service is unencrypted and susceptible to man-in-the-middle attack. |
| Evidence | Endpoint URL with `http://` scheme. |
| Recommendation | Ensure all interactions with upstream/third-party APIs use HTTPS (TLS). Replace `http://` with `https://` and verify the upstream service's TLS certificate. Do not disable certificate verification. |

---

## 🎭 Attack Scenarios (OWASP API10:2023)

### Scenario 1 — SQL injection via third-party data

An API relies on a third-party address-enrichment service. When an address is submitted, it is sent to the third-party service and the returned data is stored in a local SQL-enabled database **without sanitization**.

An attacker plants an SQL injection payload in the third-party service (by creating a business record with a malicious name), then queries the vulnerable API with the specific input that causes it to pull the attacker's record. The SQLi payload executes against the database.

**What apileaks detects:** The API enrichment endpoint is classified as upstream-sourced (keyword `external` or `enrich` in the URL). The module injects `' OR 1=1--` into query parameters. If the payload appears verbatim in the response or triggers a database error, `UNSAFE_UPSTREAM_DATA` is emitted.

```bash
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --unsafe-upstream-indicators enrich \
  --unsafe-upstream-indicators lookup \
  --unsafe-payloads "' OR 1=1--" \
  --unsafe-payloads "'; DROP TABLE users;--" \
  --unsafe-payloads "' UNION SELECT 1,2,3--"
```

### Scenario 2 — Sensitive data exfiltration via blind redirect (OWASP reference scenario)

An API integrates with a third-party to store sensitive user medical records. The third-party starts responding with `308 Permanent Redirect` to `https://attacker.com/`. The API blindly follows the redirect and sends the full medical record payload to the attacker's server.

**What apileaks detects:** The storage endpoint is upstream-sourced. The module injects the `redirect_test_url` into URL-carrying parameters. If the response contains an IMDS signature or a 3xx pointing at the injected URL, `UNSAFE_BLIND_REDIRECT` is emitted.

```bash
python apileaks.py owasp unsafe_consumption \
  --target https://api.example.com \
  --unsafe-upstream-indicators store \
  --unsafe-check-redirects \
  --unsafe-redirect-url "https://xyz.interact.sh"
```

### Scenario 3 — SQL injection via malicious git repository name

An API integrates with a source control service and builds SQL queries using repository names without escaping. An attacker creates a repository named `'; DROP TABLE projects;--`. The API fetches the repository list from the external service and the name is used unsanitized in a SQL query.

**What apileaks detects:** The repository-sync endpoint is upstream-sourced. The injected payload `' OR 1=1--` appears in the response body (error message or data echo), triggering `UNSAFE_UPSTREAM_DATA`.

---

## 🛡️ Remediation

### Unvalidated data reflection (UNSAFE_UPSTREAM_DATA)

- **Validate at intake:** Apply schema validation to all data received from third-party APIs. Reject any response that does not conform to the expected schema.
- **Output encoding:** Encode all externally sourced data before embedding it in HTML, SQL, JSON, or any other output format.
- **Type coercion:** Cast values to their expected types (string → int, etc.) rather than passing raw strings. This eliminates most injection payloads automatically.
- **Don't reflect errors:** Never include raw upstream error messages or upstream data in API error responses without sanitization.

### Blind redirect following (UNSAFE_BLIND_REDIRECT)

- **Allowlist redirect destinations:** Before following any redirect, verify the Location target is in an explicit allowlist of known-good domains.
- **Disable auto-follow for sensitive flows:** For endpoints that transfer or store sensitive data, disable automatic redirect following in your HTTP client and validate the Location explicitly.
- **Log redirect attempts:** Alert on unexpected redirect destinations from integrated services — this can indicate a supply-chain compromise.

### Cleartext upstream channel (UNSAFE_CLEARTEXT_UPSTREAM)

- **Enforce TLS for all upstream calls:** Replace all `http://` URLs in your integration code with `https://`.
- **Verify certificates:** Do not set `verify=False` in your HTTP client configuration for production integrations.
- **Use mutual TLS (mTLS)** for high-value internal service-to-service communication.
- **Periodic scanning:** Re-run `--unsafe-check-cleartext` as part of your CI/CD pipeline to catch new HTTP-only integrations introduced during development.

---

See also: [OWASP Coverage](README.md) · [SSRF Testing (API7)](ssrf-testing.md) · [OWASP Command Reference](../owasp-command.md) · [Scan Guide](../scan-guide.md)
