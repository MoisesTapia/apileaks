# 📖 APILeak CLI Reference

Complete command-line interface reference for APILeak v0.2.0 - Enterprise API security testing tool.

## Table of Contents

- [Global Options](#global-options)
- [Commands Overview](#commands-overview)
- [Directory Fuzzing (`dir`)](#directory-fuzzing-dir)
  - [Discovery Control Options](#discovery-control-options)
  - [Proxy Options](#proxy-options)
  - [Discovery Robustness Options](#discovery-robustness-options)
    - [Seed Inputs and Extensions](#seed-inputs-and-extensions)
    - [Request Context (Headers, Cookies, Auth)](#request-context-headers-cookies-auth)
    - [Response Matchers and Filters](#response-matchers-and-filters)
    - [Method Enumeration and GraphQL](#method-enumeration-and-graphql)
    - [Per-Request Resilience](#per-request-resilience)
    - [Transport and TLS](#transport-and-tls)
    - [Secret and Leak Detection](#secret-and-leak-detection)
    - [Machine-Readable Output](#machine-readable-output)
    - [Path and Status Scope (Storage-Time Selection)](#path-and-status-scope-storage-time-selection)
    - [Recursion Scope](#recursion-scope)
    - [Hit Confirmation](#hit-confirmation)
    - [Checkpoint and Resume](#checkpoint-and-resume)
  - [Discovery Triage Options](#discovery-triage-options)
  - [Discovery-to-Scan Integration (Batch Scan Scope)](#discovery-to-scan-integration-batch-scan-scope)
  - [Status Code Filtering](#status-code-filtering)
  - [Examples](#examples)
  - [Rate Limiting and User-Agent in Discovery and Triage](#rate-limiting-and-user-agent-in-discovery-and-triage)
- [Parameter Fuzzing (`par`)](#parameter-fuzzing-par)
- [Security Scan (`scan`)](#security-scan-scan)
- [OWASP Module Commands (`owasp`)](#owasp-module-commands-owasp)
- [JWT Utilities](#jwt-utilities)
- [Proxy Integration](#proxy-integration)
- [Environment Variables](#environment-variables)
- [Exit Codes](#exit-codes)
- [Examples](#examples)

## Global Options

These options are available for all commands:

| Option | Description | Default |
|--------|-------------|---------|
| `--no-banner` | Suppress banner output | `false` |
| `--help` | Show help message and exit | - |

## Commands Overview

APILeak provides the following main commands:

| Command | Purpose | Use Case |
|---------|---------|----------|
| `dir` | Directory/endpoint fuzzing | Discover hidden endpoints and directories |
| `par` | Parameter fuzzing | Find hidden parameters in API endpoints |
| `scan` | Orchestrated OWASP scan (primary) | Runs discovery + all registered OWASP modules and drives the CI gate |
| `owasp` | OWASP module group | List modules, or run exactly one OWASP module in isolation (`owasp <key>`) |
| `jwt` | JWT security utilities | JWT token manipulation and security testing |

> **Deprecation.** `full` and `main` are deprecated, hidden aliases of `scan`. They still work and forward to `scan` (printing a one-line deprecation notice to stderr), but you should migrate scripts to `scan`. Module selection through the alias also migrates: `full --modules bola` → `apileaks owasp bola`.

### Help System

APILeak provides comprehensive help at multiple levels:

```bash
# Main help - shows all commands and global options
python apileaks.py --help

# Command-specific help - shows all options for a specific command
python apileaks.py scan --help
python apileaks.py owasp --help
python apileaks.py dir --help
python apileaks.py par --help

# JWT utilities help
python apileaks.py jwt --help
python apileaks.py jwt decode --help
python apileaks.py jwt encode --help
```

## Directory Fuzzing (`dir`)

Discover hidden API endpoints and administrative interfaces.

**Purpose.** The `dir` command performs directory and endpoint fuzzing against a target: it sends candidate paths (from wordlists and/or imported API specs), classifies each discovered endpoint, and optionally recurses into promising paths. On top of raw discovery it layers an opt-in **triage workflow** (status grouping, session persistence, exports, an interactive table) and can feed discovered endpoints straight into an OWASP scan.

**Option groups at a glance:**

| Group | What it controls |
|-------|------------------|
| [Discovery Control](#discovery-control-options) | Recursion depth, request budget, and concurrency |
| [Proxy](#proxy-options) | Routing traffic through an intercepting proxy |
| [Discovery Robustness](#discovery-robustness-options) | Seeds/extensions, request context, response matchers/filters, method/GraphQL probing, resilience, TLS, secret detection, machine output, storage-time scope, recursion scope, hit confirmation, checkpoint/resume |
| [Discovery Triage](#discovery-triage-options) | Sessions, exports, and the interactive table |
| [Discovery-to-Scan Integration](#discovery-to-scan-integration-batch-scan-scope) | Batch-scanning discovered endpoints |
| [Status Code Filtering](#status-code-filtering) | How `--status-code` is parsed in triage mode |
| [Rate Limiting and User-Agent](#rate-limiting-and-user-agent-in-discovery-and-triage) | Pacing and identifying discovery requests |

### Syntax

```bash
python apileaks.py dir [OPTIONS]
```

### Required Options

| Option | Description | Example |
|--------|-------------|---------|
| `--target`, `-t` | Target URL to scan | `--target https://api.example.com` |

### Optional Parameters

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--wordlist`, `-w` | Wordlist file for directory fuzzing | `wordlists/endpoints.txt` | `--wordlist custom_endpoints.txt` |
| `--output`, `-o` | Output filename for reports | Auto-generated | `--output my-scan` |
| `--log-level` | Logging level | `WARNING` | `--log-level DEBUG` |
| `--log-file` | Log file path | Console only | `--log-file scan.log` |
| `--json-logs` | Output logs in JSON format | `false` | `--json-logs` |
| `--rate-limit` | Requests per second limit | `10` | `--rate-limit 5` |
| `--methods` | HTTP methods to test | `GET,POST,PUT,DELETE,PATCH` | `--methods GET,POST` |
| `--jwt` | JWT token for authentication | - | `--jwt eyJ0eXAi...` |
| `--response` | Filter by response codes | All codes | `--response 200,301,404` |
| `--status-code` | Filter displayed results by status code or status class | All codes | `--status-code 2xx` |

### User Agent Options (Mutually Exclusive)

| Option | Description | Example |
|--------|-------------|---------|
| `--user-agent-random` | Use random User-Agent headers | `--user-agent-random` |
| `--user-agent-custom` | Custom User-Agent string | `--user-agent-custom "MyScanner/1.0"` |
| `--user-agent-file` | File with User-Agent strings | `--user-agent-file agents.txt` |

### Advanced Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--detect-framework`, `--df` | Enable framework detection | `false` | `--detect-framework` |
| `--fuzz-versions`, `--fv` | Enable API version fuzzing | `false` | `--fuzz-versions` |

### Discovery Control Options

These flags tune recursive discovery so you can trade breadth for speed. They keep recursion agile: stay shallow and fast for a quick sweep, or go deep and thorough when you need full coverage — always bounded by the request budget and catch-all detection.

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--depth` | Max recursion depth for discovery (`0` = no recursion, depth-0 pass only) | `3` (see precedence below) | `--depth 5` |
| `--recursive` / `--no-recursive` | Enable or disable recursive discovery | enabled | `--no-recursive` |
| `--max-requests` | Global request budget for discovery | unbounded | `--max-requests 5000` |
| `--concurrency` | Max concurrent in-flight discovery requests | `50` | `--concurrency 100` |

**Depth precedence.** The effective recursion depth is resolved as: explicit CLI `--depth` > the `APILEAK_MAX_DEPTH` environment variable > the built-in default of `3`. So `--depth` always wins when supplied; otherwise `APILEAK_MAX_DEPTH` is honored if set; otherwise depth `3` is used.

**Notes.**
- `--depth 0` performs only the depth-0 pass and disables recursion (equivalent to `--no-recursive`).
- `--max-requests` defaults to unbounded; when set, it caps the total number of discovery requests across all depths.
- `--concurrency` defaults to `50` concurrent in-flight requests when not specified.
- `--depth` must be `>= 0`; `--max-requests` and `--concurrency` must be `>= 1`.

### Proxy Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--proxy` | Route all HTTP traffic through an intercepting proxy (Burp/Caido/Hetty). Also accepts a SOCKS5 URL, optionally with auth | - | `--proxy http://127.0.0.1:8080` |
| `--proxy-verify-ssl` | Keep TLS verification on when proxying (after installing the proxy CA) | `false` | `--proxy-verify-ssl` |

> **SOCKS5 dependency.** Routing through a SOCKS5 proxy (e.g. `--proxy socks5://user:pass@host:port`) requires the optional `httpx[socks]` extra to be installed (`pip install "httpx[socks]"`). Without it, SOCKS5 URLs are rejected by the underlying HTTP client. Plain `http://`/`https://` proxies need no extra dependency.

See [Proxy Integration](#proxy-integration) for details.

### Discovery Robustness Options

These flags harden and broaden discovery: they widen the candidate set (seeds and extensions), attach request context (headers/cookies/auth), refine which results are kept (response matchers/filters), enumerate methods and GraphQL surfaces, control per-request resilience and transport/TLS, scan responses for secrets, and emit machine-readable output. Unless noted otherwise these options apply to the `dir` command. The shared options `-x`/`--extensions`, `--timeout`, and `--retries` are also accepted by the `scan` command.

#### Seed Inputs and Extensions

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--wordlist`, `-w` | Wordlist file for discovery. **Repeatable**; values are merged and de-duplicated after normalization. Pass `-` to read entries from stdin (empty lines and `#` comment lines are skipped) | `wordlists/endpoints.txt` | `-w a.txt -w b.txt` / `cat list.txt \| ... -w -` |
| `--openapi` | OpenAPI/Swagger document (JSON or YAML) to seed discovery from. **Repeatable** | - | `--openapi api.yaml` |
| `--postman` | Postman collection to seed discovery from. **Repeatable** | - | `--postman collection.json` |
| `--extensions`, `-x` | File extensions appended to each wordlist entry (comma-separated, **repeatable**). Leading dots are optional, so `-x json,php` and `-x .json -x .php` are equivalent. Also available on `scan` | - | `-x json,php` |

Notes:

- Repeated `--wordlist` values and `--openapi`/`--postman` seeds are merged into a single candidate set with no duplicate normalized paths. If the merged candidate set is empty, the command completes without issuing any request and reports that no candidates were available.
- An unparseable OpenAPI/Postman source is rejected with a descriptive error and no discovery is performed.
- Each extension expands a wordlist entry into the original entry plus one candidate per distinct normalized extension (so `W` entries with `E` distinct extensions produce `W × (E + 1)` candidates per method). Every expanded candidate counts toward `--max-requests` and stays within `--concurrency`.

#### Positional Fuzz Markers (`--fuzz-keyword`, `--fuzz-mode`)

Positional fuzzing places a literal keyword directly inside the target URL and sweeps each marked position with candidate values — the ffuf/wfuzz convention. This lets you fuzz a version segment, a filename, a query-parameter value, or several positions at once, instead of only appending wordlist entries to a base path.

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--fuzz-keyword` | Literal token in the target URL that marks positions to fuzz. Every non-overlapping literal occurrence becomes a marker, scanned left-to-right. Matched as a plain literal (never a regex) | `FUZZ` | `--fuzz-keyword FUZZ` |
| `--fuzz-mode` | How two or more markers combine their wordlists: `clusterbomb` (cartesian product) or `pitchfork` (index-wise pairing). Case-insensitive | `clusterbomb` | `--fuzz-mode pitchfork` |

**How markers are detected.** Every literal occurrence of the keyword in the target URL is treated as a marker (a *Marker_Position*), scanned left-to-right and counted as the number of non-overlapping occurrences. A marker may fall inside a path segment (as a substring or a whole segment), a query-parameter name or value, a filename, or a file extension. Substitution preserves every other character, path segment, and query parameter of the target URL unchanged.

**When marker mode engages.** Marker mode is active whenever the target URL contains the keyword. If the target URL contains no occurrence of the keyword — and no marker-only option was supplied — `dir` falls back to the existing base-path behavior, appending each wordlist entry to the base path via URL join.

**Per-marker wordlist association.** In marker mode the repeatable `--wordlist` values become the per-marker wordlists, associated with markers in the left-to-right order the markers occur (the first `--wordlist` is the wordlist of the first marker, and so on). This differs from the non-marker merge-and-de-duplicate behavior. Fallback rules:

- **Fewer wordlists than markers:** the last supplied wordlist fills every remaining marker that has no explicitly associated wordlist.
- **Exactly one wordlist, two or more markers:** that single wordlist is used for every marker.
- **More wordlists than markers:** rejected with a descriptive error (see below).

**Combination modes.** With two or more markers, `--fuzz-mode` controls how the per-marker wordlists combine:

- `clusterbomb` (default): the cartesian product of all wordlists — every combination of one value per marker becomes a candidate. For `M` markers with wordlist sizes `W1 … WM`, this generates `W1 × … × WM` candidates.
- `pitchfork`: the wordlists are iterated in parallel, pairing the i-th value of each list, stopping at the shortest wordlist — `min(W1, …, WM)` candidates. Use it to pair related lists position-by-position (e.g. a versions list with a matching filenames list).

A single marker reduces to exactly `W` candidates in either mode. Marker-generated candidates obey the same discovery controls as any other candidate: URL normalization and de-duplication, the `--max-requests` budget, the `--concurrency` limit, `--rate-limit`, the User-Agent options, the response matchers/filters, and `--confirm-hits`.

**Choosing a distinct keyword.** Because *every* literal occurrence of the keyword is treated as a marker, pick a keyword that does not appear in legitimate URL text. If `FUZZ` (or your chosen keyword) could collide with real path, query, or hostname text, choose a distinct token (for example `__FUZZ__`) to avoid creating unintended marker positions.

**Marker-mode validation (exit-before-discovery).** These configurations are rejected with a descriptive error and issue **no** requests:

- An empty or whitespace-only `--fuzz-keyword`.
- A marker-only option (`--fuzz-keyword` or `--fuzz-mode` given explicitly on the command line) while the target URL contains no occurrence of the keyword.
- More `--wordlist` sources than there are markers (the error names both counts).
- `--fuzz-mode pitchfork` with an empty associated wordlist (the error identifies the empty wordlist).
- A `--fuzz-mode` value other than `clusterbomb` or `pitchfork`.
- An associated wordlist that cannot be read from its source (the error names the unreadable source).

#### Request Context (Headers, Cookies, Auth)

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--header`, `-H` | Custom header applied to every discovery request, in `"Name: Value"` format. **Repeatable** | - | `-H "X-API-Key: key123"` |
| `--cookie` | Raw `Cookie` header string applied to every discovery request | - | `--cookie "session=abc123"` |
| `--basic-auth` | HTTP Basic credentials as `user:pass`, sent as an `Authorization` header on every discovery request | - | `--basic-auth admin:secret` |

Notes:

- These request-context settings are carried into the targeted follow-up scan launched from interactive triage.
- `--basic-auth` and `--jwt` are mutually exclusive; supplying both is rejected with a descriptive error and no discovery runs.
- A `--basic-auth` value without a `:` separating user and password is rejected with a descriptive error and no discovery runs.
- When `--load-session` reloads a prior session, no requests are issued, so none of these options are applied to that run.

#### Response Matchers and Filters

Matchers keep only results that satisfy them; filters exclude results that satisfy them. When both are present, matchers are applied first and filters are applied to the retained set. They compose conjunctively with `--status-code`. All of these options are **repeatable**.

| Option | Description | Example |
|--------|-------------|---------|
| `--match-size` | Keep results whose response body size (bytes) satisfies the expression | `--match-size >100` |
| `--match-words` | Keep results whose response word count satisfies the expression | `--match-words 10-20` |
| `--match-lines` | Keep results whose response line count satisfies the expression | `--match-lines <50` |
| `--match-regex` | Keep results whose response body matches the regular expression | `--match-regex "api_key"` |
| `--match-time` | Keep results whose response time (seconds) satisfies the expression | `--match-time >2` |
| `--filter-size` | Exclude results whose response body size (bytes) satisfies the expression | `--filter-size 0` |
| `--filter-words` | Exclude results whose response word count satisfies the expression | `--filter-words <5` |
| `--filter-lines` | Exclude results whose response line count satisfies the expression | `--filter-lines 1` |
| `--filter-regex` | Exclude results whose response body matches the regular expression | `--filter-regex "Not Found"` |
| `--filter-time` | Exclude results whose response time (seconds) satisfies the expression | `--filter-time >10` |

**Expression forms.** Numeric attributes (`size`, `words`, `lines`, `time`) accept `>N`, `<N`, an inclusive range `N-M`, or an exact value `N`. The `regex` attributes take a regular expression matched against the response body. A syntactically invalid expression (an unparseable regex or a non-numeric bound) is rejected with a descriptive error and no discovery is performed. A soft-404 baseline is derived automatically and matching noise is suppressed independently of these selectors.

#### Method Enumeration and GraphQL

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--enumerate-methods` | After discovering an endpoint, issue an `OPTIONS` request and record the methods parsed from the `Allow` header. An absent/empty `Allow` records an empty set; a `405` marks the path valid under a different method | `false` | `--enumerate-methods` |
| `--graphql` | Probe common GraphQL paths and report whether introspection is enabled (read-only introspection query). No finding is recorded when no GraphQL endpoint is found | `false` | `--graphql` |

Both are off by default, and each extra request they issue counts toward `--max-requests` and stays within `--concurrency`.

#### Per-Request Resilience

These options apply to both `dir` and `scan`.

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--timeout` | Per-request timeout in seconds applied to every discovery request (must be `> 0`) | `10` | `--timeout 30` |
| `--retries` | Number of automatic retries for each failed discovery request (must be `>= 0`) | `2` | `--retries 5` |

A request exceeding `--timeout` is abandoned and retried up to `--retries`. A `429` response triggers automatic throttle/backoff that continues to honor the configured rate limit and concurrency. An invalid `--timeout` (not a positive number) or `--retries` (not a non-negative integer) is rejected with a descriptive error and no discovery is performed.

#### Transport and TLS

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--client-cert` | Client certificate for mutual TLS, presented on every request. A combined `cert+key` PEM path, or a `cert:key` pair of paths | - | `--client-cert client.pem` |
| `--ca-bundle` | Custom CA bundle used to verify target certificates for every request | - | `--ca-bundle ca.pem` |
| `--allow-cross-domain-redirects` | Follow redirects to other domains. By default discovery follows redirects only to the originating request's domain | `false` | `--allow-cross-domain-redirects` |
| `--resolve` | Override DNS resolution for a host to a given IP for every request, expressed as `host:ip` | - | `--resolve api.example.com:127.0.0.1` |

Notes:

- A `--client-cert` or `--ca-bundle` path that does not exist or cannot be read is rejected with a descriptive error naming the path, and no discovery is performed.
- A `--resolve` value not expressed as `host:ip` is rejected with a descriptive error naming the value, and no discovery is performed.
- SOCKS5 proxies are supplied through the existing `--proxy` flag and require the `httpx[socks]` extra (see the Proxy Options note above).

#### Secret and Leak Detection

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--detect-secrets` | Scan each discovery response body and headers for secrets/leaked credentials (read-only). Matched values are redacted in output | `false` | `--detect-secrets` |
| `--secret-patterns` | Path to a JSON file mapping pattern names to regex strings used for secret detection. Defaults to the built-in patterns when omitted | built-in patterns | `--secret-patterns patterns.json` |

Secret detection is off by default. When enabled, a response with no matching content yields no finding; a match is tagged to the endpoint whose response contained it, with the matched value redacted.

#### Machine-Readable Output

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--output-format` | Write a machine-readable discovery output in the selected format (`csv` or `jsonl`) | - | `--output-format jsonl` |
| `--output-file` | Destination path for the machine-readable output (the extension selects the format) | - | `--output-file results.jsonl` |

Records are ordered consistently with the triage table, grouped by status class in ascending order. An unsupported format is rejected with a descriptive error and writes no file; a write failure on an unwritable path also errors. This is distinct from `--export`/`--export-file`, which produce a human-readable `md`/`txt` report.

#### Path and Status Scope (Storage-Time Selection)

These options decide which discovered records are ever **persisted**, applied at discovery time as a record is recorded. They are distinct from the display-only `--status-code` filter and the `--match-*`/`--filter-*` selectors, which act on records that have already been stored.

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--include-path` | Only persist discovered endpoints whose path **or** URL matches the regular expression. **Repeatable** | - | `--include-path "^/api/"` |
| `--exclude-path` | Never persist discovered endpoints whose path **or** URL matches the regular expression. **Repeatable**; takes precedence over `--include-path` | - | `--exclude-path "\.png$"` |
| `--include-status` | Only persist discovered endpoints whose status matches the selection — a status class (`2xx`) or explicit codes/ranges (`200,404` or `200-300`) | - | `--include-status 2xx` |
| `--exclude-status` | Never persist discovered endpoints whose status matches the selection; takes precedence over `--include-status` | - | `--exclude-status 404` |

**Exclude precedence (path).** A candidate path or URL matching *any* `--exclude-path` pattern is neither tested nor stored, regardless of which `--include-path` patterns it also matches. When one or more `--include-path` patterns are supplied, a candidate must match at least one of them to be kept; with no include patterns, everything not excluded is kept.

**Exclude precedence (status).** A record whose status matches `--exclude-status` is dropped even if it also matches `--include-status`. With no `--include-status`, every status not excluded is kept.

**Storage vs. display.** These are storage-time decisions: a record dropped here never enters the discovery session file (`--save-session`), the machine-readable output (`--output-format`), or the triage table — regardless of any later display-only `--status-code` value. By contrast, `--status-code`, `--match-*`, and `--filter-*` only change which already-stored records are shown.

**Validation.** An `--include-path`/`--exclude-path` value that is not a valid regular expression, or an `--include-status`/`--exclude-status` value that is an explicit code outside `100-599` or a token that is neither a status class nor an explicit code, is rejected with a descriptive error naming the offending value, and no discovery is performed.

#### Recursion Scope

These options narrow which discovered endpoints recursion descends into. They are accepted by both `dir` and `scan`. They only ever *narrow* the default VALID/AUTH_REQUIRED recursion eligibility — they never relax it.

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--recursion-status` | Restrict recursion to endpoints whose status class is in the comma-separated list of status classes (`2xx,3xx`) | - | `--recursion-status 2xx,3xx` |
| `--recursion-type` | Restrict recursion to endpoints whose type is in the comma-separated list of endpoint types (`admin`, `api_version`, `authentication`, `development`, `standard`) | - | `--recursion-type admin,api_version` |

Notes:

- When a recursion-scope option is supplied, only discovered records that satisfy *every* supplied selection are recursed into; the set recursed into is always a subset of the records that already satisfy the default recursion eligibility (VALID or AUTH_REQUIRED and not a catch-all response).
- Recursion still respects `--depth`, `--max-requests` (every recursive request counts toward the budget), `--concurrency`, and catch-all suppression.
- With no recursion-scope option, the existing recursion behavior is preserved unchanged.
- A `--recursion-status` status class or `--recursion-type` endpoint type that is not recognized is rejected with a descriptive error naming the value, and no discovery is performed.

#### Hit Confirmation

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--confirm-hits` | Enable Hit_Confirmation: re-request each interesting candidate `N` times and record it only when the responses are consistent (must be `>= 1`) | off | `--confirm-hits 3` |

Hit confirmation is **off by default**. When enabled, each candidate interesting result is re-requested `N` times and is recorded only when the confirmation responses are consistent — meaning they share the same status class and a comparable response body size. Inconsistent (flaky or randomized) responses are not recorded, which reduces false positives. Each confirmation request counts toward `--max-requests`, stays within `--concurrency`, and honors the configured `--rate-limit`. A `--confirm-hits` value that is not an integer `>= 1` is rejected with a descriptive error, and no discovery is performed.

#### Checkpoint and Resume

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--checkpoint` | Periodically write a discovery checkpoint to `PATH` so an interrupted run can be resumed (atomic writes) | - | `--checkpoint scan.ckpt` |
| `--resume` | Resume an interrupted discovery run from the checkpoint at `PATH` (loaded before discovery) | - | `--resume scan.ckpt` |

Checkpoint/resume contract:

- **Checkpointing.** With `--checkpoint`, discovery periodically writes a checkpoint recording the candidates already tested and the results discovered so far. Writes are atomic (a temporary file is written then moved into place), so a failure never leaves a partially written checkpoint. A checkpoint path that cannot be written is rejected with a descriptive error.
- **Resuming.** With `--resume`, the checkpoint is loaded *before* any discovery runs. Candidates recorded as already tested are treated as tested and are not re-requested (no-recompute), and the checkpointed results are merged with newly discovered ones so the union contains no two records sharing the same `(url, method)` pair (no-duplication).
- **Combine them.** Pass both `--resume` and `--checkpoint` to resume a run and keep checkpointing it.
- **Validation.** A `--resume` checkpoint that does not exist, cannot be read, or cannot be parsed into the expected checkpoint structure is rejected with a descriptive error naming the artifact, and no discovery is performed.
- **Separate from sessions.** The discovery checkpoint is a distinct artifact from the `--save-session`/`--load-session` session file; it additionally records the in-flight tested candidates and is intended for resuming, not for triage reload.

### Discovery Triage Options

The triage workflow is an additive layer on top of discovery. It is engaged automatically when you pass any of the flags below; otherwise `dir` behaves exactly as before. Discovered endpoints are projected into `DiscoveryResult` records (URL, method, status code, EndpointStatus) that can be grouped/filtered by status class, rendered as a `rich` table, saved to a structured session file, exported in a human-readable form, and used to drive an opt-in follow-up scan.

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--save-session` | Save all discovery results to a JSON session file (the source of truth for reload) | - | `--save-session session.json` |
| `--load-session` | Reload discovery results exclusively from a JSON session file (skips discovery) | - | `--load-session session.json` |
| `--export` | Write a human-readable export in the selected format (`md` or `txt`) | - | `--export md` |
| `--export-file` | Destination path for the human-readable export (the extension selects the format) | `reports/discovery_export.<fmt>` | `--export-file results.md` |
| `--interactive`, `--triage` | Enable interactive triage mode (opt-in; auto-disabled in CI mode) | `false` | `--interactive` |
| `--scan-scope` | Non-interactively select a batch of discovered records (`2xx`/`3xx`/`4xx`/`5xx`/`valid`/`auth_required`) and run an OWASP scan over them | - | `--scan-scope valid` |
| `--ci-mode` | Enable CI mode; disables the interactive prompt so it never blocks a pipeline | `false` | `--ci-mode` |

Key behaviors:

- **Session file is the source of truth.** `--load-session` reads records only from the JSON session file; the human-readable export is never read back.
- **Atomic session writes.** A failed `--save-session` never leaves a partially written file, and surfaces a descriptive error.
- **Triage table.** Results render in a four-column table — URL, Method, Status, EndpointStatus — grouped by status class in ascending order (`2xx`, `3xx`, `4xx`, `5xx`). An empty/filtered-to-empty result set shows the header row with zero data rows.
- **Export grouping.** The `.md`/`.txt` export groups records by status class in the same ascending order. Any format other than `.md`/`.txt` is rejected with a descriptive error and writes nothing.
- **Interactive mode is opt-in and CI-safe.** It is off by default, prompts for exactly one endpoint when enabled, re-prompts on invalid input up to 3 consecutive attempts (then abandons without a scan), and is automatically disabled under `--ci-mode` so it never blocks.

### Discovery-to-Scan Integration (Batch Scan Scope)

Discovery can feed an OWASP scan directly over a set of discovered endpoints, so you don't have to launch a single-endpoint follow-up for each result. The batch scope can be selected interactively or non-interactively.

- **Interactive multi-select.** In interactive triage (`--interactive`), entering two or more record indices — a comma list like `1,3,5` or a range like `2-4` — selects a batch scan scope and runs an OWASP scan over exactly those records. A single index keeps the existing single-endpoint follow-up.
- **Non-interactive `--scan-scope`.** `--scan-scope <2xx|3xx|4xx|5xx|valid|auth_required>` selects all discovered records of the chosen status class or EndpointStatus (`valid` selects all VALID records, `auth_required` selects all AUTH_REQUIRED records) and runs an OWASP scan over them through the `scan` command engine path.
- **CI-only non-interactive.** Under `--ci-mode` the batch scope is determined *only* from `--scan-scope`; the interactive selection prompt never runs and never blocks the pipeline.
- **Inherited request settings.** The batch scan applies the same `--rate-limit`, User-Agent option, and `--header`/`--cookie`/`--basic-auth` request context supplied to the originating `dir` invocation.
- **Empty scope.** If the determined scope is empty (no records match the token, or an empty multi-select), no scan runs and the command reports that there is nothing to scan.
- **Invalid token.** A `--scan-scope` value that is neither a recognized status class nor a recognized EndpointStatus is rejected with a descriptive error naming the value, and no scan runs.

### Status Code Filtering

The `--status-code` flag accepts three forms in triage mode (parsed by `parse_status_filter`):

| Form | Example | Meaning |
|------|---------|---------|
| Status class token | `2xx`, `3xx`, `4xx`, `5xx` (case-insensitive) | Keep records whose status code shares that leading digit |
| Explicit codes | `200,404,500` | Keep records whose status code is exactly in the set |
| Ranges | `200-299`, `400-403` | Keep records whose status code falls in the range |

Notes:

- A class token is single-valued — use `2xx` on its own, not `2xx,404`.
- Explicit codes are validated to the inclusive range `100-599`; an out-of-range value (e.g. `700`) is rejected with an error naming the offending value and exits non-zero.
- Records whose leading digit is not 2-5 (for example a `1xx`) are excluded from all status-class groups.

### Examples

**Basic discovery**

```bash
# Basic directory fuzzing
python apileaks.py dir --target https://api.example.com

# Custom wordlist and a gentler rate limit
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist custom_endpoints.txt \
  --rate-limit 5

# Restrict the HTTP methods that are tested
python apileaks.py dir \
  --target https://api.example.com \
  --methods GET,POST

# Authenticated discovery with a JWT
python apileaks.py dir \
  --target https://api.example.com \
  --jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

**Framework detection and version fuzzing**

```bash
# Detect the backend framework while fuzzing
python apileaks.py dir \
  --target https://api.example.com \
  --detect-framework

# Enumerate API versions (/v1, /v2, /api/v1, ...)
python apileaks.py dir \
  --target https://api.example.com \
  --fuzz-versions

# Both, with random User-Agent rotation for WAF evasion
python apileaks.py dir \
  --target https://api.example.com \
  --user-agent-random \
  --detect-framework \
  --fuzz-versions
```

**Status-code filtering**

```bash
# Only successful responses (status class)
python apileaks.py dir \
  --target https://api.example.com \
  --status-code 2xx \
  --save-session session.json

# Only redirects
python apileaks.py dir \
  --target https://api.example.com \
  --status-code 3xx \
  --save-session session.json

# Explicit codes
python apileaks.py dir \
  --target https://api.example.com \
  --status-code 200,401,403 \
  --save-session session.json

# A range of codes
python apileaks.py dir \
  --target https://api.example.com \
  --status-code 400-403 \
  --save-session session.json
```

**Session persistence and reload**

```bash
# Save the full result set to a session file (source of truth)
python apileaks.py dir \
  --target https://api.example.com \
  --save-session session.json

# Reload a prior session (skips discovery entirely) and re-render the table
python apileaks.py dir \
  --target https://api.example.com \
  --load-session session.json

# Reload and filter to server errors only
python apileaks.py dir \
  --target https://api.example.com \
  --load-session session.json \
  --status-code 5xx
```

**Human-readable export**

```bash
# Markdown export (grouped by status class, ascending)
python apileaks.py dir \
  --target https://api.example.com \
  --export md \
  --export-file results.md

# Plain-text export
python apileaks.py dir \
  --target https://api.example.com \
  --export txt \
  --export-file results.txt

# Save the session AND export a human-readable report in one run
python apileaks.py dir \
  --target https://api.example.com \
  --save-session session.json \
  --export md \
  --export-file results.md
```

**Interactive triage and targeted follow-up**

```bash
# Enable the interactive selection prompt (opt-in)
python apileaks.py dir \
  --target https://api.example.com \
  --interactive

# --triage is an alias for --interactive
python apileaks.py dir \
  --target https://api.example.com \
  --triage

# Reload a session, filter, and triage interactively
python apileaks.py dir \
  --target https://api.example.com \
  --load-session session.json \
  --status-code 2xx \
  --interactive
```

**CI/CD-safe runs**

```bash
# CI mode disables the interactive prompt so it never blocks a pipeline,
# even if --interactive is also passed
python apileaks.py dir \
  --target https://api.example.com \
  --interactive \
  --ci-mode \
  --save-session session.json \
  --export md \
  --export-file results.md
```

**Full triage workflow**

```bash
# Discover, filter to successful endpoints, save a session, export Markdown,
# and open the interactive prompt — all in one invocation
python apileaks.py dir \
  --target https://api.example.com \
  --wordlist wordlists/endpoints.txt \
  --rate-limit 10 \
  --detect-framework \
  --status-code 2xx \
  --save-session session.json \
  --export md \
  --export-file discovery.md \
  --interactive
```

### Rate Limiting and User-Agent in Discovery and Triage

`--rate-limit` and the three User-Agent options apply to every discovery request the `dir` command issues, and they compose freely with the discovery-control and triage flags (`--depth`, `--max-requests`, `--save-session`, `--status-code`, `--interactive`). The same settings are also inherited by the targeted follow-up scan launched from interactive triage (see notes below).

**Rate limit + each User-Agent option, combined with discovery/triage flags**

```bash
# Random User-Agent rotation + gentle rate limit, bounded recursive discovery,
# saving a session for later triage
python apileaks.py dir \
  --target https://api.example.com \
  --rate-limit 5 \
  --user-agent-random \
  --depth 4 \
  --max-requests 5000 \
  --status-code 2xx \
  --save-session session.json

# Custom (single) User-Agent + rate limit, with interactive triage so the
# follow-up scan inherits both settings
python apileaks.py dir \
  --target https://api.example.com \
  --rate-limit 8 \
  --user-agent-custom "MyScanner/1.0" \
  --status-code 2xx \
  --save-session session.json \
  --interactive

# Rotating User-Agents from a file + rate limit, deep discovery with a budget,
# saving a session and opening interactive triage
python apileaks.py dir \
  --target https://api.example.com \
  --rate-limit 10 \
  --user-agent-file user_agents.txt \
  --depth 5 \
  --max-requests 8000 \
  --save-session session.json \
  --interactive
```

**Notes.**

- **Mutually exclusive User-Agent options.** Exactly one of `--user-agent-random`, `--user-agent-custom "<UA>"`, or `--user-agent-file <list.txt>` may be supplied per invocation. Passing more than one is rejected with an error that names the conflict, and no discovery is performed.
- **`--user-agent-custom`** uses the single supplied string as the User-Agent for every discovery request.
- **`--user-agent-random`** picks a User-Agent at random from the built-in set for each discovery request.
- **`--user-agent-file`** loads User-Agents from the file, one per line; empty lines and lines whose first non-whitespace character is `#` (comments) are skipped. The loaded strings are then rotated in round-robin order across discovery requests. A missing or unreadable file path is rejected with an error naming the path, and no discovery is performed.
- **`--rate-limit` applies only to requests actually issued.** When `--load-session` reloads a prior session, no discovery requests are made, so the rate limit is not applied to that run.
- **Targeted follow-up inherits these settings.** The `Targeted_Follow_Up_Scan` launched from interactive triage reuses the same `--rate-limit` and User-Agent option (random / custom / file) from the originating `dir` invocation, applying them to every request it issues. A `--user-agent-file` list is reloaded and rotated for the follow-up the same way.

## Parameter Fuzzing (`par`)

Identify hidden parameters and input validation issues.

### Syntax

```bash
python apileaks.py par [OPTIONS]
```

### Required Options

| Option | Description | Example |
|--------|-------------|---------|
| `--target`, `-t` | Target URL to scan | `--target https://api.example.com/users` |

### Optional Parameters

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--wordlist`, `-w` | Wordlist file for parameter fuzzing | `wordlists/parameters.txt` | `--wordlist custom_params.txt` |
| `--output`, `-o` | Output filename for reports | Auto-generated | `--output param-scan` |
| `--log-level` | Logging level | `WARNING` | `--log-level INFO` |
| `--log-file` | Log file path | Console only | `--log-file param.log` |
| `--json-logs` | Output logs in JSON format | `false` | `--json-logs` |
| `--rate-limit` | Requests per second limit | `10` | `--rate-limit 3` |
| `--methods` | HTTP methods to test | `GET,POST` | `--methods GET,POST,PUT` |
| `--jwt` | JWT token for authentication | - | `--jwt eyJ0eXAi...` |
| `--response` | Filter by response codes | All codes | `--response 200,400,422` |
| `--status-code` | Show only specific status codes | All codes | `--status-code 200,500-599` |

### User Agent Options (Mutually Exclusive)

Same as directory fuzzing - see above.

### Advanced Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--detect-framework`, `--df` | Enable framework detection | `false` | `--detect-framework` |

### Examples

```bash
# Basic parameter fuzzing
python apileaks.py par --target https://api.example.com/users/123

# With authentication and custom wordlist
python apileaks.py par \
  --target https://api.example.com/api/v1/users \
  --jwt "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." \
  --wordlist custom_parameters.txt

# Test multiple HTTP methods
python apileaks.py par \
  --target https://api.example.com/api/v1/orders \
  --methods GET,POST,PUT

# WAF evasion with random user agents and a gentle rate limit
python apileaks.py par \
  --target https://api.example.com/search \
  --user-agent-random \
  --rate-limit 3

# Framework detection while fuzzing parameters
python apileaks.py par \
  --target https://api.example.com/api/v1/products \
  --detect-framework

# Focus on error responses
python apileaks.py par \
  --target https://api.example.com/search \
  --status-code 400,422,500-599 \
  --output error-parameters
```

## Security Scan (`scan`)

The `scan` command is APILeak's **primary orchestrator**. It runs endpoint discovery and then executes **all registered OWASP API Security Top 10 modules by default**, aggregating every finding through the unified reporting pipeline and driving the CI/CD severity gate. Use `--modules a,b` to restrict the run to selected module keys.

To run a **single** OWASP module in isolation (red-team focus), use the [`owasp <key>`](#owasp-module-commands-owasp) command instead.

> **Deprecation.** `full` and `main` are deprecated, hidden aliases of `scan`. They forward to `scan` unchanged (emitting a one-line stderr deprecation notice) and are retained only for backward compatibility — migrate scripts to `scan`. A single-module alias invocation such as `full --modules bola` should become `apileaks owasp bola`.

### Syntax

```bash
python apileaks.py scan [OPTIONS]
```

### Required Options

| Option | Description | Example |
|--------|-------------|---------|
| `--target`, `-t` | Target URL to scan (required if no config) | `--target https://api.example.com` |

### Configuration Options

| Option | Description | Example |
|--------|-------------|---------|
| `--config`, `-c` | Configuration file path (YAML/JSON) | `--config config/api.yaml` |

### Basic Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--output`, `-o` | Output filename for reports | Auto-generated | `--output comprehensive-scan` |
| `--log-level` | Logging level | `WARNING` | `--log-level INFO` |
| `--log-file` | Log file path | Console only | `--log-file full-scan.log` |
| `--json-logs` | Output logs in JSON format | `false` | `--json-logs` |
| `--rate-limit` | Requests per second limit | `10` | `--rate-limit 15` |
| `--jwt` | JWT token for authentication | - | `--jwt eyJ0eXAi...` |
| `--status-code` | Show only specific status codes | All codes | `--status-code 200,401,403` |

### OWASP Module Selection

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--modules` | Comma-separated OWASP modules | All modules | `--modules bola,auth,property` |

Available modules:
- `bola` - BOLA (Broken Object Level Authorization) testing — API1
- `auth` - Authentication testing (JWT vulnerabilities) — API2
- `property` - Property Level Authorization testing — API3
- `resource` - Unrestricted Resource Consumption testing — API4
- `function_auth` - Function Level Authorization testing — API5
- `business_flow` - Unrestricted Access to Sensitive Business Flows — API6
- `ssrf` - Server-Side Request Forgery testing — API7
- `security_misconfig` - Security Misconfiguration (CORS, missing headers) — API8
- `inventory` - Improper Inventory Management (deprecated/undocumented versions) — API9
- `unsafe_consumption` - Unsafe Consumption of APIs — API10

### User Agent Options (Mutually Exclusive)

Same as directory fuzzing - see above.

### Advanced Discovery Features

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--detect-framework`, `--df` | Enable framework detection | `false` | `--detect-framework` |
| `--fuzz-versions`, `--fv` | Enable API version fuzzing | `false` | `--fuzz-versions` |
| `--framework-confidence` | Framework detection confidence | `0.6` | `--framework-confidence 0.8` |
| `--version-patterns` | Custom version patterns | Default patterns | `--version-patterns /v1,/v2,/api/v1` |
| `--enable-advanced` | Enable all advanced features | `false` | `--enable-advanced` |
| `--enable-payload-encoding` | Enable payload encoding/obfuscation | `false` | `--enable-payload-encoding` |
| `--enable-waf-evasion` | Enable WAF detection and evasion | `false` | `--enable-waf-evasion` |
| `--enable-subdomain-discovery` | Enable subdomain discovery | `false` | `--enable-subdomain-discovery` |
| `--enable-cors-analysis` | Enable CORS analysis | `false` | `--enable-cors-analysis` |

### Discovery Control Options

These flags tune recursive discovery so you can trade breadth for speed. They keep recursion agile: stay shallow and fast for a quick sweep, or go deep and thorough when you need full coverage — always bounded by the request budget and catch-all detection.

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--depth` | Max recursion depth for discovery (`0` = no recursion, depth-0 pass only) | `3` (see precedence below) | `--depth 5` |
| `--recursive` / `--no-recursive` | Enable or disable recursive discovery | enabled | `--no-recursive` |
| `--max-requests` | Global request budget for discovery | unbounded | `--max-requests 5000` |
| `--concurrency` | Max concurrent in-flight discovery requests | `50` | `--concurrency 100` |

**Depth precedence.** The effective recursion depth is resolved as: explicit CLI `--depth` > the `APILEAK_MAX_DEPTH` environment variable > the built-in default of `3`. So `--depth` always wins when supplied; otherwise `APILEAK_MAX_DEPTH` is honored if set; otherwise depth `3` is used.

**Notes.**
- `--depth 0` performs only the depth-0 pass and disables recursion (equivalent to `--no-recursive`).
- `--max-requests` defaults to unbounded; when set, it caps the total number of discovery requests across all depths.
- `--concurrency` defaults to `50` concurrent in-flight requests when not specified.
- `--depth` must be `>= 0`; `--max-requests` and `--concurrency` must be `>= 1`.

#### Recursion Scope

The `scan` command accepts the same recursion-scope options as `dir` to narrow which discovered endpoints recursion descends into. They only narrow the default VALID/AUTH_REQUIRED recursion; they never relax it.

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--recursion-status` | Restrict recursion to endpoints whose status class is in the comma-separated list of status classes (`2xx,3xx`) | - | `--recursion-status 2xx,3xx` |
| `--recursion-type` | Restrict recursion to endpoints whose type is in the comma-separated list of endpoint types (`admin`, `api_version`, `authentication`, `development`, `standard`) | - | `--recursion-type admin,api_version` |

An unrecognized `--recursion-status` status class or `--recursion-type` endpoint type is rejected with a descriptive error naming the value, and no discovery is performed. See the `dir` command's [Recursion Scope](#recursion-scope) notes for the full behavior.

### Discovery Robustness Options

The `scan` command shares the discovery seed and per-request resilience controls described in detail under the `dir` command's [Discovery Robustness Options](#discovery-robustness-options). The following are accepted by `scan`:

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--extensions`, `-x` | File extensions appended to each wordlist entry (comma-separated, repeatable; leading dots optional) | - | `-x json,php` |
| `--timeout` | Per-request timeout in seconds applied to every discovery request (must be `> 0`) | `10` | `--timeout 30` |
| `--retries` | Number of automatic retries for each failed discovery request (must be `>= 0`) | `2` | `--retries 5` |

Invalid `--timeout` or `--retries` values are rejected with a descriptive error before any discovery runs. The richer request-context, response-matcher/filter, GraphQL, transport/TLS, secret-detection, and machine-readable-output options are specific to the `dir` command.

### CI/CD Integration

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--ci-mode` | Enable CI/CD mode with deterministic exit codes and artifact generation | `false` | `--ci-mode` |
| `--fail-on` | Fail on findings of this severity or higher | `high` | `--fail-on high` |
| `--sarif` | Generate a SARIF 2.1.0 report (for code scanning / CI integration) | `false` | `--sarif` |
| `--safe-mode` | Non-destructive scan: skip state-changing probes (POST/PUT/PATCH/DELETE) and restrict to safe methods | `false` | `--safe-mode` |
| `--baseline` | Path to a baseline JSON report; only new findings drive the severity gate (missing path treats all findings as new) | - | `--baseline baseline.json` |

Available severity levels: `critical`, `high`, `medium`, `low`

> **Default gate.** The severity gate default is now `high` (it was previously `critical`). Runs without an explicit `--fail-on` fail on high or critical findings. Pass `--fail-on critical` to keep the old behavior.

### Examples

```bash
# Basic scan (runs discovery + all OWASP modules by default)
python apileaks.py scan --target https://api.example.com

# With specific OWASP modules and a JWT
python apileaks.py scan \
  --target https://api.example.com \
  --modules bola,auth,property \
  --jwt "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

# All ten OWASP API Security Top 10 modules run by default — a plain scan is enough
python apileaks.py scan --target https://api.example.com

# Advanced scan with all discovery features
python apileaks.py scan \
  --target https://api.example.com \
  --enable-advanced \
  --user-agent-random \
  --output advanced-security-scan

# Non-destructive scan against a shared/production-like environment
python apileaks.py scan \
  --target https://api.example.com \
  --safe-mode \
  --modules bola,auth,security_misconfig

# Generate a SARIF report for code-scanning dashboards
python apileaks.py scan \
  --target https://api.example.com \
  --sarif \
  --output scan-results

# CI/CD gate: fail on high+ findings and emit SARIF
python apileaks.py scan \
  --target https://api.example.com \
  --ci-mode \
  --fail-on high \
  --sarif

# CI/CD with a baseline: only newly introduced findings fail the pipeline
python apileaks.py scan \
  --target https://api.example.com \
  --ci-mode \
  --fail-on medium \
  --baseline reports/previous-scan.json

# CI/CD, non-destructive, baseline-gated, with SARIF artifact
python apileaks.py scan \
  --target https://api.example.com \
  --ci-mode \
  --fail-on high \
  --safe-mode \
  --sarif \
  --baseline reports/baseline.json

# Using a configuration file
python apileaks.py scan \
  --config config/production_api.yaml \
  --target https://api.example.com
```

## OWASP Module Commands (`owasp`)

The `owasp` command group exposes each OWASP API Security Top 10 detection module as a first-class subcommand so you can run **exactly one module in isolation** (a red-team focus), rather than the full orchestrated `scan`.

- `apileaks owasp` (no subcommand) prints one line per registered module — its key, OWASP category, and a one-line summary.
- `apileaks owasp <key> --target URL` runs **only** that module against the target.

Each module subcommand accepts the shared transversal options; `bola` and `auth` additionally accept their own module-specific options (the other eight modules accept transversal options only).

### Available modules

| Key | OWASP | Summary |
|-----|-------|---------|
| `bola` | API1 | Broken Object Level Authorization (BOLA) detection |
| `auth` | API2 | Broken Authentication detection |
| `property` | API3 | Broken Object Property Level Authorization detection |
| `resource` | API4 | Unrestricted Resource Consumption detection |
| `function_auth` | API5 | Broken Function Level Authorization detection |
| `business_flow` | API6 | Unrestricted Access to Sensitive Business Flows detection |
| `ssrf` | API7 | Server-Side Request Forgery (SSRF) detection |
| `security_misconfig` | API8 | Security Misconfiguration detection |
| `inventory` | API9 | Improper Inventory Management detection |
| `unsafe_consumption` | API10 | Unsafe Consumption of APIs detection |

### Syntax

```bash
# List every module (key, OWASP category, summary)
python apileaks.py owasp

# Run exactly one module in isolation
python apileaks.py owasp <key> --target URL [OPTIONS]
```

### Examples

```bash
# List all available modules
python apileaks.py owasp

# Run only the BOLA module against a target
python apileaks.py owasp bola --target https://api.example.com

# Run only Broken Authentication detection with a JWT
python apileaks.py owasp auth \
  --target https://api.example.com \
  --jwt "eyJ0eXAiOiJKV1Q..."

# Run only the SSRF module
python apileaks.py owasp ssrf --target https://api.example.com
```

> **When to use which.** Prefer `scan` for full-coverage assessments and CI gating (it runs discovery + all modules and drives `--ci-mode`/`--fail-on`/`--sarif`/`--baseline`/`--safe-mode`). Reach for `owasp <key>` when you want to focus on a single vulnerability class. Use `scan --modules a,b` when you want a subset of two or more modules aggregated in one report. A deprecated `full --modules bola` invocation maps directly to `apileaks owasp bola`.

## JWT Utilities

APILeak includes comprehensive JWT security testing utilities organized as a command group.

### JWT Command Group

All JWT utilities are accessed through the `jwt` command group:

```bash
python apileaks.py jwt [SUBCOMMAND] [OPTIONS]
```

> This is a brief reference. For the full JWT attack methodology and deep-dive walkthroughs, see [JWT Attacks](jwt-attacks.md).

#### Available Subcommands

| Subcommand | Purpose | Description |
|------------|---------|-------------|
| `decode` | Token Analysis | Decode and analyze JWT tokens |
| `encode` | Token Generation | Create JWT tokens for testing |
| `verify` | Signature Verification | Verify a token's signature (HMAC secret or public key) |
| `genkey` | Key Generation | Generate an RSA or EC keypair for testing |
| `jwks-to-key` | JWKS Conversion | Convert a JWKS entry to a PEM public key |
| `test-alg-none` | Algorithm Confusion | Test alg:none vulnerability |
| `test-null-signature` | Null Signature | Test null signature bypass |
| `brute-secret` | Secret Brute-force | Crack weak HMAC secrets |
| `test-kid-injection` | Key ID Injection | Test kid parameter injection |
| `test-jwks-spoof` | JWKS Spoofing | Test JWKS URL spoofing |
| `test-inline-jwks` | Inline JWKS | Test inline JWKS injection |
| `attack-test` | Comprehensive Suite | Run all attack vectors against a live endpoint |

#### Live-Endpoint Testing Options

Every `test-*` subcommand (and `attack-test`) accepts the following options to validate an attack against a real endpoint:

| Option | Description | Example |
|--------|-------------|---------|
| `-u`, `--url` | Target URL to test the attack against | `--url https://api.example.com/protected` |
| `-H`, `--header` | Custom header (repeatable) | `-H "X-API-Key: key123"` |
| `-d`, `--data` | POST data for endpoint testing | `-d '{"action":"read"}'` |
| `--timeout` | Request timeout in seconds | `--timeout 30` |

### JWT Decode (`jwt decode`)

Decode and analyze JWT tokens with security insights.

#### Syntax

```bash
python apileaks.py jwt decode TOKEN
```

#### Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `TOKEN` | JWT token to decode | `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...` |

#### Example

```bash
python apileaks.py jwt decode eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### JWT Encode (`jwt encode`)

Create JWT tokens for testing purposes.

#### Syntax

```bash
python apileaks.py jwt encode PAYLOAD [OPTIONS]
```

#### Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `PAYLOAD` | JWT payload as JSON string | `'{"sub":"user123","role":"admin"}'` |

#### Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--header` | JWT header as JSON string | `{"alg":"HS256","typ":"JWT"}` | `--header '{"alg":"HS512","typ":"JWT"}'` |
| `--secret` | Secret key for signing | `secret` | `--secret mysecretkey` |

#### Examples

```bash
# Basic JWT encoding
python apileaks.py jwt encode '{"sub":"user123","role":"user"}'

# With custom secret
python apileaks.py jwt encode \
  '{"sub":"admin","role":"admin","exp":1735689600}' \
  --secret mysecretkey

# With custom header
python apileaks.py jwt encode \
  '{"sub":"user123"}' \
  --header '{"alg":"HS512","typ":"JWT"}' \
  --secret strongsecret
```

### JWT Security Testing

APILeak provides advanced JWT security testing capabilities to identify common vulnerabilities.

#### Algorithm Confusion Attack (`jwt test-alg-none`)

Test if the server accepts unsigned tokens with `alg:none`.

```bash
python apileaks.py jwt test-alg-none TOKEN [--payload CUSTOM_PAYLOAD]
```

**Examples:**
```bash
# Basic alg:none test
python apileaks.py jwt test-alg-none eyJ0eXAiOiJKV1Q...

# Inject a custom admin payload
python apileaks.py jwt test-alg-none TOKEN --payload '{"sub":"admin","role":"admin"}'

# Validate the attack against a live endpoint
python apileaks.py jwt test-alg-none TOKEN --url https://api.example.com/admin
```

#### Null Signature Testing (`jwt test-null-signature`)

Test null/empty signature bypass techniques.

```bash
python apileaks.py jwt test-null-signature TOKEN [--payload CUSTOM_PAYLOAD]
```

**Examples:**
```bash
# Basic null signature test
python apileaks.py jwt test-null-signature TOKEN

# Inject a custom admin payload
python apileaks.py jwt test-null-signature TOKEN --payload '{"sub":"admin","admin":true}'

# Validate against a protected endpoint
python apileaks.py jwt test-null-signature TOKEN --url https://api.example.com/protected
```

#### HMAC Secret Brute-force (`jwt brute-secret`)

Attempt to crack weak HMAC secrets using wordlists, then forge a token.

```bash
python apileaks.py jwt brute-secret TOKEN [OPTIONS]
```

**Options:**
- `--wordlist`, `-w`: Wordlist file (default: `wordlists/jwt_secrets.txt`)
- `--max-attempts`: Maximum attempts (default: `1000`)
- `-u/--url`, `-H/--header`, `-d/--data`, `--timeout`: live-endpoint testing (see above)

**Examples:**
```bash
# Basic secret brute-force
python apileaks.py jwt brute-secret TOKEN

# Use a custom secrets wordlist
python apileaks.py jwt brute-secret TOKEN --wordlist custom_secrets.txt

# Crack the secret and test the forged token against a real endpoint
python apileaks.py jwt brute-secret TOKEN \
  --url https://api.example.com/admin \
  -H "X-API-Key: key123"
```

#### Key ID Injection (`jwt test-kid-injection`)

Test `kid` parameter injection (path traversal, arbitrary keys, remote key fetch).

```bash
python apileaks.py jwt test-kid-injection TOKEN [--kid-payload PAYLOAD] [--payload JSON]
```

**Examples:**
```bash
# Basic kid injection test
python apileaks.py jwt test-kid-injection TOKEN

# Path-traversal kid payload
python apileaks.py jwt test-kid-injection TOKEN --kid-payload "../../etc/passwd"

# Remote key fetch + custom payload against a live endpoint
python apileaks.py jwt test-kid-injection TOKEN \
  --kid-payload "http://attacker.com/key.pem" \
  --payload '{"admin":true}' \
  --url https://api.example.com/protected
```

#### JWKS Spoofing (`jwt test-jwks-spoof`)

Test JWKS URL (`jku`) spoofing vulnerabilities.

```bash
python apileaks.py jwt test-jwks-spoof TOKEN [--jwks-url URL]
```

**Examples:**
```bash
# Basic JWKS spoofing test
python apileaks.py jwt test-jwks-spoof TOKEN

# Custom malicious JWKS URL
python apileaks.py jwt test-jwks-spoof TOKEN --jwks-url http://attacker.com/jwks.json

# Validate against a live endpoint
python apileaks.py jwt test-jwks-spoof TOKEN \
  --jwks-url http://attacker.com/jwks.json \
  --url https://api.example.com/protected
```

#### Inline JWKS Injection (`jwt test-inline-jwks`)

Test inline JWKS injection (embed an attacker-controlled public key in the header).

```bash
python apileaks.py jwt test-inline-jwks TOKEN
```

**Examples:**
```bash
# Basic inline JWKS test
python apileaks.py jwt test-inline-jwks TOKEN

# Validate against a live endpoint with custom headers
python apileaks.py jwt test-inline-jwks TOKEN \
  --url https://api.example.com/admin \
  -H "X-API-Key: key123"
```

#### Comprehensive Attack Testing (`jwt attack-test`)

Run all attack vectors (algorithm confusion, secret attacks, injection, payload manipulation) against a live endpoint with baseline comparison and confidence scoring.

```bash
python apileaks.py jwt attack-test TOKEN --url URL [OPTIONS]
```

**Examples:**
```bash
# Full automated attack suite against a protected endpoint
python apileaks.py jwt attack-test TOKEN --url https://api.example.com/protected

# With custom headers
python apileaks.py jwt attack-test TOKEN \
  -u https://api.example.com/protected \
  -H "X-API-Key: key123"

# With POST data for the endpoint under test
python apileaks.py jwt attack-test TOKEN \
  -u https://api.example.com/protected \
  -d '{"action":"read"}'
```

### JWT Security Testing Workflow

For comprehensive JWT security testing, use this workflow:

```bash
# 1. Decode and analyze the token
python apileaks.py jwt decode $TOKEN

# 2. Test algorithm confusion
python apileaks.py jwt test-alg-none $TOKEN

# 3. Test null signature bypass
python apileaks.py jwt test-null-signature $TOKEN

# 4. Attempt secret brute-force
python apileaks.py jwt brute-secret $TOKEN

# 5. Test kid injection
python apileaks.py jwt test-kid-injection $TOKEN

# 6. Test JWKS spoofing
python apileaks.py jwt test-jwks-spoof $TOKEN

# 7. Test inline JWKS
python apileaks.py jwt test-inline-jwks $TOKEN

# 8. Or run the full automated suite against a live endpoint in one shot
python apileaks.py jwt attack-test $TOKEN --url https://api.example.com/protected
```

## Proxy Integration

APILeak can route all of its HTTP traffic (discovery, parameter/header fuzzing, OWASP testing, and the targeted follow-up scan) through an intercepting proxy so that every request and response can be captured, inspected, and replayed in tools like **Burp Suite**, **Caido**, or **Hetty**.

### Flags

| Option | Description |
|--------|-------------|
| `--proxy URL` | Send all traffic through the proxy at `URL` (e.g. `http://127.0.0.1:8080`). Available on `dir`, `par`, and `scan`. |
| `--proxy-verify-ssl` | Keep TLS certificate verification enabled while proxying. |

### TLS behavior

Intercepting proxies terminate TLS with their own certificate authority. To avoid certificate errors against HTTPS targets, **TLS verification is automatically disabled when `--proxy` is set**. After installing the proxy's CA certificate in your trust store, pass `--proxy-verify-ssl` to re-enable verification.

### Default proxy endpoints

| Tool | Default proxy listener |
|------|------------------------|
| Burp Suite | `http://127.0.0.1:8080` |
| Caido | `http://127.0.0.1:8080` |
| Hetty | `http://127.0.0.1:8080` |

### Examples

```bash
# Directory discovery through Burp Suite
python apileaks.py dir \
  --target https://api.example.com \
  --proxy http://127.0.0.1:8080

# Authenticated discovery through a proxy (JWT + proxy together)
python apileaks.py dir \
  --target https://api.example.com \
  --jwt "eyJ0eXAiOiJKV1Q..." \
  --proxy http://127.0.0.1:8080

# Parameter fuzzing through Caido
python apileaks.py par \
  --target https://api.example.com/users/123 \
  --proxy http://127.0.0.1:8080

# Full OWASP scan through Hetty
python apileaks.py scan \
  --target https://api.example.com \
  --modules bola,auth,ssrf \
  --proxy http://127.0.0.1:8080

# Proxy with TLS verification kept on (after installing the proxy CA)
python apileaks.py scan \
  --target https://api.example.com \
  --proxy http://127.0.0.1:8080 \
  --proxy-verify-ssl

# Triage discovery through a proxy, saving a session for later replay
python apileaks.py dir \
  --target https://api.example.com \
  --proxy http://127.0.0.1:8080 \
  --status-code 2xx \
  --save-session session.json
```

## Environment Variables

APILeak supports configuration through environment variables:

| Variable | Description | Default | CLI Equivalent |
|----------|-------------|---------|----------------|
| `APILEAK_TARGET` | Target URL | - | `--target` |
| `APILEAK_LOG_LEVEL` | Logging level | `INFO` | `--log-level` |
| `APILEAK_RATE_LIMIT` | Requests per second | `10` | `--rate-limit` |
| `APILEAK_MODULES` | OWASP modules | All modules | `--modules` |
| `APILEAK_JWT_TOKEN` | JWT token | - | `--jwt` |
| `APILEAK_USER_AGENT` | Custom User-Agent | Default | `--user-agent-custom` |
| `APILEAK_TIMEOUT` | Request timeout | `10` | - |
| `APILEAK_MAX_DEPTH` | Max recursion depth | `3` | - |
| `APILEAK_VERIFY_SSL` | Verify SSL certificates | `true` | - |
| `APILEAK_OUTPUT_DIR` | Output directory | `reports` | - |

### Example Usage

```bash
# Set environment variables
export APILEAK_TARGET="https://api.example.com"
export APILEAK_MODULES="bola,auth,property"
export APILEAK_JWT_TOKEN="eyJ0eXAiOiJKV1Q..."
export APILEAK_RATE_LIMIT="5"

# Run scan with environment variables
python apileaks.py scan
```

## Exit Codes

APILeak uses specific exit codes to indicate scan results:

| Exit Code | Meaning | Description |
|-----------|---------|-------------|
| `0` | Success | No critical or high severity findings |
| `1` | High Severity | High severity vulnerabilities found |
| `2` | Critical Severity | Critical vulnerabilities found |
| `3` | Scan Error | Scan failed due to technical issues (CI mode only) |

### CI/CD Integration

In CI/CD mode (`--ci-mode`), exit codes are determined by the `--fail-on` setting. The default is now `high` (previously `critical`), so a run without an explicit `--fail-on` fails on high or critical findings:

```bash
# Default gate (high): a plain --ci-mode run fails on high or critical findings
python apileaks.py scan --target URL --ci-mode

# Fail only on critical findings (previous default; still available explicitly)
python apileaks.py scan --target URL --ci-mode --fail-on critical

# Fail on high or critical findings (the new default, stated explicitly)
python apileaks.py scan --target URL --ci-mode --fail-on high

# Fail on medium, high, or critical findings
python apileaks.py scan --target URL --ci-mode --fail-on medium
```

## Examples

### Basic Usage Examples

```bash
# Quick endpoint discovery
python apileaks.py dir --target https://api.example.com

# Parameter fuzzing with authentication
python apileaks.py par \
  --target https://api.example.com/users/123 \
  --jwt "eyJ0eXAiOiJKV1Q..."

# Full security scan
python apileaks.py scan \
  --target https://api.example.com \
  --modules bola,auth,property
```

### Advanced Usage Examples

```bash
# WAF evasion with random user agents
python apileaks.py scan \
  --target https://api.example.com \
  --user-agent-random \
  --enable-waf-evasion \
  --rate-limit 3

# Framework detection and version fuzzing
python apileaks.py scan \
  --target https://api.example.com \
  --detect-framework \
  --fuzz-versions \
  --framework-confidence 0.8

# Comprehensive scan with all advanced features
python apileaks.py scan \
  --target https://api.example.com \
  --enable-advanced \
  --jwt "eyJ0eXAiOiJKV1Q..." \
  --output comprehensive-scan
```

### CI/CD Integration Examples

```bash
# GitHub Actions - SARIF artifact for code scanning, baseline-gated
python apileaks.py scan \
  --target ${{ vars.API_TARGET_URL }} \
  --jwt ${{ secrets.API_JWT_TOKEN }} \
  --ci-mode \
  --fail-on critical \
  --sarif \
  --baseline reports/baseline.json \
  --output github-scan-${{ github.run_id }}

# GitLab CI - non-destructive scan that fails on high+ findings
python apileaks.py scan \
  --target $API_TARGET_URL \
  --jwt $API_JWT_TOKEN \
  --ci-mode \
  --fail-on high \
  --safe-mode \
  --sarif \
  --output gitlab-scan-$CI_PIPELINE_ID

# Jenkins
python apileaks.py scan \
  --target ${API_TARGET_URL} \
  --jwt ${API_JWT_TOKEN} \
  --ci-mode \
  --fail-on critical \
  --output jenkins-scan-${BUILD_ID}

# Non-blocking discovery triage in CI (publishes session + Markdown artifacts)
python apileaks.py dir \
  --target $API_TARGET_URL \
  --status-code 2xx \
  --save-session artifacts/session.json \
  --export md \
  --export-file artifacts/discovery.md \
  --interactive \
  --ci-mode
```

### Configuration File Examples

```bash
# Using YAML configuration
python apileaks.py scan --config config/production_api.yaml

# Override config with CLI parameters
python apileaks.py scan \
  --config config/base_config.yaml \
  --target https://staging-api.example.com \
  --modules bola,auth
```

### JWT Utility Examples

```bash
# Decode a JWT token
python apileaks.py jwt decode eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...

# Create a test JWT token
python apileaks.py jwt encode \
  '{"sub":"testuser","role":"admin","exp":1735689600}' \
  --secret testsecret

# Create JWT with custom algorithm
python apileaks.py jwt encode \
  '{"sub":"user123"}' \
  --header '{"alg":"HS512","typ":"JWT"}' \
  --secret strongsecret

# Test JWT security vulnerabilities
python apileaks.py jwt test-alg-none TOKEN
python apileaks.py jwt brute-secret TOKEN --wordlist secrets.txt
python apileaks.py jwt test-kid-injection TOKEN

# Run the full automated JWT attack suite against a live endpoint
python apileaks.py jwt attack-test TOKEN --url https://api.example.com/protected
```

### Output and Logging Examples

```bash
# Debug logging to file
python apileaks.py scan \
  --target https://api.example.com \
  --log-level DEBUG \
  --log-file debug-scan.log

# JSON structured logging
python apileaks.py scan \
  --target https://api.example.com \
  --json-logs \
  --log-file structured.log

# Custom output filename
python apileaks.py scan \
  --target https://api.example.com \
  --output my-security-audit-2024
```

---

For more detailed information, see:
- [User Guide](user-guide.md) - Comprehensive usage guide
- [Configuration Guide](configuration.md) - Configuration file reference
- [OWASP Modules Guide](owasp-modules-guide.md) - Detailed module documentation
- [Docker Usage](docker-usage.md) - Container deployment guide