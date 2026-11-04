"""
cli.commands.request_cmd — Single-shot HTTP request command.

Sends a single arbitrary HTTP request and prints a rich, coloured
request/response dump — like curl or httpie, but integrated into the
APILeak toolchain with the same proxy, auth, and TLS options used by
every other command.

Usage::

    apileaks req GET  https://api.example.com/users
    apileaks req POST https://api.example.com/users --json '{"name":"alice"}'
    apileaks req POST https://api.example.com/users name=alice role=admin
    apileaks req PATCH https://api.example.com/users/42 \\
        --json '{"role":"admin"}' \\
        --proxy http://127.0.0.1:8080
    apileaks req GET  https://api.example.com/token --quiet | jq .access_token

Registered under two names in ``apileaks.py``:
    cli.add_command(request_cmd, name="request")
    cli.add_command(request_cmd, name="req")
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import click

from cli.output import print_banner
from cli.parsers import parse_header_options, validate_header_options
from core.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# ANSI colour constants (duplicated from utils/replay.py to keep this module
# self-contained and avoid a circular import through the display path).
# ---------------------------------------------------------------------------
_RESET = "\033[0m"
_BOLD = "\033[1m"
_CYAN = "\033[96m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_RED = "\033[91m"
_GRAY = "\033[90m"
_MAGENTA = "\033[95m"
_BLUE = "\033[94m"


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
    """Parse httpie-style KEY=VALUE and KEY:=RAWJSON pairs into a body dict.

    Examples::

        name=alice          → {"name": "alice"}
        age:=30             → {"age": 30}
        roles:=["admin"]    → {"roles": ["admin"]}
        active:=true        → {"active": true}
    """
    result: dict[str, Any] = {}
    for field in fields:
        if ":=" in field:
            key, _, raw = field.partition(":=")
            try:
                result[key.strip()] = json.loads(raw.strip())
            except json.JSONDecodeError:
                # Fall back to treating the raw value as a string.
                result[key.strip()] = raw.strip()
        elif "=" in field:
            key, _, value = field.partition("=")
            result[key.strip()] = value
        else:
            raise click.BadParameter(
                f"Invalid field {field!r}. "
                "Use key=value (string) or key:=rawjson (typed value, e.g. key:=42).",
                param_hint="FIELDS",
            )
    return result


def _parse_kvpairs(pairs: tuple[str, ...], option_name: str) -> dict[str, str]:
    """Parse 'key=value' pairs into a string dict (for --param, --form)."""
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
) -> None:
    """Print a human-readable, coloured request/response dump to stdout.

    Styled consistently with :func:`utils.replay._print_replay_dump` but
    labelled "HTTP REQUEST" (not "REPLAY REQUEST") and extended with:
    - Query parameters shown separately.
    - Response body length shown when the body is truncated.
    - Content-Type colour hint on the response side.
    """
    sep = "─" * 60
    wide = "═" * 60

    # ── REQUEST ──────────────────────────────────────────────────────────
    click.echo(f"\n{_BOLD}{_CYAN}{wide}")
    click.echo("  HTTP REQUEST")
    click.echo(f"{wide}{_RESET}")

    parsed = urlparse(url)
    path = parsed.path or "/"
    qs = f"?{parsed.query}" if parsed.query else ""
    # If --param was used, show them in the path line too
    if req_params:
        qs_extra = "&".join(f"{k}={v}" for k, v in req_params.items())
        qs = (qs + "&" + qs_extra) if qs else ("?" + qs_extra)
    click.echo(f"{_BOLD}{_MAGENTA}{method}{_RESET} {path}{qs}  {_GRAY}HTTP/1.1{_RESET}")
    click.echo(f"{_GRAY}Host: {parsed.netloc}{_RESET}")

    for name, value in sorted(req_headers.items()):
        if name.lower() in ("host",):
            continue  # already shown
        if name.lower() == "authorization":
            parts = value.split(" ", 1)
            token_preview = (
                parts[1][:16] + "…"
                if len(parts) > 1 and len(parts[1]) > 16
                else (parts[1] if len(parts) > 1 else "")
            )
            click.echo(f"{_GRAY}{name}: {parts[0]} {token_preview}{_RESET}")
        else:
            click.echo(f"{_GRAY}{name}: {value}{_RESET}")

    if req_body:
        click.echo()
        if isinstance(req_body, dict):
            click.echo(json.dumps(req_body, indent=2, ensure_ascii=False))
        else:
            click.echo(str(req_body))

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
    truncated = len(resp_body or "") > MAX_BODY

    # Pretty-print JSON if the content type or the body looks like JSON
    is_json = "json" in content_type.lower()
    if not is_json and body_to_show and body_to_show.strip().startswith("{"):
        is_json = True

    if is_json:
        try:
            parsed_body = json.loads(body_to_show if not truncated else resp_body)
            click.echo(json.dumps(parsed_body, indent=2, ensure_ascii=False))
        except (json.JSONDecodeError, ValueError):
            click.echo(body_to_show)
    else:
        click.echo(body_to_show)

    if truncated:
        click.echo(
            f"\n{_YELLOW}… body truncated — showing {MAX_BODY} of "
            f"{len(resp_body)} bytes total{_RESET}"
        )

    click.echo(f"{_BOLD}{_CYAN}{wide}{_RESET}\n")


def _print_scan_results(
    secrets: list,
    resp_body: str,
    resp_headers: dict[str, str],
    url: str,
    method: str,
) -> None:
    """Print secret-scan results after the response dump."""
    if not secrets:
        click.echo(f"{_GREEN}[✓] Secret scan: no patterns matched in the response.{_RESET}")
        return

    click.echo(f"\n{_BOLD}{_RED}{'━' * 60}")
    click.echo(f"  SECRET SCAN — {len(secrets)} match(es) found")
    click.echo(f"{'━' * 60}{_RESET}")
    for s in secrets:
        click.echo(
            f"  {_RED}▶{_RESET} {_BOLD}{s.pattern_name}{_RESET}  "
            f"redacted: {_YELLOW}{s.redacted}{_RESET}"
        )
    click.echo(
        f"\n{_YELLOW}⚠  Sensitive data detected in the response. "
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
    """Send one HTTP request via :class:`~utils.http_client.HTTPRequestEngine`.

    Returns a result dict with keys:
    ``method``, ``url``, ``request_headers``, ``request_body``,
    ``status_code``, ``response_headers``, ``response_body``, ``elapsed``.
    """
    from core.config import RateLimitConfig
    from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig

    # Single-shot: no rate limiting, no retries.
    rate_limiter = RateLimiter(RateLimitConfig(requests_per_second=1000, burst_size=1000))
    retry_cfg = RetryConfig(max_attempts=1)

    # Proxy disables TLS verification by default (the proxy terminates TLS).
    effective_verify = False if proxy else verify_ssl

    engine = HTTPRequestEngine(
        rate_limiter=rate_limiter,
        retry_config=retry_cfg,
        timeout=timeout,
        verify_ssl=effective_verify,
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
    except Exception as exc:  # noqa: BLE001
        raise click.ClickException(
            f"Request failed: {type(exc).__name__}: {exc}"
        ) from exc

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
# Session persistence helpers
# ---------------------------------------------------------------------------

def _save_to_session(result: dict[str, Any], path: str) -> None:
    """Append the request/response to a session JSON file for later replay.

    The session file uses the same format as an apileaks scan report so
    ``apileaks replay <session.json>`` can re-issue the saved requests::

        apileaks replay sessions/my-session.json --proxy http://127.0.0.1:8080
    """
    session_path = Path(path)
    if session_path.exists():
        try:
            session = json.loads(session_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            session = {"findings": []}
    else:
        session = {"findings": []}

    session.setdefault("findings", []).append(
        {
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
        }
    )

    session_path.parent.mkdir(parents=True, exist_ok=True)
    session_path.write_text(
        json.dumps(session, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    click.echo(f"{_GRAY}[session] Saved to {session_path}{_RESET}", err=True)


# ---------------------------------------------------------------------------
# Click command
# ---------------------------------------------------------------------------

KNOWN_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"}


@click.command("request")
@click.argument("method")
@click.argument("url")
@click.argument("fields", nargs=-1, metavar="[KEY=VALUE ...]")
@click.option(
    "--json",
    "json_str",
    default=None,
    metavar="JSON",
    help=(
        "Request body as a JSON string. Mutually exclusive with KEY=VALUE fields. "
        "Sets Content-Type: application/json automatically.\n\n"
        "Example: --json '{\"role\":\"admin\"}'"
    ),
)
@click.option(
    "--form",
    "-F",
    "form_pairs",
    multiple=True,
    metavar="KEY=VALUE",
    help=(
        "Form field (repeatable). Sends the body as application/x-www-form-urlencoded. "
        "Mutually exclusive with --json.\n\nExample: -F username=admin -F password=test"
    ),
)
@click.option(
    "--raw",
    "raw_body",
    default=None,
    metavar="TEXT",
    help="Request body as a raw string (no Content-Type set automatically).",
)
@click.option(
    "--header", "-H",
    "raw_headers",
    multiple=True,
    metavar="Name: Value",
    help="Extra request header (repeatable).\n\nExample: -H 'X-API-Key: secret' -H 'Accept: application/json'",
)
@click.option(
    "--jwt",
    "jwt_token",
    default=None,
    metavar="TOKEN",
    help="JWT / Bearer token injected as 'Authorization: Bearer <token>'.",
)
@click.option(
    "--proxy",
    default=None,
    metavar="URL",
    help=(
        "Route the request through an intercepting proxy "
        "(Burp Suite, Caido, Hetty, mitmproxy …).\n\n"
        "HTTP:  --proxy http://127.0.0.1:8080\n"
        "SOCKS5: --proxy socks5://127.0.0.1:9050\n\n"
        "TLS verification is disabled automatically when a proxy is set."
    ),
)
@click.option(
    "--param", "-p",
    "raw_params",
    multiple=True,
    metavar="KEY=VALUE",
    help="Query-string parameter (repeatable). Appended to the URL before sending.",
)
@click.option(
    "--follow-redirects",
    is_flag=True,
    default=False,
    help="Follow HTTP 3xx redirects (default: stop at the first redirect).",
)
@click.option(
    "--no-verify",
    is_flag=True,
    default=False,
    help="Disable TLS certificate verification.",
)
@click.option(
    "--timeout",
    type=float,
    default=30.0,
    show_default=True,
    metavar="SECS",
    help="Per-request timeout in seconds.",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    default=False,
    help="Print only the response body (useful for piping: apileaks req GET ... --quiet | jq .).",
)
@click.option(
    "--output", "-o",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    show_default=True,
    help=(
        "'text' — rich coloured request/response dump (default).\n"
        "'json' — machine-readable JSON with request + response details."
    ),
)
@click.option(
    "--scan-response",
    is_flag=True,
    default=False,
    help=(
        "After the request, scan the response body and headers for leaked "
        "secrets / credentials using APILeak's built-in pattern library "
        "(AWS keys, GitHub tokens, JWTs, private keys, etc.)."
    ),
)
@click.option(
    "--save-session",
    "save_session",
    default=None,
    type=click.Path(dir_okay=False, writable=True),
    metavar="FILE",
    help=(
        "Append the request/response to a session JSON file for later replay.\n\n"
        "Example: --save-session sessions/pentest.json\n"
        "Replay:  apileaks replay sessions/pentest.json --proxy http://127.0.0.1:8080"
    ),
)
@click.option(
    "--fail-on-error",
    is_flag=True,
    default=False,
    help="Exit with status code 1 when the server returns a 4xx or 5xx response.",
)
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
    scan_response: bool,
    save_session: str | None,
    fail_on_error: bool,
) -> None:
    """Send a single HTTP request and display a coloured request/response dump.

    METHOD is the HTTP verb (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, …).
    URL is the full request URL.
    KEY=VALUE pairs build a JSON body (httpie-style).

    \b
    Basic examples:
      apileaks req GET  https://api.example.com/users
      apileaks req POST https://api.example.com/users --json '{"name":"alice"}'
      apileaks req POST https://api.example.com/users name=alice role=admin
      apileaks req DELETE https://api.example.com/users/42

    \b
    With auth:
      apileaks req GET  https://api.example.com/me --jwt eyJhbGci...
      apileaks req GET  https://api.example.com/me -H 'Authorization: Bearer eyJ...'
      apileaks req GET  https://api.example.com/me -H 'X-API-Key: secret'

    \b
    Through a proxy (Burp / Caido / Hetty):
      apileaks req PATCH https://api.example.com/users/42 \\
        --json '{"role":"admin"}' --proxy http://127.0.0.1:8080
      apileaks req GET  https://api.example.com/users \\
        --proxy http://127.0.0.1:8080 --jwt eyJhbGci...

    \b
    Query params:
      apileaks req GET https://api.example.com/search -p q=admin -p limit=100

    \b
    Form data:
      apileaks req POST https://api.example.com/login -F username=admin -F password=test

    \b
    Scripting / piping:
      apileaks req GET  https://api.example.com/token --quiet | jq .access_token
      apileaks req POST https://api.example.com/login \\
        --json '{"user":"admin","pass":"test"}' --output json > result.json

    \b
    Secret scan:
      apileaks req GET https://api.example.com/config --scan-response

    \b
    Save for later replay:
      apileaks req POST https://api.example.com/users name=alice \\
        --save-session sessions/pentest.json
      apileaks replay sessions/pentest.json --proxy http://127.0.0.1:8080
    """
    # ── Banner ───────────────────────────────────────────────────────────
    no_banner = ctx.obj.get("no_banner", False) if ctx.obj else False
    if not no_banner and not quiet and output == "text":
        print_banner()

    # ── Validate method ──────────────────────────────────────────────────
    method = method.upper()
    if method not in KNOWN_METHODS:
        click.echo(
            f"{_YELLOW}⚠  '{method}' is not a standard HTTP method. "
            f"Known: {', '.join(sorted(KNOWN_METHODS))}. Proceeding anyway.{_RESET}",
            err=True,
        )

    # ── Validate URL ─────────────────────────────────────────────────────
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
        if not quiet:
            click.echo(
                f"{_GRAY}[auto] Prefixed URL with https:// → {url}{_RESET}", err=True
            )

    # ── Parse request components ─────────────────────────────────────────
    # 1. Headers
    validate_header_options(raw_headers)
    extra_headers: dict[str, str] = parse_header_options(raw_headers)
    if jwt_token:
        extra_headers["Authorization"] = f"Bearer {jwt_token}"

    # 2. Body — priority: --json > KEY=VALUE fields > --form > --raw
    json_body: dict[str, Any] | None = None
    form_data: dict[str, str] | None = None

    body_sources = sum([bool(json_str), bool(fields), bool(form_pairs), bool(raw_body)])
    if body_sources > 1:
        raise click.UsageError(
            "Conflicting body options: use only one of --json, KEY=VALUE fields, --form, or --raw."
        )

    if json_str:
        try:
            json_body = json.loads(json_str)
        except json.JSONDecodeError as exc:
            raise click.BadParameter(
                f"--json value is not valid JSON: {exc}", param_hint="--json"
            ) from exc
        extra_headers.setdefault("Content-Type", "application/json")

    elif fields:
        try:
            json_body = _parse_fields(fields)
        except click.BadParameter:
            raise
        extra_headers.setdefault("Content-Type", "application/json")

    elif form_pairs:
        try:
            form_data = _parse_kvpairs(form_pairs, "--form")
        except click.BadParameter:
            raise
        extra_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    # 3. Query params
    params: dict[str, str] = {}
    if raw_params:
        try:
            params = _parse_kvpairs(raw_params, "--param")
        except click.BadParameter:
            raise

    # ── Execute ──────────────────────────────────────────────────────────
    try:
        result = asyncio.run(
            _execute_request(
                method,
                url,
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
    except Exception as exc:  # noqa: BLE001
        raise click.ClickException(f"Unexpected error: {exc}") from exc

    # ── Display ──────────────────────────────────────────────────────────
    if quiet:
        # Only the response body — useful for piping
        click.echo(result["response_body"])

    elif output.lower() == "json":
        output_data = {
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
        # Attach secret findings if scan was requested
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
        # Default: rich coloured dump
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
        )
        if scan_response:
            from utils.secret_scanner import scan_for_secrets
            secrets = scan_for_secrets(
                body=result["response_body"],
                headers=result["response_headers"],
                endpoint=url,
                method=method,
            )
            _print_scan_results(
                secrets=secrets,
                resp_body=result["response_body"],
                resp_headers=result["response_headers"],
                url=url,
                method=method,
            )

    # ── Save session ──────────────────────────────────────────────────────
    if save_session:
        _save_to_session(result, save_session)

    # ── Exit code ─────────────────────────────────────────────────────────
    if fail_on_error and result["status_code"] >= 400:
        sys.exit(1)
