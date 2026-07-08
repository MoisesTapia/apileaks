"""
Request Replay Utility
Reconstructs and re-issues HTTP requests from prior apileaks scan reports.

Given a JSON report (produced by ``dir``, ``par``, or ``scan``), this module
lets the user pick a specific endpoint or finding by URL/index and replay
the exact request — optionally forwarding through an intercepting proxy
(Burp/Caido/Hetty) for manual inspection.

Design goals:
- Zero new dependencies beyond what apileaks already uses (httpx).
- Works with both "discovered_endpoints" and "findings" sections.
- Reconstructs the request as faithfully as the report allows: method,
  headers, query params, and JSON body (when available in finding metadata).
- Outputs a clear request/response dump to stdout so the result is immediately
  actionable.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Type
from urllib.parse import urlparse, urlunparse, urlencode, parse_qs

from core.logging import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Report loading
# ---------------------------------------------------------------------------

def load_report(report_path: str) -> Dict[str, Any]:
    """Load and parse a JSON report file produced by apileaks.

    Raises:
        SystemExit: If the file is missing or not valid JSON.
    """
    path = Path(report_path)
    if not path.exists():
        logger.error("Report file not found", path=report_path)
        sys.exit(f"Error: report file not found: {report_path}")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        sys.exit(f"Error: report file is not valid JSON: {report_path} ({exc})")


# ---------------------------------------------------------------------------
# Request extraction
# ---------------------------------------------------------------------------

def _extract_requests_from_report(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten all replayable requests from a report into a uniform list.

    Each entry is a dict with at minimum:
        url       (str)
        method    (str, upper-cased)
        headers   (dict, may be empty)
        params    (dict of query params, may be empty)
        json_body (dict or None)
        source    ("endpoint" | "finding")
        label     (human-readable one-line description)
    """
    requests: List[Dict[str, Any]] = []

    # Discovered endpoints (from ``dir``)
    for ep in report.get("discovered_endpoints") or []:
        url = ep.get("url", "")
        method = (ep.get("method") or "GET").upper()
        if not url:
            continue
        requests.append({
            "url": url,
            "method": method,
            "headers": {},
            "params": {},
            "json_body": None,
            "source": "endpoint",
            "label": f"[endpoint] {method} {url}  [{ep.get('status_code', '?')}]",
        })

    # Security findings (from ``scan``, ``owasp``, ``par``)
    for finding in report.get("findings") or []:
        url = finding.get("endpoint", "")
        method = (finding.get("method") or "GET").upper()
        if not url:
            continue
        meta = finding.get("metadata") or {}
        # Best-effort reconstruction of payload / headers from finding metadata
        raw_payload = finding.get("payload") or meta.get("payload")
        json_body = None
        if isinstance(raw_payload, dict):
            json_body = raw_payload
        elif isinstance(raw_payload, str) and raw_payload.strip().startswith("{"):
            try:
                json_body = json.loads(raw_payload)
            except (json.JSONDecodeError, ValueError):
                pass

        extra_headers: Dict[str, str] = {}
        if isinstance(meta.get("headers"), dict):
            extra_headers = {k: str(v) for k, v in meta["headers"].items()
                             if k and v is not None}

        severity = finding.get("severity", "")
        category = finding.get("category", "")
        status = finding.get("status_code", "?")
        label = (
            f"[finding|{severity}] {method} {url}  [{status}]  {category}"
        )
        requests.append({
            "url": url,
            "method": method,
            "headers": extra_headers,
            "params": {},
            "json_body": json_body,
            "source": "finding",
            "label": label,
            "finding_id": finding.get("id"),
            "evidence": finding.get("evidence", ""),
        })

    return requests


# ---------------------------------------------------------------------------
# Filtering / selection
# ---------------------------------------------------------------------------

def filter_requests(
    requests: List[Dict[str, Any]],
    *,
    url_filter: Optional[str] = None,
    method_filter: Optional[str] = None,
    source_filter: Optional[str] = None,
    index: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Apply optional filters to the flat request list.

    Args:
        requests:      Full list from :func:`_extract_requests_from_report`.
        url_filter:    Substring match against the request URL.
        method_filter: Case-insensitive HTTP method match (e.g. "POST").
        source_filter: ``"endpoint"`` | ``"finding"`` | None (all).
        index:         Return only the item at this 0-based index (after
                       applying the other filters).

    Returns:
        Filtered (and optionally single-element) list.
    """
    result = list(requests)

    if url_filter:
        result = [r for r in result if url_filter.lower() in r["url"].lower()]
    if method_filter:
        result = [r for r in result if r["method"] == method_filter.upper()]
    if source_filter:
        result = [r for r in result if r["source"] == source_filter]
    if index is not None:
        if 0 <= index < len(result):
            result = [result[index]]
        else:
            result = []

    return result


# ---------------------------------------------------------------------------
# HTTP replay
# ---------------------------------------------------------------------------

async def replay_request(
    entry: Dict[str, Any],
    *,
    extra_headers: Optional[Dict[str, str]] = None,
    jwt_token: Optional[str] = None,
    proxy: Optional[str] = None,
    verify_ssl: bool = True,
    timeout: float = 30.0,
    verbose: bool = True,
) -> Dict[str, Any]:
    """Re-issue a single request described by ``entry`` and return a result dict.

    Uses the apileaks ``HTTPRequestEngine`` so the same proxy / TLS / UA logic
    applies consistently.

    Args:
        entry:         Dict from :func:`_extract_requests_from_report`.
        extra_headers: Additional headers injected on top of the entry headers
                       (e.g. operator-supplied ``-H`` values).
        jwt_token:     Bearer token applied to the ``Authorization`` header.
        proxy:         Intercepting proxy URL (http://127.0.0.1:8080, etc.).
        verify_ssl:    Verify TLS certificates.
        timeout:       Per-request timeout in seconds.
        verbose:       Print request/response dump to stdout.

    Returns:
        Dict with keys: method, url, request_headers, request_body,
        status_code, response_headers, response_body, elapsed.
    """
    import asyncio
    from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig
    from core.config import AuthContext, AuthType

    # Build merged headers: entry headers < extra_headers < JWT
    merged_headers: Dict[str, str] = {}
    merged_headers.update(entry.get("headers") or {})
    if extra_headers:
        merged_headers.update(extra_headers)
    if jwt_token:
        merged_headers["Authorization"] = f"Bearer {jwt_token}"

    rate_limiter = RateLimiter(requests_per_second=10)
    retry_config = RetryConfig(max_attempts=1)  # replay: no retries

    engine = HTTPRequestEngine(
        rate_limiter=rate_limiter,
        retry_config=retry_config,
        timeout=timeout,
        verify_ssl=verify_ssl if not proxy else False,
        proxy=proxy,
        default_headers=merged_headers,
    )

    method = entry["method"]
    url = entry["url"]
    json_body = entry.get("json_body")
    params = entry.get("params") or {}

    req_kwargs: Dict[str, Any] = {}
    if params:
        req_kwargs["params"] = params
    if json_body:
        req_kwargs["json"] = json_body
        merged_headers.setdefault("Content-Type", "application/json")

    try:
        async with engine:
            response = await engine.request(method, url, **req_kwargs)
    except Exception as exc:
        logger.error("Replay request failed", url=url, method=method, error=str(exc))
        raise

    # ---- verbose dump -------------------------------------------------------
    if verbose:
        _print_replay_dump(
            method=method,
            url=url,
            req_headers=merged_headers,
            req_body=json_body,
            status=response.status_code,
            resp_headers=response.headers,
            resp_body=response.text,
            elapsed=response.elapsed,
        )

    return {
        "method": method,
        "url": url,
        "request_headers": merged_headers,
        "request_body": json_body,
        "status_code": response.status_code,
        "response_headers": dict(response.headers),
        "response_body": response.text,
        "elapsed": response.elapsed,
    }


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

_RESET = "\033[0m"
_BOLD  = "\033[1m"
_CYAN  = "\033[96m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_RED   = "\033[91m"
_GRAY  = "\033[90m"
_MAGENTA = "\033[95m"


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


def _print_replay_dump(
    *,
    method: str,
    url: str,
    req_headers: Dict[str, str],
    req_body: Optional[Any],
    status: int,
    resp_headers: Dict[str, str],
    resp_body: str,
    elapsed: float,
) -> None:
    """Print a human-readable request/response dump to stdout."""
    sep = "─" * 60

    # ---- REQUEST -----------------------------------------------------------
    print(f"\n{_BOLD}{_CYAN}{'═' * 60}")
    print(f"  REPLAY REQUEST")
    print(f"{'═' * 60}{_RESET}")

    parsed = urlparse(url)
    path_qs = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    print(f"{_BOLD}{_MAGENTA}{method}{_RESET} {path_qs}  {_GRAY}HTTP/1.1{_RESET}")
    print(f"{_GRAY}Host: {parsed.netloc}{_RESET}")

    for name, value in sorted(req_headers.items()):
        # Redact auth values in output
        if name.lower() == "authorization":
            parts = value.split(" ", 1)
            token_preview = parts[1][:12] + "…" if len(parts) > 1 and len(parts[1]) > 12 else (parts[1] if len(parts) > 1 else "")
            print(f"{_GRAY}{name}: {parts[0]} {token_preview}{_RESET}")
        else:
            print(f"{_GRAY}{name}: {value}{_RESET}")

    if req_body:
        print()
        print(json.dumps(req_body, indent=2))

    # ---- RESPONSE ----------------------------------------------------------
    col = _status_color(status)
    print(f"\n{_BOLD}{_CYAN}{sep}")
    print(f"  RESPONSE")
    print(f"{sep}{_RESET}")
    print(f"{col}{_BOLD}HTTP/1.1 {status}{_RESET}  {_GRAY}({elapsed:.3f}s){_RESET}")

    # Print response headers (truncated)
    SKIP_HEADERS = {"transfer-encoding", "connection"}
    for name, value in sorted(resp_headers.items()):
        if name.lower() in SKIP_HEADERS:
            continue
        print(f"{_GRAY}{name}: {value}{_RESET}")

    # Print response body (truncated at 4 KB)
    print()
    MAX_BODY = 4096
    body_preview = resp_body[:MAX_BODY] if resp_body else ""
    if len(resp_body or "") > MAX_BODY:
        body_preview += f"\n{_YELLOW}… (truncated, {len(resp_body)} bytes total){_RESET}"

    # Try pretty-print JSON body
    try:
        parsed_body = json.loads(body_preview)
        print(json.dumps(parsed_body, indent=2, ensure_ascii=False))
    except (json.JSONDecodeError, ValueError):
        print(body_preview)

    print(f"{_BOLD}{_CYAN}{'═' * 60}{_RESET}\n")


def print_request_list(requests: List[Dict[str, Any]]) -> None:
    """Print an indexed list of replayable requests to stdout."""
    if not requests:
        print("No replayable requests found in report.")
        return
    print(f"\n{_BOLD}{'#':>4}  {'SRC':<9} {'METHOD':<7} {'STATUS':<7} URL{_RESET}")
    print("─" * 80)
    for i, req in enumerate(requests):
        src = req["source"]
        method = req["method"]
        status = req.get("status_code") or (
            req["label"].split("[")[-1].rstrip("]").strip()
            if "[" in req["label"] else "?"
        )
        url = req["url"]
        # Truncate long URLs
        url_display = url if len(url) <= 55 else url[:52] + "…"
        src_col = _CYAN if src == "endpoint" else _MAGENTA
        print(f"{i:>4}  {src_col}{src:<9}{_RESET} {method:<7} {str(status):<7} {url_display}")
    print()
