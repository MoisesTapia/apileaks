"""
SSRF Import Sources — Burp Suite XML and HAR file parsers.

Produces ``ImportedRequest`` objects consumed by ``SSRFTestingModule``
for Full_Replay_Mode probing: each imported request is replayed with its
original headers and body, with only URL-like field values swapped for
SSRF payloads.

Supported formats:
  * Burp Suite XML export  (Proxy → HTTP History → Save items)
  * HAR (HTTP Archive) JSON  (Burp Logger, Caido, Hetty, Chrome DevTools)
"""

import base64
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from core.logging import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class ImportSourceError(Exception):
    """Raised for file-level or parse-level failures in an importer.

    The message always includes the offending file path so the caller can
    surface a human-readable error before issuing any probe requests.
    """


# ---------------------------------------------------------------------------
# URL-like field detection
# ---------------------------------------------------------------------------

# Field name keywords (checked case-insensitively) that indicate the field
# is intended to carry a URL, hostname, or fetchable resource reference.
_URL_KEYWORDS: frozenset = frozenset({
    "url", "uri", "host", "endpoint", "target", "webhook", "callback",
    "redirect", "link", "href", "src", "source", "dest", "destination",
    "fetch", "import", "feed", "avatar", "image", "thumbnail",
    "imageurl", "avatarurl", "feedurl", "importurl",
})


def _is_url_like_field(name: str, value: Any) -> bool:
    """Return True when a body field is URL-like by name OR by value.

    Detection rules (Requirement 2):
    1. Field name (lowercased) contains any entry from ``_URL_KEYWORDS``.
    2. Field string value starts with ``http://`` or ``https://``
       (case-insensitive).
    """
    name_lower = name.lower()
    if any(kw in name_lower for kw in _URL_KEYWORDS):
        return True
    if isinstance(value, str) and value.lower().startswith(("http://", "https://")):
        return True
    return False


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ImportedRequest:
    """A single HTTP request extracted from an import source.

    Attributes:
        method: Upper-cased HTTP method (e.g. ``"POST"``).
        path: Request path and optional query string (e.g. ``"/api/v1/upload"``).
        headers: Case-preserving header dictionary from the original request.
        body: Parsed JSON object when the request carries a JSON body, else None.
        url_like_fields: Names of fields in ``body`` classified as URL-like.
        raw_body: The raw body string before JSON parsing, or None.
    """

    method: str
    path: str
    headers: Dict[str, str]
    body: Optional[Dict[str, Any]]
    url_like_fields: List[str]
    raw_body: Optional[str]


def _detect_url_like_fields(body: Optional[Dict[str, Any]]) -> List[str]:
    """Return names of URL-like fields from a parsed JSON body dict."""
    if not body or not isinstance(body, dict):
        return []
    return [k for k, v in body.items() if _is_url_like_field(k, v)]


def _parse_json_body(raw_body: Optional[str]) -> Optional[Dict[str, Any]]:
    """Try to parse raw_body as a JSON object; return None on failure."""
    if not raw_body:
        return None
    try:
        parsed = json.loads(raw_body)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, ValueError):
        pass
    return None


# ---------------------------------------------------------------------------
# Burp Suite XML importer
# ---------------------------------------------------------------------------


class BurpXmlImporter:
    """Parse a Burp Suite XML Proxy-History export.

    Usage::

        importer = BurpXmlImporter("/path/to/burp_export.xml")
        requests = importer.parse()

    Each ``<item>`` element in the XML produces one ``ImportedRequest``.
    The ``<request>`` child is either plain text or base64-encoded
    (indicated by ``base64="true"``).
    """

    def __init__(self, path: str) -> None:
        self._path = path

    def parse(self) -> List[ImportedRequest]:
        """Parse the XML file and return a list of ``ImportedRequest`` objects."""
        import os
        if not os.path.exists(self._path):
            raise ImportSourceError(
                f"Burp XML file not found: '{self._path}'"
            )

        try:
            tree = ET.parse(self._path)
        except ET.ParseError as exc:
            raise ImportSourceError(
                f"Burp XML file is not valid XML: '{self._path}': {exc}"
            ) from exc

        root = tree.getroot()
        # Support both <items> root with <item> children and flat <item> roots.
        items = root.findall("item") if root.tag != "item" else [root]

        results: List[ImportedRequest] = []
        for idx, item in enumerate(items):
            try:
                req = self._parse_item(item)
                if req is not None:
                    results.append(req)
            except Exception as exc:
                logger.warning(
                    "Skipping malformed Burp XML item",
                    index=idx,
                    reason=str(exc),
                )
        return results

    def _parse_item(self, item: ET.Element) -> Optional["ImportedRequest"]:
        """Extract an ``ImportedRequest`` from a single ``<item>`` element."""
        request_elem = item.find("request")
        if request_elem is None or request_elem.text is None:
            raise ValueError("Missing or empty <request> element")

        is_b64 = (request_elem.get("base64", "false").lower() == "true")
        raw_bytes: bytes
        if is_b64:
            try:
                raw_bytes = base64.b64decode(request_elem.text.strip())
            except Exception as exc:
                raise ValueError(f"base64 decode failed: {exc}") from exc
        else:
            raw_bytes = request_elem.text.encode("latin-1", errors="replace")

        return self._parse_raw_http(raw_bytes)

    @staticmethod
    def _parse_raw_http(raw: bytes) -> "ImportedRequest":
        """Parse raw HTTP/1.x request bytes into an ``ImportedRequest``."""
        # Split on the first blank line (headers / body separator).
        if b"\r\n\r\n" in raw:
            head_part, body_part = raw.split(b"\r\n\r\n", 1)
        elif b"\n\n" in raw:
            head_part, body_part = raw.split(b"\n\n", 1)
        else:
            head_part = raw
            body_part = b""

        lines = head_part.decode("latin-1", errors="replace").splitlines()
        if not lines:
            raise ValueError("Empty HTTP request")

        # Request line: METHOD /path HTTP/1.x
        request_line = lines[0].split()
        if len(request_line) < 2:
            raise ValueError(f"Malformed request line: {lines[0]!r}")
        method = request_line[0].upper()
        full_path = request_line[1]

        # Headers
        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                hname, _, hval = line.partition(":")
                headers[hname.strip()] = hval.strip()

        # Body
        raw_body_str = body_part.decode("utf-8", errors="replace") if body_part else None
        content_type = next(
            (v for k, v in headers.items() if k.lower() == "content-type"), ""
        )
        body = None
        if "application/json" in content_type.lower():
            body = _parse_json_body(raw_body_str)

        return ImportedRequest(
            method=method,
            path=full_path,
            headers=headers,
            body=body,
            url_like_fields=_detect_url_like_fields(body),
            raw_body=raw_body_str,
        )


# ---------------------------------------------------------------------------
# HAR importer
# ---------------------------------------------------------------------------


class HarImporter:
    """Parse a HAR (HTTP Archive) JSON file.

    HAR is produced by Burp Suite Logger, Caido, Hetty, Chrome DevTools,
    and Firefox. Each entry in ``log.entries[].request`` becomes one
    ``ImportedRequest``.

    Usage::

        importer = HarImporter("/path/to/export.har")
        requests = importer.parse()
    """

    def __init__(self, path: str) -> None:
        self._path = path

    def parse(self) -> List[ImportedRequest]:
        """Parse the HAR file and return a list of ``ImportedRequest`` objects."""
        import os
        if not os.path.exists(self._path):
            raise ImportSourceError(
                f"HAR file not found: '{self._path}'"
            )

        try:
            with open(self._path, encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ImportSourceError(
                f"HAR file is not valid JSON: '{self._path}': {exc}"
            ) from exc

        if not isinstance(data, dict) or "log" not in data:
            raise ImportSourceError(
                f"HAR file missing required 'log' key: '{self._path}'"
            )

        entries = data["log"].get("entries", [])
        if not entries:
            return []

        results: List[ImportedRequest] = []
        for idx, entry in enumerate(entries):
            try:
                req = self._parse_entry(entry)
                if req is not None:
                    results.append(req)
            except Exception as exc:
                logger.warning(
                    "Skipping malformed HAR entry",
                    index=idx,
                    reason=str(exc),
                )
        return results

    @staticmethod
    def _parse_entry(entry: dict) -> Optional["ImportedRequest"]:
        """Extract an ``ImportedRequest`` from a single HAR entry dict."""
        if not isinstance(entry, dict):
            raise ValueError("Entry is not a dict")

        request = entry.get("request")
        if not isinstance(request, dict):
            raise ValueError("Entry missing 'request' field")

        method = str(request.get("method", "GET")).upper()
        url = str(request.get("url", ""))

        # Keep path + query string only (strip scheme and host).
        parsed = urlsplit(url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        # Headers: HAR uses [{name, value}, ...] format.
        headers: Dict[str, str] = {}
        for hdr in request.get("headers", []):
            if isinstance(hdr, dict) and "name" in hdr and "value" in hdr:
                headers[hdr["name"]] = hdr["value"]

        # Body from postData.
        post_data = request.get("postData")
        raw_body_str: Optional[str] = None
        body: Optional[Dict[str, Any]] = None

        if isinstance(post_data, dict):
            raw_body_str = post_data.get("text") or None
            mime = post_data.get("mimeType", "") or ""
            if "application/json" in mime.lower():
                body = _parse_json_body(raw_body_str)
            elif not mime:
                # Fall back: try JSON parse regardless of missing MIME.
                body = _parse_json_body(raw_body_str)

        return ImportedRequest(
            method=method,
            path=path,
            headers=headers,
            body=body,
            url_like_fields=_detect_url_like_fields(body),
            raw_body=raw_body_str,
        )
