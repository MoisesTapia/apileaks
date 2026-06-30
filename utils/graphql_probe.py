"""
GraphQL Probe Helpers

Pure, side-effect-free helpers used by GraphQL endpoint discovery (Requirement
27). This module supplies the common GraphQL paths to probe, the minimal
read-only introspection query, and the detection predicates that classify a
response object as a GraphQL endpoint and decide whether introspection is
enabled on the target.

These helpers never perform network I/O: they only inspect a response object
that has already been fetched through the existing ``HTTPRequestEngine`` so the
budget/concurrency/rate path is preserved by the caller. They are intentionally
defensive — non-JSON bodies, missing attributes, missing keys, and non-200
statuses all yield ``False`` rather than raising — which keeps discovery robust
and makes the predicates trivially unit-testable.

The introspection query is a single read-only GraphQL operation (no mutations),
so issuing it is ``Safe_Mode`` compatible (Requirement 27.5).
"""

import json
from typing import Any, Optional

from core.logging import get_logger

logger = get_logger(__name__)

# Common paths where a GraphQL endpoint is typically exposed. Probed against the
# base URL when GraphQL discovery is enabled (Requirement 27.2).
COMMON_GRAPHQL_PATHS = (
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/graphql/console",
    "/graphiql",
)

# Minimal read-only introspection query, serialized as a JSON request body
# string. It asks only for the schema's query type name, which is enough to tell
# whether introspection is enabled without enumerating the full schema. Sent as
# a single read-only POST body (no mutations) so it remains Safe_Mode compatible
# (Requirements 27.3, 27.5). The HTTPRequestEngine sends raw string bodies via
# its ``data=`` parameter, matching the convention used elsewhere for non-JSON
# and pre-serialized payloads in modules/fuzzing/orchestrator.py.
INTROSPECTION_QUERY = '{"query":"{ __schema { queryType { name } } }"}'


def _response_body(resp: Any) -> Optional[str]:
    """Best-effort extraction of a response body as text.

    Prefers the ``text`` attribute used by the project's
    :class:`~utils.http_client.Response`, falling back to decoding raw
    ``content`` bytes. Returns ``None`` when no body can be read.

    Args:
        resp: A response-like object (e.g. ``utils.http_client.Response``).

    Returns:
        The response body as a string, or ``None`` if unavailable.
    """
    text = getattr(resp, "text", None)
    if isinstance(text, str):
        return text

    content = getattr(resp, "content", None)
    if isinstance(content, (bytes, bytearray)):
        try:
            return content.decode("utf-8", errors="replace")
        except Exception:  # pragma: no cover - decode is already error-tolerant
            return None

    return None


def _parse_json_body(resp: Any) -> Optional[dict]:
    """Parse a response body into a JSON object, defensively.

    Args:
        resp: A response-like object.

    Returns:
        The parsed JSON object when the body is a JSON ``dict``; otherwise
        ``None`` (for empty, non-JSON, or non-object bodies).
    """
    body = _response_body(resp)
    if not body:
        return None

    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return None

    return parsed if isinstance(parsed, dict) else None


def is_graphql_response(resp: Any) -> bool:
    """Return ``True`` when a response looks like it came from a GraphQL endpoint.

    A GraphQL endpoint replies with a JSON object that carries GraphQL-shaped
    top-level keys: ``data`` (a successful result) and/or ``errors`` (a list of
    GraphQL errors, e.g. when the probe query is rejected). The presence of
    either key is treated as evidence of a ``GraphQL_Endpoint`` (Requirement
    27.2).

    The check is defensive: a missing body, a non-JSON body, a non-object JSON
    body, or a missing attribute all yield ``False`` rather than raising.

    Args:
        resp: A response-like object with ``text``/``content`` attributes.

    Returns:
        ``True`` if the response indicates a GraphQL endpoint, else ``False``.
    """
    parsed = _parse_json_body(resp)
    if parsed is None:
        return False

    return "data" in parsed or "errors" in parsed


def introspection_enabled(resp: Any) -> bool:
    """Return ``True`` when an introspection response shows introspection is on.

    Introspection is considered enabled only when the response is an HTTP 200
    with a JSON body containing a populated ``data.__schema`` object — i.e.
    ``data`` is an object whose ``__schema`` value is a non-empty object
    (Requirement 27.4). Anything else (non-200 status, non-JSON body, missing
    ``data``/``__schema``, an empty or null ``__schema``, or a GraphQL
    ``errors`` response) yields ``False``.

    The check is defensive and never raises on malformed input.

    Args:
        resp: A response-like object with ``status_code`` and ``text``/
            ``content`` attributes.

    Returns:
        ``True`` if introspection is enabled on the target, else ``False``.
    """
    status_code = getattr(resp, "status_code", None)
    if status_code != 200:
        return False

    parsed = _parse_json_body(resp)
    if parsed is None:
        return False

    data = parsed.get("data")
    if not isinstance(data, dict):
        return False

    schema = data.get("__schema")
    # A populated schema is a non-empty object. An empty dict, ``None``, or a
    # non-object value all mean introspection did not return a usable schema.
    return isinstance(schema, dict) and bool(schema)
