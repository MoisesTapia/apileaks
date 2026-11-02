"""
HTTP Parameter Pollution (HPP) — pure variant builders.

Shared, reusable primitives for building the three request variants an HPP
probe needs for any single candidate parameter, regardless of where that
parameter came from (a discovered endpoint's query string, or a field in a
captured Burp Suite / Caido / HAR request body):

  * ``baseline_a`` — the request with the parameter set to ``value_a`` only.
  * ``baseline_b`` — the request with the parameter set to ``value_b`` only.
  * ``polluted``   — the request with the SAME parameter supplied twice
    (query string) or wrapped in an array (JSON body), once per value.

Comparing the server's response to ``polluted`` against the two baselines is
what lets a caller detect inconsistent parameter resolution (first-value-wins
vs last-value-wins vs array-coercion) — the classic HTTP Parameter Pollution
signal. This module only builds the three variants; interpreting the
responses is the caller's job (see ``modules/owasp/parameter_pollution.py``).

Kept dependency-free (stdlib only) so it can be reused by any module —
OWASP's own ``ParameterPollutionModule`` as well as any future caller —
without pulling in HTTP client or OWASP-module concerns.
"""

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def build_query_pollution_variants(
    url: str, param: str, value_a: str, value_b: str
) -> tuple[str, str, str]:
    """Return ``(url_a, url_b, url_polluted)`` for a query-string HPP probe.

    Every other query parameter and the rest of the URL (scheme, host, path,
    fragment) are preserved unchanged in all three variants — only ``param``
    is touched, so a response difference can be attributed to the pollution
    itself rather than to an unrelated change.

    Args:
        url: The original request URL. If ``param`` is already present in its
            query string, its first occurrence's position is preserved in the
            rebuilt query string; otherwise ``param`` is appended.
        param: The query parameter name to pollute.
        value_a: The single value for ``url_a``.
        value_b: The single value for ``url_b``. Also the second value paired
            with ``value_a`` in ``url_polluted``.

    Returns:
        A 3-tuple of URLs: single value A, single value B, and both values
        supplied for ``param`` in the same request (``?param=A&param=B``).
    """
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    other_pairs = [(k, v) for k, v in pairs if k != param]

    def _rebuild(query_pairs: list[tuple[str, str]]) -> str:
        new_query = urlencode(query_pairs, doseq=False)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))

    url_a = _rebuild([*other_pairs, (param, value_a)])
    url_b = _rebuild([*other_pairs, (param, value_b)])
    url_polluted = _rebuild([*other_pairs, (param, value_a), (param, value_b)])
    return url_a, url_b, url_polluted


def build_form_body_pollution_variants(
    other_fields: dict[str, str], param: str, value_a: str, value_b: str
) -> tuple[str, str, str]:
    """Return ``(body_a, body_b, body_polluted)`` raw ``application/x-www-form-urlencoded`` bodies.

    Unlike JSON, a form-urlencoded body CAN carry the same key twice on the
    wire (``a=1&a=2``), so this is a true duplicate-key HPP probe rather than
    the array-wrapping approximation :func:`build_json_array_pollution_variants`
    has to use for JSON bodies.

    Args:
        other_fields: Every other form field to keep unchanged across all
            three variants.
        param: The field name to pollute.
        value_a: The single value for ``body_a``.
        value_b: The single value for ``body_b``.

    Returns:
        A 3-tuple of raw request bodies (strings), ready to send with
        ``Content-Type: application/x-www-form-urlencoded``.
    """
    other_pairs = list(other_fields.items())
    body_a = urlencode([*other_pairs, (param, value_a)])
    body_b = urlencode([*other_pairs, (param, value_b)])
    body_polluted = urlencode([*other_pairs, (param, value_a), (param, value_b)])
    return body_a, body_b, body_polluted


def build_json_array_pollution_variants(
    body: dict, param: str, value_a: str, value_b: str
) -> tuple[dict, dict, dict]:
    """Return ``(body_a, body_b, body_polluted)`` JSON body dicts.

    JSON objects cannot carry a duplicate key on the wire, so the practical
    equivalent HPP probe for a JSON API is "array coercion": does the backend
    accept (and how does it resolve) ``{"param": [A, B]}`` where it declared
    ``{"param": <scalar>}``? Many frameworks built on a PHP/Node query-parsing
    heritage silently coerce this to the last element, the first element, a
    concatenation, or crash — any of which is evidence worth surfacing.

    Args:
        body: The original JSON body dict. Every key other than ``param`` is
            preserved unchanged (deep-copied per variant) in all three results.
        param: The body field name to pollute.
        value_a: The single value for ``body_a``.
        value_b: The single value for ``body_b``.

    Returns:
        A 3-tuple of JSON-serializable dicts: single value A, single value B,
        and ``param`` set to ``[value_a, value_b]`` in the third.
    """
    base = {k: v for k, v in body.items() if k != param}
    body_a = {**base, param: value_a}
    body_b = {**base, param: value_b}
    body_polluted = {**base, param: [value_a, value_b]}
    return body_a, body_b, body_polluted


def classify_pollution_response(status_a: int, status_b: int, status_polluted: int) -> str | None:
    """Classify an HPP probe's three response status codes into a finding category.

    This is a conservative, status-code-only heuristic (callers with access to
    full response bodies can layer a stricter body-signature comparison on top
    before deciding whether to actually emit a finding — this function only
    flags candidates worth that closer look).

    Returns:
        ``"inconsistent_resolution"`` when the polluted request's status
            matches NEITHER single-value baseline — the backend parsed the
            duplicated/array-wrapped parameter in a way that produced a
            genuinely different outcome, not just "picked one of A or B".
        ``"bypass_via_pollution"`` when ``status_b`` alone was rejected
            (4xx/5xx) but the polluted request (which also carries ``value_b``)
            succeeded (2xx/3xx) — the duplicate/array form let an otherwise-
            rejected value through.
        ``None`` when the polluted response matches one of the two baselines
            in the ordinary way (first-value-wins or last-value-wins), which
            is expected, documented HPP-tolerant behavior, not a finding.
    """
    polluted_is_success = 200 <= status_polluted < 400
    b_is_rejected = status_b >= 400
    if b_is_rejected and polluted_is_success:
        return "bypass_via_pollution"
    if status_polluted not in (status_a, status_b):
        return "inconsistent_resolution"
    return None
