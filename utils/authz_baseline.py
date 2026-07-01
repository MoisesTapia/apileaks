"""
Authorization Baseline Helpers

Shared, cross-cutting building blocks reused by the BOLA module (OWASP API1)
and the Property-Level module (OWASP API3) to make authorization decisions
*identity-based* and *negative-control calibrated* rather than relying on
response-size or word-similarity heuristics.

This module provides:

* ``IDENTIFYING_FIELD_NAMES`` - the recognized field names whose values
  identify an object or its owner (Requirements 2, 4.4).
* ``NegativeControlBaseline`` - a reference response captured for a known-invalid
  or nonexistent identifier, used to distinguish a genuinely accessible object
  from a generic success response (Requirement 3, 25).
* ``extract_identifying_fields`` - parse a JSON body and return the recognized
  Identifying_Fields it exposes (Requirements 2.1, 4.4).
* ``responses_identify_same_object`` - decide whether two responses describe the
  same object by comparing Identifying_Field values, never size/similarity
  (Requirement 2).
* ``responses_equivalent`` - compare a candidate response to a
  ``NegativeControlBaseline`` independent of any fixed byte threshold
  (Requirements 3.5, 25.2).
* ``NegativeControlMixin`` - an async helper mixin that issues the known-invalid
  request under the same auth context and builds the baseline, flagging
  non-discriminating endpoints (Requirements 3.4, 25.3).

Design principle: non-JSON / unparseable bodies degrade gracefully to
"no identifying field" / "not accessible" rather than raising.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from utils.http_client import Response


# Field names whose values identify an object or its owner (Requirement 2,
# Requirement 4.4). Matching is performed case-insensitively against response
# body keys; both snake_case and camelCase spellings are listed so either is
# recognized.
IDENTIFYING_FIELD_NAMES: List[str] = [
    "id",
    "user_id",
    "userId",
    "owner_id",
    "ownerId",
    "account_id",
    "accountId",
    "email",
    "uuid",
    "guid",
]

# Pre-computed lowercase lookup so extraction is a cheap membership test that
# tolerates differing key casing across responses.
_RECOGNIZED_LOWER = {name.lower() for name in IDENTIFYING_FIELD_NAMES}


@dataclass
class NegativeControlBaseline:
    """Reference response for a known-invalid/nonexistent id or unauth request.

    Captured by :meth:`NegativeControlMixin.build_negative_control` and consumed
    by accessibility decisions. ``non_discriminating`` is ``True`` when the
    known-invalid request itself returned a success status, meaning the endpoint
    answers successfully for any input and therefore cannot be used to decide
    accessibility (Requirements 3.4, 25.3).
    """

    status_code: int
    identifying_fields: Dict[str, Any] = field(default_factory=dict)
    content_length: int = 0
    is_success: bool = False
    non_discriminating: bool = False


def _parse_json_body(response: Optional[Response]) -> Any:
    """Best-effort parse of a response body into a Python object.

    Returns the decoded JSON value, or ``None`` when the body is absent, not
    JSON, or otherwise unparseable. Never raises (Requirements 2.1, 4.4) so
    callers degrade to "no identifying field".
    """
    if response is None:
        return None

    text = getattr(response, "text", None)
    if not text:
        return None

    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _scalar_equal(a: Any, b: Any) -> bool:
    """Compare two scalar Identifying_Field values for equality.

    Booleans are treated as distinct from integers so that ``True`` does not
    spuriously equal ``1``. Only direct equality is used; no size, length, or
    similarity heuristic is involved (Requirement 2.4).
    """
    if isinstance(a, bool) != isinstance(b, bool):
        return False
    return a == b


def extract_identifying_fields(response: Optional[Response]) -> Dict[str, Any]:
    """Return the recognized Identifying_Fields exposed by a response body.

    The JSON body is parsed and searched at the top level; when the top level is
    a list, the first object inside the list is inspected. Recognized fields are
    matched case-insensitively against :data:`IDENTIFYING_FIELD_NAMES` and keyed
    in the result by their lowercase canonical name so that values can be
    compared reliably across responses regardless of key casing.

    Returns an empty dict when the body is not JSON or contains no recognized
    Identifying_Field. Non-JSON / unparseable bodies degrade to ``{}`` rather
    than raising (Requirements 2.1, 4.4).
    """
    body = _parse_json_body(response)

    obj: Optional[Dict[str, Any]] = None
    if isinstance(body, dict):
        obj = body
    elif isinstance(body, list):
        # Inspect the first object inside a top-level list.
        for item in body:
            if isinstance(item, dict):
                obj = item
                break

    if not isinstance(obj, dict):
        return {}

    fields: Dict[str, Any] = {}
    for key, value in obj.items():
        if not isinstance(key, str):
            continue
        if key.lower() not in _RECOGNIZED_LOWER:
            continue
        # Only scalar values can serve as identity values; skip nested
        # objects/arrays and nulls.
        if value is None or isinstance(value, (dict, list)):
            continue
        fields[key.lower()] = value

    return fields


def responses_identify_same_object(
    r1: Optional[Response], r2: Optional[Response]
) -> Tuple[bool, Optional[str], Optional[Any]]:
    """Decide whether two responses describe the same object by identity.

    Returns ``(same, field_name, value)``. ``same`` is ``True`` only when both
    responses expose a recognized Identifying_Field sharing an EQUAL value; the
    matching field name and value are returned for use as finding evidence
    (Requirement 2.3). The decision never considers response size or word
    similarity (Requirement 2.4). When either response exposes no
    Identifying_Field - including non-JSON bodies - the result is
    ``(False, None, None)`` (Requirement 2.4).
    """
    fields1 = extract_identifying_fields(r1)
    fields2 = extract_identifying_fields(r2)

    if not fields1 or not fields2:
        return (False, None, None)

    for name, value in fields1.items():
        if name in fields2 and _scalar_equal(fields2[name], value):
            return (True, name, value)

    return (False, None, None)


def responses_equivalent(candidate: Optional[Response], baseline: NegativeControlBaseline) -> bool:
    """Compare a candidate response to a ``NegativeControlBaseline``.

    The candidate is considered equivalent to the baseline when their status
    classes match AND the candidate exposes no Identifying_Field that is
    distinct from the baseline's (i.e. a recognized field absent from the
    baseline, or present with a different value). This comparison is independent
    of any fixed byte threshold (Requirements 3.5, 25.2).

    A candidate that is equivalent to the baseline has not surfaced any real,
    distinct identifying data and is therefore treated as "not accessible";
    a candidate that is NOT equivalent has exposed distinct identifying data and
    is treated as "accessible" (Requirements 3.2, 3.3).
    """
    if candidate is None:
        return True

    # Status class comparison (2xx, 4xx, ...) rather than exact code equality.
    if (candidate.status_code // 100) != (baseline.status_code // 100):
        return False

    candidate_fields = extract_identifying_fields(candidate)
    baseline_fields = baseline.identifying_fields or {}

    for name, value in candidate_fields.items():
        if name not in baseline_fields:
            # The candidate surfaced an identifying field the baseline lacks.
            return False
        if not _scalar_equal(baseline_fields[name], value):
            # Same field, different identity value -> distinct object.
            return False

    return True


class NegativeControlMixin:
    """Mixin providing the negative-control baseline build step.

    The consuming class is expected to expose ``self.http_client`` (an
    ``HTTPRequestEngine``) and a structured ``self.logger`` (created via
    :func:`core.logging.get_logger`). Reused by the BOLA and Property-Level
    modules so accessibility decisions share one implementation.
    """

    async def build_negative_control(
        self,
        endpoint: str,
        auth_context: Any = None,
        invalid_id: str = "0",
        substitute: Optional[Callable[[str], str]] = None,
    ) -> NegativeControlBaseline:
        """Capture a ``NegativeControlBaseline`` for ``endpoint``.

        Issues a single GET for a known-invalid / nonexistent identifier under
        the SAME auth context that will be used for the real probes
        (Requirement 3.1). When ``substitute`` is supplied it is called with
        ``invalid_id`` to build the target URL so the invalid id is placed at
        the correct path segment or query parameter; otherwise ``endpoint`` is
        requested as-is.

        The returned baseline is flagged ``non_discriminating`` when the
        invalid-id request itself returns a success status, signalling that the
        endpoint answers successfully for any input and accessibility findings
        must be suppressed for it (Requirements 3.4, 25.3).
        """
        if auth_context is not None:
            self.http_client.set_auth_context(auth_context)

        if substitute is not None:
            test_url = substitute(invalid_id)
        else:
            test_url = endpoint

        response = await self.http_client.request("GET", test_url)

        identifying_fields = extract_identifying_fields(response)
        content_length = len(response.content) if getattr(response, "content", None) else 0
        is_success = 200 <= response.status_code < 300

        baseline = NegativeControlBaseline(
            status_code=response.status_code,
            identifying_fields=identifying_fields,
            content_length=content_length,
            is_success=is_success,
            non_discriminating=is_success,
        )

        logger = getattr(self, "logger", None)
        if logger is not None:
            if baseline.non_discriminating:
                logger.info(
                    "Negative-control baseline is non-discriminating; "
                    "endpoint returns success for an invalid id",
                    endpoint=endpoint,
                    invalid_id=invalid_id,
                    status_code=baseline.status_code,
                )
            else:
                logger.debug(
                    "Negative-control baseline captured",
                    endpoint=endpoint,
                    invalid_id=invalid_id,
                    status_code=baseline.status_code,
                    identifying_fields=list(baseline.identifying_fields.keys()),
                )

        return baseline
