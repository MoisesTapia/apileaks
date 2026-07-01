"""
Unit Tests for the Authorization Baseline Helpers

**Feature: owasp-auth-modules-hardening**

Covers the identity-based / negative-control-calibrated accessibility helpers
in ``utils.authz_baseline`` that the BOLA (API1) and Property-Level (API3)
modules share:

* ``responses_equivalent`` - a candidate response is equivalent to a captured
  ``NegativeControlBaseline`` when their status CLASSES match AND the candidate
  exposes no Identifying_Field distinct from the baseline's, independent of any
  byte threshold (Requirements 3.2, 3.3, 25.2).
* ``NegativeControlMixin.build_negative_control`` - issues the known-invalid
  request under the supplied auth context and flags ``non_discriminating`` when
  that request itself returns a success status (Requirements 3.4, 25.3).

These are plain example-based unit tests (not property-based) using pytest and
the ``@pytest.mark.asyncio`` marker style established across the test suite.
"""

import json

import pytest

from utils.authz_baseline import (
    NegativeControlBaseline,
    NegativeControlMixin,
    responses_equivalent,
)
from utils.http_client import Response


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _make_response(status_code: int, body=None, *, url: str = "https://api.test/resource") -> Response:
    """Construct a real :class:`utils.http_client.Response` for a test.

    ``body`` may be a Python object (serialized to JSON), a raw string, or
    ``None`` for an empty body. ``content``/``text`` are populated consistently
    so ``responses_equivalent`` and ``extract_identifying_fields`` see the same
    payload a live response would carry.
    """
    if body is None:
        text = ""
    elif isinstance(body, str):
        text = body
    else:
        text = json.dumps(body)

    return Response(
        status_code=status_code,
        headers={"Content-Type": "application/json"},
        content=text.encode("utf-8"),
        text=text,
        url=url,
        elapsed=0.01,
        request_method="GET",
    )


class _StubLogger:
    """Minimal structured-logger stand-in accepting info/debug with kwargs."""

    def __init__(self):
        self.info_calls = []
        self.debug_calls = []

    def info(self, message, **kwargs):
        self.info_calls.append((message, kwargs))

    def debug(self, message, **kwargs):
        self.debug_calls.append((message, kwargs))


class _FakeHTTPClient:
    """Async HTTP client double exposing ``request`` and ``set_auth_context``.

    Records the auth context it was given and the (method, url) it was asked to
    fetch, and returns a pre-configured :class:`Response`.
    """

    def __init__(self, response: Response):
        self._response = response
        self.auth_context_calls = []
        self.requests = []

    def set_auth_context(self, auth_context):
        self.auth_context_calls.append(auth_context)

    async def request(self, method: str, url: str, **kwargs) -> Response:
        self.requests.append((method, url))
        return self._response


class _Probe(NegativeControlMixin):
    """Concrete consumer mixing in NegativeControlMixin with the expected attrs."""

    def __init__(self, http_client, logger=None):
        self.http_client = http_client
        self.logger = logger


# ---------------------------------------------------------------------------
# responses_equivalent (Requirements 3.2, 3.3, 25.2)
# ---------------------------------------------------------------------------


def test_equivalent_when_same_status_class_and_no_distinct_field():
    """
    **Validates: Requirements 3.2, 3.3**

    A candidate sharing the baseline's status class and exposing no
    Identifying_Field distinct from the baseline's is equivalent (True),
    meaning the object is NOT accessible.
    """
    baseline = NegativeControlBaseline(
        status_code=200,
        identifying_fields={"id": 0},
        content_length=12,
        is_success=True,
        non_discriminating=True,
    )
    candidate = _make_response(200, {"id": 0})

    assert responses_equivalent(candidate, baseline) is True


def test_not_equivalent_when_candidate_exposes_field_absent_from_baseline():
    """
    **Validates: Requirements 3.2, 25.2**

    A candidate exposing a recognized Identifying_Field the baseline lacks is
    NOT equivalent (False) -> a distinct object was surfaced (accessible).
    """
    baseline = NegativeControlBaseline(
        status_code=200,
        identifying_fields={},
        content_length=2,
        is_success=True,
    )
    candidate = _make_response(200, {"id": 42})

    assert responses_equivalent(candidate, baseline) is False


def test_not_equivalent_when_same_field_different_value():
    """
    **Validates: Requirements 3.2, 3.3**

    A candidate exposing the SAME field name with a DIFFERENT value than the
    baseline identifies a distinct object and is NOT equivalent (False).
    """
    baseline = NegativeControlBaseline(
        status_code=200,
        identifying_fields={"id": 0},
        content_length=12,
        is_success=True,
    )
    candidate = _make_response(200, {"id": 99})

    assert responses_equivalent(candidate, baseline) is False


def test_not_equivalent_when_status_class_differs():
    """
    **Validates: Requirement 3.3**

    A candidate whose status class differs from the baseline (200 vs 404) is
    NOT equivalent (False) regardless of body contents.
    """
    baseline = NegativeControlBaseline(
        status_code=404,
        identifying_fields={},
        content_length=0,
        is_success=False,
    )
    candidate = _make_response(200, {"id": 0})

    assert responses_equivalent(candidate, baseline) is False


def test_equivalence_is_independent_of_byte_threshold():
    """
    **Validates: Requirement 25.2**

    A candidate with a much larger body but matching status class and no
    distinct Identifying_Field is still equivalent (True): the decision never
    relies on a fixed byte/size threshold.
    """
    baseline = NegativeControlBaseline(
        status_code=200,
        identifying_fields={},
        content_length=2,
        is_success=True,
    )
    # Large body, but it carries NO recognized identifying field.
    large_body = {"message": "ok", "details": "x" * 5000, "items": list(range(100))}
    candidate = _make_response(200, large_body)

    assert len(candidate.content) > 5000
    assert responses_equivalent(candidate, baseline) is True


def test_smaller_body_without_distinct_field_is_still_equivalent():
    """
    **Validates: Requirement 25.2**

    The mirror case: a candidate whose body is much smaller than the baseline's
    captured ``content_length`` is still equivalent when the status class
    matches and no distinct identifying field is present.
    """
    baseline = NegativeControlBaseline(
        status_code=200,
        identifying_fields={},
        content_length=10000,  # baseline had a large body
        is_success=True,
    )
    candidate = _make_response(200, {})  # tiny body, no identifying field

    assert responses_equivalent(candidate, baseline) is True


# ---------------------------------------------------------------------------
# build_negative_control non-discriminating detection (Requirements 3.4, 25.3)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_build_negative_control_flags_non_discriminating_on_2xx():
    """
    **Validates: Requirements 3.4, 25.3**

    When the invalid-id request returns a 2xx success, the captured baseline is
    flagged ``non_discriminating`` (the endpoint answers successfully for any
    input and cannot be used to decide accessibility).
    """
    response = _make_response(200, {"id": 0, "name": "anything"})
    client = _FakeHTTPClient(response)
    logger = _StubLogger()
    probe = _Probe(client, logger)

    baseline = await probe.build_negative_control("https://api.test/users/0")

    assert baseline.non_discriminating is True
    assert baseline.is_success is True
    assert baseline.status_code == 200
    # The endpoint was probed exactly once with GET.
    assert client.requests == [("GET", "https://api.test/users/0")]
    # A non-discriminating baseline is surfaced at info level.
    assert len(logger.info_calls) == 1


@pytest.mark.asyncio
async def test_build_negative_control_discriminating_on_4xx():
    """
    **Validates: Requirements 3.4, 25.3**

    When the invalid-id request returns a 4xx (404), the baseline is
    discriminating (``non_discriminating`` False) and its ``status_code`` /
    ``identifying_fields`` reflect the captured response.
    """
    response = _make_response(404, {"error": "not found"})
    client = _FakeHTTPClient(response)
    logger = _StubLogger()
    probe = _Probe(client, logger)

    baseline = await probe.build_negative_control("https://api.test/users/0")

    assert baseline.non_discriminating is False
    assert baseline.is_success is False
    assert baseline.status_code == 404
    # "error" is not a recognized Identifying_Field, so none are captured.
    assert baseline.identifying_fields == {}
    # A discriminating baseline is logged at debug level, not info.
    assert logger.info_calls == []
    assert len(logger.debug_calls) == 1


@pytest.mark.asyncio
async def test_build_negative_control_captures_identifying_fields_on_4xx_body():
    """
    **Validates: Requirement 3.4**

    Recognized Identifying_Fields present in the invalid-id response body are
    captured into the baseline (keyed by canonical lowercase name).
    """
    response = _make_response(404, {"id": 0, "owner_id": 7})
    client = _FakeHTTPClient(response)
    probe = _Probe(client, _StubLogger())

    baseline = await probe.build_negative_control("https://api.test/users/0")

    assert baseline.identifying_fields == {"id": 0, "owner_id": 7}


@pytest.mark.asyncio
async def test_build_negative_control_uses_substitute_and_auth_context():
    """
    **Validates: Requirements 3.1, 3.4**

    When a ``substitute`` callable is supplied it builds the target URL from the
    invalid id, and the supplied ``auth_context`` is applied via
    ``set_auth_context`` before the probe is issued.
    """
    response = _make_response(404, {"error": "not found"})
    client = _FakeHTTPClient(response)
    probe = _Probe(client, _StubLogger())

    auth_context = object()  # opaque sentinel; only identity matters here

    def substitute(invalid_id):
        return f"https://api.test/users/{invalid_id}/profile"

    baseline = await probe.build_negative_control(
        "https://api.test/users/{id}/profile",
        auth_context=auth_context,
        invalid_id="0",
        substitute=substitute,
    )

    # The substitute callable determined the probed URL.
    assert client.requests == [("GET", "https://api.test/users/0/profile")]
    # The supplied auth context was applied before probing.
    assert client.auth_context_calls == [auth_context]
    assert baseline.status_code == 404


@pytest.mark.asyncio
async def test_build_negative_control_skips_auth_context_when_none():
    """
    **Validates: Requirement 3.1**

    With no auth context supplied, ``set_auth_context`` is not called and the
    endpoint is requested as-is.
    """
    response = _make_response(404, {"error": "not found"})
    client = _FakeHTTPClient(response)
    probe = _Probe(client, _StubLogger())

    await probe.build_negative_control("https://api.test/users/0")

    assert client.auth_context_calls == []
    assert client.requests == [("GET", "https://api.test/users/0")]
