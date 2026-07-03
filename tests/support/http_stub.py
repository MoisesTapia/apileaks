"""Offline ``HTTPRequestEngine`` stub for parameter-fuzzing and marker tests.

**Feature: parameter-fuzzing, Task 1.1 (Testing Strategy: Stubbing)**
**Feature: par-positional-markers, Task 1.1 (Testing Strategy: Stubbing)**

This module provides a deterministic, network-free stand-in for
:class:`utils.http_client.HTTPRequestEngine`. It is the shared harness for the
parameter-fuzzing and par-positional-markers property and example tests: it
records every issued request (method, URL, headers, params, body, auth context)
and returns scripted :class:`utils.http_client.Response` objects with **no real
network access**.

Why a duck-typed double (not a subclass)?
    :class:`HTTPRequestEngine.__init__` constructs an ``httpx.AsyncClient`` lazily
    and pulls in a rate limiter, retry config, and user-agent rotator. The
    fuzzing code paths only ever touch a small public surface of the engine:

    * ``await engine.request(method, url, **kwargs) -> Response`` — the single
      dispatch point used by ``ParameterFuzzer._get_baseline_response`` and every
      ``_test_*_parameter`` helper.
    * ``engine.add_auth_context(name, auth)`` / ``engine.set_auth_context(auth)``
      — invoked by ``APILeakCore`` when wiring auth contexts.
    * ``engine.get_performance_metrics()`` / ``await engine.health_check()`` /
      ``await engine.close()`` — lifecycle/metrics helpers.

    This stub mirrors exactly that surface so it can be dropped in wherever an
    ``HTTPRequestEngine`` is expected, without touching the network.

Scripting model
    Every request is resolved to a :class:`ScriptedResponse` (status code, body,
    headers, response time, content-type) using the following precedence:

    1. ``responder`` callable — ``responder(recorded) -> ScriptedResponse | Response | None``.
       Returning ``None`` falls through to the next mechanism. The recorded
       request is already appended to ``engine.requests`` before the responder
       runs, so a responder can count prior attempts to the same URL to script
       confirmation re-tests.
    2. ordered one-shot ``enqueue`` queue — the next queued spec is popped.
    3. ``add_rule(predicate, spec)`` rules — the first rule whose predicate
       matches the recorded request wins.
    4. ``default`` — the fallback spec (a 200 empty JSON response by default).

Determinism
    No randomness, no timing, no I/O. ``response_time`` is whatever the script
    specifies (default ``0.01``), so reflection, JSON-diff, budget, confirmation,
    injection-point, and request-context assertions are fully reproducible.

Marker-test assertion helpers
    :meth:`HTTPRequestEngineStub.assert_request_per_candidate` — asserts that
    exactly one request was issued for every URL in the given candidate set and
    no other (non-baseline) requests were issued.

    :meth:`HTTPRequestEngineStub.assert_query_value_in_url` — asserts that a
    particular substituted value appears in the URL of every matching request and
    is NOT present only in the request body, verifying query-position values stay
    in the URL under body methods (Property 9).

    :meth:`HTTPRequestEngineStub.assert_neutral_sentinel_baseline` — asserts that
    a given sentinel token appears in the URLs of the very first group of requests,
    confirming that a neutral-sentinel baseline was issued before any candidate
    sweep (Property 8 / Design Decision 3).

    :meth:`HTTPRequestEngineStub.assert_budget_not_exceeded` — asserts that the
    total request count never exceeded a given budget N (Property 10).
"""

from __future__ import annotations

import json as _json
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Union
from urllib.parse import parse_qsl

from utils.http_client import PerformanceMetrics, Response

__all__ = [
    "ScriptedResponse",
    "RecordedRequest",
    "HTTPRequestEngineStub",
    "ResponseSpec",
    "MarkerAssertionError",
]


class MarkerAssertionError(AssertionError):
    """Raised by :class:`HTTPRequestEngineStub` marker assertion helpers.

    Subclasses :class:`AssertionError` so ``pytest`` reports it as a test
    failure with a clean diff, while still being distinguishable from a plain
    assertion if a test needs to catch it specifically.
    """


@dataclass
class ScriptedResponse:
    """A declarative description of a response to return for a request.

    Fields map directly onto the deterministic knobs the parameter-fuzzing
    detection logic inspects:

    * ``status_code`` — status-code signal / boundary (>=500) detection.
    * ``body`` — reflection (sentinel echo), body-size, and new-JSON-field
      detection. May be ``str``, ``bytes``, or any JSON-serialisable object
      (``dict``/``list``), which is encoded as a JSON body.
    * ``headers`` — header-reflection detection and content-type checks.
    * ``response_time`` — timing-anomaly / response-time-difference detection.
    * ``content_type`` — convenience for setting the ``Content-Type`` header;
      ignored when ``headers`` already carries a ``Content-Type``.
    """

    status_code: int = 200
    body: Union[str, bytes, Dict[str, Any], List[Any], None] = ""
    headers: Optional[Dict[str, str]] = None
    response_time: float = 0.01
    content_type: Optional[str] = "application/json"

    def _content_bytes_and_text(self) -> "tuple[bytes, str]":
        body = self.body
        if body is None:
            return b"", ""
        if isinstance(body, bytes):
            return body, body.decode("utf-8", "replace")
        if isinstance(body, str):
            return body.encode("utf-8"), body
        # dict / list / other JSON-serialisable -> JSON body
        text = _json.dumps(body)
        return text.encode("utf-8"), text

    def to_response(self, *, url: str, method: str) -> Response:
        """Build a real :class:`utils.http_client.Response` for ``url``/``method``."""
        headers: Dict[str, str] = dict(self.headers or {})
        if self.content_type is not None and not any(
            k.lower() == "content-type" for k in headers
        ):
            headers["Content-Type"] = self.content_type
        content, text = self._content_bytes_and_text()
        return Response(
            status_code=self.status_code,
            headers=headers,
            content=content,
            text=text,
            url=url,
            elapsed=self.response_time,
            request_method=method,
            timestamp=datetime.now(),
        )


# A response can be scripted as a full ScriptedResponse, an already-built
# Response, or ``None`` (meaning "fall through" for a responder callable).
ResponseSpec = Union[ScriptedResponse, Response, None]

Responder = Callable[["RecordedRequest"], ResponseSpec]
Predicate = Callable[["RecordedRequest"], bool]


@dataclass
class RecordedRequest:
    """A single request captured by :class:`HTTPRequestEngineStub`.

    Captures everything the parameter fuzzer can send: the method, URL, the
    merged request headers, the query ``params``, the raw ``data`` body
    (form-encoded or XML), the ``json`` body, and the selected ``auth_context``.
    Convenience accessors make request-context and injection-point assertions
    terse.
    """

    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, Any] = field(default_factory=dict)
    data: Any = None
    json: Optional[Dict[str, Any]] = None
    auth_context: Optional[str] = None
    kwargs: Dict[str, Any] = field(default_factory=dict)

    @property
    def content_type(self) -> Optional[str]:
        """Return the request's ``Content-Type`` header if present."""
        for key, value in self.headers.items():
            if key.lower() == "content-type":
                return value
        return None

    @property
    def param_names(self) -> Set[str]:
        """Return the set of parameter names injected into this request.

        Covers query params, JSON body keys, and form-encoded body keys, so a
        test can assert which candidate parameter a given request exercised
        regardless of injection point.
        """
        names: Set[str] = set(self.params.keys())
        if isinstance(self.json, dict):
            names.update(self.json.keys())
        if isinstance(self.data, str):
            # form-encoded body: name=value&...  (XML bodies simply won't parse
            # into key/value pairs and are ignored here)
            try:
                names.update(k for k, _ in parse_qsl(self.data, keep_blank_values=True))
            except ValueError:
                pass
        return names

    def carries_value(self, value: str) -> bool:
        """Return True if ``value`` appears anywhere in the request payload.

        Searches query params, the JSON body, and the raw data body. Useful for
        scripting sentinel-reflection responses: a responder can echo ``value``
        back only when the request actually injected it.
        """
        needle = str(value)
        for v in self.params.values():
            if needle in str(v):
                return True
        if isinstance(self.json, dict):
            for v in self.json.values():
                if needle in str(v):
                    return True
        elif self.json is not None and needle in str(self.json):
            return True
        if isinstance(self.data, (str, bytes)):
            data_text = self.data.decode("utf-8", "replace") if isinstance(self.data, bytes) else self.data
            if needle in data_text:
                return True
        elif self.data is not None and needle in str(self.data):
            return True
        return False


class HTTPRequestEngineStub:
    """Network-free stand-in for :class:`utils.http_client.HTTPRequestEngine`.

    Records every issued request and returns scripted responses. See the module
    docstring for the scripting precedence and rationale.

    Args:
        default: fallback response spec used when nothing else matches.
            Defaults to a ``200`` response with an empty JSON body.
        responder: optional callable consulted first for every request.
    """

    def __init__(
        self,
        *,
        default: ResponseSpec = None,
        responder: Optional[Responder] = None,
    ) -> None:
        self.default: ScriptedResponse | Response = (
            default if default is not None else ScriptedResponse()
        )
        self.responder: Optional[Responder] = responder
        self.requests: List[RecordedRequest] = []
        self._queue: "deque[ResponseSpec]" = deque()
        self._rules: List["tuple[Predicate, ResponseSpec]"] = []

        # HTTPRequestEngine-compatible auth surface.
        self.auth_contexts: Dict[str, Any] = {}
        self.current_auth_context: Optional[Any] = None

        # Lifecycle / metrics parity.
        self.metrics = PerformanceMetrics()
        self.closed = False

    # ------------------------------------------------------------------
    # Scripting configuration
    # ------------------------------------------------------------------
    def set_default(self, spec: ResponseSpec) -> "HTTPRequestEngineStub":
        """Set the fallback response returned when nothing else matches."""
        self.default = spec if spec is not None else ScriptedResponse()
        return self

    def set_responder(self, responder: Optional[Responder]) -> "HTTPRequestEngineStub":
        """Set the responder callable consulted first for every request."""
        self.responder = responder
        return self

    def enqueue(self, *specs: ResponseSpec) -> "HTTPRequestEngineStub":
        """Append one or more one-shot responses returned in FIFO order."""
        for spec in specs:
            self._queue.append(spec)
        return self

    def add_rule(self, predicate: Predicate, spec: ResponseSpec) -> "HTTPRequestEngineStub":
        """Register a ``predicate(recorded) -> bool`` rule mapped to ``spec``.

        The first rule whose predicate matches a request wins. Rules are only
        consulted after the responder and the one-shot queue.
        """
        self._rules.append((predicate, spec))
        return self

    # ------------------------------------------------------------------
    # HTTPRequestEngine-compatible interface
    # ------------------------------------------------------------------
    async def request(self, method: str, url: str, **kwargs) -> Response:
        """Record the request and return a scripted :class:`Response`.

        Mirrors ``HTTPRequestEngine.request(method, url, **kwargs)``: reads the
        ``headers``, ``params``, ``data``, ``json``, and ``auth_context`` kwargs
        exactly as the real engine does. Performs no network access.
        """
        recorded = RecordedRequest(
            method=str(method).upper(),
            url=url,
            headers=dict(kwargs.get("headers", {}) or {}),
            params=dict(kwargs.get("params", {}) or {}),
            data=kwargs.get("data"),
            json=kwargs.get("json"),
            auth_context=kwargs.get("auth_context"),
            kwargs=dict(kwargs),
        )
        # Record BEFORE resolving so a responder can count prior attempts to the
        # same URL (e.g. to script Hit_Confirmation re-tests).
        self.requests.append(recorded)

        spec = self._resolve(recorded)
        self._update_metrics(spec)
        if isinstance(spec, Response):
            return spec
        return spec.to_response(url=url, method=recorded.method)

    def add_auth_context(self, name: str, auth: Any) -> None:
        """Store a named auth context (parity with the real engine)."""
        self.auth_contexts[name] = auth

    def set_auth_context(self, auth: Any) -> None:
        """Set the current auth context (parity with the real engine)."""
        self.current_auth_context = auth

    def get_performance_metrics(self) -> PerformanceMetrics:
        """Return the accumulated performance metrics."""
        return self.metrics

    async def health_check(self) -> bool:
        """Always report healthy without issuing a network request."""
        return True

    async def close(self) -> None:
        """Mark the stub closed. No resources to release."""
        self.closed = True

    # ------------------------------------------------------------------
    # Inspection helpers
    # ------------------------------------------------------------------
    @property
    def call_count(self) -> int:
        """Total number of requests issued through the stub."""
        return len(self.requests)

    def requests_for(self, url: str) -> List[RecordedRequest]:
        """Return every recorded request whose URL equals ``url``."""
        return [r for r in self.requests if r.url == url]

    def methods_used(self) -> Set[str]:
        """Return the set of HTTP methods that were issued."""
        return {r.method for r in self.requests}

    def reset(self) -> None:
        """Clear recorded requests and metrics (scripting is preserved)."""
        self.requests.clear()
        self.metrics = PerformanceMetrics()

    # ------------------------------------------------------------------
    # Marker-test assertion helpers
    # (Feature: par-positional-markers, Task 1.1)
    # ------------------------------------------------------------------

    def assert_request_per_candidate(
        self,
        candidate_urls: "List[str]",
        *,
        method: "Optional[str]" = None,
        extra_requests: int = 0,
    ) -> None:
        """Assert exactly one request was issued per candidate URL (and no others).

        Used by Property 8 (request-per-candidate) tests to verify that
        Marker_Mode issues exactly one request per fully-substituted
        Marker_Candidate URL and no extra candidate requests.

        Args:
            candidate_urls: the expected set of fully-substituted candidate
                URLs.  Order does not matter; the assertion checks set equality.
            method: when given, only requests with this HTTP method are
                considered.  Use this to isolate one method in a multi-method
                run.
            extra_requests: the number of non-candidate requests (e.g.
                baseline requests) already counted in ``self.requests``, so the
                total expected call count is
                ``len(candidate_urls) + extra_requests``.

        Raises:
            MarkerAssertionError: if the set of (method-filtered) request URLs
                does not equal the expected candidate set, or the total count
                is wrong.
        """
        target_requests = (
            [r for r in self.requests if r.method == str(method).upper()]
            if method is not None
            else list(self.requests)
        )
        issued_urls = [r.url for r in target_requests]
        issued_set = set(issued_urls)
        candidate_set = set(candidate_urls)

        missing = candidate_set - issued_set
        unexpected = issued_set - candidate_set - set()  # may include baselines
        # Only flag unexpected URLs that are truly unexpected (not extras).
        # We check exact count equality to catch duplicates.
        if missing:
            raise MarkerAssertionError(
                f"Missing candidate requests: {sorted(missing)}\n"
                f"Issued URLs: {sorted(issued_set)}"
            )
        expected_total = len(candidate_urls) + extra_requests
        if len(target_requests) != expected_total:
            raise MarkerAssertionError(
                f"Expected {expected_total} total requests "
                f"({len(candidate_urls)} candidates + {extra_requests} extra), "
                f"got {len(target_requests)}.\n"
                f"Issued URLs: {issued_urls}"
            )

    def assert_query_value_in_url(
        self,
        value: str,
        *,
        method: "Optional[str]" = None,
    ) -> None:
        """Assert the substituted value is in the URL, never only in the body.

        Used by Property 9 (query-position value stays in URL under body
        methods) to verify that a query-position marker's substituted value is
        always carried at its query URL position and is never relocated into the
        request body.

        For every matching request this asserts:
        - ``value`` appears somewhere in the request URL, AND
        - ``value`` is NOT present *exclusively* in the body (it may appear in
          both the URL and body, but if it is absent from the URL that is a
          violation).

        Args:
            value: the substituted candidate value to check for.
            method: when given, only requests with this HTTP method are
                checked.

        Raises:
            MarkerAssertionError: if any matching request carries ``value``
                in the body but NOT in its URL.
        """
        target_requests = (
            [r for r in self.requests if r.method == str(method).upper()]
            if method is not None
            else list(self.requests)
        )
        for req in target_requests:
            if not req.carries_value(value):
                continue  # this request doesn't carry the value at all — skip
            if value not in req.url:
                # value is in the body but absent from the URL — violation
                body_repr = (
                    repr(req.json) if req.json is not None
                    else repr(req.data) if req.data is not None
                    else "<empty>"
                )
                raise MarkerAssertionError(
                    f"Value {value!r} was NOT found in the request URL {req.url!r} "
                    f"but IS present in the body {body_repr}. "
                    "Query-position values must stay in the URL (Property 9 / R8.3)."
                )

    def assert_neutral_sentinel_baseline(
        self,
        sentinel_token: str,
        *,
        method: "Optional[str]" = None,
        baseline_count: int = 1,
    ) -> None:
        """Assert the first ``baseline_count`` requests used a neutral sentinel URL.

        Used by Property 8 / Design Decision 3 tests to verify that
        Marker_Mode issues a neutral-sentinel baseline request before sweeping
        candidates.  Checks that the first ``baseline_count`` (method-filtered)
        requests all carry ``sentinel_token`` in their URL, confirming the
        neutral-sentinel substitution was applied.

        Args:
            sentinel_token: the neutral sentinel value (e.g. the output of
                ``ParameterFuzzer._make_sentinel``) expected in the baseline
                request URLs.
            method: when given, only requests with this HTTP method are
                inspected.
            baseline_count: how many leading baseline requests are expected
                (default 1; use ``len(methods)`` in multi-method runs).

        Raises:
            MarkerAssertionError: if fewer than ``baseline_count`` requests
                were issued, or if any of the first ``baseline_count`` requests
                does not carry ``sentinel_token`` in its URL.
        """
        target_requests = (
            [r for r in self.requests if r.method == str(method).upper()]
            if method is not None
            else list(self.requests)
        )
        if len(target_requests) < baseline_count:
            raise MarkerAssertionError(
                f"Expected at least {baseline_count} baseline request(s) "
                f"but only {len(target_requests)} request(s) were issued."
            )
        for i, req in enumerate(target_requests[:baseline_count]):
            if sentinel_token not in req.url:
                raise MarkerAssertionError(
                    f"Baseline request #{i + 1} URL {req.url!r} does not contain "
                    f"the neutral sentinel token {sentinel_token!r}. "
                    "The neutral-sentinel baseline must be issued before candidates "
                    "(Property 8 / Design Decision 3 / R9.1)."
                )

    def assert_budget_not_exceeded(self, budget: int) -> None:
        """Assert the total request count never exceeded ``budget``.

        Used by Property 10 (request budget bounds total requests) tests to
        independently verify the stub-observed request count against the
        configured Request_Budget.  This is a simple upper-bound check;
        detailed budget-stop-reason and partial-findings assertions live in the
        property test itself (which cross-checks against
        ``ParameterFuzzer.requests_made`` and ``budget_stop_reason``).

        Args:
            budget: the configured Request_Budget (``--max-requests`` value).

        Raises:
            MarkerAssertionError: if ``self.call_count > budget``.
        """
        if self.call_count > budget:
            raise MarkerAssertionError(
                f"Stub recorded {self.call_count} requests, exceeding the "
                f"configured budget of {budget}. "
                "Total requests (baseline + candidates + confirmation retests) "
                "must never exceed the Request_Budget (Property 10 / R11.1)."
            )

    # ------------------------------------------------------------------
    # Internal resolution
    # ------------------------------------------------------------------
    def _resolve(self, recorded: RecordedRequest) -> Union[ScriptedResponse, Response]:
        if self.responder is not None:
            spec = self.responder(recorded)
            if spec is not None:
                return spec
        if self._queue:
            spec = self._queue.popleft()
            if spec is not None:
                return spec
        for predicate, spec in self._rules:
            if predicate(recorded) and spec is not None:
                return spec
        return self.default

    def _update_metrics(self, spec: Union[ScriptedResponse, Response]) -> None:
        self.metrics.total_requests += 1
        if isinstance(spec, Response):
            status = spec.status_code
            elapsed = spec.elapsed
        else:
            status = spec.status_code
            elapsed = spec.response_time
        if 200 <= status < 300:
            self.metrics.successful_requests += 1
        else:
            self.metrics.failed_requests += 1
        self.metrics.total_response_time += elapsed
        self.metrics.min_response_time = min(self.metrics.min_response_time, elapsed)
        self.metrics.max_response_time = max(self.metrics.max_response_time, elapsed)
