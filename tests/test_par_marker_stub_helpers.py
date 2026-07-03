"""Smoke tests for the marker-test assertion helpers added to HTTPRequestEngineStub.

**Feature: par-positional-markers, Task 1.1**

These tests confirm the four new marker-specific helpers on
:class:`tests.support.http_stub.HTTPRequestEngineStub` are functional and
report failures correctly.  They are *unit tests of the test helper itself* —
not of the production fuzzing code — so they can run fully offline with no
real network access and no fuzzer wiring.

Helpers verified:
  * ``assert_request_per_candidate``  — Property 8 / R12.1
  * ``assert_query_value_in_url``     — Property 9 / R8.3
  * ``assert_neutral_sentinel_baseline`` — Property 8 / Design Decision 3
  * ``assert_budget_not_exceeded``    — Property 10 / R11.1
"""

from __future__ import annotations

import asyncio

import pytest

from tests.support.http_stub import (
    HTTPRequestEngineStub,
    MarkerAssertionError,
    ScriptedResponse,
)


# ---------------------------------------------------------------------------
# Helpers to issue real async requests through the stub
# ---------------------------------------------------------------------------

def _issue(stub: HTTPRequestEngineStub, method: str, url: str, **kwargs) -> None:
    """Issue a single request through the stub (synchronous wrapper)."""
    asyncio.run(stub.request(method, url, **kwargs))


# ===========================================================================
# assert_request_per_candidate
# ===========================================================================

class TestAssertRequestPerCandidate:
    def test_passes_when_exact_candidates_issued(self):
        stub = HTTPRequestEngineStub()
        urls = [
            "https://api.example.com/?id=1",
            "https://api.example.com/?id=2",
            "https://api.example.com/?id=3",
        ]
        for url in urls:
            _issue(stub, "GET", url)

        stub.assert_request_per_candidate(urls)

    def test_passes_with_extra_baseline_requests_counted(self):
        stub = HTTPRequestEngineStub()
        baseline = "https://api.example.com/?id=SENTINEL_XYZ"
        candidates = [
            "https://api.example.com/?id=foo",
            "https://api.example.com/?id=bar",
        ]
        _issue(stub, "GET", baseline)
        for url in candidates:
            _issue(stub, "GET", url)

        # extra_requests=1 accounts for the baseline
        stub.assert_request_per_candidate(candidates, extra_requests=1)

    def test_passes_when_method_filter_isolates_subset(self):
        stub = HTTPRequestEngineStub()
        _issue(stub, "GET", "https://api.example.com/?id=1")
        _issue(stub, "POST", "https://api.example.com/?id=1")

        stub.assert_request_per_candidate(
            ["https://api.example.com/?id=1"], method="GET"
        )
        stub.assert_request_per_candidate(
            ["https://api.example.com/?id=1"], method="POST"
        )

    def test_fails_when_candidate_is_missing(self):
        stub = HTTPRequestEngineStub()
        _issue(stub, "GET", "https://api.example.com/?id=1")

        with pytest.raises(MarkerAssertionError, match="Missing candidate"):
            stub.assert_request_per_candidate(
                [
                    "https://api.example.com/?id=1",
                    "https://api.example.com/?id=2",  # never issued
                ]
            )

    def test_fails_when_count_is_too_high(self):
        stub = HTTPRequestEngineStub()
        url = "https://api.example.com/?id=1"
        _issue(stub, "GET", url)
        _issue(stub, "GET", url)  # duplicate

        with pytest.raises(MarkerAssertionError, match="Expected 1 total"):
            stub.assert_request_per_candidate([url])

    def test_empty_candidate_list_with_no_requests_passes(self):
        stub = HTTPRequestEngineStub()
        stub.assert_request_per_candidate([])

    def test_empty_candidate_list_with_extra_baseline_passes(self):
        stub = HTTPRequestEngineStub()
        _issue(stub, "GET", "https://api.example.com/?id=BASELINE")
        stub.assert_request_per_candidate([], extra_requests=1)


# ===========================================================================
# assert_query_value_in_url
# ===========================================================================

class TestAssertQueryValueInUrl:
    def test_passes_when_value_in_url(self):
        stub = HTTPRequestEngineStub()
        # Value in query string of the URL
        _issue(stub, "POST", "https://api.example.com/?id=secret99")
        stub.assert_query_value_in_url("secret99")

    def test_passes_when_value_in_url_and_also_in_body(self):
        """If value appears in BOTH URL and body, the assertion still passes."""
        stub = HTTPRequestEngineStub()
        _issue(
            stub,
            "POST",
            "https://api.example.com/?id=secret99",
            json={"id": "secret99"},
        )
        stub.assert_query_value_in_url("secret99")

    def test_passes_for_requests_not_carrying_value(self):
        """Requests that don't carry the value at all are silently skipped."""
        stub = HTTPRequestEngineStub()
        _issue(stub, "POST", "https://api.example.com/", json={"x": "other"})
        stub.assert_query_value_in_url("secret99")

    def test_fails_when_value_in_body_but_not_url(self):
        stub = HTTPRequestEngineStub()
        # Value appears ONLY in the JSON body — not in the URL
        _issue(
            stub,
            "POST",
            "https://api.example.com/resource",
            json={"id": "secret99"},
        )
        with pytest.raises(MarkerAssertionError, match="NOT found in the request URL"):
            stub.assert_query_value_in_url("secret99")

    def test_fails_when_value_in_form_body_but_not_url(self):
        stub = HTTPRequestEngineStub()
        _issue(
            stub,
            "POST",
            "https://api.example.com/resource",
            data="id=secret99",
        )
        with pytest.raises(MarkerAssertionError, match="NOT found in the request URL"):
            stub.assert_query_value_in_url("secret99")

    def test_method_filter_only_checks_matching_requests(self):
        stub = HTTPRequestEngineStub()
        # POST carries value in body only (would fail for POST, but we filter to GET)
        _issue(
            stub,
            "POST",
            "https://api.example.com/resource",
            json={"id": "secret99"},
        )
        # GET carries value in URL (fine)
        _issue(stub, "GET", "https://api.example.com/?id=secret99")
        # Only checking GET — POST violation is ignored
        stub.assert_query_value_in_url("secret99", method="GET")


# ===========================================================================
# assert_neutral_sentinel_baseline
# ===========================================================================

class TestAssertNeutralSentinelBaseline:
    def test_passes_when_first_request_contains_sentinel(self):
        stub = HTTPRequestEngineStub()
        sentinel = "ABCD1234EFGH5678"
        _issue(stub, "GET", f"https://api.example.com/?id={sentinel}")
        _issue(stub, "GET", "https://api.example.com/?id=candidate1")

        stub.assert_neutral_sentinel_baseline(sentinel)

    def test_passes_with_multiple_baseline_requests(self):
        stub = HTTPRequestEngineStub()
        sentinel = "XYZSENTINEL"
        # Two baseline requests (one per method)
        _issue(stub, "GET", f"https://api.example.com/?id={sentinel}")
        _issue(stub, "POST", f"https://api.example.com/?id={sentinel}")
        _issue(stub, "GET", "https://api.example.com/?id=candidate1")

        stub.assert_neutral_sentinel_baseline(sentinel, baseline_count=2)

    def test_passes_with_method_filter(self):
        stub = HTTPRequestEngineStub()
        sentinel = "TESTSENTINEL"
        _issue(stub, "GET", f"https://api.example.com/?id={sentinel}")
        _issue(stub, "POST", "https://api.example.com/?id=candidate")

        stub.assert_neutral_sentinel_baseline(sentinel, method="GET")

    def test_fails_when_first_request_missing_sentinel(self):
        stub = HTTPRequestEngineStub()
        sentinel = "EXPECTEDSENTINEL"
        # First request does NOT contain sentinel — it went straight to a candidate
        _issue(stub, "GET", "https://api.example.com/?id=candidate1")
        _issue(stub, "GET", f"https://api.example.com/?id={sentinel}")

        with pytest.raises(MarkerAssertionError, match="does not contain"):
            stub.assert_neutral_sentinel_baseline(sentinel)

    def test_fails_when_no_requests_issued(self):
        stub = HTTPRequestEngineStub()
        with pytest.raises(MarkerAssertionError, match="at least 1 baseline"):
            stub.assert_neutral_sentinel_baseline("ANYSENTINEL")

    def test_fails_when_fewer_requests_than_baseline_count(self):
        stub = HTTPRequestEngineStub()
        sentinel = "SENTINEL123"
        _issue(stub, "GET", f"https://api.example.com/?id={sentinel}")

        with pytest.raises(MarkerAssertionError, match="at least 2 baseline"):
            stub.assert_neutral_sentinel_baseline(sentinel, baseline_count=2)


# ===========================================================================
# assert_budget_not_exceeded
# ===========================================================================

class TestAssertBudgetNotExceeded:
    def test_passes_when_under_budget(self):
        stub = HTTPRequestEngineStub()
        for i in range(5):
            _issue(stub, "GET", f"https://api.example.com/?id={i}")
        stub.assert_budget_not_exceeded(10)

    def test_passes_when_exactly_at_budget(self):
        stub = HTTPRequestEngineStub()
        for i in range(7):
            _issue(stub, "GET", f"https://api.example.com/?id={i}")
        stub.assert_budget_not_exceeded(7)

    def test_passes_with_zero_requests_and_nonzero_budget(self):
        stub = HTTPRequestEngineStub()
        stub.assert_budget_not_exceeded(5)

    def test_fails_when_over_budget(self):
        stub = HTTPRequestEngineStub()
        for i in range(8):
            _issue(stub, "GET", f"https://api.example.com/?id={i}")

        with pytest.raises(MarkerAssertionError, match="exceeding the"):
            stub.assert_budget_not_exceeded(7)

    def test_fails_when_budget_is_zero_and_request_issued(self):
        stub = HTTPRequestEngineStub()
        _issue(stub, "GET", "https://api.example.com/?id=1")

        with pytest.raises(MarkerAssertionError, match="exceeding the"):
            stub.assert_budget_not_exceeded(0)


# ===========================================================================
# Existing stub behavior preserved
# ===========================================================================

class TestExistingStubBehaviorPreserved:
    """Confirm the pre-existing stub surface is fully intact."""

    def test_call_count_tracks_requests(self):
        stub = HTTPRequestEngineStub()
        assert stub.call_count == 0
        _issue(stub, "GET", "https://example.com/")
        _issue(stub, "POST", "https://example.com/")
        assert stub.call_count == 2

    def test_requests_for_filters_by_url(self):
        stub = HTTPRequestEngineStub()
        _issue(stub, "GET", "https://example.com/a")
        _issue(stub, "GET", "https://example.com/b")
        _issue(stub, "POST", "https://example.com/a")
        results = stub.requests_for("https://example.com/a")
        assert len(results) == 2

    def test_methods_used(self):
        stub = HTTPRequestEngineStub()
        _issue(stub, "GET", "https://example.com/")
        _issue(stub, "POST", "https://example.com/")
        assert stub.methods_used() == {"GET", "POST"}

    def test_reset_clears_requests(self):
        stub = HTTPRequestEngineStub()
        _issue(stub, "GET", "https://example.com/")
        stub.reset()
        assert stub.call_count == 0

    def test_enqueue_returns_scripted_responses_in_order(self):
        stub = HTTPRequestEngineStub()
        stub.enqueue(
            ScriptedResponse(status_code=201, body="first"),
            ScriptedResponse(status_code=404, body="second"),
        )
        r1 = asyncio.run(stub.request("GET", "https://example.com/"))
        r2 = asyncio.run(stub.request("GET", "https://example.com/"))
        assert r1.status_code == 201
        assert r2.status_code == 404

    def test_default_response_is_200_json(self):
        stub = HTTPRequestEngineStub()
        r = asyncio.run(stub.request("GET", "https://example.com/"))
        assert r.status_code == 200

    def test_responder_callable_takes_priority(self):
        stub = HTTPRequestEngineStub()
        stub.set_responder(
            lambda req: ScriptedResponse(status_code=503, body="down")
        )
        r = asyncio.run(stub.request("GET", "https://example.com/"))
        assert r.status_code == 503

    def test_add_rule_matches_predicate(self):
        stub = HTTPRequestEngineStub()
        stub.add_rule(
            lambda req: "admin" in req.url,
            ScriptedResponse(status_code=403, body="forbidden"),
        )
        r_normal = asyncio.run(stub.request("GET", "https://example.com/users"))
        r_admin = asyncio.run(stub.request("GET", "https://example.com/admin"))
        assert r_normal.status_code == 200
        assert r_admin.status_code == 403

    def test_carries_value_on_query_params(self):
        stub = HTTPRequestEngineStub()
        _issue(stub, "GET", "https://example.com/", params={"id": "secret"})
        req = stub.requests[0]
        assert req.carries_value("secret")
        assert not req.carries_value("other")

    def test_marker_assertion_error_is_assertion_error(self):
        """MarkerAssertionError subclasses AssertionError for pytest compatibility."""
        from tests.support.http_stub import MarkerAssertionError
        err = MarkerAssertionError("test")
        assert isinstance(err, AssertionError)


if __name__ == "__main__":
    import pytest as _pytest
    raise SystemExit(_pytest.main([__file__, "-v"]))
