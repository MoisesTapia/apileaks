# Feature: owasp-auth-modules-hardening, Property 13: No state-changing probe while Safe Mode is on or the opt-in is absent
"""
Property-based test for the BOLA destructive gate.

Feature: owasp-auth-modules-hardening

Property 13: No state-changing probe while Safe Mode is on or the opt-in is
absent.
For all sequences of advanced BOLA operations (write BOLA, chained state
manipulation, verb tampering, composite, and ID-leakage probes), whenever
``safe_mode`` is enabled OR the ``Destructive_Opt_In`` is absent OR ``dry_run``
is enabled, every HTTP method actually issued by the module is a ``Safe_Method``
(``GET``/``HEAD``/``OPTIONS``) and no ``State_Changing_Method_Probe`` is issued.

The module is driven with a ``RecordingHTTPEngine`` double that records every
``(method, url)`` it is asked to issue. Advanced state-changing probes route
through the module's single destructive choke point
(``_issue_guarded_write_probe``); this test drives that choke point directly
(alongside the read-only ``execute_tests`` surface) so it stays valid once the
concrete write/composite/leakage probes land in a later task.

**Validates: Requirements 28.2, 28.3, 28.6, 31.2, 31.6, 32.1, 34.4, 36.4**
"""

import asyncio
from dataclasses import dataclass

from hypothesis import given, settings, strategies as st

from core.config import AuthContext, AuthType, BOLAConfig
from modules.owasp.bola_testing import BOLATestingModule
from utils.http_client import Response
from utils.safe_mode import SAFE_METHODS, STATE_CHANGING_METHODS


# ---------------------------------------------------------------------------
# Recording HTTP engine double
# ---------------------------------------------------------------------------


def _default_response(method: str, url: str) -> Response:
    """A benign JSON 200 response with recognized Identifying_Fields."""
    body = '{"id": 1, "user_id": 1, "email": "user@example.com", "name": "sample"}'
    return Response(
        status_code=200,
        headers={"content-type": "application/json"},
        content=body.encode("utf-8"),
        text=body,
        url=url,
        elapsed=0.001,
        request_method=str(method).upper(),
    )


class RecordingHTTPEngine:
    """Async HTTP engine double recording every issued ``(method, url)``."""

    def __init__(self):
        self.calls = []  # list of (METHOD, url)
        self.current_auth_context = None

    def set_auth_context(self, auth_context):
        self.current_auth_context = auth_context

    async def request(self, method, url, **kwargs):
        self.calls.append((str(method).upper(), url))
        return _default_response(method, url)

    @property
    def issued_methods(self):
        return {method for method, _ in self.calls}


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------


@dataclass
class _Endpoint:
    url: str
    method: str


_RESOURCES = ["users", "accounts", "orders", "items", "profiles"]
_WRITE_METHOD_POOL = ["PATCH", "PUT", "POST", "DELETE"]
_ALL_METHODS = sorted(SAFE_METHODS | STATE_CHANGING_METHODS)


@st.composite
def _endpoints(draw):
    """Generate 1-2 endpoints, each with an object id and an arbitrary method."""
    count = draw(st.integers(min_value=1, max_value=2))
    endpoints = []
    for _ in range(count):
        resource = draw(st.sampled_from(_RESOURCES))
        obj_id = draw(st.integers(min_value=1, max_value=9999))
        method = draw(st.sampled_from(_ALL_METHODS))
        endpoints.append(
            _Endpoint(url=f"https://api.example.com/{resource}/{obj_id}",
                      method=method)
        )
    return endpoints


@st.composite
def _gated_scenario(draw):
    """Generate a config whose guardrails forbid any state-changing probe.

    At least one of {safe_mode, opt-in absent, dry_run} is guaranteed true so
    the scenario always falls under Property 13's precondition.
    """
    safe_mode = draw(st.booleans())
    allow_destructive = draw(st.booleans())
    dry_run = draw(st.booleans())
    # Force the precondition: Safe Mode on OR opt-in absent OR dry-run on.
    if not (safe_mode or (not allow_destructive) or dry_run):
        # The only excluded combo is (off, opted-in, off); flip one dimension.
        choice = draw(st.sampled_from(["safe", "optout", "dry"]))
        if choice == "safe":
            safe_mode = True
        elif choice == "optout":
            allow_destructive = False
        else:
            dry_run = True
    destructive_methods = draw(
        st.sets(st.sampled_from(_WRITE_METHOD_POOL), max_size=4)
    )
    return safe_mode, allow_destructive, dry_run, destructive_methods


def _auth_contexts():
    return [
        AuthContext(name="user1", type=AuthType.BEARER, token="user1-token",
                    privilege_level=1),
        AuthContext(name="user2", type=AuthType.BEARER, token="user2-token",
                    privilege_level=1),
    ]


def _assert_no_state_change(engine: RecordingHTTPEngine):
    offending = [(m, u) for m, u in engine.calls if m not in SAFE_METHODS]
    assert not offending, (
        f"BOLA issued state-changing method(s) while the destructive gate "
        f"should have blocked them: {offending}"
    )
    assert not (engine.issued_methods & STATE_CHANGING_METHODS)


# ---------------------------------------------------------------------------
# Property 13
# ---------------------------------------------------------------------------


@settings(max_examples=150, deadline=None)
@given(scenario=_gated_scenario(), endpoints=_endpoints())
def test_guarded_write_probe_issues_no_state_change(scenario, endpoints):
    # Feature: owasp-auth-modules-hardening, Property 13: No state-changing probe while Safe Mode is on or the opt-in is absent
    safe_mode, allow_destructive, dry_run, destructive_methods = scenario

    engine = RecordingHTTPEngine()
    config = BOLAConfig(
        enabled=True,
        enumeration_bound=3,
        safe_mode=safe_mode,
        allow_destructive=allow_destructive,
        destructive_methods=set(destructive_methods),
        dry_run=dry_run,
    )
    module = BOLATestingModule(config, engine, _auth_contexts())

    async def _drive():
        # Drive the destructive choke point repeatedly across a sequence of
        # advanced operations. Every advanced state-changing probe (write BOLA,
        # chained state manipulation, verb tampering, composite, ID-leakage)
        # routes through this helper before any request is issued.
        for ep in endpoints:
            for field, value in (("email", "victim@example.com"),
                                 ("role", "admin"),
                                 ("balance", "999999")):
                await module._issue_guarded_write_probe(
                    ep.url, substituted_id="2", body={field: value},
                    test_name="advanced_probe",
                )

    asyncio.run(_drive())

    _assert_no_state_change(engine)


@settings(max_examples=150, deadline=None)
@given(scenario=_gated_scenario(), endpoints=_endpoints())
def test_dry_run_records_intent_without_issuing(scenario, endpoints):
    # Feature: owasp-auth-modules-hardening, Property 13: No state-changing probe while Safe Mode is on or the opt-in is absent
    safe_mode, allow_destructive, dry_run, destructive_methods = scenario

    engine = RecordingHTTPEngine()
    config = BOLAConfig(
        enabled=True,
        enumeration_bound=3,
        safe_mode=safe_mode,
        allow_destructive=allow_destructive,
        destructive_methods=set(destructive_methods),
        dry_run=dry_run,
    )
    module = BOLATestingModule(config, engine, _auth_contexts())

    async def _drive():
        for ep in endpoints:
            await module._issue_guarded_write_probe(
                ep.url, substituted_id="2", body={"email": "victim@example.com"},
                test_name="advanced_probe",
            )

    asyncio.run(_drive())

    # No state-changing request is ever issued under the gate precondition.
    _assert_no_state_change(engine)

    # A dry-run record is only ever produced WITHOUT issuing a request, and only
    # when the gate would otherwise have permitted the probe (opt-in present,
    # Safe Mode off, a write method configured) with dry_run enabled.
    if module._dry_run_records:
        assert dry_run is True
        assert allow_destructive is True
        assert safe_mode is False
        # Nothing was sent for the recorded intents.
        assert engine.calls == []
        for record in module._dry_run_records:
            assert record["method"] in {"PATCH", "PUT", "POST", "DELETE"}


if __name__ == "__main__":
    import pytest
    pytest.main([__file__])
