# Feature: owasp-auth-modules-hardening, Property 32: No spec-driven state-changing probe while Safe Mode is on or the opt-in is absent
"""
Property-based test for spec-driven Safe Mode / Destructive_Opt_In gating.

Feature: owasp-auth-modules-hardening

Property 32: No spec-driven state-changing probe while Safe Mode is on or the
opt-in is absent.

The spec-driven probes are:

* **typed-payload mass-assignment** - ``PropertyLevelAuthModule._test_mass_assignment``
  builds a schema-valid ``Typed_Payload`` (``build_typed_payload``) when a
  ``Spec_Schema`` resolves the operation, then injects the mass-assignment field
  on top. It is a state-changing (``POST``/``PUT``/``PATCH``) probe gated by
  Safe_Mode (``skip_if_state_changing``);
* **spec-driven write BOLA** - ``BOLATestingModule._test_write_bola`` mutates a
  foreign object with a ``Typed_Payload`` through the single destructive choke
  point ``_issue_guarded_write_probe``. It is gated by BOTH Safe_Mode AND the
  ``Destructive_Opt_In`` (``_destructive_allowed``);
* **spec-driven identifier probes** - ``_identifier_from_spec`` targets the
  declared ``path`` slot and drives ``_test_object_access``, which reads with a
  Safe_Method (``GET``) only.

For all of these, whenever ``safe_mode`` is enabled OR (for the destructive-write
probe) the ``Destructive_Opt_In`` is absent, every HTTP method actually issued is
a ``Safe_Method`` (``GET``/``HEAD``/``OPTIONS``) and no state-changing method
carrying a ``Typed_Payload`` is issued. A state-changing spec-driven probe issues
only when Safe_Mode is off AND (for the destructive write) the opt-in is present.

The gating invariant scopes the ``Destructive_Opt_In`` to destructive-write
probes: the property mass-assignment probe is gated by Safe_Mode only (design
"Spec-Driven Security Testing", Reqs 52.4, 52.5, 56.3, 56.5). The two directions
are therefore validated per the gate that actually governs each probe: the
mass-assignment probe is proven safe under Safe_Mode, and the write-BOLA probe is
proven safe under Safe_Mode OR opt-in-absent.

Each probe is driven with a ``RecordingHTTPEngine`` double that records every
``(method, url, body)`` it is asked to issue (mirrors the doubles used by the
sibling gating property tests).

**Validates: Requirements 57.5, 52.4, 52.5, 56.3, 56.5**
"""

import asyncio
from dataclasses import dataclass
from typing import Iterable, List

from hypothesis import given, settings, strategies as st

from core.config import (
    AuthContext,
    AuthType,
    BOLAConfig,
    PropertyTestingConfig,
)
from modules.owasp.bola_testing import BOLATestingModule, ObjectIdentifier
from modules.owasp.property_level_auth import PropertyLevelAuthModule
from utils.http_client import Response
from utils.spec_import import SpecOperation, SpecParameter, SpecSchema
from utils.safe_mode import SAFE_METHODS, STATE_CHANGING_METHODS


# ---------------------------------------------------------------------------
# Recording HTTP engine double
# ---------------------------------------------------------------------------


def _default_response(method: str, url: str) -> Response:
    """A benign JSON 200 response carrying recognized Identifying_Fields.

    The identifying fields (``id``/``user_id``/``email``) let the modules
    exercise their identity-comparison, object-access, and write-candidate logic
    without erroring; the body content is otherwise irrelevant to the property
    under test (only the issued HTTP method - and whether it carries a
    Typed_Payload - matters).
    """
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
    """Async HTTP engine double recording every issued ``(method, url, body)``."""

    def __init__(self):
        self.calls = []  # list of (METHOD, url, json_body)
        self.current_auth_context = None

    def set_auth_context(self, auth_context):
        self.current_auth_context = auth_context

    async def request(self, method, url, **kwargs):
        self.calls.append((str(method).upper(), url, kwargs.get("json")))
        return _default_response(method, url)

    @property
    def issued_methods(self):
        return {method for method, _, _ in self.calls}

    @property
    def state_changing_calls(self):
        return [(m, u, b) for m, u, b in self.calls if m not in SAFE_METHODS]


# ---------------------------------------------------------------------------
# Generators / fixtures
# ---------------------------------------------------------------------------


@dataclass
class _Endpoint:
    """Minimal discovered-endpoint stand-in exposing ``url`` and ``method``."""

    url: str
    method: str


_RESOURCES = ["users", "accounts", "orders", "items", "profiles"]
_WRITE_METHOD_POOL = ["PATCH", "PUT", "POST", "DELETE"]


@st.composite
def _endpoint(draw):
    """Generate a single endpoint with a numeric object id in the path."""
    resource = draw(st.sampled_from(_RESOURCES))
    obj_id = draw(st.integers(min_value=1, max_value=9999))
    method = draw(st.sampled_from(sorted(SAFE_METHODS | STATE_CHANGING_METHODS)))
    return _Endpoint(
        url=f"https://api.example.com/{resource}/{obj_id}", method=method
    )


# A representative request body schema: a required typed field, an integer, and
# an enum-constrained field. build_typed_payload must produce a schema-valid base
# from this before any mass-assignment / write-BOLA field is injected on top.
_BODY_SCHEMA = {
    "type": "object",
    "required": ["title"],
    "properties": {
        "title": {"type": "string"},
        "count": {"type": "integer"},
        "status": {"type": "string", "enum": ["open", "closed"]},
    },
}


def _concrete_schema(endpoint_url: str, methods: Iterable[str]) -> SpecSchema:
    """A Spec_Schema whose operations match ``(endpoint_url, method)`` exactly.

    ``SpecSchema.operation_for`` compares the concrete endpoint URL against the
    operation ``path``, so the operation path is the concrete URL. Each operation
    declares ``_BODY_SCHEMA`` so ``build_typed_payload`` yields a Typed_Payload
    for the write-BOLA and mass-assignment probes.
    """
    return SpecSchema(
        operations=[
            SpecOperation(
                path=endpoint_url,
                method=method,
                request_body_schema=_BODY_SCHEMA,
            )
            for method in methods
        ]
    )


def _template_operation(endpoint_url: str) -> SpecOperation:
    """A Spec_Operation declaring a single ``{id}`` path parameter.

    Feeds ``_identifier_from_spec`` so the spec-driven identifier probe targets
    the declared path slot (Req 53.1). The template path (``/{resource}/{id}``)
    right-aligns against the concrete endpoint path.
    """
    # endpoint_url == https://api.example.com/<resource>/<id>
    resource = endpoint_url.rstrip("/").split("/")[-2]
    return SpecOperation(
        path=f"/{resource}/{{id}}",
        method="GET",
        parameters=[SpecParameter(name="id", location="path", type="string")],
    )


def _auth_contexts():
    return [
        AuthContext(name="user1", type=AuthType.BEARER, token="user1-token",
                    privilege_level=1),
        AuthContext(name="user2", type=AuthType.BEARER, token="user2-token",
                    privilege_level=1),
    ]


@st.composite
def _gated_scenario(draw):
    """Generate a BOLA config whose guardrails forbid any destructive write.

    At least one of {safe_mode on, opt-in absent, dry_run on} is guaranteed so
    the scenario always falls under Property 32's precondition for the
    destructive-write probe.
    """
    safe_mode = draw(st.booleans())
    allow_destructive = draw(st.booleans())
    dry_run = draw(st.booleans())
    # Force the precondition: Safe Mode on OR opt-in absent OR dry-run on. The
    # only excluded combo is (off, opted-in, off); flip one dimension.
    if not (safe_mode or (not allow_destructive) or dry_run):
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


# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------


def _assert_no_state_change(engine: RecordingHTTPEngine, probe: str):
    offending = engine.state_changing_calls
    assert not offending, (
        f"{probe} issued state-changing method(s) while the spec-driven gate "
        f"should have blocked them: {[(m, u) for m, u, _ in offending]}"
    )
    assert not (engine.issued_methods & STATE_CHANGING_METHODS)


# ---------------------------------------------------------------------------
# Property 32 - "no state-changing probe" direction (gate closed)
# ---------------------------------------------------------------------------


@settings(max_examples=150, deadline=None)
@given(scenario=_gated_scenario(), endpoint=_endpoint())
def test_spec_driven_write_bola_issues_no_state_change_when_gated(scenario, endpoint):
    # Feature: owasp-auth-modules-hardening, Property 32: No spec-driven state-changing probe while Safe Mode is on or the opt-in is absent
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
    # Schema declares the write operation (concrete-path) so the mutation body is
    # a Typed_Payload, and a template operation drives spec-driven identifier
    # targeting.
    schema = _concrete_schema(endpoint.url, _WRITE_METHOD_POOL)
    module = BOLATestingModule(config, engine, _auth_contexts(), spec_schema=schema)

    contexts = _auth_contexts()
    template_op = _template_operation(endpoint.url)

    async def _drive():
        # Spec-driven identifier targeting selects the declared path slot; the
        # returned identifier feeds the destructive write BOLA probe.
        identifier = module._identifier_from_spec(template_op, endpoint.url)
        assert identifier is not None and identifier.location == "path"
        await module._test_write_bola(identifier, victim_id="2", contexts=contexts)

    asyncio.run(_drive())

    _assert_no_state_change(engine, "spec-driven write BOLA")
    # No state-changing method ever carries a Typed_Payload under the closed gate.
    assert engine.state_changing_calls == []
    # A dry-run record is only produced without issuing a request, and only when
    # the gate would otherwise have permitted the write (opt-in present, Safe
    # Mode off, a write method configured) with dry_run enabled.
    if module._dry_run_records:
        assert dry_run is True and allow_destructive is True and safe_mode is False


@settings(max_examples=120, deadline=None)
@given(scenario=_gated_scenario(), endpoint=_endpoint())
def test_spec_driven_identifier_probes_are_read_only(scenario, endpoint):
    # Feature: owasp-auth-modules-hardening, Property 32: No spec-driven state-changing probe while Safe Mode is on or the opt-in is absent
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
    template_op = _template_operation(endpoint.url)

    async def _drive():
        identifier = module._identifier_from_spec(template_op, endpoint.url)
        assert identifier is not None
        # The spec-driven identifier probe reads the substituted object; it is
        # always a Safe_Method regardless of the guardrail scenario.
        for candidate in ("2", "3", identifier.value):
            await module._test_object_access(identifier, "user1", candidate)

    asyncio.run(_drive())

    _assert_no_state_change(engine, "spec-driven identifier probe")
    # The probe DID issue requests (it is not vacuously safe) - all reads.
    assert engine.calls, "expected the identifier probe to issue read requests"
    assert engine.issued_methods <= SAFE_METHODS


@settings(max_examples=120, deadline=None)
@given(endpoint=_endpoint(), opt_in=st.booleans())
def test_typed_payload_mass_assignment_safe_under_safe_mode(endpoint, opt_in):
    # Feature: owasp-auth-modules-hardening, Property 32: No spec-driven state-changing probe while Safe Mode is on or the opt-in is absent
    # The property mass-assignment probe is gated by Safe_Mode (Reqs 52.4,
    # 56.3). Under Safe_Mode no state-changing Typed_Payload probe is issued,
    # regardless of any opt-in dimension.
    engine = RecordingHTTPEngine()
    config = PropertyTestingConfig(enabled=True, safe_mode=True)
    schema = _concrete_schema(endpoint.url, ["POST", "PUT", "PATCH"])
    module = PropertyLevelAuthModule(config, engine, _auth_contexts(),
                                     spec_schema=schema)

    asyncio.run(module._test_mass_assignment([endpoint]))

    _assert_no_state_change(engine, "typed-payload mass-assignment")


# ---------------------------------------------------------------------------
# Property 32 - "issues only when permitted" direction (gate open, non-vacuous)
# ---------------------------------------------------------------------------


@settings(max_examples=120, deadline=None)
@given(endpoint=_endpoint(),
       write_methods=st.sets(st.sampled_from(["PATCH", "PUT", "POST"]),
                             min_size=1, max_size=3))
def test_write_bola_issues_state_change_only_when_safe_off_and_opt_in(
        endpoint, write_methods):
    # Feature: owasp-auth-modules-hardening, Property 32: No spec-driven state-changing probe while Safe Mode is on or the opt-in is absent
    engine = RecordingHTTPEngine()
    config = BOLAConfig(
        enabled=True,
        enumeration_bound=3,
        safe_mode=False,               # Safe Mode OFF
        allow_destructive=True,        # Destructive_Opt_In PRESENT
        destructive_methods=set(write_methods),
        dry_run=False,
    )
    schema = _concrete_schema(endpoint.url, _WRITE_METHOD_POOL)
    module = BOLATestingModule(config, engine, _auth_contexts(), spec_schema=schema)

    identifier = ObjectIdentifier(
        value="1", type="sequential", endpoint=endpoint.url,
        parameter_name="id", location="path",
    )

    asyncio.run(module._test_write_bola(identifier, victim_id="2",
                                        contexts=_auth_contexts()))

    # The gate is open ONLY here (Safe_Mode off AND opt-in present), so a
    # state-changing spec-driven write probe IS issued (the "only when" direction
    # is non-vacuous).
    assert engine.state_changing_calls, (
        "expected a state-changing write probe when Safe_Mode is off and the "
        "Destructive_Opt_In is present"
    )
    # Every state-changing method issued is the least-destructive configured one
    # and carries a Typed_Payload (a dict body derived from the schema).
    expected_method = module._select_write_method()
    for method, _url, body in engine.state_changing_calls:
        assert method == expected_method
        assert method in write_methods
        assert isinstance(body, dict) and "title" in body  # schema-required field


@settings(max_examples=120, deadline=None)
@given(endpoint=_endpoint())
def test_mass_assignment_issues_typed_payload_only_when_safe_off(endpoint):
    # Feature: owasp-auth-modules-hardening, Property 32: No spec-driven state-changing probe while Safe Mode is on or the opt-in is absent
    schema = _concrete_schema(endpoint.url, ["POST", "PUT", "PATCH"])

    # Safe_Mode ON -> no state-changing Typed_Payload probe issued.
    safe_engine = RecordingHTTPEngine()
    safe_module = PropertyLevelAuthModule(
        PropertyTestingConfig(enabled=True, safe_mode=True),
        safe_engine, _auth_contexts(), spec_schema=schema,
    )
    asyncio.run(safe_module._test_mass_assignment([endpoint]))
    assert safe_engine.state_changing_calls == []

    # Safe_Mode OFF -> the state-changing mass-assignment probe IS issued and it
    # carries a schema-derived Typed_Payload (the "only when Safe_Mode is off"
    # direction is non-vacuous).
    open_engine = RecordingHTTPEngine()
    open_module = PropertyLevelAuthModule(
        PropertyTestingConfig(enabled=True, safe_mode=False),
        open_engine, _auth_contexts(), spec_schema=schema,
    )
    asyncio.run(open_module._test_mass_assignment([endpoint]))

    assert open_engine.state_changing_calls, (
        "expected a state-changing mass-assignment probe when Safe_Mode is off"
    )
    typed_bodies = [
        body for _m, _u, body in open_engine.state_changing_calls
        if isinstance(body, dict) and "title" in body
    ]
    assert typed_bodies, "expected the mass-assignment probe to carry a Typed_Payload"


if __name__ == "__main__":
    import pytest
    pytest.main([__file__])
