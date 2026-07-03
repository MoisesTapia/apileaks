# Feature: owasp-auth-modules-hardening, Property 5: Safe Mode never issues a state-changing method
"""
Property-based test for cross-module Safe Mode enforcement.

Feature: owasp-auth-modules-hardening

Property 5: Safe Mode never issues a state-changing method.
For all sequences of module/engine operations executed while ``safe_mode`` is
enabled, every HTTP method issued by the BOLA, Auth, and Property modules and
the ``JWTAttackEngine`` is a ``Safe_Method`` (``GET``/``HEAD``/``OPTIONS``); no
``State_Changing_Method`` (``POST``/``PUT``/``PATCH``/``DELETE``) is ever
issued (Requirement 21.3: for all requests issued by any module while Safe Mode
is enabled, the issued HTTP method shall be a Safe_Method).

The four components are driven with a ``RecordingHTTPEngine`` double that
records every ``(method, url)`` it is asked to issue. After driving each
component over Hypothesis-generated endpoints with ``safe_mode=True``, the test
asserts every recorded method is in ``SAFE_METHODS``.

**Validates: Requirements 9.3, 11.1, 11.3, 17.2, 21.2, 21.3, 24.5**
"""

import asyncio
import time
from dataclasses import dataclass

from hypothesis import given, settings, strategies as st

from core.config import (
    AuthContext,
    AuthType,
    AuthTestingConfig,
    BOLAConfig,
    PropertyTestingConfig,
)
from modules.owasp.auth_testing import AuthenticationTestingModule
from modules.owasp.bola_testing import BOLATestingModule
from modules.owasp.property_level_auth import PropertyLevelAuthModule
from utils.http_client import Response
from utils.jwt_attack_engine import JWTAttackEngine
from utils.jwt_utils import encode_jwt
from utils.safe_mode import SAFE_METHODS, STATE_CHANGING_METHODS


# ---------------------------------------------------------------------------
# Recording HTTP engine double
# ---------------------------------------------------------------------------

# The full HTTP method space the modules could conceivably issue. Generating
# endpoints across both Safe_Methods and State_Changing_Methods exercises the
# universal Safe Mode guarantee (Req 21.3): even when an endpoint's declared
# method is state-changing, no module may issue a state-changing request.
_ALL_METHODS = sorted(SAFE_METHODS | STATE_CHANGING_METHODS)


def _default_response(method: str, url: str) -> Response:
    """A benign JSON 200 response carrying recognized Identifying_Fields.

    The identifying fields let the modules exercise their identity-comparison
    and object-access logic without erroring; the body content is irrelevant to
    the property under test (only the issued HTTP method matters).
    """
    body = '{"id": 1, "user_id": 1, "email": "user@example.com", "name": "sample"}'
    return Response(
        status_code=200,
        headers={"content-type": "application/json"},
        content=body.encode("utf-8"),
        text=body,
        url=url,
        elapsed=0.001,
        request_method=method.upper(),
    )


class RecordingHTTPEngine:
    """Async HTTP engine double that records every issued ``(method, url)``.

    Mirrors the slice of the ``HTTPRequestEngine`` surface the OWASP modules and
    the JWT engine rely on: an async ``request(method, url, **kwargs)`` plus the
    ``set_auth_context`` / ``current_auth_context`` hooks the modules toggle.
    """

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
    """Minimal discovered-endpoint stand-in exposing ``url`` and ``method``."""

    url: str
    method: str


_RESOURCES = ["users", "accounts", "orders", "items", "profiles"]


@st.composite
def _endpoints(draw):
    """Generate 1-3 endpoints, each with an object id and an arbitrary method."""
    count = draw(st.integers(min_value=1, max_value=3))
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


def _auth_contexts():
    """Two distinct user contexts so multi-context code paths are reachable."""
    return [
        AuthContext(name="user1", type=AuthType.BEARER, token="user1-token",
                    privilege_level=1),
        AuthContext(name="user2", type=AuthType.BEARER, token="user2-token",
                    privilege_level=1),
    ]


def _base_jwt_token():
    """A realistic HS256 token used as the JWT engine's original token."""
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {"sub": "user-1", "user_id": 1, "role": "user",
               "iat": now, "exp": now + 3600}
    return encode_jwt(header, payload, "operator-signing-secret")


def _assert_all_safe(engine: RecordingHTTPEngine, component: str):
    """Assert every recorded method is a Safe_Method (Req 21.3)."""
    offending = [(m, u) for m, u in engine.calls if m not in SAFE_METHODS]
    assert not offending, (
        f"{component} issued state-changing method(s) under safe mode: "
        f"{offending}"
    )


# ---------------------------------------------------------------------------
# Property 5 - one test per component driven under safe_mode=True
# ---------------------------------------------------------------------------


@settings(max_examples=120, deadline=None)
@given(endpoints=_endpoints())
def test_bola_module_issues_only_safe_methods_in_safe_mode(endpoints):
    # Feature: owasp-auth-modules-hardening, Property 5: Safe Mode never issues a state-changing method
    engine = RecordingHTTPEngine()
    config = BOLAConfig(enabled=True, enumeration_bound=3, safe_mode=True)
    module = BOLATestingModule(config, engine, _auth_contexts())

    asyncio.run(module.execute_tests(endpoints))

    _assert_all_safe(engine, "BOLATestingModule")


@settings(max_examples=120, deadline=None)
@given(endpoints=_endpoints())
def test_auth_module_issues_only_safe_methods_in_safe_mode(endpoints):
    # Feature: owasp-auth-modules-hardening, Property 5: Safe Mode never issues a state-changing method
    engine = RecordingHTTPEngine()
    config = AuthTestingConfig(enabled=True, safe_mode=True)
    module = AuthenticationTestingModule(config, engine, _auth_contexts())

    asyncio.run(module.execute_tests(endpoints))

    _assert_all_safe(engine, "AuthenticationTestingModule")


@settings(max_examples=120, deadline=None)
@given(endpoints=_endpoints())
def test_property_module_issues_only_safe_methods_in_safe_mode(endpoints):
    # Feature: owasp-auth-modules-hardening, Property 5: Safe Mode never issues a state-changing method
    engine = RecordingHTTPEngine()
    config = PropertyTestingConfig(enabled=True, safe_mode=True)
    module = PropertyLevelAuthModule(config, engine, _auth_contexts())

    asyncio.run(module.execute_tests(endpoints))

    _assert_all_safe(engine, "PropertyLevelAuthModule")


@settings(max_examples=120, deadline=None)
@given(endpoints=_endpoints())
def test_jwt_attack_engine_issues_only_safe_methods_in_safe_mode(endpoints):
    # Feature: owasp-auth-modules-hardening, Property 5: Safe Mode never issues a state-changing method
    engine = RecordingHTTPEngine()
    target_url = endpoints[0].url
    jwt_engine = JWTAttackEngine(
        target_url=target_url,
        original_token=_base_jwt_token(),
        http_engine=engine,
        signing_secret="operator-signing-secret",
        # A POST body would normally drive a POST request; safe mode must
        # downgrade it to a Safe_Method (Req 17.2).
        post_data='{"foo": "bar"}',
        safe_mode=True,
    )

    asyncio.run(jwt_engine.execute_all())

    _assert_all_safe(engine, "JWTAttackEngine")
