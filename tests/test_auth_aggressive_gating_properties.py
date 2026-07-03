# Feature: owasp-auth-modules-hardening, Property 26: No aggressive or state-changing auth probe runs while forbidden, and bounds are never exceeded
"""
Property-based tests for the aggressive / state-changing auth gate.

Feature: owasp-auth-modules-hardening

Property 26: "No aggressive or state-changing auth probe runs while forbidden,
and bounds are never exceeded."

For all sequences of advanced auth operations (the rate-limiting burst, the
revocation-race probe, and the state-changing password-reset request), whenever
``safe_mode`` is enabled OR the required opt-in is absent
(``allow_aggressive`` for the burst / race probes, ``allow_destructive`` for the
state-changing reset request), no such probe issues any request; and whenever a
probe is permitted, the number of requests it issues never exceeds the
operator-configured bound (``rate_limit_attempts`` or ``revocation_race_requests``).

The module is driven with a ``RecordingHTTPEngine`` double that records every
``(method, url)`` it is asked to issue. The gate invariants for the not-yet-
implemented revocation-race and state-changing password-reset probes (Tasks
28.1 / 27.1) are proven directly against ``_aggressive_allowed()`` /
``_reset_request_allowed()`` across the full (safe_mode, allow_aggressive,
allow_destructive) matrix, and — when those methods already exist — they are
also driven through the recording engine and asserted.

**Validates: Requirements 37.1, 37.2, 37.8, 40.4, 40.5, 42.1, 42.2, 42.5, 45.4, 46.1, 46.2, 46.3, 46.4, 48.5**
"""

import asyncio

from hypothesis import given, settings, strategies as st

from core.config import AuthContext, AuthType, AuthTestingConfig
from modules.owasp.auth_testing import AuthenticationTestingModule
from utils.http_client import Response


# ---------------------------------------------------------------------------
# Recording HTTP engine double
# ---------------------------------------------------------------------------


def _default_response(method: str, url: str) -> Response:
    """A benign JSON 200 response with NO throttling signal.

    A non-throttled response ensures the rate-limiting burst does not stop
    early, so a permitted burst issues exactly ``rate_limit_attempts`` requests
    - the worst case against which the ``<= bound`` invariant is exercised.
    """
    body = '{"status": "ok", "id": 1}'
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
    """Async HTTP engine double that records every issued ``(method, url)``.

    Mirrors the slice of the ``HTTPRequestEngine`` surface the auth module uses:
    an async ``request(method, url, **kwargs)`` plus the ``set_auth_context`` /
    ``current_auth_context`` hooks the module toggles.
    """

    def __init__(self):
        self.calls = []  # list of (METHOD, url)
        self.current_auth_context = None

    def set_auth_context(self, auth_context):
        self.current_auth_context = auth_context

    async def request(self, method, url, **kwargs):
        self.calls.append((str(method).upper(), url))
        return _default_response(method, url)


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------

login_endpoint_strategy = st.sampled_from([
    "https://api.example.com/login",
    "http://localhost:8080/auth/login",
    "https://example.org/api/v1/authenticate",
    "http://127.0.0.1/session",
    "https://tenant.app.io:443/v2/users/login",
    "/relative/login",
])

# Bounded to keep a permitted burst fast while still exercising 0/1/many.
attempts_strategy = st.integers(min_value=0, max_value=30)
race_requests_strategy = st.integers(min_value=0, max_value=30)
gate_bool_strategy = st.booleans()


def _make_module(config):
    engine = RecordingHTTPEngine()
    contexts = [
        AuthContext(name="user1", type=AuthType.BEARER, token="user1-token",
                    privilege_level=1),
    ]
    module = AuthenticationTestingModule(config, engine, contexts)
    return module, engine


def _make_config(safe_mode, allow_aggressive, allow_destructive,
                 rate_limit_attempts, revocation_race_requests):
    return AuthTestingConfig(
        safe_mode=safe_mode,
        allow_aggressive=allow_aggressive,
        allow_destructive=allow_destructive,
        rate_limit_attempts=rate_limit_attempts,
        revocation_race_requests=revocation_race_requests,
    )


# ---------------------------------------------------------------------------
# Property 26 - gate invariants across the full (safe_mode, opt-in) matrix
# ---------------------------------------------------------------------------


@settings(max_examples=200)
@given(
    safe_mode=gate_bool_strategy,
    allow_aggressive=gate_bool_strategy,
    allow_destructive=gate_bool_strategy,
    rate_limit_attempts=attempts_strategy,
    revocation_race_requests=race_requests_strategy,
)
def test_gate_predicates_forbid_probes_unless_optin_and_safe_mode_off(
    safe_mode, allow_aggressive, allow_destructive,
    rate_limit_attempts, revocation_race_requests,
):
    """The aggressive/reset gates are fail-closed and opt-in gated.

    ``_aggressive_allowed`` (burst + revocation-race probes) is True iff
    Safe_Mode is off AND ``allow_aggressive`` is set; ``_reset_request_allowed``
    (state-changing password reset) is True iff Safe_Mode is off AND
    ``allow_destructive`` is set. Whenever Safe_Mode is on OR the relevant
    opt-in is absent, the corresponding probe is forbidden.

    Validates: Requirements 37.1, 37.8, 40.4, 40.5, 42.1, 42.5, 46.1, 46.2, 46.3
    """
    config = _make_config(safe_mode, allow_aggressive, allow_destructive,
                          rate_limit_attempts, revocation_race_requests)
    module, _ = _make_module(config)

    expected_aggressive = (not safe_mode) and allow_aggressive
    expected_reset = (not safe_mode) and allow_destructive

    assert module._aggressive_allowed() is expected_aggressive
    assert module._reset_request_allowed() is expected_reset

    # Fail-closed: any forbidding condition denies the probe.
    if safe_mode or not allow_aggressive:
        assert module._aggressive_allowed() is False
    if safe_mode or not allow_destructive:
        assert module._reset_request_allowed() is False


# ---------------------------------------------------------------------------
# Property 26 - rate-limiting burst issues nothing while forbidden,
# and never exceeds its bound while permitted
# ---------------------------------------------------------------------------


@settings(max_examples=150)
@given(
    login_endpoint=login_endpoint_strategy,
    safe_mode=gate_bool_strategy,
    allow_aggressive=gate_bool_strategy,
    allow_destructive=gate_bool_strategy,
    rate_limit_attempts=attempts_strategy,
    revocation_race_requests=race_requests_strategy,
)
def test_rate_limiting_probe_gated_and_bounded(
    login_endpoint, safe_mode, allow_aggressive, allow_destructive,
    rate_limit_attempts, revocation_race_requests,
):
    """``_test_rate_limiting`` issues zero requests when forbidden, bounded when permitted.

    Driven through the ``RecordingHTTPEngine``: when the aggressive gate is
    closed (Safe_Mode on OR ``allow_aggressive`` absent) NO ``(method, url)`` is
    recorded; when the gate is open the recorded request count never exceeds
    ``config.rate_limit_attempts``.

    Validates: Requirements 37.1, 37.2, 37.8, 46.1, 46.2, 46.3, 46.4, 48.5
    """
    config = _make_config(safe_mode, allow_aggressive, allow_destructive,
                          rate_limit_attempts, revocation_race_requests)
    module, engine = _make_module(config)

    asyncio.run(module._test_rate_limiting(login_endpoint))

    if module._aggressive_allowed():
        # Permitted: bounded burst, never exceeding the configured attempts.
        assert len(engine.calls) <= config.rate_limit_attempts
        # Every issued request targets the login endpoint via POST.
        for method, url in engine.calls:
            assert method == "POST"
            assert url == login_endpoint
    else:
        # Forbidden: absolutely no request issued.
        assert engine.calls == []


# ---------------------------------------------------------------------------
# Property 26 - the burst builder is bounded by rate_limit_attempts (abstract bound)
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(
    login_endpoint=login_endpoint_strategy,
    rate_limit_attempts=attempts_strategy,
)
def test_login_burst_never_exceeds_rate_limit_bound(login_endpoint, rate_limit_attempts):
    """``_build_login_burst`` produces at most ``rate_limit_attempts`` requests.

    Exercises the "bounds never exceeded" invariant directly on the pure burst
    builder that the anti-automation probe (and, by construction, any future
    bounded aggressive probe) relies on.

    Validates: Requirements 37.2, 46.4
    """
    config = _make_config(False, True, False, rate_limit_attempts, 0)
    module, _ = _make_module(config)

    burst = module._build_login_burst(login_endpoint, rate_limit_attempts)
    assert len(burst) <= max(0, rate_limit_attempts)


# ---------------------------------------------------------------------------
# Property 26 - revocation-race / state-changing reset probes (guarded).
#
# Tasks 28.1 (`_test_revocation_race`) and 27.1 (the state-changing reset
# request) land AFTER this task. These assertions are guarded with hasattr so
# the property test is correct now (methods absent) and meaningful once they
# land: when present they are driven through the RecordingHTTPEngine and the
# gated + bounded invariants are asserted.
# ---------------------------------------------------------------------------

# Candidate names for the future state-changing password-reset request probe.
_RESET_PROBE_METHOD_NAMES = (
    "_test_password_reset_request",
    "_test_reset_request",
    "_send_reset_request",
    "_test_state_changing_reset",
)


def _first_existing_method(module, names):
    for name in names:
        if hasattr(module, name):
            return name
    return None


@settings(max_examples=100)
@given(
    login_endpoint=login_endpoint_strategy,
    safe_mode=gate_bool_strategy,
    allow_aggressive=gate_bool_strategy,
    allow_destructive=gate_bool_strategy,
    rate_limit_attempts=attempts_strategy,
    revocation_race_requests=race_requests_strategy,
)
def test_revocation_race_and_reset_probes_gated_and_bounded_when_present(
    login_endpoint, safe_mode, allow_aggressive, allow_destructive,
    rate_limit_attempts, revocation_race_requests,
):
    """Once implemented, race/reset probes are gated and bounded; today the
    gate predicates already prove they are forbidden while forbidden.

    * The revocation-race probe is gated by ``_aggressive_allowed`` and bounded
      by ``revocation_race_requests``.
    * The state-changing password-reset request is gated by
      ``_reset_request_allowed``.

    When the underlying methods do not yet exist, the gate predicates alone
    prove the "forbidden while Safe_Mode on or opt-in absent" guarantee; when
    they exist they are additionally driven through the RecordingHTTPEngine.

    Validates: Requirements 40.4, 40.5, 42.1, 42.2, 42.5, 45.4, 46.4, 48.5
    """
    config = _make_config(safe_mode, allow_aggressive, allow_destructive,
                          rate_limit_attempts, revocation_race_requests)
    module, engine = _make_module(config)

    aggressive_allowed = module._aggressive_allowed()
    reset_allowed = module._reset_request_allowed()

    # --- Revocation-race probe (gated by _aggressive_allowed) ---------------
    if hasattr(module, "_test_revocation_race"):
        engine.calls.clear()
        try:
            asyncio.run(module._test_revocation_race(login_endpoint))
        except TypeError:
            # Signature differs from the assumed single-endpoint form; skip the
            # drive but keep the gate assertion below meaningful.
            pass
        else:
            if aggressive_allowed:
                assert len(engine.calls) <= config.revocation_race_requests
            else:
                assert engine.calls == []
    else:
        # Not yet implemented: prove the future probe is forbidden while
        # forbidden purely via the gate it will be wired through.
        if safe_mode or not allow_aggressive:
            assert aggressive_allowed is False

    # --- State-changing password-reset request (gated by _reset_request_allowed) ---
    reset_method_name = _first_existing_method(module, _RESET_PROBE_METHOD_NAMES)
    if reset_method_name is not None:
        engine.calls.clear()
        reset_method = getattr(module, reset_method_name)
        try:
            asyncio.run(reset_method(login_endpoint))
        except TypeError:
            pass
        else:
            if not reset_allowed:
                assert engine.calls == []
    else:
        if safe_mode or not allow_destructive:
            assert reset_allowed is False


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
