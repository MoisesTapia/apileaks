"""
Property-based tests for Write-Method BOLA persistence verification and
write-outcome classification.

Feature: owasp-auth-modules-hardening

Property 14: Write-BOLA success requires the mutation to persist.
For all generated write responses and subsequent re-read responses,
``_verify_persistence`` (and therefore ``_test_write_bola``) classifies a write
probe as successful if and only if the exact submitted field value is present in
the re-read of the same object - independent of the write response status code,
response size, or response time.

**Validates: Requirements 27.2, 27.3**

Property 15: Write outcome is classified by credential-ness and foreign ownership.
For all persisted mutations on an object, ``_classify_write_outcome`` returns
``BOLA_ACCOUNT_TAKEOVER`` if and only if the mutated field is a credential field
AND the object belongs to a different Auth_Context; it returns
``BOLA_WRITE_ESCALATION`` for a persisted non-credential mutation on a foreign
object; and it returns no finding when the object belongs to the requesting
context.

**Validates: Requirements 27.4, 27.5**

Property 16: Chained probe success requires both unauthorized access and
persistence.
For all combinations of unauthorized-access-confirmed and
injected-value-persisted, ``_test_chained_state_manipulation`` reports a
``BOLA_STATE_MANIPULATION`` finding if and only if BOTH the unauthorized access
to the victim object AND the persistence of the injected privileged/state-
transition value are confirmed; if either is unconfirmed the chained probe is
unsuccessful and no finding is reported.

**Validates: Requirements 32.2, 32.3**
"""

import asyncio
import json
import string
from unittest.mock import Mock, AsyncMock

from hypothesis import given, settings, strategies as st

from modules.owasp.bola_testing import BOLATestingModule, ObjectIdentifier
from utils.http_client import HTTPRequestEngine, Response
from core.config import AuthContext, AuthType, BOLAConfig


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_URL = "https://api.example.com/users/2"

# Safe tokens that survive a JSON round-trip unambiguously.
_SAFE_ALPHABET = string.ascii_letters + string.digits + "-_"
_safe_text = st.text(alphabet=_SAFE_ALPHABET, min_size=1, max_size=12)

# Mutated field names that are NOT recognized Identifying_Fields, so the
# persistence decision's identity resolution stays independent of the mutated
# field under test.
_NON_IDENTIFYING_FIELDS = [
    "role", "balance", "nickname", "bio", "status_text", "phone", "address",
    "score",
]


def _make_module():
    """Build a BOLATestingModule with a stub HTTP client.

    Both methods under test either take all inputs as arguments
    (``_classify_write_outcome``) or drive the HTTP client through the double
    injected per-test (``_verify_persistence``), so a stub client here is safe.
    """
    client = Mock(spec=HTTPRequestEngine)
    client.request = AsyncMock()
    client.set_auth_context = Mock()
    return BOLATestingModule(BOLAConfig(enabled=True), client, [])


def _make_response(status, body_text, *, elapsed=0.001, method="GET",
                   url=_URL):
    content = body_text.encode("utf-8")
    return Response(
        status_code=status,
        headers={"content-type": "application/json"},
        content=content,
        text=body_text,
        url=url,
        elapsed=elapsed,
        request_method=method,
    )


# ===========================================================================
# Property 14: Write-BOLA success requires the mutation to persist.
# ===========================================================================


class _WriteThenRereadEngine:
    """Async HTTP engine double.

    Returns ``write_resp`` for state-changing methods and ``reread_resp`` for
    Safe_Methods (the ``GET`` re-read issued by ``_verify_persistence``). This
    lets the test vary the write response's status/size/time freely while
    holding the re-read fixed, demonstrating the persistence verdict depends
    solely on the re-read.
    """

    _SAFE = {"GET", "HEAD", "OPTIONS"}

    def __init__(self, write_resp, reread_resp):
        self.write_resp = write_resp
        self.reread_resp = reread_resp
        self.calls = []
        self.current_auth_context = None

    def set_auth_context(self, auth_context):
        self.current_auth_context = auth_context

    async def request(self, method, url, **kwargs):
        m = str(method).upper()
        self.calls.append(m)
        if m in self._SAFE:
            return self.reread_resp
        return self.write_resp


@st.composite
def _persistence_case(draw):
    """Generate a re-read scenario plus an unrelated, varied write response."""
    # --- the re-read that determines persistence ------------------------
    reread_status = draw(st.sampled_from([200, 201, 204, 299, 301, 400, 403,
                                          404, 500]))
    identifying_present = draw(st.booleans())
    reflected = draw(st.booleans())

    field = draw(st.sampled_from(_NON_IDENTIFYING_FIELDS))
    value = draw(st.one_of(_safe_text,
                           st.integers(min_value=-1000, max_value=1000),
                           st.booleans()))

    obj = {}
    if identifying_present:
        obj["id"] = draw(st.integers(min_value=1, max_value=99999))
    if reflected:
        # The exact submitted value is reflected in the re-read.
        obj[field] = value
    # When not reflected, the mutated field is simply absent from the re-read.

    reread_resp = _make_response(reread_status, json.dumps(obj))

    # --- a write response with arbitrary status / size / time -----------
    write_status = draw(st.integers(min_value=100, max_value=599))
    write_pad = draw(st.integers(min_value=0, max_value=2000))
    write_elapsed = draw(st.floats(min_value=0.0, max_value=30.0,
                                   allow_nan=False, allow_infinity=False))
    write_body = json.dumps({"ok": True, "pad": "x" * write_pad})
    write_resp = _make_response(write_status, write_body,
                                elapsed=write_elapsed, method="PATCH")

    expected = bool(200 <= reread_status < 300) and identifying_present and reflected
    return field, value, reread_resp, write_resp, expected


@settings(max_examples=200, deadline=None)
@given(_persistence_case())
def test_persistence_success_iff_value_reflected_in_reread(case):
    # Feature: owasp-auth-modules-hardening, Property 14: Write-BOLA success requires the mutation to persist
    field, value, reread_resp, write_resp, expected = case

    module = _make_module()
    engine = _WriteThenRereadEngine(write_resp, reread_resp)
    module.http_client = engine

    ctx = AuthContext(name="user1", type=AuthType.BEARER, token="t",
                      privilege_level=1)

    async def _drive():
        # Issue the (varied) write first, then verify persistence via the
        # Safe_Method re-read. The write response is intentionally unrelated to
        # the verdict.
        await module.http_client.request("PATCH", _URL, json={field: value})
        return await module._verify_persistence(_URL, field, value, ctx)

    persisted, reread = asyncio.run(_drive())

    # Success is determined solely by whether the exact submitted value appears
    # in the re-read of a still-resolving object - never by the write response
    # status/size/time (Requirements 27.2, 27.3).
    assert persisted == expected
    # The re-read returned is the Safe_Method response, not the write response.
    assert reread is reread_resp


@settings(max_examples=200, deadline=None)
@given(_persistence_case(),
       st.lists(st.tuples(st.integers(min_value=100, max_value=599),
                          st.integers(min_value=0, max_value=3000),
                          st.floats(min_value=0.0, max_value=60.0,
                                    allow_nan=False, allow_infinity=False)),
                min_size=1, max_size=4))
def test_persistence_invariant_across_write_status_size_time(case, variants):
    # Feature: owasp-auth-modules-hardening, Property 14: Write-BOLA success requires the mutation to persist
    field, value, reread_resp, _write_resp, expected = case

    ctx = AuthContext(name="user1", type=AuthType.BEARER, token="t",
                      privilege_level=1)

    outcomes = []
    for status, pad, elapsed in variants:
        module = _make_module()
        write_resp = _make_response(
            status, json.dumps({"pad": "y" * pad}), elapsed=elapsed,
            method="PUT",
        )
        engine = _WriteThenRereadEngine(write_resp, reread_resp)
        module.http_client = engine

        async def _drive():
            await module.http_client.request("PUT", _URL, json={field: value})
            persisted, _ = await module._verify_persistence(
                _URL, field, value, ctx
            )
            return persisted

        outcomes.append(asyncio.run(_drive()))

    # Every write-response variant yields the same persistence verdict, equal to
    # the re-read-only expectation: the verdict is independent of the write
    # response status code, size, and time (Requirement 27.2).
    assert all(o == expected for o in outcomes)


# ===========================================================================
# Property 15: Write outcome is classified by credential-ness and foreign
# ownership.
# ===========================================================================

# Field names whose lowercase form is a credential-class field per the module's
# CREDENTIAL_FIELD_NAMES (includes case variants to exercise case-insensitivity).
_CREDENTIAL_FIELDS = [
    "email", "password", "passwd", "secret", "api_key", "apikey", "token",
    "credential", "EMAIL", "Password", "API_KEY", "Token",
]

# Field names whose lowercase form is NOT a credential-class field.
_NON_CREDENTIAL_FIELDS = [
    "role", "balance", "name", "status", "phone", "is_admin", "nickname",
    "address", "bio", "Role", "IS_ADMIN",
]

# Identity mechanisms: OWNER_FIELD_NAMES take precedence, and bare "id" is the
# fallback identity in _object_belongs_to_context.
_IDENTITY_KEYS = [
    "user_id", "owner_id", "account_id", "email", "id",
]

_MODULE = _make_module()


@st.composite
def _classification_case(draw):
    """Generate (field, victim_fields, own_fields, is_credential, is_foreign)."""
    # Credential-ness of the mutated field, by construction.
    is_credential = draw(st.booleans())
    if is_credential:
        field = draw(st.sampled_from(_CREDENTIAL_FIELDS))
    else:
        field = draw(st.sampled_from(_NON_CREDENTIAL_FIELDS))

    # Ownership scenario, by construction.
    #   "own"     -> victim shares the identity value -> belongs -> None
    #   "foreign" -> victim's identity value differs   -> foreign
    #   "unknown" -> victim exposes no comparable identity -> belongs -> None
    scenario = draw(st.sampled_from(["own", "foreign", "unknown"]))

    identity_key = draw(st.sampled_from(_IDENTITY_KEYS))
    own_val = draw(st.integers(min_value=1, max_value=100000))
    own_fields = {identity_key: own_val}

    if scenario == "own":
        victim_fields = {identity_key: own_val}
        is_foreign = False
    elif scenario == "foreign":
        foreign_val = draw(
            st.integers(min_value=1, max_value=100000).filter(
                lambda v: v != own_val
            )
        )
        victim_fields = {identity_key: foreign_val}
        is_foreign = True
    else:  # unknown: no comparable Identifying_Field -> ownership not disproved
        victim_fields = {}
        is_foreign = False

    return field, victim_fields, own_fields, is_credential, is_foreign


@settings(max_examples=200, deadline=None)
@given(_classification_case())
def test_write_outcome_classified_by_credentialness_and_foreign_ownership(case):
    # Feature: owasp-auth-modules-hardening, Property 15: Write outcome is classified by credential-ness and foreign ownership
    field, victim_fields, own_fields, is_credential, is_foreign = case

    result = _MODULE._classify_write_outcome(field, victim_fields, own_fields)

    # ACCOUNT_TAKEOVER iff credential field AND foreign object (Req 27.4).
    assert (result == "BOLA_ACCOUNT_TAKEOVER") == (is_credential and is_foreign)
    # WRITE_ESCALATION for a persisted non-credential foreign mutation (Req 27.5).
    assert (result == "BOLA_WRITE_ESCALATION") == ((not is_credential) and is_foreign)
    # No finding when the object belongs to the requesting context (Req 27.3).
    assert (result is None) == (not is_foreign)


# ===========================================================================
# Property 16: Chained probe success requires both unauthorized access and
# persistence.
# ===========================================================================

# The endpoint carries the requester's OWN id in the path. Substituting the
# victim / invalid id changes only that path segment, so the three GET targets
# are distinct URLs the engine double can route on.
_CHAIN_ENDPOINT = "https://api.example.com/users/1"
_OWN_ID = "1"
_VICTIM_ID = "2"
_OWN_URL = "https://api.example.com/users/1"
_VICTIM_URL = "https://api.example.com/users/2"
_BASELINE_URL = "https://api.example.com/users/0"

# A single privileged/state-transition field is injected so persistence is
# deterministic; "role" -> "admin" is drawn straight from the module's
# PRIVILEGED_INJECTION_FIELDS catalog.
_INJECT_FIELD = "role"
_INJECT_VALUE = "admin"


def _chain_identifier():
    return ObjectIdentifier(
        value=_OWN_ID,
        type="sequential",
        endpoint=_CHAIN_ENDPOINT,
        parameter_name="user_id",
        location="path",
    )


class _ChainedEngine:
    """Async HTTP engine double for the chained state-manipulation probe.

    Routes safe GETs by URL: the requester's own object, the negative-control
    (invalid-id) baseline, and the victim object. The first victim GET is the
    access check; every subsequent victim GET is the persistence re-read. Any
    state-changing method returns a fixed write response. This lets the test set
    unauthorized-access and persistence independently.
    """

    _SAFE = {"GET", "HEAD", "OPTIONS"}

    def __init__(self, *, own_resp, baseline_resp, victim_resp, write_resp,
                 reread_resp):
        self.own_resp = own_resp
        self.baseline_resp = baseline_resp
        self.victim_resp = victim_resp
        self.write_resp = write_resp
        self.reread_resp = reread_resp
        self.calls = []
        self.current_auth_context = None
        self._victim_get_count = 0

    def set_auth_context(self, auth_context):
        self.current_auth_context = auth_context

    async def request(self, method, url, **kwargs):
        m = str(method).upper()
        self.calls.append((m, url))
        if m in self._SAFE:
            if url == _BASELINE_URL:
                return self.baseline_resp
            if url == _OWN_URL:
                return self.own_resp
            if url == _VICTIM_URL:
                self._victim_get_count += 1
                if self._victim_get_count == 1:
                    return self.victim_resp   # access-check GET
                return self.reread_resp       # persistence re-read GET
            return self.baseline_resp
        # State-changing write probe.
        return self.write_resp


@st.composite
def _chained_case(draw):
    """Generate independent (access_confirmed, persisted) scenarios."""
    access_confirmed = draw(st.booleans())
    persisted = draw(st.booleans())

    # Own object: id=1, so a foreign victim (id=2) is a different auth context.
    own_resp = _make_response(200, json.dumps({"id": 1}), url=_OWN_URL)

    # Negative-control baseline: an invalid id returns 404 (discriminating), so
    # accessibility is decided purely by the victim response's identity data.
    baseline_resp = _make_response(404, json.dumps({}), url=_BASELINE_URL)

    if access_confirmed:
        # Accessible (2xx, distinct id) AND foreign (id 2 != own id 1).
        victim_resp = _make_response(200, json.dumps({"id": 2}), url=_VICTIM_URL)
    else:
        # Equivalent to the baseline (same 4xx class, no identifying data) ->
        # not accessible -> unauthorized access NOT confirmed.
        victim_resp = _make_response(404, json.dumps({}), url=_VICTIM_URL)

    # The write response status/size/time is arbitrary and must not influence
    # the verdict.
    write_status = draw(st.integers(min_value=100, max_value=599))
    write_pad = draw(st.integers(min_value=0, max_value=500))
    write_resp = _make_response(
        write_status, json.dumps({"ok": True, "pad": "z" * write_pad}),
        method="PATCH", url=_VICTIM_URL,
    )

    if persisted:
        # Safe re-read reflects the exact injected value on a resolving object.
        reread_resp = _make_response(
            200, json.dumps({"id": 2, _INJECT_FIELD: _INJECT_VALUE}),
            url=_VICTIM_URL,
        )
    else:
        # Re-read does not reflect the injected value -> not persisted.
        reread_resp = _make_response(200, json.dumps({"id": 2}), url=_VICTIM_URL)

    expected_success = access_confirmed and persisted
    return access_confirmed, persisted, expected_success, {
        "own_resp": own_resp,
        "baseline_resp": baseline_resp,
        "victim_resp": victim_resp,
        "write_resp": write_resp,
        "reread_resp": reread_resp,
    }


def _make_chained_module():
    """BOLATestingModule with the Destructive_Opt_In on and Safe_Mode off."""
    client = Mock(spec=HTTPRequestEngine)
    client.request = AsyncMock()
    client.set_auth_context = Mock()
    config = BOLAConfig(enabled=True, allow_destructive=True, safe_mode=False)
    return BOLATestingModule(config, client, [])


@settings(max_examples=200, deadline=None)
@given(_chained_case())
def test_chained_probe_successful_iff_access_and_persistence(case):
    # Feature: owasp-auth-modules-hardening, Property 16: Chained probe success requires both unauthorized access and persistence
    access_confirmed, persisted, expected_success, responses = case

    module = _make_chained_module()
    engine = _ChainedEngine(**responses)
    module.http_client = engine
    # Restrict the injection to a single deterministic field so persistence of
    # the injected value is unambiguous; the AND-logic property is unaffected.
    module._privileged_injection_candidates = lambda resp: {_INJECT_FIELD: _INJECT_VALUE}

    ctx = AuthContext(name="user1", type=AuthType.BEARER, token="t",
                      privilege_level=1)

    findings = asyncio.run(
        module._test_chained_state_manipulation(_chain_identifier(), _VICTIM_ID, [ctx])
    )

    # A BOLA_STATE_MANIPULATION finding is reported iff BOTH unauthorized access
    # and injected-value persistence are confirmed (Requirements 32.2, 32.3).
    reported = len(findings) > 0
    assert reported == expected_success

    if reported:
        finding = findings[0]
        assert finding.category == "BOLA_STATE_MANIPULATION"
        # OWASP_Category must be within {API1, API3} (Requirement 32.4).
        assert finding.owasp_category in {"API1", "API3"}
        # Evidence carries the injected field name and the substituted id (32.5).
        assert _INJECT_FIELD in finding.evidence
        assert _VICTIM_ID in finding.evidence


@settings(max_examples=200, deadline=None)
@given(st.booleans(), st.booleans())
def test_chained_probe_success_helper_is_logical_and(access, persisted):
    # Feature: owasp-auth-modules-hardening, Property 16: Chained probe success requires both unauthorized access and persistence
    module = _make_module()
    # The success decision is the logical AND of the two confirmations, and is
    # unsuccessful whenever either is unconfirmed (Requirement 32.3).
    assert module._chained_probe_successful(access, persisted) == (access and persisted)


if __name__ == "__main__":
    import pytest
    pytest.main([__file__])
