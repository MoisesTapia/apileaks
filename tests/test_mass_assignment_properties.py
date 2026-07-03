# Feature: owasp-auth-modules-hardening, Property 6: Mass-assignment success requires persisted/reflected value
"""
Property-Based Tests for Property-Level Mass-Assignment Persistence Verification.

Property 6 (design.md): For all generated write responses and subsequent re-read
responses, ``PropertyLevelAuthModule._is_mass_assignment_successful`` classifies the
attempt as successful *if and only if* the exact injected field value is reflected in
the write response body OR present in a safe re-read (GET) of the same object -
independent of any response-size delta or response-time difference.

Validates: Requirements 10.1, 10.2, 10.3
"""

import asyncio
import json
from unittest.mock import AsyncMock, Mock

import hypothesis
from hypothesis import given, settings, strategies as st
from hypothesis.strategies import composite

from modules.owasp.property_level_auth import PropertyLevelAuthModule
from core.config import PropertyTestingConfig, AuthContext, AuthType
from utils.http_client import Response


ENDPOINT_URL = "https://api.example.test/v1/objects/42"

# Injected privileged field names (mirrors MASS_ASSIGNMENT_FIELDS vocabulary).
INJECTED_FIELDS = ["is_admin", "role", "permissions", "user_id", "admin", "status"]

# Padding keys/values use a dedicated namespace so they can never collide with an
# injected field name or an injected value (text values are letters/digits only,
# so they can never contain the "zzpad" underscore-prefixed sentinels).
_PAD_KEY_PREFIX = "zzpad_field_"
_PAD_VALUE_PREFIX = "zzpad_value_"


def _make_module():
    """Build a PropertyLevelAuthModule with a mockable async http client."""
    config = PropertyTestingConfig(
        enabled=True,
        sensitive_fields=["password", "api_key", "secret"],
        mass_assignment_fields=["is_admin", "role", "user_id"],
    )
    http_client = Mock()
    http_client.set_auth_context = Mock()
    http_client.request = AsyncMock()
    auth_contexts = [
        AuthContext(name="user", type=AuthType.BEARER, token="tok", privilege_level=1)
    ]
    return PropertyLevelAuthModule(config, http_client, auth_contexts), http_client


def _build_body(reflect, field, value, pad_count, big_padding):
    """Build a JSON-serializable dict.

    When ``reflect`` is True the exact injected field/value pair is present. Padding
    fields/values are injected from a disjoint namespace so a non-reflecting body can
    never accidentally match the injected field or value, regardless of size.
    """
    body = {}
    for i in range(pad_count):
        body[f"{_PAD_KEY_PREFIX}{i}"] = f"{_PAD_VALUE_PREFIX}{i}"
    if big_padding:
        # A large blob creates a big response-size delta with NO reflected value.
        body["zzpad_blob"] = "x" * 5000
    if reflect:
        body[field] = value
    return body


def _make_response(status_code, body_dict, elapsed, content_type="application/json"):
    text = json.dumps(body_dict)
    return Response(
        status_code=status_code,
        headers={"content-type": content_type},
        content=text.encode(),
        text=text,
        url=ENDPOINT_URL,
        elapsed=elapsed,
        request_method="POST",
    )


@composite
def scenario_strategy(draw):
    """Generate an independent mass-assignment persistence scenario."""
    field = draw(st.sampled_from(INJECTED_FIELDS))
    value = draw(
        st.one_of(
            st.booleans(),
            st.integers(min_value=1, max_value=999999),
            st.text(
                min_size=1,
                max_size=20,
                alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd")),
            ),
        )
    )

    write_success = draw(st.booleans())
    reflect_in_write = draw(st.booleans())
    reread_success = draw(st.booleans())
    reflect_in_reread = draw(st.booleans())

    # Size/time dimensions that MUST NOT influence the success decision.
    write_pad = draw(st.integers(min_value=0, max_value=6))
    reread_pad = draw(st.integers(min_value=0, max_value=6))
    write_big = draw(st.booleans())
    reread_big = draw(st.booleans())
    write_elapsed = draw(
        st.floats(min_value=0.0, max_value=30.0, allow_nan=False, allow_infinity=False)
    )
    reread_elapsed = draw(
        st.floats(min_value=0.0, max_value=30.0, allow_nan=False, allow_infinity=False)
    )

    return {
        "field": field,
        "value": value,
        "write_success": write_success,
        "reflect_in_write": reflect_in_write,
        "reread_success": reread_success,
        "reflect_in_reread": reflect_in_reread,
        "write_pad": write_pad,
        "reread_pad": reread_pad,
        "write_big": write_big,
        "reread_big": reread_big,
        "write_elapsed": write_elapsed,
        "reread_elapsed": reread_elapsed,
    }


class TestMassAssignmentPersistenceProperties:
    """Property 6: success iff persisted/reflected value, not size/time deltas."""

    @given(scenario=scenario_strategy())
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[hypothesis.HealthCheck.too_slow],
    )
    def test_success_iff_injected_value_persisted_or_reflected(self, scenario):
        """
        **Validates: Requirements 10.1, 10.2, 10.3**

        success (non-None evidence) iff the exact injected value is reflected in the
        write response body OR present in a successful safe re-read - independent of
        response-size deltas and response-time deltas.
        """
        module, http_client = _make_module()

        field = scenario["field"]
        value = scenario["value"]

        write_body = _build_body(
            scenario["reflect_in_write"], field, value,
            scenario["write_pad"], scenario["write_big"],
        )
        reread_body = _build_body(
            scenario["reflect_in_reread"], field, value,
            scenario["reread_pad"], scenario["reread_big"],
        )

        write_response = _make_response(
            200 if scenario["write_success"] else 403,
            write_body,
            scenario["write_elapsed"],
        )
        reread_response = _make_response(
            200 if scenario["reread_success"] else 404,
            reread_body,
            scenario["reread_elapsed"],
        )
        http_client.request = AsyncMock(return_value=reread_response)

        result = asyncio.run(
            module._is_mass_assignment_successful(
                write_response, ENDPOINT_URL, field, value
            )
        )

        # Compute the expected outcome purely from persistence/reflection facts.
        # A failed write (non-2xx) can never be a success.
        if not scenario["write_success"]:
            expected_success = False
        elif scenario["reflect_in_write"]:
            expected_success = True
        elif scenario["reread_success"] and scenario["reflect_in_reread"]:
            expected_success = True
        else:
            expected_success = False

        # Property: evidence string returned iff expected_success (biconditional).
        assert (result is not None) == expected_success, (
            f"expected success={expected_success} but got {result!r} for scenario={scenario}"
        )
        if expected_success:
            assert isinstance(result, str) and result, "success must yield evidence text"

    @given(
        field=st.sampled_from(INJECTED_FIELDS),
        value=st.one_of(
            st.booleans(),
            st.integers(min_value=1, max_value=999999),
            st.text(min_size=1, max_size=20,
                    alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"))),
        ),
        write_elapsed=st.floats(min_value=5.0, max_value=60.0,
                                allow_nan=False, allow_infinity=False),
        reread_elapsed=st.floats(min_value=5.0, max_value=60.0,
                                 allow_nan=False, allow_infinity=False),
    )
    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[hypothesis.HealthCheck.too_slow],
    )
    def test_large_size_and_time_delta_without_reflection_is_unsuccessful(
        self, field, value, write_elapsed, reread_elapsed
    ):
        """
        **Validates: Requirement 10.3**

        A successful write and re-read with a large response-size delta and a large
        response-time delta but NO reflected injected value must be classified as
        unsuccessful (None).
        """
        module, http_client = _make_module()

        # Big bodies (huge size delta), slow responses (time delta), no reflection.
        write_body = _build_body(False, field, value, pad_count=6, big_padding=True)
        reread_body = _build_body(False, field, value, pad_count=6, big_padding=True)

        write_response = _make_response(200, write_body, write_elapsed)
        reread_response = _make_response(200, reread_body, reread_elapsed)
        http_client.request = AsyncMock(return_value=reread_response)

        result = asyncio.run(
            module._is_mass_assignment_successful(
                write_response, ENDPOINT_URL, field, value
            )
        )

        assert result is None, (
            "size/time deltas alone must never indicate mass-assignment success"
        )
