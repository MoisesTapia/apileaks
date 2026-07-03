# Feature: owasp-auth-modules-hardening, Property 23: Anti-automation burst never locks out a real account and never exceeds its bound
"""
Property-Based Tests for anti-automation login-burst construction.

Property 23: "Anti-automation burst never locks out a real account and never
exceeds its bound" - for all configured attempt counts and login endpoints,
``AuthenticationTestingModule._build_login_burst`` produces at most
``rate_limit_attempts`` requests, all sharing a single benign username and
varying only the password.

Validates: Requirements 37.2, 37.4, 46.4
"""

from unittest.mock import Mock

import pytest
from hypothesis import given, settings, strategies as st

from modules.owasp.auth_testing import AuthenticationTestingModule
from core.config import AuthTestingConfig
from utils.http_client import HTTPRequestEngine, Request


# The placeholder username the builder falls back to when no benign username is
# configured. Kept in sync with the implementation under test.
DEFAULT_BENIGN_USERNAME = "apileaks_benign_probe"


def _make_module(benign_username):
    """Construct an AuthenticationTestingModule minimally for pure-method use.

    ``_build_login_burst`` is a pure synchronous method that only reads
    ``self.config``; a mock HTTP client and empty auth contexts are sufficient.
    """
    config = AuthTestingConfig(benign_username=benign_username)
    http_client = Mock(spec=HTTPRequestEngine)
    return AuthenticationTestingModule(config, http_client, [])


# Login endpoint URLs spanning schemes, hosts, ports, and paths.
login_endpoint_strategy = st.sampled_from([
    "https://api.example.com/login",
    "http://localhost:8080/auth/login",
    "https://example.org/api/v1/authenticate",
    "http://127.0.0.1/session",
    "https://tenant.app.io:443/v2/users/login",
    "/relative/login",
    "https://api.example.com/login?redirect=/home",
])

# Benign usernames: both unconfigured (None) and a range of configured values.
benign_username_strategy = st.one_of(
    st.none(),
    st.text(
        min_size=1,
        max_size=40,
        alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd", "Pc")),
    ),
)

# Attempt counts including 0, negatives, and large values.
attempts_strategy = st.integers(min_value=-5, max_value=250)


@settings(max_examples=200)
@given(
    login_endpoint=login_endpoint_strategy,
    attempts=attempts_strategy,
    benign_username=benign_username_strategy,
)
def test_login_burst_bounded_and_account_safe(login_endpoint, attempts, benign_username):
    """The login burst is bounded, single-account, and password-only varying.

    Validates: Requirements 37.2, 37.4, 46.4
    """
    module = _make_module(benign_username)
    result = module._build_login_burst(login_endpoint, attempts)

    expected_username = benign_username or DEFAULT_BENIGN_USERNAME

    # Invariant 1: bound never exceeded; zero/negative attempts -> empty burst.
    assert len(result) <= max(0, attempts)
    if attempts <= 0:
        assert result == []
    else:
        assert len(result) == attempts

    # Invariant 2: exactly ONE username shared across the entire burst.
    usernames = {req.json["username"] for req in result}
    if result:
        assert usernames == {expected_username}

    # Invariant 3: passwords vary - every request uses a unique password.
    passwords = [req.json["password"] for req in result]
    assert len(set(passwords)) == len(passwords)

    # Invariant 4: every request is a safe, well-structured login probe.
    for req in result:
        assert isinstance(req, Request)
        assert req.method == "POST"
        assert req.url == login_endpoint
        assert set(req.json.keys()) == {"username", "password"}
        assert req.json["username"] == expected_username


@settings(max_examples=100)
@given(attempts=attempts_strategy, benign_username=benign_username_strategy)
def test_login_burst_never_exceeds_configured_rate_limit(attempts, benign_username):
    """When driven by the configured rate limit, the burst never exceeds it.

    Uses ``config.rate_limit_attempts`` as the attempt count to model the
    real anti-automation driver, asserting the produced burst stays within the
    configured bound (Requirements 37.2, 46.4).

    Validates: Requirements 37.2, 46.4
    """
    module = _make_module(benign_username)
    rate_limit = module.config.rate_limit_attempts
    result = module._build_login_burst("https://api.example.com/login", rate_limit)

    assert len(result) <= rate_limit
    # A single account is targeted regardless of the bound (Requirement 37.4).
    usernames = {req.json["username"] for req in result}
    if result:
        assert len(usernames) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
