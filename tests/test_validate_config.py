"""
tests/test_validate_config.py
Tests for ci-cd/scripts/validate_config.py

Requirements: 11.3, 11.4, 2.10, 3.7, 3.9, 4.4, 4.5, 8.2
"""

import logging
import sys
import os

# ---------------------------------------------------------------------------
# Import path — ci-cd/scripts has a hyphen so we inject the path manually.
# ---------------------------------------------------------------------------
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "ci-cd", "scripts"),
)

from validate_config import ConfigValidator  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_validator() -> ConfigValidator:
    return ConfigValidator()


# ---------------------------------------------------------------------------
# 1. Full valid config returns no errors
# ---------------------------------------------------------------------------


def test_valid_full_config_returns_no_errors():
    """A complete, coherent configuration should produce zero validation errors."""
    env = {
        "APILEAK_LOGIN_URL":      "https://api.example.com/auth/login",
        "APILEAK_LOGIN_USERNAME": "user@example.com",
        "APILEAK_LOGIN_PASSWORD": "s3cr3t",
        "APILEAK_JWT_TOKEN":      "eyJhbGciOiJIUzI1NiJ9.payload.sig",
        "APILEAK_TARGET":         "https://api.example.com",
        "APILEAK_JWT_ATTACKS":    "alg_none,weak_secret",
        "APILEAK_BOLA_TEST":      "false",
    }
    errors = make_validator().validate(env)
    assert errors == [], f"Expected no errors but got: {errors}"


# ---------------------------------------------------------------------------
# 2. Partial login vars — 1 of 3 defined
# ---------------------------------------------------------------------------


def test_partial_login_vars_one_of_three():
    """Having only one of the three login vars must produce a validation error."""
    env = {"APILEAK_LOGIN_URL": "https://api.example.com/auth/login"}
    errors = make_validator().validate(env)
    assert len(errors) > 0, "Expected an error for partial login vars (1/3)"
    # Error message should name at least one missing variable.
    combined = " ".join(errors)
    assert "APILEAK_LOGIN_USERNAME" in combined or "APILEAK_LOGIN_PASSWORD" in combined


# ---------------------------------------------------------------------------
# 3. Partial login vars — 2 of 3 defined
# ---------------------------------------------------------------------------


def test_partial_login_vars_two_of_three():
    """Having two of three login vars (missing password) must produce a validation error."""
    env = {
        "APILEAK_LOGIN_URL":      "https://api.example.com/auth/login",
        "APILEAK_LOGIN_USERNAME": "user@example.com",
    }
    errors = make_validator().validate(env)
    assert len(errors) > 0, "Expected an error for partial login vars (2/3)"
    combined = " ".join(errors)
    assert "APILEAK_LOGIN_PASSWORD" in combined


# ---------------------------------------------------------------------------
# 4. BOLA roles / tokens count mismatch
# ---------------------------------------------------------------------------


def test_bola_roles_token_count_mismatch():
    """Mismatched BOLA_ROLES (2) vs ROLE_TOKENS (1) must produce an error."""
    env = {
        "APILEAK_BOLA_ROLES":       "admin,user",
        "APILEAK_BOLA_ROLE_TOKENS": "token1",
    }
    errors = make_validator().validate(env)
    assert len(errors) > 0, "Expected a count-mismatch error"
    combined = " ".join(errors)
    assert "2" in combined and "1" in combined


# ---------------------------------------------------------------------------
# 5. BOLA roles / tokens count match — no error
# ---------------------------------------------------------------------------


def test_bola_roles_token_count_match():
    """Equal counts for BOLA_ROLES and ROLE_TOKENS should produce no error from that rule."""
    env = {
        "APILEAK_BOLA_ROLES":       "admin,user",
        "APILEAK_BOLA_ROLE_TOKENS": "tok1,tok2",
    }
    errors = make_validator().validate(env)
    # Filter only bola-roles-related errors
    bola_errors = [e for e in errors if "BOLA_ROLES" in e or "ROLE_TOKENS" in e]
    assert bola_errors == [], f"Unexpected BOLA roles error: {bola_errors}"


# ---------------------------------------------------------------------------
# 6. Unknown JWT attack name
# ---------------------------------------------------------------------------


def test_unknown_jwt_attack_name():
    """An unrecognised attack name in APILEAK_JWT_ATTACKS must produce an error."""
    env = {
        "APILEAK_JWT_TOKEN":   "tok",
        "APILEAK_TARGET":      "http://x",
        "APILEAK_JWT_ATTACKS": "alg_none,invalid_attack",
    }
    errors = make_validator().validate(env)
    assert len(errors) > 0, "Expected an error for unrecognised attack name"
    combined = " ".join(errors)
    assert "invalid_attack" in combined


# ---------------------------------------------------------------------------
# 7. Valid JWT attack names — no error
# ---------------------------------------------------------------------------


def test_valid_jwt_attack_names():
    """Known attack names should not produce any JWT-name validation error."""
    env = {
        "APILEAK_JWT_TOKEN":   "tok",
        "APILEAK_TARGET":      "http://x",
        "APILEAK_JWT_ATTACKS": "alg_none,weak_secret",
    }
    errors = make_validator().validate(env)
    name_errors = [e for e in errors if "Unrecognised" in e or "attack name" in e.lower()]
    assert name_errors == [], f"Unexpected JWT name error: {name_errors}"


# ---------------------------------------------------------------------------
# 8. APILEAK_JWT_ATTACKS=all is valid
# ---------------------------------------------------------------------------


def test_jwt_attacks_value_all():
    """The special value 'all' for APILEAK_JWT_ATTACKS should produce no error."""
    env = {
        "APILEAK_JWT_TOKEN":   "tok",
        "APILEAK_TARGET":      "http://x",
        "APILEAK_JWT_ATTACKS": "all",
    }
    errors = make_validator().validate(env)
    name_errors = [e for e in errors if "Unrecognised" in e or "attack name" in e.lower()]
    assert name_errors == [], f"Unexpected JWT name error for 'all': {name_errors}"


# ---------------------------------------------------------------------------
# 9. CSV delimiter — multi-character value must produce an error
# ---------------------------------------------------------------------------


def test_csv_delimiter_multi_char():
    """A multi-character APILEAK_CSV_DELIMITER must produce a validation error."""
    env = {"APILEAK_CSV_DELIMITER": ",,"}
    errors = make_validator().validate(env)
    assert len(errors) > 0, "Expected an error for multi-char CSV delimiter"
    combined = " ".join(errors)
    assert "CSV_DELIMITER" in combined or "delimiter" in combined.lower()


# ---------------------------------------------------------------------------
# 10. CSV delimiter — single character is valid
# ---------------------------------------------------------------------------


def test_csv_delimiter_single_char():
    """A single-character APILEAK_CSV_DELIMITER should produce no delimiter error."""
    env = {"APILEAK_CSV_DELIMITER": "|"}
    errors = make_validator().validate(env)
    delimiter_errors = [
        e for e in errors
        if "CSV_DELIMITER" in e or "delimiter" in e.lower()
    ]
    assert delimiter_errors == [], f"Unexpected delimiter error: {delimiter_errors}"


# ---------------------------------------------------------------------------
# 11. apply_defaults logs each default and fills in all missing keys
# ---------------------------------------------------------------------------


def test_apply_defaults_logs_each_default(caplog):
    """apply_defaults({}) should fill every DEFAULT_VALUES key and log each one."""
    validator = make_validator()

    with caplog.at_level(logging.INFO, logger="root"):
        result = validator.apply_defaults({})

    # Every default key must appear in the returned dict with the correct value.
    for key, expected_value in ConfigValidator.DEFAULT_VALUES.items():
        assert key in result, f"Missing default key: {key}"
        assert result[key] == expected_value, (
            f"Wrong value for {key}: expected {expected_value!r}, got {result[key]!r}"
        )

    # An INFO log entry must have been emitted for each default.
    logged_messages = [r.message for r in caplog.records if r.levelno == logging.INFO]
    for key, value in ConfigValidator.DEFAULT_VALUES.items():
        expected_fragment = f"Config default applied: {key}={value}"
        assert any(expected_fragment in msg for msg in logged_messages), (
            f"Expected log message containing {expected_fragment!r} but got: {logged_messages}"
        )


# ---------------------------------------------------------------------------
# 12. apply_defaults does not override existing keys
# ---------------------------------------------------------------------------


def test_apply_defaults_does_not_override_existing():
    """An already-set value must not be overwritten by apply_defaults."""
    validator = make_validator()
    result = validator.apply_defaults({"APILEAK_CSV_DELIMITER": ","})
    # The user supplied comma; the default is semicolon — user value wins.
    assert result["APILEAK_CSV_DELIMITER"] == ",", (
        "apply_defaults should NOT overwrite an existing key"
    )


# ---------------------------------------------------------------------------
# 13. BOLA_TEST=true without any spec or target must produce an error
# ---------------------------------------------------------------------------


def test_bola_test_true_without_spec_or_target():
    """APILEAK_BOLA_TEST=true without any discovery source must produce an error."""
    env = {"APILEAK_BOLA_TEST": "true"}
    errors = make_validator().validate(env)
    assert len(errors) > 0, "Expected an error for BOLA_TEST=true with no source"
    combined = " ".join(errors)
    assert "BOLA_TEST" in combined or "target" in combined.lower() or "openapi" in combined.lower()


# ---------------------------------------------------------------------------
# 14. BOLA_TEST=true with APILEAK_TARGET is valid
# ---------------------------------------------------------------------------


def test_bola_test_true_with_target():
    """APILEAK_BOLA_TEST=true with APILEAK_TARGET set should produce no bola-test error."""
    env = {
        "APILEAK_BOLA_TEST": "true",
        "APILEAK_TARGET":    "http://x",
    }
    errors = make_validator().validate(env)
    bola_errors = [e for e in errors if "BOLA_TEST" in e]
    assert bola_errors == [], f"Unexpected BOLA_TEST error: {bola_errors}"


# ---------------------------------------------------------------------------
# 15. JWT_ATTACKS without APILEAK_JWT_TOKEN (or APILEAK_TARGET) must produce an error
# ---------------------------------------------------------------------------


def test_jwt_attacks_without_token():
    """APILEAK_JWT_ATTACKS defined but no token/target must produce a missing-token error."""
    env = {"APILEAK_JWT_ATTACKS": "alg_none"}
    errors = make_validator().validate(env)
    assert len(errors) > 0, "Expected an error about missing JWT_TOKEN/TARGET"
    combined = " ".join(errors)
    assert "APILEAK_JWT_TOKEN" in combined or "APILEAK_TARGET" in combined
