"""
Unit tests for the shared ``SafeModeGuard`` mixin (Task 1.2).

Covers the skip-and-log gate that the BOLA, Broken Authentication, and
Property-Level modules reuse:
- ``_init_safe_mode`` reads ``safe_mode`` from the config, defaulting to False
  when the attribute is absent.
- ``is_state_changing`` is case-insensitive and classifies state-changing
  (POST/PUT/PATCH/DELETE) vs safe (GET/HEAD/OPTIONS) methods.
- ``skip_if_state_changing`` returns True (and logs the skip) only when safe
  mode is on AND the method is state-changing; returns False for safe methods
  even in safe mode, and False for state-changing methods when safe mode is off.

Validates: Requirements 21.2, 21.3, 21.4
"""

from types import SimpleNamespace

import pytest

from utils.safe_mode import (
    STATE_CHANGING_METHODS,
    SAFE_METHODS,
    SafeModeGuard,
)


class StubLogger:
    """Minimal structured-logger stub that records ``.info`` calls.

    The mixin calls ``self.logger.info(message, **kwargs)``; we capture each
    call so tests can assert the skip was logged with the expected metadata.
    """

    def __init__(self):
        self.info_calls = []

    def info(self, message, **kwargs):
        self.info_calls.append((message, kwargs))


class Guard(SafeModeGuard):
    """Concrete consumer of the mixin, mirroring how the OWASP modules wire it.

    The real modules expose ``self.logger`` (a structured logger) and call
    ``_init_safe_mode(config)`` from ``__init__``.
    """

    def __init__(self, config):
        self.logger = StubLogger()
        self._init_safe_mode(config)


def make_guard(safe_mode=None):
    """Build a Guard. When ``safe_mode`` is None the config omits the attribute
    entirely so the default-False path is exercised."""
    if safe_mode is None:
        config = SimpleNamespace()
    else:
        config = SimpleNamespace(safe_mode=safe_mode)
    return Guard(config)


# --- _init_safe_mode --------------------------------------------------------

class TestInitSafeMode:
    def test_defaults_to_false_when_attribute_absent(self):
        guard = make_guard(safe_mode=None)
        assert guard.safe_mode is False

    def test_reads_true_from_config(self):
        guard = make_guard(safe_mode=True)
        assert guard.safe_mode is True

    def test_reads_false_from_config(self):
        guard = make_guard(safe_mode=False)
        assert guard.safe_mode is False


# --- is_state_changing ------------------------------------------------------

class TestIsStateChanging:
    @pytest.mark.parametrize("method", sorted(STATE_CHANGING_METHODS))
    def test_state_changing_methods_classified_true(self, method):
        guard = make_guard(safe_mode=False)
        assert guard.is_state_changing(method) is True

    @pytest.mark.parametrize("method", sorted(SAFE_METHODS))
    def test_safe_methods_classified_false(self, method):
        guard = make_guard(safe_mode=False)
        assert guard.is_state_changing(method) is False

    @pytest.mark.parametrize("method", ["post", "Put", "pAtCh", "delete"])
    def test_is_case_insensitive_for_state_changing(self, method):
        guard = make_guard(safe_mode=False)
        assert guard.is_state_changing(method) is True

    @pytest.mark.parametrize("method", ["get", "Head", "options"])
    def test_is_case_insensitive_for_safe(self, method):
        guard = make_guard(safe_mode=False)
        assert guard.is_state_changing(method) is False


# --- skip_if_state_changing -------------------------------------------------

class TestSkipIfStateChanging:
    @pytest.mark.parametrize("method", sorted(STATE_CHANGING_METHODS))
    def test_skips_and_logs_state_changing_when_safe_mode_on(self, method):
        """Requirements 21.2 & 21.4: in safe mode a state-changing probe is
        skipped (returns True) and the skip is logged."""
        guard = make_guard(safe_mode=True)

        result = guard.skip_if_state_changing(method, test_name="some_test")

        assert result is True
        assert len(guard.logger.info_calls) == 1
        message, kwargs = guard.logger.info_calls[0]
        assert "safe mode" in message.lower()
        assert kwargs["test"] == "some_test"
        # Logged method is normalized to upper case.
        assert kwargs["method"] == method.upper()

    def test_skips_and_logs_lowercase_state_changing_when_safe_mode_on(self):
        """Requirement 21.4: case-insensitive input still skips and logs the
        normalized (upper-case) method."""
        guard = make_guard(safe_mode=True)

        result = guard.skip_if_state_changing("post", test_name="lower_test")

        assert result is True
        message, kwargs = guard.logger.info_calls[0]
        assert kwargs["method"] == "POST"
        assert kwargs["test"] == "lower_test"

    @pytest.mark.parametrize("method", sorted(SAFE_METHODS))
    def test_safe_method_not_skipped_in_safe_mode_and_not_logged(self, method):
        """Requirement 21.3: safe methods are still allowed in safe mode -
        skip returns False and nothing is logged."""
        guard = make_guard(safe_mode=True)

        result = guard.skip_if_state_changing(method, test_name="safe_test")

        assert result is False
        assert guard.logger.info_calls == []

    @pytest.mark.parametrize("method", sorted(STATE_CHANGING_METHODS))
    def test_state_changing_not_skipped_when_safe_mode_off(self, method):
        """Requirement 21.2 (converse): with safe mode off, a state-changing
        probe is allowed (returns False) and no skip is logged."""
        guard = make_guard(safe_mode=False)

        result = guard.skip_if_state_changing(method, test_name="off_test")

        assert result is False
        assert guard.logger.info_calls == []

    @pytest.mark.parametrize("method", sorted(SAFE_METHODS))
    def test_safe_method_not_skipped_when_safe_mode_off(self, method):
        guard = make_guard(safe_mode=False)

        result = guard.skip_if_state_changing(method, test_name="off_safe")

        assert result is False
        assert guard.logger.info_calls == []


if __name__ == "__main__":
    pytest.main([__file__])
