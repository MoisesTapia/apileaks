"""
Safe Mode Gate

Provides the shared Safe Mode vocabulary and the :class:`SafeModeGuard` mixin
reused by the OWASP testing modules (BOLA, Broken Authentication, and
Property-Level Authorization). Centralizing the gate keeps the Safe Mode
behavior uniform across modules and mirrors the constants already used by
``modules/owasp/business_flows.py`` and ``modules/owasp/ssrf_testing.py``.

When Safe Mode is enabled (``config.safe_mode``), modules MUST NOT issue any
State_Changing_Method request (POST/PUT/PATCH/DELETE) and SHALL restrict their
probes to Safe_Methods (GET/HEAD/OPTIONS). Each skipped state-changing probe is
logged so the operator can see what was suppressed.
"""

# HTTP methods that change server state. In safe mode these are skipped so the
# module only issues non-state-changing probes (GET/HEAD/OPTIONS).
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Methods considered safe to probe with when safe mode is enabled.
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class SafeModeGuard:
    """Mixin read by the BOLA, Auth, and Property modules.

    The consuming class is expected to expose a structured ``self.logger``
    (created via :func:`core.logging.get_logger`). The mixin is initialized in
    the module ``__init__`` via :meth:`_init_safe_mode`.
    """

    def _init_safe_mode(self, config) -> None:
        """Read the Safe_Mode flag from the module configuration.

        ``safe_mode`` is an optional attribute on the config, defaulting to
        ``False`` when absent (Requirement 21.1).
        """
        self.safe_mode = getattr(config, "safe_mode", False)

    def is_state_changing(self, method: str) -> bool:
        """Return True when ``method`` is a State_Changing_Method.

        The comparison is case-insensitive so callers may pass methods in any
        casing (for example ``"post"`` or ``"POST"``).
        """
        return method.upper() in STATE_CHANGING_METHODS

    def skip_if_state_changing(self, method: str, test_name: str) -> bool:
        """Decide whether a state-changing probe must be skipped in Safe Mode.

        Returns ``True`` (and logs the skip, Requirement 21.4) when Safe_Mode is
        enabled AND ``method`` is a State_Changing_Method; otherwise returns
        ``False``. Callers MUST honor the return value and refrain from issuing
        the request when it is ``True`` (Requirements 21.2, 21.3).
        """
        if self.safe_mode and self.is_state_changing(method):
            self.logger.info("Skipping state-changing probe in safe mode",
                             test=test_name, method=method.upper())
            return True
        return False

    def safe_read_method(self, method: str, test_name: str) -> str:
        """Return a Safe_Method to use for a read/discovery probe.

        Read/discovery probes replay an endpoint's declared HTTP method. When
        Safe_Mode is enabled and that declared method is a
        State_Changing_Method, issuing it would violate the Safe Mode guarantee
        (Requirement 21.3). In that case this returns ``"GET"`` (a Safe_Method)
        and logs the downgrade (Requirement 21.4); otherwise the original
        ``method`` is returned unchanged so non-safe-mode behavior is preserved
        (Requirement 26).
        """
        if self.safe_mode and self.is_state_changing(method):
            self.logger.info("Downgrading read probe to GET in safe mode",
                             test=test_name, original_method=method.upper())
            return "GET"
        return method
