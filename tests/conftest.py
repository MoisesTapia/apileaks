"""Shared pytest configuration for the APILeak test suite.

Registers Hypothesis profiles so property-based tests can trade example
count for speed. The active profile is selected via the ``HYPOTHESIS_PROFILE``
environment variable and defaults to ``fast`` for quick local runs.

Profiles:
    fast    - very few examples, for the tightest local feedback loop.
    dev     - a modest example count, the default balance of speed/coverage.
    ci      - the full example count matching Hypothesis' historical default.

Examples:
    # quick local run (default)
    python -m pytest tests/

    # full coverage, e.g. in CI
    HYPOTHESIS_PROFILE=ci python -m pytest tests/
"""

import os

from hypothesis import HealthCheck, settings

settings.register_profile(
    "fast",
    max_examples=3,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.register_profile(
    "dev",
    max_examples=10,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.register_profile(
    "ci",
    max_examples=100,
    deadline=None,
)

_ACTIVE_PROFILE = os.getenv("HYPOTHESIS_PROFILE", "fast")
settings.load_profile(_ACTIVE_PROFILE)

# Cap on per-test example counts. Property tests that pin their own
# ``@settings(max_examples=...)`` would otherwise override the loaded profile
# and keep running hundreds of examples. Unless HYPOTHESIS_PROFILE=ci is set,
# clamp every test's max_examples down to the active profile's value so the
# whole suite honours the "run faster" intent.
_MAX_EXAMPLES_CAP = None if _ACTIVE_PROFILE == "ci" else settings().max_examples


def pytest_collection_modifyitems(config, items):
    """Clamp each Hypothesis test's max_examples to the active profile cap."""
    if _MAX_EXAMPLES_CAP is None:
        return
    for item in items:
        func = getattr(getattr(item, "obj", None), "__func__", getattr(item, "obj", None))
        current = getattr(func, "_hypothesis_internal_use_settings", None)
        if current is None:
            continue
        if current.max_examples > _MAX_EXAMPLES_CAP:
            func._hypothesis_internal_use_settings = settings(
                parent=current, max_examples=_MAX_EXAMPLES_CAP
            )
