"""Unit tests for ``par`` config threading and behavior preservation (task 12.3).

**Feature: parameter-fuzzing, Task 12.3**

These tests lock in the config-threading work landed in tasks 12.1
(``apileaks.create_enhanced_config`` / ``create_default_config`` thread the new
``fuzzing.parameters.*`` keys plus the transversal transport keys) and 12.2
(``core.config.ConfigurationManager.load_config_from_dict`` maps those keys into
the extended ``ParameterFuzzingConfig``).

Three guarantees are covered, fully offline (no HTTP request is issued -- the
tests exercise only the config factory + the configuration loader):

1. End-to-end threading: the new ``par`` keys -- ``methods``, ``confirm_hits``,
   ``max_requests``, ``query_candidates``, ``body_candidates`` -- and the
   transversal transport keys ``client_cert`` / ``ca_bundle`` / ``resolve``
   flow from the CLI config factory (``create_default_config`` /
   ``create_enhanced_config``) through ``load_config_from_dict`` into the
   resolved ``APILeakConfig`` / ``ParameterFuzzingConfig``.
2. ``par`` preservation: a ``par`` invocation (``scan_type == "par"``) continues
   to set ``fuzzing.endpoints.enabled = False`` and
   ``fuzzing.parameters.enabled = True``.
3. Behavior preservation: other commands' config (``dir`` / ``scan`` / ``full``)
   is unaffected by the additive parameter keys -- their parameter fields resolve
   to defaults and their endpoint-discovery / parameter-fuzzing enablement is
   unchanged (Requirements 2.1, 2.2, 2.3).

**Validates: Requirements 2.1, 2.2, 2.3**
"""

from __future__ import annotations

import apileaks
from core.config import ConfigurationManager, ParameterFuzzingConfig


TARGET = "https://api.example.test/resource"


def _load(config_dict):
    """Resolve a raw config dict into a validated APILeakConfig (offline)."""
    return ConfigurationManager().load_config_from_dict(config_dict)


# --------------------------------------------------------------------------- #
# (1) End-to-end threading of the new par keys + transversal transport keys
# --------------------------------------------------------------------------- #

class TestParameterKeyThreadingEndToEnd:
    """The new fuzzing.parameters.* keys thread from the config factory through
    load_config_from_dict into the extended ParameterFuzzingConfig."""

    def _threaded_config_dict(self, factory):
        """Build a par config dict with every new parameter key populated."""
        return factory(
            TARGET, None, "par",
            parameter_methods=["GET", "DELETE"],
            confirm_hits=3,
            parameter_max_requests=250,
            query_candidates=["q_alpha", "q_beta"],
            body_candidates=["b_gamma"],
        )

    def test_create_default_config_threads_parameter_keys(self):
        config_dict = self._threaded_config_dict(apileaks.create_default_config)

        # The raw dict carries the values under fuzzing.parameters.*
        params = config_dict["fuzzing"]["parameters"]
        assert params["methods"] == ["GET", "DELETE"]
        assert params["confirm_hits"] == 3
        assert params["max_requests"] == 250
        assert params["query_candidates"] == ["q_alpha", "q_beta"]
        assert params["body_candidates"] == ["b_gamma"]

        # And they map onto the extended ParameterFuzzingConfig dataclass.
        cfg = _load(config_dict)
        pf = cfg.fuzzing.parameters
        assert pf.methods == ["GET", "DELETE"]
        assert pf.confirm_hits == 3
        assert pf.max_requests == 250
        assert pf.query_candidates == ["q_alpha", "q_beta"]
        assert pf.body_candidates == ["b_gamma"]

    def test_create_enhanced_config_threads_parameter_keys(self):
        config_dict = self._threaded_config_dict(apileaks.create_enhanced_config)

        cfg = _load(config_dict)
        pf = cfg.fuzzing.parameters
        assert pf.methods == ["GET", "DELETE"]
        assert pf.confirm_hits == 3
        assert pf.max_requests == 250
        assert pf.query_candidates == ["q_alpha", "q_beta"]
        assert pf.body_candidates == ["b_gamma"]

    def test_transversal_transport_keys_thread_end_to_end(self):
        """client_cert / ca_bundle / resolve thread onto the resolved config."""
        resolve_override = ("api.example.test", "127.0.0.1")
        config_dict = apileaks.create_default_config(
            TARGET, None, "par",
            client_cert="/tmp/client.pem",
            ca_bundle="/tmp/ca.pem",
            resolve=resolve_override,
        )

        # Raw dict carries the transversal keys at the top level.
        assert config_dict["client_cert"] == "/tmp/client.pem"
        assert config_dict["ca_bundle"] == "/tmp/ca.pem"
        assert config_dict["resolve"] == resolve_override

        # And they resolve onto the APILeakConfig.
        cfg = _load(config_dict)
        assert cfg.client_cert == "/tmp/client.pem"
        assert cfg.ca_bundle == "/tmp/ca.pem"
        assert cfg.resolve == resolve_override

    def test_omitted_parameter_keys_fall_back_to_defaults(self):
        """When the new keys are omitted, the resolved config keeps the extended
        dataclass defaults (so threading is opt-in and inert when unused)."""
        cfg = _load(apileaks.create_default_config(TARGET, None, "par"))
        pf = cfg.fuzzing.parameters
        defaults = ParameterFuzzingConfig()

        assert pf.methods == defaults.methods == ["GET", "POST"]
        assert pf.confirm_hits is None
        assert pf.max_requests is None
        assert pf.query_candidates is None
        assert pf.body_candidates is None

        # Transversal keys default to None when not supplied.
        assert cfg.client_cert is None
        assert cfg.ca_bundle is None
        assert cfg.resolve is None


# --------------------------------------------------------------------------- #
# (2) par preservation: endpoints disabled, parameters enabled
# --------------------------------------------------------------------------- #

class TestParModePreservation:
    """A ``par`` invocation continues to disable endpoint discovery and enable
    parameter fuzzing, both in the raw dict and the resolved config."""

    def test_par_disables_endpoints_enables_parameters_default_factory(self):
        config_dict = apileaks.create_default_config(TARGET, None, "par")

        assert config_dict["fuzzing"]["endpoints"]["enabled"] is False
        assert config_dict["fuzzing"]["parameters"]["enabled"] is True

        cfg = _load(config_dict)
        assert cfg.fuzzing.endpoints.enabled is False
        assert cfg.fuzzing.parameters.enabled is True

    def test_par_disables_endpoints_enables_parameters_enhanced_factory(self):
        config_dict = apileaks.create_enhanced_config(TARGET, None, "par")

        assert config_dict["fuzzing"]["endpoints"]["enabled"] is False
        assert config_dict["fuzzing"]["parameters"]["enabled"] is True

        cfg = _load(config_dict)
        assert cfg.fuzzing.endpoints.enabled is False
        assert cfg.fuzzing.parameters.enabled is True

    def test_par_preservation_holds_even_with_new_keys_threaded(self):
        """Threading the additive keys must not disturb the par enable/disable
        assignment."""
        config_dict = apileaks.create_default_config(
            TARGET, None, "par",
            parameter_methods=["POST", "PUT"],
            confirm_hits=2,
            parameter_max_requests=10,
            query_candidates=["q"],
            body_candidates=["b"],
            client_cert="/tmp/c.pem",
            ca_bundle="/tmp/ca.pem",
            resolve=("h", "1.2.3.4"),
        )
        cfg = _load(config_dict)
        assert cfg.fuzzing.endpoints.enabled is False
        assert cfg.fuzzing.parameters.enabled is True


# --------------------------------------------------------------------------- #
# (3) Behavior preservation: other commands' config is unaffected (R2.1-R2.3)
# --------------------------------------------------------------------------- #

class TestOtherCommandsUnaffected:
    """dir / scan / full config is unaffected by the additive parameter keys."""

    def test_dir_endpoint_and_parameter_enablement(self):
        cfg = _load(apileaks.create_default_config(TARGET, None, "dir"))
        # dir discovers endpoints and does NOT fuzz parameters.
        assert cfg.fuzzing.endpoints.enabled is True
        assert cfg.fuzzing.parameters.enabled is False

    def test_full_endpoint_and_parameter_enablement(self):
        cfg = _load(apileaks.create_enhanced_config(TARGET, None, "full"))
        # full does both discovery and parameter fuzzing.
        assert cfg.fuzzing.endpoints.enabled is True
        assert cfg.fuzzing.parameters.enabled is True

    def test_dir_parameter_fields_resolve_to_defaults(self):
        """dir never supplies the new parameter keys, so they resolve to the
        extended dataclass defaults (no leakage from the par threading path)."""
        cfg = _load(apileaks.create_default_config(TARGET, None, "dir"))
        pf = cfg.fuzzing.parameters
        defaults = ParameterFuzzingConfig()

        assert pf.methods == defaults.methods
        assert pf.confirm_hits is None
        assert pf.max_requests is None
        assert pf.query_candidates is None
        assert pf.body_candidates is None

    def test_full_parameter_fields_resolve_to_defaults(self):
        cfg = _load(apileaks.create_enhanced_config(TARGET, None, "full"))
        pf = cfg.fuzzing.parameters

        assert pf.confirm_hits is None
        assert pf.max_requests is None
        assert pf.query_candidates is None
        assert pf.body_candidates is None

    def test_dir_and_full_transversal_keys_default_when_omitted(self):
        for factory, scan_type in (
            (apileaks.create_default_config, "dir"),
            (apileaks.create_enhanced_config, "full"),
        ):
            cfg = _load(factory(TARGET, None, scan_type))
            assert cfg.client_cert is None
            assert cfg.ca_bundle is None
            assert cfg.resolve is None

    def test_threading_par_keys_does_not_mutate_dir_config(self):
        """Building a fully-threaded par config alongside a plain dir config must
        leave the dir config's parameter fields at their defaults (the additive
        threading is scoped to the par path only)."""
        apileaks.create_default_config(
            TARGET, None, "par",
            parameter_methods=["DELETE"],
            confirm_hits=5,
            parameter_max_requests=1,
            query_candidates=["leak_q"],
            body_candidates=["leak_b"],
        )
        dir_cfg = _load(apileaks.create_default_config(TARGET, None, "dir"))
        pf = dir_cfg.fuzzing.parameters

        assert pf.methods == ["GET", "POST"]
        assert pf.confirm_hits is None
        assert pf.max_requests is None
        assert pf.query_candidates is None
        assert pf.body_candidates is None


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
