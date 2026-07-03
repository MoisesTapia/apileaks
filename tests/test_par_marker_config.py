"""Unit tests for par positional-marker config fields and end-to-end threading
(spec: par-positional-markers, tasks 2.1, 2.2, 2.3).

Five guarantees are verified, fully offline (no HTTP requests):

1. ``ParameterFuzzingConfig()`` defaults: ``fuzz_keyword == "FUZZ"``,
   ``fuzz_mode == "clusterbomb"``, ``marker_wordlists is None``.
2. Explicit construction round-trips: supplying non-default values works.
3. End-to-end threading: ``create_default_config(..., scan_type="par",
   fuzz_keyword=..., fuzz_mode=..., marker_wordlists=...)`` produces a config
   dict where ``config_dict['fuzzing']['parameters']`` carries the supplied
   values.
4. ``load_config_from_dict`` maps the three keys into a ``ParameterFuzzingConfig``
   object correctly.
5. Other scan types (``"dir"``, ``"scan"``, ``"full"``) are unaffected: their
   ``fuzzing.parameters`` sections do NOT receive the marker keys and the rest of
   their config is undisturbed.

Requirements: 2.4, 2.5, 10.7
"""

from __future__ import annotations

import apileaks
from core.config import ConfigurationManager, ParameterFuzzingConfig


TARGET = "https://api.example.test/v1/resource"


def _load(config_dict):
    """Resolve a raw config dict into a validated APILeakConfig (offline)."""
    return ConfigurationManager().load_config_from_dict(config_dict)


# --------------------------------------------------------------------------- #
# 1.  ParameterFuzzingConfig defaults
# --------------------------------------------------------------------------- #

class TestParameterFuzzingConfigMarkerDefaults:
    """ParameterFuzzingConfig() constructs with the correct marker-field defaults
    (Requirements 1.1, 5.1, 7.1).  All three fields must be present and must not
    affect any pre-existing field default."""

    def test_fuzz_keyword_default(self):
        config = ParameterFuzzingConfig()
        assert config.fuzz_keyword == "FUZZ"

    def test_fuzz_mode_default(self):
        config = ParameterFuzzingConfig()
        assert config.fuzz_mode == "clusterbomb"

    def test_marker_wordlists_default_is_none(self):
        """None is the Name_Discovery_Mode sentinel (R2.1)."""
        config = ParameterFuzzingConfig()
        assert config.marker_wordlists is None

    def test_pre_existing_defaults_are_unchanged(self):
        """Adding three new fields must not perturb any pre-existing default."""
        config = ParameterFuzzingConfig()
        assert config.enabled is True
        assert config.query_wordlist == "wordlists/parameters.txt"
        assert config.body_wordlist == "wordlists/parameters.txt"
        assert config.boundary_testing is True
        assert config.methods == ["GET", "POST"]
        assert config.confirm_hits is None
        assert config.max_requests is None
        assert config.query_candidates is None
        assert config.body_candidates is None


# --------------------------------------------------------------------------- #
# 2.  Explicit construction round-trips
# --------------------------------------------------------------------------- #

class TestParameterFuzzingConfigExplicitConstruction:
    """Supplying non-default marker values produces the expected object state."""

    def test_custom_fuzz_keyword(self):
        config = ParameterFuzzingConfig(fuzz_keyword="LEAK")
        assert config.fuzz_keyword == "LEAK"

    def test_custom_fuzz_mode(self):
        config = ParameterFuzzingConfig(fuzz_mode="pitchfork")
        assert config.fuzz_mode == "pitchfork"

    def test_custom_marker_wordlists(self):
        wl = [["a", "b"], ["c", "d"]]
        config = ParameterFuzzingConfig(marker_wordlists=wl)
        assert config.marker_wordlists == [["a", "b"], ["c", "d"]]

    def test_all_three_fields_together(self):
        wl = [["v1", "v2"]]
        config = ParameterFuzzingConfig(
            fuzz_keyword="LEAK",
            fuzz_mode="pitchfork",
            marker_wordlists=wl,
        )
        assert config.fuzz_keyword == "LEAK"
        assert config.fuzz_mode == "pitchfork"
        assert config.marker_wordlists == [["v1", "v2"]]

    def test_other_fields_unaffected_when_only_marker_fields_supplied(self):
        config = ParameterFuzzingConfig(
            fuzz_keyword="X",
            fuzz_mode="pitchfork",
            marker_wordlists=[["val"]],
        )
        # Every pre-existing field must still carry its default.
        assert config.enabled is True
        assert config.query_wordlist == "wordlists/parameters.txt"
        assert config.body_wordlist == "wordlists/parameters.txt"
        assert config.boundary_testing is True
        assert config.methods == ["GET", "POST"]
        assert config.confirm_hits is None
        assert config.max_requests is None
        assert config.query_candidates is None
        assert config.body_candidates is None


# --------------------------------------------------------------------------- #
# 3.  End-to-end threading through create_default_config
# --------------------------------------------------------------------------- #

class TestMarkerKeyThreadingThroughCreateDefaultConfig:
    """create_default_config with scan_type="par" writes the three marker keys
    under config_dict['fuzzing']['parameters'] (Requirements 2.4, 2.5)."""

    def test_fuzz_keyword_threaded_into_raw_dict(self):
        config_dict = apileaks.create_default_config(
            TARGET, None, "par", fuzz_keyword="X"
        )
        assert config_dict["fuzzing"]["parameters"]["fuzz_keyword"] == "X"

    def test_fuzz_mode_threaded_into_raw_dict(self):
        config_dict = apileaks.create_default_config(
            TARGET, None, "par", fuzz_mode="pitchfork"
        )
        assert config_dict["fuzzing"]["parameters"]["fuzz_mode"] == "pitchfork"

    def test_marker_wordlists_threaded_into_raw_dict(self):
        wl = [["v1", "v2"]]
        config_dict = apileaks.create_default_config(
            TARGET, None, "par", marker_wordlists=wl
        )
        assert config_dict["fuzzing"]["parameters"]["marker_wordlists"] == [["v1", "v2"]]

    def test_all_three_marker_keys_together(self):
        wl = [["v1", "v2"]]
        config_dict = apileaks.create_default_config(
            TARGET, None, "par",
            fuzz_keyword="X",
            fuzz_mode="pitchfork",
            marker_wordlists=wl,
        )
        params = config_dict["fuzzing"]["parameters"]
        assert params["fuzz_keyword"] == "X"
        assert params["fuzz_mode"] == "pitchfork"
        assert params["marker_wordlists"] == [["v1", "v2"]]

    def test_par_enablement_preserved(self):
        """Adding marker keys must not break the par-specific enablement."""
        config_dict = apileaks.create_default_config(
            TARGET, None, "par",
            fuzz_keyword="X",
            fuzz_mode="pitchfork",
            marker_wordlists=[["v1"]],
        )
        assert config_dict["fuzzing"]["endpoints"]["enabled"] is False
        assert config_dict["fuzzing"]["parameters"]["enabled"] is True

    def test_create_enhanced_config_also_threads_marker_keys(self):
        """create_enhanced_config (the delegate) is also correct."""
        wl = [["v1", "v2"]]
        config_dict = apileaks.create_enhanced_config(
            TARGET, None, "par",
            fuzz_keyword="X",
            fuzz_mode="pitchfork",
            marker_wordlists=wl,
        )
        params = config_dict["fuzzing"]["parameters"]
        assert params["fuzz_keyword"] == "X"
        assert params["fuzz_mode"] == "pitchfork"
        assert params["marker_wordlists"] == [["v1", "v2"]]


# --------------------------------------------------------------------------- #
# 4.  load_config_from_dict maps marker keys onto ParameterFuzzingConfig
# --------------------------------------------------------------------------- #

class TestLoadConfigFromDictMarkerKeys:
    """The three marker keys thread from the raw config dict all the way through
    load_config_from_dict into a ParameterFuzzingConfig dataclass
    (Requirements 1.1, 5.1, 7.1, 10.7)."""

    def _build_and_load(self, fuzz_keyword="FUZZ", fuzz_mode="clusterbomb",
                        marker_wordlists=None):
        config_dict = apileaks.create_default_config(
            TARGET, None, "par",
            fuzz_keyword=fuzz_keyword,
            fuzz_mode=fuzz_mode,
            marker_wordlists=marker_wordlists,
        )
        return _load(config_dict)

    def test_fuzz_keyword_maps_onto_config_object(self):
        cfg = self._build_and_load(fuzz_keyword="LEAK")
        assert cfg.fuzzing.parameters.fuzz_keyword == "LEAK"

    def test_fuzz_mode_maps_onto_config_object(self):
        cfg = self._build_and_load(fuzz_mode="pitchfork")
        assert cfg.fuzzing.parameters.fuzz_mode == "pitchfork"

    def test_marker_wordlists_maps_onto_config_object(self):
        wl = [["v1", "v2"]]
        cfg = self._build_and_load(marker_wordlists=wl)
        assert cfg.fuzzing.parameters.marker_wordlists == [["v1", "v2"]]

    def test_all_three_fields_together(self):
        wl = [["v1", "v2"]]
        cfg = self._build_and_load(
            fuzz_keyword="X",
            fuzz_mode="pitchfork",
            marker_wordlists=wl,
        )
        pf = cfg.fuzzing.parameters
        assert pf.fuzz_keyword == "X"
        assert pf.fuzz_mode == "pitchfork"
        assert pf.marker_wordlists == [["v1", "v2"]]

    def test_marker_wordlists_none_is_name_discovery_sentinel(self):
        """marker_wordlists=None leaves Name_Discovery_Mode enabled (R2.1)."""
        cfg = self._build_and_load(marker_wordlists=None)
        assert cfg.fuzzing.parameters.marker_wordlists is None

    def test_default_values_round_trip_correctly(self):
        """When no marker args are supplied the defaults survive the round-trip."""
        config_dict = apileaks.create_default_config(TARGET, None, "par")
        cfg = _load(config_dict)
        pf = cfg.fuzzing.parameters
        assert pf.fuzz_keyword == "FUZZ"
        assert pf.fuzz_mode == "clusterbomb"
        assert pf.marker_wordlists is None


# --------------------------------------------------------------------------- #
# 5.  Other scan types are unaffected
# --------------------------------------------------------------------------- #

class TestOtherScanTypesUnaffected:
    """dir / scan / full config must not receive marker keys under their
    fuzzing.parameters section (Requirements 2.4, 2.5, 10.7).
    The marker keys only get written for scan_type == "par"."""

    def _params_for(self, scan_type):
        config_dict = apileaks.create_default_config(TARGET, None, scan_type)
        return config_dict["fuzzing"]["parameters"]

    def test_dir_parameters_section_has_no_marker_keys(self):
        params = self._params_for("dir")
        # The three new keys must NOT be present in the raw dict (they are only
        # injected for par); if they were written unconditionally this assert
        # would still pass because the defaults are benign, but we verify the
        # dict itself lacks them for a clean separation.
        assert "fuzz_keyword" not in params
        assert "fuzz_mode" not in params
        assert "marker_wordlists" not in params

    def test_scan_parameters_section_has_no_marker_keys(self):
        params = self._params_for("scan")
        assert "fuzz_keyword" not in params
        assert "fuzz_mode" not in params
        assert "marker_wordlists" not in params

    def test_full_parameters_section_has_no_marker_keys(self):
        params = self._params_for("full")
        assert "fuzz_keyword" not in params
        assert "fuzz_mode" not in params
        assert "marker_wordlists" not in params

    def test_dir_endpoint_fuzzing_unaffected(self):
        """dir must keep endpoints.enabled=True (its existing behaviour)."""
        config_dict = apileaks.create_default_config(TARGET, None, "dir")
        assert config_dict["fuzzing"]["endpoints"]["enabled"] is True

    def test_dir_parameters_enabled_is_false(self):
        config_dict = apileaks.create_default_config(TARGET, None, "dir")
        assert config_dict["fuzzing"]["parameters"]["enabled"] is False

    def test_full_endpoint_and_parameter_both_enabled(self):
        config_dict = apileaks.create_default_config(TARGET, None, "full")
        assert config_dict["fuzzing"]["endpoints"]["enabled"] is True
        assert config_dict["fuzzing"]["parameters"]["enabled"] is True

    def test_dir_loaded_config_marker_fields_carry_dataclass_defaults(self):
        """Even for dir, the loaded ParameterFuzzingConfig must carry the
        dataclass defaults for the new marker fields (they were never set in the
        raw dict, so they come from the dataclass definition itself)."""
        cfg = _load(apileaks.create_default_config(TARGET, None, "dir"))
        pf = cfg.fuzzing.parameters
        assert pf.fuzz_keyword == "FUZZ"
        assert pf.fuzz_mode == "clusterbomb"
        assert pf.marker_wordlists is None
