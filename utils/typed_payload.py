"""
Schema-directed request body and parameter builders (Req 52).

This module is a small, pure (no network IO, no file IO, no request issuance)
helper that turns a :class:`~utils.spec_import.SpecOperation` into schema-valid
request bodies and parameter values. It is consumed by BOLA write probes and the
Property mass-assignment checks to construct a valid base payload and then inject
the field(s) under test on top of it. It never issues a request; request gating
stays in the modules.

Values honor the declared JSON Schema semantics (Reqs 52.1-52.3):

* Every property listed in a schema's ``required`` list is present in the built
  body, and each value matches the declared ``type``
  (``string``/``integer``/``number``/``boolean``/``array``/``object``) (Req 52.1).
* When a property declares an ``enum``, the chosen value is drawn from the enum
  (Req 52.2).
* When a property declares an ``example`` (or ``examples``), that declared value
  is preferred (Req 52.3).

:func:`build_typed_payload` returns ``{}`` when the operation declares no request
body (``request_body_schema`` is ``None``), preserving existing behavior
(Req 52.6). ``overrides``, when supplied, are always applied on top of the built
base (even for fields not declared in the schema, and even when no schema is
declared) so callers can inject a mass-assignment or BOLA-mutated field.
"""

from typing import Any, Dict, List, Optional, Tuple, Union

from utils.spec_import import SpecOperation, SpecParameter

# Parameter locations whose values are built by :func:`build_typed_params`.
# ``path`` parameters are intentionally excluded; those are handled elsewhere.
_PAYLOAD_PARAMETER_LOCATIONS = ("query", "header")

# Canonical value produced for each declared JSON Schema type when no
# ``example``/``examples`` and no ``enum`` narrow the choice. An unknown or
# absent type defaults to ``"string"``.
_CANONICAL_BY_TYPE: Dict[str, Any] = {
    "string": "x",
    "integer": 1,
    "number": 1.0,
    "boolean": True,
    "array": None,  # handled specially so the item type is honored
    "object": {},
}


def build_typed_payload(
    operation: SpecOperation,
    overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Construct a request body honoring ``operation.request_body_schema``.

    Every property listed in the schema's ``required`` list is present in the
    result, and each generated value matches the declared JSON Schema ``type``
    (Req 52.1). A property that declares an ``enum`` takes a value drawn from the
    enum (Req 52.2); a property that declares an ``example``/``examples`` prefers
    the declared value (Req 52.3).

    ``overrides`` lets a caller inject the field(s) under test (for example a
    mass-assignment ``is_admin`` or a BOLA-mutated field) on top of the valid
    base; overrides take precedence over generated values and may introduce
    fields not declared in the schema.

    Returns ``{}`` when the operation declares no request body
    (``request_body_schema`` is ``None``), applying ``overrides`` on top of that
    empty base when they are supplied (Req 52.6).
    """
    schema = operation.request_body_schema
    body: Dict[str, Any] = {}

    if schema is not None:
        properties = schema.get("properties") or {}
        required = schema.get("required") or []

        # Emit every declared property so required fields are always present and
        # the base body is representative. Non-required properties are harmless
        # to include and keep the payload schema-valid.
        for name, prop in properties.items():
            if isinstance(prop, dict):
                body[name] = _value_for(prop)

        # Defensively cover any required field that lacks a full property node so
        # the required contract (Req 52.1) still holds.
        for name in required:
            if name not in body:
                declared = properties.get(name)
                body[name] = _value_for(declared if isinstance(declared, dict) else {})

    if overrides:
        body.update(overrides)

    return body


def apply_actor_profile(
    auth_context: Any,
    endpoint: str,
    *,
    query: Optional[Dict[str, Any]] = None,
    body: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Overlay an Auth_Context's Actor_Profile per-endpoint values onto a base.

    Consumes the per-identity :class:`~core.config.ActorProfile` carried by an
    :class:`~core.config.AuthContext` (Requirement 54.2). The typed base values
    produced by :func:`build_typed_params`/:func:`build_typed_payload` (or a
    module's existing values) are passed in as ``query`` and ``body``; the
    profile's ``query``/``body`` values for ``endpoint`` are merged on top, with
    the **profile values taking precedence** over the base.

    Behavior when nothing applies (each preserved independently so callers keep
    their existing behavior without error):

    * When ``auth_context`` carries no ``actor_profile`` (Requirement 54.3), or
    * When the profile omits ``endpoint`` for a given section (Requirement 54.4),

    the corresponding base is returned unchanged (a ``None`` base stays ``None``
    so a caller that was not sending query params/body keeps doing so).

    Returns ``(query, body)`` — the (possibly merged) values to pass to the
    request. Neither the base dicts nor the profile dicts are mutated.
    """
    profile = getattr(auth_context, "actor_profile", None) if auth_context is not None else None
    if profile is None:
        return query, body

    profile_query = getattr(profile, "query", None)
    if isinstance(profile_query, dict):
        overlay = profile_query.get(endpoint)
        if isinstance(overlay, dict) and overlay:
            query = {**(query or {}), **overlay}

    profile_body = getattr(profile, "body", None)
    if isinstance(profile_body, dict):
        overlay = profile_body.get(endpoint)
        if isinstance(overlay, dict) and overlay:
            body = {**(body or {}), **overlay}

    return query, body


def build_typed_params(operation: SpecOperation) -> Dict[str, Dict[str, Any]]:
    """Build valid values for ``query`` and ``header`` parameters.

    Returns a mapping grouped by parameter ``location`` (for example
    ``{"query": {...}, "header": {...}}``), honoring type/required/enum/example
    the same way as :func:`build_typed_payload` (Reqs 52.1-52.3). Required
    parameters are always included; optional parameters are included as well.
    ``path`` parameters are intentionally excluded.
    """
    grouped: Dict[str, Dict[str, Any]] = {loc: {} for loc in _PAYLOAD_PARAMETER_LOCATIONS}

    for param in operation.parameters:
        if param.location in grouped:
            grouped[param.location][param.name] = _value_for(param)

    return grouped


def _value_for(spec: Union[SpecParameter, Dict[str, Any]]) -> Any:
    """Type-directed value factory for a parameter or JSON Schema property node.

    Accepts either a :class:`~utils.spec_import.SpecParameter` or a raw JSON
    Schema property node (``dict``). Precedence: prefer a declared ``example``
    (or the first of ``examples``), then the first ``enum`` value, else a
    canonical value for the declared ``type`` (``string`` -> ``"x"``,
    ``integer`` -> ``1``, ``number`` -> ``1.0``, ``boolean`` -> ``True``,
    ``array`` -> ``[<item>]``, ``object`` -> ``{}``). An unknown or absent type
    defaults to ``"string"`` (Reqs 52.1-52.3).
    """
    example, has_example = _read_example(spec)
    if has_example:
        return example

    enum = _read_enum(spec)
    if enum:
        return enum[0]

    declared_type = _read_type(spec)
    if declared_type == "array":
        item_spec = _read_items(spec)
        return [_value_for(item_spec)]

    canonical = _CANONICAL_BY_TYPE.get(declared_type)
    if canonical is not None:
        # ``object`` maps to a fresh dict so callers never share a mutable value.
        return dict(canonical) if isinstance(canonical, dict) else canonical

    # Unknown or absent type -> default to a string value.
    return _CANONICAL_BY_TYPE["string"]


def _read_type(spec: Union[SpecParameter, Dict[str, Any]]) -> str:
    """Return the declared JSON Schema type, defaulting to ``"string"``."""
    if isinstance(spec, dict):
        declared = spec.get("type")
    else:
        declared = getattr(spec, "type", None)
    return declared if isinstance(declared, str) and declared else "string"


def _read_enum(spec: Union[SpecParameter, Dict[str, Any]]) -> Optional[List[Any]]:
    """Return the declared ``enum`` values when present, else ``None``."""
    if isinstance(spec, dict):
        enum = spec.get("enum")
    else:
        enum = getattr(spec, "enum", None)
    return enum if isinstance(enum, list) and enum else None


def _read_example(spec: Union[SpecParameter, Dict[str, Any]]) -> "tuple[Any, bool]":
    """Return ``(value, found)`` for a declared ``example``/``examples``.

    Prefers a scalar ``example`` when present; otherwise uses the first entry of
    a non-empty ``examples`` list. ``found`` is ``False`` when neither is
    declared, letting the caller fall through to enum/canonical selection.
    """
    if isinstance(spec, dict):
        example = spec.get("example")
        examples = spec.get("examples")
        has_example_key = "example" in spec
    else:
        example = getattr(spec, "example", None)
        examples = getattr(spec, "examples", None)
        has_example_key = example is not None

    if has_example_key and example is not None:
        return example, True
    if isinstance(examples, list) and examples:
        return examples[0], True
    return None, False


def _read_items(spec: Union[SpecParameter, Dict[str, Any]]) -> Dict[str, Any]:
    """Return the ``array`` item schema node, defaulting to an empty node.

    Only raw JSON Schema property nodes carry an ``items`` definition;
    :class:`~utils.spec_import.SpecParameter` has no nested item schema, so an
    empty node is returned (yielding a canonical string item).
    """
    if isinstance(spec, dict):
        items = spec.get("items")
        if isinstance(items, dict):
            return items
    return {}
