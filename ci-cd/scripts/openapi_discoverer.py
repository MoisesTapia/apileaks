#!/usr/bin/env python3
"""
openapi_discoverer.py — OpenAPI/Swagger spec loader and endpoint discoverer
for APILeaks CI/CD pipelines.

Supports OpenAPI 2.0 (Swagger), 3.0.x, and 3.1.x.
Loads specs from a URL or a local file, extracts endpoints with security
metadata and ID-parameter detection, and writes results to a JSON report.

Priority: APILEAK_OPENAPI_FILE > APILEAK_OPENAPI_URL  (Req 1.1)
Exit behavior: errors are logged as warnings; the process does NOT exit.
"""

import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ID parameter detection pattern (Req 4.1)
# ---------------------------------------------------------------------------
ID_PARAM_PATTERN = re.compile(r'.*[_-]?id$', re.IGNORECASE)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class EndpointParameter:
    """A single parameter on a discovered endpoint."""
    name: str
    location: str           # "path" | "query" | "body"
    type: str               # "integer" | "string" | "array" | "object" | …
    format: Optional[str]   # "uuid" | "int64" | None …

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location,
            "type": self.type,
            "format": self.format,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EndpointParameter":
        return cls(
            name=d["name"],
            location=d["location"],
            type=d["type"],
            format=d.get("format"),
        )


@dataclass
class DiscoveredEndpoint:
    """Metadata for a single API endpoint extracted from an OpenAPI spec."""
    path: str
    methods: List[str]
    security_schemes: List[str]
    is_authenticated: bool
    parameters: List[EndpointParameter]
    id_parameters: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "methods": self.methods,
            "security_schemes": self.security_schemes,
            "is_authenticated": self.is_authenticated,
            "parameters": [p.to_dict() for p in self.parameters],
            "id_parameters": self.id_parameters,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "DiscoveredEndpoint":
        return cls(
            path=d["path"],
            methods=d["methods"],
            security_schemes=d["security_schemes"],
            is_authenticated=d["is_authenticated"],
            parameters=[EndpointParameter.from_dict(p) for p in d.get("parameters", [])],
            id_parameters=d.get("id_parameters", []),
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DiscoveredEndpoint):
            return NotImplemented
        return (
            self.path == other.path
            and sorted(self.methods) == sorted(other.methods)
            and sorted(self.security_schemes) == sorted(other.security_schemes)
            and self.is_authenticated == other.is_authenticated
            and sorted((p.name, p.location, p.type, p.format) for p in self.parameters)
            == sorted((p.name, p.location, p.type, p.format) for p in other.parameters)
            and sorted(self.id_parameters) == sorted(other.id_parameters)
        )

    def __hash__(self) -> int:
        return hash((
            self.path,
            tuple(sorted(self.methods)),
            tuple(sorted(self.security_schemes)),
            self.is_authenticated,
            tuple(sorted((p.name, p.location, p.type, p.format) for p in self.parameters)),
            tuple(sorted(self.id_parameters)),
        ))


@dataclass
class ScanMeta:
    """Pipeline-level metadata attached to a scan run."""
    pipeline_id: str
    project_name: str
    target_url: str
    scan_start: datetime
    scan_end: datetime
    apileaks_version: str
    openapi_endpoints_discovered: int = 0
    openapi_endpoints_scanned: int = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_id_param(name: str, param_type: str, param_format: Optional[str]) -> bool:
    """Return True when the parameter should be treated as an ID parameter.

    Criteria (Req 4.1):
    - Name matches ID_PARAM_PATTERN (e.g. user_id, userId, id …)
    - OR type is 'integer'
    - OR type is 'string' with format 'uuid'
    """
    if ID_PARAM_PATTERN.match(name):
        return True
    if param_type == "integer":
        return True
    if param_type == "string" and param_format == "uuid":
        return True
    return False


def _parse_parameter(raw: Dict[str, Any]) -> EndpointParameter:
    """Convert a raw OpenAPI parameter object to an EndpointParameter."""
    name = raw.get("name", "")
    location = raw.get("in", "query")  # path / query / header / cookie / body / formData

    # Normalise location to the three documented values
    if location in ("formData", "body"):
        location = "body"
    elif location == "path":
        location = "path"
    else:
        location = "query"

    # OpenAPI 2: type/format at top level
    # OpenAPI 3: type/format under schema
    schema = raw.get("schema", {}) or {}
    param_type = raw.get("type") or schema.get("type") or "string"
    param_format = raw.get("format") or schema.get("format") or None

    return EndpointParameter(
        name=name,
        location=location,
        type=param_type,
        format=param_format,
    )


def _security_names_from_requirement(requirement: List[Dict[str, Any]]) -> List[str]:
    """Extract a flat list of security scheme names from a security requirement array."""
    names: List[str] = []
    for item in requirement:
        names.extend(item.keys())
    return names


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class OpenAPIDiscoverer:
    """Loads an OpenAPI specification and discovers endpoints.

    Source priority (Req 1.1): file > URL.
    When both are provided, a WARNING is logged and the URL is ignored.
    """

    ID_PARAM_PATTERN = ID_PARAM_PATTERN

    def __init__(
        self,
        source_url: Optional[str] = None,
        source_file: Optional[str] = None,
    ) -> None:
        # Determine effective source respecting priority (Req 1.1)
        if source_file and source_url:
            logger.warning(
                "Both APILEAK_OPENAPI_FILE (%s) and APILEAK_OPENAPI_URL (%s) are defined. "
                "APILEAK_OPENAPI_FILE takes priority; APILEAK_OPENAPI_URL will be ignored.",
                source_file,
                source_url,
            )

        self.source_file: Optional[str] = source_file
        self.source_url: Optional[str] = source_url
        self._spec: Optional[Dict[str, Any]] = None

    # -----------------------------------------------------------------------
    # Internal loaders
    # -----------------------------------------------------------------------

    def _parse_content(self, content: str, hint: str) -> Optional[Dict[str, Any]]:
        """Try JSON first, then YAML.  Returns None and logs on failure."""
        # Try JSON
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass

        # Try YAML
        if _YAML_AVAILABLE:
            try:
                result = yaml.safe_load(content)
                if isinstance(result, dict):
                    return result
                logger.warning(
                    "YAML parsed from %s did not produce a dict (got %s). "
                    "Continuing with no spec.",
                    hint, type(result).__name__,
                )
                return None
            except yaml.YAMLError as exc:
                logger.warning(
                    "Failed to parse %s as YAML: %s. Continuing with no spec.", hint, exc
                )
                return None
        else:
            logger.warning(
                "Could not parse %s as JSON and PyYAML is not available. "
                "Continuing with no spec.",
                hint,
            )
            return None

    def _load_from_file(self, path: str) -> Optional[Dict[str, Any]]:
        """Load and parse a spec from a local file path."""
        try:
            with open(path, "r", encoding="utf-8") as fh:
                content = fh.read()
        except OSError as exc:
            logger.warning(
                "Failed to read OpenAPI spec file '%s': %s (%s). Continuing with no spec.",
                path, exc, type(exc).__name__,
            )
            return None
        return self._parse_content(content, path)

    def _load_from_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Fetch and parse a spec from an HTTP(S) URL."""
        if not _REQUESTS_AVAILABLE:
            logger.warning(
                "Cannot fetch '%s': 'requests' library is not available. "
                "Continuing with no spec.",
                url,
            )
            return None
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            content = response.text
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Network error while fetching OpenAPI spec from '%s': %s (%s). "
                "Continuing with no spec.",
                url, exc, type(exc).__name__,
            )
            return None
        return self._parse_content(content, url)

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def load(self) -> Optional[Dict[str, Any]]:
        """Load the OpenAPI spec from the configured source.

        File takes priority over URL (Req 1.1).
        On any error (network, parse, missing file): logs a warning and
        returns None — never raises or exits.

        Supports OpenAPI 2.0, 3.0.x, 3.1.x (Req 1.4).
        """
        if self.source_file:
            self._spec = self._load_from_file(self.source_file)
        elif self.source_url:
            self._spec = self._load_from_url(self.source_url)
        else:
            logger.warning(
                "No OpenAPI source configured "
                "(APILEAK_OPENAPI_FILE and APILEAK_OPENAPI_URL are both unset). "
                "Continuing with no spec."
            )
            self._spec = None

        return self._spec

    # -----------------------------------------------------------------------
    # Endpoint discovery
    # -----------------------------------------------------------------------

    def discover_endpoints(self) -> List[DiscoveredEndpoint]:
        """Extract all endpoints from the loaded spec.

        Must be called after load().  If the spec is None / unparsed the
        method returns an empty list.

        Marks is_authenticated based on declared security schemes (Req 1.2).
        Identifies ID parameters (Req 4.1).
        Round-trip stable — serializing to JSON and re-parsing produces
        identical DiscoveredEndpoint objects (Req 1.6).
        """
        if self._spec is None:
            return []

        spec = self._spec

        # Determine spec version
        openapi_version = spec.get("openapi", "")   # 3.x
        swagger_version = spec.get("swagger", "")   # 2.x

        # Global security requirement (applies when an operation has no own security)
        global_security: List[Dict[str, Any]] = spec.get("security", []) or []

        # Collect defined security scheme names so we can report them
        if swagger_version.startswith("2"):
            defined_schemes: Dict[str, Any] = spec.get("securityDefinitions", {}) or {}
        else:
            # openapi 3.x
            components = spec.get("components", {}) or {}
            defined_schemes = components.get("securitySchemes", {}) or {}

        paths: Dict[str, Any] = spec.get("paths", {}) or {}
        endpoints: List[DiscoveredEndpoint] = []

        HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            # Path-level parameters (merged into each operation below)
            path_level_params: List[Dict[str, Any]] = path_item.get("parameters", []) or []

            # Collect all methods for this path that describe operations
            method_names = [
                m for m in path_item.keys() if m.lower() in HTTP_METHODS
            ]

            if not method_names:
                continue

            # Gather endpoint-level attributes across all methods on this path
            all_methods: List[str] = []
            all_security_scheme_names: List[str] = []
            any_authenticated = False
            all_parameters: List[EndpointParameter] = []

            for method in method_names:
                operation: Dict[str, Any] = path_item[method]
                if not isinstance(operation, dict):
                    continue

                all_methods.append(method.upper())

                # Security resolution (Req 1.2)
                # An operation can override global security with its own `security` key.
                # An empty list [] means "no auth required" (explicit override).
                op_security_raw = operation.get("security")  # None = not overridden
                if op_security_raw is not None:
                    effective_security = op_security_raw
                else:
                    effective_security = global_security

                is_auth = len(effective_security) > 0
                if is_auth:
                    any_authenticated = True

                scheme_names = _security_names_from_requirement(effective_security)
                for s in scheme_names:
                    if s not in all_security_scheme_names:
                        all_security_scheme_names.append(s)

                # Parameters — merge path-level + operation-level (operation wins on name+in)
                op_params_raw: List[Dict[str, Any]] = operation.get("parameters", []) or []
                merged_params_raw: Dict[tuple, Dict[str, Any]] = {}

                for p in path_level_params:
                    key = (p.get("name", ""), p.get("in", ""))
                    merged_params_raw[key] = p
                for p in op_params_raw:
                    key = (p.get("name", ""), p.get("in", ""))
                    merged_params_raw[key] = p

                for raw_param in merged_params_raw.values():
                    ep = _parse_parameter(raw_param)
                    # Avoid duplicates across methods on the same path
                    if not any(
                        existing.name == ep.name and existing.location == ep.location
                        for existing in all_parameters
                    ):
                        all_parameters.append(ep)

            if not all_methods:
                continue

            # Identify ID parameters (Req 4.1)
            id_param_names = [
                p.name for p in all_parameters
                if _is_id_param(p.name, p.type, p.format)
            ]

            endpoints.append(DiscoveredEndpoint(
                path=path,
                methods=sorted(all_methods),
                security_schemes=sorted(all_security_scheme_names),
                is_authenticated=any_authenticated,
                parameters=all_parameters,
                id_parameters=id_param_names,
            ))

        return endpoints

    def get_id_endpoints(self) -> List[DiscoveredEndpoint]:
        """Return only endpoints that have at least one ID parameter."""
        return [ep for ep in self.discover_endpoints() if ep.id_parameters]

    def get_authenticated_endpoints(self) -> List[DiscoveredEndpoint]:
        """Return only endpoints that require authentication."""
        return [ep for ep in self.discover_endpoints() if ep.is_authenticated]

    def write_output(
        self,
        pipeline_id: str,
        output_dir: str = "reports",
    ) -> str:
        """Serialize discovered endpoints to JSON and write to output_dir.

        Filename: openapi-endpoints-{pipeline_id}.json  (Req 1.5)
        Returns the absolute path of the written file.
        """
        endpoints = self.discover_endpoints()
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        output_path = os.path.join(output_dir, f"openapi-endpoints-{pipeline_id}.json")
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump([ep.to_dict() for ep in endpoints], fh, indent=2)
        logger.info(
            "Wrote %d discovered endpoint(s) to %s", len(endpoints), output_path
        )
        return output_path


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    source_url = os.environ.get("APILEAK_OPENAPI_URL")
    source_file = os.environ.get("APILEAK_OPENAPI_FILE")
    pipeline_id = os.environ.get("APILEAK_PIPELINE_ID", "local")

    discoverer = OpenAPIDiscoverer(source_url=source_url, source_file=source_file)
    discoverer.load()
    output_path = discoverer.write_output(pipeline_id=pipeline_id)
    print(f"OpenAPI discovery complete. Output: {output_path}")
    sys.exit(0)
