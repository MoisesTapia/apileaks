"""
Spec-Driven Security Testing Module

Audits an OpenAPI/Swagger (or Postman) specification's own declared input
contract and checks whether the live API actually enforces it. This is the
one OWASP-registered module that drives its attack surface directly from the
Spec_Schema (``utils/spec_import.py``) instead of from crawled/discovered
endpoints — every declared operation is tested whether or not the discovery
phase ever found it, so it audits the FULL documented surface, including
operations discovery never reached.

``utils/spec_import.py`` already parses, per declared parameter, its
``type`` (string/integer/number/boolean/...), ``required`` flag, ``enum``
values, and ``example`` — but before this module existed nothing in the
codebase read ``SpecParameter.type``/``.enum``/``.required`` to drive test
logic; `bola_testing.py`/`property_level_auth.py`/`ssrf_testing.py` only use
``operation_for()`` to read the raw ``request_body_schema`` dict, never the
per-parameter metadata (see technical-debt/code-quality-audit.md). This
module is what finally consumes that previously-unused metadata:

* **Enum violation** — a query/header parameter declares a fixed ``enum``;
  send a value outside it and check whether the backend still processes the
  request as if it were valid (same success family as a valid baseline).
* **Type confusion** — a parameter is declared ``integer``/``number``/
  ``boolean``; send a value of the wrong type and check whether it's still
  accepted.
* **Required-parameter omission** — a parameter is declared ``required``;
  omit it entirely and check whether the backend still serves the request.

None of these probes are injection payloads — the signal is purely "does the
server enforce the contract it itself publishes?" A spec that promises
validation the implementation doesn't perform is a real, if often
low-individual-severity, security-relevant gap: undeclared/invalid input is
reaching business logic that assumed the contract held.

Scope / limitations (documented honestly, not hidden):
  * Path parameters are filled with a type-appropriate dummy value (or the
    spec's own ``example``) to build a concrete URL; this module does NOT
    try to match discovered endpoints to resolve real path values, since
    ``SpecSchema.operation_for()`` matches on the literal declared path
    template, not a resolved one.
  * Request bodies are built from ``required`` JSON Schema properties only —
    this is a minimal "good enough to pass validation" body, not a full
    schema-conformant payload generator.
  * Each operation is probed with at most a handful of requests (one per
    constrained parameter, plus omission checks), bounded overall by
    ``max_operations``, so auditing a large spec cannot explode into an
    unbounded request count.
"""

from typing import Any
from urllib.parse import urlsplit, urlunsplit

from core.config import AuthContext, Severity, SpecDrivenTestingConfig
from core.logging import get_logger
from utils.findings import Finding
from utils.http_client import HTTPRequestEngine, Response
from utils.safe_mode import SafeModeGuard
from utils.spec_import import SpecOperation, SpecParameter, SpecSchema

from .registry import OWASPModule

# Values used to build a "should be valid" baseline for each declared type.
_TYPE_DEFAULTS: dict[str, str] = {
    "string": "apileak_test",
    "integer": "1",
    "number": "1.0",
    "boolean": "true",
}

# Deliberately wrong-typed values to probe type enforcement.
_TYPE_CONFUSION_VALUES: dict[str, str] = {
    "integer": "apileak_not_an_integer",
    "number": "apileak_not_a_number",
    "boolean": "apileak_not_a_boolean",
}

_ENUM_VIOLATION_SENTINEL = "__apileak_value_outside_declared_enum__"

_DEFAULT_MAX_OPERATIONS = 30


def _default_value_for(param: SpecParameter) -> str:
    """Return a value suitable for a Baseline_Request for ``param``."""
    if param.example is not None:
        return str(param.example)
    if param.enum:
        return str(param.enum[0])
    return _TYPE_DEFAULTS.get(param.type, "apileak_test")


def _build_minimal_body(schema: dict[str, Any] | None) -> dict[str, Any] | None:
    """Build a minimal JSON body satisfying only the schema's ``required`` properties."""
    if not schema or schema.get("type") not in (None, "object"):
        return None
    properties = schema.get("properties") or {}
    required = schema.get("required") or []
    body: dict[str, Any] = {}
    for name in required:
        prop_schema = properties.get(name, {})
        prop_type = prop_schema.get("type", "string")
        body[name] = _TYPE_DEFAULTS.get(prop_type, "apileak_test")
    return body or None


class SpecDrivenTestingModule(OWASPModule, SafeModeGuard):
    """Audits whether the live API enforces its own declared OpenAPI/Swagger contract."""

    def __init__(
        self,
        config: SpecDrivenTestingConfig,
        http_client: HTTPRequestEngine,
        auth_contexts: list[AuthContext],
        spec_schema: SpecSchema | None = None,
    ):
        super().__init__(config)
        self.http_client = http_client
        self.auth_contexts = auth_contexts
        self.spec_schema = spec_schema
        self.logger = get_logger(__name__).bind(module="spec_driven_testing")
        self._init_safe_mode(config)

        self.max_operations = getattr(config, "max_operations", _DEFAULT_MAX_OPERATIONS)

        self.logger.info(
            "Spec-Driven Testing Module initialized",
            safe_mode=self.safe_mode,
            has_spec_schema=self.spec_schema is not None,
            operations=len(self.spec_schema.operations) if self.spec_schema else 0,
            max_operations=self.max_operations,
        )

    def get_module_name(self) -> str:
        return "spec_driven_testing"

    async def execute_tests(self, endpoints: list[Any]) -> list[Finding]:
        """Audit every declared operation's input contract against the live API.

        ``endpoints`` (discovered endpoints) is accepted for interface
        consistency with every other OWASP module but is NOT the source of
        truth here — the attack surface is ``self.spec_schema.operations``,
        so this module is useful even against an API that was never crawled,
        as long as an ``--openapi``/``--postman`` source was supplied.
        """
        if self.spec_schema is None or not self.spec_schema.operations:
            self.logger.info(
                "No Spec_Schema available (supply --openapi/--postman); "
                "spec-driven testing has nothing to audit, skipping"
            )
            return []

        base_url = self._infer_base_url(endpoints)
        if not base_url:
            self.logger.warning(
                "No base URL available (no discovered endpoints); "
                "spec-driven testing requires at least one discovered endpoint "
                "to derive scheme://host, skipping"
            )
            return []

        findings: list[Finding] = []
        operations_tested = 0

        for operation in self.spec_schema.operations:
            if operations_tested >= self.max_operations:
                self.logger.info(
                    "max_operations reached, stopping spec-driven audit",
                    max_operations=self.max_operations,
                )
                break
            if self.skip_if_state_changing(operation.method, "spec_driven_testing"):
                continue

            operations_tested += 1
            try:
                findings.extend(await self._audit_operation(base_url, operation))
            except Exception as exc:
                self.logger.debug(
                    "Spec-driven audit of operation failed",
                    path=operation.path,
                    method=operation.method,
                    error=str(exc),
                )

        self.logger.info(
            "Spec-driven testing completed",
            operations_tested=operations_tested,
            total_findings=len(findings),
        )
        return findings

    @staticmethod
    def _infer_base_url(endpoints: list[Any]) -> str | None:
        if not endpoints:
            return None
        first = endpoints[0]
        raw = first.url if hasattr(first, "url") else str(first)
        parts = urlsplit(raw)
        if not parts.scheme or not parts.netloc:
            return None
        return urlunsplit((parts.scheme, parts.netloc, "", "", ""))

    def _build_url(
        self, base_url: str, operation: SpecOperation, query_overrides: dict[str, str | None]
    ) -> str:
        """Substitute path placeholders and append the query string."""
        from urllib.parse import urlencode

        path = operation.path
        for param in operation.parameters:
            if param.location == "path":
                path = path.replace("{" + param.name + "}", _default_value_for(param))

        query_pairs = []
        for param in operation.parameters:
            if param.location != "query":
                continue
            if param.name in query_overrides:
                value = query_overrides[param.name]
                if value is None:
                    continue  # omitted deliberately
                query_pairs.append((param.name, value))
            else:
                query_pairs.append((param.name, _default_value_for(param)))

        query_string = urlencode(query_pairs)
        full_path = f"{path}?{query_string}" if query_string else path
        return base_url.rstrip("/") + "/" + full_path.lstrip("/")

    def _build_headers(
        self, operation: SpecOperation, header_overrides: dict[str, str | None]
    ) -> dict[str, str]:
        headers: dict[str, str] = {}
        for param in operation.parameters:
            if param.location != "header":
                continue
            if param.name in header_overrides:
                value = header_overrides[param.name]
                if value is None:
                    continue
                headers[param.name] = value
            else:
                headers[param.name] = _default_value_for(param)
        return headers

    async def _probe(
        self,
        base_url: str,
        operation: SpecOperation,
        *,
        # Overrides map a parameter name to either a replacement value, or
        # explicitly to None to mean "omit this parameter entirely" (used by
        # the required-parameter omission check).
        query_overrides: dict[str, str | None] | None = None,
        header_overrides: dict[str, str | None] | None = None,
    ) -> Response | None:
        url = self._build_url(base_url, operation, query_overrides or {})
        headers = self._build_headers(operation, header_overrides or {})
        body = _build_minimal_body(operation.request_body_schema)
        kwargs: dict[str, Any] = {"headers": headers}
        if body is not None:
            kwargs["json"] = body
            headers.setdefault("Content-Type", "application/json")
        try:
            return await self.http_client.request(operation.method, url, **kwargs)
        except Exception as exc:
            self.logger.debug(
                "Spec-driven probe request failed",
                path=operation.path,
                method=operation.method,
                error=str(exc),
            )
            return None

    async def _audit_operation(self, base_url: str, operation: SpecOperation) -> list[Finding]:
        findings: list[Finding] = []

        baseline = await self._probe(base_url, operation)
        if baseline is None:
            return findings
        baseline_success = 200 <= baseline.status_code < 400

        for param in operation.parameters:
            if param.location not in ("query", "header"):
                continue  # path params aren't meaningfully "omittable" or type-confusable here

            overrides_kwarg = "query_overrides" if param.location == "query" else "header_overrides"

            if param.enum:
                mutated = await self._probe(
                    base_url,
                    operation,
                    **{overrides_kwarg: {param.name: _ENUM_VIOLATION_SENTINEL}},
                )
                finding = self._finding_if_not_enforced(
                    operation,
                    param,
                    "enum",
                    baseline_success,
                    mutated,
                    evidence_detail=f"declared enum {param.enum!r} but accepted "
                    f"'{_ENUM_VIOLATION_SENTINEL}'",
                )
                if finding is not None:
                    findings.append(finding)

            elif param.type in _TYPE_CONFUSION_VALUES:
                mutated = await self._probe(
                    base_url,
                    operation,
                    **{overrides_kwarg: {param.name: _TYPE_CONFUSION_VALUES[param.type]}},
                )
                finding = self._finding_if_not_enforced(
                    operation,
                    param,
                    "type",
                    baseline_success,
                    mutated,
                    evidence_detail=f"declared type '{param.type}' but accepted "
                    f"'{_TYPE_CONFUSION_VALUES[param.type]}'",
                )
                if finding is not None:
                    findings.append(finding)

            if param.required:
                omit: dict[str, str | None] = {param.name: None}
                mutated = await self._probe(base_url, operation, **{overrides_kwarg: omit})
                finding = self._finding_if_not_enforced(
                    operation,
                    param,
                    "required",
                    baseline_success,
                    mutated,
                    evidence_detail="declared required=true but accepted the request "
                    "with the parameter omitted entirely",
                )
                if finding is not None:
                    findings.append(finding)

        return findings

    _CATEGORY_BY_CHECK = {
        "enum": "SPEC_ENUM_NOT_ENFORCED",
        "type": "SPEC_TYPE_NOT_ENFORCED",
        "required": "SPEC_REQUIRED_PARAM_NOT_ENFORCED",
    }

    def _finding_if_not_enforced(
        self,
        operation: SpecOperation,
        param: SpecParameter,
        check: str,
        baseline_success: bool,
        mutated: Response | None,
        evidence_detail: str,
    ) -> Finding | None:
        if mutated is None:
            return None
        mutated_success = 200 <= mutated.status_code < 400
        # Only a finding when the spec's constraint was violated AND the
        # backend still treated the request as successfully as the valid
        # baseline did — i.e. the constraint demonstrably isn't enforced.
        if not (baseline_success and mutated_success):
            return None

        return Finding(
            id="",
            scan_id="",
            category=self._CATEGORY_BY_CHECK[check],
            owasp_category="API8",
            severity=Severity.LOW if check == "type" else Severity.MEDIUM,
            endpoint=operation.path,
            method=operation.method,
            status_code=mutated.status_code,
            response_size=len(mutated.content) if mutated.content else 0,
            response_time=mutated.elapsed,
            evidence=(
                f"Parameter '{param.name}' ({param.location}) on "
                f"{operation.method} {operation.path} {evidence_detail}, "
                f"and the request still succeeded (status {mutated.status_code})."
            ),
            recommendation=(
                "Enforce the constraints declared in the published OpenAPI/Swagger "
                "contract server-side (enum membership, declared type, required "
                "presence) — a spec that documents validation the implementation "
                "doesn't perform lets undeclared/invalid input reach business logic "
                "that assumed the contract held."
            ),
            payload=f"{param.location}:{param.name}",
        )
