"""
Findings Collector
Aggregates and manages security findings from all modules
"""

from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from uuid import uuid4
import hashlib

from core.logging import get_logger
from core.config import Severity


class FindingClassificationError(ValueError):
    """
    Raised when a Finding_Category emitted by one of the hardened
    capabilities (BOLA / Auth / JWT / Property-Level) fails to resolve to a
    defined Severity or an in-scope OWASP_Category.

    This makes a classification gap a detectable/asserted condition rather
    than a silent default (Req 22.1, 22.2, 22.3, 22.4, 26.1).
    """


@dataclass
class Finding:
    """Security finding data model"""
    id: str
    scan_id: str
    category: str
    owasp_category: Optional[str]
    severity: Severity
    endpoint: str
    method: str
    status_code: int
    response_size: int
    response_time: float
    evidence: str
    recommendation: str
    payload: Optional[str] = None
    response_snippet: Optional[str] = None
    # Advanced BOLA findings (Reqs 27, 29-32) attach a structured Evidence_Chain
    # and a Confidence_Score (Req 33.1, 33.2). Typed as Any to avoid a circular
    # import of the EvidenceChain dataclass (defined in the BOLA module); the
    # attached object is an ``EvidenceChain`` whose response snippet is always
    # passed through ``redact_secrets`` before storage (Req 33.3).
    evidence_chain: Optional[Any] = None
    confidence: Optional[str] = None
    headers: Dict[str, str] = None
    timestamp: datetime = None
    # Parameter-fuzzing detection-signal fields (R3.5/R4.2/R5). All defaulted
    # so existing Finding construction sites and other commands are unaffected
    # (behavior preservation, R2).
    detection_signal: Optional[str] = None            # R3.5/R4.2: e.g. "reflection", "new_json_field", "status_code"
    detection_signals: List[str] = field(default_factory=list)  # all signals that fired
    reflection_location: Optional[str] = None         # R3.5: "body" | "header"
    new_json_fields: Optional[List[str]] = None        # R4.2: absent-in-baseline keys detected
    confirmation_status: Optional[str] = None          # R5: "confirmed" | "excluded_failed_retest" | None
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {}
        if self.timestamp is None:
            self.timestamp = datetime.now()


class FindingsCollector:
    """
    Findings Collector for aggregating security findings
    
    Manages collection, deduplication, and classification of findings
    from fuzzing and OWASP testing modules with advanced classification
    and prioritization based on OWASP API Security Top 10
    """
    
    # OWASP API Security Top 10 2023 mapping
    OWASP_CATEGORIES = {
        "API1": "Broken Object Level Authorization",
        "API2": "Broken Authentication", 
        "API3": "Broken Object Property Level Authorization",
        "API4": "Unrestricted Resource Consumption",
        "API5": "Broken Function Level Authorization",
        "API6": "Unrestricted Access to Sensitive Business Flows",
        "API7": "Server Side Request Forgery",
        "API8": "Security Misconfiguration",
        "API9": "Improper Inventory Management",
        "API10": "Unsafe Consumption of APIs"
    }
    
    # Severity classification rules based on vulnerability types
    SEVERITY_RULES = {
        # Critical vulnerabilities - immediate security risk
        "BOLA_ANONYMOUS_ACCESS": Severity.CRITICAL,
        "AUTH_BYPASS": Severity.CRITICAL,
        "PRIVILEGE_ESCALATION": Severity.CRITICAL,
        "SSRF_INTERNAL_ACCESS": Severity.CRITICAL,
        "ADMIN_ACCESS_ANONYMOUS": Severity.CRITICAL,
        "SENSITIVE_DATA_EXPOSURE": Severity.CRITICAL,
        "FILE_PROTOCOL_ACCESS": Severity.CRITICAL,
        
        # High severity - significant security risk
        "WEAK_JWT_ALGORITHM": Severity.HIGH,
        "TOKEN_NOT_EXPIRED": Severity.HIGH,
        "MASS_ASSIGNMENT": Severity.HIGH,
        "FUNCTION_LEVEL_BYPASS": Severity.HIGH,
        "CORS_MISCONFIGURATION": Severity.HIGH,
        "BUSINESS_FLOW_NO_LIMIT": Severity.HIGH,
        "UNSAFE_UPSTREAM_DATA": Severity.HIGH,
        
        # Medium severity - moderate security risk
        "MISSING_RATE_LIMITING": Severity.MEDIUM,
        "LARGE_PAYLOAD_ACCEPTED": Severity.MEDIUM,
        "MISSING_SECURITY_HEADERS": Severity.MEDIUM,
        "UNDOCUMENTED_ENDPOINT": Severity.MEDIUM,
        "PARAMETER_POLLUTION": Severity.MEDIUM,
        
        # Low severity - minor security concerns
        "INFORMATION_DISCLOSURE": Severity.LOW,
        "VERBOSE_ERROR_MESSAGES": Severity.LOW,
        "DEPRECATED_API_VERSION": Severity.LOW,
        "UNDOCUMENTED_API_VERSION": Severity.LOW,
        
        # Info - informational findings
        "ENDPOINT_DISCOVERED": Severity.INFO,
        "FRAMEWORK_DETECTED": Severity.INFO,
        "API_VERSION_FOUND": Severity.INFO,

        # ------------------------------------------------------------------
        # Hardened-capability categories (Req 22.1, 22.3) - BOLA / Auth /
        # JWT / Property-Level. Every category emitted by these four
        # capabilities resolves to a concrete severity (strict resolution).
        # ------------------------------------------------------------------
        # API1 - BOLA (Broken Object Level Authorization)
        # NOTE: "BOLA_ANONYMOUS_ACCESS" is defined above as CRITICAL.
        "BOLA_HORIZONTAL_ESCALATION": Severity.CRITICAL,
        "BOLA_OBJECT_ACCESS": Severity.HIGH,
        "BOLA_ID_ENUMERATION": Severity.HIGH,
        "BOLA_GUID_ENUMERATION": Severity.MEDIUM,
        # API1 - Advanced BOLA categories (Reqs 27-32; strict resolution per
        # Req 35.1, 35.3). Object-level / object-relationship authorization
        # issues. Severities calibrated against the existing BOLA_* rules.
        "BOLA_ACCOUNT_TAKEOVER": Severity.CRITICAL,
        "BOLA_WRITE_ESCALATION": Severity.HIGH,
        "BOLA_CROSS_TENANT": Severity.HIGH,
        "BOLA_BROKEN_OBJECT_RELATIONSHIP": Severity.HIGH,
        "BOLA_STATE_MANIPULATION": Severity.HIGH,
        "BOLA_ID_LEAKAGE": Severity.MEDIUM,
        "BOLA_PREDICTABLE_IDENTIFIER": Severity.MEDIUM,

        # Spec-driven Unauthorized_Endpoint_Assertion categories (Req 55, 56.1).
        # One per hardened module, each within that module's in-scope OWASP
        # category. All HIGH: a context reaching an endpoint an operator
        # explicitly declared forbidden is a broken-access-control finding.
        "BOLA_UNAUTHORIZED_ENDPOINT_ACCESS": Severity.HIGH,
        "AUTH_UNAUTHORIZED_ENDPOINT_ACCESS": Severity.HIGH,
        "PROPERTY_UNAUTHORIZED_ENDPOINT_ACCESS": Severity.HIGH,

        # API2 - Broken Authentication / JWT subsystem
        "AUTH_ANONYMOUS_ACCESS": Severity.HIGH,
        "JWT_NONE_ALGORITHM": Severity.CRITICAL,
        "JWT_NONE_ALGORITHM_ACCEPTED": Severity.CRITICAL,
        "JWT_NULL_SIGNATURE": Severity.CRITICAL,
        "JWT_WEAK_SECRET": Severity.HIGH,
        "JWT_ALGORITHM_CONFUSION": Severity.CRITICAL,
        "JWT_EXPIRED_TOKEN_ACCEPTED": Severity.HIGH,
        "JWT_NO_EXPIRATION": Severity.HIGH,
        "JWT_WEAK_EXPIRATION_VALIDATION": Severity.MEDIUM,
        "JWT_TOKEN_NOT_INVALIDATED_AFTER_LOGOUT": Severity.HIGH,
        "JWT_KID_INJECTION": Severity.HIGH,
        "JWT_JWKS_SPOOF": Severity.HIGH,
        "JWT_INLINE_JWKS": Severity.HIGH,
        "JWT_PRIVILEGE_ESCALATION": Severity.CRITICAL,
        "JWT_USER_IMPERSONATION": Severity.CRITICAL,
        "JWT_EXPIRATION_BYPASS": Severity.HIGH,
        "JWT_SCAN_COMPLETED_NO_FINDINGS": Severity.INFO,

        # API2 - Advanced Broken-Authentication / JWT categories
        # (Reqs 37-45; strict resolution per Req 47.1, 47.2, 47.3). All map
        # to API2. Severities calibrated against comparable existing rules:
        # rate-limiting/CSRF-style issues MEDIUM, credential leakage /
        # audience / OAuth-redirect / reset-token / revocation-race issues
        # HIGH, and MFA bypass CRITICAL (a form of authentication bypass,
        # consistent with AUTH_BYPASS above).
        "AUTH_NO_RATE_LIMITING": Severity.MEDIUM,
        "AUTH_CREDENTIAL_STUFFING_EXPOSURE": Severity.HIGH,
        "AUTH_SECRET_IN_URL": Severity.HIGH,
        "AUTH_MFA_BYPASS": Severity.CRITICAL,
        "AUTH_PREDICTABLE_RESET_TOKEN": Severity.HIGH,
        "AUTH_OAUTH_REDIRECT_URI": Severity.HIGH,
        "AUTH_TOKEN_AUDIENCE_CONFUSION": Severity.HIGH,
        "AUTH_OAUTH_MISSING_STATE": Severity.MEDIUM,
        "AUTH_TOKEN_REVOCATION_RACE": Severity.HIGH,
        "JWT_SENSITIVE_DATA_IN_PAYLOAD": Severity.MEDIUM,
        # NOTE: "JWT_KID_INJECTION" (HIGH) is defined above.
        "JWT_JKU_SSRF": Severity.HIGH,

        # API2 - New JWT attack categories (Reqs 58-64; strict resolution).
        # Severities per design.md: blank-secret / psychic signature are
        # CRITICAL (signature verification is effectively defeated); claim
        # fuzzing / timestamp tampering are HIGH.
        "JWT_BLANK_SECRET_ACCEPTED": Severity.CRITICAL,
        "JWT_PSYCHIC_SIGNATURE": Severity.CRITICAL,
        "JWT_CLAIM_FUZZING_ACCEPTED": Severity.HIGH,
        "JWT_TIMESTAMP_TAMPERING_ACCEPTED": Severity.HIGH,

        # API2 - New JWT lifetime / missing-claim categories (Req 68; strict
        # resolution). Per design.md: excessive lifetime and missing exp/aud
        # claims are MEDIUM (weakened token hygiene / audience scoping), while
        # missing iss/jti claims are LOW (defense-in-depth / replay hardening).
        "JWT_EXCESSIVE_TOKEN_LIFETIME": Severity.MEDIUM,
        "JWT_MISSING_EXP_CLAIM": Severity.MEDIUM,
        "JWT_MISSING_AUD_CLAIM": Severity.MEDIUM,
        "JWT_MISSING_ISS_CLAIM": Severity.LOW,
        "JWT_MISSING_JTI_CLAIM": Severity.LOW,

        # API3 - Broken Object Property Level Authorization
        # NOTE: "SENSITIVE_DATA_EXPOSURE" (CRITICAL) and "MASS_ASSIGNMENT"
        # (HIGH) are defined above.
        "MASS_ASSIGNMENT_PRIVILEGE": Severity.CRITICAL,
        "READONLY_PROPERTY_MODIFICATION": Severity.HIGH,
        # NOTE: "UNDOCUMENTED_FIELD" maps to MEDIUM below via default in the
        # legacy rules; it is added explicitly here for strict resolution.
        "UNDOCUMENTED_FIELD": Severity.MEDIUM,

        # API5 - Broken Function Level Authorization (all four attack levels)
        "BFLA_ADMIN_ENDPOINT_EXPOSED": Severity.MEDIUM,
        "BFLA_LOW_PRIV_ACCESS": Severity.CRITICAL,
        "BFLA_ANONYMOUS_ADMIN_ACCESS": Severity.CRITICAL,
        "BFLA_VERB_TAMPERING": Severity.HIGH,
        "BFLA_METHOD_OVERRIDE": Severity.HIGH,
        "BFLA_MASS_ASSIGNMENT_ROLE": Severity.CRITICAL,
        "BFLA_VERSION_DOWNGRADE": Severity.HIGH,
    }
    
    # Category to OWASP mapping
    CATEGORY_TO_OWASP = {
        "BOLA_ANONYMOUS_ACCESS": "API1",
        "BOLA_HORIZONTAL_ESCALATION": "API1", 
        "BOLA_OBJECT_ACCESS": "API1",
        "AUTH_BYPASS": "API2",
        "WEAK_JWT_ALGORITHM": "API2",
        "TOKEN_NOT_EXPIRED": "API2",
        "SENSITIVE_DATA_EXPOSURE": "API3",
        "MASS_ASSIGNMENT": "API3",
        "UNDOCUMENTED_FIELD": "API3",
        "MISSING_RATE_LIMITING": "API4",
        "LARGE_PAYLOAD_ACCEPTED": "API4",
        "RESOURCE_EXHAUSTION": "API4",
        "ADMIN_ACCESS_ANONYMOUS": "API5",
        "FUNCTION_LEVEL_BYPASS": "API5",
        "HTTP_METHOD_BYPASS": "API5",
        "BUSINESS_FLOW_NO_LIMIT": "API6",
        "SSRF_INTERNAL_ACCESS": "API7",
        "SSRF_BLIND": "API7",
        "FILE_PROTOCOL_ACCESS": "API7",
        "CORS_MISCONFIGURATION": "API8",
        "MISSING_SECURITY_HEADERS": "API8",
        "ENDPOINT_DISCOVERED": "API9",
        "FRAMEWORK_DETECTED": "API9",
        "DEPRECATED_API_VERSION": "API9",
        "UNDOCUMENTED_API_VERSION": "API9",
        "UNSAFE_UPSTREAM_DATA": "API10",

        # ------------------------------------------------------------------
        # Hardened-capability categories (Req 22.2, 22.4, 26.1). OWASP
        # categories restricted to {API1, API2, API3}.
        # ------------------------------------------------------------------
        # API1 - BOLA (BOLA_ANONYMOUS_ACCESS / BOLA_HORIZONTAL_ESCALATION /
        # BOLA_OBJECT_ACCESS mapped above)
        "BOLA_ID_ENUMERATION": "API1",
        "BOLA_GUID_ENUMERATION": "API1",
        # API1 - Advanced BOLA categories (Reqs 27-32). OWASP categories for
        # these are restricted to {API1, API3}; all seven are object-level /
        # object-relationship authorization issues and map to API1
        # (Req 35.2, 26.1).
        "BOLA_ACCOUNT_TAKEOVER": "API1",
        "BOLA_WRITE_ESCALATION": "API1",
        "BOLA_CROSS_TENANT": "API1",
        "BOLA_BROKEN_OBJECT_RELATIONSHIP": "API1",
        "BOLA_STATE_MANIPULATION": "API1",
        "BOLA_ID_LEAKAGE": "API1",
        "BOLA_PREDICTABLE_IDENTIFIER": "API1",

        # Spec-driven Unauthorized_Endpoint_Assertion categories (Req 55, 56.2):
        # each resolves within its own module's in-scope OWASP category.
        "BOLA_UNAUTHORIZED_ENDPOINT_ACCESS": "API1",
        "AUTH_UNAUTHORIZED_ENDPOINT_ACCESS": "API2",
        "PROPERTY_UNAUTHORIZED_ENDPOINT_ACCESS": "API3",

        # API2 - Broken Authentication / JWT subsystem
        "AUTH_ANONYMOUS_ACCESS": "API2",
        "JWT_NONE_ALGORITHM": "API2",
        "JWT_NONE_ALGORITHM_ACCEPTED": "API2",
        "JWT_NULL_SIGNATURE": "API2",
        "JWT_WEAK_SECRET": "API2",
        "JWT_ALGORITHM_CONFUSION": "API2",
        "JWT_EXPIRED_TOKEN_ACCEPTED": "API2",
        "JWT_NO_EXPIRATION": "API2",
        "JWT_WEAK_EXPIRATION_VALIDATION": "API2",
        "JWT_TOKEN_NOT_INVALIDATED_AFTER_LOGOUT": "API2",
        "JWT_KID_INJECTION": "API2",
        "JWT_JWKS_SPOOF": "API2",
        "JWT_INLINE_JWKS": "API2",
        "JWT_PRIVILEGE_ESCALATION": "API2",
        "JWT_USER_IMPERSONATION": "API2",
        "JWT_EXPIRATION_BYPASS": "API2",
        "JWT_SCAN_COMPLETED_NO_FINDINGS": "API2",

        # API2 - Advanced Broken-Authentication / JWT categories
        # (Reqs 37-45; Req 47.2 mandates OWASP_Category API2 for all twelve).
        "AUTH_NO_RATE_LIMITING": "API2",
        "AUTH_CREDENTIAL_STUFFING_EXPOSURE": "API2",
        "AUTH_SECRET_IN_URL": "API2",
        "AUTH_MFA_BYPASS": "API2",
        "AUTH_PREDICTABLE_RESET_TOKEN": "API2",
        "AUTH_OAUTH_REDIRECT_URI": "API2",
        "AUTH_TOKEN_AUDIENCE_CONFUSION": "API2",
        "AUTH_OAUTH_MISSING_STATE": "API2",
        "AUTH_TOKEN_REVOCATION_RACE": "API2",
        "JWT_SENSITIVE_DATA_IN_PAYLOAD": "API2",
        # NOTE: "JWT_KID_INJECTION" -> API2 is defined above.
        "JWT_JKU_SSRF": "API2",

        # API2 - New JWT attack categories (Reqs 58-64; all map to API2).
        "JWT_BLANK_SECRET_ACCEPTED": "API2",
        "JWT_PSYCHIC_SIGNATURE": "API2",
        "JWT_CLAIM_FUZZING_ACCEPTED": "API2",
        "JWT_TIMESTAMP_TAMPERING_ACCEPTED": "API2",

        # API2 - New JWT lifetime / missing-claim categories (Req 68; all map
        # to API2).
        "JWT_EXCESSIVE_TOKEN_LIFETIME": "API2",
        "JWT_MISSING_EXP_CLAIM": "API2",
        "JWT_MISSING_AUD_CLAIM": "API2",
        "JWT_MISSING_ISS_CLAIM": "API2",
        "JWT_MISSING_JTI_CLAIM": "API2",

        # API3 - Property-Level (SENSITIVE_DATA_EXPOSURE / MASS_ASSIGNMENT /
        # UNDOCUMENTED_FIELD mapped above)
        "MASS_ASSIGNMENT_PRIVILEGE": "API3",
        "READONLY_PROPERTY_MODIFICATION": "API3",

        # API5 - Broken Function Level Authorization (all four levels)
        "BFLA_ADMIN_ENDPOINT_EXPOSED": "API5",
        "BFLA_LOW_PRIV_ACCESS": "API5",
        "BFLA_ANONYMOUS_ADMIN_ACCESS": "API5",
        "BFLA_VERB_TAMPERING": "API5",
        "BFLA_METHOD_OVERRIDE": "API5",
        "BFLA_MASS_ASSIGNMENT_ROLE": "API5",
        "BFLA_VERSION_DOWNGRADE": "API5",
    }

    # OWASP categories that the four hardened capabilities are restricted to
    # (Req 22.2, 26.1). Any emitted category resolving outside this set is a
    # detectable error.
    IN_SCOPE_OWASP_CATEGORIES = frozenset({"API1", "API2", "API3", "API5"})

    # Canonical list of every Finding_Category emitted by the four hardened
    # capabilities (BOLA_Module, Auth_Module, Property_Module, and the
    # JWT_Attack_Engine). Resolution is STRICT for these categories: each MUST
    # resolve to a defined Severity (in SEVERITY_RULES) and an in-scope
    # OWASP_Category (in CATEGORY_TO_OWASP). This list is the single source of
    # truth used by the classification-completeness property test (Req 24.6).
    EMITTED_CATEGORIES = frozenset({
        # API1 - BOLA
        "BOLA_ANONYMOUS_ACCESS",
        "BOLA_HORIZONTAL_ESCALATION",
        "BOLA_OBJECT_ACCESS",
        "BOLA_ID_ENUMERATION",
        "BOLA_GUID_ENUMERATION",
        # API1 - Advanced BOLA (Reqs 27-32)
        "BOLA_ACCOUNT_TAKEOVER",
        "BOLA_WRITE_ESCALATION",
        "BOLA_CROSS_TENANT",
        "BOLA_BROKEN_OBJECT_RELATIONSHIP",
        "BOLA_STATE_MANIPULATION",
        "BOLA_ID_LEAKAGE",
        "BOLA_PREDICTABLE_IDENTIFIER",
        # API1 - Spec-driven Unauthorized_Endpoint_Assertion (Req 55, 56.1)
        "BOLA_UNAUTHORIZED_ENDPOINT_ACCESS",
        # API2 - Auth / JWT
        "AUTH_ANONYMOUS_ACCESS",
        "JWT_NONE_ALGORITHM",
        "JWT_NONE_ALGORITHM_ACCEPTED",
        "JWT_NULL_SIGNATURE",
        "JWT_WEAK_SECRET",
        "JWT_ALGORITHM_CONFUSION",
        "JWT_EXPIRED_TOKEN_ACCEPTED",
        "JWT_NO_EXPIRATION",
        "JWT_WEAK_EXPIRATION_VALIDATION",
        "JWT_TOKEN_NOT_INVALIDATED_AFTER_LOGOUT",
        "JWT_KID_INJECTION",
        "JWT_JWKS_SPOOF",
        "JWT_INLINE_JWKS",
        "JWT_PRIVILEGE_ESCALATION",
        "JWT_USER_IMPERSONATION",
        "JWT_EXPIRATION_BYPASS",
        "JWT_SCAN_COMPLETED_NO_FINDINGS",
        # API2 - Advanced Broken-Authentication / JWT (Reqs 37-45)
        "AUTH_NO_RATE_LIMITING",
        "AUTH_CREDENTIAL_STUFFING_EXPOSURE",
        "AUTH_SECRET_IN_URL",
        "AUTH_MFA_BYPASS",
        "AUTH_PREDICTABLE_RESET_TOKEN",
        "AUTH_OAUTH_REDIRECT_URI",
        "AUTH_TOKEN_AUDIENCE_CONFUSION",
        "AUTH_OAUTH_MISSING_STATE",
        "AUTH_TOKEN_REVOCATION_RACE",
        "JWT_SENSITIVE_DATA_IN_PAYLOAD",
        "JWT_JKU_SSRF",
        # API2 - Spec-driven Unauthorized_Endpoint_Assertion (Req 55, 56.1)
        "AUTH_UNAUTHORIZED_ENDPOINT_ACCESS",
        # API2 - New JWT attack categories (Reqs 58-64)
        "JWT_BLANK_SECRET_ACCEPTED",
        "JWT_PSYCHIC_SIGNATURE",
        "JWT_CLAIM_FUZZING_ACCEPTED",
        "JWT_TIMESTAMP_TAMPERING_ACCEPTED",
        # API2 - New JWT lifetime / missing-claim categories (Req 68)
        "JWT_EXCESSIVE_TOKEN_LIFETIME",
        "JWT_MISSING_EXP_CLAIM",
        "JWT_MISSING_AUD_CLAIM",
        "JWT_MISSING_ISS_CLAIM",
        "JWT_MISSING_JTI_CLAIM",
        # API3 - Property-Level
        "SENSITIVE_DATA_EXPOSURE",
        "MASS_ASSIGNMENT",
        "MASS_ASSIGNMENT_PRIVILEGE",
        "READONLY_PROPERTY_MODIFICATION",
        # API3 - Spec-driven Unauthorized_Endpoint_Assertion (Req 55, 56.1)
        "PROPERTY_UNAUTHORIZED_ENDPOINT_ACCESS",
        "UNDOCUMENTED_FIELD",
        # API5 - Broken Function Level Authorization (all four attack levels)
        "BFLA_ADMIN_ENDPOINT_EXPOSED",
        "BFLA_LOW_PRIV_ACCESS",
        "BFLA_ANONYMOUS_ADMIN_ACCESS",
        "BFLA_VERB_TAMPERING",
        "BFLA_METHOD_OVERRIDE",
        "BFLA_MASS_ASSIGNMENT_ROLE",
        "BFLA_VERSION_DOWNGRADE",
    })
    
    def __init__(self, scan_id: str):
        """
        Initialize Findings Collector
        
        Args:
            scan_id: Unique scan identifier
        """
        self.scan_id = scan_id
        self.findings: List[Finding] = []
        self.logger = get_logger(__name__).bind(scan_id=scan_id)
        self._deduplication_cache: Set[str] = set()
        
        self.logger.info("Findings Collector initialized with enhanced classification")
    
    def add_finding(self, 
                   category: str,
                   severity: Optional[Severity],
                   endpoint: str,
                   method: str,
                   evidence: str,
                   recommendation: str,
                   **kwargs) -> Finding:
        """
        Add a new finding with automatic classification
        
        Args:
            category: Finding category
            severity: Finding severity (if None, will be auto-classified)
            endpoint: Affected endpoint
            method: HTTP method
            evidence: Evidence of the finding
            recommendation: Remediation recommendation
            **kwargs: Additional finding attributes
            
        Returns:
            Created finding
        """
        # Auto-classify severity if not provided
        if severity is None:
            severity = self._classify_severity(category)
        
        # Auto-assign OWASP category
        owasp_category = self._get_owasp_category(category)
        
        finding = Finding(
            id=str(uuid4()),
            scan_id=self.scan_id,
            category=category,
            severity=severity,
            endpoint=endpoint,
            method=method,
            evidence=evidence,
            recommendation=recommendation,
            owasp_category=owasp_category or kwargs.get('owasp_category'),
            status_code=kwargs.get('status_code', 0),
            response_size=kwargs.get('response_size', 0),
            response_time=kwargs.get('response_time', 0.0),
            payload=kwargs.get('payload'),
            response_snippet=kwargs.get('response_snippet'),
            headers=kwargs.get('headers', {})
        )
        
        # Check for duplicates before adding
        if not self._is_duplicate(finding):
            self.findings.append(finding)
            self._add_to_deduplication_cache(finding)
            
            self.logger.info("Finding added",
                            category=category,
                            severity=severity.value,
                            endpoint=endpoint,
                            owasp_category=owasp_category)
        else:
            self.logger.debug("Duplicate finding ignored",
                             category=category,
                             endpoint=endpoint)
        
        return finding
    
    def add_findings(self, findings: List[Finding]) -> int:
        """
        Add multiple findings with deduplication
        
        Args:
            findings: List of findings to add
            
        Returns:
            Number of unique findings added
        """
        added_count = 0
        
        for finding in findings:
            finding.scan_id = self.scan_id
            
            # Auto-classify if needed
            if not finding.severity:
                finding.severity = self._classify_severity(finding.category)
            
            if not finding.owasp_category:
                finding.owasp_category = self._get_owasp_category(finding.category)
            
            # Check for duplicates
            if not self._is_duplicate(finding):
                self.findings.append(finding)
                self._add_to_deduplication_cache(finding)
                added_count += 1
        
        self.logger.info("Multiple findings processed", 
                        total_submitted=len(findings),
                        unique_added=added_count,
                        duplicates_ignored=len(findings) - added_count)
        
        return added_count
    
    def _classify_severity(self, category: str) -> Severity:
        """
        Automatically classify finding severity based on category

        Resolution is strict for categories emitted by the four hardened
        capabilities (see EMITTED_CATEGORIES): a missing severity rule for
        such a category raises FindingClassificationError rather than
        silently defaulting (Req 22.1, 22.3). Other categories preserve the
        legacy MEDIUM default.

        Args:
            category: Finding category

        Returns:
            Classified severity level

        Raises:
            FindingClassificationError: If a hardened-capability category has
                no defined severity rule.
        """
        severity = self.SEVERITY_RULES.get(category)
        if severity is None:
            if category in self.EMITTED_CATEGORIES:
                raise FindingClassificationError(
                    f"No severity rule defined for emitted category "
                    f"'{category}' (strict resolution required)"
                )
            return Severity.MEDIUM
        return severity

    def _get_owasp_category(self, category: str) -> Optional[str]:
        """
        Get OWASP API Security Top 10 category for finding

        Resolution is strict for categories emitted by the four hardened
        capabilities (see EMITTED_CATEGORIES): such a category MUST resolve to
        an in-scope OWASP_Category in {API1, API2, API3}. A missing or
        out-of-scope mapping raises FindingClassificationError rather than
        returning None (Req 22.2, 22.4, 26.1). Other categories preserve the
        legacy behavior of returning None when unmapped.

        Args:
            category: Finding category

        Returns:
            OWASP category (API1-API10) or None

        Raises:
            FindingClassificationError: If a hardened-capability category has
                no mapping or maps outside {API1, API2, API3}.
        """
        owasp_category = self.CATEGORY_TO_OWASP.get(category)

        if category in self.EMITTED_CATEGORIES:
            if owasp_category is None:
                raise FindingClassificationError(
                    f"No OWASP category mapping for emitted category "
                    f"'{category}' (strict resolution required)"
                )
            if owasp_category not in self.IN_SCOPE_OWASP_CATEGORIES:
                raise FindingClassificationError(
                    f"Emitted category '{category}' maps to out-of-scope "
                    f"OWASP category '{owasp_category}'; must be one of "
                    f"{sorted(self.IN_SCOPE_OWASP_CATEGORIES)}"
                )

        return owasp_category
    
    def _is_duplicate(self, finding: Finding) -> bool:
        """
        Check if finding is a duplicate
        
        Args:
            finding: Finding to check
            
        Returns:
            True if duplicate, False otherwise
        """
        # Create deduplication key based on endpoint, method, category, and evidence hash.
        # usedforsecurity=False: this hash is used only for deduplication, not for any
        # cryptographic or security purpose, so a non-collision-resistant hash is acceptable.
        evidence_hash = hashlib.md5(finding.evidence.encode(), usedforsecurity=False).hexdigest()[:8]
        dedup_key = f"{finding.endpoint}:{finding.method}:{finding.category}:{evidence_hash}"

        return dedup_key in self._deduplication_cache
    
    def _add_to_deduplication_cache(self, finding: Finding) -> None:
        """
        Add finding to deduplication cache
        
        Args:
            finding: Finding to add to cache
        """
        evidence_hash = hashlib.md5(finding.evidence.encode(), usedforsecurity=False).hexdigest()[:8]
        dedup_key = f"{finding.endpoint}:{finding.method}:{finding.category}:{evidence_hash}"
        self._deduplication_cache.add(dedup_key)
    
    def get_findings(self, 
                    severity: Optional[Severity] = None,
                    category: Optional[str] = None,
                    owasp_category: Optional[str] = None) -> List[Finding]:
        """
        Get findings with optional filtering
        
        Args:
            severity: Filter by severity
            category: Filter by category
            owasp_category: Filter by OWASP category
            
        Returns:
            Filtered list of findings
        """
        filtered_findings = self.findings
        
        if severity:
            filtered_findings = [f for f in filtered_findings if f.severity == severity]
        
        if category:
            filtered_findings = [f for f in filtered_findings if f.category == category]
        
        if owasp_category:
            filtered_findings = [f for f in filtered_findings if f.owasp_category == owasp_category]
        
        return filtered_findings
    
    def get_findings_by_severity(self) -> Dict[str, List[Finding]]:
        """
        Get findings grouped by severity with prioritization
        
        Returns:
            Dictionary mapping severity to findings (ordered by priority)
        """
        findings_by_severity = {
            Severity.CRITICAL.value: [],
            Severity.HIGH.value: [],
            Severity.MEDIUM.value: [],
            Severity.LOW.value: [],
            Severity.INFO.value: []
        }
        
        for finding in self.findings:
            findings_by_severity[finding.severity.value].append(finding)
        
        # Sort findings within each severity by OWASP category priority
        for severity_level in findings_by_severity:
            findings_by_severity[severity_level].sort(
                key=lambda f: self._get_owasp_priority(f.owasp_category)
            )
        
        return findings_by_severity
    
    def get_findings_by_owasp_category(self) -> Dict[str, List[Finding]]:
        """
        Get findings grouped by OWASP API Security Top 10 category
        
        Returns:
            Dictionary mapping OWASP category to findings
        """
        findings_by_owasp = {}
        
        for finding in self.findings:
            if finding.owasp_category:
                if finding.owasp_category not in findings_by_owasp:
                    findings_by_owasp[finding.owasp_category] = []
                findings_by_owasp[finding.owasp_category].append(finding)
        
        # Sort by OWASP category priority (API1 first, API10 last)
        sorted_owasp = {}
        for category in sorted(findings_by_owasp.keys(), key=self._get_owasp_priority):
            sorted_owasp[category] = findings_by_owasp[category]
        
        return sorted_owasp
    
    def _get_owasp_priority(self, owasp_category: Optional[str]) -> int:
        """
        Get priority order for OWASP categories (lower number = higher priority)
        
        Args:
            owasp_category: OWASP category (API1-API10)
            
        Returns:
            Priority number (1-10, or 99 for unknown)
        """
        if not owasp_category:
            return 99
        
        try:
            return int(owasp_category.replace("API", ""))
        except (ValueError, AttributeError):
            return 99
    
    def get_prioritized_findings(self, limit: Optional[int] = None) -> List[Finding]:
        """
        Get findings prioritized by severity and OWASP category
        
        Args:
            limit: Maximum number of findings to return
            
        Returns:
            List of findings ordered by priority (most critical first)
        """
        # Define severity priority (lower number = higher priority)
        severity_priority = {
            Severity.CRITICAL: 1,
            Severity.HIGH: 2,
            Severity.MEDIUM: 3,
            Severity.LOW: 4,
            Severity.INFO: 5
        }
        
        # Sort findings by severity priority, then OWASP priority
        prioritized = sorted(
            self.findings,
            key=lambda f: (
                severity_priority.get(f.severity, 99),
                self._get_owasp_priority(f.owasp_category)
            )
        )
        
        if limit:
            prioritized = prioritized[:limit]
        
        return prioritized
    
    def deduplicate_findings(self) -> int:
        """
        Remove duplicate findings (legacy method for compatibility)
        
        Returns:
            Number of duplicates removed (always 0 since deduplication is automatic)
        """
        # Deduplication is now automatic during add_finding
        # This method is kept for backward compatibility
        self.logger.debug("Deduplication called - automatic deduplication already active")
        return 0
    
    def get_owasp_coverage(self) -> Dict[str, Any]:
        """
        Get OWASP API Security Top 10 coverage analysis
        
        Returns:
            Dictionary with coverage statistics and gaps
        """
        findings_by_owasp = self.get_findings_by_owasp_category()
        
        coverage = {}
        for category, description in self.OWASP_CATEGORIES.items():
            findings_count = len(findings_by_owasp.get(category, []))
            critical_count = len([f for f in findings_by_owasp.get(category, []) 
                                if f.severity == Severity.CRITICAL])
            high_count = len([f for f in findings_by_owasp.get(category, []) 
                            if f.severity == Severity.HIGH])
            
            coverage[category] = {
                "description": description,
                "findings_count": findings_count,
                "critical_findings": critical_count,
                "high_findings": high_count,
                "tested": findings_count > 0,
                "risk_level": self._calculate_risk_level(critical_count, high_count, findings_count)
            }
        
        # Calculate overall coverage
        tested_categories = sum(1 for cat in coverage.values() if cat["tested"])
        coverage_percentage = (tested_categories / len(self.OWASP_CATEGORIES)) * 100
        
        return {
            "categories": coverage,
            "total_categories": len(self.OWASP_CATEGORIES),
            "tested_categories": tested_categories,
            "coverage_percentage": coverage_percentage,
            "untested_categories": [cat for cat, data in coverage.items() if not data["tested"]]
        }
    
    def _calculate_risk_level(self, critical: int, high: int, total: int) -> str:
        """
        Calculate risk level for an OWASP category
        
        Args:
            critical: Number of critical findings
            high: Number of high findings
            total: Total findings
            
        Returns:
            Risk level string
        """
        if critical > 0:
            return "CRITICAL"
        elif high > 0:
            return "HIGH"
        elif total > 0:
            return "MEDIUM"
        else:
            return "NONE"
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive findings statistics
        
        Returns:
            Enhanced statistics dictionary
        """
        findings_by_severity = self.get_findings_by_severity()
        owasp_coverage = self.get_owasp_coverage()
        
        return {
            "total_findings": len(self.findings),
            "critical_findings": len(findings_by_severity[Severity.CRITICAL.value]),
            "high_findings": len(findings_by_severity[Severity.HIGH.value]),
            "medium_findings": len(findings_by_severity[Severity.MEDIUM.value]),
            "low_findings": len(findings_by_severity[Severity.LOW.value]),
            "info_findings": len(findings_by_severity[Severity.INFO.value]),
            "unique_endpoints": len(set(f.endpoint for f in self.findings)),
            "unique_categories": len(set(f.category for f in self.findings)),
            "owasp_categories_tested": owasp_coverage["tested_categories"],
            "owasp_coverage_percentage": owasp_coverage["coverage_percentage"],
            "most_critical_category": self._get_most_critical_category(),
            "deduplication_cache_size": len(self._deduplication_cache)
        }
    
    def _get_most_critical_category(self) -> Optional[str]:
        """
        Get the OWASP category with the most critical findings
        
        Returns:
            OWASP category with highest risk or None
        """
        findings_by_owasp = self.get_findings_by_owasp_category()
        
        max_critical = 0
        most_critical = None
        
        for category, findings in findings_by_owasp.items():
            critical_count = len([f for f in findings if f.severity == Severity.CRITICAL])
            if critical_count > max_critical:
                max_critical = critical_count
                most_critical = category
        
        return most_critical
    
    def export_findings_summary(self) -> Dict[str, Any]:
        """
        Export a comprehensive findings summary for reporting
        
        Returns:
            Dictionary suitable for report generation
        """
        statistics = self.get_statistics()
        owasp_coverage = self.get_owasp_coverage()
        prioritized_findings = self.get_prioritized_findings(limit=10)
        
        return {
            "scan_id": self.scan_id,
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_findings": statistics["total_findings"],
                "risk_distribution": {
                    "critical": statistics["critical_findings"],
                    "high": statistics["high_findings"], 
                    "medium": statistics["medium_findings"],
                    "low": statistics["low_findings"],
                    "info": statistics["info_findings"]
                },
                "owasp_coverage": {
                    "tested_categories": owasp_coverage["tested_categories"],
                    "total_categories": owasp_coverage["total_categories"],
                    "coverage_percentage": owasp_coverage["coverage_percentage"]
                }
            },
            "top_findings": [
                {
                    "id": f.id,
                    "category": f.category,
                    "owasp_category": f.owasp_category,
                    "severity": f.severity.value,
                    "endpoint": f.endpoint,
                    "method": f.method,
                    "evidence": f.evidence[:200] + "..." if len(f.evidence) > 200 else f.evidence
                }
                for f in prioritized_findings
            ],
            "owasp_breakdown": owasp_coverage["categories"]
        }