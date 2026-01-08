"""
JWT Attack Testing Data Models
Data structures for JWT attack testing results and configurations
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum


class AttackType(str, Enum):
    """JWT attack vector types"""
    ALG_NONE = "alg_none"
    NULL_SIGNATURE = "null_signature"
    WEAK_SECRET = "weak_secret"
    KID_INJECTION = "kid_injection"
    JWKS_SPOOF = "jwks_spoof"
    INLINE_JWKS = "inline_jwks"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    USER_IMPERSONATION = "user_impersonation"
    EXPIRATION_BYPASS = "expiration_bypass"


class VulnerabilitySeverity(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class RequestDetails:
    """HTTP request details for attack testing"""
    url: str
    method: str
    headers: Dict[str, str]
    body: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ResponseDetails:
    """HTTP response details from attack testing"""
    status_code: int
    headers: Dict[str, str]
    body: str
    response_time: float
    content_length: int
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class VulnerabilityAssessment:
    """Assessment of potential vulnerability from attack response"""
    is_vulnerable: bool
    vulnerability_type: str
    severity: VulnerabilitySeverity
    evidence: List[str] = field(default_factory=list)
    exploitation_steps: List[str] = field(default_factory=list)
    remediation_advice: str = ""
    confidence_score: float = 0.0  # 0.0 to 1.0


@dataclass
class AttackResult:
    """Result of a single JWT attack test"""
    attack_type: AttackType
    attack_variant: str
    jwt_token: str
    request_details: RequestDetails
    response_details: ResponseDetails
    vulnerability_assessment: VulnerabilityAssessment
    timestamp: datetime = field(default_factory=datetime.now)
    success_indicators: List[str] = field(default_factory=list)
    baseline_comparison: Optional[Dict[str, Any]] = None


@dataclass
class BaselineResponse:
    """Baseline response using original JWT token"""
    request_details: RequestDetails
    response_details: ResponseDetails
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class AttackConfiguration:
    """Configuration for JWT attack testing session"""
    target_url: str
    original_jwt: str
    custom_headers: Dict[str, str] = field(default_factory=dict)
    post_data: Optional[str] = None
    attack_vectors: List[AttackType] = field(default_factory=list)
    timeout: int = 30
    max_retries: int = 3
    verify_ssl: bool = True
    session_id: Optional[str] = None


@dataclass
class AttackSession:
    """Complete JWT attack testing session"""
    session_id: str
    configuration: AttackConfiguration
    baseline_response: Optional[BaselineResponse] = None
    attack_results: List[AttackResult] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    total_attacks: int = 0
    successful_attacks: int = 0
    
    @property
    def duration(self) -> Optional[float]:
        """Calculate session duration in seconds"""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None
    
    @property
    def success_rate(self) -> float:
        """Calculate attack success rate"""
        if self.total_attacks == 0:
            return 0.0
        return (self.successful_attacks / self.total_attacks) * 100


@dataclass
class AttackSummary:
    """Summary of attack testing results"""
    session: AttackSession
    vulnerabilities_found: List[AttackResult] = field(default_factory=list)
    potential_vulnerabilities: List[AttackResult] = field(default_factory=list)
    failed_attacks: List[AttackResult] = field(default_factory=list)
    
    @property
    def critical_vulnerabilities(self) -> List[AttackResult]:
        """Get critical severity vulnerabilities"""
        return [v for v in self.vulnerabilities_found 
                if v.vulnerability_assessment.severity == VulnerabilitySeverity.CRITICAL]
    
    @property
    def high_vulnerabilities(self) -> List[AttackResult]:
        """Get high severity vulnerabilities"""
        return [v for v in self.vulnerabilities_found 
                if v.vulnerability_assessment.severity == VulnerabilitySeverity.HIGH]
    
    @property
    def has_critical_findings(self) -> bool:
        """Check if any critical vulnerabilities were found"""
        return len(self.critical_vulnerabilities) > 0
    
    @property
    def has_high_findings(self) -> bool:
        """Check if any high severity vulnerabilities were found"""
        return len(self.high_vulnerabilities) > 0