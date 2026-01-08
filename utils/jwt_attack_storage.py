"""
JWT Attack Storage Manager
Handles file operations for JWT attack testing sessions
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from core.logging import get_logger
from .jwt_attack_models import (
    AttackResult, AttackSession, AttackSummary, AttackType, 
    BaselineResponse, VulnerabilitySeverity
)


class AttackStorageManager:
    """
    Manages storage of JWT attack tokens, results, and reports
    
    Features:
    - Session-based directory structure
    - JWT token file storage with descriptive names
    - Response result file storage
    - Comprehensive report generation
    - Session management
    """
    
    def __init__(self, base_dir: str = "jwtattack"):
        """
        Initialize attack storage manager
        
        Args:
            base_dir: Base directory for storing attack data
        """
        self.base_dir = Path(base_dir)
        self.session_id = self.generate_session_id()
        self.session_dir = self.base_dir / self.session_id
        
        self.logger = get_logger(__name__).bind(component="jwt_attack_storage")
        
        self.logger.info("Attack Storage Manager initialized",
                        base_dir=str(self.base_dir),
                        session_id=self.session_id)
    
    def generate_session_id(self) -> str:
        """
        Generate unique session ID
        
        Returns:
            Unique session identifier
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_id = str(uuid.uuid4())[:8]
        return f"jwt_attack_{timestamp}_{unique_id}"
    
    def create_session_directory(self) -> None:
        """Create directory structure for attack session"""
        try:
            # Create base directory if it doesn't exist
            self.base_dir.mkdir(exist_ok=True)
            
            # Create session directory
            self.session_dir.mkdir(exist_ok=True)
            
            # Create subdirectories for organization
            (self.session_dir / "tokens").mkdir(exist_ok=True)
            (self.session_dir / "responses").mkdir(exist_ok=True)
            (self.session_dir / "reports").mkdir(exist_ok=True)
            
            self.logger.info("Session directory created",
                           session_dir=str(self.session_dir))
            
        except Exception as e:
            self.logger.error("Failed to create session directory",
                            error=str(e))
            raise
    
    def save_attack_token(self, attack_type: AttackType, token: str, 
                         variant_id: int = 0) -> Path:
        """
        Save generated attack token to file
        
        Args:
            attack_type: Type of attack vector
            token: JWT token string
            variant_id: Variant number for multiple tokens of same type
            
        Returns:
            Path to saved token file
        """
        try:
            # Ensure session directory exists
            if not self.session_dir.exists():
                self.create_session_directory()
            
            # Generate descriptive filename
            if variant_id > 0:
                filename = f"{attack_type.value}_variant_{variant_id}.jwt"
            else:
                filename = f"{attack_type.value}.jwt"
            
            token_path = self.session_dir / "tokens" / filename
            
            # Save token to file
            with open(token_path, 'w', encoding='utf-8') as f:
                f.write(token)
            
            self.logger.debug("Attack token saved",
                            attack_type=attack_type.value,
                            variant_id=variant_id,
                            file_path=str(token_path))
            
            return token_path
            
        except Exception as e:
            self.logger.error("Failed to save attack token",
                            attack_type=attack_type.value,
                            error=str(e))
            raise
    
    def save_attack_result(self, attack_result: AttackResult) -> Path:
        """
        Save attack result details to file
        
        Args:
            attack_result: Complete attack result object
            
        Returns:
            Path to saved result file
        """
        try:
            # Ensure session directory exists
            if not self.session_dir.exists():
                self.create_session_directory()
            
            # Generate filename based on attack type and timestamp
            timestamp = attack_result.timestamp.strftime("%H%M%S")
            filename = f"{attack_result.attack_type.value}_{timestamp}_result.json"
            
            result_path = self.session_dir / "responses" / filename
            
            # Convert attack result to dictionary for JSON serialization
            result_dict = {
                'attack_type': attack_result.attack_type.value,
                'attack_variant': attack_result.attack_variant,
                'jwt_token': attack_result.jwt_token,
                'timestamp': attack_result.timestamp.isoformat(),
                'request_details': {
                    'url': attack_result.request_details.url,
                    'method': attack_result.request_details.method,
                    'headers': attack_result.request_details.headers,
                    'body': attack_result.request_details.body,
                    'timestamp': attack_result.request_details.timestamp.isoformat()
                },
                'response_details': {
                    'status_code': attack_result.response_details.status_code,
                    'headers': attack_result.response_details.headers,
                    'body': attack_result.response_details.body,
                    'response_time': attack_result.response_details.response_time,
                    'content_length': attack_result.response_details.content_length,
                    'timestamp': attack_result.response_details.timestamp.isoformat()
                },
                'vulnerability_assessment': {
                    'is_vulnerable': attack_result.vulnerability_assessment.is_vulnerable,
                    'vulnerability_type': attack_result.vulnerability_assessment.vulnerability_type,
                    'severity': attack_result.vulnerability_assessment.severity.value,
                    'evidence': attack_result.vulnerability_assessment.evidence,
                    'exploitation_steps': attack_result.vulnerability_assessment.exploitation_steps,
                    'remediation_advice': attack_result.vulnerability_assessment.remediation_advice,
                    'confidence_score': attack_result.vulnerability_assessment.confidence_score
                },
                'success_indicators': attack_result.success_indicators,
                'baseline_comparison': attack_result.baseline_comparison
            }
            
            # Save result to JSON file
            with open(result_path, 'w', encoding='utf-8') as f:
                json.dump(result_dict, f, indent=2, ensure_ascii=False)
            
            self.logger.debug("Attack result saved",
                            attack_type=attack_result.attack_type.value,
                            file_path=str(result_path))
            
            return result_path
            
        except Exception as e:
            self.logger.error("Failed to save attack result",
                            attack_type=attack_result.attack_type.value,
                            error=str(e))
            raise
    
    def save_baseline_response(self, baseline: BaselineResponse) -> Path:
        """
        Save baseline response for comparison
        
        Args:
            baseline: Baseline response object
            
        Returns:
            Path to saved baseline file
        """
        try:
            # Ensure session directory exists
            if not self.session_dir.exists():
                self.create_session_directory()
            
            baseline_path = self.session_dir / "baseline_response.json"
            
            # Convert baseline to dictionary
            baseline_dict = {
                'timestamp': baseline.timestamp.isoformat(),
                'request_details': {
                    'url': baseline.request_details.url,
                    'method': baseline.request_details.method,
                    'headers': baseline.request_details.headers,
                    'body': baseline.request_details.body,
                    'timestamp': baseline.request_details.timestamp.isoformat()
                },
                'response_details': {
                    'status_code': baseline.response_details.status_code,
                    'headers': baseline.response_details.headers,
                    'body': baseline.response_details.body,
                    'response_time': baseline.response_details.response_time,
                    'content_length': baseline.response_details.content_length,
                    'timestamp': baseline.response_details.timestamp.isoformat()
                }
            }
            
            # Save baseline to JSON file
            with open(baseline_path, 'w', encoding='utf-8') as f:
                json.dump(baseline_dict, f, indent=2, ensure_ascii=False)
            
            self.logger.debug("Baseline response saved",
                            file_path=str(baseline_path))
            
            return baseline_path
            
        except Exception as e:
            self.logger.error("Failed to save baseline response",
                            error=str(e))
            raise
    
    def generate_attack_report(self, attack_summary: AttackSummary) -> Path:
        """
        Generate comprehensive attack report
        
        Args:
            attack_summary: Complete attack summary
            
        Returns:
            Path to generated report file
        """
        try:
            # Ensure session directory exists
            if not self.session_dir.exists():
                self.create_session_directory()
            
            report_path = self.session_dir / "reports" / "attack_report.json"
            
            # Generate comprehensive report
            report = {
                'session_info': {
                    'session_id': attack_summary.session.session_id,
                    'start_time': attack_summary.session.start_time.isoformat(),
                    'end_time': attack_summary.session.end_time.isoformat() if attack_summary.session.end_time else None,
                    'duration_seconds': attack_summary.session.duration,
                    'total_attacks': attack_summary.session.total_attacks,
                    'successful_attacks': attack_summary.session.successful_attacks,
                    'success_rate': attack_summary.session.success_rate
                },
                'configuration': {
                    'target_url': attack_summary.session.configuration.target_url,
                    'attack_vectors': [av.value for av in attack_summary.session.configuration.attack_vectors],
                    'custom_headers': attack_summary.session.configuration.custom_headers,
                    'post_data': attack_summary.session.configuration.post_data,
                    'timeout': attack_summary.session.configuration.timeout,
                    'verify_ssl': attack_summary.session.configuration.verify_ssl
                },
                'summary': {
                    'vulnerabilities_found': len(attack_summary.vulnerabilities_found),
                    'potential_vulnerabilities': len(attack_summary.potential_vulnerabilities),
                    'failed_attacks': len(attack_summary.failed_attacks),
                    'critical_vulnerabilities': len(attack_summary.critical_vulnerabilities),
                    'high_vulnerabilities': len(attack_summary.high_vulnerabilities),
                    'has_critical_findings': attack_summary.has_critical_findings,
                    'has_high_findings': attack_summary.has_high_findings
                },
                'vulnerabilities': [
                    self._attack_result_to_dict(result) 
                    for result in attack_summary.vulnerabilities_found
                ],
                'potential_vulnerabilities': [
                    self._attack_result_to_dict(result) 
                    for result in attack_summary.potential_vulnerabilities
                ],
                'failed_attacks': [
                    self._attack_result_to_dict(result) 
                    for result in attack_summary.failed_attacks
                ]
            }
            
            # Save report to JSON file
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            self.logger.info("Attack report generated",
                           file_path=str(report_path),
                           vulnerabilities_found=len(attack_summary.vulnerabilities_found))
            
            return report_path
            
        except Exception as e:
            self.logger.error("Failed to generate attack report",
                            error=str(e))
            raise
    
    def generate_human_readable_report(self, attack_summary: AttackSummary) -> Path:
        """
        Generate human-readable text report
        
        Args:
            attack_summary: Complete attack summary
            
        Returns:
            Path to generated text report
        """
        try:
            # Ensure session directory exists
            if not self.session_dir.exists():
                self.create_session_directory()
            
            report_path = self.session_dir / "reports" / "attack_report.txt"
            
            with open(report_path, 'w', encoding='utf-8') as f:
                # Header
                f.write("="*80 + "\n")
                f.write("JWT ATTACK TESTING REPORT\n")
                f.write("="*80 + "\n\n")
                
                # Session info
                f.write("SESSION INFORMATION\n")
                f.write("-" * 40 + "\n")
                f.write(f"Session ID: {attack_summary.session.session_id}\n")
                f.write(f"Target URL: {attack_summary.session.configuration.target_url}\n")
                f.write(f"Start Time: {attack_summary.session.start_time}\n")
                if attack_summary.session.end_time:
                    f.write(f"End Time: {attack_summary.session.end_time}\n")
                    f.write(f"Duration: {attack_summary.session.duration:.2f} seconds\n")
                f.write(f"Total Attacks: {attack_summary.session.total_attacks}\n")
                f.write(f"Successful Attacks: {attack_summary.session.successful_attacks}\n")
                f.write(f"Success Rate: {attack_summary.session.success_rate:.1f}%\n\n")
                
                # Summary
                f.write("ATTACK SUMMARY\n")
                f.write("-" * 40 + "\n")
                f.write(f"Vulnerabilities Found: {len(attack_summary.vulnerabilities_found)}\n")
                f.write(f"Potential Vulnerabilities: {len(attack_summary.potential_vulnerabilities)}\n")
                f.write(f"Failed Attacks: {len(attack_summary.failed_attacks)}\n")
                f.write(f"Critical Findings: {len(attack_summary.critical_vulnerabilities)}\n")
                f.write(f"High Severity Findings: {len(attack_summary.high_vulnerabilities)}\n\n")
                
                # Vulnerabilities
                if attack_summary.vulnerabilities_found:
                    f.write("CONFIRMED VULNERABILITIES\n")
                    f.write("-" * 40 + "\n")
                    for i, vuln in enumerate(attack_summary.vulnerabilities_found, 1):
                        f.write(f"{i}. {vuln.attack_type.value.upper()} - {vuln.vulnerability_assessment.severity.value}\n")
                        f.write(f"   Confidence: {vuln.vulnerability_assessment.confidence_score:.2f}\n")
                        f.write(f"   Evidence: {', '.join(vuln.vulnerability_assessment.evidence)}\n")
                        if vuln.vulnerability_assessment.exploitation_steps:
                            f.write(f"   Exploitation: {'; '.join(vuln.vulnerability_assessment.exploitation_steps)}\n")
                        f.write("\n")
                
                # Potential vulnerabilities
                if attack_summary.potential_vulnerabilities:
                    f.write("POTENTIAL VULNERABILITIES (MANUAL REVIEW REQUIRED)\n")
                    f.write("-" * 40 + "\n")
                    for i, vuln in enumerate(attack_summary.potential_vulnerabilities, 1):
                        f.write(f"{i}. {vuln.attack_type.value.upper()}\n")
                        f.write(f"   Response Code: {vuln.response_details.status_code}\n")
                        f.write(f"   Response Time: {vuln.response_details.response_time:.3f}s\n")
                        f.write("\n")
                
                # Footer
                f.write("="*80 + "\n")
                f.write("Report generated by APILeak JWT Attack Tester\n")
                f.write("="*80 + "\n")
            
            self.logger.info("Human-readable report generated",
                           file_path=str(report_path))
            
            return report_path
            
        except Exception as e:
            self.logger.error("Failed to generate human-readable report",
                            error=str(e))
            raise
    
    def _attack_result_to_dict(self, result: AttackResult) -> Dict:
        """Convert AttackResult to dictionary for JSON serialization"""
        return {
            'attack_type': result.attack_type.value,
            'attack_variant': result.attack_variant,
            'timestamp': result.timestamp.isoformat(),
            'vulnerability_assessment': {
                'is_vulnerable': result.vulnerability_assessment.is_vulnerable,
                'vulnerability_type': result.vulnerability_assessment.vulnerability_type,
                'severity': result.vulnerability_assessment.severity.value,
                'confidence_score': result.vulnerability_assessment.confidence_score,
                'evidence': result.vulnerability_assessment.evidence,
                'exploitation_steps': result.vulnerability_assessment.exploitation_steps
            },
            'response_details': {
                'status_code': result.response_details.status_code,
                'response_time': result.response_details.response_time,
                'content_length': result.response_details.content_length
            }
        }
    
    def get_session_directory(self) -> Path:
        """Get current session directory path"""
        return self.session_dir
    
    def list_session_files(self) -> Dict[str, List[Path]]:
        """
        List all files in current session
        
        Returns:
            Dictionary with file categories and their paths
        """
        if not self.session_dir.exists():
            return {'tokens': [], 'responses': [], 'reports': []}
        
        return {
            'tokens': list((self.session_dir / "tokens").glob("*.jwt")) if (self.session_dir / "tokens").exists() else [],
            'responses': list((self.session_dir / "responses").glob("*.json")) if (self.session_dir / "responses").exists() else [],
            'reports': list((self.session_dir / "reports").glob("*")) if (self.session_dir / "reports").exists() else []
        }