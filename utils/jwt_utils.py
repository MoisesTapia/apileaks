"""
JWT Utilities for APILeak
Handles JWT encoding, decoding, and manipulation
"""

import json
import base64
import hmac
import hashlib
from typing import Dict, Any, Optional
import click


def base64url_decode(data: str) -> bytes:
    """Decode base64url encoded data"""
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def base64url_encode(data: bytes) -> str:
    """Encode data as base64url"""
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def decode_jwt(token: str) -> Dict[str, Any]:
    """
    Decode a JWT token without verification
    
    Args:
        token: JWT token string
        
    Returns:
        Dictionary with header, payload, and signature
        
    Raises:
        ValueError: If token format is invalid
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format - must have 3 parts separated by dots")
        
        header_data = base64url_decode(parts[0])
        payload_data = base64url_decode(parts[1])
        signature = parts[2]
        
        header = json.loads(header_data.decode('utf-8'))
        payload = json.loads(payload_data.decode('utf-8'))
        
        return {
            'header': header,
            'payload': payload,
            'signature': signature,
            'raw_header': parts[0],
            'raw_payload': parts[1],
            'raw_signature': parts[2]
        }
        
    except Exception as e:
        raise ValueError(f"Failed to decode JWT: {str(e)}")


def encode_jwt(header: Dict[str, Any], payload: Dict[str, Any], secret: str = "secret") -> str:
    """
    Encode a JWT token with HMAC SHA256 signature
    
    Args:
        header: JWT header dictionary
        payload: JWT payload dictionary
        secret: Secret key for signing (default: "secret")
        
    Returns:
        Encoded JWT token string
    """
    try:
        # Ensure algorithm is set in header
        if 'alg' not in header:
            header['alg'] = 'HS256'
        if 'typ' not in header:
            header['typ'] = 'JWT'
        
        # Encode header and payload
        header_encoded = base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
        payload_encoded = base64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
        
        # Create signature
        message = f"{header_encoded}.{payload_encoded}"
        signature = hmac.new(
            secret.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).digest()
        signature_encoded = base64url_encode(signature)
        
        return f"{header_encoded}.{payload_encoded}.{signature_encoded}"
        
    except Exception as e:
        raise ValueError(f"Failed to encode JWT: {str(e)}")


def get_random_user_agents() -> list:
    """Get list of random user agents for WAF evasion"""
    return [
        # Chrome
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        
        # Firefox
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        
        # Safari
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        
        # Edge
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        
        # Mobile
        "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
        "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        
        # API Clients
        "curl/8.4.0",
        "HTTPie/3.2.2",
        "Postman/10.20.0",
        "insomnia/2023.8.0",
        
        # Security Tools (for legitimate testing)
        "Burp Suite Professional/2023.10.3.4",
        "OWASP ZAP/2.14.0",
        "Nmap Scripting Engine",
        "sqlmap/1.7.11",
        
        # Custom API testing
        "APITester/1.0",
        "SecurityScanner/2.1",
        "PenetrationTest/1.5"
    ]


def print_jwt_info(decoded_jwt: Dict[str, Any]) -> None:
    """Pretty print JWT information"""
    click.echo("\n" + "="*60)
    click.echo("JWT Token Analysis")
    click.echo("="*60)
    
    # Header
    click.echo("\n📋 HEADER:")
    click.echo("-" * 20)
    for key, value in decoded_jwt['header'].items():
        click.echo(f"  {key}: {value}")
    
    # Payload
    click.echo("\n🔐 PAYLOAD:")
    click.echo("-" * 20)
    for key, value in decoded_jwt['payload'].items():
        if key in ['exp', 'iat', 'nbf']:
            # Convert timestamp to readable date
            try:
                import datetime
                readable_date = datetime.datetime.fromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S UTC')
                click.echo(f"  {key}: {value} ({readable_date})")
            except:
                click.echo(f"  {key}: {value}")
        else:
            click.echo(f"  {key}: {value}")
    
    # Signature info
    click.echo("\n🔏 SIGNATURE:")
    click.echo("-" * 20)
    click.echo(f"  Algorithm: {decoded_jwt['header'].get('alg', 'Unknown')}")
    click.echo(f"  Signature: {decoded_jwt['signature'][:20]}...")
    
    # Security warnings
    click.echo("\n⚠️  SECURITY NOTES:")
    click.echo("-" * 20)
    
    alg = decoded_jwt['header'].get('alg', '').upper()
    if alg == 'NONE':
        click.echo("  🚨 WARNING: Algorithm is 'none' - no signature verification!")
    elif alg.startswith('HS'):
        click.echo("  ℹ️  Uses HMAC signature - requires shared secret")
    elif alg.startswith('RS') or alg.startswith('ES'):
        click.echo("  ℹ️  Uses asymmetric signature - requires public key verification")
    
    # Check expiration
    if 'exp' in decoded_jwt['payload']:
        import datetime
        exp_time = datetime.datetime.fromtimestamp(decoded_jwt['payload']['exp'])
        now = datetime.datetime.now()
        if exp_time < now:
            click.echo("  🚨 WARNING: Token is EXPIRED!")
        else:
            time_left = exp_time - now
            click.echo(f"  ✅ Token expires in: {time_left}")
    
    click.echo("\n" + "="*60)