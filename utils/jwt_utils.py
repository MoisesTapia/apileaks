"""
JWT Utilities for APILeak
Handles JWT encoding, decoding, and manipulation
"""

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional

import click
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey,
    EllipticCurvePublicNumbers,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


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


def decode_jwt(token: str) -> dict[str, Any]:
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
        raise ValueError(f"Failed to decode JWT: {str(e)}") from e


def encode_jwt(header: dict[str, Any], payload: dict[str, Any], secret: str = "secret") -> str:
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

        # alg:none — no signature, trailing dot only (RFC 7519 §6)
        if header.get('alg', '').lower() == 'none':
            return f"{header_encoded}.{payload_encoded}."

        # Create HMAC signature
        message = f"{header_encoded}.{payload_encoded}"
        signature = hmac.new(
            secret.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).digest()
        signature_encoded = base64url_encode(signature)

        return f"{header_encoded}.{payload_encoded}.{signature_encoded}"

    except Exception as e:
        raise ValueError(f"Failed to encode JWT: {str(e)}") from e


def verify_hmac_secret(token: str, secret: str) -> bool:
    """
    Verify an HMAC-signed JWT against a candidate secret (Req 16.1/16.2/16.3).

    HMAC-signs the ORIGINAL raw `header.payload` segments (never re-encodes the
    full token) and compares the resulting base64url-encoded digest to the
    original signature segment using a constant-time comparison.

    Args:
        token: JWT token string
        secret: Candidate secret key to test

    Returns:
        True if the candidate secret produces a signature matching the token's
        original signature segment, False otherwise (including malformed tokens
        and unsupported/non-HMAC algorithms).
    """
    parts = token.split('.')
    if len(parts) != 3:
        return False

    # HMAC over the ORIGINAL raw header.payload segments (no re-encoding).
    signing_input = f"{parts[0]}.{parts[1]}".encode()

    # Select the digest based on the header's declared algorithm.
    try:
        header = json.loads(base64url_decode(parts[0]).decode('utf-8'))
        alg = str(header.get('alg', 'HS256')).upper()
    except Exception:
        return False

    digestmod = {
        'HS256': hashlib.sha256,
        'HS384': hashlib.sha384,
        'HS512': hashlib.sha512,
    }.get(alg)
    if digestmod is None:
        return False

    computed = base64url_encode(
        hmac.new(secret.encode('utf-8'), signing_input, digestmod).digest()
    )
    return hmac.compare_digest(computed, parts[2])


# ---------------------------------------------------------------------------
# ECDSA support and the Psychic Signature (CVE-2022-21449) — Requirement 59.
#
# Added ALONGSIDE the HMAC primitives above; none of the existing functions are
# altered. The `cryptography` library provides ECDSA key handling and DER<->raw
# signature conversion, so JWT crypto is not reimplemented from scratch.
# ---------------------------------------------------------------------------

# ECDSA curves keyed by JOSE algorithm name (Req 59.1).
ES_CURVES = {
    "ES256": ec.SECP256R1,
    "ES384": ec.SECP384R1,
    "ES512": ec.SECP521R1,
}

# hashlib digests keyed by JOSE algorithm name (Req 59.1).
ES_DIGESTS = {
    "ES256": hashlib.sha256,
    "ES384": hashlib.sha384,
    "ES512": hashlib.sha512,
}

# Raw (r||s) signature byte length per algorithm (JOSE encoding, Req 59.1/59.2).
ES_SIG_BYTES = {
    "ES256": 64,
    "ES384": 96,
    "ES512": 132,
}

# `cryptography` hash primitives keyed by JOSE algorithm name (internal helper
# used for signing/verification; the public digest mapping is ``ES_DIGESTS``).
_ES_EC_HASHES = {
    "ES256": hashes.SHA256,
    "ES384": hashes.SHA384,
    "ES512": hashes.SHA512,
}


def encode_jwt_ecdsa(header: dict[str, Any], payload: dict[str, Any],
                     private_key: "ec.EllipticCurvePrivateKey") -> str:
    """Sign ``header.payload`` with an ECDSA private key (Req 59.1).

    Emits the JOSE raw ``r||s`` signature (fixed-width big-endian components,
    NOT the DER encoding produced by ``private_key.sign``) for the algorithm
    named in the header. Defaults ``alg`` to ``ES256`` and ``typ`` to ``JWT``
    when absent, mirroring ``encode_jwt``.

    Args:
        header: JWT header dictionary (its ``alg`` selects the curve/digest).
        payload: JWT payload dictionary.
        private_key: An ECDSA private key from the ``cryptography`` library.

    Returns:
        The encoded ``header.payload.signature`` JWT string.

    Raises:
        ValueError: If the header ``alg`` is not a supported ECDSA algorithm.
    """
    header = dict(header)
    if 'alg' not in header:
        header['alg'] = 'ES256'
    if 'typ' not in header:
        header['typ'] = 'JWT'

    alg = str(header['alg']).upper()
    if alg not in ES_SIG_BYTES:
        raise ValueError(f"Unsupported ECDSA algorithm: {header.get('alg')}")

    header_encoded = base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    payload_encoded = base64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
    message = f"{header_encoded}.{payload_encoded}".encode()

    der_signature = private_key.sign(message, ec.ECDSA(_ES_EC_HASHES[alg]()))
    r, s = asym_utils.decode_dss_signature(der_signature)

    component_size = ES_SIG_BYTES[alg] // 2
    raw_signature = r.to_bytes(component_size, 'big') + s.to_bytes(component_size, 'big')
    signature_encoded = base64url_encode(raw_signature)

    return f"{header_encoded}.{payload_encoded}.{signature_encoded}"


def verify_ecdsa_signature(token: str, public_key: "ec.EllipticCurvePublicKey") -> bool:
    """Verify an ES*-signed JWT against a public key (Req 59.1).

    Decodes the JOSE raw ``r||s`` signature, reconstructs the DER encoding and
    verifies it. A correct verifier rejects the Psychic Signature
    (CVE-2022-21449): a null ECDSA signature with ``r == s == 0`` returns
    ``False`` here rather than being accepted.

    Args:
        token: JWT token string.
        public_key: An ECDSA public key from the ``cryptography`` library.

    Returns:
        True only if the signature is a valid, non-null ECDSA signature over the
        original ``header.payload`` segments; False otherwise (including
        malformed tokens, non-ECDSA algorithms, wrong-length signatures, and the
        null ``r == s == 0`` Psychic Signature).
    """
    parts = token.split('.')
    if len(parts) != 3:
        return False

    try:
        header = json.loads(base64url_decode(parts[0]).decode('utf-8'))
        alg = str(header.get('alg', '')).upper()
    except Exception:
        return False

    if alg not in ES_SIG_BYTES:
        return False

    try:
        raw_signature = base64url_decode(parts[2])
    except Exception:
        return False

    expected_len = ES_SIG_BYTES[alg]
    if len(raw_signature) != expected_len:
        return False

    half = expected_len // 2
    r = int.from_bytes(raw_signature[:half], 'big')
    s = int.from_bytes(raw_signature[half:], 'big')

    # Psychic Signature (CVE-2022-21449): a null (r == 0, s == 0) signature must
    # never verify. Reject it explicitly (Req 59.2).
    if r == 0 and s == 0:
        return False

    try:
        der_signature = asym_utils.encode_dss_signature(r, s)
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        public_key.verify(der_signature, signing_input, ec.ECDSA(_ES_EC_HASHES[alg]()))
        return True
    except Exception:
        return False


def psychic_signature_segment(alg: str) -> str:
    """Return the base64url of ``ES_SIG_BYTES[alg]`` zero bytes (Req 59.2).

    This is the JOSE encoding of an ECDSA signature with ``r == 0`` and
    ``s == 0`` — the Psychic Signature used to probe null-signature acceptance
    flaws (CVE-2022-21449).
    """
    return base64url_encode(b"\x00" * ES_SIG_BYTES[alg.upper()])


# ---------------------------------------------------------------------------
# Algorithm-confusion public-key representation variants — Requirement 60.
# ---------------------------------------------------------------------------

def _public_key_variants(material: str | bytes) -> list[tuple[str, bytes]]:
    """Yield ``(representation_name, key_bytes)`` for the same source public key.

    Produces the public-key representations an algorithm-confusion test submits
    as the HMAC key (Reqs 60.1, 60.2):

      - ``'pem_with_newline'``    : PEM SubjectPublicKeyInfo ending in ``\\n``
      - ``'pem_without_newline'`` : the same PEM with the trailing newline stripped
      - ``'der'``                 : DER-encoded SubjectPublicKeyInfo bytes
      - ``'x5c_cert_der'``        : certificate DER bytes (only when the material
                                    is/contains an X.509 certificate)

    The source ``material`` may be a PEM/DER public key or a PEM/DER X.509
    certificate (the same JWK/PEM/cert conversion used for Reqs 6.2/45.1).
    Representations that cannot be produced from the given material are OMITTED,
    never raised — an unparseable input yields an empty list.
    """
    variants: list[tuple[str, bytes]] = []

    if isinstance(material, str):
        raw = material.encode('utf-8')
    elif isinstance(material, bytes | bytearray):
        raw = bytes(material)
    else:
        return variants

    public_key = None
    certificate = None

    # Prefer certificate loaders so the x5c representation is available; a raw
    # public key falls through to the SPKI loaders below.
    for cert_loader in (x509.load_pem_x509_certificate, x509.load_der_x509_certificate):
        try:
            certificate = cert_loader(raw)
            public_key = certificate.public_key()
            break
        except Exception:
            certificate = None

    if public_key is None:
        for key_loader in (serialization.load_pem_public_key,
                           serialization.load_der_public_key):
            try:
                public_key = key_loader(raw)
                break
            except Exception:
                continue

    if public_key is None:
        return variants

    # PEM SubjectPublicKeyInfo (with and without the trailing newline).
    try:
        pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        pem_with_nl = pem if pem.endswith(b"\n") else pem + b"\n"
        pem_without_nl = pem_with_nl[:-1]
        variants.append(('pem_with_newline', pem_with_nl))
        variants.append(('pem_without_newline', pem_without_nl))
    except Exception:
        pass

    # DER SubjectPublicKeyInfo bytes.
    try:
        der = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        variants.append(('der', der))
    except Exception:
        pass

    # Certificate-derived (x5c) bytes — only producible from a certificate.
    if certificate is not None:
        try:
            variants.append(('x5c_cert_der', certificate.public_bytes(Encoding.DER)))
        except Exception:
            pass

    return variants


# ---------------------------------------------------------------------------
# Static claim-hygiene and lifetime/replay analyzers — Requirements 61 & 62.
#
# Added ALONGSIDE the crypto primitives above; none of the existing functions
# are altered. Both analyzers are PURE and STATIC: they inspect an already
# decoded payload and issue NO HTTP request (Reqs 61.1, 62.4).
# ---------------------------------------------------------------------------

# Security-relevant Registered_Claims inspected by the claim-hygiene analyzer
# (Req 61.1). Order is preserved so findings are emitted deterministically.
SECURITY_CLAIMS = ("exp", "iss", "aud", "jti")

# Maps each inspected Registered_Claim to the Finding_Category emitted when the
# claim is absent (Reqs 61.2-61.5). These categories resolve to OWASP API2 in
# the Findings_Collector.
CLAIM_MISSING_CATEGORY = {
    "exp": "JWT_MISSING_EXP_CLAIM",
    "iss": "JWT_MISSING_ISS_CLAIM",
    "aud": "JWT_MISSING_AUD_CLAIM",
    "jti": "JWT_MISSING_JTI_CLAIM",
}


@dataclass
class ClaimFinding:
    """A static claim/lifetime assessment result (Reqs 61, 62).

    Attributes:
        category: The Finding_Category (e.g. ``JWT_MISSING_EXP_CLAIM`` or
            ``JWT_EXCESSIVE_TOKEN_LIFETIME``).
        claim: The named Registered_Claim the finding concerns (Req 61.6).
        detail: Optional supporting data — for a lifetime finding this carries
            the computed ``lifetime`` and the ``threshold`` (Req 62.2).
    """
    category: str
    claim: str
    detail: dict[str, Any] = field(default_factory=dict)


def assess_claim_hygiene(payload: dict[str, Any]) -> list[ClaimFinding]:
    """Statically assess Registered_Claim hygiene of a decoded JWT payload.

    Reports one ``ClaimFinding`` per ABSENT Registered_Claim in
    ``SECURITY_CLAIMS`` (Reqs 61.2-61.5), each finding naming exactly the absent
    claim (Req 61.6). A claim that is present — regardless of its value —
    produces no finding. This is a pure, read-only inspection that issues NO
    HTTP request (Req 61.1).

    Args:
        payload: The decoded JWT payload (claims) dictionary.

    Returns:
        A list of ``ClaimFinding`` objects, one per absent security claim, in
        the fixed ``SECURITY_CLAIMS`` order.
    """
    findings: list[ClaimFinding] = []
    for claim in SECURITY_CLAIMS:
        if claim not in payload:
            findings.append(ClaimFinding(
                category=CLAIM_MISSING_CATEGORY[claim],
                claim=claim,
                detail={},
            ))
    return findings


def assess_lifetime(payload: dict[str, Any],
                    threshold_seconds: int) -> list[ClaimFinding]:
    """Statically assess token lifetime and replay protection (Req 62).

    When both ``exp`` and ``iat`` are present, computes ``lifetime = exp - iat``
    and, if it exceeds ``threshold_seconds``, reports a
    ``JWT_EXCESSIVE_TOKEN_LIFETIME`` finding whose ``detail`` carries the
    computed ``lifetime`` and the ``threshold`` (Reqs 62.1, 62.2). When the
    ``jti`` Registered_Claim providing Replay_Protection is absent, reports a
    ``JWT_MISSING_JTI_CLAIM`` finding (Req 62.3). This is a pure, read-only
    assessment that issues NO HTTP request (Req 62.4).

    Args:
        payload: The decoded JWT payload (claims) dictionary.
        threshold_seconds: The configurable lifetime threshold in seconds.

    Returns:
        A list of ``ClaimFinding`` objects for the lifetime/replay weaknesses
        detected (possibly empty).
    """
    findings: list[ClaimFinding] = []

    if "exp" in payload and "iat" in payload:
        lifetime = payload["exp"] - payload["iat"]
        if lifetime > threshold_seconds:
            findings.append(ClaimFinding(
                category="JWT_EXCESSIVE_TOKEN_LIFETIME",
                claim="exp",
                detail={"lifetime": lifetime, "threshold": threshold_seconds},
            ))

    if "jti" not in payload:
        findings.append(ClaimFinding(
            category=CLAIM_MISSING_CATEGORY["jti"],
            claim="jti",
            detail={},
        ))

    return findings


# ---------------------------------------------------------------------------
# Verify-mode, key-generation, JWKS-reconstruction, vector-file, and raw-request
# helpers — Requirements 63.6, 65, 66, 67.
#
# Added ALONGSIDE the crypto/claim primitives above; none of the existing
# functions are altered. Every helper here is network-free: verify mode, key
# generation, JWKS reconstruction, vector-file reading, and raw-request parsing
# all operate on local material and issue NO HTTP request (Reqs 65.3, 66.4,
# 67.2). Error paths raise descriptive errors that NAME the offending source.
# ---------------------------------------------------------------------------

# RSA JOSE algorithm -> `cryptography` hash primitive (RS*/PS* verification).
_RSA_HASHES = {
    "RS256": hashes.SHA256, "RS384": hashes.SHA384, "RS512": hashes.SHA512,
    "PS256": hashes.SHA256, "PS384": hashes.SHA384, "PS512": hashes.SHA512,
}

# JWK `crv` name -> EC curve class (mirrors ES_CURVES keyed by JOSE alg).
_JWK_EC_CURVES = {
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
    "P-521": ec.SECP521R1,
}


@dataclass
class VerifyResult:
    """Result of a network-free Token_Verification (Req 65).

    Attributes:
        valid: Whether the token signature verifies against the supplied key
            material (Req 65.1).
        algorithm: The algorithm named in the token header (Req 65.2).
        key_source: Which key source was used — one of ``secret``, ``key file``,
            ``pem``, or ``jwks``.
    """
    valid: bool
    algorithm: str
    key_source: str


def _verify_rsa_signature(token: str, public_key: "RSAPublicKey", alg: str) -> bool:
    """Verify an RS*/PS*-signed JWT against an RSA public key.

    RS* uses PKCS#1 v1.5 padding; PS* uses PSS with an MGF1 mask and a salt
    length equal to the digest size. Returns False for malformed tokens,
    non-RSA keys, or a signature that does not verify.
    """
    parts = token.split('.')
    if len(parts) != 3:
        return False

    hash_cls = _RSA_HASHES.get(alg)
    if hash_cls is None:
        return False

    try:
        signature = base64url_decode(parts[2])
    except Exception:
        return False

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    hash_alg = hash_cls()

    if alg.startswith("PS"):
        pad = padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=hash_alg.digest_size)
    else:
        pad = padding.PKCS1v15()

    try:
        public_key.verify(signature, signing_input, pad, hash_alg)
        return True
    except Exception:
        return False


def _load_public_key_for_verify(key_file: str | None, pem: str | None,
                                jwks: dict[str, Any] | None):
    """Resolve an asymmetric public key from exactly one supplied source.

    Returns ``(public_key, key_source_name)``. Raises a ``ValueError`` whose
    message NAMES the offending source when the material is missing or cannot be
    read/parsed (Req 65.4). No HTTP is issued for any source (Req 65.3).
    """
    if pem is not None:
        try:
            data = pem.encode('utf-8') if isinstance(pem, str) else bytes(pem)
            return serialization.load_pem_public_key(data), "pem"
        except Exception:
            # A PEM certificate is also acceptable material.
            try:
                cert = x509.load_pem_x509_certificate(data)
                return cert.public_key(), "pem"
            except Exception as exc:
                raise ValueError(f"Could not parse public key from PEM material: {exc}") from exc

    if key_file is not None:
        try:
            with open(key_file, 'rb') as fh:
                data = fh.read()
        except Exception as exc:
            raise ValueError(f"Could not read key file '{key_file}': {exc}") from exc
        for loader in (serialization.load_pem_public_key,
                       serialization.load_der_public_key):
            try:
                return loader(data), "key file"
            except Exception:
                continue
        for cert_loader in (x509.load_pem_x509_certificate,
                            x509.load_der_x509_certificate):
            try:
                return cert_loader(data).public_key(), "key file"
            except Exception:
                continue
        raise ValueError(f"Could not parse public key from key file '{key_file}'")

    if jwks is not None:
        # Accept either a full JWKS ({"keys": [...]}) or a single JWK entry.
        try:
            entry = jwks
            if isinstance(jwks, dict) and "keys" in jwks:
                keys = jwks.get("keys") or []
                if not keys:
                    raise ValueError("JWKS contains no keys")
                entry = keys[0]
            reconstructed_pem = reconstruct_public_key_from_jwks(entry)
            return serialization.load_pem_public_key(reconstructed_pem.encode('utf-8')), "jwks"
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError(f"Could not reconstruct public key from JWKS: {exc}") from exc

    raise ValueError(
        "No asymmetric key source supplied (expected one of: key file, pem, jwks)"
    )


def verify_token(token: str, *, secret: str | None = None,
                 key_file: str | None = None, pem: str | None = None,
                 jwks: dict[str, Any] | None = None) -> VerifyResult:
    """Verify a token signature against exactly one supplied key source (Req 65).

    Dispatches on the header ``alg``:

      - ``HS*`` -> :func:`verify_hmac_secret` with the supplied ``secret``.
      - ``RS*``/``PS*`` -> RSA public-key verification.
      - ``ES*`` -> :func:`verify_ecdsa_signature` with an EC public key.

    Reports validity and the header algorithm and issues NO HTTP request
    (Reqs 65.1-65.3). Raises a descriptive ``ValueError`` naming the offending
    key source when the required material is missing or cannot be read/parsed
    (Req 65.4).

    Args:
        token: JWT token string.
        secret: Candidate secret for HMAC (``HS*``) algorithms.
        key_file: Path to a PEM/DER public key or certificate file.
        pem: Inline PEM public key or certificate material.
        jwks: A JWKS dict (``{"keys": [...]}``) or a single JWK entry.

    Returns:
        A :class:`VerifyResult` with ``valid``, ``algorithm``, and ``key_source``.
    """
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT format - must have 3 parts separated by dots")

    try:
        header = json.loads(base64url_decode(parts[0]).decode('utf-8'))
    except Exception as exc:
        raise ValueError(f"Could not decode JWT header: {exc}") from exc

    alg_raw = header.get('alg', '')
    alg = str(alg_raw).upper()

    if alg.startswith("HS"):
        if secret is None:
            raise ValueError(
                f"Token alg '{alg_raw}' requires a secret, but no secret was supplied"
            )
        valid = verify_hmac_secret(token, secret)
        return VerifyResult(valid=valid, algorithm=str(alg_raw), key_source="secret")

    if alg.startswith("RS") or alg.startswith("PS") or alg.startswith("ES"):
        public_key, key_source = _load_public_key_for_verify(key_file, pem, jwks)

        if alg.startswith("ES"):
            if not isinstance(public_key, EllipticCurvePublicKey):
                raise ValueError(
                    f"Token alg '{alg_raw}' requires an EC public key, but the "
                    f"supplied {key_source} is not an EC key"
                )
            valid = verify_ecdsa_signature(token, public_key)
        else:
            if not isinstance(public_key, RSAPublicKey):
                raise ValueError(
                    f"Token alg '{alg_raw}' requires an RSA public key, but the "
                    f"supplied {key_source} is not an RSA key"
                )
            valid = _verify_rsa_signature(token, public_key, alg)

        return VerifyResult(valid=valid, algorithm=str(alg_raw), key_source=key_source)

    raise ValueError(f"Unsupported algorithm '{alg_raw}' for token verification")


def generate_rsa_keypair(bits: int = 2048) -> tuple[str, str]:
    """Generate a fresh RSA keypair for testing (Req 66.1).

    Args:
        bits: RSA modulus size in bits.

    Returns:
        A ``(private_pem, public_pem)`` tuple. The private key is PKCS#8 PEM
        (unencrypted) and the public key is SubjectPublicKeyInfo PEM.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    private_pem = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode('utf-8')
    public_pem = private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return private_pem, public_pem


def generate_ec_keypair(curve: str = "ES256") -> tuple[str, str]:
    """Generate a fresh EC keypair for testing (Req 66.1).

    Args:
        curve: An ECDSA_Algorithm name (``ES256``/``ES384``/``ES512``) selecting
            the curve via :data:`ES_CURVES`.

    Returns:
        A ``(private_pem, public_pem)`` tuple (PKCS#8 / SubjectPublicKeyInfo PEM).

    Raises:
        ValueError: If ``curve`` is not a supported ECDSA algorithm.
    """
    curve_cls = ES_CURVES.get(str(curve).upper())
    if curve_cls is None:
        raise ValueError(f"Unsupported EC curve/algorithm: {curve}")

    private_key = ec.generate_private_key(curve_cls())
    private_pem = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode('utf-8')
    public_pem = private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return private_pem, public_pem


def reconstruct_public_key_from_jwks(jwk: dict[str, Any]) -> str:
    """Reconstruct a PEM public key from a single JWK entry (Req 66.2).

    Reuses the same JWK-to-key conversion approach used for Algorithm_Confusion
    (Req 6.2) and jku/x5u signing (Req 45.1): an RSA JWK is rebuilt from
    base64url ``n``/``e`` via ``RSAPublicNumbers``, and an EC JWK from ``crv``
    plus base64url ``x``/``y`` via ``EllipticCurvePublicNumbers``. Reconstruction
    is purely local and issues NO HTTP request (Req 66.4).

    Args:
        jwk: A single JWK entry dictionary.

    Returns:
        The reconstructed public key as SubjectPublicKeyInfo PEM text.

    Raises:
        ValueError: If the entry cannot be parsed or lacks the RSA ``n``/``e`` or
            EC ``crv``/``x``/``y`` parameters required to reconstruct a key
            (Req 66.5).
    """
    if not isinstance(jwk, dict):
        raise ValueError("JWKS entry could not be parsed: expected a JWK object")

    kty = str(jwk.get('kty', '')).upper()

    # Infer key type from present parameters when kty is absent.
    if not kty:
        if jwk.get('n') and jwk.get('e'):
            kty = "RSA"
        elif jwk.get('x') and jwk.get('y'):
            kty = "EC"

    try:
        if kty == "RSA":
            n_b64 = jwk.get('n')
            e_b64 = jwk.get('e')
            if not n_b64 or not e_b64:
                raise ValueError("RSA JWK entry is missing the 'n'/'e' parameters")
            n = int.from_bytes(base64url_decode(n_b64), 'big')
            e = int.from_bytes(base64url_decode(e_b64), 'big')
            public_key = RSAPublicNumbers(e, n).public_key()

        elif kty == "EC":
            crv = str(jwk.get('crv', ''))
            x_b64 = jwk.get('x')
            y_b64 = jwk.get('y')
            curve_cls = _JWK_EC_CURVES.get(crv)
            if curve_cls is None:
                raise ValueError(f"EC JWK entry has an unsupported curve: {crv!r}")
            if not x_b64 or not y_b64:
                raise ValueError("EC JWK entry is missing the 'x'/'y' parameters")
            x = int.from_bytes(base64url_decode(x_b64), 'big')
            y = int.from_bytes(base64url_decode(y_b64), 'big')
            public_key = EllipticCurvePublicNumbers(x, y, curve_cls()).public_key()

        else:
            raise ValueError(
                f"JWKS entry has an unsupported or missing key type (kty={jwk.get('kty')!r})"
            )
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Could not reconstruct public key from JWKS entry: {exc}") from exc

    return public_key.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')


def read_vector_file(path: str) -> list[str]:
    """Read a Vector_File, returning one candidate value per line (Req 63.6).

    Blank lines are skipped; each returned value has its trailing line-ending
    removed. Raises a descriptive ``ValueError`` NAMING ``path`` when the file
    cannot be read — consumed before any request is issued.

    Args:
        path: Filesystem path to the Vector_File.

    Returns:
        A list of candidate values, one per non-empty line.

    Raises:
        ValueError: If the Vector_File cannot be read (message names ``path``).
    """
    try:
        with open(path, encoding='utf-8') as fh:
            lines = fh.readlines()
    except Exception as exc:
        raise ValueError(f"Could not read vector file '{path}': {exc}") from exc

    values: list[str] = []
    for line in lines:
        value = line.rstrip('\r\n')
        if value:
            values.append(value)
    return values


# Matches a JWT (three base64url segments; the signature segment may be empty
# for an unsigned/`alg=none` token).
_JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')


@dataclass
class RawRequest:
    """A parsed raw HTTP request with the JWT located within it (Req 67).

    Attributes:
        method: The HTTP method from the request line.
        url: The request URL (scheme + Host header + path when derivable).
        headers: Parsed request headers.
        cookies: Parsed cookies (from the ``Cookie`` header).
        body: The request body, or ``None`` when absent.
        token: The JWT located within the request (Authorization: Bearer, a
            cookie value, or the body).
    """
    method: str
    url: str
    headers: dict[str, str]
    cookies: dict[str, str]
    body: str | None
    token: str


def _locate_jwt(headers: dict[str, str], cookies: dict[str, str],
                body: str | None) -> str | None:
    """Locate a JWT within parsed request components.

    Search order: ``Authorization: Bearer <token>``, then any cookie value, then
    the body, then any remaining header value. Returns the located token or
    ``None``.
    """
    # 1) Authorization: Bearer <token>
    for name, value in headers.items():
        if name.lower() == 'authorization':
            match = _JWT_PATTERN.search(value)
            if match:
                return match.group(0)

    # 2) Cookie values.
    for value in cookies.values():
        match = _JWT_PATTERN.search(value)
        if match:
            return match.group(0)

    # 3) Body (form field or JSON value).
    if body:
        match = _JWT_PATTERN.search(body)
        if match:
            return match.group(0)

    # 4) Fallback: any other header value.
    for value in headers.values():
        match = _JWT_PATTERN.search(value)
        if match:
            return match.group(0)

    return None


def _parse_cookie_header(cookie_value: str) -> dict[str, str]:
    """Parse a ``Cookie`` header value into a name->value dict."""
    cookies: dict[str, str] = {}
    for pair in cookie_value.split(';'):
        pair = pair.strip()
        if not pair or '=' not in pair:
            continue
        name, _, value = pair.partition('=')
        cookies[name.strip()] = value.strip()
    return cookies


def parse_raw_request(path: str) -> RawRequest:
    """Parse a raw HTTP request file and locate the JWT within it (Req 67.1).

    Populates method/url/headers/cookies/body and locates the JWT
    (Authorization: Bearer, a cookie value, or a body field). Raises a
    descriptive ``ValueError`` NAMING ``path`` when the file cannot be read or
    parsed, or contains no locatable JWT — raised BEFORE any request would be
    issued (Req 67.2).

    Args:
        path: Filesystem path to the Raw_Request_Input file.

    Returns:
        A populated :class:`RawRequest`.

    Raises:
        ValueError: If the file cannot be read/parsed or contains no JWT
            (message names ``path``).
    """
    try:
        with open(path, encoding='utf-8') as fh:
            raw = fh.read()
    except Exception as exc:
        raise ValueError(f"Could not read raw request file '{path}': {exc}") from exc

    if not raw.strip():
        raise ValueError(f"Raw request file '{path}' is empty")

    # Normalize line endings and split headers from the body on the first blank line.
    normalized = raw.replace('\r\n', '\n')
    if '\n\n' in normalized:
        header_block, body = normalized.split('\n\n', 1)
        body = body if body != '' else None
    else:
        header_block, body = normalized, None

    header_lines = [ln for ln in header_block.split('\n') if ln.strip()]
    if not header_lines:
        raise ValueError(f"Raw request file '{path}' has no request line")

    # Request line: METHOD PATH [HTTP/VERSION]
    request_line_parts = header_lines[0].split()
    if len(request_line_parts) < 2:
        raise ValueError(
            f"Raw request file '{path}' has a malformed request line: "
            f"{header_lines[0]!r}"
        )
    method = request_line_parts[0]
    request_target = request_line_parts[1]

    headers: dict[str, str] = {}
    for line in header_lines[1:]:
        if ':' not in line:
            continue
        name, _, value = line.partition(':')
        headers[name.strip()] = value.strip()

    # Build a best-effort URL from the Host header and request target.
    if request_target.lower().startswith(('http://', 'https://')):
        url = request_target
    else:
        host = ''
        for name, value in headers.items():
            if name.lower() == 'host':
                host = value
                break
        url = f"http://{host}{request_target}" if host else request_target

    cookies: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() == 'cookie':
            cookies = _parse_cookie_header(value)
            break

    token = _locate_jwt(headers, cookies, body)
    if not token:
        raise ValueError(
            f"Raw request file '{path}' contains no locatable JWT token"
        )

    return RawRequest(
        method=method,
        url=url,
        headers=headers,
        cookies=cookies,
        body=body,
        token=token,
    )


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


# Per-section colours for JWT visualisation. Mirrors the jwt.io convention so
# each segment is instantly recognisable: header=red, payload=magenta,
# signature=cyan. Colours are applied via ``click.style`` which degrades
# gracefully to plain text when the output is not a TTY.
JWT_HEADER_COLOR = 'red'
JWT_PAYLOAD_COLOR = 'magenta'
JWT_SIGNATURE_COLOR = 'cyan'


def colorize_jwt(decoded_jwt: dict[str, Any]) -> str:
    """Return the raw token with each segment coloured by section.

    The header, payload, and signature segments are styled in their section
    colours (with the separating dots left uncoloured) so the three parts of the
    token can be told apart at a glance.
    """
    header_seg = click.style(decoded_jwt.get('raw_header', ''), fg=JWT_HEADER_COLOR, bold=True)
    payload_seg = click.style(decoded_jwt.get('raw_payload', ''), fg=JWT_PAYLOAD_COLOR, bold=True)
    signature_seg = click.style(decoded_jwt.get('raw_signature', ''), fg=JWT_SIGNATURE_COLOR, bold=True)
    return f"{header_seg}.{payload_seg}.{signature_seg}"


def print_jwt_info(decoded_jwt: dict[str, Any]) -> None:
    """Pretty print JWT information with per-section colours."""
    click.echo("\n" + "="*60)
    click.echo("JWT Token Analysis")
    click.echo("="*60)

    # Colour-coded raw token so each section is visually distinguishable.
    click.echo("\n🎫 TOKEN (colour-coded by section):")
    click.echo("-" * 20)
    click.echo(f"  {colorize_jwt(decoded_jwt)}")
    click.echo("  " + click.style("■ header", fg=JWT_HEADER_COLOR, bold=True)
               + "  " + click.style("■ payload", fg=JWT_PAYLOAD_COLOR, bold=True)
               + "  " + click.style("■ signature", fg=JWT_SIGNATURE_COLOR, bold=True))

    # Header
    click.echo("\n" + click.style("📋 HEADER:", fg=JWT_HEADER_COLOR, bold=True))
    click.echo(click.style("-" * 20, fg=JWT_HEADER_COLOR))
    for key, value in decoded_jwt['header'].items():
        click.echo("  " + click.style(f"{key}: {value}", fg=JWT_HEADER_COLOR))

    # Payload
    click.echo("\n" + click.style("🔐 PAYLOAD:", fg=JWT_PAYLOAD_COLOR, bold=True))
    click.echo(click.style("-" * 20, fg=JWT_PAYLOAD_COLOR))
    for key, value in decoded_jwt['payload'].items():
        if key in ['exp', 'iat', 'nbf']:
            # Convert timestamp to readable date
            try:
                import datetime
                readable_date = datetime.datetime.fromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S UTC')
                click.echo("  " + click.style(f"{key}: {value} ({readable_date})", fg=JWT_PAYLOAD_COLOR))
            except Exception:
                click.echo("  " + click.style(f"{key}: {value}", fg=JWT_PAYLOAD_COLOR))
        else:
            click.echo("  " + click.style(f"{key}: {value}", fg=JWT_PAYLOAD_COLOR))

    # Signature info
    click.echo("\n" + click.style("🔏 SIGNATURE:", fg=JWT_SIGNATURE_COLOR, bold=True))
    click.echo(click.style("-" * 20, fg=JWT_SIGNATURE_COLOR))
    click.echo("  " + click.style(f"Algorithm: {decoded_jwt['header'].get('alg', 'Unknown')}", fg=JWT_SIGNATURE_COLOR))
    click.echo("  " + click.style(f"Signature: {decoded_jwt['signature'][:20]}...", fg=JWT_SIGNATURE_COLOR))

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
