# Feature: owasp-auth-modules-hardening, Property 38: Algorithm-confusion key-format variation attempts every representation of the source public key
"""
Property-Based Tests for algorithm-confusion public-key representation coverage.

**Feature: owasp-auth-modules-hardening, Property 38: Algorithm-confusion
key-format variation attempts every representation of the source public key**

Property 38 (from design.md):
    For all source public keys, ``_public_key_variants`` covers each derivable
    representation (``pem_with_newline``, ``pem_without_newline``, ``der``,
    ``x5c_cert_der``) and every attempted representation preserves the token
    header and payload, varying only the key bytes and the ``alg`` header.

These tests drive the real ``_public_key_variants`` helper in
``utils.jwt_utils``. Because generating RSA/EC keys and X.509 certificates is
expensive, a small handful of source materials (raw RSA/EC public keys and
self-signed RSA/EC certificates) are pre-generated once at module load and
sampled from with Hypothesis rather than regenerated per example.

The properties asserted are:
  1. For a raw public key, the derivable representations
     {pem_with_newline, pem_without_newline, der} are all present.
  2. For certificate material, ``x5c_cert_der`` is additionally present.
  3. Every returned variant's key bytes load back to the SAME underlying public
     key (only the byte encoding differs) — this demonstrates "varying only the
     key bytes" while the header/payload are unaffected by the representation.
  4. Unparseable/garbage input returns an empty list without raising.

Requirements covered: 60.1, 60.2, 69.6.

**Validates: Requirements 60.1, 60.2, 69.6**
"""

import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from hypothesis import given, settings, strategies as st

from utils.jwt_utils import (
    _public_key_variants,
    generate_rsa_keypair,
    generate_ec_keypair,
)


# ---------------------------------------------------------------------------
# Pre-generated source key material (built once at module load).
#
# Each entry is a tuple:
#   (label, material, is_certificate, expected_spki_der)
# where ``material`` is the source passed to ``_public_key_variants`` (a raw
# public key or an X.509 certificate, as str or bytes), ``is_certificate``
# marks whether the ``x5c_cert_der`` representation should be present, and
# ``expected_spki_der`` is the canonical DER SubjectPublicKeyInfo of the
# underlying public key used to check representation equivalence.
# ---------------------------------------------------------------------------

# The three representations that must always be derivable from a raw public key.
RAW_REPRESENTATIONS = {"pem_with_newline", "pem_without_newline", "der"}


def _spki_der(public_key) -> bytes:
    """Canonical DER SubjectPublicKeyInfo bytes for a public key."""
    return public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def _self_signed_cert(private_key) -> bytes:
    """Build a minimal self-signed X.509 certificate (PEM bytes)."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"apileaks-test"),
    ])
    now = datetime.datetime(2020, 1, 1)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.PEM)


def _build_materials():
    materials = []

    # --- Raw RSA public key (as PEM str) ---
    rsa_priv_pem, rsa_pub_pem = generate_rsa_keypair(bits=2048)
    rsa_pub = serialization.load_pem_public_key(rsa_pub_pem.encode("utf-8"))
    materials.append(("rsa_pub_pem_str", rsa_pub_pem, False, _spki_der(rsa_pub)))
    # Same RSA public key as raw DER bytes.
    rsa_pub_der = rsa_pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    materials.append(("rsa_pub_der_bytes", rsa_pub_der, False, _spki_der(rsa_pub)))

    # --- Raw EC public key (as PEM str) ---
    ec_priv_pem, ec_pub_pem = generate_ec_keypair(curve="ES256")
    ec_pub = serialization.load_pem_public_key(ec_pub_pem.encode("utf-8"))
    materials.append(("ec_pub_pem_str", ec_pub_pem, False, _spki_der(ec_pub)))

    # --- Self-signed RSA certificate (PEM bytes) ---
    rsa_private = serialization.load_pem_private_key(
        rsa_priv_pem.encode("utf-8"), password=None
    )
    rsa_cert_pem = _self_signed_cert(rsa_private)
    materials.append(("rsa_cert_pem", rsa_cert_pem, True, _spki_der(rsa_pub)))

    # --- Self-signed EC certificate (PEM bytes) ---
    ec_private = serialization.load_pem_private_key(
        ec_priv_pem.encode("utf-8"), password=None
    )
    ec_cert_pem = _self_signed_cert(ec_private)
    materials.append(("ec_cert_pem", ec_cert_pem, True, _spki_der(ec_pub)))

    return materials


MATERIALS = _build_materials()

key_materials = st.sampled_from(MATERIALS)


def _load_variant_public_key(name: str, key_bytes: bytes):
    """Load the underlying public key from a variant's key bytes."""
    if name == "x5c_cert_der":
        cert = x509.load_der_x509_certificate(key_bytes)
        return cert.public_key()
    # PEM or DER SubjectPublicKeyInfo.
    for loader in (
        serialization.load_pem_public_key,
        serialization.load_der_public_key,
    ):
        try:
            return loader(key_bytes)
        except Exception:
            continue
    raise AssertionError(f"variant {name!r} key bytes could not be loaded")


# ---------------------------------------------------------------------------
# Property 38: representation coverage + key-preservation
# ---------------------------------------------------------------------------


@settings(max_examples=200)
@given(entry=key_materials)
def test_public_key_variants_cover_every_representation(entry):
    """Every derivable representation is present and preserves the key.

    **Validates: Requirements 60.1, 60.2, 69.6**
    """
    label, material, is_certificate, expected_spki_der = entry

    variants = _public_key_variants(material)
    names = {name for name, _ in variants}

    # (1) The three raw-key representations are always present.
    assert RAW_REPRESENTATIONS.issubset(names), (
        f"{label}: missing raw representations, got {names}"
    )

    # (2) Certificate material additionally yields the x5c representation.
    if is_certificate:
        assert "x5c_cert_der" in names, (
            f"{label}: certificate material must yield x5c_cert_der, got {names}"
        )
    else:
        assert "x5c_cert_der" not in names, (
            f"{label}: raw key must not yield x5c_cert_der, got {names}"
        )

    # (3) Every variant's key bytes load back to the SAME underlying public key;
    #     only the byte encoding differs across representations.
    for name, key_bytes in variants:
        assert isinstance(key_bytes, (bytes, bytearray)) and len(key_bytes) > 0
        loaded = _load_variant_public_key(name, key_bytes)
        assert _spki_der(loaded) == expected_spki_der, (
            f"{label}/{name}: representation changed the underlying public key"
        )


@settings(max_examples=200)
@given(entry=key_materials)
def test_pem_variants_differ_only_by_trailing_newline(entry):
    """pem_with_newline and pem_without_newline differ only by the trailing \\n.

    **Validates: Requirements 60.1, 60.2**
    """
    _label, material, _is_cert, _spki = entry
    variants = dict(_public_key_variants(material))

    with_nl = variants["pem_with_newline"]
    without_nl = variants["pem_without_newline"]

    assert with_nl.endswith(b"\n")
    assert not without_nl.endswith(b"\n")
    assert with_nl[:-1] == without_nl


# ---------------------------------------------------------------------------
# Property 38 (part 4): unparseable input yields an empty list, never raises
# ---------------------------------------------------------------------------

# Plain ASCII text that is never valid PEM/DER key or certificate material.
garbage = st.one_of(
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz 0123456789", max_size=80),
    st.binary(max_size=80).map(lambda b: b"not-a-key-" + b),
)


@settings(max_examples=200)
@given(blob=garbage)
def test_unparseable_input_returns_empty_list(blob):
    """Garbage/unparseable input returns an empty list without raising.

    **Validates: Requirements 60.1, 60.2, 69.6**
    """
    result = _public_key_variants(blob)
    assert result == []
