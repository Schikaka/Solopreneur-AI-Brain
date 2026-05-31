import base64
import hashlib
import hmac
import json
import os
import time
import uuid

from dotenv import load_dotenv


load_dotenv()

try:
    import jwt as pyjwt
except ImportError:  # pragma: no cover - exercised when PyJWT is not installed locally.
    pyjwt = None


TOKEN_ISSUER = "narrativeai-client"
TOKEN_AUDIENCE = "narrativeai-gatekeeper"
DEFAULT_TOKEN_TTL_SECONDS = 60
DEFAULT_JWT_SECRET = "development-only-gatekeeper-jwt-secret-change-me"


class TokenError(ValueError):
    pass


def get_jwt_secret():
    secret = os.getenv("GATEKEEPER_JWT_SECRET") or os.getenv("JWT_SECRET") or os.getenv("SECRET_KEY")
    if secret:
        return secret

    if os.getenv("APP_ENV") == "production":
        raise RuntimeError("GATEKEEPER_JWT_SECRET must be set in production.")

    return DEFAULT_JWT_SECRET


def canonical_json(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def payload_hash(payload):
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def gatekeeper_payload(stats, license_key):
    return {
        "license_key": str(license_key or "").strip(),
        "stats": stats,
    }


def create_gatekeeper_jwt(payload, secret=None, ttl_seconds=DEFAULT_TOKEN_TTL_SECONDS):
    now = int(time.time())
    claims = {
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
        "iat": now,
        "nbf": now - 1,
        "exp": now + int(ttl_seconds),
        "jti": uuid.uuid4().hex,
        "payload_hash": payload_hash(payload),
    }
    signing_secret = secret or get_jwt_secret()

    if pyjwt is not None:
        token = pyjwt.encode(claims, signing_secret, algorithm="HS256")
        return token.decode("utf-8") if isinstance(token, bytes) else token

    return _encode_hs256(claims, signing_secret)


def verify_gatekeeper_jwt(token, payload, secret=None, leeway_seconds=5):
    if not token:
        raise TokenError("Missing bearer token.")

    signing_secret = secret or get_jwt_secret()
    if pyjwt is not None:
        try:
            claims = pyjwt.decode(
                token,
                signing_secret,
                algorithms=["HS256"],
                audience=TOKEN_AUDIENCE,
                issuer=TOKEN_ISSUER,
                leeway=leeway_seconds,
            )
        except Exception as exc:  # PyJWT raises a family of decode exceptions.
            raise TokenError("Invalid or expired bearer token.") from exc
    else:
        claims = _decode_hs256(token, signing_secret, leeway_seconds)

    expected_hash = payload_hash(payload)
    if not hmac.compare_digest(str(claims.get("payload_hash", "")), expected_hash):
        raise TokenError("Bearer token payload hash mismatch.")

    return claims


def authorization_header(payload):
    return f"Bearer {create_gatekeeper_jwt(payload)}"


def _b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(value):
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(f"{value}{padding}".encode("ascii"))


def _encode_hs256(claims, secret):
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = ".".join(
        [
            _b64url_encode(canonical_json(header).encode("utf-8")),
            _b64url_encode(canonical_json(claims).encode("utf-8")),
        ]
    )
    signature = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url_encode(signature)}"


def _decode_hs256(token, secret, leeway_seconds):
    try:
        encoded_header, encoded_claims, encoded_signature = token.split(".")
    except ValueError as exc:
        raise TokenError("Malformed bearer token.") from exc

    signing_input = f"{encoded_header}.{encoded_claims}"
    expected_signature = hmac.new(
        secret.encode("utf-8"),
        signing_input.encode("ascii"),
        hashlib.sha256,
    ).digest()
    supplied_signature = _b64url_decode(encoded_signature)
    if not hmac.compare_digest(expected_signature, supplied_signature):
        raise TokenError("Invalid bearer token signature.")

    try:
        header = json.loads(_b64url_decode(encoded_header))
        claims = json.loads(_b64url_decode(encoded_claims))
    except (json.JSONDecodeError, ValueError) as exc:
        raise TokenError("Malformed bearer token.") from exc

    if header.get("alg") != "HS256":
        raise TokenError("Unsupported bearer token algorithm.")

    now = int(time.time())
    leeway = int(leeway_seconds)
    if claims.get("iss") != TOKEN_ISSUER or claims.get("aud") != TOKEN_AUDIENCE:
        raise TokenError("Invalid bearer token issuer or audience.")
    if int(claims.get("nbf", 0)) > now + leeway:
        raise TokenError("Bearer token is not active yet.")
    if int(claims.get("exp", 0)) < now - leeway:
        raise TokenError("Bearer token has expired.")

    return claims
