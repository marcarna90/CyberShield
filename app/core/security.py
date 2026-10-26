"""Password hashing (Argon2id), password policy and JWT access tokens.

References: OWASP ASVS v4.0.3 V2 (Authentication) and V3 (Session Management).
"""

from __future__ import annotations

import secrets
import string
import uuid
from datetime import datetime, timedelta
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import Settings
from app.core.models import utcnow

_hasher = PasswordHasher()  # Argon2id with library defaults (RFC 9106 recommended)
_ISSUER = "cybershield"
_AUDIENCE = "cybershield-api"

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
_COMMON_PASSWORDS = frozenset(
    {
        "password123!",
        "administrator",
        "welcome123!",
        "changeme123!",
        "p@ssw0rd1234",
        "qwerty123456",
        "letmein12345",
    }
)


class TokenError(Exception):
    """Raised when an access token is invalid, expired or revoked."""


def hash_password(password: str) -> str:
    """Hash a password with Argon2id."""
    return _hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """Constant-time verification; never raises on malformed hashes."""
    try:
        return _hasher.verify(hashed, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(hashed: str) -> bool:
    try:
        return _hasher.check_needs_rehash(hashed)
    except InvalidHashError:
        return True


def password_policy_violations(password: str, username: str | None = None) -> list[str]:
    """Return human readable policy violations (empty list = compliant)."""
    problems: list[str] = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"must be at least {MIN_PASSWORD_LENGTH} characters long")
    if len(password) > MAX_PASSWORD_LENGTH:
        problems.append(f"must be at most {MAX_PASSWORD_LENGTH} characters long")
    if not any(c.islower() for c in password):
        problems.append("must contain a lowercase letter")
    if not any(c.isupper() for c in password):
        problems.append("must contain an uppercase letter")
    if not any(c.isdigit() for c in password):
        problems.append("must contain a digit")
    if not any(c in string.punctuation for c in password):
        problems.append("must contain a special character")
    if username and username.lower() in password.lower():
        problems.append("must not contain the username")
    if password.lower() in _COMMON_PASSWORDS:
        problems.append("is too common")
    return problems


def generate_password(length: int = 24) -> str:
    """Generate a random password that satisfies :func:`password_policy_violations`."""
    if length < MIN_PASSWORD_LENGTH:
        raise ValueError("length too small")
    alphabet = string.ascii_letters + string.digits + "!@#%^*-_=+"
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        if not password_policy_violations(candidate):
            return candidate


def create_access_token(
    settings: Settings, subject: str, role: str, expires_minutes: int | None = None
) -> tuple[str, datetime, str]:
    """Create a signed JWT. Returns ``(token, expires_at, jti)``."""
    now = utcnow()
    expires_at = now + timedelta(minutes=expires_minutes or settings.access_token_expire_minutes)
    jti = uuid.uuid4().hex
    claims = {
        "sub": subject,
        "role": role,
        "iat": now,
        "nbf": now,
        "exp": expires_at,
        "jti": jti,
        "iss": _ISSUER,
        "aud": _AUDIENCE,
    }
    token = jwt.encode(claims, settings.get_secret_key(), algorithm=settings.jwt_algorithm)
    return token, expires_at, jti


def decode_access_token(settings: Settings, token: str) -> dict[str, Any]:
    """Validate signature, expiry, issuer and audience. Raises :class:`TokenError`."""
    try:
        claims = jwt.decode(
            token,
            settings.get_secret_key(),
            algorithms=[settings.jwt_algorithm],  # pinned: prevents alg confusion / "none"
            issuer=_ISSUER,
            audience=_AUDIENCE,
            options={"require": ["exp", "iat", "sub", "jti", "role"]},
        )
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc
    return claims
