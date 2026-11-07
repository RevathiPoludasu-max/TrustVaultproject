"""
TrustVault JWT Handler
=======================
Handles JWT creation and verification for access tokens.

SECURITY DESIGN:
- Tokens are signed with HMAC-SHA256.
- Each token carries a session_id (sid) claim that is verified against
  the live sessions table on every request (see authorization.py).
- Tokens DO NOT carry permissions — permissions are always fetched live from DB.
- Tokens DO NOT authorize resource access — they only authenticate identity.

NEVER:
- Use token claims (role, etc.) as the sole authorization proof.
- Skip the live session check in get_current_user.
- Increase token TTL above 60 minutes without security review.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional
import uuid

import jwt
from jwt import DecodeError, ExpiredSignatureError, InvalidTokenError

from app.core.config import settings


def create_access_token(
    subject: str,
    session_id: str,
    role: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Create a signed JWT access token.

    Claims:
        sub: User UUID (string)
        sid: Session UUID (verified against live DB on each request)
        role: User role (informational only — NOT used for authorization decisions)
        iat: Issued at timestamp
        exp: Expiry timestamp
        jti: Unique token ID (for future revocation list support)

    Args:
        subject: User UUID as string.
        session_id: Session UUID as string.
        role: User role value.
        expires_delta: Optional custom expiry. Defaults to JWT_ACCESS_TOKEN_EXPIRE_MINUTES.

    Returns:
        Signed JWT string.
    """
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
        )

    payload: dict[str, Any] = {
        "sub": subject,
        "sid": session_id,
        "role": role,  # Informational — authorization uses live DB, not this claim
        "iat": datetime.now(timezone.utc),
        "exp": expire,
        "jti": str(uuid.uuid4()),
        "iss": settings.APP_NAME,
    }

    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decode and verify a JWT access token.

    Verifies:
        - Signature validity (HMAC-SHA256)
        - Expiry (exp claim)
        - Issuer (iss claim)

    Does NOT verify:
        - User is still active (done in get_current_user via DB query)
        - Session is still valid (done in get_current_user via DB query)
        - User has permission for a specific resource (done in enforce_document_access)

    Args:
        token: Raw JWT string from Authorization header.

    Returns:
        Decoded payload dict.

    Raises:
        ExpiredSignatureError: Token has expired.
        DecodeError: Token signature is invalid.
        InvalidTokenError: Token is malformed.
    """
    return jwt.decode(
        token,
        settings.JWT_SECRET,
        algorithms=[settings.JWT_ALGORITHM],
        options={
            "require": ["sub", "sid", "exp", "iat", "jti"],
            "verify_exp": True,
            "verify_signature": True,
        },
    )
