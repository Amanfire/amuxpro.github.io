"""Password hashing, JWT creation/verification, license key generation."""
from __future__ import annotations

import secrets
import string
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext

from backend.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ── Passwords ─────────────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ── JWT tokens ────────────────────────────────────────────────────────────────

def create_access_token(user_id: str, extra: dict | None = None) -> tuple[str, int]:
    """Returns (token, expiry_unix_timestamp)."""
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {"sub": user_id, "exp": expire, "type": "access"}
    if extra:
        payload.update(extra)
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return token, int(expire.timestamp())


def create_refresh_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    payload = {"sub": user_id, "exp": expire, "type": "refresh",
               "jti": secrets.token_hex(16)}
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str, expected_type: str = "access") -> str | None:
    """Returns user_id or None if invalid/expired."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET,
                             algorithms=[settings.JWT_ALGORITHM])
        if payload.get("type") != expected_type:
            return None
        return payload.get("sub")
    except JWTError:
        return None


# ── License key generation ────────────────────────────────────────────────────

_CHARS = string.ascii_uppercase + string.digits
_CHARS = _CHARS.replace("O", "").replace("0", "").replace("I", "").replace("1", "")


def generate_license_key() -> str:
    """Generate a cryptographically secure AMUX-PRO-XXXX-XXXX-XXXX key."""
    groups = ["".join(secrets.choice(_CHARS) for _ in range(4)) for _ in range(3)]
    return f"AMUX-PRO-{'-'.join(groups)}"


def hash_license_key(key: str) -> str:
    """Store only the hash of a license key, never the plaintext."""
    import hashlib
    return hashlib.sha256(key.strip().upper().encode()).hexdigest()


# ── Password reset tokens ─────────────────────────────────────────────────────

def generate_reset_token() -> str:
    return secrets.token_urlsafe(32)
