"""Auth router: register, login, refresh, logout, password reset, email verify."""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.deps import get_current_user
from backend.core.email import send_password_reset_email, send_verification_email
from backend.core.security import (
    create_access_token, create_refresh_token, decode_token,
    hash_password, verify_password, generate_reset_token,
)
from backend.models.db_models import License, PasswordResetToken, User

router = APIRouter(prefix="/auth", tags=["auth"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email:        EmailStr
    password:     str
    display_name: str = ""
    device_id:    str = ""
    device_name:  str = ""


class LoginRequest(BaseModel):
    email:       EmailStr
    password:    str
    device_id:   str = ""
    device_name: str = ""
    platform:    str = ""


class RefreshRequest(BaseModel):
    refresh_token: str
    device_id:     str = ""


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token:        str
    new_password: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(status_code=400, detail="Email already registered.")
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")

    user = User(
        email         = req.email,
        display_name  = req.display_name or req.email.split("@")[0],
        password_hash = hash_password(req.password),
        is_verified   = False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Send verification email (best-effort)
    send_verification_email(req.email, token=create_refresh_token(user.id))

    return {"success": True, "message": "Account created! Please verify your email, then log in."}


@router.post("/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if user.is_suspended:
        raise HTTPException(status_code=403, detail="Account suspended. Contact support.")

    # Gather license & device info
    lic = user.license
    is_pro        = lic is not None and not lic.is_revoked
    license_key   = lic.key_masked if lic else ""
    license_expiry= lic.expiry if lic else ""
    devices_used  = sum(1 for d in user.devices if d.is_active)

    access_token, expiry = create_access_token(user.id)
    refresh_token        = create_refresh_token(user.id)

    return {
        "success":       True,
        "user_id":       user.id,
        "display_name":  user.display_name,
        "access_token":  access_token,
        "refresh_token": refresh_token,
        "token_expiry":  expiry,
        "is_pro":        is_pro,
        "license_key":   license_key,
        "license_expiry":license_expiry,
        "devices_used":  devices_used,
    }


@router.post("/refresh")
def refresh_token(req: RefreshRequest, db: Session = Depends(get_db)):
    user_id = decode_token(req.refresh_token, expected_type="refresh")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token.")
    user = db.query(User).filter(User.id == user_id).first()
    if not user or user.is_suspended:
        raise HTTPException(status_code=401, detail="User not found or suspended.")

    access_token, expiry = create_access_token(user_id)
    new_refresh          = create_refresh_token(user_id)
    return {
        "success":       True,
        "access_token":  access_token,
        "refresh_token": new_refresh,
        "token_expiry":  expiry,
    }


@router.post("/logout")
def logout(current_user: User = Depends(get_current_user)):
    # Stateless JWT — client discards token. For full revocation, add a denylist.
    return {"success": True}


@router.post("/password-reset")
def request_password_reset(req: PasswordResetRequest, db: Session = Depends(get_db)):
    # Always return success to prevent email enumeration
    user = db.query(User).filter(User.email == req.email).first()
    if user:
        raw_token    = generate_reset_token()
        token_hash   = hashlib.sha256(raw_token.encode()).hexdigest()
        expires_at   = datetime.now(timezone.utc) + timedelta(hours=1)
        reset_entry  = PasswordResetToken(
            user_id    = user.id,
            token_hash = token_hash,
            expires_at = expires_at,
        )
        db.add(reset_entry)
        db.commit()
        send_password_reset_email(req.email, raw_token)
    return {"success": True, "message": "If that email exists, a reset link has been sent."}


@router.post("/password-reset/confirm")
def confirm_password_reset(req: PasswordResetConfirm, db: Session = Depends(get_db)):
    if len(req.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")

    token_hash = hashlib.sha256(req.token.encode()).hexdigest()
    entry = db.query(PasswordResetToken).filter(
        PasswordResetToken.token_hash == token_hash,
        PasswordResetToken.used == False,
    ).first()

    if not entry:
        raise HTTPException(status_code=400, detail="Invalid or already-used reset token.")
    if entry.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Reset token has expired. Please request a new one.")

    user = db.query(User).filter(User.id == entry.user_id).first()
    user.password_hash = hash_password(req.new_password)
    entry.used = True
    db.commit()
    return {"success": True, "message": "Password updated. You can now log in."}


@router.get("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    user_id = decode_token(token, expected_type="refresh")
    if not user_id:
        raise HTTPException(status_code=400, detail="Invalid or expired verification link.")
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        user.is_verified = True
        db.commit()
    return {"success": True, "message": "Email verified. You can now log in."}
