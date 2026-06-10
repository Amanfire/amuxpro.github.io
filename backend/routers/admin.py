"""Admin endpoints: generate license keys, revoke keys, suspend users."""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.security import generate_license_key, hash_license_key
from backend.models.db_models import License, User

router = APIRouter(prefix="/admin", tags=["admin"])

ADMIN_KEY = os.getenv("ADMIN_API_KEY", "change-me-admin-key")


def _require_admin(x_admin_key: str = Header(default="")):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Invalid admin key.")


class GenerateKeysRequest(BaseModel):
    count:  int = 1
    expiry: str = "lifetime"   # "lifetime" or ISO date string


class RevokeRequest(BaseModel):
    license_key: str
    reason:      str = ""


class SuspendRequest(BaseModel):
    email:  str
    suspend: bool = True


@router.post("/generate-keys", dependencies=[Depends(_require_admin)])
def generate_keys(req: GenerateKeysRequest, db: Session = Depends(get_db)):
    """Generate N new license keys and store hashes in DB."""
    if req.count < 1 or req.count > 500:
        raise HTTPException(status_code=400, detail="count must be 1–500.")
    keys = []
    for _ in range(req.count):
        key  = generate_license_key()
        # Masked display version: AMUX-PRO-A3F1-****-****
        parts   = key.split("-")
        masked  = f"{parts[0]}-{parts[1]}-{parts[2]}-****-****"
        lic = License(
            key_hash   = hash_license_key(key),
            key_masked = masked,
            expiry     = req.expiry,
            is_revoked = False,
        )
        db.add(lic)
        keys.append(key)
    db.commit()
    return {"success": True, "keys": keys}


@router.post("/revoke", dependencies=[Depends(_require_admin)])
def revoke_key(req: RevokeRequest, db: Session = Depends(get_db)):
    key_hash = hash_license_key(req.license_key)
    lic = db.query(License).filter(License.key_hash == key_hash).first()
    if not lic:
        raise HTTPException(status_code=404, detail="License key not found.")
    lic.is_revoked = True
    db.commit()
    return {"success": True, "message": f"License revoked. Reason: {req.reason}"}


@router.post("/suspend-user", dependencies=[Depends(_require_admin)])
def suspend_user(req: SuspendRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    user.is_suspended = req.suspend
    db.commit()
    action = "suspended" if req.suspend else "unsuspended"
    return {"success": True, "message": f"User {req.email} {action}."}


@router.get("/stats", dependencies=[Depends(_require_admin)])
def admin_stats(db: Session = Depends(get_db)):
    total_users    = db.query(User).count()
    pro_users      = db.query(License).filter(License.is_revoked == False,
                                               License.user_id != None).count()
    total_keys     = db.query(License).count()
    revoked_keys   = db.query(License).filter(License.is_revoked == True).count()
    return {
        "total_users":  total_users,
        "pro_users":    pro_users,
        "total_keys":   total_keys,
        "revoked_keys": revoked_keys,
        "free_users":   total_users - pro_users,
    }
