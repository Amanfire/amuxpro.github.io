"""License router: activate, verify, list devices, deactivate, history."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.core.database import get_db
from backend.core.deps import get_current_user
from backend.core.security import hash_license_key
from backend.models.db_models import Device, License, User

router = APIRouter(prefix="/license", tags=["license"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class ActivateRequest(BaseModel):
    license_key: str
    device_id:   str
    device_name: str = "Unknown Device"
    platform:    str = ""


class DeactivateRequest(BaseModel):
    device_id: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _active_device_count(user: User) -> int:
    return sum(1 for d in user.devices if d.is_active)


def _get_device(user: User, device_id: str) -> Device | None:
    return next((d for d in user.devices if d.device_id == device_id and d.is_active), None)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/activate")
def activate_license(
    req: ActivateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    key_hash = hash_license_key(req.license_key)
    lic = db.query(License).filter(License.key_hash == key_hash).first()

    if not lic:
        raise HTTPException(status_code=400,
                            detail="License key not found. Please check the key and try again.")
    if lic.is_revoked:
        raise HTTPException(status_code=400,
                            detail="This license has been revoked. Contact support.")
    if lic.user_id and lic.user_id != current_user.id:
        raise HTTPException(status_code=400,
                            detail="This key is already activated on another account.")

    # Link key to this user if not already
    if not lic.user_id:
        lic.user_id      = current_user.id
        lic.activated_at = datetime.now(timezone.utc)

    # Check device limit
    existing_device = _get_device(current_user, req.device_id)
    if not existing_device:
        active_count = _active_device_count(current_user)
        if active_count >= settings.MAX_DEVICES_PER_LICENSE:
            raise HTTPException(
                status_code=400,
                detail=f"Device limit reached ({active_count}/{settings.MAX_DEVICES_PER_LICENSE}). "
                       "Remove a device from your account dashboard first.",
            )
        new_device = Device(
            user_id     = current_user.id,
            device_id   = req.device_id,
            device_name = req.device_name,
            platform    = req.platform,
            is_active   = True,
        )
        db.add(new_device)

    db.commit()
    db.refresh(current_user)

    return {
        "success":      True,
        "expiry":       lic.expiry,
        "devices_used": _active_device_count(current_user),
    }


@router.get("/verify")
def verify_license(
    device_id: str = "",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    lic = current_user.license
    is_pro   = lic is not None and not lic.is_revoked
    revoked  = lic.is_revoked if lic else False
    expiry   = lic.expiry if lic else ""
    devices  = _active_device_count(current_user)

    return {
        "is_pro":          is_pro,
        "license_expiry":  expiry,
        "devices_used":    devices,
        "revoked":         revoked,
    }


@router.get("/devices")
def list_devices(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    active = [d for d in current_user.devices if d.is_active]
    return {
        "devices": [
            {
                "device_id":    d.device_id,
                "device_name":  d.device_name,
                "platform":     d.platform,
                "activated_at": d.activated_at.isoformat() if d.activated_at else "",
            }
            for d in active
        ]
    }


@router.post("/deactivate")
def deactivate_device(
    req: DeactivateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    device = _get_device(current_user, req.device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found.")
    device.is_active = False
    db.commit()
    return {"success": True}


@router.get("/history")
def activation_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return {
        "history": [
            {
                "device_id":    d.device_id,
                "device_name":  d.device_name,
                "platform":     d.platform,
                "activated_at": d.activated_at.isoformat() if d.activated_at else "",
                "is_active":    d.is_active,
            }
            for d in current_user.devices
        ]
    }
