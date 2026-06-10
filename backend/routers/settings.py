"""Settings cloud backup router."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.deps import get_current_user
from backend.models.db_models import CloudSettings, User

router = APIRouter(prefix="/settings", tags=["settings"])


class BackupRequest(BaseModel):
    settings: dict


def _require_pro(user: User) -> None:
    lic = user.license
    if not lic or lic.is_revoked:
        raise HTTPException(status_code=403, detail="Cloud backup requires an active Pro license.")


@router.post("/backup")
def push_settings(
    req: BackupRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_pro(current_user)
    row = current_user.cloud_settings
    if row:
        row.data = json.dumps(req.settings, ensure_ascii=False)
    else:
        row = CloudSettings(user_id=current_user.id,
                            data=json.dumps(req.settings, ensure_ascii=False))
        db.add(row)
    db.commit()
    return {"success": True}


@router.get("/backup")
def pull_settings(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_pro(current_user)
    row = current_user.cloud_settings
    if not row:
        return {"success": True, "settings": {}}
    try:
        data = json.loads(row.data)
    except Exception:
        data = {}
    return {"success": True, "settings": data}
