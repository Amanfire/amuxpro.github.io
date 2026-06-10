"""SQLAlchemy ORM models for the Amux backend."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (Boolean, Column, DateTime, ForeignKey,
                        Integer, String, Text)
from sqlalchemy.orm import relationship

from backend.core.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id             = Column(String, primary_key=True, default=_uuid)
    email          = Column(String, unique=True, nullable=False, index=True)
    display_name   = Column(String, default="")
    password_hash  = Column(String, nullable=False)
    is_verified    = Column(Boolean, default=False)
    is_suspended   = Column(Boolean, default=False)
    created_at     = Column(DateTime(timezone=True), default=_now)

    license        = relationship("License", back_populates="user",
                                  uselist=False, cascade="all, delete-orphan")
    devices        = relationship("Device", back_populates="user",
                                  cascade="all, delete-orphan")
    reset_tokens   = relationship("PasswordResetToken", back_populates="user",
                                  cascade="all, delete-orphan")
    cloud_settings = relationship("CloudSettings", back_populates="user",
                                  uselist=False, cascade="all, delete-orphan")


class License(Base):
    __tablename__ = "licenses"

    id           = Column(String, primary_key=True, default=_uuid)
    user_id      = Column(String, ForeignKey("users.id"), nullable=True, index=True)
    key_hash     = Column(String, unique=True, nullable=False, index=True)
    # Store a masked display version: AMUX-PRO-A3F1-****-****
    key_masked   = Column(String, nullable=False)
    expiry       = Column(String, default="lifetime")   # ISO date or "lifetime"
    is_revoked   = Column(Boolean, default=False)
    created_at   = Column(DateTime(timezone=True), default=_now)
    activated_at = Column(DateTime(timezone=True), nullable=True)

    user         = relationship("User", back_populates="license")


class Device(Base):
    __tablename__ = "devices"

    id           = Column(String, primary_key=True, default=_uuid)
    user_id      = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    device_id    = Column(String, nullable=False, index=True)   # hardware fingerprint
    device_name  = Column(String, default="Unknown Device")
    platform     = Column(String, default="")
    activated_at = Column(DateTime(timezone=True), default=_now)
    is_active    = Column(Boolean, default=True)

    user         = relationship("User", back_populates="devices")


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id         = Column(String, primary_key=True, default=_uuid)
    user_id    = Column(String, ForeignKey("users.id"), nullable=False)
    token_hash = Column(String, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used       = Column(Boolean, default=False)

    user       = relationship("User", back_populates="reset_tokens")


class CloudSettings(Base):
    __tablename__ = "cloud_settings"

    id         = Column(String, primary_key=True, default=_uuid)
    user_id    = Column(String, ForeignKey("users.id"), nullable=False, unique=True)
    data       = Column(Text, default="{}")
    updated_at = Column(DateTime(timezone=True), default=_now, onupdate=_now)

    user       = relationship("User", back_populates="cloud_settings")
