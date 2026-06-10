"""
Amux Autoclicker Pro — Backend API Server
==========================================
Run locally:   uvicorn backend.main:app --reload
Production:    uvicorn backend.main:app --host 0.0.0.0 --port 8000 --workers 4
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from backend.core.config import settings
from backend.core.database import Base, engine
from backend.routers import admin, auth, license, settings as settings_router

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── Rate limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Amux Autoclicker Pro API",
    version="1.0.0",
    description="Account, license, and settings cloud backup API",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # Restrict to your domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Auto-create tables on startup ────────────────────────────────────────────
@app.on_event("startup")
def create_tables():
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables verified/created.")

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth.router,             prefix="/v1")
app.include_router(license.router,          prefix="/v1")
app.include_router(settings_router.router,  prefix="/v1")
app.include_router(admin.router,            prefix="/v1")

# ── Rate-limited auth endpoints ───────────────────────────────────────────────
@app.middleware("http")
async def rate_limit_auth(request: Request, call_next):
    # Allow FastAPI/slowapi to handle limits via decorators
    return await call_next(request)

# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/health", tags=["health"])
def health():
    return {"status": "ok", "app": settings.APP_NAME}

@app.get("/", tags=["health"])
def root():
    return {"message": f"Welcome to {settings.APP_NAME} API", "docs": "/docs"}
