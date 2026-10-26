from __future__ import annotations

import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import jwt

ACCESS_TTL_MIN = 15
REFRESH_TTL_DAYS = 30


def _secret() -> str:
    return os.getenv("VULN_AGENT_JWT_SECRET") or os.getenv("JWT_SECRET") or "dev-scanlead-change-me"


def create_access_token(user: Dict[str, Any]) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user["id"],
        "email": user.get("email"),
        "name": user.get("name"),
        "plan": user.get("plan") or "free",
        "typ": "access",
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TTL_MIN),
    }
    return jwt.encode(payload, _secret(), algorithm="HS256")


def create_refresh_token(user_id: str) -> tuple[str, str]:
    """Return (token, jti)."""
    now = datetime.now(timezone.utc)
    jti = secrets.token_urlsafe(24)
    payload = {
        "sub": user_id,
        "typ": "refresh",
        "jti": jti,
        "iat": now,
        "exp": now + timedelta(days=REFRESH_TTL_DAYS),
    }
    return jwt.encode(payload, _secret(), algorithm="HS256"), jti


def decode_token(token: str, *, expect_typ: str) -> Dict[str, Any]:
    data = jwt.decode(token, _secret(), algorithms=["HS256"])
    if data.get("typ") != expect_typ:
        raise jwt.InvalidTokenError("wrong token type")
    return data


def public_user(user: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": user.get("id"),
        "email": user.get("email"),
        "name": user.get("name"),
        "picture": user.get("picture"),
        "plan": user.get("plan") or "free",
        "plan_expires_at": user.get("plan_expires_at"),
    }
