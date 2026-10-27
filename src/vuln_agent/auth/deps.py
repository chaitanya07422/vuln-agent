from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt

from vuln_agent.auth.api_keys import (
    hash_api_key,
    looks_like_api_key,
    touch_api_key,
    verify_user_api_key,
)
from vuln_agent.auth.tokens import decode_token

_bearer = HTTPBearer(auto_error=False)


async def optional_user(
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> Optional[Dict[str, Any]]:
    request.state.auth_via = None
    if not creds or not creds.credentials:
        return None
    token = creds.credentials
    users = request.app.state.users

    # Personal API keys (MCP / CLI): sl_live_…
    if looks_like_api_key(token):
        key_hash = hash_api_key(token)
        user = await users.find_by_api_key_hash(key_hash)
        if not user:
            return None
        entry = verify_user_api_key(user, token)
        if not entry:
            return None
        # Best-effort last_used stamp (ignore races)
        try:
            keys = touch_api_key(list(user.get("api_keys") or []), entry["id"])
            user = await users.update(user["id"], api_keys=keys)
        except Exception:
            pass
        request.state.auth_via = "api_key"
        return user

    try:
        payload = decode_token(token, expect_typ="access")
    except jwt.PyJWTError:
        return None
    user = await users.get(payload["sub"])
    if user:
        request.state.auth_via = "jwt"
    return user


def request_scan_source(request: Request) -> str:
    """API key → mcp bucket; JWT / anonymous → web bucket."""
    from vuln_agent.auth.quotas import SCAN_SOURCE_MCP, SCAN_SOURCE_WEB

    if getattr(request.state, "auth_via", None) == "api_key":
        return SCAN_SOURCE_MCP
    return SCAN_SOURCE_WEB


async def require_user(
    user: Optional[Dict[str, Any]] = Depends(optional_user),
) -> Dict[str, Any]:
    if not user:
        raise HTTPException(status_code=401, detail="authentication required")
    return user


def effective_plan(user: Optional[Dict[str, Any]]) -> str:
    if not user:
        return "anon"
    plan = user.get("plan") or "free"
    expires = user.get("plan_expires_at")
    if plan == "pro" and expires:
        from datetime import datetime, timezone

        try:
            exp = datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
            if exp < datetime.now(timezone.utc):
                return "free"
        except ValueError:
            pass
    return plan
