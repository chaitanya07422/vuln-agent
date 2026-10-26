from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt

from vuln_agent.auth.tokens import decode_token

_bearer = HTTPBearer(auto_error=False)


async def optional_user(
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> Optional[Dict[str, Any]]:
    if not creds or not creds.credentials:
        return None
    try:
        payload = decode_token(creds.credentials, expect_typ="access")
    except jwt.PyJWTError:
        return None
    users = request.app.state.users
    user = await users.get(payload["sub"])
    return user


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
