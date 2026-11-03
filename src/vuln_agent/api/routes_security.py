from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from vuln_agent.auth.deps import optional_user

router = APIRouter(prefix="/v1/admin/security", tags=["admin-security"])


async def require_admin(request: Request, user=Depends(optional_user)) -> dict[str, Any]:
    if not user:
        raise HTTPException(status_code=401, detail="authentication required")
    allowed = {
        item.strip().lower()
        for item in os.getenv("VULN_AGENT_ADMIN_EMAILS", "").split(",")
        if item.strip()
    }
    email = str(user.get("email") or "").strip().lower()
    if not allowed or email not in allowed:
        raise HTTPException(status_code=403, detail="administrator access required")
    return user


class BlockIPBody(BaseModel):
    ip: str
    reason: str = Field(default="manual", max_length=200)
    ttl_seconds: int = Field(default=0, ge=0, le=2_592_000)


@router.get("/events")
async def get_events(
    request: Request,
    limit: int = 100,
    _: dict = Depends(require_admin),
):
    return {"events": await request.app.state.security.recent_events(max(1, min(limit, 500)))}


@router.get("/blocked")
async def get_blocked(
    request: Request,
    _: dict = Depends(require_admin),
):
    return {"blocked": await request.app.state.security.list_blocked()}


@router.post("/block", status_code=200)
async def block_ip(
    body: BlockIPBody,
    request: Request,
    _: dict = Depends(require_admin),
):
    try:
        ip = request.app.state.security.normalize_ip(body.ip)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid IP address") from exc
    await request.app.state.security.block(ip, body.reason, body.ttl_seconds)
    return {"ok": True, "ip": ip, "ttl_seconds": body.ttl_seconds}


@router.delete("/block/{ip}")
async def unblock_ip(
    ip: str,
    request: Request,
    _: dict = Depends(require_admin),
):
    try:
        normalized = request.app.state.security.normalize_ip(ip)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid IP address") from exc
    await request.app.state.security.unblock(normalized)
    return {"ok": True, "ip": normalized, "blocked": False}
