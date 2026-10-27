from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from vuln_agent.auth.api_keys import (
    MAX_KEYS_PER_USER,
    append_api_key,
    public_key_meta,
    remove_api_key,
)
from vuln_agent.auth.deps import require_user
from vuln_agent.auth.quotas import FREE_MCP_SCAN_LIMIT

router = APIRouter(prefix="/v1/me/api-keys", tags=["api-keys"])


class CreateKeyBody(BaseModel):
    name: str = Field(default="", max_length=64)


@router.get("")
async def list_api_keys(
    user: Dict[str, Any] = Depends(require_user),
) -> Dict[str, Any]:
    keys = [public_key_meta(k) for k in (user.get("api_keys") or [])]
    return {
        "keys": keys,
        "limit": MAX_KEYS_PER_USER,
        "mcp_free_limit": FREE_MCP_SCAN_LIMIT,
    }


@router.post("")
async def create_api_key(
    request: Request,
    body: CreateKeyBody,
    user: Dict[str, Any] = Depends(require_user),
) -> Dict[str, Any]:
    try:
        keys, raw = append_api_key(user, name=body.name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    updated = await request.app.state.users.update(user["id"], api_keys=keys)
    created = keys[-1]
    return {
        "key": public_key_meta(created),
        "api_key": raw,  # shown once
        "keys": [public_key_meta(k) for k in (updated.get("api_keys") or [])],
        "limit": MAX_KEYS_PER_USER,
        "mcp_free_limit": FREE_MCP_SCAN_LIMIT,
    }


@router.delete("/{key_id}")
async def delete_api_key(
    key_id: str,
    request: Request,
    user: Dict[str, Any] = Depends(require_user),
) -> Dict[str, Any]:
    try:
        keys = remove_api_key(user, key_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="api key not found") from exc
    updated = await request.app.state.users.update(user["id"], api_keys=keys)
    return {
        "ok": True,
        "keys": [public_key_meta(k) for k in (updated.get("api_keys") or [])],
        "limit": MAX_KEYS_PER_USER,
        "mcp_free_limit": FREE_MCP_SCAN_LIMIT,
    }
