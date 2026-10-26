from __future__ import annotations

import os
import secrets
from typing import Any, Dict, Optional
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
import jwt

from vuln_agent.auth import google_oauth
from vuln_agent.auth.deps import require_user
from vuln_agent.auth.tokens import (
    REFRESH_TTL_DAYS,
    create_access_token,
    create_refresh_token,
    decode_token,
    public_user,
)

router = APIRouter(prefix="/v1/auth", tags=["auth"])

REFRESH_COOKIE = "scanlead_refresh"


def _cookie_secure() -> bool:
    return os.getenv("VULN_AGENT_COOKIE_SECURE", "true").lower() in ("1", "true", "yes")


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=token,
        httponly=True,
        secure=_cookie_secure(),
        samesite="lax",
        max_age=REFRESH_TTL_DAYS * 86400,
        path="/",
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(key=REFRESH_COOKIE, path="/")


@router.get("/google")
async def google_start(request: Request) -> RedirectResponse:
    if not google_oauth.google_configured():
        raise HTTPException(status_code=503, detail="Google auth not configured")
    state = secrets.token_urlsafe(24)
    # stash state briefly on app (best-effort); production can use Redis
    store: dict = getattr(request.app.state, "oauth_states", {})
    store[state] = True
    request.app.state.oauth_states = store
    return RedirectResponse(google_oauth.authorize_url(state=state), status_code=302)


@router.get("/google/callback")
async def google_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
) -> RedirectResponse:
    front = google_oauth.frontend_origin()
    if error:
        return RedirectResponse(f"{front}/auth/callback?error={quote(error)}", status_code=302)
    if not code:
        return RedirectResponse(f"{front}/auth/callback?error=missing_code", status_code=302)
    states: dict = getattr(request.app.state, "oauth_states", {})
    if state and state in states:
        states.pop(state, None)
    try:
        info = await google_oauth.exchange_code(code)
        profile = google_oauth.parse_google_profile(info)
        if not profile["google_id"]:
            raise ValueError("missing google id")
        user = await request.app.state.users.upsert_google(
            google_id=profile["google_id"],
            email=profile["email"] or "",
            name=profile["name"] or "",
            picture=profile.get("picture"),
        )
    except Exception as exc:  # noqa: BLE001
        return RedirectResponse(
            f"{front}/auth/callback?error={quote(str(exc)[:120])}",
            status_code=302,
        )

    access = create_access_token(user)
    refresh, jti = create_refresh_token(user["id"])
    await request.app.state.refresh_store.put(
        jti, user["id"], ttl_sec=REFRESH_TTL_DAYS * 86400
    )
    # Hash fragment keeps access token out of server logs on next hop
    dest = f"{front}/auth/callback#access_token={quote(access)}"
    resp = RedirectResponse(dest, status_code=302)
    _set_refresh_cookie(resp, refresh)
    return resp


@router.post("/refresh")
async def refresh(request: Request) -> JSONResponse:
    token = request.cookies.get(REFRESH_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="no refresh cookie")
    try:
        payload = decode_token(token, expect_typ="refresh")
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="invalid refresh") from exc
    jti = payload.get("jti")
    user_id = await request.app.state.refresh_store.pop(jti or "")
    if not user_id or user_id != payload.get("sub"):
        raise HTTPException(status_code=401, detail="refresh revoked")
    user = await request.app.state.users.get(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="user gone")
    access = create_access_token(user)
    new_refresh, new_jti = create_refresh_token(user["id"])
    await request.app.state.refresh_store.put(
        new_jti, user["id"], ttl_sec=REFRESH_TTL_DAYS * 86400
    )
    body = {"access_token": access, "user": public_user(user)}
    resp = JSONResponse(body)
    _set_refresh_cookie(resp, new_refresh)
    return resp


@router.post("/logout")
async def logout(request: Request) -> JSONResponse:
    token = request.cookies.get(REFRESH_COOKIE)
    if token:
        try:
            payload = decode_token(token, expect_typ="refresh")
            jti = payload.get("jti")
            if jti:
                await request.app.state.refresh_store.revoke(jti)
        except jwt.PyJWTError:
            pass
    resp = JSONResponse({"ok": True})
    _clear_refresh_cookie(resp)
    return resp


@router.get("/me")
async def me(user: Dict[str, Any] = Depends(require_user)) -> Dict[str, Any]:
    return public_user(user)


@router.get("/status")
async def auth_status() -> Dict[str, Any]:
    return {"google": google_oauth.google_configured()}
