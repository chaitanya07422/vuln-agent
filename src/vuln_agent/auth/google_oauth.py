from __future__ import annotations

import os
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import httpx

GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO = "https://www.googleapis.com/oauth2/v3/userinfo"


def google_configured() -> bool:
    return bool(os.getenv("GOOGLE_CLIENT_ID") and os.getenv("GOOGLE_CLIENT_SECRET"))


def callback_url() -> str:
    return os.getenv(
        "GOOGLE_CALLBACK_URL",
        "http://127.0.0.1:8000/v1/auth/google/callback",
    )


def frontend_origin() -> str:
    return os.getenv("VULN_AGENT_FRONTEND_URL", "http://localhost:3000").rstrip("/")


def authorize_url(*, state: str) -> str:
    params = {
        "client_id": os.environ["GOOGLE_CLIENT_ID"],
        "redirect_uri": callback_url(),
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "online",
        "include_granted_scopes": "true",
        "state": state,
        "prompt": "select_account",
    }
    return f"{GOOGLE_AUTH}?{urlencode(params)}"


async def exchange_code(code: str) -> Dict[str, Any]:
    async with httpx.AsyncClient(timeout=20.0) as client:
        token_res = await client.post(
            GOOGLE_TOKEN,
            data={
                "code": code,
                "client_id": os.environ["GOOGLE_CLIENT_ID"],
                "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
                "redirect_uri": callback_url(),
                "grant_type": "authorization_code",
            },
        )
        token_res.raise_for_status()
        tokens = token_res.json()
        access = tokens.get("access_token")
        if not access:
            raise RuntimeError("Google token response missing access_token")
        info_res = await client.get(
            GOOGLE_USERINFO,
            headers={"Authorization": f"Bearer {access}"},
        )
        info_res.raise_for_status()
        return info_res.json()


def parse_google_profile(info: Dict[str, Any]) -> Dict[str, Optional[str]]:
    email = info.get("email")
    if not email:
        raise ValueError("Google account has no email")
    if info.get("email_verified") is False:
        raise ValueError("Google email is not verified")
    return {
        "google_id": str(info.get("sub") or ""),
        "email": email,
        "name": info.get("name") or email.split("@")[0],
        "picture": info.get("picture"),
    }
