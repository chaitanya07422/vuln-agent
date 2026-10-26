from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from vuln_agent.auth.deps import effective_plan, require_user
from vuln_agent.auth.tokens import public_user

router = APIRouter(prefix="/v1/billing", tags=["billing"])

PRO_MONTHLY_INR = 99900  # paise
PRO_YEARLY_INR = 799900


class CheckoutBody(BaseModel):
    interval: str = "month"  # month | year


def _razorpay_configured() -> bool:
    return bool(os.getenv("RAZORPAY_KEY_ID") and os.getenv("RAZORPAY_KEY_SECRET"))


@router.get("/plans")
async def plans() -> Dict[str, Any]:
    return {
        "currency": "INR",
        "plans": [
            {
                "id": "free",
                "name": "Free",
                "price": 0,
                "history": 10,
                "pdf": False,
            },
            {
                "id": "pro_monthly",
                "name": "Pro",
                "interval": "month",
                "price": PRO_MONTHLY_INR // 100,
                "history": 500,
                "pdf": True,
            },
            {
                "id": "pro_yearly",
                "name": "Pro yearly",
                "interval": "year",
                "price": PRO_YEARLY_INR // 100,
                "history": 500,
                "pdf": True,
            },
        ],
        "razorpay_ready": _razorpay_configured(),
    }


@router.post("/checkout")
async def checkout(
    body: CheckoutBody,
    request: Request,
    user: Dict[str, Any] = Depends(require_user),
) -> Dict[str, Any]:
    if not _razorpay_configured():
        raise HTTPException(status_code=503, detail="Billing not configured yet")
    amount = PRO_YEARLY_INR if body.interval == "year" else PRO_MONTHLY_INR
    receipt = f"sl_{user['id'][:8]}_{uuid4().hex[:8]}"
    auth = (os.environ["RAZORPAY_KEY_ID"], os.environ["RAZORPAY_KEY_SECRET"])
    async with httpx.AsyncClient(timeout=20.0) as client:
        res = await client.post(
            "https://api.razorpay.com/v1/orders",
            auth=auth,
            json={
                "amount": amount,
                "currency": "INR",
                "receipt": receipt,
                "notes": {
                    "user_id": user["id"],
                    "email": user.get("email") or "",
                    "interval": body.interval,
                },
            },
        )
        if res.status_code >= 400:
            raise HTTPException(status_code=502, detail=f"Razorpay error: {res.text[:200]}")
        order = res.json()
    return {
        "order_id": order["id"],
        "amount": order["amount"],
        "currency": order["currency"],
        "key_id": os.environ["RAZORPAY_KEY_ID"],
        "name": "ScanLead Pro",
        "description": f"Pro ({body.interval})",
        "prefill": {"email": user.get("email"), "name": user.get("name")},
        "notes": {"user_id": user["id"], "interval": body.interval},
    }


@router.post("/webhook")
async def webhook(request: Request) -> Dict[str, str]:
    raw = await request.body()
    secret = os.getenv("RAZORPAY_WEBHOOK_SECRET") or ""
    sig = request.headers.get("X-Razorpay-Signature", "")
    if secret:
        expected = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            raise HTTPException(status_code=400, detail="bad signature")
    try:
        payload = json.loads(raw.decode() or "{}")
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="invalid json") from exc

    event = payload.get("event") or ""
    if event not in ("payment.captured", "order.paid"):
        return {"ok": "ignored"}

    entity = (payload.get("payload") or {}).get("payment", {}).get("entity") or {}
    notes = entity.get("notes") or {}
    user_id = notes.get("user_id")
    interval = notes.get("interval") or "month"
    if not user_id:
        # try order notes
        order_ent = (payload.get("payload") or {}).get("order", {}).get("entity") or {}
        notes = order_ent.get("notes") or notes
        user_id = notes.get("user_id")
        interval = notes.get("interval") or interval
    if not user_id:
        return {"ok": "no_user"}

    days = 365 if interval == "year" else 30
    expires = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
    try:
        await request.app.state.users.update(
            user_id,
            plan="pro",
            plan_expires_at=expires,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="user not found") from None
    return {"ok": "upgraded"}


@router.get("/me")
async def billing_me(user: Dict[str, Any] = Depends(require_user)) -> Dict[str, Any]:
    return {
        "user": public_user(user),
        "plan": effective_plan(user),
        "history_limit": 500 if effective_plan(user) == "pro" else 10,
        "pdf": effective_plan(user) == "pro",
    }
